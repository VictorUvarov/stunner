# server

The actual STUN service. The job is almost comically simple: a device behind
a home router doesn't know what IP address the outside world sees it as.
So it sends this server a **Binding Request** ("what's my address?"), and
the server replies with the address and port the request *arrived from* —
which is exactly the public-facing address the client wanted to know.
No accounts, no sessions, no stored state: every request is answered from
the envelope it came in.

## API

Two entry points, one per transport:

```go
conn, _ := net.ListenUDP("udp", addr)
err := server.Serve(conn)     // blocks; returns nil when conn is closed

ln, _ := net.Listen("tcp", addr)
err = server.ServeTCP(ln)     // same contract, one goroutine per connection
```

Shutdown model: there is no Stop method — close the socket/listener and the
serve loop returns. That's the whole lifecycle.

## What it does with each packet

| Input | Response |
|---|---|
| Valid Binding Request | Success response carrying the sender's address (XOR-MAPPED-ADDRESS) |
| … containing an attribute we're required to understand but don't | Error 420 listing the offending attributes, so the client knows why |
| … containing auth attributes (USERNAME, MESSAGE-INTEGRITY) | Ignored and answered normally — unless auth is enabled, see below |
| Anything else: random non-STUN bytes, corrupt messages, bad checksums | Silence |
| A source IP over its rate budget (`RPS`/`Burst` package vars) | Silence |

The silence rule comes from [RFC 8489 §6.3](https://datatracker.ietf.org/doc/html/rfc8489#section-6.3):
answering broken input would let attackers use the server as a traffic
reflector, and STUN ports see plenty of stray internet noise.

Every response carries a SOFTWARE attribute (the `Software` package
variable), a FINGERPRINT checksum, and echoes the request's transaction ID
so the client can match it to what it sent.

Replies go out the same socket the request came in on. That matters: the
client is waiting for an answer from the exact ip:port it messaged, and its
router will only let the reply through on that path.

## Authentication (opt-in)

Public STUN servers run unauthenticated — the response contains nothing an
on-path observer doesn't already know. But if you want to restrict who may
use the server, set the `Credentials` package variable and every request
must prove knowledge of a username/password using
[RFC 8489 §9.2](https://datatracker.ietf.org/doc/html/rfc8489#section-9.2)
long-term credentials:

```go
auth, err := server.NewAuth("example.org", map[string]string{"alice": "s3cret"})
server.Credentials = auth
```

The exchange is challenge/response. A first, unauthenticated request draws
a 401 carrying the realm, a nonce, and the password algorithms the server
offers (SHA-256 preferred, MD5 for legacy clients). The client retries with
USERNAME (or USERHASH, for username anonymity), REALM, NONCE, its algorithm
choice, and a MESSAGE-INTEGRITY(-SHA256) HMAC keyed by hash(user:realm:
password). Expired nonces draw a 438 with a fresh one — but only after the
credentials check out; a bad password always draws another 401. Responses
are signed with MESSAGE-INTEGRITY-SHA256 when the client negotiated an
algorithm, legacy MESSAGE-INTEGRITY otherwise, exactly as
[§9.2.4](https://datatracker.ietf.org/doc/html/rfc8489#section-9.2.4)
prescribes.

Bid-down protection: every nonce starts with the RFC's "nonce cookie" —
a magic string plus feature bits covering password-algorithm negotiation
and username anonymity. An on-path attacker who strips those bits to force
weaker auth invalidates the nonce, and the downgrade dies with a 438.

Nonces are stateless: an expiry timestamp plus an HMAC under a per-process
random secret (5 minute lifetime). Nothing is stored per client, so the
nonce table can't be flooded; a server restart just costs clients one extra
438 round trip. Realm, usernames, and passwords are run through the
OpaqueString profile ([RFC 8265](https://datatracker.ietf.org/doc/html/rfc8265))
at setup, and only derived keys are kept in memory — raw passwords are not.

## TCP differences

A TCP connection can carry many requests back to back — messages are framed
by the header's length field. But a stream can't skip bad input the way UDP
skips a bad datagram: after a framing error there's no way to find the next
message. So on TCP, anything that would be "silence" on UDP (malformed
message, bad checksum, oversize frame, rate-limit hit) closes the
connection instead. Idle connections are dropped after 40s.

## NAT behavior discovery (RFC 5780)

Beyond "what's my address?", a client may want to know *how* its NAT
behaves — e.g. whether the same public port is reused for every destination
(good for peer-to-peer) or whether inbound packets from unknown hosts get
dropped. Answering that requires the server to reply from *different*
addresses on request, so the client can observe what gets through.

`Discovery` implements this
([RFC 5780](https://datatracker.ietf.org/doc/html/rfc5780)): four UDP
sockets (two IPs × two ports), plus three attributes:

- **RESPONSE-ORIGIN** — where this response was actually sent from.
- **OTHER-ADDRESS** — the alternate IP:port the client could probe.
- **CHANGE-REQUEST** — client asks: reply from the other IP and/or port.

```go
d, _ := server.ListenDiscovery(ip1, ip2, 3478, 3479)
err := d.Serve()   // blocks; d.Close() ends it
```

Error responses always leave from the socket that received the request.
PADDING and RESPONSE-PORT (fragment/lifetime tests) are not implemented;
being comprehension-required attributes, they correctly draw a 420.

## Tests

`server_test.go` runs the real loop over loopback sockets: success path,
420 path, ignored-auth-attribute path, and silent-drop cases (garbage,
corrupt checksum) verified by read timeout.
