# server

The actual STUN service. The job is almost comically simple: a device behind
a home router doesn't know what IP address the outside world sees it as.
So it sends this server a **Binding Request** ("what's my address?"), and
the server replies with the address and port the request *arrived from* —
which is exactly the public-facing address the client wanted to know.
No accounts, no sessions, no stored state: every request is answered from
the envelope it came in.

## API

One entry point per transport, all with the same contract:

```go
conn, _ := net.ListenUDP("udp", addr)
err := server.Serve(conn)     // blocks; returns nil when conn is closed

ln, _ := net.Listen("tcp", addr)
err = server.ServeTCP(ln)     // same contract, one goroutine per connection

tln, _ := tls.Listen("tcp", addr, tlsConfig)
err = server.ServeTCP(tln)    // STUN over TLS is STUN over TCP in a secure stream

dln, _ := dtls.ListenWithOptions("udp", udpAddr, dtls.WithCertificates(cert))
err = server.ServeDTLS(dln)   // DTLS: connection lifecycle like TCP, framing like UDP
```

Shutdown model: there is no Stop method — close the socket/listener and the
serve loop returns. That's the whole lifecycle.

## What it does with each packet

| Input | Response |
|---|---|
| Valid Binding Request | Success response carrying the sender's address (XOR-MAPPED-ADDRESS) |
| … containing an attribute we're required to understand but don't | Error 420 listing the offending attributes, so the client knows why |
| … containing auth attributes (USERNAME, MESSAGE-INTEGRITY) | Ignored and answered normally — unless auth is enabled, see below |
| A Binding Indication | Silence — indications get no response by design; their receipt alone refreshes NAT bindings |
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

One wire-format subtlety: the HMAC covers only what precedes it, so
attributes *after* MESSAGE-INTEGRITY(-SHA256) could have been appended by
anyone without invalidating the signature. The server discards them on
receipt (only FINGERPRINT, which must trail, survives), as
[RFC 8489 §9](https://datatracker.ietf.org/doc/html/rfc8489#section-9)
requires — nothing ever acts on unauthenticated trailing attributes.

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
message. So on TCP, input that isn't parseable STUN (garbage bytes,
malformed framing, oversize frames) and rate-limit hits close the
connection instead. Well-formed messages that simply draw no reply — a
Binding Indication keepalive, an unsupported method, a bad FINGERPRINT —
leave the connection open: the framing survived, and
[§6.2.2](https://datatracker.ietf.org/doc/html/rfc8489#section-6.2.2) has
the server let the client decide when to hang up. Idle connections are
dropped after 40s.

## Secure transports: TLS and DTLS (`stuns`)

[RFC 8489 §6.2.3](https://datatracker.ietf.org/doc/html/rfc8489#section-6.2.3)
runs the same exchanges inside an encrypted session on port 5349. TLS needs
no code of its own: a `tls.Listen` listener handed to `ServeTCP` is the
entire feature, with the handshake bounded by the same idle deadline as a
first read. DTLS (TLS's datagram sibling) gets `ServeDTLS`, backed by
[pion/dtls](https://github.com/pion/dtls) — the one dependency this package
takes beyond the stdlib, because Go ships no DTLS. Its semantics are a
hybrid: connection lifecycle like TCP (per-association goroutine, 40s idle
hangup), but message handling like UDP — each DTLS record frames exactly
one message, so malformed input is dropped and the association survives.

One §6.2.3 note: the RFC's mandatory-to-implement cipher list includes a
DHE suite that Go's TLS stack deliberately omits; the equally mandated
ECDHE suites are all there, which every real client negotiates.

## Redirects: ALTERNATE-SERVER (opt-in)

A server that wants clients to go elsewhere — draining for maintenance,
splitting load — sets the `Alternate` package variable, and every Binding
Request draws a 300 (Try Alternate) error naming the replacement
([RFC 8489 §10](https://datatracker.ietf.org/doc/html/rfc8489#section-10)):

```go
server.Alternate = &server.AlternateServer{
    V4:     netip.MustParseAddrPort("198.51.100.20:3478"),
    Domain: "stun.example.org", // ALTERNATE-DOMAIN, for TLS/DTLS cert checks
}
```

The RFC requires the ALTERNATE-SERVER address to match the client's address
family, so targets are configured per family and requests from a family
with no target are served normally. With auth enabled, the redirect happens
only after credentials verify and the 300 is integrity-protected — an
off-path attacker can't forge one. The NAT discovery usage never redirects:
its whole value is this server's specific four-socket topology.

## NAT behavior discovery (RFC 5780)

Beyond "what's my address?", a client may want to know *how* its NAT
behaves — e.g. whether the same public port is reused for every destination
(good for peer-to-peer) or whether inbound packets from unknown hosts get
dropped. Answering that requires the server to reply from *different*
addresses on request, so the client can observe what gets through.

`Discovery` implements this
([RFC 5780](https://datatracker.ietf.org/doc/html/rfc5780)): four UDP
sockets (two IPs × two ports), plus five attributes:

- **RESPONSE-ORIGIN** — where this response was actually sent from.
- **OTHER-ADDRESS** — the alternate IP:port the client could probe.
- **CHANGE-REQUEST** — client asks: reply from the other IP and/or port.
- **RESPONSE-PORT** — client asks: send the reply to this port instead of
  the one I sent from. Used to time out NAT bindings (how long does my
  mapping survive without traffic?) without refreshing the binding under
  test.
- **PADDING** — client asks: inflate your reply with this many junk bytes
  (we use the outgoing interface's MTU, as the RFC recommends), so both
  request and response overshoot the path MTU and the client learns whether
  its NAT passes IP fragments.

```go
d, _ := server.ListenDiscovery(ip1, ip2, 3478, 3479)
err := d.Serve()   // blocks; d.Close() ends it
```

A request combining PADDING and RESPONSE-PORT draws a 400, per the RFC —
a fragment test redirected to a port nobody reads couldn't be observed
anyway. Error responses always leave from the socket that received the
request, back to the true source: RESPONSE-PORT redirects successes only,
so a failing request can't aim even a small reply at a port its sender
doesn't hold.

## Tests

`server_test.go` runs the real loop over loopback sockets: success path,
420 path, ignored-auth-attribute path, and silent-drop cases (garbage,
corrupt checksum) verified by read timeout.
