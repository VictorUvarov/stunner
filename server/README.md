# server

The actual STUN service. The job is almost comically simple: a device behind
a home router doesn't know what IP address the outside world sees it as.
So it sends this server a **Binding Request** ("what's my address?"), and
the server replies with the address and port the request *arrived from* —
which is exactly the public-facing address the client wanted to know.
No accounts, no sessions, no stored state: every request is answered from
the envelope it came in.

## API

One exported entry point:

```go
conn, _ := net.ListenUDP("udp", addr)
err := server.Serve(conn)   // blocks; returns nil when conn is closed
```

Shutdown model: there is no Stop method — close the socket and `Serve`
returns. That's the whole lifecycle.

## What it does with each packet

| Input | Response |
|---|---|
| Valid Binding Request | Success response carrying the sender's address (XOR-MAPPED-ADDRESS) |
| … containing an attribute we're required to understand but don't | Error 420 listing the offending attributes, so the client knows why |
| … containing auth attributes (USERNAME, MESSAGE-INTEGRITY) | Ignored — this server doesn't do auth — and answered normally |
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

## Tests

`server_test.go` runs the real loop over loopback sockets: success path,
420 path, ignored-auth-attribute path, and silent-drop cases (garbage,
corrupt checksum) verified by read timeout.
