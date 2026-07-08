# stunclient

The client side of the STUN Binding usage
([RFC 8489 §6.2](https://datatracker.ietf.org/doc/html/rfc8489#section-6.2)):
where the [`server`](../server/) package answers *"what's my public
address?"*, this package asks the question. It exists so the repo can test
itself end to end in Go (see [`cmd/stunc`](../../cmd/stunc/)) and so the
[`stunmsg`](../stunmsg/) codec earns its keep outside the server.

```go
c, err := stunclient.DialUDP("stun.example.org:3478", stunclient.Config{})
if err != nil { ... }
defer c.Close()
mapped, err := c.Binding() // your address as the server saw it
```

## What it handles for you

- **Retransmission** — UDP gives no delivery guarantee, so
  [§6.2.1](https://datatracker.ietf.org/doc/html/rfc8489#section-6.2.1)
  prescribes a schedule: send, wait RTO (500ms), double and resend, up to
  Rc (7) sends, then wait Rm×RTO before declaring `ErrTimeout`. `Config`
  exposes all three knobs; stream transports use the schedule's total
  duration as their overall deadline instead.
- **Transaction matching** — responses are matched on the random 96-bit
  transaction ID; stray datagrams, unparseable input, and messages with
  broken FINGERPRINTs are ignored, as a client must.
- **Authentication** — given `Config.Username`/`Password`, a 401 challenge
  is answered per [§9.2.5](https://datatracker.ietf.org/doc/html/rfc8489#section-9.2.5):
  credentials are OpaqueString-processed, the server's PASSWORD-ALGORITHMS
  list is echoed and an algorithm chosen (SHA-256 preferred) — but only
  when the nonce cookie's security-feature bit vouches for the list, which
  is the bid-down protection — and the response's own integrity attribute
  is verified before the result is trusted. Stale nonces (438) cost one
  silent retry.
- **Redirects** — a 300 Try Alternate surfaces as a typed `Redirect` error
  carrying ALTERNATE-SERVER and ALTERNATE-DOMAIN; following it is the
  caller's decision, because over TLS/DTLS the domain must be validated
  against the alternate's certificate.

## Transports

| Constructor | Semantics | Use for |
|---|---|---|
| `DialUDP` / `NewDatagram` | one message per read, retransmission | UDP, DTLS (pass a pion `dtls.Conn`) |
| `DialTCP` / `NewStream` | length-framed stream, single send | TCP, TLS (pass a `tls.Conn`) |

A `Client` owns its connection and runs one transaction at a time; it is
not safe for concurrent use.
