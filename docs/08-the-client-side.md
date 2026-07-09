# Chapter 8: The client side

Every chapter so far has stood behind the server, watching requests arrive.
Now cross to the other side of the wire. The client is the code that *asks*
"what's my address?" — and it faces a set of problems the server never does,
because the client is the one dealing with an unreliable network and an
unpredictable answer.

This server ships with a full client, in
[`internal/stunclient`](../internal/stunclient/), driving the `stunc` binary.
It exists for a practical reason beyond completeness: because it speaks every
transport the server does, it lets the project test itself end-to-end in Go.
Point `stunc` at `stund` over UDP, TCP, TLS, and DTLS and you've exercised the
whole stack.

## Problem one: your packet might vanish

The server's world is simple — a request arrives, it answers. The client's
world is not, because on UDP there's no guarantee the request ever arrived, or
that the answer ever came back. Either can silently disappear.

So the client can't just send and wait forever. It follows the retransmission
schedule from
[RFC 8489 §6.2.1](https://datatracker.ietf.org/doc/html/rfc8489#section-6.2.1):
send the request, wait one **RTO** (retransmission timeout, 500ms to start),
and if no answer comes, send it again and *double* the wait. Keep doubling up
to **Rc** attempts (7), then wait one final stretch (**Rm** × RTO) before
giving up with `ErrTimeout`. The doubling — exponential backoff — means a brief
blip costs one quick retry, while a truly dead server doesn't get hammered.
All three knobs (RTO, Rc, Rm) are configurable.

Stream transports (TCP, TLS) don't retransmit — the stream handles delivery —
so instead they take the schedule's *total* duration and use it as one overall
deadline. Same time budget, different mechanism.

## Problem two: which answer is mine?

If the client has fired off several requests, or if a stray packet wanders in,
how does it know which datagram is the answer to which question? The
transaction ID from chapter 2. The client generates a random 96-bit ID per
request and matches responses against it. Anything that doesn't match — a stray
datagram, unparseable bytes, a response with a broken FINGERPRINT — is ignored,
exactly as a well-behaved client must. The retransmission loop keeps waiting
for the *right* answer rather than being fooled by noise.

## Problem three: authenticating, in reverse

Chapter 5 walked the authentication dance from the server's chair. The client
plays the same dance from the other side, and the two are mirror images
([§9.2.5](https://datatracker.ietf.org/doc/html/rfc8489#section-9.2.5) for the
client, §9.2.4 for the server). Given a username and password, the client:

1. Sends its first request, gets a 401.
2. Reads the REALM, NONCE, and PASSWORD-ALGORITHMS out of the challenge.
3. Prepares its credentials with OpaqueString (chapter 5 — both sides must
   normalize identically or the HMAC won't match), picks an algorithm
   (SHA-256 preferred), and retries with a MESSAGE-INTEGRITY HMAC.

Two details carry over from chapter 5, seen now from the client's side:

- **Bid-down protection, enforced by the client.** The client only *engages*
  the negotiated PASSWORD-ALGORITHMS list when the nonce cookie's
  security-feature bit vouches for it. If those bits don't confirm the server
  really offered the list, the client refuses to trust the negotiation — which
  is what stops the downgrade attack from working. The defense needs both ends
  to check, and this is the client's half.
- **Verify the answer, not just send the question.** When the signed response
  comes back, the client verifies *its* MESSAGE-INTEGRITY before trusting the
  address inside. A correct answer from an attacker is still an attacker's
  answer.

A stale-nonce 438 costs one silent retry with the fresh nonce — the caller
never sees it. That mirrors the server's willingness to hand out a new nonce
once the credentials otherwise check out.

## Problem four: being told to go elsewhere

When the server answers 300 Try Alternate (chapter 7), the client surfaces it
as a typed `Redirect` error carrying the ALTERNATE-SERVER and ALTERNATE-DOMAIN.
It does **not** automatically follow it. That's deliberate: over TLS or DTLS,
the domain must be validated against the alternate server's certificate before
you trust the handoff, and only the caller knows its security requirements. So
the library hands the decision up rather than chasing the redirect blindly.

## The shape of the API

The client mirrors the transport split from chapter 4:

| Constructor | Semantics | Use for |
|---|---|---|
| `DialUDP` / `NewDatagram` | one message per read, with retransmission | UDP, DTLS (pass a pion `dtls.Conn`) |
| `DialTCP` / `NewStream` | length-framed stream, single send | TCP, TLS (pass a `tls.Conn`) |

And the common case is two lines:

```go
c, err := stunclient.DialUDP("stun.example.org:3478", stunclient.Config{})
if err != nil { ... }
defer c.Close()
mapped, err := c.Binding() // your address as the server saw it
```

A `Client` owns its connection and runs one transaction at a time — it's not
built for concurrent use. If you want parallelism, use several clients. That
keeps the retransmission and transaction-matching logic simple: one question,
one answer, at a time.

## Where this is going

You've now seen both ends of every exchange. The last chapter steps out of the
protocol entirely and into operations: how the running server protects itself
from abuse, reports what it's doing, rotates its certificates without a
restart, and gets packaged up so you can actually deploy it.

---

**Read the code**

- [`internal/stunclient/client.go`](../internal/stunclient/client.go) — the
  whole client: retransmission, transaction matching, the auth flow, and the
  redirect error.
- [`cmd/stunc/main.go`](../cmd/stunc/main.go) — flags wired to a transport;
  the thin binary over the library.
- [`internal/stunclient/README.md`](../internal/stunclient/README.md) — the API
  as reference.

---

[← Chapter 7: Redirects and classic clients](07-redirects-and-classic-clients.md) · [Contents](README.md) · **Next:** [Chapter 9: Running it in production →](09-running-it-in-production.md)
