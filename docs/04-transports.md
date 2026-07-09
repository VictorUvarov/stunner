# Chapter 4: Four transports

So far the exchange has run over UDP: one request in a datagram, one response
in a datagram. But this server speaks four transports — UDP, TCP, TLS, and
DTLS — and a client picks whichever fits. A browser doing WebRTC might use any
of them. This chapter is about what changes across the four, and the surprising
answer is: less than you'd think, except for one difference that changes
everything about error handling.

That difference is **datagram versus stream**. UDP and DTLS are datagram
transports: the network hands you one whole message at a time, with clear
edges. TCP and TLS are stream transports: the network hands you a firehose of
bytes with no edges, and you have to find the message boundaries yourself.
Every difference below flows from that one fact.

## UDP: one datagram, one message

This is the transport from chapter 3, and it's the simplest. Each datagram
holds exactly one STUN message. If a datagram is garbage, you drop it and read
the next one — the boundaries are given to you by the network, so a bad packet
costs you nothing. The silence rule (chapter 3) is easy here: "drop and keep
listening" is the natural thing to do.

## TCP: a stream you have to cut into messages

TCP hands you a byte stream. Several requests can arrive back-to-back with no
gaps, and it's on you to know where one ends and the next begins. STUN's header
makes this possible: the length field (chapter 2) tells you exactly how many
attribute bytes follow, so you read the 20-byte header, learn the length, read
that many more bytes, and you've got one message. Repeat.

`ServeTCP` runs one goroutine per connection, each reading length-framed
messages in a loop. Two guardrails keep a connection honest: a **40-second
idle timeout** hangs up a connection that goes quiet, and a **4 KiB frame cap**
rejects an absurd length field before it can allocate a huge buffer.

But here's where the datagram/stream difference bites. On UDP, a malformed
packet is harmless — you skip it. On TCP, a malformed *frame* is a catastrophe,
because once the bytes don't parse, you've lost track of where the next message
begins. There's no way to resync a stream. So the rule flips:

- **Input that isn't parseable as STUN** — garbage bytes, broken framing, an
  oversized frame — forces the server to **close the connection.** It can't do
  anything else; the stream is unintelligible from here on.
- **Well-formed STUN that simply draws no reply** — a Binding Indication
  keepalive, an unsupported method, a bad FINGERPRINT — leaves the connection
  **open.** The framing survived, so the next message is still findable, and
  [RFC 8489 §6.2.2](https://datatracker.ietf.org/doc/html/rfc8489#section-6.2.2)
  says to let the *client* decide when to hang up.

That distinction — "did the framing survive?" — is the whole of TCP's extra
complexity. Getting it wrong was a real bug caught during the conformance
sweep: the server used to treat "no reply" as "framing lost" and hang up on a
harmless keepalive. Now `handle` reports whether the bytes parsed as STUN at
all, and only a genuine parse failure closes the connection.

## TLS: TCP in a sealed envelope

STUN over TLS sounds like it should need a pile of new code. It needs none.

TLS is just TCP inside an encrypted session. Once the TLS handshake completes,
what flows through is an ordinary byte stream — the same stream `ServeTCP`
already knows how to cut into messages. So "STUN over TLS" is implemented by
handing `ServeTCP` a TLS listener instead of a plain one:

```go
tln, _ := tls.Listen("tcp", addr, tlsConfig)
err = server.ServeTCP(tln)   // that's the entire feature
```

The standard port for encrypted STUN — called **`stuns`** — is 5349, versus
3478 for plaintext. Beyond choosing that port and supplying a certificate,
there's nothing TLS-specific in the server. The handshake is bounded by the
same idle deadline as a first read, so a client that connects and then stalls
mid-handshake gets timed out rather than tying up a goroutine.

One footnote for the spec-minded:
[RFC 8489 §6.2.3](https://datatracker.ietf.org/doc/html/rfc8489#section-6.2.3)
lists a mandatory cipher suite (a DHE one) that Go's TLS stack doesn't ship.
But Go has all the *ECDHE* suites the RFC also mandates, and ECDHE is what every
real client negotiates, so in practice nothing is missing.

## DTLS: the hybrid

DTLS is "TLS for datagrams" — encryption over UDP instead of TCP. It's what
you use when you want the security of TLS but the low-latency, connectionless
feel of UDP, which is exactly what real-time media wants. Go ships TLS but no
DTLS, so this is one of only two places the codebase reaches outside the
standard library, using [pion/dtls](https://github.com/pion/dtls).

`ServeDTLS` is a genuine hybrid of the two models you've now seen:

- Its **lifecycle is like TCP**: there's a handshake, a per-association
  goroutine, and a 40-second idle hangup. A DTLS "connection" is a real thing
  that gets set up and torn down.
- Its **message handling is like UDP**: each DTLS record frames exactly one
  message, so a malformed record is dropped and the association survives —
  no stream to lose sync on.

So DTLS borrows the connection management from the stream side and the
forgiving error handling from the datagram side. It runs on the same `stuns`
port, 5349, over UDP.

DTLS also brings a security obligation that TCP doesn't, and it's worth knowing
the server meets it. Because DTLS runs over spoofable UDP, an attacker could
fire off handshake openers (`ClientHello`s) with a forged source, tricking the
server into allocating handshake state — or sending handshake data — toward a
victim who never asked. [RFC 8489 §13](https://datatracker.ietf.org/doc/html/rfc8489#section-13)
requires a DTLS server to defend against this with a **cookie exchange** (from
[RFC 6347](https://datatracker.ietf.org/doc/html/rfc6347)): before committing
any state, the server makes the client prove it can receive at the address it
claims. pion/dtls does this by default, the server never disables it, and a
test (`TestDTLSCookieExchange`) pins the behavior so that a future library
upgrade can't silently weaken it.

## The payoff: one core, four front doors

Step back and the design is clean. There's one message codec (chapter 2) and
one core request-handling path (chapter 3). The four transports are four ways
of getting bytes to and from that core: UDP and DTLS deliver whole messages,
TCP and TLS deliver streams that get cut into messages, and TLS/DTLS wrap the
whole thing in encryption. The `stund` binary can run all four at once — plain
STUN on 3478, `stuns` on 5349 — from the same handler.

## Where this is going

Every exchange so far has been anonymous: anyone who can reach the server gets
an answer. That's correct for a public STUN server, because the answer reveals
nothing an on-path observer doesn't already know. But sometimes you want to
restrict who may use the server. The next chapter is about authentication — the
most intricate part of the protocol, and the place where the wire format from
chapter 2 finally gets used to its full extent.

---

**Read the code**

- [`internal/server/server.go`](../internal/server/server.go) — the UDP path
  and the shared handler.
- [`internal/server/tcp.go`](../internal/server/tcp.go) — `ServeTCP`, framing,
  timeouts, and the "did it parse?" hang-up rule. TLS reuses this.
- [`internal/server/dtls.go`](../internal/server/dtls.go) — `ServeDTLS` and the
  hybrid lifecycle.
- [`internal/server/dtls_cookie_test.go`](../internal/server/dtls_cookie_test.go)
  — the cookie-exchange guard.

---

[← Chapter 3: The Binding exchange](03-the-binding-exchange.md) · [Contents](README.md) · **Next:** [Chapter 5: Authentication →](05-authentication.md)
