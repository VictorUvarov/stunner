# Chapter 3: The Binding exchange

Everything so far has been setup. This chapter is the actual service. A client
sends a **Binding Request**, the server replies with a **Binding Success
Response** carrying the client's public address, and the client is done. This
one exchange is what 99% of STUN traffic is. If you understand it, you
understand STUN.

The code lives in [`internal/server/server.go`](../internal/server/server.go),
and the shape of it is deliberately thin: read a datagram, parse it, decide
what to do, send a reply. Let's walk a good request through it, then spend the
rest of the chapter on the more interesting question — what the server does
with everything that *isn't* a good request.

## The happy path

A well-formed Binding Request arrives. The server:

1. Parses it into a `Message` (chapter 2's codec).
2. Confirms it's a Binding Request and that there's nothing in it the server is
   required to understand but doesn't (more on that below).
3. Builds a Binding Success Response: it copies the request's transaction ID so
   the client can match the answer, adds an **XOR-MAPPED-ADDRESS** attribute
   holding the address the datagram arrived from, adds a **SOFTWARE** attribute
   and a **FINGERPRINT** checksum, and serializes it.
4. Sends the reply **back out the same socket**, to the address the request
   came from.

That last point matters more than it looks. The client is behind a NAT, waiting
for an answer from the exact IP and port it sent to. Its router only opened a
return path for *that* conversation. If the server replied from a different
address or port, the router would drop the reply as unsolicited, and the client
would hear nothing. So "reply from the socket you received on, to the sender you
received from" isn't a nicety — it's the only thing that works. (Chapter 6,
where the server deliberately replies from a *different* address, is the
exception that proves the rule: that's a feature the client explicitly asks
for.)

Notice what the server didn't do: it didn't store anything. The address it
reported came straight off the incoming packet. When a retransmitted copy of
the same request arrives — which happens constantly on UDP — the server just
recomputes the same answer from scratch. There's no transaction table to look
up, because there's nothing to remember. The spec explicitly blesses this
"stateless recompute" approach for Binding, and it's why the server scales the
way it does.

## The silence rule

Now the interesting part. What does the server do with a packet that's
malformed? Or isn't STUN at all? Or is STUN but has a bad checksum? Or asks for
a method the server doesn't support?

For most of these, the answer is: **nothing.** No reply. The packet is dropped
and the server moves on. This is [RFC 8489 §6.3](https://datatracker.ietf.org/doc/html/rfc8489#section-6.3),
and it's not laziness — it's a security property.

Think about what a STUN server is: a machine on the public internet that sends
a reply to whatever address a request claims to come from. On UDP, that source
address is trivial to forge. If the server answered every packet, an attacker
could send a flood of requests with a *victim's* address forged as the source,
and the server would dutifully bombard the victim with replies. The server
would become a **reflector** — a tool for pointing traffic at someone else, and
often an *amplifier*, since a small request can draw a larger response.

Staying silent on anything questionable shrinks that risk. The server only ever
replies to input it has affirmatively recognized as a valid request. STUN ports
on the public internet see a constant drizzle of stray packets, port scans, and
other protocols' traffic; the silence rule means all of that draws no response
and costs almost nothing.

Here's the full table of what draws silence versus a reply:

| Input | What the server does |
|---|---|
| Valid Binding Request | Success response with XOR-MAPPED-ADDRESS |
| Binding Request with an attribute it must understand but doesn't | Error 420, listing the offending attributes |
| Binding Indication (a keepalive) | Silence — indications never get a reply |
| Random non-STUN bytes | Silence |
| Corrupt framing, or a bad FINGERPRINT | Silence |
| A source IP over its rate budget | Silence (chapter 9) |

## The one time it says "no": error 420

There's a single exception to "drop bad input silently," and it exists to be
*helpful* rather than to answer a question. STUN attributes come in two
flavors: **comprehension-required** and **comprehension-optional**. If a
request carries a comprehension-required attribute the server doesn't
understand, the server can't just proceed as if it weren't there — the client
clearly wanted something specific. So it replies with error **420 (Unknown
Attribute)**, listing exactly which attributes it didn't understand. Now the
client knows why it didn't get what it asked for, instead of guessing.

This is different from silence because a 420 is a legitimate answer to a
legitimate, well-formed request. The client sent valid STUN; it just asked for
a feature this server doesn't have. Telling it so is useful. (Comprehension-
*optional* attributes it doesn't recognize, by contrast, it simply ignores —
that's what "optional" means.)

A couple of auth-related attributes, USERNAME and MESSAGE-INTEGRITY, are
whitelisted as ignorable even though a naive reading might 420 them. A plain
Binding request needs no authentication, so if a client includes those, the
server just answers normally. Chapter 5 is where they start to matter.

## Binding Indications: the silent keepalive

One entry in the table deserves a note. Besides the request/response pair,
STUN has a one-way message called a **Binding Indication**. It gets no reply,
ever — and that's the point. A client sends indications periodically to a
server (or a peer) purely to keep its NAT mapping alive. Routers close idle
mappings after a while; a trickle of indications is enough traffic to keep the
door open. The server receives it, notes that a valid STUN message came in, and
says nothing. The receipt alone did the job.

## Starting and stopping

The server's lifecycle is as minimal as its state. You hand `Serve` a socket
and it blocks, handling packets, until the socket closes:

```go
conn, _ := net.ListenUDP("udp", addr)
err := server.Serve(conn)   // blocks; returns nil when conn is closed
```

There's no `Stop` method and no shutdown dance. Closing the socket makes the
blocked read return, which ends the loop cleanly. The `stund` binary wires a
SIGINT/SIGTERM handler to that close, so Ctrl-C exits 0 (chapter 9 shows the
wiring). This is the same theme again: no state means nothing to drain, nothing
to flush, nothing to lose on shutdown.

## Where this is going

You've now seen the complete service over one transport (UDP): a request comes
in, an answer goes out, and everything else is met with silence. The next
chapter asks: what changes when the same exchange runs over TCP, or inside an
encrypted TLS or DTLS session? The answer turns out to hinge on a single
difference between a datagram and a stream.

---

**Read the code**

- [`internal/server/server.go`](../internal/server/server.go) — `Serve`, and
  the `validate` / respond / seal path every transport shares.
- [`internal/server/README.md`](../internal/server/README.md) — the behavior
  table above, plus more detail on each case.
- [RFC 8489 §6.3](https://datatracker.ietf.org/doc/html/rfc8489#section-6.3) —
  the processing rules, including the silent-discard set.

---

[← Chapter 2: Anatomy of a STUN message](02-anatomy-of-a-message.md) · [Contents](README.md) · **Next:** [Chapter 4: Four transports →](04-transports.md)
