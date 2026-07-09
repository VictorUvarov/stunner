# Chapter 6: NAT behavior discovery

Knowing your public address is enough to *attempt* a direct connection. It
isn't enough to know whether that attempt will *work*. That depends on how your
NAT behaves — and NATs behave in maddeningly different ways. Some give you the
same public port no matter who you talk to; others hand out a fresh port for
every destination. Some let a stranger's packet reach you if you've talked to
anyone on that port; others slam the door unless you've talked to that exact
stranger.

These behaviors decide whether two peers can connect directly or need to fall
back to a relay. [RFC 5780](https://datatracker.ietf.org/doc/html/rfc5780)
extends STUN to *measure* them, and this server implements it in
[`internal/server/discovery.go`](../internal/server/discovery.go). It's an
optional mode — off unless you turn it on — because, as you'll see, it needs
something a basic server doesn't: two public IP addresses.

## The trick: reply from somewhere else

How do you probe a NAT's rules from the outside? You get the server to reply
from *different* addresses and see which replies make it back through. If a
reply from a brand-new IP:port reaches the client, the client's NAT must be
permissive; if it's dropped, the NAT is strict. The pattern of what gets
through tells the client exactly how its NAT filters and maps.

This is the one place the chapter-3 rule — "always reply from the socket you
received on" — is deliberately broken. And it's not really an exception,
because the client *asks* for the reply to come from elsewhere. That's the
whole point of the measurement.

## Four sockets

To reply from different places, the server needs different places to reply
from. So discovery mode listens on **four UDP sockets**: two IP addresses
crossed with two ports.

```
            port A            port B
   IP 1   socket (1,A)     socket (1,B)
   IP 2   socket (2,A)     socket (2,B)
```

That's why discovery needs two public IPs on the machine. With four sockets,
the server can answer from the same IP and port the request came in on, or the
same IP different port, or different IP same port, or different IP and port —
the four combinations a client needs to map out its NAT. You start it like
this:

```go
d, _ := server.ListenDiscovery(ip1, ip2, 3478, 3479)
err := d.Serve()   // blocks; d.Close() ends it
```

## The five attributes

Discovery adds five attributes to the vocabulary. Three are the server telling
the client where things are; two are the client asking the server to do
something.

The server reports:

- **RESPONSE-ORIGIN** — "this reply came from *this* address." Lets the client
  confirm which socket answered.
- **OTHER-ADDRESS** — "here's the other IP:port you could probe" — the
  diagonal socket, the one differing in both IP and port. This is the client's
  map to the rest of the grid.

The client requests:

- **CHANGE-REQUEST** — "reply from the other IP, or the other port, or both."
  This is the core probe. Internally it just flips which of the four sockets
  sends the answer, following RFC 5780 §6.1's Table 1.
- **RESPONSE-PORT** — "send the reply to *this* port instead of the one I sent
  from." Used to measure how long a NAT keeps a mapping alive: the client can
  receive the answer on a fresh port without sending traffic on the port being
  timed, so the measurement doesn't disturb what it's measuring.
- **PADDING** — "pad your reply with this many junk bytes." Used to force the
  response past the path's MTU so the client learns whether its NAT passes
  fragmented IP packets. The server sizes the padding to the outgoing
  interface's MTU, as the RFC recommends.

A discovery success response also carries plain **MAPPED-ADDRESS** alongside
the XOR-MAPPED-ADDRESS, because RFC 5780 requires it.

## The safety rules

Redirecting replies is exactly the reflection risk from chapter 3, so
discovery draws its lines carefully:

- **Error responses always go back to the true source**, out the socket that
  received the request. Only *success* responses honor a RESPONSE-PORT
  redirect. That way a malformed or unauthorized request can never aim even a
  small reply at a port its sender doesn't actually hold.
- **PADDING and RESPONSE-PORT together draw a 400.** A padded reply redirected
  to a port nobody is reading couldn't be observed anyway, so the combination
  is rejected rather than serviced pointlessly.
- **On a single-IP server, CHANGE-REQUEST draws a 420.** Without a second IP
  the server can't honor "reply from the other address," and
  comprehension-required attributes it can't satisfy get the honest 420 from
  chapter 3. So a client's discovery probe degrades gracefully into "this
  server doesn't do discovery" rather than a silent wrong answer.

That last rule is why discovery is a separate, opt-in mode rather than
something the plain server half-does. A basic `stund` with one IP correctly
tells discovery clients "not here," and only a server explicitly started with a
second IP claims the capability.

## Where this is going

You've now seen every *answer* the server can give: a plain address, an
authenticated address, and a full NAT-behavior probe. The next chapter covers
the two ways the server can decline to answer in the normal way — sending the
client to a different server, and speaking to clients that predate the modern
protocol entirely.

---

**Read the code**

- [`internal/server/discovery.go`](../internal/server/discovery.go) —
  `ListenDiscovery`, the four-socket topology, and the CHANGE-REQUEST /
  RESPONSE-PORT / PADDING handling.
- [`internal/server/README.md`](../internal/server/README.md) — the "NAT
  behavior discovery" section, with the attribute list.
- [RFC 5780](https://datatracker.ietf.org/doc/html/rfc5780) — the extension in
  full; §6.1 Table 1 is the CHANGE-REQUEST socket-selection logic.

---

[← Chapter 5: Authentication](05-authentication.md) · [Contents](README.md) · **Next:** [Chapter 7: Redirects and classic clients →](07-redirects-and-classic-clients.md)
