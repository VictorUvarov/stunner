# Understanding STUN, one chapter at a time

This is a guided tour of STUN — the protocol that lets a device behind a home
router discover its own public address — taught through the code that
implements it. By the end you'll know what every byte on the wire means, why
the protocol makes the choices it does, and where each choice lives in this
codebase.

You don't need to know STUN already. You do need to be comfortable reading Go
and to know roughly what an IP address and a port are. Everything else is built
up from there.

## How to read this

Start at chapter 1 and go in order. Each chapter assumes the one before it.
The arc runs from "why does this protocol exist" to "here is the whole thing
running in production," and the concepts stack: the wire format explains the
Binding exchange, the Binding exchange explains the transports, and so on.

Every chapter ends with a **Read the code** box pointing at the files that
implement what you just learned. Open them alongside the prose — the whole
point of learning a protocol from a real server is that you can see the spec
turn into running code.

Two companion documents sit one level up:

- [`README.md`](../README.md) — what stunner is and why you'd run it.
- [`OVERVIEW.md`](../OVERVIEW.md) — the design log, written as the server was
  built, phase by phase. This tutorial is the "learn it" view; OVERVIEW is the
  "how it was made" view.

## The chapters

1. [The NAT problem](01-the-nat-problem.md) — why a device can't just look up
   its own address, and how one round trip fixes it.
2. [Anatomy of a STUN message](02-anatomy-of-a-message.md) — the 20-byte
   header, attributes, the magic cookie, and why the address is scrambled.
3. [The Binding exchange](03-the-binding-exchange.md) — the entire core
   service in one request and one response, and the rule that the server stays
   silent on anything it doesn't like.
4. [Four transports](04-transports.md) — the same exchange over UDP, TCP, TLS,
   and DTLS, and why a stream forces different error handling than a datagram.
5. [Authentication](05-authentication.md) — long-term credentials: the
   challenge/response, the HMAC, and the tricks that stop an attacker from
   forcing weaker security.
6. [NAT behavior discovery](06-nat-behavior-discovery.md) — going beyond "what
   is my address" to "how does my NAT behave," using four sockets and a few
   clever attributes.
7. [Redirects and classic clients](07-redirects-and-classic-clients.md) —
   sending a client elsewhere, and still answering the 2003 version of the
   protocol.
8. [The client side](08-the-client-side.md) — asking the question:
   retransmission, matching answers to questions, and running the auth flow in
   reverse.
9. [Running it in production](09-running-it-in-production.md) — rate limiting,
   graceful shutdown, metrics, certificate rotation, and shipping it.

## A note on the RFCs

STUN is defined by [RFC 8489](https://datatracker.ietf.org/doc/html/rfc8489),
with NAT behavior discovery in
[RFC 5780](https://datatracker.ietf.org/doc/html/rfc5780) and the original
"classic" version in [RFC 3489](https://datatracker.ietf.org/doc/html/rfc3489).
This tutorial links the exact section whenever the code follows a specific
rule. You never have to read the RFCs to follow along — but when you want the
authoritative word, the pointer is right there.
