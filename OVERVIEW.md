# stun — a STUN server in Go

A from-scratch STUN server (RFC 8489), built to learn the protocol while ending up
with something actually usable. Stdlib only — `net`, `crypto`, `encoding/binary`
cover everything STUN needs; no dependencies.

This document is the living overview. Every commit updates the **Progress log**
below and, when the design changes, the sections above it.

## What STUN does

STUN (Session Traversal Utilities for NAT) lets a client behind a NAT discover
its public IP and port. The client sends a **Binding Request**; the server
replies with the source address it saw the packet come from, encoded in an
**XOR-MAPPED-ADDRESS** attribute. That's the whole core protocol — the server
is stateless and never relays traffic (that's TURN, out of scope).

Wire format in one paragraph: every message is a 20-byte header — 2-byte type,
2-byte length, the 4-byte magic cookie `0x2112A442`, and a 12-byte transaction
ID — followed by zero or more TLV attributes padded to 4-byte boundaries.
Addresses are XORed with the magic cookie so dumb NATs can't rewrite them in
transit.

## Architecture

```
cmd/stund/        main: flags, listener setup, shutdown
stunmsg/          message parse/serialize: header, attributes (no I/O)
server/           UDP (later TCP) loop: decode request → build response → send
```

`stunmsg` is a pure library with no networking, so it's trivially testable
against RFC 5769's test vectors. The server layer stays thin: read datagram,
parse, respond.

## Roadmap

1. **Message codec** — header + attribute parse/serialize, XOR-MAPPED-ADDRESS,
   ERROR-CODE, FINGERPRINT. Verified against RFC 5769 test vectors.
2. **UDP server** — Binding Request → Binding Success Response. Malformed
   input is dropped silently (per RFC), unknown comprehension-required
   attributes get a 420 error response.
3. **Hardening** — per-IP rate limiting, graceful shutdown, structured logs,
   TCP listener.
4. **Maybe later** — RFC 5780 NAT behavior discovery (needs two public IPs),
   long-term-credential auth. Only if there's a real use.

Skipped deliberately: TURN relaying, TLS/DTLS transport, authentication for the
basic binding service (public STUN servers like Google's run unauthenticated —
the response contains nothing an on-path attacker doesn't already know).

## References

- RFC 8489 — STUN (current spec, obsoletes 5389)
- RFC 5769 — test vectors for STUN messages
- RFC 5780 — NAT behavior discovery using STUN

## Progress log

- **2026-07-07** — Project start: repo, Go module, this overview.
