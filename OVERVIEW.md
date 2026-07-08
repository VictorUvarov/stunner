# Design overview

Implementation notes for stund (see [README.md](README.md) for what/why).
Built from scratch against RFC 8489, stdlib only — `net`, `crypto`,
`encoding/binary` cover everything STUN needs.

This is the living design doc. Every commit updates the **Progress log**
below and, when the design changes, the sections above it.

## Protocol core

The server handles one exchange: a client sends a **Binding Request**, the
server replies with the source address the packet arrived from, encoded as
**XOR-MAPPED-ADDRESS**. Stateless, no relaying.

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
- **2026-07-07** — Split docs: user-facing README.md, this file now dev-only.
- **2026-07-07** — Phase 1 done: `stunmsg` codec. Parse/Marshal with strict
  framing checks, XOR-MAPPED-ADDRESS (v4+v6), ERROR-CODE, SOFTWARE,
  FINGERPRINT add/verify. Tested against RFC 5769 §2.1–2.3 vectors, including
  their non-zero padding bytes. Notable design choices: attributes are kept as
  raw `[]Attr` (typed accessors only where the server needs them), and
  `AddFingerprint` computes the CRC via a `marshal(extraLen)` hook because the
  spec requires the header length to already count the fingerprint attribute.
  MESSAGE-INTEGRITY is parsed as an opaque attribute — validation comes only
  if auth ever lands (roadmap #4).
