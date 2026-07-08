# Design overview

Implementation notes for stund (see [README.md](README.md) for what/why).
Built from scratch against [RFC 8489](https://datatracker.ietf.org/doc/html/rfc8489), stdlib only — `net`, `crypto`,
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
server/           UDP and TCP loops: decode request → build response → send
```

`stunmsg` is a pure library with no networking, so it's trivially testable
against [RFC 5769](https://datatracker.ietf.org/doc/html/rfc5769)'s test vectors. The server layer stays thin: read datagram,
parse, respond.

## Roadmap

1. **Message codec** — header + attribute parse/serialize, XOR-MAPPED-ADDRESS,
   ERROR-CODE, FINGERPRINT. Verified against [RFC 5769](https://datatracker.ietf.org/doc/html/rfc5769) test vectors.
2. **UDP server** — Binding Request → Binding Success Response. Malformed
   input is dropped silently (per RFC), unknown comprehension-required
   attributes get a 420 error response.
3. ~~**Hardening** — per-IP rate limiting, graceful shutdown, structured
   logs, TCP listener.~~ Done.
4. ~~**NAT behavior discovery** — [RFC 5780](https://datatracker.ietf.org/doc/html/rfc5780):
   OTHER-ADDRESS, RESPONSE-ORIGIN, CHANGE-REQUEST, answering from alternate
   port/IP so clients can classify their NAT. Full mode needs two public
   IPs.~~ Done (mapping + filtering tests; PADDING/RESPONSE-PORT skipped).
5. **Auth** — RFC 8489 long-term credentials: 401 challenge with REALM/NONCE,
   MESSAGE-INTEGRITY(-SHA256) validation. Opt-in; anonymous binding stays the
   default (public STUN servers run unauthenticated — the response contains
   nothing an on-path attacker doesn't already know).

Skipped deliberately: TURN relaying, TLS/DTLS transport.

## References

- [RFC 8489](https://datatracker.ietf.org/doc/html/rfc8489) — STUN (current spec, obsoletes 5389)
- [RFC 5769](https://datatracker.ietf.org/doc/html/rfc5769) — test vectors for STUN messages
- [RFC 5780](https://datatracker.ietf.org/doc/html/rfc5780) — NAT behavior discovery using STUN

## Progress log

- **2026-07-07** — Project start: repo, Go module, this overview.
- **2026-07-07** — Split docs: user-facing README.md, this file now dev-only.
- **2026-07-07** — Phase 1 done: `stunmsg` codec. Parse/Marshal with strict
  framing checks, XOR-MAPPED-ADDRESS (v4+v6), ERROR-CODE, SOFTWARE,
  FINGERPRINT add/verify. Tested against [RFC 5769 §2.1–2.3](https://datatracker.ietf.org/doc/html/rfc5769#section-2.1) vectors, including
  their non-zero padding bytes. Notable design choices: attributes are kept as
  raw `[]Attr` (typed accessors only where the server needs them), and
  `AddFingerprint` computes the CRC via a `marshal(extraLen)` hook because the
  spec requires the header length to already count the fingerprint attribute.
  MESSAGE-INTEGRITY is parsed as an opaque attribute — validation comes only
  if auth ever lands (roadmap #4).
- **2026-07-07** — Phase 2 done: UDP server (`server/`) and `cmd/stund`
  binary. Single-goroutine read loop: parse → handle → reply from the same
  socket, so the response source port matches what the client expects.
  Drops silently: non-STUN bytes, malformed framing, bad FINGERPRINT,
  non-Binding types. Replies 420 + UNKNOWN-ATTRIBUTES for unrecognized
  comprehension-required attributes, but whitelists USERNAME and
  MESSAGE-INTEGRITY(-SHA256) as ignorable since Binding needs no auth.
  Shutdown model: closing the socket ends `Serve` cleanly (SIGINT/SIGTERM
  handler in main). Verified with package tests over real loopback sockets
  plus an independent Python client against the built binary.
- **2026-07-07** — Per-package READMEs: `stunmsg/` (API + wire-format
  gotchas), `server/` (behavior table + lifecycle), `cmd/stund/` (flags).
  This file stays the cross-cutting design doc and progress log.
- **2026-07-07** — Package READMEs rewritten for readers new to STUN: each
  now opens with plain-language context (what a STUN message is, what the
  Binding service does, why XOR/FINGERPRINT exist) before the reference
  material. RFC mentions are links.
- **2026-07-07** — Per-IP rate limiting (phase 3, part 1). Token bucket per
  source IP (`server/ratelimit.go`), default 10 rps + 20 burst, `-rps` flag,
  disabled with 0. Over-budget packets are dropped without a reply — a
  response would spend exactly the bandwidth the limit protects. Buckets
  idle past full refill are pruned at most once a minute, under the same
  lock. Deliberately one mutex + map; shard if it ever shows in a profile.
- **2026-07-07** — TCP listener (phase 3, part 2; phase 3 complete).
  `ServeTCP` accepts, one goroutine per connection, multiple length-framed
  requests per connection. Stream semantics change error handling: UDP
  drops bad input and keeps listening, TCP must hang up because a framing
  error loses message boundaries. 40s idle timeout, 4 KiB frame cap.
  `stund` now listens on both transports by default (`-tcp=false` to
  disable). Verified with loopback tests and a Python TCP client against
  the binary.
- **2026-07-07** — Cleanup pass before phases 4–5. Moved wire-format
  knowledge out of `server` into `stunmsg`: attribute constants for
  USERNAME / MESSAGE-INTEGRITY(-SHA256), `AddUnknownAttributes`, and
  `Required()` for the comprehension-required check. Roadmap updated: NAT
  discovery and auth are now planned work, not "maybe later".
- **2026-07-07** — RFC 5780 NAT behavior discovery (phase 4). `Discovery`
  runs four UDP sockets ([2 IPs][2 ports]) sharing one rate limiter;
  CHANGE-REQUEST flips the socket indices per §6.1 Table 1, RESPONSE-ORIGIN
  reports the actual sender, OTHER-ADDRESS the diagonal alternate. Success
  responses carry MAPPED-ADDRESS alongside XOR-MAPPED-ADDRESS as the RFC
  requires. The plain handler was split into validate/respond/seal so both
  usages share validation and the 420 path. Error responses leave from the
  receiving socket. Without `-alt-ip`, CHANGE-REQUEST stays outside the
  ignorable set and draws a 420 — exactly what §6 mandates for single-IP
  servers. PADDING and RESPONSE-PORT (fragment/lifetime tests) skipped;
  as comprehension-required attrs they 420 too, which degrades those
  client tests gracefully.
