# Design overview

Implementation notes for stund (see [README.md](README.md) for what/why).
Built from scratch against [RFC 8489](https://datatracker.ietf.org/doc/html/rfc8489). Stdlib except two dependencies where
hand-rolling would be a project of its own: `golang.org/x/text/secure/precis`
for the OpaqueString profile ([RFC 8265](https://datatracker.ietf.org/doc/html/rfc8265)) the auth spec requires, and
`github.com/pion/dtls` for the DTLS transport (Go ships TLS but no DTLS).

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

Goal: a **feature-complete STUN server** — everything in the spec,
for learning and for production use. Nothing gets skipped permanently;
deferred items live at the bottom of this list until they're done.

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
5. ~~**Auth** — RFC 8489 long-term credentials: 401 challenge with REALM/NONCE,
   MESSAGE-INTEGRITY(-SHA256) validation. Opt-in; anonymous binding stays the
   default (public STUN servers run unauthenticated — the response contains
   nothing an on-path attacker doesn't already know).~~ Done.
6. ~~**Auth, complete** — PASSWORD-ALGORITHMS negotiation with bid-down
   protection (nonce cookie + security-feature bits), USERHASH username
   anonymity, truncated MESSAGE-INTEGRITY-SHA256 acceptance, OpaqueString
   string preparation.~~ Done.
7. ~~**RFC 5780, complete** — PADDING and RESPONSE-PORT so clients can run
   fragment and binding-lifetime tests.~~ Done.
8. ~~**TLS + DTLS transports** — RFC 8489 §6.2.3 (`stuns`, port 5349),
   including the ALTERNATE-SERVER / ALTERNATE-DOMAIN redirect machinery
   (§10, §14.15, §14.16).~~ Done.
9. **Full §6 protocol conformance sweep** — walk RFC 8489 front to back
   and close every remaining MUST/SHOULD (e.g. DNS discovery notes,
   FINGERPRINT/demux corner cases), documenting each verdict here.

Out of scope: TURN relaying (RFC 8656 is a different protocol and a
different threat model, not part of STUN itself).

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
- **2026-07-08** — Long-term credential auth (phase 5, roadmap complete).
  `stunmsg`: LongTermKey (MD5 per §9.2.2), Add/VerifyMessageIntegrity in
  SHA-1 and SHA-256 variants sharing one helper; verification rewrites the
  header length as if the integrity attribute were last (§14.5), so a
  trailing FINGERPRINT still verifies. SHA-1 checked against the RFC 5769
  §2.4 vector byte-for-byte; SHA-256 has no published vector, so round-trip
  tested. `server`: opt-in via the `Credentials` package var
  (`-realm`/`-user` flags); §9.2.4 flow — no integrity → 401 + REALM/NONCE,
  missing auth attrs → 400, expired nonce → 438, bad key → 401.
  Nonces are stateless (hex of expiry ‖ HMAC-SHA256(secret, expiry), 5 min
  TTL, per-process secret), so there's no nonce table to store or flood.
  Responses are signed with the client's variant. Deliberately skipped:
  PASSWORD-ALGORITHMS negotiation and the §9.2 security-feature nonce
  cookie (obMatJos2), truncated SHA-256 MACs, SASLprep (usernames/passwords
  are compared as raw bytes). Verified by loopback tests plus independent
  Python clients against the binary, now committed under `test/`
  (binding + auth handshake, runnable against any stund).
- **2026-07-08** — Auth completed to full RFC 8489 (phase 6); project goal
  restated: feature-complete STUN server, everything in the spec, for
  learning and production. What phase 5 skipped, now in:
  - **PASSWORD-ALGORITHMS negotiation** — challenges offer SHA-256 then
    MD5; clients echo the list and pick one (§9.2.4's exact check order,
    including the subtlety that a stale nonce is only reported *after*
    the credentials verify, and that responses carry MESSAGE-INTEGRITY-
    SHA256 only for negotiating clients — legacy ones get MESSAGE-
    INTEGRITY even if they signed with the SHA-256 variant).
  - **Bid-down protection** — nonces now start with the "obMatJos2"
    cookie + base64 feature bits. Two verified errata mattered: 6290
    (bit 0 is the *rightmost* bit, opposite of the RFC prose) and 6268
    (the Appendix B.1 vector is wrong as printed). Our codec verifies
    and byte-for-byte rebuilds the corrected B.1 vector.
  - **USERHASH** — username anonymity via a SHA-256(user:realm) lookup
    table precomputed in NewAuth.
  - **OpaqueString (RFC 8265)** — realm/usernames/passwords prepared via
    `x/text/secure/precis`, the one non-stdlib dep; only derived keys are
    retained. `stunmsg` stays stdlib-only: it documents that key inputs
    arrive pre-processed.
  - **Truncated MESSAGE-INTEGRITY-SHA256** — verification accepts 16–32
    bytes in multiples of 4 per §14.6 (sending stays full-length).
  Python auth client extended with the negotiated USERHASH flow; both
  clients pass against the binary alongside 33 Go tests.
- **2026-07-08** — RFC 5780 completed (phase 7): PADDING and RESPONSE-PORT
  in the discovery usage. RESPONSE-PORT (§7.5) redirects the success
  response to the named port on the source IP — the binding-lifetime test —
  while the mapped-address attributes keep reflecting where the request
  actually came from; errors always go back to the true source, so a bad
  request can't point a reply at a port its sender doesn't hold. PADDING
  (§6.1) echoes as junk bytes sized to the outgoing interface's MTU rounded
  up to a 4-multiple (clamped under the 64 KiB datagram limit — Linux
  loopback reports MTU 65536), forcing response-direction fragmentation;
  the discovery read buffer grew to 64 KiB so oversized *requests* (the
  other fragment direction) survive the read, and the sockets raise
  SO_SNDBUF because Darwin caps a UDP send at that size (9216 default).
  PADDING + RESPONSE-PORT in one request is the RFC's mandated 400.
  Running the suite under `-race` for this exposed two pre-existing test
  bugs, both "package var written while a previous server goroutine still
  runs": serve-loop goroutines are now joined in test cleanup, and the auth
  handshake loops became subtests so each iteration's server is torn down
  before the next writes `Credentials`.
- **2026-07-08** — TLS + DTLS transports and ALTERNATE-SERVER (phase 8).
  TLS (§6.2.3) cost nothing new in `server`: STUN over TLS is STUN over TCP
  inside the stream, so `ServeTCP` over a `tls.Listen` listener is the
  feature; `stund` grew `-tls-addr/-tls-cert/-tls-key` (TLS 1.2 minimum;
  Go's stack lacks the RFC's mandated DHE suite but has all the ECDHE
  ones). DTLS is `ServeDTLS` over [pion/dtls](https://github.com/pion/dtls)
  — the second non-stdlib dependency, taken for the same reason as x/text —
  with hybrid semantics: TCP's lifecycle (per-association goroutine, 40s
  idle hangup, shared accept loop), UDP's message handling (records frame
  one message; bad input drops without killing the association).
  ALTERNATE-SERVER (§10): opt-in `Alternate` package var / `-redirect`
  flag; 300 Try Alternate with per-family targets (family without a target
  is served normally, as §10's same-family rule demands), optional
  ALTERNATE-DOMAIN (§14.16), and redirect-after-auth so the 300 is
  integrity-protected whenever auth is on. Discovery never redirects.
  Verified by loopback Go tests (TLS round trip, DTLS round trip +
  garbage-record survival, redirect variants) and a new independent
  `test/tls_client.py`; DTLS end-to-end rides the pion loopback tests since
  Python has no stdlib DTLS.
