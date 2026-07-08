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
cmd/stund/            server main: flags, listener setup, cert reload, shutdown
cmd/stunc/            client main: query a server, print the mapped address
internal/stunmsg/     message parse/serialize: header, attributes (no I/O)
internal/server/      UDP and TCP loops: decode request → build response → send
internal/stunclient/  client transactions: retransmission, auth handshake
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
9. ~~**Full §6 protocol conformance sweep** — walk RFC 8489 front to back
   and close every remaining MUST/SHOULD (e.g. DNS discovery notes,
   FINGERPRINT/demux corner cases), documenting each verdict here.~~ Done
   (two fixes — attributes after MESSAGE-INTEGRITY now ignored, streams
   stay open through valid no-reply messages — full verdict list in the
   progress log; the one deliberately declined SHOULD, RFC 3489 backwards
   compatibility, became phase 10).
10. ~~**RFC 3489 backwards compat** — serve "classic STUN" clients:
    cookie-less detection, 128-bit transaction ID echo, plain
    MAPPED-ADDRESS, classic wire alignment, 500 for classic-over-DTLS
    (§11), SOURCE-ADDRESS/CHANGED-ADDRESS in discovery.~~ Done.

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
- **2026-07-08** — Conformance sweep (phase 9, roadmap complete). Walked
  RFC 8489 §5–§14 requirement by requirement against the code. Two gaps
  found, both fixed:
  1. **Attributes after MESSAGE-INTEGRITY(-SHA256) are now ignored**
     (§9's receiving rule, easy to miss — it lives in the section intro,
     not a numbered subsection). The HMAC covers only what precedes it, so
     an attacker can append attributes to a captured signed request without
     invalidating it. Before the fix, appended junk drew a 420 instead of
     being ignored, and — the real bite — an appended RESPONSE-PORT or
     CHANGE-REQUEST would have steered a *discovery* response while riding
     someone else's signature. `stunmsg.TrimAfterIntegrity` (keeps only
     MESSAGE-INTEGRITY-SHA256 and FINGERPRINT past the boundary), applied
     centrally in `validate` so every transport and both usages inherit it.
  2. **Streams no longer hang up on valid no-reply messages** (§6.3.2 +
     §6.2.2's "let the client close it"). A Binding Indication — the
     TCP/TLS keepalive — or an unsupported-method request used to kill the
     connection, because `serveConn` read every nil response as "framing
     lost". `handle` now reports whether the message parsed as STUN at
     all: parse failure still hangs up (a stream can't resync), but
     well-formed silently-discarded messages leave the connection open.
     DTLS/UDP behavior unchanged.
  Verdicts on everything else, in RFC order: §5 framing checks (leading
  zero bits, magic cookie, length ≡ 0 mod 4 and matching the buffer) were
  already strict in `Parse`; §6.3's silent-discard set and §6.3.1's
  ordering (auth, *then* unknown-attribute 420 — the §6.3 text is explicit)
  already matched; retransmissions are handled by stateless recompute,
  which §6.3.1 blesses for idempotent methods and Binding specifically;
  §6.3.1.1/.2 response forming (transaction ID echo, XOR-MAPPED-ADDRESS
  from the transport source, ERROR-CODE + SOFTWARE, same transport/
  connection back) all held. §7/§12: FINGERPRINT is verified when present,
  never required — as §12 mandates for a basic server. §8 DNS discovery is
  deployment guidance; the default ports are already 3478/5349. §12's
  SHOULD-NOTs (no auth, no ALTERNATE-SERVER on a basic server) hold since
  both are opt-in and default-off. Declined: §12's SHOULD for RFC 3489
  ("classic STUN") backwards compatibility — magic-cookie-less clients are
  effectively extinct, and §11 support would weaken the demux checks that
  keep the silent-discard path cheap; revisit only if a real client class
  ever surfaces. New tests: trim table test in `stunmsg`, appended-attr
  420-suppression over loopback UDP, and a TCP test proving indications
  and unknown methods don't cost the connection.
- **2026-07-08** — RFC 3489 "classic STUN" backwards compat (phase 10),
  reversing phase 9's declined verdict at the operator's call — §12's last
  unmet SHOULD. Detection is the absence of the magic cookie (RFC 5389
  §12.2): `Message` grew a `Cookie` field (zero marshals as the magic, so
  every existing construction site kept working) and `Parse` now accepts
  cookie-less messages — with the documented demux cost: the codec can't
  be used to split STUN from other protocols on one port, which 5389
  forbids for compat servers anyway. Classic responses follow the 2003
  wire format: plain MAPPED-ADDRESS (a classic parser rejects unknown
  mandatory attributes, so no XOR form), the full 128-bit transaction ID
  echoed, and nothing that would break a parser with no concept of
  attribute padding — no SOFTWARE (odd length), no FINGERPRINT (§7: not
  backwards compatible), space-padded ERROR-CODE reasons and even-count
  UNKNOWN-ATTRIBUTES lists (both alignment rules live in the codec, keyed
  off Cookie). Auth-enabled servers give classic clients a bare 401 —
  REALM/NONCE are meaningless to a parser that must reject them. Discovery
  answers classic NAT-type detection (RFC 3489 §10.1) with the era-correct
  SOURCE-ADDRESS/CHANGED-ADDRESS names, so CHANGE-REQUEST probing works
  for classic clients too. RFC 8489 §11's one addition is honored: classic
  never rides DTLS — requests of any method draw a 500, the rest is
  ignored, and the association survives. Also picked up en route: §10's
  until-now-missed SHOULD that a redirect list the *other* family's
  ALTERNATE-SERVER after the mandatory same-family one. Verified by codec
  and loopback tests plus a classic exchange in the Python binding client;
  `just check` green.
- **2026-07-08** — Fuzzing for the codec's hostile-input surface. Two native
  Go fuzz targets in `stunmsg`: `FuzzParse` feeds arbitrary bytes to every
  raw-buffer entry point (Parse, VerifyFingerprint, both integrity
  verifiers, the attribute accessors) and checks that accepted input
  survives marshal → reparse with meaning intact — including the
  zero-cookie corner where a classic transaction ID is indistinguishable
  from an unset field; `FuzzBuild` drives the construction path with
  arbitrary in-contract inputs and asserts built messages verify, the
  wrong key never does, and the XOR address transform inverts exactly.
  Seeded with the RFC 5769/8489 vectors. ~50M execs clean at landing;
  `just fuzz [time]` runs both.
- **2026-07-08** — RFC 8489 §13 DTLS DoS countermeasure, verdict closed:
  a server offering DTLS MUST do the RFC 6347 §4.2.1 cookie exchange, so a
  spoofed ClientHello can't make it commit handshake state (or amplify)
  toward an address that never asked. We inherit this from pion/dtls, which
  cookie-verifies unconditionally server-side unless its explicitly-named
  `WithInsecureSkipVerifyHello` option is set (we never set it). Pinned by
  `TestDTLSCookieExchange`: a recording UDP proxy sits in a real handshake
  and asserts the server's first flight is HelloVerifyRequest — and carries
  no ServerHello — so a pion upgrade that ever changed the default would
  fail the suite, not just weaken the deployment.
- **2026-07-08** — Operations pass, part 1: metrics and certificate reload.
  Per-transport counters (`server/metrics.go`: received / replies / errors /
  rate-limited, atomics keyed udp·tcp·tls·dtls·discovery — TCP and TLS split
  by a type assertion in the shared serve loop) exported in Prometheus text
  format via the new `-metrics-addr` flag; silent discards are deliberately
  the remainder received − replies − limited rather than a counter of their
  own. Certificate rotation without restart: `-tls-cert`/`-tls-key` now feed
  a `certLoader` (cmd/stund/reload.go) that both `tls.Config.GetCertificate`
  and pion's `WithGetCertificate` consult per handshake; it re-stats the
  files at most once a second, reloads on newer mtimes, and keeps the last
  good pair when a rotation writes garbage — a bad renewal logs instead of
  killing the listener. Loader behavior pinned by unit tests (rotation,
  throttle, broken-reload fallback, bad startup).
- **2026-07-08** — Operations pass, part 2: packaging and deployment docs.
  Multi-stage Dockerfile under `deploy/` (static build into `scratch`,
  non-root UID, no shell — STUN needs no filesystem at runtime), hardened
  systemd unit also under `deploy/` (DynamicUser, strict ProtectSystem,
  inet-only address families;
  no capabilities since 3478/5349 are unprivileged), and a README deployment
  section covering both plus the RFC 8489 §8 DNS SRV records (`_stun._udp`,
  `_stun._tcp`, `_stuns._tcp`, and RFC 7350's `_stuns._udp` for DTLS).
- **2026-07-08** — Go client: `internal/stunclient` package and `cmd/stunc`
  binary. The client side of the Binding usage over every transport the
  server speaks: datagram semantics (UDP, or a pion DTLS conn) with the
  §6.2.1 retransmission schedule (RTO 500ms doubling, Rc=7, Rm=16, all
  configurable — responses matched on transaction ID, stray/broken-
  fingerprint datagrams ignored), stream semantics (TCP, TLS) with length
  framing under the schedule's total as deadline. Long-term credentials run
  the §9.2.5 client flow mirror-imaged to our server's §9.2.4 checks:
  OpaqueString preparation, PASSWORD-ALGORITHMS echoed verbatim with
  SHA-256 preferred — engaged only when the nonce cookie's feature bit
  vouches for the list (client-side bid-down protection) — response
  integrity verified before the result is trusted, one silent retry on a
  438. 300 redirects surface as a typed `Redirect` error; following is the
  caller's call because of §14.16 certificate validation. Tested against
  the real server package over loopback (UDP/TCP binding, drop-first-
  request retransmission, full-schedule timeout, auth good/bad/absent,
  redirect), and `just test-e2e` runs the built `stunc` against the built
  `stund` over UDP, TCP, TLS, DTLS, and the auth handshake — the Go
  counterpart to the Python integration clients, now part of `just check`.
