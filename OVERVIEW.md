# Design overview

Implementation notes for stund (see [README.md](README.md) for what and why).
It's built from scratch against [RFC 8489](https://datatracker.ietf.org/doc/html/rfc8489), stdlib only apart from two
dependencies where hand-rolling would be a project of its own:
`golang.org/x/text/secure/precis` for the OpaqueString profile
([RFC 8265](https://datatracker.ietf.org/doc/html/rfc8265)) the auth spec requires, and `github.com/pion/dtls` for the
DTLS transport, since Go ships TLS but no DTLS.

This is the living design doc. Every commit updates the **Progress log**
below, and the sections above it whenever the design changes.

## Protocol core

The server handles one exchange. A client sends a **Binding Request**, and the
server replies with the source address the packet arrived from, encoded as
**XOR-MAPPED-ADDRESS**. It's stateless, with no relaying.

The wire format: every message is a 20-byte header (a 2-byte
type, a 2-byte length, the 4-byte magic cookie `0x2112A442`, and a 12-byte
transaction ID) followed by zero or more TLV attributes padded to 4-byte
boundaries. Addresses are XORed with the magic cookie so that dumb NATs can't
rewrite them in transit.

## Architecture

```
cmd/stund/            server main: flags, listener setup, cert reload, shutdown
cmd/stunc/            client main: query a server, print the mapped address
internal/stunmsg/     message parse/serialize: header, attributes (no I/O)
internal/server/      UDP and TCP loops: decode request → build response → send
internal/stunclient/  client transactions: retransmission, auth handshake
```

`stunmsg` is a pure library with no networking, so it's easy to test against
[RFC 5769](https://datatracker.ietf.org/doc/html/rfc5769)'s test vectors. The server layer stays thin: read datagram, parse,
respond.

## Roadmap

The goal is a **feature-complete STUN server**: everything in the spec, for
learning and for production use. Nothing gets skipped permanently. Deferred
items sit at the bottom of this list until they're done.

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

Out of scope: TURN relaying. RFC 8656 is a different protocol with a
different threat model, not part of STUN itself.

## References

- [RFC 8489](https://datatracker.ietf.org/doc/html/rfc8489) — STUN (current spec, obsoletes 5389)
- [RFC 5769](https://datatracker.ietf.org/doc/html/rfc5769) — test vectors for STUN messages
- [RFC 5780](https://datatracker.ietf.org/doc/html/rfc5780) — NAT behavior discovery using STUN

## Progress log

- **2026-07-07** — Project start: repo, Go module, this overview.
- **2026-07-07** — Split docs: user-facing README.md, this file now dev-only.
- **2026-07-07** — Phase 1 done: `stunmsg` codec. Parse/Marshal with strict
  framing checks, XOR-MAPPED-ADDRESS (v4+v6), ERROR-CODE, SOFTWARE, and
  FINGERPRINT add/verify. Tested against [RFC 5769 §2.1–2.3](https://datatracker.ietf.org/doc/html/rfc5769#section-2.1) vectors,
  including their non-zero padding bytes. Two design choices worth noting.
  Attributes are kept as raw `[]Attr`, with typed accessors only where the
  server needs them. And `AddFingerprint` computes the CRC via a
  `marshal(extraLen)` hook, because the spec requires the header length to
  already count the fingerprint attribute. MESSAGE-INTEGRITY is parsed as an
  opaque attribute for now; validation waits until auth lands (roadmap #4).
- **2026-07-07** — Phase 2 done: UDP server (`server/`) and `cmd/stund`
  binary. The read loop runs on a single goroutine: parse, handle, then reply
  from the same socket so the response source port matches what the client
  expects. It drops non-STUN bytes, malformed framing, bad FINGERPRINTs, and
  non-Binding types silently. Unrecognized comprehension-required attributes
  get a 420 with UNKNOWN-ATTRIBUTES, but USERNAME and MESSAGE-INTEGRITY(-SHA256)
  are whitelisted as ignorable since Binding needs no auth. Shutdown is simple:
  closing the socket ends `Serve` cleanly, driven by a SIGINT/SIGTERM handler
  in main. Verified with package tests over real loopback sockets and an
  independent Python client against the built binary.
- **2026-07-07** — Per-package READMEs: `stunmsg/` (API and wire-format
  gotchas), `server/` (behavior table and lifecycle), `cmd/stund/` (flags).
  This file stays the cross-cutting design doc and progress log.
- **2026-07-07** — Rewrote the package READMEs for readers new to STUN. Each
  one now opens with plain-language context (what a STUN message is, what the
  Binding service does, why XOR and FINGERPRINT exist) before the reference
  material. RFC mentions are links.
- **2026-07-07** — Per-IP rate limiting (phase 3, part 1). A token bucket per
  source IP (`server/ratelimit.go`), default 10 rps plus 20 burst, controlled
  by the `-rps` flag and disabled with 0. Over-budget packets are dropped
  without a reply, since a response would spend the very bandwidth the limit
  protects. Buckets idle past a full refill are pruned at most once a minute,
  under the same lock. It's one mutex and one map on purpose; shard it if it
  ever shows up in a profile.
- **2026-07-07** — TCP listener (phase 3, part 2, and phase 3 complete).
  `ServeTCP` accepts connections and runs one goroutine per connection, each
  handling multiple length-framed requests. Stream semantics change the error
  handling: UDP drops bad input and keeps listening, but TCP has to hang up,
  because a framing error loses the message boundaries. 40s idle timeout, 4 KiB
  frame cap. `stund` now listens on both transports by default (`-tcp=false`
  to disable). Verified with loopback tests and a Python TCP client against
  the binary.
- **2026-07-07** — Cleanup pass before phases 4–5. Moved wire-format knowledge
  out of `server` into `stunmsg`: attribute constants for USERNAME and
  MESSAGE-INTEGRITY(-SHA256), `AddUnknownAttributes`, and `Required()` for the
  comprehension-required check. Roadmap updated so that NAT discovery and auth
  are now planned work rather than "maybe later".
- **2026-07-07** — RFC 5780 NAT behavior discovery (phase 4). `Discovery`
  runs four UDP sockets (two IPs by two ports) that share one rate limiter.
  CHANGE-REQUEST flips the socket indices per §6.1 Table 1, RESPONSE-ORIGIN
  reports the actual sender, and OTHER-ADDRESS reports the diagonal alternate.
  Success responses carry MAPPED-ADDRESS alongside XOR-MAPPED-ADDRESS, as the
  RFC requires. The plain handler was split into validate/respond/seal so both
  usages share validation and the 420 path. Error responses leave from the
  socket that received the request. Without `-alt-ip`, CHANGE-REQUEST stays
  outside the ignorable set and draws a 420, which is what §6 mandates for
  single-IP servers. PADDING and RESPONSE-PORT (the fragment and lifetime
  tests) are skipped for now; as comprehension-required attributes they 420
  too, so those client tests degrade gracefully.
- **2026-07-08** — Long-term credential auth (phase 5, roadmap complete). In
  `stunmsg`: LongTermKey (MD5 per §9.2.2) and Add/VerifyMessageIntegrity in
  SHA-1 and SHA-256 variants that share one helper. Verification rewrites the
  header length as if the integrity attribute were last (§14.5), so a trailing
  FINGERPRINT still verifies. SHA-1 is checked against the RFC 5769 §2.4 vector
  byte-for-byte; SHA-256 has no published vector, so it's round-trip tested. In
  `server`: opt-in via the `Credentials` package var (the `-realm`/`-user`
  flags). The §9.2.4 flow maps to error codes: no integrity gives 401 with
  REALM/NONCE, missing auth attributes give 400, an expired nonce gives 438,
  and a bad key gives 401. Nonces are stateless (hex of expiry ‖
  HMAC-SHA256(secret, expiry), 5 min TTL, per-process secret), so there's no
  nonce table to store or flood. Responses are signed with the client's
  variant. Skipped for now: PASSWORD-ALGORITHMS negotiation, the §9.2
  security-feature nonce cookie (obMatJos2), truncated SHA-256 MACs, and
  SASLprep (usernames and passwords are compared as raw bytes). Verified by
  loopback tests and independent Python clients against the binary, now
  committed under `test/` (binding and auth handshake, runnable against any
  stund).
- **2026-07-08** — Auth completed to full RFC 8489 (phase 6). Restating the
  project goal: a feature-complete STUN server, everything in the spec, for
  learning and production. Here's what phase 5 skipped and phase 6 adds:
  - **PASSWORD-ALGORITHMS negotiation.** Challenges offer SHA-256, then MD5.
    Clients echo the list and pick one. This follows §9.2.4's exact check
    order, including two subtleties: a stale nonce is only reported *after*
    the credentials verify, and responses carry MESSAGE-INTEGRITY-SHA256 only
    for negotiating clients. Legacy clients get MESSAGE-INTEGRITY even if they
    signed with the SHA-256 variant.
  - **Bid-down protection.** Nonces now start with the "obMatJos2" cookie plus
    base64 feature bits. Two verified errata mattered here: 6290 (bit 0 is the
    *rightmost* bit, opposite of the RFC prose) and 6268 (the Appendix B.1
    vector is wrong as printed). Our codec verifies and byte-for-byte rebuilds
    the corrected B.1 vector.
  - **USERHASH.** Username anonymity via a SHA-256(user:realm) lookup table
    precomputed in NewAuth.
  - **OpaqueString (RFC 8265).** Realm, usernames, and passwords are prepared
    via `x/text/secure/precis`, the one non-stdlib dependency. Only derived
    keys are retained. `stunmsg` stays stdlib-only and documents that key
    inputs arrive pre-processed.
  - **Truncated MESSAGE-INTEGRITY-SHA256.** Verification accepts 16–32 bytes
    in multiples of 4 per §14.6; sending stays full-length.

  The Python auth client gained the negotiated USERHASH flow. Both clients
  pass against the binary, alongside 33 Go tests.
- **2026-07-08** — RFC 5780 completed (phase 7): PADDING and RESPONSE-PORT in
  the discovery usage. RESPONSE-PORT (§7.5) is the binding-lifetime test. It
  redirects the success response to the named port on the source IP, while the
  mapped-address attributes keep reflecting where the request actually came
  from. Errors always go back to the true source, so a bad request can't point
  a reply at a port its sender doesn't hold. PADDING (§6.1) echoes as junk
  bytes, sized to the outgoing interface's MTU rounded up to a 4-multiple and
  clamped under the 64 KiB datagram limit (Linux loopback reports MTU 65536).
  That forces response-direction fragmentation. Two matching adjustments: the
  discovery read buffer grew to 64 KiB so oversized *requests* (the other
  fragment direction) survive the read, and the sockets raise SO_SNDBUF because
  Darwin caps a UDP send at that size (9216 default). PADDING and RESPONSE-PORT
  in one request is the RFC's mandated 400. Running the suite under `-race`
  exposed two pre-existing test bugs, both a package var written while a
  previous server goroutine was still running: serve-loop goroutines are now
  joined in test cleanup, and the auth handshake loops became subtests so each
  iteration's server is torn down before the next writes `Credentials`.
- **2026-07-08** — TLS + DTLS transports and ALTERNATE-SERVER (phase 8). TLS
  (§6.2.3) cost nothing new in `server`, because STUN over TLS is just STUN
  over TCP inside the stream: handing `ServeTCP` a `tls.Listen` listener is the
  whole feature. `stund` grew `-tls-addr`, `-tls-cert`, and `-tls-key` (TLS 1.2
  minimum; Go's stack lacks the RFC's mandated DHE suite but has all the ECDHE
  ones). DTLS is `ServeDTLS` over [pion/dtls](https://github.com/pion/dtls),
  the second non-stdlib dependency, taken for the same reason as x/text. Its
  semantics are a hybrid: TCP's lifecycle (per-association goroutine, 40s idle
  hangup, shared accept loop) with UDP's message handling (records frame one
  message, and bad input drops without killing the association).
  ALTERNATE-SERVER (§10) is opt-in through the `Alternate` package var and the
  `-redirect` flag: a 300 Try Alternate with per-family targets (a family with
  no target is served normally, as §10's same-family rule demands), optional
  ALTERNATE-DOMAIN (§14.16), and redirect-after-auth so the 300 is
  integrity-protected whenever auth is on. Discovery never redirects. Verified
  by loopback Go tests (TLS round trip, DTLS round trip plus garbage-record
  survival, redirect variants) and a new independent `test/tls_client.py`.
  DTLS end-to-end rides the pion loopback tests, since Python has no stdlib
  DTLS.
- **2026-07-08** — Conformance sweep (phase 9, roadmap complete). Walked
  RFC 8489 §5–§14 requirement by requirement against the code. Two gaps
  found, both fixed:
  1. **Attributes after MESSAGE-INTEGRITY(-SHA256) are now ignored.** This is
     §9's receiving rule, and it's easy to miss because it lives in the
     section intro rather than a numbered subsection. The HMAC covers only
     what precedes it, so an attacker can append attributes to a captured
     signed request without invalidating it. Before the fix, appended junk
     drew a 420 instead of being ignored. The real bite: an appended
     RESPONSE-PORT or CHANGE-REQUEST would have steered a *discovery* response
     while riding someone else's signature. The fix is
     `stunmsg.TrimAfterIntegrity`, which keeps only MESSAGE-INTEGRITY-SHA256
     and FINGERPRINT past the boundary, applied centrally in `validate` so
     every transport and both usages inherit it.
  2. **Streams no longer hang up on valid no-reply messages** (§6.3.2 plus
     §6.2.2's "let the client close it"). A Binding Indication (the TCP/TLS
     keepalive) or an unsupported-method request used to kill the connection,
     because `serveConn` read every nil response as "framing lost". `handle`
     now reports whether the message parsed as STUN at all: a parse failure
     still hangs up, since a stream can't resync, but a well-formed
     silently-discarded message leaves the connection open. DTLS and UDP
     behavior is unchanged.

  Verdicts on everything else, in RFC order. §5 framing checks (leading zero
  bits, magic cookie, length ≡ 0 mod 4 and matching the buffer) were already
  strict in `Parse`. §6.3's silent-discard set and §6.3.1's ordering (auth
  first, *then* the unknown-attribute 420, which the §6.3 text is explicit
  about) already matched. Retransmissions are handled by stateless recompute,
  which §6.3.1 blesses for idempotent methods and for Binding specifically.
  §6.3.1.1/.2 response forming (transaction ID echo, XOR-MAPPED-ADDRESS from
  the transport source, ERROR-CODE plus SOFTWARE, same transport and
  connection back) all held. For §7/§12, FINGERPRINT is verified when present
  and never required, as §12 mandates for a basic server. §8 DNS discovery is
  deployment guidance, and the default ports are already 3478/5349. §12's
  SHOULD-NOTs (no auth, no ALTERNATE-SERVER on a basic server) hold, since both
  are opt-in and default-off. One SHOULD declined: §12's RFC 3489 ("classic
  STUN") backwards compatibility. Magic-cookie-less clients are effectively
  extinct, and §11 support would weaken the demux checks that keep the
  silent-discard path cheap; revisit only if a real client class ever surfaces.
  New tests: a trim table test in `stunmsg`, appended-attr 420-suppression over
  loopback UDP, and a TCP test proving that indications and unknown methods
  don't cost the connection.
- **2026-07-08** — RFC 3489 "classic STUN" backwards compat (phase 10),
  reversing phase 9's declined verdict at the operator's call. This was §12's
  last unmet SHOULD. Detection is the absence of the magic cookie (RFC 5389
  §12.2). `Message` grew a `Cookie` field (zero marshals as the magic, so every
  existing construction site kept working), and `Parse` now accepts cookie-less
  messages. That carries a documented cost: the codec can't be used to split
  STUN from other protocols on one port, which 5389 forbids for compat servers
  anyway. Classic responses follow the 2003 wire format. They use plain
  MAPPED-ADDRESS (a classic parser rejects unknown mandatory attributes, so no
  XOR form) and echo the full 128-bit transaction ID. They also avoid anything
  that would break a parser with no concept of attribute padding: no SOFTWARE
  (odd length), no FINGERPRINT (§7 says it isn't backwards compatible),
  space-padded ERROR-CODE reasons, and even-count UNKNOWN-ATTRIBUTES lists.
  Both alignment rules live in the codec, keyed off Cookie. Auth-enabled
  servers give classic clients a bare 401, since REALM/NONCE are meaningless to
  a parser that must reject them. Discovery answers classic NAT-type detection
  (RFC 3489 §10.1) with the era-correct SOURCE-ADDRESS/CHANGED-ADDRESS names,
  so CHANGE-REQUEST probing works for classic clients too. RFC 8489 §11's one
  addition is honored: classic never rides DTLS. Such requests draw a 500 for
  any method, the rest is ignored, and the association survives. One thing
  picked up en route: §10's until-now-missed SHOULD that a redirect list the
  *other* family's ALTERNATE-SERVER after the mandatory same-family one.
  Verified by codec and loopback tests plus a classic exchange in the Python
  binding client. `just check` is green.
- **2026-07-08** — Fuzzing for the codec's hostile-input surface. Two native
  Go fuzz targets in `stunmsg`. `FuzzParse` feeds arbitrary bytes to every
  raw-buffer entry point (Parse, VerifyFingerprint, both integrity verifiers,
  the attribute accessors) and checks that accepted input survives marshal
  then reparse with its meaning intact, including the zero-cookie corner where
  a classic transaction ID is indistinguishable from an unset field.
  `FuzzBuild` drives the construction path with arbitrary in-contract inputs
  and asserts that built messages verify, the wrong key never does, and the
  XOR address transform inverts exactly. Both are seeded with the RFC 5769/8489
  vectors. ~50M execs clean at landing; `just fuzz [time]` runs both.
- **2026-07-08** — RFC 8489 §13 DTLS DoS countermeasure, verdict closed. A
  server offering DTLS MUST do the RFC 6347 §4.2.1 cookie exchange, so a
  spoofed ClientHello can't make it commit handshake state (or amplify) toward
  an address that never asked. We inherit this from pion/dtls, which
  cookie-verifies unconditionally server-side unless its explicitly-named
  `WithInsecureSkipVerifyHello` option is set, and we never set it. It's pinned
  by `TestDTLSCookieExchange`: a recording UDP proxy sits in a real handshake
  and asserts that the server's first flight is a HelloVerifyRequest carrying
  no ServerHello, so a pion upgrade that ever changed the default would fail
  the suite rather than silently weaken the deployment.
- **2026-07-08** — Operations pass, part 1: metrics and certificate reload.
  Per-transport counters live in `server/metrics.go` (received, replies,
  errors, rate-limited; atomics keyed udp·tcp·tls·dtls·discovery, with TCP and
  TLS split by a type assertion in the shared serve loop) and are exported in
  Prometheus text format via the new `-metrics-addr` flag. Silent discards are
  the remainder (received − replies − limited) rather than a counter of their
  own, on purpose. Certificate rotation now works without a restart:
  `-tls-cert`/`-tls-key` feed a `certLoader` (cmd/stund/reload.go) that both
  `tls.Config.GetCertificate` and pion's `WithGetCertificate` consult per
  handshake. It re-stats the files at most once a second, reloads on newer
  mtimes, and keeps the last good pair when a rotation writes garbage, so a bad
  renewal logs instead of killing the listener. Loader behavior is pinned by
  unit tests (rotation, throttle, broken-reload fallback, bad startup).
- **2026-07-08** — Operations pass, part 2: packaging and deployment docs. A
  multi-stage Dockerfile under `deploy/` (static build into `scratch`, non-root
  UID, no shell, since STUN needs no filesystem at runtime), a hardened systemd
  unit also under `deploy/` (DynamicUser, strict ProtectSystem, inet-only
  address families, and no capabilities since 3478/5349 are unprivileged), and
  a README deployment section covering both plus the RFC 8489 §8 DNS SRV
  records (`_stun._udp`, `_stun._tcp`, `_stuns._tcp`, and RFC 7350's
  `_stuns._udp` for DTLS).
- **2026-07-08** — Go client: `internal/stunclient` package and `cmd/stunc`
  binary. This is the client side of the Binding usage over every transport the
  server speaks. Datagram transports (UDP, or a pion DTLS conn) use the §6.2.1
  retransmission schedule (RTO 500ms doubling, Rc=7, Rm=16, all configurable;
  responses matched on transaction ID, stray and broken-fingerprint datagrams
  ignored). Stream transports (TCP, TLS) use length framing with the schedule's
  total as the overall deadline. Long-term credentials run the §9.2.5 client
  flow, mirror-imaged to our server's §9.2.4 checks: OpaqueString preparation,
  PASSWORD-ALGORITHMS echoed verbatim with SHA-256 preferred (engaged only when
  the nonce cookie's feature bit vouches for the list, which is the client-side
  bid-down protection), the response's integrity verified before the result is
  trusted, and one silent retry on a 438. A 300 redirect surfaces as a typed
  `Redirect` error; following it is the caller's call, because of §14.16
  certificate validation. Tested against the real server package over loopback
  (UDP/TCP binding, drop-first-request retransmission, full-schedule timeout,
  auth good/bad/absent, redirect). `just test-e2e` runs the built `stunc`
  against the built `stund` over UDP, TCP, TLS, DTLS, and the auth handshake:
  the Go counterpart to the Python integration clients, now part of
  `just check`.
