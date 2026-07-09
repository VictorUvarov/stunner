# Chapter 5: Authentication

Every exchange up to now has been anonymous. Anyone who can reach the server
gets an answer, and that's the right default for a public STUN server: the
answer is just the client's own public address, which any on-path observer can
already see. Authenticating it would protect nothing.

But sometimes you want to lock the door — a private deployment where only your
own app's users should get answers. STUN's answer is **long-term credentials**
([RFC 8489 §9.2](https://datatracker.ietf.org/doc/html/rfc8489#section-9.2)): a
username and password, shared in advance, proven on every request without ever
sending the password over the wire. It's the most intricate part of the
protocol, and it's where the wire format from chapter 2 finally gets a full
workout. In this codebase it's opt-in, off by default, and lives in
[`internal/server/auth.go`](../internal/server/auth.go).

## The problem authentication has to solve

You can't just send a password in a STUN attribute. Anyone watching the network
would read it. And you can't rely on the transport being encrypted, because
plain UDP STUN isn't. So the protocol borrows the classic trick from HTTP
digest auth: **prove you know the password without transmitting it.**

The tool for that is an HMAC — a keyed checksum. The client computes a checksum
over its whole message, keyed by (a hash of) the password, and attaches it as a
**MESSAGE-INTEGRITY** attribute. The server, which also knows the password,
recomputes the same checksum. If they match, the client must know the password
— and as a bonus, the checksum also proves the message wasn't tampered with in
transit. The password itself never appears on the wire.

## The challenge/response dance

There's a chicken-and-egg problem: the client's first request can't include a
valid HMAC, because it doesn't yet know some things the server will demand
(chiefly a nonce). So authentication is a two-round-trip conversation:

1. **Client sends a plain Binding Request** (no auth).
2. **Server replies 401 (Unauthorized)**, and the 401 carries what the client
   needs to try again: a **REALM** (which password set to use — think of it as
   naming the login domain), a **NONCE** (a one-time-ish value that stops
   replay), and a **PASSWORD-ALGORITHMS** list (which hash functions the server
   accepts, SHA-256 preferred, MD5 offered for legacy clients).
3. **Client retries**, now including USERNAME, REALM, NONCE, its choice of
   algorithm, and a MESSAGE-INTEGRITY HMAC keyed by
   `hash(username:realm:password)`.
4. **Server verifies the HMAC.** If it matches, the client gets its Binding
   Success Response — signed with the server's own MESSAGE-INTEGRITY, so the
   client knows the *answer* is genuine too.

Every error along the way maps to a specific code, and the order the server
checks things in is dictated by the spec:

| Situation | Response |
|---|---|
| No integrity attribute at all (the first request) | 401, with REALM / NONCE / algorithms |
| Auth attributes present but malformed/incomplete | 400 (Bad Request) |
| Everything valid but the nonce has expired | 438 (Stale Nonce), with a fresh one |
| The HMAC doesn't match (wrong password) | 401 |

There's a subtlety in that ordering worth calling out, because it's easy to get
backwards: a stale nonce (438) is only reported *after* the credentials
otherwise check out. You don't tell an attacker "your nonce is stale" — and
thereby confirm the rest was right — until they've proven they know the
password. Get that order wrong and you leak information.

## The append attack, and why trailing attributes are dropped

Here's an attack the naive implementation is wide open to. The MESSAGE-INTEGRITY
HMAC only covers the bytes *before* it. Anything after it in the message is
unsigned. So an attacker who captures a validly-signed request can *append*
extra attributes to it, and the signature still verifies — because the HMAC
never saw the appendix.

Why does that matter for a "harmless" address-reflection protocol? Because some
attributes *change what the server does*. In the NAT-discovery usage (chapter
6), an appended RESPONSE-PORT or CHANGE-REQUEST could redirect the server's
reply to a different address — all while riding someone else's valid signature.
That turns a captured legitimate request into a reflection weapon.

[RFC 8489 §9](https://datatracker.ietf.org/doc/html/rfc8489#section-9) closes
this by ruling that a receiver must **ignore everything after
MESSAGE-INTEGRITY** (except a trailing FINGERPRINT, which is allowed to come
last). This code does it centrally with `stunmsg.TrimAfterIntegrity`, applied
in the shared `validate` path so every transport and both usages inherit it.
Nothing unauthenticated after the signature can influence anything. This was
one of two gaps found during the conformance sweep — before the fix, appended
junk drew a 420 instead of being quietly dropped.

## Stopping the downgrade: the nonce cookie

An attacker who can't break the password might try a different angle:
**downgrade** the security. If the server offers both SHA-256 and MD5, a
man-in-the-middle could strip SHA-256 from the offer, forcing both sides down
to the weaker MD5. This is a "bid-down" attack, and it's insidious because both
parties think they negotiated honestly.

The defense is to make the negotiation itself tamper-evident. Every nonce this
server issues begins with a fixed marker — the "nonce cookie," the literal
string `obMatJos2` — followed by encoded **security-feature bits** that record
which features (password-algorithm negotiation, username anonymity) the server
advertised. Those bits are baked into the nonce, and the nonce is echoed back
by the client. If an attacker tampers with the advertised algorithms, the bits
no longer match the nonce, and the exchange dies with a 438. The negotiation
can't be quietly rewritten.

Implementing this surfaced two *verified errata* in the RFC itself, both
encoded in the tests: erratum 6290 (the feature bit numbering runs right-to-
left, opposite the RFC's prose) and erratum 6268 (a printed example vector in
Appendix B.1 is simply wrong). The codec rebuilds the *corrected* B.1 vector
byte-for-byte, so the tests double as a record of which errata this
implementation trusts.

## Hiding the username: USERHASH

The username normally travels in the clear. For deployments where even the
username is sensitive, the protocol offers **USERHASH**: instead of the
username, the client sends `SHA-256(username:realm)`. The server can't reverse
a hash, so it precomputes the hash of every configured user at startup and
looks the incoming hash up in that table. The username never appears on the
wire, and the lookup is still a fast map hit.

## Comparing strings that came from humans: OpaqueString

One quietly hard problem: usernames and passwords are Unicode, and Unicode has
many ways to write what looks like the same string. If one side's password is
stored one way and typed another — different normalization, a stray non-
printing character — the HMAC won't match even though the human "got it right."

STUN defers to [RFC 8265](https://datatracker.ietf.org/doc/html/rfc8265)'s
**OpaqueString** profile, which defines a canonical form for exactly this. The
realm, usernames, and passwords are all run through it at setup, using
`golang.org/x/text/secure/precis` — the *other* of the two non-stdlib
dependencies (DTLS was the first). This is deliberately kept out of the
`stunmsg` codec, which stays stdlib-only and documents that its key-derivation
inputs must arrive already-prepared. Only the derived keys are kept in memory;
the raw passwords are discarded after setup.

## Nonces with no memory

You'd expect the server to store the nonces it issues, so it can recognize them
later. This one doesn't store any — and that's a feature.

A stored-nonce table is something an attacker can flood: request a million
nonces and watch the server's memory climb. Instead, this server makes its
nonces **self-verifying**. A nonce is the expiry timestamp plus
`HMAC-SHA256(secret, expiry)`, where `secret` is a random value generated once
per process. To check a nonce later, the server recomputes the HMAC from the
embedded expiry and its secret — if it matches and the time hasn't passed, the
nonce is genuine. Nothing is stored per client. The nonce table can't be
flooded because there is no nonce table, and a server restart costs clients
exactly one extra 438 round trip (the old secret is gone, so old nonces stop
verifying). The lifetime is five minutes.

This is the same stateless philosophy from chapter 1, applied to security:
push the state into the token itself and there's nothing to store, drain, or
overflow.

## Where this is going

That's the door and its lock. The response, by the way, is signed with the same
algorithm variant the client used — SHA-256 for a modern client that
negotiated, legacy MESSAGE-INTEGRITY otherwise — and it even accepts truncated
SHA-256 HMACs down to 16 bytes, as §14.6 allows, while always sending the full
length itself.

So far the server has answered "what is my address?" The next chapter is about
a richer question a client can ask: not just *what* its address is, but *how*
its NAT behaves — information it needs to predict whether a direct
peer-to-peer connection will actually work.

---

**Read the code**

- [`internal/server/auth.go`](../internal/server/auth.go) — `NewAuth`, the
  challenge/response flow, the error-code mapping, and stateless nonces.
- [`internal/stunmsg/integrity.go`](../internal/stunmsg/integrity.go) —
  `LongTermKey`, the HMAC add/verify helpers, USERHASH, the PASSWORD-ALGORITHMS
  codec, and `TrimAfterIntegrity`.
- [`internal/server/README.md`](../internal/server/README.md) — the
  "Authentication (opt-in)" section restates this as reference.
- [RFC 8489 §9.2](https://datatracker.ietf.org/doc/html/rfc8489#section-9.2) —
  the authoritative flow.

---

[← Chapter 4: Four transports](04-transports.md) · [Contents](README.md) · **Next:** [Chapter 6: NAT behavior discovery →](06-nat-behavior-discovery.md)
