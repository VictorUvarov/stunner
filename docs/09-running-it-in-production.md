# Chapter 9: Running it in production

A protocol that's correct on the wire is only half of a server you'd actually
run. The other half is everything around the exchange: surviving abuse,
telling you what it's doing, keeping its certificates fresh, and shipping in a
form you can deploy. This chapter is that half. None of it changes the
protocol — it's the operational shell around the core you've spent eight
chapters learning.

## Rate limiting: not answering too much

Chapter 3 explained why the server stays *silent* on bad input — reflection
protection. Rate limiting is the same instinct applied to *valid* input: even
legitimate-looking requests, in a flood, can turn the server into an amplifier
aimed at a spoofed victim. So each source IP gets a budget.

The mechanism is a **token bucket** per IP
([`internal/server/ratelimit.go`](../internal/server/ratelimit.go)): each IP
earns tokens at a steady rate (default 10 per second) up to a burst ceiling
(20), and each request spends one. Run out and further packets are **dropped
without a reply** — because a reply would spend the very bandwidth the limit is
there to protect. The `-rps` flag tunes the rate, and `0` disables it.

Two design choices are worth noting. First, over-budget packets get silence,
not a 486 or any error — consistent with the reflection logic, since an error
reply is still a reply an attacker could aim at a victim. Second, the
bookkeeping is intentionally one mutex and one map: buckets that idle long
enough to have fully refilled are pruned, at most once a minute, under the same
lock. It's simple on purpose; the comment in the code says to shard it only if
it ever shows up in a profile.

## Graceful shutdown: nothing to drain

Chapter 3 promised this would be easy, and statelessness is why. There's no
`Stop` method and no shutdown sequence, because there's no in-flight state to
flush. The `stund` binary installs a SIGINT/SIGTERM handler that simply
**closes the sockets**. Closing a socket makes its blocked read return, which
ends the serve loop, which returns cleanly. Ctrl-C exits 0. A server that
remembers nothing has nothing to lose on the way down.

## Metrics: knowing what it's doing

A production server you can't observe is a production server you don't trust.
Passing `-metrics-addr` (say `127.0.0.1:9478`) turns on an HTTP endpoint
serving per-transport counters in Prometheus text format on `/metrics`
([`internal/server/metrics.go`](../internal/server/metrics.go)). The counters
are received, replies, errors, and rate-limited, keyed by transport
(udp · tcp · tls · dtls · discovery), all plain atomics.

There's a nice bit of arithmetic in what's *not* counted. Silent discards —
all the stray internet noise from chapter 3 — have no counter of their own.
They're simply `received − replies − rate-limited`. Rather than pay for a
counter on the hottest, least interesting path, the number falls out of the
others by subtraction. Bind the endpoint to localhost or an internal interface;
it has no authentication of its own.

## Certificate rotation without a restart

The TLS and DTLS transports (chapter 4) need a certificate, and certificates
expire — every 90 days if you're using Let's Encrypt. A server that had to
restart to pick up a renewed cert would drop every connection on renewal day.
This one doesn't restart.

`-tls-cert` and `-tls-key` feed a `certLoader`
([`cmd/stund/reload.go`](../cmd/stund/reload.go)) that both Go's TLS stack and
pion's DTLS consult *per handshake*. It re-stats the files at most once a
second, reloads when it sees a newer modification time, and — the important
part — **keeps the last good pair if a rotation writes garbage.** A broken
renewal gets logged; it doesn't kill the listener. So whether you renew with
certbot, `acme.sh`, or anything else that writes a new pair to disk, the new
certificate is picked up on the next handshake with no restart, no signal, and
no downtime. The loader's behavior — rotation, throttle, broken-reload
fallback, bad startup — is pinned by unit tests.

## Shipping it

A binary nobody can install isn't deployed. There are three ways to run
`stund`, under [`deploy/`](../deploy/):

- **Docker.** A multi-stage build compiles a static binary into a `scratch`
  image — no shell, no filesystem, running as a non-root numeric UID. STUN
  needs nothing at runtime, so the image is nothing but the binary. Chapter 1's
  statelessness shows up even here: there's no config file to mount.
- **systemd.** A hardened unit (`DynamicUser`, strict `ProtectSystem`,
  inet-only address families, no capabilities — 3478 and 5349 are unprivileged,
  so it needs none).
- **Prebuilt releases.** Tagging `vX.Y.Z` runs GoReleaser (see
  [`.goreleaser.yaml`](../.goreleaser.yaml)), which cross-compiles `stund` and
  `stunc` for Linux, macOS, and Windows, publishes them on a GitHub Release
  with checksums, and pushes a multi-arch container image. `stund -version`
  reports the tag it was built from.

## Finding the server: DNS

One deployment note that's pure protocol.
[RFC 8489 §8](https://datatracker.ietf.org/doc/html/rfc8489#section-8) has
clients discover servers through SRV records, which also let you move or
load-balance the service later without touching client configuration:

```dns
_stun._udp.example.org.  IN SRV 0 0 3478 stun.example.org.
_stun._tcp.example.org.  IN SRV 0 0 3478 stun.example.org.
_stuns._tcp.example.org. IN SRV 0 0 5349 stun.example.org.  ; TLS
_stuns._udp.example.org. IN SRV 0 0 5349 stun.example.org.  ; DTLS (RFC 7350)
```

The ports 3478 (`stun`) and 5349 (`stuns`) are just the defaults for clients
that don't look up SRV records; the records themselves are authoritative for
clients that do.

## The end of the tour

You started with a device that didn't know its own address and a one-packet
fix. Nine chapters later you've seen the whole thing: the wire format that
carries the question and answer, the exchange at the core, four transports
around it, authentication, NAT-behavior discovery, redirects, a 20-year-old
compatibility mode, the client that asks, and the operational shell that keeps
it all running. The thread through every layer was the same idea from chapter
1 — *the server remembers nothing* — and you've now watched it pay off in
scaling, in shutdown, in flood resistance, and in nonces with no table behind
them.

To actually run what you've been reading about, the fastest path is:

```sh
go build ./cmd/stund && ./stund
```

and in another terminal:

```sh
go build ./cmd/stunc && ./stunc 127.0.0.1
```

That's a STUN server answering a STUN client on your own machine — the whole
tutorial, in two commands.

---

**Read the code**

- [`internal/server/ratelimit.go`](../internal/server/ratelimit.go) — the
  per-IP token bucket.
- [`internal/server/metrics.go`](../internal/server/metrics.go) — the
  per-transport counters and the Prometheus endpoint.
- [`cmd/stund/reload.go`](../cmd/stund/reload.go) — hot certificate reload.
- [`cmd/stund/main.go`](../cmd/stund/main.go) — flags, listener setup, and the
  shutdown handler that ties it together.
- [`deploy/`](../deploy/) and [`.goreleaser.yaml`](../.goreleaser.yaml) —
  Docker, systemd, DNS, and release packaging.

---

[← Chapter 8: The client side](08-the-client-side.md) · [Contents](README.md)
