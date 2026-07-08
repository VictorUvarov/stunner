# stunner

![Stunner Image](./static/stunner.png)

A small, fast STUN server written in Go. One binary.

> **Status: feature-complete.** Every MUST and SHOULD in RFC 8489 — Binding
> over UDP, TCP, TLS, and DTLS, long-term credential auth, NAT behavior
> discovery (RFC 5780), even RFC 3489 "classic STUN" backwards compatibility.
> See the [progress log](OVERVIEW.md#progress-log) for the full story.

## What is this for?

If your app does video calls, voice chat, multiplayer games, or any other
peer-to-peer networking, devices behind home routers don't know their own
public address. A STUN server tells them: a device asks *"what's my IP and
port from the outside?"* and the server answers. That one answer is usually
all it takes for two devices to connect directly to each other.

Reasons to run your own instead of using a public one:

- **Privacy** — public STUN servers see the IP of every user of your app.
- **Reliability** — no dependence on someone else's free service staying up.
- **It's cheap** — STUN is stateless and tiny; the smallest VPS you can rent
  will handle enormous traffic.

## Quick start

```sh
git clone <this repo> && cd stun
go build ./cmd/stund
./stund              # listens on :3478, the standard STUN port
./stund -addr :3479 -v   # custom port, debug logging
```

Then point your WebRTC config (or any STUN client) at `stun:your-host:3478`.
Stop it with Ctrl-C.

A client ships in the same repo, handy for checking a deployment:

```sh
go build ./cmd/stunc
./stunc your-host        # prints the address the server saw you as
```

## What it will and won't do

- ✅ STUN Binding over UDP and TCP (the thing WebRTC needs), per [RFC 8489](https://datatracker.ietf.org/doc/html/rfc8489)
- ✅ Secure transports: `stuns` over TLS and DTLS (`-tls-cert`/`-tls-key`),
  with certificate rotation picked up without a restart
- ✅ Long-term credential auth (`-realm`/`-user`), including USERHASH and
  password-algorithm negotiation
- ✅ Per-IP rate limiting, on by default
- ✅ NAT behavior discovery ([RFC 5780](https://datatracker.ietf.org/doc/html/rfc5780)) on servers with two IPs (`-alt-ip`)
- ✅ Prometheus counters (`-metrics-addr`)
- ❌ TURN (media relaying) — different, much heavier protocol; use
  [coturn](https://github.com/coturn/coturn) if you need relaying

## Deployment

**Docker** — the image is a static binary in an empty (`scratch`) image:

```sh
docker build -t stund -f deploy/Dockerfile .
docker run --rm -p 3478:3478/udp -p 3478:3478/tcp stund
```

**systemd** — a hardened unit lives in [`deploy/stund.service`](deploy/stund.service):

```sh
go build -o /usr/local/bin/stund ./cmd/stund
cp deploy/stund.service /etc/systemd/system/ && systemctl enable --now stund
```

**DNS** — [RFC 8489 §8](https://datatracker.ietf.org/doc/html/rfc8489#section-8)
clients discover servers through SRV records, which also let you move or
load-balance the service later without touching client config:

```dns
_stun._udp.example.org.  IN SRV 0 0 3478 stun.example.org.
_stun._tcp.example.org.  IN SRV 0 0 3478 stun.example.org.
_stuns._tcp.example.org. IN SRV 0 0 5349 stun.example.org.  ; TLS
_stuns._udp.example.org. IN SRV 0 0 5349 stun.example.org.  ; DTLS (RFC 7350)
```

The port numbers in the SRV records are authoritative for clients that look
them up; 3478 (`stun`) and 5349 (`stuns`) are just the defaults for clients
that don't.

**Monitoring** — `-metrics-addr 127.0.0.1:9478` serves per-transport
request/reply/error counters in Prometheus text format on `/metrics`. Bind
it to localhost or an internal interface; it has no auth of its own.

## For developers

Design, wire-format notes, roadmap, and a per-commit progress log live in
[OVERVIEW.md](OVERVIEW.md). To build, run, and test locally, see
[CONTRIBUTING.md](CONTRIBUTING.md).

## License

TBD
