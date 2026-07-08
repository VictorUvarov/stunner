# stund

A small, fast STUN server written in Go. No dependencies, one binary.

> **Status: early development.** The core works — Binding over UDP — but
> hardening (rate limiting, TCP) is still in progress. See the
> [progress log](OVERVIEW.md#progress-log).

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

## What it will and won't do

- ✅ STUN Binding over UDP (the thing WebRTC needs), per RFC 8489
- ✅ TCP support and rate limiting, later
- ❌ TURN (media relaying) — different, much heavier protocol; use
  [coturn](https://github.com/coturn/coturn) if you need relaying

## For developers

Design, wire-format notes, roadmap, and a per-commit progress log live in
[OVERVIEW.md](OVERVIEW.md).

## License

TBD
