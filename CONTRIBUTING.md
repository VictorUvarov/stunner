# Contributing

Everything routes through [`just`](https://github.com/casey/just) — run `just`
with no arguments to list every recipe. If you'd rather not install it, each
recipe is a thin wrapper you can read off the [`justfile`](justfile) and run by
hand.

Design notes, wire-format details, and the roadmap live in
[OVERVIEW.md](OVERVIEW.md).

## Building

```sh
just build                 # compiles stund into ./bin
```

Or the plain Go commands the recipes wrap, if you'd rather not install `just`:

```sh
go build ./cmd/stund       # the server
go build ./cmd/stunc       # the client
```

Run the server straight out of the source tree. With no flags it listens on
`:3478`, the standard STUN port. Use `-addr` to pick a different port and `-v`
to turn on debug logging:

```sh
./stund
./stund -addr :3479 -v
```

`stunc` reports the address the server saw you as, which is a quick way to
probe a deployment:

```sh
./stunc your-host
```

The full flag reference lives in [cmd/stund/README.md](cmd/stund/README.md).

## Running the server

| Recipe | What it does |
|---|---|
| `just prod` | Standard `:3478`, no debug logging |
| `just dev` | `127.0.0.1:3478` with debug logging (`-v`) |
| `just auth` | Long-term credential auth — `alice:s3cret` @ `example.org` |
| `just tls` | TLS + DTLS on `:5349` (self-signed cert generated on first run) |

All four accept extra `stund` flags after `--`, e.g.:

```sh
just dev -- -rps 0        # dev server with rate limiting off
just prod -- -tcp=false   # UDP only
```

The dev/auth/tls recipes bind `127.0.0.1` so they don't trip the macOS firewall
prompt; `just prod` keeps the public `:3478`. See
[cmd/stund/README.md](cmd/stund/README.md) for the full flag reference.

## Testing

**Go:**

```sh
just test        # go test ./...
just test-race   # with the race detector
just cover       # per-package coverage
```

**Python integration clients** — each builds the binary, spins up a fresh
`stund`, runs the client, then tears the server down:

```sh
just test-py           # all three below
just test-py-binding   # Binding over UDP + TCP (RFC 8489) + a classic RFC 3489 exchange
just test-py-auth      # long-term credential handshake (RFC 5389 legacy + RFC 8489)
just test-py-tls       # Binding inside a TLS stream (RFC 8489 §6.2.3)
```

`just check` runs the lot: lint, Go tests, and the Python clients.

## Before you commit

```sh
just fmt    # gofmt -w .
just lint   # go vet + gofmt check
```

## Other recipes

| Recipe | What it does |
|---|---|
| `just cert` | Generate a self-signed cert/key in `./dev` for local TLS/DTLS |
| `just clean` | Remove `./bin` and generated dev certs |

Both `bin/` and `dev/` are gitignored — build artifacts and throwaway certs
never get committed.
