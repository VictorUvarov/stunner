# stund

The server binary — what you actually run. It wires command-line flags to a
UDP socket and hands it to the [`server`](../../server/) package, which does
the real work (answering "what's my public address?" queries; see the
[root README](../../README.md) for why that's useful).

```sh
go build ./cmd/stund
./stund                  # listen on :3478 (standard STUN port)
./stund -addr :3479 -v   # custom port, debug logging
```

| Flag | Default | Meaning |
|---|---|---|
| `-addr` | `:3478` | UDP listen address |
| `-rps` | `10` | per-IP request rate limit, with 2× burst headroom (`0` disables) |
| `-v` | off | debug logging (logs each handled request) |

Logs go to stderr. Stop it with Ctrl-C (or SIGTERM): that closes the
socket, which ends the serve loop cleanly and exits 0.

Port 3478 is the standard STUN port and doesn't require root — only ports
below 1024 do.
