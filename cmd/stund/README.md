# stund

The server binary. Wires flags → socket → `server.Serve`, nothing else.

```sh
go build ./cmd/stund
./stund                  # listen on :3478 (standard STUN port)
./stund -addr :3479 -v   # custom port, debug logging
```

| Flag | Default | Meaning |
|---|---|---|
| `-addr` | `:3478` | UDP listen address |
| `-v` | off | debug logging (logs each handled request) |

Logs go to stderr via `log/slog`. SIGINT/SIGTERM close the socket, which
ends the serve loop cleanly and exits 0.

Ports below 1024 need root (or `setcap`/launchd on the target platform);
the standard port 3478 is above that, so no privileges required.
