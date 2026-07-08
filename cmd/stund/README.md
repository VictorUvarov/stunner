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
| `-addr` | `:3478` | listen address, used for both UDP and TCP |
| `-tcp` | on | also serve STUN over TCP (`-tcp=false` for UDP only) |
| `-rps` | `10` | per-IP request rate limit, with 2× burst headroom (`0` disables) |
| `-alt-ip` | off | second IP; enables RFC 5780 NAT discovery (four UDP sockets) |
| `-alt-port` | primary + 1 | alternate port for NAT discovery |
| `-v` | off | debug logging (logs each handled request) |

NAT discovery mode needs two public IPs on the machine and an explicit IP
in `-addr`, e.g.:

```sh
./stund -addr 198.51.100.10:3478 -alt-ip 198.51.100.11
```

Logs go to stderr. Stop it with Ctrl-C (or SIGTERM): that closes the
socket, which ends the serve loop cleanly and exits 0.

Port 3478 is the standard STUN port and doesn't require root — only ports
below 1024 do.
