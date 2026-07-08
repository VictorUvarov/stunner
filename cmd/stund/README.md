# stund

The server binary, the one you actually run. It wires command-line flags to a
UDP socket and hands it to the [`server`](../../internal/server/) package,
which answers the "what's my public address?" queries. See the
[root README](../../README.md) for why that's useful.

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
| `-realm` | off | enables long-term credential auth (RFC 8489 §9.2); needs `-user` |
| `-user` | — | `username:password` credential, repeatable; needs `-realm` |
| `-tls-cert` / `-tls-key` | off | certificate + key files; enable `stuns` over TLS *and* DTLS |
| `-tls-addr` | `:5349` | TLS/DTLS listen address (standard `stuns` port) |
| `-redirect` | off | `ip:port` for 300 Try Alternate redirects; repeatable, one per address family |
| `-redirect-domain` | — | ALTERNATE-DOMAIN sent with redirects (TLS/DTLS cert validation) |
| `-metrics-addr` | off | HTTP address serving Prometheus counters on `/metrics` |
| `-v` | off | debug logging (logs each handled request) |

With auth enabled, only clients that know a listed username/password get
answers. Anyone else gets a 401 challenge:

```sh
./stund -realm example.org -user alice:s3cret -user bob:hunter2
```

Note the passwords are visible in the process list (`ps`); for anything
beyond a private deployment, start it from a wrapper that keeps the
credentials out of shell history.

NAT discovery mode needs two public IPs on the machine and an explicit IP
in `-addr`, e.g.:

```sh
./stund -addr 198.51.100.10:3478 -alt-ip 198.51.100.11
```

Handing the binary a certificate turns on the secure transports: TLS on
`-tls-addr`'s TCP port and DTLS on its UDP port, both named `stuns`:

```sh
./stund -tls-cert cert.pem -tls-key key.pem
```

The files are re-read automatically when they change on disk (checked at most
once a second, at handshake time), so certificate renewal needs no restart or
signal, whether it's certbot, `acme.sh`, or anything else that writes the new
pair. A rotation that leaves broken files behind is logged, and the previous
certificate keeps serving.

To drain a server (say, for maintenance), point clients elsewhere and they
get a 300 Try Alternate instead of an answer:

```sh
./stund -redirect 198.51.100.20:3478 -redirect-domain stun.example.org
```

Logs go to stderr. Stop it with Ctrl-C (or SIGTERM): that closes the
socket, which ends the serve loop cleanly and exits 0.

Port 3478 is the standard STUN port and doesn't require root. Only ports
below 1024 do.
