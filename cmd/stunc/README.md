# stunc

The client binary: asks a STUN server what address it sees and prints it,
one line, suitable for scripts. The protocol work lives in
[`stunclient`](../../internal/stunclient/); this wires flags to a transport.

```sh
go build ./cmd/stunc
./stunc stun.example.org               # UDP, port 3478
./stunc -proto tcp stun.example.org
./stunc -proto tls stun.example.org    # stuns, port 5349
./stunc -proto dtls -insecure 127.0.0.1  # dev server, self-signed cert
./stunc -user alice:s3cret 127.0.0.1:3489
```

| Flag | Default | Meaning |
|---|---|---|
| `-proto` | `udp` | transport: `udp`, `tcp`, `tls`, or `dtls` |
| `-user` | — | `username:password` for servers that demand auth |
| `-software` | `stunc` | SOFTWARE attribute value (empty sends none) |
| `-insecure` | off | skip certificate verification (`tls`/`dtls` against self-signed certs) |

Without an explicit port, `udp`/`tcp` use 3478 and `tls`/`dtls` use 5349,
the registered `stun` and `stuns` ports.

Exit codes: 0 with the mapped address on stdout; 1 on any failure (timeout,
error response, bad credentials); 3 when the server answered
300 Try Alternate, with the alternate printed to stderr.

Because it speaks every transport `stund` serves, it doubles as the repo's
end-to-end self-test — `just test-e2e` runs it against a freshly built
server over UDP, TCP, TLS, DTLS, and the auth handshake.
