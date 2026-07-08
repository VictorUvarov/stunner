# Deploying stunner

Ways to run `stund` in production. All of them assume you've built the binary —
see [CONTRIBUTING.md](../CONTRIBUTING.md) — or use the Docker image below, which
builds it for you.

## Docker

The image is a static binary in an empty (`scratch`) image:

```sh
docker build -t stund -f deploy/Dockerfile .
docker run --rm -p 3478:3478/udp -p 3478:3478/tcp stund
```

## systemd

A hardened unit lives in [`stund.service`](stund.service):

```sh
go build -o /usr/local/bin/stund ./cmd/stund
cp deploy/stund.service /etc/systemd/system/ && systemctl enable --now stund
```

## DNS

[RFC 8489 §8](https://datatracker.ietf.org/doc/html/rfc8489#section-8) clients
discover servers through SRV records, which also let you move or load-balance
the service later without touching client config:

```dns
_stun._udp.example.org.  IN SRV 0 0 3478 stun.example.org.
_stun._tcp.example.org.  IN SRV 0 0 3478 stun.example.org.
_stuns._tcp.example.org. IN SRV 0 0 5349 stun.example.org.  ; TLS
_stuns._udp.example.org. IN SRV 0 0 5349 stun.example.org.  ; DTLS (RFC 7350)
```

The port numbers in the SRV records are authoritative for clients that look
them up; 3478 (`stun`) and 5349 (`stuns`) are just the defaults for clients that
don't.

## Monitoring

`-metrics-addr 127.0.0.1:9478` serves per-transport request/reply/error counters
in Prometheus text format on `/metrics`. Bind it to localhost or an internal
interface; it has no auth of its own.
