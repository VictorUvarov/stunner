# Build stage — static binary, no cgo, so the runtime stage can be empty.
FROM golang:1.26 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /stund ./cmd/stund

# Runtime stage — nothing but the binary. STUN is stateless: no config
# files, no writable paths, no shell. Runs as a non-root numeric UID so
# it also satisfies runAsNonRoot policies.
FROM scratch
COPY --from=build /stund /stund
USER 65534:65534
# 3478: STUN over UDP and TCP. 5349: stuns over TLS (TCP) and DTLS (UDP),
# active only when a certificate is mounted and passed via flags.
EXPOSE 3478/udp 3478/tcp 5349/tcp 5349/udp
ENTRYPOINT ["/stund"]
