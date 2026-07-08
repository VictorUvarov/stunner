# stunner — task runner. Run `just` (or `just --list`) to see all recipes.

# Standard ports: 3478 is STUN, 5349 is stuns (TLS/DTLS).
addr      := "127.0.0.1:3478"
tls-addr  := "127.0.0.1:5349"
auth-addr := "127.0.0.1:3489"
bin       := "bin/stund"
certdir   := "dev"

# List available recipes.
default:
    @just --list

# ── build ─────────────────────────────────────────────────────────────────

# Compile the stund binary into ./bin.
build:
    go build -o {{bin}} ./cmd/stund

# Remove build artifacts and generated dev certs.
clean:
    rm -rf bin {{certdir}}

# ── run ───────────────────────────────────────────────────────────────────

# Run for production: standard STUN port, no debug logging. Pass extra flags after `--`.
prod *args: build
    {{bin}} -addr :3478 {{args}}

# Run for development: debug logging on. Pass extra flags after `--`.
dev *args: build
    {{bin}} -addr {{addr}} -v {{args}}

# Run with long-term credential auth (RFC 8489 §9.2): alice:s3cret @ example.org.
auth *args: build
    {{bin}} -addr {{auth-addr}} -realm example.org -user alice:s3cret -v {{args}}

# Run with TLS + DTLS on the stuns port (self-signed cert generated if missing).
tls *args: build cert
    {{bin}} -tls-addr {{tls-addr}} -tls-cert {{certdir}}/cert.pem -tls-key {{certdir}}/key.pem -v {{args}}

# Generate a self-signed cert/key for local TLS/DTLS testing (skips if present).
cert:
    #!/usr/bin/env bash
    set -euo pipefail
    mkdir -p {{certdir}}
    if [[ -f {{certdir}}/cert.pem && -f {{certdir}}/key.pem ]]; then
        echo "cert already exists in {{certdir}}/"
        exit 0
    fi
    openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
        -subj "/CN=localhost" \
        -keyout {{certdir}}/key.pem -out {{certdir}}/cert.pem
    echo "generated self-signed cert in {{certdir}}/"

# ── Go tests ──────────────────────────────────────────────────────────────

# Run the Go unit tests.
test:
    go test ./...

# Run the Go tests with the race detector.
test-race:
    go test -race ./...

# Run the Go tests with coverage reported per package.
cover:
    go test -cover ./...

# Vet, format-check, and tidy-check — the pre-commit sweep.
lint:
    #!/usr/bin/env bash
    set -euo pipefail
    go vet ./...
    unformatted=$(gofmt -l .)
    if [[ -n "$unformatted" ]]; then
        echo "not gofmt'd:"; echo "$unformatted"; exit 1
    fi
    echo "ok"

# Format all Go source in place.
fmt:
    gofmt -w .

# ── Python integration tests ──────────────────────────────────────────────
# Each spins up a fresh stund, runs the client, then tears the server down.

# Run every Python integration client (binding, auth, TLS).
test-py: test-py-binding test-py-auth test-py-tls

# Binding over UDP and TCP (RFC 8489), no auth.
test-py-binding: build
    #!/usr/bin/env bash
    set -euo pipefail
    {{bin}} -addr {{addr}} & pid=$!
    trap 'kill $pid 2>/dev/null || true' EXIT
    sleep 0.3
    python3 test/binding_client.py 127.0.0.1 3478

# Long-term credential handshake (RFC 5389 legacy + RFC 8489).
test-py-auth: build
    #!/usr/bin/env bash
    set -euo pipefail
    {{bin}} -addr {{auth-addr}} -realm example.org -user alice:s3cret & pid=$!
    trap 'kill $pid 2>/dev/null || true' EXIT
    sleep 0.3
    python3 test/auth_client.py 127.0.0.1 3489

# Binding inside a TLS stream (RFC 8489 §6.2.3).
test-py-tls: build cert
    #!/usr/bin/env bash
    set -euo pipefail
    {{bin}} -tls-addr {{tls-addr}} -tls-cert {{certdir}}/cert.pem -tls-key {{certdir}}/key.pem & pid=$!
    trap 'kill $pid 2>/dev/null || true' EXIT
    sleep 0.3
    python3 test/tls_client.py 127.0.0.1 5349

# ── everything ────────────────────────────────────────────────────────────

# Full check: lint, Go tests, and Python integration tests.
check: lint test test-py
