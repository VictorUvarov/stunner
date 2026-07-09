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

# Compile the stund and stunc binaries into ./bin.
build:
    go build -o {{bin}} ./cmd/stund
    go build -o bin/stunc ./cmd/stunc

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

# Serve the browser WebRTC test page and run stund alongside it (Docker Compose).
# Opens http://localhost:8080/ in your browser; click Test. Ctrl-C tears it down.
web:
    #!/usr/bin/env bash
    set -euo pipefail
    compose="docker compose -f deploy/compose.yaml"
    trap '$compose down' EXIT
    $compose up --build -d
    # Wait for nginx to answer, then open the page.
    for _ in $(seq 1 30); do
        curl -sf -o /dev/null http://localhost:8080/ && break || sleep 0.5
    done
    (open http://localhost:8080/ || xdg-open http://localhost:8080/) 2>/dev/null || \
        echo "open http://localhost:8080/ in your browser"
    $compose logs -f

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

# Fuzz the stunmsg codec (30s per target by default: `just fuzz 5m` for longer).
fuzz time="30s":
    go test -fuzz FuzzParse -fuzztime {{time}} ./internal/stunmsg
    go test -fuzz FuzzBuild -fuzztime {{time}} ./internal/stunmsg

# Vet, format-check, and tidy-check — the pre-commit sweep.
lint:
    #!/usr/bin/env bash
    set -euo pipefail
    go vet ./...
    unformatted=$(gofmt -l .)
    if [[ -n "$unformatted" ]]; then
        echo "not gofmt'd:"; echo "$unformatted"; exit 1
    fi
    # golangci-lint installs to GOPATH/bin, which isn't always on PATH.
    export PATH="$(go env GOPATH)/bin:$PATH"
    if ! command -v golangci-lint >/dev/null; then
        echo "golangci-lint not found; install with:"
        echo "  go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@latest"
        exit 1
    fi
    golangci-lint run ./...
    echo "ok"

# Format all Go source in place.
fmt:
    gofmt -w .

# Apply go fix rewrites to bring code up to date with the current Go toolchain.
fix:
    go fix ./...

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

# ── Go end-to-end test ────────────────────────────────────────────────────

# stunc against stund over every transport plus the auth handshake.
test-e2e: build cert
    #!/usr/bin/env bash
    set -euo pipefail
    {{bin}} -addr {{addr}} -tls-addr {{tls-addr}} -tls-cert {{certdir}}/cert.pem -tls-key {{certdir}}/key.pem & pid=$!
    {{bin}} -addr {{auth-addr}} -realm example.org -user alice:s3cret & pid2=$!
    trap 'kill $pid $pid2 2>/dev/null || true' EXIT
    sleep 0.3
    bin/stunc {{addr}}
    bin/stunc -proto tcp {{addr}}
    bin/stunc -proto tls -insecure {{tls-addr}}
    bin/stunc -proto dtls -insecure {{tls-addr}}
    bin/stunc -user alice:s3cret {{auth-addr}}
    echo "e2e ok"

# ── everything ────────────────────────────────────────────────────────────

# Full check: lint, Go tests, and the integration tests (Python + Go e2e).
check: lint test test-py test-e2e
