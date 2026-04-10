.PHONY: all build build-server build-client \
        test test-fast test-integration test-update-golden \
        gen-test-certs smoke-pi clean help

REPO_ROOT     := $(shell pwd)
SERVER_CERTS  := internal/tlsserver/testdata/certs
CLIENT_CERTS  := internal/tlsclient/testdata/certs
CA_CERT       := $(SERVER_CERTS)/ca-cert.pem

# === Build targets ==========================================================

all: build

build: build-server build-client

build-server:
	@mkdir -p bin
	go build -o bin/server ./server

build-client:
	@mkdir -p bin
	go build -o bin/client ./client

# === Test targets ===========================================================

# Run everything: unit + integration for both packages.
test: $(CA_CERT) test-fast test-integration

# Fast unit tests across both packages — pure-Go logic only.
# Pulls cgo for compilation but does no TLS handshakes.
test-fast:
	go test ./internal/tlsserver/ ./internal/tlsclient/

# Full integration tests with real TLS handshakes. Requires fixtures.
test-integration: $(CA_CERT)
	go test -tags=integration -v ./internal/tlsserver/ ./internal/tlsclient/

# Regenerate the DCAP golden file. Run after intentionally changing
# the DCAP XML format. The -args separator is required because Go's
# test command doesn't know our custom -update flag is a boolean.
test-update-golden:
	go test ./internal/tlsserver/ -args -update

# === Cert fixtures ==========================================================

# Manual cert regeneration.
gen-test-certs:
	bash scripts/gen-test-certs.sh

# Auto-generate certs on first test run via dependency tracking.
$(CA_CERT):
	@echo "Test certs missing — generating..."
	@bash scripts/gen-test-certs.sh

# === Pi deployment smoke test ==============================================

# Manual smoke test against real hardware. NOT part of `make test` —
# requires Pi reachable and server running on WSL.
#
# Override defaults via environment:
#   PI_HOST=user@host SERVER_ADDR=10.0.0.5:11111 make smoke-pi
smoke-pi:
	bash scripts/smoke-pi.sh

# === Cleanup ================================================================

clean:
	rm -rf bin/
	rm -rf $(SERVER_CERTS)/ $(CLIENT_CERTS)/

# === Help ===================================================================

help:
	@echo "Build:"
	@echo "  make build               Build both client and server binaries"
	@echo "  make build-server        Build only the server binary"
	@echo "  make build-client        Build only the client binary"
	@echo ""
	@echo "Test:"
	@echo "  make test                Run all tests (unit + integration)"
	@echo "  make test-fast           Unit tests only (sub-second)"
	@echo "  make test-integration    Full TLS handshake tests"
	@echo "  make test-update-golden  Refresh DCAP golden file"
	@echo ""
	@echo "Fixtures:"
	@echo "  make gen-test-certs      Regenerate test cert fixtures"
	@echo ""
	@echo "Hardware validation:"
	@echo "  make smoke-pi            Cross-compile, deploy to Pi, run smoke test"
	@echo ""
	@echo "Cleanup:"
	@echo "  make clean               Remove binaries and test certs"
