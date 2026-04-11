.PHONY: all build build-server build-client sync-pi \
        test test-fast test-integration test-update-golden \
        gen-test-certs gen-client-cert smoke-pi clean help

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

# Sync source files to the Pi for a native build.
# wolfSSL headers are not available for arm64 on WSL, so we build on the Pi.
# The Pi must have Go and wolfSSL installed.
# Override PI_HOST: make sync-pi PI_HOST=user@hostname
PI_HOST ?= dmitri@192.168.0.81
PI_DIR  ?= ~/csip-tls-test

sync-pi:
	ssh $(PI_HOST) "mkdir -p $(PI_DIR)/client $(PI_DIR)/internal/wolfssl $(PI_DIR)/internal/tlsclient $(PI_DIR)/bin"
	scp go.mod $(PI_HOST):$(PI_DIR)/
	scp client/main.go $(PI_HOST):$(PI_DIR)/client/
	scp internal/wolfssl/wolfssl.go $(PI_HOST):$(PI_DIR)/internal/wolfssl/
	scp $(filter-out %_test.go, $(wildcard internal/tlsclient/*.go)) $(PI_HOST):$(PI_DIR)/internal/tlsclient/
	@echo "Source synced. On the Pi, run: cd $(PI_DIR) && go build -o bin/client ./client"

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

# Generate a client cert for a DER device from the existing production CA.
# Output lands in certs/client-staging/. SCP to device, then delete staging.
# Override CN: make gen-client-cert CN=csip-pi-002
gen-client-cert:
	bash scripts/gen-client-cert.sh $(CN)

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
	@echo "  make sync-pi             Sync client source to Pi for native build"
	@echo "                           Override: make sync-pi PI_HOST=user@host"
	@echo ""
	@echo "Test:"
	@echo "  make test                Run all tests (unit + integration)"
	@echo "  make test-fast           Unit tests only (sub-second)"
	@echo "  make test-integration    Full TLS handshake tests"
	@echo "  make test-update-golden  Refresh DCAP golden file"
	@echo ""
	@echo "Fixtures:"
	@echo "  make gen-test-certs      Regenerate test cert fixtures"
	@echo "  make gen-client-cert     Issue a client cert from the production CA"
	@echo "                           Output: certs/client-staging/ — SCP then delete"
	@echo "                           Override CN: make gen-client-cert CN=csip-pi-002"
	@echo ""
	@echo "Hardware validation:"
	@echo "  make smoke-pi            Cross-compile, deploy to Pi, run smoke test"
	@echo ""
	@echo "Cleanup:"
	@echo "  make clean               Remove binaries and test certs"
