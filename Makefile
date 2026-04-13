.PHONY: all build build-server build-client build-conformance sync-pi \
        start-server conformance-pi \
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

# conformance runner is Pi-only (cgo wolfSSL, arm64)
# build via sync-pi or directly on the Pi
build-conformance:
	@mkdir -p bin
	go build -o bin/conformance ./cmd/conformance

# Sync source files to the Pi for a native build.
# wolfSSL headers are not available for arm64 on WSL, so we build on the Pi.
# The Pi must have Go and wolfSSL installed.
# Override PI_HOST: make sync-pi PI_HOST=user@hostname
PI_HOST ?= dmitri@192.168.0.81
PI_DIR  ?= ~/csip-tls-test

sync-pi:
	rsync -a --delete \
	    --exclude=bin/ --exclude='*-key.pem' --exclude='.git/' \
	    ./ $(PI_HOST):$(PI_DIR)/
	ssh $(PI_HOST) "mkdir -p $(PI_DIR)/bin && cd $(PI_DIR) && \
	    go build -o bin/client ./client && \
	    go build -o bin/conformance ./cmd/conformance"
	@echo "Source synced; client and conformance runner built on Pi at $(PI_DIR)/bin/"

# Run the CSIP conformance suite on the Pi against the WSL server.
# Prerequisites:
#   1. WSL:  make start-server                    (runs the gridsim mTLS server)
#   2. Pi:   make sync-pi                         (builds conformance runner)
#   3. Pi:   make conformance-pi SERVER=<WSL-IP>  (runs conformance, writes log)
#
# Find your WSL IP:  hostname -I   (run on WSL) — typically 172.x.x.x
# The log is saved to /tmp/csip-conformance.log on the Pi.
#
# Override: make conformance-pi SERVER=172.28.0.1 PI_HOST=dmitri@192.168.0.81
SERVER ?= $(shell hostname -I | awk '{print $$1}'):11111

conformance-pi:
	@echo "Running CSIP conformance suite on $(PI_HOST)..."
	@echo "Server: $(SERVER)"
	ssh $(PI_HOST) "cd $(PI_DIR) && ./bin/conformance \
	    -server $(SERVER) \
	    -ca    certs/ca-cert.pem \
	    -cert  certs/client-cert.pem \
	    -key   certs/client-key.pem \
	    -out   /tmp/csip-conformance.log"
	@echo ""
	@echo "Fetching log from Pi..."
	scp $(PI_HOST):/tmp/csip-conformance.log csip-conformance.log
	@echo "Log saved to: csip-conformance.log"

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

# Start the production server (WSL desktop, for Pi smoke test).
# Run this in a separate terminal before `make smoke-pi`.
start-server: build-server
	./bin/server

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
	@echo "  make build               Build client + server (amd64/WSL)"
	@echo "  make build-server        Build only the server binary"
	@echo "  make build-client        Build only the client binary"
	@echo "  make sync-pi             Sync source to Pi; build client + conformance"
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
	@echo "  make smoke-pi            Deploy to Pi, run quick smoke test"
	@echo "  make conformance-pi      Run full CSIP conformance suite on Pi"
	@echo "                           Requires: make start-server on WSL first"
	@echo "                           Override: make conformance-pi SERVER=172.x.x.x:11111"
	@echo ""
	@echo "Cleanup:"
	@echo "  make clean               Remove binaries and test certs"
