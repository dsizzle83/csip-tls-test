.PHONY: all build build-server build-client build-conformance build-modsim build-hub \
        build-modsim-client-pi build-modsim-conformance-pi deploy-modsim-conformance-pi \
        deploy-modsim-client-pi smoke-modbus-pi modbus-conformance-pi sync-pi sync-hub-pi \
        start-server conformance-pi \
        test test-fast test-integration test-update-golden test-southbound \
        modsim-image modsim-run modsim-stop \
        gen-test-certs gen-client-cert smoke-pi clean help

REPO_ROOT     := $(shell pwd)
SERVER_CERTS  := sim/tlsserver/testdata/certs
CLIENT_CERTS  := internal/tlsclient/testdata/certs
CA_CERT       := $(SERVER_CERTS)/ca-cert.pem

# === Build targets ==========================================================

all: build

build: build-server build-client

build-server:
	@mkdir -p bin
	go build -o bin/server ./sim/server

build-client:
	@mkdir -p bin
	go build -o bin/client ./sim/client

# conformance runner is Pi-only (cgo wolfSSL, arm64)
# build via sync-pi or directly on the Pi
build-conformance:
	@mkdir -p bin
	go build -o bin/conformance ./sim/conformance

build-modsim:
	@mkdir -p bin
	go build -o bin/modsim ./sim/modsim

build-batsim:
	@mkdir -p bin
	go build -o bin/batsim ./sim/batsim

build-metersim:
	@mkdir -p bin
	go build -o bin/metersim ./sim/metersim

build-evsim:
	@mkdir -p bin
	go build -o bin/evsim ./sim/evsim

build-httpsim:
	@mkdir -p bin
	go build -o bin/httpsim ./sim/httpsim

# Hub uses wolfSSL (cgo) — must be built natively on Pi.
# Use sync-hub-pi to sync and build on the Pi in one step.
build-hub:
	@mkdir -p bin
	go build -o bin/hub ./cmd/hub

# Cross-compile the Modbus diagnostic client for the Pi (linux/arm64).
# No cgo — southbound packages are pure Go.
build-modsim-client-pi:
	@mkdir -p bin
	GOOS=linux GOARCH=arm64 go build -o bin/modsim-client-arm64 ./sim/modsim-client

# Cross-compile the Modbus conformance runner for the Pi (linux/arm64).
# Runs on the Pi; connects to a simulator on the desktop or another Pi.
build-modsim-conformance-pi:
	@mkdir -p bin
	GOOS=linux GOARCH=arm64 go build -o bin/modsim-conformance-arm64 ./sim/modsim-conformance

# Deploy the Modbus conformance binary to the Pi.
deploy-modsim-conformance-pi: build-modsim-conformance-pi
	scp bin/modsim-conformance-arm64 $(PI_HOST):$(PI_DIR)/bin/modsim-conformance
	@echo ""
	@echo "Run on the Pi against the desktop simulator:"
	@echo "  $(PI_DIR)/bin/modsim-conformance -server $(DESKTOP_IP):$(MODSIM_PORT) -device inverter -out /tmp/modsim-conformance.log"

# === SunSpec simulator (Docker) ============================================

MODSIM_IMAGE  ?= csip-modsim
MODSIM_PORT   ?= 5020
MODSIM_WMAX   ?= 5000
MODSIM_NAME   ?= modsim

# Build the Docker image for the SunSpec solar simulator.
modsim-image:
	docker build -f Dockerfile.modsim -t $(MODSIM_IMAGE) .

# Start the simulator container in the background.
# The Modbus TCP port is published to the host so Pi and local clients can reach it.
modsim-run: modsim-image
	docker run -d --rm \
	    --name $(MODSIM_NAME) \
	    -p $(MODSIM_PORT):$(MODSIM_PORT) \
	    $(MODSIM_IMAGE) \
	    -port $(MODSIM_PORT) -wmax $(MODSIM_WMAX)
	@echo "Simulator running. Modbus TCP → host:$(MODSIM_PORT)"
	@echo "Stop with: make modsim-stop"

# Stop the simulator container.
modsim-stop:
	docker stop $(MODSIM_NAME) 2>/dev/null || true

# ── Docker Compose (solar + battery together) ───────────────────────────────

# Build and start both simulator containers (solar :5020, battery :5021).
sim-up:
	docker compose up -d --build
	@echo "Solar  → host:5020  (PV inverter, animated)"
	@echo "Battery → host:5021  (Li-Ion storage, animated)"
	@echo "Stop with: make sim-down"

# Stop and remove simulator containers.
sim-down:
	docker compose down

# Stream logs from both simulators.
sim-logs:
	docker compose logs -f

# Cross-compile and deploy the Modbus diagnostic client to the Pi.
# The southbound packages are pure Go so no Pi-side toolchain is needed.
# Override: make deploy-modsim-client-pi PI_HOST=user@host DESKTOP_IP=x.x.x.x
DESKTOP_IP ?= $(shell hostname -I | awk '{print $$1}')

deploy-modsim-client-pi: build-modsim-client-pi
	scp bin/modsim-client-arm64 $(PI_HOST):$(PI_DIR)/bin/modsim-client
	@echo ""
	@echo "Run on the Pi:"
	@echo "  $(PI_DIR)/bin/modsim-client -url tcp://$(DESKTOP_IP):$(MODSIM_PORT)"

# Quick end-to-end smoke test: start the simulator, deploy the client to the
# Pi, run one measurement read, and print the result.
# Prerequisites: make modsim-run (simulator already started on desktop).
# Override DESKTOP_IP if the Pi cannot reach the WSL2 address directly.
smoke-modbus-pi: deploy-modsim-client-pi
	@echo "Running Modbus smoke test on $(PI_HOST)..."
	ssh $(PI_HOST) "$(PI_DIR)/bin/modsim-client -url tcp://$(DESKTOP_IP):$(MODSIM_PORT)"
	@echo "Smoke test complete."

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
	    go build -o bin/client ./sim/client && \
	    go build -o bin/conformance ./sim/conformance"
	@echo "Source synced; client and conformance runner built on Pi at $(PI_DIR)/bin/"

# Sync source to Pi and build the hub binary natively (wolfSSL requires native arm64 build).
# Deprecated in favour of pi-hub (git pull workflow).
sync-hub-pi:
	rsync -a --delete \
	    --exclude=bin/ --exclude='*-key.pem' --exclude='.git/' \
	    ./ $(PI_HOST):$(PI_DIR)/
	ssh $(PI_HOST) "mkdir -p $(PI_DIR)/bin && cd $(PI_DIR) && \
	    go build -o bin/hub ./cmd/hub"
	@echo "Hub built on Pi at $(PI_DIR)/bin/hub"
	@echo "Run: $(PI_DIR)/bin/hub -config $(PI_DIR)/hub.json"

# ── Git-based Pi build workflow ─────────────────────────────────────────────
# Push from WSL with `git push`, then use these targets to pull and build on
# the Pi over SSH. No rsync needed.

# Pull latest from git and build just the hub binary on the Pi.
pi-hub:
	ssh $(PI_HOST) "cd $(PI_DIR) && git pull && mkdir -p bin && go build -o bin/hub ./cmd/hub"
	@echo "hub built on $(PI_HOST):$(PI_DIR)/bin/hub"

# Pull latest from git and build all Pi binaries (hub + client + conformance).
pi-build:
	ssh $(PI_HOST) "cd $(PI_DIR) && git pull && mkdir -p bin && \
	    go build -o bin/hub ./cmd/hub && \
	    go build -o bin/client ./sim/client && \
	    go build -o bin/conformance ./sim/conformance"
	@echo "All Pi binaries built on $(PI_HOST):$(PI_DIR)/bin/"

# Run the hub on the Pi (assumes bin/hub already built and hub.json present).
pi-run:
	ssh -t $(PI_HOST) "cd $(PI_DIR) && ./bin/hub -config hub.json"

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

# Run the Modbus conformance suite on the Pi against the desktop simulator.
# Prerequisites:
#   1. Desktop: make modsim-run                  (start solar inverter sim on port 5020)
#   2. Desktop: make deploy-modsim-conformance-pi (deploy binary to Pi)
#   3. Pi:      make modbus-conformance-pi        (runs checks, writes log)
#
# Override: make modbus-conformance-pi DESKTOP_IP=192.168.0.50 MODSIM_PORT=5020
# For battery: make modbus-conformance-pi MODSIM_PORT=5021 MODBUS_DEVICE=battery
MODBUS_DEVICE ?= inverter

modbus-conformance-pi:
	@echo "Running Modbus conformance suite on $(PI_HOST)..."
	@echo "Simulator: $(DESKTOP_IP):$(MODSIM_PORT) ($(MODBUS_DEVICE))"
	ssh $(PI_HOST) "cd $(PI_DIR) && ./bin/modsim-conformance \
	    -server $(DESKTOP_IP):$(MODSIM_PORT) \
	    -device $(MODBUS_DEVICE) \
	    -out   /tmp/modsim-conformance.log"
	@echo ""
	@echo "Fetching log from Pi..."
	scp $(PI_HOST):/tmp/modsim-conformance.log modsim-conformance.log
	@echo "Log saved to: modsim-conformance.log"

# === Test targets ===========================================================

# Run everything: unit + integration for both packages.
test: $(CA_CERT) test-fast test-integration

# Fast unit tests across both packages — pure-Go logic only.
# Pulls cgo for compilation but does no TLS handshakes.
test-fast:
	go test ./sim/tlsserver/ ./internal/tlsclient/ ./internal/southbound/sunspec/

# Southbound unit + integration tests (no hardware required; uses in-process Modbus server).
# Includes the in-process Modbus conformance suite (TestModbusConformance_*).
test-southbound:
	go test ./internal/southbound/... ./internal/bridge/...
	go test ./tests/ -run TestModbusConformance -v

# Full integration tests with real TLS handshakes. Requires fixtures.
test-integration: $(CA_CERT)
	go test -tags=integration -v ./sim/tlsserver/ ./internal/tlsclient/

# Regenerate the DCAP golden file. Run after intentionally changing
# the DCAP XML format. The -args separator is required because Go's
# test command doesn't know our custom -update flag is a boolean.
test-update-golden:
	go test ./sim/tlsserver/ -args -update

# === Cert fixtures ==========================================================

# Manual cert regeneration.
gen-test-certs:
	bash scripts/gen-test-certs.sh

# Generate a client cert for a DER device from the existing production CA.
# Output lands in certs/client-staging/. SCP to device, then delete staging.
# Override CN: make gen-client-cert CN=csip-pi-002
gen-client-cert:
	bash scripts/gen-client-cert.sh $(CN)

# Regenerate the production server cert.  Optionally add LAN IPs to the SAN:
#   make gen-server-cert IPS="192.168.10.1 10.0.0.5"
gen-server-cert:
	bash scripts/gen-server-cert.sh $(IPS)

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
	@echo "  make build-hub           Build hub binary locally (requires wolfSSL)"
	@echo "  make pi-hub              git pull + build hub on Pi (preferred workflow)"
	@echo "  make pi-build            git pull + build all Pi binaries on Pi"
	@echo "  make pi-run              Run hub on Pi via SSH (hub.json must exist)"
	@echo "  make sync-pi             (legacy) rsync source to Pi; build client + conformance"
	@echo ""
	@echo "Test:"
	@echo "  make test                Run all tests (unit + integration)"
	@echo "  make test-fast           Unit tests only (sub-second)"
	@echo "  make test-integration    Full TLS handshake tests"
	@echo "  make test-southbound     Southbound Modbus/SunSpec tests (in-process server)"
	@echo ""
	@echo "Simulator:"
	@echo "  make modsim-image        Build the Docker image for the SunSpec simulator"
	@echo "  make modsim-run          Start the simulator container (port 5020)"
	@echo "  make modsim-stop         Stop the simulator container"
	@echo "  make build-modsim        Build the simulator binary locally (bin/modsim)"
	@echo "  make build-modsim-client-pi  Cross-compile Modbus client for Pi (arm64)"
	@echo "  make deploy-modsim-client-pi Deploy the client binary to the Pi"
	@echo "  make smoke-modbus-pi     Deploy + run one-shot measurement read on Pi"
	@echo "                           Override: make smoke-modbus-pi DESKTOP_IP=x.x.x.x"
	@echo ""
	@echo "Fixtures:"
	@echo "  make test-update-golden  Refresh DCAP golden file"
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
	@echo "  make build-modsim-conformance-pi  Cross-compile Modbus conformance runner for Pi"
	@echo "  make deploy-modsim-conformance-pi Deploy conformance runner to Pi"
	@echo "  make modbus-conformance-pi Run Modbus conformance suite on Pi"
	@echo "                           Requires: make modsim-run on desktop first"
	@echo "                           Override: make modbus-conformance-pi DESKTOP_IP=x.x.x.x"
	@echo "                           Battery:  make modbus-conformance-pi MODSIM_PORT=5021 MODBUS_DEVICE=battery"
	@echo ""
	@echo "Cleanup:"
	@echo "  make clean               Remove binaries and test certs"
