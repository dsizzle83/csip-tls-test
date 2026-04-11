#!/bin/bash
# Smoke test: Pi as CSIP client, WSL desktop as mTLS server with gridsim.
#
# What it validates (Milestone 3 complete):
#   1. mTLS handshake Pi → WSL (cipher ECDHE-ECDSA-AES128-CCM-8)
#   2. Server extracts LFDI from live peer cert (Step A)
#   3. Discovery walker traverses /dcap → /edev → /fsa → /derp (Steps B, C)
#   4. Pi client finds its own EndDevice by LFDI match
#   5. DERPrograms + DefaultDERControl are discovered
#
# Prerequisites:
#   - Server running on WSL: bin/server (in another terminal, or start-server.sh)
#   - Pi reachable at $PI_HOST over SSH (key auth, no password)
#   - Production certs on Pi at $PI_CERTS_DIR
#
# Usage:
#   make smoke-pi
#   PI_HOST=user@host SERVER_ADDR=10.0.0.5:11111 make smoke-pi

set -euo pipefail

PI_HOST="${PI_HOST:-dmitri@dhpi4}"
PI_BIN_DIR="${PI_BIN_DIR:-/home/dmitri/csip-tls-test/bin}"
PI_CERTS_DIR="${PI_CERTS_DIR:-/home/dmitri/csip-tls-test/certs}"
SERVER_ADDR="${SERVER_ADDR:-192.168.0.188:11111}"

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

# ── Step 1: build client on Pi (native, avoids arm64 cgo cross-compile) ──────

echo "==> [1/4] Syncing source and building client on Pi..."
rsync -a --delete \
    --exclude=bin/ --exclude='*-key.pem' --exclude='.git/' \
    ./ "$PI_HOST:/tmp/csip-tls-test-src/"
ssh "$PI_HOST" "mkdir -p $PI_BIN_DIR && cd /tmp/csip-tls-test-src && go build -o $PI_BIN_DIR/client ./client"
echo "    Client built on Pi at $PI_BIN_DIR/client"

# ── Step 2: verify server is reachable from Pi ────────────────────────────────

echo "==> [2/4] Checking server reachability from Pi (${SERVER_ADDR})..."
ssh "$PI_HOST" "nc -zv ${SERVER_ADDR%:*} ${SERVER_ADDR##*:} 2>&1" || {
    echo
    echo "ERROR: Pi cannot reach $SERVER_ADDR"
    echo "  Start the server on WSL first:"
    echo "    ./bin/server"
    echo "  (or: make build-server && bin/server)"
    exit 1
}

# ── Step 3: run the discovery walk on Pi ─────────────────────────────────────

echo "==> [3/4] Running discovery walk on Pi → $SERVER_ADDR..."
echo
OUTPUT=$(ssh "$PI_HOST" "$PI_BIN_DIR/client \
    -server $SERVER_ADDR \
    -ca    $PI_CERTS_DIR/ca-cert.pem \
    -cert  $PI_CERTS_DIR/client-cert.pem \
    -key   $PI_CERTS_DIR/client-key.pem \
    2>&1")
echo "$OUTPUT"
echo

# ── Step 4: assert expected outputs ──────────────────────────────────────────

echo "==> [4/4] Verifying outputs..."
FAIL=0
check() {
    local label="$1"
    local pattern="$2"
    if echo "$OUTPUT" | grep -qF "$pattern"; then
        echo "    ✓ $label"
    else
        echo "    ✗ MISSING: $label  (looking for: $pattern)"
        FAIL=1
    fi
}

check "mTLS handshake"             "mTLS handshake: ECDHE-ECDSA-AES128-CCM-8 TLSv1.2"
check "DeviceCapability fetched"   "DeviceCapability fetched"
check "EndDeviceList discovered"   "EndDeviceList: /edev"
check "Time fetched"               "Time fetched"
check "SelfDevice LFDI matched"    "SelfDevice matched by LFDI"
check "DERPrograms discovered"     "DERPrograms discovered: 1"
check "DefaultDERControl present"  "DefaultDERControl: OpModExpLimW="

if [ "$FAIL" -ne 0 ]; then
    echo
    echo "❌ Smoke test FAILED"
    exit 1
fi

echo
echo "✅ Milestone 3 smoke test PASSED — full CSIP discovery walk over mTLS"
