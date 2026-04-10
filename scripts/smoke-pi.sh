#!/bin/bash
# Cross-compile the client for ARM64, deploy it to the Pi, and run a
# smoke test against the WSL desktop server.
#
# This is a deliberate manual smoke test, NOT part of `go test`. We
# don't bake the Pi into the test framework because:
#   1. It would require Pi availability for the fast feedback loop
#   2. It would require SSH credentials in test code
#   3. Other developers (and future-you on a different laptop) would
#      need the same hardware setup to run the suite
#
# Instead, run this script deliberately when you want to validate
# against real hardware:  make smoke-pi
#
# Prerequisites:
#   - Server running on the WSL desktop (in another terminal)
#   - Pi reachable at $PI_HOST
#   - Production certs already deployed to the Pi at $PI_CERTS_DIR
#   - SSH key auth set up so this script doesn't prompt for a password

set -euo pipefail

PI_HOST="${PI_HOST:-dmitri@dhpi4}"
PI_BIN_DIR="${PI_BIN_DIR:-/home/dmitri/csip-tls-test/bin}"
PI_CERTS_DIR="${PI_CERTS_DIR:-/home/dmitri/csip-tls-test/certs}"
SERVER_ADDR="${SERVER_ADDR:-192.168.0.188:11111}"

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

echo "==> [1/5] Cross-compiling client for ARM64..."
# Note on cross-compilation with cgo: this requires an ARM64 cross
# toolchain on WSL (gcc-aarch64-linux-gnu) AND wolfSSL built for ARM64
# in a location the cross-linker can find. If you don't have this set
# up yet, the alternative is to scp the source and build natively on
# the Pi — slower but no toolchain setup. The "build natively" path is
# the fallback in step 2.
if command -v aarch64-linux-gnu-gcc >/dev/null 2>&1; then
    CGO_ENABLED=1 \
    GOOS=linux GOARCH=arm64 \
    CC=aarch64-linux-gnu-gcc \
    go build -o bin/client-arm64 ./client
    CLIENT_BIN="bin/client-arm64"
    BUILD_MODE="cross-compiled"
else
    echo "    aarch64-linux-gnu-gcc not found — falling back to native build on Pi"
    CLIENT_BIN=""
    BUILD_MODE="pi-native"
fi

echo "==> [2/5] Deploying to $PI_HOST..."
ssh "$PI_HOST" "mkdir -p $PI_BIN_DIR"
if [ -n "$CLIENT_BIN" ]; then
    scp "$CLIENT_BIN" "$PI_HOST:$PI_BIN_DIR/client"
else
    # Native build path: rsync the source to the Pi and build there.
    # The Pi already has wolfSSL installed natively from earlier setup.
    rsync -a --delete \
        --exclude=bin --exclude='*.pem' \
        ./ "$PI_HOST:/tmp/csip-tls-test-src/"
    ssh "$PI_HOST" "cd /tmp/csip-tls-test-src && go build -o $PI_BIN_DIR/client ./client"
fi

echo "==> [3/5] Verifying server reachability from Pi..."
ssh "$PI_HOST" "nc -zv ${SERVER_ADDR%:*} ${SERVER_ADDR##*:}" || {
    echo "ERROR: Pi cannot reach $SERVER_ADDR — is the server running on WSL?"
    exit 1
}

echo "==> [4/5] Running client on Pi against $SERVER_ADDR..."
OUTPUT=$(ssh "$PI_HOST" "$PI_BIN_DIR/client \
    -server $SERVER_ADDR \
    -ca $PI_CERTS_DIR/ca-cert.pem \
    -cert $PI_CERTS_DIR/client-cert.pem \
    -key $PI_CERTS_DIR/client-key.pem 2>&1")

echo "$OUTPUT"

echo "==> [5/5] Verifying expected outputs..."
FAIL=0
for expected in \
    "mTLS handshake" \
    "ECDHE-ECDSA-AES128-CCM-8" \
    "TLSv1.2" \
    "DeviceCapability fetched" \
    "EndDeviceList:    /edev"
do
    if echo "$OUTPUT" | grep -qF "$expected"; then
        echo "    ✓ $expected"
    else
        echo "    ✗ MISSING: $expected"
        FAIL=1
    fi
done

if [ "$FAIL" -ne 0 ]; then
    echo
    echo "❌ Smoke test FAILED ($BUILD_MODE binary)"
    exit 1
fi

echo
echo "✅ Smoke test PASSED ($BUILD_MODE binary)"
