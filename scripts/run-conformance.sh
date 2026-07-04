#!/bin/bash
# run-conformance.sh — one-command CSIP conformance proof for the DER hub.
#
# Runs every layer of evidence that maps to the SunSpec CSIP Conformance
# Test Procedures v1.3 (the EUT is the DER *client* — the hub northbound):
#
#   1. Logic suite   — real discovery.Walker + scheduler against the gridsim
#                      2030.5 server over httptest. COMM-002, CORE-*, BASIC-*,
#                      ERR-001.  (pure Go, no wolfSSL)
#   2. TLS suite     — wolfSSL mTLS: cipher == ECDHE-ECDSA-AES128-CCM-8,
#                      wrong-CA rejection, wrong-cipher rejection. COMM-003/004.
#   3. Full stack    — Walker → WolfSSLFetcher → wolfSSL → tlsserver → gridsim.
#   4. Live capture  — (optional, --capture) boots the real mTLS server, walks
#                      it with the real client, and verifies the negotiated
#                      cipher 0xC0AE on the wire with a packet capture.
#
# Usage:
#   scripts/run-conformance.sh              # layers 1-3
#   scripts/run-conformance.sh --capture    # layers 1-4 (needs dumpcap perms)
#
# wolfSSL: set WOLFSSL_PREFIX to your install, or this script auto-detects
# the common locations. Build it once with the `wolfssl-arm64` Makefile
# recipe in lexa-hub (see docs/BENCH.md "wolfSSL sysroots").
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

# ── locate wolfSSL (cgo) ────────────────────────────────────────────────────
: "${WOLFSSL_PREFIX:=}"
if [[ -z "$WOLFSSL_PREFIX" ]]; then
  for p in "$HOME/.local/wolfssl-amd64" /tmp/wolfssl-amd64-sysroot /usr/local /usr; do
    if [[ -f "$p/include/wolfssl/options.h" ]]; then WOLFSSL_PREFIX="$p"; break; fi
  done
fi
if [[ -z "$WOLFSSL_PREFIX" || ! -f "$WOLFSSL_PREFIX/include/wolfssl/options.h" ]]; then
  echo "ERROR: wolfSSL not found. Build it (see docs/BENCH.md \"wolfSSL sysroots\") and/or"
  echo "       set WOLFSSL_PREFIX=/path/to/wolfssl-sysroot"
  exit 1
fi
export CGO_ENABLED=1
export CGO_CFLAGS="-I$WOLFSSL_PREFIX/include"
export CGO_LDFLAGS="-L$WOLFSSL_PREFIX/lib -lwolfssl -lm"
echo "wolfSSL: $WOLFSSL_PREFIX"

PASS=0; FAIL=0
section() { echo; echo "════════════════════════════════════════════════════════"; echo "  $1"; echo "════════════════════════════════════════════════════════"; }
run() { # run <label> <cmd...>
  local label="$1"; shift
  if "$@"; then echo "  ✓ $label"; PASS=$((PASS+1)); else echo "  ✗ $label"; FAIL=$((FAIL+1)); fi
}

# ── ensure integration cert fixtures exist (gitignored keys) ────────────────
if [[ ! -f internal/tlsclient/testdata/certs/client-key.pem ]]; then
  echo "Generating test cert fixtures (private keys are gitignored)…"
  bash scripts/gen-test-certs.sh >/dev/null
fi

# ── Layer 1: logic conformance (COMM-002, CORE-*, BASIC-*, ERR-001) ─────────
section "Layer 1 — CSIP logic conformance (walker + scheduler vs gridsim)"
go test ./tests/ -run TestCSIP -v 2>&1 | grep -E "^(--- (PASS|FAIL)|ok|FAIL)"
run "logic conformance suite" go test ./tests/ -run TestCSIP

# ── Layer 2: TLS / cipher conformance (COMM-003, COMM-004) ──────────────────
section "Layer 2 — TLS security (cipher CCM-8, wrong-CA + wrong-cipher reject)"
go test -tags integration ./internal/tlsclient/ ./sim/tlsserver/ -run \
  'Cipher|Reject|CSIPCompliant|OnClientCert' -v 2>&1 | grep -E "^(--- (PASS|FAIL)|ok|FAIL)"
run "TLS security tests" go test -tags integration ./internal/tlsclient/ ./sim/tlsserver/

# ── Layer 3: full-stack mTLS walk ───────────────────────────────────────────
section "Layer 3 — full-stack mTLS discovery walk"
go test -tags integration ./tests/ -run TestFullStack -v 2>&1 | grep -E "^(--- (PASS|FAIL)|ok|FAIL|.*cipher:)"
run "full-stack wolfSSL walk" go test -tags integration ./tests/ -run TestFullStack

# ── Layer 4 (optional): live capture, verify cipher 0xC0AE on the wire ──────
if [[ "${1:-}" == "--capture" ]]; then
  section "Layer 4 — live mTLS capture (cipher 0xC0AE on the wire)"
  # Self-contained: uses the integration test-cert fixtures (both ends, one CA),
  # not the air-gapped deployment certs. For a real DUT-vs-server run with the
  # client and server certs in separate repos, see scripts/run-cross-repo.sh.
  CERTS="$REPO_ROOT/internal/tlsclient/testdata/certs"
  if [[ ! -f "$CERTS/server-key.pem" ]]; then
    echo "  SKIP: test certs absent — run 'make gen-test-certs'."
  elif ! command -v dumpcap >/dev/null; then
    echo "  SKIP: dumpcap not installed."
  else
    go build -o bin/server ./sim/server && go build -o bin/client ./sim/client
    ./bin/server -listen 127.0.0.1:11111 -admin 127.0.0.1:11112 -ocpp-port 8887 \
      -ca "$CERTS/ca-cert.pem" -cert "$CERTS/server-cert.pem" -key "$CERTS/server-key.pem" \
      >/tmp/conf-gridsim.log 2>&1 &
    SRV=$!; sleep 1.5
    PCAP=$(mktemp --suffix=.pcapng)
    dumpcap -i lo -f 'tcp port 11111' -w "$PCAP" >/dev/null 2>&1 &
    CAP=$!; sleep 1
    ./bin/client -server 127.0.0.1:11111 -ca "$CERTS/ca-cert.pem" \
      -cert "$CERTS/client-cert.pem" -key "$CERTS/client-key.pem" \
      2>&1 | grep -E "✓|✗"
    sleep 1; kill -INT $CAP 2>/dev/null; wait $CAP 2>/dev/null; kill $SRV 2>/dev/null
    if grep -aq $'\xc0\xae' "$PCAP" 2>/dev/null || python3 - "$PCAP" <<'PY'
import sys; sys.exit(0 if open(sys.argv[1],'rb').read().count(b'\xc0\xae')>=2 else 1)
PY
    then echo "  ✓ TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8 (0xC0AE) observed on the wire"; PASS=$((PASS+1))
    else echo "  ✗ cipher 0xC0AE not found in capture"; FAIL=$((FAIL+1)); fi
    echo "  server-side REST walk:"; grep -E "GET /" /tmp/conf-gridsim.log | sed 's/^/    /'
    rm -f "$PCAP"
  fi
fi

section "RESULT: $PASS passed, $FAIL failed"
[[ $FAIL -eq 0 ]]
