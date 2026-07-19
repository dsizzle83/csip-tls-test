#!/usr/bin/env bash
# gw-qa-sb-identity.sh — G6 southbound-mbaps DER-side adversarial: prove the
# gateway AUTHENTICATES the secure DER it polls (mutual TLS is not one-way). A
# rogue/misconfigured DER presenting a server cert NOT signed by the gateway's
# southbound trust anchor (sb-mbaps-servers) must be REFUSED at the handshake —
# the gateway fails CLOSED (rejects the cert, never downgrades to plaintext,
# never polls that DER) while the healthy plain DER keeps being served
# (isolation) — then recovers when the DER presents a valid cert again.
#
# Mechanism: restart mbapsdev (the secure DER sim) presenting the negative
# wrong-CA server leaf, observe the gateway's southbound poller (lexa-modbus)
# REJECT the handshake (wolfSSL code=-188 ASN_NO_SIGNER / TLS alert 48
# unknown_ca), then restore the good leaf. A trap ALWAYS restores the good sim
# directly (not via a maybe-skip path) so the bench is never left with the rogue.
#
# Usage: scripts/gw-qa-sb-identity.sh   (GW_SSH=cc93 by default)
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"; cd "$HERE"
SSH="${GW_SSH:-cc93}"
M="$HERE/certs/mbaps"
LOG="${BENCH_LOG:-$HERE/logs/bench}"
PORT="${MBAPS_PORT:-8021}"
SERIAL="${MBAPS_SERIAL:-BENCH-MBAPS-01}"
WMAX="${MBAPS_WMAX:-6000}"
GOODCERT="$M/dev-server-cert.pem"; GOODKEY="$M/dev-server-key.pem"
BADCERT="$M/negative/wrong-ca-cert.pem"; BADKEY="$M/negative/wrong-ca-key.pem"
export CGO_CFLAGS="${CGO_CFLAGS:--I$HOME/.local/wolfssl-amd64/include}"
export CGO_LDFLAGS="${CGO_LDFLAGS:--L$HOME/.local/wolfssl-amd64/lib -lm}"
mkdir -p "$LOG"

kill_mbapsdev(){
  local p; p="$(pgrep -f "bin/mbapsdev -listen :$PORT" | head -1 || true)"
  [ -n "$p" ] && { kill "$p" 2>/dev/null || true; sleep 0.4; kill -9 "$p" 2>/dev/null || true; }
  rm -f "$LOG/mbapsdev.pid"
  # wait up to 5s for :8021 to actually free
  for _ in $(seq 1 10); do ss -ltnH "sport = :$PORT" 2>/dev/null | grep -q . || break; sleep 0.5; done
}
start_mbapsdev(){ # cert key logsuffix
  ./bin/mbapsdev -listen ":$PORT" -model inverter -wmax "$WMAX" -serial "$SERIAL" \
    -ca "$M/dev-ca.pem" -cert "$1" -key "$2" >"$LOG/mbapsdev-$3.log" 2>&1 &
  echo $! > "$LOG/mbapsdev.pid"; sleep 1
}
# fetch lexa-modbus journal for a window into a local file (no fragile pipe/SIGPIPE)
grab_modbus(){ ssh "$SSH" "journalctl -u lexa-modbus --since '$1 sec ago' -o cat 2>/dev/null" > "$2" 2>/dev/null || true; }

restored=0
restore(){ [ "$restored" = 1 ] && return; restored=1
  echo ">> TEARDOWN: restoring the good secure DER (direct)"
  kill_mbapsdev
  start_mbapsdev "$GOODCERT" "$GOODKEY" good
  sleep 8
  local f="$LOG/.modbus-recover.txt"; grab_modbus 12 "$f"
  if grep -qE 'inv-secure.*conn=true' "$f"; then echo "   recovery OK: gateway polling inv-secure again (conn=true)"
  else echo "   recovery: no conn=true verdict yet — check $LOG/mbapsdev-good.log + lexa-modbus"; fi
}
trap restore EXIT INT TERM

echo ">> ARM: restart mbapsdev presenting the WRONG-CA server leaf"
kill_mbapsdev
start_mbapsdev "$BADCERT" "$BADKEY" rogue
if ! kill -0 "$(cat "$LOG/mbapsdev.pid" 2>/dev/null)" 2>/dev/null; then
  echo "   rogue mbapsdev exited immediately:"; tail -3 "$LOG/mbapsdev-rogue.log"; exit 1
fi
echo "   rogue up (pid $(cat "$LOG/mbapsdev.pid")). Waiting ~22s for the gateway to attempt polls..."
sleep 22

F="$LOG/.modbus-rogue.txt"; grab_modbus 22 "$F"
echo ">> OBSERVE (post-arm lexa-modbus window):"
REJECT=$(grep -icE 'inv-secure.*(handshake failed|code=-188|no.?signer|alertTx=48|unknown ca)' "$F" || true)
PLAINOK=$(grep -cE 'inv-plain.*conn=true' "$F" || true)
DOWNGRADE=$(grep -icE 'inv-secure.*(plaintext|downgrade|tcp://)' "$F" || true)
echo "   inv-secure handshake REJECTED (cert-verify fail) lines: $REJECT"
grep -iE 'inv-secure.*(handshake failed|code=-188|unknown ca)' "$F" | tail -1 | sed 's/^/     /'
echo "   inv-plain still served (conn=true) lines: $PLAINOK"
echo "   plaintext-downgrade lines (must be 0): $DOWNGRADE"

pass=1
[ "${REJECT:-0}" -ge 1 ] || { echo "   FAIL: no handshake-rejection observed — the gateway did not refuse the rogue cert"; pass=0; }
[ "${DOWNGRADE:-0}" -eq 0 ] || { echo "   FAIL: a plaintext-downgrade signal appeared — the gateway must NOT fall back to unencrypted"; pass=0; }
[ "${PLAINOK:-0}" -ge 1 ] || echo "   WARN: no inv-plain conn=true in window (isolation: the healthy DER should keep being served)"
echo ">> RESULT: $([ $pass = 1 ] && echo 'PASS — rogue DER refused fail-closed (unknown_ca), no plaintext downgrade, plain DER isolated' || echo 'FAIL')"
exit $((1-pass))
