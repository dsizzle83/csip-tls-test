#!/usr/bin/env bash
# bench-sims-up.sh — bring up the desktop-side simulators for the lexa-gw live
# smoke test (see lexa-gw/docs/BENCH_SMOKE_TEST.md). Run from anywhere; it cd's
# to the csip-tls-test repo root (cert paths are repo-relative).
#
# Sims launched (all on the desktop, 69.0.0.20; the gateway at 69.0.0.2 connects
# to these — except the aggregator, which drives the gateway's :802 server):
#   modsim    tcp/plain SunSpec inverter   0.0.0.0:5020   (SOUTH plain  <- gw)
#   mbapsdev  mbaps/mTLS SunSpec inverter  0.0.0.0:8021   (SOUTH secure <- gw)
#   gridsim   IEEE 2030.5 / CSIP mTLS srv  0.0.0.0:11111  (NORTH CSIP   <- gw)   admin :11112
#   aggregator mbaps/mTLS client (loop)    -> 69.0.0.2:802 (NORTH mbaps -> gw)
#
# TRUST: every sim uses the csip-tls-test mbaps PKI (single root). The gateway's
# identity leaves are mbaps-CA-signed by bench-pki-bootstrap.sh, so the sims
# trust the gateway with NO extra config, and gridsim/mbapsdev present their
# mbaps server certs with -ca = mbaps root so they trust the gateway's
# mbaps-signed client/southbound leaves.
#
# NOTE: gridsim here deliberately uses the mbaps PKI (not the demo's Production
# PKI) so it trusts the gateway's mbaps-signed CSIP client. If the standing csip
# demo already holds :11111, stop it first — this script will refuse to spawn a
# doomed second gridsim rather than silently leave the incompatible one serving.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$HERE"

GW_HOST="${GW_HOST:-69.0.0.2}"
LOG="${BENCH_LOG:-$HERE/logs/bench}"
MODSIM_PORT="${MODSIM_PORT:-5020}"
MBAPS_PORT="${MBAPS_PORT:-8021}"
# 11113/11114, not the standard 11111/11112: a Production-PKI demo gridsim
# holds those; our gateway's CSIP client presents an mbaps-PKI leaf, so it needs
# a gridsim on the mbaps PKI (this script's -ca certs/mbaps) on a free port.
GRIDSIM_PORT="${GRIDSIM_PORT:-11113}"
GRIDSIM_ADMIN="${GRIDSIM_ADMIN:-11114}"
WITH_AGG="${WITH_AGG:-1}"
AGG_ROLE="${AGG_ROLE:-GridServiceSunSpec}"
AGG_CAMPAIGN="${AGG_CAMPAIGN:-$HERE/qa/aggregator/curtail-solar-50.json}"
AGG_PERIOD="${AGG_PERIOD:-20}"

M="$HERE/certs/mbaps"
mkdir -p "$LOG"
FAIL=0

export CGO_CFLAGS="${CGO_CFLAGS:--I$HOME/.local/wolfssl-amd64/include}"
export CGO_LDFLAGS="${CGO_LDFLAGS:--L$HOME/.local/wolfssl-amd64/lib -lm}"
build_if_missing(){ [ -x "bin/$1" ] || { echo "building bin/$1 ..."; go build -o "bin/$1" "./sim/$2"; }; }
build_if_missing modsim modsim
build_if_missing mbapsdev mbapsdev
build_if_missing aggregator aggregator
build_if_missing server server

for f in "$M/ca-cert.pem" "$M/dev-ca.pem" "$M/dev-server-cert.pem" "$M/dev-server-key.pem"; do
  [ -r "$f" ] || { echo "FATAL: missing $f — run: make gen-mbaps-certs (ONCE)"; exit 1; }
done

port_pid(){ ss -ltnpH "sport = :$1" 2>/dev/null | grep -oE 'pid=[0-9]+' | head -1 | cut -d= -f2; }

start(){ # name port cmd...
  local name="$1" port="$2"; shift 2
  local pf="$LOG/$name.pid" holder
  holder="$(port_pid "$port" || true)"
  if [ -n "$holder" ]; then
    if [ -f "$pf" ] && [ "$holder" = "$(cat "$pf" 2>/dev/null)" ]; then
      echo "  = $name already running (pid $holder, :$port)"; return
    fi
    echo "  !! $name NOT started — :$port held by foreign pid $holder ($(ps -o args= -p "$holder" 2>/dev/null | cut -c1-60)). Free it (bench-sims-down.sh / stop the csip demo) or override the port."
    FAIL=1; return
  fi
  "$@" >"$LOG/$name.log" 2>&1 &
  echo $! > "$pf"
  sleep 0.4
  if kill -0 "$(cat "$pf")" 2>/dev/null; then
    echo "  + started $name  pid=$(cat "$pf")  :$port  log=$LOG/$name.log"
  else
    echo "  !! $name exited immediately — see $LOG/$name.log:"; tail -3 "$LOG/$name.log" | sed 's/^/       /'; FAIL=1
  fi
}

echo "Bringing up sims (logs in $LOG):"
start modsim   "$MODSIM_PORT"  ./bin/modsim   -port "$MODSIM_PORT" -advanced -wmax 8000
start mbapsdev "$MBAPS_PORT"   ./bin/mbapsdev -listen ":$MBAPS_PORT" -model inverter -wmax 6000 \
                 -ca "$M/dev-ca.pem" -cert "$M/dev-server-cert.pem" -key "$M/dev-server-key.pem"
start gridsim  "$GRIDSIM_PORT" ./bin/server   -listen "0.0.0.0:$GRIDSIM_PORT" -admin "0.0.0.0:$GRIDSIM_ADMIN" \
                 -ca "$M/ca-cert.pem" -cert-chain "$M/dev-server-cert.pem" -key "$M/dev-server-key.pem"

if [ "$WITH_AGG" = 1 ]; then
  if [ -f "$LOG/aggregator.pid" ] && kill -0 "$(cat "$LOG/aggregator.pid" 2>/dev/null)" 2>/dev/null; then
    echo "  = aggregator loop already running (pid $(cat "$LOG/aggregator.pid"))"
  else
    ( trap 'exit 0' TERM INT
      while :; do
        echo "=== $(date -u +%FT%TZ) aggregator run vs ${GW_HOST}:802 (role $AGG_ROLE) ==="
        ./bin/aggregator -target "${GW_HOST}:802" -role "$AGG_ROLE" \
          -campaign "$AGG_CAMPAIGN" -json -out "$LOG/agg" || echo "  (aggregator run rc=$? — gw not ready? retrying)"
        sleep "$AGG_PERIOD"
      done ) >>"$LOG/aggregator.log" 2>&1 &
    echo $! > "$LOG/aggregator.pid"
    echo "  + started aggregator loop  pid=$!  log=$LOG/aggregator.log  (-> ${GW_HOST}:802)"
  fi
fi

echo
if [ "$FAIL" = 0 ]; then echo "All server sims up. Stop with scripts/bench-sims-down.sh"; else
  echo "One or more sims did NOT start (see above). Stop with scripts/bench-sims-down.sh"; exit 1; fi
