#!/usr/bin/env bash
# bench-sims-up.sh — bring up the desktop-side simulators for the lexa-gw live
# smoke test (see lexa-gw/docs/BENCH_SMOKE_TEST.md). Run from anywhere; it cd's
# to the csip-tls-test repo root (cert paths are repo-relative).
#
# Sims launched (all on the desktop, 69.0.0.20; the gateway at 69.0.0.2 connects
# to these — except the aggregator, which drives the gateway's :802 server):
#   modsim    tcp/plain SunSpec inverter   0.0.0.0:5020   (SOUTH plain  <- gw)   simapi :6020
#   mbapsdev  mbaps/mTLS SunSpec inverter  0.0.0.0:8021   (SOUTH secure <- gw)   simapi :6031
#   gridsim   IEEE 2030.5 / CSIP mTLS srv  0.0.0.0:11111  (NORTH CSIP   <- gw)   admin  :11112
#   aggregator mbaps/mTLS client (loop)    -> 69.0.0.2:802 (NORTH mbaps -> gw)
#
# SIM_FLEET=4 additionally launches two more plain modsims, for the CSIP
# conformance catalog's DER AGGREGATOR CLIENT rows (owner decision 2026-07-28 —
# csip-tls-test/docs/PROFILE_SCOPE_2026-07-28_der-aggregator-client.md). Those
# rows are written against CTP Figure 15, which needs FOUR managed end devices:
#   modsim2   tcp/plain SunSpec inverter   0.0.0.0:5030   simapi :6040
#   modsim3   tcp/plain SunSpec inverter   0.0.0.0:5031   simapi :6041
#
# ┌── BOARD CONFIG REQUIRED — the sims alone are NOT enough ──────────────────┐
# │ The gateway does NOT discover southbound devices by sweeping. Discovery is│
# │ "configured endpoints only" for mbaps, and configs/modbus.json ships      │
# │ admission.sweep_enabled=false for plain TCP too, so a sim nobody listed   │
# │ is a sim the gateway never dials. Adding two inverters therefore needs a  │
# │ BOARD-SIDE edit that this script cannot and must not make.                │
# │                                                                           │
# │ On 69.0.0.2, /etc/lexa/modbus.json — "devices" must list all four:        │
# │                                                                           │
# │   "devices": [                                                            │
# │     { "name": "inv-eda1", "endpoint": "tcp://69.0.0.20:5020",             │
# │       "unit_id": 1, "role": "inverter", "max_w": 8000, "der_gen": "7xx" },│
# │     { "name": "inv-eda2", "endpoint": "tcp://69.0.0.20:5030",             │
# │       "unit_id": 1, "role": "inverter", "max_w": 8000, "der_gen": "7xx" },│
# │     { "name": "inv-edb1", "endpoint": "tcp://69.0.0.20:5031",             │
# │       "unit_id": 1, "role": "inverter", "max_w": 8000, "der_gen": "7xx" },│
# │     { "name": "inv-edb2", "endpoint": "mbaps://69.0.0.20:8021",           │
# │       "unit_id": 1, "role": "inverter", "max_w": 6000, "der_gen": "7xx" } │
# │   ]                                                                       │
# │                                                                           │
# │ then:  systemctl restart lexa-modbus                                      │
# │ verify: southbound.device_count == 4 on the dev-API :9100 /status, with   │
# │         every device connected:true.                                      │
# │ (No "pin" on inv-edb2 ⇒ CA-mode trust via the sb-mbaps-servers bundle,    │
# │  exactly as docs/BENCH_SMOKE_TEST.md §4.2 sets up for the two-sim case.)  │
# │                                                                           │
# │ THE NORTHBOUND HALF IS STILL MISSING, and four sims do not supply it.     │
# │ The AGG/MAINT/UTIL rows also need sim/gridsim to SERVE four EndDevices    │
# │ (CTP Figure 15: an aggregator EndDevice plus EDA1/EDA2 under SPA1/SPA2    │
# │ and EDB1/EDB2 under SPB1/SPB2, each with a FunctionSetAssignmentsListLink │
# │ and a DERListLink) and to implement the Subscription/Notification         │
# │ function set. gridsim does neither today. Until it does, those rows       │
# │ report SKIP naming the gap — see the PROFILE_SCOPE doc §5.                │
# └───────────────────────────────────────────────────────────────────────────┘
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
# SIM_FLEET: 2 (default, the smoke-test pair) or 4 (the CTP Figure-15 fleet the
# DER Aggregator Client rows need). Anything else is refused rather than
# silently rounded, because "3" would half-build a fixture and read as success.
SIM_FLEET="${SIM_FLEET:-2}"
# The two extra plain inverters. Ports are deliberately AWAY from the Pi sim map
# (modsim 5020/6020, batsim 5021/6021, metersim 5022/6022 — CLAUDE.md): these
# run on the desktop and reusing 5021/5022 would make a stray connection to a Pi
# look like a healthy fleet member.
MODSIM2_PORT="${MODSIM2_PORT:-5030}"
MODSIM2_API="${MODSIM2_API:-6040}"
MODSIM3_PORT="${MODSIM3_PORT:-5031}"
MODSIM3_API="${MODSIM3_API:-6041}"
# 11113/11114, not the standard 11111/11112: a Production-PKI demo gridsim
# holds those; our gateway's CSIP client presents an mbaps-PKI leaf, so it needs
# a gridsim on the mbaps PKI (this script's -ca certs/mbaps) on a free port.
GRIDSIM_PORT="${GRIDSIM_PORT:-11113}"
GRIDSIM_ADMIN="${GRIDSIM_ADMIN:-11114}"
# DER_MODELS: which SunSpec DER model set the modsims serve. Empty (default)
# passes nothing and every modsim starts with -advanced exactly as it always
# has, so the register image on a running bench does not change under anyone.
# Set DER_MODELS=full to add the IEEE 1547-2018 trip models 707/708/709/710
# (DERTripLV/HV/LF/HF, Category III default curves) — the fixture the gateway's
# Stage-4 northbound 1547 mirror needs something to mirror FROM, and the reason
# MOD-4 keeps 707-710 in its missing set. Adding them lengthens the SunSpec
# chain every scenario walks, which is why it is opt-in rather than the default.
#
# build_if_missing below will NOT rebuild an existing bin/modsim, so after
# pulling this change run `rm -f bin/modsim` (or `make build-modsim`) once, or
# DER_MODELS=full silently starts a binary that does not know the flag.
DER_MODELS="${DER_MODELS:-}"
WITH_AGG="${WITH_AGG:-1}"
AGG_ROLE="${AGG_ROLE:-GridServiceSunSpec}"
AGG_CAMPAIGN="${AGG_CAMPAIGN:-$HERE/qa/aggregator/curtail-solar-50.json}"
AGG_PERIOD="${AGG_PERIOD:-20}"

case "$SIM_FLEET" in
  2|4) ;;
  *) echo "FATAL: SIM_FLEET=$SIM_FLEET — only 2 (smoke-test pair) or 4 (CTP Figure-15 fleet) are defined."; exit 1;;
esac

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

# Distinct -serial per sim: the gateway keys device identity on
# manufacturer|model|serial, so two inverters sharing the hardcoded default
# serial dedup into ONE northbound unit. Give them distinct serials so they
# present as two DERs (override via MODSIM_SERIAL/MBAPS_SERIAL).
MODSIM_SERIAL="${MODSIM_SERIAL:-BENCH-MODSIM-01}"
MBAPS_SERIAL="${MBAPS_SERIAL:-BENCH-MBAPS-01}"
MODSIM2_SERIAL="${MODSIM2_SERIAL:-BENCH-MODSIM-02}"
MODSIM3_SERIAL="${MODSIM3_SERIAL:-BENCH-MODSIM-03}"
echo "Bringing up sims (logs in $LOG, fleet size $SIM_FLEET):"
start modsim   "$MODSIM_PORT"  ./bin/modsim   -port "$MODSIM_PORT" -advanced ${DER_MODELS:+-der-models "$DER_MODELS"} -wmax 8000 -serial "$MODSIM_SERIAL"
start mbapsdev "$MBAPS_PORT"   ./bin/mbapsdev -listen ":$MBAPS_PORT" -model inverter -wmax 6000 -serial "$MBAPS_SERIAL" \
                 -ca "$M/dev-ca.pem" -cert "$M/dev-server-cert.pem" -key "$M/dev-server-key.pem"

if [ "$SIM_FLEET" = 4 ]; then
  # The CTP's four managed end devices. Distinct -serial per sim for the same
  # reason the pair above has them: the gateway keys device identity on
  # manufacturer|model|serial, and four inverters sharing a serial dedup into
  # ONE northbound unit — which would present as a passing four-device fleet
  # while actually being one device. Distinct -api-port too, or the second and
  # third modsim both grab 6020 and the third exits on a bind error.
  #
  # Mapping to the CTP's names (Figure 15), for the operator reading a log:
  #   EDA1 = modsim  :5020   EDA2 = modsim2 :5030
  #   EDB1 = modsim3 :5031   EDB2 = mbapsdev :8021
  start modsim2 "$MODSIM2_PORT" ./bin/modsim -port "$MODSIM2_PORT" -api-port "$MODSIM2_API" \
                 -advanced ${DER_MODELS:+-der-models "$DER_MODELS"} -wmax 8000 -serial "$MODSIM2_SERIAL"
  start modsim3 "$MODSIM3_PORT" ./bin/modsim -port "$MODSIM3_PORT" -api-port "$MODSIM3_API" \
                 -advanced ${DER_MODELS:+-der-models "$DER_MODELS"} -wmax 8000 -serial "$MODSIM3_SERIAL"
fi
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
if [ "$SIM_FLEET" = 4 ]; then
  cat <<'EOF'
NOTE (SIM_FLEET=4): the sims are only the SOUTHBOUND half of the CTP Figure-15
fixture. Two things are still needed and neither is done by this script:
  1. BOARD: /etc/lexa/modbus.json must list all four devices and lexa-modbus
     must be restarted — see the block at the top of this file for the exact
     JSON. The gateway does not sweep; an unlisted sim is never dialled.
  2. BENCH: sim/gridsim must serve four EndDevices and a Subscription/
     Notification function set before the AGG / MAINT / UTIL conformance rows
     can do more than SKIP. See
     docs/PROFILE_SCOPE_2026-07-28_der-aggregator-client.md §5.
EOF
fi
if [ "$FAIL" = 0 ]; then echo "All server sims up. Stop with scripts/bench-sims-down.sh"; else
  echo "One or more sims did NOT start (see above). Stop with scripts/bench-sims-down.sh"; exit 1; fi
