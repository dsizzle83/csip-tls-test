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
# │ THE NORTHBOUND HALF is gridsim's, and SIM_FLEET=4 now turns it on: this   │
# │ script starts gridsim with -fleet 4 -subscription, so it serves the CTP   │
# │ Figure-15 EndDeviceList (an aggregator EndDevice plus EDA1/EDA2 under     │
# │ SPA1/SPA2 and EDB1/EDB2 under SPB1/SPB2, each with a                      │
# │ FunctionSetAssignmentsListLink, a DERListLink and its parent nodes'       │
# │ DERPrograms) and the Subscription/Notification function set.              │
# │                                                                           │
# │ Override either half with GRIDSIM_FLEET=0 / GRIDSIM_SUBSCRIPTION=0.       │
# │ At SIM_FLEET=2 both stay OFF and gridsim serves exactly the               │
# │ single-EndDevice tree it always has — the direct-DER-client rows were     │
# │ certified against that tree and must not be silently re-measured against  │
# │ a different one. See the PROFILE_SCOPE doc §5.                            │
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
# Bind hosts for the WAN/LAN split bench (2026-08-07): gridsim (northbound) can
# be pinned to the desktop's WiFi address and mbapsdev (southbound) to the
# ethernet address, so each protocol is reachable on exactly one segment.
# MODSIM_BIND (also southbound) pins modsim/modsim2/modsim3 the same way as
# mbapsdev — they share one var since all three plain inverters sit on the
# same segment. Defaults preserve the historical wildcard binds.
GRIDSIM_BIND="${GRIDSIM_BIND:-0.0.0.0}"
MBAPS_BIND="${MBAPS_BIND:-}"
MODSIM_BIND="${MODSIM_BIND:-}"
# Conformance-evidence launches (2026-08-07): the keylog BUILDS of gridsim and
# mbapsdev plus full-handshake posture. Without these a conformance leg runs
# but every decryption/citation-dependent case collapses to SKIP/FAIL
# (PREFLIGHT_2026-08-05 §2 rule 3; the 2026-08-07 cycle-01 lesson).
#   GRIDSIM_BIN/MBAPS_BIN     e.g. ./bin/server-keylog / ./bin/mbapsdev-keylog
#   SIMS_KEYLOG=<path>        append both sims' TLS secrets there (keylog builds only)
#   GRIDSIM_NO_TICKETS=1      full mTLS handshake on every gateway dial
#   GRIDSIM_IDLE_S=<s>        close idle CSIP sessions => one observable session per walk
GRIDSIM_BIN="${GRIDSIM_BIN:-./bin/server}"
MBAPS_BIN="${MBAPS_BIN:-./bin/mbapsdev}"
SIMS_KEYLOG="${SIMS_KEYLOG:-}"
GRIDSIM_NO_TICKETS="${GRIDSIM_NO_TICKETS:-}"
GRIDSIM_IDLE_S="${GRIDSIM_IDLE_S:-}"
#   GRIDSIM_POLL_S=<s>        advertise a uniform pollRate. WITHOUT this the
#     built-ins apply (300 /dcap, 900 /tm, 60 control lists) and a
#     poll_rate_mode=honor DUT paces its WHOLE walk at the slowest one (900 s),
#     so every wait-for-fetch conformance case times out (2026-08-08 lesson:
#     64/79 CSIP verdicts collapsed). Campaign posture: 60.
GRIDSIM_POLL_S="${GRIDSIM_POLL_S:-}"
# The NORTHBOUND half of the CTP Figure-15 fixture. Both default to ON at
# SIM_FLEET=4 and OFF at SIM_FLEET=2, so the smoke-test pair keeps serving the
# byte-identical single-EndDevice tree it always has. Set either to 0 to run a
# four-sim southbound against the old northbound tree (which is what you want if
# you are bisecting a change to the southbound half and do not want the
# northbound one moving underneath you).
if [ "$SIM_FLEET" = 4 ]; then
  GRIDSIM_FLEET="${GRIDSIM_FLEET:-4}"
  GRIDSIM_SUBSCRIPTION="${GRIDSIM_SUBSCRIPTION:-1}"
else
  GRIDSIM_FLEET="${GRIDSIM_FLEET:-0}"
  GRIDSIM_SUBSCRIPTION="${GRIDSIM_SUBSCRIPTION:-0}"
fi
# DER_MODELS: which SunSpec DER model set the modsims serve. It overrides BOTH
# defaults below when set; leave it unset for the intended posture.
#
# THE CENSUS DEVICE NOW DEFAULTS TO "full" — 707/708/709/710 (DERTripLV/HV/LF/HF,
# Category III default curves) on top of the 7xx set. It used to default to the
# reduced fixture, and that reduction was being measured as a product gap:
# MOD-4's ten not-implemented points were the SIM'S missing models, not the
# gateway's, and the ruling on it is re-run-with-the-full-fixture. Every suite in
# this repo already expects the trip models to be there —
# suitemodbusserver/models.go marks 707-710 `Served: true` and its unit rows list
# them in the served chain — so the reduced fixture was the outlier, not the
# default.
#
# Adding them lengthens the SunSpec chain a scenario walks, and that is the whole
# cost: they are APPENDED after every other model (populateSolar7xx), so no
# existing block moves and no register address changes. sim/southbound's
# TestTripModelsDoNotDisturbTheDefaultAdvancedImage pins exactly that.
#
# THE FLEET SIMS (modsim2/modsim3, SIM_FLEET=4) DELIBERATELY DO NOT FOLLOW. They
# exist to make the CTP's four-device fleet, where what is under test is device
# identity and fan-out rather than any one device's model set, and lengthening
# three chain walks to fix a ruling about one device would be paying the cost
# three times over for nothing. Set DER_MODELS=full to bring them along.
#
# build_if_missing below will NOT rebuild an existing bin/modsim. A binary
# predating -der-models now fails AT STARTUP (Go's flag package rejects the
# unknown flag and exits) rather than quietly serving something else — but it
# still fails, so after pulling this change run `rm -f bin/modsim` (or
# `make build-modsim`) once.
DER_MODELS="${DER_MODELS:-}"
# The census device: the single configured southbound DER a bench battery
# measures. Full fixture unless DER_MODELS overrides it.
CENSUS_DER_MODELS="${DER_MODELS:-full}"
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

# port_holder PORT BIND — prints "PID ADDR" for a listener on PORT that would
# actually conflict with a sim about to bind BIND, else prints nothing.
#
# A wildcard/unset BIND (empty, 0.0.0.0, *, ::, [::]) keeps the historical
# behavior: ANY existing listener on PORT is a conflict, regardless of its
# address (we're about to claim the whole port ourselves).
#
# A specific BIND (e.g. 192.168.0.188) only conflicts with a listener on that
# SAME address or on a wildcard address — two sims bound to different
# addresses of the same port coexist fine (the WAN/LAN split bench relies on
# exactly this: a detector canary on 69.0.0.20:11113 must not block gridsim
# from starting on 192.168.0.188:11113). Uses `ss -tlnpH` because, unlike a
# port-only check, its Local-Address:Port column tells them apart.
port_holder(){
  local port="$1" bind="${2:-}" ss_out line addr pid
  case "$bind" in
    ""|0.0.0.0|"*"|"::"|"[::]") bind="";;
  esac
  ss_out="$(ss -tlnpH "sport = :$port" 2>/dev/null)" || true
  while IFS= read -r line; do
    [ -n "$line" ] || continue
    addr="$(printf '%s\n' "$line" | awk '{print $4}')"
    addr="${addr%:*}"; addr="${addr#\[}"; addr="${addr%\]}"
    pid="$(printf '%s\n' "$line" | grep -oE 'pid=[0-9]+' | head -1 | cut -d= -f2)"
    [ -n "$pid" ] || continue
    if [ -z "$bind" ]; then
      printf '%s %s\n' "$pid" "$addr"; return 0
    fi
    case "$addr" in
      "$bind"|0.0.0.0|"*"|"::")
        printf '%s %s\n' "$pid" "$addr"; return 0;;
    esac
  done <<EOF
$ss_out
EOF
  return 0
}

start(){ # name port bind cmd...
  local name="$1" port="$2" bind="$3"; shift 3
  local pf="$LOG/$name.pid" holder holder_addr
  holder="$(port_holder "$port" "$bind" || true)"
  holder_addr="${holder#* }"
  holder="${holder%% *}"
  if [ -n "$holder" ]; then
    if [ -f "$pf" ] && [ "$holder" = "$(cat "$pf" 2>/dev/null)" ]; then
      echo "  = $name already running (pid $holder, :$port)"; return
    fi
    echo "  !! $name NOT started — :$port held by foreign pid $holder on $holder_addr ($(ps -o args= -p "$holder" 2>/dev/null | cut -c1-60)). Free it (bench-sims-down.sh / stop the csip demo) or override the port."
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

# BASIC-010-WMAXLIMPCT-RESOLVES-TO-ZERO (lexa-gw/docs/known_issues.json,
# closed 2026-08-25): mbapsdev is inv-secure, this leg's SECOND fixture device
# (controllable:false — the SD-04-excluded, non-CSIP-controlled DER). Its
# declared nameplate used to be 6000W against the site's DERP-SP-001 default
# ceiling of 5000W: internal/authority's LXR-013 worst-case reservation
# correctly reserves an uncontrollable device's FULL nameplate out of the site
# ceiling before dividing the remainder among controllable devices, so a
# 6000W nameplate alone exceeded the whole 5000W ceiling and zeroed every
# controllable device's budget — including inv-plain's, which is what
# BASIC-010 measures. That is LXR-013 working exactly as designed against a
# fixture whose own topology guaranteed it would fire; it was never a product
# defect. 2000W is a realistic nameplate for a second, smaller inverter/
# battery sharing the site (not one that alone dominates the whole site's
# budget) and leaves 3000W of headroom under the 5000W default for the
# reservation math to divide among the controllable fleet instead of zeroing
# it (override via MBAPS_WMAX).
MBAPS_WMAX="${MBAPS_WMAX:-2000}"
echo "Bringing up sims (logs in $LOG, fleet size $SIM_FLEET):"
MODSIM_ARGS=()
[ -n "$MODSIM_BIND" ] && MODSIM_ARGS+=(-bind "$MODSIM_BIND")
# THE DETERMINISTIC WIRE TAP is ON by default in modsim (-tap), and this script
# deliberately does not turn it off. It is what serves GET /ledger, GET /poll
# and GET /poll/wait — the epoch fence and poll barrier the SunSpec Modbus
# CLIENT conformance rows use instead of sleeping through the gateway's poll
# interval. With nothing armed it forwards every byte verbatim (pinned in
# sim/southbound/tap_test.go); pass MODSIM_NO_TAP=1 to take it out of the path
# and get the pre-LAB29-010 byte path back, at the cost of every deterministic
# endpoint answering 501.
[ -n "${MODSIM_NO_TAP:-}" ] && [ "${MODSIM_NO_TAP}" != "0" ] && MODSIM_ARGS+=(-tap=false)
# MODSIM_PROTOFAULT=1 additionally interposes the proto-fault relay, which is
# what §2.8.2 PROT-2 needs to compel a TCP-segmented response (segment_response).
# OFF by default: it is an adversary relay, not a witness, and a shared bench is
# never silently reframed. Turn it on for a conformance capture that has to
# drive PROT-2's headline criterion rather than report it as a launch-flag gap.
[ -n "${MODSIM_PROTOFAULT:-}" ] && [ "${MODSIM_PROTOFAULT}" != "0" ] && MODSIM_ARGS+=(-protofault)
start modsim   "$MODSIM_PORT"  "$MODSIM_BIND" ./bin/modsim   -port "$MODSIM_PORT" -advanced -der-models "$CENSUS_DER_MODELS" -wmax 8000 -serial "$MODSIM_SERIAL" \
                 ${MODSIM_ARGS+"${MODSIM_ARGS[@]}"}
# MBAPS_NO_TICKETS=1 forces every gateway southbound dial to be a FULL mTLS
# handshake (mbapsdev -no-tickets). Leave it OFF for resumption-behaviour runs
# (TCP-46); turn it ON for a conformance capture, so the gateway's client
# certificate — and the SunSpec role extension RBAC-011 reads from it — is on the
# wire on every poll cycle instead of only after the first handshake. Without it,
# steady-state sessions RESUME and RBAC-011 has no client Certificate to cite.
MBAPS_ARGS=()
[ -n "${MBAPS_NO_TICKETS:-}" ] && [ "${MBAPS_NO_TICKETS}" != "0" ] && MBAPS_ARGS+=(-no-tickets)
[ -n "$SIMS_KEYLOG" ] && MBAPS_ARGS+=(-keylog "$SIMS_KEYLOG")
start mbapsdev "$MBAPS_PORT"   "$MBAPS_BIND" "$MBAPS_BIN" -listen "$MBAPS_BIND:$MBAPS_PORT" -model inverter -wmax "$MBAPS_WMAX" -serial "$MBAPS_SERIAL" \
                 -ca "$M/dev-ca.pem" -cert "$M/dev-server-cert.pem" -key "$M/dev-server-key.pem" \
                 ${MBAPS_ARGS+"${MBAPS_ARGS[@]}"}

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
  start modsim2 "$MODSIM2_PORT" "$MODSIM_BIND" ./bin/modsim -port "$MODSIM2_PORT" -api-port "$MODSIM2_API" \
                 -advanced ${DER_MODELS:+-der-models "$DER_MODELS"} -wmax 8000 -serial "$MODSIM2_SERIAL" \
                 ${MODSIM_ARGS+"${MODSIM_ARGS[@]}"}
  start modsim3 "$MODSIM3_PORT" "$MODSIM_BIND" ./bin/modsim -port "$MODSIM3_PORT" -api-port "$MODSIM3_API" \
                 -advanced ${DER_MODELS:+-der-models "$DER_MODELS"} -wmax 8000 -serial "$MODSIM3_SERIAL" \
                 ${MODSIM_ARGS+"${MODSIM_ARGS[@]}"}
fi
GRIDSIM_ARGS=()
[ "$GRIDSIM_FLEET" != 0 ] && GRIDSIM_ARGS+=(-fleet "$GRIDSIM_FLEET")
if [ "$GRIDSIM_SUBSCRIPTION" != 0 ]; then
  GRIDSIM_ARGS+=(-subscription)
  # The notification leg's CLIENT identity. A Notification travels on a
  # connection gridsim OPENS to the subscriber, so on that leg the simulator is
  # the mTLS client and needs a client certificate — not the one it serves with.
  # Without it an https:// notificationURI is refused (Go's crypto/tls has no
  # ECDHE-ECDSA-AES128-CCM-8) and the conformance suite reports every
  # notification criterion as unmeasured, naming this flag.
  #
  # grid-service is the bench's existing northbound client identity, signed by
  # the same CA the sims already use. Override with GRIDSIM_NOTIFY_CERT/KEY.
  GRIDSIM_NOTIFY_CERT="${GRIDSIM_NOTIFY_CERT:-$M/clients/grid-service-cert.pem}"
  GRIDSIM_NOTIFY_KEY="${GRIDSIM_NOTIFY_KEY:-$M/clients/grid-service-key.pem}"
  if [ -r "$GRIDSIM_NOTIFY_CERT" ] && [ -r "$GRIDSIM_NOTIFY_KEY" ]; then
    GRIDSIM_ARGS+=(-notify-cert "$GRIDSIM_NOTIFY_CERT" -notify-key "$GRIDSIM_NOTIFY_KEY")
  else
    echo "  ! no notification client identity at $GRIDSIM_NOTIFY_CERT — an https:// notificationURI"
    echo "    will be REFUSED and every notification criterion will report unmeasured. Set"
    echo "    GRIDSIM_NOTIFY_CERT/GRIDSIM_NOTIFY_KEY, or use an http:// listener."
  fi
fi
[ -n "$SIMS_KEYLOG" ] && GRIDSIM_ARGS+=(-keylog "$SIMS_KEYLOG")
[ -n "$GRIDSIM_NO_TICKETS" ] && [ "$GRIDSIM_NO_TICKETS" != 0 ] && GRIDSIM_ARGS+=(-no-tickets)
[ -n "$GRIDSIM_IDLE_S" ] && GRIDSIM_ARGS+=(-idle-timeout-s "$GRIDSIM_IDLE_S")
[ -n "$GRIDSIM_POLL_S" ] && GRIDSIM_ARGS+=(-poll-rate-s "$GRIDSIM_POLL_S")
start gridsim  "$GRIDSIM_PORT" "$GRIDSIM_BIND" "$GRIDSIM_BIN" -listen "$GRIDSIM_BIND:$GRIDSIM_PORT" -admin "$GRIDSIM_BIND:$GRIDSIM_ADMIN" \
                 -ca "$M/ca-cert.pem" -cert-chain "$M/dev-server-cert.pem" -key "$M/dev-server-key.pem" \
                 ${GRIDSIM_ARGS+"${GRIDSIM_ARGS[@]}"}

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
  cat <<EOF
NOTE (SIM_FLEET=4): gridsim now serves the NORTHBOUND half of the CTP Figure-15
fixture (-fleet $GRIDSIM_FLEET, subscription=$GRIDSIM_SUBSCRIPTION); verify with
  curl -s localhost:$GRIDSIM_ADMIN/admin/status | jq '.fleet, .subscription'
  curl -s localhost:$GRIDSIM_ADMIN/admin/fleet  | jq '.devices'
Notifications the server pushed, and what came back, are at
  curl -s localhost:$GRIDSIM_ADMIN/admin/notifications | jq '.notifications'
An entry with http_status 0 and an "error" naming ECDHE-ECDSA-AES128-CCM-8 means
the notification CLIENT identity is missing — see GRIDSIM_NOTIFY_CERT above.
One thing is still needed and this script cannot do it:
  BOARD: /etc/lexa/modbus.json must list all four devices and lexa-modbus must
  be restarted — see the block at the top of this file for the exact JSON. The
  gateway does not sweep; an unlisted sim is never dialled.
The aggregator rows' NOTIFICATION-PUSH criteria stay SKIP until the DUT's
inbound listener is reachable from gridsim: an https:// notificationURI is
refused by the built-in notifier, because gridsim is pure Go and Go's
crypto/tls has no ECDHE-ECDSA-AES128-CCM-8. See sim/gridsim/subscribe.go and
docs/PROFILE_SCOPE_2026-07-28_der-aggregator-client.md §5.
EOF
fi
if [ "$FAIL" = 0 ]; then echo "All server sims up. Stop with scripts/bench-sims-down.sh"; else
  echo "One or more sims did NOT start (see above). Stop with scripts/bench-sims-down.sh"; exit 1; fi
