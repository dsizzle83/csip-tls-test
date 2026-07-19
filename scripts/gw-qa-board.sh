#!/usr/bin/env bash
# gw-qa-board.sh — orchestrate ONE Family-D (board-mutating) gw-mayhem scenario:
# pause the standing aggregator, ARM the board mutation, run the scenario's Go
# OBSERVE arm with -board-armed, TEARDOWN (restore the resting state), resume the
# aggregator. A trap guarantees teardown + aggregator restore even on error/^C, so
# the bench is never left mutated.
#
# The board is the CC93 (busybox: no jq/sponge/curl; python3 IS present) with
# lexa-gw configs under /etc/lexa and services lexa-{mode,mbaps,certmgr,...}. The
# board-hooks.md commands are the IDEALISED form; the arm/teardown here are the
# real-board equivalents (python3 JSON edits, real service names/paths).
#
# Usage:  scripts/gw-qa-board.sh <scenario-id>
#   scenario-id ∈ { authority-switch-honors-exclusive,
#                   privacy-switch-vendor-access,
#                   service-restart-mid-cap }
# The two PKI-mutating scenarios (cert-rotation-mid-session,
# trust-store-tamper-failclosed) are intentionally NOT automated here: their
# teardown needs verified rotate/reseal tooling over the certmgr unix socket, and
# a botched reseal wedges the whole mbaps stack — run them by hand under
# supervision. See board-hooks.md.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"; cd "$HERE"
SSH="${GW_SSH:-cc93}"
GW_HOST="${GW_HOST:-69.0.0.2}"
LOG="${BENCH_LOG:-$HERE/logs/bench}"
AGG_PID="$LOG/aggregator.pid"
OUT="${OUT:-$HERE/logs/gw-mayhem/board-$1.txt}"
mkdir -p "$(dirname "$OUT")"
ID="${1:?scenario-id required}"

export CGO_CFLAGS="${CGO_CFLAGS:--I$HOME/.local/wolfssl-amd64/include}"
export CGO_LDFLAGS="${CGO_LDFLAGS:--L$HOME/.local/wolfssl-amd64/lib -lm}"
[ -x bin/gw-mayhem ] || go build -o bin/gw-mayhem ./cmd/gw-mayhem

pause_aggregator(){
  if [ -f "$AGG_PID" ]; then local p; p="$(cat "$AGG_PID" 2>/dev/null||true)"
    [ -n "$p" ] && { kill "$p" 2>/dev/null||true; pkill -P "$p" 2>/dev/null||true; }
    rm -f "$AGG_PID"; fi
  pkill -f 'bin/aggregator -target' 2>/dev/null||true
}
resume_aggregator(){ WITH_AGG=1 bash scripts/bench-sims-up.sh >/dev/null 2>&1 || true; }

# set a top-level string/bool field in /etc/lexa/mode.json on the board (python3).
mode_set(){ ssh "$SSH" "python3 - <<PY
import json
p='/etc/lexa/mode.json'; d=json.load(open(p)); d['$1']=$2
json.dump(d,open(p,'w'),indent=2)
PY"; }
mode_get(){ ssh "$SSH" "python3 -c \"import json;print(json.load(open('/etc/lexa/mode.json'))['$1'])\""; }

teardown(){ :; }  # replaced per-scenario below
cleanup(){ echo ">> TEARDOWN + restore"; teardown; resume_aggregator; }
trap cleanup EXIT INT TERM

echo ">> [$ID] pausing aggregator"; pause_aggregator; sleep 1

case "$ID" in
  authority-switch-honors-exclusive)
    teardown(){ mode_set authority '"mbaps"'; ssh "$SSH" 'systemctl restart lexa-mode'; sleep 1; echo "   restored authority=$(mode_get authority)"; }
    echo ">> ARM: authority mbaps->csip"
    mode_set authority '"csip"'; ssh "$SSH" 'systemctl restart lexa-mode'; sleep 2
    echo "   armed: authority=$(mode_get authority) lexa-mode=$(ssh "$SSH" systemctl is-active lexa-mode)"
    ;;
  privacy-switch-vendor-access)
    # resting vendor_access may already be false; drive a true->false TRANSITION so
    # the ≤5s removal is observable. Restore to the ORIGINAL value on teardown.
    ORIG="$(mode_get vendor_access)"   # python bool literal: "True" / "False"
    teardown(){ mode_set vendor_access "$ORIG"; ssh "$SSH" 'systemctl reload-or-restart lexa-mode'; sleep 1; echo "   restored vendor_access=$(mode_get vendor_access)"; }
    echo ">> ARM: vendor_access -> True (seed), then -> False (the transition under test)"
    mode_set vendor_access True;  ssh "$SSH" 'systemctl reload-or-restart lexa-mode'; sleep 3
    mode_set vendor_access False; ssh "$SSH" 'systemctl reload-or-restart lexa-mode'
    echo "   armed: vendor_access=$(mode_get vendor_access)"
    ;;
  service-restart-mid-cap)
    SVC="${RESTART_SVC:-lexa-mbaps}"
    teardown(){ echo "   releasing cap (aggregator curtail campaign final step -> 100%)";
      ./bin/aggregator -target "${GW_HOST}:802" -role GridServiceSunSpec -pki certs/mbaps \
        -campaign qa/aggregator/curtail-solar-50.json >/dev/null 2>&1 || true; }
    echo ">> ARM: set an active cap (curtail 50%) then restart $SVC"
    ./bin/aggregator -target "${GW_HOST}:802" -role GridServiceSunSpec -pki certs/mbaps \
      -campaign qa/aggregator/curtail-solar-50.json >/dev/null 2>&1 || echo "   (cap campaign rc=$?)"
    ssh "$SSH" "systemctl restart $SVC"; sleep 2
    echo "   armed: $SVC=$(ssh "$SSH" systemctl is-active $SVC)"
    ;;
  *) echo "unknown/gated board scenario: $ID (see board-hooks.md)"; exit 2 ;;
esac

echo ">> OBSERVE: gw-mayhem -board-armed $ID -only $ID"
./bin/gw-mayhem -target "${GW_HOST}:802" -board-armed "$ID" -only "$ID" > "$OUT" 2>&1
rc=$?
echo "---- verdict ----"; grep -E '^\[|Roll-up|ok |FAIL|refus|accept|held|revert|recover' "$OUT" | head -20
echo "(full log: $OUT)"
exit $rc