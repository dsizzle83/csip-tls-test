#!/usr/bin/env bash
# mayhem-campaign.sh — mode-managed, N-cycle Mayhem campaign with evidence capture.
#
# Wraps the proven mayhem-100.sh loop with explicit hub-timing management so a
# campaign can be run in either FAST (development) or STOCK (release-gate)
# timing: set the mode -> verify it took -> N cycles of the Mayhem suite with
# --json evidence + a human-readable log per cycle -> a summary (per-cycle
# verdict counts + a per-scenario drift table) -> restore FAST unconditionally,
# even on error/Ctrl-C (FAST is the bench's resting state per bench-up.sh).
#
# Usage:
#   scripts/mayhem-campaign.sh --mode fast|stock [--cycles N] [--dashboard URL]
#                               [--only id,id] [--hub-ip IP] [--ssh-user USER]
#
#   --mode fast|stock   (required) hub timing regime for this campaign
#   --cycles N          number of Mayhem runs (default 10)
#   --dashboard URL     dashboard base URL (default http://localhost:8080)
#   --only id,id        passthrough to scripts/mayhem.py (default: full suite)
#   --hub-ip IP         hub Pi address (default 69.0.0.1)
#   --ssh-user USER     SSH user for the hub (default dmitri)
#
# Each cycle runs scripts/mayhem.py TWICE against the bench: once with --json
# for machine-parseable evidence, once in human-readable form (tee'd to a
# .txt log), matching the mayhem-100.sh precedent. That doubles per-cycle
# bench time — expected and accounted for; STOCK cycles are already several
# times longer than FAST (15s/20s/10s ticks vs 3s/5s/2s).
#
# Evidence lands in logs/campaign-<mode>-<timestamp>/:
#   cycle-NN.json         raw --json status per cycle
#   cycle-NN.txt           human-readable report per cycle
#   summary.tsv            per-cycle verdict counts (+ exit code)
#   scenario-drift.tsv     scenario x cycle -> verdict matrix
#   campaign.log           full stdout/stderr transcript
#
# Exit code: 0 if the campaign ran to completion (regardless of individual
# cycle FAIL/BLIND — that's the payload, not a wrapper failure); 1 on
# argument/setup error or if the STOCK/FAST mode verification fails; 2 if a
# cycle reports exit code 2 (mayhem.py run/connection error — bench broken,
# campaign aborted early). The FAST-restore trap always fires.

set -uo pipefail

# A real Ctrl-C in a terminal delivers SIGINT to the whole foreground process
# group — including the `tee` logger spawned below by `exec > >(tee ...)`.
# If that logger dies first, any later `echo`/`printf` in this script would
# raise SIGPIPE and could kill bash before the EXIT trap's restore command
# runs. Ignore SIGPIPE for this script and everything it execs (SIG_IGN is
# preserved across exec, so hub-replay-tune.sh inherits it too) so a dead
# log pipe never aborts the restore. Verified against a real group-SIGINT
# during wrapper testing — see mayhem-campaign.sh test notes.
trap '' PIPE

REPO="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO"

MODE=""
CYCLES=10
DASHBOARD="http://localhost:8080"
ONLY=""
HUB_IP="69.0.0.1"
SSH_USER="dmitri"

usage() {
  cat >&2 <<'EOF'
Usage: scripts/mayhem-campaign.sh --mode fast|stock [--cycles N] [--single-run] [--dashboard URL] [--only id,id] [--hub-ip IP] [--ssh-user USER]
  --single-run: one bench pass per cycle (JSON only; txt is a stub) — halves wall time
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --mode)      MODE="${2:-}"; shift 2 ;;
    --cycles)    CYCLES="${2:-}"; shift 2 ;;
    --single-run) SINGLE_RUN=1; shift ;;
    --dashboard) DASHBOARD="${2:-}"; shift 2 ;;
    --only)      ONLY="${2:-}"; shift 2 ;;
    --hub-ip)    HUB_IP="${2:-}"; shift 2 ;;
    --ssh-user)  SSH_USER="${2:-}"; shift 2 ;;
    -h|--help)   usage; exit 0 ;;
    *) echo "unknown argument: $1" >&2; usage; exit 1 ;;
  esac
done

case "$MODE" in
  fast|stock) ;;
  "") echo "error: --mode fast|stock is required" >&2; usage; exit 1 ;;
  *)  echo "error: --mode must be 'fast' or 'stock', got '$MODE'" >&2; usage; exit 1 ;;
esac

if ! [[ "$CYCLES" =~ ^[0-9]+$ ]] || [[ "$CYCLES" -lt 1 ]]; then
  echo "error: --cycles must be a positive integer, got '$CYCLES'" >&2
  exit 1
fi

TUNE="$REPO/scripts/hub-replay-tune.sh"
MAYHEM_PY="$REPO/scripts/mayhem.py"
TS="$(date +%Y%m%dT%H%M%S)"
OUTDIR="logs/campaign-${MODE}-${TS}"
SUMMARY="$OUTDIR/summary.tsv"
DRIFT="$OUTDIR/scenario-drift.tsv"
CAMPAIGN_LOG="$OUTDIR/campaign.log"

mkdir -p "$OUTDIR"

# Tee everything to campaign.log while still showing it on the terminal.
exec > >(tee -a "$CAMPAIGN_LOG") 2>&1

expected_engine() { [[ "$1" == "fast" ]] && echo 3 || echo 15; }

read_engine_interval() {
  # Best-effort read of /etc/lexa/hub.json's engine_interval_s over SSH.
  # Prints "?" (never fails the caller) if the hub is unreachable.
  ssh -o ConnectTimeout=8 "$SSH_USER@$HUB_IP" \
    'sudo cat /etc/lexa/hub.json 2>/dev/null' 2>/dev/null \
    | python3 -c 'import json,sys
try:
    print(json.load(sys.stdin).get("engine_interval_s", "?"))
except Exception:
    print("?")' 2>/dev/null || echo "?"
}

RESTORED=0
restore_fast() {
  if [[ "$RESTORED" -eq 1 ]]; then return; fi
  RESTORED=1
  # Run the restore itself FIRST, before any status printing. On a real
  # Ctrl-C the `tee` logger (see the SIGPIPE-ignore note above) may already
  # be gone; the actual restore command must not be gated behind output that
  # could fail. SIGPIPE is ignored process-wide, but keep the ordering too.
  local ok=1
  bash "$TUNE" fast "$HUB_IP" "$SSH_USER" || ok=0
  echo ""
  echo "── restoring FAST timing (unconditional) ──────────────────────────────"
  if [[ "$ok" -eq 1 ]]; then
    local now; now="$(read_engine_interval)"
    echo "★★★ mayhem-campaign: bench timing restored to FAST (engine_interval_s=${now}) ★★★"
  else
    echo "★★★ mayhem-campaign: FAST RESTORE FAILED — bench may still be in ${MODE^^} timing." >&2
    echo "★★★ Run manually:  bash scripts/hub-replay-tune.sh fast $HUB_IP $SSH_USER" >&2
  fi
}
trap restore_fast EXIT

echo "=================================================================="
echo "mayhem-campaign: mode=$MODE cycles=$CYCLES dashboard=$DASHBOARD"
[[ -n "$ONLY" ]] && echo "mayhem-campaign: --only $ONLY"
echo "mayhem-campaign: evidence -> $OUTDIR/"
echo "=================================================================="

PRIOR="$(read_engine_interval)"
echo "hub engine_interval_s before this campaign: $PRIOR"

echo ""
echo "── setting hub timing to $MODE ─────────────────────────────────────"
bash "$TUNE" "$MODE" "$HUB_IP" "$SSH_USER"

WANT="$(expected_engine "$MODE")"
GOT="$(read_engine_interval)"
if [[ "$GOT" != "$WANT" ]]; then
  echo "error: hub.json engine_interval_s=$GOT after requesting $MODE (expected $WANT) — aborting campaign" >&2
  exit 1
fi
echo "verified: hub engine_interval_s=$GOT (matches $MODE)"

ONLY_ARGS=()
[[ -n "$ONLY" ]] && ONLY_ARGS=(--only "$ONLY")

echo -e "cycle\ttimestamp\tpass\tdegraded\tfail\tblind\tinconclusive\texit_code" > "$SUMMARY"

for i in $(seq 1 "$CYCLES"); do
  n="$(printf '%02d' "$i")"
  cts="$(date +%Y%m%dT%H%M%S)"
  jsonfile="$OUTDIR/cycle-${n}.json"
  txtfile="$OUTDIR/cycle-${n}.txt"

  echo ""
  echo "[cycle $i/$CYCLES] $(date '+%Y-%m-%d %H:%M:%S') mode=$MODE (json) -> $jsonfile"
  json_exit=0
  python3 "$MAYHEM_PY" --dashboard "$DASHBOARD" "${ONLY_ARGS[@]}" --json > "$jsonfile" || json_exit=$?

  txt_exit=0
  if [[ "${SINGLE_RUN:-0}" -eq 1 ]]; then
    # --single-run (P0-exit gate decision 2026-07-04): one bench pass per
    # cycle; summary + drift tables come from the JSON. Halves wall time.
    echo "(single-run mode: human-readable pass skipped; verdicts in ${jsonfile##*/})" > "$txtfile"
  else
    echo "[cycle $i/$CYCLES] $(date '+%Y-%m-%d %H:%M:%S') mode=$MODE (human) -> $txtfile"
    python3 "$MAYHEM_PY" --dashboard "$DASHBOARD" "${ONLY_ARGS[@]}" 2>&1 | tee "$txtfile" || txt_exit=$?
  fi

  exit_code="$json_exit"
  if [[ "$txt_exit" -gt "$exit_code" ]]; then exit_code="$txt_exit"; fi

  if [[ "$exit_code" -eq 2 ]]; then
    echo "error: cycle $i returned exit 2 (mayhem.py run/connection error) — bench appears broken, aborting campaign" >&2
    echo -e "${i}\t${cts}\tERR\tERR\tERR\tERR\tERR\t${exit_code}" >> "$SUMMARY"
    exit 2
  fi

  read -r cpass cdeg cfail cblind cinc <<< "$(python3 -c '
import json, sys
try:
    with open(sys.argv[1]) as f:
        d = json.load(f)
except Exception:
    print("0 0 0 0 0"); sys.exit()
s = d.get("summary") or {}
print(s.get("pass",0), s.get("degraded",0), s.get("fail",0), s.get("blind",0), s.get("inconclusive",0))
' "$jsonfile")"

  echo -e "${i}\t${cts}\t${cpass}\t${cdeg}\t${cfail}\t${cblind}\t${cinc}\t${exit_code}" >> "$SUMMARY"
  echo "  → P=$cpass D=$cdeg F=$cfail B=$cblind I=$cinc (exit $exit_code)"
done

echo ""
echo "── building scenario drift table ───────────────────────────────────"
python3 - "$OUTDIR" "$CYCLES" > "$DRIFT" <<'PYEOF'
import json, sys, glob, os

outdir, cycles = sys.argv[1], int(sys.argv[2])
verdict_letter = {"PASS": "P", "DEGRADED": "D", "FAIL": "F", "BLIND": "B", "INCONCLUSIVE": "I"}

order = []
by_scenario = {}
for i in range(1, cycles + 1):
    path = os.path.join(outdir, f"cycle-{i:02d}.json")
    findings = []
    if os.path.exists(path):
        try:
            with open(path) as f:
                d = json.load(f)
            findings = d.get("findings") or []
        except Exception:
            findings = []
    seen_this_cycle = set()
    for finding in findings:
        sid = finding.get("id", "?")
        v = finding.get("verdict", "?")
        if sid not in by_scenario:
            by_scenario[sid] = {}
            order.append(sid)
        by_scenario[sid][i] = verdict_letter.get(v, "?")
        seen_this_cycle.add(sid)

header = ["scenario"] + [f"C{n:02d}" for n in range(1, cycles + 1)] + ["fail_count", "sequence"]
print("\t".join(header))
for sid in order:
    row = [sid]
    seq = []
    fail_count = 0
    for i in range(1, cycles + 1):
        v = by_scenario[sid].get(i, "-")
        row.append(v)
        seq.append(v)
        if v == "F":
            fail_count += 1
    row.append(str(fail_count))
    row.append(" ".join(seq))
    print("\t".join(row))
PYEOF

echo "scenario drift table -> $DRIFT"

echo ""
echo "── campaign summary (mode=$MODE, $CYCLES cycles) ──────────────────"
column -t -s $'\t' "$SUMMARY"
python3 - "$SUMMARY" <<'PYEOF'
import csv
import sys

path = sys.argv[1]
tot = dict(pass_=0, degraded=0, fail=0, blind=0, inconclusive=0, n=0)
with open(path) as f:
    r = csv.DictReader(f, delimiter="\t")
    for row in r:
        if row["fail"] == "ERR":
            continue
        tot["pass_"] += int(row["pass"])
        tot["degraded"] += int(row["degraded"])
        tot["fail"] += int(row["fail"])
        tot["blind"] += int(row["blind"])
        tot["inconclusive"] += int(row["inconclusive"])
        tot["n"] += 1
n = tot["n"]
if n:
    avg_pass = tot["pass_"] / n
    avg_deg = tot["degraded"] / n
    avg_fail = tot["fail"] / n
    avg_blind = tot["blind"] / n
    avg_inc = tot["inconclusive"] / n
    print(f"\navg over {n} cycle(s): "
          f"PASS={avg_pass:.1f}  DEGRADED={avg_deg:.1f}  "
          f"FAIL={avg_fail:.1f}  BLIND={avg_blind:.1f}  "
          f"INCONCLUSIVE={avg_inc:.1f}")
PYEOF

echo ""
echo "Evidence: $OUTDIR/ (cycle-NN.json, cycle-NN.txt, summary.tsv, scenario-drift.tsv, campaign.log)"
echo "mayhem-campaign: done (mode=$MODE, $CYCLES cycles)."
