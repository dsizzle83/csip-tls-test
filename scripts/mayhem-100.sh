#!/usr/bin/env bash
# Run the Mayhem QA suite 100 times and log each run.
# Usage: bash scripts/mayhem-100.sh [--dashboard URL]
# Results land in logs/mayhem-100/ with one file per run + a summary.

set -euo pipefail

DASHBOARD="${1:-http://localhost:8080}"
OUTDIR="logs/mayhem-100"
SUMMARY="$OUTDIR/summary.tsv"

mkdir -p "$OUTDIR"

echo -e "run\ttimestamp\tpass\tdegraded\tfail\tblind\tinconclusive\texit_code" > "$SUMMARY"

echo "Starting 100 Mayhem runs. Results in $OUTDIR/"
echo "Dashboard: $DASHBOARD"
echo ""

for i in $(seq 1 100); do
    ts=$(date +%Y%m%dT%H%M%S)
    logfile="$OUTDIR/run-$(printf '%03d' "$i")-${ts}.txt"

    echo "[run $i/100] $(date '+%Y-%m-%d %H:%M:%S') → $logfile"

    exit_code=0
    python3 scripts/mayhem.py --dashboard "$DASHBOARD" 2>&1 | tee "$logfile" || exit_code=$?

    pass=$(grep -c '^\[PASS\]'         "$logfile" 2>/dev/null || true)
    deg=$(grep -c '^\[DEGRADED\]'      "$logfile" 2>/dev/null || true)
    fail=$(grep -c '^\[FAIL\]'         "$logfile" 2>/dev/null || true)
    blind=$(grep -c '^\[BLIND\]'       "$logfile" 2>/dev/null || true)
    inc=$(grep -c '^\[INCONCLUSIVE\]'  "$logfile" 2>/dev/null || true)

    echo -e "$i\t$ts\t$pass\t$deg\t$fail\t$blind\t$inc\t$exit_code" >> "$SUMMARY"
    echo "  → P=$pass D=$deg F=$fail B=$blind I=$inc (exit $exit_code)"
    echo ""
done

echo "Done. Summary:"
column -t -s $'\t' "$SUMMARY"
