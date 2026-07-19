#!/usr/bin/env bash
# bench-sims-down.sh — stop the sims started by bench-sims-up.sh.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GW_HOST="${GW_HOST:-69.0.0.2}"
LOG="${BENCH_LOG:-$HERE/logs/bench}"

stop(){
  local name="$1" pf="$LOG/$1.pid" pid
  if [ -f "$pf" ]; then
    pid="$(cat "$pf")"
    if kill -0 "$pid" 2>/dev/null; then kill "$pid" 2>/dev/null && echo "  stopped $name (pid $pid)"; fi
    rm -f "$pf"
  else
    echo "  $name: no pidfile"
  fi
}
echo "Stopping sims:"
stop aggregator
# the aggregator loop may have a live child mid-campaign — reap our specific one:
pkill -f "bin/aggregator -target ${GW_HOST}:802" 2>/dev/null && echo "  reaped aggregator child" || true
stop gridsim
stop mbapsdev
stop modsim
echo "Done."
