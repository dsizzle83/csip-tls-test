#!/bin/bash
# Deterministic-regression run mode for the hostile-QA suite (Phase 5).
#
# Unit mode (default): runs the fault-injector and diagnoser unit tests — fast,
# no bench, suitable for a per-commit CI gate. Exits non-zero on any failure.
#
# Bench mode (--bench <dashboard-url> [--matrix]): additionally runs the live
# mayhem suite against a bench (or the fault-matrix mode with --matrix), gating
# on its exit code (0 = no FAIL/BLIND).
#
# Usage:
#   scripts/qa-regression.sh                                  # unit gate (CI)
#   scripts/qa-regression.sh --bench http://69.0.0.20:8080    # + curated suite
#   scripts/qa-regression.sh --bench http://69.0.0.20:8080 --matrix
set -euo pipefail
HERE="$(cd "$(dirname "$0")/.." && pwd)"
cd "$HERE"

echo "== QA unit regression: fault injectors + diagnosers =="
# -race (WS-7, HANDOFF §8): cmd/dashboard is concurrency-heavy (mayhem engine,
# SSE /logs, WS handlers) and had no race coverage anywhere in CI. Needs
# CGO_ENABLED=1 (cgo, not the wolfSSL sysroot); the caller (CI's pure-go job)
# overrides the job-level CGO_ENABLED=0 for this step. Native local runs
# default CGO_ENABLED=1 already (no cross-compile), so this is a no-op change
# for `make qa` on a dev machine.
go test -race ./sim/southbound/... ./sim/evsim/... ./sim/gridsim/... ./cmd/dashboard/...
echo "== QA unit regression: PASS =="

if [[ "${1:-}" == "--bench" ]]; then
  BENCH="${2:?usage: qa-regression.sh --bench <dashboard-url> [--matrix]}"
  MODE="${3:-}"
  echo "== QA bench suite via $BENCH ${MODE} =="
  exec "$HERE/scripts/mayhem.py" --dashboard "$BENCH" ${MODE}
fi
