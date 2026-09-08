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
# -race (WS-7, HANDOFF §8): needs CGO_ENABLED=1 (cgo, not the wolfSSL
# sysroot); the caller (CI's pure-go job) overrides the job-level
# CGO_ENABLED=0 for this step. Native local runs default CGO_ENABLED=1
# already (no cross-compile), so this is a no-op change for `make qa` on a
# dev machine.
#
# WP7-T1 (REV0907-E1/H8/E10): ./sim/evsim/... and ./cmd/dashboard/... dropped
# from this line — neither is reachable from cmd/certify or cmd/gw-campaign
# (the certify live set; `go list -deps` confirms it, see the
# CERTIFY_LIVE_SET comment in the Makefile), so their -race time here was
# never proving anything about the thing this repo ships as a conformance
# tool. cmd/dashboard's own -race coverage (added under WS-7 for exactly this
# line — "concurrency-heavy... had no race coverage anywhere in CI") is a
# real loss, not a wash: flagged as a gap for the dashboard's own QA plan,
# restoring it elsewhere is not this task's scope.
#
# ./sim/southbound/... and ./sim/gridsim/... stay: sim/southbound IS in the
# live set (cmd/gw-campaign's world.go imports it directly for its in-process
# Modbus device). sim/gridsim is NOT in the live set by import (cmd/certify
# and cmd/gw-campaign never import it) but IS a genuine build/test-time
# dependency of internal/certify/suitecsip's own _test.go files (13 of them
# import it directly to grow the fixture EndDevice tree the CSIP oracle
# suites exercise) — `go test ./internal/certify/suitecsip` will not compile
# without it, so it stays covered here for the same reason internal/mbtls
# does not need re-deriving: it is load-bearing for a live-set package's own
# tests, one hop removed from cmd/certify/cmd/gw-campaign's own import graph
# rather than in it.
go test -race ./sim/southbound/... ./sim/gridsim/...
echo "== QA unit regression: PASS =="

if [[ "${1:-}" == "--bench" ]]; then
  BENCH="${2:?usage: qa-regression.sh --bench <dashboard-url> [--matrix]}"
  MODE="${3:-}"
  echo "== QA bench suite via $BENCH ${MODE} =="
  exec "$HERE/scripts/mayhem.py" --dashboard "$BENCH" ${MODE}
fi
