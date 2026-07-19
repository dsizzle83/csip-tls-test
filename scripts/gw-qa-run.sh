#!/usr/bin/env bash
# gw-qa-run.sh — run the gw-mayhem hostile-QA suite against the LIVE gateway with a
# clean, ISOLATED session budget, then restore the bench.
#
# Why this wrapper exists (2026-07-19): the standing aggregator loop that
# bench-sims-up.sh starts is BOTH
#   (1) a competing control authority — it curtails the very DER the control-loop
#       family (control-rapid-recurtail / -reversion-timer / -conflicting) drives,
#       so its setpoints race the QA's readbacks and manufacture false FAILs; and
#   (2) a consumer of the gateway's CAPPED mbaps session budget (max_sessions=8) —
#       its residual sessions, left over the instant the loop is killed, starve the
#       first few authz/transport scenarios' connects (the gateway refuses an
#       over-cap session POST-handshake, so the client's first read fails with
#       wolfSSL_read -1 / "no SunS header").
# Together these produced a spurious 8-gate-failure run; the identical suite is
# GATE PASS once the aggregator is paused AND the session table has drained. This
# wrapper enforces that isolation so a bench QA run is deterministic. (The runner
# is ALSO hardened to ride out transient cap pressure via connectAsReady — this
# wrapper removes the SUSTAINED pressure + the competing-authority conflict that
# no client-side retry can paper over.)
#
# Usage:  scripts/gw-qa-run.sh [gw-mayhem flags...]
#   e.g.  scripts/gw-qa-run.sh -json -out logs/gw-mayhem/run.json
#         scripts/gw-qa-run.sh -only control-rapid-recurtail
#         scripts/gw-qa-run.sh -board-armed authority-switch-honors-exclusive -only authority-switch-honors-exclusive
# GW_HOST (default 69.0.0.2), GW_SSH (default cc93), NO_RESUME=1 to leave the
# aggregator paused after the run.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"; cd "$HERE"
GW_HOST="${GW_HOST:-69.0.0.2}"
SSH="${GW_SSH:-cc93}"
LOG="${BENCH_LOG:-$HERE/logs/bench}"
AGG_PID="$LOG/aggregator.pid"

export CGO_CFLAGS="${CGO_CFLAGS:--I$HOME/.local/wolfssl-amd64/include}"
export CGO_LDFLAGS="${CGO_LDFLAGS:--L$HOME/.local/wolfssl-amd64/lib -lm}"
[ -x bin/gw-mayhem ] || { echo "building bin/gw-mayhem ..."; go build -o bin/gw-mayhem ./cmd/gw-mayhem; }

# count ESTABLISHED sessions to the gateway's :802 (port 802 = hex 0322) via the
# board's /proc/net/tcp — busybox has no `ss` on the non-login PATH.
gw_sessions(){ ssh "$SSH" 'awk "\$2 ~ /:0322\$/ && \$4==\"01\"{n++} END{print n+0}" /proc/net/tcp' 2>/dev/null || echo "?"; }

pause_aggregator(){
  if [ -f "$AGG_PID" ]; then
    local p; p="$(cat "$AGG_PID" 2>/dev/null || true)"
    if [ -n "$p" ]; then kill "$p" 2>/dev/null || true; pkill -P "$p" 2>/dev/null || true; fi
    rm -f "$AGG_PID"
  fi
  pkill -f 'bin/aggregator -target' 2>/dev/null || true
}

resumed=0
resume_aggregator(){
  [ "$resumed" = 1 ] && return; resumed=1
  [ "${NO_RESUME:-0}" = 1 ] && { echo "gw-qa-run: NO_RESUME=1 — leaving aggregator paused"; return; }
  echo "gw-qa-run: restoring the standing aggregator loop ..."
  # bench-sims-up.sh is idempotent: the live sims are left untouched, only the
  # now-dead aggregator loop is restarted (single source of truth for its invocation).
  WITH_AGG=1 bash scripts/bench-sims-up.sh >/dev/null 2>&1 || echo "  (bench-sims-up.sh reported non-zero — check logs/bench)"
}
trap resume_aggregator EXIT INT TERM

echo "gw-qa-run: pausing the standing aggregator + draining the :802 session budget ..."
pause_aggregator
for i in $(seq 1 40); do
  n="$(gw_sessions)"
  if [ "$n" = 0 ]; then echo "  :802 drained (0 live sessions)"; break; fi
  echo "  waiting for :802 to drain ($n live) ..."; sleep 0.5
  [ "$i" = 40 ] && echo "  WARNING: :802 still shows $n live after 20s — running anyway (connectAsReady will ride out residual pressure)"
done

echo "gw-qa-run: running  gw-mayhem -target ${GW_HOST}:802 $*"
set +e
./bin/gw-mayhem -target "${GW_HOST}:802" "$@"
rc=$?
set -e
resume_aggregator
exit "$rc"
