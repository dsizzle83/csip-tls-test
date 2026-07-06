#!/bin/bash
# cert-churn-soak.sh — TASK-073 / RSK-07 reconnect-churn soak driver.
#
# Drives lexa-northbound on the hub Pi through N cert rotations/hour for a
# configurable duration (default 12/hour x 24h = 288 rotations), alternating
# between two cert FILE PATHS with the SAME LFDI (see
# docs/CERT_ROTATION_SOAK_RUNBOOK.md's "Why alternating cert A/B is trickier
# than it sounds" — a genuinely different cert would legitimately trip the
# LFDI-mismatch refusal every cycle; this soak is about wolfSSL fd/lifecycle
# churn, not the re-enrollment path), while sampling RSS/fd/restart-count
# every 5 minutes and FAILING IMMEDIATELY if lexa-northbound restarts
# (segfault or otherwise) — see the "must FAIL the soak on restart, not
# silently re-resolve" note in the runbook and in this script's sampling
# loop below.
#
# THIS SCRIPT IS NOT RUN AS PART OF TASK-073's implementation session — the
# 24h soak is bench time, deferred per this program's soak-gating
# convention. It is written to be run precisely, standalone, in its own
# dedicated bench session (never during a Mayhem campaign or Bench Replay
# run — bench contention, and it pollutes both the campaign's timing
# assumptions and this soak's fd/RSS baseline).
#
# Usage:
#   bash scripts/cert-churn-soak.sh <hub-pi-ip> \
#     [--rotations-per-hour N] [--duration-hours H] [--ssh-user U] \
#     [--cn CN]
#
# Prerequisites:
#   - lexa-hub deployed to <hub-pi-ip> with TASK-073's RotationController
#     (cmd/northbound/rotate.go) built in.
#   - The bench device is already enrolled with gridsim under some CN (the
#     cert currently live at /etc/lexa/certs/client.pem on the Pi). Pass
#     --cn if it differs from the default csip-test-der-001
#     (scripts/gen-client-cert.sh's own default).
#   - lexa-hub checked out as a sibling directory (../lexa-hub) so this
#     script can invoke its scripts/rotate-cert.sh.
#
# Output: docs/CERT_ROTATION_SOAK_<UTC-start-timestamp>.csv (one row per
# 5-minute sample) plus a matching .md summary written on completion (clean
# 24h) OR on early failure (a restart/segfault detected mid-soak — the
# summary still gets written, marked FAIL, with the sample count reached).
set -euo pipefail

PI="${1:?usage: cert-churn-soak.sh <hub-pi-ip> [--rotations-per-hour N] [--duration-hours H] [--ssh-user U] [--cn CN]}"
shift

ROTATIONS_PER_HOUR=12
DURATION_HOURS=24
SSHUSER=dmitri
CN=csip-test-der-001
SAMPLE_INTERVAL_S=300 # 5 minutes

while [[ $# -gt 0 ]]; do
  case "$1" in
    --rotations-per-hour) ROTATIONS_PER_HOUR="$2"; shift 2 ;;
    --duration-hours)     DURATION_HOURS="$2";     shift 2 ;;
    --ssh-user)            SSHUSER="$2";             shift 2 ;;
    --cn)                  CN="$2";                  shift 2 ;;
    *) echo "unknown arg: $1" >&2; exit 1 ;;
  esac
done

HERE="$(cd "$(dirname "$0")/.." && pwd)"
LEXAHUB="$(cd "$HERE/../lexa-hub" && pwd)"
ROTATE_SCRIPT="$LEXAHUB/scripts/rotate-cert.sh"
[[ -x "$ROTATE_SCRIPT" ]] || { echo "error: $ROTATE_SCRIPT not found/executable — deploy TASK-073's lexa-hub branch first" >&2; exit 1; }

STAGE="$HERE/certs/client-staging"
START_TS="$(date -u +%Y%m%dT%H%M%SZ)"
CSV="$HERE/docs/CERT_ROTATION_SOAK_${START_TS}.csv"
SUMMARY="$HERE/docs/CERT_ROTATION_SOAK_${START_TS}.md"

echo "== cert-churn-soak: $PI, ${ROTATIONS_PER_HOUR}/hour for ${DURATION_HOURS}h =="
echo "   CSV:     $CSV"
echo "   Summary: $SUMMARY"

echo "-- Preparing cert A (fresh, CN=$CN) and cert B (byte-identical copy, different path)"
bash "$HERE/scripts/gen-client-cert.sh" "$CN"
CERT_A="$STAGE/client-cert.pem"
KEY_A="$STAGE/client-key.pem"
CERT_B="$STAGE/client-cert-b.pem"
KEY_B="$STAGE/client-key-b.pem"
cp "$CERT_A" "$CERT_B"
cp "$KEY_A" "$KEY_B"

echo "-- Establishing baseline: rotating onto cert A once before the soak proper starts"
bash "$ROTATE_SCRIPT" "$PI" "$CERT_A" "$KEY_A" "$SSHUSER"

echo "ts_utc,rotation_count,pid,rss_kb,fd_count,nrestarts,wolfssl_err_lines" > "$CSV"

get_pid() { ssh "$SSHUSER@$PI" "systemctl show lexa-northbound -p MainPID --value"; }
get_nrestarts() { ssh "$SSHUSER@$PI" "systemctl show lexa-northbound -p NRestarts --value"; }
get_rss_kb() { ssh "$SSHUSER@$PI" "ps -o rss= -p $1" 2>/dev/null | tr -d ' ' || echo ""; }
get_fd_count() { ssh "$SSHUSER@$PI" "ls /proc/$1/fd 2>/dev/null | wc -l" || echo ""; }

BASELINE_PID="$(get_pid)"
BASELINE_NRESTARTS="$(get_nrestarts)"
echo "   baseline PID=$BASELINE_PID NRestarts=$BASELINE_NRESTARTS"

TOTAL_SECONDS=$((DURATION_HOURS * 3600))
ROTATION_INTERVAL_S=$((3600 / ROTATIONS_PER_HOUR))
ELAPSED=0
ROTATION_COUNT=0
NEXT_ROTATION_AT=0
LAST_JOURNAL_TS="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
FAILED=0
FAIL_REASON=""

while (( ELAPSED < TOTAL_SECONDS )); do
  # --- restart/segfault check FIRST, every sample — see the runbook's
  # "must FAIL the soak on restart, not silently re-resolve" note. This
  # explicitly compares against the PREVIOUS known-good PID/NRestarts,
  # rather than trusting whatever `systemctl show` returns right now as if
  # it were always the same long-lived process.
  CURRENT_PID="$(get_pid)"
  CURRENT_NRESTARTS="$(get_nrestarts)"
  if [[ "$CURRENT_NRESTARTS" != "$BASELINE_NRESTARTS" ]]; then
    FAILED=1
    FAIL_REASON="NRestarts changed ($BASELINE_NRESTARTS -> $CURRENT_NRESTARTS) at rotation $ROTATION_COUNT, elapsed ${ELAPSED}s — lexa-northbound restarted (crash or otherwise). Soak FAILED; not silently re-resolving to the new PID."
    echo "FAIL: $FAIL_REASON" >&2
    break
  fi
  if [[ "$CURRENT_PID" != "$BASELINE_PID" ]]; then
    FAILED=1
    FAIL_REASON="MainPID changed ($BASELINE_PID -> $CURRENT_PID) with NRestarts unchanged — unexpected; treating as a failure rather than silently tracking the new PID."
    echo "FAIL: $FAIL_REASON" >&2
    break
  fi

  RSS="$(get_rss_kb "$CURRENT_PID")"
  FDS="$(get_fd_count "$CURRENT_PID")"
  NOW_TS="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  WOLFSSL_ERR_LINES="$(ssh "$SSHUSER@$PI" "journalctl -u lexa-northbound --since '$LAST_JOURNAL_TS' | grep -Ec 'wolfSSL|segfault|SIGSEGV|panic:'" || echo 0)"
  LAST_JOURNAL_TS="$NOW_TS"

  echo "$NOW_TS,$ROTATION_COUNT,$CURRENT_PID,$RSS,$FDS,$CURRENT_NRESTARTS,$WOLFSSL_ERR_LINES" >> "$CSV"
  echo "   [$NOW_TS] rotation=$ROTATION_COUNT pid=$CURRENT_PID rss=${RSS}KB fds=$FDS restarts=$CURRENT_NRESTARTS wolfssl_err_lines=$WOLFSSL_ERR_LINES"

  if (( ELAPSED >= NEXT_ROTATION_AT )); then
    if (( ROTATION_COUNT % 2 == 0 )); then
      bash "$ROTATE_SCRIPT" "$PI" "$CERT_B" "$KEY_B" "$SSHUSER" || echo "   (rotation to B reported non-zero — recorded in next sample's journal grep)"
    else
      bash "$ROTATE_SCRIPT" "$PI" "$CERT_A" "$KEY_A" "$SSHUSER" || echo "   (rotation to A reported non-zero — recorded in next sample's journal grep)"
    fi
    ROTATION_COUNT=$((ROTATION_COUNT + 1))
    NEXT_ROTATION_AT=$((NEXT_ROTATION_AT + ROTATION_INTERVAL_S))
  fi

  sleep "$SAMPLE_INTERVAL_S"
  ELAPSED=$((ELAPSED + SAMPLE_INTERVAL_S))
done

VERDICT="PASS"
if [[ "$FAILED" == "1" ]]; then
  VERDICT="FAIL"
fi

FIRST_ROW="$(sed -n '2p' "$CSV" || true)"
LAST_ROW="$(tail -n1 "$CSV" || true)"

{
  echo "# Cert rotation churn soak — $START_TS"
  echo
  echo "Target: $PI ($SSHUSER)  ·  Rate: ${ROTATIONS_PER_HOUR}/hour  ·  Planned duration: ${DURATION_HOURS}h"
  echo
  echo "**Verdict: $VERDICT**"
  echo
  if [[ "$FAILED" == "1" ]]; then
    echo "Reason: $FAIL_REASON"
    echo
  fi
  echo "Rotations attempted before stopping: $ROTATION_COUNT"
  echo
  echo "First sample: \`$FIRST_ROW\`"
  echo
  echo "Last sample:  \`$LAST_ROW\`"
  echo
  echo "Raw data: \`$(basename "$CSV")\`"
  echo
  echo "Pass criteria (TASK-073): zero segfaults (flat NRestarts), zero"
  echo "watchdog fires, flat fd count, flat RSS, no wolfSSL error lines"
  echo "outside deliberately-induced probe-rejection cycles. Inspect the CSV's"
  echo "fd_count/rss_kb columns for a trend, not just the first/last values —"
  echo "a slow leak may not be visible from the endpoints alone."
} > "$SUMMARY"

echo "== Soak ended: $VERDICT — see $SUMMARY =="
[[ "$VERDICT" == "PASS" ]]
