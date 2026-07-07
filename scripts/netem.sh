#!/usr/bin/env bash
# netem.sh — tc netem packet-chaos primitive for the bench Pis (GAP-11,
# TASK-052). Applies loss/reorder/delay/jitter to a bench Pi's LAN-facing
# interface over SSH, with a mandatory self-healing scheduled reset so a lost
# teardown (aborted run, dashboard crash) still clears itself. Reusable by
# cmd/dashboard's mayhem netem scenarios (mayhem_world.go builds/executes the
# equivalent remote command directly over its own SSH plumbing) and by
# TASK-078's soak background-netem windows.
#
# Usage:
#   netem.sh <pi-ip> apply "<netem-args>" <auto_reset_s> [--dry-run]
#   netem.sh <pi-ip> reset [--dry-run]
#
# Examples:
#   netem.sh 69.0.0.11 apply "loss 5% delay 50ms 10ms" 60
#   netem.sh 69.0.0.11 apply "loss 5% delay 50ms 10ms" 60 --dry-run   # print only
#   netem.sh 69.0.0.11 reset
#
# apply:
#   1. Discovers the target's bench-LAN interface via
#      `ip -o route get <peer-ip>` and uses its `dev` — NEVER the default
#      route. The bench Pis are dual-homed (a WiFi uplink is their default
#      route); netem on the wrong iface silently no-ops, and every scenario
#      that relies on it would report a false PASS. The peer used depends on
#      the target (see PEER selection below); applying netem itself does not
#      self-check the effect — that's done by the Go driver's ping-RTT delta
#      check (mayhem_world.go netemModifier) before it trusts the apply.
#   2. Runs `sudo -n tc qdisc replace dev <iface> root netem <netem-args>`.
#      `replace` (not `add`) so re-arming an already-active profile does not
#      error. `sudo -n` so a node without passwordless sudo fails fast
#      instead of hanging on a password prompt inside an automated caller.
#   3. Schedules the self-healing reset in a background subshell
#      (`(sleep <auto_reset_s>; tc qdisc del ...) >/dev/null 2>&1 &`), so it
#      fires even if this script, its SSH session, or the caller process
#      dies before running `reset`. This is the safety net; an explicit
#      `reset` (or the caller's own teardown) is the fast path. Deliberately
#      NOT `disown` — that's not a builtin on a POSIX /bin/sh (e.g. dash),
#      which some Pi images use as /bin/sh; plain `&` with fds redirected to
#      /dev/null is the portable, tested idiom.
#
# reset:
#   Discovers the same iface and runs
#   `sudo -n tc qdisc del dev <iface> root 2>/dev/null || true` — idempotent,
#   safe to call when no qdisc is present (already clean, or the self-heal
#   already fired).
#
# Peer selection for iface discovery (see docs/BENCH.md for the bench map):
#   target 69.0.0.1  (hub)         -> peer 69.0.0.10 (solar-pi)
#   any other target (sim Pi)      -> peer 69.0.0.20 (desktop / gridsim)
# A sim Pi's only interesting bench link is to the desktop (gridsim northbound
# is desktop-hosted); the hub's is to a sim. Either peer resolves to the
# single real bench-LAN iface on a healthy dual-homed Pi.
#
# NEVER target 69.0.0.20 (the desktop) — it hosts gridsim AND the dashboard
# that is likely the very thing invoking this script; netem there would sever
# the dashboard's own network path and the SSH session trying to fix it. This
# is a hard guard, not a suggestion — do not remove it.
#
# --dry-run prints the exact remote script this run would execute (no SSH
# connection is made) — the manual verification path when no bats/go-test
# harness covers shell scripts in this repo: run
#   scripts/netem.sh 69.0.0.11 apply "loss 5% delay 50ms 10ms" 60 --dry-run
# and confirm the printed commands contain the floor/guard properties this
# header documents (replace not add, sudo -n, the self-heal subshell, the
# correct peer route lookup) before trusting a live apply.
set -uo pipefail

DESKTOP_IP="69.0.0.20"
HUB_IP="69.0.0.2"   # ConnectCore 93 dev-kit hub (lexa-hub/DEVKIT.md)
DEFAULT_SIM_PEER="69.0.0.10" # solar-pi; any provisioned sim Pi works as the hub's peer
SSHUSER="${NETEM_SSH_USER:-dmitri}"

usage() {
  cat >&2 <<'USAGE'
usage: netem.sh <pi-ip> apply "<netem-args>" <auto_reset_s> [--dry-run]
       netem.sh <pi-ip> reset [--dry-run]
USAGE
  exit 2
}

[[ $# -ge 2 ]] || usage
PI="$1"
CMD="$2"
shift 2

if [[ "$PI" == "$DESKTOP_IP" ]]; then
  echo "netem.sh: refusing target $DESKTOP_IP — that is the desktop (gridsim + dashboard). Applying netem there would cut the dashboard and this SSH session. Never target it." >&2
  exit 2
fi

# Peer used purely for `ip -o route get` iface discovery — never the target's
# own default route (see header).
if [[ "$PI" == "$HUB_IP" ]]; then
  PEER="$DEFAULT_SIM_PEER"
else
  PEER="$DESKTOP_IP"
fi

DRYRUN=0
case "$CMD" in
apply)
  [[ $# -ge 2 ]] || usage
  ARGS="$1"
  AUTORESET="$2"
  [[ "${3:-}" == "--dry-run" ]] && DRYRUN=1
  ;;
reset)
  [[ "${1:-}" == "--dry-run" ]] && DRYRUN=1
  ;;
*)
  usage
  ;;
esac

# The remote script: pure text built here, then piped to `ssh ... bash -s`
# (or printed, for --dry-run) as a single connection. $PEER/$ARGS/$AUTORESET
# are substituted NOW (this shell); $IFACE is escaped so it is resolved on
# the REMOTE side only.
iface_discover='IFACE=$(ip -o route get '"$PEER"' 2>/dev/null | awk '"'"'{for(i=1;i<=NF;i++) if ($i=="dev"){print $(i+1); exit}}'"'"'); if [ -z "$IFACE" ]; then echo "netem: could not discover iface via ip -o route get '"$PEER"' (never falls back to the default route)" >&2; exit 1; fi; echo "netem: using iface $IFACE (peer '"$PEER"')" >&2'

case "$CMD" in
apply)
  remote_script="set -e
$iface_discover
sudo -n tc qdisc replace dev \"\$IFACE\" root netem $ARGS
sudo -n sh -c '(sleep $AUTORESET; tc qdisc del dev '\"\$IFACE\"' root) >/dev/null 2>&1 &'
echo \"netem: applied '$ARGS' on \$IFACE, self-heal in ${AUTORESET}s\" >&2"
  ;;
reset)
  remote_script="set -e
$iface_discover
sudo -n tc qdisc del dev \"\$IFACE\" root 2>/dev/null || true
echo \"netem: reset \$IFACE\" >&2"
  ;;
esac

if [[ "$DRYRUN" == "1" ]]; then
  echo "# dry-run — would run over: ssh -o BatchMode=yes -o ConnectTimeout=4 $SSHUSER@$PI 'bash -s'"
  echo "$remote_script"
  exit 0
fi

ssh -o BatchMode=yes -o ConnectTimeout=4 "$SSHUSER@$PI" 'bash -s' <<EOF
$remote_script
EOF
