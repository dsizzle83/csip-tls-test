#!/usr/bin/env bash
# netfault.sh — L3 network-partition + DNS-failure primitives for the bench hub
# (audit docs/QA_COMPLETENESS_AUDIT.md P2-3). netem.sh degrades the wire
# (loss/reorder/delay); this SEVERS it — a genuine partition (iptables DROP,
# both directions) and a DNS blackout — the two field events netem cannot model.
# Applied over SSH to the HUB, with a self-healing scheduled reset so a lost
# teardown (aborted run, dashboard crash) still clears it.
#
# Requires passwordless sudo + iptables on the target (the hub is the only bench
# node guaranteed both, per docs/BENCH.md). It cannot self-test here (no root in
# the WSL dev env); use --dry-run to inspect the exact remote commands, and the
# cmd/dashboard mayhem netfault scenarios' survival oracle to confirm the effect
# on a live bench.
#
# Usage:
#   netfault.sh <hub-ip> partition <gridsim-ip> <gridsim-port> <auto_reset_s> [--dry-run]
#   netfault.sh <hub-ip> dns-fail  <auto_reset_s> [--dry-run]
#   netfault.sh <hub-ip> reset [--dry-run]
#
# Examples:
#   netfault.sh 69.0.0.2 partition 69.0.0.20 11111 90     # sever hub↔gridsim for 90s
#   netfault.sh 69.0.0.2 dns-fail 90
#   netfault.sh 69.0.0.2 reset
#
# partition:
#   Blocks TCP to/from <gridsim-ip>:<gridsim-port> ONLY — both directions
#   (OUTPUT --dport, INPUT --sport). Port-scoped on purpose: gridsim (mTLS
#   :11111) AND the dashboard that scrapes the hub's /status (:9100) share the
#   desktop host, so a whole-IP DROP would also blind the survival oracle. This
#   severs the northbound TLS to gridsim while leaving hub:9100 reachable.
#   `-I` (insert at top) so the DROP wins over any ACCEPT; the self-heal deletes
#   the exact same rules.
#
# dns-fail:
#   Backs up /etc/resolv.conf to /etc/resolv.conf.netfault.bak and replaces it
#   with a single black-hole nameserver (192.0.2.1, TEST-NET-1, guaranteed
#   unroutable) so every unicast DNS lookup fails/times out. mDNS/DNS-SD
#   (multicast) is unaffected — this models a lost DNS server, the cheap first
#   cut docs/QA_GAPS_20260701.md flagged (a second gridsim instance for a full
#   DNS-SD flap is still deferred). On an IP-configured bench northbound this
#   mainly proves the hub does not WEDGE on DNS loss; a hostname-configured
#   deployment would exercise the resolve path itself.
#
# reset:
#   Deletes the partition rules (idempotent, `|| true`) AND restores resolv.conf
#   from the backup if present. Safe to call when nothing is armed.
#
# The self-heal subshell mirrors netem.sh: `(sleep N; undo) >/dev/null 2>&1 &`,
# fds redirected, NO `disown` (not a POSIX /bin/sh builtin) — the portable idiom.
set -uo pipefail

DESKTOP_IP="69.0.0.20"
SSHUSER="${NETFAULT_SSH_USER:-${NETEM_SSH_USER:-dmitri}}"
RESOLV_BAK="/etc/resolv.conf.netfault.bak"
DNS_BLACKHOLE="192.0.2.1" # TEST-NET-1 (RFC 5737) — guaranteed unroutable

usage() {
  cat >&2 <<'USAGE'
usage: netfault.sh <hub-ip> partition <gridsim-ip> <gridsim-port> <auto_reset_s> [--dry-run]
       netfault.sh <hub-ip> dns-fail  <auto_reset_s> [--dry-run]
       netfault.sh <hub-ip> reset [--dry-run]
USAGE
  exit 2
}

[[ $# -ge 2 ]] || usage
HUB="$1"
CMD="$2"
shift 2

if [[ "$HUB" == "$DESKTOP_IP" ]]; then
  echo "netfault.sh: refusing target $DESKTOP_IP — that is the desktop (gridsim + dashboard). Partitioning/DNS-failing it would cut the dashboard and this SSH session. Never target it." >&2
  exit 2
fi

DRYRUN=0

case "$CMD" in
partition)
  [[ $# -ge 3 ]] || usage
  GRIDSIM_IP="$1"
  GRIDSIM_PORT="$2"
  AUTORESET="$3"
  [[ "${4:-}" == "--dry-run" ]] && DRYRUN=1
  remote_script="set -e
sudo -n iptables -I OUTPUT -d ${GRIDSIM_IP} -p tcp --dport ${GRIDSIM_PORT} -j DROP
sudo -n iptables -I INPUT  -s ${GRIDSIM_IP} -p tcp --sport ${GRIDSIM_PORT} -j DROP
sudo -n iptables -C OUTPUT -d ${GRIDSIM_IP} -p tcp --dport ${GRIDSIM_PORT} -j DROP
sudo -n sh -c '(sleep ${AUTORESET}; iptables -D OUTPUT -d ${GRIDSIM_IP} -p tcp --dport ${GRIDSIM_PORT} -j DROP; iptables -D INPUT -s ${GRIDSIM_IP} -p tcp --sport ${GRIDSIM_PORT} -j DROP) >/dev/null 2>&1 &'
echo \"netfault: partitioned hub↔${GRIDSIM_IP}:${GRIDSIM_PORT}, self-heal in ${AUTORESET}s\" >&2"
  ;;
dns-fail)
  [[ $# -ge 1 ]] || usage
  AUTORESET="$1"
  [[ "${2:-}" == "--dry-run" ]] && DRYRUN=1
  remote_script="set -e
sudo -n sh -c '[ -f ${RESOLV_BAK} ] || cp /etc/resolv.conf ${RESOLV_BAK}'
sudo -n sh -c 'printf \"nameserver ${DNS_BLACKHOLE}\\n\" > /etc/resolv.conf'
grep -q ${DNS_BLACKHOLE} /etc/resolv.conf
sudo -n sh -c '(sleep ${AUTORESET}; [ -f ${RESOLV_BAK} ] && mv ${RESOLV_BAK} /etc/resolv.conf) >/dev/null 2>&1 &'
echo \"netfault: DNS blackholed to ${DNS_BLACKHOLE}, self-heal in ${AUTORESET}s\" >&2"
  ;;
reset)
  [[ "${1:-}" == "--dry-run" ]] && DRYRUN=1
  # Reset needs the gridsim ip/port to delete the exact rules; accept them
  # optionally (env or args), else fall back to the bench defaults.
  GRIDSIM_IP="${NETFAULT_GRIDSIM_IP:-69.0.0.20}"
  GRIDSIM_PORT="${NETFAULT_GRIDSIM_PORT:-11111}"
  remote_script="set +e
sudo -n iptables -D OUTPUT -d ${GRIDSIM_IP} -p tcp --dport ${GRIDSIM_PORT} -j DROP 2>/dev/null
sudo -n iptables -D INPUT  -s ${GRIDSIM_IP} -p tcp --sport ${GRIDSIM_PORT} -j DROP 2>/dev/null
sudo -n sh -c '[ -f ${RESOLV_BAK} ] && mv ${RESOLV_BAK} /etc/resolv.conf'
echo \"netfault: reset (partition rules removed, resolv.conf restored if backed up)\" >&2
true"
  ;;
*)
  usage
  ;;
esac

if [[ "$DRYRUN" == "1" ]]; then
  echo "# dry-run — would run over: ssh -o BatchMode=yes -o ConnectTimeout=4 $SSHUSER@$HUB 'bash -s'"
  echo "$remote_script"
  exit 0
fi

ssh -o BatchMode=yes -o ConnectTimeout=4 "$SSHUSER@$HUB" 'bash -s' <<EOF
$remote_script
EOF
