#!/usr/bin/env bash
# gw-qa-bus.sh — G3 internal-bus (MQTT) hostile-QA check. Runs the pure-stdlib
# probe qa-bus-probe.py ON the gateway (the broker is loopback-only, so it can
# only be reached on-box) and asserts the internal control bus is defended in
# depth: (1) anonymous CONNECT refused, (2) bogus-cred CONNECT refused, (3) a
# real service is ACL-confined to its topic lane (in-lane SUBSCRIBE granted,
# out-of-lane SUBSCRIBE refused / disconnected).
#
# The bus is the gateway's INTERNAL control plane (reconcile reports, mode/
# intent, mbaps writes). Its first defense is that mosquitto binds
# `listener 1883 localhost` — NOT network-reachable — so this probe runs on the
# board over loopback; there is no off-box bus attack surface to drive from the
# desktop. Usage: scripts/gw-qa-bus.sh   (GW_SSH=cc93 by default)
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SSH="${GW_SSH:-cc93}"
PROBE="$HERE/scripts/qa-bus-probe.py"
[ -r "$PROBE" ] || { echo "missing $PROBE"; exit 1; }

echo "gw-qa-bus: probing the internal MQTT bus on $SSH (loopback broker)"
scp -q "$PROBE" "$SSH:/tmp/qa-bus-probe.py"
# lexa-cloudlink is a good ACL subject: it may READ lexa/mode but the write lane
# lexa/desired/# belongs to lexa-mode alone, so an out-of-lane SUBSCRIBE must be
# refused. Its password is root-readable at the standard secrets path.
rc=0
ssh "$SSH" 'PW=$(cat /etc/lexa/secrets/cloudlink-mqtt.pass 2>/dev/null); python3 /tmp/qa-bus-probe.py "$PW"; r=$?; rm -f /tmp/qa-bus-probe.py; exit $r' || rc=$?
echo "gw-qa-bus: probe exit=$rc"
exit $rc
