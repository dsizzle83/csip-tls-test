#!/usr/bin/env bash
# hub-replay-tune.sh — switch the lexa hub between stock and replay-fast timing.
#
# The bench-replay driver (dashboard "Bench Replay") paces 15-min simulated
# ticks at ~8 real seconds. For the hub to observe-decide-actuate inside each
# tick, its engine and CSIP discovery loops must run much faster than stock:
#
#   fast :  engine_interval_s=3,  discovery_interval_s=5   (replay)
#   stock:  engine_interval_s=15, discovery_interval_s=20  (normal demo)
#
# Usage: scripts/hub-replay-tune.sh fast|stock [hub-ip] [ssh-user]
set -euo pipefail

MODE="${1:?usage: hub-replay-tune.sh fast|stock [hub-ip] [ssh-user]}"
PI="${2:-69.0.0.1}"
SSHUSER="${3:-dmitri}"

case "$MODE" in
  fast)  ENGINE=3;  DISC=5;  POLL=2  ;;
  stock) ENGINE=15; DISC=20; POLL=10 ;;
  *) echo "mode must be 'fast' or 'stock'" >&2; exit 1 ;;
esac

echo "hub-replay-tune: $MODE (engine=${ENGINE}s discovery=${DISC}s poll=${POLL}s) on $PI"

ssh "$SSHUSER@$PI" sudo bash -s <<EOF
set -e
python3 - <<PY
import json
for path, key, val in [("/etc/lexa/hub.json", "engine_interval_s", $ENGINE),
                       ("/etc/lexa/northbound.json", "discovery_interval_s", $DISC),
                       ("/etc/lexa/modbus.json", "poll_interval_s", $POLL)]:
    with open(path) as f:
        cfg = json.load(f)
    cfg[key] = val
    with open(path, "w") as f:
        json.dump(cfg, f, indent=2)
        f.write("\n")
    print(f"  {path}: {key} = {val}")
PY
systemctl restart lexa-hub lexa-northbound lexa-modbus
sleep 2
for s in lexa-hub lexa-northbound lexa-modbus; do
  printf '  %-18s %s\n' "\$s" "\$(systemctl is-active \$s)"
done
echo "  hub timezone: \$(timedatectl show -p Timezone --value)"
EOF

echo "hub-replay-tune: done. Remember to run 'stock' after the replay."
