#!/usr/bin/env bash
# mqtt-chaos.sh — deploy (or remove) the QA MQTT fault proxy on the hub and point
# the lexa services' MQTT broker through it.
#
#   Usage:  bash scripts/mqtt-chaos.sh deploy  [hub-ip] [ssh-user]
#           bash scripts/mqtt-chaos.sh restore [hub-ip] [ssh-user]
#           bash scripts/mqtt-chaos.sh status  [hub-ip] [ssh-user]
#
# deploy : cross-builds bin/arm64/mqttproxy, installs it + the systemd unit on the
#          hub, repoints every /etc/lexa/*.json mqtt_broker to tcp://localhost:1882,
#          and restarts the lexa services. The proxy starts in transparent PASS
#          mode, so the bench behaves normally until the mayhem suite injects a
#          fault via the control API (69.0.0.1:11882).
# restore: repoints the services back to :1883, restarts them, stops+disables the
#          proxy. Run this when QA is done — like bench-up.sh --stock.
#
# INVASIVE: this rewrites broker config and restarts all six lexa services on the
# live hub (passwordless sudo). Only the hub (69.0.0.1) has sudo; see docs/BENCH.md.
set -uo pipefail

CMD="${1:?usage: mqtt-chaos.sh deploy|restore|status [hub-ip] [ssh-user]}"
HUB="${2:-69.0.0.1}"
SSHUSER="${3:-dmitri}"
HERE="$(cd "$(dirname "$0")/.." && pwd)"
SERVICES=(lexa-modbus lexa-ocpp lexa-api lexa-northbound lexa-telemetry lexa-hub)

case "$CMD" in
deploy)
  echo "── Cross-building mqttproxy (arm64)"
  GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -o "$HERE/bin/arm64/mqttproxy" ./cmd/mqttproxy || exit 1
  echo "── Staging to $SSHUSER@$HUB"
  scp -q "$HERE/bin/arm64/mqttproxy" "$SSHUSER@$HUB:/tmp/mqttproxy" || exit 1
  scp -q "$HERE/sim/mqttproxy.service" "$SSHUSER@$HUB:/tmp/mqttproxy.service" || exit 1
  echo "── Installing + repointing services (sudo)"
  ssh "$SSHUSER@$HUB" 'sudo bash -s' <<'REMOTE'
set -euo pipefail
install -m 755 /tmp/mqttproxy /usr/local/sbin/mqttproxy
install -m 644 /tmp/mqttproxy.service /etc/systemd/system/mqttproxy.service
systemctl daemon-reload
systemctl enable mqttproxy >/dev/null 2>&1 || true
systemctl restart mqttproxy
# Repoint each service's broker to the proxy (idempotent: only rewrites :1883).
for f in /etc/lexa/*.json; do
  if grep -q 'localhost:1883' "$f"; then
    sed -i 's#tcp://localhost:1883#tcp://localhost:1882#' "$f"
    echo "  repointed $f → :1882"
  fi
done
for s in lexa-modbus lexa-ocpp lexa-api lexa-northbound lexa-telemetry lexa-hub; do
  systemctl restart "$s"
done
sleep 2
echo "── proxy + services:"
systemctl is-active mqttproxy
for s in lexa-modbus lexa-ocpp lexa-api lexa-northbound lexa-telemetry lexa-hub; do
  printf '  %-18s %s\n' "$s" "$(systemctl is-active "$s")"
done
rm -f /tmp/mqttproxy /tmp/mqttproxy.service
REMOTE
  echo "── Control API: curl http://$HUB:11882/state"
  ;;

restore)
  echo "── Restoring direct broker + stopping proxy (sudo)"
  ssh "$SSHUSER@$HUB" 'sudo bash -s' <<'REMOTE'
set -euo pipefail
for f in /etc/lexa/*.json; do
  if grep -q 'localhost:1882' "$f"; then
    sed -i 's#tcp://localhost:1882#tcp://localhost:1883#' "$f"
    echo "  restored $f → :1883"
  fi
done
for s in lexa-modbus lexa-ocpp lexa-api lexa-northbound lexa-telemetry lexa-hub; do
  systemctl restart "$s"
done
systemctl stop mqttproxy 2>/dev/null || true
systemctl disable mqttproxy 2>/dev/null || true
echo "── proxy stopped; services back on :1883"
REMOTE
  ;;

status)
  echo "── proxy control state:"
  curl -s --max-time 5 "http://$HUB:11882/state" || echo "(control API unreachable — proxy not deployed?)"
  echo
  ;;

*)
  echo "unknown command: $CMD (want deploy|restore|status)" >&2
  exit 2
  ;;
esac
