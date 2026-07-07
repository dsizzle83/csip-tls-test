#!/usr/bin/env bash
# mqtt-chaos.sh — deploy (or remove) the QA MQTT fault proxy on the hub and point
# the lexa services' MQTT broker through it.
#
#   Usage:  bash scripts/mqtt-chaos.sh deploy  [hub-ip] [ssh-user]
#           bash scripts/mqtt-chaos.sh restore [hub-ip] [ssh-user]
#           bash scripts/mqtt-chaos.sh status  [hub-ip] [ssh-user]
#
# deploy : provisions a qa-inject broker user (mosquitto_passwd against the same
#          /etc/mosquitto/lexa-passwd lexa-hub's deploy-hub-pi.sh manages —
#          TASK-013/W7; the ACL grant for qa-inject lives in lexa-hub's
#          systemd/mosquitto-lexa.acl), cross-builds bin/arm64/mqttproxy,
#          installs it + the systemd unit (which passes -user qa-inject
#          -passfile ... so /inject still authenticates once the hub's ACL
#          requires it) on the hub, repoints every /etc/lexa/*.json mqtt_broker
#          to tcp://localhost:1882, and restarts the lexa services. The proxy
#          starts in transparent PASS mode, so the bench behaves normally until
#          the mayhem suite injects a fault via the control API (69.0.0.1:11882).
#          Every proxied lexa service still presents its own mqtt_user/
#          mqtt_pass_file end-to-end through the passthrough — only /inject's
#          direct publish needs the qa-inject credentials.
# restore: repoints the services back to :1883, restarts them, stops+disables the
#          proxy. Run this when QA is done — like bench-up.sh --stock.
#
# INVASIVE: this rewrites broker config and restarts all six lexa services on the
# live hub (passwordless sudo). Only the hub (69.0.0.1) has sudo; see docs/BENCH.md.
set -uo pipefail

CMD="${1:?usage: mqtt-chaos.sh deploy|restore|status [hub-ip] [ssh-user]}"
# ConnectCore 93 dev-kit hub (Yocto, root@) — pass 69.0.0.1 dmitri for the legacy Pi hub.
HUB="${2:-69.0.0.2}"
SSHUSER="${3:-root}"
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
# qa-inject broker user (TASK-013 / W7): mqttproxy's /inject endpoint needs
# its own credentials once the hub's ACL requires them — same passwd file
# lexa-hub's deploy-hub-pi.sh manages, so both scripts must agree on its
# path. Idempotent: an existing pass-file's password is reused, so re-runs
# don't rotate the secret or need a proxy restart to notice a changed one.
PASSWD_FILE=/etc/mosquitto/lexa-passwd
PASSFILE=/etc/lexa/mqtt/qa-inject.pass
install -d -m 750 -o lexa -g lexa /etc/lexa/mqtt 2>/dev/null || install -d -m 750 /etc/lexa/mqtt
if [[ ! -s "$PASSFILE" ]]; then
  ( umask 077 && openssl rand -hex 16 > "$PASSFILE" )
  chown lexa:lexa "$PASSFILE" 2>/dev/null || true
  chmod 600 "$PASSFILE"
  echo "  generated $PASSFILE (0600)"
fi
QA_PASS="$(cat "$PASSFILE")"
# The Yocto dev-kit hub has no mosquitto_passwd and runs the broker with
# allow_anonymous true (see lexa-hub/DEVKIT.md) — credentials are then
# accepted without a passwd entry, so skipping this is safe there.
if command -v mosquitto_passwd >/dev/null 2>&1; then
  if [[ -s "$PASSWD_FILE" ]]; then
    mosquitto_passwd -b "$PASSWD_FILE" qa-inject "$QA_PASS"
  else
    mosquitto_passwd -b -c "$PASSWD_FILE" qa-inject "$QA_PASS"
  fi
  chown root:mosquitto "$PASSWD_FILE" 2>/dev/null || true
  chmod 640 "$PASSWD_FILE"
  echo "  qa-inject broker user provisioned in $PASSWD_FILE (ACL grant lives in lexa-hub's systemd/mosquitto-lexa.acl)"
else
  echo "  mosquitto_passwd not present (anonymous broker) — skipping qa-inject passwd entry"
fi

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
