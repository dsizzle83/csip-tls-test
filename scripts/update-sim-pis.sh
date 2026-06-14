#!/bin/bash
# Pushes the current cross-built simulator binaries to the device Pis and
# restarts their services. Also rewrites the metersim unit to linked mode and
# points evsim's CSMS at the hub.
#
# Usage:   bash scripts/update-sim-pis.sh <hub-ip> [ssh-user]
# Example: bash scripts/update-sim-pis.sh 69.0.0.1 dmitri
#
# Handles both Pi layouts, auto-detected per node:
#   user   — unit in ~/.config/systemd/user/<sim>.service, no sudo (current bench)
#   system — unit in /etc/systemd/system/<sim>.service, needs sudo (legacy pi@ layout)
# The binary is installed wherever the unit's ExecStart already points.
#
# IMPORTANT: metersim and the hub's lexa-modbus changed register layout
# together (audit finding MTR-4) — run deploy-hub-pi.sh in the same session.
set -euo pipefail

HUB="${1:?usage: update-sim-pis.sh <hub-ip> [ssh-user]}"
SSHUSER="${2:-dmitri}"
HERE="$(cd "$(dirname "$0")/.." && pwd)"

declare -A SIM=( [69.0.0.10]=modsim [69.0.0.11]=batsim [69.0.0.12]=metersim [69.0.0.14]=evsim )

for ip in "${!SIM[@]}"; do
  s="${SIM[$ip]}"
  [[ -x "$HERE/bin/arm64/$s" ]] || { echo "missing bin/arm64/$s — build with: GOOS=linux GOARCH=arm64 go build -o bin/arm64/$s ./sim/$s"; exit 1; }
done

for ip in 69.0.0.10 69.0.0.11 69.0.0.12 69.0.0.14; do
  s="${SIM[$ip]}"
  echo "── $ip ($s)"
  scp -q "$HERE/bin/arm64/$s" "$SSHUSER@$ip:/tmp/$s.new"
  ssh "$SSHUSER@$ip" "SIM=$s HUB=$HUB bash -s" <<'REMOTE'
set -euo pipefail

# systemctl --user needs the session bus when invoked over non-interactive SSH
export XDG_RUNTIME_DIR="${XDG_RUNTIME_DIR:-/run/user/$(id -u)}"
export DBUS_SESSION_BUS_ADDRESS="${DBUS_SESSION_BUS_ADDRESS:-unix:path=$XDG_RUNTIME_DIR/bus}"

USER_UNIT="$HOME/.config/systemd/user/$SIM.service"
SYS_UNIT="/etc/systemd/system/$SIM.service"
if [[ -f "$USER_UNIT" ]]; then
  UNIT="$USER_UNIT"; SC="systemctl --user"; AS=""; MODE=user
elif [[ -f "$SYS_UNIT" ]]; then
  UNIT="$SYS_UNIT"; SC="sudo systemctl"; AS="sudo"; MODE=system
else
  echo "   ERROR: no $SIM.service in ~/.config/systemd/user or /etc/systemd/system" >&2
  exit 1
fi

# Install over the path the unit actually executes.
BIN="$($AS awk -F= '/^ExecStart=/{print $2}' "$UNIT" | awk '{print $1}')"
[[ -n "$BIN" ]] || { echo "   ERROR: no ExecStart in $UNIT" >&2; exit 1; }
$AS install -m 755 "/tmp/$SIM.new" "$BIN" && rm "/tmp/$SIM.new"

if [[ "$SIM" == metersim ]]; then
  # Linked mode: meter computes the PCC balance from the other sims + hub EV.
  $AS sed -i "s|^ExecStart=.*|ExecStart=$BIN -port 5022 -api-port 6022 -solar-api http://69.0.0.10:6020 -battery-api http://69.0.0.11:6021 -hub-api http://$HUB:9100 -load 3000|" "$UNIT"
fi
if [[ "$SIM" == evsim ]]; then
  # Point the charging station at the hub's CSMS.
  $AS sed -i "s|-csms ws://[0-9.]*:8887/ocpp|-csms ws://$HUB:8887/ocpp|" "$UNIT"
fi

$SC daemon-reload
$SC restart "$SIM"
sleep 2
printf '   %s (%s unit): %s\n' "$SIM" "$MODE" "$($SC is-active "$SIM")"
REMOTE
done

echo
echo "── Done. Spot-check:"
echo "   curl -s http://69.0.0.12:6022/state | python3 -m json.tool | grep -A6 energy_balance"
