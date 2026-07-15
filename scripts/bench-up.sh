#!/usr/bin/env bash
# bench-up.sh — bring the demo bench back up on the DESKTOP after a reboot and
# get it ready for a long replay.  Run this from the desktop (69.0.0.20) in a
# logged-in terminal.  Idempotent: safe to re-run.
#
#   Usage:  bash scripts/bench-up.sh [--fast|--stock]
#           --fast  (default) put the hub in replay-fast timing (for replays)
#           --stock                  restore normal demo timing and exit
#
# What it does:
#   1. Restores the desktop's bench-LAN static IP (enp1s0 = 69.0.0.20) — this
#      does NOT survive reboot and needs a sudo password.
#   2. (Re)starts gridsim + dashboard as systemd --user units — these are NOT
#      boot-persistent (no linger), so a reboot wipes them.
#   3. Verifies every bench node: gridsim, dashboard, hub, and the four sims.
#      The Pis (hub .1, sims .10-.14) auto-start via linger and do NOT reboot
#      with the desktop, so they should already be up once the LAN is back.
#   4. Sets the hub to replay-fast timing.
#
# TASK-014 (W7, AD-008): lexa-api may require a bearer token. This script
# relays ~/.config/lexa/hub-api.token from the hub's /etc/lexa/api.token over
# SSH on every run (idempotent — empty if the hub hasn't enabled auth yet,
# which is the staged-rollout default) and points the dashboard at it via
# -hub-token-file. An empty token file is exactly today's unauthenticated
# behavior; nothing here can make an already-working bench start failing.
#
# The sims/hub run committed code already; nothing is deployed here.
set -uo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO"
MODE="fast"; [[ "${1:-}" == "--stock" ]] && MODE="stock"

# Hub = ConnectCore 93 dev kit (Yocto, root@ — see lexa-hub/DEVKIT.md).
# Override for the legacy Pi hub with: HUB_IP=69.0.0.1 HUB_SSH_USER=dmitri
HUB="${HUB_IP:-69.0.0.2}"; HUBUSER="${HUB_SSH_USER:-root}"
SOLAR=69.0.0.10; BAT=69.0.0.11; MTR=69.0.0.12; EV=69.0.0.14
ok(){ printf '  \033[32m✓\033[0m %s\n' "$1"; }
bad(){ printf '  \033[31m✗\033[0m %s\n' "$1"; }
hr(){ printf '\n── %s\n' "$1"; }

# ── stock-only shortcut ─────────────────────────────────────────────────────
if [[ "$MODE" == "stock" ]]; then
  echo "Restoring stock hub timing (post-replay)…"
  bash "$REPO/scripts/hub-replay-tune.sh" stock "$HUB" "$HUBUSER"
  exit $?
fi

# ── 1. bench-LAN IP ─────────────────────────────────────────────────────────
hr "Bench LAN (enp1s0 → 69.0.0.20)"
if ip -br addr show enp1s0 2>/dev/null | grep -q '69\.0\.0\.20'; then
  ok "enp1s0 already has 69.0.0.20"
else
  echo "  enp1s0 missing its bench IP — restoring (needs your sudo password)…"
  sudo nmcli connection up "Wired connection 1"
  sleep 2
  if ip -br addr show enp1s0 2>/dev/null | grep -q '69\.0\.0\.20'; then
    ok "enp1s0 → 69.0.0.20 restored"
  else
    bad "enp1s0 still has no 69.0.0.20 — fix the LAN before continuing:"
    echo "      sudo nmcli connection modify 'Wired connection 1' ipv4.addresses 69.0.0.20/24 ipv4.method manual"
    echo "      sudo nmcli connection up 'Wired connection 1'"
    exit 1
  fi
fi

# ── 2. desktop services (gridsim + dashboard) ───────────────────────────────
hr "Desktop services (gridsim + dashboard)"
start_unit(){  # name, cmd...
  local unit="$1"; shift
  if systemctl --user is-active --quiet "$unit"; then ok "$unit already running"; return; fi
  systemctl --user reset-failed "$unit" 2>/dev/null || true
  if systemd-run --user --unit="$unit" -p WorkingDirectory="$REPO" \
       --description="$unit" "$@" >/dev/null 2>&1; then
    ok "$unit started"
  else
    bad "$unit failed to start — run manually:  $*"
  fi
}
[[ -x bin/server    ]] || { echo "  building bin/server…";    make build >/dev/null 2>&1 || bad "make build failed"; }
[[ -x bin/dashboard ]] || { echo "  building bin/dashboard…"; make build >/dev/null 2>&1 || bad "make build failed"; }
[[ -x bin/vtnsim    ]] || { echo "  building bin/vtnsim…";    make build-vtnsim >/dev/null 2>&1 || bad "make build-vtnsim failed"; }

# Relay the hub's bearer token (TASK-014, AD-008) so the dashboard can
# present it. Best-effort: if the hub is unreachable or hasn't generated a
# token yet, the file ends up empty and the dashboard runs open (unchanged
# behavior) — never fatal to bench-up.
HUB_TOKEN_FILE="$HOME/.config/lexa/hub-api.token"
mkdir -p "$(dirname "$HUB_TOKEN_FILE")"
if ( umask 077; ssh -o ConnectTimeout=5 $HUBUSER@$HUB 'sudo cat /etc/lexa/api.token 2>/dev/null || true' > "$HUB_TOKEN_FILE" 2>/dev/null ); then
  if [[ -s "$HUB_TOKEN_FILE" ]]; then
    ok "hub API token relayed → $HUB_TOKEN_FILE (dashboard will present it)"
  else
    ok "hub API token not yet configured — dashboard runs open (staged rollout)"
  fi
else
  : > "$HUB_TOKEN_FILE"; chmod 600 "$HUB_TOKEN_FILE"
  bad "couldn't reach hub to fetch its API token — dashboard runs open"
fi

start_unit csip-gridsim   "$REPO/bin/server" -ca certs/ca-cert.pem -cert certs/server-cert.pem -key certs/vault/server-key.pem
# OpenADR 3.1 VTN stub (WP-15 demo): serves prices/limits the hub's lexa-openadr
# VEN adopts. -base-url is the address it advertises in GET /auth/server.
start_unit csip-vtnsim    "$REPO/bin/vtnsim" -addr :6030 -base-url http://69.0.0.20:6030
# --setenv is consumed by systemd-run (option parsing stops at the binary path):
# LEXA_SSH_USER tells the mayhem engine how to SSH into the hub node.
start_unit csip-dashboard --setenv=LEXA_SSH_USER="$HUBUSER" \
  "$REPO/bin/dashboard" -addr :8080 -hub https://$HUB:9100 \
  -mqttproxy http://$HUB:11882 \
  -gridsim http://localhost:11112 -solar http://$SOLAR:6020 -battery http://$BAT:6021 \
  -meter http://$MTR:6022 -ev http://$EV:6024 -vtn http://localhost:6030 -hub-token-file "$HUB_TOKEN_FILE"
sleep 3

# ── 3. verify the whole bench ───────────────────────────────────────────────
hr "Verify bench"
probe(){ # label url [-H "..."]
  local label="$1" url="$2"; shift 2
  local code; code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 6 "$@" "$url" 2>/dev/null)
  [[ "$code" =~ ^[2-4][0-9][0-9]$ ]] && ok "$label ($url → $code)" || bad "$label unreachable ($url)"
}
probe "gridsim admin" http://localhost:11112/
probe "vtnsim"        http://localhost:6030/programs
probe "dashboard"     http://localhost:8080/
# Present the token if we have one — a 401 here would otherwise read as a
# false "hub down" when auth is actually on and working as intended.
# -k: lexa-api serves HTTPS with a per-device self-signed leaf (WS-B); the
# air-gapped bench has no CA to validate against, so allow the insecure cert.
HUB_TOKEN="$(tr -d '[:space:]' < "$HUB_TOKEN_FILE" 2>/dev/null || true)"
if [[ -n "$HUB_TOKEN" ]]; then
  probe "hub status"  https://$HUB:9100/status -k -H "Authorization: Bearer $HUB_TOKEN"
else
  probe "hub status"  https://$HUB:9100/status -k
fi
probe "solar sim"     http://$SOLAR:6020/state
probe "battery sim"   http://$BAT:6021/state
probe "meter sim"     http://$MTR:6022/state
probe "ev sim"        http://$EV:6024/state

# ── 4. hub replay-fast timing ───────────────────────────────────────────────
hr "Hub timing"
bash "$REPO/scripts/hub-replay-tune.sh" fast "$HUB" "$HUBUSER" 2>&1 | sed 's/^/  /'

cat <<EOF

✅ Bench is up.  To run a long replay (server-side, survives this terminal):

   python3 scripts/replay-launch.py 99 --tick-ms 8000 --launch       # full 92 days (~19.6 h)
   python3 scripts/replay-launch.py 99 --days 7 --tick-ms 8000 --launch   # 7-day spot check

   Watch:   curl -s http://localhost:8080/api/replay/status | python3 -m json.tool
   Log:     replay-ticklog-<timestamp>.csv  (this dir; gitignored)

   WHEN DONE with replays, restore normal demo timing:
   bash scripts/bench-up.sh --stock
EOF
