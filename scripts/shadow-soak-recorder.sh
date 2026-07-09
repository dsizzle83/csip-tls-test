#!/usr/bin/env bash
# shadow-soak-recorder.sh — persist the hub's constraint-shadow divergence
# stream + metrics during the flip-gate soak (WS-5.2, R4 endgame).
#
# The dev-kit hub's journald is volatile (4MB RAM) — hours of retention.
# This runs on the DESKTOP as a user unit and keeps three artifacts under
# logs/shadow-soak/:
#   divergence.jsonl   one line per WARN "constraint-shadow divergence"
#   metrics.tsv        minutely: epoch, divergence_total, hub uptime marker
#   recorder.log       recorder lifecycle (reconnects etc.)
#
#   Start:  systemd-run --user --unit=lexa-soak-recorder \
#             bash /home/dmitri/projects/csip-tls-test/scripts/shadow-soak-recorder.sh
#   Stop:   systemctl --user stop lexa-soak-recorder
set -u
HUB="${HUB_IP:-69.0.0.2}"
HUBUSER="${HUB_SSH_USER:-root}"
OUT="${SOAK_DIR:-$HOME/projects/csip-tls-test/logs/shadow-soak}"
mkdir -p "$OUT"

echo "$(date -Is) recorder start (hub $HUBUSER@$HUB)" >> "$OUT/recorder.log"

# Metrics scraper (background of this unit)
(
  while true; do
    total=$(curl -s --max-time 5 "http://$HUB:9101/metrics" | awk '/^lexa_constraint_shadow_divergence_total/ {print $2}')
    echo -e "$(date +%s)\t${total:-NA}" >> "$OUT/metrics.tsv"
    sleep 60
  done
) &

# Divergence stream (auto-reconnect; journalctl -f from the hub)
while true; do
  ssh -o ConnectTimeout=10 -o ServerAliveInterval=30 -o ServerAliveCountMax=3 \
      "$HUBUSER@$HUB" 'journalctl -u lexa-hub -f --no-pager -o cat' 2>>"$OUT/recorder.log" \
    | grep --line-buffered 'constraint-shadow divergence' >> "$OUT/divergence.jsonl"
  echo "$(date -Is) stream dropped; reconnecting in 10s" >> "$OUT/recorder.log"
  sleep 10
done
