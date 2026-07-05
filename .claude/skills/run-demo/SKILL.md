---
name: run-demo
description: Bring up the full CSIP demo end to end — gridsim + dashboard on the desktop, sims on the Pis, hub services — verify every link, and run the dashboard scenarios. Use for "run the demo", "start the demo", "bring the bench up", or post-reboot recovery.
---

# Run the demo

Full chain: gridsim (desktop) ←mTLS← hub (69.0.0.1) ←Modbus/OCPP→ sims (Pis), all
visualized at **http://69.0.0.20:8080**. Topology details: `docs/BENCH.md`.

The only fragile part is the **desktop**: gridsim and the dashboard run as *transient*
user units that vanish on reboot/logout. The Pis (linger) and hub (root units) survive
reboots on their own.

## 1. Desktop services (do this first — and always after a desktop reboot)

```bash
systemctl --user is-active csip-gridsim csip-dashboard
```
For each one not `active`, start it with exactly this (relative cert paths require the
working directory):

```bash
# If a previous instance failed, clear it first or systemd-run refuses the name:
systemctl --user reset-failed csip-gridsim csip-dashboard 2>/dev/null

systemd-run --user --unit=csip-gridsim \
  --working-directory="$HOME/projects/csip-tls-test" \
  "$HOME/projects/csip-tls-test/bin/server" \
  -ca certs/ca-cert.pem -cert certs/server-cert.pem -key certs/vault/server-key.pem

systemd-run --user --unit=csip-dashboard \
  --working-directory="$HOME/projects/csip-tls-test" \
  "$HOME/projects/csip-tls-test/bin/dashboard" -addr :8080 \
  -hub http://69.0.0.1:9100 -gridsim http://localhost:11112 \
  -solar http://69.0.0.10:6020 -battery http://69.0.0.11:6021 \
  -meter http://69.0.0.12:6022 -ev http://69.0.0.14:6024 \
  -hub-token-file "$HOME/.config/lexa/hub-api.token"
```

`-hub-token-file` (TASK-014, AD-008): lexa-api may require a bearer token on
`/status`/`/logs`. The flag is safe to pass even when auth is off — a missing or
empty file just means no header is sent. `scripts/bench-up.sh` relays the token
from the hub automatically; if starting the unit by hand and the file doesn't
exist yet, run `bash scripts/bench-up.sh` once first, or fetch it directly:
`ssh dmitri@69.0.0.1 sudo cat /etc/lexa/api.token > ~/.config/lexa/hub-api.token`.

If a binary is missing: `go build -o bin/server ./sim/server` (cgo — the Makefile/session
env wire the wolfSSL sysroot) and `go build -o bin/dashboard ./cmd/dashboard`.

Expected gridsim startup log (`journalctl --user -u csip-gridsim -n 5`):
`Server listening on [::]:11111 (mTLS, cipher=ECDHE-ECDSA-AES128-CCM-8)` + admin on :11112.

Network precheck if nothing is reachable: `nmcli -f NAME,DEVICE,STATE con show --active`
must list "Wired connection 1" on enp1s0 (desktop = 69.0.0.20; internet stays on WiFi).

## 2. Verify the rest of the bench (normally already up)

```bash
curl -s --max-time 3 http://69.0.0.10:6020/state >/dev/null && echo solar OK
curl -s --max-time 3 http://69.0.0.11:6021/state >/dev/null && echo battery OK
curl -s --max-time 3 http://69.0.0.12:6022/state >/dev/null && echo meter OK
curl -s --max-time 3 http://69.0.0.14:6024/state >/dev/null && echo ev OK
curl -s --max-time 3 http://69.0.0.1:9100/status | head -c 300   # hub (401 if auth is on and you didn't pass a token)
```
If lexa-api auth is on (`docs/BENCH.md`), add
`-H "Authorization: Bearer $(ssh dmitri@69.0.0.1 sudo cat /etc/lexa/api.token)"` to the
hub curl above; `/healthz` never needs it.
- Dead sim: `ssh dmitri@<ip> systemctl --user restart <modsim|batsim|metersim|evsim>`
- Dead hub service: `ssh dmitri@69.0.0.1 'sudo systemctl restart lexa-<svc>'`
  (order if everything is down: mosquitto → modbus/ocpp/api → northbound/telemetry → hub)

## 3. Confirm the chain is closed (in dependency order)

1. Hub is walking gridsim: `journalctl --user -u csip-gridsim -n 5` shows periodic
   `GET ... (peer=<40-char LFDI>)` lines.
2. Hub sees devices: `curl -s http://69.0.0.1:9100/status` lists solar/battery/meter
   readings and EV state.
3. Meter balance closes (linked mode): meter W ≈ load + ev − solar − battery on the
   dashboard's power chart / meter card.
4. Dashboard header KPIs: hub link green, program count > 0.

## 4. Run the demo itself

Open **http://69.0.0.20:8080** → Scenarios tab. Five narrated scenarios
(export-limit, import-cap, zero-import emergency, DR dispatch, self-consumption); each
stages the sims, fires the grid event via the gridsim admin API, then asserts the
expected PCC condition and renders PASS/FAIL with history. The Logs tab merges all six
backends (filter, pause, JSON/CSV export); the Grid tab composes ad-hoc DERControls.

## Rules
- Don't restart services mid-demo; if a scenario fails its assertion, check the Logs
  tab before touching anything.
- Don't kill the transient units to "refresh" them unless something is actually wrong —
  `systemctl --user restart csip-dashboard` works; gridsim restarts drop the hub's mTLS
  session (it auto-redials within its poll interval, but say so first).
- Scenario assertions need the meter in linked mode (it is, per its unit file) — don't
  inject raw meter watts while a scenario is running.
