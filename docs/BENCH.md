# Live demo bench (updated 2026-06-12)

Flat air-gapped LAN `69.0.0.x/24`. Desktop interface `enp1s0` (static 69.0.0.20,
NM profile "Wired connection 1", never-default); internet stays on WiFi `wlp2s0`.
SSH user is **`dmitri@` everywhere** (not `pi@`); key auth from this desktop works.

| Node | IP | Runs | Service model |
|---|---|---|---|
| desktop | 69.0.0.20 | gridsim `bin/server` (mTLS :11111, admin :11112), dashboard :8080 | transient user units `csip-gridsim`, `csip-dashboard` (NOT boot-persistent) |
| hub-pi `dhpi4` | 69.0.0.1 | all six lexa services + distro mosquitto | root systemd units; **passwordless sudo** (only node with it) |
| solar-pi | 69.0.0.10 | modsim (Modbus 5020, simapi 6020) | user systemd unit + linger |
| battery-pi | 69.0.0.11 | batsim (5021/6021) | user systemd unit + linger |
| meter-pi `pi5-gridsim` | 69.0.0.12 | metersim linked mode, `-hub-api 69.0.0.1:9100` (5022/6022), `-hub-token-file ~/.config/lexa/hub-api.token` | user systemd unit + linger |
| ev-pi | 69.0.0.14 | evsim `-csms ws://69.0.0.1:8887/ocpp` (simapi 6024) | user systemd unit + linger |

ConnectCore 93 dev kit (69.0.0.2) is **offline/unused**; the hub moved to 69.0.0.1.
evsim/metersim/dashboard all point at 69.0.0.1 — repoint when the dev kit returns
(runbook: `lexa-hub/DEVKIT.md`).

## Demo bring-up / recovery

Exact start commands for the desktop's transient units (`csip-gridsim`, `csip-dashboard`),
the verification chain, and scenario usage live in the **run-demo skill**
(`.claude/skills/run-demo/SKILL.md`; hub-side twin in lexa-hub). Key fact: those two
desktop units do NOT survive reboot — everything else on the bench does.

## Deploy

- Hub (all six lexa services): `bash ~/projects/lexa-hub/scripts/deploy-hub-pi.sh 69.0.0.1 dmitri`
  (needs `make build-arm64` in lexa-hub first; stages client certs from this repo's `certs/client-staging/`).
- Sims: `bash scripts/update-sim-pis.sh <hub-ip> dmitri` — auto-detects each Pi's layout
  (user unit in `~/.config/systemd/user/<sim>.service`, or legacy root unit in
  `/etc/systemd/system/`), installs over the unit's existing ExecStart path, rewrites
  metersim to linked mode + evsim's CSMS URL, restarts, and reports `is-active`.
- **MTR-4 lockstep**: metersim and lexa-modbus share SunSpec register maps — always deploy
  hub and sims in the same session, never one side alone.

### lexa-api bearer-token auth (TASK-014, AD-008)

`lexa-api` (:9100) can require `Authorization: Bearer <token>` on `/status`/`/logs`
(`/healthz` always stays open). Staged rollout — an unconfigured token is exactly
today's open behavior, so this never flag-days the bench:

1. `deploy-hub-pi.sh 69.0.0.1 dmitri` (no flag) — deploys the auth-capable code and
   idempotently generates `/etc/lexa/api.token` (0600 lexa:lexa) but leaves
   `api_token_file` unset in `/etc/lexa/api.json` — **auth stays off**.
2. `scripts/update-sim-pis.sh 69.0.0.1 dmitri` and `scripts/bench-up.sh` relay that
   token (over SSH, no local temp file) to the meter Pi
   (`~/.config/lexa/hub-api.token`) and the desktop (same path) and restart
   metersim/the dashboard with `-hub-token-file` pointing at it. Harmless while the
   hub isn't requiring the header yet.
3. `deploy-hub-pi.sh 69.0.0.1 dmitri --enable-api-auth` — patches `api_token_file`
   into the installed `api.json` and restarts `lexa-api`. Auth is now enforced.
4. Verify:
   ```
   curl -s http://69.0.0.1:9100/status                                              # → 401
   curl -s -H "Authorization: Bearer $(ssh dmitri@69.0.0.1 sudo cat /etc/lexa/api.token)" \
        http://69.0.0.1:9100/status | python3 -m json.tool | head                    # → 200
   curl -s http://69.0.0.1:9100/healthz                                              # → 200, never authenticated
   ```
Rollback: on the hub, clear `api_token_file` in `/etc/lexa/api.json` and
`systemctl restart lexa-api`. Every consumer already tolerates an unconfigured
token (they just keep sending the header — lexa-api simply stops checking it),
so no consumer-side change is needed to roll back.

## wolfSSL sysroots (desktop)

- amd64: `~/.local/wolfssl-amd64` (persistent). Both repos' Makefiles auto-wire it into
  `CGO_CFLAGS`/`CGO_LDFLAGS` when the dir exists (the static `libwolfssl.a` also needs
  `-lm`); for direct `go test` outside make, the same env is set in
  `.claude/settings.local.json`.
- arm64: `/tmp/wolfssl-arm64-sysroot` (wiped on reboot) — rebuild with `make wolfssl-arm64`
  in lexa-hub before `make build-arm64`.

## Gotchas

- `pkill -f <pattern>` over SSH can match the wrapping `bash -c` command line and kill your
  own session. Use `systemctl [--user] restart <unit>` instead.
- Admin API (11112), simapi ports, and the dashboard are unauthenticated by design and bind
  0.0.0.0 — fine on this air-gapped LAN, never bridge it. lexa-api (:9100) is the one
  exception: bearer-token auth on `/status`/`/logs` (TASK-014, AD-008) — see the deploy
  section above; TLS on :9100 is a deferred backlog item, not yet implemented.
- Sanity probes: `curl -s http://<pi>:60xx/state` per sim; dashboard health at
  `http://69.0.0.20:8080`; hub — `curl -s http://69.0.0.1:9100/status` if auth is off,
  else add `-H "Authorization: Bearer $(ssh dmitri@69.0.0.1 sudo cat /etc/lexa/api.token)"`;
  `curl -s http://69.0.0.1:9100/healthz` is always unauthenticated.
