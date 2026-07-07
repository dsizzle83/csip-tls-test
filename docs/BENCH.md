# Live demo bench (updated 2026-07-07 — hub migrated to the ConnectCore 93 dev kit)

Flat air-gapped LAN `69.0.0.x/24`. Desktop interface `enp1s0` (static 69.0.0.20,
NM profile "Wired connection 1", never-default); internet stays on WiFi `wlp2s0`.
SSH user is **`dmitri@` on the desktop and sim Pis, `root@` on the dev-kit hub**;
key auth from this desktop works everywhere.

| Node | IP | Runs | Service model |
|---|---|---|---|
| desktop | 69.0.0.20 | gridsim `bin/server` (mTLS :11111, admin :11112), dashboard :8080 | transient user units `csip-gridsim`, `csip-dashboard` (NOT boot-persistent) |
| **hub dev kit** `ccimx93-dvk` | 69.0.0.2 | all six lexa services + cross-built mosquitto (no-TLS, anonymous) + mqttproxy | root systemd units; login `root@` (Digi Yocto — no sudo binary; a `/usr/bin/sudo` shim strips sudo flags so unmodified bench scripts work) |
| hub-pi `dhpi4` | 69.0.0.1 | **STANDBY** — lexa services + mqttproxy stopped AND disabled 2026-07-07 (distro mosquitto still runs, harmless). Re-activate: `sudo systemctl enable --now lexa-{hub,modbus,ocpp,api,northbound,telemetry} mqttproxy` | root systemd units; **passwordless sudo** |
| solar-pi | 69.0.0.10 | modsim (Modbus 5020, simapi 6020) | user systemd unit + linger |
| battery-pi | 69.0.0.11 | batsim (5021/6021) | user systemd unit + linger |
| meter-pi `pi5-gridsim` | 69.0.0.12 | metersim linked mode, `-hub-api 69.0.0.2:9100` (5022/6022), `-hub-token-file ~/.config/lexa/hub-api.token` | user systemd unit + linger |
| ev-pi | 69.0.0.14 | evsim `-csms ws://69.0.0.2:8887/ocpp` (simapi 6024) — `wss://` + Basic Auth once OCPP Security Profile 2 is enabled, see below (TASK-074) | user systemd unit + linger |

The hub moved from hub-pi (69.0.0.1) to the ConnectCore 93 dev kit (69.0.0.2,
i.MX 93, Digi Embedded Yocto) on 2026-07-07 — bring-up/deploy runbook:
`lexa-hub/DEVKIT.md`. evsim/metersim/dashboard and the bench scripts
(`bench-up.sh`, `update-sim-pis.sh`, `mayhem-campaign.sh`, `mqtt-chaos.sh`,
`netem.sh`) all default to 69.0.0.2/root now; each takes env/flag overrides
(`HUB_IP`/`HUB_SSH_USER`, `--hub-ip/--ssh-user`, args) to drive the legacy Pi
hub. The dashboard is started with `LEXA_SSH_USER=root` (bench-up.sh) so the
Mayhem engine SSHes to the hub as root.

**Dev-kit hub caveats (vs the Pi):** its DEY kernel has `CONFIG_NET_SCH_NETEM`
unset and no `tc` binary, so the three `netem-*` Mayhem scenarios report
INCONCLUSIVE when targeting the hub (kernel rebuild required to fix); the
broker is a cross-built no-TLS mosquitto with `allow_anonymous true` (no
mosquitto_passwd on Yocto — services still send their credentials, the broker
accepts them; the Pi's passwd+ACL hardening does not apply there); `scp` to it
works (dropbear).

### netem packet-chaos harness (TASK-052 / GAP-11)

`scripts/netem.sh` and the `mayhem_world.go` `netemModifier`/`netem-*` scenarios apply
real `tc netem` loss/reorder/delay/jitter to a bench Pi's LAN interface over SSH — the
first Mayhem faults to touch the actual wire instead of only the application layer.

- **Every bench Pi is dual-homed** (LAN `69.0.0.x` + a WiFi uplink) and **defaults out
  the WiFi iface, not the LAN one**. The harness therefore never uses the default route
  to find the interface to fault — it resolves it via `ip -o route get <bench peer IP>`
  (69.0.0.20 from a sim Pi; 69.0.0.10 from the hub Pi) and uses that route's `dev`. Using
  the default route here would silently arm netem on the WAN iface and every scenario
  relying on it would falsely PASS (nothing on the bench LAN would actually degrade).
- **Never target 69.0.0.20 (the desktop)** — it hosts gridsim AND the dashboard process
  that runs this harness; netem there would cut the dashboard's own network path and the
  SSH session needed to undo it. `scripts/netem.sh` and `mayhem_world.go`'s
  `nodeSSHTarget` both hard-refuse it.
- **Passwordless sudo is only guaranteed on the hub** (see table above). The sim Pis
  (`.10`/`.11`/`.12`/`.14`) may NOT have it — `netemModifier` probes `sudo -n true`
  first and reports the scenario INCONCLUSIVE rather than hang/prompt when it's missing.
- The harness self-checks that netem actually took effect (ping-RTT delta across the
  bench LAN before/after apply) before trusting a profile — a ~0ms delta is the exact
  signature of the wrong-interface trap above, and refuses the scenario rather than run
  it against a no-op fault.
- Every apply schedules a self-healing scheduled `tc qdisc del` on the target Pi
  regardless of whether the fast-path teardown ever runs — a lost teardown (aborted
  Mayhem run, dashboard crash) still self-clears.

### Metrics (TASK-044)

Every lexa service serves Prometheus text exposition; bench configs bind
`metrics_addr` to the LAN IP (AD-008 — the product default stays 127.0.0.1):
`lexa-hub 69.0.0.2:9101 · lexa-northbound :9102 · lexa-modbus :9103 ·
lexa-ocpp :9104 · lexa-telemetry :9105 · lexa-api :9100/metrics` (existing
`:9100` listener, new route — no separate port). Scrape from the desktop with
`scripts/prometheus-bench.yml` (see file header for the one-line podman/native
prometheus run command); quick check: `curl 69.0.0.2:910N/metrics | grep lexa_up`.

**Deploy gotcha (same class as the STOCK-timing reset):** `deploy-hub-pi.sh`
overwrites `/etc/lexa/*.json` from the repo's `configs/`, which resets four
Pi-side bench enables — re-apply after every hub deploy:
`metrics_addr` → LAN IP per service (back to `""` = localhost default),
`modbus.json` `"reconciler":{"battery":"shadow"}` (back to `"off"`, TASK-027),
the mqttproxy repoint (`mqtt_broker` back to `:1883`; re-run
`scripts/mqtt-chaos.sh deploy` if QA needs the :1882 fault proxy), and
`ocpp.json`'s `cert_path`/`key_path`/`basic_auth_user`/`basic_auth_pass`
(back to `""` = plain `ws://`, no auth — re-run `deploy-hub-pi.sh
--enable-ocpp-sp2`, TASK-074).
Then restart the edited services and re-run `hub-replay-tune.sh fast`.

## Demo bring-up / recovery

Exact start commands for the desktop's transient units (`csip-gridsim`, `csip-dashboard`),
the verification chain, and scenario usage live in the **run-demo skill**
(`.claude/skills/run-demo/SKILL.md`; hub-side twin in lexa-hub). Key fact: those two
desktop units do NOT survive reboot — everything else on the bench does.

## Deploy

- Hub (all six lexa services) on the **dev kit**: manual root@ scp path per
  `lexa-hub/DEVKIT.md` (`deploy-hub-pi.sh` is Debian/sudo/lexa-user only and does
  NOT run against Yocto). The 2026-07-07 migration installed the exact binaries
  the Pi was running (desktop `lexa-hub/bin/arm64/`), the Pi's live `/etc/lexa`
  configs with `metrics_addr` rewritten to 69.0.0.2, units with `User=lexa`
  stripped, plus cross-built mosquitto and mqttproxy.
- Legacy Pi hub: `bash ~/projects/lexa-hub/scripts/deploy-hub-pi.sh 69.0.0.1 dmitri`
  (needs `make build-arm64` in lexa-hub first; stages client certs from this repo's `certs/client-staging/`).
- Sims: `bash scripts/update-sim-pis.sh <hub-ip> dmitri` — auto-detects each Pi's layout
  (user unit in `~/.config/systemd/user/<sim>.service`, or legacy root unit in
  `/etc/systemd/system/`), installs over the unit's existing ExecStart path, rewrites
  metersim to linked mode + evsim's CSMS URL, restarts, and reports `is-active`. Add
  `--enable-ocpp-sp2` to flip evsim to `wss://` + Basic Auth in lockstep with
  `deploy-hub-pi.sh --enable-ocpp-sp2` (TASK-074 — see the OCPP Security Profile 2
  runbook below).
- **MTR-4 lockstep (deploy half)**: metersim and lexa-modbus share the `lexa-proto`
  SunSpec register-map codec — always deploy hub and sims in the same session, never one
  side alone, whenever the pinned `lexa-proto` version bumps. The *code* half of MTR-4
  (both repos importing the identical version) is CI-enforced now
  (`scripts/check-proto-pin.sh`, TASK-024) — this bullet is the operational half that
  enforcement doesn't cover: a green CI pin check doesn't deploy anything for you.

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

### OCPP Security Profile 2 — wss:// + Basic Auth (TASK-074, AD-008, 09 Security hard gate)

The CSMS/evsim link already implements Security Profile 2 on both sides
(`lexa-proto/ocppserver`'s `ws.NewTLSServer` + constant-time `BasicAuthHandler`;
evsim's `-tls-ca`/`-auth-user`/`-auth-pass`) — enabling it is cert provisioning
+ staged config, not development. **`ws://` (no auth) is a bench-only
fallback; `wss://` + Basic Auth is the product default** (lexa-hub CLAUDE.md
"Critical invariants"). **Lockstep**: flipping the CSMS to require TLS while
evsim still dials `ws://` instantly rejects it — every EV Mayhem scenario
goes BLIND until both sides are done in the SAME session (05 §11, same class
as MTR-4).

1. Issue the CSMS cert from the bench CA, SAN = the hub's LAN IP (IP SAN is
   required — a hostname-only cert makes evsim's TLS verification refuse the
   connection):
   `bash scripts/gen-ev-cert.sh 69.0.0.1` (or `make gen-ev-cert IPS=69.0.0.1`)
   → `certs/ev-server-cert.pem` (commit), `certs/vault/ev-server-key.pem`
   (gitignored, stays local).
2. `bash ~/projects/lexa-hub/scripts/deploy-hub-pi.sh 69.0.0.1 dmitri --enable-ocpp-sp2`
   — stages the cert/key to `/etc/lexa/certs/ocpp-{cert,key}.pem` (0644/0600
   lexa:lexa), idempotently generates `/etc/lexa/ocpp-auth.pass` (0600
   lexa:lexa, `openssl rand -hex 16` — never committed, never leaves the hub
   except via the relay in step 3), and patches `cert_path`/`key_path`/
   `basic_auth_user` (fixed `evse-bench`)/`basic_auth_pass` into
   `/etc/lexa/ocpp.json`. Restarts `lexa-ocpp`.
3. **Same session**: `bash scripts/update-sim-pis.sh 69.0.0.1 dmitri --enable-ocpp-sp2`
   — relays `certs/ca-cert.pem` (public) and the hub's
   `/etc/lexa/ocpp-auth.pass` to ev-pi over SSH (no local temp file, same
   pattern as the lexa-api token relay above) and rewrites evsim's unit to
   `-csms wss://69.0.0.1:8887/ocpp -tls-ca ~/.config/lexa/ocpp-ca.pem
   -auth-user evse-bench -auth-pass <relayed secret>`. Restarts evsim.
4. Verify:
   ```
   ssh dmitri@69.0.0.1 sudo journalctl -u lexa-ocpp -n 20 --no-pager | grep 'TLS enabled'   # → 1 line (server.go:59)
   ssh dmitri@69.0.0.14 journalctl --user -u evsim -n 20 --no-pager | grep 'TLS enabled'     # → 1 line (main.go newWSClient)
   curl -s http://69.0.0.1:9100/status | python3 -m json.tool | grep -A4 '"cs-001"'          # a TransactionEvent lifecycle still updates lexa/evse/cs-001/state
   ```
   Negative-auth check (evsim with the wrong password must be rejected —
   don't skip this, it's the acceptance criterion): temporarily point a
   second evsim instance (or `update-sim-pis.sh`'s relayed
   `~/.config/lexa/ocpp-auth.pass` edited to a wrong value) at the same
   `wss://` URL and confirm the connection is refused
   (`journalctl -u lexa-ocpp | grep 'basic-auth rejected'`). The unit-level
   equivalent that runs in CI is `go test ./cmd/ocpp/... -run
   TestOCPPSecurityProfile2_BasicAuth` in lexa-hub (wrong password, wrong
   username, and correct credentials, all against the real
   `ocppserver.New`/`SetBasicAuthHandler` code path — no bench needed to
   exercise the auth logic itself).
5. Re-run the 7 EV Mayhem scenarios at their accepted verdicts (transport
   change only, same scenario semantics): `python3 scripts/mayhem.py
   --dashboard http://69.0.0.20:8080 --only
   ev-profile-reject,ev-accept-but-ignore,ev-min-current-floor,ev-meter-freeze,ev-connector-flap,ev-delayed-obey,ev-wrong-units`
   ×3.

Rollback: `bash ~/projects/lexa-hub/scripts/deploy-hub-pi.sh 69.0.0.1 dmitri`
(no `--enable-ocpp-sp2`) resets `ocpp.json`'s cert/auth fields to `""` (see
the deploy-gotcha note above) and restarts `lexa-ocpp`; **same session**,
`bash scripts/update-sim-pis.sh 69.0.0.1 dmitri` (no flag) rewrites evsim back
to plain `-csms ws://69.0.0.1:8887/ocpp` — the ExecStart rewrite is a regex
substitution that strips the `-tls-ca`/`-auth-user`/`-auth-pass` flags
cleanly in either direction, so this is a clean revert, not a manual edit.

Backlog: Security Profile 3 (mTLS on the OCPP link) is out of scope — AD-008
scopes TASK-074 to "≥2"; tracked in `docs/refactor/10_BACKLOG.md`.

### MQTT broker credentials + ACL (TASK-013, W7/AD-008)

Mosquitto (`localhost:1883` on the hub) no longer accepts anonymous clients once
flipped: each of the six lexa services plus the QA `qa-inject` user
(`cmd/mqttproxy`'s `/inject`) authenticates with its own broker user, and
`lexa-hub/systemd/mosquitto-lexa.acl` grants each only the topics
`internal/bus/topics.go` says it owns. Staged rollout, same shape as the
lexa-api token above:

1. `deploy-hub-pi.sh 69.0.0.1 dmitri` (no flag) — always generates per-service
   passwords under `/etc/lexa/mqtt/<svc>.pass` (0600 lexa:lexa), installs
   `/etc/mosquitto/lexa-passwd`/`lexa-acl`, and patches every service's
   `mqtt_user`/`mqtt_pass_file` — but the broker's conf.d drop-in still says
   `allow_anonymous true` and doesn't reference `password_file`/`acl_file` yet.
2. Confirm every service authenticated (harmless while anonymous is still on):
   `ssh dmitri@69.0.0.1 sudo journalctl -u lexa-modbus -n 20 --no-pager | grep 'broker user='`
3. `deploy-hub-pi.sh 69.0.0.1 dmitri --enable-mqtt-acl` — flips
   `allow_anonymous false` and installs `password_file`/`acl_file`; restarts
   mosquitto and all six services.
4. Verify:
   ```
   ssh dmitri@69.0.0.1 sudo journalctl -u mosquitto -n 50 --no-pager | grep -i 'not authorised'   # want: empty
   ssh dmitri@69.0.0.1 mosquitto_pub -h localhost -t lexa/control/battery/battery-0 -m '{}'         # want: rejected (no creds)
   ```
- **qa-inject**: `scripts/mqtt-chaos.sh deploy` provisions this broker user
  (idempotent, `openssl rand -hex 16` → `/etc/lexa/mqtt/qa-inject.pass`,
  registered into the same `/etc/mosquitto/lexa-passwd`) and passes
  `-user qa-inject -passfile ...` to `sim/mqttproxy.service`'s ExecStart — the
  ACL grant itself (`lexa/#` readwrite, bench-only) lives in lexa-hub's
  `mosquitto-lexa.acl`. Every lexa service proxied through mqttproxy during a
  Mayhem run (`:1882`) still authenticates end-to-end with its own credentials
  through the transparent PASSTHROUGH; only the direct `/inject` publish needs
  the qa-inject user.
- Rollback: revert the hub's conf.d drop-in to `allow_anonymous true` (drop
  `password_file`/`acl_file`) and `systemctl restart mosquitto`. Services keep
  working unmodified since their credentials are additive, not required by
  their own config.
- Re-run `scripts/hub-replay-tune.sh fast` after any mosquitto restart from
  this flow (deploy resets hub timing to STOCK).

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
