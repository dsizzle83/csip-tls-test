# QA Report — V1.0 Release-Candidate Gate (TASK-081) — 2026-07-06

**Verdict: V1.0-RC CONDITIONALLY READY.** The mega-merge of all P2–P6
code-complete work was deployed to the live bench as one release build and
put through the full gate. Core control regression is clean; OCPP Security
Profile 2, certificate monitoring, conformance, and the merged hardening
scenarios all validate on hardware. Three findings and a set of genuinely
external items remain before a `v1.0.0` tag — enumerated below and in
`docs/refactor/09_RELEASE_CHECKLIST.md`. No safety breach was observed in any
run (SAFETY AUDIT held on every scenario; 0 BLIND across the entire gate).

## Frozen build under test
| Repo | SHA (main) |
|---|---|
| lexa-hub (product) | `c730302` |
| csip-tls-test (bench) | `695da02` |
| lexa-proto (shared codec) | `4e8b940` (both repos `replace => ../lexa-proto`) |

Deployed via `deploy-hub-pi.sh --enable-api-auth --enable-mqtt-acl` +
`mqtt-chaos.sh deploy` + `hub-replay-tune.sh fast`. Bench config at gate time:
reconciler active (battery/solar/EVSE), `constraint_shadow=true` (SHADOW),
lexa-api bearer auth ON, mosquitto ACL ON (`allow_anonymous false`), FAST
timing (engine 3 s / discovery 5 s / poll 2 s).

## Gate 1 — Deploy + bench health: PASS (one deploy finding)
All six lexa services + mosquitto + mqttproxy active; `/status` fresh
(plan_heartbeat ok, live solar/battery/meter/EVSE); API auth enforced
(401 without token, 200 with, `/healthz` always open); MQTT per-service auth
(`broker user=lexa-*`); cert monitoring live (`certificate expiry OK
client_days_left=341 ca_days_left=3622`).

- **FINDING D (deploy provisioning):** the release `lexa-northbound` (journal
  feature 039/041) fails to start because it cannot create
  `/var/lib/lexa/journal/northbound` — neither the systemd unit nor
  `deploy-hub-pi.sh` provisions `/var/lib/lexa` (owned `lexa:lexa`). Worked
  around operationally (`install -d -o lexa -g lexa /var/lib/lexa`). **Fix:**
  add `StateDirectory=lexa` to the six units (systemd auto-creates it) or a
  `mkdir`/`install` step in the deploy script.

## Gate 2 — Watchdog (◆): PASS
All six services `Type=notify` + `WatchdogSec` (60 s; northbound 120 s). Live
wedge test: `SIGSTOP` on `lexa-telemetry` → systemd killed and restarted it at
t≈57 s (WatchdogSec=60), new PID, `NRestarts=1`, back to `active`. Mechanism
proven on the shipping build (007/008).

## Gate 3 — Full FAST Mayhem campaign (◆ core regression): PASS
Single full-suite run, 51 default scenarios (`logs/campaign-v1rc-fast-20260706/`).

**32 PASS / 18 DEGRADED / 1 FAIL / 0 BLIND / 0 INCONCLUSIVE.**

- Band expectation 33–35P / 16–18D → 32P/18D is within noise (the one FAIL
  displaced a would-be PASS).
- **The single FAIL — `control-churn` — is EXPLAINED and accepted-borderline.**
  Verbatim the known V5 cluster-2 signature: rapid ~12 s export-cap rewrites
  outrun the hub's convergence-verification window, so CannotComply is not
  admitted before the cap changes again (peak 3900 W over for 20 s).
  **SAFETY AUDIT held — no violations.** Same compliance-timing class as the
  M2 accepted-borderline `battery-charge-disabled` (which DEGRADED this run);
  which of the two tips on a given single run is timing-luck. Tracked to
  **TASK-064** (R4 constraint controller sizes the detection window adaptively
  from the plant model, eliminating the flake class rather than tuning a
  constant). **FINDING C.**
- **Mega-merge validated:** every historically-failing scenario is now green —
  `clock-jump-forward`, `release-while-rebooting`, `curtailment-release`,
  `wan-outage-hold/expiry`, `northbound-hang`, `hub-restart-mid-cap`, and all
  `malform-*` PASS. This clears the batch backlog: 046 async publishes
  (`mqtt-broker-latency` PASS, `mqtt-broker-restart` DEGRADED,
  `mqtt-malformed-control` PASS, `mqtt-stale-retained` PASS), 068 decomposed
  northbound fail-closed (`malform-*` PASS), context propagation (070),
  constraint shadow — none regressed control.
- No new DEGRADED signature appeared vs the M2 accepted ledger.

Single-run, not 10-cycle: the fuller 10-cycle FAST + 10-cycle STOCK campaigns
(09 Safety ◆) remain a pre-tag item (see checklist).

## Gate 4 — OCPP Security Profile 2 lockstep flip (◆): PASS
Full `docs/BENCH.md` SP2 runbook executed live (074):
- `gen-ev-cert.sh 69.0.0.1` → CSMS cert with **IP SAN 69.0.0.1** (key in
  gitignored vault).
- `deploy-hub-pi.sh --enable-ocpp-sp2` + **same-session**
  `update-sim-pis.sh --enable-ocpp-sp2` (lockstep).
- **Positive path:** hub logs `[ocpp] TLS enabled`; evsim ExecStart flipped to
  `wss://69.0.0.1:8887/ocpp -tls-ca … -auth-user evse-bench -auth-pass …`,
  logs `TLS enabled`; hub logs `connected: evse-001` + `BootNotification` over
  the TLS listener — the wss handshake + Basic Auth succeed and the OCPP
  lifecycle flows.
- **Negative auth (live):** wrong password → **401**, no auth → **401**, hub
  logs `basic-auth rejected user="evse-bench"`. Unit equivalent
  `go test ./cmd/ocpp/... -run TestOCPPSecurityProfile2_BasicAuth` → **ok**
  (wrong-pass / wrong-user / correct, real `ocppserver` code path).
- **7 EV scenarios over wss:** 4 PASS / 3 DEGRADED / **0 FAIL / 0 BLIND**
  (verdicts match the ws:// baseline; 0 BLIND confirms the transport swap did
  not break the EV control path).
- Rolled back to `ws://` (bench QA default) in the same session; full bench
  config re-applied. SP2 is validated and runbook-ready; `wss`+auth is the
  product default, `ws://` is the documented bench-only fallback.

## Gate 5 — Conformance regeneration (◆): PASS
On the frozen build (`CONFORMANCE_REPORT.md` updated):
- CSIP `run-conformance.sh` → **3 layers passed, 0 failed** (logic; TLS
  CCM-8 + wrong-CA/wrong-cipher reject; full-stack wolfSSL walk, cipher
  `ECDHE-ECDSA-AES128-CCM-8` verified).
- Modbus/SunSpec `modsim-conformance` vs live bench sims: inverter **19/0**,
  battery **22/0**, meter **9/0**.

## Gate 6 — New-scenario spot validation (batch backlog): 8 PASS / 1 DEGRADED-accepted / 2 real findings / 1 INCONCLUSIVE
First-ever bench run of the code-merged QA scenarios (038/042/043/049–052/054).
A batch run initially showed 6 FAIL, but triage found **5 were poisoned by a
single earlier scenario knocking `lexa-api` permanently offline** (see FINDING
A); re-run individually with a healthy `lexa-api`, they all PASS:

| Scenario | Task | Verdict (solo) | Note |
|---|---|---|---|
| duplicate-client-id | 049 | PASS | |
| mqtt-storm | 051 | PASS | |
| netem-loss-export-cap | 052 | PASS | |
| corrupted-retained-control | 042/043 | **PASS** | retained-trust: hub contained the corrupt control, held the cap |
| local-clock-step-forward | 038 | **PASS** | utilitytime monotonic anchoring holds |
| local-clock-step-back | 038 | **PASS** | |
| netem-reorder-northbound | 052 | **PASS** | |
| disk-full | 050 | **PASS** | |
| power-cut-retained-rollback | 043 | **FAIL** | FINDING A (real) |
| export-dither-at-breach | 054 | **FAIL** | FINDING B (real) |
| netem-jitter-evse | 052 | INCONCLUSIVE | needs passwordless sudo on ev-pi (infra) |

- **FINDING A (real) — `power-cut-retained-rollback`.** The GAP-01 unclean
  SIGKILL power-cut causes a ~40 s 4400 W export-cap breach during the rollback
  window (compliance-timing, SAFETY held), **and it crashes `lexa-api` past its
  systemd start-limit, leaving it permanently `inactive`** — which poisoned the
  five scenarios that ran after it in the batch (all diagnosed “/status
  unreachable” while the control plane, `lexa-hub`+`lexa-northbound`, stayed up
  and enforcing). Compounding root cause: **`lexa-api.service` puts
  `StartLimitIntervalSec`/`StartLimitBurst` in `[Service]`, where systemd
  ignores them** (journal: *“Unknown key 'StartLimitIntervalSec' in section
  [Service], ignoring”*), so it falls back to the default 10 s/5 window and
  gives up under the power-cut’s restart storm. **Fix:** move those two keys to
  `[Unit]` (all services), and size the rollback re-adopt window. Recovery:
  `systemctl reset-failed lexa-api && systemctl restart lexa-api`.
- **FINDING B (real) — `export-dither-at-breach` (054).** The hub posts
  CannotComply during a pure ±ε dither at `exportCap ≤ 0 W` that never sustains
  a real breach (breach-seconds 4 of 304 s): the leaky breach counter
  (`expOverTicks`/`genGuard.overCount`) accumulates across sub-threshold dither
  cycles — a false-positive CannotComply. SAFETY held; this is
  compliance-reporting precision, same class as `control-churn` (FINDING C),
  tracked to **TASK-064**.

## Findings summary (all → separate reviewed fixes, none authored here)
| # | Where | Severity | Disposition |
|---|---|---|---|
| A | power-cut rollback breach + `lexa-api` start-limit unit bug | med | fix unit `[Unit]` section + rollback window; recovery documented |
| B | dither false CannotComply (leaky counter) | low | → TASK-064 (adaptive window) |
| C | control-churn convergence-window borderline | low | → TASK-064 (accepted-borderline) |
| D | deploy: `/var/lib/lexa` not provisioned | low | add `StateDirectory=lexa` / deploy mkdir |

## What is shippable now vs external work remaining
**Shippable (validated on hardware, frozen build):** reconciler control
(battery/solar/EVSE), fail-closed disciplines, CannotComply chain, cert
monitoring (072) + rotation mechanism (073), OCPP SP2 (074), MQTT ACL (013),
lexa-api auth (014), cipher pinning + mTLS, watchdog on all six, compliance
journal (039/040) + snapshot (041) live on disk, metrics on all services (044),
CSIP + Modbus conformance.

**External / pre-tag (not blockers this gate — see 09 for the PENDING set):**
10-cycle FAST + 10-cycle STOCK campaigns; 30-day soak (078); golden vendor
fixtures (075, needs HW); cert-rotation 24 h churn soak (073); constraint
shadow→active flip (≥1-week soak, 03 §P5); P5 optimizer decomposition
(056–067, `optimizer.go` still 2289 lines — god-file box open); field pilot;
third-party cert lab. Plus FINDINGS A–D above.

## Bench final state
Restored clean: FAST timing, reconcilers active, `constraint_shadow=true`,
lexa-api auth ON, MQTT ACL ON, mqttproxy `:1882` pass-mode, OCPP `ws://`, all
services `active`.
