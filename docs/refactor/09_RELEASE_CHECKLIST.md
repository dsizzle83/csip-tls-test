# 09 — V1.0 Release Checklist

*The definition of "shippable to a paying utility." Every box needs linked
evidence (campaign report, CI run, doc, config). Executed as TASK-081.
Boxes marked ◆ are hard gates — no waivers without an AD entry in 02.*

**Walk status (2026-07-06, TASK-081 V1.0-RC gate):** frozen build
`lexa-hub@c730302` · `csip-tls-test@695da02` · `lexa-proto@4e8b940`.
Primary evidence: `docs/QA_REPORT_V1RC_20260706.md` (gate report),
`CONFORMANCE_REPORT.md` (regenerated), `logs/campaign-v1rc-fast-20260706/`.
Legend: `[x]` satisfied with evidence · `[ ] PENDING` genuinely-external / not
run this gate (runbook noted) · `[ ] OPEN` blocked on a named finding.
This walk is a **release-candidate readiness** pass, not the final tag; the
tag follows once the PENDING measurement gates and FINDINGS A–D close.

## Process & CI
- [ ] ◆ PENDING — CI green on both repos: build, `go vet`, `-race` unit suites, conformance logic tests, `govulncheck` clean, lockstep/module-pin gate (002–005, 024). *This gate ran conformance-logic (green, 3/3 layers) + the SP2 unit test (green) + module pins verified (both repos `replace lexa-proto => ../lexa-proto`, identical `4e8b940`); full `-race`/`govulncheck`/vet CI run not executed here — attach the CI links at tag.*
- [ ] ◆ PENDING — Zero uncommitted work; `main` protected; all release commits PR-reviewed (001). *Both repos were clean on `main` at freeze; branch-protection screenshot/link is an external artifact to attach.*
- [ ] PENDING — Nightly fuzz jobs ≥30 days without new crashers (047, 048). *Fuzz corpora merged (65 M+ execs, 0 crashers historically, 053); 30-day nightly window is external.*
- [ ] PENDING — Toolchain: supported Go release; dependencies within one minor or waivered (006).

## Safety & control behavior
- [ ] ◆ PENDING (single-run PASS) — 10-cycle **FAST** Mayhem campaign: 0 FAIL, 0 BLIND, DEGRADEDs ⊆ ledger. *This gate ran **1 cycle**: 32P/18D/**1F**(explained)/**0 BLIND** — the one FAIL (`control-churn`) is the accepted-borderline convergence-window class (FINDING C, → TASK-064; SAFETY held). All historically-failing scenarios now PASS. `docs/QA_REPORT_V1RC_20260706.md` §Gate 3. Full 10-cycle FAST is the pre-tag run.*
- [ ] ◆ PENDING — 10-cycle **STOCK** Mayhem campaign (015). *Not run this gate; GAP-15 closure needs the shipped-timing run. Prior STOCK baseline: `docs/QA_REPORT_STOCK_M0_20260705.md`.*
- [x] ◆ Preservation-ledger scenarios individually green on the shipping build (025 ledger). *Reconciler ledger proven at M2 (`docs/QA_REPORT_M2_20260706.md`); this gate re-confirmed the reconciler paths (`release-while-rebooting`, `curtailment-release`, battery/solar/EVSE all PASS/DEGRADED-accepted).*
- [x] ◆ Battery safety chain: Tier-0 interlock, Tier-1 fast trip, reserve protection. *SAFETY AUDIT (INV-SOC/INV-EXPIRED/INV-EVMAX/INV-CONNECT) **held on every scenario** across the full campaign + all gate-6 runs (0 safety violations); mutation-verified reconciler tests at 99.4% cov (026/M2).*
- [x] ◆ Fail-closed disciplines: scheduler last-known-good, outage hold, clock-regression + default-fallback, local expiry (035). *Live PASS: `wan-outage-hold`, `wan-outage-expiry`, `northbound-hang`, `expired-control`, `local-clock-step-forward/back` (038), `corrupted-retained-control`, `malform-*`. `QA_REPORT_V1RC` §Gate 3/6.*
- [x] Export/import/gen convergence + CannotComply incl. restart-mid-breach (031, 041). *`hub-restart-mid-cap` PASS (re-adopts retained control on restart); snapshot on disk. Borderline: `control-churn`/`export-dither` late/false CannotComply (FINDINGS C/B, → TASK-064).*

## Security
- [x] ◆ Broker: per-service credentials + topic ACLs; `allow_anonymous false` (013). *Deployed `--enable-mqtt-acl`; each service logs `broker user=lexa-*`; `allow_anonymous false` + `password_file`/`acl_file` live. `docs/BENCH.md` §MQTT ACL.*
- [x] ◆ lexa-api: auth; no unauthenticated surface (014). *`--enable-api-auth`: `/status` 401 without token, 200 with, `/healthz` always open. (TLS termination is a deployment concern per AD-008; bench uses bearer-over-HTTP on the LAN.)*
- [x] ◆ OCPP: security profile ≥2 **enabled** (074). *Live lockstep flip validated: wss + Basic Auth, positive path (BootNotification over TLS) + negative auth (401 + `basic-auth rejected`) + unit test PASS + 7 EV scenarios over wss (0 FAIL/0 BLIND). `ws://` documented bench-only. `QA_REPORT_V1RC` §Gate 4.*
- [x] ◆ Cipher pinning unchanged (`ECDHE-ECDSA-AES128-CCM-8 TLSv1.2`); `RequireClientCert` audit. *Fresh audit: `DefaultCipherList = "ECDHE-ECDSA-AES128-CCM-8"` in `tlsclient/config.go` + `tlsserver/config.go`; `wolfssl.RequireClientCert` at `sim/tlsserver/server.go:78` (only production mTLS server); conformance Layer 2 asserts CCM-8 + wrong-cipher reject.*
- [x] Hostile-boundary parsers fuzzed with size caps (047, 048). *httpwire/XML/bus-JSON fuzz merged (053: 65 M execs, 0 crashers); live `malform-empty-program`/`malform-huge-activepower`/`malformed-csip` PASS (fail-closed).*
- [x] Private keys: gitignore audit; deployment `install -m 600`; no keys in images. *Fresh audit: `certs/client-key.pem` gitignored; no tracked `*-key.pem`; tracked pems are public certs only; deploy stages keys `install -m 600 -o lexa`.*
- [ ] PENDING — Vulnerability management: `govulncheck` in CI + monthly triage (005). *Not run this gate.*
- [x] Bench-only open surfaces (simapi, admin :11112, dashboard) documented as non-product (AD-008). *`docs/BENCH.md` + AD-008.*

## Certificates
- [x] ◆ Expiry monitoring + alert ≥30 days out (072). *Live: `lexa-northbound` logs `certificate expiry OK client_days_left=341 ca_days_left=3622`; `/status` reports expiry. Alert fires ≥30 d out.*
- [ ] ◆ PENDING (mechanism done, soak pending) — Rotation without control interruption incl. reconnect-churn soak (073). *Probe-then-commit `WolfSSLFetcher.Reload` merged (`c730302`), unit + real-wolfSSL integration tests green; 24 h reconnect-churn soak DEFERRED — runbook `docs/CERT_ROTATION_SOAK_RUNBOOK.md` + `scripts/cert-churn-soak.sh`. RSK-07.*
- [x] Re-enrollment/commissioning runbook (LFDI/SFDI, `gen-client-cert`). *`make gen-client-cert CN=…`; SFDI/LFDI derivation in CONFORMANCE_REPORT §BASIC-001.*

## Reliability & operations
- [x] ◆ `WatchdogSec` + `sd_notify` on all six services; wedge test demonstrates restart (007, 008). *All six `Type=notify` + `WatchdogSec` (60 s; northbound 120 s); live `SIGSTOP` wedge on `lexa-telemetry` → watchdog restarted it at t≈57 s, `NRestarts=1`. `QA_REPORT_V1RC` §Gate 2.*
- [ ] ◆ OPEN (FINDING A) — Restart safety: power-cut retained rollback + corrupted-retained PASS (043); snapshot restore (041). *`corrupted-retained-control` PASS, `hub-restart-mid-cap` PASS, snapshot on disk (`/var/lib/lexa/snapshot/hub.json`) — but **`power-cut-retained-rollback` FAILs**: ~40 s export breach on rollback (SAFETY held) **and it crashes `lexa-api` past its systemd start-limit** (unit bug: `StartLimitIntervalSec` in `[Service]` is ignored). FINDING A in `QA_REPORT_V1RC`; needs the unit fix + rollback-window tuning before this ◆ closes.*
- [x] Journald rate/size caps + flash write budget (009); journal rotation proven (039). *Units set journald output; compliance journal live on disk (`journal/hub/journal.ndjson` 1435 entries, `journal/northbound` 77, structured `{v,ts,seq,type,svc,data}`). Rotation-under-size proof: attach at tag.*
- [x] Tick budget: no synchronous publish stalls; overrun counter under broker-latency (046). *`mqtt-broker-latency` PASS (async publishes merged); overrun counter exposed via `/metrics`.*
- [x] Broker-loss behavior documented + scenario-verified (051). *`mqtt-broker-restart` DEGRADED (bounded, recovers), `mqtt-storm` PASS, `duplicate-client-id` PASS.*
- [ ] PENDING — Deploy: scripts idempotent, preserve timing mode, keep rollback backup; runbooks current. *Deploy is idempotent but **resets timing to STOCK + clobbers bench config** (documented gotcha, re-applied each time) and **does not provision `/var/lib/lexa`** (FINDING D). Timing-preserve + `StateDirectory=lexa` are the fixes.*

## Observability
- [x] ◆ `/metrics` on all services, scraped; dashboards for control/convergence/breach/CannotComply/tick/MQTT/cert/watchdog (044). *Live `/metrics` on hub:9101, northbound:9102, modbus:9103, ocpp:9104 (28–36 series each), api:9100/metrics; `scripts/prometheus-bench.yml` scrape config. (telemetry:9105 was mid-restart at capture — re-verify.)*
- [x] Plan-heartbeat stall alert consuming `lexa/hub/plan` (045). *`/status.plan_heartbeat` = `{state:ok, age_s}` live.*
- [x] Structured logs with transition-not-steady-state discipline (045). *slog structured logs across services (transition events, not per-tick spam; −957 LOC publish-spam removed at 032).*
- [x] ◆ Compliance event journal: adoptions, dispatches, breaches, CannotComply — rotated, restart-surviving, documented (039, 040). *Live NDJSON journal with `seq`, survives hub restart; sample `{"type":"dispatch","svc":"hub","data":{"device":"inverter-0","ceiling_w":5588}}`. Utility-audit format documented (039).*

## Conformance & protocol
- [x] ◆ Full CSIP conformance evidence regenerated on the release build (`run-conformance.sh`; CONFORMANCE_REPORT.md updated). *3 layers passed / 0 failed; cipher CCM-8 verified. `CONFORMANCE_REPORT.md` §V1.0-RC regeneration.*
- [x] ◆ Modbus/SunSpec conformance: all three device types (modsim-conformance). *inverter 19/0, battery 22/0, meter 9/0 vs live bench sims.*
- [ ] ◆ PENDING — Golden vendor fixtures green against shipping `lexa-proto` (075). *Needs vendor hardware captures (RSK-16); until then conformance-green is necessary-not-sufficient.*
- [ ] PENDING — Server poll-interval compliance verified against gridsim (071). *Not re-run this gate.*
- [x] Curve-functions scope: implemented **or** de-scoped in writing (080 / AD-010) — **de-scoped**, 2026-07-06: AD-010 (`02_ARCHITECTURE_DECISIONS.md`) + `docs/refactor/adr-inputs/curve-functions-survey.md`; conformance-statement language applied at TASK-081's regeneration.
- [ ] PENDING — Bus schema versions frozen + documented; mixed-version behavior defined (017, 018).

## Performance & endurance
- [ ] ◆ PENDING — 30-day soak: flat RSS/fd/goroutine, zero watchdog fires, netem chaos windows survived (078). *External; TASK-078 rig + runbook exist. Must start ≥30 days before tag; this gate's redeploy invalidates any in-flight window — a fresh window is required.*
- [x] MQTT storm scenario: bounded latency, counted drops (051). *`mqtt-storm` PASS.*
- [ ] PENDING — 92-day bench replay within cost/compliance envelope (release build). *Not run this gate; `docs/REPLAY_RUNBOOK.md`.*

## Multi-device & field readiness
- [ ] ◆ PENDING — Second inverter + second EVSE scenarios PASS; multi-breach reporting verified (065). *Bench ran single inverter/EVSE this gate; multi-device scenario set is a pre-tag run (RSK-18).*
- [ ] PENDING — Plant-model parameters documented per device; no "20× demo" constants in product code (064). *Tied to TASK-064 (R4 constraint controller / plant model), also the fix vector for FINDINGS B/C.*
- [ ] PENDING — Field pilot: ≥1 non-bench site, ≥30 days, incident review. *External; owner's call to carry post-tag (not ◆).*
- [ ] PENDING — Third-party conformance/certification engagement scheduled or complete. *External (RSK-15); pre-audit package = the regenerated conformance evidence + AD-010.*

## Documentation & maintainability
- [x] CLAUDE.md invariants current in both repos; 02/05/06 match shipped reality. *Invariants (cipher, mTLS, wolfSSL_Init, XML ns, clock offset, register scaling, OCPP lifecycle, keys, fetcher) audited against code this gate — all hold.*
- [x] Operator runbook: install, commission, rotate certs, read journal, interpret alerts. *`docs/BENCH.md` (deploy, SP2, MQTT ACL, api-auth), `docs/CERT_ROTATION_SOAK_RUNBOOK.md`, `docs/REPLAY_RUNBOOK.md`.*
- [ ] PENDING — Onboarding doc: a new engineer can deploy the bench + run a campaign from docs alone (kills RSK-11). *Needs the non-author walk-through test.*
- [ ] OPEN — No file >600 lines in `internal/orchestrator`; god-file audit clean (066, 068). *068 northbound decomposition DONE (1206→241). **`internal/orchestrator/optimizer.go` is 2289 lines** — P5 optimizer decomposition (056–067) not yet on `main`; box closes when P5 merges.*
