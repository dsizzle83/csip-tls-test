# 09 — V1.0 Release Checklist

*The definition of "shippable to a paying utility." Every box needs linked
evidence (campaign report, CI run, doc, config). Executed as TASK-081.
Boxes marked ◆ are hard gates — no waivers without an AD entry in 02.*

## Process & CI
- [ ] ◆ CI green on both repos: build, `go vet`, `-race` unit suites, conformance logic tests, `govulncheck` clean (or triaged allowlist), lockstep/module-pin gate (TASK-002–005, 024)
- [ ] ◆ Zero uncommitted work; `main` protected; all release commits PR-reviewed (001)
- [ ] Nightly fuzz jobs ≥30 days without new crashers (047, 048)
- [ ] Toolchain: supported Go release; dependencies within one minor of upstream or waivered (006)

## Safety & control behavior
- [ ] ◆ 10-cycle **FAST** Mayhem campaign: 0 FAIL, 0 BLIND, DEGRADEDs ⊆ accepted ledger (033/066 baseline maintained)
- [ ] ◆ 10-cycle **STOCK** Mayhem campaign: same bar — the shipped timing is the tested timing (015)
- [ ] ◆ Preservation-ledger scenarios individually green on the shipping build (025 ledger)
- [ ] ◆ Battery safety chain intact: Tier-0 interlock, Tier-1 fast trip, reserve protection — mutation-verified tests present (existing + 056)
- [ ] ◆ Fail-closed disciplines verified: scheduler last-known-good, outage hold, clock-regression + default-fallback guards, local expiry (035 ports)
- [ ] Export/import/gen convergence + CannotComply verified end-to-end incl. restart-mid-breach (031, 041)

## Security
- [ ] ◆ Broker: per-service credentials + topic ACLs; `allow_anonymous false` (013)
- [ ] ◆ lexa-api: TLS + auth; no unauthenticated surface on the product image (014)
- [ ] ◆ OCPP: security profile ≥2 **enabled** (implementation already exists in ocppserver/evsim — 074 is provisioning + enablement); `ws://` documented bench-only, disabled in product config (074)
- [ ] ◆ Cipher pinning unchanged (`ECDHE-ECDSA-AES128-CCM-8 TLSv1.2`); `RequireClientCert` audit across all servers
- [ ] Hostile-boundary parsers fuzzed with size caps (readResponse/XML/bus JSON) (047, 048)
- [ ] Private keys: gitignore audit; deployment `install -m 600 -o lexa`; no keys in images/backups
- [ ] Vulnerability management: `govulncheck` in CI + documented monthly triage process (005)
- [ ] Bench-only open surfaces (simapi, admin :11112, dashboard) documented as non-product (AD-008)

## Certificates
- [ ] ◆ Expiry monitoring + alert ≥30 days out (072)
- [ ] ◆ Rotation procedure without control interruption, exercised on bench incl. reconnect-churn soak (073)
- [ ] Re-enrollment/commissioning runbook (LFDI/SFDI derivation, `gen-client-cert` flow)

## Reliability & operations
- [ ] ◆ `WatchdogSec` + `sd_notify` on all six services; wedge test demonstrates restart (007, 008)
- [ ] ◆ Restart safety: power-cut retained rollback + corrupted-retained scenarios PASS (043); snapshot restore on (041)
- [ ] Journald rate/size caps + flash write budget documented (009); journal rotation proven (039)
- [ ] Tick budget: no synchronous publish stalls; overrun counter zero under broker-latency scenario (046)
- [ ] Broker-loss behavior documented + scenario-verified (existing scenarios + 051)
- [ ] Deploy: scripts idempotent, preserve timing mode, keep rollback backup; DEVKIT/hub-Pi runbooks current

## Observability
- [ ] ◆ `/metrics` on all services, scraped; dashboards for: control adoption, convergence, breach episodes, CannotComply, tick duration, MQTT depth, cert expiry, watchdog (044)
- [ ] Plan-heartbeat stall alert consuming `lexa/hub/plan` (045)
- [ ] Structured logs with transition-not-steady-state discipline (045)
- [ ] ◆ Compliance event journal: adoptions, dispatches, breaches, CannotComply — rotated, restart-surviving, documented for utility audit (039, 040)

## Conformance & protocol
- [ ] ◆ Full CSIP conformance evidence regenerated on the release build (`scripts/run-conformance.sh`; CONFORMANCE_REPORT.md updated)
- [ ] ◆ Modbus/SunSpec conformance: all three device types (modsim-conformance)
- [ ] ◆ Golden vendor fixtures green against shipping `lexa-proto` (075)
- [ ] Server poll-interval compliance verified against gridsim (071)
- [ ] Curve-functions scope: implemented **or** de-scoped in writing (080 / AD-010)
- [ ] Bus schema versions frozen + documented; mixed-version behavior defined (017, 018)

## Performance & endurance
- [ ] ◆ 30-day soak: flat RSS/fd/goroutine, zero watchdog fires, netem chaos windows survived (078)
- [ ] MQTT storm scenario: bounded latency, counted drops (051)
- [ ] 92-day bench replay within cost/compliance envelope (existing replay, release build)

## Multi-device & field readiness
- [ ] ◆ Second inverter + second EVSE scenarios PASS; multi-breach reporting verified (065)
- [ ] Plant-model parameters documented per supported device; no "20× demo" constants in product code (064)
- [ ] Field pilot: ≥1 non-bench site, ≥30 days, incident review complete
- [ ] Third-party conformance/certification engagement scheduled or complete (IEEE 1547.1 / CSIP lab)

## Documentation & maintainability
- [ ] CLAUDE.md invariants current in both repos; 02/05/06 docs match shipped reality
- [ ] Operator runbook: install, commission, rotate certs, read journal, interpret alerts
- [ ] Onboarding doc: a new engineer can deploy the bench + run a campaign from docs alone (kills RSK-11)
- [ ] No file >600 lines in `internal/orchestrator`; god-file audit clean (066, 068)
