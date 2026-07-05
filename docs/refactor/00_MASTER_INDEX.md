# 00 — Master Index: LEXA DERMS V1.0 Refactor Program

*Generated 2026-07-04 from `ARCHITECTURE_REVIEW.MD`. This directory is the
engineering playbook for delivering Version 1.0. Start here.*

## The documents

| Doc | What it is | Update cadence |
|---|---|---|
| `00_MASTER_INDEX.md` | This file: map + program status | Every phase boundary |
| `01_IMPLEMENTATION_GAMEPLAN.md` | Vision, philosophy, priorities, milestones, timeline, definition of done | Rarely (structural changes only) |
| `02_ARCHITECTURE_DECISIONS.md` | Living decision log (AD-001…) incl. open questions | Whenever a decision is made/superseded |
| `03_REFACTOR_PHASES.md` | Phases P0–P6: purpose, risks, rollback, exit criteria | Phase boundaries |
| `04_DEPENDENCY_GRAPH.md` | **Task inventory (single source of truth)**, blocking graph, critical path, review-item traceability | When tasks are added/split |
| `05_ENGINEERING_PRINCIPLES.md` | Standards that prevent W1–W7 recurring | Rarely |
| `06_TESTING_STRATEGY.md` | Every test layer, gates, missing coverage | Phase boundaries |
| `07_QA_GAP_PLAN.md` | Review §9 blind spots → prioritized work | As gaps close |
| `08_RISK_REGISTER.md` | Risks, mitigation, detection, recovery | Phase boundaries + incidents |
| `09_RELEASE_CHECKLIST.md` | V1.0 ship gate (executed as TASK-081) | As boxes close |
| `10_BACKLOG.md` | Valuable, non-critical-path work | Phase boundaries |
| `tasks/TASK-001…082.md` | Self-contained implementation tasks (hand one to a coding model verbatim) | Task completion → status header |
| `tasks/TASK_TEMPLATE.md` | Canonical task structure | Rarely |

## Reading order

1. **New to the program:** 01 → 03 → 05 → this status table.
2. **Picking up work:** status table below → 04 (is it unblocked?) → the
   task file → its "Files to read" list.
3. **Making a design call:** 02 (has it been decided?) → add/extend an AD.
4. **Before merging anything in the radioactive zone** (05 §12): 06 gates.
5. **Cutting a release:** 09.

Background (read once): `ARCHITECTURE_REVIEW.MD` (repo root),
`lexa-hub/docs/ADR-0001-distributed-vs-monolith.md`, `docs/BENCH.md`,
`docs/QA_GAPS_20260701.md`, both repos' `CLAUDE.md`.

## How the documents relate

`ARCHITECTURE_REVIEW.MD` findings → traceability matrix (04 §5) → phases
(03) → tasks (04 §1, `tasks/`). Decisions the tasks depend on live in 02;
the behavior they must not break lives in 05/06 and each task's
"Things that must NOT change"; the risks they carry live in 08; the finish
line is 09. 07 is the QA-specific slice of the same pipeline.

## Program status

*Update this table as work lands. "Campaign" = full Mayhem run reference.*

| Phase | Tasks | Status | Exit campaign | Notes |
|---|---|---|---|---|
| P0 Foundations | 001–018 | P0 COMPLETE (pending Principal review) | 51-scen FAST 32P/19D/0F/0B post-006 (`qa-mayhem-20260705-091544.md`) | Done + merged: 001–005, 010–018 except as noted (details in task headers). 012 code validated (lexa-hub 8844f68; campaign 33P/17D/1F/0B, sole FAIL = known-flaky control-churn → TASK-060; merge on 2026-07-05 per 05 §12 cooling-off). 015 DONE (2026-07-05): first STOCK-timing Mayhem baseline recorded — 0.8 FAIL/cycle, 0 BLIND, 0 safety-invariant escalations (5 cycles/255 scenario-runs, `docs/QA_REPORT_STOCK_M0_20260705.md`); 2 findings filed (QA-STOCK-001/002), 0 margin edits — STOCK M0 baseline for TASK-081 to defend going forward. P0-EXIT GATE EXECUTED (2026-07-05): lexa-hub main (through merge 75f2943) deployed to hub Pi. 007/008 watchdogs PROVEN — SIGSTOP-wedge of all six services triggered systemd watchdog-kill + restart within ~1× WatchdogSec (modbus 65s, ocpp 66s, api 64s, telemetry 66s, hub 64s; northbound 129s @120s watchdog), every service recovered and data resumed. 009 journald measured over 10min FAST: ~148 lines/min aggregate (hub 108, nb/modbus/ocpp ~12 each, telemetry 3, api 0.1) ≈ 213k lines/day — all far under per-unit LogRateLimitBurst caps; `journald.conf.d/lexa.conf` (SystemMaxUse=200M) installed, disk 34.8M. NOTE: hub line-rate ~2.7× FLASH_BUDGET.md's per-tick estimate (still << cap) — update that table's numbers, no cap change needed. 013 ACL FLIPPED (allow_anonymous false, password_file+acl_file live; anon CONNECT refused, per-service creds accepted; qa-inject provisioned via mqtt-chaos deploy). 014 API AUTH FLIPPED (api_token_file set; /status 401 w/o token, 200 with, /healthz 200; dashboard + metersim carry the token, no 401s). 018 rolling-restart self-healed on deploy. Validation: targeted 5-scenario 3P/2D/0F (`qa-mayhem-20260705-042237.md`) + FULL 51-scenario FAST 35P/16D/**0 FAIL**/0 BLIND/0 INCONCLUSIVE (`qa-mayhem-20260705-053159.md`). 006 DONE (2026-07-05, `task/006-dep-refresh` both repos, unmerged): Go 1.21→1.26 both repos; x/crypto/x/net/x/sys/x/sync refresh both repos (clears 47/csip-tls-test + 42/lexa-hub Required-tier + GO-2025-3503 Called-tier); paho.mqtt.golang 1.4.3→1.5.1 lexa-hub-only, own commit, campaign-gated (clears GO-2025-4173) — mqttutil's OnConnect-fires-every-reconnect/CleanSession-default-true/WaitTimeout assumptions re-verified against v1.5.1 source, still hold. govulncheck now 0 Called/0 informational both repos; `vulncheck` CI job flipped to required (both workflows). Gate campaigns: post-x/* full FAST 34P/17D/0F/0B, post-paho mqtt×10-solo 0F/0B + full FAST 32P/19D/0F/0B — all verdict deltas vs the 35P/16D baseline are documented historically-wobbly scenarios (`battery-charge-disabled`, `clock-jitter`, `conflicting-primacy`, `mqtt-broker-latency`, `mqtt-broker-restart`, `pv-flicker`), 0 unexplained FAIL throughout. Found+fixed an unrelated blocking bug in `deploy-hub-pi.sh` (06931cc's `root:root 0600` mosquitto passwd/acl mode is unreadable by the privilege-dropped mosquitto process — broke every `--enable-mqtt-acl` deploy; reverted to `root:mosquitto 0640` in lexa-hub `7ea23f9`) — flagged for Principal review, recommended cherry-pick to main independent of TASK-006. **P0 is now complete pending Principal Engineer review/merge of 006 (and 012, still on its own branch per cooling-off) and the human-side open item below.** Open: branch protection + `LEXA_HUB_RO_TOKEN` PAT (human, AD-012/TASK-004). |
| P1 Shared modules (R2) | 019–024, 082 | NOT STARTED | — | |
| P2 Device Reconciler (R1) | 025–033 | NOT STARTED | — | Critical path |
| P3 Time & persistence | 034–043 | NOT STARTED | — | |
| P4 Observability & QA depth | 044–055 | NOT STARTED | — | Parallel track |
| P5 Optimizer split (R4) | 056–067 | NOT STARTED | — | Critical path |
| P6 Commercialization | 068–081 | NOT STARTED | — | Order hardware during P2 |

**Milestones:** M0 = P0 exit · M1 = P1 · M2 = P2 · M3 = P3+P4 · M4 = P5 ·
M5 = V1.0 (see 01 §9).

**QA baseline to defend:** V6 campaign, 0.6 FAIL/cycle, 0 BLIND
(2026-07-03); accepted DEGRADEDs per `docs/QA_REPORT_V5_20260703.md` + V6
notes. Next scheduled: V7 10-cycle (expected ~0 FAIL) — becomes the M0
FAST baseline if clean.

**STOCK M0 baseline (2026-07-05, TASK-015):** 0.8 FAIL/cycle, 0 BLIND, 0
safety-invariant escalations (5 cycles/255 scenario-runs, first campaign run
in the product's actual shipping timing regime); see
`docs/QA_REPORT_STOCK_M0_20260705.md`. Future STOCK release gates (TASK-081)
compare against this number.

## Working agreements (short form)

- Task files are written to be handed to a smaller coding model verbatim;
  if one needed extra context to succeed, fix the task file afterward.
- In task files, **symbol names are authoritative; line numbers are hints**
  — the tree moves under a months-long program, so re-verify any `file:line`
  by grep at execution time before editing.
- Full Mayhem campaign before merging radioactive-zone changes; bench must
  be FAST (`bash scripts/bench-up.sh --fast`); STOCK campaigns at release
  gates.
- Nothing uncommitted overnight. Lockstep changes ship same-session in
  both repos.
- Every completed task updates: its own status header, this status table,
  and any invariant doc it touched.
