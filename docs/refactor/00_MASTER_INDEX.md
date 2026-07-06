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
| P0 Foundations | 001–018 | **COMPLETE — M0 (2026-07-05)** | FAST 35P/16D/0F/0B (`qa-mayhem-20260705-053159.md`); post-006 32P/19D/0F/0B (`qa-mayhem-20260705-091544.md`); STOCK M0 baseline 0.8F/cyc 0B (`docs/QA_REPORT_STOCK_M0_20260705.md`) | All 18 tasks done + merged (details in task headers + campaign reports). Watchdogs wedge-proven ×6; journald measured (FLASH_BUDGET updated); broker ACL + API auth LIVE on bench; deps current, govulncheck 0 findings, vulncheck CI required; 2 STOCK findings filed (QA-STOCK-001/002). Open (human): `LEXA_HUB_RO_TOKEN` PAT + required-checks toggle (AD-012/TASK-004); branch protection ON both repos (pushes currently admin-bypass, PR flow needs `gh` auth). |
| P1 Shared modules (R2) | 019–024, 082 | **COMPLETE — M1 (2026-07-05)** | 021 lockstep: FAST 34P/17D/0F/0B; conformance 50/50 (re-verified at 082); CSIP layers 1-3 3/3 | All 7 tasks done + merged. One shared codec (lexa-proto: sunspec/modbus/ocppserver/csipmodel/derbase) proven on hardware; every fork disposed or referee-designated (AD-003(g)/(h)); proto.pin gate live in both CIs; interim vendoring (AD-003(e)) until hosting. Open (human): create dsizzle83/lexa-proto + hosted-flip checklist (AD-003(f), backlog); CSIP_TLS_TEST_RO_TOKEN + LEXA_HUB_RO_TOKEN PATs for the cross-repo CI jobs. |
| P2 Device Reconciler (R1) | 025–033 | **COMPLETE — M2 (2026-07-06)** | 10-cycle FAST soak: avg 34.1P/16.8D/**0.10 FAIL/cyc**/0 BLIND (`docs/QA_REPORT_M2_20260706.md`) | R1 PROVEN ON HARDWARE. All 3 device classes reconciler-active; 4 convergence mechanisms → 1; CannotComply 5→3 hops (breachEpisodes); legacy machinery deleted (−957 LOC). Sole FAIL = characterized boundary flake (battery-charge-disabled 1/10, export-detection latency → TASK-064; safety never at risk, code path intact). 033 sign-off = this report. Follow-ups: 041-NB snapshot half, phase-QA-scenario bench validation. |
| P3 Time & persistence | 034–043 | IN PROGRESS | — | 034 utilitytime core + 035 walker/scheduler (guards verbatim, failclosed untouched) + 036 hub/api/optimizer + 037 local clock-step (monotonic anchoring) all DONE + MERGED — **W4 closed, one time owner**. 039 journal library DONE + MERGED (zero consumers). 040 journal wiring code complete (`lexa-hub` merge `38496e0`). **041 PARTIAL (2026-07-06, `lexa-hub` `task/041-snapshot`, unmerged):** hub-side breach-episode snapshot (atomic tmp+rename, 60 s while-active resave, restore-on-start behind `hub.json` `snapshot.enabled` default off) code complete + unit-tested (`go test -race ./internal/... ./cmd/...` green); northbound-side `responseTracker` persistence and all bench acceptance criteria (live restart evidence, `hub-restart-mid-cap` 10×, flag-on/flag-off campaigns) not done this session — see AD-005's TASK-041 update. Remaining: 038 (local-clock scenario), 041's northbound half + bench validation, 042/043 (retained-trust + power-cut scenarios). |
| P4 Observability & QA depth | 044–055 | IN PROGRESS | — | Parallel track. DONE + MERGED: 044 metrics, 045 slog+heartbeat, 047 httpwire+fuzz, 048 XML/bus fuzz, 049/050/051 (dup-client-ID, disk-full, mqtt-storm), 052 (netem harness), 053 int16/scale sweep (65M execs 0 crashers), 054 (dither sweeps, extended-set), 055 NaN-string bus robustness — all code-merged, bench validation batched to next deploying session. Remaining: 046 (async publishes). |
| P5 Optimizer split (R4) | 056–067 | IN PROGRESS | — | Critical path. 056 DONE (unblocker): orchestrator decision-string oracles replaced with behavioral plan assertions (solar `CurtailToW`, EVSE `MaxCurrentA`), mutation-verified ×3; test-only, zero product LOC (GAP-14). Migrations 058–067 now have a refactor-proof behavior net. 057 DONE: plant-model vocabulary (`internal/orchestrator/plantmodel.go` + hub.json per-device `plant` schema, AD-007) — bench-constant defaults, unwired (05 §12 exception); TASK-064 wires + burns down the globals. 058 DONE: constraint-controller skeleton `internal/orchestrator/constraint` (Constraint/Demand/Arbiter/Session/Stack; safety>compliance>economics, bounds-intersection narrowing-only, per-device detection-window derivation from plant model) — Stack implements `orchestrator.Optimizer`, unwired (05 §12); TASK-059 shadow harness is first caller. 059 DONE: shadow-mode dual-run harness (`internal/orchestrator/constraint/shadow.go`) behind `hub.json` `constraint_shadow` (default off) — wraps the live optimizer, runs the candidate Stack observe-only each tick, tolerance-banded candidate-scoped diff of FINAL per-device outputs, rate-limited JSON divergence log + `lexa_constraint_shadow_divergence_total` metric + `shadow_divergences` on `lexa/hub/plan`; legacy cascade stays sole actuator. Flag-on campaign deferred to 060's flip gate (05 §12 shadow-only). |
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
