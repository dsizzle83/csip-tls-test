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
| P1 Shared modules (R2) | 019–024, 082 | IN PROGRESS (2026-07-05) | 021 lockstep: FAST 34P/17D/0F/0B; conformance 50/50; CSIP layers 1-3 3/3; 082 conformance ×3 vs live bench (unredeployed): 19/22/9 all PASS, matches 021 baseline | 019, 020, 021, 022, 023, 082 DONE (details in task headers + `docs/refactor/notes/` disposition docs). One shared codec proven on hardware; bench sunspec AND derbase forks deleted (082); lockstep gate green, 0 allow-list entries needed (csipref/derbase out of the gate's scope by design, AD-003(g)); AD-003(e) interim vendoring keeps hosted CI green until TASK-024 hosting; bench `internal/csip/discovery`+`scheduler` moved to `internal/csipref`, recorded as a deliberate conformance referee (AD-003(f)/(g), diff-rq exit-criterion exception in 03). Remaining: 024 (pin gate; also should carry forward the "no allow-list needed for csipref/derbase" note when it replaces the gate). |
| P2 Device Reconciler (R1) | 025–033 | IN PROGRESS (2026-07-05) | — | Critical path. 025 DONE: AD-013 desired-state schema + bus types (`internal/bus/desired.go`, unused) + `PRESERVATION_LEDGER.md` (11 rows, every legacy convergence mechanism → gate scenarios; 8/11 line-cites re-verified/corrected). AD-002 open questions closed (meter: no desired doc; interlock: measurement-only). |
| P3 Time & persistence | 034–043 | NOT STARTED | — | |
| P4 Observability & QA depth | 044–055 | IN PROGRESS (2026-07-05) | — | Parallel track. 047 DONE (code+CI on lexa-hub `task/047-httpwire`, review/merge pending): tlsclient parsing core → CGo-free `internal/tlsclient/httpwire` leaf; missing 64 KiB header cap added; 3 fuzz targets seeded with 11 real gridsim responses, 15 min/target clean (0 crashers); nightly CI fuzz job (no sysroot needed). AD-009 updated — corpus + zero-findings feed the TASK-069 shim-vs-harden decision. Bench items (conformance smoke, Mayhem spot runs) batched to next deploying session. |
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
