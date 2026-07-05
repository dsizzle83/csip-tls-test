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
| P2 Device Reconciler (R1) | 025–033 | IN PROGRESS (2026-07-05) | — | Critical path. 025 DONE: AD-013 desired-state schema + bus types (`internal/bus/desired.go`, unused) + `PRESERVATION_LEDGER.md` (11 rows, every legacy convergence mechanism → gate scenarios; 8/11 line-cites re-verified/corrected). AD-002 open questions closed (meter: no desired doc; interlock: measurement-only). 026 DONE (lexa-hub aba9988, unwired per 05 §12): pure I/O-free reconciler core `internal/reconcile` — write-on-diff / verify-by-readback / reassert-on-reconnect / retry-backoff / non-convergence + AD-013 seq/staleness/NaN/SeqReset; subsumes ledger L1–L4 semantics; injected clock; exhaustive table-driven suite `go test -race`, 99.4% coverage; ledger rows unchanged (replaces nothing yet). 027 **DONE at the P2 wave gate (2026-07-05)**: shadow live on the bench (`"reconciler":{"battery":"shadow"}`), retained doc on `lexa/desired/battery/battery-0`, PRESERVATION_LEDGER L1–L4 → `shadow`. Wave gate found + fixed a blocking gap: `systemd/mosquitto-lexa.acl` had no `lexa/desired/` grant (retained doc silently dropped by the ACL'd broker; early shadow matches vacuous) — battery-scoped grants added, lexa-hub branch `task/027-desired-topic-acl` (1a2d777, needs merge). Soak: steady-state divergences 0; single counted divergence during battery-charge-disabled injection dispositioned (reconciler-notices-faster, T028 data); SeqReset/SeqRegression/StaleDesired all exercised on real faults; Connect-completeness hold confirmed live (matches counter freezes — by design, see ledger). Campaign 34P/17D/0F/0B (`qa-mayhem-20260705-151009.md`), better than pre-gate 32P/19D baseline. **028 DONE (2026-07-05, lexa-hub `task/028-battery-flip` f7dcef4, merge deferred to post-05 §12):** first live write-path flip — `"reconciler":{"battery":"active"}` on the bench; reconciler owns battery writes through the legacy registry path; `Reconnected` wired (shadow never fed it); Tier-0 interlock kept SENIOR via read-only `isTripped` (connect-restore suppressed while tripped → `InterlockHold`); legacy topic still published/subscribed but ignored on hw (belt-and-braces, deletion is 032). PRESERVATION_LEDGER L1–L4 battery → `reconciler-active`; AD-002 interlock-seniority confirmed in practice. Gates: targeted battery 3P/4D/0F/0B + full **33P/18D/0F/0B** (within 34P/17D band; sole P→D = pinned-accepted `export-cap-full-battery`), no INV-HUNT/oscillation, SAFETY held; evidence `docs/qa-task028/`. Bench left FAST + battery-active; rollback rehearsed. |
| P3 Time & persistence | 034–043 | IN PROGRESS (2026-07-05) | — | 034 DONE (lexa-hub 400b152, branch `task/034-utilitytime`): AD-004 core library `internal/utilitytime` (`Clock`/`SetOffset`→`StepClass`/`Offset`/`ServerNow`/`ServerNowAt`, `Expired`/`InWindow`, `DebouncedExpiry`/`ReportGrace`); zero consumers by design, `go test -race` 100% statement coverage. Migrations (walker/scheduler/hub/api/optimizer onto it, verbatim-port gate) are TASK-035/036/037. 035 DONE (lexa-hub `task/035-scheduler-time` 7c1b03f+c612e1e, **unmerged — 05 §12 cooling-off**): AD-004 consumers 1–3 (walker offset→`Clock`, serverNow via `clk.ServerNow()`, scheduler `Expired`/`InWindow`, responseTracker) — guards verbatim, `failclosed_test.go` empty diff, differential equiv test added; northbound-only deploy (028-active bench preserved); targeted time/fail-closed gate 6/6 PASS (`qa-mayhem-20260705-173448.md`); full FAST 31P/20D/0F/0B (`qa-mayhem-20260705-183429.md`; P→D drifts dispositioned — 2 flakes PASS on solo re-run `qa-mayhem-20260705-184018.md`, 2 reflect the 028-active battery baseline; clock-jitter at exact baseline parity — no time-family regression). 039 DONE (lexa-hub 01e7b0b): AD-005 journal library `internal/journal` (NDJSON, rotation, batched fsync, torn-tail self-heal found+fixed, Scan reader; 95.1% cov; zero consumers — wiring is TASK-040). |
| P4 Observability & QA depth | 044–055 | IN PROGRESS (2026-07-05) | — | Parallel track. Done + merged: 044 (metrics ×6 services), 045 (slog + plan heartbeat, arrival-time based), 047 (httpwire leaf + 64 KiB header cap + nightly fuzz, 0 crashers), 048 (5 XML/bus fuzz targets, shared seed corpus, namespace-lore corrected + tripwire; findings: Time.CurrentTime ungated, csipref scheduler gate-less — backlogged; csipref CI gap closed). Bench validation batch CLOSED at the P2 wave gate (2026-07-05): 044 — metrics live on the bench, `lexa_up 1` ×6 from the desktop, exposition golden-format-clean, `scripts/prometheus-bench.yml` + BENCH.md ports created **at the gate** (the paired csip-tls-test deliverable had never actually been committed); 045 — live stop/start heartbeat proof (ok→stalled@75s→ok, edge-triggered WARN/INFO pair, metric 0→1→0); 044/045/047/048 full-campaign item covered by `qa-mayhem-20260705-151009.md` (34P/17D/0F/0B). Bench gotcha: deploy resets metrics_addr/reconciler/mqttproxy Pi-side enables — documented in BENCH.md. 049/050/051 CODE COMPLETE (csip-tls-test `task/049-051-scenarios` 01e97bc, unmerged, batched per the 05 §12 deadline amendment): `duplicate-client-id` (mqttproxy `/hold` + shared `dialAndConnect` helper, live hub client-ID read over SSH, TASK-044 reconnect-counter detection), `mqtt-storm` (mqttproxy `/storm` reusing the same connect helper, diagnoseConstraint + INV-HUNT + TASK-044 overflow-counter "silent wedge" check), `disk-full` (size-guarded fallocate ballast, floor/reserve guard unit-tested). Unit tests + `go build`/`go vet`/`go test ./...` green, `bin/dashboard` rebuilt as compile proof; bench validation (10× solo, abort/teardown checks, full campaign) explicitly deferred to the next batched wave gate. |
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
