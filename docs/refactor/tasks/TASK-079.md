# TASK-079 — DST / timezone / leap-smear TOU boundary tests

*Status: DONE (2026-07-06, lexa-hub `36e55f7`, merged to main (from branch `task/079-dst-tou`)) · Phase: P6 · Effort: M (≈4–6 h) · Difficulty: med · Risk: med*

## Objective
Table-driven tests with explicit `time.Location` (America/Los_Angeles)
pin `TOUCostModel` behavior — `IsPeakHour`, `CurrentRate`,
`CurrentPeriodLabel`, `OptimalChargeWindow` — and the planner's TOU
window evaluation across DST-forward and DST-back transitions and a
smeared leap second. Any small defects the tests expose are fixed inline;
anything structural becomes a filed follow-up, never a silent skip.

## Background
Verified time handling (lexa-hub/internal/orchestrator):
- `costmodel.go`: `TOUPeriod{StartHour, EndHour}` in "24-hour local
  time"; `CurrentRate(t)` uses `t.Hour()` (:54-62) — i.e., hour-of-day in
  WHATEVER Location `t` carries; `hourInPeriod` handles midnight wrap
  (:117-123); `IsPeakHour = CurrentRate ≥ peakThreshold` (:64-68);
  `OptimalChargeWindow` builds `time.Date(..., now.Location())` (:96-114)
  — on a DST-forward day, constructing 02:xx yields a time that does not
  exist; Go normalizes it (to 03:xx PDT) — is the resulting 23-hour day
  double-counting or skipping a rate hour? UNTESTED.
- Callers: optimizer Rule 5 computes
  `serverNow := time.Unix(now.Unix()+state.ClockOffset, 0)` — a Unix
  instant rendered in the PROCESS's local zone (the SOM's /etc/localtime)
  — then `IsPeakHour(serverNow)` (optimizer.go:324-330; post-P5 this
  lives in the economics constraint — verify location). The planner:
  `localHourOf(unix)` (planner.go:609) and price-shaping helpers
  (planStepImportPrice/planStepExportPrice, :631-651) — read them; they
  likely share the same local-zone dependency.
- Implication to encode in tests (and challenge): "local time" here means
  the SOM's configured zone. A DST transition therefore shifts TOU
  boundaries with the zone — which is CORRECT for a tariff defined in
  local clock time (utility tariffs are), but the 23/25-hour days must
  not break window arithmetic, and a UTC-configured SOM serving a
  local-time tariff is a deployment hazard worth an explicit test +
  documented requirement.
- GAP-05 (07): "a wrong peak window misprices an entire evening
  fleet-wide, twice a year." Review §9 time family; W4 context.
- Dependency note: the graph says 036 (utilitytime migration of optimizer
  TOU) precedes this — post-036, TOU evaluation may route through
  `utilitytime`; write the tests against the CURRENT entry points found
  in the code (grep `IsPeakHour` callers first).

## Why this task exists
GAP-05: `CostModel.IsPeakHour` across a `time.Location` transition is
unverified; leap-smear vs event expiry likewise. Cheap tests, expensive
field bug.

## Architecture review sections
§9 time family · GAP-05 · W4 · 05 §5 (time principles) · 02 AD-004.

## Prerequisites
TASK-036 DONE (per the dependency graph — so these tests land on the
post-utilitytime code and pin its behavior, not a superseded path).
No bench required.

## Files
- **Read first:** internal/orchestrator/costmodel.go + costmodel_test.go
  (existing coverage — 103 lines, likely no TZ cases); planner.go:599-651
  (localHourOf + price shaping + clearSkyShape's hour use); the
  post-036 utilitytime TOU path (grep `IsPeakHour\|CurrentRate` across
  lexa-hub); optimizer/economics serverNow construction.
- **Modify:** `internal/orchestrator/costmodel_test.go` (extend),
  `internal/orchestrator/planner_test.go` (TZ cases), possibly
  costmodel.go/planner.go for inline fixes.
- **Create:** none (tests live beside subjects), unless a fix warrants a
  helper.

## Blast radius
Tests + at most small localized fixes in costmodel/planner. Any fix that
changes TOU decisions on the bench must be called out (the bench SOM zone
and replay cost baselines could shift — check `timedatectl` on the hub Pi
and note it).

## Implementation strategy
Fix the zone explicitly in every test: `loc, _ :=
time.LoadLocation("America/Los_Angeles")` — never the test runner's
local zone (CI portability). Use concrete 2026 dates: DST-forward
2026-03-08 (02:00→03:00 PST→PDT), DST-back 2026-11-01 (02:00→01:00
PDT→PST). Sweep minute-resolution instants across each transition against
the DefaultTOUCostModel schedule (peak 16-21, partial 7-16, off-peak
21-7) plus a synthetic schedule whose boundary lands INSIDE the
transition window (peak starting 02:00) to hit the nonexistent/repeated
hours directly. Leap smear: model as ±0.5 s clock skew across a boundary
instant (Go/POSIX time has no leap second; smear = tiny offset — assert
boundary evaluation is stable under ±1 s jitter at window edges).

## Detailed steps
1. Inventory current behavior: run a throwaway sweep (in a test with
   `t.Log`) across both transitions; record what `CurrentRate/IsPeakHour`
   return for the repeated 01:xx hour (DST-back: occurs twice — PDT and
   PST instants both render Hour()==1 → same rate: fine; document) and
   for `OptimalChargeWindow` on 23/25-hour days (cost sums use 24
   constructed hours regardless — quantify the error).
2. `costmodel_test.go` additions (table-driven, explicit loc):
   - boundary instants ±1 s around every DefaultTOUCostModel edge on a
     normal day, DST-forward day, DST-back day;
   - synthetic 02:00-boundary schedule across both transitions;
   - midnight-wrap period (22-06) across both transitions
     (hourInPeriod wrap logic × DST);
   - `OptimalChargeWindow(now, 4)` invoked ON each transition day —
     assert it returns a sane in-range hour and (per step 1 findings)
     document/fix the 23/25-hour accounting;
   - leap-smear jitter: IsPeakHour stable under ±1 s at edges (no flap).
3. `planner_test.go`: `localHourOf` across both transitions (it derives
   hours from unix seconds — check whether it uses time.Local or a
   passed loc; if time.Local, the test must set an explicit zone via the
   function's contract or expose a loc parameter — a MINIMAL API change
   is acceptable as an inline fix, threaded from PlannerParams);
   price-shaping continuity across the transitions (no double-priced or
   skipped step in the 96-step day).
4. UTC-SOM hazard test: same instant evaluated in UTC vs LA yields
   different IsPeakHour — assert the DIFFERENCE exists and add a
   documented deployment requirement (CLAUDE.md/config doc: "SOM zone
   must match the tariff zone") rather than papering over it.
5. Fix inline anything small the tables expose (e.g. OptimalChargeWindow
   normalization); anything structural (e.g. planner needs a Location
   plumbed through PlannerParams broadly) → file follow-up with the
   failing test committed as `t.Skip`-with-issue? NO — never skip:
   commit the test asserting CURRENT behavior with a `// KNOWN-GAP:` tag
   + backlog entry, so drift is still caught.
6. `make test` green; run the planner bench test (planner_bench_test.go)
   to confirm no perf regression if planner code changed.

## Testing changes
This task IS tests (+ inline fixes). Run:
`cd ~/projects/lexa-hub && make test`.

## Documentation changes
- lexa-hub CLAUDE.md (or config docs): SOM-timezone-matches-tariff
  requirement.
- 07 GAP-05: closed with test list.
- 10_BACKLOG: any structural findings.

## Common mistakes to avoid
- Using the runner's local zone (tests pass on a UTC CI box and lie).
- Testing only 2 a.m. — the tariff edges (07/16/21:00) matter on
  transition days too (sunset shift is why utilities care).
- "Fixing" the local-clock-time tariff semantics to UTC (tariffs ARE
  local-clock; the correct behavior is zone-aware, not zone-free).
- Conflating this with server-clock offset handling (W4's other half —
  ClockOffset is seconds arithmetic, orthogonal to zone rendering;
  don't touch scheduler/walker time code here).
- Skipping found bugs (the KNOWN-GAP pattern keeps them visible).

## Things that must NOT change
- DefaultTOUCostModel schedule values (bench replay cost baselines
  depend on them).
- serverNow construction semantics (offset seconds + local rendering) —
  document, don't redesign (that was 034-036's job).
- Existing costmodel/planner test expectations (extend, don't rewrite).
- Scheduler/walker/hub expiry time handling (out of scope).

## Acceptance criteria
- [ ] Table tests cover: both 2026 DST transitions × (default schedule
  edges, 02:00-boundary schedule, midnight-wrap schedule) ×
  IsPeakHour/CurrentRate/CurrentPeriodLabel; OptimalChargeWindow on
  transition days; localHourOf/price-shaping continuity; ±1 s edge
  stability; UTC-vs-LA divergence documented.
- [ ] All tests use explicit LoadLocation; suite green on any runner TZ
  (verify with `TZ=UTC make test` and `TZ=America/New_York make test`).
- [ ] Inline fixes reviewed; structural findings filed with KNOWN-GAP
  tests.
- [ ] Deployment TZ requirement documented.

## Regression checklist
- [ ] `go test -race ./internal/...` (lexa-hub) green (under ≥2 TZ env
  values)
- [ ] Conformance logic tests: none
- [ ] Mayhem: none (unit-level); if an inline fix changed TOU decisions,
  run `--only clock-jitter,clock-jump-forward` ×1 as a smoke
- [ ] planner bench test unchanged (if planner touched)

## Mayhem scenarios affected
None expected; clock-jitter/clock-jump-forward smoke only if fixes
changed decision timing.

## Conformance implications
None (TOU is local economics, not 2030.5 protocol — pricing function-set
handling is untouched).

## Suggested commit message
`test(orchestrator): DST/leap-smear TOU boundary tables (GAP-05) + inline fixes`
(+ trailer: `Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>`)

## Suggested PR title & description
**Title:** DST/timezone TOU boundary tests (GAP-05)
**Description:** Explicit-Location table tests across 2026 transitions +
leap-smear jitter; UTC-SOM hazard documented; inline fixes listed;
KNOWN-GAP tests for anything structural. Risk: med only if fixes landed
(called out per fix). Rollback: revert fixes independently of tests.

## Code review checklist
- Every table uses explicit loc; TZ-env matrix actually run.
- Fix vs KNOWN-GAP classification sound.
- No semantics invented (local-clock tariff preserved).

## Definition of done
Acceptance criteria + regression checklist + docs updated + status headers
(this file + 00_MASTER_INDEX) updated.

## Possible follow-up tasks
Backlog items from KNOWN-GAPs; a Mayhem local-clock+DST scenario variant
(extends TASK-038's local-clock-step scenario); TASK-081 references
GAP-05 closure.
