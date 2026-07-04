# TASK-056 — Convert decision-string tests → behavioral/invariant tests

*Status: TODO · Phase: P5 · Effort: L (≈6–8 h) · Difficulty: med · Risk: low*

## Objective
Every test in `lexa-hub/internal/orchestrator` asserts *behavior* (plan
contents: commands, setpoints, ceilings, breaches; or invariant outcomes) —
never the human-readable decision strings the optimizer emits. After this
task, renaming/rewording/reorganizing the optimizer's `Decision` text cannot
break a test, and no safety test passes with its guard unwired. This task
BLOCKS every Phase 5 migration task (TASK-058…066): do not start any of them
until this is DONE.

## Background
`internal/orchestrator` is I/O-free: `DefaultOptimizer.Optimize(SystemState)
Plan` (optimizer.go, 2,329 lines). A `Plan` (model.go:302) carries
`BatteryCommands`/`SolarCommands`/`EVSECommands`, `Breach *ComplianceBreach`
(model.go:313), and `Decisions` — human-readable records appended via
`plan.AddDecision(rule, reason, impact)`. Some tests assert against those
strings instead of the commands/breaches:

- `convergence_test.go:21` defines `hasDecisionContaining(p *Plan, substr)`
  (matches `d.Reason`/`d.Impact` substrings); used at lines 49, 78, 97 to
  assert "battery not absorbing".
- `optimizer_test.go:980-984` asserts `contains(d.Reason, "cooldown")` on
  `d.Rule == "import-limit"` decisions.
- `logDecisions(t, plan)` (optimizer_test.go:465) is logging-only — fine,
  keep it.

The good pattern already exists in the same files: e.g.
`TestCheckGenConvergence_CaughtByMeterFloorDespiteEchoedReport`
(convergence_test.go:106) asserts `plan.Breach` fields, and
`TestOptimizer_ExportChurnEscalatesCannotComply` (optimizer_test.go:1088) is
the mutation-verified standard — the test was proven to FAIL when the
session-scoped `expOverTicks` counter is unwired. Phase 5 splits the
optimizer into a constraint controller (AD-007); string-asserting tests
would shatter on the refactor without catching behavior changes (GAP-14).

## Why this task exists
Review §9 tail: "tests verifying implementation" — decision-string
assertions verify wording, not behavior, and will produce false failures
(or worse, false confidence) throughout the P5 migration. 07 GAP-14.

## Architecture review sections
§9 (tests-verify-implementation) · §13 · 05 §8 (assert invariants, not
decision strings) · 06 §2 (behavioral assertions precondition for R4) ·
07 GAP-14 · R4 context: W1.

## Prerequisites
TASK-033 (reconciler sign-off campaign) DONE — P5 must not start earlier.
No bench needed; this is a pure unit-test task.

## Files
- **Read first:** `~/projects/lexa-hub/internal/orchestrator/optimizer.go`
  (the rules each test exercises), `model.go` (Plan/ComplianceBreach),
  `convergence_test.go`, `optimizer_test.go`, `optimizer_rules_test.go`,
  `optimizer_compliance_test.go`, `engine_test.go`.
- **Modify:** `internal/orchestrator/convergence_test.go`,
  `internal/orchestrator/optimizer_test.go` (any other file only if the
  inventory step finds string oracles there).
- **Create:** none.

## Blast radius
Test files only. No product code changes. No config, no bus schema, no
public API. If a rewrite reveals a test that only ever passed because of a
string match (i.e., the behavior it claims to pin is not actually pinned),
that is a FINDING — record it, do not silently fix product code here.

## Implementation strategy
Inventory first, rewrite second, mutation-verify third. Grep the test
package for every assertion that reads `Decision.Reason`/`Impact`/`Rule` as
a pass/fail condition. For each, identify the behavior the original QA
finding pinned (the `// QA`/`audit:` comment in optimizer.go names it) and
re-express it as an assertion on plan outputs: solar ceiling watts, battery
setpoint sign/magnitude, EVSE current, `plan.Breach` (LimitType/ShortfallW/
non-nil-ness), or absence of commands. Then re-run the mutation check on
every rewritten safety test: temporarily unwire the guard, confirm the test
fails, restore.

## Detailed steps
1. Inventory: `grep -n "hasDecisionContaining\|\.Reason\|\.Impact\|d.Rule"
   internal/orchestrator/*_test.go` — build the full list (expected:
   convergence_test.go:49,78,97; optimizer_test.go:980-984; confirm nothing
   else asserts on strings — `logDecisions` and empty-Reason sanity checks
   in `TestOptimizer_DecisionsAreRecorded` (optimizer_test.go:442) may stay,
   as they assert decisions exist, not what they say).
2. `TestExportLimit_BatteryStallCurtailsSolar` (convergence_test.go:34) and
   `TestExportLimit_BatteryStallToleratesBlip` (:61): replace
   `hasDecisionContaining(last, "battery not absorbing")` with an assertion
   that the plan curtails solar — a `SolarCommand` with `CurtailToW`
   at/below the expected ceiling — after `battBreachTicks` stall ticks, and
   does NOT curtail on the blip case.
3. `convergence_test.go:97` (negative case): assert no solar curtailment
   command is issued while the battery is genuinely absorbing, instead of
   asserting the string is absent.
4. `optimizer_test.go:980-984` (EV import-cooldown): replace the
   `contains(d.Reason, "cooldown")` probe with a behavioral one: after the
   cooldown expires (tick 5), the plan must contain an `EVSECommand` with
   `MaxCurrentA > 0` (EV re-allowed); while suppressed, `MaxCurrentA == 0`
   or no resume command.
5. Delete `hasDecisionContaining` once unused; keep `logDecisions`.
6. Mutation-verify each rewritten test: e.g. for step 2, comment out the
   `battStallTicks` escalation in `applyExportLimitRule`
   (optimizer.go:873-879 region) and confirm the test fails; restore.
   Record each mutation check in the PR description (the
   `TestOptimizer_ExportChurnEscalatesCannotComply` precedent).
7. Run the full suite: `make test` (= `go test -race ./internal/...`).

## Testing changes
This task IS testing changes. Run: `cd ~/projects/lexa-hub && make test`.
Every rewritten test must be listed in the PR with its mutation-check
evidence (which line was unwired, test failed, restored).

## Documentation changes
- 06_TESTING_STRATEGY.md §2 "Unit": mark the decision-string migration done.
- Add a one-line note to `internal/orchestrator`'s package doc or CLAUDE.md
  (lexa-hub): new orchestrator tests assert plan contents/invariants, never
  Decision strings.

## Common mistakes to avoid
- Rewriting the assertion but losing the *timing* semantics (e.g. the
  battery-stall tests pin `battBreachTicks`=3 leaky-counter behavior — the
  blip test must still prove one noisy tick does not trip it).
- "Fixing" a rewritten test by weakening it until it passes — if behavior
  and string disagree, investigate; the string may have been asserting a
  stale claim.
- Touching optimizer.go itself. This task changes zero product lines.
- Deleting `TestOptimizer_DecisionsAreRecorded` — decisions must still be
  *recorded* (operators read them); we only stop asserting their wording.

## Things that must NOT change
- `TestOptimizer_ExportChurnEscalatesCannotComply` (optimizer_test.go:1088)
  stays as-is — it already asserts `plan.Breach` behaviorally and is the
  mutation-verification precedent.
- The behaviors pinned by the rewritten tests (preservation ledger,
  TASK-025): battery-absorption stall → solar curtail (scenario
  `battery-charge-disabled`), single-tick blip tolerance, EV import
  cooldown (scenario `battery-empty-import-cap` family).
- `internal/orchestrator` stays I/O-free (05 §1).

## Acceptance criteria
- [ ] `grep -rn "hasDecisionContaining" internal/orchestrator/` → no matches.
- [ ] No test in `internal/orchestrator` fails or passes based on
  `Decision.Reason`/`Impact` content (grep-audit in PR).
- [ ] Every rewritten safety test has a recorded mutation check.
- [ ] `make test` green with `-race`.

## Regression checklist
- [ ] `go test -race ./internal/...` (lexa-hub) green
- [ ] Conformance logic tests: not protocol-adjacent — none
- [ ] Mayhem: none (test-only change; no product behavior touched)
- [ ] Mutation checks recorded in PR for each rewritten safety test

## Mayhem scenarios affected
None at runtime. The rewritten tests pin the unit-level halves of
`battery-charge-disabled`, `control-churn`, and `battery-empty-import-cap`.

## Conformance implications
None.

## Suggested commit message
`test(orchestrator): replace decision-string assertions with behavioral plan assertions (GAP-14)`
(+ trailer: `Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>`)

## Suggested PR title & description
**Title:** Orchestrator tests: behavioral assertions replace decision strings
**Description:** Rewrites the string-oracle tests (inventory listed) to
assert plan outputs; mutation-check evidence per test; zero product-code
changes. Risk: low — test-only. Rollback: revert the single commit.
Unblocks all P5 migration tasks.

## Code review checklist
- Each rewritten test still pins the original QA semantics (check the
  `audit:`/`// QA` comment the guard cites).
- Mutation-check evidence present and plausible for every safety test.
- No product source touched; no assertion weakened.

## Definition of done
Acceptance criteria + regression checklist green; 06 updated; status header
here and in 00_MASTER_INDEX set to DONE with date + commit.

## Possible follow-up tasks
TASK-058 (constraint skeleton — now unblocked with TASK-057), TASK-060/061
(migrations rely on these tests as the behavior net).
