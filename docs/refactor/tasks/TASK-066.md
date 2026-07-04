# TASK-066 — Delete the legacy cascade; enforce <600-line orchestrator files

*Status: TODO · Phase: P5 · Effort: M (≈4–6 h) · Difficulty: med · Risk: high*

## Objective
The legacy rule-cascade code in `optimizer.go` — every rule, guard struct,
and convergence checker that 060–063 reimplemented — is DELETED in
separate, individually revertible commits; the constraint stack becomes
the only optimizer; the per-constraint `off|shadow|active` modes collapse
(constraints are simply on); and no file under `internal/orchestrator/`
exceeds 600 lines. Gate: 10-cycle FAST **and** 10-cycle STOCK campaigns at
≤ baseline before the first deletion commit merges.

## Background
By this point `DefaultOptimizer` (optimizer.go, 2,329 lines at P5 start)
is a shell: export/gen/import/economics/battery-safety run in
`internal/orchestrator/constraint/` behind `active` modes, with legacy
paths short-circuited but still compiled (060 step 4 pattern). Deletion
discipline comes from 05 §11: "Deleting defensive code requires: the
replacing mechanism named, the originating scenario green on the
replacement, and the deletion in its own commit." The preservation ledger
(TASK-025 doc, extended by 060-064) maps every guard to its scenario.

What remains in the orchestrator package after deletion:
`engine.go` (670 lines today — TASK-067 handles its state), `model.go`,
`interfaces.go`, `costmodel.go`, `planner.go` (739 lines — over cap;
split `planner.go` mechanically if touched, else record a justified
exception per 05 §1), the constraint package, and a thin
`DefaultOptimizer` that wires Stack + safety fast path (or the Stack
replaces it outright — decide in step 1).

## Why this task exists
W1's end state; 03 §P5 exit criterion "optimizer.go gone or <600 lines";
09 checklist "No file >600 lines in internal/orchestrator". Leaving dead
legacy paths compiled is exactly the D1/D3 mistake (monolith fork, dead
`SetCSIPPrograms` path) this program is burning down.

## Architecture review sections
W1 · R4 · D1/D3 (the cautionary precedents) · 03 §P5 exit criteria ·
05 §1 (file cap) / §11 (deletion discipline) / §12 · 06 §Mayhem (10-cycle
before legacy deletion) · 08 RSK-01/RSK-03.

## Prerequisites
TASK-063, TASK-064, TASK-065 ALL DONE and holding on the bench. The
10-cycle FAST + STOCK campaigns are run at the START of this task (they
gate the first deletion).

## Files
- **Read first:** the preservation ledger; optimizer.go (current state);
  every `constraint/*.go`; cmd/hub/main.go + config.go (mode wiring).
- **Modify:** `internal/orchestrator/optimizer.go` (shrink/delete),
  `cmd/hub/config.go` + `configs/hub.json` (retire mode map),
  `cmd/hub/main.go`, test files whose subjects are deleted (their
  constraint twins from 060-062 already exist — delete originals only
  after a coverage cross-check).
- **Create:** possibly `internal/orchestrator/optimizer.go` successors
  (split files), each <600 lines.

## Blast radius
`internal/orchestrator` (radioactive) + cmd/hub config surface. No bus
schema. Rollback after merge is git-revert-per-commit + redeploy — which
is precisely why each deletion is its own commit and the campaign gate
comes first.

## Implementation strategy
Campaign first, delete second, per-constraint third. Run both 10-cycle
campaigns on the pre-deletion build (everything active) to establish that
the constraint stack alone carries the baseline. Then delete in ledger
order — export, gen, import, economics, battery-safety legacy, then the
cascade skeleton (`Optimize`'s rule sequence, guard structs, helpers) —
one commit each, `make test` + targeted scenarios between commits, full
FAST campaign at the end. Finally retire the mode config and enforce the
line cap.

## Detailed steps
1. Decide the end shape: (a) `Stack` becomes the `Optimizer` cmd/hub
   constructs, `DefaultOptimizer` deleted, safety fast path exposed by the
   Stack (implements `SafetyEvaluator`); or (b) thin `DefaultOptimizer`
   delegate retained for API stability. Prefer (a); record in 02.
2. Gate: `bash scripts/bench-up.sh --fast`; 10-cycle FAST campaign
   (10 × `python3 scripts/mayhem.py --dashboard http://69.0.0.20:8080`,
   or the `scripts/mayhem-100.sh` loop pattern trimmed to 10); then
   `bash scripts/bench-up.sh --stock` + 10-cycle STOCK; restore fast.
   Both ≤ baseline (0.6 FAIL/cycle, 0 BLIND, DEGRADEDs ⊆ accepted ledger).
   Archive reports under `docs/` per the QA_REPORT pattern.
3. Coverage cross-check: for every legacy test file/case being deleted,
   name its constraint twin (table in PR). Any orphan behavior = STOP,
   port the test first.
4. Deletion commits (each: delete + grep-proof + `make test` + 1 targeted
   scenario run):
   c1 export legacy (applyExportLimitRule, exportGuard, expOverTicks,
      checkExportLimitConvergence) — scenario control-churn;
   c2 gen legacy (applyGenLimitRule leftovers, genGuard,
      restoreOnGenLimitClear, checkGenLimitConvergence) — curtailment-release;
   c3 import legacy (applyImportLimitRule, importGuard,
      checkImportConvergence) — battery-empty-import-cap;
   c4 economics legacy (applyPlanRule/applyFixedDispatchRule/
      applySelfConsumptionRule/TOU block/applyEVChargingRule/
      applyRestoreRule — CHECK: restore-rule deletion belongs to TASK-032's
      reconciler work; if any restore behavior survived into P5, verify its
      constraint-side owner before deleting) — expired-control +
      curtailment-release;
   c5 battery-safety legacy (checkBatterySafety body, counters) —
      battery-wrong-sign;
   c6 cascade skeleton + `recordBreach` etc. — perfect-storm.
5. Retire `constraints:` mode map from config (unknown-key warning keeps
   old files loading); cmd/hub constructs the stack unconditionally.
6. Line-cap audit: `wc -l internal/orchestrator/*.go
   internal/orchestrator/constraint/*.go` — split any file >600 (pure
   moves); planner.go decision per Background.
7. Final full FAST campaign; update ledger + docs.

## Testing changes
No new tests (twins exist); deletions of superseded tests with the step-3
table. Run: `make test` after every commit; campaigns per steps 2/7.

## Documentation changes
- lexa-hub CLAUDE.md: defensive-fault-handling section now points only at
  constraint files; directory map updated.
- Preservation ledger: entries marked "legacy deleted (commit …)".
- 02 AD-007 closed as implemented; 00_MASTER_INDEX P5 status.

## Common mistakes to avoid
- Batching deletions into one commit (unbisectable, unrevertable —
  RSK-01's recovery depends on per-commit revert).
- Deleting a guard whose constraint twin was never mutation-verified —
  re-run the mutation checks from 060-062 on the final build first.
- Skipping the STOCK campaign ("FAST passed") — the shipped timing is the
  tested timing (GAP-15; this gate exists because scaleTicks equivalence
  is a theory until tested).
- Letting the mode-map removal break deployed hub.json parsing.
- Touching engine.go beyond what deletion forces — mutex consolidation is
  TASK-067, not here.

## Things that must NOT change
- Every preservation-ledger scenario verdict (the whole list re-gates:
  control-churn, export-cap-full-battery, meter-ct-inverted, pv-flicker,
  battery-charge-disabled, reject-write-curtail, enable-gate-curtail,
  ramp-limit-curtail, ack-before-effect, curtailment-release,
  battery-soc-refuse, battery-empty-import-cap, stale-meter,
  battery-wrong-sign, expired-control, conflicting-primacy,
  two-inverter-export-cap, two-evse-churn).
- Tier-1 safety latency (safetyTick path).
- `orchestrator.Optimizer`/`SafetyEvaluator` contracts as consumed by the
  engine.
- V6 baseline, INV-HUNT clean.

## Acceptance criteria
- [ ] 10-cycle FAST + 10-cycle STOCK reports archived, ≤ baseline, BEFORE
  first deletion merge.
- [ ] Six deletion commits, each with grep-proof + green tests + scenario
  evidence.
- [ ] `wc -l` audit: no orchestrator file >600 lines (or recorded
  exception for planner.go).
- [ ] Final FAST campaign ≤ baseline.
- [ ] Mode map retired; legacy symbols gone
  (`grep -rn "expGuard\|impGuard\|genGuard\|applyExportLimitRule" internal/` → 0).

## Regression checklist
- [ ] `go test -race ./internal/...` (lexa-hub) green after EVERY commit
- [ ] Conformance logic tests: none
- [ ] Mayhem: 10-cycle FAST + STOCK gate up front; full FAST at end
- [ ] Per-commit targeted scenario runs logged

## Mayhem scenarios affected
All optimizer-driven scenarios (the campaign IS the acceptance). No
verdict may regress; accepted DEGRADEDs unchanged.

## Conformance implications
None if verdicts hold (CannotComply timing already gated in 060/061).

## Suggested commit message
Series: `chore(orchestrator): delete legacy <export|gen|import|economics|battery-safety|cascade> path (preservation ledger §…)`
(+ trailer each: `Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>`)

## Suggested PR title & description
**Title:** P5 finale: legacy cascade deletion (campaign-gated)
**Description:** 10-cycle FAST+STOCK evidence links; per-constraint
deletion commits with scenario proofs; file-size audit. Risk: HIGH —
mitigated by gate-first ordering and per-commit reverts. Rollback: revert
the specific deletion commit + redeploy.

## Code review checklist
- Step-3 twin-coverage table complete.
- Each commit's grep-proof shows no dangling references.
- STOCK campaign actually run (report link, not a promise).

## Definition of done
Acceptance criteria + regression checklist + docs updated + status headers
(this file + 00_MASTER_INDEX) updated.

## Possible follow-up tasks
TASK-067 (engine consolidation on the shrunken package), TASK-081
(release gate reuses the campaign machinery).
