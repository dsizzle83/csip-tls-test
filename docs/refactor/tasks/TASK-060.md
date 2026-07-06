# TASK-060 — Migrate the export-limit constraint (+ its convergence session)

*Status: SHADOW-VALIDATED (2026-07-06, lexa-hub task/060-export-constraint d093a28) — export-axis shadow divergence 0 across the export family + a full 51-scenario FAST campaign; active flip DEFERRED per launch plan (needs the longer soak before `export: active`). · Phase: P5 · Effort: L (≈8 h) · Difficulty: high · Risk: high*

## Objective
The export-limit behavior — ceiling controller (`applyExportLimitRule` +
`expGuard`) and measured-effect convergence backstop
(`expOverTicks`/`checkExportLimitConvergence`) — lives in the constraint
package as `ExportConstraint` with a typed session, runs in shadow until
its diff gate passes, then FLIPS to active per-constraint config while the
legacy export code path is disabled (not deleted — deletion is TASK-066).
This is the first flip of P5: it sets the pattern for 061/062.

## Background
Read these fully before writing any code (all verified):
- `applyExportLimitRule` (optimizer.go:643-1168): conservative target
  `limit×(1−ExportMarginFrac)`; low-pass filter `filterAlpha=0.4`
  (:696-701); first-active-EVSE selection (:721-728); conservation
  identity using last COMMANDED values (:734-770); battery absorption with
  SOC taper + `socStepEstimate` EV pre-positioning (:777-830); absorption
  ratchet; battery-stall leaky counter (`battStallTicks`,
  `battConvergeFrac=0.5`, `battBreachTicks=3`, :60-72, :873-879); sticky
  solar ceiling with slew `maxDropW=1500/maxRiseW=500` per tuned tick
  (:1060-1065); relax gated on `safeCount ≥ ExportRelaxCycles`; feed-
  forward saturation curtail (:1148+).
- `expGuard` (optimizer.go:13-22) — 8 fields: `evSetpointA, evCmdW,
  batteryAbsorbW, safeCount, activeLimitW, filteredExportW, solarCeilingW,
  battStallTicks`. Resets when the limit VALUE changes (new controller
  session).
- `expOverTicks` (optimizer.go:132-142) + `checkExportLimitConvergence`
  (:1170-1234): the 2026-07-03 session-scoped counter. **Its reset
  semantics are load-bearing:** deliberately NOT in expGuard; resets ONLY
  when the export limit clears to NaN (:1194-1196); survives cap-value
  rewrites (control-churn rewrites the cap every ~12 s — a counter on the
  controller's reset cadence could never fire); leaky (decrement on under-
  cap tick, cap at threshold); NaN-meter tick HOLDS the counter (:1200).
  Mutation-tested by `TestOptimizer_ExportChurnEscalatesCannotComply`
  (optimizer_test.go:1088).
- Tests pinning this behavior: `optimizer_compliance_test.go` (phantom EV
  credit, sticky curtailment no-release, battery-credit cancel,
  feed-forward saturation), `convergence_test.go:34-104` (battery stall),
  plus the churn test above. TASK-056 made them behavioral.

## Why this task exists
W1/R4: this is the biggest, most QA-scarred rule in the cascade; migrating
it first under the shadow gate proves the constraint architecture on the
hardest case, per AD-007 and the 03 §P5 per-constraint flip plan.

## Architecture review sections
W1 · R4 · §8.1 · D6 (constants stay constants here; TASK-064 parameterizes)
· 02 AD-007 · 03 §P5 · 08 RSK-01/RSK-03 · 05 §12.

## Prerequisites
TASK-059 DONE **plus its gate satisfied**: ≥1 week of bench shadow data
including one full campaign. Bench in FAST mode. TASK-056 tests are the
behavior net.

## Files
- **Read first:** everything under Background; `constraint/stack.go`,
  `constraint/session.go` (058), `shadow.go` (059), `cmd/hub/config.go`.
- **Modify:** `cmd/hub/config.go` + `configs/hub.json` (per-constraint
  mode: `"constraints": {"export": "off"|"shadow"|"active"}`),
  `cmd/hub/main.go` (mode wiring), `internal/orchestrator/optimizer.go`
  (ONLY the flip mechanism: skip legacy export path when the constraint is
  active — one guarded early-out, clearly commented, nothing deleted).
- **Create:** `internal/orchestrator/constraint/export.go`,
  `constraint/export_session.go`, `constraint/export_test.go`.

## Blast radius
`internal/orchestrator` (radioactive zone — one-per-PR, full campaign,
never merged same day, 05 §12). cmd/hub config. No bus schema change (the
Stack emits the same command/breach types). Mayhem export scenarios are
the behavior contract.

## Implementation strategy
Port, don't redesign: `ExportConstraint.Evaluate` reproduces the legacy
algorithm against a typed `ExportSession` holding BOTH state groups with
their DIFFERENT reset cadences — controller state (expGuard-equivalent,
resets on limit-value change) and compliance state (expOverTicks-
equivalent, resets only on limit-clear-to-NaN). Emits demands
(solar-ceiling max, battery-setpoint max ≤ −absorb, EVSE current) at
TierCompliance plus a Breach when the convergence counter fires. Shadow
until the export-axis diff rate is ~0 for a week + campaign, then flip via
config; legacy path short-circuits when active.

## Detailed steps
1. Define `ExportSession` mirroring the two reset domains; document each
   field with the optimizer.go line it ports and the QA scenario it serves
   (the `// QA`/`audit:` comments carry over verbatim).
2. Port the algorithm into `Evaluate` in stages that compile: (a) filter +
   safeCount, (b) battery absorption + taper + ratchet + stall counter,
   (c) EV pre-position/relax, (d) sticky ceiling + slew + feed-forward
   curtail, (e) convergence counter + breach. Keep constants identical
   (import/duplicate them; parameterization is TASK-064).
3. Port the behavioral tests: every export test from
   optimizer_compliance_test.go / convergence_test.go / the churn test
   gets a constraint-package twin driving `Evaluate` through the same tick
   sequences and asserting the same outcomes. Mutation-verify the churn
   twin (unwire the session counter → test fails).
4. Wire modes in cmd/hub: `off` (default; stack has no export constraint),
   `shadow` (registered in the 059 candidate stack only), `active` (legacy
   export path short-circuited via a flag on DefaultOptimizer; stack's
   export demands are merged into the actuated plan — implement as: active
   constraints run in the PRIMARY optimizer position for their axes while
   the remaining legacy rules still run; the simplest correct wiring is
   the Wrapper composing per-axis, and it must be covered by a unit test
   proving exactly one author per axis per tick).

   **Per-axis single-author rule (active-mode composition):** when a
   constraint owns an axis (export/import/gen), the wrapper REMOVES that
   axis's device commands from the legacy plan output before merge —
   legacy Rules 4/5/6 and `applyRestoreRule` still run for unmigrated
   axes, but their writes to migrated axes are dropped and counted in a
   `legacyOverrideDropped` metric. The restore rule is axis-owned by the
   export/gen constraint once migrated, so its solar-restore emissions for
   migrated axes are dropped too — otherwise the restore rule idling a
   battery the ExportConstraint told to absorb would regress
   export-cap-full-battery / pv-flicker. The required one-author-per-axis
   unit test must specifically cover the restore-rule-vs-ExportConstraint
   battery-absorb case.
5. Shadow soak: deploy (then `hub-replay-tune.sh fast`), set
   `export: shadow`, accumulate ≥1 week incl. one full campaign; export-
   axis divergence ~0 on accepted scenarios (RSK-03 gate).
6. Flip: `export: active`, restart lexa-hub; run targeted scenarios ×3
   solo (`python3 scripts/mayhem.py --only export-cap-full-battery,
   control-churn,meter-ct-inverted,pv-flicker --dashboard
   http://69.0.0.20:8080`), then one full FAST campaign.
7. Hold: leave active for the remainder of P5; rollback = set `shadow`.

## Testing changes
- `constraint/export_test.go`: ported behavioral suite + mutation checks.
- Unit test: exactly-one-author-per-axis in active mode.
- Bench: step 5 shadow campaign + step 6 targeted ×3 + full campaign.
- Run: `make test` (lexa-hub); `scripts/mayhem.py` as above.

## Documentation changes
- Preservation-ledger (TASK-025 doc): mark export entries as "reimplemented
  in constraint/export.go" with test names.
- lexa-hub CLAUDE.md defensive-fault-handling section: update the export
  bullet to name the new home.
- 02 AD-007: note first flip completed + evidence links.

## Common mistakes to avoid
- Merging the two reset cadences into one session reset — that is the
  exact bug class the 2026-07-03 fix closed (a rewritten cap value is a
  new controller session with the SAME compliance obligation).
- Zeroing the compliance counter on a NaN meter tick (it must HOLD —
  "a blind meter must not launder a breach", optimizer.go:1198-1203).
- Forgetting the floor-of-2 in tick scaling (STOCK campaigns will flake).
- Running another radioactive-zone task in the same window — campaign
  attribution becomes impossible (04 §3).
- Deploy gotchas: re-run `scripts/hub-replay-tune.sh fast` after
  `deploy-hub-pi.sh`; use systemctl (never `pkill -f`) over SSH.

## Things that must NOT change
Preservation-ledger entries this task touches (guard → originating
scenario; each must PASS on the new path before flip):
- `expOverTicks` session-scoped reset ↔ **control-churn** (utility rewrites
  cap every ~12 s; CannotComply must still escalate).
- Export cap enforcement with full battery ↔ **export-cap-full-battery**
  (4 s DEGRADED oracle line is accepted-by-design — do not "fix" it here).
- CannotComply on unmeetable cap ↔ **meter-ct-inverted** (expected-
  DEGRADED pins the gap; the hub must ADMIT non-convergence).
- Filter/ratchet ride-through ↔ **pv-flicker** (sawtooth must not unseat
  the ceiling).
- Battery-stall → curtail ↔ **battery-charge-disabled**.
Also: Tier-1 safety loop untouched; V6 baseline (0.6 FAIL/cycle, 0 BLIND)
defended.

## Acceptance criteria
- [ ] Shadow week + campaign: export-axis divergence ~0 (report attached).
- [ ] Flip: targeted scenarios ×3 each at their accepted verdicts; full
  FAST campaign ≤ baseline.
- [ ] Ported tests green incl. recorded mutation checks.
- [ ] `export: shadow` rollback verified live once (flip back, one
  scenario run, flip forward).

## Regression checklist
- [ ] `go test -race ./internal/...` (lexa-hub) green
- [ ] Conformance logic tests: none
- [ ] Mayhem: full FAST campaign post-flip (mandatory, radioactive zone)
- [ ] Rollback drill performed

## Mayhem scenarios affected
export-cap-full-battery, control-churn, meter-ct-inverted, pv-flicker,
battery-charge-disabled, ack-before-effect (export lever half),
perfect-storm. Verdicts must not regress; accepted DEGRADEDs stay as
enumerated in the V5/V6 reports.

## Conformance implications
CannotComply Response emission timing for export breaches must stay inside
the compliance window (the ~9 s detection budget the leaky counter
encodes) — covered by scenario verdicts, no suite change.

## Suggested commit message
`feat(orchestrator): ExportConstraint with dual-cadence session; per-constraint off/shadow/active modes`
(+ trailer: `Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>`)

## Suggested PR title & description
**Title:** P5 flip 1/3: export-limit constraint migration
**Description:** Ports applyExportLimitRule + expGuard + session-scoped
convergence counter into constraint/export.go; off/shadow/active config;
shadow evidence + campaign links; rollback = config flip to shadow.
Risk: HIGH (radioactive zone) — gated per 03 §P5.

## Code review checklist
- Field-by-field port audit against optimizer.go line refs.
- Two reset cadences preserved and separately tested.
- Exactly-one-author-per-axis proof in active mode.
- QA comments carried over; preservation ledger updated.

## Definition of done
Acceptance criteria + regression checklist + docs updated + status headers
(this file + 00_MASTER_INDEX) updated.

## Possible follow-up tasks
TASK-061 (import+gen on this pattern), TASK-064 (parameterize the ported
constants), TASK-066 (delete the disabled legacy path).
