# TASK-064 — Bench constants → plant-model parameters (identical-behavior proof)

*Status: DONE (2026-07-06, `lexa-hub` `task/064-constants-plant` @ `a6334ae`; Stage A `2e6c573` + Stage B `a6334ae`; unmerged, Principal reviews/merges; bench campaign + STOCK spot-check gated at the P5 wave) · Phase: P5 · Effort: L (≈6–8 h) · Difficulty: high · Risk: high*

> **Completion note (2026-07-06).** Two commits (Stage A wire + prove, Stage B
> burn). Constant→plant swap map + parameter reference table:
> `docs/refactor/notes/TASK-064-plant-parameters.md`. evSafeCount folded into one
> shared `EVImportCooldown` (import writes, economics reads). On-cap residual is the
> irreducible shared-`surplusW` interleaving, confined to the economics
> `evse-current`/battery axes (compliance solar ceiling proven bit-faithful); see the
> notes doc + AD-007. socStep kept as explicit `SOCStepPctPerTickOverride` legacy debt
> (10_BACKLOG). `go test -race ./internal/... ./cmd/hub/...` green; `plantwiring_test.go`
> is the equivalence + single-owner + on-cap-parity + residual-characterisation proof.
> NOT done (gated, not blocked): bench FAST campaign, STOCK spot-check, the flip.

## Objective
The bench-calibrated globals in the migrated constraint code —
`socStepEstimate`-derived EV pre-positioning, ceiling slew
(`maxDropW`/`maxRiseW`), export filter (`filterAlpha`), SOC taper start,
`battConvergeFrac` — are read from the per-device plant model (TASK-057)
instead of constants. A `bench-plant` configuration numerically equal to
today's constants FIRST reproduces identical bench behavior (shadow diff
≈ 0 and campaign ≤ baseline), and only THEN are the constants deleted.

## Background
The constants and their physical meaning (verified in optimizer.go, now
ported into `internal/orchestrator/constraint/` by 060-063 — re-verify the
post-migration locations before editing):
- `socStepEstimate = 1.0` %/tick — "Calibrated for the 20× demo (10 kWh /
  5 kW pack, 3 s tick ≈ 0.83 %)" (originally optimizer.go:780-787). In the
  plant model this is DERIVED: `socStepPct = MaxChargeW × tickS /
  (CapacityKWh × 36,000)` — with bench values (5000 W, 10 kWh, 3 s) that
  yields ≈0.42 %/tick, NOT 1.0. **Decision required** (step 3): preserve
  behavior first with an explicit override parameter equal to 1.0, derive
  later; never silently change the effective value in this task.
- `maxDropW = 1500` / `maxRiseW = 500` W per tuned 3 s tick
  (:1060-1065) → `MaxRampDownWPerS = 500`, `MaxRampUpWPerS ≈ 166.7`
  (TASK-057 defaults) scaled by `TickSeconds` at the edge.
- `filterAlpha = 0.4` (:696-701) — encodes THIS bench's meter/OCPP lag
  (5 s vs 10 s cadences). Parameterize as `MeterLagS`-derived alpha with a
  documented mapping, plus an explicit `FilterAlpha` override defaulting
  to 0.4 for the bench file (same preserve-first discipline).
- `socTaperStart = 80.0` (:777), `battConvergeFrac = 0.5` /
  `battBreachTicks = 3` (:60-72) → BatteryPlant fields.
- Breach-tick thresholds (`genBreachTicks`/`importBreachTicks`/
  `exportBreachTicks` = 3) are COMPLIANCE latency policy, not plant
  physics — they stay constants (05 §5 wall-clock rule already handles
  cadence). State this boundary in the PR.

TASK-057 shipped the types + hub.json schema with defaults equal to these
constants; TASK-059's shadow machinery measures divergence.

## Why this task exists
D6/§8.1: "bench physics baked into product constants … won't transfer to
real vendors." 09 release checklist: "no '20× demo' constants in product
code; plant-model parameters documented per supported device." This is the
step that makes multi-vendor (065, 075) honest.

## Architecture review sections
D6 · W1 · §8.1 · R4 · 02 AD-007 · 03 §P5 ("must reproduce identical
FAST-bench behavior with the bench's plant-model file before any
generalization") · 05 §6 · 09 (multi-device & field readiness).

## Prerequisites
TASK-060 DONE (04 graph). Practically: run after 062/063 so the constants'
new homes are stable — verify the constraint files exist before starting.
TASK-057 DONE. Bench FAST; solo radioactive window.

## Files
- **Read first:** `constraint/export.go`, `constraint/importlimit.go`,
  `constraint/genlimit.go`, `constraint/batterysafety.go`,
  `constraint/economics.go` (wherever the constants landed),
  `internal/orchestrator/plantmodel.go`, `cmd/hub/config.go`,
  `configs/hub.json`.
- **Modify:** the constraint files (constant reads → plant reads),
  `configs/hub.json` (bench-plant values), cmd/hub plumbing if the plant
  map isn't already threaded into `constraint.Input` (058 defined the
  field).
- **Create:** `constraint/plantwiring_test.go` (equivalence tests);
  optionally `configs/plant-examples/` with a second, non-bench example
  demonstrating generalization (documentation-only, not deployed).

## Blast radius
`internal/orchestrator/constraint` (radioactive) + hub.json content on the
bench Pi. No bus schema. Behavior change is the FAILURE mode — the whole
task is an identical-behavior proof.

## Implementation strategy
Two gated stages. Stage A (preserve): thread plant parameters everywhere a
listed constant is read, with the bench hub.json populated to reproduce
today's numbers EXACTLY (including the socStep=1.0 and alpha=0.4
overrides); prove equivalence by unit vectors, shadow diff ≈ 0 (the
pre-064 build's outputs vs post-064 — run the old binary's stack as the
059 "legacy" side, or diff against recorded golden sequences), and a full
campaign. Stage B (burn): delete the Go constants; missing plant config
now falls back to `withDefaults()` (same numbers) — so field units without
plant blocks keep bench behavior, documented as such.

## Detailed steps
1. Inventory grep in the constraint package: `socStepEstimate|maxDropW|
   maxRiseW|filterAlpha|socTaperStart|battConvergeFrac` — table of
   (constant → plant field → conversion formula) in the PR.
2. Stage A: replace reads with `in.Plant[dev].<Field>` conversions
   (per-second → per-tick via `in.TickSeconds`); keep constants as the
   `withDefaults()` source only.
3. socStep decision: add `SOCStepPctPerTickOverride` (default 1.0, marked
   "bench legacy — burn down after real-pack calibration" per 05 §6 debt
   rule); file a backlog note for the derived formula.
4. Unit equivalence: golden multi-tick sequences (reuse 063's) byte-equal
   before/after Stage A with the bench plant file.
5. Bench: deploy hub.json with explicit bench-plant blocks +
   `hub-replay-tune.sh fast`; targeted `--only export-cap-full-battery,
   ramp-limit-curtail,ack-before-effect,pv-flicker,control-churn` ×3;
   full FAST campaign ≤ baseline. STOCK spot-check: `bash scripts/
   bench-up.sh --stock` then `--only export-cap-full-battery,clock-jitter`
   (tick-scaling × plant-scaling interaction is the STOCK-specific risk),
   then restore `--fast`.
6. Stage B: delete constants in a SEPARATE commit (05 §11 deletion
   discipline); `grep` proves no reads remain; `make test` green.
7. Document every parameter: units, bench value, provenance, which
   vendor datasheet field populates it (09 checklist line).

## Testing changes
- `plantwiring_test.go`: constant↔parameter equivalence vectors incl.
  FAST/STOCK tick conversions.
- Golden-sequence equality (Stage A).
- Run: `make test`; scenarios per step 5.

## Documentation changes
- Plant-parameter reference table (lexa-hub docs or CLAUDE.md appendix) —
  the 09 "documented per supported device" artifact.
- 02 AD-007: Stage A/B completion + socStep override note.
- 10_BACKLOG: derived-socStep calibration entry.

## Common mistakes to avoid
- "Improving" a value while parameterizing (the derived socStep ≈0.42 vs
  legacy 1.0 trap — the comment says the overestimate is DELIBERATE, it
  errs conservative; changing it is a behavior change this task forbids).
- Converting W-per-tick to W-per-second with the wrong tick (constants
  were calibrated at `tunedTickInterval = 3 s`, not the configured engine
  interval).
- Deleting constants in the same commit as the wiring (kills bisection).
- Skipping the STOCK spot-check — plant scaling × scaleTicks is exactly
  the FAST/STOCK validation hole (§13).
- Editing bench hub.json by hand on the Pi without committing the example
  config (deploy scripts overwrite configs — the phantom-FAIL detour).

## Things that must NOT change
- Effective numeric behavior on the bench (the entire acceptance).
- The preservation-ledger scenarios of 060-062 (they re-gate here:
  control-churn, export-cap-full-battery, ramp-limit-curtail,
  ack-before-effect, pv-flicker, battery-charge-disabled).
- Compliance-latency constants (breach-tick thresholds) — explicitly out
  of the plant model.
- V6 baseline; INV-HUNT clean (ramp/filter mistakes present as hunting).

## Acceptance criteria
- [ ] Inventory table complete; every conversion formula reviewed.
- [ ] Stage A golden sequences byte-equal; shadow/targeted/campaign ≤
  baseline; STOCK spot-check clean.
- [ ] Stage B: `grep -rn "socStepEstimate\|maxDropW\|filterAlpha"
  internal/` → only `withDefaults()`/docs hits.
- [ ] Parameter reference table published.

## Regression checklist
- [ ] `go test -race ./internal/...` (lexa-hub) green
- [ ] Conformance logic tests: none
- [ ] Mayhem: full FAST campaign + STOCK spot-check (mandatory)
- [ ] Stage B deletion in its own revertible commit

## Mayhem scenarios affected
export-cap-full-battery, ramp-limit-curtail, ack-before-effect,
pv-flicker, control-churn, clock-jitter (STOCK leg), perfect-storm.
INV-HUNT is the cross-cutting watch.

## Conformance implications
None directly; convergence latency unchanged.

## Suggested commit message
Stage A: `refactor(orchestrator): constraints read plant model; bench-plant config reproduces constants`
Stage B: `chore(orchestrator): burn down bench-calibrated constants (D6)`
(+ trailer: `Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>`)

## Suggested PR title & description
**Title:** P5: bench constants become plant-model parameters (behavior-
preserving)
**Description:** Two-stage: wire + prove identical (golden sequences,
targeted ×3, FAST campaign, STOCK spot-check), then delete constants.
socStep kept as explicit legacy override (documented debt). Risk: HIGH.
Rollback: Stage B is one revert; Stage A guarded by defaults-equivalence.

## Code review checklist
- Conversion formulas against `tunedTickInterval`, not engine interval.
- No effective-value drift anywhere (diff the golden outputs, not the code).
- Debt markers on override parameters per 05 §6.

## Definition of done
Acceptance criteria + regression checklist + docs updated + status headers
(this file + 00_MASTER_INDEX) updated.

## Possible follow-up tasks
TASK-065 (second devices get their own plant blocks), TASK-075 (vendor
fixtures populate real parameter values), backlog: discovery probe +
derived socStep.
