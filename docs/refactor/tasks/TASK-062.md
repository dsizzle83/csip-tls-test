# TASK-062 — Per-constraint session structs: consolidate remaining guard state

*Status: TODO · Phase: P5 · Effort: L (≈6–8 h) · Difficulty: high · Risk: high*

## Objective
Every remaining piece of inter-tick state on `DefaultOptimizer` is either
(a) moved into a typed per-constraint session in the constraint package, or
(b) explicitly assigned to the SAFETY tier and documented as such — leaving
`DefaultOptimizer` with no undocumented cross-tick state. The Tier-1 fast
protection path (`EvaluateSafety` + `criticalBatteryInversion`) keeps its
current cadence and latency — battery safety is NOT slowed or moved behind
the arbiter.

## Background
After 060/061 move `expGuard`/`expOverTicks`/`impGuard`/`genGuard`/
`genCapActive`, the remaining inter-tick fields on `DefaultOptimizer`
(verified inventory, optimizer.go:84-184) are:
- `battDrainTicks map[string]int` (:152-157) — consecutive ticks a pack
  measured discharging at/below SOC reserve (audit: battery-wrong-sign);
  drives `checkBatterySafety` disconnect (:1565+,
  `batteryReserveDrainTicks` scaled via `scaleTicks`).
- `battWrongDirTicks map[string]int` (:159-162) — commanded-charge vs
  measured-discharge regardless of SOC (sign-flipped battery).
- `lastBattCmd map[string]float64` (:176-184) — last commanded battery
  setpoint, written by `Optimize`, read by `EvaluateSafety` between
  economic ticks so the fast loop can infer commanded direction; same
  goroutine, no lock (documented contract).
- `tickInterval` + `scaleTicks` (:170-215) — cadence scaling; becomes a
  shared session utility (already scaffolded in 058's session.go).

Safety structure (verified): `checkBatterySafety` (:1565-1640) runs on the
economic tick and handles BOTH fault modes with debounce;
`criticalBatteryInversion` (:1508-1520) is the unambiguous act-now
predicate; `EvaluateSafety` (:1534-1563) is the Tier-1 pass called from
`Engine.safetyTick()` (engine.go:294-317) at `SafetyIntervalS` (default
1 s, cmd/hub/config.go:32) via the `SafetyEvaluator`/`SafetyReader`
optional interfaces (interfaces.go). ADR-0001's two-loop hierarchy and the
Phase 0/1/2 work (Tier-0 interlock in cmd/modbus, Tier-1 fast loop) depend
on this path staying fast and simple.

## Why this task exists
W1's "nine+ pieces of inter-tick state in nine+ places" ends here: after
this task, every piece of guard state has exactly one typed, documented,
reset-specified owner (05 §1 "one owner per concept"), which is what makes
TASK-066's deletion of the legacy cascade safe to review.

## Architecture review sections
W1 · R4 · §8.1 · 02 AD-007 (one session struct per constraint) ·
ADR-0001 (two-loop; Tier-1 latency) · 03 §P5 · 05 §1/§4 · 08 RSK-01.

## Prerequisites
TASK-061 DONE (import/gen flipped and holding). Bench FAST. Solo
radioactive-zone window.

## Files
- **Read first:** optimizer.go:1495-1640 (battery safety block + both
  counters), engine.go:294-317 (safetyTick), interfaces.go,
  `constraint/session.go` + the 060/061 sessions.
- **Modify:** `internal/orchestrator/optimizer.go` (state moves),
  `internal/orchestrator/constraint/*` (BatterySafety session home),
  `cmd/hub/main.go` if wiring shifts.
- **Create:** `constraint/batterysafety.go` + `batterysafety_test.go`
  (or equivalently a documented SAFETY-tier home — see step 2 decision).

## Blast radius
`internal/orchestrator` + constraint package. The Tier-1 loop's inputs.
No bus schema, no config schema beyond a possible `"battery_safety"`
constraints-map entry (active-only; it never ships in `off`).

## Implementation strategy
Treat battery safety as a first-class SAFETY-tier constraint with its own
session (drain/wrong-dir counters + lastBattCmd), evaluated BOTH on the
economic tick (full logic) and by the fast path (criticalBatteryInversion
only, exactly as today). The fast path must not acquire new locks or run
the arbiter: `EvaluateSafety` keeps its direct, allocation-light shape and
reads the session on the same control goroutine (the engine already
serializes Optimize/EvaluateSafety — interfaces.go documents it; verify in
engine.go before relying on it).

## Detailed steps
1. Create `BatterySafetySession` {drainTicks, wrongDirTicks map[string]int;
   lastCmdW map[string]float64} with per-field doc comments carrying the
   audit tags (battery-wrong-sign) and reset semantics (counters reset on
   compliant tick; maps pruned when a device disappears — check legacy for
   pruning behavior and match it).
2. DECISION (record in the PR + 02): `BatterySafetyConstraint` lives at
   `TierSafety` in the constraint package, but its `EvaluateFast` method is
   invoked directly by the optimizer's `EvaluateSafety` — the arbiter is
   only involved on the economic tick. Justify: keeps one owner for the
   state while preserving the Tier-1 latency contract.
3. Move `checkBatterySafety` logic + both counters into the constraint;
   `DefaultOptimizer.checkBatterySafety` delegates (legacy path stays
   callable until 066).
4. Move `lastBattCmd` writes: every place `Optimize` records a battery
   command (grep `lastBattCmd` — optimizer.go:376-379 region) now writes
   the session; `EvaluateSafety` reads it via the constraint's fast path.
5. Migrate `scaleTicks` callers in moved code onto the 058 session helper;
   delete nothing else.
6. Port tests: `TestCheckBatterySafety_*` (convergence_test.go:152-193)
   and `TestEvaluateSafety_*` (:194-238) get constraint twins; mutation-
   verify the reserve-drain disconnect (unwire counter → test fails).
7. Assert no remaining undocumented cross-tick state:
   `grep -n "o\." optimizer.go` audit — every surviving field of
   `DefaultOptimizer` is either config (SOCReserve etc.), `CostModel`,
   `Debug`, `tickInterval`, or a documented delegation handle. List the
   survivors in the PR.
8. Bench: `--only battery-wrong-sign,battery-soc-refuse,
   battery-charge-disabled,battery-reboot,battery-nan-sentinel` ×3;
   full FAST campaign.

## Testing changes
Constraint-package twins for the five battery-safety tests + fast-path
latency guard (a benchmark or an allocation assertion on EvaluateFast).
Run: `make test`; scenarios per step 8.

## Documentation changes
- lexa-hub CLAUDE.md: `checkBatterySafety` bullet → new home; note the
  SAFETY-tier fast-path contract.
- 02 AD-007: step-2 decision recorded.
- Preservation ledger: battery entries updated.

## Common mistakes to avoid
- Running `criticalBatteryInversion` through the arbiter/demand pipeline —
  that adds latency and allocation to a 1 s protective loop for zero
  benefit; the fast path bypasses arbitration BY DESIGN (record it).
- Adding a mutex to the session "just in case" — the engine serializes
  both entry points on one goroutine; a lock would hide a future contract
  violation instead of crashing it under `-race`. Add a race test instead.
- Changing counter thresholds or the ride-out-single-tick semantics
  (`TestCheckBatterySafety_RidesOutSingleTick`).
- Forgetting map pruning parity — a leaked per-device counter map is the
  `registries sync.Map` lesson (§11).
- Overlapping with TASK-063/064 in the same campaign window.

## Things that must NOT change
- Tier-1 latency: `EvaluateSafety` cadence (SafetyIntervalS=1 s), its
  direct disconnect on `criticalBatteryInversion`, and `safetyTick`'s
  plan-observer notification (engine.go:303-310).
- Preservation-ledger entries: reserve-drain disconnect + wrong-direction
  disconnect ↔ **battery-wrong-sign**; single-tick ride-out ↔ HIL meter
  blips; `lastBattCmd` commanded-direction inference ↔ the fast loop
  acting between economic ticks.
- INV-SOC invariant behavior (the harness's ground-truth oracle for these
  scenarios).
- V6 baseline.

## Acceptance criteria
- [ ] `DefaultOptimizer` field audit in PR: no undocumented inter-tick
  state remains.
- [ ] Battery scenario set ×3 at accepted verdicts; full FAST campaign ≤
  baseline.
- [ ] Fast-path parity: EvaluateSafety twins green; no new locks; race
  test green.
- [ ] Mutation check recorded for the reserve-drain disconnect.

## Regression checklist
- [ ] `go test -race ./internal/...` (lexa-hub) green
- [ ] Conformance logic tests: none
- [ ] Mayhem: full FAST campaign (mandatory)
- [ ] Targeted battery scenarios ×3

## Mayhem scenarios affected
battery-wrong-sign, battery-soc-refuse, battery-charge-disabled,
battery-reboot, battery-nan-sentinel, perfect-storm (INV-SOC leg).

## Conformance implications
None (battery safety is local protection, not a 2030.5 function).

## Suggested commit message
`refactor(orchestrator): battery-safety session in SAFETY tier; DefaultOptimizer inter-tick state emptied`
(+ trailer: `Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>`)

## Suggested PR title & description
**Title:** P5: guard-state consolidation into per-constraint sessions
**Description:** battDrainTicks/battWrongDirTicks/lastBattCmd →
BatterySafetySession (SAFETY tier, arbiter-bypassing fast path);
field audit shows DefaultOptimizer has no residual undocumented state.
Risk: HIGH (touches the battery safety chain) — full campaign + targeted
×3 evidence attached. Rollback: revert commit (state moves are mechanical).

## Code review checklist
- Fast-path bypass justified + documented; no arbiter in the 1 s loop.
- Counter/reset/pruning parity line-by-line.
- Field audit list complete and honest.

## Definition of done
Acceptance criteria + regression checklist + docs updated + status headers
(this file + 00_MASTER_INDEX) updated.

## Possible follow-up tasks
TASK-063 (economic isolation now that compliance+safety are session-
owned), TASK-065 (per-device sessions enable multi-device), TASK-066.
