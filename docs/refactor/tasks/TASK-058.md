# TASK-058 — Constraint-controller package skeleton (safety > compliance > economics)

*Status: TODO · Phase: P5 · Effort: L (≈6–8 h) · Difficulty: high · Risk: low*

## Objective
A new, fully unit-tested, I/O-free package
`lexa-hub/internal/orchestrator/constraint` exists containing: the
`Constraint` interface, per-constraint `Session` state, a priority-ordered
`Arbiter` (safety > compliance > economics) that resolves constraint
demands into per-device desired state, and a `Stack` type implementing
`orchestrator.Optimizer`. NOTHING is wired into the engine or cmd/hub —
the legacy cascade remains the only active path.

## Background
Today `DefaultOptimizer.Optimize()` (optimizer.go:262-380) is a strictly
ordered rule cascade — Rule 1 disconnect → 2 fixed dispatch → 2.5 plan →
3/3.1/3.5 export/gen/import limits + convergence checkers → 4 self-use →
5 TOU → 6 EV → restore → safety backstop — threading a mutable `batteries`
slice and `*Plan` through every rule, with inter-tick guard state in 9+
fields on `DefaultOptimizer` (`expGuard` 8 fields, `impGuard` 5, `genGuard`,
`expOverTicks`, `battDrainTicks`, `battWrongDirTicks`, `lastBattCmd`,
`genCapActive`, `tickInterval`). Rule ORDERING is implicit conflict
resolution (review W1). AD-007 replaces this with an explicit priority
ladder over a per-device plant model (TASK-057 types).

Key existing seams (verified):
- `orchestrator.Optimizer` interface: `Optimize(SystemState) Plan`,
  single-goroutine contract (interfaces.go:9-11) — the Stack implements
  this, so the engine never needs to know which stack runs.
- `SafetyEvaluator`/`EvaluateSafety` (interfaces.go:25-27,
  optimizer.go:1542) is the Tier-1 fast loop — OUT of scope here; it stays
  on `DefaultOptimizer` until TASK-062 addresses battery-safety sessions.
- Package placement decision: `internal/orchestrator/constraint`
  (subpackage), NOT `internal/constraint`. Justification: it reuses the
  orchestrator's exported types (`SystemState`, `Plan`, `ComplianceBreach`)
  without a new export surface, inherits the I/O-free rule (05 §1 names
  `internal/orchestrator` as the defended I/O-free layer), and the
  radioactive-zone rule (05 §12: `internal/orchestrator/*`) automatically
  covers it. No import cycle: `constraint` imports `orchestrator`;
  `orchestrator` never imports `constraint`; wiring happens in `cmd/hub`
  (TASK-059).

## Why this task exists
W1: the cascade's implicit ordering is the dominant defect source
(guard×guard interactions). AD-007 mandates an explicit priority ladder
with one session struct per constraint. This skeleton gives TASK-059's
shadow harness something to run and TASK-060/061 somewhere to migrate into.

## Architecture review sections
W1 · R4 · §8.1 · 02 AD-007 · 03 §P5 · 05 §1/§2/§8.

## Prerequisites
TASK-056 (behavioral tests) and TASK-057 (plant-model types) DONE.

## Files
- **Read first:** `internal/orchestrator/optimizer.go` (Optimize cascade,
  262-380; guard structs 13-58; DefaultOptimizer fields 84-184),
  `interfaces.go`, `model.go` (Plan/SystemState), `plantmodel.go` (057).
- **Modify:** none.
- **Create:** `internal/orchestrator/constraint/constraint.go`,
  `constraint/arbiter.go`, `constraint/session.go`, `constraint/stack.go`,
  `constraint/*_test.go`, `constraint/doc.go`.

## Blast radius
New package only. Zero changes to existing packages, configs, bus schemas,
or binaries (the package compiles but nothing imports it yet).

## Implementation strategy
Define the vocabulary first (Demand, Session, priority tiers), then the
Arbiter's resolution semantics as pure functions with exhaustive
table-driven tests, then a Stack that runs constraints in priority order
and emits an `orchestrator.Plan`. Model demands as *bounds* (min/max per
actuator axis), not commands — arbitration is interval intersection with
priority override, which makes conflicts explicit and testable, unlike the
cascade's "later rule silently overwrites".

## Detailed steps
1. `constraint.go`: core types.
   ```go
   type Tier int // TierSafety > TierCompliance > TierEconomics (resolution order)
   type Demand struct {
       Device string            // matches SystemState device names / station IDs
       Axis   Axis              // SolarCeilingW | BatterySetpointW | EVSECurrentA | Connect
       Min, Max float64         // admissible interval (NaN = unbounded side)
       Connect  *bool           // only for Axis Connect
       Tier   Tier
       Source string            // constraint name, for decisions/diagnostics
   }
   type Input struct {
       State orchestrator.SystemState
       Plant map[string]orchestrator.DevicePlant // from TASK-057 (role-appropriate)
       TickSeconds float64
   }
   type Constraint interface {
       Name() string
       Tier() Tier
       Evaluate(in Input, s *Session) ([]Demand, *orchestrator.ComplianceBreach)
   }
   ```
   (Adapt `DevicePlant` naming to whatever TASK-057 landed; verify before
   writing.)
2. `session.go`: `Session` = named per-constraint-instance inter-tick
   state: generic fields (a `Counters map[string]int` is NOT acceptable —
   sessions are typed per constraint in 060+; here define only the shared
   scaffolding: reset hooks, `ScaleTicks(wallClock)` helper mirroring
   `DefaultOptimizer.scaleTicks` semantics incl. the floor-of-2 rule,
   optimizer.go:203-215).
3. `arbiter.go`: `Resolve([]Demand) map[string]Desired` — per device+axis,
   intersect intervals top tier first; a lower tier may only narrow, never
   widen; empty intersection at the same tier → most-restrictive wins
   (lowest Max for ceilings, safest for Connect=false) and the conflict is
   recorded on the output for the plan's decision log. Deterministic
   ordering (sort by tier, then source name) — no map-iteration
   nondeterminism.
4. `stack.go`: `Stack{constraints []Constraint, sessions map[string]*Session,
   plant ..., tickSeconds float64}` with
   `Optimize(state orchestrator.SystemState) orchestrator.Plan` — runs
   Evaluate per constraint, arbitrates, converts `Desired` into
   Battery/Solar/EVSE commands + `Breach` via `recordBreach`-equivalent
   worst-shortfall selection (mirror optimizer.go:2192-2197), and appends
   one Decision per resolved conflict. With zero constraints registered it
   returns an empty plan.
5. Table-driven tests: interval intersection cases, tier override, same-
   tier conflict, Connect precedence (false beats true), determinism (run
   1000×, identical output), ScaleTicks floor-of-2 parity with
   `DefaultOptimizer.scaleTicks` (copy its test vectors).
6. `doc.go`: package comment stating the ladder, the "constraints narrow,
   economics propose" contract, the no-I/O rule, and that sessions reset
   semantics are constraint-owned (load-bearing, see TASK-060).
7. `make test` green.

## Testing changes
New `constraint/*_test.go` (table-driven, no bench). Run:
`cd ~/projects/lexa-hub && make test`.

## Documentation changes
- 02 AD-007: record the package-location decision + demand/arbiter model.
- lexa-hub CLAUDE.md: add `internal/orchestrator/constraint` to the
  directory map (skeleton, unwired).

## Common mistakes to avoid
- Wiring the Stack anywhere. The engine/cmd/hub must not reference it —
  that is TASK-059's shadow flag.
- Letting the arbiter widen a bound at a lower tier (economics must never
  relax a compliance ceiling).
- Map-ordering nondeterminism in Resolve — shadow diffing (059) needs
  reproducible output.
- Re-implementing `scaleTicks` with different rounding — copy the
  semantics and the floor of 2 exactly; FAST/STOCK equivalence depends on
  it.
- Designing sessions as untyped counter bags — each constraint gets a
  typed session struct in 060/061/062; this task only ships scaffolding.

## Things that must NOT change
- Existing optimizer behavior and all existing tests (zero edits).
- `orchestrator.Optimizer` interface signature.
- The Tier-1 safety loop (`EvaluateSafety`) — untouched, stays on
  `DefaultOptimizer` (moves are TASK-062's problem, and battery safety
  stays in the SAFETY tier there).

## Acceptance criteria
- [ ] `go build ./...` and `make test` green; no existing file modified.
- [ ] `Stack` satisfies `orchestrator.Optimizer` (compile-time assertion
  `var _ orchestrator.Optimizer = (*Stack)(nil)` in a test).
- [ ] Arbiter property tests: narrowing-only, determinism, tier order.
- [ ] Package doc states ladder + contracts.

## Regression checklist
- [ ] `go test -race ./internal/...` (lexa-hub) green
- [ ] Conformance logic tests: none
- [ ] Mayhem: none (unwired-code exception per 05 §12; the PR that first
      wires this code pays the full campaign)
- [ ] grep confirms no imports of `orchestrator/constraint` outside itself

## Mayhem scenarios affected
None yet (nothing executes this code on the bench).

## Conformance implications
None.

## Suggested commit message
`feat(orchestrator): constraint-controller skeleton — demands, arbiter, sessions, stack (AD-007, unwired)`
(+ trailer: `Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>`)

## Suggested PR title & description
**Title:** Constraint controller skeleton (unwired)
**Description:** New I/O-free `internal/orchestrator/constraint` package:
priority arbiter + session scaffolding + Optimizer-compatible Stack, fully
table-tested; no wiring, no behavior change. Risk: low. Rollback: delete
the package.

## Code review checklist
- Arbiter narrowing-only property actually enforced (not just tested).
- ScaleTicks parity vectors match optimizer.go.
- No I/O, no time.Now(), no logging side effects in Evaluate/Resolve
  (injected clock/tick only).

## Definition of done
Acceptance criteria + regression checklist + docs updated + status headers
(this file + 00_MASTER_INDEX) updated.

## Possible follow-up tasks
TASK-059 (shadow harness runs the Stack), TASK-060 (first real constraint).
