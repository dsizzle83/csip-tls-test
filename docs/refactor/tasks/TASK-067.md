# TASK-067 — Engine state consolidation: one state struct, single writer (R7 rest)

*Status: DONE (2026-07-06, lexa-hub 6317a8d) · Phase: P5 · Effort: M (≈4–6 h) · Difficulty: med · Risk: med*

> Done 2026-07-06 on lexa-hub branch `task/067-engine-consolidation` (commit 6317a8d,
> not pushed/merged). All four remaining engine mutexes collapsed into one `engineState`
> struct (`internal/orchestrator/engine_state.go`) with a single designated writer per
> field + lock-free `atomic.Pointer` snapshot reads; `grep -c "sync.RWMutex\|sync.Mutex"
> engine.go` = 0 (only `stopOnce sync.Once` remains, unrelated). `csipMu` confirmed
> already gone (TASK-012). Before→after lock map:
> - `actuMu` (RWMutex) → DELETED. Actuator registries are plain maps, immutable after
>   `Start()`; `RegisterBattery/Solar/EVSEActuator` panic if called post-Start (init-time
>   impossibility, 05 §3), so `executePlan` reads them lock-free.
> - `planInMu` (RWMutex) → `engineState.planIn atomic.Pointer[plannerInput]`, written only
>   on the control goroutine via `engineCmd`s drained from a bounded `cmdCh` (cap 16,
>   drop-and-count). `SetDERConstraints`/`SetPrices` now ENQUEUE (async, ≤1-tick latency,
>   never block an MQTT callback); read by `replan()` via atomic load.
> - `dailyPlanMu` (RWMutex) → `engineState.dailyPlan atomic.Pointer[DailyPlan]`; planner
>   goroutine (`replan`) is sole writer, control goroutine (`tick`) reads (chose option (b),
>   dedicated atomic pointer — no plan-adoption delay).
> - `planMu` (RWMutex) → `engineState.lastPlan atomic.Pointer[Plan]`; `LastPlan()` is a
>   lock-free load.
> Closure sweep: no remaining closure-held control-path state in engine.go or cmd/hub's
> tick/observer path (`activeBreachMRID`/`dedupeResets` already promoted to the named
> `breachEpisodes` component in cmd/hub/breach.go by TASK-031/032; verified by grep).
> `Wake()`/`urgentWake` and the ADR-0001 Tier-1 fast safety loop (`EvaluateSafety`/
> `safetyTick`) preserved exactly — safety tick never touches `cmdCh`. `engine_test.go`
> UNCHANGED (empty diff vs origin/main) and green under `-race` (run ×5); new
> `engine_concurrency_test.go` adds command-ordering, mid-tick-drain, and race-hammer
> tests. `make test` (`go test -race ./internal/...`) green; `go test -race ./...`,
> `go vet ./...`, `go build ./...` all green. Bench/Mayhem campaign BATCHED at the wave
> gate per the deadline addendum (radioactive zone, code+test only this session). Awaiting
> review/merge.

## Objective
`Engine`'s five mutex-guarded state groups collapse into ONE state struct
owned by a single writer goroutine with snapshot reads; any remaining
closure-held state in the hub's control path gets promoted to named,
documented fields. `Wake()`, the economic tick, the 1 s safety tick, and
the planner goroutine keep their exact external behavior and cadences.

## Background
Verified in `lexa-hub/internal/orchestrator/engine.go` (670 lines): five
mutexes —
- `actuMu sync.RWMutex` (:43) — actuator registries
  (RegisterBatteryActuator/RegisterSolarActuator/RegisterEVSEActuator,
  :176-196);
- `csipMu sync.RWMutex` (:49) — CSIP program state (the `SetCSIPPrograms`/
  `e.sched` dual path at :198-226/:506-530 was DELETED by TASK-012 in P0 —
  verify it is gone; if TASK-012 slipped, do it first, not here);
- `planInMu sync.RWMutex` (:66) — planner inputs (SetDERConstraints :149,
  SetPrices :159, signalReplan :167);
- `dailyPlanMu sync.RWMutex` (:70) — planner output (`dailyPlan`, written
  by replan :361-363, read by tick :536-540);
- `planMu sync.RWMutex` (:74) — `LastPlan()` (:565).

Concurrency actors: `run()` control loop (economic tick + safety tick on
one goroutine, :248+), `plannerLoop()` goroutine (:321-346), external
callers (cmd/hub MQTT subscribers calling SetDERConstraints/SetPrices/
Wake; RegisterXActuator at startup), and readers (LastPlan for lexa-api
via cmd/hub). 05 §4: "One writer per state struct; snapshot reads. (Engine
mutex consolidation, TASK-067, is the model.)" and "No state in closures.
If it has a name in a bug report, it needs a name in the code
(`activeBreachMRID` lesson)."

Closure state in cmd/hub/main.go today: `activeBreachMRID` (:98) and
`dedupeResets []func()` (:99-115) — TASK-031 (CannotComply collapse) and
TASK-032 (dedupe deletion) rework these in P2; whatever named component
they produced is the pattern; this task sweeps any REMAINING closure
state in the tick/observer path (grep before assuming).

## Why this task exists
R7 remainder (TASK-012 took the dead dual path in P0): five lock domains
in a 670-line file is where a future engineer deadlocks or reads torn
state; the review's C08 wedge hypothesis and W6 both point at engine
plumbing. Post-066 the engine is the last un-refactored piece of the
control core.

## Architecture review sections
R7 · W6 (context) · D3 (dead path — P0 precedent) · §11 (goroutine
hygiene) · 05 §4 · 03 §P5 exit ("engine mutexes collapsed to one state
struct with single writer").

## Prerequisites
TASK-066 DONE. TASK-012 verified done (grep `SetCSIPPrograms` → gone).
Solo radioactive-zone window; bench FAST for the campaign.

## Files
- **Read first:** engine.go in full; cmd/hub/main.go (all Engine call
  sites + remaining closures); cmd/hub/actuators.go (post-032 state);
  engine_test.go.
- **Modify:** `internal/orchestrator/engine.go`, `engine_test.go`,
  `cmd/hub/main.go` (only if closure promotion lands there).
- **Create:** none (or `engine_state.go` if the split helps the 600-line
  cap).

## Blast radius
Engine internals + its exported method contracts' timing (must not
change). All six services are consumers-by-behavior via the plans the
engine emits; lexa-api reads LastPlan-derived output. No config, no bus
schema.

## Implementation strategy
Introduce `engineState` holding all five groups; route ALL mutations
through the control goroutine via a buffered command channel (mutators
like SetDERConstraints enqueue; Wake stays a signal); reads return
snapshots (copy-on-read of small structs; the actuator maps are
registered-at-startup — enforce registration-before-Start and make them
immutable after Start, which removes actuMu entirely). Keep `run()` as
the single writer. Do it as a sequence of compiling refactors, one lock
domain at a time, `-race` after each.

## Detailed steps
1. Grep-audit call sites of each mutex; write the table (who writes, who
   reads, from which goroutine) in the PR. Confirm `csipMu`'s domain is
   empty post-012; delete it first as a freebie.
2. Enforce actuator registration before `Start()` (cmd/hub already does —
   verify order in main.go, :202-214 region); make registries plain maps,
   drop `actuMu`; add a guard panic on post-Start registration (init-time
   impossibility, allowed per 05 §3).
3. Add `type engineCmd func(*engineState)` channel (buffered, e.g. 16);
   `run()` drains commands at tick top and on Wake. Convert
   SetDERConstraints/SetPrices to enqueue + signalReplan. Preserve
   ordering guarantee: commands from one caller apply in order.
4. Planner output: `replan()` runs on the planner goroutine today and
   writes `dailyPlan` — either (a) planner goroutine sends the result as a
   command, or (b) keep one dedicated `atomic.Pointer[DailyPlan]`.
   Choose (a) for single-writer purity unless it delays plan adoption by
   >1 tick; record the choice.
5. `LastPlan()`: `atomic.Pointer[Plan]` snapshot written only by the
   control goroutine (drop planMu).
6. Sweep closures: grep cmd/hub for `func()` captures holding state in
   the tick/observer path; promote leftovers into a named struct with doc
   comments (the `activeBreachMRID` lesson).
7. `-race` suite + new concurrency tests: concurrent SetPrices/Wake/
   LastPlan hammer test; a test that a command enqueued mid-tick applies
   before the next Optimize.
8. Bench: deploy, `hub-replay-tune.sh fast`;
   `--only hub-restart-mid-cap,mqtt-broker-restart,clock-jitter` ×3
   (restart/reseed + timing-sensitive set); full FAST campaign.

## Testing changes
engine_test.go: rewrite lock-dependent tests to the command/snapshot API;
add the hammer + ordering tests. Run: `make test`; scenarios per step 8.

## Documentation changes
- 05 §4 already names this task as the model — add a pointer to the final
  shape.
- lexa-hub CLAUDE.md: note the single-writer engine contract (mutators
  are async; effective next tick).

## Common mistakes to avoid
- Making mutators synchronous-blocking on the control loop (a stalled
  tick would then stall MQTT callbacks — the C08 wedge shape). Enqueue
  with timeout-drop-and-count per 05 §4 bounded-channel policy.
- Changing WHEN state becomes visible to Optimize (today: a SetPrices
  during a tick is visible next tick via RLock timing; the command drain
  point must preserve "at most one tick" latency — the timing-sensitive
  scenarios in step 8 guard this).
- Slowing `safetyTick` (it must not wait on the command channel; it reads
  via the same control goroutine so no locks needed by construction).
- Removing `Wake()` semantics (SetCSIPPrograms is gone, but Wake is still
  called — grep cmd/hub for remaining callers before touching it).
- Batching with any other radioactive change.

## Things that must NOT change
- Tick cadence (EngineIntervalS), safety cadence (SafetyIntervalS),
  planner cadence (ReplanIntervalS) and their goroutine ownership.
- `executePlan`/`logPlan`/planObserver ordering (breach-alert edge logic
  depends on observer-before-execute or current order — read and preserve
  exactly; safetyTick notifies the observer at :303-310).
- Plan visibility to lexa-api (LastPlan freshness).
- Restart/reseed behavior (**hub-restart-mid-cap** scenario) and broker
  reseed (**mqtt-broker-restart**).
- V6 baseline.

## Acceptance criteria
- [ ] `grep -c "sync.RWMutex\|sync.Mutex" engine.go` ≤ 1 (ideally 0;
  channel + atomics instead).
- [ ] Call-site table in PR; every mutation on the control goroutine.
- [ ] Hammer/ordering tests green under `-race`.
- [ ] Targeted ×3 + full FAST campaign ≤ baseline.
- [ ] No closure-held control-path state remains (grep evidence).

## Regression checklist
- [ ] `go test -race ./internal/...` (lexa-hub) green
- [ ] Conformance logic tests: none
- [ ] Mayhem: full FAST campaign (radioactive zone)
- [ ] hub-restart-mid-cap / mqtt-broker-restart / clock-jitter ×3

## Mayhem scenarios affected
hub-restart-mid-cap, mqtt-broker-restart, mqtt-broker-latency,
clock-jitter, perfect-storm (timing legs). Verdicts must hold.

## Conformance implications
None.

## Suggested commit message
`refactor(orchestrator): engine single-writer state (5 mutexes → command channel + snapshots)`
(+ trailer: `Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>`)

## Suggested PR title & description
**Title:** Engine state consolidation (R7 remainder)
**Description:** One state struct, single writer, snapshot reads;
mutators enqueue; closure sweep. Call-site table + race-hammer tests +
campaign evidence. Risk: med. Rollback: single revert.

## Code review checklist
- Command-drain point preserves ≤1-tick mutation latency.
- Safety tick never blocks on the channel.
- Observer/execute ordering byte-identical.
- No new goroutines without owner/shutdown (05 §4).

## Definition of done
Acceptance criteria + regression checklist + docs updated + status headers
(this file + 00_MASTER_INDEX) updated.

## Possible follow-up tasks
TASK-081 (P5 exit rolls into release gate); backlog: engine.go file split
if the refactor leaves it near the 600-line cap.
