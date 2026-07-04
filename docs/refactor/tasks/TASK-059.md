# TASK-059 — Shadow-mode dual-run harness (old cascade vs new stack, decision diff)

*Status: TODO · Phase: P5 · Effort: L (≈6–8 h) · Difficulty: high · Risk: med*

## Objective
Behind a `constraint_shadow` config flag, every economic tick runs BOTH the
legacy `DefaultOptimizer` (authoritative — its plan is the only one
actuated) and the new constraint `Stack` (observe-only), diffs their FINAL
per-device outputs under tolerance bands, logs divergences with a state
snapshot, and exposes a divergence counter. This harness is the gate for
every P5 flip: ≥1 week of bench shadow data including one full Mayhem
campaign with ~0 diff rate on accepted scenarios before any constraint
goes active (03 §P5).

## Background
The engine calls `o.Optimize(state)` once per tick from a single control
goroutine (`Engine.tick()`, engine.go:496+; interfaces.go documents the
single-goroutine contract). `cmd/hub/main.go` constructs the optimizer and
engine (config: `configs/hub.json`, decoded by cmd/hub/config.go). The
constraint `Stack` (TASK-058) implements `orchestrator.Optimizer` but is
unwired.

Diff-noise policy (bake into the design, not the review): the legacy
cascade contains slews (`maxDropW/maxRiseW`), a low-pass filter
(`filterAlpha`), and leaky counters — the new stack reproduces these
*approximately* via plant parameters, so **bit-exact comparison is wrong**.
Compare with tolerance bands and compare *final outputs*, not intermediate
decisions: `SolarCommands.CurtailToW`, `BatteryCommands.SetpointW/Connect`,
`EVSECommands.MaxCurrentA`, and `Breach` presence/LimitType.

Metrics: TASK-044 (Prometheus `/metrics`) is a P4 deliverable and should be
DONE by P5; if it is, the divergence counter is a metric; if not, fall back
to a counter in the retained plan-log message (`lexa/hub/plan`,
bus.TopicHubPlan, topics.go:61) so the dashboard/QA can see it either way.

## Why this task exists
RSK-03: the cascade's implicit rule-ordering semantics may resolve a
conflict differently in the explicit ladder; shadow-diffing on live bench
input is the only way to find those before a flip. 03 §P5 makes shadow
data a hard gate.

## Architecture review sections
W1 · R4 · §8.1 · 02 AD-007 (shadow-mode dual-run gates every flip) ·
03 §P5 · 08 RSK-03 · 05 §12 (radioactive zone).

## Prerequisites
TASK-058 DONE. TASK-044 preferably DONE (metric path); soft dependency —
the plan-log fallback keeps this task unblocked. Bench available in FAST
mode for validation (`bash scripts/bench-up.sh --fast` in csip-tls-test).

## Files
- **Read first:** `internal/orchestrator/engine.go` (tick + executePlan +
  planObserver), `cmd/hub/main.go` (optimizer/engine construction,
  planObserver wiring at 98-140), `cmd/hub/config.go`,
  `internal/orchestrator/constraint/stack.go` (058),
  `internal/bus/topics.go` (TopicHubPlan).
- **Modify:** `cmd/hub/config.go` (+`"constraint_shadow": bool`),
  `cmd/hub/main.go` (wrap the optimizer when flag set),
  `configs/hub.json` (example, default false).
- **Create:** `internal/orchestrator/constraint/shadow.go` +
  `shadow_test.go`.

## Blast radius
cmd/hub wiring + one new file in the constraint package. When the flag is
false (default): zero behavior change. When true: extra CPU per tick
(`Optimize()` is sub-ms, review §12 — negligible) and extra log lines
(rate-limited). The actuated plan is ALWAYS the legacy one.

## Implementation strategy
Implement `shadow.Wrap(legacy, stack, opts) orchestrator.Optimizer`: its
`Optimize()` calls legacy first, then the stack with the same
`SystemState`, diffs, records, and returns the LEGACY plan unmodified.
Wire it in cmd/hub behind the config flag. Divergence records are
structured one-line JSON (state snapshot + both outputs) with a per-signature
rate limit so a persistent divergence cannot flood journald (05 §9,
flash budget).

## Detailed steps
1. `shadow.go`: `type Wrapper struct { legacy, candidate orchestrator.Optimizer;
   tol Tolerances; count uint64; onDiverge func(Divergence) }` implementing
   `orchestrator.Optimizer`. Default `Tolerances`: watt axes ±150 W or ±5 %
   of the commanded value (whichever larger — covers slew/filter phase
   lag); `MaxCurrentA` ±0.5 A; `Connect` exact; `Breach`: same
   presence AND LimitType, onset allowed to differ by ≤2 ticks (implement
   as a 2-tick debounce on breach-presence mismatch).
2. Diff only FINAL outputs (command lists keyed by device+axis; a command
   absent on one side with the other side commanding a change = divergence;
   both-absent = agree). Never compare `Decisions` strings.
3. `Divergence` record: tick timestamp, per-axis (legacy, candidate,
   delta), a compact `SystemState` snapshot (grid net W, per-device power/
   SOC/connect, active CSIP limits), and the candidate's session names.
   Log as one JSON line, rate-limited to 1/min per divergence signature
   (device+axis), with a suppressed-count field.
4. Counter: increment `count` per divergent tick; if TASK-044 metrics
   exist, register `lexa_constraint_shadow_divergence_total`; always also
   include the running count in the plan-log publish (extend the
   `logPlan`/plan-log payload in cmd/hub — additive JSON field, no schema
   break; bus envelope rules from TASK-017 apply if landed).
5. cmd/hub wiring: when `cfg.ConstraintShadow`, build the Stack (with
   plant models from hub.json, TASK-057) and wrap. The wrapper must also
   pass through the `SafetyEvaluator`/`SafetyReader` type-assertions cmd/
   hub and the engine perform — implement `EvaluateSafety` by delegating
   to the LEGACY optimizer only (candidate safety comes in TASK-062), and
   document that.
6. Unit tests: tolerance-band edges, breach-debounce, rate limiter,
   passthrough (returned plan is pointer-equal/deep-equal to legacy's),
   SafetyEvaluator delegation.
7. Bench validation: deploy hub (`bash ~/projects/lexa-hub/scripts/
   deploy-hub-pi.sh 69.0.0.1 dmitri` after `make build-arm64`), re-run
   `scripts/hub-replay-tune.sh fast` (deploy resets timing to STOCK —
   known gotcha), enable the flag, confirm divergence counter visible and
   ~0 with the empty/echo Stack, run one full Mayhem campaign
   (`python3 scripts/mayhem.py --dashboard http://69.0.0.20:8080`).

## Testing changes
- `shadow_test.go` as above.
- Bench: 1 campaign with flag on; verdicts must equal a flag-off baseline
  campaign (shadow must be observationally inert).
- Run: `make test` (lexa-hub); campaign via scripts/mayhem.py.

## Documentation changes
- lexa-hub CLAUDE.md: `constraint_shadow` flag documented (observe-only).
- 03 §P5 gate text: link the divergence counter location.
- 08 RSK-03 row: detection column now "shadow decision-diff rate".

## Common mistakes to avoid
- Letting the candidate's plan leak into actuation (the wrapper must
  return the legacy plan object, and executePlan must never see the
  candidate's).
- Bit-exact diffing (guaranteed false alarms from slew/filter phase) — or
  tolerances so wide they hide real ordering differences. Justify every
  band in a comment with the physical source (filter alpha, slew step).
- Unbounded divergence logging — journald/flash budget (review §11, 05 §9).
- Forgetting `hub-replay-tune.sh fast` after deploy — campaign runs at
  STOCK timing and every latency-sensitive verdict goes INCONCLUSIVE.
- Dashboard rebuild trap when touching csip-tls-test: the csip-dashboard
  unit execs `bin/dashboard` — irrelevant here unless you also touch the
  dashboard; hub-side only.

## Things that must NOT change
- Actuated behavior with flag on or off: the legacy cascade remains the
  sole author of executed plans until TASK-060 flips export.
- Tick budget: shadow work happens on the control goroutine — keep it
  allocation-light; no blocking I/O (05 §4).
- `EvaluateSafety` cadence and semantics (Tier-1 loop untouched).
- V6 campaign baseline: 0.6 FAIL/cycle, 0 BLIND — a flag-on campaign may
  not regress it.

## Acceptance criteria
- [ ] Flag off: byte-identical behavior (campaign verdicts match baseline).
- [ ] Flag on: divergence counter visible (metric or plan-log field);
  divergences logged with snapshot, rate-limited.
- [ ] Legacy plan provably the only actuated plan (unit test + code path).
- [ ] One full FAST campaign with flag on, verdicts ≤ baseline.

## Regression checklist
- [ ] `go test -race ./internal/...` (lexa-hub) green
- [ ] Conformance logic tests: none
- [ ] Mayhem: full FAST campaign (flag on) + baseline comparison
- [ ] `hub-replay-tune.sh fast` re-applied after every hub deploy

## Mayhem scenarios affected
None should change verdict. The campaign is run to prove exactly that and
to start accumulating shadow-diff data for 060's gate.

## Conformance implications
None.

## Suggested commit message
`feat(hub): constraint-stack shadow harness behind constraint_shadow flag (observe-only)`
(+ trailer: `Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>`)

## Suggested PR title & description
**Title:** Shadow-mode dual-run harness for the constraint stack
**Description:** Legacy cascade stays authoritative; candidate stack runs
observe-only per tick; tolerance-banded final-output diff, rate-limited
divergence log, counter. Flag default off. Risk: med (control-goroutine
code) — mitigated by passthrough tests + flag-on campaign. Rollback: set
`constraint_shadow: false`, restart lexa-hub.

## Code review checklist
- Passthrough correctness (no mutation of the legacy plan).
- Tolerance bands justified with physical sources.
- No I/O in the diff path; log emission rate-limited.
- Safety delegation to legacy only.

## Definition of done
Acceptance criteria + regression checklist + docs updated + status headers
(this file + 00_MASTER_INDEX) updated.

## Possible follow-up tasks
TASK-060 (uses ≥1 week of shadow data as its flip gate), TASK-064
(shadow-diff ≈ 0 proof for plant parameters).
