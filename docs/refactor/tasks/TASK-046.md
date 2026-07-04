# TASK-046 — Async actuator publishes; tick time budget + overrun counter

*Status: TODO · Phase: P4 · Effort: L (≈6–8 h) · Difficulty: high · Risk: med*

## Objective
Decouple the hub's actuator MQTT publishes from the engine tick:
fire-with-timeout instead of synchronous PUBACK waits, completion checked
at the next tick, per-device ordering preserved, failures still resetting
the dedupe for re-issue — plus a measured tick time budget with an exported
overrun counter that must read zero under the mqtt-latency scenario in FAST
mode (Phase 4 exit criterion).

## Background
Repo `~/projects/lexa-hub`. Review §11: "Synchronous QoS-1 publish waits in
the tick path: worst case, one tick can spend 5 s per publish (plan log +
alert + N commands) against a sick-but-alive broker — fast-mode ticks (3 s)
overrun."

Verified mechanics:
- `mqttutil.publishJSON` (internal/mqttutil/mqttutil.go:119–129) does
  `client.Publish(...)` then `tok.WaitTimeout(publishTimeout)` with
  `publishTimeout = 5 * time.Second` (line 72). The comment (lines 65–71)
  documents the tradeoff and the idempotence that makes late/dropped
  commands harmless: "every command topic is re-issued on the next tick and
  all handlers are idempotent".
- Tick path: `Engine.tick()` (internal/orchestrator/engine.go:496) →
  `executePlan(plan)` (line 571) fans out to registered actuators;
  `safetyTick()` (line 294) also executes plans at 1 s cadence. The
  actuators (`cmd/hub/actuators.go`) call `mqttutil.PublishJSON`
  synchronously from that engine goroutine; on error they reset their
  deduper (`a.dedupe = cmdDeduper{}`, lines 85, 113, 140) so the next tick
  re-publishes.
- The planObserver (cmd/hub/main.go:103–149) ALSO publishes synchronously
  on the engine goroutine: `PublishJSONRetained(mc, bus.TopicHubPlan, …)`
  every pass and `PublishJSON(mc, bus.TopicCSIPComplianceAlert, …)` on
  breach edges — same 5 s worst case each.
- Paho ordering: messages published from one goroutine on one client are
  transmitted in call order (the client serializes onto one connection;
  `max_inflight_messages 20` broker-side). Waiting is not what orders them
  — so dropping the wait does not reorder. What the wait BUYS today is (a)
  backpressure and (b) the error return that triggers dedupe reset. The
  async design must replace (b) with a completion check and keep (a) via a
  bounded pending set.

Radioactive zone: `cmd/hub/actuators.go` is explicitly listed (05 §12) —
one-per-PR, full campaign, never same-day merge.

## Why this task exists
§11 reliability finding; 05 §4 ("Nothing in a tick/poll loop may block
unboundedly: publishes are fire-with-timeout (TASK-046) … tick overruns are
counted and exported"); Phase 4 exit criterion ("tick-overrun counter
exposed and zero under mqtt-latency scenario in FAST mode").

## Architecture review sections
§11 (sync publish waits), §12 (perf-adjacent risk), W2-adjacent (command
delivery is convergence-critical). Roadmap: 03 Phase 4; 05 §4/§12; 04 row
046; 07 GAP-10 adjacency (TASK-051 storms this path).

## Prerequisites
None hard (04 row 046: no deps). TASK-044 recommended first (the counters
get exported; without it they are logged only — acceptable, register names
anyway).

## Files
- **Read first:**
  - `~/projects/lexa-hub/internal/mqttutil/mqttutil.go` (all)
  - `~/projects/lexa-hub/cmd/hub/actuators.go` + `actuators_test.go`
  - `~/projects/lexa-hub/cmd/hub/main.go` (planObserver)
  - `~/projects/lexa-hub/internal/orchestrator/engine.go` (lines 248–320, 496–620: run loop, tick, executePlan)
  - `~/projects/csip-tls-test/cmd/dashboard/mqtt_scenarios.go` (mqtt-broker-latency/restart oracles)
- **Modify:**
  - `~/projects/lexa-hub/internal/mqttutil/mqttutil.go` (add async publish)
  - `~/projects/lexa-hub/cmd/hub/actuators.go` (+ tests)
  - `~/projects/lexa-hub/cmd/hub/main.go` (planObserver publishes + tick budget measurement)
- **Create:** none.

## Blast radius
Command delivery timing for battery/solar/EVSE actuators, plan log, and
compliance alert. `internal/mqttutil` gains an API (other services keep the
sync one). Failure-handling semantics of actuators change shape (deferred
error) — the dedupe-reset contract must survive exactly.

## Implementation strategy
Add `mqttutil.PublishJSONAsync(client, topic, v, retained) (*PendingPub, error)`
returning immediately after `client.Publish` (marshal errors still
synchronous); `PendingPub.Done() (bool, error)` wraps the token. Actuators
keep a one-slot `pending *PendingPub` per actuator (= per device topic): at
the START of each `Apply*Command`, harvest the previous pending — if it
failed or is still incomplete past `publishTimeout`, reset the deduper
(same re-issue semantics as today, shifted one tick) and increment a
counter. Then publish the new command (never two in flight per topic: if
still pending and not timed out, skip publish when dedupe would have
suppressed anyway; if a genuinely new command must go out, publish — paho
orders it after the pending one). planObserver: plan log uses
fire-and-harvest the same way; the breach alert keeps a SHORT sync wait
(1 s) — it is rare, edge-triggered, and ordering/latency matter more than
tick budget (document this exception). Tick budget: wrap the engine
callbacks in cmd/hub — measure wall time of each executePlan pass
(PlanObserver gives the hook points) or wrap actuator Apply calls;
`budget = 50% of engine_interval_s`; exceeding it increments
`lexa_hub_tick_overruns_total` and logs edge-triggered.

## Detailed steps
1. mqttutil: `PendingPub{tok mqtt.Token, topic string, sentAt time.Time}`;
   `PublishJSONAsync` + `PublishJSONRetainedAsync`; `(*PendingPub).Harvest(
   timeout time.Duration) (ok bool, timedOut bool, err error)` — non-blocking
   check via `tok.WaitTimeout(0)` semantics (paho tokens support
   `WaitTimeout(0)` returning completion state; verify against paho v1.4.3
   vendored source — if `WaitTimeout(0)` blocks-then-times-out immediately
   it still works; test it).
2. Actuators: per-actuator `pending *mqttutil.PendingPub` + harvest logic at
   the top of `ApplyBatteryCommand`/`ApplySolarCommand`/`ApplyEVSECommand`;
   on harvest failure/timeout: `a.dedupe = cmdDeduper{}` (identical to
   today's error branch) + counter. Publish via async. Preserve the exact
   dedupe/sig computation and the breach-reset path (`dedupe.reset()` wired
   from main.go:202–215) untouched.
3. planObserver: plan log → async with harvest-next-pass (a dropped plan
   log is refreshed ≤1 s later by the safety pass — retained topic, last
   write wins); compliance alert → sync with 1 s cap + existing error log.
4. Tick budget in cmd/hub: record `time.Since(start)` around the plan
   fan-out — implement by timestamping in planObserver entry and comparing
   engine pass cadence; simpler and sufficient: measure in the actuator
   wrapper — total time all Apply* calls took this pass; expose
   `lexa_hub_tick_duration_seconds` (gauge) + `lexa_hub_tick_overruns_total`
   (counter, fires when duration > 0.5 × EngineInterval). Document the
   budget fraction in a comment + CLAUDE.md.
5. Unit tests (fake `mqtt.Client`/token — actuators_test.go already stubs
   the client surface; extend):
   - async publish failure → dedupe reset next call → re-publish happens.
   - pending-not-complete → no duplicate in-flight for identical sig.
   - ordering: two DIFFERENT commands to one device both publish, in order.
   - breach reset still forces immediate publish (existing test must pass).
   - overrun counter fires on injected slow publish.
6. Bench: deploy + `hub-replay-tune.sh fast`. Gates:
   `python3 scripts/mayhem.py --dashboard http://localhost:8080 --only mqtt-broker-latency,mqtt-broker-restart,export-cap-full-battery,solar-reboot-forget`
   10× each — verdicts at baseline AND
   `lexa_hub_tick_overruns_total == 0` after the mqtt-broker-latency run
   (curl the metric before/after; this is the Phase 4 exit criterion).
   Then full FAST campaign.

## Testing changes
Extended `cmd/hub/actuators_test.go` (cases in step 5); mqttutil async unit
test with a stub token. Run: `go test -race ./internal/... ./cmd/...`;
bench gates above.

## Documentation changes
- lexa-hub CLAUDE.md: note the async actuator contract (fire-with-timeout,
  harvest-next-tick, dedupe-reset-on-failure) and the tick budget.
- 02: one-line AD note if the reviewer considers the alert's sync exception
  structural.
- mqttutil doc comments: when to use sync vs async.

## Common mistakes to avoid
- **Losing the dedupe-reset-on-failure contract**: today a failed publish
  resets the deduper so the NEXT tick re-publishes (actuators.go:85). If
  the async harvest forgets this, a device misses a command for up to
  `reassertEvery` (60 s) — exactly the class the 2026-07-03 breach-reset
  fix addressed. The mutation test: unwire the harvest-reset and the new
  test must fail.
- Do not make the SAFETY path (disconnects) async-and-forget without
  bounds: `Engine.Wake()` on a CSIP disconnect (cmd/hub/main.go:166–173)
  exists so cease-to-energize applies within MQTT latency — the EVSE/battery
  disconnect command must still go out immediately (async is fine; the
  publish call itself is fast — it's the WAIT we drop).
- Two-in-flight per topic: paho keeps order, but a timed-out-then-delivered
  old command AFTER a new one is the hazard the one-slot pending design
  prevents for identical sigs; for differing sigs order is preserved by the
  client — comment this reasoning in the code.
- `WaitTimeout(0)` semantics on paho v1.4.3: verify, don't assume (step 1).
- Radioactive zone: this PR contains ONLY this change; full campaign before
  merge; not merged the day it's written (05 §12).
- Deploy gotcha: `hub-replay-tune.sh fast` after deploy.

## Things that must NOT change
Preservation ledger entries touched:
- `cmdDeduper` suppress/reassert (60 s watchdog) + breach-triggered reset ↔
  QA 2026-07-03 "0 W ceiling suppressed 30 s" + `export-cap-full-battery`
  ghost (actuators.go:15–56 comments).
- Idempotent re-issue contract (mqttutil.go:65–71 comment) — late/dropped
  commands harmless BECAUSE next tick re-issues; the harvest must keep that
  true.
- Breach alert edge semantics: one Active=true per episode, published
  before/with the tick's commands (planObserver order: dedupe resets run
  BEFORE executePlan — main.go:103–118 comment; do not reorder).
- `mqtt-broker-restart`/`mqtt-broker-latency` verdicts (bus resilience
  ledger).
- No change to `internal/orchestrator` (engine loop untouched; measurement
  lives in cmd/hub).

## Acceptance criteria
- [ ] Unit: all step-5 cases green under `-race`; mutation check on
      harvest-reset documented in the PR.
- [ ] Bench: `lexa_hub_tick_overruns_total` = 0 after a
      `mqtt-broker-latency` run in FAST mode (metric curl evidence).
- [ ] Gates 10× at baseline verdicts; full FAST campaign ≤ baseline.
- [ ] Worst-case tick fan-out time under injected 800 ms broker latency
      measured < 1 s (was: up to 5 s × N publishes) — journal/metric
      evidence.

## Regression checklist
- [ ] `go test -race ./internal/... ./cmd/...` (lexa-hub) green
- [ ] Conformance logic tests: none
- [ ] Mayhem: targeted mqtt + export scenarios 10× + full campaign
      (radioactive file)
- [ ] `hub-replay-tune.sh fast` re-applied after deploy

## Mayhem scenarios affected
`mqtt-broker-latency` (primary — cap must hold AND ticks must not overrun),
`mqtt-broker-restart`, `export-cap-full-battery`, `solar-reboot-forget`,
`grid-disconnect` (disconnect latency), `perfect-storm`. Baseline verdicts
must hold.

## Conformance implications
None (bus-internal). Disconnect (cease-to-energize) latency must remain
within the bounds the `grid-disconnect` scenario asserts.

## Suggested commit message
`perf(hub): async actuator publishes with harvest-next-tick + tick budget/overrun counter (TASK-046)`

Trailer: `Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>`

## Suggested PR title & description
**Title:** Async actuator publishes + tick time budget (TASK-046)
**Description:** Removes up-to-5 s-per-publish PUBACK waits from the engine
tick (§11): fire-with-timeout, completion harvested next tick,
dedupe-reset-on-failure preserved (mutation-checked), per-device ordering
argued and tested; compliance alert keeps a 1 s sync bound (rationale
inline). Tick overrun counter exported; zero under mqtt-latency FAST.
Radioactive-zone PR: full campaign attached. Rollback: revert (sync path
retained in mqttutil).

## Code review checklist
- Harvest-reset equivalence with today's error branch (side-by-side).
- One-slot pending reasoning per topic; no unbounded pending growth.
- Safety/disconnect path latency unchanged or better.
- paho token semantics verified against vendored v1.4.3.
- Campaign + metric evidence attached.

## Definition of done
Acceptance + regression checklists green; docs updated; status headers
updated (this file + 00_MASTER_INDEX).

## Possible follow-up tasks
TASK-051 (MQTT storm leans on these counters), TASK-078 (soak watches
overruns), P2 reconciler (TASK-026+) inherits the async pattern for
desired-state publishes.
