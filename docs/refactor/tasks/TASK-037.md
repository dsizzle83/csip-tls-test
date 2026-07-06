# TASK-037 — Local (hub-side) clock-step policy + implementation

*Status: CODE COMPLETE (2026-07-05, lexa-hub `task/037-local-clock` 8f7e60e,
unmerged) · Phase: P3 · Effort: M (≈4–6 h) · Difficulty: high · Risk: med*

Unit-scope acceptance criteria and `go test -race ./internal/... ./cmd/...`
green (see 02 AD-004 extension for detail). Bench gates
(`clock-jitter`/`clock-jump-forward`/`wan-outage-expiry`/`wan-outage-hold`
10× + full FAST campaign) deferred to the batched wave gate per this
session's launch scoping (code + unit tests only, no bench/deploy access
this pass); TASK-038's Mayhem local-clock-step scenario is the HIL proof
and is tracked separately.

## Objective
Define and implement an explicit policy for steps of the **hub's own wall
clock** (NTP correction at commissioning, RTC drift fix-up): freshness
windows stay monotonic-safe, utility-time evaluations (control expiry, TOU)
become immune to local steps via monotonic anchoring in `utilitytime`, and
wall steps are detected, classified (forward: re-anchor; backward: hold +
alarm), and logged. Extends AD-004; validated by TASK-038's Mayhem scenario.

## Background
All clock hardening so far addresses the *server's* clock. Review §8.4: if
the SOM's wall clock steps, `Ts` fields, freshness windows, `reassertEvery`,
and TOU boundaries all shift. Ground truth in the code (verify before
writing):

- **Freshness windows are already monotonic-safe.** `cmd/hub/state.go`
  stamps arrival with `time.Now()` (`onMeasurement` line 146,
  `onEVSEState` line 166) and compares with `now.Sub(s.at)` (`fresh()` line
  91, `frozenW()` line 98, `evseSnapshot.fresh` line 108). Go's `time.Time`
  carries a monotonic reading when produced by `time.Now()`, and `Sub`
  between two such values uses it — a wall step does NOT shift these. The
  publisher-side `Ts` field in `bus.Measurement` (stamped
  `time.Now().Unix()` in `cmd/modbus/main.go:137`) is **not used** for
  freshness — the hub uses receiver-side arrival stamping. This is the
  design decision to document: **cross-process freshness = receiver-side
  arrival stamp + monotonic age; message `Ts` is observability only.**
- **The exposed comparisons are the wall-clock ones:**
  1. Control expiry: `now.Unix() + r.clockOffset >= ValidUntil`
     (state.go:360–361). A local step forward of +1 h makes every control
     read expired for the whole window between walks; the debounce
     (TASK-036) only rides out ~2–3 ticks. A backward step holds controls
     up to 1 h too long. The northbound walker re-derives the offset every
     walk (`ClockOffset = tm.CurrentTime − time.Now().Unix()`,
     walker.go:162) which *compensates* — but only after the next successful
     walk reaches the hub via a fresh `ActiveControl.ClockOffset`; during a
     WAN outage it never does.
  2. lexa-api reporting grace (handlers.go:131) — same exposure, cosmetic.
  3. TOU `IsPeakHour` (optimizer.go:326) — same exposure, economic.
  4. `cmdDeduper` re-assert watchdog `reassertEvery = 60 s`
     (cmd/hub/actuators.go:24,37) uses `now.Sub(d.lastSent)` with
     `time.Now()` values — monotonic-safe already.
- **The fix primitive:** the hub records, at the arrival of each
  `bus.ActiveControl` message, the pair (wall time, monotonic instant). At
  evaluation time, `effectiveServerNow = arrivalWall.Unix() + msg.ClockOffset
  + monotonicElapsedSince(arrival)`. Monotonic elapsed is immune to local
  wall steps, and each fresh control message re-anchors (northbound
  publishes one per successful walk — `runDiscovery`,
  cmd/northbound/main.go:280). Same primitive serves northbound itself
  (anchor at /tm fetch).

## Why this task exists
Review §8.4 [Speculative but urgent] and GAP-04: an NTP step on
commissioning is the first thing a field deployment does; today the behavior
is untested and partially wrong ("everything expired/held for up to a walk
period" — worse during WAN outages). RSK-06.

## Architecture review sections
§8.4, §9 time family, W4. Roadmap: 02 AD-004 (this task extends it — record
the receiver-side-arrival-stamping decision there); 07 GAP-04; 08 RSK-06.

## Prerequisites
TASK-034 DONE (utilitytime exists), TASK-036 DONE (hub/api/optimizer already
call `utilitytime.ServerNowAt` — this task changes what feeds it).
TASK-035 DONE for the northbound half.

## Files
- **Read first:**
  - `~/projects/lexa-hub/cmd/hub/state.go` (all — especially 83–110, 129–168, 348–375)
  - `~/projects/lexa-hub/cmd/hub/actuators.go` (lines 15–56)
  - `~/projects/lexa-hub/cmd/modbus/main.go` (lines 130–180, Ts stamping)
  - `~/projects/lexa-hub/internal/utilitytime/` (TASK-034/035/036 state)
  - `~/projects/lexa-hub/cmd/api/handlers.go` (lines 120–135)
- **Modify:**
  - `~/projects/lexa-hub/internal/utilitytime/utilitytime.go` (+ tests)
  - `~/projects/lexa-hub/cmd/hub/state.go` (+ `state_test.go`)
  - `~/projects/lexa-hub/cmd/northbound/main.go` (anchor at /tm)
  - `~/projects/lexa-hub/cmd/api/state.go` / `handlers.go` (same anchoring for grace)
- **Create:** none.

## Blast radius
`internal/utilitytime` API (adds an anchored mode), `cmd/hub` expiry
evaluation, `cmd/northbound` serverNow, `cmd/api` grace. No bus schema
change. Control-plane semantics under a *stable* local clock must be
bit-identical (anchored serverNow == wall serverNow when wall never steps).

## Implementation strategy
Add monotonic anchoring to `utilitytime.Clock`: `Anchor(serverTime int64)`
records (server time, monotonic now); `ServerNow()` returns
`anchorServer + monotonicElapsed` when anchored. Add step detection:
`LocalStep() (driftS int64, stepped bool)` comparing wall elapsed vs
monotonic elapsed since anchor (threshold configurable, default 30 s).
Policy: forward step → log transition + rely on anchoring (no behavior
flap); backward step → same anchoring keeps enforcement correct, plus an
alarm log (and metric once TASK-044 lands). Hub-side: anchor on every
`onCSIPControl` arrival. Document all of it as an AD-004 extension.

## Detailed steps
1. Extend `utilitytime`:
   - `Clock.Anchor(serverUnix int64)` — store `anchorServer`,
     `anchorMono := cfg.Now()` (the time.Time keeps its monotonic reading;
     also store `anchorWall := cfg.Now().Unix()` for drift detection).
   - `Clock.ServerNow()`: if anchored, `anchorServer + int64(cfg.Now().Sub(anchorMono).Seconds())`
     (floor); else legacy wall+offset. NOTE for tests: a fake `Now` must
     return `time.Time`s built from a base via `.Add()` so monotonic deltas
     are simulated consistently.
   - `Clock.LocalStep()`: `drift := (wallNow − anchorWall) − monoElapsed`;
     `stepped = |drift| ≥ StepThresholdS` (new Config field, default 30).
   - Unit tests: anchored ServerNow under simulated forward/backward wall
     steps (wall lies, mono honest) — serverNow unaffected; LocalStep
     classification both directions; re-anchor clears drift.
2. **Hub:** in `onCSIPControl` (state.go:157), anchor a reader-owned Clock:
   `r.utclk.Anchor(msg.Ts + msg.ClockOffset)` — the northbound stamped `Ts`
   at publish on the SAME HOST (all six services share the hub Pi/SOM
   clock), so `Ts + ClockOffset` is server time at publish; MQTT localhost
   latency ≪ 1 s. In `ReadSystemState`, replace
   `utilitytime.ServerNowAt(now, r.clockOffset)` with `r.utclk.ServerNow()`
   for the expiry check; keep `state.ClockOffset = r.clockOffset` for the
   optimizer (see step 4). Each tick, call `LocalStep()`; on transition to
   stepped, log
   `[hub] local clock step detected (drift ≈ %+ds) — utility-time evaluation is monotonic-anchored; freshness unaffected`
   once (edge-triggered, like `noteStaleness`).
3. **Northbound:** anchor its Clock right after the /tm fetch in
   `runDiscovery` (`clk.Anchor(tm.CurrentTime)` conceptually — implement as
   anchor with the just-computed serverNow). Between walks the
   responseTracker then produces step-immune `CreatedDateTime`s.
4. **Optimizer/TOU:** `SystemState.ClockOffset` is an int64 offset; instead
   of changing the orchestrator (I/O-free), have `ReadSystemState` publish a
   *derived* offset: `state.ClockOffset = r.utclk.ServerNow() − now.Unix()`
   so `ServerNowAt(now, state.ClockOffset)` inside the optimizer equals the
   anchored value. One-line change; optimizer untouched.
5. **lexa-api:** same derived-offset trick in its snapshot assembly so the
   grace comparison is anchored.
6. Sweep for other wall-clock-sensitive comparisons:
   `grep -rn "\.Unix()" ~/projects/lexa-hub/cmd ~/projects/lexa-hub/internal --include=*.go | grep -v _test` —
   classify each hit in the PR description (enforcement / observability /
   stamp). `Ts` stamps stay wall (they are observability; document).
7. `go test -race ./internal/... ./cmd/...`; deploy; run gates
   (`clock-jitter`, `clock-jump-forward`, `wan-outage-expiry` 10×). The real
   local-step validation is TASK-038's scenario.

## Testing changes
- utilitytime: anchored-clock + LocalStep table tests (injected clock).
- `cmd/hub/state_test.go`: expiry evaluation with a simulated local step
  between control arrival and evaluation (fake reader clock) — control does
  NOT drop on a +1 h local step; does drop when server time genuinely passes
  ValidUntil.
- Run: `go test -race ./internal/... ./cmd/...`; bench gates as above.

## Documentation changes
- 02 AD-004: append the extension — (a) monotonic anchoring for utility
  time, (b) receiver-side arrival stamping is THE cross-process freshness
  mechanism (`Ts` fields are observability only), (c) local-step policy:
  forward = re-anchor silently + transition log; backward = anchored + alarm.
- lexa-hub CLAUDE.md: add one line under invariants: "Local wall-clock steps
  must not move utility-time evaluation (utilitytime anchoring) nor
  freshness windows (monotonic ages)."

## Common mistakes to avoid
- `time.Time` loses its monotonic reading after `Round(0)`, marshaling, or
  arithmetic through Unix seconds — keep the anchor as an unmodified
  `time.Now()` value.
- Do not anchor on `msg.Ts` from a *different host* — this works only
  because all lexa services share one clock (hub Pi / SOM). Say so in a
  comment; a split-host deployment must re-derive.
- Anchoring must not survive too long without refresh: if no control message
  arrives (northbound dead) the anchor ages but stays correct (monotonic);
  do NOT add an expiry on the anchor itself — the retained-control staleness
  problem is TASK-042's, not this one's.
- Do not "fix" `reassertEvery` or freshness windows — they are already
  monotonic; touching them risks the `solar-reboot-forget` /
  `export-cap-full-battery` watchdog behavior.
- A backward local step with anchoring means log wall-times regress while
  behavior stays steady — never key any logic off journald timestamps.

## Things that must NOT change
- Expiry discipline + debounce semantics under a stable clock
  (`wan-outage-expiry`, `clock-jump-forward` — TASK-036 ledger entries).
- SERVER-clock step behavior: a +2 h *server* step must still expire
  controls within the confirm window (`clock-jump-forward` PASS) — anchoring
  moves with fresh server time on the next walk/control message; verify the
  scenario stays PASS.
- Freshness windows (`measStaleAfter` 60 s, `evseStaleAfter` 90 s,
  `meterFrozenAfter` 30 s) — values and monotonic behavior untouched
  (`stale-meter`, `ev-meter-freeze` scenarios).
- `cmdDeduper.reassertEvery` 60 s watchdog (`export-cap-full-battery` ghost,
  QA ledger) — untouched.
- If TASK-032 has landed, the dedupe/watchdog references here are historical
  — the reconciler owns reassert; skip those specific checks.

## Acceptance criteria
- [ ] Unit test proves: +1 h and −1 h simulated local steps leave anchored
      `ServerNow()` within 1 s of truth and do not drop an active control.
- [ ] Unit test proves: genuine server-side expiry still drops after the
      confirm window.
- [ ] Edge-triggered local-step log appears exactly once per step (test via
      fake clock; verify format).
- [ ] `clock-jitter`, `clock-jump-forward`, `wan-outage-expiry`,
      `wan-outage-hold` 10× solo at baseline verdicts on the bench.
- [ ] Sweep table (step 6) included in the PR description.

## Regression checklist
- [ ] `go test -race ./internal/... ./cmd/...` (lexa-hub) green
- [ ] Conformance logic tests green (`go test ./tests/` in csip-tls-test) —
      Response CreatedDateTime path touched
- [ ] Mayhem: targeted clock/wan scenarios 10× + full FAST campaign
- [ ] `hub-replay-tune.sh fast` re-applied after deploy

## Mayhem scenarios affected
`clock-jitter`, `clock-jump-forward`, `wan-outage-hold`, `wan-outage-expiry`,
`hub-restart-mid-cap` (anchor re-established from retained control on
restart — verify re-adoption unaffected). New scenario arrives in TASK-038
(`local-clock-step-forward/-back`).

## Conformance implications
CSIP §5.2.1.3 (client clock within 30 s of server): anchoring *improves*
holdover accuracy between walks. Response timestamps become step-immune.
No resource format changes.

## Suggested commit message
`feat(utilitytime,hub,northbound): monotonic-anchored utility time + local clock-step policy (TASK-037)`

Trailer: `Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>`

## Suggested PR title & description
**Title:** Local clock-step policy: monotonic anchoring for utility time (TASK-037)
**Description:** Implements GAP-04 product half (AD-004 extension). Utility
time anchored to (server time, monotonic) pairs re-anchored per walk/control
message; local wall steps detected + alarmed; freshness already monotonic
(documented). Behavior identical under stable clocks (tests). Risk: med.
Rollback: revert commit; anchoring is internal, no schema/config change.

## Code review checklist
- Anchor pairs never pass through Unix-seconds round trips (monotonic
  preserved).
- Derived-offset trick keeps `internal/orchestrator` I/O-free.
- Same-host assumption for `Ts + ClockOffset` anchoring is commented.
- Server-step scenario (`clock-jump-forward`) verdict attached.

## Definition of done
Acceptance + regression checklists green; 02/CLAUDE.md updated; status
headers updated (this file + 00_MASTER_INDEX).

## Possible follow-up tasks
TASK-038 (Mayhem local-clock-step scenario — the HIL proof), TASK-044
(local-step alarm as a metric), TASK-079 (DST/timezone TOU tests).
