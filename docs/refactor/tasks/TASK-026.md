# TASK-026 — Reconciler core library: pure logic + exhaustive table-driven tests

*Status: TODO · Phase: P2 · Effort: L (≈6–8 h) · Difficulty: high · Risk: low*

## Objective
A new pure-Go, I/O-free package `lexa-hub/internal/reconcile` implements the per-device
desired-state reconciliation state machine — desired vs last-written vs last-read;
write-on-diff; verify-by-readback with plausibility; reassert-on-reconnect; escalating
retry with backoff; wall-clock non-convergence reporting; seq/staleness rejection — with
an injected clock and an exhaustive table-driven test suite. Nothing wires it into any
service yet (TASK-027 does).

## Background
AD-002/AD-013 (see `docs/refactor/PRESERVATION_LEDGER.md` and
`lexa-hub/internal/bus/desired.go` from TASK-025): the hub will publish retained
`bus.DesiredState` documents on `lexa/desired/{class}/{device}`; a reconciler co-located
with the hardware driver (`lexa-modbus` for battery/solar, `lexa-ocpp` for EVSE) makes
the device converge and reports when it cannot.

The behaviors this core must subsume (ledger rows L1–L4, verified in code):
- **L1/L2 standing intent + watchdog:** today `applyRestoreRule`
  (`optimizer.go:2241`) re-commands every tick and `cmdDeduper` suppresses identical
  publishes but re-asserts every 60 s (`cmd/hub/actuators.go:24`). Core equivalent: the
  desired doc is durable intent; the reconciler re-writes when observed state diverges,
  and optionally re-asserts on a slow timer.
- **L3 revert detection:** a device that ACKs then reverts (reboot-to-defaults, installer
  override) must get a corrective write bounded by the readback interval — today handled
  by the breach-triggered dedupe reset (`cmd/hub/main.go:99–118`). Core equivalent:
  verify-by-readback compares `lastRead` to `desired` every observation.
- **L4 reassert-on-reconnect:** today `retryDevice.lastCtrl`/`reassertLocked`
  (`cmd/modbus/main.go:314–412`). Core equivalent: a `Reconnected` input event makes the
  next action an unconditional write of `desired`.
- **Non-convergence reporting** feeds the CannotComply collapse (TASK-031): after a
  wall-clock threshold of sustained divergence, emit a report (begin), and a resolution
  when convergence returns. Thresholds are **seconds, not ticks** (05 §5 — FAST and
  STOCK must mean the same seconds; the tick-scaling lesson is `scaleTicks`,
  `optimizer.go:197–213`).
- **Staleness/seq (AD-013, RSK-17):** reject a doc iff `seq <= lastAppliedSeq` AND
  `issuedAt <= lastAppliedIssuedAt` (count + report); a strictly newer `issuedAt` with a
  lower/reset `seq` is ACCEPTED with a `SeqReset` report + counter (publisher restarted).
  Reject stale docs (`issuedAt` older than the staleness bound) regardless of seq;
  absence of fresh docs = hold last-known-good and report staleness after the AD-013
  threshold — never auto-release.

Plausibility precedent for readback: `plausibleW` (`cmd/modbus/main.go:261–278`) — a
readback beyond physical plausibility must not be trusted as evidence of anything
(neither convergence nor divergence); it holds the previous assessment.

Design constraint from 05 §1/§4: `internal/orchestrator` earned real unit tests by being
I/O-free; this package inherits that discipline. One writer per state struct; no state in
closures; every exported type documented.

## Why this task exists
W2: the four convergence mechanisms interact emergently (the 2026-07-03 dedupe/breach bug
is the proof). A single, pure, exhaustively-tested state machine is the replacement; its
correctness must be established *before* it touches hardware (TASK-027+).

## Architecture review sections
W2, R1, D11, §8.2, §14 item 3; 02 AD-002/AD-013; 05 §1/§4/§5/§8; 08 RSK-01/RSK-17.

## Prerequisites
- TASK-025 DONE (`bus.DesiredState` + AD-013 + ledger).

## Files
- **Read first:** `internal/bus/desired.go`; `docs/refactor/PRESERVATION_LEDGER.md`;
  `cmd/modbus/main.go:300–447` (retryDevice — semantics being absorbed);
  `cmd/hub/actuators.go`; `internal/orchestrator/interfaces.go` (actuator interface
  style); AD-013 in `02_ARCHITECTURE_DECISIONS.md`.
- **Modify:** nothing outside the new package.
- **Create:** `lexa-hub/internal/reconcile/{reconcile.go,report.go,reconcile_test.go}`
  (split further only past the 600-line soft cap, 05 §1).

## Blast radius
None at runtime (unused package). API: new `internal/reconcile` exported surface that
TASK-027/029/030 will build against — design it for consumption, not speculation (05 §2).

## Implementation strategy
Functional core / imperative shell: the core is a `Reconciler` struct whose single method
consumes an input event and the injected time and returns actions + reports — it performs
no I/O and starts no goroutines. Drivers (Modbus write, OCPP SetChargingProfile) are the
shell's job in later tasks; here they exist only as returned action values, which is what
makes exhaustive table-driven testing possible.

## Detailed steps
1. Define the types (names indicative; keep the shapes):
   - `type Observed struct { Read map[Field]float64; Connected bool; At time.Time; Plausible bool }`
     — one normalized readback sample; `Field` covers `SetpointW|CeilingW|Connect|MaxCurrentA`.
   - `type Config struct { ReadbackTolerance map[Field]float64; ConvergeTimeout time.Duration;
     RetryBackoff []time.Duration; StaleAfter time.Duration; ReassertEvery time.Duration }`
     — all durations wall-clock; zero values get documented defaults in ONE place (05 §6).
   - `type Action struct { Kind ActionKind; Fields ... }` with kinds `Write`, `None`.
   - `type Report struct { Kind ReportKind; ... }` with kinds `NonConvergedBegin`,
     `NonConvergedEnd`, `StaleDesired`, `RejectedDoc` (carrying reason:
     seq-and-issuedAt-regression), `SeqReset` (accepted doc whose seq reset — publisher
     restart), each carrying `deviceID`, `mrid`, `seq`, and a monotonic
     episode counter (TASK-031 consumes these).
   - `type Reconciler struct` holding `desired *bus.DesiredState`, `lastWritten`,
     `lastRead Observed`, retry/backoff state, episode state. Single writer assumed;
     document it (like `cmdDeduper`'s concurrency note).
2. Implement the event API:
   `SetDesired(doc bus.DesiredState, now time.Time) (Action, []Report)` (applies AD-013
   seq/issuedAt rejection first), `Observe(o Observed, now time.Time) (Action, []Report)`,
   `Reconnected(now time.Time) (Action, []Report)`, `Tick(now time.Time) (Action, []Report)`
   (drives retry backoff, staleness, non-convergence timer).
3. Semantics (each bullet = test cases):
   - Write-on-diff: `Observe` with `lastRead` differing from `desired` beyond
     `ReadbackTolerance` → `Write` action; within tolerance → `None` + convergence.
   - Verify-by-readback: after a `Write`, convergence is judged ONLY from a later
     plausible `Observe` (never from write success — "trust measurement, not the
     command", lexa-hub/CLAUDE.md).
   - Implausible readback (`Plausible=false`): ignored for convergence judgment; does not
     trigger a write storm (holds previous assessment) — the `plausibleW` discipline.
   - Reassert-on-reconnect: `Reconnected` → unconditional `Write` of `desired` (L4), even
     if the last readback before the drop matched.
   - Escalating retry: repeated non-convergence re-writes follow `RetryBackoff`
     (e.g. 2 s, 5 s, 15 s, then every 30 s — defaults documented; caller supplies real
     values from config), never a tight loop.
   - Non-convergence report: `NonConvergedBegin` once when divergence has persisted
     `ConvergeTimeout` seconds (wall-clock, measured from first divergence observation),
     `NonConvergedEnd` once on re-convergence — edge semantics, mirroring
     `breachAlert`'s once-per-episode contract (L5).
   - Staleness: no fresh doc for `StaleAfter` → `StaleDesired` report; desired is HELD
     (fail-closed), not cleared.
   - Rejection: `seq <= lastAppliedSeq` AND `issuedAt <= lastAppliedIssuedAt` →
     `RejectedDoc`, state unchanged. A strictly newer issuedAt with a lower/reset seq is
     ACCEPTED and applied, emitting a `SeqReset` report + counter (publisher restarted —
     AD-013). Stale docs (issuedAt older than the staleness bound) rejected regardless
     of seq.
   - NaN defense: any NaN in a doc field or observation → reject that input with a
     report; never store NaN (bus convention says it can't arrive, defend anyway).
4. Table-driven tests (`reconcile_test.go`): scripted event sequences with a fake clock
   (plain `time.Time` arithmetic — no sleeping). Cover every bullet above, plus:
   convergence within tolerance boundary (exactly at tolerance), backoff schedule
   exhaustion, reconnect mid-episode, doc update mid-episode (new seq resets the
   convergence window and re-writes), stale-then-fresh recovery, episode counter
   monotonicity, publisher restart (seq resets to 0, issuedAt newer → accepted,
   `SeqReset` counter increments). Mutation-check the safety-relevant guards (05 §8): temporarily unwire
   the seq check and confirm a test fails (do this as a review exercise, not committed).
5. `go vet` + `make test` green; file sizes ≤600 lines each.

## Testing changes
The new suite IS the deliverable's proof: aim for exhaustive transition coverage (every
`(state, event)` pair reachable in the tables). Run:
`cd ~/projects/lexa-hub && go test -race ./internal/reconcile/ && make test`.

## Documentation changes
- Package doc comment: state machine diagram in words, the ledger rows it subsumes
  (L1–L4), and the "no I/O ever" rule.
- `docs/refactor/PRESERVATION_LEDGER.md`: no status changes yet (nothing replaced).

## Common mistakes to avoid
- Tick-denominated thresholds. Everything is `time.Duration`/wall-clock; the *caller*
  chooses observation cadence (poll interval differs between modbus and ocpp).
- Letting the reconciler call a driver interface directly — actions out, that's it. The
  moment it does I/O, the exhaustive tests become integration tests.
- Judging convergence from write-ACK (the `ack-before-effect` / `reject-write-curtail`
  scenario family exists because devices lie).
- Baking battery/solar/EVSE specifics into the core — field-generic; class specifics live
  in the shells (TASK-027/029/030 map fields to registers/profiles).
- Designing a speculative plugin system. Two consumers are known (modbus, ocpp); build
  for exactly those seams (05 §2).

## Things that must NOT change
- No existing file modified: `git status` shows only `internal/reconcile/*` added.
- Preservation ledger rows: none flip status here — this task *builds* the replacement,
  it replaces nothing yet.
- The bus schema (AD-013) — if the core's needs reveal a schema gap, amend AD-013 via a
  documented decision update, not an ad-hoc field.

## Acceptance criteria
- [ ] `go test -race ./internal/reconcile/` green; coverage of the package ≥90%
      statements (`go test -cover`).
- [ ] Every Background bullet has at least one named test case (reviewer maps them 1:1).
- [ ] Zero I/O imports in the package (no mqtt, no net, no os; `time` used only for
      types/arithmetic — verify no `time.Now`/`time.Sleep`/`time.After` calls).
- [ ] Reports carry device/mrid/seq/episode fields TASK-031 needs (cross-read its spec).

## Regression checklist
- [ ] `go test -race ./internal/...` (lexa-hub) green
- [ ] `make test-fast` (csip-tls-test) green (untouched)
- [ ] Conformance logic tests: skip (not protocol-adjacent)
- [ ] Mayhem: none (no runtime change)

## Mayhem scenarios affected
None yet. The suite's scripted sequences deliberately mirror scenario shapes:
battery-reboot (reconnect), solar-reboot-forget (revert), control-churn (doc churn),
release-while-rebooting (doc update while disconnected → reassert on reconnect).

## Conformance implications
None directly; non-convergence reports become CannotComply input in TASK-031.

## Suggested commit message
`feat(reconcile): pure desired-state reconciler core with table-driven suite (TASK-026)`
`Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>`

## Suggested PR title & description
**Title:** Phase 2: reconciler core (pure logic, no wiring)
**Description:** I/O-free state machine per AD-002/AD-013; subsumes ledger rows L1–L4
semantics; exhaustive table-driven tests incl. staleness/seq/NaN/reconnect. Zero runtime
change. Rollback: revert (unused package).

## Code review checklist
- (state,event) table coverage vs implementation switch arms — no untested transitions.
- Wall-clock-only thresholds; no tick counts anywhere.
- Report edge semantics: exactly-once begin/end per episode under event replay.
- API is consumable by both planned shells without type-switching hacks.

## Definition of done
Acceptance criteria + regression checklist; package docs written; status headers (this
file + 00_MASTER_INDEX) updated.

## Possible follow-up tasks
TASK-027 (battery shadow wiring), TASK-029/030 (solar/EVSE shells), TASK-031 (report
consumer), TASK-041 (episode state snapshot).
