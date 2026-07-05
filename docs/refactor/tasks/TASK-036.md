# TASK-036 — Migrate hub `expiryConfirmTicks`, api `csipReportGraceS`, optimizer TOU onto `utilitytime`

*Status: DONE (2026-07-05, lexa-hub `fc00029`, branch `task/036-time-consumers`, unmerged — code+unit-tests only, bench validation batched at next gate) · Phase: P3 · Effort: L (≈6–8 h) · Difficulty: med · Risk: med*

## Objective
Move the last three utility-time owners onto `internal/utilitytime`:
lexa-hub's control-expiry debounce becomes a `utilitytime.DebouncedExpiry`
policy denominated in wall-clock seconds, lexa-api's reporting grace becomes
`utilitytime.ReportGrace`, and the optimizer's TOU `serverNow` computation
goes through a utilitytime helper — leaving **zero** grace/debounce/offset
constants outside the package (Phase 3 exit criterion).

## Background
Repo `~/projects/lexa-hub`. The three remaining owners after TASK-035:

1. **Hub expiry debounce** — `cmd/hub/state.go`:
   - `expiryConfirmTicks = 3` (line 33): consecutive `ReadSystemState` ticks a
     retained CSIP control must read past `ValidUntil` in server time before
     being dropped; counter `csipExpiredTicks` (line 71); logic lines 348–371:
     `now.Unix()+r.clockOffset >= r.lastCSIP.ValidUntil` increments, else
     resets; on the 3rd consecutive tick the control is dropped with a log.
   - The engine tick is `hub.json` `engine_interval_s` (default 15; bench
     FAST mode runs 3 — see `cmd/hub/config.go`). So today the debounce means
     **9 s wall-clock in FAST, 45 s in STOCK** — a tick-denominated threshold,
     exactly what 05_ENGINEERING_PRINCIPLES §5 says to denominate in seconds
     and scale at the edge (the optimizer already does this via
     `SetTickInterval`/`scaleTicks`, optimizer.go:186 region).
   - The hub learns `clockOffset` from `bus.ActiveControl.ClockOffset`
     (`onCSIPControl`, state.go:157–162).
2. **lexa-api grace** — `cmd/api/handlers.go`: `csipReportGraceS = 15`
   (line 92), applied at line 131 so `/status` stops reporting a control 15 s
   past `ValidUntil` (server time). Pinned by `cmd/api/stale_test.go`.
   Rationale comment (lines 122–130): covers the hub's expiry-confirm
   debounce plus clock-jitter margin — QA 2026-07-02 `wan-outage-expiry`
   INV-EXPIRED artifact.
3. **Optimizer TOU** — `internal/orchestrator/optimizer.go:326`:
   `serverNow := time.Unix(now.Unix()+state.ClockOffset, 0)` feeding
   `o.CostModel.IsPeakHour(serverNow)` (Rule 5, peak discharge).
   `internal/orchestrator` is I/O-free by design (05 §1) — it may import a
   pure helper but must not own a `Clock` with wall-time reads.

## Why this task exists
W4: four different grace/debounce constants for one concept. After TASK-035,
these three are the stragglers; Phase 3's exit criterion is "zero local
grace/debounce constants outside utilitytime".

## Architecture review sections
W4, R3, Top-20 item 7. Roadmap: 02 AD-004; 03 Phase 3 (exit criteria);
05 §5 (wall-clock denomination, scale at the edge); 07 GAP-04 adjacency.

## Prerequisites
TASK-035 DONE (utilitytime proven on the northbound plane). Bench FAST for
gates.

## Files
- **Read first:**
  - `~/projects/lexa-hub/cmd/hub/state.go` (lines 14–50, 155–170, 348–371) and `cmd/hub/state_test.go`
  - `~/projects/lexa-hub/cmd/hub/config.go` (EngineIntervalS)
  - `~/projects/lexa-hub/cmd/api/handlers.go` (lines 85–140) and `cmd/api/stale_test.go`
  - `~/projects/lexa-hub/internal/orchestrator/optimizer.go` (lines 320–335, 180–200 for `SetTickInterval`/`scaleTicks`)
  - `~/projects/lexa-hub/internal/utilitytime/` (whole package)
- **Modify:**
  - `~/projects/lexa-hub/cmd/hub/state.go` (+ `state_test.go`)
  - `~/projects/lexa-hub/cmd/api/handlers.go` (+ `stale_test.go` only if call sites move)
  - `~/projects/lexa-hub/internal/orchestrator/optimizer.go`
- **Create:** none.

## Blast radius
`cmd/hub` state reader (expiry semantics — control-plane!), `cmd/api`
reporting, `internal/orchestrator` TOU rule. No bus schema or config-file
format changes (one optional new hub.json key, below). `cmd/hub` is adjacent
to the radioactive zone; treat this PR as radioactive (05 §12).

## Implementation strategy
Three commits, one consumer each. The hub debounce is re-expressed as a
wall-clock window with tick scaling at the edge: define
`expiryConfirmWindowS = 9` (the QA-validated FAST behavior: 3 ticks × 3 s)
and compute `confirmTicks = max(2, ceil(window/tick))`. That preserves FAST
behavior exactly (9/3 = 3 ticks) and keeps a ≥2-tick debounce in STOCK
(2 ticks × 15 s = 30 s vs. today's 45 s — a *slightly faster* STOCK release,
still debounced; document this deliberate change, it is the 05 §5
"FAST and STOCK must mean the same seconds" correction). lexa-api and the
optimizer are mechanical substitutions.

## Detailed steps
1. **Commit 1 — hub.** In `cmd/hub/state.go`:
   - Replace `expiryConfirmTicks`/`csipExpiredTicks` with a
     `utilitytime.DebouncedExpiry` field on `MQTTSystemReader`, its `Confirm`
     computed at construction from the engine interval:
     `confirm = max(2, int(math.Ceil(9.0/interval.Seconds())))`. Thread the
     interval into `newMQTTSystemReader` (cmd/hub/main.go:59 constructs it;
     `cfg.EngineInterval()` is available there).
   - The 348–371 block becomes: `expired := utilitytime.Expired(v.ValidUntil, utilitytime.ServerNowAt(now, r.clockOffset))`
     then `if r.expiry.Observe(expired) { drop + log }` — keep the exact log
     line content (mrid, source, validUntil, server-now, tick count).
   - Reset semantics identical: a back-inside-window tick resets (DebouncedExpiry does this).
   - Update `state_test.go` expectations if they reference the constant.
2. **Commit 2 — api.** In `cmd/api/handlers.go`, replace the manual
   comparison at line 131 with
   `utilitytime.ReportGrace{GraceS: 15}.Reportable(c.ValidUntil, utilitytime.ServerNowAt(snap.now, snap.clockOffsetS))`
   (keep 15; keep the rationale comment). `stale_test.go` must still pass.
3. **Commit 3 — optimizer.** Replace optimizer.go:326 with
   `serverNow := time.Unix(utilitytime.ServerNowAt(now, state.ClockOffset), 0)`.
   No other optimizer change; `internal/orchestrator` gains only a pure
   import (verify no wall-clock read enters the package).
4. Sweep: `grep -rn "GraceS\|ConfirmTicks\|clockOffset\b" --include=*.go ~/projects/lexa-hub/cmd ~/projects/lexa-hub/internal | grep -v utilitytime`
   — audit every hit; remaining offset *plumbing* (bus field, state fields)
   is fine, remaining *policy arithmetic* is not.
5. Deploy to hub Pi, re-apply FAST tuning, run gates.

## Testing changes
- `cmd/hub/state_test.go`: add a table test for the debounce at FAST (3 s →
  3 ticks) and STOCK (15 s → 2 ticks) intervals, including the
  transient-excursion reset case from the state.go comment.
- `cmd/api/stale_test.go` unchanged semantics (15 s boundary).
- Add an orchestrator test asserting Rule 5 peak detection uses
  server time (existing TOU tests in `optimizer_rules_test.go` /
  `costmodel_test.go` — extend with a nonzero ClockOffset case if absent).
- Bench gates: `python3 scripts/mayhem.py --dashboard http://localhost:8080 --only wan-outage-expiry,clock-jump-forward,clock-jitter,expired-control`
  10× each; then full FAST campaign.

## Documentation changes
- 02 AD-004: record the STOCK debounce change (45 s → 30 s) as a deliberate
  wall-clock-denomination correction with this task's ID.
- lexa-hub CLAUDE.md: no invariant text change needed (serverNow formula
  unchanged; note utilitytime ownership if TASK-035 didn't already).

## Common mistakes to avoid
- Do **not** pick 45 s as the wall-clock window "to preserve STOCK": it would
  make FAST release take 15 ticks and break the `clock-jump-forward` oracle
  ("release lands ~t=25–35 … expiry confirm ticks bound the release
  latency" — see the scenario comment in
  `~/projects/csip-tls-test/cmd/dashboard/mayhem_world.go:321–326`).
- Do not drop the minimum-2-ticks floor: a 1-tick debounce at STOCK would
  reintroduce the transient-clock-excursion drop the constant exists to
  prevent.
- Keep enforcement-while-debouncing: during the confirm window the control is
  still enforced (state.go comment: "a cap is conservative, so holding it
  across a transient clock jump is the safe choice").
- `internal/orchestrator` must remain I/O-free — only `ServerNowAt` (pure)
  may be imported, never `utilitytime.Clock` with a default `time.Now`.
- Deploy gotcha: re-run `scripts/hub-replay-tune.sh fast` after
  `deploy-hub-pi.sh` before any Mayhem run.

## Things that must NOT change
Preservation ledger entries touched:
- Hub local-expiry discipline (drop retained control at ValidUntil without a
  walk) ↔ `wan-outage-expiry` (QA 2026-07-02: the northbound cannot clear it
  when the WAN is dark; state.go:348–360 comment).
- Expiry-confirm debounce (ride out transient clock excursions) ↔
  `clock-jitter`, `clock-jump-forward` (release within a few ticks of a real
  jump; never drop on a one-tick excursion).
- `/status` must never report a control meaningfully after enforcement
  stopped ↔ wan-outage-expiry INV-EXPIRED artifact (cmd/api comment, QA
  2026-07-02).
- Rule 5 TOU behavior at zero offset (all existing optimizer tests).
- FAST-mode wall-clock semantics of the debounce (9 s) — bit-identical.

## Acceptance criteria
- [x] `grep -rn "expiryConfirmTicks\|csipReportGraceS" ~/projects/lexa-hub --include=*.go`
      returns only comments/history (constants gone or delegated).
- [x] `go test -race ./internal/... && go test -race ./cmd/...` green
      (note: `make test` covers `./internal/...` only — run `./cmd/...` too;
      cmd packages have tests: state_test.go, stale_test.go, etc.).
- [x] FAST debounce = 3 ticks (test-proven); STOCK = 2 ticks (test-proven).
- [ ] Gate scenarios 10× at baseline; full FAST campaign ≤ 0.6 FAIL/cycle,
      0 BLIND. **Deferred to the next batched bench gate** (Principal's
      launch instructions for this task: code+unit-tests only, no bench
      access this session; the 05 §12 deadline amendment permits batching
      unit-gated merges and gating the campaign at the wave/reconciler-flip
      boundary instead).

## Regression checklist
- [x] `go test -race ./internal/...` (lexa-hub) green, plus `go test -race ./cmd/...`
- [x] Conformance logic tests: not needed (no protocol resource changes)
- [ ] Mayhem: targeted scenarios 10× + full campaign (radioactive-adjacent) —
      **batched at the next wave gate**, not run this session (see above).
- [ ] STOCK spot-check: one `bench-up.sh --stock` run of `wan-outage-expiry`
      + `clock-jump-forward` to observe the new 30 s release (record verdicts
      in the PR; STOCK differences are findings, not blockers, per 03 P0) —
      **pending**, batched with the campaign above.

## Mayhem scenarios affected
`wan-outage-expiry`, `clock-jump-forward`, `clock-jitter`, `expired-control`
(release timing paths); `hub-restart-mid-cap` (retained re-adoption then
expiry policy). FAST verdicts must hold; STOCK release latency improves
45 s → 30 s (expected, documented).

## Conformance implications
None to CSIP resources. Local expiry is a client-side discipline; the
Response state machine (northbound) is untouched.

## Suggested commit message
Three commits:
`refactor(hub): expiry debounce → utilitytime.DebouncedExpiry, wall-clock denominated (TASK-036 1/3)`
`refactor(api): csipReportGraceS → utilitytime.ReportGrace (TASK-036 2/3)`
`refactor(orchestrator): TOU serverNow via utilitytime.ServerNowAt (TASK-036 3/3)`

Trailer: `Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>`

## Suggested PR title & description
**Title:** hub/api/optimizer: last three utility-time consumers onto utilitytime (TASK-036)
**Description:** Completes AD-004 consumer migration (5/5). Hub debounce now
wall-clock denominated (FAST identical: 9 s/3 ticks; STOCK 45→30 s,
deliberate, documented). Testing: unit tables both cadences, 10× gate
scenarios, full FAST campaign, STOCK spot-check. Rollback: revert
per-commit; each consumer is independent.

## Code review checklist
- Confirm-tick arithmetic: `max(2, ceil(9/tick_s))` — verify 3 s→3, 15 s→2,
  1 s→9.
- Enforcement continues during the confirm window (no early drop).
- Optimizer gained no I/O or clock state.
- Log lines preserved (QA harness greps journals).

## Definition of done
Acceptance + regression checklists green; 02 AD-004 note added; status
headers updated (this file + 00_MASTER_INDEX).

## Possible follow-up tasks
TASK-037 (local clock-step policy), TASK-079 (DST/leap TOU tests — Rule 5 is
now the single site to test), backlog: fold `failClosed` policy itself into
utilitytime during P5 if the optimizer split wants it.
