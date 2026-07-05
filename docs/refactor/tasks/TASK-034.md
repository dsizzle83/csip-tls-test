# TASK-034 — `utilitytime` package core (offset, smoothing, step classification, windows)

*Status: DONE (2026-07-05, lexa-hub 400b152) · Phase: P3 · Effort: L (≈6–8 h) · Difficulty: med · Risk: low*

## Objective
Create a new pure-Go package `lexa-hub/internal/utilitytime` that is the single
owner of utility (server) time: clock-offset acquisition, offset smoothing and
step classification, `ServerNow()`, event-window evaluation, and composable
expiry policies — with an injected local clock and an exhaustive table-driven
test suite. This task builds the library only; no existing consumer changes
(migrations are TASK-035/036/037).

## Background
The product (repo `~/projects/lexa-hub`, module path `lexa-hub`) talks IEEE
2030.5/CSIP to a utility server whose clock is authoritative. Today utility
time has **five independent owners**:

1. **Walker /tm resync** — `internal/northbound/discovery/walker.go:162`:
   `tree.ClockOffset = tm.CurrentTime - time.Now().Unix()` (offset = server −
   local, seconds), recomputed on every discovery walk. `ClockOffset` field is
   declared at walker.go:66-69.
2. **Scheduler** — `internal/northbound/scheduler/scheduler.go`:
   `ServerNow(clockOffset int64)` (line 112) returns
   `time.Now().Unix() + clockOffset`; `Evaluate(programs, serverNow)` (line
   142) resolves the active control; `failClosed()` (lines 191–274) holds two
   clock-regression guards; `controlExpired()` (line 278) implements
   `ValidUntil != 0 && serverNow >= ValidUntil`.
3. **Hub expiry debounce** — `cmd/hub/state.go`: const `expiryConfirmTicks = 3`
   (line 33) and the debounce block in `ReadSystemState()` (lines 348–371):
   the retained control is dropped only after 3 consecutive ticks past
   `ValidUntil` in server time (`now.Unix()+r.clockOffset`).
4. **lexa-api report grace** — `cmd/api/handlers.go`: const
   `csipReportGraceS = 15` (line 92), used at line 131 so `/status` stops
   reporting a control 15 s after `ValidUntil` in server time.
5. **Optimizer TOU** — `internal/orchestrator/optimizer.go:326`:
   `serverNow := time.Unix(now.Unix()+state.ClockOffset, 0)` feeding
   `CostModel.IsPeakHour(serverNow)`.

Four different grace/debounce constants exist for one concept, and the
clock-jitter QA saga (four fixes across three services) proved the cost.
This package becomes the one owner (AD-004). The bus carries the offset to
other services as `bus.ActiveControl.ClockOffset` (`internal/bus/messages.go`,
`clock_offset` JSON field).

**CRITICAL invariant (lexa-hub CLAUDE.md / scheduler doc comment):**
`serverNow = time.Now().Unix() + tree.ClockOffset`. `ServerNow()` in this
package MUST reproduce exactly that arithmetic on the last *accepted raw*
offset. Smoothing/step classification is **advisory output for policies and
logging** — it must never silently alter the value `ServerNow()` returns,
or TASK-035's verbatim guard ports become impossible to verify.

## Why this task exists
Review W4: "Utility time has five owners" — five local patches, four grace
constants, and a history of clock-regression bugs fixed one consumer at a
time. R3/AD-004 demand a single owned abstraction with one test suite.

## Architecture review sections
W4, R3, §8.4 (local clock steps — policy itself is TASK-037), Top-20 item 7.
Roadmap: 02 AD-004; 03 Phase 3; 07 GAP-04 (downstream).

## Prerequisites
None (04_DEPENDENCY_GRAPH row 034 has no dependencies). P0 CI (TASK-002) is
desirable but not blocking. Work in `~/projects/lexa-hub` on a branch.

## Files
- **Read first:**
  - `~/projects/lexa-hub/internal/northbound/scheduler/scheduler.go` (whole file)
  - `~/projects/lexa-hub/internal/northbound/scheduler/failclosed_test.go`
  - `~/projects/lexa-hub/internal/northbound/discovery/walker.go` (lines 60–170)
  - `~/projects/lexa-hub/cmd/hub/state.go` (lines 14–50, 348–371)
  - `~/projects/lexa-hub/cmd/api/handlers.go` (lines 85–135)
  - `~/projects/lexa-hub/internal/orchestrator/optimizer.go` (lines 320–335)
  - `~/projects/lexa-hub/CLAUDE.md` (invariants) and this repo's `docs/refactor/02_ARCHITECTURE_DECISIONS.md` AD-004
- **Modify:** none (library-only task).
- **Create:**
  - `~/projects/lexa-hub/internal/utilitytime/utilitytime.go`
  - `~/projects/lexa-hub/internal/utilitytime/expiry.go`
  - `~/projects/lexa-hub/internal/utilitytime/utilitytime_test.go`
  - `~/projects/lexa-hub/internal/utilitytime/expiry_test.go`

## Blast radius
None at runtime: a new leaf package with no consumers. Public API surface of
`internal/utilitytime` becomes load-bearing for TASK-035/036/037 — design it
here, change it later only with those tasks' agreement. No config, no bus
schema, no service behavior changes.

## Implementation strategy
Pure library, injected clock, no I/O, no goroutines. Model: a `Clock` struct
fed raw offsets by whoever owns acquisition (the walker, in TASK-035);
`ServerNow()` = injected `now().Unix()` + last accepted offset. Offset updates
return a classification (`Wobble`/`Step`) computed from configurable
thresholds so consumers/policies can react, without the classification
changing `ServerNow()` semantics. Expiry policies (`DebouncedExpiry`,
`ReportGrace`) are small composable state machines that TASK-036 will
substitute for `expiryConfirmTicks` and `csipReportGraceS`.

## Detailed steps
1. Create `internal/utilitytime/utilitytime.go`:
   ```go
   package utilitytime

   type StepClass int
   const (
       First  StepClass = iota // first offset ever observed
       Wobble                  // |Δ| <= WobbleMaxS — jitter/drift
       Step                    // |Δ| >  WobbleMaxS — a real clock step
   )

   type Config struct {
       WobbleMaxS int64            // default 60 (covers the ±60 s NTP-flap class from the clock-jitter finding)
       Now        func() time.Time // injected; defaults to time.Now
   }

   type Clock struct { /* mu, cfg, offset int64, haveOffset bool, lastUpdate time.Time */ }

   func New(cfg Config) *Clock
   func (c *Clock) SetOffset(offset int64) StepClass // classify vs previous, then accept raw
   func (c *Clock) Offset() (int64, bool)            // last accepted offset, whether one exists
   func (c *Clock) ServerNow() int64                 // cfg.Now().Unix() + offset (0 if none yet)
   ```
   Also add stateless helpers (used by scheduler in TASK-035 without needing a
   `Clock`): `func ServerNowAt(now time.Time, offset int64) int64`,
   `func Expired(validUntil, serverNow int64) bool` (semantics identical to
   `scheduler.controlExpired`: `validUntil != 0 && serverNow >= validUntil`),
   and `func InWindow(start, end, serverNow int64) bool` (`start <= serverNow < end`,
   matching `scheduler.activeEvent`'s interval check at scheduler.go:341).
2. Create `internal/utilitytime/expiry.go` with two policies:
   ```go
   // DebouncedExpiry: expiry must persist N consecutive observations before
   // it reports true (generalizes cmd/hub expiryConfirmTicks=3).
   type DebouncedExpiry struct { Confirm int /* private counter */ }
   func (d *DebouncedExpiry) Observe(expired bool) bool // true only after Confirm consecutive trues; resets on false
   func (d *DebouncedExpiry) Reset()

   // ReportGrace: pure predicate for reporting surfaces (generalizes
   // csipReportGraceS=15): still-reportable until ValidUntil+GraceS.
   type ReportGrace struct{ GraceS int64 }
   func (g ReportGrace) Reportable(validUntil, serverNow int64) bool
   ```
   Document in comments which existing constant each generalizes and where it
   lives today (state.go:33, handlers.go:92).
3. Write table-driven tests with an injected fake clock:
   - `ServerNow` arithmetic incl. negative offsets and offset 0.
   - `SetOffset` classification: first, wobble at ±WobbleMaxS boundary, step
     just past it, repeated steps, step back.
   - `Expired`: ValidUntil 0 never expires; boundary `serverNow == ValidUntil`
     expires (matches `>=` in scheduler.go:279 and state.go:361).
   - `InWindow` boundary semantics (`start` inclusive, `end` exclusive).
   - `DebouncedExpiry`: 2-of-3 flapping never fires with Confirm=3; 3
     consecutive fires; Reset() restarts; equivalence test mirroring the
     state.go:348–371 comment scenario (transient forward jump past
     ValidUntil rides out, sustained expiry drops on tick 3).
   - `ReportGrace`: 15 s grace boundary (mirrors `cmd/api/stale_test.go`).
4. `go vet ./internal/utilitytime/ && go test -race ./internal/utilitytime/`.
5. Add a package doc comment stating the ownership rule from
   05_ENGINEERING_PRINCIPLES §5: after P3, new grace constants/debounces
   outside this package are review-blocking.

## Testing changes
New: `internal/utilitytime/utilitytime_test.go`, `expiry_test.go`.
Run: `cd ~/projects/lexa-hub && go test -race ./internal/utilitytime/` and the
full `make test` (`go test -race ./internal/...`).

## Documentation changes
- Append a short "implemented" note to AD-004 in
  `~/projects/csip-tls-test/docs/refactor/02_ARCHITECTURE_DECISIONS.md`
  naming the package and the two policy types.
- Do NOT touch CLAUDE.md invariants yet — the `serverNow` invariant text
  changes only when consumers migrate (TASK-035/036).

## Common mistakes to avoid
- Do not make `ServerNow()` return a smoothed/filtered value. Classification
  informs; the raw last-accepted offset rules. TASK-035 will diff behavior
  against `scheduler.ServerNow()` — they must be bit-identical.
- Do not import this package from any `cmd/` or existing `internal/` package
  in this task — zero consumers keeps the diff reviewable and revertible.
- Do not add goroutines, tickers, or wall-clock reads outside the injected
  `Now` func — the whole point is deterministic tests.
- Boundary semantics: `>=` for expiry, `[start,end)` for windows. Off-by-one
  here would silently shift every event edge when consumers migrate.

## Things that must NOT change
Nothing changes at runtime in this task. Protected behavior that this
package's API must be *able* to reproduce verbatim (verified by TASK-035/036
gates, designed for here): the scheduler clock-regression guards (both
halves, scheduler.go:191–274, QA scenarios `clock-jitter` 2026-07-02/03), the
default-fallback hold (scheduler.go:210–216, QA v6 C3/C4), `expiryConfirmTicks`
debounce (`wan-outage-expiry`, `clock-jump-forward` scenarios), and
`csipReportGraceS` reporting grace (wan-outage-expiry INV-EXPIRED artifact,
QA 2026-07-02).

## Acceptance criteria
- [ ] `go test -race ./internal/utilitytime/` passes; coverage of the new
      package ≥ 90% statements (`go test -cover`).
- [ ] `go build ./...` in lexa-hub succeeds; `grep -rn "utilitytime" cmd/ internal/ --include=*.go | grep -v internal/utilitytime` returns nothing (no consumers).
- [ ] API includes: `Clock`, `New`, `SetOffset` (returning `StepClass`),
      `Offset`, `ServerNow`, `ServerNowAt`, `Expired`, `InWindow`,
      `DebouncedExpiry`, `ReportGrace` — all documented.
- [ ] A test demonstrates `ServerNowAt(now, off) == now.Unix()+off` for a
      table of offsets including the CLAUDE.md formula.

## Regression checklist
- [ ] `go test -race ./internal/...` (lexa-hub) green
- [ ] Conformance logic tests: not protocol-adjacent — none
- [ ] Mayhem: none (no runtime change)
- [ ] No consumer imports the new package yet

## Mayhem scenarios affected
None in this task. `clock-jitter`, `clock-jump-forward`, `wan-outage-hold`,
`wan-outage-expiry` become the gates for TASK-035/036.

## Conformance implications
None yet. The event-window and expiry helpers encode IEEE 2030.5 §12.3 edge
semantics (start inclusive, end exclusive, ValidUntil `>=`) — identical to
today's scheduler; conformance behavior is unchanged until migration.

## Suggested commit message
`feat(utilitytime): single-owner utility time package — offset, step classification, windows, expiry policies (TASK-034)`

Trailer: `Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>`

## Suggested PR title & description
**Title:** utilitytime: core package for single-owner utility time (TASK-034)
**Description:** New pure library implementing AD-004: raw-offset ServerNow,
wobble/step classification, window/expiry helpers, DebouncedExpiry +
ReportGrace policies. Zero consumers; behavior-neutral. Testing: new
table-driven suite, `-race`, ≥90% coverage. Rollback: revert the commit —
nothing imports it.

## Code review checklist
- ServerNow uses the raw accepted offset (no smoothing leakage).
- Expiry/window boundary operators match scheduler.go:279/341 exactly.
- No `time.Now()` outside the injected default; no I/O; no exported mutable
  globals.
- Policy structs document which legacy constant they generalize.

## Definition of done
Acceptance criteria + regression checklist green; AD-004 note added; this
file's Status header and `00_MASTER_INDEX.md` P3 row updated.

## Possible follow-up tasks
TASK-035 (walker+scheduler migration), TASK-036 (hub/api/optimizer),
TASK-037 (local clock-step policy), TASK-079 (DST/leap tests).
