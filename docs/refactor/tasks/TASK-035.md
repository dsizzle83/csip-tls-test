# TASK-035 — Migrate walker + scheduler onto `utilitytime` (guards ported verbatim)

*Status: TODO · Phase: P3 · Effort: L (≈6–8 h) · Difficulty: high · Risk: high*

## Objective
Make the northbound discovery walker and the scheduler consume
`internal/utilitytime` (TASK-034) for offset acquisition, `serverNow`, and
expiry/window primitives — with the two clock-regression guards and the
2026-07-03 default-fallback guard preserved **verbatim** (same semantics, same
tests, same log lines), proven by the existing `failclosed_test.go` suite and
the clock-family Mayhem scenarios.

## Background
Repo `~/projects/lexa-hub`. Today:

- **Walker** (`internal/northbound/discovery/walker.go`): on each walk,
  step 2 fetches `/tm` and sets
  `tree.ClockOffset = tm.CurrentTime - time.Now().Unix()` (line 162).
  `ClockOffset` (line 69) rides the `ResourceTree` to every consumer.
- **Northbound main** (`cmd/northbound/main.go`): `runDiscovery()` (line 240)
  computes `serverNow := scheduler.ServerNow(tree.ClockOffset)` (line 270)
  and calls `sched.Evaluate(tree.Programs, serverNow)`. On a walk **error** it
  publishes NOTHING (fail-closed hold, lines 252–267 — QA 2026-07-02
  `northbound-hang` FAIL / `wan-outage-hold` DEGRADED fix). The
  `responseTracker` (lines 666–830) also calls `scheduler.ServerNow` (lines
  735, 809 region) for Response timestamps and completion checks.
- **Scheduler** (`internal/northbound/scheduler/scheduler.go`): pure —
  `Evaluate(programs, serverNow int64)`. Inside `failClosed()` live three
  load-bearing guards:
  1. **Default-fallback half** (lines 210–216): when a resolved control has
     `Source=="default"` but `lastGood` is an unexpired, still-served event,
     hold the event (QA 2026-07-03 v6 `clock-jitter` C3/C4: 0 W ↔ 5 kW flap
     every walk, drained breach counter, no CannotComply).
  2. **Explicit-clear half** (lines 245–263): `programFound && resolved==nil`
     releases — UNLESS lastGood is unexpired and `stillServed` (QA 2026-07-02
     `clock-jitter`: ±60 s NTP correction aliased with the 5 s walk).
  3. Malformed/absent-programs holds (lines 225–233, 265–273).
  Helpers: `controlExpired` (line 278), `stillServed` (line 287),
  `plausibleControl` (line 306), `activeEvent` window check (line 341).
- **Tests**: `internal/northbound/scheduler/failclosed_test.go` has 15 test
  functions. The clock-guard family:
  `TestEvaluate_HoldsThroughClockRegression` (197),
  `TestEvaluate_ClockRegressionStillReleasesWithdrawnEvent` (223),
  `TestEvaluate_ClockRegressionStillReleasesCancelledEvent` (235),
  `TestEvaluate_ClockRegressionDoesNotResurrectEndedEvent` (251),
  `TestEvaluate_ClockRegressionHoldsEventOverDefault` (272), plus the three
  release-path twins `TestEvaluate_{Ended,Withdrawn,Cancelled}EventFallsBackToDefault`
  (301/317/330). These pin the guards; they must pass **unmodified** except
  for mechanical call-site changes if a helper moves.

`utilitytime` (TASK-034) provides `Clock` (SetOffset/ServerNow with step
classification), and stateless `ServerNowAt`, `Expired`, `InWindow`.

## Why this task exists
W4/R3: the walker and scheduler are two of the five time owners. This is the
highest-risk migration of the batch because the scheduler's clock-regression
behavior is the most QA-scarred code in the northbound plane (four fixes,
three services, three days — see scheduler.go comments).

## Architecture review sections
W4, R3, §3 strength 3 (fail-closed discipline — must survive), Top-20 item 7.
Roadmap: 02 AD-004 ("Non-negotiable ports: clock-regression guard both
halves; default-fallback guard; serverNow = local + offset"); 03 Phase 3
risks; 05 §12 (scheduler = radioactive zone: one change per PR, full
campaign, never merged same-day).

## Prerequisites
TASK-034 DONE. Bench available in FAST mode for the campaign gate
(`bash ~/projects/csip-tls-test/scripts/bench-up.sh --fast`).

## Files
- **Read first:**
  - `~/projects/lexa-hub/internal/northbound/scheduler/scheduler.go` (all)
  - `~/projects/lexa-hub/internal/northbound/scheduler/failclosed_test.go` (all)
  - `~/projects/lexa-hub/internal/northbound/discovery/walker.go` (lines 60–170)
  - `~/projects/lexa-hub/cmd/northbound/main.go` (lines 240–330, 660–830)
  - `~/projects/lexa-hub/internal/utilitytime/` (TASK-034 output)
- **Modify:**
  - `~/projects/lexa-hub/internal/northbound/discovery/walker.go`
  - `~/projects/lexa-hub/internal/northbound/scheduler/scheduler.go`
  - `~/projects/lexa-hub/cmd/northbound/main.go`
- **Create:** `~/projects/lexa-hub/internal/northbound/scheduler/utilitytime_equiv_test.go`

## Blast radius
`internal/northbound/discovery`, `internal/northbound/scheduler`,
`cmd/northbound`. Bus messages unchanged (`ActiveControl.ClockOffset` still
published). No config changes. Consumers of `ResourceTree.ClockOffset`
elsewhere (schedule builder `schedule.Build`, pricing/billing publishers in
cmd/northbound/main.go) keep working because the field remains.

## Implementation strategy
One consumer per commit (03 Phase 3 rule: "migrate one consumer per task,
never two" — within this task, one per COMMIT, walker first, scheduler
second, responseTracker third). The scheduler stays a pure function of
`(programs, serverNow)`; what migrates is (a) who computes `serverNow`
(a `utilitytime.Clock` owned by `cmd/northbound`, fed by the walker's /tm
result) and (b) the expiry/window primitives, which delegate to
`utilitytime.Expired`/`InWindow`. Guards port verbatim: the `failClosed`
logic itself does not move in this task — moving its policy into utilitytime
is explicitly out of scope (it can follow in P5 if ever needed).

## Detailed steps
1. **Commit 1 — walker feeds a Clock.** Add a
   `utilitytime.Clock` to `cmd/northbound` (constructed in `main`, passed to
   `runDiscovery`). In `runDiscovery`, after a successful walk, call
   `clk.SetOffset(tree.ClockOffset)` and log the returned `StepClass` when it
   is `Step` (transition log only, 05 §9). Walker keeps computing
   `tree.ClockOffset` exactly as today (line 162) — acquisition site
   unchanged, ownership of the *accumulated* offset moves to the Clock.
   Build + unit tests.
2. **Commit 2 — serverNow from the Clock.** Replace
   `scheduler.ServerNow(tree.ClockOffset)` in `runDiscovery` (line ~270) with
   `clk.ServerNow()`. Add a temporary assertion (debug log if they differ) for
   one bench soak, then remove — they must be identical by construction
   (raw offset, same formula). Keep `scheduler.ServerNow` exported but mark
   deprecated in its doc comment pointing at utilitytime (TASK-036 still uses
   the formula hub-side until it migrates).
3. **Commit 3 — scheduler primitives delegate.** Inside scheduler.go, change
   `controlExpired` to call `utilitytime.Expired(ac.ValidUntil, serverNow)`
   and the `activeEvent`/`SupersededMRIDs` interval checks (lines 341, 449)
   to `utilitytime.InWindow(start, end, serverNow)`. **Do not** restructure
   `failClosed`, `stillServed`, `plausibleControl`, or any guard ordering.
   The 15 `failclosed_test.go` tests must pass without semantic edits.
4. **Commit 4 — responseTracker.** In cmd/northbound/main.go, pass the Clock
   (or its `ServerNow`) into `responseTracker` instead of storing
   `clockOffset` + calling `scheduler.ServerNow` (lines 735 and
   `postResponse`). Response `CreatedDateTime` values must be unchanged.
5. Write `utilitytime_equiv_test.go`: a differential test that runs
   `Evaluate` across the clock-regression test fixtures at a sweep of
   serverNow values computed both ways (legacy formula vs utilitytime) and
   asserts identical `*ActiveControl` results.
6. `go test -race ./internal/...` then deploy to the hub Pi
   (`make build-arm64 && bash scripts/deploy-hub-pi.sh 69.0.0.1 dmitri` from
   lexa-hub) and run the gate scenarios, then the full campaign (see below).

## Testing changes
- All existing scheduler tests must pass unmodified (assert by
  `git diff --stat` showing no changes to `failclosed_test.go` /
  `scheduler_test.go` beyond none).
- New `utilitytime_equiv_test.go` differential test.
- Bench gates (bench FAST, from csip-tls-test):
  `python3 scripts/mayhem.py --dashboard http://localhost:8080 --only clock-jitter,clock-jump-forward,wan-outage-hold,wan-outage-expiry`
  — each 10× solo (loop the command; verdicts must be stable at their V6
  baseline: clock-jitter PASS, clock-jump-forward PASS, wan-outage-* per V6
  notes). Then one full campaign:
  `python3 scripts/mayhem.py --dashboard http://localhost:8080`.

## Documentation changes
- Update `~/projects/lexa-hub/CLAUDE.md` invariant wording: serverNow formula
  now owned by `internal/utilitytime` (formula itself unchanged).
- Note in 02 AD-004: walker/scheduler/responseTracker migrated (date, commit).

## Common mistakes to avoid
- **Deploy gotcha:** `deploy-hub-pi.sh` resets hub timing to STOCK — run
  `bash ~/projects/csip-tls-test/scripts/hub-replay-tune.sh fast` after every
  deploy before running Mayhem, or every clock scenario will flake.
- Do not "improve" guard logic while touching it (e.g. merging the two
  regression-guard halves) — verbatim means verbatim; improvements go through
  a separate task with its own campaign.
- Do not compute serverNow once per walk and cache it across the walk's
  publish + responseTracker calls differently than today — `runDiscovery`
  computes it once (line 270) and reuses it; keep that exact sharing.
- `scheduler.Scheduler` must stay reusable across polls (randomization cache,
  scheduler.go:74–79) — do not reconstruct it when threading the Clock.
- Never batch this with any other change; radioactive zone (05 §12).

## Things that must NOT change
Preservation ledger entries touched (guard → originating QA scenario):
- Clock-regression guard, explicit-clear half (scheduler.go:245–263) ↔
  `clock-jitter` (QA 2026-07-02).
- Clock-regression guard, default-fallback half (scheduler.go:210–216) ↔
  `clock-jitter` V6 C3/C4 (QA 2026-07-03), pinned by
  `TestEvaluate_ClockRegressionHoldsEventOverDefault` + the three
  `*FallsBackToDefault` release tests.
- Fail-closed publish-nothing on walk error (cmd/northbound/main.go:252–267)
  ↔ `wan-outage-hold`, `northbound-hang` (QA 2026-07-02).
- Last-known-good hold + explicit-clear release (`failClosed`) ↔
  `malform-empty-program`, `malform-huge-activepower`, `curtailment-release`
  (comments in scheduler.go:127–141).
- Response state machine transitions (responseTracker, CORE-022/023) — same
  statuses, same POST timing.
Also: retained publish of `lexa/csip/control` (QoS 1, retained), and the
`ECDHE-ECDSA-AES128-CCM-8` mTLS invariants are untouched.

## Acceptance criteria
- [ ] `go test -race ./internal/...` green with zero edits to
      `failclosed_test.go` assertions.
- [ ] Differential test proves legacy-vs-utilitytime `Evaluate` equivalence.
- [ ] Gate scenarios 10× solo each at baseline verdicts; full FAST campaign
      ≤ V6 baseline (0.6 FAIL/cycle, 0 BLIND).
- [ ] `grep -n "time.Now().Unix() + " cmd/northbound internal/northbound -r`
      shows no remaining ad-hoc serverNow computation in migrated files.

## Regression checklist
- [ ] `go test -race ./internal/...` (lexa-hub) green
- [ ] Conformance logic tests green (`cd ~/projects/csip-tls-test && go test ./tests/`) — protocol-adjacent (Response timing)
- [ ] Mayhem: targeted clock/wan scenarios 10× + full campaign (05 §12)
- [ ] `hub-replay-tune.sh fast` re-applied after deploy

## Mayhem scenarios affected
`clock-jitter`, `clock-jump-forward`, `wan-outage-hold`, `wan-outage-expiry`,
`northbound-hang`, `expired-control`, `control-churn`, `curtailment-release` —
verdicts must not move from the V6 baseline; any drift is a finding.

## Conformance implications
Response resources (CORE-022/023, GEN.044) carry `CreatedDateTime` computed
from serverNow — must remain server-time-correct. Run
`go test ./tests/` (csip-tls-test) for the conformance logic suite; full
evidence regeneration not required.

## Suggested commit message
Four commits, e.g. `refactor(northbound): walker feeds utilitytime.Clock (TASK-035 1/4)`
… `refactor(scheduler): expiry/window via utilitytime, guards verbatim (TASK-035 3/4)`

Trailer: `Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>`

## Suggested PR title & description
**Title:** northbound: migrate walker+scheduler serverNow onto utilitytime (TASK-035)
**Description:** AD-004 consumers 1–3 of 5. Guards ported verbatim (tests
untouched); differential equivalence test added. Risk: high (radioactive
zone). Testing: unit + 10× gate scenarios + full FAST campaign (attach
report). Rollback: revert per-commit; scheduler commit is independent of
walker commits.

## Code review checklist
- `failclosed_test.go` diff is empty.
- Guard code moves are mechanical only (compare side-by-side).
- serverNow computed once per walk and shared, as before.
- Deprecation note on `scheduler.ServerNow` present; no other callers broken
  (`grep -rn "scheduler.ServerNow" ~/projects/lexa-hub`).
- Campaign report attached and ≤ baseline.

## Definition of done
Acceptance criteria + regression checklist green; docs updated (CLAUDE.md,
AD-004); status headers updated (this file + 00_MASTER_INDEX).

## Possible follow-up tasks
TASK-036 (remaining consumers), TASK-037 (local-step policy uses the Clock's
StepClass), TASK-079 (DST/TOU tests).
