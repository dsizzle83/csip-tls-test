# TASK-033 — Mayhem reconciler-era review + 10-cycle FAST & STOCK sign-off campaigns

*Status: DONE (2026-07-06) — M2 sign-off; see docs/QA_REPORT_M2_20260706.md*

## Objective
Every Mayhem scenario whose injection choreography, hold times, or diagnosis text assumes
the *legacy* convergence machinery is reviewed against reconciler semantics and updated
(or its gap pinned) without weakening any oracle; a 10-cycle FAST campaign and a STOCK
campaign are run on the post-TASK-032 system; `docs/QA_FINDINGS.md` and the baseline in
`docs/refactor/00_MASTER_INDEX.md` are updated — this closes Phase 2 (milestone M2).

## Background
The suite (51 scenarios: `python3 scripts/mayhem.py --list`) was built against a hub
whose convergence behavior had specific, now-changed timing signatures:
- **Dedupe window (gone):** identical commands were suppressed up to `reassertEvery=60 s`;
  scenarios sized holds around it (e.g. re-assert expectations in `solar-reboot-forget`,
  whose PASS note reads "hub re-asserts the limit every cycle"). Reconciler semantics:
  corrective writes bound by poll+readback, reasserts on reconnect, content-change
  publishes — generally FASTER, so most timing margins get safer, but any diagnoser that
  asserts *presence of periodic re-commands* or counts command traffic will misread.
- **`export-cap-full-battery` Ena choreography:** the scenario body drives batsim's
  `WMaxLimPct_pct`/`Ena` registers in a specific order (`sim/southbound/battery.go:209–262`
  — Ena sent as a separate POST because map order within one body is unspecified;
  scenario at `cmd/dashboard/mayhem.go:2321`). Its accepted verdict is the documented
  4 s DEGRADED-at-oracle-line (V6 notes). Verify the choreography still exercises what it
  intends when writes come from the reconciler, and that the accepted-DEGRADED signature
  is unchanged or improved.
- **`control-churn`** (utility rewrites the cap every ~12 s): historically interacted
  with dedupe/guard resets (the `expOverTicks` session-scoping fix). Reconciler-era: doc
  churn → seq churn; diagnoser expectations about command cadence may need re-reading.
- **`curtailment-release` / `release-while-rebooting`:** HoldS margins were tuned to
  legacy release timing (V5 history; harness-margin precedents). Expect PASS with margin
  to spare; do not tighten margins just because it got faster (oracle changes need
  physical justification — 06 §4.5).
- **Diagnosis/finding text** in `cmd/dashboard/mayhem.go` refers to hub internals
  ("actuator deduper", "re-asserts every cycle", "lastCtrl") in several `Findings`/
  `Diagnosis` strings — stale text produces misleading triage output even when verdicts
  are right. Grep and update.
- **INV-HUNT** (`cmd/dashboard/invariants.go`): hunting detection could misclassify
  reconciler retry-with-backoff against a refusing device as oscillation — the
  `reject-write-curtail`/`enable-gate-curtail` runs are the check. Review thresholds
  only if evidence shows misclassification; document any change with the physical
  justification.

STOCK requirement (§13, GAP-15): the product ships at the 15 s engine tick but is
validated at 3 s FAST. Phase-2 exit explicitly requires a STOCK campaign
(`bash scripts/bench-up.sh --stock`, then the campaign; restore `--fast` after). The
reconciler's wall-clock thresholds (05 §5) should make FAST/STOCK behavior converge —
this campaign is the first real test of that claim.

Baseline to defend: V6 = 0.6 FAIL/cycle, 0 BLIND, accepted DEGRADEDs per
`docs/QA_REPORT_V5_20260703.md` + V6 notes.

## Why this task exists
06 §4.4/§4.5: verdicts are only trustworthy if oracles track the system they judge; a
suite asserting legacy internals would go green-blind or noisy-red after R1. And 03
Phase 2's exit criteria (10-cycle FAST ≤ baseline, STOCK run, ledger scenarios
individually PASS, QA_FINDINGS updated) need one owning task.

## Architecture review sections
§9 (tests-verify-implementation tail), §13 (FAST/STOCK validation hole), R1 wrap-up,
§14 items 3/11; 03 Phase 2 exit criteria; 06 §2 (campaign gates)/§4; 07 GAP-15;
08 RSK-13; ledger (all rows' gate evidence).

## Prerequisites
- TASK-032 DONE (deletions landed; pre-deletion + final campaign artifacts exist).
- Bench healthy; an overnight window for the 10-cycle FAST run and a second window for
  STOCK.

## Files
- **Read first:** `cmd/dashboard/mayhem.go` (scenario defs; grep
  `dedupe|reassert|lastCtrl|re-assert|every cycle` in string literals),
  `cmd/dashboard/mayhem_world.go` (world model + any legacy-topic listeners),
  `cmd/dashboard/invariants.go` (INV-HUNT), `sim/southbound/battery.go:200–262`
  (Ena choreography), `docs/QA_REPORT_V5_20260703.md` (accepted DEGRADEDs),
  `docs/refactor/PRESERVATION_LEDGER.md` (gate list to re-verify at scale).
- **Modify:** `cmd/dashboard/mayhem.go` (stale text; any legacy-timing assumptions);
  possibly `cmd/dashboard/invariants.go` (only with justification);
  `docs/QA_FINDINGS.md`; `docs/refactor/00_MASTER_INDEX.md` (P2 row + new baseline);
  `docs/refactor/PRESERVATION_LEDGER.md` (campaign-scale evidence links).
- **Create:** campaign reports land as `qa-mayhem-<ts>.md` (gitignored) — copy the
  summary into a committed `docs/QA_REPORT_*` per the existing pattern.

## Blast radius
Test bench only (csip-tls-test). No product code. Scenario/diagnoser edits change what
future campaigns assert — which is exactly why every oracle change needs written
justification here.

## Implementation strategy
Review pass first (static: greps + reading the flagged scenarios), classify each finding
as (a) stale text — fix freely, (b) timing assumption — re-derive from reconciler
semantics with margins per the HoldS-precedent discipline, (c) genuine gap the reconciler
introduced — pin with an expected-FAIL scenario or file a product finding; then rebuild,
run edited scenarios 10× solo (verdict-stability rule), then the two campaigns, then the
docs.

## Detailed steps
1. Static review: grep `cmd/dashboard/mayhem.go` (+ `mayhem_world.go`, `matrix.go`) for
   legacy-internal references in strings and comments; list every scenario touched with
   its classification (a/b/c above) in the PR description.
2. Deep-check the four named scenarios: `export-cap-full-battery` (Ena choreography +
   accepted-DEGRADED signature), `control-churn` (cadence expectations),
   `solar-reboot-forget` (re-assert expectations), `curtailment-release` +
   `release-while-rebooting` (HoldS margins). Any margin/oracle edit carries an in-code
   comment with the physical justification (06 §4.5 — never tune to pass).
3. INV-HUNT review: run `reject-write-curtail` and `enable-gate-curtail` 10× solo on the
   post-032 system BEFORE any invariant edits; only if INV-HUNT misfires on
   backoff-retry, adjust with justification + comment.
4. Rebuild and redeploy the dashboard: `go build -o bin/dashboard ./cmd/dashboard` then
   restart the `csip-dashboard` user unit (the unit execs `bin/dashboard` — the
   2026-07-03 stale-binary trap; a scenario edit that isn't rebuilt silently runs the
   old suite, D8).
5. Edited-scenario stability: each modified scenario ×10 solo
   (`python3 scripts/mayhem.py --dashboard http://localhost:8080 --only <id> --json`),
   verdicts stable per RSK-13 practice.
6. **10-cycle FAST campaign** (bench `bash scripts/bench-up.sh --fast`): ≤ 0.6
   FAIL/cycle, 0 BLIND, DEGRADED signatures ⊆ accepted list (new signature = finding,
   not noise — 06 §4.4).
7. **STOCK campaign** (`bash scripts/bench-up.sh --stock`, ≥1 full cycle; 10 if wall
   clock permits): triage per 03 Phase 0/2 rules — STOCK failures become tracked
   findings, phase-blocking only if they reveal safety regressions. Restore FAST after
   (`bench-up.sh --fast`).
8. Docs: update `docs/QA_FINDINGS.md` (reconciler-era status of each finding it lists —
   several of its FAIL entries are long-fixed; bring the "current source of truth"
   pointers up to date); write the committed campaign report; set the new baseline
   numbers in `00_MASTER_INDEX.md` and mark P2 exit with links; ledger rows get
   campaign-scale evidence links.
9. If any classification-(c) gap was pinned expected-FAIL, add it to the findings doc
   with owner/task reference (meter-ct-inverted precedent).

## Testing changes
Harness self-tests: `make test-fast` covers `cmd/dashboard` unit tests
(`mayhem_test.go`, `invariants_test.go`, `matrix_test.go`) — must pass after edits; add
cases for any diagnoser logic changed (the diagnoser-fix-with-test culture,
QA_FINDINGS §3 precedent). Campaigns per steps 5–7.

## Documentation changes
Steps 8–9 (QA_FINDINGS, campaign report, 00 baseline, ledger links). Also update the
Mayhem section of the root `CLAUDE.md` if scenario count or verdict semantics changed
(they should not).

## Common mistakes to avoid
- Weakening an oracle to make a run pass (06 §4.5). If the reconciler genuinely regressed
  a behavior, that is a product finding for the phase — not a margin tweak.
- Editing scenarios and campaigning without rebuilding `bin/dashboard` (step 4).
- Running the STOCK campaign with the hub still in FAST replay tuning (or vice versa) —
  `bench-up.sh` sets hub timing; verify via lexa-api `/status` cadence before trusting
  verdicts.
- Treating a DEGRADED-signature *change* (e.g. export-cap-full-battery's 4 s window
  shrinking) as automatically fine — record it; the accepted-DEGRADED ledger must stay
  accurate for future drift detection.
- Leaving the bench in STOCK when done (every future session assumes FAST).

## Things that must NOT change
- Verdict taxonomy (PASS/DEGRADED/FAIL/BLIND/INCONCLUSIVE) and invariant set
  (INV-SOC/-CONNECT/-EXPIRED/-EVMAX/-HUNT) semantics.
- Ground-truth independence: diagnosers judge from sim `/state`, never from hub
  self-reporting.
- Scenario count and IDs (downstream docs/memory reference them); no scenario deleted —
  outdated ones are updated or expected-FAIL-pinned.
- The accepted-DEGRADED entries remain documented — additions/removals only with
  evidence.

## Acceptance criteria
- [ ] Review table (scenario → classification → action) in the PR; zero unexplained
      legacy-internal references remain (`grep` clean or justified).
- [ ] Edited scenarios stable 10/10 solo.
- [ ] 10-cycle FAST campaign report: ≤ 0.6 FAIL/cycle, 0 BLIND, no unaccepted DEGRADED
      signatures.
- [ ] STOCK campaign run + triaged; findings filed; bench restored to FAST.
- [ ] `docs/QA_FINDINGS.md`, committed campaign report, `00_MASTER_INDEX.md` baseline +
      P2 status, ledger evidence links — all updated.

## Regression checklist
- [ ] `make test-fast` (csip-tls-test) green — incl. dashboard/mayhem unit tests
- [ ] `go test -race ./internal/...` (lexa-hub) green (untouched — cheap proof)
- [ ] Conformance logic tests: skip (harness-only changes)
- [ ] Mayhem: edited ×10 solo + 10-cycle FAST + STOCK (this task IS the gate)

## Mayhem scenarios affected
Reviewed set (at minimum): `export-cap-full-battery`, `control-churn`,
`solar-reboot-forget`, `curtailment-release`, `release-while-rebooting`,
`reject-write-curtail`, `enable-gate-curtail`, `battery-reboot`, `ev-connector-flap`,
`mqtt-broker-restart`, `hub-restart-mid-cap`, `perfect-storm` — plus any the step-1 grep
surfaces. Verdict expectations: baseline or better, with signature changes documented.

## Conformance implications
None (harness + docs). The STOCK campaign result feeds the release-gate practice
(TASK-015/081).

## Suggested commit message
`qa(mayhem): reconciler-era scenario review + M2 sign-off campaigns (TASK-033)`
`Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>`

## Suggested PR title & description
**Title:** Phase 2 sign-off: Mayhem updated for reconciler semantics; FAST+STOCK campaigns
**Description:** Scenario review table (stale text / timing / pinned gaps), diagnoser
edits with physical justifications, 10-cycle FAST + STOCK evidence, QA docs + baseline
updated. Rollback: revert (harness-only).

## Code review checklist
- Every oracle/margin edit has an in-code justification comment.
- No diagnoser weakened relative to what it proved before (diff the FAIL conditions).
- Campaign artifacts linked; baseline math checked.
- Bench state restored (FAST, clock 0, programs cleared — the engine restores on
  finish/abort; verify).

## Definition of done
Acceptance criteria + regression checklist; all Phase 2 exit criteria in
`03_REFACTOR_PHASES.md` checked off with evidence; status headers (this file +
00_MASTER_INDEX, P2 row → DONE/M2) updated.

## Possible follow-up tasks
TASK-034+ (P3 utilitytime can start), TASK-041 (restart-mid-breach scenario interplay),
TASK-015/081 (STOCK release-gate cadence), TASK-054 (dither sweeps against reconciler
thresholds), backlog: scenario asserting desired-doc staleness rejection (RSK-17 probe).
