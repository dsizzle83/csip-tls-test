# TASK-015 — Stock-timing Mayhem release gate (campaign wrapper + first STOCK baseline)

*Status: DONE (2026-07-05, da6e629 on `task/015-stock-report`) · Phase: P0 · Effort: M (≈4–6 h + overnight run) · Difficulty: low · Risk: low*

**Completion note (2026-07-05):** the P0-exit STOCK baseline is executed. `scripts/mayhem-campaign.sh`
ran 5 cycles (single-run mode, `c39f820` — the wall-time decision taken at the P0-exit
gate; see the report footnote) against the M0 shipping hub build:
`logs/campaign-stock-20260704T224628/` (an earlier same-day attempt,
`campaign-stock-20260704T214633/`, was killed after cycle 1 and is a footnote only, not
counted). Result: **0.8 FAIL/cycle, 0 BLIND, 0 safety-invariant escalations** over 255
scenario-runs — triaged per `docs/QA_STOCK_TRIAGE_TEMPLATE.md` in
`docs/QA_REPORT_STOCK_M0_20260705.md`. Four singleton FAILs (no repeats): two filed as
findings (`QA-STOCK-001` malform-huge-activepower, `QA-STOCK-002` clock-jitter, both in
`docs/QA_FINDINGS.md` §6), two dispositioned as pre-existing documented gaps needing no
new action (perfect-storm, meter-ct-inverted). Zero scenario-margin edits made. Bench
verified restored to FAST at campaign end (`campaign.log` closing line). This declares
the STOCK M0 baseline (0.8 FAIL/cycle) that future STOCK release gates (TASK-081)
compare against, alongside FAST V6's 0.6 FAIL/cycle.

## Objective
A campaign wrapper script runs N Mayhem cycles in FAST **or** STOCK bench timing with
per-cycle JSON evidence and a summary; the first 10-cycle STOCK campaign is executed
overnight, triaged with a written template, and recorded as the M0 STOCK baseline —
where STOCK-only failures become tracked findings, not phase blockers (03 P0 exit
criteria).

## Background
The validation hole (review §13, GAP-15): thresholds are tick-scaled (`scaleTicks`
keeps wall-clock semantics), but the product **ships** STOCK (engine 15 s, discovery
20 s, poll 10 s) while every campaign to date ran FAST (3 s / 5 s / 2 s). The shipped
safety/CannotComply latencies are literally untested.

Verified tooling:
- `scripts/mayhem.py` — headless runner: `--dashboard URL`, `--only id,id`, `--list`,
  `--json`, `--abort`; exit 0 = no FAIL/BLIND, 1 = any FAIL/BLIND, 2 = run error.
- `scripts/mayhem-100.sh` — existing loop precedent (N runs → `logs/mayhem-100/` +
  `summary.tsv` counting `[PASS]`/`[DEGRADED]`/… lines). Model the wrapper on it.
- Timing control: `scripts/hub-replay-tune.sh fast|stock [hub-ip] [ssh-user]` edits
  `/etc/lexa/{hub,northbound,modbus}.json` on 69.0.0.1 and restarts the three services;
  `bash scripts/bench-up.sh --stock` is a thin shortcut to `hub-replay-tune.sh stock`.
- CLAUDE.md says "Bench must be in FAST mode" for Mayhem — that guidance reflects that
  scenario `HoldS` windows and settle margins were calibrated against FAST latencies.
  Running STOCK is exactly the point here: expect DEGRADED/INCONCLUSIVE noise where a
  scenario's window is too tight for 15 s ticks. Those become *triage rows*, classified
  as (a) real product latency finding, (b) harness margin mis-calibration —
  margin changes require a physical justification written into the scenario (06 §4.5,
  the HoldS-adjustment precedent), or (c) accepted-by-design STOCK behavior.
- Baseline to compare against: V6 FAST = 0.6 FAIL/cycle, 0 BLIND; accepted DEGRADEDs in
  `docs/QA_REPORT_V5_20260703.md` + V6 notes.

## Why this task exists
GAP-15 / review §13 / §14 item 11: "the product ships in a timing regime that QA doesn't
run. One stock-timing campaign before any release is mandatory." This task builds the
gate and records the first baseline; TASK-081 makes it a release ritual.

## Architecture review sections
§13 (FAST/STOCK duality), §14 item 11; 07 GAP-15; 06 §2 (campaign gates), §4.5 (never
weaken an oracle); 03 P0 exit criteria; RSK-12/13.

## Prerequisites
Bench healthy; TASK-001 (committed tree). Best run AFTER the other P0 bench-touching
tasks (006/007/008/013/014) so the baseline reflects M0's shipping state — sequence it
late in P0.

## Files
- **Read first:** `scripts/mayhem.py` (flags/exit codes), `scripts/mayhem-100.sh`,
  `scripts/hub-replay-tune.sh`, `scripts/bench-up.sh`, `docs/QA_REPORT_V5_20260703.md`
  (accepted-DEGRADED ledger format), CLAUDE.md Mayhem section.
- **Modify:** `CLAUDE.md` (Mayhem section: FAST-only note becomes "FAST for development
  campaigns; STOCK via mayhem-campaign.sh for release gates").
- **Create:** `scripts/mayhem-campaign.sh`,
  `docs/QA_STOCK_TRIAGE_TEMPLATE.md`,
  `docs/QA_REPORT_STOCK_M0_<date>.md` (the executed baseline).

## Blast radius
Bench-only tooling. The STOCK run itself re-tunes the live hub's timing for hours —
the wrapper MUST restore FAST afterward or the next dev session runs mis-tuned
(the classic deploy-gotcha class).

## Implementation strategy
Wrap the proven mayhem-100 loop with explicit mode management: set timing → verify
timing took → N cycles with `--json` evidence → summary with per-scenario verdict drift
vs the FAST baseline → restore prior timing unconditionally (trap on EXIT). Then execute
10 STOCK cycles overnight and write the triage.

## Detailed steps
1. Write `scripts/mayhem-campaign.sh`:
   - Args: `--mode fast|stock` (required), `--cycles N` (default 10),
     `--dashboard URL` (default `http://localhost:8080`), `--only id,...` (passthrough).
   - Preamble: record current mode (read `engine_interval_s` from the hub over SSH —
     same mechanism hub-replay-tune uses), then `hub-replay-tune.sh <mode> 69.0.0.1
     dmitri`; verify via SSH that `hub.json` shows the expected interval.
   - Loop N cycles: `python3 scripts/mayhem.py --dashboard $URL --json >
     logs/campaign-<ts>/cycle-NN.json` plus the human-readable run
     (`| tee cycle-NN.txt` like mayhem-100.sh). Continue on exit 1 (FAIL/BLIND is data),
     abort the campaign on exit 2 (bench broken).
   - Summary: per-cycle verdict counts TSV + a per-scenario table (scenario × cycles →
     verdict string) so drift/flake is visible; FAIL-rate/cycle computed at the end.
   - `trap 'hub-replay-tune.sh fast …' EXIT` — restore FAST unconditionally (FAST is
     the bench's resting state per bench-up.sh default); print a loud closing line
     stating the restored mode.
2. Dry-run: `--mode fast --cycles 1` end-to-end (evidence dir, summary, restore).
3. Write `docs/QA_STOCK_TRIAGE_TEMPLATE.md`: columns — scenario, STOCK verdict(s), FAST
   baseline verdict, delta class (product-latency finding / harness-margin
   miscalibration / accepted STOCK behavior), evidence pointer (cycle JSON + journal),
   disposition (finding ID / margin change WITH physical justification / accepted),
   and the standing rule: **STOCK failures are findings, not M0 blockers, unless they
   reveal a safety regression** (03 P0 exit criteria; safety = INV-SOC/INV-CONNECT/
   INV-EXPORT/INV-EXPIRED violations).
4. Execute the baseline: bench healthy check (`bash scripts/bench-up.sh --fast` first,
   then) `bash scripts/mayhem-campaign.sh --mode stock --cycles 10` overnight.
5. Triage every non-PASS against the template; file findings (docs/QA_FINDINGS.md
   pattern) for product-latency deltas; do NOT change any scenario margin in this task
   unless the physical justification is airtight and documented in the scenario's `Fix`
   text.
6. Write `docs/QA_REPORT_STOCK_M0_<date>.md` (same structure as the V5 report): totals,
   per-scenario table, triage table, the declared M0 STOCK baseline numbers, and the
   sentence future release gates compare against.
7. Update CLAUDE.md Mayhem section + 00_MASTER_INDEX (M0 baseline recorded).

## Testing changes
The wrapper is the test tool; validate via the step-2 dry-run. No Go changes.

## Documentation changes
CLAUDE.md (Mayhem section), the two new docs, 00_MASTER_INDEX status + QA baseline note.

## Common mistakes to avoid
- Leaving the bench in STOCK after the run (the EXIT trap is mandatory; also verify
  manually — a killed SSH can skip traps).
- Comparing STOCK results against the FAST baseline as pass/fail — the deliverable is a
  *triage*, not a green board. Alarm-fatigue risk (RSK-13) is managed by the
  disposition discipline, not by tuning scenarios green (06 §4.5).
- Running the baseline before the other P0 bench changes land — the M0 baseline must
  describe M0, or every later comparison is polluted. Sequence last in P0.
- Editing scenario `HoldS`/margins to make STOCK pass without a physical justification
  written into the scenario — explicitly forbidden (the HoldS-45 precedent in
  clock-jitter shows the required form).
- Forgetting that a full FAST campaign ≈ 45 min ⇒ STOCK cycles run several× longer
  (walk/tick latencies stretch every settle phase); 10 cycles is genuinely overnight —
  don't schedule against a demo.

## Things that must NOT change
- `scripts/mayhem.py` and the Mayhem engine (`cmd/dashboard/mayhem.go`) — wrapper-only
  task; zero scenario/oracle edits (any margin change found necessary spawns its own
  reviewed change with justification).
- `hub-replay-tune.sh` fast/stock values (they define the regimes being compared).
- The V6 FAST baseline and accepted-DEGRADED ledger.

## Acceptance criteria
- [ ] `mayhem-campaign.sh --mode fast --cycles 1` produces evidence dir + summary + restores timing (dry-run evidence).
- [ ] 10-cycle STOCK campaign completed; per-cycle JSON + per-scenario drift table exist.
- [ ] Every non-PASS dispositioned per the template; safety-invariant violations (if any) escalated as blockers.
- [ ] `docs/QA_REPORT_STOCK_M0_<date>.md` committed; declared baseline numbers present.
- [ ] Bench verified back in FAST at the end.

## Regression checklist
- [ ] `make test-fast` green (trivially — scripts only)
- [ ] Conformance logic tests: unaffected
- [ ] Mayhem: the STOCK campaign IS the payload; plus one FAST cycle afterward confirming the bench restored clean
- [ ] `git status` clean (evidence dirs under `logs/` — confirm gitignored; commit only the report docs)

## Mayhem scenarios affected
All 51 observed under STOCK for the first time. Expected noisy candidates: tight-window
scenarios (`ack-before-effect`, `battery-wrong-sign` heritage classes, clock scenarios)
where 15 s ticks eat the HoldS margin — these become triage rows, not scenario edits.

## Conformance implications
None directly; the M0 conformance evidence regeneration (06 §2) should cite the same
bench state.

## Suggested commit message
`qa: mayhem-campaign.sh (fast/stock, N-cycle, evidence+restore) + STOCK triage template + M0 STOCK baseline report (GAP-15)`
`Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>`

## Suggested PR title & description
**Title:** Stock-timing campaign gate + first STOCK baseline (M0)
**Description:** Wrapper (mode-managed, evidence-preserving, FAST-restoring), triage
template with the findings-not-blockers rule, and the executed 10-cycle STOCK report.
Rollback: none needed (tooling + docs).

## Code review checklist
- EXIT trap restores timing on every path (test with Ctrl-C).
- Summary math (FAIL/cycle) matches the raw JSONs on a spot check.
- Triage dispositions each cite evidence; zero unexplained scenario edits in the diff.

## Definition of done
Acceptance criteria + regression checklist + docs + status headers updated; 00's QA
baseline section gains the STOCK numbers.

## Possible follow-up tasks
TASK-081 (release gate executes this at V1.0), findings filed here feed P5 latency work;
RSK-12 (nightly scheduled campaigns could reuse the wrapper).
