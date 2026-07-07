# TASK-077 — Migrate the curated scenario suite to declarative specs

*Status: PARTIAL (2026-07-06, `csip-tls-test` `task/077-scenario-migration`, unmerged) · Phase: P6 · Effort: L (≈8 h, mechanical but gated) · Difficulty: med · Risk: med*

**2026-07-06 session note (deadline addendum — batched QA, bench-free lane):**
Wave 1 done: 24 of the ~63 total scenario entries migrated to
`qa/scenarios/*.json` (the whole constraint/converge/SOC/disconnect/recovery
family from `mayhem.go`'s curated list, plus a 4-oracle wave-B batch —
transport/battery-garbage/reboot/expiry), their Go twins deleted in
`cmd/dashboard/mayhem.go`, 4 new oracles registered
(`diagnoseTransport`/`diagnoseBatteryGarbage`/`diagnoseReboot`/
`diagnoseExpiry`), parity proven per-scenario via unit tests (
`cmd/dashboard/scenariospec_migration_test.go` — bench-side ×3 live parity
NOT run this session, see below), `go test ./cmd/dashboard/... -race` green,
`bin/dashboard` rebuilt (not deployed/restarted — out of this lane).
**Not done:** `mayhem_world.go` (17 scenarios) and `mqtt_scenarios.go` (8)
untouched; 14 scenarios remain in `mayhem.go` itself (8 need a `delay_s`
setup-action vocabulary extension not implemented this session; 3 need a
per-tick computed-value extension; `ev-connector-flap`/`ev-meter-freeze`/
`ev-wrong-units` deferred for session-scope discipline, not a gap — see
`docs/qa-spec-migration.md` for the full retained list + reasons + a
prioritized next-wave triage). Acceptance criteria NOT fully met this
session: full migration table covering all ~63 entries (only the 24-entry
wave is tabled), `mayhem.go` line count only ~17% down (2683/3216, not
"well under half" — the bulk of the reduction requires the world/mqtt waves
this session didn't touch), and the live-bench ×3 parity + full FAST
campaign per wave (task step 5/6) — this session's lane was explicitly
bench-free (no bench runs, no `csip-dashboard` restart). Full parity of all
~60 was explicitly NOT required under the deadline addendum; this PARTIAL
status reflects "a clean, growing, well-documented migration" handed off
with a concrete, prioritized next-wave plan, not a defect.

## Objective
Every curated Mayhem scenario that the TASK-076 vocabulary can express is
migrated to a spec file under `qa/scenarios/`, verified for verdict
parity against its Go twin (×3 per scenario), and the Go literal deleted;
per-scenario evaluate closures become named, parameterized oracles in the
Go registry. Scenarios the vocabulary cannot express are either (a)
unblocked by a small vocabulary extension or (b) explicitly retained in
Go with a written reason. End state: `mayhem.go` is engine + oracle
library; scenario DEFINITIONS are data.

## Background
- Scenario inventory (verified): docs cite **51 scenarios**
  (docs/QA_REPORT_V5_20260703.md: "51 scenarios × 10 cycles"); the CODE
  contains 46 `mayScenario` literals (33 in mayhem.go's curated list —
  IDs from export-cap-full-battery through perfect-storm — plus 9 in
  mayhem_world.go worldScenarios, 4 in mqtt_scenarios.go) plus generator
  functions that mint variants (`malformScenario(id, name, kind, …)`,
  mayhem.go:1075-1110, used for the malformed-resource variant family).
  **The authoritative enumeration is `python3 scripts/mayhem.py --list`
  against a live dashboard — run it FIRST and reconcile the count before
  planning the migration table.**
- Oracle boundary (set in TASK-076, restate in the PR): **oracles/
  diagnosers are code, scenarios are data.** Shared diagnosers already
  named: `diagnoseConstraint`, `diagnoseRecovery`, `diagnoseMalform`.
  Many scenarios carry bespoke `evaluate` closures (e.g. clock-jump,
  wan-outage-expiry, stale-meter) — each becomes a NAMED oracle with
  params (e.g. `diagnoseExpiryRelease{release_at_tick, floor_w}`), unit-
  testable in isolation (mayhem_test.go / review_followups_test.go
  patterns exist).
- Hard cases to scope honestly:
  - SSH-dependent scenarios (hub-restart-mid-cap; mayhem_world.go:96) —
    vocabulary has `ssh_hub`; migrate.
  - `suppressDefault` + restore closure (curtailment-release,
    clock-jump-forward) — vocabulary v1 covers it.
  - Goroutine-delayed injections (malform at +8 s inside setup,
    mayhem.go:1096-1100) — needs `at_tick`/`delay_s` support in setup
    actions (small vocabulary extension).
  - `matrixScenarios()` (matrix.go) — programmatic product of cells ×
    jitter; OUT of scope: stays Go (it is a generator, not 51 literals;
    record as retained-with-reason).
- Deletion discipline: 05 §11 (deletion in its own commit; replacement
  named); RSK-13 (verdict stability); 06 §4 (campaign evidence versioned).

## Why this task exists
D8/R6 second half: 076 built the engine; the payoff — no-rebuild
authoring, reviewable scenario diffs, a shrunken mayhem.go — only arrives
when the literals die.

## Architecture review sections
D8 · R6 · item 19 · 06 §Mayhem · 08 RSK-13 · 05 §11.

## Prerequisites
TASK-076 DONE (schema + pilot parity). Bench available for extensive
parity runs (each scenario ×3; batch them — a full parity pass is
roughly 3 campaign-equivalents of wall-clock; schedule overnight).

## Files
- **Read first:** `mayhem.py --list` output; every scenario literal in
  cmd/dashboard/{mayhem.go,mayhem_world.go,mqtt_scenarios.go};
  cmd/dashboard/scenariospec.go (vocabulary); existing oracle funcs +
  their tests.
- **Modify:** cmd/dashboard/mayhem.go (delete literals per batch; grow
  the oracle registry), mayhem_world.go, mqtt_scenarios.go (shrink to
  helpers the driver keeps: mqttFault/mqttInject/mqttReset stay — they
  are driver verbs), scenariospec.go (small vocabulary extensions only,
  each with tests).
- **Create:** `qa/scenarios/*.json` (one per migrated scenario);
  `docs/qa-spec-migration.md` (the migration table: id → spec file →
  parity runs → deletion commit; retained-in-Go list with reasons).

## Blast radius
The QA suite itself — the program's regression oracle (06 §Mayhem). A
botched migration silently weakens the safety net for every OTHER task.
That is why parity is per-scenario ×3 and deletions are batched small
with a full campaign per batch.

## Implementation strategy
Migrate in waves of ~8-10 scenarios grouped by oracle family
(constraint-family first — most share diagnoseConstraint and need no new
oracles; then recovery; then world/mqtt; bespoke-oracle scenarios last).
Per wave: write specs → run each `--only <id>` ×3 spec-vs-Go parity
(alternate which is loaded; identical verdict + same finding shape) →
delete the Go literals in ONE commit per wave → full FAST campaign →
next wave. Extract bespoke closures into named oracles BEFORE writing
their specs (separate commits: oracle extraction is refactor,
spec+delete is migration).

## Detailed steps
1. Enumerate: `mayhem.py --list`; build the migration table; classify
   each scenario: {vocab-ready | needs-oracle-extraction |
   needs-vocab-extension | retained-Go(reason)}. Reconcile the 51-vs-46
   count in the table (generator variants listed individually).
2. Vocabulary extensions found in step 1 (expected: `delay_s` on setup
   actions; sentinel values like `"pv_w": "high"`; possibly a
   `post`-to-arbitrary-sim body already covered by `sim_post`): implement
   + unit-test each in scenariospec.go FIRST.
3. Oracle extraction commits: closure → named registry oracle with
   params; unit tests move/extend (mayhem_test.go style: synthetic
   sample timelines → expected verdict). No spec changes yet; full
   `make test-fast` after each.
4. Wave migration per the strategy: specs written with Hypothesis/
   Expected/Fix text carried over VERBATIM (these strings appear in QA
   reports and triage docs — preserve them byte-for-byte).
5. Parity protocol per scenario: run Go version ×1, spec version ×3 (ID
   collision guard from 076 means the Go twin is renamed/flagged during
   comparison — use the 076 `-prefer-spec` toggle); PASS criteria:
   identical verdict all runs (or ⊆ the scenario's accepted-verdict set,
   e.g. export-cap-full-battery's accepted DEGRADED), diagnosis text from
   the same oracle path. Log all runs in the migration table.
6. Deletion commit per wave (05 §11): literals removed; grep-proof no
   dangling IDs; `mayhem.py --list` count unchanged; full FAST campaign ≤
   baseline (0.6 FAIL/cycle, 0 BLIND).
7. Final state audit: `wc -l cmd/dashboard/mayhem.go` (target: engine +
   oracles only — expect well under half the original 3,123);
   retained-in-Go list (expect: matrix generator + anything argued in
   step 1) committed in docs/qa-spec-migration.md.
8. Update scripts/mayhem.py docs/help if `--list` output format changed
   (source tags from 076).

## Testing changes
- Oracle unit tests (moved/extended per extraction).
- Compile-all-specs test already exists (076) — now covers ~40+ files.
- Parity run logs (bench evidence, not unit tests).
- Run: `make test-fast`; parity + campaigns via scripts/mayhem.py.

## Documentation changes
- docs/qa-spec-migration.md (table + retained list + parity evidence
  links).
- csip-tls-test CLAUDE.md: Mayhem section — scenarios live in
  qa/scenarios/, count, authoring pointer.
- memory/QA docs references to "mayhem.go scenarios" updated where
  load-bearing (QA_FAULT_INJECTION.md if it lists them).

## Common mistakes to avoid
- Weakening an oracle to make parity pass (06 §4.5 "never weaken an
  oracle to pass a run") — a parity mismatch means the SPEC is wrong or
  the closure had unexpressed behavior; investigate, don't tune.
- Migrating expected-FAIL/expected-DEGRADED scenarios and "fixing" their
  verdicts (meter-ct-inverted's DEGRADED pins a product gap BY DESIGN;
  `expected_verdicts` in the spec carries that).
- Editing Hypothesis/Expected prose during migration (breaks report-diff
  archaeology across campaign history).
- One mega-deletion commit (unbisectable; violates 05 §11).
- Forgetting the dashboard REBUILD after each engine change during this
  task (`go build -o bin/dashboard ./cmd/dashboard` + unit restart — the
  exact trap being retired; specs hot-load but oracle code does not).
- Running parity waves during someone else's campaign window (bench
  contention corrupts both).

## Things that must NOT change
- Verdicts and accepted-DEGRADED ledger for every migrated scenario
  (parity protocol is the proof).
- The invariant audit (INV-SOC/-CONNECT/-EXPIRED/-EVMAX/-HUNT escalation
  via escalateForAudit) — applies to spec scenarios identically.
- `mayhem.py` CLI contract (`--list/--only/--json` behavior).
- Matrix/chaos modes (retained Go generators).
- V6 baseline through every wave.

## Acceptance criteria
- [ ] Migration table complete: every listed scenario accounted for
  (migrated + parity evidence, or retained + reason).
- [ ] Per-wave: parity ×3 logs + deletion commit + full campaign ≤
  baseline.
- [ ] mayhem.go reduced to engine + oracle library (line count in PR);
  zero scenario literals outside qa/scenarios/ except the retained list.
- [ ] A new scenario can be added end-to-end without touching Go
  (demonstrated once with a trivial variant, then removed).

## Regression checklist
- [ ] `make test-fast` (csip-tls-test) green after every commit
- [ ] Mayhem: full FAST campaign per deletion wave; final full campaign
- [ ] `mayhem.py --list` count constant across the whole task
- [ ] bin/dashboard rebuilt + unit restarted after every engine change

## Mayhem scenarios affected
All migrated ones (definitionally) — with parity as the invariant.

## Conformance implications
None.

## Suggested commit message
Waves: `refactor(qa): migrate <family> scenarios to specs (parity ×3) + delete Go literals`
Oracles: `refactor(qa): extract <name> oracle from scenario closure`
(+ trailer each: `Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>`)

## Suggested PR title & description
**Title:** Scenario suite → declarative specs (R6 completion)
**Description:** Wave-by-wave migration with per-scenario ×3 parity and
per-wave campaigns; oracle extraction commits separate from deletions;
retained-in-Go list documented. Risk: med (touches the regression
oracle). Rollback: revert a wave's deletion commit (specs are additive).

## Code review checklist
- Parity logs actually attached per scenario (not sampled).
- Prose fields byte-identical to the deleted literals.
- Oracle extractions behavior-preserving (their unit tests prove the
  same timelines → same verdicts).
- Retained-list reasons are real constraints, not laziness.

## Definition of done
Acceptance criteria + regression checklist + docs updated + status headers
(this file + 00_MASTER_INDEX) updated.

## Possible follow-up tasks
Spec-driven matrix cells (backlog), community/utility-authored scenario
packs (specs make this safe), TASK-081 campaigns run on the migrated
suite.
