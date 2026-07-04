# TASK-061 — Migrate import + generation constraints

*Status: TODO · Phase: P5 · Effort: L (≈8 h) · Difficulty: high · Risk: high*

## Objective
The import-limit rule (`applyImportLimitRule` + `impGuard` +
`checkImportConvergence`) and the generation-limit rule
(`applyGenLimitRule` + `genGuard` + `restoreOnGenLimitClear` +
`checkGenLimitConvergence`) live in the constraint package as
`ImportConstraint` and `GenLimitConstraint` with typed sessions, follow the
060 pattern (shadow → targeted scenarios ×3 → flip → full campaign), and
the legacy paths short-circuit when active. The meter-independent
generation floor is preserved verbatim.

## Background
All verified in `lexa-hub/internal/orchestrator/optimizer.go`:
- **Import:** `impGuard` (:31-37) — 5 fields: `dischargeW, safeCount,
  evSafeCount, activeLimitW, breachTicks`. `applyImportLimitRule`
  (:1974+): sticky discharge command with relax-cycle ramp-down
  (anti-oscillation, see the struct comment), EV resume gated on
  `evSafeCount` + `EVImportCooldownCycles`; guard session tracked by a
  tolerance band on the limit value (:1988, mirrors the gen fix; QA
  2026-07-01). `checkImportConvergence` (:1437-1493): leaky counter,
  `importBreachTicks = 3` (was 5; lowered after the battery-soc-refuse
  timing race, comment :1426-1436), **NaN-holds** — a NaN meter tick holds
  the counter rather than draining it (V3 Issue-3 semantics; test
  `TestCheckImportConvergence_NaNTickHoldsCounter`,
  convergence_test.go:300).
- **Generation:** `genGuard` (:47-51) — `activeLimitW, overCount`.
  `checkGenLimitConvergence` (:1344-1425): cap-session tolerance band
  (resets only on MEANINGFUL cap change, > `complianceBreachW` — bit-exact
  reset was the reject-write/enable-gate nondeterminism), leaky counter
  `genBreachTicks = 3`, and the **meter-independent floor**
  (:1368-1389): `generation ≥ export − batteryDischarge` from the site
  energy balance, so a device that ECHOES the commanded limit while still
  generating full output is caught (audit: enable-gate-curtail). **That
  floor is a hard preserve.** `restoreOnGenLimitClear` (:1251+) +
  `genCapActive` (:164-167): explicit uncurtail on the cap→NaN release
  edge (audit: curtailment-release Mode A).
- Tests: `convergence_test.go:106-150` (meter floor + battery-discharge
  no-false-trip), `:239-331` (import counter semantics incl. NaN-hold and
  cap-drift session), `optimizer_compliance_test.go:126-323`
  (import raises plan setpoint; battery-floored breach; headroom no-breach).

## Why this task exists
W1/R4 continuation: with export (060) proven, import and generation
complete the compliance tier of the constraint controller, emptying the
cascade's CSIP-enforcement core ahead of 062/063.

## Architecture review sections
W1 · R4 · §8.1 · 02 AD-007 · 03 §P5 · 08 RSK-01/RSK-03 · 05 §12.

## Prerequisites
TASK-060 DONE (flipped and holding). Bench FAST. One radioactive-zone task
at a time — do not overlap with 062/064.

## Files
- **Read first:** optimizer.go sections above; `constraint/export.go`
  (the pattern), `constraint/arbiter.go`; `convergence_test.go`,
  `optimizer_compliance_test.go`.
- **Modify:** `cmd/hub/config.go`/`configs/hub.json` (add `"import"`,
  `"gen"` to the constraints mode map), `cmd/hub/main.go`,
  `optimizer.go` (two guarded short-circuits, nothing deleted).
- **Create:** `constraint/importlimit.go`, `constraint/genlimit.go`,
  matching `*_session.go` and `*_test.go`.

## Blast radius
`internal/orchestrator` (radioactive). cmd/hub config. No bus schema
change. Import/gen Mayhem scenario families are the contract.

## Implementation strategy
Same port-don't-redesign discipline as 060, two constraints in one task
because they share the leaky-counter/tolerance-band pattern — but they
flip SEPARATELY (gen first, then import; gen has the richer scenario
family to validate against). Each gets its own session struct, its own
config key, its own targeted-scenario gate; one full campaign after both
are active.

## Detailed steps
1. `GenLimitConstraint`: port curtail demand (solar-ceiling max = cap
   share), release-edge explicit uncurtail (session field replacing
   `genCapActive`), convergence counter with the tolerance-band session
   reset and the meter floor VERBATIM (copy the :1368-1389 block with its
   comment). Emits Breach{LimitType:"generation"} at threshold.
2. `ImportConstraint`: port sticky discharge + relax ramp-down +
   EV-resume cooldown into `ImportSession` (5+ fields, one per impGuard
   field, documented with line refs); convergence counter with NaN-hold.
   Emits Breach{LimitType:"import"} with `batteryHeadroomReason`-
   equivalent context (optimizer.go:2199+).
3. Port the behavioral tests for both (constraint-package twins driving
   multi-tick sequences); mutation-verify: unwire the meter floor → the
   echoed-report test must fail; unwire NaN-hold → the NaN test must fail.
4. Wire config modes; unit-test one-author-per-axis with export+gen+import
   all active (the battery-setpoint axis is shared by import discharge and
   export absorb — the arbiter must resolve, and a test must pin which
   wins under a simultaneous import+export cap, matching legacy cascade
   output on the same input).
5. Shadow both (`gen: shadow`, `import: shadow`) ≥3 bench days including
   one campaign; divergence ~0 on their axes.
6. Flip gen: `--only reject-write-curtail,enable-gate-curtail,
   ramp-limit-curtail,ack-before-effect,curtailment-release` ×3; hold 1 day.
7. Flip import: `--only battery-soc-refuse,battery-empty-import-cap` ×3.
8. Full FAST campaign with export+gen+import active; compare to baseline.

## Testing changes
Constraint-package twins of every import/gen test named above + the
simultaneous-cap arbitration test + mutation checks. Run:
`make test` (lexa-hub); `scripts/mayhem.py --only …` per steps 6-8.

## Documentation changes
- Preservation ledger: gen/import entries → new homes + test names.
- lexa-hub CLAUDE.md: update `checkGenLimitConvergence` bullet (names the
  meter floor) to point at constraint/genlimit.go.
- 02 AD-007 progress note.

## Common mistakes to avoid
- Draining the import counter on a NaN tick (it HOLDS — V3 Issue-3; the
  drain-vs-hold distinction is one character and a QA regression).
- Resetting the gen session on bit-exact cap inequality — the decoded cap
  jitters via the watts→ActivePower×10^mult bus round-trip; the tolerance
  band (> complianceBreachW) is the fix (optimizer.go:1349-1358).
- Losing the release-edge uncurtail (curtailment-release Mode A) — an
  early-out on NaN cap that forgets the transition leaves inverters
  clamped.
- Letting economics (TOU discharge) widen an import-cap battery bound —
  arbiter narrowing-only property.
- Flipping both constraints in one step — separate flips, separate
  attribution.
- Deploy gotchas: `hub-replay-tune.sh fast` after deploy; systemctl not
  `pkill -f`.

## Things that must NOT change
Preservation-ledger entries:
- Meter-independent floor `gen ≥ export − batteryDischarge` ↔
  **enable-gate-curtail** (echoed-limit fraud caught) and
  **reject-write-curtail**.
- Leaky counters + threshold 3 (≈9 s) ↔ **ramp-limit-curtail** /
  **ack-before-effect** (normal ramps ride out; sustained miss escalates
  inside the compliance window).
- NaN-hold ↔ stale/blind meter during an import cap (**stale-meter**,
  **battery-soc-refuse**).
- EV import cooldown ↔ **battery-empty-import-cap** (EV must not resume
  during over-discharge settling).
- Release-edge uncurtail ↔ **curtailment-release**.
- Tier-1 safety loop untouched; V6 baseline defended.

## Acceptance criteria
- [ ] Shadow gate met for both axes; evidence attached.
- [ ] Gen flip: 5 targeted scenarios ×3 at accepted verdicts.
- [ ] Import flip: 2 targeted scenarios ×3 at accepted verdicts.
- [ ] Full FAST campaign ≤ baseline with three constraints active.
- [ ] Mutation checks recorded (meter floor, NaN-hold, churn still green).

## Regression checklist
- [ ] `go test -race ./internal/...` (lexa-hub) green
- [ ] Conformance logic tests: none
- [ ] Mayhem: full FAST campaign (mandatory)
- [ ] Rollback drill: each constraint individually back to `shadow` once

## Mayhem scenarios affected
reject-write-curtail, enable-gate-curtail, ramp-limit-curtail,
ack-before-effect, curtailment-release, battery-soc-refuse,
battery-empty-import-cap, stale-meter, perfect-storm.

## Conformance implications
CannotComply for generation/import breaches must keep current latency
(threshold 3 ≈ 9 s at tuned tick); IEEE 2030.5 Response semantics
unchanged.

## Suggested commit message
`feat(orchestrator): Import/GenLimit constraints with ported sessions (meter floor + NaN-hold preserved)`
(+ trailer: `Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>`)

## Suggested PR title & description
**Title:** P5 flips 2-3: generation + import constraint migration
**Description:** Ports both rules + convergence checkers into the
constraint package; separate config-gated flips with scenario evidence;
meter-independent floor and NaN-hold semantics preserved verbatim and
mutation-verified. Risk: HIGH — 03 §P5 gates applied. Rollback: per-
constraint config to `shadow`.

## Code review checklist
- Meter-floor block byte-comparable to optimizer.go:1368-1389 (modulo
  receiver plumbing).
- Counter semantics: leaky, capped at threshold, NaN-hold (import),
  tolerance-band session resets.
- Shared battery-axis arbitration pinned by test against legacy output.

## Definition of done
Acceptance criteria + regression checklist + docs updated + status headers
(this file + 00_MASTER_INDEX) updated.

## Possible follow-up tasks
TASK-062 (battery guard-state consolidation), TASK-064 (parameterize),
TASK-065 (multi-device breach list feeds on these constraints).
