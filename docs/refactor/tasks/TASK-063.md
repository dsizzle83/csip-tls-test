# TASK-063 — Economic layer isolation (TOU / self-consumption / planner below constraints)

*Status: DONE — code-complete, full-stack shadow-wired (2026-07-06, lexa-hub `ad27f1c`) · Phase: P5 · Effort: L (≈6–8 h) · Difficulty: med · Risk: med*

> **Completion note (2026-07-06, batched-deadline scope).** SHADOW-ONLY per the
> Principal's launch: the legacy `Optimize()` cascade is untouched and remains
> authoritative. Delivered: `EconomicsConstraint` (TierEconomics) porting Rules
> 2/2.5/4/5/6 as PointDemand proposals; tier-aware arbiter making
> economics-below-compliance STRUCTURAL; battery safety post-arbitration
> (wrong-direction lag closed) + `RecordCommands` wiring; EV connector carried
> through the demand key; full stack (safety+compliance+economics) registered in
> the TASK-059 shadow Wrapper (`cmd/hub`). Golden in-process shadow parity vs the
> real cascade at **0 divergence off-cap**; economics-clamped-by-compliance
> mutation tests green; `go test -race ./internal/orchestrator/...` green.
> **Deferred to the P5 wave (Principal-gated):** the bench shadow campaign (step
> 5/7), the ≥3-bench-day soak spanning a TOU peak, and the `economics: active`
> flip — none doable in the deadline window; the controller is proven, the flip
> is soak-gated. On-cap shadow divergence is CHARACTERISED (not bit-matched) as
> the TASK-064 finding — see `docs/refactor/notes/TASK-063-seam-review.md`. The
> step-6 written review (battery-reserve × 3 tiers, first-active-EVSE) is in that
> same note. Config `economics: off|shadow|active` mode (step-4 wiring) was NOT
> added — the shadow uses the existing `ConstraintShadow` flag; the per-constraint
> mode toggle lands with the flip (TASK-066 territory).

## Objective
The economic rules — TOU peak discharge, self-consumption, plan-following
(24 h DP planner) — run as a distinct economics layer strictly BELOW the
constraint controller: they PROPOSE device targets; the compliance and
safety tiers DISPOSE (narrow or veto). The seam is documented, the arbiter
enforces it structurally (economics can never widen a compliance bound),
and battery-reserve + first-active-EVSE logic get a written review (the
single-EVSE fix itself lands in TASK-065).

## Background
Verified economics inventory in `lexa-hub/internal/orchestrator`:
- **Rule 2.5 plan-following:** `applyPlanRule` (optimizer.go:496-580) —
  applies `state.DailyPlanTarget` battery setpoint + EV current; skipped
  when CSIP mandates `OpModFixedW` (:295-298). Targets come from the DP
  planner: `DailyPlanner.Plan(PlannerParams) *DailyPlan` (planner.go:183),
  re-run by `Engine.plannerLoop()` every `ReplanIntervalS` (default 15 min,
  engine.go:321-346) on its own goroutine; `Engine.tick()` reads
  `dailyPlan.CurrentTarget(serverTime)` into the SystemState
  (engine.go:536-540).
- **Rule 4 self-consumption:** `applySelfConsumptionRule` — solar surplus
  → battery, gated on `ExcessSolarThreshold`/`SOCFullThreshold` (:321-323).
- **Rule 5 TOU:** `o.CostModel.IsPeakHour(serverNow)` with
  `serverNow = time.Unix(now.Unix()+state.ClockOffset, 0)` (:324-330;
  costmodel.go:64-68) — battery discharge during expensive hours.
- **Rule 6 EV charging allocation:** `applyEVChargingRule` (:351-357) —
  remaining budget to EVSEs, suppressed by import cooldown.
- Rules 4/5 already only run when `!planFollowed` (:320); Rule 2.5 only
  when no fixed dispatch — i.e., precedence exists but is encoded as
  if-guards inside one function, invisible to the arbiter.
- Battery reserve: economics respect `SOCReserve` (default 20 %) as a
  discharge floor; compliance (import) also discharges to reserve;
  safety disconnects AT reserve on wrong-direction — three tiers touch
  one number (review this seam, step 6).

## Why this task exists
R4's second half: after 060-062 the compliance/safety tiers are explicit,
but economics still lives inside the legacy cascade where its precedence
is implicit if-nesting (W1). AD-007: "economics propose, constraints
dispose" must be structural, not conventional, before the cascade can be
deleted (066).

## Architecture review sections
W1 · R4 · 02 AD-007 (economic layer strictly below; DP planner stays
as-is unless shadow diffs implicate it) · 03 §P5 · §8.5 (single-EVSE noted,
fixed in 065) · 05 §1.

## Prerequisites
TASK-062 DONE. Solo radioactive-zone window. Bench FAST.

## Files
- **Read first:** optimizer.go:262-380 (cascade order + skip conditions),
  :496-641 (applyPlanRule/applyFixedDispatchRule), Rule 4/5/6 bodies;
  planner.go:16-130 (params/plan types); engine.go:321-372 + :496-560;
  costmodel.go; `constraint/arbiter.go`.
- **Modify:** `cmd/hub/config.go`/`configs/hub.json` (constraints map:
  `"economics"` mode), `cmd/hub/main.go`, optimizer.go (short-circuit
  when active).
- **Create:** `constraint/economics.go` (+`economics_test.go`) — one
  economics constraint at `TierEconomics` wrapping the three proposal
  sources (plan-following, self-consumption, TOU) + EV allocation.

## Blast radius
`internal/orchestrator` + constraint package + cmd/hub config. The DP
planner itself is NOT modified (AD-007 open question keeps it as-is);
only where its output enters the tick. No bus schema change.

## Implementation strategy
Port the four economic rules as proposal-emitters at `TierEconomics`
producing point-target demands (setpoint intervals of width 0 — the
arbiter narrows them against compliance bounds; if a compliance tier
already bounds the axis, the economics proposal is clamped into the bound,
reproducing today's "limit rules still run after plan rule" behavior,
:291-294 comment). Keep the internal precedence (fixed-dispatch > plan >
self-use/TOU) INSIDE the economics constraint, mirroring the legacy
if-structure, so shadow diffs isolate tier-seam changes from
intra-economics changes.

## Detailed steps
1. `EconomicsSession`: port the small cross-tick pieces the rules use
   (inventory during the read — e.g. EV cooldown interaction is import-
   session-owned already after 061; confirm and document what remains;
   expected: little to none).
2. `EconomicsConstraint.Evaluate`: fixed-dispatch check → plan target →
   (else) self-use + TOU → EV allocation, emitting proposals with
   `Source` strings naming the sub-rule for diagnostics.
3. Arbiter check: add a test proving a TOU discharge proposal is clamped
   by an active import cap, and a plan-rule EV current is clamped by an
   export cap — outputs equal to the legacy cascade on identical
   multi-tick inputs (golden-sequence tests reusing 059's diff machinery
   in-process).
4. Document the seam: `constraint/doc.go` + a short
   `docs/` note in lexa-hub (or CLAUDE.md section): "economics may only
   propose; a proposal never relaxes a compliance/safety bound; CSIP
   fixed dispatch is economics-tier input, not compliance" (it is a
   *target*, not a limit — mirror legacy Rule 2 placement; verify
   `applyFixedDispatchRule` consequences before finalizing this wording).
5. Wire `economics: off|shadow|active`; shadow ≥3 bench days incl. one
   campaign (TOU/plan divergences show up across peak boundaries — make
   sure the soak spans at least one simulated peak window; the bench TOU
   schedule is DefaultTOUCostModel 16:00-21:00 peak).
6. Written review (PR appendix, no code): battery-reserve interactions
   across tiers (economics floor vs import-cap discharge vs safety
   disconnect — name the winner per pair) and first-active-EVSE selection
   (optimizer.go:721-728) — confirm single-EVSE assumption is contained in
   export/EV allocation and list what TASK-065 must change.
7. Flip; `--only expired-control,grid-disconnect,conflicting-primacy,
   battery-empty-import-cap` ×3 (CSIP-precedence-sensitive set), then full
   FAST campaign.

## Testing changes
- Golden-sequence equivalence tests (legacy vs stack, multi-tick, covering
  plan-following + TOU + self-use under each cap type).
- Clamping tests per step 3.
- Run: `make test`; scenarios per step 7.

## Documentation changes
- Seam documentation (step 4).
- 02 AD-007: economics-layer decision + the fixed-dispatch classification.
- Preservation ledger: plan/TOU/self-use entries.

## Common mistakes to avoid
- Reclassifying CSIP fixed dispatch (OpModFixedW) as a compliance
  constraint without checking legacy semantics — in the cascade it is
  Rule 2 (above plan, below disconnect) and limit rules still constrain
  its result; keep that exact relationship.
- Letting the DP planner goroutine interact with the constraint stack
  directly — it feeds `SystemState.DailyPlanTarget` only (engine seam
  unchanged).
- Widening: an economics proposal outside a compliance bound must CLAMP,
  not error and not drop (dropping changes EV-resume behavior).
- Running the shadow soak entirely off-peak — TOU divergence would be
  invisible.

## Things that must NOT change
- CSIP precedence: disconnect > fixed dispatch > everything (Rule 1
  early-return stays in force wherever it ends up).
- `plannerLoop` cadence, DP algorithm, `PlannerCfg` semantics (AD-007:
  planner untouched).
- Preservation entries: plan-following suppressed under fixed dispatch;
  Rules 4/5 suppressed when plan followed; EV import-cooldown suppression
  (**battery-empty-import-cap**); TOU uses SERVER time via ClockOffset
  (**clock-jitter/clock-jump-forward** family — serverNow computation
  verbatim).
- V6 baseline.

## Acceptance criteria
- [ ] Golden-sequence equivalence: legacy vs economics-active outputs equal
  (within 059 tolerances) across the covered scenarios.
- [ ] Clamping property tests green; arbiter never widened by economics.
- [ ] Step-6 written review attached to the PR.
- [ ] Targeted ×3 + full FAST campaign ≤ baseline.

## Regression checklist
- [ ] `go test -race ./internal/...` (lexa-hub) green
- [ ] Conformance logic tests: none
- [ ] Mayhem: full FAST campaign (mandatory)
- [ ] Shadow soak spanned ≥1 TOU peak boundary

## Mayhem scenarios affected
conflicting-primacy, expired-control, grid-disconnect,
battery-empty-import-cap, clock-jitter (TOU serverNow leg), perfect-storm.

## Conformance implications
CSIP §12.3 precedence behavior must be preserved (scheduler resolves
programs; hub-side precedence between control types unchanged).

## Suggested commit message
`refactor(orchestrator): economics tier (plan/TOU/self-use/EV) proposes below constraints`
(+ trailer: `Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>`)

## Suggested PR title & description
**Title:** P5: economic layer isolated below the constraint controller
**Description:** Rules 2/2.5/4/5/6 ported as TierEconomics proposals;
clamping enforced by the arbiter; golden-sequence equivalence + campaign
evidence; battery-reserve & single-EVSE review appended. Risk: med.
Rollback: `economics: shadow`.

## Code review checklist
- Fixed-dispatch classification argued from legacy code, not assumption.
- Golden sequences actually cover plan/TOU/self-use × each cap type.
- Reserve-interaction review complete (three tiers × pairwise winners).

## Definition of done
Acceptance criteria + regression checklist + docs updated + status headers
(this file + 00_MASTER_INDEX) updated.

## Possible follow-up tasks
TASK-065 (first-active-EVSE → all-active), TASK-066 (cascade deletion),
backlog: planner-vs-constraint interaction revisit if shadow diffs
implicate the DP (AD-007 open question).
