# TASK-054 — Guard-threshold dither sweeps (SoC@reserve, export@breach)

*Status: TODO · Phase: P4 · Effort: M (≈4–6 h) · Difficulty: med · Risk: low*

## Objective
Add Mayhem scenarios that drive measurements in a small ±ε oscillation
exactly at the optimizer's guard thresholds — battery SoC at the 20% reserve
and metered export at the `complianceBreachW` boundary — for ≥5 minutes, and
assert breach-seconds stay bounded, INV-HUNT stays clean, and CannotComply
fires iff the breach is sustained (never on the dither alone). Stable 10×
before curation.

## Background
Repo `~/projects/csip-tls-test`. GAP-08 / review §9: "SoC dithering exactly
at reserve, export dithering at `complianceBreachW`: leaky counters are
believed hold-biased, but no one has swept the boundary; INV-HUNT only
catches sustained oscillation." The suite's static faults hold the world
still; dither is the dynamic stressor at the exact decision line.

Verified thresholds (in `~/projects/lexa-hub/internal/orchestrator/optimizer.go`):
- `SOCReserve` default **20.0** (%) — set on the optimizer
  (optimizer.go:227); the reserve guards (`applyDemandResponseRule` skip,
  `criticalBatteryInversion`, `dischargingAtReserve` at
  optimizer.go:1580: `b.PowerW > complianceBreachW && b.SOC <= o.SOCReserve`)
  fire at/below reserve.
- `complianceBreachW` = **100.0** (W) (optimizer.go:2188) — the tolerance
  band on every convergence/breach check
  (`actualExportW > exportLimitW + complianceBreachW`, optimizer.go:1211,
  1148; gen/import equivalents). The leaky breach counters
  (`expOverTicks`, `genGuard.overCount`, `impGuard.breachTicks`) increment
  over-cap and decay under-cap — "hold-biased" means a value dithering
  around the line should NOT accumulate to a false CannotComply.

Injection helpers (verified):
- Battery SoC: `d.post("battery", "/inject", {"SoC_pct": X})` — batsim
  `pendingSoC` (sim/southbound/battery.go:49,138). Dither X around 20.
- Meter/export: the harness `d.injectEnv(pvW, loadW)` posts
  `solar /inject {W_W}` and `meter /inject {LoadW_W}` (mayhem.go:2244);
  metersim linked mode computes net export from solar − load
  (sim/metersim/main.go:102 `LoadW_W`). To dither EXPORT around the cap+band,
  hold PV high and dither the LOAD by ±ε so net export crosses
  `cap + complianceBreachW` back and forth (load down ⇒ more export). A
  zero-export cap (0 W) with export dithering around ~100 W exercises the
  band directly.

Oracles already exist: `diagnoseConstraint` (mayhem.go:679) +
`safetyAudit`'s `invHunt` (invariants.go, hysteresis 300 W, settling-gated)
+ `invSOC` (battery over-discharge past reserve). The scenario's job is to
drive the dither and let these judge; the NEW assertion is the biconditional
"CannotComply iff sustained" — read `CannotComply` sampled field
(mayhem.go:90) and require it FALSE during pure dither, TRUE only if the
scenario also drives a sustained over-band excursion.

Duration: "≥5 min" = HoldS ≈ 300+ (the longest scenarios today are ~100 s).
This is a deliberately long scenario — note the campaign-time cost
(RSK-12); it may run in the extended/nightly set, not every FAST campaign.

## Why this task exists
GAP-08 / §9 value-domain family: the belief that leaky counters are
hold-biased is untested at the boundary; a hunting or false-CannotComply
regression here is invisible to static scenarios.

## Architecture review sections
§9 value-domain family (threshold dither), item 12. Roadmap: 07 GAP-08
(validation: "breach-seconds bounded, INV-HUNT clean, CannotComply fires
iff sustained"); 06 §2 (10× solo).

## Prerequisites
Bench FAST (`bench-up.sh --fast`). No SSH/mqttproxy needed (pure simapi
injection). No product dependency (tests existing guards).

## Files
- **Read first:**
  - `~/projects/lexa-hub/internal/orchestrator/optimizer.go` (lines 40–75 breach constants; 1140–1220 export breach; 1560–1600 reserve/inversion; 2188 complianceBreachW)
  - `~/projects/csip-tls-test/cmd/dashboard/mayhem.go` (injectEnv 2244, postCap 2268, diagnoseConstraint 679, sample fields 56–95, invSOC via safetyAudit)
  - `~/projects/csip-tls-test/cmd/dashboard/invariants.go` (invHunt hysteresis/settling; invSOC; safetyAudit)
  - `~/projects/csip-tls-test/sim/southbound/battery.go` (SoC inject), `sim/metersim/main.go` (LoadW_W)
- **Modify:**
  - `~/projects/csip-tls-test/cmd/dashboard/mayhem.go` (add scenarios in `scenarios()`), or `mayhem_world.go` if grouping with dynamic-environment scenarios (pv-flicker is there — a natural neighbor)
- **Create:** none.

## Blast radius
Harness only. No product code, no SSH, no filesystem. Long-running scenarios
add campaign wall-clock (RSK-12) — gate them into the extended set.

## Implementation strategy
Two (optionally three) scenarios reusing the export-cap / battery preamble,
with `perTick` driving a square or sine ±ε around the threshold, judged by
the existing constraint + safety oracles plus the CannotComply biconditional.
A shared `perTick` dither helper keeps the cadence consistent.

## Detailed steps
1. Scenario `export-dither-at-breach` (Category: "Value-domain (INV-EXPORT/
   INV-HUNT)", HoldS ≈ 300):
   - Hypothesis: metered export oscillates ±ε across `cap + complianceBreachW`
     (~100 W band) for 5 min — sensor noise / a flickering load at the exact
     decision line.
   - Expected: the cap holds (bounded breach-seconds), the loop does NOT
     hunt (INV-HUNT clean via the 300 W hysteresis + settling gate), and NO
     CannotComply is posted for a dither that never SUSTAINS over the band.
   - setup: full battery + high PV; `postCap("exportCap", 0, 300, …)`.
   - perTick: hold PV high; dither load so net export crosses the band:
     alternate `injectEnv(pvHigh, loadLow)` and
     `injectEnv(pvHigh, loadLow + Δ)` every ~4 s where Δ is sized (from the
     baseline PV/load) so export swings ~50→~150 W (straddling the ~100 W
     band around a 0 cap). Keep the swing SMALL and BELOW a sustained
     breach — the point is dither, not a real over-cap hold.
   - evaluate: `diagnoseConstraint` (bounded breach) + extend the finding:
     assert `!any(sample.CannotComply)` (biconditional's "not sustained ⇒
     no CannotComply" half) and INV-HUNT clean (safetyAudit already runs it;
     surface a FAIL if it flags).
2. Scenario `soc-dither-at-reserve` (Category: "Value-domain (INV-SOC)",
   HoldS ≈ 300):
   - Hypothesis: battery SoC dithers ±ε across the 20% reserve for 5 min
     (a nearly-empty pack under a discharge demand), where the reserve guard
     toggles.
   - Expected: no over-discharge past reserve (INV-SOC clean), no
     command hunting (battery connect/setpoint not flapping — INV-HUNT /
     no chatter), stable behavior at the line.
   - setup: arm a discharge demand (e.g. a TOU-peak or import cap that would
     discharge the battery — reuse an existing import/DR preamble; simplest:
     `postCap("importCap", <low>, 300, …)` with a load so the optimizer
     wants battery discharge), then inject SoC ~20.
   - perTick: dither `d.post("battery","/inject",{"SoC_pct": 19 or 21})`
     every ~4 s; keep env steady.
   - evaluate: a custom ladder using `invSOC` (via safetyAudit) + battery
     command-stability: FAIL on any post-settling INV-SOC violation
     (discharge past reserve) or sustained command flapping; DEGRADED on
     bounded transient; PASS on clean hold. (invSOC already excuses the
     setup settling transient via `pastSettling`, invariants.go.)
3. (Optional third) `import-dither-at-breach` — mirror export for the import
   cap if time permits; lower priority.
4. Sizing ε: derive from the baseline (`d.pvHighW` is set at baseline;
   `loadLow=250`). Compute Δ so export peaks just above `cap + 100 W` and
   troughs well below — verify empirically in a first run (adjust Δ, never
   the oracle margins — 06 §4.5).
5. Rebuild `bin/dashboard`, restart csip-dashboard.
6. Validate 10× solo each; full (extended) campaign. Mark these
   `HoldS≈300` scenarios as extended-set in a comment so the standard FAST
   campaign can exclude them for time (they run in nightly / release gates).
7. **Control run** (proves acceptance criterion 3's other half):
   temporarily raise the dither amplitude/offset so the over-band phase is
   sustained > `scaleTicks(exportBreachTicks)` ticks; run
   `python3 scripts/mayhem.py --only export-dither-at-breach` once; confirm
   CannotComply posts; revert the parameter — do NOT commit the variant.

## Testing changes
- `cmd/dashboard`: pure test for the dither-cadence helper + the
  CannotComply-biconditional check if extracted.
- HIL: 10× solo each + one extended campaign including them.
- `make test-fast` unaffected.

## Documentation changes
- `docs/QA_FINDINGS.md`: scenarios + verdicts + observed counter behavior at
  the boundary (confirms/refutes the hold-bias belief — new knowledge).
- csip-tls-test CLAUDE.md Mayhem count + a note that these are long
  (extended-set) scenarios.

## Common mistakes to avoid
- Do NOT drive a SUSTAINED over-band excursion in the pure-dither
  scenario — that would (correctly) trip CannotComply and defeat the
  biconditional test. Keep the dither's over-band phase SHORTER than the
  breach-tick threshold (`exportBreachTicks=3` ≈ 9 s FAST) so no phase
  sustains.
- The 300 W INV-HUNT hysteresis (invariants.go) means the dither amplitude
  must be chosen relative to it: too small and INV-HUNT can't fire even on
  real hunting (masking a bug); too large and it's not "dither". Aim the
  export swing to straddle the CAP by ~±50–100 W (inside the 300 W
  hysteresis so only genuine chase-cycles, not the injected dither, would
  flag) — this is exactly the boundary the test probes.
- Size ε from the measured baseline, and tune ε (not oracle margins) if the
  swing over/undershoots.
- SoC dither must not fight the batsim animation — `pendingSoC` overrides
  the sine (battery.go:49); re-inject each dither tick so it sticks.
- Long HoldS = long runs; mark extended-set to protect FAST campaign time
  (RSK-12).
- Rebuild `bin/dashboard` (D8). Unique IDs.

## Things that must NOT change
- Existing scenario verdicts/baselines (V6), especially `pv-flicker`
  (dynamic-environment neighbor), `export-cap-full-battery`,
  `battery-soc-refuse`, `battery-wrong-sign` (reserve/inversion family).
- Oracle margins: `complianceBreachW` (product), `invHuntHysteresisW=300`,
  `mayConvergeDeadlineS/HoldS` — NONE tuned to pass (06 §4.5); only ε
  (injected amplitude) is adjustable.
- INV-SOC / INV-HUNT / INV-EXPORT definitions.
- Product guards (`expOverTicks` leaky counter, reserve checks) — the test
  probes them, must not require changes to pass (a failure is a real
  finding — pin it, e.g. expected-FAIL if it exposes hunting).

## Acceptance criteria
- [ ] `--list` shows `export-dither-at-breach`, `soc-dither-at-reserve`
      (+ optional import).
- [ ] 10× solo stable; pure-dither runs post NO CannotComply and keep
      INV-HUNT/INV-SOC clean; breach-seconds bounded.
- [ ] The CannotComply biconditional verified: the step-7 control run of
      the SAME scenario with a SUSTAINED excursion DOES post
      CannotComply — proving the oracle isn't just always-false.
- [ ] Extended campaign including the dither scenarios ≤ baseline; any
      hunting/false-CannotComply exposed is pinned as a finding.
- [ ] Scenarios marked extended-set (long HoldS) in code + docs.

## Regression checklist
- [ ] `make test-fast` + `go test ./cmd/dashboard/` green
- [ ] Conformance logic tests: none (harness)
- [ ] Mayhem: 10× solo each + one extended campaign
- [ ] `bin/dashboard` rebuilt + csip-dashboard restarted before validation

## Mayhem scenarios affected
Adds `export-dither-at-breach`, `soc-dither-at-reserve` (+ optional import).
Neighbors: `pv-flicker`, `control-churn` (dynamic), `battery-soc-refuse`,
`battery-wrong-sign`, `export-cap-full-battery`. No verdict changes expected
elsewhere.

## Conformance implications
None (harness). Validates that the client does not spuriously self-report
CannotComply (a 2030.5 Response) on sensor noise — over-reporting
noncompliance is its own protocol/operational problem.

## Suggested commit message
`feat(mayhem): guard-threshold dither sweeps at SoC-reserve and export-breach (GAP-08, TASK-054)`

Trailer: `Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>`

## Suggested PR title & description
**Title:** Mayhem: threshold-dither sweeps (SoC@reserve, export@breach) (GAP-08, TASK-054)
**Description:** Long-running (~5 min) scenarios oscillating measurements
±ε at the optimizer's decision lines; asserts bounded breach-seconds,
INV-HUNT/INV-SOC clean, and CannotComply iff sustained (biconditional
proven with a control run). Extended-set (campaign-time note). Confirms the
leaky-counter hold-bias belief with data. Evidence: 10× solo + extended
campaign. Rollback: revert; additive.

## Code review checklist
- Pure-dither never sustains over-band (< breach-tick window per phase).
- ε sized to straddle the cap within the 300 W hysteresis; only ε tuned.
- CannotComply biconditional has both halves demonstrated.
- Extended-set marking present; SoC re-injected each dither tick.

## Definition of done
Acceptance + regression checklists green; QA docs updated; status headers
updated (this file + 00_MASTER_INDEX).

## Possible follow-up tasks
TASK-056/062 (behavioral tests + per-constraint sessions — dither becomes a
unit-level property once the constraint controller exists), backlog: dither
as a matrix modifier over more caps.
