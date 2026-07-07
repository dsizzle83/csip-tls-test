# TASK-064 — plant-parameter reference & constant→plant swap map

*PR appendix + the 09 "plant-model parameters documented per supported device"
artifact. Companion to AD-007's TASK-064 note and the TASK-063 seam review. Written
reference, no code.*

The bench-calibrated globals that used to live in `optimizer.go` (and were ported
verbatim into `internal/orchestrator/constraint/export.go` by 060–063) now read the
per-device plant model (TASK-057, `internal/orchestrator/plantmodel.go`). The bench
`hub.json` plant blocks reproduce the legacy numbers EXACTLY, so bench behaviour is
identical; the point is that a real vendor device supplies its OWN numbers.

## 1. Constant → plant swap map

| Legacy constant (optimizer.go) | Value | Plant field | Conversion at the consuming edge | Bench value reproduced |
|---|---|---|---|---|
| `filterAlpha` (:696) | 0.4 | `MeterPlant.FilterAlpha` | direct (EMA coefficient) | 0.4 (explicit tuned override) |
| `socTaperStart` (:778) | 80.0 % | `BatteryPlant.SOCTaperStartPct` | direct | 80 |
| `socStepEstimate` (:787) | 1.0 %/tick | `BatteryPlant.SOCStepPctPerTickOverride` | direct (explicit override — see §3) | 1.0 |
| `battConvergeFrac` (:72) | 0.5 | `BatteryPlant.ConvergeFrac` | direct | 0.5 |
| `maxDropW` (:1060) | 1500 W/tick | `InverterPlant.MaxRampDownWPerS` | `× TickSeconds` | 500 W/s × 3 s = 1500 |
| `maxRiseW` (:1061) | 500 W/tick | `InverterPlant.MaxRampUpWPerS` | `× TickSeconds` | 166.67 W/s × 3 s ≈ 500 |

`WithDefaults()` in `plantmodel.go` is the single source of the bench values (the
`bench*` provenance constants). A device with no plant block, or a partial one, fills
from there — so a field unit without plant config keeps bench behaviour.

**NOT swapped (stay constants — the D6 boundary).** Breach-tick thresholds
(`exportBreachTicks`/`importBreachTicks`/`genBreachTicks`/`battBreachTicks` = 3) are
COMPLIANCE-LATENCY POLICY, not plant physics; the 05 §5 wall-clock rule already scales
them for cadence (`Session.ScaleTicks`). Also unchanged: controller gains
(`exportCeilGain`), EV deadband/step limits, `exportMarginFrac`, `exportRelaxCycles`,
`complianceBreachW`, `SOCFullThreshold` (a CSIP config default, not a plant number).

## 2. Parameter reference (per supported device — the 09 artifact)

Units are in the field name suffix (W, WPerS, S, Pct, KWh). "Datasheet field" is what
populates it for a real vendor device (TASK-075 fixtures).

### InverterPlant (smart inverter / PV string)
| Field | Unit | Bench | Meaning | Vendor datasheet source |
|---|---|---|---|---|
| `MaxRampDownWPerS` | W/s | 500 | how fast the export ceiling may TIGHTEN (defend the cap fast) | inverter active-power ramp-down limit / slew rate |
| `MaxRampUpWPerS` | W/s | 166.7 | how fast the ceiling may RELAX (give generation back slowly) | ramp-up / soft-start rate |
| `ControlLatencyS` | s | 3 | command→measured-effect lag (feeds the adaptive breach window) | setpoint response / settling time |

### BatteryPlant (storage)
| Field | Unit | Bench | Meaning | Vendor datasheet source |
|---|---|---|---|---|
| `CapacityKWh` | kWh | 10 | usable pack energy (feeds the derived-socStep backlog item) | pack nameplate energy |
| `SOCTaperStartPct` | % | 80 | SOC at which charge power begins its linear taper | BMS CV-knee / taper start |
| `SOCStepPctPerTickOverride` | %/tick | 1.0 | assumed SOC climb/tick for the taper pre-position — **legacy debt** (§3) | derive from CapacityKWh (see §3) |
| `ConvergeFrac` | frac | 0.5 | measured/commanded absorption floor before phantom-absorption curtail | inverter charge-command tracking accuracy |
| `ControlLatencyS` | s | 3 | charge-setpoint command→effect lag | BMS setpoint response |
| `TaperCurve` | points | nil | optional piecewise SOC→charge-frac override (vendor CV knee) | charge-current-vs-SOC curve |

### MeterPlant (revenue / CT meter)
| Field | Unit | Bench | Meaning | Vendor datasheet source |
|---|---|---|---|---|
| `MeterLagS` | s | 5 | export-reading refresh cadence (feeds the adaptive breach window) | meter reporting interval |
| `FilterAlpha` | frac | 0.4 | EMA low-pass on measured export (rejects meter/OCPP jitter) | derive from MeterLagS (`FilterAlphaFor`) or tune |

### EVSEPlant (EV charger)
| Field | Unit | Bench | Meaning | Vendor datasheet source |
|---|---|---|---|---|
| `MeterLagS` | s | 10 | OCPP MeterValues reporting cadence | charger telemetry interval |

## 3. socStep — why an explicit override, not the derived value

The physically-derived per-tick SOC climb is
`MaxChargeW × tickSeconds ÷ (CapacityKWh × 36000)` — for the bench pack (5 kW, 10 kWh,
3 s) ≈ **0.42 %/tick**, NOT the legacy 1.0. The legacy comment ("Calibrated for the
20× demo") makes the 1.0 a **deliberate conservative overestimate**: it errs HIGH so
the SOC taper hands off EARLY (never late — a late handoff would let charge power
overshoot the taper). TASK-064's mandate is identical bench behaviour, so switching to
0.42 is out of scope (a behaviour change the task's common-mistakes list explicitly
forbids). It is therefore an explicit `SOCStepPctPerTickOverride` (default 1.0, legacy
debt 05 §6), deliberately NOT derived so no silent change slips in. The derived-formula
migration is backlogged (10_BACKLOG, "Derived socStep") and needs its own soak.

## 4. FilterAlpha — the documented mapping the override stands in for

`FilterAlphaFor(meterLagS, tickS) = tickS / (meterLagS + tickS)` — a slower meter
(larger lag) yields a smaller alpha (heavier filter). For the bench (lag 5 s, tick 3 s)
it yields **0.375**, close to but NOT the tuned 0.4, which is exactly why the bench
keeps the explicit `FilterAlpha` override rather than deriving (preserve-first). A
vendor meter with only a datasheet refresh cadence can use the mapping; a tuned site
sets the override.

## 5. STOCK caveat (ramp × tick scaling — §13 validation hole)

The ceiling ramp is now stored per wall-clock SECOND and scaled by the engine tick at
the edge (`MaxRampDownWPerS × TickSeconds`). At the bench FAST tick (3 s) this is
bit-identical to the legacy per-tick `maxDropW`/`maxRiseW`. At the STOCK tick (15 s) the
ceiling may physically move FURTHER per (longer) tick — the cadence-correct behaviour
the legacy per-tick constant could not express, and thus an INTENTIONAL difference from
legacy on STOCK. Bench runs FAST, so the identical-behaviour acceptance holds; the STOCK
spot-check (`export-cap-full-battery,clock-jitter` on `bench-up.sh --stock`) at the P5
wave gate is where this is validated live. The FilterAlpha override and the direct-map
fields (taper start, converge frac, socStep) carry NO STOCK change — the ramp is the
only tick-scaled parameter.

## 6. On-cap residual (what a layered design cannot close)

Off-cap: **0** divergence (compliance rules are no-ops; `TestEconomics_ShadowParityOffCap`).

On-cap the cascade interleaves compliance BETWEEN the economic rules, mutating the
shared `surplusW`/battery state the later economic rules read; a below-compliance
economics layer sizes from raw state and diverges. TASK-064 closed the ONE part that
was a code artifact — the duplicated `evSafeCount` (now one shared `EVImportCooldown`,
import writes / economics reads, so the seed+1 arrival edge can no longer disagree). The
shared-`surplusW` interleaving is **irreducible without running compliance between
economics, which would defeat the layering** — so it is documented, not contorted.

Proof (`plantwiring_test.go`):
- `OnCapCeilingParityWithLegacy` — the compliance **solar ceiling is bit-faithful to
  the cascade tick-for-tick** on an active export cap (the parameterised path did not
  move compliance actuation).
- `OnCapDivergenceCharacterized` — asserts NO divergence on the solar-ceiling axis and
  bounds the total.
- `OnCapEconomicsResidual` — with an EV session under an export cap, the residual
  surfaces and is **confined to the `evse-current` axis** (EV budget sized from
  pre-interleave surplus): 5/5 ticks divergent on that axis, solar faithful.

The residual disappears at the shadow→active flip: once the Stack is authoritative
there is no cascade to shadow, and the layered economics simply IS the behaviour.
