# TASK-057 — Plant-model types + per-device config schema (ramp, latency, taper)

*Status: DONE (2026-07-06, task/057-plant-model @ lexa-hub) · Phase: P5 · Effort: L (≈6–8 h) · Difficulty: med · Risk: low*

## Objective
A `PlantModel` type set exists in `lexa-hub/internal/orchestrator` with a
per-device config schema (loaded from `hub.json`'s `devices`/`stations`
sections), unit-suffixed field names, documented provenance and defaults —
and NOTHING reads it yet. This is the vocabulary Phase 5 uses to replace the
bench-calibrated globals; the wiring happens in TASK-064.

## Background
The optimizer hard-codes this bench's physics (review D6, §8.1):
- `socStepEstimate = 1.0` %/tick — comment says "Calibrated for the 20×
  demo (10 kWh / 5 kW pack, 3 s tick ≈ 0.83 %)" (optimizer.go:780-787).
- Ceiling slew `maxDropW = 1500` / `maxRiseW = 500` W per tick
  (optimizer.go:1060-1065) — encodes how fast THIS inverter may be walked.
- `filterAlpha = 0.4` low-pass on measured export (optimizer.go:696-701) —
  encodes THIS bench's meter/OCPP reporting lags (5 s vs 10 s cadences, per
  the comment at 692-695).
- SOC taper: `socTaperStart = 80.0` + `SOCFullThreshold` linear taper
  (optimizer.go:777-810), `battConvergeFrac = 0.5`/`battBreachTicks = 3`
  (optimizer.go:60-72).
- Tick-scaled thresholds go through `scaleTicks` (optimizer.go:203-215,
  `tunedTickInterval = 3s`) so wall-clock meaning survives FAST/STOCK.

Config today: `configs/hub.json` has `devices` entries
(`{"name","role","max_w"}` — cmd/hub/config.go:15-17) and `stations`
(`{"id","max_current_a"}`); `configs/modbus.json` has connection-level
device entries (url/unit_id/role/max_w). The hub consumes the plant model
(the optimizer runs in lexa-hub), so the schema extends **hub.json's
`devices`/`stations` entries** — modbus.json stays a transport config.
AD-007: V1.0 is configured-only; parameter discovery (probe ramps at
commissioning) is backlog.

## Why this task exists
W1/D6: bench physics baked into product constants "won't transfer to real
vendors" — a Sunny Boy + Powerwall + random CT meter has different ramps
and lags. The constraint controller (TASK-058+) consumes per-device plant
parameters instead of globals. 05 §6: every plant-physics constant becomes
a named, unit-suffixed, provenance-documented parameter.

## Architecture review sections
W1 · D6 · §8.1 · R4 · 02 AD-007 · 05 §6 (units in names, provenance,
config path).

## Prerequisites
TASK-033 DONE (P5 start gate). Independent of TASK-056 (can run in
parallel with it — 04 shows both feeding TASK-058).

## Files
- **Read first:** `~/projects/lexa-hub/internal/orchestrator/optimizer.go`
  (lines cited above), `cmd/hub/config.go`, `configs/hub.json`,
  `configs/modbus.json`, `internal/orchestrator/interfaces.go`
  (BatteryMetrics already carries MaxChargeW/MaxDischargeW/CapacityWh).
- **Modify:** `cmd/hub/config.go` (parse the new sections),
  `configs/hub.json` (example values = today's bench constants).
- **Create:** `internal/orchestrator/plantmodel.go`,
  `internal/orchestrator/plantmodel_test.go`.

## Blast radius
New types + config parsing only. `Optimize()` behavior unchanged (nothing
reads the model until TASK-064). cmd/hub config decode gains optional keys
— missing keys get defaults, unknown keys warn (05 §6), so existing
deployed hub.json files keep working byte-for-byte.

## Implementation strategy
Derive the parameter list from the constants inventory above, define one
`PlantModel` struct per device role with units in every field name, give
each field a doc comment naming the constant it will replace and its
provenance ("bench-calibrated, optimizer.go vX"), and a `withDefaults()`
that yields exactly today's constants when a field is absent. Parse it in
cmd/hub as an optional `"plant"` object on each `devices[]`/`stations[]`
entry. No consumer changes.

## Detailed steps
1. Create `internal/orchestrator/plantmodel.go` with (minimum — extend if
   the inventory read surfaces more):
   ```go
   type InverterPlant struct {
       MaxRampDownWPerS float64 // ceiling slew, tighten; default 500  (=1500 W / 3 s tick)
       MaxRampUpWPerS   float64 // ceiling slew, relax;   default 166.7 (=500 W / 3 s tick)
       ControlLatencyS  float64 // cmd→measured-effect lag; default 3
   }
   type BatteryPlant struct {
       CapacityKWh      float64 // pack energy; default 10 (bench pack)
       SOCTaperStartPct float64 // default 80
       TaperCurve       []TaperPoint // optional; empty = linear taper to SOCFullThreshold
       ConvergeFrac     float64 // measured/commanded absorption floor; default 0.5
       ControlLatencyS  float64 // default 3
   }
   type MeterPlant  struct { MeterLagS float64 /* default 5; filterAlpha derives from it in 064 */ }
   type EVSEPlant   struct { MeterLagS float64 /* OCPP MeterValues cadence; default 10 */ }
   type TaperPoint  struct { SOCPct, Frac float64 }
   ```
   Express slews **per second**, not per tick (05 §5: wall-clock
   denominated, scaled to ticks at the edge). Note in comments that
   `socStepEstimate` is DERIVED (MaxChargeW, CapacityKWh, tick) — do not
   make it a parameter.
2. Add `withDefaults()` per struct returning today's bench values;
   table-test that defaults reproduce the constants exactly (e.g.
   `MaxRampDownWPerS * 3s == 1500`).
3. Extend cmd/hub/config.go: optional `"plant"` object per device/station
   entry; decode into the matching role's struct; warn-log unknown keys;
   plumb into the `Devices`/`Stations` structs (unused downstream for now).
4. Update `configs/hub.json` with a fully-populated example `plant` block
   per device, values = bench constants, each with provenance via adjacent
   doc (JSON has no comments — provenance lives in the Go doc comments and
   in the docs update below).
5. `make test` green; build all six binaries (`make build`).

## Testing changes
- `plantmodel_test.go`: defaults table (bench-constant equivalence),
  decode round-trip with/without `plant` blocks, unknown-key warning path.
- Run: `cd ~/projects/lexa-hub && make test`.

## Documentation changes
- lexa-hub CLAUDE.md config table: note hub.json now accepts per-device
  `plant` blocks (optional; defaults = bench calibration).
- 02_ARCHITECTURE_DECISIONS.md AD-007: record the config-location decision
  (hub.json, because the hub consumes it) and that discovery stays backlog.

## Common mistakes to avoid
- Naming fields without units (`maxRamp`) — 05 §6 makes that
  review-blocking; every field carries `W`, `S`, `Pct`, `KWh`.
- Encoding per-tick values in the schema. Ticks are an engine detail
  (FAST 3 s vs STOCK 15 s); the schema is per-second/per-percent.
- Putting the schema in modbus.json — lexa-modbus never reads plant
  physics; the optimizer does, and it lives behind hub.json.
- Wiring any optimizer read of the model — that is TASK-064, gated on the
  export-constraint migration (060) and its identical-behavior proof.

## Things that must NOT change
- All optimizer constants and behavior — `Optimize()` output is
  bit-identical before/after this task (assert: full `make test` green
  with zero test edits).
- `configs/hub.json` compatibility: a pre-task hub.json must load
  unchanged (defaults fill in).
- `internal/orchestrator` I/O-free rule (config decoding stays in cmd/hub;
  the orchestrator package only defines types).

## Acceptance criteria
- [ ] `plantmodel.go` exists; every field unit-suffixed with a provenance
  doc comment naming the constant it will replace.
- [ ] Defaults test proves equivalence to today's constants.
- [ ] Old hub.json (no `plant` keys) loads; new example hub.json loads.
- [ ] `make test` and `make build` green; zero behavior change.

## Regression checklist
- [ ] `go test -race ./internal/...` (lexa-hub) green
- [ ] Conformance logic tests: none (not protocol-adjacent)
- [ ] Mayhem: none (no runtime behavior change; unwired-code exception per
      05 §12 — the PR that first wires this code pays the full campaign)
- [ ] `make build` produces all six binaries

## Mayhem scenarios affected
None (types + config only).

## Conformance implications
None.

## Suggested commit message
`feat(orchestrator): plant-model types + hub.json per-device schema (AD-007, no consumers yet)`
(+ trailer: `Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>`)

## Suggested PR title & description
**Title:** Plant-model types and config schema (unwired)
**Description:** Adds PlantModel types with bench-constant defaults and
hub.json parsing; nothing reads them yet (TASK-064 wires). Risk: low —
additive. Testing: defaults-equivalence table, decode round-trips.
Rollback: revert; config keys are optional.

## Code review checklist
- Field-by-field provenance against optimizer.go line comments.
- Defaults arithmetic (per-second ↔ per-3s-tick conversions) correct.
- Config decode ignores/warns unknown keys, never fails on legacy files.

## Definition of done
Acceptance criteria + regression checklist + docs updated + status headers
(this file + 00_MASTER_INDEX) updated.

## Possible follow-up tasks
TASK-058 (skeleton consumes these types), TASK-064 (wiring + constant
burn-down), backlog: plant-parameter discovery probe (AD-007 open q).
