# Southbound Stack (Modbus / SunSpec)

Pure Go — zero cgo. Implements `Device` interface consumed by `internal/southbound/registry/`.

**TASK-021 (2026-07-05):** the bench's own `sunspec`/`modbus` packages are gone from this
tree — every consumer here now imports the shared `lexa-proto/sunspec` and `lexa-proto/modbus`
(product-authoritative generation; see `docs/refactor/notes/TASK-020-sunspec-disposition.md`).

**TASK-082 (2026-07-05):** the bench's own `derbase/` fork (the trimmed M701-712/legacy
mapping layer TASK-021 adapted onto the shared sunspec codec) is now gone too. `battery/` and
`inverter/` embed `lexa-proto/derbase.Base` directly — the same package lexa-hub consumes
(moved there in TASK-023). `device.Measurements` is a type alias to
`lexa-proto/derbase.Measurements` (mirrors the identical trick lexa-hub's own `device` package
uses). No protocol-semantics fork (register maps, layouts, DERControl write sequencing) exists
in this repo anymore. The three `M701St*` operating-state constants the shared codec doesn't
symbolize (`sunspec.ACMeasurement.St` stays a raw `uint16` by design) are a tiny read-only shim
kept locally in `battery.go`/`inverter.go` — spec values, not protocol semantics, and not worth
a shared-module round-trip for three integers used by exactly one call site each.

## Package map
```
device/    Device interface: ApplyControl, ReadMeasurements, Status, Close.
           DeviceStatus is bench-local; Measurements = lexa-proto/derbase.Measurements (alias).
inverter/  Inverter implements Device. Reads Model 103 (or 101/102 fallback), nameplate from 121, controls via 123.
battery/   BatteryDevice implements Device. Model 103 AC + 802 Li-Ion battery state.
meter/     MeterDevice for bi-directional smart meter. Model 201 (single-phase AC).
registry/  Registry: fan-out ApplyControl, background poll, MeasurementUpdate channel.
sim/       Animated Modbus TCP servers. NewSolarServer / NewBatteryServer / NewMeterServer.
```

`lexa-proto/derbase`: shared SunSpec DER logic for inverter/battery — model-presence detection
(`Has701..714`), measurement parsing (`ReadMeasurementsM701` via `sunspec.Parse701`,
`ReadMeasurementsACModel` for legacy M103), and `ApplyControl` (CSIP `DERControlBase` -> M123
legacy or M704 IEEE 1547-2018 writes, plus the full VoltVar/VoltWatt/trip/droop/WattVar curve
surface). This is a superset of what the deleted bench fork exposed (TASK-020 disposition
§2c/§2d adjudicated every behavioral difference product-authoritative, zero bench-side fixes
lost) — battery/inverter pick up `OpModFixedW`, `GenLimW`/`LoadLimW` ceilings, and reversion
timers they didn't handle before, with the legacy-model paths the bench sims actually exercise
(M103/121/123/802/201) unchanged (same tests, same assertions, unaffected).

**Note:** `battery`, `meter`, and `registry` currently have no consumer outside their own test
files in this repo (`cmd/hub`/`sim/orchestrator`, their pre-TASK-010 consumers, are deleted).
Only `inverter` has a live external consumer (`sim/modsim-client`, a Pi-side Modbus validation
CLI). They are kept because they build, have their own passing test suites, and are cheap
insurance if a manual validation CLI for battery/meter is ever needed — not because anything
calls them today. Flagged here for visibility, not treated as this task's problem to solve.

`lexa-proto/modbus`: Transport wrapping simonvetter/modbus.
URL selects layer: `tcp://host:502` | `rtu:///dev/ttyUSB0` | `rtuovertcp://host:502`

`lexa-proto/sunspec`: Scan (model discovery, reads IDs only — no data burst).
Reader: `ReadModel(id)` / `WriteModel(id, offset, values)`, 0-based offsets within named block.
`scale.go`: `ApplyScaleSigned/Unsigned`, `RawFromScaleSigned/Unsigned`. `0x8000` → NaN.
Legacy models (103/120/121/122/123/802/201-203) use raw offset constants (`M103_W`, etc.,
unchanged from the old bench fork). IEEE 1547-2018 models (701-712) use a declarative layout
engine instead (`Parse701`, `L704.View(regs).Float("WMaxLimPct")`, etc.) — no raw `M701_*`
offset constants exist in this generation.

## SunSpec wire format
Header at address 40000 (0-based): `0x5375 0x6E53` ("SunS")
Block layout: `[ModelID uint16][Length uint16][Length × data uint16]`
End sentinel: ModelID = `0xFFFF`

## Key model offsets (0-based within block data section)
| Model | Field | Offset |
|-------|-------|--------|
| 103 (inverter AC) | W, W_SF | 12, 13 |
| 103 | Hz, Hz_SF | 14, 15 |
| 103 | PhVphA, V_SF | 8, 11 |
| 103 | St (operating state) | 36 |
| 121 (nameplate) | WMax, WMax_SF | 0, 22 |
| 123 (controls) | WMaxLimPct, _Ena, Conn, _SF | 0, 4, 16, 20 |
| 201 (meter) | W, W_SF | 16, 20 |
| 802 (Li-Ion) | SoC, SoH, DoD, ChaSt | 10, 11, 12, 16 |

## Simulator API summary
All sims expose HTTP + WebSocket via `internal/simapi/`:
- Ports: modsim 5020/6020 · batsim 5021/6021 · metersim 5022/6022 · evsim —/6024
- `GET /state` → typed JSON · `POST /inject {"W_W":3000}` · `POST /control {"cmd":"pause","speed":5}` · `GET /registers` · `GET /ws` (2 s push)
- CORS wildcard enabled (legacy — the web dashboard proxies same-origin and does not need it).

## Tests
Inverter, battery, meter packages test against an in-process simonvetter Modbus server — no hardware required.
`go test ./internal/southbound/...`
