# Dashboard V2 — Contracts (schemas + API)

**Authoritative for the V2 build (2026-07-12).** Every agent/worker builds against this
document. If a contract must change, change it HERE first, then the code. Go packages own
validation; the UI trusts the wire.

Program plan: `docs/DASHBOARD_V2_PLAN.md`. Design: `docs/dashboard-v2/DESIGN_BRIEF.md`.

---

## 1. Tariff schema (`data/tariffs/*.json`, Go: `internal/tariff`)

One file = one retail electricity plan a real customer could have been on, with provenance.

```jsonc
{
  "id": "tx-txu-free-nights-2025",          // kebab, unique, stable
  "name": "TXU Energy Free Nights & Solar Days",
  "short_name": "Free Nights",                // UI chips
  "utility": "TXU Energy (REP) · Oncor (TDU)",// human string, names all parties
  "territory": "east-texas-tx",               // matches scenario.location.territory
  "timezone": "America/Chicago",              // IANA; ALL window math in this TZ
  "currency": "USD",
  "effective": { "from": "2025-06-01", "to": "2025-09-30" },
  "provenance": {
    "source_url": "https://…",
    "retrieved": "2026-07-12",
    "confidence": "published",   // "filed" | "published" | "estimated"
    "notes": "EFL summer 2025; delivery folded per Oncor 2025-07 rate sheet"
  },
  "fixed_monthly_usd": 9.95,
  "energy": {
    // Seasons partition the year; within a season, day_types partition the week;
    // within a day_type, periods MUST cover [00:00,24:00) with no overlap.
    "seasons": [{
      "id": "summer", "months": [6,7,8,9],
      "day_types": [{
        "days": ["mon","tue","wed","thu","fri","sat","sun"], // or weekday/weekend split
        "periods": [
          { "id": "night", "label": "Free Nights", "start": "21:00", "end": "06:00",
            "rate_usd_per_kwh": 0.0 },
          { "id": "day",   "label": "Day",         "start": "06:00", "end": "21:00",
            "rate_usd_per_kwh": 0.209 }
        ]
      }]
    }],
    // OPTIONAL usage tiers (monthly kWh breakpoints) that ADD to period rates
    // (LADWP-style tier adders) — omit when not applicable:
    "tiers": [
      { "up_to_kwh": 350, "adder_usd_per_kwh": 0.0 },
      { "up_to_kwh": null, "adder_usd_per_kwh": 0.03 }   // null = unbounded
    ]
  },
  // Per-kWh adders always applied on IMPORT (TDU delivery, riders, surcharges):
  "riders_usd_per_kwh": 0.052,
  // OPTIONAL demand charge(s), $/kW on max 15-min import demand in window/month:
  "demand": [
    { "label": "On-peak demand", "usd_per_kw": 8.03,
      "months": [6,7,8,9], "days": ["weekday"], "start": "16:00", "end": "21:00" }
  ],
  "export": {
    // "net_metering": export credited at the moment's period energy rate
    //                 (riders NOT credited; monthly tier adders excluded — a
    //                 tier position has no well-defined per-instant value)
    // "buyback":      flat rate_usd_per_kwh
    // "none":         export earns nothing
    "type": "buyback",
    "rate_usd_per_kwh": 0.05
  }
}
```

Validation rules (`tariff.Validate()` — hard errors):
- Seasons cover months 1–12 exactly once **for the months the scenario touches** (a
  summer-only file is legal; using it outside `effective` is a load-time error).
- Within each day_type: periods cover 24 h with zero overlap (periods may wrap midnight,
  e.g. 21:00–06:00). Every weekday name appears exactly once across day_types.
- All rates ≥ 0 and < 5 $/kWh (sanity); `confidence` ∈ enum; timezone parses.

Engine surface (Go, `internal/tariff`):
```go
func Load(dir string) (map[string]*Tariff, error)        // all *.json, validated
func (t *Tariff) RateAt(ts time.Time) RateInfo           // ts converted to t.TZ
   // RateInfo{PeriodID, PeriodLabel string; ImportUSDPerKWh, ExportUSDPerKWh float64}
   // ImportUSDPerKWh EXCLUDES tier adders (monthly state) but INCLUDES riders.
type BillCalc struct{ … }                                 // one billing month accumulator
func NewBillCalc(t *Tariff, year int, month time.Month) *BillCalc
func (b *BillCalc) Add(ts time.Time, importKWh, exportKWh, intervalPeakImportKW float64)
func (b *BillCalc) Close() Bill
type Bill struct {
    LineItems []LineItem  // {Kind, Label, Qty, QtyUnit, Rate, AmountUSD}
    TotalUSD  float64
    // Kinds: fixed | energy(per period) | tier_adder | riders | demand | export_credit
}
```
Tier adders and demand charges are applied at `Close()` from accumulated monthly state.
15-min interval peak demand = `intervalPeakImportKW` max. **Unit tests must include a
hand-computed fixture bill per marquee tariff** (spreadsheet-style expected values in the
test, cross-checkable against the published rate sheet).

## 2. Scenario dataset (`data/scenarios/<id>/`, Go: `internal/scenariodata`)

```
data/scenarios/east-texas-jul2025/
  scenario.json
  weather.json
```

`scenario.json`:
```jsonc
{
  "id": "east-texas-jul2025",
  "label": "East Texas — July 2025",
  "location": { "city": "Tyler", "state": "TX", "lat": 32.35, "lon": -95.30,
                "timezone": "America/Chicago", "territory": "east-texas-tx",
                "blurb": "Oncor delivery; deregulated ERCOT retail choice" },
  "period": { "start": "2025-07-01", "end": "2025-07-31" },
  "weather": { "source": "open-meteo-era5", "retrieved": "2026-07-12",
               "source_url": "https://archive-api.open-meteo.com/…" },
  "tariff_ids": ["tx-txu-free-nights-2025", "tx-flat-12-2025", "…"],
  "default_tariff_id": "tx-flat-12-2025",
  "home_defaults":   { "profile": "single-family-3br", "base_kw": 0.45,
                       "hvac": { "cool_setpoint_f": 75, "kw_per_degf": 0.16, "max_kw": 4.2 } },
  "instrument_defaults": { "pv_kw": 8.0,
    "battery": { "kwh": 13.5, "kw": 5.0, "reserve_pct": 10, "round_trip_eff": 0.90 },
    "ev": { "present": true, "battery_kwh": 60, "charger_kw": 7.2,
            "weekday_kwh": 11, "depart_hour": 8, "return_hour": 17 } }
}
```

`weather.json` — hourly, local-time aligned, full period:
```jsonc
{ "timezone": "America/Chicago",
  "hours": ["2025-07-01T00:00", …],          // ISO local
  "ghi_wm2": [0, 0, …],                       // shortwave_radiation
  "temp_c":  [27.1, …] }
```
Loader validates: equal array lengths, hours contiguous & hourly, period matches
scenario.json, no NaNs. Missing hours (API gaps) are a load error, not silently filled.

**Load model is computed, not shipped** (keeps instruments adjustable): documented
formula in `internal/whatif`, provenance string surfaced to UI:
*"Modeled residential load: base + occupancy schedule + AC response fitted to observed
hourly temperatures (source: Open-Meteo ERA5)."* Deterministic per scenario (seeded by
scenario id) — same scenario always yields the same bill.

## 3. What-if engine (Go: `internal/whatif`) + API

15-minute tick simulation over the scenario period (hourly weather linearly
interpolated). Sign convention **everywhere**: grid import > 0, export < 0 (matches
bench meter convention).

Policies (`policy` enum):
- `baseline`  — home load only; no PV, no battery, no EV smart-charging (EV charges on
  arrival if EV present).
- `der_dumb`  — PV + battery greedy self-consumption (charge from PV excess, discharge
  to net load, reserve floor respected); EV charges on arrival at full rate.
- `der_lexa`  — LEXA policy model: TOU-aware battery arbitrage (pre-position before the
  most expensive period of the day, discharge through it, never below reserve), PV
  self-consumption, EV deferred to cheapest coverage window that still meets
  `depart_hour` need, demand-charge limiting when tariff has demand charges.
  **Honest label** (UI + JSON): "LEXA policy model — mirrors hub dispatch semantics;
  hardware-validated via bench replay (planned)".

PV model: `ac_kw = ghi/1000 * pv_kw * 0.85 * (1 - 0.004*max(0, cell_temp-25))`,
`cell_temp ≈ temp_c + 0.03*ghi`. Battery: symmetric √eff on charge/discharge.

### `POST /api/whatif/run`
```jsonc
{ "scenario_id": "east-texas-jul2025",
  "tariff_ids": ["tx-flat-12-2025", "tx-txu-free-nights-2025"],  // 1..4
  "instruments": { …same shape as instrument_defaults, all optional… },
  "policies": ["baseline", "der_dumb", "der_lexa"] }              // default all 3
```
→ `200`:
```jsonc
{ "scenario": { …scenario.json echo… },
  "runs": [ { "tariff_id": "…", "policy": "baseline",
      "bill": { "line_items": […], "total_usd": 412.33 },
      "kpis": { "import_kwh": 0.0, "export_kwh": 0.0, "peak_import_kw": 0.0,
                "self_consumption_pct": 0.0, "avg_soc_pct": 0.0 },
      "daily": { "dates": ["2025-07-01",…], "cost_usd": […], "import_kwh": […],
                 "export_kwh": […], "pv_kwh": […], "load_kwh": […] },
      "day_detail": { "date": "2025-07-21",   // engine picks: costliest baseline day
        "ticks": 96, "load_kw": […], "pv_kw": […], "batt_kw": […],
        "ev_kw": […], "grid_kw": […], "soc_pct": […], "rate_usd_per_kwh": […] } } ],
  "savings": [ { "tariff_id": "…", "vs": "baseline", "policy": "der_lexa",
      "usd": 134.05, "pct": 32.5,
      "attribution": { "solar_self_use_usd": …, "battery_arbitrage_usd": …,
                       "ev_shift_usd": …, "demand_usd": …, "export_usd": … } } ],
  "provenance": { "weather": "…", "load_model": "…", "tariffs": [ …provenance blocks… ],
                  "engine": "whatif v1 — 15-min deterministic simulation" } }
```
Errors: 400 (unknown scenario/tariff, bad instruments), 422 (tariff/scenario
territory/timezone mismatch). Runs are synchronous (a month at 15-min = 2,976 ticks ×
policies × tariffs — milliseconds).

### `GET /api/scenarios` → `[{scenario.json…}]`  ·  `GET /api/tariffs?territory=` → `[{tariff sans internals}]`

## 4. QA additions (additive; NO changes to verdict semantics or scenario specs)

- Reports move to `logs/qa/` (`writeReport` path change only).
  `GET /api/qa/reports` → `[{name, mtime, bytes}]` newest-first;
  `GET /api/qa/reports/{name}` → `text/markdown` (name validated `^qa-mayhem-[0-9-]+\.md$`).
- `mayFinding` gains `violations []{ inv string, t_s float64, detail string }` populated
  by the safety audit alongside the existing prose bullet. `invariants.go` predicates
  return structured hits; prose derived from them (single source).
- Everything else (`/api/qa/start|status|scenarios|abort`, `live[]`, verdicts) unchanged.

## 5. gridsim dynamic tariff (`sim/gridsim`)

- `POST /admin/tariff` — body = the §1 tariff JSON. Rebuilds the §10.5 pricing tree
  (TariffProfile → RateComponent → TTI → CTI) from the tariff's periods for a rolling
  48 h window centered on **warped server time** (`s.Now()`), prices in milli-currency
  (`PricePowerOfTenMultiplier: -3`, rate×100000 → tenth-millicents… **use existing
  convention: dollars → `Price = round(rate_usd_per_kwh * 100 * 1000)` matching
  12000 = 12.0¢**). `ActiveTimeTariffIntervalList` = the interval containing `s.Now()`.
- Tree regenerates on: tariff set, `/admin/clock` change, and lazily when `s.Now()`
  passes the window edge.
- `GET /admin/tariff` → `{tariff_id, name, active_period, intervals:[{start,end,rate}]}`
  (UI inspector reads this — no XML parsing in the browser).
- `DELETE /admin/tariff` → restore legacy static two-tier tree (back-compat for
  existing tests).
- Existing tests must stay green; new tests: window regeneration on clock warp,
  midnight-wrap periods, active-interval correctness.

## 6. UI (cmd/dashboard/ui — Vite + React + TS, embedded)

- `go:embed ui/dist` served at `/` (old `dashboard.html` kept at `/legacy` until parity).
- **`ui/dist` is committed** so `pure-go` CI needs no node. `make ui` rebuilds it;
  `make build` depends on `ui` when `ui/src` is dirty (simple mtime check ok).
- No external network at runtime: all JS/CSS/fonts/logo bundled. ECharts for charts.
- Views (routes): `/studio` (Savings Studio), `/ops` (Live Ops), `/proof` (Proof
  Center), `/logs`, `/bench` (sim detail panels), `/present` (presenter mode, stretch).
- SSE: `GET /api/logs/all` (existing shape `{src,line,at}`); polling: hub status 1 s,
  qa status 1.5 s, replay 3 s (match legacy cadences).
- All existing backend routes keep working; UI additions consume only contracts in this
  doc + already-existing endpoints (`/api/hub/status`, `/api/hub/plan`,
  `/api/qa/scenarios`, gridsim admin, simapi).

## 7. Repo/process invariants for every worker

- `make test-fast` green after every change; `go vet ./...` clean; `CGO_ENABLED=0 go
  build ./...` must succeed (CI pure-go gate).
- No new Go module deps without a note in the phase commit message; UI deps pinned in
  package-lock.json.
- Artifacts (reports, checkpoints, tick logs) under `logs/`, never CWD/source dirs.
- Private keys stay gitignored; nothing in `data/` may embed API keys.
- Provenance discipline: any number shown to a customer traces to a `provenance` block.
  Estimated ≠ filed; the UI must render the confidence level, never hide it.
