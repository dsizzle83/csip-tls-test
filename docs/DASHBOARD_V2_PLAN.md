# Dashboard V2 — Savings Studio + Proof Center

**Status: ACTIVE (accepted 2026-07-12).** Scope amendments from acceptance: three
marquee scenarios, all **July 2025** — East Texas (Tyler, Oncor/REP), Los Angeles CA
(LADWP), Haverhill MA (National Grid) — not just East Texas; brand visuals driven by
the LEXA logo (green bolt / sage ring / white field); full bench simulations deferred
(build + smoke-test only; test plan at end). Build contracts:
`docs/dashboard-v2/CONTRACTS.md` · design: `docs/dashboard-v2/DESIGN_BRIEF.md`. Survey of the existing dashboard, brainstorm, and a
phased gameplan for a ground-up rebuild. Goal: a tool that (a) answers *"how much would
you have paid in July 2024 in East Texas with these instruments"* from **real** tariff and
weather data, (b) shows the hub responding live with its decision criteria visible, and
(c) turns the QA/conformance machinery into a customer/investor-grade proof surface.
The compliance-demo era (Scenarios tab) is over; this is a sales-and-proof instrument.

---

## Part 1 — Survey of what exists today

### The SPA (`cmd/dashboard/dashboard.html`, 3,461 lines / 167 KB)

One hand-rolled vanilla-JS file: 9 tabs (Hub, Solar, Battery, EV, Grid Controls,
Scenarios, 3-Month Cost Sim, Mayhem QA, Logs), Chart.js 4.4 **from a CDN** (breaks
offline — real risk for demos), state in module globals, imperative
`getElementById().innerHTML` everywhere, no routing/deep links, unbounded live-chart
arrays (leaks on long-lived tabs), duplicated constants (TOU rates + system sizes exist
as worker constants *and* hand-typed display strings; the QA tab hardcodes 7 scenario IDs
while the server has 69).

**Worth preserving (as patterns, not code):**
- Server-side long-running drivers (replay, mayhem) that survive tab close; UI reattaches
  by polling status. Genuinely robust — keep this architecture.
- The QA findings UX: verdict taxonomy, hypothesis/expected, diagnosis chains,
  live "real meter vs hub belief" readout.
- `logmux.go`: SSE fan-in of all 6 backends with an 800-event replay ring.
- Web-worker isolation of the cost sim (pattern only — the engine itself moves server-side).
- Tab-switch poller hygiene (`switchTab` tears down and re-registers intervals).

### The pricing model: three fictional definitions + one orphan

1. `replay.go:36-53` — hardcoded `0.38/0.18/0.10 $/kWh` + `0.07` export credit, three
   fixed daily windows, **no** weekends/seasons/demand charges/fixed charges.
2. `dashboard.html:1082` — the same constants duplicated in the JS worker.
3. lexa-hub's `DefaultTOUCostModel` — the source of truth the other two mirror, enforced
   only by a pinned-constant unit test (`replay_test.go:15`).
4. `sim/gridsim/pricing.go` — a *different* tariff (12¢/45¢) served over the IEEE 2030.5
   §10.5 Pricing function set, built **once at startup** with fixed intervals: it does
   not follow the warped clock and disagrees with everything else. The hub's TOU behavior
   during replay comes from its internal model, **not** from the protocol.

No utility, region, or timezone binding anywhere. Replay epoch is hardcoded
`2026-06-01 time.Local` (`replay.go:246`) and silently assumes driver-host TZ == hub TZ.

### The environment model

Entirely synthetic, generated in the browser worker (`genEnv`, `dashboard.html:1107-1206`):
sine-bell solar with hardcoded sunrise/sunset, a **New England** Markov weather chain,
parametric load, randomized DER events. No ingestion path for real irradiance, real
temperature, real load shapes, or real prices.

### Untapped backend capability (exists today, unrendered)

- **`GET /api/hub/plan`** — 24 h plan series on a 5-min grid **plus economics**. The single
  richest "watch the hub think" surface. Never called by the UI.
- **`/status.last_plan.decisions[]`** — `{rule, reason, impact}` optimizer decision trace.
  Consumed by mayhem sampling (`mayhem.go:2618`), never rendered live.
- **`GET /api/qa/scenarios`** — full 69-scenario catalogue with hypothesis/expected/
  category/source. UI ignores it (hardcoded list of 7).
- **QA `live[]` sample stream** — 120-sample rolling window per running scenario with
  ground-truth vs hub-view channels for every device, adoption state, CannotComply counts,
  staleness flags. The blindness-gap visualization writes itself; today only 4 numbers show.
- **QA reports** — written as `qa-mayhem-*.md` to process CWD (littering `cmd/dashboard/`),
  path returned but **no HTTP route serves them**.
- Invariants (`invariants.go`: INV-EXPORT/CONVERGE/SOC/CONNECT/EXPIRED/EVMAX/HUNT) are
  evaluated on every scenario but exposed only as prose bullets + verdict escalation — no
  structured JSON.
- gridsim `/admin/clock`, `/admin/malform`, `/admin/outage`; simapi `/ws`, `/fault`;
  hub `/telemetry/recent`, `/metrics` (~90 Prometheus series) — all reachable through the
  existing proxies, all unused by the UI.

---

## Part 2 — Brainstorm: what V2 should be

Organizing idea: **three audiences, three surfaces, one data spine.**

| Surface | Audience | Question it answers |
|---|---|---|
| **Savings Studio** | customers/investors | "What would I have paid, and what does LEXA save me?" |
| **Live Ops** | demos + Dmitri | "Show me the hub responding, and the criteria it's using." |
| **Proof Center** | investors + Dmitri | "Is it safe and reliable? Prove it." |

### A. The data spine (the killer feature)

**Tariffs as data, with provenance.** A tariff schema (`data/tariffs/*.json`) expressive
enough for real plans: seasonal + weekday/weekend TOU windows, tiered/block rates, fixed
monthly charges, demand charges ($/kW), export compensation (net metering, avoided-cost
buyback, free-nights style). Every tariff carries provenance fields (utility, plan name,
effective dates, source URL) rendered in the UI — the demo says *"TXU Energy Free Nights
& Solar Days, July 2024 filed rate,"* not "made-up numbers." Sources:
- **OpenEI URDB API** (free key) for real filed tariff structures.
- Hand-curated marquee retail plans for the East Texas story (Oncor TDU delivery charges
  + a flat plan, a free-nights plan, a wholesale-indexed plan; SWEPCO for the non-ERCOT
  corner of East Texas).
- **ERCOT historical settlement point prices** (DAM/RTM per load zone, public CSVs) for
  indexed plans and for the "grid stress day" narrative — real $5/kWh scarcity spikes are
  a far better demand-response story than an invented event.

**Real weather → real solar + real AC load.**
- **Open-Meteo historical archive** (free, no key, hourly GHI + temperature for any
  lat/lon, 1940→present) as the default; NREL NSRDB/PVWatts as the higher-fidelity option.
- PV model: nameplate kW, derate, orientation → AC output from irradiance.
- Load: NREL **ResStock** hot-humid Texas residential archetype as the base shape, with
  the AC component driven by the *actual* July 2024 temperature series. July 2024 in
  Tyler, TX was brutally hot — the real data *is* the demo.

**Offline-first.** Fetchers (`scripts/fetch-scenario-data.*`) run once with internet and
write normalized, versioned datasets under `data/scenarios/<id>/`; marquee datasets are
committed so the bench demos never depend on connectivity. (Same reason: no CDN scripts
in the new UI — everything embedded.)

### B. Savings Studio (the what-if tool)

- **Scenario builder:** location (ZIP → lat/lon + utility territory), period (e.g. July
  2024), home profile (monthly kWh or archetype), instruments (PV kW, battery kWh/kW, EV
  + commute pattern), tariff plan(s).
- **Three policies compared:** (1) no DER, (2) DER without LEXA (naive self-consumption),
  (3) DER with LEXA optimization. Headline: *"July 2024, East Texas: $412 → $278."*
- **Server-side what-if engine in Go** (replaces the browser worker): shares the tariff
  engine and datasets with the replay driver, runs a month in milliseconds, deterministic,
  unit-testable. The LEXA policy mirrors the hub's dispatch model (TOU cost model +
  constraint stack semantics) — and is **calibrated against HIL replay**: the engine
  predicts, the bench measures, the dashboard shows the delta. "Our simulations are
  validated against real hardware in the loop" is itself an investor line, and the
  measured-vs-modeled chart already exists in embryo (`renderReplayComparison`).
- **Outputs:** utility-bill-style line-item breakdown; daily cost stacks; hour×day TOU
  price heatmap with battery-dispatch overlay; plan comparison ("on plan B, LEXA saves
  another $31/mo"); savings attribution (arbitrage vs solar-shifting vs EV deferral vs
  demand-charge avoidance).
- Every what-if scenario is a saved artifact (JSON) that can be re-run, shared, and —
  key — **sent to the bench** (see D).

### C. Make pricing real end-to-end (protocol truth)

Replace `sim/gridsim/pricing.go`'s static tree with a **dynamic tariff engine**:
`/admin/tariff` loads a tariff spec (same schema as the Studio), and the
TimeTariffInterval tree regenerates to follow the warped clock. The hub then discovers
*real July 2024 prices over IEEE 2030.5* instead of using a hardcoded internal model —
the demo becomes protocol-true, and the Protocol Inspector (D) can show the tariff the
grid is actually serving.
**Cross-repo check (lexa-hub):** confirm whether the optimizer prices from the walked
CSIP tariff or only from `DefaultTOUCostModel` (the tariff read-back gap was closed
hub-side; H6's milli-currency divisor is in this path). If it's internal-only, a paired
hub change to prefer the discovered tariff is part of this program.

### D. Bench Replay V2 ("prove it on hardware")

- Driver consumes a **scenario reference**, not browser-generated arrays: same dataset
  and tariff the Studio used. Configurable epoch + timezone (America/Chicago), so
  "replay July 15 2024" is literal.
- Cost booked through the shared tariff engine (delete `replayRate` and the JS twin —
  one price basis, one implementation).
- Live view: dollar tickers (cost-so-far with LEXA vs modeled without — visceral for
  investors), compliance events, hub decisions feed, measured-vs-modeled convergence.
- Keep: checkpointing, tick CSV, restore-on-abort, CannotComply excusal. Artifacts move
  to `logs/replay/` (not CWD).

### E. Live Ops — watch the hub think

- **Power-flow diagram:** animated grid/solar/battery/home/EV node graph with live flows
  (the centerpiece demo visual), backed by 1 s `/status` polling like today.
- **Hub brain panel:** live `last_plan.decisions[]` feed (rule → reason → impact);
  `/plan` 24 h planned-vs-actual chart with its economics; mode; constraint-stack status.
  **Cross-repo item:** expose per-axis constraint verdicts (which of the five R4 axes is
  binding, and why) in `/status` or a `/decisions` endpoint — the deepest possible answer
  to "show me the criteria."
- **CSIP Protocol Inspector** ("the criteria the grid is using"): what gridsim currently
  advertises — DERControls per program with primacy, DefaultDERControl, the live TOU
  tariff intervals with countdown timers — side-by-side with what the hub adopted
  (mRID, valid-until) and the Response/CannotComply feed. This is the self-proof surface:
  utility said X over 2030.5, hub acknowledged Y, meter measured Z.
- **Grid event console:** the old Scenarios tab reborn — one-click "utility issues export
  cap" style events with the existing assertion engine (settle/hold/PASS-FAIL) retained,
  now framed as live grid events rather than canned compliance demos.

### F. Proof Center (QA + safety case)

- **Scenario browser** built on `GET /api/qa/scenarios`: all 69, filterable by category/
  source/extended, with hypothesis + expected shown. Campaign presets (dev FAST run,
  release STOCK gate, extended dither set).
- **Live run view:** verdict stream as findings complete; the `live[]` timeline charted —
  real power vs hub belief with the blindness gap shaded; phase indicator; breach markers.
- **Structured invariants:** backend emits `violations[]` (`{inv, t, detail}`) alongside
  prose so the UI renders an invariant timeline; safety-audit escalations become visible
  events instead of buried bullets.
- **Safety case panel:** INV-SOC / INV-CONNECT / INV-EXPORT / INV-EXPIRED (+EVMAX/HUNT)
  as first-class cards — plain-language meaning, how it's tested, last campaign evidence.
  *"Every release passes 69 adversarial hardware-in-the-loop scenarios"* with the receipts.
- **Run history:** persist campaign results as JSON under `logs/qa/`, serve reports over
  HTTP (`/api/qa/reports/…`), pass-rate trend across campaigns. Kills the CWD litter.

### G. Logs V2

Keep logmux + SSE. Add: level parsing, per-source filters, regex search, pause/scrollback
(much of this exists client-side — port it), and **event correlation**: markers for
control-issued / verdict / invariant-breach / replay-day boundaries overlaid on the log
timeline and linked from other views. Retire the redundant second pipeline on the Hub tab.

### H. Presenter mode (the wow layer)

A scripted, keyboard-driven walkthrough for live demos: (1) this home, this heat wave —
real July 2024 data; (2) prices spike 4–9 pm; (3) watch the hub pre-position the battery
(Live Ops); (4) utility issues an export cap over IEEE 2030.5 — adoption within seconds
(Inspector); (5) month closes: bill comparison (Studio); (6) "and here's why you can
trust it" (Proof Center). Big type, staged reveals, no dead ends.

---

## Part 3 — Platform decisions (recommendations)

1. **Frontend:** scrap `dashboard.html`; build `cmd/dashboard/ui/` with **Vite + React +
   TypeScript**, `go:embed` the built `dist/` (single binary preserved). Rationale: the
   surface is now 6 substantial views with shared state — past the vanilla-JS ceiling
   that produced today's duplication. Alternative if node-in-repo is unacceptable:
   Preact+htm no-build ES modules. CI gets a `ui-build` job; `make build` runs it.
2. **Charts:** embedded library (no CDN). **uPlot** for high-rate streaming charts +
   **ECharts** for rich composed ones (heatmap, sankey/flow) — or ECharts alone for
   simplicity. Follow the dataviz skill when building.
3. **What-if engine server-side in Go**, not JS: shares tariff/env code with replay,
   testable in `make test-fast`, and the browser worker's only remaining job disappears.
4. **Backend layout:** `internal/tariff/` (schema, engine, bill calculator),
   `internal/scenariodata/` (dataset loading/normalization), `internal/whatif/` (engine);
   `cmd/dashboard/` keeps main/proxies/logmux/replay/mayhem. Mayhem engine untouched
   except additive API (structured invariants, reports route).
5. **Persistence:** JSON artifacts under `logs/` (matches mayhem-campaign convention).
   No database until run history proves it needs one.
6. **API stability:** existing `/api/qa/*`, `/api/replay/*`, proxy mounts stay
   contract-compatible; new capability is additive (`/api/whatif/*`, `/api/tariffs`,
   `/api/scenarios`, `/api/qa/reports`, gridsim `/admin/tariff`).

---

## Part 4 — Gameplan (phases; each is a session-or-two, independently landable)

**Phase 0 — Data spine.** Tariff schema + Go engine (windows/tiers/demand/fixed/export;
bill calculator; unit tests with real-bill fixtures). Dataset fetchers (Open-Meteo,
ERCOT CSV, URDB) → normalized `data/scenarios/<id>/`; commit the marquee **East Texas
July 2024** dataset (weather, prices, 2–3 real tariffs, ResStock-derived load shape).
Exit: `go test` computes a July-2024 bill from real data that hand-checks against the
tariff sheet.

**Phase 1 — What-if engine.** `internal/whatif/`: tick simulator (PV/load/battery/EV),
three policies, LEXA policy mirroring the hub's dispatch semantics; savings attribution;
`POST /api/whatif/run`. Validate ballpark against the old JS worker before deleting it.
Exit: East-Texas-July-2024 comparison JSON with bill breakdowns, in milliseconds.

**Phase 2 — UI platform + Live Ops core.** Scaffold Vite/React/TS + embed pipeline +
Makefile/CI. Port the always-on surfaces: header, power cards, power-flow diagram, live
chart (bounded buffers), Logs V2, sim detail panels. Exit: new UI at :8080 fully replaces
today's live-monitoring value, offline-capable.

**Phase 3 — Savings Studio UI.** Scenario builder → engine → results (headline, bill
line items, daily stacks, TOU heatmap, plan comparison, assumptions/provenance panel).
Saved scenarios. Exit: the East Texas pitch runs end-to-end in the browser.

**Phase 4 — Protocol truth + Replay V2.** gridsim dynamic tariff (`/admin/tariff`,
clock-following intervals); replay driver consumes scenario refs + tariff engine,
configurable epoch/TZ; live dollar tickers + measured-vs-modeled view; delete the three
duplicated price definitions. Cross-repo: verify/enable hub pricing from the walked CSIP
tariff (paired lexa-hub session; H6 divisor). Exit: "replay July 15 2024 on the bench"
with prices served over 2030.5.

**Phase 5 — Hub brain + Protocol Inspector + event console.** Decisions feed, `/plan`
chart + economics, CSIP inspector (advertised vs adopted vs measured, tariff countdown),
grid-event console with assertions. Cross-repo (optional but high-value): per-axis
constraint verdict exposure. Exit: "show me the criteria" answered live.

**Phase 6 — Proof Center.** Scenario browser on `/api/qa/scenarios`; live `live[]`
timeline visualization; structured `violations[]` + `/api/qa/reports` routes (report
files → `logs/qa/`); campaign history + trend; safety-case panel. Exit: a QA campaign is
watchable, legible, and its evidence is one click away.

**Phase 7 — Presenter mode + polish.** Scripted demo flow, offline audit, docs
(`docs/DASHBOARD.md` runbook), dead-code removal (old scenarios tab, JS worker,
`replayRate` twins), CLAUDE.md updates.

### Sequencing notes
- 0→1→3 is the pure-software savings story (no bench needed); 2 can proceed in parallel
  with 1; 4–6 need the bench. Phases 4/5 carry the cross-repo items — schedule lexa-hub
  sessions accordingly.
- Mayhem verdict semantics and scenario specs are **not** touched by any phase; only
  additive API surface. STOCK/FAST campaign discipline unchanged.

### Risks / open questions
- **Hub policy fidelity** in the what-if engine — mitigated by HIL calibration (Phase 4)
  and keeping a pinned-constants test against the hub model until the CSIP-tariff path lands.
- **Hub tariff consumption** unknown until the lexa-hub check (Phase 4 gate).
- **ResStock data bulk** — pre-process to one archetype series per scenario; never ship
  raw ResStock.
- **Node toolchain in CI** — new `ui-build` job; keep `pure-go` job green without node by
  committing `dist/` or gating embed behind a build tag (decide in Phase 2).
- **East Texas ≠ one utility** — deregulated ERCOT (Oncor TDU + retail plans) vs SWEPCO
  territory; the Studio should name the territory it's modeling and offer both.
