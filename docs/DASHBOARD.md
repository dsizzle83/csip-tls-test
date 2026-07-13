# LEXA Dashboard V2 — Runbook

V2 replaces the legacy single-file dashboard (still served at `/legacy` until parity
sign-off). Program docs: `docs/DASHBOARD_V2_PLAN.md`, contracts:
`docs/dashboard-v2/CONTRACTS.md`, design: `docs/dashboard-v2/DESIGN_BRIEF.md`.

## Run

```bash
make ui            # rebuild the SPA (node 18+; dist/ is committed — CI needs no node)
make build         # or: go build -o bin/dashboard ./cmd/dashboard
bin/dashboard -addr :8080 -hub https://69.0.0.2:9100 -mqttproxy http://69.0.0.2:11882 \
  -gridsim http://localhost:11112 -solar http://69.0.0.10:6020 -battery http://69.0.0.11:6021 \
  -meter http://69.0.0.12:6022 -ev http://69.0.0.14:6024 \
  -hub-token-file ~/.config/lexa/hub-api.token
# What-if data dirs default to data/scenarios + data/tariffs (repo-relative):
# run from the repo root, or pass -whatif-scenario-dir/-whatif-tariff-dir.
```

UI dev loop: `cd cmd/dashboard/ui && npm run dev` (proxies `/api` → :8080).

## Views

| Route | What it is |
|---|---|
| `/studio` | **Savings Studio** — what-if cost sim on real July-2025 weather + sourced tariffs (Tyler TX, Los Angeles, Haverhill MA). Baseline vs DER-without-LEXA vs LEXA; bill line items, TOU heatmap, day detail, plan comparison, full provenance. |
| `/ops` | **Live Ops** — animated power flow, hub decision feed, plan-vs-actual, CSIP protocol inspector (advertised/adopted/measured), grid event console with adoption/compliance timing. |
| `/proof` | **Proof Center** — 7 safety invariants, 69-scenario Mayhem browser, live run timeline (real vs hub-believed power), findings with violations, report history. |
| `/logs` | Merged SSE log stream, per-source filters, regex search, export. |
| `/bench` | Sim detail cards: telemetry, inject/control, SunSpec registers. |
| `/legacy` | The pre-V2 dashboard, unchanged. |

## New backend surface (all additive)

- `POST /api/whatif/run`, `GET /api/scenarios`, `GET /api/tariffs?territory=` —
  CONTRACTS.md §3. Engine: `internal/whatif`; tariff math: `internal/tariff`
  (NEM monthly credit cap → `credit_carryover_usd`).
- `GET /api/qa/reports`, `GET /api/qa/reports/{name}` — Mayhem evidence (now written
  under `logs/qa/`); findings carry structured `violations[]`.
- gridsim `POST|GET|DELETE /admin/tariff` — dynamic IEEE 2030.5 §10.5 pricing tree that
  follows the warped clock; legacy static tree when unset.

## Data provenance policy

Every dollar shown traces to `data/tariffs/*.json` provenance (source URL, retrieved
date, confidence **filed / published / estimated**) — the UI renders the confidence
badge; `data/tariffs/SOURCES.md` documents every number. Weather is Open-Meteo ERA5
(July 2025, hourly, per-site). Home load is a documented closed-form model driven by
the real temperature series (`internal/whatif` package doc). Refresh datasets with
`python3 scripts/fetch-scenario-data.py --all` (idempotent).

## 10-minute demo script (investor walkthrough)

1. **Studio, East Texas** (pre-loaded): "Real July 2025 — actual Tyler weather, actual
   filed Oncor delivery charges." Point at hero: baseline vs LEXA. Switch tariff chip to
   **TXU Free Nights**: LEXA drops the bill to fixed charges (~$14) by shifting EV +
   battery into the free window — the cumulative-cost race shows the gap opening
   day by day. Open the assumptions card: every number has a source and a
   confidence badge.
2. **Studio, Los Angeles**: same instruments, LADWP TOU — show the plan-comparison
   table ("LEXA also tells you which plan to be on") and the credits-banked chip
   (NEM carryover — we model the cap honestly, no fake negative bills).
3. **Live Ops**: "That was the model — this is the real hardware." Power flow is live
   from the bench. Fire **Export cap 1 kW** in the event console: watch
   issued → adopted (~3 s) → compliant in the timeline, the inspector's three columns
   agreeing (what the utility advertised over IEEE 2030.5, what the hub adopted, what
   the meter measured). Clear it.
4. **Proof Center**: "And this is why you can trust it." Safety strip (plain-language
   invariants), run **Quick sweep** live if time allows (~5 min) or open the latest
   report from History; show a finding's diagnosis + the real-vs-believed chart.
   Close: "69 adversarial hardware-in-the-loop scenarios, 7 safety invariants,
   every release."

## Known limits / next steps

- Bench Replay still uses the legacy hardcoded 3-window prices (`replay.go`) — tariff-
  engine integration + configurable epoch/TZ is the next work item (V2 plan Phase 4);
  the gridsim `/admin/tariff` half is done.
- Presenter mode (`/present`) not built; use the script above.
- LEXA-vs-dumb differentiation is largest on TOU/demand tariffs (by design — on flat
  tariffs there is nothing to arbitrage). ERCOT wholesale-indexed plan omitted pending
  honest 2025 price data.
- Savings >60% on default instruments are real but driven by 8 kW PV vs ~1 MWh July
  load; adjust sliders live if a skeptic wants a smaller system.
