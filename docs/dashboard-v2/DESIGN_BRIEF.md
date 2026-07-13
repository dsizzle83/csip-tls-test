# Dashboard V2 — Design Brief

**Authoritative visual/UX spec (2026-07-12).** Companion to `CONTRACTS.md`. The brand
mark is a green lightning bolt inside a sage ring on a white field
(`cmd/dashboard/ui/public/brand/logo.png`) — the product should feel like that logo:
clean white field, confident green, black ink, generous whitespace, zero clutter.

## 1. Brand tokens (CSS custom properties, `ui/src/theme.css`)

```css
:root {
  /* Brand (sampled from logo) */
  --bolt:        #82E28B;   /* accents, highlights, hero fills — NEVER body text */
  --sage:        #B2CCB3;   /* borders, inactive states, subtle fills */
  --sage-soft:   #EAF2EB;   /* tinted card/backdrop fills */
  --ink:         #0B0F0C;   /* primary text */
  --ink-2:       #4B5563;   /* secondary text */
  --ink-3:       #9CA3AF;   /* muted/axis text */
  --surface:     #FCFCFB;   /* page */
  --card:        #FFFFFF;   /* panels */
  --line:        #E5E9E6;   /* hairlines, grid rules */
  --green-ink:   #1F7A34;   /* accessible green: links, buttons, emphasis text */

  /* Categorical (VALIDATED 2026-07-12: CVD worst-pair ΔE 42.9, all ≥3:1 on surface).
     Fixed order; assign by ENTITY, never by rank; never cycle. */
  --c-green:  #2E9E44;   /* slot 1 */
  --c-blue:   #2A78D6;   /* slot 2 */
  --c-amber:  #C88500;   /* slot 3 */
  --c-teal:   #0E9268;   /* slot 4 */
  --c-indigo: #4A3AA7;   /* slot 5 */
  --c-red:    #E34948;   /* slot 6 — spare; NOT for status */

  /* Status (reserved; always icon + label, never color alone) */
  --s-good:     #15803D;  /* PASS */
  --s-warn:     #B45309;  /* DEGRADED */
  --s-serious:  #C2410C;  /* BLIND */
  --s-critical: #B91C1C;  /* FAIL */
  --s-neutral:  #64748B;  /* INCONCLUSIVE / pending */
}
```

**Fixed entity→color maps** (semantic, used everywhere; charts never repaint on filter):

| Power/flow entities | | Policy entities | |
|---|---|---|---|
| Solar | `--c-amber` | Baseline (no DER) | `--ink-2` gray (it's the reference) |
| Battery | `--c-green` | DER without LEXA | `--c-blue` |
| Grid | `--c-blue` | **DER + LEXA** | `--c-green` (brand = the win) |
| Home load | `--c-indigo` | | |
| EV | `--c-teal` | | |

Sequential ramp (TOU price heatmaps — magnitude): single warm hue, light→dark:
`#FFF4DC → #F3C874 → #DD9A2B → #A96A08 → #6F4402` (expensive = dark amber; green must
NOT encode price). Diverging (import/export around zero): `--c-blue` pole (import) ↔
`--c-green` pole (export), neutral `#E5E7EB` midpoint.

## 2. Non-negotiable chart rules (from the dataviz method — enforce in review)

- **One y-axis per chart. Never dual-axis.** Two measures → two stacked charts or
  indexed series.
- Thin marks: 2px lines, bars with 2px surface gaps between segments/neighbors,
  4px rounded data-ends, ≥8px hover markers.
- Legend present for ≥2 series; single series = no legend (title names it). ≤4 series
  also get selective direct labels (last-point labels on lines). Never a number on
  every point.
- Text (values, labels, legends) wears ink tokens, never series color.
- Crosshair + shared tooltip on every time-series chart; per-cell tooltip on heatmaps;
  per-mark on bars. Tooltips show formatted values + units.
- Grid/axes recessive: `--line` hairlines, `--ink-3` 11–12px axis text, no chart borders.
- Status colors only for status (verdicts, invariants); a series is never `--s-*`.
- Live/streaming charts keep bounded buffers (∼2 h at 1 s) — no unbounded arrays.
- ECharts: disable default animation on streaming charts; 250 ms ease on static renders.

## 3. Layout & shell

- **Top bar** (56px, white, hairline bottom): logo (28px) + product name
  "LEXA · Grid Intelligence" in ink; right side: bench health dot-row (hub, gridsim,
  4 sims — 8px dots, `--s-good`/`--s-critical` + tooltip) and a subtle live clock
  (bench sim-time when replay/warp active, else wall).
- **Left nav** (200px, `--surface`, collapsible to 56px icons): Studio ⚡ · Live Ops 📡
  · Proof 🛡 · Logs 📜 · Bench 🔧 (+ Present ▶ when built). Active item: `--sage-soft`
  pill + `--green-ink` text + 3px `--bolt` left rail.
- **Content**: max-width 1440px, 24px gutters, cards on `--card` with 12px radius,
  1px `--line` border, NO drop shadows heavier than `0 1px 2px rgb(0 0 0 / .04)`.
- Type: system-ui stack. Page title 20/600, card title 14/600 uppercase-tracked
  `--ink-2`, body 14, data/mono `ui-monospace` for register/log values. Hero numbers
  32–44/700 tabular-nums.
- Density: generous. This is a pitch surface, not an ops terminal — prefer 3 strong
  cards over 8 cramped ones. Empty states get one quiet sentence, never a spinner farm.

## 4. Views

### `/studio` — Savings Studio (the money view)
Two-zone layout. **Left rail (320px): scenario builder** — location picker (3 scenario
cards with city + one-line territory blurb), month chip, tariff multi-select (chips w/
utility name + confidence badge), instrument sliders (PV kW, battery kWh/kW, EV toggle +
commute), "Run" button (`--green-ink` filled, bolt icon). Defaults pre-loaded so the
first paint already shows a result. **Main zone:**
1. **Hero strip**: three stat tiles — "Without LEXA $412.33" (gray), "With LEXA
   $278.28" (green-ink, `--sage-soft` fill), "Saved $134.05 · 32.5%" (hero, `--bolt`
   underline accent). Small provenance line under the strip.
2. **Cumulative cost race** (line, x=day, y=cumulative $): baseline gray, dumb blue,
   LEXA green; direct labels at line ends; the gap between baseline and LEXA lightly
   filled `--sage-soft`.
3. **Bill breakdown** (two horizontal stacked bars, one per policy): line-item kinds as
   segments (energy/fixed/riders/demand/export-credit as negative), 2px gaps, table
   view toggle. Export credit renders left of zero.
4. **TOU heatmap** (x=day 1..31, y=hour 0..23, cell=rate): sequential amber ramp,
   battery-discharge overlay as small green dots, cell tooltip (date, hour, rate,
   battery/EV action). One per selected tariff (small multiples, max 2).
5. **Day detail** (the engine's `day_detail`): stacked area of load/pv/batt/ev with
   grid line overlaid + rate band strip underneath; picker for date.
6. **Plan comparison table** when >1 tariff: per-tariff totals per policy, best cell
   highlighted `--sage-soft`, provenance + confidence badges.
Assumptions/provenance card at the bottom (weather source, load model sentence, tariff
sources with URLs + retrieved dates + confidence).

### `/ops` — Live Ops (watch the hub think)
1. **Power flow diagram** (top, full width, ~260px): five nodes (Grid, Solar, Battery,
   Home, EV) in the entity colors, SVG links whose stroke width ∝ |W| with animated
   dash-flow in the flow direction; W labels on links; node cards show live value +
   sparkline (last 5 min). Data: 1 s `/api/hub/status` poll.
2. **Hub brain** (left card): live `last_plan.decisions[]` feed — rows of
   `[rule] reason → impact`, newest first, mono, rule as a `--sage-soft` chip; a mode
   badge; stale-source warnings (`--s-warn` chip + icon) from `status.stale_sources`.
3. **Plan vs actual** (right card): `/api/hub/plan` 24 h series (planned grid/battery)
   as dashed lines vs live measured solid; its economics as a small stat row.
4. **CSIP Protocol Inspector** (full width): three columns —
   *Advertised* (gridsim `/admin/status` programs: controls w/ primacy, default
   control; `/admin/tariff` intervals w/ live countdown to next price change);
   *Adopted* (hub `csip_control`: mRID, type, limit, valid-until countdown);
   *Measured* (meter W vs limit, compliance state chip). Mismatches get `--s-warn`
   outline. This card is the "criteria the grid is using" proof surface.
5. **Grid event console** (card): preset event buttons (export cap, import cap, gen
   limit, cease) + custom form; on fire: timeline strip showing issued→adopted→
   compliant with measured seconds between; assertion verdict chip on settle.

### `/proof` — Proof Center
1. **Safety case strip**: 4 invariant cards (INV-SOC, INV-CONNECT, INV-EXPORT,
   INV-EXPIRED): plain-language one-liner, last-campaign status icon+label, "tested by
   N scenarios".
2. **Scenario browser**: table from `/api/qa/scenarios` (69) — id, name, category chip,
   source chip (go/spec), extended badge, hypothesis on expand; filter row (category,
   source, text); checkbox select + presets (Quick 7 / Full curated / Extended).
3. **Run panel**: start (sample cadence select) → progress bar, phase chip
   (setup/hold/recover), live verdict pills accumulating; **live timeline chart** of
   the running scenario from `status.live[]`: real meter W (solid blue) vs hub-believed
   W (dashed gray) — divergence shaded `--s-serious` at 20% opacity; breach markers;
   CannotComply ticks; decisions feed sidebar.
4. **Findings list**: verdict icon+label chips, headline, metric chips, expandable
   diagnosis; `violations[]` rendered as a mini timeline strip per finding.
5. **History**: past reports from `/api/qa/reports` — list + click-through rendered
   markdown; pass-rate trend line when ≥3 campaigns.

### `/logs`
Merged SSE stream (existing `{src,line,at}`): per-source color chips (entity colors ONLY
for sim sources by role; hub=ink; grid=`--green-ink`), level detection (ERROR/WARN
highlighting via `--s-*` text, not fills), regex + text filter, pause/resume with
buffered count, autoscroll toggle, export. Virtualized list (10k ring), mono 12px.

### `/bench`
Per-sim cards (solar/battery/meter/EV): live state, inject/control forms (port the
legacy tab functions), register table (mono, scaled values + raw), SunSpec model
labels. Utility surface — plain, functional, still on-brand.

## 5. Voice

Labels sell without hype: "Saved $134 this July" not "AMAZING SAVINGS!!". Provenance
lines are quiet but always present. Verdicts stay technical (PASS/FAIL/BLIND) — the
credibility IS the pitch. En-dash ranges, tabular numbers, $ with 2 decimals under
$1000, else whole dollars. Dates as "Jul 21".
