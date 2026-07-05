# QA STOCK-timing triage template

*Use this to triage every non-PASS verdict from a `scripts/mayhem-campaign.sh
--mode stock` run before writing the campaign report
(`docs/QA_REPORT_STOCK_M<n>_<date>.md`). One row per distinct failure
signature (group repeat offenders across cycles the way the FAST reports do
— see `docs/QA_REPORT_V5_20260703.md`'s "Repeat-Offender Tally").*

## Standing rule (03 P0 exit criteria)

> STOCK failures are findings, not M0/phase blockers, unless they reveal a
> **safety regression** — a violation of INV-SOC, INV-CONNECT, INV-EXPORT,
> or INV-EXPIRED. Safety regressions escalate immediately as blockers,
> regardless of timing regime.

STOCK timing (engine 15 s / discovery 20 s / poll 10 s) is what the product
actually ships. Running it is expected to surface noise that FAST (engine
3 s / discovery 5 s / poll 2 s) never could: scenario `HoldS` windows and
settle margins were calibrated against FAST latencies (CLAUDE.md), so a
STOCK-only DEGRADED/FAIL is data about the harness *or* the product, not
automatically a regression. The job of this triage is to sort which.

**Never weaken an oracle to make STOCK green** (06 §4.5). A margin change is
only acceptable with a physical justification written into the scenario's
`Fix` text — see the HoldS-45 clock-jitter precedent. Absent that
justification, the correct dispositions are "product-latency finding" or
"accepted STOCK behavior," not a silent scenario edit.

## Triage table

| Scenario | STOCK verdict(s) (cycle sequence) | FAST baseline verdict | Delta class | Evidence pointer | Disposition |
|---|---|---|---|---|---|
| `example-scenario-id` | e.g. `F P F F P P F P P F` (7/10 non-PASS) | PASS (V6, 0/10 FAIL) | product-latency finding / harness-margin miscalibration / accepted STOCK behavior | `logs/campaign-stock-<ts>/cycle-03.json` finding `example-scenario-id`; hub journal excerpt if relevant | Finding `QA-STOCK-NNN` filed in `docs/QA_FINDINGS.md` / margin change with justification in scenario `Fix` text / accepted — no action |

### Column definitions

- **Scenario** — the Mayhem scenario ID (`--list` to enumerate).
- **STOCK verdict(s)** — the full per-cycle sequence for this scenario from
  `scenario-drift.tsv` (e.g. `P P F D P F P P P P`), plus the FAIL/BLIND
  count out of N cycles.
- **FAST baseline verdict** — how this scenario behaved in the FAST baseline
  being defended (V6: 0.6 FAIL/cycle, 0 BLIND; accepted DEGRADEDs per
  `docs/QA_REPORT_V5_20260703.md`). "Clean" if it never appears in the FAST
  repeat-offender tally.
- **Delta class** — exactly one of:
  - **product-latency finding** — the hub's real behavior is slower/wronger
    at STOCK cadence than the scenario's window allows for a legitimate
    reason (e.g. a fix that assumes sub-poll-interval reaction time). File
    it; it is real product behavior users will see.
  - **harness-margin miscalibration** — the *scenario's* `HoldS`/settle
    window assumed FAST cadence and STOCK's slower ticks structurally can't
    fit inside it, even though the hub is doing the right thing. Only valid
    with a physical justification (tick counts, not "make it pass") written
    into the scenario's `Fix` text, and only as a follow-up change — do not
    edit margins inside this triage pass.
  - **accepted STOCK behavior** — expected, harmless, already-understood
    slower convergence at STOCK cadence (e.g. a CannotComply that takes
    proportionally longer to post because poll_interval_s tripled). No fix
    needed; document the reasoning so the next campaign doesn't re-litigate
    it.
- **Evidence pointer** — cycle JSON file + finding ID at minimum; hub/sim
  journal excerpt (`journalctl -u lexa-hub`) if the finding's `diagnosis`
  isn't self-explanatory.
- **Disposition** — one of:
  - a new finding ID in `docs/QA_FINDINGS.md` (pattern: follow the existing
    entries' format — headline, evidence, suspected file, priority),
  - a margin change, ONLY with the physical justification recorded in the
    scenario's own `Fix` text (mayhem.go), referenced here by commit/PR,
  - "accepted — no action," with the one-line reasoning inline.

## Safety-invariant check (do this first, every row)

Before classifying anything above, scan every FAIL/BLIND finding's
`headline`/`diagnosis` for a safety-invariant violation:

- **INV-SOC** — battery SoC driven outside safe bounds.
- **INV-CONNECT** — a device commanded to a state that violates
  connect/disconnect safety (e.g. reconnecting energized).
- **INV-EXPORT** — export limit breached with the hub believing it's
  in compliance (`hub_adopted=True, hub_reacted=True` but no
  `reported_cannot_comply` and no convergence).
- **INV-EXPIRED** — an expired/stale control still being asserted
  (`ValidUntil` in the past, hub still enforcing it).

Any of these — regardless of delta class, regardless of whether the FAST
baseline was clean — escalates immediately as a blocker, not a triage row.
Say so explicitly in the report's summary and do not let it get lost among
accepted-STOCK rows.

## Summary rollup (goes in the campaign report, not here)

- Total scenario-cycles run: `51 × N`.
- Per-cycle PASS/DEGRADED/FAIL/BLIND/INCONCLUSIVE averages (from
  `summary.tsv`).
- Count of rows per delta class.
- Count of findings filed vs. margin changes made (expect ~0 margin changes
  per "never weaken an oracle without justification").
- Any safety-invariant escalations (expect 0; if not 0, this is the
  headline of the report, not a footnote).
- The declared STOCK baseline numbers this campaign becomes, for future
  release gates to compare against (mirrors the FAST V6 baseline sentence
  in `docs/refactor/00_MASTER_INDEX.md`).
