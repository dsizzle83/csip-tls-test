# TASK-063 seam review — economic layer below the constraint controller

*PR appendix (step 6). Written review, no code. Companion to AD-007's TASK-063
note and the `internal/orchestrator/constraint` package doc. Reviews the two
seams the task flags — battery-reserve across tiers, and first-active-EVSE — and
characterises the full-stack shadow divergence for TASK-064.*

## 1. Battery-reserve interaction across the three tiers

The SOC reserve (default 20 %) is touched by three tiers. The task asks: name the
winner for each pairwise interaction. In the constraint model the winner is
decided by the tier-aware arbiter (safety > compliance > economics) plus the
post-arbitration safety override — not by ad-hoc if-ordering.

| Pair | What each wants at/near reserve | Winner | Mechanism |
|---|---|---|---|
| **Economics floor vs Economics** | Rules 2/2.5/5 all self-limit: fixed-dispatch and TOU skip a pack at `SOC ≤ reserve`; plan-following's live-SOC clamp zeroes a discharge share at `SOC ≤ reserve`. | n/a (self-consistent) | Ported verbatim into `EconomicsConstraint` (`socReserve`), so economics never *proposes* a discharge below reserve. |
| **Economics discharge vs Compliance import-cap discharge** | Both discharge; import defends the cap only as far as needed, economics (TOU) proposes `MaxDischargeW`. Import compliance ALSO stops at reserve (`applyImportControl` skips `SOC ≤ reserve`). | **Compliance** | Arbiter cross-tier fold keeps the (smaller) compliance discharge point; economics is clamped down. `TestEconomics_TOUDischargeClampedByImportCapInStack`. Neither drives below reserve because both self-limit there. |
| **Economics discharge vs Safety reserve-drain** | Economics may propose a discharge; safety trips (force-disconnect) after `batteryReserveDrainTicks` of measured discharge at/below reserve, OR immediately on critical inversion. | **Safety** | Safety runs POST-arbitration and overrides the resolved command to `{0, disconnect}`, dominating every tier. The reserve-drain check is on MEASURED power+SOC, independent of the economics command. |
| **Compliance import discharge vs Safety** | Import defends the cap by discharging; if the pack inverts/keeps draining at reserve, safety disconnects. | **Safety** | Same post-arbitration override. A CannotComply(import) may be reported the same tick (compliance breach) while safety ceases the pack — the two are not in conflict: the cap is genuinely unmeetable AND the pack is protected. |

**Net rule:** at the reserve floor, **safety disconnect > compliance discharge >
economics discharge**, and every tier independently refuses to *command* a
sub-reserve discharge, so the reserve is defended in depth. The one behaviour the
constraint model does NOT reproduce from the cascade is legacy's *charge
neutralisation* (import rule walking the shared plan to zero a commanded charge):
there is no shared plan; the arbiter resolves the shared battery axis instead
(documented in `importlimit.go`; only reachable under a contradictory
simultaneous import+export cap, not in the scenario families).

## 2. First-active-EVSE selection (single-EVSE assumption)

Legacy `applyExportLimitRule` and `applyEVChargingRule` both select EVSEs with a
`for … { if Connected && SessionActive { ev = …; break } }` first-match loop
(export: `optimizer.go:721-728`; the EV rule iterates all EVSEs but the
export-side pre-position uses only the first). The single-EVSE assumption is
therefore contained in **two places**:

- **Export ceiling feed-forward** (compliance) — uses ONE active EVSE's setpoint
  in the conservation identity / feed-forward ceiling. Ported as-is into
  `ExportConstraint` (still first-match); a second charging EVSE is not counted in
  the export feed-forward. This is a `TASK-065` change (all-active EVSEs in the
  export identity), NOT a `063` change — `063` preserves the legacy behaviour.
- **EV allocation** (economics) — `applyEVChargingRule` DOES iterate every active
  EVSE and command each; the per-EVSE `hasEVSECommand` guard prevents double
  authoring. So economics already emits one demand per active connector, keyed
  `station#connector` (the Stack now carries the OCPP connector via
  `parseEVSEDevice`). The single-EVSE limitation is thus **only** in the export
  feed-forward's *sizing*, not in who gets commanded.

**What TASK-065 must change:** (a) sum ALL active EVSEs into the export
conservation identity / feed-forward ceiling (`ExportConstraint`), replacing the
first-match pointer; (b) confirm the economics EV budget (`surplusW` splitting) is
divided across multiple active sessions rather than the first one consuming it.
Neither touches the tier seam — both are within-constraint sizing fixes.

## 3. Characterised full-stack shadow divergence (for TASK-064)

The full stack (safety + compliance + economics) now shadows the whole cascade.
Expect MORE divergence than the compliance-only shadow — this is expected and is
the finding for `TASK-064`, not a defect to bit-match now.

**Faithful (≈0 divergence expected):**

- **Off-cap ticks** (no active export/import/gen limit): the compliance rules are
  no-ops, so a below-compliance economics layer sees exactly what the cascade fed
  its economic rules. Self-consumption, TOU peak, and EV allocation reproduce the
  cascade. Proven in-process: `TestEconomics_ShadowParityOffCap` (full stack vs
  real `DefaultOptimizer`, 0 divergence across a self-use / TOU / EV sequence).
- **Battery reserve-drain / critical-inversion safety** (no command dependence, or
  reads this-tick resolved setpoint): bit-faithful — the post-arbitration ordering
  closes the ≤1-tick wrong-direction lag.

**Divergence EXPECTED (owned by TASK-064):**

- **On-cap economic ticks.** In the cascade the compliance rules run BETWEEN the
  economic rules and mutate the shared `surplusW` / battery `PowerW` the later
  economic rules read (export absorbs into the battery and lowers `surplusW`
  before self-consumption/TOU/EV see it; import discharges the battery before the
  EV budget is sized). A below-compliance economics layer computes `surplusW` from
  raw state and threads only its OWN prior sub-rule commands, so its
  self-consumption sizing and EV budget differ whenever a cap is active. This is
  the shared-state seam TASK-064 owns (constants→plant + one owner for the
  surplus/headroom the tiers pass down).
- **EV import cooldown edges.** `evSafeCount` is reproduced economics-locally
  (preserving the `battery-empty-import-cap` suspension) but its seed/increment
  ordering relative to the import constraint's own copy can differ by a tick on cap
  arrival — a small, bounded divergence until TASK-064 gives the counter one owner.
- **Same-battery contradictory caps** (simultaneous import+export cap): the arbiter
  collapses the battery axis rather than legacy's import-wins-and-neutralises — a
  known gap (`importlimit.go`), not in the scenario families.

**Bottom line for the flip:** the compliance layer is proven at 0 divergence; the
economics layer is faithful off-cap and diverges on-cap in exactly the places the
cascade's compliance interleaving is load-bearing. Those places are TASK-064's
constants→plant + shared-state work; the flip is gated on that plus the ≥1-week
clean-shadow soak (P5 plan). Do not force economics to bit-match a
bench-calibrated cascade interleaving — move the interleaved state into the plant
model / a shared owner (TASK-064) and re-measure.
