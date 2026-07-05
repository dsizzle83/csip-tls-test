# Behavior-Preservation Ledger

*Created by TASK-025 (2026-07-05). Governs Phase 2 (Device Reconciler,
TASK-026…033) and the reporting-path changes that ride with it.*

## What this is

The LEXA hub makes "the device match what the hub wants" true through several
**legacy convergence mechanisms** — the optimizer's per-tick restore rule, the
actuator command dedupers + re-assert watchdog + breach reset, `lexa-modbus`'s
reconnect re-assert, and the multi-hop CannotComply chain. **Every one of them
encodes a specific QA scenario** (review W2, RSK-01): each was written to make a
named Mayhem fault-injection scenario pass. Deleting one without knowing which
scenario it protects silently reopens that scenario.

This ledger is the contract that lets AD-002's reconciler (AD-013 schema)
replace that code while **provably preserving behavior**. Each row maps one
legacy mechanism to: the scenario/finding that created it, the behavior that
must survive the replacement, what replaces it, and the Mayhem scenarios that
gate the swap.

## The rule (05 §11)

**No row's mechanism may be deleted until its gate scenarios pass — green — on
the replacement.** Behavior survives even when code does not. A reconciler task
that removes a mechanism whose gate scenarios have not been re-run (or that
regress) is not done, regardless of unit-test status.

## How this file is maintained

- **TASK-027…033 update the `Status` column** as they land: `legacy-active` →
  `shadow` (reconciler observing, legacy still authoritative) → `replaced`
  (legacy deleted, gates green) — or `keep` / `keep-until-P5` rows stay as-is.
- File:line citations are @HEAD as of the date in the header row; a task that
  finds them drifted re-verifies and corrects them in the same PR (the tree
  moves — this table was itself re-verified against HEAD on 2026-07-05, and 8 of
  11 rows' line numbers had drifted from the TASK-025 draft).
- Gate-scenario names must exist in the Mayhem catalog (`cmd/dashboard/mayhem.go`,
  `mayhem_world.go`, `mqtt_scenarios.go`; `scripts/mayhem.py --list`).

## Ledger

| # | Legacy mechanism (file:line @2026-07-05) | Originating QA scenario / finding | Behavior that must survive | Replaced by | Gate scenarios | Status |
|---|---|---|---|---|---|---|
| L1 | `applyRestoreRule` per-tick re-command (`optimizer.go:2241–2276`, call site `:365–366` with `solarCapActive` gate) | curtailment-release Mode A/B; solar-reboot-forget (re-assert each cycle); 92-day-replay battery reserve sail-through (in-code comment `:2259–2268`) | Uncommanded connected battery idled to 0 W at ANY SoC (idle enforces the reserve); uncurtailed inverter restored; dark inverter under an active cap KEEPS held curtailment; after release, restore reaches a dark inverter on reconnect | Retained desired doc is the standing intent; reconciler reasserts (T026–T029) | curtailment-release, release-while-rebooting, solar-reboot-forget | legacy-active |
| L2 | `cmdDeduper` + `reassertEvery=60s` watchdog (`cmd/hub/actuators.go:24` const, `:26–56` deduper+`shouldSend`+`reset`; per-actuator `dedupe` fields `:59–147`) | export-cap-full-battery ghost (watchdog re-assert); lexa-modbus/-ocpp restart resync | A restarted/state-lossy consumer re-converges without waiting on a command *change* (today ≤60 s; retained doc makes it immediate on subscribe) | Broker redelivers retained doc on subscribe; reconciler reassert (T026/T027) | export-cap-full-battery, battery-reboot, mqtt-broker-restart | legacy-active |
| L3 | Breach-triggered dedupe reset (`cmd/hub/actuators.go:45–56` `reset()`; `cmd/hub/main.go:104–107,130–134` `dedupeResets` in `planObserver`, wired `:218/:222/:230`) | QA 2026-07-03: 0 W ceiling dedupe-suppressed 30 s against an uncurtailed inverter while CannotComply posted (device reverted behind hub's back) | A device that reverts while the commanded value is unchanged gets a corrective write bounded by the poll/readback interval, not by a 60 s watchdog | Reconciler verify-by-readback + write-on-diff (T026) | export-cap-full-battery, curtailment-release, control-churn | legacy-active |
| L4 | `retryDevice.lastCtrl` + `reassertLocked` (`cmd/modbus/main.go:336–433`; reconnect reconcile in `ReadMeasurements` `:372–384`; desired recorded while disconnected `:421–427`; never-commanded-inverter stale-ceiling clear `:411–414`) | QA 2026-07-02: release-while-rebooting (released cap left inverter clamped at stale ceiling indefinitely) | Reconnected device converges to hub's CURRENT desire before its first measurement is trusted; never-commanded inverter gets a stale-ceiling clear; never-commanded battery gets nothing; meter never written | Reconciler reassert-on-reconnect from retained doc (T026/T027) — `retryDevice` session drop/reopen mechanics stay | release-while-rebooting, solar-reboot-forget, battery-reboot | legacy-active |
| L5 | `breachAlert` mRID-keyed edge detector + `activeBreachMRID` (`cmd/hub/main.go:103`, `:253–281`); `Plan.Safety` nil-Breach guard (`orchestrator/model.go:311–319`) | reject-write-curtail / enable-gate-curtail flakiness (mRID-agnostic flag latched across episodes); 2026-07-03 safety-plan spurious clear | One alert at onset, one at clear; a NEW mRID breaching mid-episode re-alerts; safety plans (Breach==nil means "not assessed") never emit a clear edge | Named breach-episode component (T031) | reject-write-curtail, enable-gate-curtail, export-cap-full-battery | legacy-active |
| L6 | `responseTracker` CannotComply episode dedupe (`cmd/northbound/main.go:221–231` alert consumer; `:707–754` `alerted` map / `alertCannotComply` / `clearAlerts`) | CannotComply spam per tick vs one per episode (design; V3 CannotComply timing races) | Exactly one CannotComply POST per breach episode; clear re-arms | Episode-ID-carrying report chain (T031) | battery-soc-refuse, battery-empty-import-cap | legacy-active |
| L7 | `restoreOnGenLimitClear` + `genCapActive` (`optimizer.go:163–166`, `:1251–1276`) | curtailment-release Mode A (V3 Issue 1: release is a WRITE, not an absence of writes) | Explicit uncurtail emitted on the cap active→clear edge | Desired doc transitions to restore ceiling on release (T029); deletion only if gates stay green | curtailment-release | legacy-active |
| L8 | Tier-0 battery interlock (`cmd/modbus/interlock.go`, whole file) | battery-wrong-sign (ADR-0001 Tier 0: local reflex, survives hub/broker death) | **KEEP — not replaced.** Force-disconnect within one poll of charge-commanded pack discharging near reserve; never reconnects on its own; sits ABOVE the reconciler | n/a (reconciler must defer to it, T027/T028) | battery-wrong-sign | keep |
| L9 | `plausibleW` nameplate gate (`cmd/modbus/main.go:283–300`, call site `:169`) | solar-bad-scale (GS-1/MTR-1: corrupt scale factor ≈10× truth) | **KEEP.** Implausible W withheld from the bus; pattern reused for reconciler readback plausibility | n/a (T026 borrows the pattern) | solar-bad-scale | keep |
| L10 | Optimizer convergence guards: `expOverTicks` session scoping (`optimizer.go:132–142`), `checkExportLimitConvergence:1194`, `checkGenLimitConvergence:1344` (meter floor gen ≥ export − battDischarge), `checkImportConvergence:1446`, `battDrainTicks`/`battWrongDirTicks`/`criticalBatteryInversion`/`checkBatterySafety` (`:1493–1641`) | control-churn + clock-jitter (silent breach via counter reset); battery-charge-disabled; battery-soc-refuse; battery-wrong-sign | **KEEP until P5 (R4).** Measured-effect breach detection and safety backstop stay in the optimizer; only their REPORTING path changes (T031) | R4 constraint sessions (T060–062) | control-churn, clock-jitter, battery-charge-disabled, battery-soc-refuse, battery-wrong-sign | keep-until-P5 |
| L11 | EVSE rejected-profile-as-error + `implausibleCurrent` (`cmd/ocpp/main.go:294–350` `applyCommand`, reject check `:343–345`; `implausibleCurrent` + call site `:393–416`) | ev-profile-reject / ev-accept-but-ignore (delivered-but-rejected ≠ success); ev-wrong-units | **KEEP.** Rejected SetChargingProfile surfaces as failure; implausible MeterValues never ingested | Folded into EVSE reconciler driver semantics unchanged (T030) | ev-profile-reject, ev-accept-but-ignore, ev-wrong-units | keep |

## Notes on re-verification (2026-07-05)

Line numbers drifted from the TASK-025 draft (the tree moved through P0/P1).
Corrected rows: **L2** (per-actuator fields 144→147), **L3** (`main.go`
99–118 → 104–107, 130–134), **L4** (module region 314–412 → 336–433;
desired-while-disconnected 396–406 → 421–427; stale-ceiling clear 385–394 →
411–414), **L5** (`main.go` 98 → 103, 230–257 → 253–281; `model.go` 315–320 →
311–319), **L6** (203–213 → 221–231, 666–710 → 707–754), **L9** (261–278 →
283–300), **L10** (checkBatterySafety end 1648 → 1641), **L11** (258–314 →
294–350, 349–368 → 393–416). Unchanged and re-confirmed: **L1, L7, L8**. All 18
distinct gate-scenario names were confirmed present in the Mayhem catalog.

## Shadow observations (TASK-027, 2026-07-05)

Code landed (lexa-hub `task/027-battery-shadow`): the hub-side battery
desired-doc publisher (`cmd/hub/desired.go`, additive — legacy actuator
delegated to first, unchanged) and the lexa-modbus shadow shell
(`cmd/modbus/reconcile_shadow.go`) driving one `internal/reconcile.Reconciler`
per battery device off the retained doc, poll readbacks, and observed legacy
writes, logging `reconciler[shadow] ...` verdict lines — a recorder only, no
write path. **Status column for L1–L4 intentionally left at `legacy-active`**:
this session was code + unit tests only (no bench deploy); the bench soak,
verdict/campaign evidence, and the `shadow` status flip are the wave-gate
follow-up the task names, not yet done.

Two things to carry into that soak, found while wiring the first real
consumer against lexa-modbus's actual (partial) measurement capability:

- **Reconnect-on-drop (L4) is deliberately not fed to the shadow.** The
  task's shadow-feed list is desired docs + poll readbacks + observed legacy
  writes only; `reconcile.Reconciler.Reconnected` is never called from
  `reconcile_shadow.go`. A battery that drops mid-poll never reaches
  `Observe` at all (its poll-error update is skipped upstream before the
  shadow is invoked), so the shadow's assessment simply holds through the
  outage and resumes at the next successful poll. Legacy's
  `retryDevice.lastCtrl` reassert-on-reconnect is unconditional and immediate;
  the shadow's write-on-diff (were it live) would only fire on the next poll
  that observes a mismatch. Watch `battery-reboot` specifically for a
  reconciler-vs-legacy timing gap in the divergence log — expected to be a
  documented semantic difference (reconciler slower by up to one poll
  interval), not a bug, but it needs a real disposition from the soak, not an
  assumption from this desk.
- **A battery doc expressing both `SetpointW` and `Connect` (the common real
  shape — e.g. the reserve-idle tick reconnects and idles every cycle) can
  never be judged "converged" by the shadow**, because lexa-modbus has no
  register to read Connect state back from. `internal/reconcile`'s
  completeness gate correctly holds forever in that case (verified
  deterministic — see the `reconcile.go` fix below), which the shadow reports
  as a permanent, silent hold rather than a match or a divergence. This is
  expected and by design (ledger L9's discipline: an unassessable sample
  proves nothing), but it means the shadow's `match` rate during the soak
  will be lower than "the reconciler agrees with legacy" — most battery
  decision points will simply never resolve to a verdict at all until a
  Connect readback exists. Worth a line in the TASK-028 write-up so nobody
  reads a quiet `matches` counter as "everything converged."

**Incidental fix, filed here for traceability:** `internal/reconcile.matches()`
(TASK-026, merged) had an order-dependent bug — a doc expressing two fields
where only one is ever supplied by the readback could non-deterministically
report `complete=true` or `complete=false` depending on Go's randomized map
iteration order, contradicting the package's own "hold on incomplete, never
write-storm" guarantee. Fixed in the same lexa-hub commit as this task (two-pass
check: completeness for every key first, then tolerance), with a new
regression test (`TestPartialReadbackIsCompleteDeterministic`). This is exactly
the L1–L4/Connect situation above — the bug would otherwise have made the
shadow's verdict flicker between `match`/`diverge` on identical inputs.
