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
| L1 | `applyRestoreRule` per-tick re-command (`optimizer.go:2241–2276`, call site `:365–366` with `solarCapActive` gate) | curtailment-release Mode A/B; solar-reboot-forget (re-assert each cycle); 92-day-replay battery reserve sail-through (in-code comment `:2259–2268`) | Uncommanded connected battery idled to 0 W at ANY SoC (idle enforces the reserve); uncurtailed inverter restored; dark inverter under an active cap KEEPS held curtailment; after release, restore reaches a dark inverter on reconnect | Retained desired doc is the standing intent; reconciler reasserts (T026–T029) | curtailment-release, release-while-rebooting, solar-reboot-forget | **spam-half deleted (T032, commit 20cc2b2)** — the per-tick QoS 1 publish through the legacy actuators is gone; `applyRestoreRule` (the INTENT) is KEPT and now feeds the desired-doc publisher (comment clarified in f87136c). Gate: curtailment-release + release-while-rebooting **PASS**, solar-reboot-forget accepted-DEGRADED (`qa-mayhem-20260706-010740.md`) |
| L2 | `cmdDeduper` + `reassertEvery=60s` watchdog (`cmd/hub/actuators.go:24` const, `:26–56` deduper+`shouldSend`+`reset`; per-actuator `dedupe` fields `:59–147`) | export-cap-full-battery ghost (watchdog re-assert); lexa-modbus/-ocpp restart resync | A restarted/state-lossy consumer re-converges without waiting on a command *change* (today ≤60 s; retained doc makes it immediate on subscribe) | Broker redelivers retained doc on subscribe; reconciler reassert (T026/T027) | export-cap-full-battery, battery-reboot, mqtt-broker-restart | **deleted (T032, commit 783a4c5)** — `cmdDeduper`+`reassertEvery` watchdog removed after the legacy publishers went (commit A, 20cc2b2). Broker redelivers the retained desired doc on subscribe (immediate, not 60 s-bounded). Gate: battery-reboot **PASS**, export-cap-full-battery + mqtt-broker-restart accepted-DEGRADED/recovered (`qa-mayhem-20260706-010740.md`) |
| L3 | Breach-triggered dedupe reset (`cmd/hub/actuators.go:45–56` `reset()`; `cmd/hub/main.go:104–107,130–134` `dedupeResets` in `planObserver`, wired `:218/:222/:230`) | QA 2026-07-03: 0 W ceiling dedupe-suppressed 30 s against an uncurtailed inverter while CannotComply posted (device reverted behind hub's back) | A device that reverts while the commanded value is unchanged gets a corrective write bounded by the poll/readback interval, not by a 60 s watchdog | Reconciler verify-by-readback + write-on-diff (T026) | export-cap-full-battery, curtailment-release, control-churn | **deleted (T032, commit 783a4c5)** — breach-triggered `dedupeResets` + observer reset block removed with `cmdDeduper`. A device reverting behind the hub's back is now corrected by reconciler verify-by-readback + write-on-diff (≤ poll/readback), and device non-convergence rides `breachEpisodes` via `lexa/reconcile/+/+/report`. Gate: curtailment-release + control-churn **PASS**, export-cap-full-battery accepted-DEGRADED (`qa-mayhem-20260706-010740.md`) |
| L4 | `retryDevice.lastCtrl` + `reassertLocked` (`cmd/modbus/main.go:336–433`; reconnect reconcile in `ReadMeasurements` `:372–384`; desired recorded while disconnected `:421–427`; never-commanded-inverter stale-ceiling clear `:411–414`) | QA 2026-07-02: release-while-rebooting (released cap left inverter clamped at stale ceiling indefinitely) | Reconnected device converges to hub's CURRENT desire before its first measurement is trusted; never-commanded inverter gets a stale-ceiling clear; never-commanded battery gets nothing; meter never written | Reconciler reassert-on-reconnect from retained doc (T026/T027) — `retryDevice` session drop/reopen mechanics stay | release-while-rebooting, solar-reboot-forget, battery-reboot | **deleted (T032, commit 9fbcaa0)** — `retryDevice.lastCtrl` + `reassertLocked` (incl. the never-commanded-inverter stale-ceiling clear) removed; reassert-on-reconnect is now solely the reconciler's, via `retryDevice.onReconnect` → shell `Reconnected()` + solar restore-ceiling seed. Retry mechanics (reopen, `dropLocked`, mutex) KEPT. Gate: release-while-rebooting + battery-reboot **PASS**, solar-reboot-forget accepted-DEGRADED (`qa-mayhem-20260706-010740.md`) |
| L5 | `breachEpisodes` component (`cmd/hub/breach.go`), fed by the plan observer (`cmd/hub/main.go`); `Plan.Safety` nil-Breach guard (`orchestrator/model.go:311–319`) | reject-write-curtail / enable-gate-curtail flakiness (mRID-agnostic flag latched across episodes); 2026-07-03 safety-plan spurious clear | One alert at onset, one at clear; a NEW mRID breaching mid-episode re-alerts; safety plans (Breach==nil means "not assessed") never emit a clear edge | Named breach-episode component (T031) | reject-write-curtail, enable-gate-curtail, export-cap-full-battery | **restructured (T031)** — `breachAlert`/`activeBreachMRID` closure retired into the named `breachEpisodes` struct (merges optimizer + reconciler evidence under one episode ID); ported edge + Safety-guard mutation tests green (`cmd/hub/breach_test.go`) |
| L6 | `responseTracker` CannotComply episode dedupe (`cmd/northbound/main.go` alert consumer; `alerted` map / `alertCannotComply(mrid,episodeID)` / `clearAlerts`) | CannotComply spam per tick vs one per episode (design; V3 CannotComply timing races) | Exactly one CannotComply POST per breach episode; clear re-arms | Episode-ID-carrying report chain (T031) | battery-soc-refuse, battery-empty-import-cap | **restructured (T031)** — dedupe keys on `EpisodeID` when present, MRID otherwise (mixed-version + hub-restart safety net); `TestResponse_CannotComply*` green |
| L7 | `restoreOnGenLimitClear` + `genCapActive` (`optimizer.go:163–166`, `:1251–1276`) | curtailment-release Mode A (V3 Issue 1: release is a WRITE, not an absence of writes) | Explicit uncurtail emitted on the cap active→clear edge | Desired doc transitions to restore ceiling on release (T029); deletion only if gates stay green | curtailment-release | **deleted (T032, commit f87136c)** — differential-equivalent to `applyRestoreRule` + the retained desired doc (both emit the NaN restore in the same pass). Gate: curtailment-release **PASS** (`qa-mayhem-20260706-010740.md`) → deletion held, no revert |
| L8 | Tier-0 battery interlock (`cmd/modbus/interlock.go`, whole file) | battery-wrong-sign (ADR-0001 Tier 0: local reflex, survives hub/broker death) | **KEEP — not replaced.** Force-disconnect within one poll of charge-commanded pack discharging near reserve; never reconnects on its own; sits ABOVE the reconciler | n/a (reconciler must defer to it, T027/T028) | battery-wrong-sign | keep |
| L9 | `plausibleW` nameplate gate (`cmd/modbus/main.go:283–300`, call site `:169`) | solar-bad-scale (GS-1/MTR-1: corrupt scale factor ≈10× truth) | **KEEP.** Implausible W withheld from the bus; pattern reused for reconciler readback plausibility | n/a (T026 borrows the pattern) | solar-bad-scale | keep |
| L10 | Optimizer convergence guards: `expOverTicks` session scoping (`optimizer.go:132–142`), `checkExportLimitConvergence:1194`, `checkGenLimitConvergence:1344` (meter floor gen ≥ export − battDischarge), `checkImportConvergence:1446`, `battDrainTicks`/`battWrongDirTicks`/`criticalBatteryInversion`/`checkBatterySafety` (`:1493–1641`) | control-churn + clock-jitter (silent breach via counter reset); battery-charge-disabled; battery-soc-refuse; battery-wrong-sign | **KEEP until P5 (R4).** Measured-effect breach detection and safety backstop stay in the optimizer; only their REPORTING path changes (T031) | R4 constraint sessions (T060–062) | control-churn, clock-jitter, battery-charge-disabled, battery-soc-refuse, battery-wrong-sign | **export half reimplemented (T060, shadow)** — `expOverTicks` + `checkExportLimitConvergence` + `applyExportLimitRule`/`expGuard` ported to `internal/orchestrator/constraint/export.go`+`export_session.go` with the two reset cadences kept SEPARATE (controller resets on cap-value change; compliance counter resets only on cap-clear-to-NaN). Ported/mutation-verified by `constraint/export_test.go` (`TestExportConstraint_ChurnEscalatesCannotComply`, `_MutationChurn_CounterUnwired`, `_OverTicksSurvivesCapRewrite_ResetsOnClear`, `_BlindMeterHoldsCounter`, `_BatteryStall*`, `_AdaptiveDetectionWindow`); detection window is now adaptive (`Plant.ExportDetectionWindowTicks`, ==3 at bench FAST). Legacy path STILL AUTHORITATIVE — shadow only (0 export-axis divergence over the export family + full FAST campaign, 2026-07-06); flip to `export: active` deferred. gen/import/safety stay keep-until-P5 |
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

### Wave-gate soak results (2026-07-05, P2 wave gate — L1–L4 flipped to `shadow`)

Deployed with `"reconciler":{"battery":"shadow"}`; soak = targeted battery-family
Mayhem run (`export-cap-full-battery, battery-wrong-sign, battery-soc-refuse,
battery-charge-disabled` → 0P/4D/0F/0B, all DEGRADED `cannot_comply=True`, at
baseline) + the full 51-scenario FAST campaign
(`qa-mayhem-20260705-151009.md`: **34P/17D/0F/0B**, within the 32–35P band and
strictly better than the pre-gate 32P/19D baseline — `export-cap-full-battery`
and `solar-reboot-forget` flipped D→P, both known boundary-flaky).

- **Blocking bug found + fixed before the soak could mean anything:**
  `systemd/mosquitto-lexa.acl` had no `lexa/desired/` grant, so with the ACL
  live the retained doc never reached the broker and the shadow's early
  `verdict=match` lines were vacuous (`would=none` because `Desired` was
  never set). Fixed (battery-scoped write grant for lexa-hub, read grant for
  lexa-modbus), lexa-hub branch `task/027-desired-topic-acl` commit 1a2d777.
- **Steady-state divergence rate: 0.** `lexa_mb_shadow_divergences_total` = 1
  for the whole session; the single counted divergence was DURING
  battery-charge-disabled fault injection (`diverge:write-on-diff`, readback
  SOC=100%/W=0 against a charge doc — the reconciler noticing, one poll
  faster than legacy's watchdog window, that a commanded charge wasn't
  happening). Disposition: expected semantic difference, informative for
  T028, not a core bug. Zero Observe-driven divergences in clean operation.
- **Predicted Connect-completeness hold confirmed live:** the battery doc
  always carries `connect`, lexa-modbus has no Connect readback, so
  `lexa_mb_shadow_matches_total` froze (206) once the real doc landed — by
  design. The log line's `verdict=match` text prints for any non-write
  decision and is NOT the counted-match signal; use the counters.
- **L4 reconnect-feed caveat stands** (shadow never calls `Reconnected`);
  `battery-reboot` PASSed with no reconciler-vs-legacy divergence surfacing
  (the hold-through-outage behavior masks the timing gap in shadow).
  T028 must wire `Reconnected` before the flip.
- **AD-013 edge machinery all exercised on real faults:** `StaleDesired` ×3
  (doc aged past staleness while faults froze commanding), `RejectedDoc
  reject=SeqRegression` ×1 (mqtt-broker-restart redelivering an older
  retained doc — correctly rejected), `SeqReset` ×1 (hub-restart-mid-cap:
  seq back to 0 with newer issued_at — accepted, reported). would_writes
  ended at 119 (dominated by benign `new-desired` adoptions under command
  churn) — the write-storm gauge for T028 looks unalarming.

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

## TASK-028 — battery flip to `reconciler-active` (2026-07-05)

L1–L4 **battery-scope** rows flipped `shadow → reconciler-active`: the
`internal/reconcile` core now owns battery hardware writes via the mode-selected
shell (`cmd/modbus/reconcile_shell.go`, lexa-hub branch `task/028-battery-flip`
f7dcef4), driving the SAME `battCommandToControl` + `registry.ApplyControlTo`
path legacy used. **Nothing deleted** — the legacy battery command topic keeps
publishing and being subscribed (ignored on hardware when active; belt and
braces for instant rollback, that is TASK-032's job). Solar/EVSE L1–L4 stay
legacy-active (T029/030).

- **L4 `Reconnected` wired** (the shadow deliberately never fed it): retryDevice
  sets an atomic reconnect flag on reopen; the shell consumes it and reasserts
  the standing desired before the post-reconnect readback is trusted. Verified
  live (batsim drop → `applied … (reason=reconnect-reassert)` next poll) and
  `battery-reboot` PASS. retryDevice's own `lastCtrl` reassert is suppressed for
  the active battery so there is exactly ONE reasserter (no double-write race);
  solar keeps `lastCtrl`.

- **L8 interlock stays `keep` and SENIOR to the reconciler** (AD-002 answer
  confirmed in practice): a read-only `isTripped` accessor was added (no logic
  change; `interlock_test.go` unedited). While Tier-0 has a pack
  force-disconnected, the reconciler **suppresses connect-restoring writes**
  (reports `InterlockHold`) instead of rewriting `Conn=1` — the guard-vs-guard
  oscillation the program exists to kill. Gate evidence: `battery-wrong-sign`
  **PASS**, INV-SOC/INV-EXPORT/SAFETY held, **no INV-HUNT/oscillation**. The
  interlock's charge intent is now fed from the desired doc the reconciler
  executes (moved off the legacy subscribe path).

**Gate results** (`docs/qa-task028/`): targeted battery set 3P/4D/0F/0B (each
PASS or accepted-DEGRADED `cannot_comply=True`); full 51-scenario FAST campaign
**33P/18D/0F/0B**, within the 34P/17D band (sole P→D drift = the task-pinned
accepted-DEGRADED `export-cap-full-battery`). SAFETY held everywhere. Bench left
FAST + battery-active. Rollback rehearsed (config `shadow` + restart).

## TASK-029/030 — solar + EVSE flip to `reconciler-active` (2026-07-05)

L1–L4 **solar-scope** and **L7** flipped `legacy-active → reconciler-active
(solar)`; **L11** noted **preserved-by-reuse (evse)**; L2 EVSE scope →
`reconciler-active (evse)`. lexa-hub branch `task/029-030-solar-evse-flip`
(2cbd894). **Nothing deleted** — legacy solar/EVSE command topics keep publishing
and being subscribed, ignored on hardware when active (belt and braces; TASK-032
deletes). ACL extended: hub write + modbus read `lexa/desired/solar/+`, hub write
+ ocpp read `lexa/desired/evse/+` (installed on the Pi + mosquitto reloaded;
delivery verified by subscription, not publish success).

- **L1/L7 (solar restore is an explicit write).** The hub's
  `desiredPublishingSolarActuator` maps `SolarCommand.CurtailToW` NaN→
  `CeilingW=RestoreCeilingW` (never absent); the `solarShell` reconciler writes
  that ceiling on the cap→clear edge, reproducing `restoreOnGenLimitClear`. The
  retained, connectivity-independent doc keeps the cap value while the inverter
  is dark and the reconciler reasserts on reconnect — so the `solarCapActive`
  dark-inverter gate needs **no publisher equivalent**. Divergence is **one-sided**
  (over-ceiling only); an inverter under its ceiling at dusk is compliant.
- **L4 (solar).** `reassertLocked`'s inverter branch is suppressed for an active
  inverter (`reconciledActive`); the shell's `Reconnected()` reassert plus a
  restore-ceiling **initial-desired seed** (never-commanded case; seed's startup
  write dropped — reassertLocked fires on reconnect, not startup) is the SINGLE
  reasserter. No double-write.
- **L11 (EVSE) preserved by reuse.** `applyCommand`'s body was refactored into
  `bridge.Apply(stationID, evseID, limitA)` used byte-identically by the legacy
  path AND the `evseShell`; rejected-profile-as-error and `implausibleCurrent`
  gating are unchanged (`meter_validate_test.go` green unmodified). Convergence is
  judged **one-sided from metered current only** — profile-Accepted is a write
  success, never convergence. The reconciler adds the reassert-on-reconnect the
  legacy path lacked (via `SetNewChargingStationHandler`); backoff starts at 15 s
  (≥ the 10 s per-call bound, no overlapping calls).

**Shadow triage (pre-flip, live):** solar shadow ran clean — 90 under-ceiling
one-sided `verdict=match`, 13 `diverge:new-desired` all with `would==legacy` on
each ceiling change (incl. the `CeilingW=1e9` restore edge), 1 `SeqReset` (hub
restart, AD-013 rule 2), **0 stale-ceiling holds**. EVSE shadow idle until an
EV session commands current (expected).

**Post-flip gate evidence:** the two release-edge **oracles** PASS solo —
`release-while-rebooting` (solar recovered to full 47 s after the device
returned) and `curtailment-release` (recovered 24 s after return). Targeted
15-scenario solar+EV set **6P/9D/0F/0B** — all DEGRADED are the refuse/reject/
lag/reboot families where the hub correctly flags CannotComply (accepted), and
every *correctness* scenario PASSes: `ev-meter-freeze` (silence≠convergence: held
+ flagged stale, cap kept), `ev-wrong-units` (implausible rejected, L11),
`ev-connector-flap` (stable, no over-command), `solar-bad-scale` (plausibleW
withheld). No INV-HUNT (active applies are backoff-paced, ≤3 identical writes to
converge a slow/refusing inverter, not a tight loop). **Full 51-scenario FAST
campaign 33P/18D/0F/0B** (`qa-mayhem-20260705-205515.md`) — EXACTLY the TASK-028
battery-active baseline, i.e. the solar+EVSE flip added **zero regressions**
(0 FAIL, 0 BLIND, SAFETY held). `solar-reboot-forget`'s DEGRADED is the known
028-baseline D. The ×10-solo per scenario and the 10-cycle campaign soak remain
as deeper Principal-gated validation. Bench left FAST + battery/solar/evse-active.
Rollback = config `shadow` + restart (rehearsed on the shadow→active transition).

## TASK-032 — legacy convergence machinery DELETED (2026-07-06)

L1 (spam half), **L2, L3, L4, L7** flipped to `deleted`. Four per-mechanism,
independently-revertible commits on lexa-hub `task/032-delete-legacy`:

- **A `20cc2b2`** — legacy command paths: the `lexa/control/{battery,solar}` +
  `lexa/evse/+/command` publish/subscribe surface and the `MQTT*Actuator`
  publishers. The desired-doc publisher (`cmd/hub/desired.go`) is now the SOLE
  actuator implementation; a failed retained publish surfaces as the actuator
  error. Config battery/solar (modbus) + evse (ocpp) must be reconciler `active`
  when devices of that role exist — off/shadow/absent is now **fatal** (no legacy
  fallback remains; a pre-032 backup config fails loud instead of running dark).
  Topic-name constants kept `Deprecated` one release (`internal/bus/topics.go`).
- **B `783a4c5`** — `cmdDeduper` + `reassertEvery` 60 s watchdog + breach-triggered
  `dedupeResets` + the observer reset block. `cmd/hub/actuators.go` +
  `actuators_test.go` deleted entirely.
- **C `9fbcaa0`** — `retryDevice.lastCtrl` + `reassertLocked` (incl. the
  never-commanded-inverter stale-ceiling clear) + the `reconciledActive` field.
  Retry transport mechanics (reopen-on-next-poll, `dropLocked`, mutex,
  `onReconnect` hook) KEPT. `interlock_test.go` unmodified.
- **D `f87136c`** — redundant `restoreOnGenLimitClear` + `genCapActive`; also
  clarified `applyRestoreRule`'s comment (L1 — it is the KEPT standing-intent
  source that now feeds the desired publisher; only its downstream publish spam
  died). Differential-equivalent to `applyRestoreRule` + retained desired doc.

`go test -race ./internal/... ./cmd/...` green after every commit; each commit
`git revert`s independently (verified). Deployed binary-only to hub-pi 69.0.0.1
(configs / mqttproxy :1882 / FAST all preserved; `.bak-t032-*` backups). Journal
steady-state shows reconciler-only actuation — no "legacy command ignored" spam,
`legacy=none` on every verdict line.

**Ledger gate** (`csip-tls-test/qa-mayhem-20260706-010740.md`, 8 gate scenarios +
2 global watches, **5P/5D/0F/0B**): each deleted mechanism's gate PASS or
accepted-DEGRADED on the reconciler path —
- L4: `release-while-rebooting` **PASS** (reconciler reasserts on reconnect; solar
  recovered to full 48 s after the device returned), `battery-reboot` **PASS**,
  `solar-reboot-forget` DEGRADED (posts CannotComply, accepted 028-baseline D).
- L7: `curtailment-release` **PASS** → the conditional `restoreOnGenLimitClear`
  deletion **held, no revert**.
- L2/L3: `control-churn` **PASS** (no hunt across mRID turnover),
  `ev-connector-flap` **PASS**, `export-cap-full-battery` + `mqtt-broker-restart`
  DEGRADED (CannotComply during the fault, clean recovery after — accepted).
- Global watches: `clock-jitter` + `perfect-storm` DEGRADED-with-CannotComply
  (accepted); SAFETY AUDIT held on every scenario; no INV-HUNT anywhere.

**Full 51-scenario FAST campaign** (`docs/qa-task032/full-campaign-20260706-020958.md`):
**35P/16D/0F/0B/0 inconclusive** — above the 32–33P/18–19D band, strictly ≥ the
T028/029/030 baseline (33P/18D), **0 FAIL, 0 BLIND**, SAFETY held on every
scenario, no INV-HUNT. The 16 DEGRADED are the known accepted CannotComply /
fault-flagging families (refuse/reject/lag/ignore/wrong-sign/wrong-units/reboot/
storm/broker). No immediate regression from the deletions (this campaign also
first-validates the batched TASK-037 local-clock anchoring + TASK-055 decode
hardening on the bench). The deeper 10-cycle overnight soak is Principal-gated.
Evidence bundle: `docs/qa-task032/` (gate + full-campaign reports). Bench left
FAST + battery/solar/evse reconciler-active, mqttproxy :1882 intact.

Rollback reality (post-032): `git revert <commit>` + redeploy, per mechanism —
the config-flip rollback ended with this deletion.
