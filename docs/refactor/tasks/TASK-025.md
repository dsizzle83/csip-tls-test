# TASK-025 — Desired-state document: schema ADR, bus types, and the behavior-preservation ledger

*Status: TODO · Phase: P2 · Effort: L (≈6–8 h) · Difficulty: med · Risk: low*

## Objective
Three deliverables, zero runtime change: (1) an ADR (new AD-013 in
`02_ARCHITECTURE_DECISIONS.md`) fixing the desired-state document schema, topic layout,
and seq/staleness policy; (2) the corresponding Go types + topic helpers + unit tests in
`lexa-hub/internal/bus` (compiled, unused — nothing publishes or subscribes yet); (3)
`docs/refactor/PRESERVATION_LEDGER.md` created from the table embedded in this task,
mapping every legacy convergence mechanism to the QA scenario(s) that created it.

## Background
Today "make the device match what the hub wants" is implemented four times (review W2):
the optimizer's restore rule re-commands every device every tick
(`internal/orchestrator/optimizer.go:2241` `applyRestoreRule`); each hub actuator carries
a `cmdDeduper` with a 60 s re-assert watchdog plus a breach-triggered reset
(`cmd/hub/actuators.go:24–56`, reset wiring `cmd/hub/main.go:99–118`); `lexa-modbus`
re-asserts `retryDevice.lastCtrl` on reconnect (`cmd/modbus/main.go:314–412`); and a
five-hop CannotComply chain reports non-convergence (optimizer → `plan.Breach` →
`breachAlert` closure edge-detector → MQTT alert → northbound `responseTracker` → HTTP
POST). AD-002 decided the replacement: the optimizer publishes a retained, versioned,
per-device **desired-state document**; a reconciler co-located with the hardware driver
owns write-on-diff, verify-by-readback, reassert-on-reconnect, escalating retry, and
non-convergence reporting.

Existing bus conventions this schema must follow (`internal/bus/messages.go`,
`internal/bus/topics.go`): JSON with `*float64` for absent values (never NaN — enforced
by `nan_test.go`); topic families `lexa/control/battery/{device}`,
`lexa/control/solar/{device}`, `lexa/evse/{station}/command`; retained control-plane
precedent `lexa/csip/control` (`bus.ActiveControl` with `Source`/`MRID`/`ValidUntil`).
TASK-017 introduced the `"v"` envelope convention (AD-006) — this document is the first
schema born versioned.

Device classes and their controllable surface (verified):
- **battery** (`bus.BattCommand`): `SetpointW *float64` (+ discharge / − charge),
  `Connect *bool`.
- **solar** (`bus.SolarCommand`): `CurtailToW *float64` (nil = restore full output; the
  modbus side encodes restore as a 1e9 W ceiling clamped by the device —
  `restoreCeilingW`, `cmd/modbus/main.go:259`).
- **evse** (`bus.EVSECommand`): `MaxCurrentA float64` (0 = suspend), `ConnectorID`.
- **meter**: read-only; no actuator exists (verified: `cmd/hub/main.go:198–216` registers
  actuators only for battery/inverter roles and EVSE stations; `cmd/modbus`
  `subscribeControls` gates on role battery/inverter) — the meter gets **no** desired
  document, closing AD-002's open question.

## Why this task exists
RSK-01: every legacy mechanism encodes a QA scenario; deleting one without knowing which
scenario it protects reopens that scenario. The ledger is the contract that lets
TASK-027…032 replace code while provably preserving behavior. The schema ADR prevents the
reconciler tasks from each inventing field semantics.

## Architecture review sections
W2, R1, D11, §8.2, §8.3, §14 item 3; 02 AD-002/AD-006; 08 RSK-01/RSK-17; 06 §4.2.

## Prerequisites
- TASK-017 DONE (bus envelope `"v"` convention defined).
- TASK-001 DONE (QA-arc fixes committed — the ledger cites them by file:line).

## Files
- **Read first:** `cmd/hub/actuators.go` (all), `cmd/hub/main.go:90–260`,
  `cmd/modbus/main.go:300–447`, `cmd/modbus/interlock.go`,
  `internal/orchestrator/optimizer.go:120–190` (guard fields), `:2241–2276`
  (`applyRestoreRule`), `:1251` (`restoreOnGenLimitClear`), `internal/orchestrator/model.go:286–320`
  (`ComplianceBreach`, `Plan.Safety`), `cmd/northbound/main.go:198–213, 666–830`
  (`responseTracker`), `internal/bus/{messages,topics,nan_test}.go` — all in
  `~/projects/lexa-hub`.
- **Modify:** `docs/refactor/02_ARCHITECTURE_DECISIONS.md` (add AD-013);
  `lexa-hub/internal/bus/topics.go` (topic helpers).
- **Create:** `lexa-hub/internal/bus/desired.go` + `desired_test.go`;
  `docs/refactor/PRESERVATION_LEDGER.md` (copy the table below, with the intro text).

## Blast radius
None at runtime — additive types and docs only. API: new exported bus types/helpers.

## Implementation strategy
Write AD-013 first (schema is a decision, not an implementation detail), then the types
to match, then instantiate the ledger file. The ledger content below was verified against
the code on 2026-07-04; re-verify each file:line while writing (they drift) and fix any
that moved.

## Detailed steps
1. Write AD-013 in `02_ARCHITECTURE_DECISIONS.md` covering:
   - **Topic:** `lexa/desired/{class}/{device}` (`class` ∈ `battery|solar|evse`),
     retained, QoS 1. EVSE `device` = stationID; `ConnectorID` rides in the document.
   - **Document fields:** `v` (int, =1), `deviceClass`, `deviceID`, `ceilingW *float64`
     (solar generation ceiling; restore = explicit `restoreCeilingW`-style large value,
     never "absence means restore"), `setpointW *float64` (battery, + discharge/− charge),
     `connect *bool`, `maxCurrentA *float64` (EVSE; 0 = suspend), `connectorID int`
     (EVSE), `source string` (e.g. `csip-event|csip-default|economic|safety`),
     `mrid string` (active CSIP control, for CannotComply attribution), `issuedAt int64`
     (Unix s), `seq uint64` (monotonic per device, publisher-owned).
   - **Seq/staleness policy (RSK-17):** consumers reject a document iff
     `seq <= lastAppliedSeq` AND `issuedAt <= lastAppliedIssuedAt`
     (out-of-order/replayed retained delivery), and count+log the rejection. A strictly
     newer `issuedAt` with a lower/reset `seq` is ACCEPTED with a `SeqReset` structured
     log + counter (the publisher restarted — hub restarts reset `seq` to 0). Reject
     stale documents (`issuedAt` older than the staleness bound) regardless of seq.
     Absence of
     fresh documents is NOT a release: hold last-known-good (fail-closed, 05 §3) and emit
     a staleness report after a wall-clock threshold (recommended default 300 s;
     record the chosen value + rationale in the ADR — full retained-trust hardening is
     TASK-042).
   - Field-absence semantics per class (nil = "no opinion", distinct from zero — the
     silent-zero XML lesson applied to the bus).
2. Implement `internal/bus/desired.go`: `type DesiredState struct{...}` with json tags
   matching the ADR, plus `DesiredTopic(class, device string) string`,
   `SubDesired = "lexa/desired/+/+"`, `ClassFromDesiredTopic`/`DeviceFromDesiredTopic`
   (follow the `nthSegment` pattern in `topics.go`).
3. `desired_test.go`: round-trip marshal/unmarshal; nil-vs-zero field distinction; NaN
   never serialized (mirror `nan_test.go`); topic helper extraction cases.
4. Create `docs/refactor/PRESERVATION_LEDGER.md`: copy the table from the next section
   verbatim, prefixed with: what the ledger is (RSK-01 contract), the rule ("no row's
   mechanism may be deleted until its gate scenarios pass on the replacement — 05 §11"),
   and an instruction that TASK-027…033 update the Status column as they land.
   **Re-verify every file:line citation against HEAD while copying; fix drift.**
5. `cd ~/projects/lexa-hub && make test` — green (new tests included, nothing else moves).

## The preservation ledger (initial content — copy into docs/refactor/PRESERVATION_LEDGER.md)

| # | Legacy mechanism (file:line @2026-07-04) | Originating QA scenario / finding | Behavior that must survive | Replaced by | Gate scenarios | Status |
|---|---|---|---|---|---|---|
| L1 | `applyRestoreRule` per-tick re-command (`optimizer.go:2241–2276`, call site `:365–366` with `solarCapActive` gate) | curtailment-release Mode A/B; solar-reboot-forget (re-assert each cycle); 92-day-replay battery reserve sail-through (in-code comment) | Uncommanded connected battery idled to 0 W at ANY SoC (idle enforces the reserve); uncurtailed inverter restored; dark inverter under an active cap KEEPS held curtailment; after release, restore reaches a dark inverter on reconnect | Retained desired doc is the standing intent; reconciler reasserts (T026–T029) | curtailment-release, release-while-rebooting, solar-reboot-forget | legacy-active |
| L2 | `cmdDeduper` + `reassertEvery=60s` watchdog (`cmd/hub/actuators.go:24–56`; per-actuator fields `:59–144`) | export-cap-full-battery ghost (watchdog re-assert); lexa-modbus/-ocpp restart resync | A restarted/state-lossy consumer re-converges without waiting on a command *change* (today ≤60 s; retained doc makes it immediate on subscribe) | Broker redelivers retained doc on subscribe; reconciler reassert (T026/T027) | export-cap-full-battery, battery-reboot, mqtt-broker-restart | legacy-active |
| L3 | Breach-triggered dedupe reset (`cmd/hub/actuators.go:44–56` `reset()`; `cmd/hub/main.go:99–118` `dedupeResets` in `planObserver`) | QA 2026-07-03: 0 W ceiling dedupe-suppressed 30 s against an uncurtailed inverter while CannotComply posted (device reverted behind hub's back) | A device that reverts while the commanded value is unchanged gets a corrective write bounded by the poll/readback interval, not by a 60 s watchdog | Reconciler verify-by-readback + write-on-diff (T026) | export-cap-full-battery, curtailment-release, control-churn | legacy-active |
| L4 | `retryDevice.lastCtrl` + `reassertLocked` (`cmd/modbus/main.go:314–412`; desired recorded while disconnected `:396–406`; never-commanded-inverter stale-ceiling clear `:385–394`) | QA 2026-07-02: release-while-rebooting (released cap left inverter clamped at stale ceiling indefinitely) | Reconnected device converges to hub's CURRENT desire before its first measurement is trusted; never-commanded inverter gets a stale-ceiling clear; never-commanded battery gets nothing; meter never written | Reconciler reassert-on-reconnect from retained doc (T026/T027) — `retryDevice` session drop/reopen mechanics stay | release-while-rebooting, solar-reboot-forget, battery-reboot | legacy-active |
| L5 | `breachAlert` mRID-keyed edge detector + `activeBreachMRID` closure (`cmd/hub/main.go:98, 230–257`); `Plan.Safety` nil-Breach guard (`orchestrator/model.go:315–320`) | reject-write-curtail / enable-gate-curtail flakiness (mRID-agnostic flag latched across episodes); 2026-07-03 safety-plan spurious clear | One alert at onset, one at clear; a NEW mRID breaching mid-episode re-alerts; safety plans (Breach==nil means "not assessed") never emit a clear edge | Named breach-episode component (T031) | reject-write-curtail, enable-gate-curtail, export-cap-full-battery | legacy-active |
| L6 | `responseTracker` CannotComply episode dedupe (`cmd/northbound/main.go:203–213, 666–710` `alerted` map / `clearAlerts`) | CannotComply spam per tick vs one per episode (design; V3 CannotComply timing races) | Exactly one CannotComply POST per breach episode; clear re-arms | Episode-ID-carrying report chain (T031) | battery-soc-refuse, battery-empty-import-cap | legacy-active |
| L7 | `restoreOnGenLimitClear` + `genCapActive` (`optimizer.go:163–166, 1251`) | curtailment-release Mode A (V3 Issue 1: release is a WRITE, not an absence of writes) | Explicit uncurtail emitted on the cap active→clear edge | Desired doc transitions to restore ceiling on release (T029); deletion only if gates stay green | curtailment-release | legacy-active |
| L8 | Tier-0 battery interlock (`cmd/modbus/interlock.go`, whole file) | battery-wrong-sign (ADR-0001 Tier 0: local reflex, survives hub/broker death) | **KEEP — not replaced.** Force-disconnect within one poll of charge-commanded pack discharging near reserve; never reconnects on its own; sits ABOVE the reconciler | n/a (reconciler must defer to it, T027/T028) | battery-wrong-sign | keep |
| L9 | `plausibleW` nameplate gate (`cmd/modbus/main.go:261–278`) | solar-bad-scale (GS-1/MTR-1: corrupt scale factor ≈10× truth) | **KEEP.** Implausible W withheld from the bus; pattern reused for reconciler readback plausibility | n/a (T026 borrows the pattern) | solar-bad-scale | keep |
| L10 | Optimizer convergence guards: `expOverTicks` session scoping (`optimizer.go:132–142`), `checkExportLimitConvergence:1194`, `checkGenLimitConvergence:1344` (meter floor gen ≥ export − battDischarge), `checkImportConvergence:1446`, `battDrainTicks`/`battWrongDirTicks`/`criticalBatteryInversion`/`checkBatterySafety` (`:1493–1648`) | control-churn + clock-jitter (silent breach via counter reset); battery-charge-disabled; battery-soc-refuse; battery-wrong-sign | **KEEP until P5 (R4).** Measured-effect breach detection and safety backstop stay in the optimizer; only their REPORTING path changes (T031) | R4 constraint sessions (T060–062) | control-churn, clock-jitter, battery-charge-disabled, battery-soc-refuse, battery-wrong-sign | keep-until-P5 |
| L11 | EVSE rejected-profile-as-error + `implausibleCurrent` (`cmd/ocpp/main.go:258–314, 349–368`) | ev-profile-reject / ev-accept-but-ignore (delivered-but-rejected ≠ success); ev-wrong-units | **KEEP.** Rejected SetChargingProfile surfaces as failure; implausible MeterValues never ingested | Folded into EVSE reconciler driver semantics unchanged (T030) | ev-profile-reject, ev-accept-but-ignore, ev-wrong-units | keep |

## Testing changes
`internal/bus/desired_test.go` (step 3). Run: `cd ~/projects/lexa-hub && make test`.

## Documentation changes
AD-013 (step 1); `docs/refactor/PRESERVATION_LEDGER.md` (step 4); note in
`06_TESTING_STRATEGY.md` §4.2 that the ledger now exists (one line, path).

## Common mistakes to avoid
- Encoding solar restore as "field absent" — absence must mean "no opinion"; restore is
  an explicit ceiling value (the modbus layer already learned this: an EMPTY control is a
  silent no-op, `cmd/modbus/main.go:241–255`).
- Publishing/subscribing anything in this task — types only; the first publisher is
  TASK-027.
- Copying the ledger without re-verifying line numbers against HEAD.
- Making `seq` per-class or global instead of per-device — reconcilers compare per device.

## Things that must NOT change
- No runtime behavior anywhere (additive types only) — `make test` diff-clean otherwise.
- Bus NaN convention (`*float64`, nil = absent) — new types must pass the same standard
  as `nan_test.go`.
- The ledger documents but does not modify any mechanism.

## Acceptance criteria
- [ ] AD-013 merged with topic, all fields, seq/staleness policy, per-class absence
      semantics, and the meter-exclusion decision recorded.
- [ ] `internal/bus/desired.go` + tests compile and pass; nothing else changed in lexa-hub.
- [ ] `docs/refactor/PRESERVATION_LEDGER.md` exists; every row's file:line verified
      against HEAD (reviewer spot-checks three rows).
- [ ] AD-002's two open questions updated (meter: no desired doc; interlock: stays
      measurement-only, above the reconciler).

## Regression checklist
- [ ] `go test -race ./internal/...` (lexa-hub) green
- [ ] `make test-fast` (csip-tls-test) green (untouched — cheap proof)
- [ ] Conformance logic tests: not protocol-adjacent — skip
- [ ] Mayhem: none (no runtime change)

## Mayhem scenarios affected
None at runtime. The ledger *names* the gate scenarios for the whole phase.

## Conformance implications
None. (`mrid` field ties desired docs to 2030.5 controls for later CannotComply
attribution — semantics defined in TASK-031.)

## Suggested commit message
`feat(bus): desired-state document schema (AD-013) + preservation ledger (TASK-025)`
`Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>`

## Suggested PR title & description
**Title:** Phase 2 foundation: desired-state schema + behavior-preservation ledger
**Description:** AD-013 schema decision, bus types (unused, additive), ledger mapping all
legacy convergence mechanisms to originating QA scenarios with gates. Zero runtime change.
Rollback: revert (nothing consumes the types).

## Code review checklist
- Schema fields ↔ AD-013 text ↔ Go tags all agree.
- Ledger line numbers verified at HEAD; scenario names exist in
  `scripts/mayhem.py --list` output.
- Staleness policy is hold-and-report, never auto-release (fail-closed).

## Definition of done
Acceptance criteria + regression checklist; AD-013 + ledger committed; status headers
(this file + 00_MASTER_INDEX) updated.

## Possible follow-up tasks
TASK-026 (reconciler core consumes the schema), TASK-042 (retained staleness hardening),
TASK-018 (envelope rollout counts this schema as done).
