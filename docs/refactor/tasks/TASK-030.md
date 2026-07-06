# TASK-030 — Migrate the EVSE to a reconciler in lexa-ocpp (shadow → flip)

*Status: DONE (2026-07-05, lexa-hub 2cbd894) — reconciler built in lexa-ocpp
(driver reuses applyCommand's L11 rejected-as-error verbatim); shadow-deployed
then flipped active on the bench. 7 EV scenarios all PASS-or-accepted-DEGRADED
(ev-meter-freeze/ev-wrong-units/ev-connector-flap/ev-delayed-obey PASS;
ev-profile-reject/ev-accept-but-ignore/ev-min-current-floor accepted-DEGRADED);
full 51-scenario FAST campaign 33P/18D/0F/0B (= 028 baseline, zero regression;
qa-mayhem-20260705-205515.md). ×10-solo + 10-cycle soak = remaining deeper
Principal-gated validation.*

*Phase: P2 · Effort: L (≈6–8 h) · Difficulty: high · Risk: **high***

## Objective
The EVSE runs on the reconciler pattern inside `lexa-ocpp`: the hub publishes retained
`lexa/desired/evse/{station}` documents (`maxCurrentA`, `connect`, `connectorID`);
`lexa-ocpp` with `"reconciler": "active"` in `ocpp.json` owns SetChargingProfile writes
with verify-by-readback from OCPP meter data, reasserts the profile when a charger
reconnects, and reports non-convergence (e.g. a 6 A hardware floor). The seven EV
scenarios pass ×10 solo and a 10-cycle FAST campaign holds baseline.

## Background
Legacy EVSE path (verified, `cmd/ocpp/main.go`): the hub's `MQTTEVSEActuator`
(`cmd/hub/actuators.go:119–144`) dedupes/publishes `bus.EVSECommand{StationID,
ConnectorID, MaxCurrentA}` (0 = suspend) on `lexa/evse/{station}/command`; `lexa-ocpp`
subscribes (`main.go:74–80`) and `applyCommand` (`:258–314`) sends an OCPP 2.0.1
SetChargingProfile (TxDefaultProfile, ChargingRateUnitAmperes) and — critically — treats
a delivered-but-**rejected** profile as an error, not success (`:305–309`, pinned by
`ev-profile-reject`). State back-flow: StatusNotification/MeterValues/TransactionEvent
handlers fold into `stationState` and publish `bus.EVSEState`; `implausibleCurrent`
(`:349–368`) rejects MeterValues current beyond 1.25× the station rating
(`ev-wrong-units`); TransactionEvent Ended zeroes current (`:420–434`).

What the EVSE **lacks** today that the reconciler adds (unlike battery/solar there is no
`lastCtrl` equivalent here): a charger that disconnects and reconnects gets NO re-assert
of its current limit until the hub's 60 s dedupe watchdog or a command change — the
`SetNewChargingStationHandler` (`:146–154`) only publishes state. Reassert-on-reconnect
is a genuine gap the reconciler closes (the `ev-connector-flap`/charger-reboot family
tolerates this today because sessions re-negotiate, but the limit is unprotected).

Readback semantics: convergence = measured `currentA ≤ maxCurrentA + tolerance` (one-
sided — an EV drawing less than its limit is compliant), judged only from plausible
MeterValues/TransactionEvent samples; profile-Accepted is a *write success*, never
convergence (`ack-before-effect` lesson, and `ev-accept-but-ignore` exists precisely
because Accepted lies). Non-convergence with reason surfaces the `ev-min-current-floor`
case: a charger that cannot go below 6 A against a 0 A desire must generate a
non-convergence report (feeding CannotComply via TASK-031) rather than retry-storm —
today the hub admits CannotComply for this via the optimizer path (QA_FINDINGS: accepted
DEGRADED). A silent charger (`ev-meter-freeze`) means no plausible readback: the
reconciler holds its last assessment and (with TASK-031) reports staleness — it must NOT
treat silence as convergence.

OCPP invariant (OCPP-1, both CLAUDE.md files): charging sessions are TransactionEvent
Started/Updated/Ended lifecycles — never bare MeterValues. The reconciler consumes the
existing handler state; it must not add any bare-MeterValues-driven session logic.

## Why this task exists
Completes the per-device-class migration (battery → solar → EVSE, AD-002 fixed order) so
TASK-032 can delete the legacy trio. Also closes the EVSE reassert gap noted above.

## Architecture review sections
W2, R1, §8.2/§8.5 (first-EVSE assumption — do not entrench it further), §14 item 3;
02 AD-002/013; 03 Phase 2; 08 RSK-01/17; ledger L2 (EVSE scope), L11.

## Prerequisites
- TASK-028 DONE (pattern proven; hub publisher/seq infrastructure exists).
  TASK-029 recommended first (04 ordering allows 029/030 in parallel off 028, but do not
  land both flips in the same campaign window — 04 §3 "never parallelize" rule applies to
  campaign attribution).
- TASK-022 helpful (shared ocppserver) but not required.

## Files
- **Read first:** `cmd/ocpp/main.go` (all), `cmd/ocpp/config.go`,
  `cmd/ocpp/meter_validate_test.go`, `internal/reconcile/` API,
  `cmd/hub/actuators.go:119–144`, `cmd/hub/main.go:211–216` (EVSE actuator wiring),
  AD-013 (EVSE field semantics).
- **Modify (lexa-hub):** `cmd/hub/` (EVSE desired publisher wrapper — same pattern);
  `cmd/ocpp/config.go` (`Reconciler string` json `"reconciler"`: `off|shadow|active`,
  default `off`); `cmd/ocpp/main.go` (wire shell; gate legacy command subscription when
  active; reconnect hook in `SetNewChargingStationHandler`); `configs/ocpp.json`.
- **Create:** `cmd/ocpp/reconcile_shell.go` + `reconcile_shell_test.go`.

## Blast radius
EVSE control writes change owner. OCPP wire behavior: same message types
(SetChargingProfile), potentially different *timing* (retry/backoff instead of
command-driven). Battery/solar reconcilers: untouched. `connect` semantics: this task
maps `connect=false` / `maxCurrentA=0` to the existing suspend behavior
(SetChargingProfile 0 A) — it does NOT introduce RequestStopTransaction (that is the
QA_FINDINGS "optional fix" for ev-accept-but-ignore; out of scope, note as follow-up).

## Implementation strategy
Same ladder compressed: publisher + shadow, triage, flip, gate. The shell adapts the
`reconcile` core with an OCPP driver (`applyCommand`'s body refactored into a driver
method — reuse, don't duplicate, the rejected-status-as-error logic). Observation feed:
the existing forwarder handlers already funnel every sample through `applySamplesLocked`
— add a tap there that forwards plausible samples to the shell (`Observe`), and a
reconnect event from `SetNewChargingStationHandler`.

## Detailed steps
1. Hub EVSE desired publisher (wrapper at `cmd/hub/main.go:211–216` registration):
   doc from `EVSECommand` — `maxCurrentA`, `connectorID`, `connect` (true unless
   suspending semantics dictate; keep it simple: publish `maxCurrentA` incl. 0-suspend,
   `connect` reserved for future disconnect semantics and set true), content-change
   gating + seq. Legacy `MQTTEVSEActuator` publish unchanged.
2. Refactor `applyCommand` into `profileDriver.Apply(stationID string, evseID int,
   limitA float64) error` used by BOTH the legacy path and the shell (behavior byte-
   identical; `meter_validate_test.go` and existing tests stay green).
3. Shell: per configured station (`cfg.Stations`), one reconciler. Inputs: desired docs
   (`mqttutil.Subscribe` on `lexa/desired/evse/+` — filter class), observations (tap in
   `OnMeterValues`/`OnTransactionEvent` after `applySamplesLocked`, carrying
   `Plausible = !implausibleCurrent(...)` and connected state), reconnect events.
   One-sided convergence rule (measured ≤ limit + tolerance). Suspend (0 A) convergence:
   currentA ≈ 0 within tolerance OR TransactionEvent Ended.
4. Shadow mode: shell computes/logs would-do vs legacy applies (tap the legacy command
   subscription) — write nothing (recorder driver). Bench: `"reconciler":"shadow"` in
   `/etc/lexa/ocpp.json` (+ in-repo `configs/ocpp.json`), run the 7 EV scenarios, triage
   divergences (expected: shadow re-asserts after `ev-connector-flap` reconnect where
   legacy waits for the watchdog — equivalent-or-better).
5. Flip: `"reconciler":"active"` — legacy EVSE commands ignored-when-active (log once);
   shell owns SetChargingProfile; retry/backoff per core config (respect OCPP timeouts:
   driver already bounds each call at 10 s, `:298–313`; backoff must be ≥ that so calls
   never overlap per station).
6. Targeted gates ×10 solo each:
   `python3 scripts/mayhem.py --dashboard http://localhost:8080 --only ev-profile-reject`
   … then `ev-accept-but-ignore`, `ev-min-current-floor`, `ev-meter-freeze`,
   `ev-connector-flap`, `ev-delayed-obey`, `ev-wrong-units`. Baseline verdicts (several
   are accepted-DEGRADED per V5 — no new FAIL/BLIND; INV-EVMAX clean).
7. 10-cycle full FAST campaign ≤ baseline.
8. Ledger: L2 (EVSE scope) → `reconciler-active (evse)`; L11 noted as preserved-by-reuse.

## Testing changes
Shell unit tests: rejected profile → write failure → retry per backoff; Accepted ≠
convergence; one-sided tolerance; suspend convergence via Ended; implausible samples
ignored; reconnect → reassert; silence ≠ convergence. Driver refactor covered by
existing tests unchanged. Commands: `make test`; mayhem runs above.

## Documentation changes
- `configs/ocpp.json` + lexa-hub CLAUDE.md (reconciler key; EVSE reassert-on-reconnect
  now exists — remove any doc claim that it doesn't).
- Ledger updates (step 8).

## Common mistakes to avoid
- Treating profile-Accepted as convergence (`ev-accept-but-ignore` exists to punish
  this). Only metered current converges.
- Retry cadence faster than the per-call 10 s timeout — overlapping SetChargingProfile
  calls to one station.
- Adding session logic driven by bare MeterValues (OCPP-1 violation). The reconciler
  reads folded state; the handlers own protocol lifecycles.
- Two-sided convergence (an EV at 0 A under a 16 A limit is fine).
- Introducing RequestStopTransaction "while here" — separate behavior change, separate
  task (backlog), separate campaign.
- Assuming one station/connector in NEW code structure (§8.5): key everything by
  (station, connector) even though the bench has one.

## Things that must NOT change
- **L11:** rejected-profile-as-error and `implausibleCurrent` gating — reused verbatim;
  `meter_validate_test.go` green unmodified.
- OCPP-1 TransactionEvent lifecycle handling (incl. Ended-zeroes-current, `:424–426`).
- `bus.EVSEState` publication behavior (lexa-hub's reader and the QA harness consume it).
- Legacy EVSE command topic keeps publishing from the hub until TASK-032.
- Accepted-DEGRADED verdicts for `ev-accept-but-ignore`/`ev-min-current-floor` (admitting
  CannotComply instead of suspending is the documented accepted behavior).

## Acceptance criteria
- [ ] Shadow divergence log triaged clean; flip evidence in journal (reconciler-issued
      SetChargingProfile; legacy commands ignored).
- [ ] Reconnect reassert demonstrated: `ev-connector-flap` run shows the limit re-sent
      after reconnect without a hub command change.
- [ ] 7 EV scenarios ×10 solo at baseline; INV-EVMAX clean.
- [ ] 10-cycle full FAST campaign ≤ 0.6 FAIL/cycle, 0 BLIND.
- [ ] Rollback rehearsed: `"reconciler":"shadow"` restores legacy path.

## Regression checklist
- [ ] `go test -race ./internal/...` (lexa-hub) green
- [ ] `make test-fast` (csip-tls-test) green
- [ ] Conformance logic tests: skip (no CSIP change); evsim tests
      (`go test ./sim/evsim/` in csip-tls-test) green — protocol peer unchanged
- [ ] Mayhem: 7 EV scenarios ×10 solo + **10-cycle full campaign**
- [ ] Timing re-tuned post-deploy

## Mayhem scenarios affected
Gates: `ev-profile-reject`, `ev-accept-but-ignore`, `ev-min-current-floor`,
`ev-meter-freeze`, `ev-connector-flap`, `ev-delayed-obey`, `ev-wrong-units`.
Watch: `grid-disconnect` (EVSE suspension via 0 A flows through the new path),
`battery-empty-import-cap` (EV lever under import cap), `perfect-storm`.

## Conformance implications
OCPP 2.0.1: same message set, reconciler-driven timing. If evsim's conformance
expectations encode command timing, TASK-033 reviews them. CSIP: none until TASK-031
(non-convergence → CannotComply).

## Suggested commit message
`feat(reconcile): EVSE reconciler in lexa-ocpp — desired docs, readback, reassert (TASK-030)`
`Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>`

## Suggested PR title & description
**Title:** Phase 2: EVSE flip — reconciler owns charging-profile writes
**Description:** Desired docs for EVSE; driver refactor reuses rejected-as-error logic;
readback from metered current only; adds the missing reassert-on-reconnect. Evidence:
7 scenarios ×10 + 10-cycle campaign. Rollback: config `shadow` + restart.

## Code review checklist
- Driver refactor is behavior-identical (legacy tests unmodified).
- No bare-MeterValues session logic added.
- Backoff ≥ call timeout; per-(station,connector) keying.
- Suspend convergence covers both currentA≈0 and Ended paths.

## Definition of done
Acceptance criteria + regression checklist; ledger updated; status headers (this file +
00_MASTER_INDEX) updated.

## Possible follow-up tasks
TASK-031 (non-convergence reports incl. min-current-floor reason), TASK-032 (legacy
deletion), TASK-074 (OCPP security profile 2), backlog: RequestStopTransaction option
for EV-only-lever caps; second EVSE (TASK-065).
