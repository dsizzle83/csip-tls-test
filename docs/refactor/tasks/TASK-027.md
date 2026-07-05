# TASK-027 — Battery reconciler in lexa-modbus: shadow mode (observe/compare, write nothing)

*Status: DONE (2026-07-05, lexa-hub 3d52412 + ACL fix task/027-desired-topic-acl
1a2d777) · Phase: P2 · Effort: L (≈6–8 h) · Difficulty: high · Risk: med*

**Wave-gate closure note (2026-07-05):** bench soak + targeted + full Mayhem
campaign run at the P2 wave gate. Deploy: `make build-arm64` +
`deploy-hub-pi.sh 69.0.0.1 dmitri --enable-api-auth --enable-mqtt-acl` +
`hub-replay-tune.sh fast` + `mqtt-chaos.sh deploy` (proxy path lost on the
config overwrite, redeployed); `modbus.json` `"reconciler":{"battery":"shadow"}`
set + services restarted.

**Bug found and fixed during the soak (not in the original code-complete
pass): `systemd/mosquitto-lexa.acl` had no grant for the new
`lexa/desired/` topic family.** With `allow_anonymous false` deny-by-default,
the hub's publish to `lexa/desired/battery/battery-0` was silently dropped
by the broker (the local `lexa_hub_desired_publishes_total` counter still
incremented — the client gets a normal PUBACK regardless of ACL outcome —
but no retained message ever reached the store, and lexa-modbus's shadow
never received a real desired doc: its `would=none...verdict=match` lines
were vacuous, matching trivially because `Desired` was never set, not
because the reconciler agreed with legacy). Fixed by adding
`topic write lexa/desired/battery/+` (user lexa-hub) and
`topic read lexa/desired/battery/+` (user lexa-modbus) to
`systemd/mosquitto-lexa.acl`, scoped to battery only (solar/EVSE get their
own grant at T029/030); committed on branch `task/027-desired-topic-acl` in
lexa-hub (commit 1a2d777), deployed via ACL file install + `systemctl reload
mosquitto` + `systemctl restart lexa-hub` (forces a fresh publish under the
new ACL). After the fix, the retained doc was confirmed on the broker:
`lexa/desired/battery/battery-0 {"v":1,"device_class":"battery","device_id":"battery-0","setpoint_w":0,"connect":true,"source":"economic","issued_at":...,"seq":0}`.

**Confirmed the ledger's predicted `Connect`-completeness limitation is
real, not theoretical**: once the retained doc (which always carries a
`Connect` opinion for battery, per the actuator's existing sign
convention) landed, `lexa_mb_shadow_matches_total` froze — it does not
resume accumulating, by design (`internal/reconcile`'s completeness gate
correctly holds forever without a Connect readback). The `verdict=match`
text in the shadow's log line is printed for every non-write decision
regardless of completeness, so it is NOT the same signal as the counted
`matches` metric — a future reader must use the metric/divergence counters,
not the log text, to assess convergence. See campaign evidence below for the
one real (Observe-driven) divergence recorded and its disposition.

## Objective
The hub publishes retained battery desired-state documents alongside (not instead of) its
legacy battery commands, and `lexa-modbus` runs a battery reconciler in **shadow mode**:
it consumes the desired topic, computes what it *would* write, compares against both the
legacy writes it observes and device readbacks, and logs divergence — while writing
nothing to hardware. A config key `"reconciler"` in `modbus.json` selects
`off | shadow | active` per device class (only `battery` acted on here; `active` remains
rejected-at-startup until TASK-028).

## Background
Legacy battery path today (verified): the engine's `executePlan` calls
`MQTTBatteryActuator.ApplyBatteryCommand` (`cmd/hub/actuators.go:65–89`) which
dedupes/publishes `bus.BattCommand` on `lexa/control/battery/{device}` (QoS 1,
non-retained); `lexa-modbus` `subscribeControls` (`cmd/modbus/main.go:181–219`) checks
role, calls `interlock.noteControl(dev, cmd)` (Tier-0 intent tracking), converts via
`battCommandToControl` (positive setpoint → `OpModExpLimW`, negative → `OpModImpLimW`,
`cmd/modbus/main.go:221–237`) and applies through
`registry.ApplyControlTo` → `retryDevice.ApplyControl` (which records `lastCtrl`).

The Tier-0 interlock (`cmd/modbus/interlock.go`) sits ABOVE everything: on each poll,
`check()` force-disconnects a pack that is commanded-to-charge but measured discharging
at/below reserve+5% (`battery-wrong-sign`), issuing `OpModConnect=false` directly through
the registry; it never reconnects on its own. Its inputs are `noteControl` (hub intent)
and raw poll measurements. **It is not touched by this task and must remain senior to the
reconciler forever** (ledger row L8; AD-002).

Shadow needs something to consume, so this task also adds the hub-side publisher: a
desired-doc publisher for battery wrapped around the existing actuator registration
(`cmd/hub/main.go:198–209`), publishing `bus.DesiredState` (retained,
`lexa/desired/battery/{device}`, per AD-013 with hub-owned `seq`) on every
`ApplyBatteryCommand` whose content changed. Legacy publishing is completely unchanged —
this is additive, which is what makes shadow a zero-risk deploy.

Measurement flow the shadow comparator can use (verified): the registry subscription loop
in `publishMeasurements` (`cmd/modbus/main.go:124–178`) sees every poll result
(`m.W`, `m.SOC`) before MQTT publication.

## Why this task exists
03 Phase 2 fixes the migration order: battery first (the Tier-0 interlock is the safety
net), shadow before flip (RSK-01). Shadow proves, on the live bench with real scenario
traffic, that reconciler decisions match legacy behavior — BEFORE any write authority
moves.

## Architecture review sections
W2, R1, §8.2, §14 item 3; 02 AD-002/AD-013; 03 Phase 2 migration order; 08 RSK-01/17;
ledger rows L1–L4, L8.

## Prerequisites
- TASK-026 DONE (reconciler core). TASK-025 DONE (schema/types/ledger).
- Bench in FAST mode, deployable.

## Files
- **Read first:** `internal/reconcile/` (core API), `cmd/modbus/interlock.go` (all),
  `cmd/modbus/main.go` (all), `cmd/hub/actuators.go`, `cmd/hub/main.go:151–219`,
  `cmd/modbus/config.go`, AD-013.
- **Modify (lexa-hub):** `cmd/hub/actuators.go` or new `cmd/hub/desired.go` (publisher);
  `cmd/hub/main.go` (wrap battery actuator registration); `cmd/modbus/config.go`
  (`Reconciler map[string]string` json `"reconciler"`, values `off|shadow|active`,
  default `off`, unknown value = fatal at load); `cmd/modbus/main.go` (wire shadow);
  new `cmd/modbus/reconcile_shadow.go`; `configs/modbus.json` (document the key, ship
  `"battery": "off"`).
- **Create:** `cmd/modbus/reconcile_shadow_test.go`, `cmd/hub/desired_test.go`.

## Blast radius
Additive: one new retained topic family gets published (battery devices only); one new
subscription + log stream in lexa-modbus. Hardware writes: none new (assert this in
review — shadow's driver is a recorder). Config: new optional key. Tick path: the
desired publisher adds one retained QoS 1 publish per battery *change* (dedupe by
content), not per tick.

## Implementation strategy
Introduce (publisher + shadow consumer) → observe on the bench under scenario load →
(TASK-028 flips). Hub side: compose, don't modify — the legacy actuator keeps its exact
dedupe/breach-reset behavior; the publisher wraps it. Modbus side: the shadow shell feeds
the pure core from three existing streams (desired docs, poll measurements, observed
legacy control applications) and emits logs + counters only.

## Detailed steps
1. **Hub publisher.** New type wrapping `orchestrator.BatteryActuator`: on
   `ApplyBatteryCommand`, first delegate to the legacy actuator (unchanged path), then
   build `bus.DesiredState{V:1, DeviceClass:"battery", DeviceID, SetpointW, Connect,
   Source, MRID, IssuedAt: now, Seq: next}` and `PublishJSONRetained` to
   `bus.DesiredTopic("battery", device)` **only when doc content (excluding
   seq/issuedAt) changed** — the retained doc is standing intent, not a tick stream.
   Source/MRID: derive from the plan's active CSIP control the same way the breach path
   does (`plan.Breach.MRID` stamping at `optimizer.go:374–376` shows where the mRID
   lives: `state.CSIPControl.MRID`); pass what `cmd/hub` already knows — if plumbing the
   control into the actuator layer is invasive, publish `source:"economic"` + empty mrid
   for now and note it for TASK-031 (which needs mrid attribution end-to-end).
2. Wire the wrapper in `cmd/hub/main.go` battery registration (`case "battery"`); keep
   `dedupeResets` wiring exactly as is.
3. **Config.** Add the `reconciler` map to `cmd/modbus/config.go` with validation:
   `active` for any class → `log.Fatalf("reconciler active mode lands in TASK-028")`
   (explicitly reserved, so a premature flip is impossible).
4. **Shadow shell** (`cmd/modbus/reconcile_shadow.go`): for each battery-role device when
   mode==shadow, hold one `reconcile.Reconciler`. Feed it:
   - `mqttutil.Subscribe(mc, bus.SubDesired, ...)` filtered to class battery →
     `SetDesired`.
   - Poll results: hook where `publishMeasurements` drains updates (pass the shadow a
     copy of `upd.Measurements` + a `Plausible` flag from `plausibleW`) → `Observe`.
   - Legacy writes: in the battery branch of `subscribeControls`, after a successful
     `ApplyControlTo`, notify the shadow (`ObserveLegacyWrite(ctrl)`).
   The shadow logs, at each decision point:
   `reconciler[shadow] battery-0: would=<action> legacy=<write|none> readback=<W,SOC,conn> verdict=<match|diverge:reason>`
   plus counters (matches, divergences, would-write-count) exposed in logs every 60 s.
   **The injected driver is a recorder; there is no code path from shadow to
   `ApplyControlTo`.**
5. Unit tests: config validation (off/shadow/active/unknown); shadow never emits a write
   (drive it with divergent inputs, assert recorder-only); hub publisher content-change
   dedupe + seq monotonicity + retained flag.
6. `make test` green. Deploy hub Pi (`deploy-hub-pi.sh 69.0.0.1 dmitri` from lexa-hub,
   then `bash scripts/hub-replay-tune.sh fast`), set `"reconciler": {"battery":"shadow"}`
   in `/etc/lexa/modbus.json` on the Pi, restart lexa-modbus.
7. Verify on bench: `mosquitto_sub -h 69.0.0.1 -t 'lexa/desired/#' -v` (run on the hub Pi
   — broker is localhost-only) shows a retained battery doc; journal shows shadow verdict
   lines with `match` during steady state.
8. Scenario-load observation: run the battery-family scenarios
   (`python3 scripts/mayhem.py --dashboard http://localhost:8080 --only battery-wrong-sign,battery-soc-refuse,battery-charge-disabled,battery-reboot,battery-empty-import-cap,export-cap-full-battery`)
   — verdicts must equal baseline (shadow is passive), and the shadow divergence log is
   collected + triaged: every `diverge` line is either explained (expected semantic
   difference, e.g. reconciler would rewrite faster than legacy watchdog) and recorded in
   the ledger notes, or is a core bug fixed before TASK-028.
9. Full FAST campaign with shadow enabled — baseline must hold (proves passivity).

## Testing changes
Step 5 unit tests; shadow soak evidence (steps 8–9) attached to the PR. Commands:
`cd ~/projects/lexa-hub && make test`; mayhem commands above.

## Documentation changes
- `configs/modbus.json` + lexa-hub `CLAUDE.md` config table: `reconciler` key.
- `docs/refactor/PRESERVATION_LEDGER.md`: add a "shadow observations" note column entry
  for L1–L4 (divergences observed + disposition).
- AD-013: note first publisher landed.

## Common mistakes to avoid
- Any path from shadow to a hardware write (incl. via interlock or registry) — review
  greps for `ApplyControlTo` in the shadow file: must be absent.
- Publishing the desired doc per tick instead of per change: retained + per-change is the
  design; per-tick recreates the QoS 1 storm the deduper exists to prevent (§11 sync
  publish waits).
- Feeding `interlock.noteControl` from desired docs in shadow — interlock inputs stay
  legacy-fed until the flip (TASK-028 moves them deliberately).
- Forgetting `hub-replay-tune.sh fast` after the hub deploy (STOCK reset gotcha).
- Editing `/etc/lexa/modbus.json` on the Pi but not `configs/modbus.json` in-repo (the
  next deploy overwrites — 05 §6 deploy-script config discipline).

## Things that must NOT change
- Legacy battery command behavior: `cmdDeduper`, breach-reset, `lastCtrl` — byte-for-byte
  untouched (ledger L1–L4 remain the active mechanisms).
- **Tier-0 interlock (L8): zero edits.** `interlock_test.go` green un-modified.
- Battery command sign convention (+ discharge / − charge → ExpLim/ImpLim mapping).
- All battery-family scenario verdicts at baseline while shadow runs.

## Acceptance criteria
- [x] Retained doc visible on `lexa/desired/battery/battery-0` on the bench; content
      matches the last legacy command's intent. (Required the ACL fix above — see
      wave-gate closure note.)
- [x] Shadow verdict lines present; steady-state divergence rate ≈ 0 (1 counted
      divergence total, during battery-charge-disabled fault injection, dispositioned
      below as reconciler-notices-faster — expected); every `diverge` line triaged.
      Note: post-ACL-fix, `lexa_mb_shadow_matches_total` does not keep accumulating
      once the doc carries a `Connect` opinion (documented limitation, see closure note)
      — absence of further match growth is NOT a regression.
- [x] Grep-proof: no write path from shadow code (`grep -n ApplyControlTo
      cmd/modbus/reconcile_shadow.go` → doc-comments only, no call sites).
- [x] Full FAST campaign with shadow on ≤ V6 baseline (0.6 FAIL/cycle, 0 BLIND) —
      see wave-gate campaign report `qa-mayhem-20260705-151009.md` (34P/17D/0F/0B, within the 32–35P band; targeted battery set `qa-mayhem-20260705-140802.md`).
- [x] `active` mode rejected at startup with a clear message
      (`cmd/modbus/config.go:107`: `"reconciler active mode lands in TASK-028 (class %q)"`;
      unit-tested, not re-proven live on the bench to avoid a disruptive mid-campaign
      service crash-restart).

## Regression checklist
- [x] `go test -race ./internal/...` (lexa-hub) green
- [x] `make test-fast` (csip-tls-test) green
- [x] Conformance logic tests: skip (no protocol change)
- [x] Mayhem: battery-family targeted set (`export-cap-full-battery,
      battery-wrong-sign, battery-soc-refuse, battery-charge-disabled` — 0P/4D/0F/0B,
      all DEGRADED verdicts `cannot_comply=True`, matches pre-shadow baseline) +
      **full campaign** (radioactive zone: cmd/hub actuator wiring touched — 05 §12)
      — see wave-gate campaign report `qa-mayhem-20260705-151009.md` (34P/17D/0F/0B, within the 32–35P band; targeted battery set `qa-mayhem-20260705-140802.md`).
- [x] Timing re-tuned post-deploy (`hub-replay-tune.sh fast`; engine=3s/discovery=5s/
      poll=2s confirmed post-restart).

## Mayhem scenarios affected
Verdicts: none may move. Observed-by-shadow: `battery-wrong-sign`, `battery-soc-refuse`,
`battery-charge-disabled`, `battery-reboot`, `battery-empty-import-cap`,
`export-cap-full-battery`, `mqtt-broker-restart` (retained-doc redelivery visible).

## Conformance implications
None (no CSIP/SunSpec wire change; new topic is internal bus).

## Suggested commit message
`feat(reconcile): battery desired-doc publisher + lexa-modbus shadow mode (TASK-027)`
`Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>`

## Suggested PR title & description
**Title:** Phase 2: battery reconciler shadow (publish + observe, zero write authority)
**Description:** Retained battery desired docs from the hub (additive), shadow reconciler
in lexa-modbus logging would-do vs legacy vs readback. Campaign evidence attached; all
divergences dispositioned. Rollback: set `"reconciler":{"battery":"off"}` + restart, or
revert (legacy path untouched either way).

## Code review checklist
- Shadow file has no `ApplyControlTo`/write reachability.
- Hub wrapper delegates FIRST to legacy actuator; dedupe/breach-reset wiring unchanged.
- Seq monotonic per device across hub restarts? (Document: seq restarts at 0 with a new
  issuedAt — per AD-013 this is ACCEPTED: verify the core accepts issuedAt-newer/
  seq-lower and emits the `SeqReset` log + counter, per AD-013's exact wording.)
- Config validation fatal on `active`.

## Definition of done
Acceptance criteria + regression checklist; ledger shadow-notes updated; status headers
(this file + 00_MASTER_INDEX) updated.

## Possible follow-up tasks
TASK-028 (flip battery to active), TASK-042 (retained staleness hardening informed by
shadow observations).
