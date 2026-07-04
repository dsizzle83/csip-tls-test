# TASK-028 — Flip battery to the reconciler (active mode); 10-cycle campaign gate

*Status: TODO · Phase: P2 · Effort: L (≈6–8 h) · Difficulty: high · Risk: **high***

## Objective
`lexa-modbus` with `"reconciler": {"battery": "active"}` gives the battery reconciler
write authority: it converges the pack to the retained desired document via
verify-by-readback, reasserts on reconnect, and ignores legacy battery commands — while
the hub continues publishing BOTH the desired doc and the legacy command topic (belt and
braces for instant rollback). The Tier-0 interlock remains senior. Battery-family
scenarios pass individually and a 10-cycle FAST campaign holds the V6 baseline.

## Background
State after TASK-027 (verified design): hub publishes retained
`lexa/desired/battery/{device}` docs (content-change-gated, seq/issuedAt per AD-013)
*and* legacy `lexa/control/battery/{device}` commands; lexa-modbus shadow-compares and
its divergence log is triaged clean. Legacy write path still in force:
`subscribeControls` battery branch → `interlock.noteControl` → `battCommandToControl` →
`registry.ApplyControlTo` → `retryDevice.ApplyControl` (records `lastCtrl`)
(`cmd/modbus/main.go:181–237, 396–412`).

What "active" must do (ledger rows this path takes over — L1/L2/L3/L4 for battery only):
- Desired doc → reconcile core `SetDesired`; core actions (`Write`) are executed through
  the SAME registry path legacy used (`ApplyControlTo` with a `DERControlBase` built by
  the existing `battCommandToControl` conversion — reuse it, do not re-implement sign
  mapping).
- Poll results → `Observe` (readback: measured W vs setpoint within tolerance, Conn
  state; `plausibleW` gates `Plausible`). Divergence → corrective write (replaces L3's
  breach-triggered dedupe reset for batteries).
- Reconnect (retryDevice reopened a session) → `Reconnected` → unconditional reassert
  (replaces L4's `lastCtrl` for batteries — but `lastCtrl` code stays present and
  continues to serve solar until TASK-029/032).
- Legacy battery commands: still subscribed, still feed `interlock.noteControl` — but no
  longer applied to hardware when active (log once per change:
  "legacy battery command ignored (reconciler active)").

**Interlock seniority (critical design point):** the interlock force-disconnect writes
`OpModConnect=false` via `ApplyControlTo` (`interlock.go:123–128`) and sets
`tripped[dev]`. An active reconciler seeing readback Conn=0 against desired connect=true
would rewrite Conn=1 — fighting Tier-0. Required: expose the interlock's tripped state
(add an accessor; `interlock.go` keeps its own mutex) and have the reconciler shell
suppress connect-restoring writes for a device while `tripped(dev)` is true (report it
instead). The interlock stops tripping when the fault clears (`check()` re-evaluates each
poll, `interlock.go:114–121`); normal reconciliation resumes then. `noteControl` intent
must now be fed from the DESIRED doc the reconciler is executing (charge intent =
`setpointW < 0 && connect != false` — mirror `noteControl`'s exact logic at
`interlock.go:88–97`).

## Why this task exists
This is the first transfer of write authority in the program (RSK-01's highest-stakes
moment before TASK-032). Battery goes first because Tier-0 catches the worst failure
mode (a wrong-sign or wrongly-reconnected pack) locally within one poll.

## Architecture review sections
W2, R1, §8.2, §14 item 3; 02 AD-002/013; 03 Phase 2 (order + rollback); 08 RSK-01/17;
04 §4.1; ledger L1–L4 (battery scope), L8.

## Prerequisites
- TASK-027 DONE with its divergence log triaged to zero unexplained lines.
- Bench FAST; a full night available for the 10-cycle campaign.

## Files
- **Read first:** shadow shell + core (`cmd/modbus/reconcile_shadow.go`,
  `internal/reconcile/`), `cmd/modbus/interlock.go` (all — the seniority contract),
  `cmd/modbus/main.go:181–237` (legacy branch to gate), `retry_test.go` +
  `interlock_test.go` (behavior pins).
- **Modify (lexa-hub):** `cmd/modbus/reconcile_shadow.go` → generalize to
  `reconcile_shell.go` (shadow/active are the same shell with a real vs recorder driver);
  `cmd/modbus/main.go` (battery branch gating; reconnect event hook in `retryDevice` —
  emit an event where `ReadMeasurements` logs "reconnected", `main.go:349–362`);
  `cmd/modbus/interlock.go` (tripped-state accessor ONLY — no logic change);
  `cmd/modbus/config.go` (allow `active` for battery); `configs/modbus.json`.
- **Create:** `cmd/modbus/reconcile_shell_test.go` additions (active-mode gating,
  interlock-suppression, legacy-ignore).

## Blast radius
Battery hardware writes change owner. Solar/meter/EVSE paths untouched. Hub side:
unchanged from TASK-027 (both streams keep publishing). Config: `active` now legal for
battery only (solar/evse `active` still fatal until their tasks). MQTT: no new topics.

## Implementation strategy
Flip = configuration, not code divergence: the shell built in TASK-027 gains a real
driver (registry-backed) selected by mode, and the legacy apply branch becomes a no-op
for battery when active. Deploy with `off`→`shadow` verified, then set `active`, then
gate hard: targeted scenarios ×10 solo each, then a 10-cycle full campaign. Rollback at
any point: config back to `shadow`, restart lexa-modbus (legacy commands never stopped
flowing).

## Detailed steps
1. Generalize the shell: driver interface `{ Apply(model.DERControlBase) error }`; shadow
   = recorder (unchanged behavior), active = registry adapter reusing
   `battCommandToControl`. Reconnect hook: `retryDevice` gains an optional callback set
   only for reconciled devices, invoked after a successful reopen+reassert-skip (in
   active mode `reassertLocked`'s `lastCtrl` branch must NOT also fire for battery —
   suppress recording/reasserting `lastCtrl` for devices in active mode so the reconciler
   is the single reasserter; keep the never-commanded-inverter branch intact for solar).
2. Gate the legacy branch: in `subscribeControls` battery case, when active — still call
   nothing on hardware; keep role checks; log-once ignore. `interlock.noteControl` moves
   to the reconciler's apply path (fed from the desired doc it executes).
3. Interlock accessor + reconciler suppression (Background contract) + report
   (`Report{Kind: InterlockHold}` or reuse NonConverged with reason) so TASK-031 can see
   "not converged because Tier-0 vetoed".
4. Unit tests: active driver applies through registry; battery legacy cmd ignored when
   active; interlock-tripped suppresses connect-restore but allows setpoint writes to a
   disconnected pack to be deferred; solar path completely unaffected by battery mode;
   `lastCtrl` suppression for active battery, intact for solar; config matrix.
5. `make test` green. Deploy hub Pi; `hub-replay-tune.sh fast`; set
   `"reconciler":{"battery":"shadow"}` → verify journal parity with TASK-027, then
   `"battery":"active"` and restart lexa-modbus.
6. Live sanity: journal shows reconciler writes on control changes; force a revert via
   batsim (`curl -s -X POST http://69.0.0.11:6021/inject ...` per scenario tooling or run
   `--only battery-reboot`) and watch a corrective write within one poll+readback.
7. Targeted gates, 10× solo each (verdict stability rule, 06 §2):
   `python3 scripts/mayhem.py --dashboard http://localhost:8080 --only battery-wrong-sign`
   … repeat for `battery-soc-refuse`, `battery-charge-disabled`, `battery-reboot`,
   `battery-empty-import-cap`, `battery-nan-sentinel`, `export-cap-full-battery`.
   Expected: PASS/DEGRADED per the V5/V6 accepted list (export-cap-full-battery's
   accepted DEGRADED oracle line included); INV-SOC/INV-HUNT clean everywhere.
8. **10-cycle full FAST campaign** (overnight): ≤ 0.6 FAIL/cycle, 0 BLIND, no new
   DEGRADED signature (06 §4.4 verdict-drift watch).
9. Update ledger: L1–L4 battery-scope entries → status `reconciler-active (battery)`;
   note the interlock interaction decision.

## Testing changes
Step 4 unit tests; step 7/8 campaign evidence archived (`--json` outputs + report md into
`docs/` per 06 §4.3). Commands as listed.

## Documentation changes
- `configs/modbus.json` + lexa-hub CLAUDE.md: battery active mode documented, incl. the
  interlock-seniority paragraph.
- `docs/refactor/PRESERVATION_LEDGER.md` status updates (step 9).
- `02_ARCHITECTURE_DECISIONS.md`: AD-002 open-question answer confirmed in practice
  (interlock stays measurement-only + senior).

## Common mistakes to avoid
- Letting BOTH `lastCtrl` reassert and the reconciler reassert fire on reconnect for the
  same battery — double-write races; step 1's suppression is mandatory.
- Fighting the interlock (rewriting Conn=1 while tripped) — the exact guard×guard
  interaction class this program exists to kill; test it explicitly.
- Removing the legacy battery publisher or subscriber — belt and braces stays until
  TASK-032; rollback depends on it.
- Running the campaign with the bench accidentally in STOCK (deploy reset) — re-run
  `hub-replay-tune.sh fast`; verdicts are FAST-calibrated.
- Tuning a scenario oracle to make a flip pass (06 §4.5) — a changed verdict is a finding.

## Things that must NOT change
- **Interlock behavior (L8):** `interlock_test.go` green with zero test edits; accessor
  addition only.
- Battery sign convention and register mapping (`battCommandToControl` reused, not
  reimplemented).
- Solar/EVSE control paths: bit-identical behavior (L1–L4 still active for solar).
- Legacy topics keep flowing (hub side unchanged from TASK-027).
- Accepted-DEGRADED list: `export-cap-full-battery` 4 s DEGRADED-at-oracle-line stays
  accepted; do not "fix" it here.

## Acceptance criteria
- [ ] Active mode: reconciler writes observed in journal; legacy battery commands logged
      as ignored; hardware behavior converges (step 6 forced-revert corrected ≤ one
      poll + readback cycle).
- [ ] Interlock trip during active mode does not oscillate (test + bench evidence from
      battery-wrong-sign run: INV-HUNT clean).
- [ ] Step 7 targeted verdicts: 10/10 stable at baseline per scenario.
- [ ] 10-cycle campaign ≤ 0.6 FAIL/cycle, 0 BLIND, no new DEGRADED signatures.
- [ ] Rollback rehearsed once: set `shadow`, restart, confirm legacy writes resume
      (journal evidence in PR).

## Regression checklist
- [ ] `go test -race ./internal/...` (lexa-hub) green
- [ ] `make test-fast` (csip-tls-test) green
- [ ] Conformance logic tests: skip (no protocol change)
- [ ] Mayhem: targeted ×10 solo each + **10-cycle full FAST campaign** (04 §4.1 gate)
- [ ] Timing re-tuned post-deploy; dashboard binary rebuilt if touched

## Mayhem scenarios affected
Gates: `battery-wrong-sign`, `battery-soc-refuse`, `battery-charge-disabled`,
`battery-reboot`, `battery-empty-import-cap`, `battery-nan-sentinel`,
`export-cap-full-battery`. Watch (indirect): `mqtt-broker-restart` (retained-doc
re-seed), `perfect-storm`, `clock-jitter`.

## Conformance implications
None on the wire. CannotComply behavior unchanged (chain untouched until TASK-031).

## Suggested commit message
`feat(reconcile): battery active mode — reconciler owns battery writes (TASK-028)`
`Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>`

## Suggested PR title & description
**Title:** Phase 2: battery flip — reconciler gets write authority (interlock senior)
**Description:** Shell gains real driver; legacy battery commands ignored-when-active but
still published; interlock seniority implemented + tested; lastCtrl suppressed for
battery. Evidence: targeted ×10 + 10-cycle campaign reports. Rollback: config `shadow` +
restart (rehearsed).

## Code review checklist
- Reconnect single-reasserter proof (no path where both lastCtrl and reconciler write).
- Interlock file diff = accessor only.
- Legacy-ignore is per-class, not global.
- Campaign artifacts attached; DEGRADED signatures diffed against V5/V6 accepted list.

## Definition of done
Acceptance criteria + regression checklist; ledger + docs updated; status headers (this
file + 00_MASTER_INDEX) updated.

## Possible follow-up tasks
TASK-029 (solar), TASK-030 (EVSE), TASK-031 (report chain), TASK-032 (legacy deletion,
gated on all flips).
