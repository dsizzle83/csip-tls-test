# TASK-029 — Migrate solar/inverter to the reconciler (shadow → flip)

*Status: DONE (2026-07-05, lexa-hub 2cbd894) — flipped active on the bench;
shadow triaged clean (would==legacy on every ceiling change, 90 under-ceiling
one-sided matches, 0 stale-ceiling holds); both release-edge oracles PASS solo
post-flip (release-while-rebooting, curtailment-release); full 51-scenario FAST
campaign 33P/18D/0F/0B (= 028 baseline, zero regression;
qa-mayhem-20260705-205515.md). ×10-solo + 10-cycle soak = remaining deeper
Principal-gated validation.*

*Phase: P2 · Effort: L (≈6–8 h) · Difficulty: high · Risk: **high***

## Objective
The inverter class runs on the reconciler: the hub publishes retained
`lexa/desired/solar/{device}` documents whose `ceilingW` encodes both curtailment and
(explicitly) restore; `lexa-modbus` in `"solar": "active"` mode owns inverter writes with
verify-by-readback and reassert-on-reconnect; the restore-while-dark semantics are
reproduced exactly; solar-family scenarios pass ×10 solo and a 10-cycle FAST campaign
holds baseline. Legacy solar command topic keeps publishing (belt and braces).

## Background
Legacy solar path (verified): `MQTTSolarActuator` (`cmd/hub/actuators.go:91–117`)
publishes `bus.SolarCommand{CurtailToW *float64}` (nil = restore) on
`lexa/control/solar/{device}`; `lexa-modbus` converts via `solarCommandToControl`
(`cmd/modbus/main.go:239–255`): nil → `OpModMaxLimW = restoreCeilingW` (1e9 W, clamped by
the device to WMax → 100% output; an EMPTY control would be a silent no-op because
`Base.ApplyControl` only ever *sets* the ceiling), value → `OpModMaxLimW = max(0, v)`.

The solar-specific semantics that took three QA rounds to get right (ledger L1/L4/L7 —
all must be reproduced in the desired-doc world):
1. **Restore is a write, not an absence** (curtailment-release Mode A; V3 Issue 1):
   `restoreOnGenLimitClear` (`optimizer.go:1251`, `genCapActive` state `:163–166`) emits
   an explicit uncurtail on the cap active→clear edge.
2. **Restore-while-dark** (curtailment-release Mode B / release-while-rebooting, QA
   2026-07-02/03): `applyRestoreRule` skips a DISCONNECTED inverter while a cap is active
   (`!sol.Connected && solarCapActive → continue`, `optimizer.go:2246–2248` with
   `solarCapActive := exportLimit || maxLimit active` at `:365`) — the held curtailment
   IS the desired state while capped; but once the cap clears, restore is queued even for
   a dark inverter and `retryDevice.lastCtrl` delivers it on reconnect
   (`cmd/modbus/main.go:326–329, 371–394`).
3. **Stale-ceiling clear for never-commanded inverters** (`reassertLocked` inverter
   branch `:385–394`): an idle inverter reconnecting with no recorded control gets the
   restore ceiling, because a ceiling latched before process start would otherwise
   persist forever.

In the desired-doc design these collapse naturally: the doc always carries an explicit
`ceilingW` (cap value while capped — connectivity-independent; `restoreCeilingW` when
released), is retained, and the reconciler reasserts on reconnect. Case 3 becomes "on
startup/reconnect with no doc yet, an inverter-class reconciler's default desired is the
restore ceiling" — encode this as the shell's initial desired for inverters (mirroring
`reassertLocked`), and document it.

Convergence checking at the meter level (`checkGenLimitConvergence`,
`checkExportLimitConvergence` — optimizer) is UNTOUCHED (ledger L10, keep-until-P5); the
reconciler adds register-level verification below it (readback of measured W vs ceiling
needs care: an inverter legitimately produces less than its ceiling — readback verifies
`W ≤ ceiling + tolerance`, and equality-style convergence only applies to the ceiling
register itself if the driver reads it back; define tolerance semantics in the shell:
divergence = measured W **exceeds** ceiling beyond tolerance, per `ReadbackTolerance`).

## Why this task exists
Solar is where the legacy convergence stack is thickest (three interacting mechanisms)
and where its bugs were found (curtailment-release Modes A/B, release-while-rebooting,
solar-reboot-forget, the 2026-07-03 0 W-ceiling dedupe incident). Migrating it removes
the largest guard×guard surface — and it must land after battery proved the pattern
under a Tier-0 net that solar does not have.

## Architecture review sections
W2, R1, D11, §8.2, §14 item 3; 02 AD-002/013; 03 Phase 2; 08 RSK-01/17;
ledger L1, L2, L3, L4, L7.

## Prerequisites
- TASK-028 DONE (battery active; 10-cycle campaign held baseline).
- TASK-027's shell generalization in place (`reconcile_shell.go` with mode-selected driver).

## Files
- **Read first:** `internal/orchestrator/optimizer.go:360–366` (solarCapActive), `:1251–1295`
  (restoreOnGenLimitClear), `:2241–2253` (restore rule solar half);
  `cmd/modbus/main.go:239–259, 371–394`; `internal/orchestrator/optimizer_test.go:1003+`
  (stuck-curtailment-on-reconnect suite — the behavior pins);
  `cmd/hub/actuators.go:91–117`.
- **Modify (lexa-hub):** `cmd/hub/desired.go`/actuator wiring (solar publisher wrapper,
  same pattern as battery incl. the cap-aware ceiling derivation);
  `cmd/modbus/reconcile_shell.go` (inverter class: driver via `solarCommandToControl`
  equivalents / direct `OpModMaxLimW`, readback semantics, initial-desired = restore
  ceiling); `cmd/modbus/main.go` (solar branch gating when active; lastCtrl suppression
  extended to active inverters); `cmd/modbus/config.go` (allow `"solar": "shadow"|"active"`);
  `configs/modbus.json`.
- **Create:** tests alongside (shell inverter cases; publisher ceiling-derivation cases).

## Blast radius
Inverter hardware writes change owner. The hub's solar desired publisher must translate
optimizer plan output (SolarCommands with NaN/nil restore) into explicit ceilings —
a semantic mapping new in this task. Battery reconciler path: untouched. Meter/EVSE:
untouched. Optimizer itself: **no code changes** (its commands keep flowing to the legacy
topic AND feed the publisher).

## Implementation strategy
Same introduce→shadow→flip ladder as battery, compressed into one task (04 row): publisher
+ shadow first, triage divergences (expect them around release edges — that is the point),
then flip. The publisher derives `ceilingW` from the plan: an explicit `CurtailToW` value
→ that value; restore (nil/NaN CurtailToW) → `restoreCeilingW`. Because the doc is
retained and connectivity-independent, the solarCapActive dark-inverter gate needs no
publisher equivalent — the doc simply keeps the cap value until the optimizer releases it
(verify this equivalence explicitly in shadow before flipping).

## Detailed steps
1. Hub publisher for solar (wrapper around `MQTTSolarActuator` registration,
   `cmd/hub/main.go:205–208`): map `cmd.CurtailToW` NaN→`ceilingW=restoreCeilingW`
   (share the constant — move `restoreCeilingW` into `internal/bus` or duplicate with a
   cross-reference comment; pick one and document), value→`ceilingW=value`;
   content-change gating + seq as battery. Note: restore is `CurtailToW == nil` on the
   bus type (`bus.SolarCommand`); if the orchestrator's internal plan struct uses NaN,
   translate at the publisher — the reconciler-side mapping must handle both nil (bus)
   and NaN (internal) as restore.
2. Shell inverter support: driver builds `model.DERControlBase{OpModMaxLimW}` via
   `activePowerFromWatts` (reuse — GS-1/MTR-1 multiplier scaling); `Observe` divergence
   rule = measured W > ceiling + tolerance (one-sided), plus Conn; initial desired for
   inverter class = restore ceiling (Background case 3).
3. Shadow phase on bench: `"solar":"shadow"`; run the solar family
   (`--only curtailment-release,release-while-rebooting,solar-reboot-forget,export-cap-full-battery,pv-flicker,ack-before-effect,reject-write-curtail,enable-gate-curtail,ramp-limit-curtail`)
   and triage every divergence line. Expected findings to disposition: shadow wants to
   write restore while legacy waits for reconnect (Mode B timing) — equivalent-or-better;
   anything where shadow would HOLD a stale ceiling legacy would have cleared is a bug.
4. Flip: `"solar":"active"`; legacy solar commands ignored-when-active (log once);
   lastCtrl suppression for active inverters; `reassertLocked`'s inverter default branch
   suppressed for active inverters (the shell's initial-desired replaces it — never both).
5. Live probes: run `--only release-while-rebooting` and `--only curtailment-release` 10×
   solo each — these two are THE oracles for the semantics in Background (V5 history:
   4/10 and 5/10 FAIL before the 2026-07-03 fixes; both PASS at V6). Then
   `solar-reboot-forget`, `pv-flicker`, `ack-before-effect`, `reject-write-curtail`,
   `enable-gate-curtail`, `ramp-limit-curtail`, `export-cap-full-battery`, `solar-bad-scale`
   ×10 solo each.
6. 10-cycle full FAST campaign ≤ baseline; INV-HUNT clean (reconciler retries on a
   refusing inverter must not read as hunting — check the `reject-write-curtail` runs).
7. Ledger updates: L1 (solar half), L4 (inverter branches), L7 → `reconciler-active
   (solar)`; note the initial-desired-replaces-reassertLocked decision.

## Testing changes
Shell inverter unit cases (restore mapping, one-sided tolerance, initial desired,
interplay: cap → doc value; release → restore write; reconnect under cap → cap
reasserted; reconnect after release → restore delivered). Publisher mapping tests.
The existing optimizer suites (`optimizer_test.go:1003+` stuck-curtailment cluster,
`optimizer_rules_test.go:942+`) must stay green UNMODIFIED — they pin the plan-level
behavior the publisher consumes.

## Documentation changes
- `configs/modbus.json` + lexa-hub CLAUDE.md (solar modes; restore-is-explicit note).
- Ledger status updates (step 7).

## Common mistakes to avoid
- Encoding restore as doc-absence or ceiling=nil. The whole Mode-A class exists because
  restore must be an explicit write; keep it explicit in the doc.
- Leaving BOTH `reassertLocked`'s inverter default AND the shell's initial desired armed
  — double reassert on reconnect; suppress the legacy one for active inverters (step 4).
- Two-sided readback tolerance for solar (an inverter under its ceiling at dusk is not
  divergent). One-sided: only over-ceiling is divergence.
- Publishing ceiling changes per optimizer tick during slewed export-cap control: the
  export rule adjusts the solar ceiling continuously under a cap (`expGuard.solarCeilingW`,
  slew constants) — content-change gating will publish each new ceiling value; that is
  correct (it IS new desired state) but verify the publish rate on the bench under
  `export-cap-full-battery` and note it for TASK-046 (tick publish budget).
- Skipping the shadow phase because battery worked — solar's semantics are the tricky ones.

## Things that must NOT change
- **Restore-while-dark contract:** a dark inverter under an active cap converges to the
  CAP on reconnect (never full output mid-cap); after release it converges to full
  output. Pinned by `release-while-rebooting` + `curtailment-release`; also by
  `optimizer_test.go:1003+` at plan level.
- `restoreCeilingW`-style restore encoding via the multiplier (values above int16 watt
  range — GS-1/MTR-1; `activePowerFromWatts` reused).
- Optimizer code: zero changes (its tests prove it).
- Battery reconciler behavior (no regression from shell generalization) — battery
  targeted set re-run in step 6's campaign.
- Meter never written (role gate stays).

## Acceptance criteria
- [ ] Shadow divergence log triaged: every line dispositioned, zero unexplained.
- [ ] `release-while-rebooting` and `curtailment-release`: 10/10 solo at baseline
      verdicts (PASS per V6).
- [ ] Remaining solar-family scenarios ×10 solo at baseline; INV-HUNT clean.
- [ ] 10-cycle full FAST campaign ≤ 0.6 FAIL/cycle, 0 BLIND, no new DEGRADED signature.
- [ ] Rollback rehearsed: `"solar":"shadow"` restores legacy writes (journal evidence).

## Regression checklist
- [ ] `go test -race ./internal/...` (lexa-hub) green — incl. optimizer suites unmodified
- [ ] `make test-fast` (csip-tls-test) green
- [ ] Conformance logic tests: skip (no protocol change)
- [ ] Mayhem: targeted ×10 solo (step 5) + **10-cycle full campaign**
- [ ] Timing re-tuned post-deploy

## Mayhem scenarios affected
Gates: `curtailment-release`, `release-while-rebooting`, `solar-reboot-forget`,
`pv-flicker`, `ack-before-effect`, `reject-write-curtail`, `enable-gate-curtail`,
`ramp-limit-curtail`, `export-cap-full-battery`, `solar-bad-scale`. Watch: `grid-disconnect`
(solar curtail-to-zero under cease-to-energize flows through the new publisher),
`perfect-storm`, `nan-sentinel`.

## Conformance implications
None on the CSIP wire. SunSpec write path unchanged at register level (same
DERControlBase → derbase mapping).

## Suggested commit message
`feat(reconcile): solar class on reconciler — explicit-ceiling desired docs (TASK-029)`
`Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>`

## Suggested PR title & description
**Title:** Phase 2: solar flip — reconciler owns inverter writes; restore-while-dark
reproduced
**Description:** Desired docs carry explicit ceilings (cap or restore); shadow-triaged
then flipped; reassertLocked/lastCtrl suppressed for active inverters (single
reasserter). Evidence: ×10 solo on the release-edge oracles + 10-cycle campaign.
Rollback: config `shadow` + restart.

## Code review checklist
- Single-reasserter proof for inverters (initial-desired vs reassertLocked).
- One-sided divergence rule.
- Publisher NaN→restore mapping tested; no doc ever encodes restore as absence.
- Optimizer diff is empty.

## Definition of done
Acceptance criteria + regression checklist; ledger updated; status headers (this file +
00_MASTER_INDEX) updated.

## Possible follow-up tasks
TASK-030 (EVSE), TASK-031 (reports), TASK-032 (deletion), TASK-046 (publish-rate budget
observation from step "Common mistakes").
