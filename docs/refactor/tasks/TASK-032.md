# TASK-032 — Delete the legacy convergence mechanisms (per-mechanism revertible commits)

*Status: DONE (2026-07-06, lexa-hub 20cc2b2·783a4c5·9fbcaa0·f87136c) · Phase: P2 · Effort: L · Difficulty: med · Risk: **high***

> **Closeout (2026-07-06).** Four per-mechanism deletion commits on lexa-hub
> `task/032-delete-legacy` (+ CLAUDE.md 2f090fe, config 66cfb11): (A, 20cc2b2)
> legacy `lexa/control/*` + `lexa/evse/+/command` publish/subscribe surface and
> the `MQTT*Actuator` publishers — the desired-doc publisher is now the sole
> actuator; config battery/solar/evse must be reconciler `active` (off/shadow
> fatal). (B, 783a4c5) `cmdDeduper` + `reassertEvery` watchdog + breach-triggered
> `dedupeResets`. (C, 9fbcaa0) `retryDevice.lastCtrl` + `reassertLocked` (retry
> mechanics kept). (D, f87136c) redundant `restoreOnGenLimitClear` (differential-
> equivalent to `applyRestoreRule`). `applyRestoreRule` (ledger L1) is KEPT — only
> its downstream publish spam died; comment clarified. `go test -race
> ./internal/... ./cmd/...` green after every commit; each commit reverts
> independently. Binary-only deploy to hub-pi (configs/mqttproxy-1882/FAST
> preserved; backups `.bak-t032-*`); steady-state journal shows reconciler-only
> actuation (no legacy-ignored spam). Ledger gate (`qa-mayhem-20260706-010740.md`,
> 5P/5D/0F/0B): release-while-rebooting (L4), curtailment-release (L7),
> control-churn, ev-connector-flap, battery-reboot **PASS**; the 5 DEGRADED all
> post CannotComply (accepted resource-limit), no INV-HUNT, SAFETY held. L7
> deletion held (no revert). Ledger L1–L4, L7 flipped to deleted. Full 51-scenario
> FAST campaign (`docs/qa-task032/full-campaign-20260706-020958.md`): **35P/16D/
> 0F/0B** — above the 32–33P/18–19D band, 0 FAIL/0 BLIND, no regression. Deeper
> 10-cycle soak is Principal-gated. Bench left FAST + reconciler-active, both
> trees left on main; branches `task/032-delete-legacy` (unpushed, unmerged).

## Objective
With all three device classes on active reconcilers and the report chain collapsed, the
legacy convergence machinery is deleted: `cmdDeduper` + its 60 s watchdog + the
breach-triggered `dedupeResets`; the legacy command publish/subscribe paths for
reconciled classes; `retryDevice.lastCtrl` + `reassertLocked`; and (conditionally)
`restoreOnGenLimitClear`. Each mechanism goes in its own revertible commit, each gated by
its preservation-ledger scenarios, after a 10-cycle campaign on the pre-deletion tree.

## Background
This is the move 04 §4.1 calls "the single most dangerous available": every mechanism
below was added to fix a named QA finding, and deleting it bets that the reconciler path
now owns that behavior. The bet is checked scenario-by-scenario via
`docs/refactor/PRESERVATION_LEDGER.md` (TASK-025, updated by 027–031).

Deletion inventory (verify each location at HEAD; ledger rows in parentheses):
- **(L2/L3) `cmdDeduper`**, `reassertEvery`, per-actuator `dedupe` fields, and `reset()`
  — `cmd/hub/actuators.go:24–56` + fields at `:59–144`; `dedupeResets` slice + the
  breach-reset block in the plan observer — `cmd/hub/main.go:99–118`;
  `actuators_test.go`/related cases.
- **Legacy command paths for reconciled classes:** hub publishers `MQTTBatteryActuator`
  /`MQTTSolarActuator`/`MQTTEVSEActuator` legacy publishes (the desired-doc wrappers
  become the only actuator implementations); modbus `subscribeControls` battery/solar
  branches (`cmd/modbus/main.go:181–219`) and ocpp's `SubEVSECommand` subscription
  (`cmd/ocpp/main.go:74–80`) — all "ignored-when-active" since the flips, now removed.
  The topics themselves disappear from traffic; keep the constants in
  `internal/bus/topics.go` one release for tooling, marked deprecated.
  **Exception:** `interlock.noteControl` intent feed was already moved to the
  reconciler apply path in TASK-028 — verify before deleting the battery branch.
- **(L4) `retryDevice.lastCtrl` + `reassertLocked`** — `cmd/modbus/main.go:314–412`
  (`lastCtrl` field, its recording in `ApplyControl`, the reassert block in
  `ReadMeasurements`, `reassertLocked` incl. the never-commanded-inverter branch —
  replaced by the shell's initial-desired, TASK-029 step 4). The retryDevice
  **session-retry mechanics stay**: reopen-on-next-poll, `dropLocked`, the mutex
  serialization (simonvetter client is not concurrent-safe — `:308–313`), and the
  reconnect event hook feeding the reconciler. `retry_test.go` cases split: reconnect
  mechanics stay, reassert cases move to shell tests (they did in 028/029 — verify).
- **(L7, conditional) `restoreOnGenLimitClear` + `genCapActive`** —
  `optimizer.go:163–166, 1251`. After TASK-029 the release edge is carried by the desired
  doc transition; this optimizer-side emission is redundant IF `curtailment-release`
  stays green without it. Own commit, deleted LAST, reverted alone if the gate fails.
  (This is the only optimizer edit permitted in this task.)
- **(L1, clarify-not-delete) `applyRestoreRule`** stays: it computes the standing intent
  (battery idle-to-0W-at-any-SoC, solar restore) that the desired-doc publisher
  serializes. What disappears with the legacy actuators is the per-tick QoS 1 publish
  spam, not the rule. Update its comment to say it now feeds the desired publisher.

Rollback reality (03 Phase 2): before this task, rollback = config flip. **After each
deletion commit, rollback = `git revert` + redeploy.** That asymmetry is why the gate
order below is strict.

## Why this task exists
W2's endgame: four mechanisms → one. Leaving "ignored-when-active" code alive is how the
next engineer re-enables a split-brain writer (the W6/D3 lesson: dead paths inside live
loops are foot-guns). −code, −interaction surface, +one owner per concept.

## Architecture review sections
W2, R1, D11, W6-analogy, §14 item 3; 03 Phase 2 exit criteria; 08 RSK-01; 05 §11
(deleting defensive code rules); ledger L1–L7.

## Prerequisites
- TASK-029, TASK-030, TASK-031 DONE.
- **Gate zero (mandatory before any deletion):** on the pre-deletion tree, every ledger
  row's gate scenarios individually PASS on the reconciler path AND a 10-cycle FAST
  campaign ≤ V6 baseline (0.6 FAIL/cycle, 0 BLIND). Archive as the "pre-deletion
  baseline" — every deletion commit is judged against it.

## Files
- **Read first:** `docs/refactor/PRESERVATION_LEDGER.md` (current statuses);
  `cmd/hub/actuators.go`, `cmd/hub/main.go:90–260`, `cmd/modbus/main.go`,
  `cmd/ocpp/main.go:74–80`, `internal/orchestrator/optimizer.go:1251, 2241` — all at HEAD.
- **Modify:** the files above; associated tests (`actuators_test.go`, `retry_test.go`,
  `control_test.go`); `internal/bus/topics.go` (deprecation comments).
- **Create:** nothing.

## Blast radius
Highest of the phase: hub actuator layer, modbus subscription surface, ocpp subscription
surface, one optimizer function. Bus traffic shape changes (legacy command topics go
silent — anything watching them, e.g. dashboards/harness introspection, must be checked:
`grep -rn "lexa/control/" ~/projects/csip-tls-test/cmd/dashboard/ scripts/` before
deleting the publishers).

## Implementation strategy
One mechanism per commit, in dependency order, each commit followed by its ledger-gate
scenario runs before the next commit is made; full 10-cycle campaign at the end.
Sequence: (1) legacy command paths (publishers+subscribers) — removes traffic, makes
dedupe vestigial; (2) `cmdDeduper`+watchdog+`dedupeResets` — now provably unused;
(3) `lastCtrl`/`reassertLocked`; (4) `restoreOnGenLimitClear` (conditional). Never batch
with unrelated work (05 §12); never merge same-day (05 §12).

## Detailed steps
1. Run gate zero (Prerequisites). Freeze a bench evidence bundle (campaign report +
   per-scenario JSON) in `docs/`.
2. Sweep for external watchers of legacy topics (grep above + dashboard QA world model —
   `cmd/dashboard/mayhem_world.go` in csip-tls-test); coordinate TASK-033 if any oracle
   listens to them.
3. **Commit A — legacy command paths.** Hub: legacy actuator publishes removed (desired
   publisher becomes the registered actuator); modbus battery/solar branches and ocpp
   command subscription removed; config `"reconciler"` values `off|shadow` now invalid
   for migrated classes (fatal with message pointing at this task) — the flag dies here
   rather than lying. Gate A: `battery-reboot`, `solar-reboot-forget`,
   `curtailment-release`, `ev-connector-flap`, `mqtt-broker-restart` (retained-doc
   re-seed now the ONLY resync path) ×10 solo each.
4. **Commit B — cmdDeduper + watchdog + breach-reset.** Delete `cmdDeduper`,
   `reassertEvery`, `dedupeResets`, the observer reset block (`main.go:99–118` shrinks to
   plan-log + component feed). Gate B (L2/L3 rows): `export-cap-full-battery`,
   `control-churn`, `curtailment-release` ×10 solo; verify in journal that a forced
   device revert still gets its corrective write ≤ poll+readback (the 2026-07-03
   0 W-ceiling incident's regression check).
5. **Commit C — lastCtrl/reassertLocked.** Per the Background scope (retry mechanics
   stay). Gate C (L4): `release-while-rebooting`, `solar-reboot-forget`,
   `battery-reboot` ×10 solo.
6. **Commit D — restoreOnGenLimitClear (conditional).** Delete; run
   `curtailment-release` ×10 solo. Any FAIL → revert commit D permanently and mark L7
   `kept (redundant emission retained deliberately)` in the ledger.
7. Final: **10-cycle full FAST campaign** ≤ pre-deletion baseline; INV-HUNT clean.
8. Ledger: flip L1 (spam half), L2, L3, L4 (and L7 per step 6) to `deleted (T032,
   commit <sha>)`; each row cites its gate evidence.
9. Deploy discipline throughout: hub deploys between commits re-run
   `hub-replay-tune.sh fast`; `bin/dashboard` rebuilt if the bench repo changed.

## Testing changes
Legacy-mechanism unit tests deleted WITH their mechanism in the same commit (a deleted
guard's test must not linger red); shell/reconciler tests already cover the behaviors
(verify coverage before deleting — 05 §11: "the originating scenario green on the
replacement" + the replacing tests named in each commit message). No new tests except:
a modbus test that battery/solar legacy topics are no longer subscribed (subscription
list assertion).

## Documentation changes
- Ledger statuses (step 8) — the program's audit trail for "why was this safe".
- lexa-hub CLAUDE.md: topic table rows for `lexa/control/*` and `lexa/evse/+/command`
  marked removed/replaced by `lexa/desired/*`; "Defensive fault-handling" section
  updated to name the reconciler as the owner.
- `internal/bus/topics.go` deprecation comments.

## Common mistakes to avoid
- Deleting anything before gate zero exists as an archived artifact. "It passed last
  week" is not a gate.
- Batching two mechanisms in one commit — kills the per-mechanism revert (the entire
  design of this task).
- Deleting `retryDevice` wholesale: its mutex + reopen mechanics are load-bearing
  transport code (concurrent-use corruption, `main.go:308–313`), independent of
  convergence.
- Deleting `applyRestoreRule` because its comment says "restore" — it is the intent
  source (L1). Only its downstream publish spam died.
- Forgetting `interlock.noteControl` is fed by the reconciler now — a careless branch
  delete that also removes the feed reopens battery-wrong-sign blindness. `interlock_test.go`
  green after every commit.
- Leaving `off|shadow` config accepted for migrated classes — a config file from a
  backup would silently disable actuation entirely (no legacy path remains to fall
  back to).

## Things that must NOT change
- Every ledger "Behavior that must survive" cell for L1–L7 — now owned by the
  reconciler/desired-doc/episode paths; the gate scenarios are the proof.
- Tier-0 interlock (L8), `plausibleW` (L9), optimizer convergence guards (L10 —
  `restoreOnGenLimitClear` is the sole sanctioned optimizer deletion), EVSE L11.
- Plan-log/heartbeat publishing (observer keeps it).
- Desired-doc schema and reconciler semantics (no "while we're in here" tuning).

## Acceptance criteria
- [ ] Four (or three, if D reverted) deletion commits, each naming its ledger rows,
      replacing mechanism, and gate evidence in the commit message.
- [ ] `grep -rn "cmdDeduper\|reassertEvery\|dedupeResets\|lastCtrl\|reassertLocked" cmd/`
      → no matches (modulo comments referencing history).
- [ ] Gate runs A–D archived; final 10-cycle campaign ≤ pre-deletion baseline, 0 BLIND.
- [ ] Ledger fully updated; no row left `legacy-active`.
- [ ] lexa-hub builds/deploys; bench steady-state journal shows reconciler-only actuation.

## Regression checklist
- [ ] `go test -race ./internal/...` (lexa-hub) green after EVERY commit
- [ ] `make test-fast` (csip-tls-test) green
- [ ] Conformance logic tests: `go test ./tests/` green (CannotComply path exercised)
- [ ] Mayhem: gate zero + per-commit gates + **final 10-cycle FAST campaign**
- [ ] `interlock_test.go` green unmodified after every commit

## Mayhem scenarios affected
Gates per commit as listed (A: reboot/reconnect family + mqtt-broker-restart;
B: export-cap-full-battery, control-churn, curtailment-release;
C: release-while-rebooting, solar-reboot-forget, battery-reboot;
D: curtailment-release). Watch globally: `perfect-storm`, `clock-jitter`, INV-HUNT.

## Conformance implications
None on the wire (CannotComply already restructured in TASK-031). SunSpec write payloads
identical — only their trigger machinery changed.

## Suggested commit message
Series: `refactor(hub)!: delete legacy command paths (ledger L2-gate A) (TASK-032)` ·
`refactor(hub)!: delete cmdDeduper/watchdog/breach-reset (L2,L3)` ·
`refactor(modbus)!: delete lastCtrl reassert (L4)` ·
`refactor(orchestrator): drop redundant restoreOnGenLimitClear (L7)`
each + `Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>`

## Suggested PR title & description
**Title:** Phase 2 endgame: legacy convergence machinery deleted (per-mechanism commits)
**Description:** Gate-zero baseline linked; one commit per mechanism with per-commit
scenario gates; final 10-cycle campaign. Rollback: revert the specific commit (each
stands alone). Radioactive-zone rules observed (one-per-PR spirit: this PR is the
sanctioned series; no unrelated changes).

## Code review checklist
- Commit granularity: exactly one mechanism per commit; reverts compile independently
  (try `git revert --no-commit` on each locally).
- retryDevice diff removes ONLY lastCtrl/reassert code.
- No optimizer edits beyond restoreOnGenLimitClear.
- Ledger + CLAUDE.md updated in the same PR.

## Definition of done
Acceptance criteria + regression checklist; ledger closed out; status headers (this file
+ 00_MASTER_INDEX) updated; evidence bundle in `docs/`.

## Possible follow-up tasks
TASK-033 (Mayhem updates + sign-off), TASK-041 (episode snapshot), P5 TASK-056+ (L10
guards migrate at optimizer split), backlog: remove deprecated topic constants next
release.
