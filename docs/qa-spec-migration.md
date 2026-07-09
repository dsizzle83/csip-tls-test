# QA scenario-spec migration (TASK-076/077)

TASK-076 built the declarative scenario-spec engine (`cmd/dashboard/scenariospec.go`,
`qa/scenarios/*.json`, oracle registry) and proved it with one pilot scenario
(`export-cap-full-battery`, shipped colliding with its still-present Go twin on
purpose). TASK-077 is the migration itself: move as much of the curated Mayhem
suite as is straightforwardly expressible in the v1 action vocabulary onto
`qa/scenarios/*.json`, delete the Go twin once parity is proven, and register
any oracle a migrated scenario needs.

**Scope taken this session (deadline addendum, 2026-07-06 owner directive):**
a solid, high-confidence first wave — every scenario whose Go twin needed no
new vocabulary and either an already-registered oracle or a trivial
no-param registration — rather than chasing all ~60 scenarios in one pass.
Full parity of the whole suite is an explicit non-goal this session; a clean,
provably-correct, well-documented migration that a successor can extend by
adding more `.json` files (no Go changes needed for the next vocab-ready
scenario) is the goal.

**Enumeration caveat:** step 1 of the task asks to reconcile the count via
`python3 scripts/mayhem.py --list` against a *live* dashboard. This session's
lane is explicitly bench-free (no bench runs, no `csip-dashboard` restart —
see the launch brief), so the table below is reconciled by static source
enumeration instead (`grep -c 'ID: "' cmd/dashboard/*.go` + `malformScenario(`
call sites), cross-checked against `qa/scenarios/*.json` file count. A
live `--list` reconciliation (and the bench-side parity runs the full
protocol calls for — see "What 'parity' means here" below) is the natural
first step for whoever picks up the next wave.

## Current counts (post-migration, static enumeration)

| Source | Count |
|---|---|
| `cmd/dashboard/mayhem.go` direct literals | 9 |
| `cmd/dashboard/mayhem.go` via `malformScenario(...)` | 5 |
| `cmd/dashboard/mayhem_world.go` (`worldScenarios()`) | 18 |
| `cmd/dashboard/mqtt_scenarios.go` (`mqttScenarios()`) | 8 |
| `qa/scenarios/*.json` (migrated specs) | 24 |
| **Total scenario entries** (excludes `matrix.go`'s programmatic product) | **64** |

Before this session: 33 direct + 5 malform + 17 world + 8 mqtt = 63 Go
literals, 1 spec file (the colliding, non-live pilot). After: 24 of the 33
direct-literal family are migrated+live specs, their Go twins deleted;
9 direct + 5 malform + 17 world + 8 mqtt = 39 Go literals remain. The total
scenario *count* is unchanged (63 → 63) — a migration replaces its twin 1:1,
per the task's "keep the campaign scenario COUNT stable" instruction.

## Migrated (24) — spec file, oracle, parity evidence

Every row: JSON spec under `qa/scenarios/<id>.json` (byte-identical
hypothesis/expected/fix prose to the deleted Go literal — the "never edit
prose during migration" rule), a dedicated parity unit test in
`cmd/dashboard/scenariospec_migration_test.go` (`export-cap-full-battery`'s
predates this task in `scenariospec_test.go`), and the registered oracle it
uses. All 24 also pass the pre-existing `TestCompileAllScenarioSpecs`
compile-all gate and the ID-collision-free load implied by
`TestScenarios_SpecDirEmpty_GoSetUnaffected`/normal `scenarios()` operation
(no more collision logged for any of these 24 — their Go twins are gone).

| ID | Oracle | Oracle status | Parity test |
|---|---|---|---|
| `export-cap-full-battery` | `diagnoseConstraint` | pre-registered (076) | `TestCompileSpec_ExportCapFullBattery_MatchesGoTwin` (076) |
| `ack-before-effect` | `diagnoseConverge` | pre-registered (076) | `TestMigrated_AckBeforeEffect` |
| `reject-write-curtail` | `diagnoseConverge` | pre-registered (076) | `TestMigrated_RejectWriteCurtail` |
| `enable-gate-curtail` | `diagnoseConverge` | pre-registered (076) | `TestMigrated_EnableGateCurtail` |
| `ramp-limit-curtail` | `diagnoseConverge` | pre-registered (076) | `TestMigrated_RampLimitCurtail` |
| `battery-wrong-sign` | `diagnoseSOC` | pre-registered (076) | `TestMigrated_BatteryWrongSign` |
| `battery-soc-refuse` | `diagnoseConstraint` | pre-registered (076) | `TestMigrated_BatterySocRefuse` |
| `battery-charge-disabled` | `diagnoseConstraint` | pre-registered (076) | `TestMigrated_BatteryChargeDisabled` |
| `battery-empty-import-cap` | `diagnoseConstraint` | pre-registered (076) | `TestMigrated_BatteryEmptyImportCap` |
| `ev-profile-reject` | `diagnoseConstraint` | pre-registered (076) | `TestMigrated_EvProfileReject` |
| `ev-accept-but-ignore` | `diagnoseConstraint` | pre-registered (076) | `TestMigrated_EvAcceptButIgnore` |
| `ev-min-current-floor` | `diagnoseConstraint` | pre-registered (076) | `TestMigrated_EvMinCurrentFloor` |
| `ev-delayed-obey` | `diagnoseConstraint` | pre-registered (076) | `TestMigrated_EvDelayedObey` |
| `grid-disconnect` | `diagnoseDisconnect` | pre-registered (076) | `TestMigrated_GridDisconnect` |
| `conflicting-primacy` | `diagnoseConstraint` | pre-registered (076) | `TestMigrated_ConflictingPrimacy` |
| `solar-reboot-forget` | `diagnoseConstraint` | pre-registered (076) | `TestMigrated_SolarRebootForget` |
| `curtailment-release` | `diagnoseRecovery` | pre-registered (076) | `TestMigrated_CurtailmentRelease` |
| `nan-sentinel` | `diagnoseTransport` | **new (077)** | `TestMigrated_NanSentinel` |
| `modbus-exception` | `diagnoseTransport` | **new (077)** | `TestMigrated_ModbusException` |
| `modbus-latency` | `diagnoseTransport` | **new (077)** | `TestMigrated_ModbusLatency` |
| `solar-bad-scale` | `diagnoseTransport` | **new (077)** | `TestMigrated_SolarBadScale` |
| `battery-nan-sentinel` | `diagnoseBatteryGarbage` | **new (077)** | `TestMigrated_BatteryNanSentinel` |
| `battery-reboot` | `diagnoseReboot` | **new (077)** | `TestMigrated_BatteryReboot` |
| `expired-control` | `diagnoseExpiry` | **new (077)** | `TestMigrated_ExpiredControl` |

### What "parity" means in this session's evidence

The full protocol (task step 5) is: Go version ×1 + spec version ×3 **on the
live bench**, alternating which is loaded, judging identical verdicts (or
⊆ the accepted set) and diagnosis text from the same oracle path. This
session's lane is explicitly bench-free, so the evidence here is the unit
half only: each parity test in `scenariospec_migration_test.go`

1. compiles the shipped `.json` (proving decode/validate/compile succeed —
   the same gate `TestCompileAllScenarioSpecs` runs over every file),
2. runs `setup()`/`perTick()`/`teardown()` against a recording fake HTTP
   backend and asserts the exact method/path/body(s) the deleted Go literal
   used to call — the scenario-specific fault-arm call, the constraint
   type/limit, `at_tick` gating where used, and the teardown clear/delete,
   and
3. asserts `sc.evaluate` is the exact registered oracle function (pointer
   identity via `reflect.ValueOf(...).Pointer()`, valid because
   `noParamOracle` returns the function value itself unwrapped) — the "same
   oracle path" half of the criterion.

This proves the compiled spec is behaviorally identical to the deleted Go
closure at the call-sequence level — the part that's easy to get wrong
migrating by hand (a typo'd fault kind, a swapped `lim_w`, a missing
`at_tick`). It does **not** re-prove the underlying diagnose* function's
verdict logic (076/earlier tasks already unit-test those in isolation) or
walk the live hub end-to-end. **Residual:** a live-bench ×3 parity pass (and
a full FAST campaign at ≤ the 0.6 FAIL/cycle / 0 BLIND baseline) is the
first thing the next bench-attached QA session should run against this
branch before treating the 24 migrated scenarios as campaign-equivalent to
their deleted Go twins. `python3 scripts/mayhem.py --list` will show all 24
as `[spec]` where they used to show as `[go]`; nothing else about a
campaign invocation changes.

## Retained in Go (39) — reason per family

### `cmd/dashboard/mayhem.go` (14 remaining)

| ID(s) | Reason |
|---|---|
| `malformed-csip`, `malform-missing-href`, `malform-empty-program`, `malform-huge-activepower`, `malform-bad-duration`, `malform-pagination` (via `malformScenario()`), `pricing-attack`, `curve-attack` | All arm the fault from inside a **goroutine that sleeps 8 s then posts**, so the safe control is adopted on a clean walk before the malform lands (`go func(){ time.Sleep(8*time.Second); ... }()` inside `setup`, returning immediately). The v1 vocabulary's `setup` actions run synchronously in order — there is no "fire this in the background after N seconds" verb. This is exactly the `delay_s`-on-setup-action extension flagged in the task background (step 2) as expected but not yet implemented; a small, well-scoped follow-up (add `DelayS float64` to `scenarioAction`, valid in `setup` only, compiling to a goroutine that does not block `setup()`'s return) unlocks all 8 of these at once — they all share `diagnoseMalform`, already registered. |
| `ev-connector-flap` | `perTick` alternates the connector status every tick (`st := []string{"Occupied","Faulted"}[i%2]`) — a computed/branching per-tick value, not a fixed action or a single `at_tick` one-shot. The v1 vocabulary deliberately has no expression/modulo support (README "Why JSON, not a scripting language"); this needs either a small `"alternate"` sentinel (like `pv_w`'s `"high"`) or stays Go. |
| `ev-meter-freeze`, `ev-wrong-units` | **Not a vocabulary gap** — both are already expressible verbatim (fixed setup/per_tick calls, no computed values) and each needs only a trivial `noParamOracle(diagnoseEVFreeze)` / `noParamOracle(diagnoseEVUnits)` registration, exactly like this wave's `diagnoseTransport` et al. Deferred purely for session-scope discipline (this wave targeted ~24, not ~30); **flagged as the cheapest possible next two migrations** for whoever picks this up. |
| `stale-meter` | `perTick` computes a ramping PV value every tick (`d.injectEnv(2000+float64(i)*400, loadLow)`) — a per-tick arithmetic expression the vocabulary cannot express (same class of gap as `clock-jitter`/`perfect-storm` below). Needs a "ramp" sentinel/extension analogous to `pv_w`'s `"high"` (e.g. `{"ramp_from":2000,"ramp_step":400}`) — a real but modest vocabulary addition, not attempted this session. `diagnoseStale` is already registered and ready the moment the ramp extension lands. |
| `clock-jitter` | `perTick` computes a clock offset from a formula of the tick index (`off := int64((i%7 - 3) * 20)`) starting at `i>=10` — the same "no expressions" gap. A `"jitter"` action-parameter sentinel could express this specific pattern, but it is narrow (one scenario's exact formula) and not generalizable the way `delay_s` is; left as documented Go. |
| `perfect-storm` | Combines a goroutine-delayed fault (`ack_before_effect` + a delayed meter-freeze), a per-tick clock-offset formula, and five simultaneous fault domains — the deliberate "kitchen sink" scenario. Even after `delay_s` and a jitter extension land, this one is a poor first migration target: it is the highest-blast-radius scenario in the suite (06 §Mayhem) and its value is in NOT changing while everything else does. Retained as Go by design, not by gap. |

### `cmd/dashboard/mayhem_world.go` (18: 17 untouched this wave + 1 added post-hoc)

`consumer-restart-after-quiescence` (WS-2, `docs/refactor/HANDOFF.md` §8,
added after this session) is Go **by explicit instruction**, not because its
`setup`/`perTick` shape is vocab-blocked — a static `injectEnv` every tick
plus one `ssh_hub` restart at a fixed `at_tick` is close to what
`hub-restart-mid-cap` already proves is expressible. The reasons it stays a
`mayhem_world.go` literal: (1) it ships a brand-new, scenario-specific oracle
(`diagnoseConsumerRestartAfterQuiescence`) reading a NEW ground-truth field
(`SolarCeilingPct`/`SolarCeilingEna`, the inverter's own WMaxLimPct register,
added to `maySample` alongside it) — "oracles are code, scenarios are data"
means the oracle had to be Go regardless, and a first-use oracle ships next
to its one scenario rather than pre-registered speculatively; (2) the task
that introduced it (WS-2 fix 3) explicitly directed a Go literal in the
mayhem_world.go family, citing this file's own retained-in-Go convention.
Once `diagnoseConsumerRestartAfterQuiescence` is registered as a
`noParamOracle`, migrating the scenario itself to a `.json` spec (mirroring
`hub-restart-mid-cap`'s vocab-ready triage below) is a small, low-risk
next-wave candidate — flagged here for whoever picks that up.

Not attempted this session (task's own wave ordering: "constraint family
first... then world/mqtt... bespoke-oracle scenarios last" — P4/P5's world
scenarios are generally the more bespoke half). Quick triage for the next
wave, from a read of the file (no vocabulary changes assumed beyond what
exists today):

- **Likely vocab-ready with only an oracle registration**, based on a skim
  of their `setup`/`perTick`/`teardown` shape: `wan-outage-hold` (already has
  an inline compiler proof under a synthetic ID in `scenariospec_test.go`,
  `TestCompileSpec_WanOutageHold_MatchesGoTwin` — a real migration is
  mostly "add the file"), `wan-outage-expiry`, `hub-restart-mid-cap` (uses
  `ssh_hub`, already in the vocabulary — the task background explicitly
  names this one as vocab-ready), `disk-full`, `northbound-hang`.
- **Likely need `delay_s` or a similar timing extension**: `release-while-rebooting`,
  `local-clock-step-forward`, `local-clock-step-back`.
- **Likely need per-tick computed values (same class as `stale-meter`/`clock-jitter`)**:
  `meter-ct-inverted` (dither pattern), `clock-jump-forward`, `control-churn`,
  `pv-flicker`, `export-dither-at-breach`, `soc-dither-at-reserve` (the two
  `Extended` RSK-12 long-running scenarios).
- **Uses the `netem` SSH helper, not just `ssh_hub` directly**: `netem-loss-export-cap`,
  `netem-reorder-northbound`, `netem-jitter-evse` — worth checking whether
  `ssh_hub` alone can express the `scripts/netem.sh` invocation, or whether
  this needs its own verb.

This triage is a read of the source, not a proof — treat it as a starting
point, not a commitment, for the next wave.

### `cmd/dashboard/mqtt_scenarios.go` (8, untouched this wave)

Not attempted this session. The vocabulary already has `mqtt_fault`/
`mqtt_inject`/`mqtt_reset` (076 built these as driver-verb sugar, explicitly
kept per this task's "Files" section: "mqtt_scenarios.go — shrink to helpers
the driver keeps: mqttFault/mqttInject/mqttReset stay — they are driver
verbs"), so several of `mqtt-broker-restart`, `mqtt-broker-latency`,
`mqtt-malformed-control`, `mqtt-stale-retained` are plausibly vocab-ready
next-wave candidates. `duplicate-client-id`, `mqtt-storm`,
`power-cut-retained-rollback`, `corrupted-retained-control` looked more
bespoke on a skim (process-level broker manipulation / custom ladders) and
were not triaged deeply this session.

### `cmd/dashboard/matrix.go` (generator, out of scope by design)

`matrixScenarios()` is a programmatic product of fault cells × jitter
variants, not N hand-written literals — the task explicitly scopes this
out ("OUT of scope: stays Go (it is a generator, not 51 literals; record as
retained-with-reason)"). A spec-driven matrix (parameterizing the JSON
schema itself, not just adding more files) is listed in TASK-077's own
"Possible follow-up tasks" as backlog, not this task's job.

## What a successor should do next

1. **Vocabulary extension: `delay_s` on setup actions.** Unlocks 8 scenarios
   in one PR (the whole `malformed-csip`/`malform-*`/`pricing-attack`/
   `curve-attack` family) — the single highest-leverage next step. Add
   `DelayS float64 \`json:"delay_s,omitempty"\`` to `scenarioAction`, valid in
   `setup` only; compile to `go func(){ time.Sleep(...); run(d) }()` inside
   `compileSetupOps`, not blocking `setup()`'s return — mirroring
   `malformScenario`'s own goroutine pattern exactly. Unit-test the timing
   contract (the delayed call must not have fired by the time `setup()`
   returns) the same way `TestCompileSpec_WanOutageHold_MatchesGoTwin` proves
   `at_tick` gating.
2. **Two free wins:** register `diagnoseEVFreeze` and `diagnoseEVUnits`
   (both already `noParamOracle`-shaped) and ship `ev-meter-freeze.json` /
   `ev-wrong-units.json` — no vocabulary work needed at all.
3. **Run the deferred bench-side parity pass** (task step 5's full protocol)
   for all 24 scenarios already migrated in this session, before or
   alongside adding more.
4. **`mayhem_world.go`/`mqtt_scenarios.go` triage above** — confirm which
   are truly vocab-ready vs. need extensions, starting with
   `hub-restart-mid-cap` (the task's own named example) and `wan-outage-hold`/
   `wan-outage-expiry` (closest analogues to already-migrated scenarios).
5. Update this document's table and the retained-count in `CLAUDE.md`'s
   Mayhem section each time a further wave lands.
