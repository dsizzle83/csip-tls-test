# QA Fault-Injection Strategy

**Date:** 2026-06-19
**Scope:** Making the `csip-tls-test` bench exercise the LEXA hub against the
faults a real field deployment produces — latency, partial compliance, device
reboot, command rejection, clock drift, broker loss, stale actuator state —
rather than only ideal protocol flows.
**Motivation:** The 2026-06 senior review concluded the bench proves "works in a
controlled simulation," not "safe in a home." Today the sims model happy-path
DER behaviour. This document is the plan to close that gap, and the spec for the
`POST /fault` injection seam that makes it possible.

> Companion docs: `HARNESS_REVIEW.md` (audit findings), `BENCH.md` (live
> topology), `REPLAY_RUNBOOK.md` (HIL cost-sim driver this reuses).

---

## Principle 0 — oracles before chaos

Fault injection without a pass/fail oracle just produces noise. Before injecting
anything, stand up a **continuous invariant monitor**: a sidecar that watches the
*real* meter + sim states and the hub's commands, and flags violations with
timestamps. Every scenario below is then "inject fault → assert the invariant
holds, or the hub degrades safely → measure **breach duration**." Breach
*duration* is the headline metric — in grid control, "wrong for 2 s" and "wrong
for an hour" are different severities.

### Safety envelope (the oracles)

| ID | Invariant | Source of truth |
|----|-----------|-----------------|
| **INV-EXPORT** | Site export/import never exceeds the active limit for more than one control interval | real meter (metersim) net W |
| **INV-SOC** | Battery SOC stays within `[reserve, max]`; no charge when full, no discharge when empty | batsim M802 SoC |
| **INV-RESTORE** | After a curtailment event ends, solar returns to ≥95% nameplate within N s (guards the restore-path class of bug) | modsim M103 W vs WAval |
| **INV-EV** | EV meets departure SOC unless physically impossible | evsim transaction meter |
| **INV-CONVERGE** | Every issued setpoint is reflected in measurement within a deadline, or an alarm fires | hub command log vs meter |
| **INV-HUNT** | The control loop converges below an active cap and stays — it never oscillates curtail→release→breach around the cap line (≥3 post-settling breach re-entries after clear recoveries = sustained hunting; demotes PASS→DEGRADED) | real meter / modsim vs the active cap |

---

## The `POST /fault` seam

Every sim already exposes `simapi` (`GET /state`, `POST /inject`, `POST
/control`, `GET /logs`). Fault injection adds one verb in the same shape:

```
POST /fault    body: {"kind":"<fault>", ...params, "clear":<bool>}
  204 No Content   — fault armed/cleared
  400 Bad Request  — unsupported kind or bad params (body: error text)
  501 Not Impl.    — this sim wires no fault handler
```

Wiring (per sim binary, after `simapi.New`):

```go
api.SetFaultFn(srv.ApplyFault)   // srv.ApplyFault(body []byte) error
```

A sim advertises only the `FaultKind`s it supports and returns `400` for the
rest. Fault kinds are defined in `sim/southbound/sim.go` (`FaultKind`,
`FaultSpec`) so all sims share one vocabulary.

### Implemented today

**Modbus DER (two fault layers — write-time *acceptance* and effect-time *physical response*):**
`ack_before_effect`, `reject_write`, `enable_gate`, `ramp_limit` (solar);
`wrong_sign`, `soc_refuse` (battery). **Meter (transport/read-path only — a
read-only device):** `invert_sign` (CT clamp installed backwards; flips the
signed W/VAR/A registers on the Modbus read path while `/state` ground truth
stays honest), `nan_sentinel`, `latency`, `exception_code`. **OCPP
(CSMS/charger boundary):** `profile_reject`, `apply_next_tx`,
`min_current_floor`, `stop_metervalues` (evsim). **Grid safety:** `disconnect`
(gridsim opModConnect=false). **Malformed CSIP** (gridsim `POST
/admin/malform`, applied at serve time): `empty_program_list`,
`huge_activepower`, `bad_duration`, `dup_mrid`, `missing_href`.
**Northbound outage** (gridsim `POST /admin/outage`, gating only the
mTLS-served CSIP tree — the admin API stays reachable): `down` (every CSIP
request 503s immediately: a dead/rebooting head-end), `hang` (each request
stalls `hang_s` before the 503: a wedged server / black-holing middlebox);
`duration_s` auto-clears so an aborted run can never leave the bench
northbound-dead.

Not a fault, but the same serve-time seam and documented here beside its
neighbours: **explicit-null `DERControlBase` elements** (gridsim
`POST /admin/control` `null_axes`) serve an element that is *present and
explicitly null* rather than omitted — RC0 §9.5 row 9's release shape. See the
section at the end of this document for the curl bodies and for what it
deliberately does not claim.

The write layer (`RegisterMap.OnWriteAttempt` → `faultController.intercept`)
decides what lands in the control register; the effect layer
(`faultController.effectiveCeilW` for solar slew, `shapeBatteryW` for the battery)
shapes the device's physical output each animation step. Together they separate
*commanded* / *accepted* / *effective*, which is where most real bugs hide.

#### Legacy quick reference

```bash
# Arm: WMaxLimPct writes ACK at the Modbus layer but take effect 30 s later.
curl -X POST 69.0.0.10:6020/fault -d '{"kind":"ack_before_effect","delay_s":30}'
# Arm: the inverter ACKs the curtailment write but keeps its old ceiling.
curl -X POST 69.0.0.10:6020/fault -d '{"kind":"reject_write"}'
# Arm (battery): a commanded charge executes as a discharge.
curl -X POST 69.0.0.11:6021/fault -d '{"kind":"wrong_sign"}'
# Clear (any kind):
curl -X POST 69.0.0.10:6020/fault -d '{"kind":"reject_write","clear":true}'
```

Mechanism: a shared `faultController` (`sim/southbound/faults.go`), embedded by
each Modbus sim, owns the armed-fault state and the `RegisterMap.OnWriteAttempt`
write-time semantics; the sim supplies the address of its control register (the
signed `M123 WMaxLimPct`) and the set of kinds it advertises (`solarFaultKinds`,
`batteryFaultKinds`). All three kinds let the Modbus layer return success while
the device misbehaves:

- `ack_before_effect` (solar) — holds the WMaxLimPct change for `delay_s`, so a
  hub that treats **write-success == converged** believes a limit is in force
  before it is. The hub should detect the lag via measurement (INV-CONVERGE).
- `reject_write` (solar) — the control value never lands; the inverter keeps its
  old ceiling. Accept-but-ignore — the same INV-CONVERGE failure made permanent.
- `wrong_sign` (battery) — a signed charge command lands as a discharge, walking
  a low pack toward empty (INV-SOC).

Unit-tested in `sim/southbound/faults_test.go` (`reject_write`, `enable_gate`,
`wrong_sign`, `soc_refuse`, `ramp_limit` slew) and `sim/evsim/faults_test.go`
(all four OCPP kinds). Driven end-to-end by the `mayhem` scenarios
`reject-write-curtail`, `enable-gate-curtail`, `ramp-limit-curtail`,
`battery-wrong-sign`, `battery-soc-refuse`, `ev-profile-reject`, `grid-disconnect`
— each judged by an INV-* oracle (INV-CONVERGE / INV-SOC / INV-CONNECT), with the
diagnosers and invariant predicates unit-tested in
`cmd/dashboard/invariants_test.go` and `cmd/dashboard/mayhem_test.go`. The
diagnosers distinguish ignore (FAIL) / catch-and-admit (DEGRADED) /
slew-converging (DEGRADED) / wrong-direction (FAIL) / ceased-to-energize (PASS).

### Run modes (Phase 5)

- **Deterministic regression gate** — `make qa` (or `scripts/qa-regression.sh`)
  runs the fault-injector + diagnoser unit tests; fast, no bench, CI-gatable
  (non-zero exit on any failure). `make qa-bench` adds the live mayhem suite.
- **Curated suite** — `scripts/mayhem.py` runs the hand-written scenarios and
  exits non-zero on any FAIL/BLIND.
- **Fault matrix** — `scripts/mayhem.py --matrix` (or `make qa-bench MODE=--matrix`)
  runs a curated, pairwise cross of {grid constraint × device fault} each WITH and
  WITHOUT a ±60 s clock-jitter modifier (`cmd/dashboard/matrix.go`), so one run
  sweeps fault×timing interactions. Each scenario is isolated by `resetForScenario`
  (clears faults/controls, uncurtails the inverter) so one scenario's device state
  cannot mask a fault in the next.
- **Seeded chaos** — `scripts/mayhem.py --chaos [--seed N] [--iterations K]` runs a
  randomized sequence drawn from the same curated cell templates with random jitter
  and ±25 % hold perturbation. The seed is reported back (and written into the
  report), so any failure is replayable byte-for-byte with `--chaos --seed N`.
- **Scenarios-as-data (TASK-076)** — the curated suite above is hand-written Go
  literals (`scenarios()`), which means adding or tweaking one needs a
  `go build -o bin/dashboard ./cmd/dashboard` + dashboard restart — the trap
  that burned the 2026-07-03 stale-binary incident. `qa/scenarios/*.json`
  scenario specs (`cmd/dashboard/scenariospec.go`) compile into the exact same
  `mayScenario` the run loop executes, but load **fresh on every run** — no
  rebuild, no restart. Oracles (the `diagnose*` funcs / INV-* invariants
  above) stay Go, registered by name; only the scenario's setup/perTick/
  teardown steps and which oracle+params judge it are data. See
  `qa/scenarios/README.md` for the schema and action vocabulary, and
  `scripts/mayhem.py --list`, which tags each scenario `[go]` or `[spec]`.

---

## Fault matrix (roadmap)

Each row is a reusable injector keyed to an existing seam. Priority: **P1** first
(highest field-risk, cheapest), then P2/P3.

| Pri | Layer | Fault kind(s) | Seam | Hub MUST |
|----|-------|---------------|------|----------|
| P1 | Physical DER | `ack_before_effect` ✅, `reject_write` ✅, `wrong_sign` ✅, `enable_gate` ✅, `ramp_limit` ✅, `soc_refuse` ✅ | sim models + `OnWriteAttempt` (write) / `effectiveCeilW`+`shapeBatteryW` (effect) | not assume success; re-issue or fall back; alarm on non-convergence |
| P1 | OCPP | `profile_reject` ✅, `apply_next_tx` ✅, `min_current_floor` (6 A) ✅, `stop_metervalues` ✅ | `evsim` / CSMS | treat reject/timeout as failure (now returns error after the 2026-06 fix); react, don't just log |
| P1 | Grid safety | `disconnect` (opModConnect=false) ✅ | gridsim `/admin/control` | cease to energize — drive every DER to ~0 within seconds (INV-CONNECT) |
| P1 | MQTT | `broker_down`, `retained_redeliver`, `dup_out_of_order` | pause/kill Mosquitto; replay driver | fail-safe when control plane is gone; idempotent commands |
| P2 | Modbus transport | `crc_error`, `exception_code`, `tcp_drop`, `latency`, `nan_sentinel` (0x8000) | sim wrapper / `toxiproxy` on 502x | stale-expire reading; never act on garbage; surface device-down |
| P2 | Network | `packet_loss`, `jitter`, `partition`, `dns_fail` | `tc/netem` + `toxiproxy` between nodes | reconnect/backoff; hold last-known-good safely |
| P2 | CSIP server | `paginate`, `resource_410`, `event_delay`, `supersede`, `clock_skew`, `malformed_xml`, `slow_loris` | gridsim handlers + `:11112/admin` | honour supersession; survive slow-loris (now bounded by the tlsclient read deadline); no walker deadlock |
| P3 | TLS / certs | `cert_expire`, `ca_rollover` | cert fixtures | graceful re-handshake, not silent stall |

---

## Combined "incident" scenarios

Single faults rarely cause harm; concurrent ones do. Script these in a chaos
driver alongside `cmd/dashboard/replay.go`, overlaid on the 92-day warp:

1. **Broker dies during an active curtailment** → solar un-curtails safely vs.
   stays pinned (control plane gone + actuator in non-default state — the
   classic unsafe-stale case). Tests INV-EXPORT + INV-RESTORE.
2. **Meter goes stale while battery near empty during peak pricing** → does the
   optimizer keep discharging blind? Tests INV-SOC.
3. **Utility cease-to-energize while solar is ramping** → export limit held
   throughout? Tests INV-EXPORT.
4. **Cert expires / CA rollover mid-session** → graceful re-handshake.
5. **Device reboots mid-event** (warm-up + re-adopt) → hub re-applies the active
   DERControl? Tests INV-CONVERGE.

---

## Tooling to add (priority order)

1. **Fault injectors** — extend each sim's `ApplyFault` with the P1 kinds. The
   `ack_before_effect` injector is the template.
2. **Invariant monitor sidecar** — watches meter + sim `/state` + hub command
   log, emits a machine-readable violation log (becomes a CI artifact).
3. **Network-chaos layer** — `toxiproxy` (per-link latency/partition) and
   `tc/netem` in front of the Pi services.
4. **Chaos driver** — like `replay.go` but schedules faults over the warp, so
   soak + fault overlap. The existing clock-warp gives **clock-drift/skew**
   testing for free.
5. **CI gate** — wire `internal/wolfssl` headers into CI so the TLS path + a
   smoke fault-scenario run on every PR; fail the build on any invariant breach.

---

## Metrics (tie to observability)

Per scenario, record: compliance-breach **duration**, command→convergence time,
stale-device count, MQTT reconnects, CSIP discovery failures, TLS handshake
failures, OCPP rejected/timed-out profiles. These are exactly the Prometheus
series the senior review asked for; the fault scenarios are how you generate
non-zero values for them before a customer does.

---

## Sequencing

- **First (cheapest, highest risk):** `ack_before_effect` + `reject_write` +
  OCPP `profile_reject`, asserted by INV-CONVERGE. This is where the
  "command success assumed too early" bugs live — the most product gaps per hour.
- **Second:** broker-down / partition chaos with the stale-state invariants
  (the genuine safety scenarios).
- **Third:** CSIP conformance edge cases (pagination, supersession, malformed
  XML) — needed for certification, lower field-safety risk.
- **Fourth:** soak/endurance with overlaid faults via the warp driver.

## Standards build-out supplemental suite (2026-07)

Scenarios + oracles for the lexa-hub standards build-out (17 WPs). Full matrix,
invariants, and bench-runnability caveats: **`docs/QA_STANDARDS_BUILDOUT.md`**.

**New invariants**: INV-REPORT (DER* PUT + LogEvent + PIN-freeze egress halt),
INV-CANNOTCOMPLY-VOCAB (IEEE Table 27 codes vs legacy 0xF0), INV-REDIRECT
(301/302 follow within `redirect_max`, fail-closed beyond), INV-ADV-READBACK
(curve/PF/energize adoption trusts measured readback, not the write/adopt
handshake), INV-AUS (gen/load-limit cascade+shadow), INV-OCPP16, INV-PAIRING,
INV-V2G-CHARGEONLY, INV-OPENADR.

**New `POST /fault` kinds (target `solar`, requires `modsim -advanced`)**:
- `raise_alarm {bits:<uint32>}` — set the model-701 Alrm bitfield (drives the
  hub's LogEvent poster). Hub-mapped bits: 64 manual-shutdown, 256 over-freq,
  512 under-freq, 1024 AC over-volt, 2048 AC under-volt.
- `curve_adopt_lies` — AdptCrvRslt reports COMPLETED while curve-1 readback stays
  stale (the INV-ADV-READBACK trap: the hub must report adopt_state=diverged).
- `pf_ack_ignore` — 704 PF/var write ACKs but measured PF/var never moves.

**New sim**: `sim/vtnsim` — a minimal OpenADR 3.1 VTN stub (token/programs/events)
for the lexa-openadr VEN; unit-tested, wired into the OpenADR scenarios' follow-up
(the shipped scenarios inject `bus.OpenADR*` docs directly to test hub adoption).

**Bench-runnability**: several scenarios need hub feature flags pre-set on the
deployed hub (`advanced_der`/`reconciler.adv`/`enforce_aus_limits`) or a
launch-time sim mode (`modsim -advanced`, `evsim -proto 1.6`) that a reactive
scenario cannot toggle mid-run. Those scenarios probe the precondition over SSH
and return **INCONCLUSIVE** (never a false PASS) when the feature is off. See the
matrix for per-scenario preconditions.

**Hub observability gaps found (candidates for follow-up)**: `GET /status`
surfaces Exp/Max/Imp/Fixed/Connect limits but not GenLimW/LoadLimW;
`lexa_constraint_shadow_divergence_total` is a single aggregate (no per-constraint
attribution); `lexa_mb_adv_divergences_total` covers only measured axes
(curve-axis divergence routes to `lexa_mb_adv_failed_total`).

---

## Measurement-freshness bench rows (2026-08-04)

`sim/southbound/lying.go` is a separate fault family from everything above: the
LYING SOUTHBOUND DEVICE layer, eight `POST /fault` kinds (`revert_after`,
`freeze_block`, `sentinel_field`, `reboot_forget`, `layout_shift`,
`exception_on_applied_write`, `slow_poll`, `ack_no_apply`) that answer
plausibly and FALSELY rather than erroring — see that file's own doc for the
full rationale. `freeze_block` gained a multi-window/except form, and the solar
sim gained a new non-fault `Night` environmental control, purpose-built to
exercise the hub-side MEAS-FRESHNESS per-class liveness/staleness detector
against a real Modbus sim rather than only unit tests. Four rows, each
runnable against `modsim -advanced` (or any `sim/mbapsdev` advanced instance):

| Row | `POST /fault` (or `/inject`) body | What it proves |
|---|---|---|
| **whole-device freeze** | `{"kind":"freeze_block","models":["701","103"]}` | Naming every model a hub might cross-check in ONE freeze defeats the S3 cross-model liveness probe — the row proving the gateway does not falsely confirm health just because some OTHER register on the device moved. |
| **701-frozen-103-live** | `{"kind":"freeze_block","models":["701"]}` | The control: freezing only 701 leaves 103 live, exactly what the S3 probe is built to catch — a naive single-window freeze IS detectable in one extra read. |
| **partial freeze** | `{"kind":"freeze_block","except":["TmpCab"]}` | The realistic cached-struct fault: the ELECTRICAL block is frozen while a firmware quirk still refreshes a slow-path field (a temperature) from a live sensor task. Defeats a naive whole-block digest (the bytes keep changing, so "did the hash move" says fresh) — the row proving a hub needs a PER-CLASS digest (volatile / slow / accumulator) to still catch the frozen majority. NOTE (2026-08-04 hardware run): `except:["Hz"]` is NOT this row — Hz is in the VOLATILE class, so keeping it alive legitimately keeps the volatile digest moving and the per-class detector correctly stays silent; excepting Hz is a no-suspicion control case, not the detection row. Now genuinely executable end to end (DEF-5, see below) — before the fix, `except:["Hz"]` alone against 701 left the low half of the value indistinguishable from a plain freeze. |
| **becalmed-but-live** | `POST /inject {"Night":1}` — **not a fault** | Drives the sim to night: W/VA/VAr/WAval collapse to a genuine 0 (unlike `Cloud_pct`, which attenuates but never reaches zero) and the Wh accumulator (`M122 ActWh` / 701 `TotWhInj`) stops climbing, while V, Hz and TmpCab's added ambient jitter keep moving. The false-positive control — a gateway must not treat "nothing to report" the same as "stopped answering." |

`freeze_block` also accepts a raw `"windows":[{"addr":...,"count":...}]` list
for a range this sim has no name for, additive with `"models"` and the
original `addr`/`count` — naming none of the three keeps the original
single-default-window behaviour byte-identical. `except` resolves by
CANONICAL field name (`"Hz_701"` and `"Hz"` are the same point for this
purpose), so one exception list applies across every frozen model in a
whole-device freeze, not just whichever one happened to own the literal key.

**DEF-5 (fixed)**: `except` was address-granular — a fields entry names only
ONE register, so a multi-register point had every register past the first
stay in the frozen snapshot. 701's `Hz` is a `Tuint32` (two registers); arming
`except:["Hz"]` freed only the high word, and the low word stayed frozen —
indistinguishable, on the wire, from a plain whole-block freeze with no
`except` at all. Bench-diagnosed on board cc93 (Hz's value word — offset 16; the register-diff evidence cited offset 34, which is `TmpCab` at 47.5 degC, mislabelled as Hz's low
word, moved 475→461 with the fault armed and `except` given). The fix resolves
each matched point's width from its SunSpec type (`sim/southbound/lying.go`'s
`layoutFieldWidth`, reading `lexa-proto/sunspec`'s Layout tables — 32-bit types
are 2 registers, 64-bit are 4) and frees every register of the point, keyed by
the SAME raw fields-entry name used to resolve the address, so two models
naming the same canonical point at different widths (M103's `Hz` is one
register; 701's is two) each free the right count. `TmpCab` and the other
previously-exempted points were never affected — they are all single-register
— which is why the bug went unnoticed until a multi-register point was tried
against real hardware.

Separately, `advMirror701` (the 701 mirror `NewSolarServerAdvanced` runs every
animation tick) now mirrors `TotWhInj`/`TotWhAbs` from the same `ActWh`
accumulator the legacy sim has always animated (`TotWhAbs` stays a truthful 0
— a PV inverter only injects). Before this fix, 701's accumulators were never
written at all: the register slice starts zero-initialised, and 0 is NOT the
Tuint64 not-implemented sentinel, so 701 read them as an IMPLEMENTED
accumulator that never moved — indistinguishable over Modbus from
`freeze_block`, and it left S1 (Δaccumulator vs ∫W dt) unexercisable on the
bench.

**Bench gap 4 (fixed)**: the SAME class of gap existed one model over. Model
103's OWN `WH` accumulator (offsets 22-23, an acc32 distinct from `M122`'s
`ActWh` that feeds the 701 mirror above) was never written by either solar
sim — `WH_SF`'s zero-initialised value is a legal, in-domain scale factor
(0), not a sentinel, so a consumer gating presence on "is the SF valid" saw
an IMPLEMENTED accumulator frozen at 0 forever, which left S1 unexercisable
on the legacy 10x leg specifically (the 701 leg already had a real
accumulator via the fix above). `solarStep` — the animation step shared by
both the plain solar sim and the advanced sim's own M103 block — now mirrors
the same integrated Wh total into 103's `WH`, so the legacy-leg S1 row is now
expressible too, on either sim.

Unit tests, image-level per the existing sim test idiom (through the real
Modbus server handler and/or `advMirror701`/`solarStep` directly):
`sim/southbound/lying_test.go` (`TestFreezeBlock_ModelsFreezesMultipleWindowsAtOnce`,
`TestFreezeBlock_SingleModelLeavesTheOtherModelLive`,
`TestFreezeBlock_ExceptLeavesNamedPointsLive`,
`TestFreezeBlock_ExceptAppliesAcrossEveryFrozenModel` (now mutates and reads
BOTH registers of 701's `Hz`, pinning DEF-5's fix),
`TestFreezeBlock_UnknownModelIsAnError`, `TestFreezeBlock_UnknownExceptFieldIsAnError`,
`TestFreezeBlock_WindowsFreezesAnExplicitRawRange`) and
`sim/southbound/solar_adv_test.go` / `sim/southbound/solar_test.go`
(`TestAdv701AccumulatorsMirrorTheAnimatedWh`,
`TestAdvSolarM103WHAlsoAnimates`, `TestSolarStep_103WHAccumulatorTracksIntegratedEnergy`,
`TestAdv701BecalmedButLiveIsNotIndistinguishableFromFrozen`,
`TestSolarServer_NightInject`, `TestSolarStep_NightCollapsesWWithAnimationStillAlive`).

---

## The battery pack (2026-08-04) — closing the bench's oldest gap

`sim/southbound/battery_pack.go` adds the BATTERY-SHAPED SIMULATOR that
lexa-gw's `docs/known_issues.json` BENCH-000 has recorded as the blocking bench
gap since IW3 and now repeats three times. Both 7xx bench devices are
inverters, and the 704-less shape exists there only as an inverter
(`modsim -der-models legacy`, registered as `inv-legacy`, `der_gen "12x"`), so
until now **nothing on the bench answered as role `battery` at all** — which
left RMD-025 (the shape-aware fail-safe) and RMD-028 (durable cease ownership)
Go-proven and bench-unproven, with six named rows queued behind the gap.

The two modes are named for the fail-safe posture a gateway will independently
MEASURE the shape to have — lexa-gw `internal/topics`'
`FailsafePostureSetpointZero` / `FailsafePostureCease`, the value that rides on
`InventoryRecord.FailsafePosture` — because the shape IS the posture.

| Mode | Model chain | Containment it can execute |
|---|---|---|
| `batsim -pack setpoint-zero` | 1 / 120 / 121 / 103 / 123 / 802 / **701 / 702 / 703 / 704 / 713** | **704 `WSet` = 0** — idle at zero, never leaving service |
| `batsim -pack cease` | 1 / 120 / 121 / 103 / 123 / 802 | **M123 `Conn` = 0** — a physical cease |
| `batsim` (no `-pack`) | unchanged historical demo battery | — |

### Launch lines

```bash
# The 704-CAPABLE pack (setpoint convergence, BENCH-000 rows (h) and
# "setpoint convergence (battery sim mode w/ 704 WSet bridge)").
./bin/batsim -pack setpoint-zero -port 5023 -api-port 6023 -kwh 20 -wmax 5000

# The 704-LESS pack (cease posture, BENCH-000 rows (e)/(f)/(g)/(k)).
./bin/batsim -pack cease -port 5024 -api-port 6024 -kwh 20 -wmax 5000

# The pre-disconnected pack (BENCH-000 row (j)): open at the cabinet BEFORE the
# gateway can dial, so a gateway holding no ownership record must leave it alone.
./bin/batsim -pack cease -port 5024 -api-port 6024 -kwh 20 -wmax 5000 -start-disconnected
```

The board-side half is `/etc/lexa/modbus.json` — the gateway does not sweep, so
an unlisted sim is never dialled. See `scripts/bench/battery-pack-sim.md` for
the device entries, the per-row recipes and the verification commands.

### The WSet bridge

`packBridgeSetpoint` is the exact mirror of `advBridgeCeiling` one axis over:
an **enabled** 704 setpoint is copied into the legacy 123 signed-`WMaxLimPct`
convention the pack's physics already runs on (`hubBatteryW`: negative =
charge, positive = discharge), so the same animation, the same SoC integration
(`animateBattery`/`clampToSoC`) and the same effect-time faults apply to a 704
setpoint as to a legacy dispatch. Bridging rather than re-deriving is what
keeps ONE physics — two derivations would be two chances for `/state` and the
wire to disagree, which is the divergence this simulator exists to make
visible, not to contain.

This is the piece `NewBatteryServerAdvanced` deliberately lacks, and its own
file comment says so: its 704 "is NOT wired to physical effect … a 704 write
still round-trips correctly, it just does not additionally command the pack."
A device that ACKs a setpoint, echoes it back and never moves is not a battery
— it is `ack_no_apply` with no way to turn it off, and every convergence row
run against it would have measured the gateway's handling of a lying device
while believing it measured convergence.

Three deliberate differences from the ceiling bridge, each of them the
battery's nature:

- **Signed.** A ceiling is a magnitude; a setpoint has a direction, and the
  direction is the whole difference between charging and discharging.
- **Honours `WSetMod`.** Watts or percent-of-max both land in the same physical
  quantity; a device understanding one spelling would mis-scale the other by
  `WMax/100` and report a plausible, wrong number.
- **The pack RAMPS** (`packRampFrac`, 34 % of nameplate per 5 s tick).
  A device that jumps is a device that is ALWAYS already converged, and a bench
  made of such devices can never exercise the gateway's
  pending/converged/diverged machinery. **A CONTACTOR IS NOT A RAMP**, though:
  `Conn=0` collapses measured power in the same tick, and on the write itself,
  so a *paused* pack still ceases and a correct cease never looks like a slow
  one inside the gateway's settle window.

### Ratings are real, and the pack honours them

`populate702Pack` writes the storage fork `solar_adv.go`'s `populate702` doc
explicitly defers to a profile like this one: `WChaRteMaxRtg` /
`WDisChaRteMaxRtg` real, **asymmetric**, and **both strictly below the
nameplate** — `packChaRteRatingFrac` 40 % and `packDisChaRteRatingFrac` 90 %,
so on the 5 kW default nameplate the pack is rated **2 000 W charging** and
**4 500 W discharging**.

Below the nameplate matters because `checkSetpointWithinNameplate` runs first:
ratings equal to the nameplate would make the rating bound unreachable and it
would ship untested. ASYMMETRY matters for a second reason, added with IW14-001:
`opModFixedW` is a SIGNED percent, and both the gateway and the referee resolve
it against the rating for the direction commanded (`derbase.fixedWReference` /
`invariant.RefWRteMax` — `WChaRteMaxRtg` negative, `WDisChaRteMaxRtg` positive,
the nameplate only where the device declares neither). With equal ratings every
candidate reference produces the same watts and a reference confusion is
invisible; with these numbers the three are distinguishable — **−60 % → −1 200
W**, **+60 % → +2 700 W**, against the ±3 000 W a nameplate fallback gives.

The pack also CLAMPS its own physical output to those ratings, PER DIRECTION, so
the M702 numbers are a fact about the device rather than a claim in a register:
a commanded discharge past 4 500 W settles at +4 500 W and a commanded charge
past 2 000 W settles at −2 000 W. Every model that carries the rate (M120
`MaxChaRte`/`MaxDisChaRte`, M802 `WChaRteMax`/`WDisChaRteMax`, M702) says the
same number **for its own direction**. The APPARENT-power rate ratings stay at
the not-implemented sentinel, honestly: a `Tuint16` zero would be a positive
declaration that the pack cannot charge or discharge at all.

### Fault rows the pack makes expressible

Both shapes carry the LYING-DEVICE layer (`sim/southbound/lying.go`) that until
now only the solar sims had, with the CONTROL registers named so the write path
is targetable.

| Row | `POST /fault` body | What it proves |
|---|---|---|
| **ACKed setpoint that never latched** | `{"kind":"ack_no_apply","fields":["WSet","WSetEna"]}` | The false-Applied shape on the setpoint axis: the write ACKs, the pack keeps doing exactly what it was doing, and only a gateway that reads back and COMPARES catches it. `setpoint-zero` only. |
| **ACKed cease that never opened** | `{"kind":"ack_no_apply","fields":["Conn"]}` | The same lie on the connect axis, and the direction that matters — a satisfied cease on a DER measurably past the cessation band. Both shapes. |
| **Conn unimplemented** | `{"kind":"sentinel_field","fields":["Conn"],"value":65535}` | BENCH-000 row (g) without a third register image: over Modbus the pack leaves `Conn` at `0xFFFF`, so its connect state can never be proven and admission must refuse it with the typed error. |
| **Stale pack measurement** | `{"kind":"freeze_block","models":["701","103"]}` (or `["103"]`, `["802"]`, `["123"]`, `["704"]`, `["713"]`) | Whole-device freeze on a battery. Every model each shape serves is registered by name, so naming one it does not serve is an arm-time error rather than a freeze covering nothing. |
| **Pack reboot-to-defaults** | `{"kind":"reboot_forget"}` | RMD-025's DER-reboot row: the pack comes back with the contactor CLOSED and no standing dispatch. A gateway treating "the pack is back" as "the pack is still ceased" is running an uncontained battery. |
| **Setpoint silently released** | `{"kind":"revert_after","delay_s":40}` | Acts on 704 `WSetEna` (not `WSet`): the ENABLE is the single register whose silent loss is exactly "the setpoint is no longer in force", and `WSet` is a `Tint32` whose high word alone is a value nobody wrote. |

The effect-time battery faults (`soc_refuse`, `charge_disabled`,
`discharge_disabled`) reach a power commanded through 704 as well, because the
bridge puts both command routes through one `shapeBatteryW`.

**Idle-at-zero needs no fault at all**, deliberately: a pack at 100 % SoC
commanded to charge (or 0 % commanded to discharge) holds a genuine 0 W through
`clampToSoC` and reports `ChaSt` FULL/EMPTY rather than HOLDING — which is how
a hub tells "this pack is refusing" from "this pack is uncommanded".
`becalm`/`Night` is a solar concept (a dark inverter) with no battery analogue
and is deliberately not offered here.

### DEF-5's rule reached one fault further (fixed)

The pack found a real defect in the lying layer. `freeze_block`'s `except`
resolved a named point to its FULL register width (DEF-5); `sentinel_field` and
`ack_no_apply` resolved it to the ONE address `lc.fields` records. That was
invisible while every named point was 16 bits wide and became load-bearing the
moment a device named 704's `WSet`, a `Tint32`: `ack_no_apply` against it
dropped the HIGH word only, so a 4000 W setpoint (high word 0, low word 4000)
**landed in full** — the fault "succeeded" at refusing to change a register
that already held the value being written, the log line announced a swallowed
write, and the device that was supposed to be lying obeyed. `sentinel_field`
carried the mirror-image bug: half-blanking a 32-bit point serves neither the
real value nor the sentinel, but a number no device would ever produce. Both
now share `resolveTargetsLocked`. A RAW `addrs` entry still means exactly one
register — someone who writes an address down said precisely what they meant,
and that is the only way to express "only the low word went bad".

Pinned by `sim/southbound/lying_test.go`
(`TestAckNoApply_DropsEveryRegisterOfAMultiWordPoint`,
`TestSentinelField_BlanksEveryRegisterOfAMultiWordPoint`).

### A pre-existing defect the live smoke found (FIXED — RMD-046, 2026-08-05)

`POST /inject {"WMaxLimPct_pct": N}` — the historical spelling on BOTH the
battery sim and the solar one — used to encode `RawFromScaleSigned(N*100, SF)`
against a scale factor of −2, which is `N x 10000`. The register therefore
**saturated at 32767 for any N above ~3.27**: an injected 80 did not command
80 %, it commanded the saturated word, which `hubBatteryW` read back as
327.67 % of nameplate and `GET /state` reported (dividing by 100 again,
matching the same mistaken convention) as `3.28`. Observed live on a 5 kW
`-pack cease` sim: `{"WMaxLimPct_pct":80,"Ena":1}` produced `M123[0] = 32767`
and a measured power pinned at the pack's declared rate rating — correct
behaviour by the pack, in response to a command nobody meant.

It was left deliberately unfixed for a time because the mistake was
load-bearing elsewhere: `cmd/dashboard/mayhem.go` used
`{"WMaxLimPct_pct":100}` to UNCURTAIL a solar sim and got the effect it wanted
*from* the saturation (327 % of nameplate is not a ceiling), and
`internal/certify/suitemodbusclient/checks_write.go` used
`{"WMaxLimPct_pct":50}` as a workaround-scaled `0.5` — a "50 % curtail" that
had never actually curtailed. `{"WMaxLimPct_pct":0}` (the QA harness's
inter-scenario reset) was unaffected either way: zero encodes to zero
regardless of the multiplier, which is why this survived as long as it did.

**RMD-046 fixed the encoding atomically, everywhere at once**, rather than
compensating for it in callers:

- `sim/southbound/battery.go` and `solar.go`'s `Inject`, case
  `"WMaxLimPct_pct"`, now encode `RawFromScaleSigned(val, SF)` directly — no
  `*100` — and CLAMP `val` to `[0,100]` (the domain the DER model defines for
  WMaxLimPct) rather than let an out-of-range percent encode into a
  representable-but-meaningless raw word. `Snapshot`'s `Controls.WMaxLimPct_pct`
  no longer divides by 100 a second time to compensate.
- `cmd/dashboard/mayhem.go`'s `{"WMaxLimPct_pct":100}` uncurtail calls are
  unaffected in EFFECT (100 now means a true 100.00 % ceiling — genuinely
  uncurtailed at nameplate — rather than an accidental 327.67 %; for a solar
  panel whose available power never exceeds nameplate, "ceiling at or above
  nameplate" behaves identically either way).
- `internal/certify/suitemodbusclient/checks_write.go`'s `divergePct`/
  `restorePct` are back to plain `50`/`100` (see that file's comment and
  `internal/certify/suitemodbusclient/writelever_test.go`, which pins both the
  fixed encoding and the historical saturated one as a regression guard).
- `qa/scenarios/solar-reboot-forget.json`'s tick-25 `{"WMaxLimPct_pct":100}`
  needed NO numeric change: its hypothesis was always "the inverter reboots
  and comes back at 100 % WMaxLimPct" — a literal 100 now delivers exactly
  that (true, uncurtailed 100 % of nameplate) instead of accidentally
  delivering 327.67 %, and the scenario's export-cap breach still triggers
  identically. Its stale `ENCODING CAVEAT` note has been removed.

A pack additionally offers `{"CommandedW_W": <signed watts>}`, which writes
704 `WSet` on the setpoint shape and the correctly-encoded M123 dispatch on
the cease shape — this remains the right lever for a SIGNED (charge/discharge)
dispatch, since `WMaxLimPct_pct` is clamped unsigned `[0,100]` and cannot
express a charge direction. Pinned, including the (now-fixed) encoding and the
clamp, by `TestPackCommandedWInjectWorksOnBothShapes` in
`sim/southbound/battery_pack_test.go`.

New API-level round-trip regression tests (`sim/southbound/battery_test.go`,
`solar_test.go`): `50 → raw 5000 → Snapshot 50.00%`, `100 → raw 10000 →
Snapshot 100.00%`, and an out-of-range guard (`150 → raw 10000 (clamped)`,
`-40 → raw 0 (clamped)`).

### Ground truth

`GET /state` grows a `"pack"` object on a `-pack` sim (omitted entirely
otherwise, so the historical document is byte-identical): shape, the posture
the gateway should measure, `connected`, `commanded_W` vs `measured_W` with the
`ramp_W_per_tick` bound between them, the declared rate ratings, the raw 704
setpoint, the 701 mirror, and the lie counters. `POST /inject` additionally
accepts `{"CommandedW_W":-3000}` on either shape and `{"WSet_W":-3000}` /
`{"WSetEna":0}` on the setpoint shape, each refused BY NAME on a shape that
cannot express it.

Unit tests: `sim/southbound/battery_pack_test.go` — the model chains and the
admission facts each one presents, WSet convergence in both signs with SoC
integrating the right way, `WSetMod` honoured, the idle-pack-commanded-discharge
row that diverges until the animation moves, the rate-rating clamp,
cease/reconnect physical effect on both shapes (including the 701 `St`/`ConnSt`
half of the two-sided proof), full/empty idle, the fault rows above, and a pin
that the historical battery images grew no pack surface.

## IW15-001 / IW15-002 — the solar setpoint, and settings vs ratings (2026-08-14)

Two defects the sims used to make untestable, closed together on the southbound
side.

### IW15-001 — the solar 704 `WSet` reached nothing

`advBridgeCeiling` mirrored the **ceiling** (`WMaxLimPct`) into the legacy 123
curtailment machinery and nothing anywhere read `WSet`. The register bank
accepted, stored and echoed a solar setpoint write perfectly — and the machine
ignored it. That is the `ack_no_apply` fault, permanently armed, with no way to
disarm it, on the axis every `opModFixedW` row is written against.

Closed by making the setpoint a **third, independent term** of the physical
step:

```
output = min(available, ceiling, setpoint)          # solar.go, solarStep
```

It is deliberately **not folded** into the M123 ceiling cell the way the battery
pack's `packBridgeSetpoint` folds (a pack's one physics *is* the signed-percent
dispatch, so the fold is lossless there). Folding here would erase the only
evidence a *"a limit is not a setpoint"* negative row has: `/state`'s
`WMaxLimPct_pct` and the 123/704 register dump. `advBridgeSetpoint` makes the
effect prompt (a downward clip of M103 `W` on the write itself, via the new
`OnWrite` hook and `advSync`), and `powerOnReset` now clears `WSetEna`/`WSet`/
`WSetPct` so `reboot_forget` cannot leave a live setpoint standing.

**`WSetMod`'s default is `MaxPct` (raw 0).** A head end that writes `WSet`
(watts) without also writing `WSetMod` has therefore commanded a **percent** —
of a `WSetPct` register it never wrote, i.e. zero output. The sim reads the wire
honestly and does not guess, so an oracle cannot be fooled by a fixture that is
kinder than a real device (`TestSolarSetpointWSetModDefaultIsPercent`).

### IW15-002 — ratings were settings

Every physics path read a Go float captured at construction, so a `WMax` or
`WChaRteMax` written over Modbus was **cosmetic**. Both sims now resolve their
percent-of-max reference live:

```
702 WMax  →  121 WMax  →  the construction nameplate      (solarWMaxRefW)
702 WChaRteMax / WDisChaRteMax  →  the construction floats (packProfile.rateLimits)
```

A not-implemented point (0xFFFF) falls through to the next source; an
implemented **zero** is honoured, because "this pack may not charge" is a thing
a configured device says. Ratings (120 `WRtg`, 702 `WMaxRtg`, 702 `…Rtg`) are
**declarations** and no physics reads them — which is what makes a
rating/setting divergence stageable at all.

### Inject keys (bench runbook)

Solar (`modsim`), on top of the existing keys:

| Key | Model(s) written | Effect |
|---|---|---|
| `WMax_W` | 121 `WMax` **+** 702 `WMax` (advanced) | **physics** — the reference every percent resolves against |
| `M121_WMax_W` | 121 `WMax` only | the cross-model divergence lever; on a legacy sim, the only `WMax` there is |
| `WMaxRtg_W` | 120 `WRtg` **+** 702 `WMaxRtg` (advanced) | declaration only (the panel is fixed at `-wmax`) |
| `WChaRteMax_W`, `WDisChaRteMax_W` | 702 settings | declaration only **on solar** (PV models no rate physics) |
| `WChaRteMaxRtg_W`, `WDisChaRteMaxRtg_W` | 702 ratings | declaration only |

Battery pack (`batsim -pack setpoint`), on top of the existing keys:

| Key | Model(s) written | Effect |
|---|---|---|
| `WChaRteMax_W`, `WDisChaRteMax_W` | 702 settings | **physics** — `clampToRateRating` reads them live |
| `WChaRteMaxRtg_W`, `WDisChaRteMaxRtg_W` | 702 ratings **+** the 120 `MaxChaRte`/`MaxDisChaRte` mirror | declaration only |
| `WMax_W`, `WMaxRtg_W` | 702 | declaration only |

Model 802's `WChaRteMax`/`WDisChaRteMax` pair stays where `populateBatteryPack`
seeded it, deliberately: freezing it makes *"the 702 setting moved and the
storage model did not"* an injectable cross-model divergence with a name rather
than an invisible coupling.

Every 702-only key is **refused by name** on a sim that serves no 702 (a legacy
inverter, the cease-shape pack). `modsim -wmax-setting N` stages the divergence
**before the gateway's first read** — same effect as `{"WMax_W":N}`, but in
place at adoption.

### Ground truth for both

`GET /state` (solar) grows `nameplate.m120_WRtg_W`, `nameplate.m121_WMax_W` and
`nameplate.pct_reference_W` (the number the device's own percents resolve
against — the referee), plus `advanced.wset_704` (`ena`, `wset_mod`, `wset_W`,
`wset_pct`, `effective_W`) and `advanced.capacity_702`. The pack's `"pack"`
object grows `w_cha_rte_max_rtg_W` / `w_discha_rte_max_rtg_W` beside the
existing `w_cha_rte_max_W` / `w_discha_rte_max_W`, which now report the setting
being **honoured** rather than the construction float.

Unit tests: `sim/southbound/solar_adv_test.go` (three-way min incl. the
anti-fold pin, `WSetMod` default, write-time coherence, power-on reset, the
702 setting moving real watts, sentinel fallback), `solar_test.go` (the legacy
120/121 split — a 50 % ceiling against a 4000 W setting on an 8000 W panel is
2000 W, and the key-vs-model refusals), `battery_pack_test.go` (the live rate
setting, the rating mirror, sentinel fallback, refusal without a 702).

## Explicit-null DERControlBase elements (2026-08-16) — RC0 §9.5 row 9

### The gap

RC0 §9.5's bench battery, row 9, grades what the gateway does when a head end
**releases** an axis by sending the element **present and explicitly null**
rather than by leaving it out:

> Release: explicit-null `volt_var` ⇒ `ModEna` = 0, `ActCrv` untouched;
> explicit-null `freq_watt` ⇒ no write at all.

It was recorded **SKIP — structurally unavailable on this harness**. Every
release gridsim could author was an *absence* (omit the field) or a
*cancellation* (`current_status: 6`, `DELETE /admin/control`,
`POST /admin/default {"clear":true}`), and those are exactly the conditions the
row exists to distinguish an explicit null **from**. A skip recorded for a
harness limitation reads, in a bundle, like a skip recorded for a product one.

`POST /admin/control` now takes a `null_axes` list. It is off by default: a
request that does not name it serves byte-for-byte what it always did.

### Author a release

```bash
# Explicit-null volt-var. activate:true replaces the program's control list, so
# this control IS the release — nothing else is commanded.
curl -X POST 127.0.0.1:11113/admin/control -d '{
  "program": 0, "activate": true, "mrid": "REL-VV-1",
  "null_axes": ["opModVoltVar"]
}'

# Explicit-null frequency-watt.
curl -X POST 127.0.0.1:11113/admin/control -d '{
  "program": 0, "activate": true, "mrid": "REL-FW-1",
  "null_axes": ["opModFreqWatt"]
}'

# Both axes on one control, and other axes still commanded by value — the
# three-way document the row needs: valued, explicitly null, and omitted.
curl -X POST 127.0.0.1:11113/admin/control -d '{
  "program": 0, "activate": true, "mrid": "REL-BOTH-1",
  "connect": true, "max_lim_W": 5000,
  "null_axes": ["opModVoltVar", "opModFreqWatt"]
}'
```

What `GET /derp/0/derc` then serves for the last one — note the markers in
**their own sequence positions**, not appended at the end:

```xml
<DERControlBase>
  <opModConnect>true</opModConnect>
  <opModFreqWatt xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:nil="true"/>
  <opModMaxLimW>5000</opModMaxLimW>
  <opModVoltVar xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:nil="true"/>
</DERControlBase>
```

The full row-9 procedure is: `POST /admin/curve` to arm the volt-var curve, let
the gateway adopt it, then `POST /admin/control` with `activate: true` and
`null_axes` to release it. The marker lands on `/derp/{p}/derc` **and**
`/derp/{p}/actderc`.

### Vocabulary, and what is refused

The axis names are `csipmodel`'s own **element names** — `opModVoltVar`,
`opModFreqWatt`, `opModConnect`, … — read off the model by reflection, so the
list cannot drift from what the server can actually emit. Curve-mode spellings
(`volt_var`) are **not** accepted. The endpoint answers 400, before storing
anything, to:

* an axis no `DERControlBase` declares (a typo would otherwise be served as
  silence, and the release simply would not happen);
* the same axis twice;
* an axis that the same request also gives a value (`{"connect": true,
  "null_axes": ["opModConnect"]}`) — one element cannot be both
  present-with-a-value and present-and-nil;
* `null_axes` on `POST /admin/default`, which shares the request struct: a
  `DefaultDERControl` is not an event and has no release to grade, so the lever
  is refused there rather than accepted and ignored.

### Teardown

`DELETE /admin/control`, `DELETE /admin/curve`, and any later `POST` that
replaces or re-posts the control all drop the marker. Nothing has to be cleared
by hand, and a marker cannot outlive its control into a later run's document.

### What this does NOT claim

**IEEE Std 2030.5-2018 says nothing about explicit nil.** It declares every
`DERControlBase` element `[0..1]` (p.248–251) and stops there; the words
"nillable", "xsi:nil" and "null" do not occur in the document, and the only use
of the XML Schema Instance namespace anywhere in the standard is `xsi:type`
(§4.7 resource design rules, p.24; Annex C example, p.278). `xsi:nil` is a W3C
XML Schema facility, available to elements a schema declares
`nillable="true"` — a question about a schema document, not about the standard.

So this lever does not make gridsim "more conformant", and a DUT that ignores
the marker is not thereby non-conformant under 2030.5-2018. What it does is let
the bench **present** a document whose distinction the *product* claims to act
on, so that claim can be graded against bytes instead of against a skip.
Anything written into a bundle from this lever must say the same thing. The
guarantee the harness gives is well-formedness and sequence position, which the
tests in `sim/gridsim/explicitnil_test.go` assert, and nothing more.

Mechanism and adjudication: `sim/gridsim/explicitnil.go`.
