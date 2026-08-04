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
| **partial freeze** | `{"kind":"freeze_block","except":["Hz","TmpCab"]}` (or `except:["Hz"]` alone against a whole-device freeze) | The realistic cached-struct fault: most of the block is frozen, but a firmware quirk still refreshes a couple of fields (a frequency counter, a temperature) from a live path. Defeats a naive whole-block digest (the bytes keep changing, so "did the hash move" says fresh) — the row proving a hub needs a PER-CLASS digest (volatile / slow / accumulator) to still catch the frozen majority. Now genuinely executable end to end (DEF-5, see below) — before the fix, `except:["Hz"]` alone against 701 left the low half of the value indistinguishable from a plain freeze. |
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
`except` at all. Bench-diagnosed on board cc93 (register offset 34, `Hz`'s low
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
