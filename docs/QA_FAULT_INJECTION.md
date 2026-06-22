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
`wrong_sign`, `soc_refuse` (battery). **OCPP (CSMS/charger boundary):**
`profile_reject`, `apply_next_tx`, `min_current_floor`, `stop_metervalues` (evsim).
**Grid safety:** `disconnect` (gridsim opModConnect=false). **Malformed CSIP**
(gridsim `POST /admin/malform`, applied at serve time): `empty_program_list`,
`huge_activepower`, `bad_duration`, `dup_mrid`, `missing_href`.

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
