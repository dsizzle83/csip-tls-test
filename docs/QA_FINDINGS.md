# Mayhem QA — Findings & Mitigation Runbook

**Last updated:** 2026-06-24
**Status:** Hostile-QA build COMPLETE (38 scenarios) and **mitigation underway**. Full
suite was run against the live hub (10 FAIL / 2 BLIND / 12 DEGRADED / 14 PASS), the
hardening commit `9d14747` was deployed, and **7 of the 9 deployed-HEAD FAILs now have
fixes** in `~/projects/lexa-hub` (closed-loop convergence, CSIP fail-closed, telemetry
plausibility, battery reserve safety). See **`QA_TRIAGE_20260624.md`** for the per-finding
root cause, the deploy-vs-fix split, and the implementation log (§6) — that is the current
source of truth; the catalogue below is the original strategy reference.

The 2 remaining BLINDs (`stale-meter`, `ev-meter-freeze`) are diagnoser/environment-limited
(safe today) — see `QA_TRIAGE_20260624.md` for why, and the production heartbeat fix.

> Companions: `QA_TRIAGE_20260624.md` (current triage + fix log), `QA_FAULT_INJECTION.md`
> (original strategy/plan), `HARNESS_REVIEW.md` (2026-06 audit), `BENCH.md` (topology/IPs/SSH),
> `REPLAY_RUNBOOK.md` (HIL driver).
> The engine is `cmd/dashboard/mayhem.go`; the headless runner is `scripts/mayhem.py`.

---

## 0. TL;DR for next session

1. **Bring the bench up** (desktop services are NOT boot-persistent):
   ```bash
   bash scripts/bench-up.sh --fast        # restores LAN IP, starts gridsim+dashboard, sets hub fast timing, verifies all nodes
   ```
   The Pis (hub .1, sims .10–.14) auto-start via linger and survive a desktop reboot;
   only gridsim + dashboard (desktop, :11111/11112 + :8080) need restarting.
2. **Run the full suite** (≈ 35–45 min for all 38; the engine restores the bench on finish/abort):
   ```bash
   python3 scripts/mayhem.py --dashboard http://localhost:8080            # all scenarios
   python3 scripts/mayhem.py --dashboard http://localhost:8080 --only <id,id>   # a subset
   python3 scripts/mayhem.py --list                                       # scenario IDs
   ```
   Exit code is non-zero on any FAIL/BLIND. Full markdown report lands as
   `qa-mayhem-<ts>.md` on the dashboard host (gitignored).
3. **Triage** against §2 below, then fix in lexa-hub. The fixes are in the *product*
   repo, not here. Re-run the relevant `--only <id>` after each fix to confirm.

**Bench must be in FAST mode for these verdicts to reproduce** (engine 3 s / discovery 5 s).
Several scenarios depend on that timing (e.g. the malform cap-drop lands ~22 s after the
malform = ~t=30). `bench-up.sh --fast` sets it; `bench-up.sh --stock` restores demo timing.

---

## 1. Verdict taxonomy

`PASS` contained/converged safely · `DEGRADED` safe but not seamless (e.g. admitted
CannotComply, or transiently breached then recovered) · `FAIL` unsafe / acted on garbage /
lost a safety control · `BLIND` stayed safe but cannot see the fault (a latent hazard) ·
`INCONCLUSIVE` couldn't judge (re-run).

A cross-cutting `safetyAudit` (INV-SOC / INV-EXPIRED / INV-EVMAX / INV-CONNECT) runs on
**every** scenario regardless of its own diagnoser.

---

## 2. FINDINGS — what to mitigate (hub work, in lexa-hub)

Ordered by severity. Each names the scenario(s), the observable, and where to look.

### FAIL — real defects (fix these first)

- **`battery-charge-disabled` — no closed-loop verification / lever fallback.**
  Under a 0-export cap at full sun the hub commands the battery to absorb the excess; when
  the pack silently refuses the charge, the hub neither falls back to curtailing the inverter
  nor posts CannotComply — it exports ~4400 W over the cap for the whole window with an empty
  plan log. (The battery-*full* variant `export-cap-full-battery` passes by curtailing solar,
  which isolates the gap.)
  → **Fix:** orchestrator must verify measured battery power vs the commanded charge and, on
  no-absorb, escalate to PV curtailment (or CannotComply). This is the same class as the
  closed-loop gap behind `ack-before-effect`/`reject-write-curtail`.

- **`malform-empty-program` + `malform-huge-activepower` — fails OPEN on malformed CSIP.**
  When gridsim serves an empty DERProgramList, or a DERControl with an absurd ActivePower
  (32767×10⁹ W, overflow bait), the hub **permanently drops/corrupts the active export cap**
  and exports 4400–9400 W over it for the rest of the window. ~22 s after the bad resource
  starts (≈ t=30) the hub stops holding last-known-good and lets the cap lapse.
  → **Fix:** northbound walker/parser must **fail closed to last-known-good controls** on a
  malformed/empty resource, and bound/validate control limits (reject overflow) before adopting.

- **`solar-bad-scale` — no nameplate sanity-check on SunSpec power.**
  A corrupted W_SF scale-factor register makes the hub read ~10× (48 kW for a 4.8 kW inverter).
  The hub ingests it (33/35 samples). Verified manually: sim `/state` = 2218 W while hub
  `/status` = 43600 W.
  → **Fix:** `internal/southbound/sunspec` (lexa-modbus) must clamp/flag decoded power against
  the inverter nameplate. This is the GS-1/MTR-1 audit hazard. **Lockstep:** the SunSpec
  register maps are mirrored in both repos — any decode change ships in both.

- **`ev-wrong-units` — no MeterValues validation vs station rating.**
  The charger reports current in mA under an "A" label (≈1000×); the hub surfaces 6000 A
  against a 32 A station max on 31/40 samples (the safety audit independently flags INV-EVMAX).
  → **Fix:** lexa-ocpp must validate MeterValues against the EVSE rated max (and unit) and
  clamp/reject implausible readings before use.

### BLIND — safe now, latent hazard

- **`ev-meter-freeze` — no stale-telemetry flag on the OCPP channel.**
  The charger keeps drawing but stops MeterValues; the hub holds the import cap off the *grid
  meter* (good) but reports the EVSE at 0 W while it truly draws ~1380 W. It would miss the car
  ramping back up.
  → **Fix:** track MeterValues freshness per EVSE; stale-expire a silent charger and surface it.

### DEGRADED — safe but worth hardening

- **`malform-pagination` + `pricing-attack` + `curve-attack` — transient cap drop on a
  walk-breaking malform.** A malformed leaf resource (lying pagination, bad price multiplier,
  empty curve list) briefly unseats the export cap mid-walk, then the hub re-establishes it
  from last-known-good. Recovers, but not seamlessly.
  → **Fix:** isolate optional/leaf-resource discovery so a bad leaf can't perturb an already-
  adopted safety control. (Note: the hub does **not** consume CSIP prices/curves today —
  lexa-northbound discovers tariffs but never walks ConsumptionTariffInterval — so the price
  "attack" has no *intended* effect; the transient drop is a discovery-robustness issue.)

- **`ev-accept-but-ignore` + `ev-min-current-floor` — admits CannotComply instead of pausing
  the EV.** With the EV as the only lever, the hub correctly posts CannotComply rather than
  suspending the transaction to reach 0 A. Acceptable, but pausing the session would actually
  comply.
  → **Fix (optional):** when EV modulation can't satisfy the cap, suspend the transaction
  (RequestStopTransaction) before admitting CannotComply.

### PASS — confirmed good (regression guards; no action)

Transport sentinel + exception + latency (`nan-sentinel`, `modbus-exception`, `modbus-latency`,
`battery-nan-sentinel`) are handled (0x8000→N/A, exception→device-down, slow read bounded).
`battery-reboot`, `solar-reboot-forget` (hub re-asserts the limit every cycle), `expired-control`
(releases at validUntil+grace), `ev-connector-flap`, `ev-delayed-obey` (tolerates a 20 s lag and
converges), and the structural malforms `malformed-csip` (dup mRID) / `malform-missing-href` /
`malform-bad-duration` all PASS.

---

## 3. Harness notes / gotchas (so you trust the verdicts)

- **`diagnoseMalform` CannotComply rule (fixed 2026-06-24):** for an EXPORT cap the hub can
  always curtail PV, so a CannotComply does **not** excuse an export breach (it does for import
  caps, where an empty battery is a real limit). The verdict is tail-based: sustained-to-end =
  FAIL, recovered-by-tail = DEGRADED. This fix **unmasked** the malform FAIL/DEGRADED findings
  that a blanket ReportedCannot excuse had been hiding — earlier "PASS" verdicts on those were
  false.
- **Battery SoC < 10% reserve floor in setup → spurious INV-SOC noise.** Don't inject SoC ≤ 10%
  unless the scenario is about the reserve floor; a transient discharge there trips the safety
  audit incidentally. Use ≥ 12% for a "near-empty non-lever" (see `ev-delayed-obey`).
- **CannotComply dominates EV-only-lever scenarios.** With an empty battery + tight cap the hub
  admits CannotComply, which is the diagnoser's DEGRADED path — it can mask the *specific*
  behaviour under test. Make the cap satisfiable when you want to test convergence (see the
  `ev-delayed-obey` 2000 W cap above the EV's 6 A floor).
- **`bad_scale` preserves ground truth:** it corrupts W_SF only on the Modbus READ path
  (`RegisterMap.OnRead` now gets the start address); the sim's `/state` (direct register read)
  stays correct, so hub-vs-truth divergence is observable.
- HIL timing isn't perfectly deterministic; a 1-sample breach at the deadline boundary is noise.
  Lengthen the hold (malform scenarios use 75 s) rather than trusting a single marginal sample.

---

## 4. Out of scope / can't run here

- ~~**`crc_error`, `tcp_drop`** — need wire-level injection (toxiproxy / `tc netem`); not in-sim.~~
  **Closed by TASK-052 (GAP-11):** `scripts/netem.sh` + `mayhem_world.go`'s
  `netemModifier`/`netem-*` scenarios now apply real `tc netem` loss/reorder/delay/jitter
  to a bench Pi's LAN interface over SSH — see §4a below.
- **MQTT chaos (Phase 4)** — broker (mosquitto) is bound to localhost on hub-pi, unreachable
  from the desktop. Needs an on-hub injector or a broker rebind.

### 4a. netem packet-chaos (TASK-052 / GAP-11) — code complete, bench validation pending

Three curated scenarios added to `mayhem_world.go` (`worldScenarios()`), the first Mayhem
faults to touch the actual wire rather than only the application layer:

- **`netem-loss-export-cap`** — 5% loss + 50±10ms delay on the hub's bench-LAN iface
  (degrades hub↔sims Modbus/OCPP AND hub↔gridsim northbound at once — the hub has one
  LAN iface). Judges: zero-export cap holds (`diagnoseConstraint`), INV-HUNT clean.
- **`netem-reorder-northbound`** — 25% reorder + 100ms delay on the hub's iface (utility
  link chaos) under an active generation limit. Judges survivability
  (`diagnoseSurvival("packet reorder")`) — the walker/fetcher's SO_RCVTIMEO + fail-closed
  hold must ride out reordering/latency the same way it does an outright outage.
- **`netem-jitter-evse`** — delay jitter (80±40ms, normal distribution) on the ev-pi's
  link during an active EV import cap. Judges the import cap (`diagnoseConstraint`);
  INV-EVMAX is checked for every scenario by the cross-cutting safety audit regardless.

All three are INCONCLUSIVE without SSH + passwordless sudo on the target node (only the
hub is guaranteed to have passwordless sudo — see BENCH.md) and self-check that netem
actually landed on the real bench-LAN iface (ping-RTT delta) before trusting a profile —
see BENCH.md's "netem packet-chaos harness" section for the dual-homed-Pi / desktop-guard
detail (FIX-H). Landed as harness code + `go build`/`go vet`/unit-test evidence only
(qdisc-command builders, iface-discovery parsing, self-check verdict logic, desktop
refusal, all unit-tested in `cmd/dashboard/mayhem_world_test.go`) — 10× solo per scenario,
abort/self-heal proof, and a full campaign against the live bench are the next batched
wave-gate item (a bench agent had the bench mid-campaign when this was authored).

### 4b. Hub-local clock step (TASK-038 / GAP-04) — code complete, bench validation pending

Two curated scenarios added to `mayhem_world.go` (`worldScenarios()`): `local-clock-step-forward`
and `local-clock-step-back`. Every prior clock scenario (`clock-jitter`, `clock-jump-forward`)
steps the *server's* clock via gridsim `/admin/clock`; these are the first to step the **hub
Pi's own wall clock** ±1 h mid-control over SSH (`timedatectl set-ntp false` + `date -s
"$(date -d '<N> seconds')"`), the first thing NTP does to a field unit after commissioning.

They validate TASK-037's monotonic clock anchoring (freshness/expiry anchored at
`onCSIPControl` arrival, not wall-clock deltas): the hypothesis is that a local step must not
expire/hold-forever the active control, must not flap enforcement, and must not mass-expire
device telemetry — judged with `diagnoseSurvival("the local clock step")` (cap held throughout)
plus the standard cross-cutting `safetyAudit` invariants (INV-EXPIRED is grace-bounded and
applies automatically). **Against a pre-037 hub this is an expected-FAIL that pins the gap**
(the `meter-ct-inverted` precedent, 06 §2) — state which case applies in the PR/campaign
report once run.

Both scenarios probe SSH availability first (`d.hubSSH("true")`, identical to
`hub-restart-mid-cap`/`disk-full`) — INCONCLUSIVE, never a fake verdict, without key auth.
Teardown (`hubClockStepTeardown`) is unconditional and abort-safe by design: rather than
"subtract what the perTick step added" (wrong if a run aborts before or after that step ever
runs), it re-enables NTP and then reads the hub's *actual* current clock, correcting it
absolutely (`date -s @<desktop-unix>`) if it drifted more than 120 s from the (untouched)
desktop clock — correct at every abort point, not just a clean finish.

Landed as harness code + `go build`/`go vet`/unit-test evidence only (NTP-toggle and
clock-step command builders, the absolute-correction command, and the teardown drift-check's
decision logic `hubClockDriftOK` are all pure-function unit-tested in
`cmd/dashboard/mayhem_world_test.go`, plus a scenario-catalogue test locking both IDs present
and every stage wired) — 10× solo per scenario (stability gate, 06 §2), an abort-mid-step
clock-restore proof, and the scenarios' first live campaign run are the next batched wave-gate
item (a soak had the bench mid-run when this was authored).

---

## 5. Bench / deploy state (as of 2026-06-24)

- Desktop (69.0.0.20): gridsim (`bin/server`, :11111/11112) + dashboard (`bin/dashboard`, :8080)
  as `systemctl --user` units (`csip-gridsim`, `csip-dashboard`) — NOT boot-persistent.
- Pis run the latest sim binaries: **modsim/.10** and **evsim/.14** were redeployed this session
  (new `bad_scale` / `apply_delayed` / `wrong_units` kinds); **batsim/.11** earlier (directional
  + transport faults). Deploy one sim manually by scp-ing `bin/arm64/<sim>` over the unit's
  ExecStart path and `systemctl --user restart <sim>` (see the bench-deploy skill), or all via
  `bash scripts/update-sim-pis.sh 69.0.0.1 dmitri` (needs `bin/arm64/*` prebuilt).
- Hub in **fast** replay timing. CSIP control back to `default`, gridsim clock offset 0.
- All work committed + pushed on branch `lexa-hub` (commits `8b477b7`..`a77e27b`).

---

## 6. STOCK M0 baseline findings (2026-07-05, TASK-015)

First campaign run in STOCK bench timing (engine 15 s / discovery 20 s / poll 10 s) —
see `docs/QA_REPORT_STOCK_M0_20260705.md` for the full triage. 0.8 FAIL/cycle, 0 BLIND,
0 safety-invariant escalations over 5 cycles / 255 scenario-runs. Two new findings filed
below; the other two non-PASS singletons (`perfect-storm`, `meter-ct-inverted`) are
pre-existing documented gaps needing no new entry (see the report's disposition table).

- **`QA-STOCK-001` — `malform-huge-activepower` FAIL recurrence at STOCK cadence
  (1/5 cycles).** Same fail-open signature as the pre-2026-06-24 bug this scenario's fix
  closed (northbound walker fails open on the overflow-bait DERControl, dropping the safe
  export cap; INV-EXPORT breached 46 samples, t=30-76s, cycle 1). 4/5 STOCK cycles were
  clean and the fix itself (fail-closed to last-known-good) is not supposed to be
  cadence-dependent, so this is filed as a **hypothesis to confirm**, not a confirmed
  regression: STOCK's 20 s discovery walk (vs. FAST's 5 s) means less last-known-good
  history has accumulated by the time the malform lands at its fixed scenario-relative
  offset, occasionally catching the walker before a fallback control exists to hold.
  → **Fix/next step:** journal forensics on a reproduction (`--only
  malform-huge-activepower` under STOCK, repeated) to confirm/refute the discovery-cadence
  hypothesis; if confirmed, the fail-closed guard needs to seed a synthetic
  last-known-good (or hold the *previous* program's default) during the walker's initial
  discovery window, not only after a first successful walk. Evidence:
  `logs/campaign-stock-20260704T224628/cycle-01.json`.
  Priority: low (1/5, no safety escalation, product build unchanged from the
  already-fixed 2026-06/07-01 state) — track, don't block M0.

- **`QA-STOCK-002` — `clock-jitter` convergence margin tight at STOCK cadence (1/5
  cycles).** The FAST-mode fix (default-fallback clock-regression guard +
  7 s-jitter-cycle deliberately coprime with FAST's 5 s walk period, `HoldS 35→45`)
  encodes FAST-cadence timing relationships explicitly. Under STOCK's 20 s discovery
  walk that coprimality no longer applies, and cycle 2 shows the hub genuinely still
  converging (43.42 s) inside the 45 s window when the sample was taken, with a 41 s
  overshoot in the interim and no CannotComply posted while catching up.
  → **Fix/next step:** recompute the STOCK-cadence-correct `HoldS`/jitter-cycle
  parameters from tick counts (per 06 §4.5 — no oracle weakening without a physical
  tick-count justification written into the scenario's `Fix` text); do not touch the
  margin without that derivation. Evidence:
  `logs/campaign-stock-20260704T224628/cycle-02.json`.
  Priority: low (1/5, converges within window most of the time, no safety escalation)
  — track, don't block M0.

---

## 7. Guard-threshold dither sweeps (GAP-08, TASK-054) — code complete, bench validation pending

Added `export-dither-at-breach` (metered export ±ε across `cap+complianceBreachW`,
~100 W) and `soc-dither-at-reserve` (battery SoC ±1 pt across `SOCReserve`, 20%) —
`cmd/dashboard/mayhem_world.go` — to sweep the belief that the product's leaky breach
counters (`expOverTicks`, `genGuard.overCount`) and the reserve guard
(`dischargingAtReserve`) are hold-biased at the exact decision line, not just under
sustained excursions. Both are **EXTENDED-SET** (`HoldS ≈ 300 s`, `mayScenario.Extended`)
and excluded from a default/full run (RSK-12) — run via `--only
export-dither-at-breach,soc-dither-at-reserve` or `--extended` for nightly / release-gate
campaigns; `--list` tags them `[extended]`.

New oracle logic: `diagnoseExportDither` (CannotComply must be FALSE for a pure dither
that never sustains past `exportBreachTicks`; a boundary-dither scenario FAILs on
INV-HUNT rather than the generic audit's DEGRADED demotion) and `diagnoseSocDither`
(`socReserveOverDischarge` — a scenario-local 20%-line predicate, deliberately separate
from `invariants.go`'s `invSOC`/10% harness floor — plus `batteryCommandFlaps` command-
chatter detection against `expectedDitherTransitions`). All pure-function logic is unit
tested in `cmd/dashboard/mayhem_dither_test.go` (cadence helper, selection/filtering,
both diagnosers' verdict ladders) — `go test ./cmd/dashboard/...` green.

**Status: CODE COMPLETE, NOT YET BENCH-VALIDATED.** This was implemented in a code-only
session (a separate bench-owning session held the live bench mid-task — TASK-032) per
the task's launch instructions; the following are deferred to a later batched HIL
session:

- 10× solo runs of each scenario against the live bench (stability check).
- Empirical tuning of `exportDitherLoadDeltaW` (currently 150 W, a starting point per
  the task's sizing guidance) against the real curtailment response — confirm the
  low-load phase's residual export sits just over `cap+complianceBreachW` and the
  high-load phase comfortably under it, both inside the 300 W INV-HUNT hysteresis.
- The **control run** proving the CannotComply biconditional's other half: temporarily
  widen the dither (larger `exportDitherLoadDeltaW`, or hold one phase past
  `scaleTicks(exportBreachTicks)`) so the over-band phase sustains, run `--only
  export-dither-at-breach` once, confirm CannotComply DOES post, then revert — not a
  committed variant.
- A full extended-set campaign including both scenarios, verdicts recorded here.

Branch: `task/054-dither` (csip-tls-test), not yet merged.
