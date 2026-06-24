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

- **`crc_error`, `tcp_drop`** — need wire-level injection (toxiproxy / `tc netem`); not in-sim.
- **MQTT chaos (Phase 4)** — broker (mosquitto) is bound to localhost on hub-pi, unreachable
  from the desktop. Needs an on-hub injector or a broker rebind.

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
