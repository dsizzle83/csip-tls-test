# TASK-038 — Mayhem: local (hub Pi) clock-step scenario

*Status: CODE COMPLETE (2026-07-06, csip-tls-test `task/038-clock-step`, unmerged) —
bench validation (10× solo per scenario, abort/self-heal proof, campaign inclusion)
deferred to the next batched wave gate (a soak had the live bench mid-run when this
was implemented, per the launch instruction) · Phase: P3 · Effort: M (≈4–6 h) ·
Difficulty: med · Risk: low*

## Objective
Add two Mayhem scenarios — `local-clock-step-forward` and
`local-clock-step-back` — that step the **hub Pi's own wall clock** ±1 h in
the middle of an active export cap via SSH (`timedatectl`/`date -s`),
assert the control is held without flapping and freshness gating recovers,
and restore NTP in teardown unconditionally. Verdicts must be stable 10×
solo before the scenarios join the curated suite.

## Background
Repo `~/projects/csip-tls-test`. The Mayhem engine lives in
`cmd/dashboard/mayhem.go` (3,123 lines): scenarios are `mayScenario` structs
(`{ID, Name, Category, Hypothesis, Expected, HoldS, Fix, setup, perTick,
evaluate, teardown}`, mayhem.go:189–202) returned by
`(d *mayhemDriver) scenarios()` (mayhem.go:2316), which appends
`d.mqttScenarios()` (mqtt_scenarios.go) and `d.worldScenarios()`
(mayhem_world.go:198). Samples (`maySample`, mayhem.go:56–95) come from the
sims' `/state` (ground truth) + the hub's `/status` on :9100.

The SSH pattern to copy is `hub-restart-mid-cap`
(mayhem_world.go:443–466): `d.hubSSH("true")` **probe in setup** — if SSH is
unavailable the setup returns an error and the run records INCONCLUSIVE
rather than a fake verdict; `hubSSH` (mayhem_world.go:91–105) runs
`ssh -o BatchMode=yes -o ConnectTimeout=4 dmitri@<hub-ip> <cmd>` (user
overridable via `LEXA_SSH_USER`; hub Pi 69.0.0.1 has passwordless sudo —
docs/BENCH.md). The standard export-cap preamble is `armExportCap`
(mayhem_world.go:203–207): battery SoC→100/Conn→1, `injectEnv(pvHigh, 250)`,
`postCap("exportCap", 0, holdS, …)`.

Product-side behavior under test is TASK-037's monotonic anchoring: with it,
a ±1 h local step must not expire/hold-forever the active control, must not
flap enforcement, and freshness windows (already monotonic) must not mass-
expire device telemetry. Without TASK-037 the forward step would read every
control as expired within `expiryConfirmTicks` — this scenario is expected
to FAIL against a pre-037 hub (acceptable "expected-FAIL pins the gap"
pattern, `meter-ct-inverted` precedent — 06 §2).

**Clock-step mechanics on the Pi:** NTP (systemd-timesyncd) will immediately
correct a manual step, so the scenario must
`sudo timedatectl set-ntp false` first, then `sudo date -s '+1 hour'`
(GNU date accepts relative specs: `sudo date -s "$(date -d '+1 hour')"` is
the portable form). Teardown: `sudo timedatectl set-ntp true` (timesyncd
re-syncs within seconds on the bench LAN — note: the air-gapped LAN has no
NTP server; verify with `timedatectl show` on 69.0.0.1 during development —
if no NTP source exists, teardown must instead step the clock back
explicitly: forward-scenario teardown `date -s '-1 hour'`, backward-scenario
`date -s '+1 hour'`, then set-ntp true as best-effort).

## Why this task exists
GAP-04 / §8.4: every clock scenario so far (`clock-jitter`,
`clock-jump-forward`) steps the *server's* clock via gridsim
`/admin/clock`. The hub-local half has zero coverage; it is the first thing
NTP does to a field unit.

## Architecture review sections
§8.4, §9 time family. Roadmap: 07 GAP-04 (validation: "control held, no
flap, freshness recovers; both directions"); 08 RSK-06; 06 §2 (10× solo
stability rule).

## Prerequisites
TASK-037 DONE (or explicitly run as expected-FAIL pinning — state which in
the PR). Bench FAST (`bash scripts/bench-up.sh --fast`), SSH key auth to
`dmitri@69.0.0.1`, mqttproxy NOT required.

## Files
- **Read first:**
  - `~/projects/csip-tls-test/cmd/dashboard/mayhem_world.go` (all — pattern source)
  - `~/projects/csip-tls-test/cmd/dashboard/mayhem.go` (lines 40–210: constants, sample/scenario types; 440–560: sample+scanSamples; 679+: diagnoseConstraint)
  - `~/projects/csip-tls-test/cmd/dashboard/invariants.go` (safetyAudit, invExpiredControl)
  - `~/projects/csip-tls-test/docs/BENCH.md`
- **Modify:**
  - `~/projects/csip-tls-test/cmd/dashboard/mayhem_world.go` (add scenarios + helpers)
- **Create:** none (scenarios live with the 2026-07-01 wave in mayhem_world.go).

## Blast radius
Test harness only (`cmd/dashboard`). No product code. The scenario
manipulates a live bench node's clock — journald timestamps on the hub Pi
will jump during runs (note it in the scenario's Hypothesis so future
journal forensics aren't confused).

## Implementation strategy
Two `mayScenario` entries appended in `worldScenarios()`, sharing a helper
`hubClockStep(d, deltaSpec string) error` built on `hubSSH`. Structure per
scenario: SSH probe in setup → armExportCap(90) → at tick 15 disable NTP +
step ±1 h → hold ~40 s stepped → at tick 55 restore clock + re-enable NTP →
judge with `diagnoseSurvival` (cap held throughout; survivability ladder,
mayhem_world.go:115) plus the standard `safetyAudit` invariants the engine
already applies. Teardown restores unconditionally (idempotent commands).

## Detailed steps
1. Add helpers to mayhem_world.go:
   ```go
   func (d *mayhemDriver) hubClockNTP(on bool) error   // timedatectl set-ntp true|false
   func (d *mayhemDriver) hubClockStep(sec int) error  // sudo date -s "$(date -d '<sec> seconds')"
   ```
   Both via `d.hubSSH(...)` with `sudo`. Quote carefully (the command passes
   through one shell on the Pi).
2. Append `local-clock-step-forward`:
   - `Category: "Time integrity (local clock, INV-EXPORT survivability)"`,
     `HoldS: 90`.
   - `Hypothesis`: NTP steps the hub's OWN clock +1 h mid-control (first
     sync after commissioning). Every wall-clock comparison on the hub moves;
     server time did not. Journald timestamps on the hub jump — expected.
   - `Expected`: keep enforcing the cap (it is still valid in SERVER time),
     no enforcement flap, no mass staleness of device telemetry, recover
     cleanly when the clock is restored.
   - `setup`: SSH probe (`d.hubSSH("true")` → error ⇒ INCONCLUSIVE), then
     `armExportCap(d, 90, "mayhem: cap through +1h local clock step")`.
   - `perTick`: `injectEnv(pvHigh, 250)` every tick; `i==15`:
     `hubClockNTP(false)` then `hubClockStep(+3600)` (in a goroutine like
     hub-restart's restart, so a slow SSH doesn't stall sampling); `i==55`:
     `hubClockStep(-3600)` then `hubClockNTP(true)`.
   - `evaluate`: `diagnoseSurvival("the local clock step")`.
   - `teardown`: best-effort `hubClockStep(∓ residual)`? No — teardown must
     be idempotent and safe when the perTick restore already ran: implement
     teardown as `hubClockNTP(true)` plus a *drift check*: read
     `date +%s` via SSH, compare to the dashboard host's clock; if |Δ| > 120 s,
     apply an absolute correction
     (`sudo date -s @<desktop-unix>`). This makes teardown correct even on
     abort at any tick.
3. Append `local-clock-step-back`: identical with −3600 at tick 15,
   +3600 restore at tick 55; Expected additionally: control must not be held
   past its genuine server-time expiry later (INV-EXPIRED is already part of
   `safetyAudit`, grace-bounded — invariants.go:177 region).
4. Manual sanity: run each once with
   `python3 scripts/mayhem.py --dashboard http://localhost:8080 --only local-clock-step-forward` (then `-back`).
   Verify on the hub Pi (`ssh dmitri@69.0.0.1 timedatectl`) that NTP is
   re-enabled and the clock is sane after both normal completion and a
   mid-run `--abort`.
5. Stability: run each 10× solo (`for i in $(seq 10); do … --only …; done`),
   record verdicts. Only after 10/10 stable (same verdict) do they stay in
   `worldScenarios()`; otherwise quarantine behind a comment and file the
   flake as a finding (RSK-13 rule — never tune the oracle to pass).
6. `go build -o bin/dashboard ./cmd/dashboard` and restart the
   `csip-dashboard` unit (it execs `bin/dashboard` — the stale-binary trap,
   see Common mistakes).

## Testing changes
- `make test-fast` (unchanged paths) + `go test ./cmd/dashboard/` (existing
  harness unit tests must still pass; add a unit test for the teardown drift
  check's decision logic if implemented as a pure function).
- HIL: the 10× solo runs above; then one full campaign including the new
  scenarios: `python3 scripts/mayhem.py --dashboard http://localhost:8080`.

## Documentation changes
- `docs/QA_GAPS_20260701.md` follow-up section (or `docs/QA_FINDINGS.md`):
  GAP-04 scenario landed, verdict history, whether expected-FAIL pinning was
  used pre-037.
- csip-tls-test CLAUDE.md Mayhem scenario count if it states "51".

## Common mistakes to avoid
- **Stale dashboard binary:** the `csip-dashboard` unit execs `bin/dashboard`
  — always `go build -o bin/dashboard ./cmd/dashboard` before restarting, or
  you will validate the OLD scenario set (D8, the 2026-07-03 incident).
- Teardown MUST restore the clock even on abort — the drift-check design in
  step 2 exists precisely because "subtract what you added" is wrong if the
  run aborted before/after the perTick restore.
- Do not use `pkill -f` over SSH (BENCH.md gotcha) — not needed here; all
  actions are timedatectl/date.
- The dashboard's sampler compares hub-reported values with its own wall
  clock (`WallUnix`, mayhem.go:87) — the DESKTOP clock is untouched; do not
  step it.
- SSH latency: wrap the step commands in goroutines (hub-restart precedent,
  mayhem_world.go:461) so a 4 s ConnectTimeout doesn't skew the sample
  cadence.
- Stepping the hub clock also affects mosquitto, lexa-api timestamps, and
  journald — assert only via ground-truth sims + `/status` fields that
  TASK-037 made step-immune; don't oracle on hub log timestamps.

## Things that must NOT change
- Existing scenario IDs, order, and verdict baselines (V6: 0.6 FAIL/cycle,
  0 BLIND) — the new scenarios are additive.
- The INCONCLUSIVE-without-SSH discipline (`hub-restart-mid-cap` precedent):
  never let a missing SSH key produce PASS/FAIL.
- `restoreBench()` behavior (mayhem.go:2249 region) — do not hook clock
  restoration into it; scenario teardown owns it (restoreBench runs for
  every run, including ones that never touched the clock).
- Oracle margins (mayConvergeDeadlineS=30, mayConvergeHoldS=10,
  invHuntHysteresisW=300) — no tuning to make these pass (06 §4.5).

## Acceptance criteria
- [x] `--list` shows `local-clock-step-forward` and `local-clock-step-back`.
      (Verified without touching the bench: `worldScenarios()` unit-tested
      for both IDs present exactly once, no ID collisions in the full
      59-scenario catalogue, every scenario stage wired —
      `TestWorldScenarios_ClockStepPairPresent`. Not yet verified live via
      `mayhem.py --list` against a running dashboard — batched.)
- [ ] Without SSH keys (e.g. `LEXA_SSH_USER=nobody`), both report
      INCONCLUSIVE with a setup error naming SSH. (Code path is structurally
      identical to the established `hub-restart-mid-cap`/`disk-full`
      `d.hubSSH("true")` probe; NOT exercised with a live SSH attempt in this
      session per the launch instruction — no bench/SSH contact while a soak
      owns the bench. Batched to the next bench session.)
- [ ] 10× solo each: stable verdicts; with TASK-037 deployed both PASS (or
      documented DEGRADED with physical justification); pre-037
      expected-FAIL recorded if applicable. **Batched — needs live bench.**
- [ ] After a `--abort` mid-step, hub Pi clock within 120 s of desktop and
      NTP re-enabled (verified via `timedatectl`). **Batched — needs live
      bench.** (The teardown drift-check's decision logic — the 120 s
      tolerance and the ahead/behind symmetry — is unit-tested via
      `hubClockDriftOK`/`TestHubClockDriftOK`; only the live SSH round-trip
      is unverified here.)
- [ ] Full campaign including new scenarios ≤ baseline FAIL rate. **Batched
      — needs live bench.**

## Regression checklist
- [x] `make test-fast` (csip-tls-test) green
- [ ] Conformance logic tests: not protocol-adjacent — none
- [ ] Mayhem: 10× solo each new scenario + one full campaign — **batched to
      the next bench session** (`go test ./cmd/dashboard/` green in the
      meantime: all existing harness tests plus the new command-builder /
      drift-check / catalogue tests pass)
- [ ] `bin/dashboard` rebuilt + unit restarted before validation — **batched
      to the next bench session** (`GOWORK=off go build -o bin/dashboard
      ./cmd/dashboard` confirmed as compile proof in this worktree; no
      bench unit restart performed — no SSH this session)

## Mayhem scenarios affected
Adds `local-clock-step-forward`, `local-clock-step-back`. Neighbors to
watch for interference in full campaigns: `clock-jitter`,
`clock-jump-forward` (server clock), `hub-restart-mid-cap` (shares SSH) —
ensure ordering leaves the clock sane between scenarios (teardown drift
check covers it).

## Conformance implications
None (harness-only). Indirectly exercises CSIP §5.2.1.3 client-clock
discipline.

## Suggested commit message
`feat(mayhem): local clock-step scenarios ±1h with NTP-safe teardown (GAP-04, TASK-038)`

Trailer: `Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>`

## Suggested PR title & description
**Title:** Mayhem: hub-local clock-step scenarios (GAP-04, TASK-038)
**Description:** Two scenarios stepping the hub Pi wall clock ±1 h
mid-export-cap via SSH (BatchMode probe → INCONCLUSIVE without keys);
teardown restores clock by absolute drift check + re-enables NTP, abort-safe.
Verdict evidence: 10× solo runs each + full campaign report attached.
Rollback: revert; scenarios are additive.

## Code review checklist
- Teardown correct at every abort point (walk through tick 0, 20, 60).
- SSH commands quoted correctly through the remote shell; goroutine-wrapped.
- INCONCLUSIVE path verified, not assumed.
- No oracle-margin changes anywhere in the diff.

## Definition of done
Acceptance + regression checklists green; QA docs updated; status headers
updated (this file + 00_MASTER_INDEX).

## Possible follow-up tasks
TASK-052 (netem — shares the SSH-modifier pattern), TASK-079 (DST tests),
backlog: a combined local+server double-step chaos cell after the first
campaign (07 "matrix/chaos cells" deferral).
