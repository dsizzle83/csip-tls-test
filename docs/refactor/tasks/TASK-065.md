# TASK-065 — Bench: second inverter + second EVSE; multi-device scenarios; multi-breach

*Status: TODO · Phase: P5 · Effort: L (≈8 h) · Difficulty: high · Risk: med*

## Objective
The bench runs a second solar inverter sim and a second EVSE sim; the hub
controls both pairs; `Plan.Breach` (single slot) becomes a breach LIST
carried through the bus with a schema version bump; the export rule's
first-active-EVSE selection becomes an all-active allocation policy; the
nameplate-share solar split is exercised with two inverters; and two new
Mayhem scenarios (two-inverter export cap, two-EVSE churn) run verdict-
stable. This kills the §8.5 single-device assumptions.

## Background
Verified single-device assumptions:
- **First-active-EVSE:** `applyExportLimitRule` picks the FIRST connected
  EVSE with an active session and breaks (optimizer.go:721-728; post-060
  this lives in `constraint/export.go` — re-verify location).
- **Single breach slot:** `Plan.Breach *ComplianceBreach`
  (model.go:302-316); `recordBreach` keeps only the worst shortfall
  (optimizer.go:2192-2197); `bus.ComplianceAlert` carries ONE mrid/limit
  per message (internal/bus/messages.go:45-55); cmd/hub's `breachAlert`
  edge-detector tracks ONE `activeBreachMRID` (cmd/hub/main.go:98-140,
  reworked by TASK-031 — read its result).
- **Bench topology** (docs/BENCH.md): solar-pi 69.0.0.10 runs modsim
  (Modbus 5020 / simapi 6020); ev-pi 69.0.0.14 runs evsim (simapi 6024,
  CSMS ws://69.0.0.1:8887/ocpp). Ports 5023/6023 and 6025 are unused
  (grep-verified). modsim flags: `-port`, `-wmax`, `-api-port`
  (sim/modsim/main.go:34-36); evsim flags: `-csms`, `-id`, `-connectors`,
  `-api-port` (sim/evsim/main.go).
- **Deploy:** `scripts/update-sim-pis.sh` installs one binary per Pi over
  the unit's existing ExecStart (a second instance needs its own unit —
  e.g. `modsim2.service`, `evsim2.service` user units with linger — and a
  script extension).
- **Configs listing devices:** hub `configs/modbus.json` (`devices[]`
  url/unit_id/role/max_w), `configs/hub.json` (`devices[]`, `stations[]`),
  `configs/ocpp.json` (`stations[]`); dashboard flags `-solar/-battery/
  -meter/-ev` point at ONE simapi each (cmd/dashboard/main.go:23-30) — the
  Mayhem driver reads/injects via those.
- Bus envelope (`"v"` field) landed in P0 (TASK-017/018): the ComplianceAlert
  schema change here is the versioned-envelope path's first real bump.

## Why this task exists
§8.5: "Fleet reality breaks these quietly" — first-EVSE, one-inverter
nameplate split, one breach slot. 09 checklist: "Second inverter + second
EVSE scenarios PASS; multi-breach reporting verified" is a hard gate.
08 RSK-18.

## Architecture review sections
§8.5 · R4 · 02 AD-007 ("multi-device from the start: breach list,
per-device sessions") · 03 §P5 · 08 RSK-18 · 06 §2 (second devices kill
single-device assumptions).

## Prerequisites
TASK-062 DONE (per-device sessions exist). TASK-017/018 (envelope) DONE.
Bench access; FAST mode. Coordinate with no other radioactive task.

## Files
- **Read first:** BENCH.md; scripts/update-sim-pis.sh; sim/modsim/main.go;
  sim/evsim/main.go; cmd/dashboard/main.go (sim endpoints);
  lexa-hub model.go + internal/bus/messages.go + cmd/hub breach path
  post-031; `constraint/export.go` EV selection.
- **Modify (lexa-hub):** `internal/orchestrator/model.go` (Breaches list —
  keep `Breach` as deprecated worst-of alias during migration),
  `constraint/export.go` (all-active EVSE allocation; per-inverter
  nameplate share), `internal/bus/messages.go` (ComplianceAlert v bump:
  breaches list), `cmd/hub` breach alerting, `cmd/northbound` responseTracker
  consumption (multiple MRIDs), configs (`modbus.json`, `hub.json`,
  `ocpp.json` — second entries).
- **Modify (csip-tls-test):** `scripts/update-sim-pis.sh` (second units),
  `cmd/dashboard/main.go` + mayhem driver (second solar/ev endpoints),
  `cmd/dashboard/mayhem.go` (+2 scenarios), docs/BENCH.md.
- **Create:** systemd user units for modsim2/evsim2 (installed by script).

## Blast radius
Both repos + the physical bench. Bus schema (ComplianceAlert) — versioned,
paired PRs, deployed same session (05 §11 lockstep rule). Mayhem driver
endpoints. This is the widest-blast task of P5; stage it.

## Implementation strategy
Three gated stages. Stage 1 (bench): second sims running and visible
(no hub change — hub ignores unknown devices). Stage 2 (hub): configs +
all-active EVSE policy + per-inverter nameplate share + breach list with
versioned alert; deploy hub+sims same session. Stage 3 (harness): driver
knows both instances; add the two scenarios; 10× solo stability each, then
a full campaign.

## Detailed steps
1. Stage 1 — units: modsim2 on solar-pi (`-port 5023 -api-port 6023
   -wmax 3000` — a DIFFERENT nameplate, so share-split math is actually
   exercised); evsim2 on ev-pi (`-csms ws://69.0.0.1:8887/ocpp -id evse-002
   -api-port 6025`). Extend update-sim-pis.sh to install/refresh both
   units; verify `curl http://69.0.0.10:6023/state` and `:6025/state`.
2. Stage 2a — configs: modbus.json + hub.json add `inverter-1`
   (tcp://69.0.0.10:5023, max_w 3000, plant block per 064); ocpp.json +
   hub.json stations add `cs-002`. Confirm lexa-ocpp accepts a second
   station and publishes `lexa/evse/cs-002/state` (read cmd/ocpp station
   handling first).
3. Stage 2b — optimizer/constraint: EVSE allocation policy: iterate ALL
   connected+active EVSEs; allocate absorption/budget proportional to
   `MaxCurrentA` headroom (document the policy); update expGuard-equivalent
   session to per-station maps. Nameplate share: gen-limit and export
   ceilings split across inverters proportional to `max_w` (verify the
   existing share code path — `applyGenLimitRule`'s per-inverter logic —
   and extend tests to 2 inverters with unequal nameplates).
4. Stage 2c — breach list: `Plan.Breaches []ComplianceBreach` (recordBreach
   appends, dedupes by LimitType); bus `ComplianceAlert` v2 carries
   `breaches[]`; hub edge-detection per (mrid,limitType); northbound posts
   one CannotComply per distinct MRID (responseTracker already keyed by
   mrid — verify update()/alertCannotComply paths). Version-tolerant
   decode: v1 consumers of v2 messages must reject-and-alarm per TASK-018
   policy; deploy all services same session (RSK-10).
5. Deploy hub + sims same session (MTR-4 discipline);
   `hub-replay-tune.sh fast`.
6. Stage 3 — harness: dashboard flags `-solar2 http://69.0.0.10:6023`,
   `-ev2 http://69.0.0.14:6025` (default empty = single-device bench keeps
   working); driver `solarSim2()/evSim2()` helpers; new scenarios:
   - `two-inverter-export-cap`: both inverters at high PV, zero-export
     cap; oracle: combined export ≤ cap (INV-EXPORT), BOTH inverters
     curtailed proportionally, no single-inverter starvation.
   - `two-evse-churn`: both EVSEs in session under an export cap with the
     cap rewritten every ~12 s (control-churn pattern); oracle: cap held,
     INV-EVMAX per station, no allocation flapping (INV-HUNT).
7. Run each new scenario 10× solo (`--only two-inverter-export-cap` etc.)
   for verdict stability; then full FAST campaign; update accepted-verdict
   ledger.

## Testing changes
- lexa-hub: 2-inverter share tests, all-active allocation tests,
  breach-list unit tests (append/dedupe/worst), bus v2 encode/decode +
  mixed-version rejection tests.
- csip-tls-test: `make test-fast` additions for driver endpoint plumbing;
  scenario stability runs.
- Run: `make test` (hub), `make test-fast` + `go test ./tests/` (bench),
  `scripts/mayhem.py` per step 7.

## Documentation changes
- BENCH.md: new ports (5023/6023, 6025), units, deploy notes.
- Both CLAUDE.md files: port map + lockstep note for the alert schema.
- Accepted-DEGRADED/verdict ledger with the two new scenarios.

## Common mistakes to avoid
- Deploying the hub's v2 alert while northbound still decodes v1
  (silent zero-values — the XML lesson on the bus); all six services same
  session, envelope rejection verified.
- Equal-nameplate second inverter (hides share-split bugs — use 3 kW vs
  10 kW).
- Forgetting metersim: linked mode computes PCC balance from solar-api
  :6020 only (update-sim-pis.sh rewrites ExecStart) — it must include
  modsim2's contribution or the meter contradicts reality; extend
  metersim's linked-mode inputs (`-solar2-api`) in the same session.
- `pkill -f` over SSH; use systemctl --user.
- Adding the scenarios to the curated set before 10× solo stability
  (RSK-13).

## Things that must NOT change
- Single-device deployments keep working (empty second-device config =
  today's behavior; CI runs both shapes).
- CannotComply single-breach behavior for single-breach situations
  (exactly one Response per episode per MRID — the dedupe/edge semantics
  from TASK-031).
- Existing scenario verdicts (control-churn, export-cap family) — the
  allocation policy change must not disturb single-EVSE behavior:
  with one active EVSE the all-active policy must reduce to today's.
- V6 baseline; MTR-4 lockstep discipline.

## Acceptance criteria
- [ ] Both new sims live and polled; hub /status shows inverter-1 + cs-002.
- [ ] 2-inverter export cap: combined export ≤ cap on bench; unit share
  tests green.
- [ ] Multi-breach: simultaneous import+gen breach produces two
  CannotComply Responses (gridsim log evidence).
- [ ] New scenarios verdict-stable 10× solo; full campaign ≤ baseline.
- [ ] Mixed-version alert rejection verified once on bench.

## Regression checklist
- [ ] `go test -race ./internal/...` (lexa-hub) green
- [ ] `make test-fast` + `go test ./tests/` (csip-tls-test) green
- [ ] Mayhem: full FAST campaign including new scenarios
- [ ] Hub + sims deployed same session; `hub-replay-tune.sh fast` re-run

## Mayhem scenarios affected
NEW: two-inverter-export-cap, two-evse-churn. Watch: control-churn,
export-cap-full-battery, ev-* family (allocation policy), perfect-storm.

## Conformance implications
Multiple simultaneous CannotComply Responses (one per MRID) — 2030.5
Response semantics per control; verify gridsim's response-set accepts
concurrent POSTs (tests/ conformance logic if touched).

## Suggested commit message
lexa-hub: `feat(hub): multi-device — breach list (alert v2), all-active EVSE allocation, per-inverter share`
csip-tls-test: `feat(bench): second inverter + EVSE sims, driver endpoints, two multi-device scenarios`
(+ trailer both: `Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>`)

## Suggested PR title & description
**Title (paired PRs, cross-referenced):** Multi-device bench + multi-breach
reporting
**Description:** Stages 1-3 as above; schema bump deployed lockstep; new
scenario stability evidence; rollback: config removes second devices
(RSK-18 recovery), alert v2 revert requires paired revert.

## Code review checklist
- Allocation policy reduces to legacy behavior with one EVSE (test).
- Share split with unequal nameplates sums exactly to the cap.
- Envelope bump follows TASK-017 policy; mixed-version behavior tested.
- metersim linked-mode includes the second inverter.

## Definition of done
Acceptance criteria + regression checklist + docs updated + status headers
(this file + 00_MASTER_INDEX) updated.

## Possible follow-up tasks
TASK-066 (deletion gate includes multi-device campaign), TASK-078 (soak
runs the multi-device bench), backlog: >2 devices / topic-batching at
fleet scale (§12).
