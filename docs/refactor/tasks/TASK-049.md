# TASK-049 — Mayhem: duplicate MQTT client-ID scenario

*Status: TODO · Phase: P4 · Effort: M (≈4–6 h) · Difficulty: med · Risk: low*

## Objective
Add a Mayhem scenario `duplicate-client-id` that launches a second MQTT
client using lexa-hub's client ID (an operator error: a stale unit on the
old dev kit, a second hub instance), triggering paho's mutual-kick
reconnect storm, and asserts: the storm is detected (reconnect-rate
metric/alarm), the cross-cutting safety invariants stay clean, and no
interleaved actuation reaches the devices. Stable 10× before curation.

## Background
Repo `~/projects/csip-tls-test`. GAP-06 / review §9 identity family: two
`lexa-hub` instances with the same MQTT client ID cause paho mutual-kick
reconnect storms with **interleaved control outputs** — "a plausible
operator error with catastrophic output".

Facts:
- Client IDs are fixed per service and default from config
  (`cmd/hub/config.go:54` → `"lexa-hub"`; other services likewise). MQTT
  3.1.1 brokers disconnect the older session when a new CONNECT arrives
  with an in-use client ID → both clients fight (connect/disconnect loop).
- Injection tool: the on-hub **mqttproxy** already has a dependency-free
  publish-only MQTT client (`cmd/mqttproxy/inject.go`: `connectPacket`,
  `publishPacket`, `mqttPublish` at lines 41–80+) and a control API at
  `http://69.0.0.1:11882` (`/inject`, `/fault`, `/reset`,
  cmd/mqttproxy/control.go). But `/inject` connects, publishes ONE message,
  disconnects (mqttPublish) — it does not HOLD a session with a colliding
  ID. Two options:
  (a) **Extend mqttproxy** with a `/hold {client_id, duration_s}` endpoint
      that opens a CONNECT with the given client ID and keeps it open,
      forcing the collision. Small, dependency-free (reuse connectPacket +
      a keepalive PINGREQ loop). This is the clean approach.
  (b) A helper binary on the hub Pi launched via SSH. More moving parts.
  Choose (a): it stays inside the existing chaos surface and needs no new
  deployed unit beyond the mqttproxy already required by mqtt scenarios.
- Detection oracle needs a product-side reconnect-rate counter — provided
  by TASK-044 (`lexa_mqtt_reconnects_total` on lexa-hub :9101). **Dependency
  on TASK-044**: the scenario samples that metric to prove detection. If
  044 is not merged, the scenario can still assert the SAFETY oracles
  (no interleaved actuation, invariants clean) and mark detection
  INCONCLUSIVE — state which mode in the PR.
- Sampling: the harness reads sims' `/state` (ground truth) + hub `/status`.
  "No interleaved actuation" is judged from ground truth — the export cap
  must hold with no anomalous curtail/release flips (INV-HUNT,
  invariants.go:250+) and no back-feed during any disconnect (INV-CONNECT).
- SSH probe → INCONCLUSIVE pattern (`hub-restart-mid-cap`) applies since the
  metric scrape and mqttproxy `/hold` both need the hub reachable.

## Why this task exists
GAP-06 / §9 identity family: catastrophic-output operator error with zero
current coverage.

## Architecture review sections
§9 identity/topology family, item 12. Roadmap: 07 GAP-06 (validation:
"INV-CONNECT/INV-EXPORT clean during the storm; alarm fires"); 06 §2 (10×
solo). Depends conceptually on 044 (metric).

## Prerequisites
mqttproxy deployed (`scripts/mqtt-chaos.sh deploy`). TASK-044 for the
detection half (else detection = INCONCLUSIVE). Bench FAST, SSH to
dmitri@69.0.0.1.

## Files
- **Read first:**
  - `~/projects/csip-tls-test/cmd/mqttproxy/{inject.go,control.go,main.go}`
  - `~/projects/csip-tls-test/cmd/dashboard/mqtt_scenarios.go` (mqttFault/mqttInject/mqttReset helpers)
  - `~/projects/csip-tls-test/cmd/dashboard/mayhem_world.go` (hubSSH, armExportCap, diagnoseSurvival)
  - `~/projects/csip-tls-test/cmd/dashboard/invariants.go` (connectBackfeed, invHunt, safetyAudit)
  - `~/projects/csip-tls-test/scripts/mqtt-chaos.sh` (deploy path)
- **Modify:**
  - `~/projects/csip-tls-test/cmd/mqttproxy/{control.go,inject.go}` (add `/hold`)
  - `~/projects/csip-tls-test/cmd/dashboard/mqtt_scenarios.go` (add scenario + `/hold` client helper)
  - `~/projects/csip-tls-test/sim/mqttproxy.service` if a version bump note is needed (check; likely no change)
- **Create:** none.

## Blast radius
Harness + mqttproxy (bench-only fault tool). No product code. The scenario
deliberately destabilizes the real hub's MQTT session — teardown must
release the held client ID and confirm the hub reconnected cleanly, or
subsequent campaign scenarios inherit a flapping hub.

## Implementation strategy
Extend mqttproxy with a session-holding endpoint, add the scenario using
the export-cap preamble, drive the collision mid-cap for a bounded window,
sample ground truth + the reconnect metric, and judge with a custom ladder
(FAIL on interleaved actuation / invariant violation; DEGRADED if storm
detected but cap wobbled within bounds; PASS if cap held cleanly and storm
detected). Restore in teardown.

## Detailed steps
1. **mqttproxy `/hold`.** Add `handleHold` (control.go) →
   POST `{client_id, duration_s}`: spawn a goroutine that CONNECTs to
   upstream with `connectPacket(client_id)` and sends PINGREQ (`0xC0 0x00`)
   every ~keepalive/2 until `duration_s` elapses, then DISCONNECT. Reuse
   `mqttPublish`'s dial/CONNACK-read code (refactor the connect preamble
   into a shared helper). TASK-051 reuses this connect helper; if 051
   landed first with a local copy, consolidate to one helper here. Guard: one active hold at a time; `/reset`
   cancels it. Cross-build + redeploy mqttproxy (`scripts/mqtt-chaos.sh
   deploy` rebuilds arm64 + installs). Add a `holdClientID` helper on
   `mayhemDriver` in mqtt_scenarios.go posting to `/hold`.
2. **Scenario `duplicate-client-id`** in `mqttScenarios()`
   (Category: "Identity/topology (INV-CONNECT/INV-EXPORT)", HoldS ≈ 90):
   - Hypothesis: a second process CONNECTs as `lexa-hub` (stale dev-kit
     unit, duplicate deploy). MQTT evicts the real hub's session; both
     flap; control outputs risk interleaving.
   - Expected: the real hub keeps enforcing the cap through the storm, no
     interleaved/contradictory actuation reaches devices, and the storm is
     detected (reconnect-rate alarm/metric). Ideal fix noted:
     unique-per-instance client IDs + a broker ACL preventing anonymous
     re-use (post-TASK-013).
   - setup: SSH probe + mqttproxy probe (else INCONCLUSIVE); armExportCap
     (0 W, battery full, high PV). Read the hub's client ID from config?
     It is `"lexa-hub"` by default (config.go:55) — hardcode with a comment
     citing that default and `LEXA_HUB_CLIENT_ID` env override for the
     scenario if the bench differs.
   - perTick: inject env; at tick ~15 `holdClientID("lexa-hub", 40)`
     (goroutine-wrapped for SSH-less HTTP call latency); the real hub now
     mutual-kicks for 40 s; at ~tick 55 the hold ends and the hub should
     settle.
   - evaluate: custom ladder using `scanSamples` + `invExport` +
     `safetyAudit` (which already runs connectBackfeed/invHunt): FAIL if any
     INV-CONNECT/INV-EXPORT violation or a sustained cap breach during the
     storm; DEGRADED if the cap held but the reconnect metric shows the
     storm AND there was transient hunting within hysteresis; PASS if cap
     held cleanly. If TASK-044 present, additionally require the reconnect
     counter to have INCREASED (detection); if absent, note detection
     INCONCLUSIVE in the finding diagnosis.
   - teardown: POST `/reset` (cancels the hold), wait ~5 s, verify the hub
     reconnected (`getJSON("hub","/status",…)` returns 200 with a fresh
     plan timestamp), `deleteControls(0)`.
3. Rebuild `bin/dashboard`, restart csip-dashboard.
4. Validate: 10× solo; verify teardown leaves the hub healthy after both
   normal finish and `--abort` (the hold goroutine must self-cancel on
   `/reset` AND on duration — an aborted run that skips teardown still ends
   the storm when `duration_s` elapses, so `duration_s` must be modest,
   ≤45 s). Full campaign.

## Testing changes
- `cmd/mqttproxy`: unit test the `/hold` handler's lifecycle (starts,
  self-cancels on duration, cancels on reset) with a fake upstream (the
  existing `inject_test.go`/`proxy_test.go` patterns).
- `cmd/dashboard`: pure-function test for any new verdict-ladder logic.
- HIL: 10× solo + full campaign.

## Documentation changes
- `docs/QA_FINDINGS.md`: scenario + verdict history; note the fix direction
  (unique client IDs; broker ACLs post-013).
- csip-tls-test CLAUDE.md Mayhem count + mqttproxy `/hold` note.

## Common mistakes to avoid
- **Bounded self-cancelling hold:** an aborted run must not leave a
  permanent client-ID squatter — cap `duration_s ≤ 45` and self-cancel; the
  `/reset` in teardown is the fast path, the duration is the safety net.
- Rebuild `bin/dashboard` before restart (D8 stale-binary trap) AND
  redeploy mqttproxy (its binary changed) via `scripts/mqtt-chaos.sh deploy`.
- Killing the real hub's session storms EVERY topic — allow settle time in
  teardown before the next scenario; verify `/status` health, not just
  "reset returned 200".
- Don't judge detection from logs; use the TASK-044 metric or mark
  INCONCLUSIVE.
- Client ID must match the RUNNING hub's actual ID — if the bench overrode
  the default in `/etc/lexa/hub.json`, the collision won't happen; read it
  (SSH `grep mqtt_client_id /etc/lexa/hub.json`) in setup and use it, else
  the scenario silently no-ops (a false PASS). Fail setup → INCONCLUSIVE if
  the ID can't be determined.
- pkill/systemctl: not needed; all via mqttproxy HTTP.

## Things that must NOT change
- Existing scenario verdicts/baselines (V6). Additive scenario + additive
  mqttproxy endpoint (existing `/inject`,`/fault`,`/reset` unchanged).
- `restoreBench()` — clock/programs/faults restore; do not add client-ID
  release there (scenario teardown owns it; `/reset` also clears proxy
  faults, so ensure teardown ordering doesn't wipe another scenario's
  state — it won't, scenarios run sequentially).
- Oracle margins untouched.
- INV-CONNECT/INV-EXPORT/INV-HUNT definitions (invariants.go) — the
  scenario CONSUMES them, never weakens them.

## Acceptance criteria
- [ ] `--list` shows `duplicate-client-id`; `/hold` endpoint on mqttproxy
      works (unit + a manual `curl -X POST .../hold -d '{"client_id":"lexa-hub","duration_s":10}'`
      observed to disrupt the hub's session then recover).
- [ ] Missing mqttproxy/SSH or indeterminable client ID ⇒ INCONCLUSIVE.
- [ ] 10× solo stable; INV-CONNECT/INV-EXPORT clean across all runs
      (any violation is a real product finding, not a harness flake — pin
      it if so).
- [ ] With TASK-044: reconnect counter rises during the storm (detection
      proven). Without: detection INCONCLUSIVE, safety oracles still judged.
- [ ] After `--abort` mid-storm, the hub is healthy within ~60 s (hold
      self-cancelled).
- [ ] Full campaign ≤ baseline (scenario excluded from FAIL rate if it
      pins a real defect pending unique-client-ID fix).

## Regression checklist
- [ ] `make test-fast` + `go test ./cmd/mqttproxy/ ./cmd/dashboard/` green
- [ ] Conformance logic tests: none (harness)
- [ ] Mayhem: 10× solo + full campaign
- [ ] `bin/dashboard` rebuilt + `mqtt-chaos.sh deploy` (proxy) before validation

## Mayhem scenarios affected
Adds `duplicate-client-id`. Neighbors: `mqtt-broker-restart` (session
churn — different cause), `hub-restart-mid-cap` (SSH). No verdict changes
expected elsewhere.

## Conformance implications
None (harness). Surfaces a real deployment-hardening gap (unique client IDs)
that feeds the security/ACL work (TASK-013/014, W7).

## Suggested commit message
`feat(mayhem,mqttproxy): duplicate client-ID storm scenario + /hold endpoint (GAP-06, TASK-049)`

Trailer: `Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>`

## Suggested PR title & description
**Title:** Mayhem: duplicate MQTT client-ID reconnect storm (GAP-06, TASK-049)
**Description:** Adds a session-holding `/hold` endpoint to mqttproxy and a
scenario that squats the hub's client ID mid-cap; asserts INV-CONNECT/
INV-EXPORT clean, no interleaved actuation, and (with TASK-044)
reconnect-rate detection. Self-cancelling hold = abort-safe. Evidence: 10×
solo + campaign. Rollback: revert; additive.

## Code review checklist
- Hold goroutine self-cancels on both duration and reset; one-at-a-time.
- Scenario reads the real hub client ID (no false PASS on mismatch).
- Detection oracle degrades to INCONCLUSIVE without TASK-044.
- Teardown verifies hub health, not just reset ACK.

## Definition of done
Acceptance + regression checklists green; QA docs updated; status headers
updated (this file + 00_MASTER_INDEX).

## Possible follow-up tasks
TASK-013/014 (unique client IDs + broker ACLs — the actual fix), backlog:
second-meter / duplicate Modbus unit-ID identity scenarios (07 deferred
list).
