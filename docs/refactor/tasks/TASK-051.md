# TASK-051 — Mayhem: MQTT storm / backpressure scenario

*Status: CODE COMPLETE (2026-07-05, csip-tls-test `task/049-051-scenarios` 01e97bc,
unmerged — batched with TASK-049/050 per the Principal Engineer's deadline-push
instruction, 05 §12 amendment): mqttproxy `/storm` (reuses TASK-049's
`dialAndConnect` helper), `mqtt-storm` scenario (diagnoseConstraint + INV-HUNT +
TASK-044 overflow-counter check; a cap breach with a flat counter is the named
"silent wedge" FAIL), unit tests (storm lifecycle, verdict ladder). Bench
validation (10× solo, abort self-cancel check, full campaign, and the actual
1000-queue overflow finding) explicitly NOT run — rides the next batched wave
gate; another session owns the live bench for this gate.
· Phase: P4 · Effort: M (≈4–6 h) · Difficulty: med · Risk: low*

## Objective
Add a Mayhem scenario `mqtt-storm` that floods the broker with publishes
against Mosquitto's `max_queued_messages 1000` bound while a zero-export cap
is active, and asserts: control latency stays bounded, drop/queue-overflow
counters surface (TASK-044), and no safety invariant is violated. Stable
10× before curation.

## Background
Repo `~/projects/csip-tls-test`. GAP-10 / review §9 load family:
"`max_queued_messages 1000` overflow behavior on QoS 1 is unobserved; a
chatty device or QA harness bug could starve the control topic." Broker
config (lexa-hub/systemd/mosquitto-lexa.conf): `max_inflight_messages 20`,
`max_queued_messages 1000`, localhost-only.

Injection: the on-hub **mqttproxy** (`cmd/mqttproxy`) is the tool. It has
`/inject` (single publish) and `/fault {mode: latency}` today. For a storm
we need sustained high-rate publishing — extend it with a
`/storm {topic, rate_hz, duration_s, payload_bytes}` endpoint reusing the
dependency-free publisher (`inject.go` `mqttPublish`/`publishPacket`) in a
rate-limited loop. Target a NON-control topic (e.g. `lexa/measurements/
storm-noise` or a junk topic) so the flood competes for broker queue/CPU
without directly overwriting real control state — the question is whether
the control PATH stays responsive under bus pressure, not whether a forged
control is honored (that's mqtt-malformed/stale, mqtt_scenarios.go).

Oracle: the export cap must hold (ground truth via sims; `diagnoseConstraint`,
mayhem.go:679) and control latency must stay bounded — measurable as: the
hub keeps adopting/enforcing (sampled `HubAdopted`/`AdoptedLimW`) and
INV-HUNT/INV-EXPORT stay clean (safetyAudit). Backpressure visibility needs
counters from TASK-044: `lexa_mqtt_publish_failures_total` (a full queue
makes QoS-1 publishes time out → the hub's 5 s wait / TASK-046 harvest
counts them) and/or a broker-side dropped-message signal
(`mosquitto_sub $SYS/broker/messages/...` or the hub's own counters).
**Dependency on TASK-044** (drop/failure counters) and, ideally, TASK-046
(so the storm-induced publish stalls become bounded overruns rather than
tick blocking — without 046 the scenario also validates that the sync 5 s
waits don't wedge the loop, which is itself worth knowing).

## Why this task exists
GAP-10 / §9 load family: queue-overflow behavior on the product's own bus
is a blind spot; a starving control topic is a safety issue.

## Architecture review sections
§9 load/duration family, §11 (sync publish waits — storm is the stressor),
item 12/20. Roadmap: 07 GAP-10 (validation: "control latency stays bounded
and dropped-message counters surface"); 06 §2 (10× solo). Depends on 044.

## Prerequisites
mqttproxy deployed. TASK-044 (counters) for the visibility half; TASK-046
recommended (bounded tick under stress). Bench FAST, SSH to hub Pi.

## Files
- **Read first:**
  - `~/projects/csip-tls-test/cmd/mqttproxy/{inject.go,control.go,proxy.go,main.go}`
  - `~/projects/csip-tls-test/cmd/dashboard/mqtt_scenarios.go` (helpers + existing bus scenarios)
  - `~/projects/csip-tls-test/cmd/dashboard/mayhem.go` (diagnoseConstraint, scanSamples, sample fields)
  - `~/projects/lexa-hub/systemd/mosquitto-lexa.conf`
- **Modify:**
  - `~/projects/csip-tls-test/cmd/mqttproxy/{control.go,inject.go}` (add `/storm`)
  - `~/projects/csip-tls-test/cmd/dashboard/mqtt_scenarios.go` (scenario + `mqttStorm` helper)
- **Create:** none.

## Blast radius
Harness + mqttproxy (bench fault tool). No product code. A sustained flood
stresses the real broker on the hub Pi — teardown must stop the storm and
let queues drain before the next scenario.

## Implementation strategy
Add `/storm` to mqttproxy (rate-limited publish loop, bounded duration,
self-cancelling), add a scenario driving it mid-cap, sample the export cap +
TASK-044 counters, judge with `diagnoseConstraint` plus a
latency/visibility check. Bounded duration = abort safety.

## Detailed steps
1. **mqttproxy `/storm`.** `handleStorm` (control.go): POST
   `{topic, rate_hz, duration_s, payload_bytes}` → a goroutine opens ONE
   CONNECT (reuse the connect helper factored in TASK-049, or a local copy)
   and publishes QoS-0 at `rate_hz` (ticker) for `duration_s`, payload of
   `payload_bytes` zeros. Cap: `rate_hz ≤ 2000`, `duration_s ≤ 30`,
   `payload_bytes ≤ 4096` (self-limiting so an aborted run's storm ends on
   its own). `/reset` cancels. Cross-build + `scripts/mqtt-chaos.sh deploy`.
   Add `func (d *mayhemDriver) mqttStorm(topic string, rateHz, durationS, payloadBytes int) error`.
2. **Scenario `mqtt-storm`** in `mqttScenarios()` (Category: "Bus
   backpressure (INV-EXPORT survivability)", HoldS ≈ 80):
   - Hypothesis: a chatty/faulty publisher floods the bus (~1500 msg/s)
     while a zero-export cap is active, pressuring `max_queued_messages
     1000` and `max_inflight 20`.
   - Expected: the control path stays responsive — the cap holds, commands
     still land within a bounded latency, and overflow is COUNTED (drops
     visible), never silently starving control.
   - setup: mqttproxy probe (else INCONCLUSIVE); armExportCap (0 W, full
     battery, high PV). Snapshot the hub's `lexa_mqtt_publish_failures_total`
     (curl :9101/metrics, if TASK-044 present) into the driver for a
     before/after delta.
   - perTick: inject env; `i==8`: `mqttStorm("lexa/measurements/storm-noise",
     1500, 25, 256)` (goroutine-wrapped).
   - evaluate: `diagnoseConstraint` (cap held is the primary oracle) +
     extend the finding: assert INV-HUNT clean (no chasing under pressure)
     and, if TASK-044 present, that the publish-failure/queue counter is
     OBSERVABLE (either it moved, proving drops surface, or it stayed zero,
     proving the queue absorbed it — both are acceptable; a WEDGE with no
     counter movement AND a cap breach is the FAIL). Judge latency
     indirectly: the hub must keep adopting (no `HubAdopted` gap > a few
     samples) through the storm.
   - teardown: `mqttReset()` (cancels storm + clears proxy fault),
     wait ~5 s for queues to drain, `deleteControls(0)`.
3. Rebuild `bin/dashboard`, restart csip-dashboard; redeploy mqttproxy.
4. Validate: 10× solo; verify the storm self-cancels on `--abort` (bounded
   duration) and `/reset` stops it immediately. Full campaign.

## Testing changes
- `cmd/mqttproxy`: unit test `/storm` lifecycle (rate honored approx,
  self-cancels on duration + reset, param caps enforced).
- `cmd/dashboard`: pure verdict-ladder test if extracted.
- HIL: 10× solo + full campaign.

## Documentation changes
- `docs/QA_FINDINGS.md`: scenario + verdict + observed queue behavior
  (what actually happens at 1000-queue overflow — this is new knowledge).
- csip-tls-test CLAUDE.md Mayhem count + mqttproxy `/storm` note.

## Common mistakes to avoid
- **Bounded, self-cancelling storm** (duration + param caps) so an aborted
  run doesn't flood the bench indefinitely; `/reset` is the fast stop.
- Flood a NON-control topic — the goal is bus PRESSURE, not forging control
  (that's covered elsewhere). Flooding `lexa/csip/control` retained would
  poison the retained store (a different, TASK-043 concern).
- Redeploy mqttproxy (binary changed) AND rebuild `bin/dashboard` (D8).
- QoS-0 flood is right (max volume, drops-on-overflow visible); a QoS-1
  flood would block on the proxy's own acks and self-throttle.
- Don't oracle on latency via wall-clock log timestamps; use sampled
  adoption continuity + counters.
- Give queues drain time in teardown before returning (a following scenario
  starting against a backed-up broker would inherit the pressure).
- Scenario/endpoint IDs unique.

## Things that must NOT change
- Existing scenario verdicts/baselines (V6), especially
  `mqtt-broker-latency`/`-restart` (same family).
- `restoreBench()` filesystem/bus neutrality.
- Oracle margins (`mayConvergeDeadlineS`, `invHuntHysteresisW`, …).
- INV definitions and `diagnoseConstraint` logic (consumed, not modified).

## Acceptance criteria
- [ ] `--list` shows `mqtt-storm`; `/storm` endpoint works (unit + a manual
      `curl` observed to drive broker `$SYS` message counters up).
- [ ] Missing mqttproxy ⇒ INCONCLUSIVE.
- [ ] 10× solo stable; cap held (diagnoseConstraint PASS/bounded), INV-HUNT
      clean; with TASK-044, counter behavior recorded.
- [ ] Storm self-cancels on abort (bounded duration verified) and on
      `/reset`.
- [ ] Full campaign ≤ baseline; documented finding on what 1000-queue
      overflow actually does.

## Regression checklist
- [ ] `make test-fast` + `go test ./cmd/mqttproxy/ ./cmd/dashboard/` green
- [ ] Conformance logic tests: none (harness)
- [ ] Mayhem: 10× solo + full campaign
- [ ] `bin/dashboard` rebuilt + `mqtt-chaos.sh deploy` before validation

## Mayhem scenarios affected
Adds `mqtt-storm`. Neighbors: `mqtt-broker-latency`, `mqtt-broker-restart`,
`perfect-storm`. No verdict changes expected elsewhere; watch that the
storm's drain time doesn't bleed into the next scenario.

## Conformance implications
None (harness). Informs the fleet-scale perf note (review §12:
per-message-JSON at hundreds of devices) with real overflow behavior.

## Suggested commit message
`feat(mayhem,mqttproxy): MQTT storm/backpressure scenario + /storm endpoint (GAP-10, TASK-051)`

Trailer: `Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>`

## Suggested PR title & description
**Title:** Mayhem: MQTT storm vs max_queued_messages (GAP-10, TASK-051)
**Description:** Adds a bounded, self-cancelling `/storm` publisher to
mqttproxy and a scenario flooding a noise topic mid-cap; asserts the control
path stays responsive (cap held, adoption continuous, INV-HUNT clean) and
overflow is counted (TASK-044). Documents actual 1000-queue overflow
behavior. Evidence: 10× solo + campaign. Rollback: revert; additive.

## Code review checklist
- Storm params capped; goroutine self-cancels on duration + reset.
- Noise topic, not control topic.
- Counter/latency oracle degrades gracefully without TASK-044.
- Drain time in teardown; no bleed into neighbors.

## Definition of done
Acceptance + regression checklists green; QA docs updated; status headers
updated (this file + 00_MASTER_INDEX).

## Possible follow-up tasks
TASK-046 (async publishes — storm proves the tick-budget), TASK-078 (soak
with background storm windows), backlog: per-topic QoS policy (TASK-016)
under storm.
