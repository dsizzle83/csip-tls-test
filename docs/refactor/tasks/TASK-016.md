# TASK-016 — QoS doc/code alignment (D5): per-topic QoS policy

*Status: DONE (2026-07-04, lexa-hub@ac673ac) · Phase: P0 · Effort: S (≈2–3 h) · Difficulty: low · Risk: low*

**Completion note:** `bus.PubQoS` + `mqttutil.PublishJSONQoS` landed on
`lexa-hub` branch `task/016-qos-policy` (commit `ac673ac`); the three
verified sites (measurement, battery metrics, EVSE state) flipped to QoS 0,
control plane untouched. `go test -race ./internal/...` green. Per the
Principal's wave-gate batching instruction, the Mayhem campaign
(`mqtt-broker-latency,mqtt-broker-restart,stale-meter,ev-meter-freeze`) was
**not** run in this session — it is batched into the post-merge wave-gate
campaign; not yet executed as of this note. Not deployed to the bench (code +
unit tests only this wave).

## Objective
Publish QoS is a per-topic policy owned next to the topic constants and matched to the
documented table (measurement-plane QoS 0, control-plane QoS 1): the doc/code divergence
D5 is gone, and QoS-0 hot-path publishes stop paying the synchronous PUBACK wait.

## Background
Verified divergence (review D5):
- `lexa-hub/internal/mqttutil/mqttutil.go` line 124: `client.Publish(topic, 1, retained,
  payload)` — **QoS 1 hardcoded for everything**, each publish synchronously waiting up
  to `publishTimeout = 5s` for a PUBACK.
- lexa-hub `CLAUDE.md` topic table documents: `lexa/measurements/{device}` QoS **0**,
  `lexa/battery/{device}/metrics` QoS **0**, `lexa/evse/{station}/state` QoS **0**;
  `lexa/csip/control` (retained) QoS 1; `lexa/control/battery/{device}`,
  `lexa/control/solar/{device}`, `lexa/evse/{station}/command` QoS 1.
- `internal/bus/topics.go` header comment annotates `lexa/csip/flowreservation/request`
  and `lexa/northbound/schedule` as QoS 1.
- Subscribe side: `mqttutil.Subscribe`/`subRegistry.replay` request QoS 1 on all
  subscriptions (lines 48, 149) — this is fine to keep: effective QoS = min(pub, sub),
  so QoS-0 publishes stay 0 and control topics stay 1. Leave subscribe untouched.
- Hot-path implication (review §11): `cmd/modbus` `publishMeasurements` publishes one
  measurement (+ battery metrics) per device per poll from its drain loop — each a 5 s
  worst-case PUBACK wait against a sick broker. Moving the measurement plane to QoS 0
  removes that wait entirely (paho QoS-0 tokens complete on write). The full
  tick-budget fix (async actuator publishes with overrun counters) is **TASK-046 — do
  not start it here**; this task only makes QoS match the documented design.

Publishers affected (verified call sites):
- `cmd/modbus/main.go` `publishMeasurements`: `bus.MeasurementTopic(...)` and
  `bus.BattMetricsTopic(...)` → QoS 0.
- `cmd/ocpp` bridge: EVSE state publishes (`bus.EVSEStateTopic`) → QoS 0.
- Everything else (control commands, csip control/pricing/billing/FR, compliance alert,
  schedule, plan log) stays QoS 1; retained topics keep retain flags.

## Why this task exists
Review D5 ("misleads; sync PUBACK waits in hot paths") and §11's tick-budget finding.
Doc and code must agree before the bus envelope work (TASK-017/018) freezes message
conventions.

## Architecture review sections
D5, §11 (synchronous QoS-1 waits), §14 item 18-adjacent. Roadmap: 05 §2 (bus messages
are the real interface), 04 row 016 (explicitly separate from TASK-046).

## Prerequisites
None hard. Best before TASK-018 (envelope rollout touches the same call sites — land
this first to avoid churn).

## Files
- **Read first:** `lexa-hub/internal/mqttutil/mqttutil.go` (whole file, 155 lines),
  `internal/bus/topics.go` (header + constants), lexa-hub `CLAUDE.md` topic table,
  `cmd/modbus/main.go` `publishMeasurements`, the EVSE-state publish site in
  `cmd/ocpp/main.go`'s bridge, `cmd/hub/actuators.go` (control publishes — must stay
  QoS 1).
- **Modify:** `internal/mqttutil/mqttutil.go`, `internal/bus/topics.go` (policy
  function + header), `cmd/modbus/main.go`, `cmd/ocpp/main.go` (state publish call),
  lexa-hub `CLAUDE.md` (table footnote).
- **Create:** `internal/bus/qos_test.go` (or extend an existing bus test file).

## Blast radius
lexa-hub only. Wire-level change on three topic families (QoS 1→0): subscribers
(hub, telemetry, api) are unaffected logically — they already tolerate lost samples
(freshness windows gate staleness) — but delivery becomes best-effort, which is the
documented design. Localhost broker makes actual loss negligible.

## Implementation strategy
Put the policy where the topics live: a `bus.QoS(topic string) byte` (or explicit
constants used at call sites) returning 0 for the measurement plane and 1 otherwise;
add `mqttutil.PublishJSONQoS0` (no-wait variant) alongside the existing QoS-1 helpers;
flip exactly the three verified publish sites; update the docs to match; verify under
the broker-fault scenarios.

## Detailed steps
1. `internal/bus/topics.go`: add a small, explicit policy —
   `func PubQoS(topic string) byte` returning 0 for topics matching the measurement
   plane (`lexa/measurements/`, `lexa/battery/.../metrics`, `lexa/evse/.../state`
   prefixes/suffixes; implement by prefix/suffix match on the same helpers the package
   already has) and 1 for everything else. Table-driven test covering every topic
   constant/builder in the package (each expected value mirrors the CLAUDE.md table).
2. `internal/mqttutil/mqttutil.go`: generalize `publishJSON(client, topic, v, retained)`
   to take `qos byte`; for `qos == 0`, publish and **do not** `WaitTimeout` for a PUBACK
   (paho completes QoS-0 tokens locally; still check `tok.Error()` after a short
   `WaitTimeout(100ms)` to catch marshal/connection errors without a 5 s stall — or use
   `token.Done()` semantics; document the choice). Keep `PublishJSON` /
   `PublishJSONRetained` as QoS-1 (unchanged signatures — every existing caller keeps
   compiling and behaving identically); add `PublishJSONQoS(client, topic string, qos
   byte, v any)`.
3. Flip call sites: `cmd/modbus` measurement + battmetrics publishes and `cmd/ocpp`
   EVSE-state publish to use QoS 0 via `bus.PubQoS(topic)` (so the policy is consulted,
   not re-hardcoded). Grep for any other publisher on those three topic families
   (verified: none) — attach the grep to the PR.
4. Docs: `internal/bus/topics.go` header comment gains the one-line policy statement;
   lexa-hub `CLAUDE.md` table stays as-is (it was right) — add "enforced by
   `bus.PubQoS`"; note the D5 closure.
5. `go test -race ./internal/... && go build ./...`.
6. Bench: deploy hub services (re-run `hub-replay-tune.sh fast`), then targeted
   scenarios: `python3 scripts/mayhem.py --dashboard http://localhost:8080 --only
   mqtt-broker-latency,mqtt-broker-restart,stale-meter,ev-meter-freeze` — verdicts
   unchanged. `mqtt-broker-latency` is the interesting one: measurement flow under an
   800 ms-latency broker no longer stacks PUBACK waits; hub freshness gating must behave
   identically or better.

## Testing changes
- `internal/bus`: `PubQoS` table test (every topic).
- `internal/mqttutil`: unit test that QoS-0 path doesn't block on a non-acking client
  (use a paho test double or measure elapsed <100 ms with broker absent — keep it
  hermetic; if paho can't be faked cheaply, cover via the bus test + bench evidence and
  say so).
- Run: `go test -race ./internal/bus/ ./internal/mqttutil/`.

## Documentation changes
`internal/bus/topics.go` header; lexa-hub CLAUDE.md footnote; 00_MASTER_INDEX status.

## Common mistakes to avoid
- Flipping any **control-plane** topic to QoS 0 — `lexa/control/*`, `evse/+/command`,
  `csip/control`, compliance alert, FR request are exactly-what-QoS-1-is-for; the
  deduper/watchdog re-assert logic (`reassertEvery=60s`) assumes commands are reliably
  delivered when the broker is up.
- Changing the retained flags anywhere (retain and QoS are orthogonal; csip/control
  stays retained QoS 1; plan log stays retained).
- Touching `Subscribe`'s QoS-1 — min(pub,sub) already yields the right effective QoS;
  changing subscribe adds risk for zero benefit.
- Scope creep into TASK-046 (async actuator publishes, tick budget, overrun counters) —
  explicitly out.
- Skipping the broker-latency scenario — it's the only place the QoS-0 non-wait
  behavior differs observably.

## Things that must NOT change
- All QoS-1 topics' publish semantics (bounded 5 s PUBACK wait — backs
  `mqtt-broker-restart`/`-latency` PASS and the idempotent re-issue design in
  mqttutil's comments).
- Hub freshness/frozen-meter gating (`snap.fresh`, `stale-meter`/`ev-meter-freeze`
  scenarios) — measurement cadence is unchanged, only ack accounting.
- `PublishJSON`/`PublishJSONRetained` signatures (no forced churn on 30+ call sites).

## Acceptance criteria
- [ ] `bus.PubQoS` exists with a table test covering every topic in the package; values match the CLAUDE.md table.
- [ ] Measurement/metrics/EVSE-state publishes go out QoS 0 (verify on the Pi: `mosquitto_sub -v -q 0 …` still receives; or journal/paho debug).
- [ ] Control-plane publishes byte-identical behavior (QoS 1, retained flags intact).
- [ ] Targeted scenarios verdict-identical.

## Regression checklist
- [ ] `go test -race ./internal/...` (lexa-hub) green
- [ ] Conformance logic tests: unaffected
- [ ] Mayhem: targeted `mqtt-broker-latency,mqtt-broker-restart,stale-meter,ev-meter-freeze`
- [ ] Grep proves no other publisher on the flipped topic families

## Mayhem scenarios affected
`mqtt-broker-latency` (measurement plane stops stacking PUBACK waits — same or better),
`mqtt-broker-restart` (QoS-0 samples lost during outage — freshness gating covers, as
today's behavior effectively was), `stale-meter`, `ev-meter-freeze` (freshness paths).

## Conformance implications
None (bus-internal). MUP telemetry POSTs are HTTP, untouched.

## Suggested commit message
`fix(bus): per-topic publish QoS policy — measurement plane QoS 0, control plane QoS 1 (D5)`
`Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>`

## Suggested PR title & description
**Title:** Close D5: QoS policy owned by internal/bus, code matches the documented table
**Description:** `bus.PubQoS` + mqttutil qos param; three verified call sites flipped;
control plane untouched; subscribe untouched (min-QoS argument in task file). Evidence:
bus table test, targeted scenario verdicts. Rollback: single revert.

## Code review checklist
- Flipped sites are exactly the three families; grep attached.
- QoS-0 path provably non-blocking; error handling still surfaces marshal/conn errors.
- No retain-flag or subscribe changes in the diff.

## Definition of done
Acceptance criteria + regression checklist + docs + status headers updated.

## Possible follow-up tasks
TASK-046 (tick budget / async actuator publishes — the QoS-1 half of §11), TASK-017/018
(envelope rides the same helpers), TASK-044 (publish-failure counters).
