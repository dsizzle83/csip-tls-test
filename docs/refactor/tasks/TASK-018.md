# TASK-018 — Bus envelope rollout: all publishers/subscribers, reject-and-alarm

*Status: TODO · Phase: P0 · Effort: L (≈6–8 h + campaign) · Difficulty: med · Risk: med*

## Objective
Every lexa bus message is published with `"v":1` and every subscriber version-checks
before decode (rejecting unknown majors with counter+log, accepting absent-`v` as v0
during the transition); a bench rolling-restart test and a full Mayhem campaign prove
mixed-version and retained-legacy messages cause zero control-path regressions (RSK-10).

## Background
TASK-017 landed the machinery in `lexa-hub/internal/bus` (`Envelope`, per-schema
version constants, `CheckVersion`, `RejectAndAlarm`, `LegacyV0Accepted=true`). This task
wires it everywhere.

**Publisher/subscriber inventory (verified via `grep -rn "mqttutil.PublishJSON\|
mqttutil.Subscribe" --include="*.go" cmd/` — re-run when implementing):**

| service | publishes (stamp v) | subscribes (check v) |
|---|---|---|
| cmd/modbus (4 sites) | measurements, battery metrics | control/battery/+, control/solar/+ (via `subscribeControls`) |
| cmd/hub (8 + actuators 3) | control/battery, control/solar, evse command (actuators.go), hub/plan (retained), compliance alert, FR request | measurements, batt metrics, csip/control (retained), evse state, northbound/schedule, csip/pricing |
| cmd/northbound (6 sites) | csip/control (retained), pricing, billing, FR status, schedule (retained) | compliance alert, FR request (note: FR request subscribe uses raw `mc.Subscribe` at main.go:192, not `mqttutil.Subscribe` — handle it too) |
| cmd/ocpp (2 sites) | evse state | evse command |
| cmd/telemetry (2 sites) | — | measurements, csip/control |
| cmd/api (6 sites) | — | measurements, batt metrics, csip/control, evse state, schedule, hub/plan |

**Bench repo:** nothing in csip-tls-test decodes bus JSON as typed structs — the sims
speak HTTP simapi, metersim's linked mode polls lexa-api over HTTP, and
`cmd/mqttproxy` handles raw bytes (its `/inject` deliberately publishes arbitrary —
including malformed/legacy — payloads; unchanged). Mayhem's
`mqtt-malformed-control` and `mqtt-stale-retained` scenarios inject payloads WITHOUT a
`v` field: they must keep working, which the v0-tolerance policy guarantees during the
transition. Note this explicitly in the harness-facing docs (when v0 tolerance is
eventually turned off, those scenarios' payloads gain `"v":1` in the same change).

**Retained-message trap (the critical one):** at deploy time the broker holds retained
messages published by PRE-envelope binaries (`lexa/csip/control`, pricing, billing, FR
status, schedule, hub/plan). Subscribers restarting after the upgrade immediately
receive **absent-`v`** retained payloads. If v0 were rejected, the hub would boot
control-less — exactly the §8.3 zero-value hazard this work exists to prevent. Hence:
`LegacyV0Accepted` stays `true` through this task and flips only in a later, separate
change once every retained topic has been re-published by a stamping binary (northbound
walks republish csip/control within one discovery interval; hub/plan republishes every
tick).

**Cheapest correct stamping mechanism:** embed `bus.Envelope` in each message struct in
`messages.go` and set `V` at each publish site (explicit, greppable); check versions
centrally by extending `mqttutil.Subscribe[T]` with a pre-unmarshal
`bus.CheckVersion(topic, payload, supported)` call (mqttutil may import bus — bus
imports only stdlib, no cycle; verified). Supported-version lookup: add
`bus.SupportedV(topic string) int` beside `PubQoS` from TASK-016.

## Why this task exists
Review §8.3 / §14 item 18: silent zero-values on shape skew; AD-006. Prereq for the
desired-state schema (TASK-025) to be "born versioned" into an already-versioned bus.

## Architecture review sections
§8.3, §14 item 18; AD-006; RSK-10 (rolling upgrade); 05 §2.

## Prerequisites
TASK-017 DONE. TASK-016 preferably done (same helpers). Bench FAST for the campaign.

## Files
- **Read first:** every file in the inventory table; `internal/bus/envelope.go`;
  `internal/mqttutil/mqttutil.go`; `cmd/northbound/main.go:192` (the raw subscribe).
- **Modify (lexa-hub):** `internal/bus/messages.go` (embed Envelope in the ~15
  top-level published types — nested sub-structs do NOT get envelopes),
  `internal/bus/topics.go` (`SupportedV`), `internal/mqttutil/mqttutil.go`
  (`Subscribe[T]` version gate), all publish sites per the table (set `V`),
  `cmd/northbound/main.go` (raw FR-request subscribe gains the same check).
- **Modify (csip-tls-test):** docs only (Mayhem scenario notes re v0 payloads —
  `cmd/dashboard/mqtt_scenarios.go` comments if helpful; no payload changes now).
- **Create:** nothing.

## Blast radius
Every bus message's wire shape gains one field; every subscriber gains a decode gate.
The failure modes are (a) a subscriber rejecting what it must accept (retained legacy —
prevented by v0 tolerance), (b) a missed publish site emitting absent-`v` forever
(harmless now, breaks at the future flip — hence the audit step), (c) mixed-version
services mid-rolling-restart (explicitly tested).

## Implementation strategy
Wire the subscriber gate first (tolerant of everything current), then stamp all
publishers, then prove: unit tests, bench rolling-restart mid-cap, full FAST campaign,
and the two harness scenarios that inject legacy/malformed payloads. Enforcement
(v0-off) is explicitly deferred and documented.

## Detailed steps
1. `internal/bus/messages.go`: embed `Envelope` in each published top-level type
   (Measurement, BattMetrics, ActiveControl, ComplianceAlert, BattCommand,
   SolarCommand, EVSEState, EVSECommand, PricingUpdate, BillingUpdate,
   FlowReservationRequestMsg, FlowReservationStatusMsg, DERScheduleMsg, PlanLog).
   Add `SupportedV(topic)` to topics.go (all 1). Extend the bus tests: each type
   marshals `"v":1` when stamped; golden legacy JSON (no `v`) still unmarshals with
   zero-value V.
2. `mqttutil.Subscribe[T]`: before unmarshal, call `bus.CheckVersion(m.Topic(),
   m.Payload(), bus.SupportedV(m.Topic()))`; on `*VersionError` →
   `bus.RejectAndAlarm(err)` and drop (do NOT call the handler). Keep the existing
   malformed-JSON log-and-drop after it. Unit-test with a fake message.
3. Stamp publishers: at every `PublishJSON*` site in the table set the embedded `V`
   (e.g. `msg.V = 1` or construct with `Envelope: bus.Envelope{V: 1}`). Prefer a tiny
   helper per call-file over magic in mqttutil — explicitness is the audit trail.
   Include `cmd/hub/actuators.go`'s three command publishes (radioactive file — this
   is a mechanical, additive one-liner per site; still: its own commit, and the
   campaign gates it).
4. `cmd/northbound/main.go:192` raw FR-request subscribe: insert the same
   CheckVersion/RejectAndAlarm guard before `frManager.handleRequest`.
5. Audit for missed sites: `grep -rn "PublishJSON" --include="*.go" cmd/ internal/` —
   every hit either stamps V or is mqttutil itself. Attach to PR.
6. `go test -race ./internal/... ./cmd/...` + build.
7. Bench rolling-upgrade test (RSK-10): with an export cap active on the bench (drive
   via dashboard scenario or gridsim admin), deploy the new binaries
   (`deploy-hub-pi.sh`, re-run `hub-replay-tune.sh fast`), restarting services one at a
   time in a mixed-version window (deploy script restarts all — simulate the mixed
   window by restarting lexa-northbound last manually before its binary is swapped if
   practical; otherwise document that same-session all-service deploy is the supported
   mode, per RSK-10's recovery column). Verify: cap enforcement never lapses
   (meter sim export bounded), hub adopted the retained legacy csip/control at boot
   (journal), and after one walk the retained control is v1
   (`mosquitto_sub -C 1 -t lexa/csip/control` shows `"v":1`).
8. Gates: `python3 scripts/mayhem.py --dashboard http://localhost:8080 --only
   mqtt-malformed-control,mqtt-stale-retained,hub-restart-mid-cap` ×5 (legacy/garbage
   payload handling + retained-boot path), then a **full FAST campaign** ≤ V6 baseline.
9. Post-flip plan (do NOT execute): document in AD-006 the enforcement criteria —
   "all retained topics observed at v1 + one campaign later ⇒ set
   `LegacyV0Accepted=false`" — and file it as a backlog item with the harness payload
   updates (mqtt_scenarios.go injected JSON gains `"v":1`).

## Testing changes
- bus: marshal/unmarshal envelope tests incl. golden legacy payloads.
- mqttutil: subscribe-gate tests (accept v1, accept absent, reject v2 + counter).
- Run: `go test -race ./internal/bus/ ./internal/mqttutil/` and full `make test`.

## Documentation changes
- lexa-hub CLAUDE.md bus invariants: add "every bus message carries `\"v\"`; absent = v0
  legacy, accepted during transition (AD-006)".
- AD-006: status 🔶 → ✅ once the rolling-restart validation passes; record the
  enforcement-flip criteria.
- 00_MASTER_INDEX status.

## Common mistakes to avoid
- Rejecting absent-`v` anywhere in this task — the retained-legacy boot path breaks
  (see Background trap). The flip is a separate future change.
- Envelope on nested structs (tariff intervals, schedule slots) — one version per
  *message*, not per sub-object.
- Forgetting the raw `mc.Subscribe` FR-request site (it bypasses mqttutil — verified
  the one exception at northbound main.go:192).
- Stamping via a sneaky mqttutil auto-inject (marshal-then-patch) — hides which schemas
  are versioned and breaks the audit grep.
- Batching the `cmd/hub/actuators.go` stamping with any behavioral change — radioactive
  file, mechanical diff only, campaign-gated (05 §12).
- Skipping the retained-topic re-publish check (step 7) — the enforcement flip later
  depends on knowing every retained payload is stamped.

## Things that must NOT change
- Decode outcomes for all current-shape messages: v1 and legacy payloads must produce
  byte-identical handler inputs (the gate only ever drops unknown-major).
- `Subscribe`'s malformed-JSON log-and-drop behavior (GAP-02's re-request improvement
  is TASK-042, not here).
- `*float64`/no-NaN conventions; retain flags; QoS policy (TASK-016).
- Harness injection scenarios' payloads (v0-tolerated by design this phase).

## Acceptance criteria
- [ ] Every publish site in the audit grep stamps `V=1`; every subscribe path checks.
- [ ] `mosquitto_sub` spot checks on the Pi show `"v":1` on measurements, control cmds, csip/control (post-walk), hub/plan.
- [ ] Injected `{"v":99,...}` on a control topic → dropped, counter increments, rate-limited log line (test via mqttproxy `/inject`).
- [ ] Rolling-restart mid-cap: enforcement never lapsed; retained legacy adopted at boot.
- [ ] Targeted scenarios ×5 verdict-identical; full FAST campaign ≤ V6 baseline.

## Regression checklist
- [ ] `go test -race ./internal/...` (lexa-hub) green
- [ ] Conformance logic tests: unaffected (`go test ./tests/` in csip-tls-test still green)
- [ ] Mayhem: targeted `mqtt-malformed-control,mqtt-stale-retained,hub-restart-mid-cap` ×5 + **full FAST campaign**
- [ ] Bench restored FAST; deploy same-session both-repo docs footnote (no csip code changed — note it)

## Mayhem scenarios affected
`mqtt-malformed-control` (garbage still dropped — now possibly at the version gate),
`mqtt-stale-retained` (legacy-shaped retained still accepted as v0 — verdict must not
change), `hub-restart-mid-cap` (retained boot path). Plus campaign-wide watch for any
decode-related drift.

## Conformance implications
None (bus-internal). CSIP XML surface untouched.

## Suggested commit message
`feat(bus): stamp v=1 on all publishers; version gate on all subscribers; v0 legacy tolerated (AD-006 rollout, RSK-10)`
`Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>`

## Suggested PR title & description
**Title:** Bus envelope rollout across all six services
**Description:** Inventory table (task file) fully wired; retained-legacy tolerance
explained + tested (rolling restart mid-cap); enforcement flip deliberately deferred
with criteria in AD-006. Evidence: mosquitto_sub captures, reject-counter demo,
scenario verdicts, campaign. Rollback: single revert (v-field is additive; old binaries
ignore it).

## Code review checklist
- Audit grep output == diff's publish sites (no absent-v stragglers).
- No rejection path reachable for absent-v (reviewer traces CheckVersion).
- actuators.go diff is mechanical one-liners only.
- Rolling-restart evidence attached; AD-006 flip criteria recorded.

## Definition of done
Acceptance criteria + regression checklist + docs (CLAUDE.md, AD-006) + status headers
updated.

## Possible follow-up tasks
Backlog: `LegacyV0Accepted=false` enforcement flip (+ harness payload stamping);
TASK-025 (desired-state schema born at v1); TASK-042 (retained re-request on
decode/version failure); TASK-044 (scrape reject counters); TASK-055 (NaN-string
rejection at the same gate).
