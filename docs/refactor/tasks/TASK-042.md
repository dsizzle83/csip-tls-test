# TASK-042 — Retained-control trust hardening (staleness bound, corrupt→re-request)

*Status: PARTIAL (2026-07-06, lexa-hub `task/042-retained-trust` @ `dd62fe8`,
code complete + unit-tested, unmerged — bench acceptance criteria (live
truncated-payload injection, mqtt-malformed-control/mqtt-stale-retained/
wan-outage-*/hub-restart-mid-cap 10× gates, full FAST campaign) explicitly
out of scope this session per launch instructions — "code + unit tests only,
no bench (scenarios are 043)" — and deferred to TASK-043) · Phase: P3 ·
Effort: M (≈4–6 h) · Difficulty: high · Risk: med*

## Objective
Stop treating the retained `lexa/csip/control` message as unconditionally
authoritative: (a) bound its **staleness at adoption** using the publish
stamp it already carries (enforce-but-verify, never fail-open), and (b) turn
a **corrupted retained payload** from a silent log-and-drop into an alarmed
re-request: the hub asks, northbound immediately re-publishes its
last-known-good and re-walks. Extends AD-006's reject-and-alarm posture to
the control plane.

## Background
Repo `~/projects/lexa-hub`. Two failure modes (review §8.3, GAP-01/02):

1. **Stale resurrection.** Mosquitto persists with `autosave_interval 60`
   (`systemd/mosquitto-lexa.conf`). An unclean broker death (power cut)
   restores `lexa/csip/control` up to 60 s stale; the hub adopts it on
   (re)subscribe. A superseded 5 kW cap resurrected during a 0 W event is a
   measured compliance violation. What the message carries today
   (`bus.ActiveControl`, internal/bus/messages.go:28–39): `Source`, `MRID`,
   limits, `ClockOffset`, `ValidUntil`, **`Ts`** — stamped
   `time.Now().Unix()` at publish in `toActiveControl`
   (cmd/northbound/main.go:604, Ts stamped :608). So a publish stamp already exists — no
   schema addition needed (the brief's "if no timestamp, ADD one" is
   satisfied; the `v` envelope field arrives separately with TASK-017/018).
   Freshness signal: northbound republishes on **every successful walk**
   (~5 s FAST), so a `Ts` much older than a few walk periods means either a
   WAN outage (northbound alive but failing walks — publishes nothing,
   fail-closed, main.go:252–267) or a resurrected corpse.
   **Design decision (record as AD extension): enforce-but-verify, never
   reject.** Rejecting a stale cap fails OPEN (a cap is conservative;
   dropping it can only increase export/import). On adopting a retained
   control whose `Ts` age exceeds `retained_adoption_max_age_s` (default
   300), the hub: keeps enforcing it (existing local-expiry discipline still
   bounds it via ValidUntil), raises an edge-triggered alarm log
   (+ metric via TASK-044 later), and publishes a re-request so a live
   northbound refreshes truth within seconds.
2. **Corrupted retained payload.** `mqttutil.Subscribe[T]`
   (internal/mqttutil/mqttutil.go:135–143) logs `[mqtt] unmarshal on %s: %v`
   and drops. For a retained control-plane topic that means: a hub that
   (re)starts against a truncated retained payload holds NO control until
   the next successful walk republish — during a WAN outage, forever.
   Fail-closed becomes fail-open-by-omission (GAP-02).
   Mechanism: add a decode-failure hook to `Subscribe`; the hub uses it on
   `TopicCSIPControl` to alarm + publish the re-request.

**Re-request mechanism (minimal, design goes into 02):** new topic
`lexa/csip/rewalk` (`bus.TopicCSIPRewalk`), QoS 1, non-retained, payload
`{"reason":"stale"|"decode","ts":...}`. Northbound subscribes; on receipt it
(1) immediately re-publishes its in-memory last-published `ActiveControl`
(fresh `Ts`) if it has one — this repairs a corrupt/stale retained value
even while the WAN is dark — and (2) triggers an immediate discovery walk
(outside the normal cadence) to refresh truth. Northbound currently builds
the control message per-walk and does not keep it; add a `lastPublished
*bus.ActiveControl` in `cmd/northbound/main.go` guarded by a mutex.

## Why this task exists
GAP-01 (retained rollback → compliance violation the utility measures),
GAP-02 (corrupt retained → control-less forever), review §8.3, RSK-05.
TASK-043 builds the Mayhem scenarios that prove both.

## Architecture review sections
§8.3, §9 persistence/restart family, W5 adjacency. Roadmap: 02 AD-006 (this
task extends it — add the re-request path as an AD note); 07 GAP-01/02;
08 RSK-05; 04 deps (034 — uses utilitytime for age arithmetic).

## Prerequisites
TASK-034 DONE (utilitytime). TASK-037 helpful (anchored clock) but not
required. Bench FAST for gates. TASK-017/018 NOT required (additive JSON
only).

## Files
- **Read first:**
  - `~/projects/lexa-hub/internal/mqttutil/mqttutil.go` (all)
  - `~/projects/lexa-hub/cmd/hub/state.go` (onCSIPControl, expiry block) and `cmd/hub/main.go` (subscription wiring, lines 159–178)
  - `~/projects/lexa-hub/cmd/northbound/main.go` (lines 240–330 runDiscovery; publish site 280; and 604–635 `toActiveControl`, Ts stamped :608 — line 329 is publishSchedule's DERScheduleMsg.Ts, a different message)
  - `~/projects/lexa-hub/internal/bus/{topics.go,messages.go}`
  - `~/projects/csip-tls-test/cmd/dashboard/mqtt_scenarios.go` (existing corrupted/stale scenarios — the oracles you must not break)
- **Modify:**
  - `~/projects/lexa-hub/internal/mqttutil/mqttutil.go` (decode-failure hook: add `SubscribeWithErrHandler[T]` or an options variant — keep `Subscribe` signature intact for all other callers)
  - `~/projects/lexa-hub/internal/bus/topics.go` (+`TopicCSIPRewalk`), `messages.go` (+`RewalkRequest`)
  - `~/projects/lexa-hub/cmd/hub/{main.go,state.go,config.go}` (staleness check, alarm, re-request publish; config `retained_adoption_max_age_s`)
  - `~/projects/lexa-hub/cmd/northbound/main.go` (lastPublished cache, rewalk subscription, immediate-walk trigger)
- **Create:** none.

## Blast radius
Control-plane adoption path (`cmd/hub`), northbound walk loop trigger,
`internal/mqttutil` (shared by all six services — hook must be opt-in and
default-inert), `internal/bus` (new topic + message). Radioactive-adjacent:
full campaign gate.

## Implementation strategy
Three commits. (1) mqttutil hook, inert for existing callers. (2) Hub:
staleness classification in `onCSIPControl` (age = `now − msg.Ts` via
utilitytime-injectable clock for tests), edge-triggered alarm + rewalk
publish; decode-failure handler on the control topic doing the same with
reason "decode". (3) Northbound: cache + rewalk handling with a
rate limit (ignore re-requests more often than once per 10 s) so a
misbehaving hub cannot make northbound hammer the utility (walk-rate
courtesy, review §12).

## Detailed steps
1. **mqttutil.** Add
   `SubscribeDecodeErr[T](client, topic, handler, onErr func(topic string, payload []byte, err error))`
   built on the same registry/replay path (registry replay must re-use the
   wrapped handler — verify resubscribe still works; see subRegistry
   comments lines 21–29). `Subscribe` delegates with a nil onErr. Unit-test
   with an in-memory fake conforming to the small surface used (or via a
   local broker if the repo has none — keep it a pure handler-level test by
   extracting the payload→handler closure into a testable function).
2. **Bus.** `TopicCSIPRewalk = "lexa/csip/rewalk"`; `RewalkRequest{Reason
   string; Ts int64}`. Update the topic-map comment block (topics.go:4–19)
   and the lexa-hub CLAUDE.md MQTT table (hub → northbound, QoS 1).
3. **Hub.** In `onCSIPControl`: compute age; if `Source != "none"` and age >
   configured bound → set a `staleSuspect` flag on the stored control, log
   `[hub] retained CSIP control mrid=%s is %ds old at adoption (bound %ds) — enforcing (fail-closed) and requesting re-publish`
   once per adoption, publish `RewalkRequest{Reason:"stale"}`. Subscribe to
   the control topic via `SubscribeDecodeErr`; onErr → log
   `[hub] retained CSIP control payload undecodable: %v — requesting re-publish`
   + `RewalkRequest{Reason:"decode"}` (rate-limit both publishes: ≥10 s
   apart). The enforcement path is UNCHANGED (same struct, same expiry).
4. **Northbound.** Keep `lastPublished` (set after every successful publish
   at main.go:280). Subscribe `TopicCSIPRewalk`: republish the cached
   control unchanged except `Ts = time.Now().Unix()` (Ts is the publish
   stamp, not the resolution stamp), then trigger an immediate walk
   (a `chan struct{}` poke into the walk ticker loop — find the loop in
   `main()`; it drives `runDiscovery` on a ticker).
5. **Tests.**
   - Hub unit: fresh control (age 0) → no alarm/no rewalk; stale → one
     alarm + one rewalk, still enforced (ReadSystemState returns it);
     decode error → rewalk with reason decode; rate limit honored.
   - Northbound unit: rewalk handler republishes cache + triggers walk;
     rate-limited; no cache → walk trigger only.
6. **Bench gates.** Deploy both; `hub-replay-tune.sh fast`. Run existing
   `mqtt-malformed-control`, `mqtt-stale-retained`, `wan-outage-hold`,
   `wan-outage-expiry`, `hub-restart-mid-cap` 10× — verdicts at baseline
   (the first two should improve in recovery speed, not change verdict).
   Full FAST campaign. TASK-043 adds the real power-cut/corrupt scenarios.

## Testing changes
Unit tests per step 5 (new files/testcases in `cmd/hub` and
`cmd/northbound` test files); mqttutil hook test. Run:
`go test -race ./internal/... ./cmd/...`; bench gates above.

## Documentation changes
- 02: extend AD-006 with the re-request path ("retained control-plane
  decode failure ⇒ alarm + lexa/csip/rewalk; stale adoption ⇒
  enforce-but-verify") — one paragraph, dated, cite this task.
- lexa-hub CLAUDE.md: MQTT topic table + one invariant line: "retained
  control adoption is staleness-checked; corrupt retained control triggers
  re-request — never silent".
- csip-tls-test CLAUDE.md: no change (harness unaffected until 043).

## Common mistakes to avoid
- **Never reject/drop a stale-but-decodable cap** — that converts an
  under-enforcement risk into a no-enforcement certainty. Enforce + verify.
- `wan-outage-hold` regression: during a WAN outage northbound publishes
  nothing, so the retained control's Ts ages past any bound while the hub
  keeps enforcing — the staleness alarm must be **adoption-time only**
  (message arrival), not a periodic re-check of the held control, or the
  outage scenarios will drown in alarms (and tempt someone to auto-drop).
- The rewalk republish must not fight the walk loop: take the same code
  path/mutexes as the ticker walk (single-flight — if a walk is running,
  coalesce).
- mqttutil hook: all six services share this package; default behavior for
  every existing `Subscribe` caller must be byte-identical.
- Rate-limit both directions (hub requests, northbound honors) — a corrupt
  retained payload is REDELIVERED on every reconnect (subRegistry.replay
  comment, mqttutil.go:38–40).
- Deploy gotcha: `hub-replay-tune.sh fast` after deploy; build
  `bin/dashboard` only if you touch the harness (you shouldn't here).

## Things that must NOT change
Preservation ledger entries touched:
- Fail-closed hold through WAN outage (northbound publishes nothing on walk
  error; hub enforces retained control until local expiry) ↔
  `wan-outage-hold`, `wan-outage-expiry`, `northbound-hang`
  (QA 2026-07-02; cmd/northbound/main.go:252–267 comment).
- Malformed **bus** payload drop-without-unseat ↔ `mqtt-malformed-control`
  (the hub must still keep the last-good control; the new behavior only ADDS
  alarm + re-request).
- Spurious retained "none" handling ↔ `mqtt-stale-retained` (a `none` that
  contradicts an unexpired control: today's transient-drop-then-recover
  behavior must not get worse; do not special-case `none` in the staleness
  check — Source=="none" is excluded from the stale alarm, step 3).
- Retained publish semantics of `lexa/csip/control` (QoS 1, retained) and
  hub re-seed on restart ↔ `hub-restart-mid-cap`.
- Local-expiry discipline (`expiryConfirmTicks`/TASK-036 policy) untouched.

## Acceptance criteria
- [x] Unit: stale adoption → enforced + one alarm + one rewalk; fresh → silent.
      (`cmd/hub/rewalk_test.go`: `TestOnCSIPControl_StaleAdoptionAlarmsAndRewalksOnceStillEnforced`,
      `TestOnCSIPControl_FreshControlNoAlarmNoRewalk`.)
- [x] Unit: decode failure on the control topic → alarm + rewalk; other
      topics unchanged (plain Subscribe). (`internal/mqttutil/mqttutil_test.go`:
      `TestSubscribeDecodeErr_OnErrFiresOnMalformedJSON`,
      `TestSubscribeDecodeErr_NilOnErrIsIdenticalToSubscribe`;
      `cmd/hub/rewalk_test.go`: `TestRequestRewalk_DecodeReasonSharesRateLimitWithStaleAdoption`.)
- [x] Unit: northbound rewalk → immediate republish (cache) + walk trigger,
      rate-limited. (`cmd/northbound/rewalk_test.go`:
      `TestHandleRewalkRequest_RepublishesCachedControlWithFreshTsAndPokesWalk`,
      `TestHandleRewalkRequest_RateLimited`, `TestHandleRewalkRequest_RepeatedPokesCoalesce`.)
- [ ] Bench: manually inject a truncated retained payload
      (`curl -s -X POST http://69.0.0.1:11882/inject -d '{"topic":"lexa/csip/control","payload":"{\"source\":\"event\",","retain":true}'`
      via mqttproxy), restart lexa-hub, observe: alarm log, rewalk request,
      control restored within one northbound response (attach journal
      excerpt). **NOT DONE this session** — launch instructions scoped this
      session to code + unit tests only ("no bench, scenarios are 043");
      deferred to TASK-043.
- [ ] Gate scenarios 10× at baseline; full FAST campaign ≤ baseline. **NOT
      DONE this session** — same deferral as above.

## Regression checklist
- [x] `go test -race ./internal/... ./cmd/...` (lexa-hub) green — commit `dd62fe8`.
- [x] Conformance logic tests green (`go test ./tests/`, csip-tls-test) —
      unaffected (no csip-tls-test code touched; this is a lexa-hub-only
      change) but re-run and green.
- [ ] Mayhem: `mqtt-malformed-control`, `mqtt-stale-retained`,
      `wan-outage-*`, `hub-restart-mid-cap` 10× + full campaign — **deferred
      to TASK-043** per launch instructions (batched at the wave gate).
- [ ] `hub-replay-tune.sh fast` after deploy — not deployed this session
      (unmerged, no bench work performed).

## Mayhem scenarios affected
`mqtt-malformed-control` (recovery now active, not walk-luck),
`mqtt-stale-retained`, `wan-outage-hold`/`-expiry` (must NOT change),
`hub-restart-mid-cap`. New scenarios arrive in TASK-043
(`power-cut-retained-rollback`, `corrupted-retained-control`).

## Conformance implications
None to the wire protocol. The immediate re-walk must respect server
courtesy (rate limit) — 2030.5 servers may rate-limit clients (review §12).

## Suggested commit message
Three commits, e.g.:
`feat(mqttutil): opt-in decode-failure hook on Subscribe (TASK-042 1/3)`
`feat(hub): retained-control staleness bound + rewalk re-request (TASK-042 2/3)`
`feat(northbound): rewalk handler — republish last-good + immediate walk (TASK-042 3/3)`

Trailer: `Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>`

## Suggested PR title & description
**Title:** Retained-control trust: staleness bound + corrupt→re-request (TASK-042)
**Description:** Closes GAP-01/02 product half (§8.3). Enforce-but-verify on
stale retained adoption (never fail-open); corrupted retained control now
alarms and triggers lexa/csip/rewalk → northbound republishes last-good +
walks immediately. AD-006 extended. Testing: units + bench injection
evidence + 10× gates + full campaign. Rollback: revert per-commit;
new topic is additive.

## Code review checklist
- No path drops/rejects a decodable control for staleness.
- Adoption-time-only staleness check (grep for periodic re-check — none).
- Rate limits both sides; redelivery-safe.
- mqttutil default path byte-identical for other callers.
- Campaign report attached.

## Definition of done
Acceptance + regression checklists green; 02/CLAUDE.md updated; status
headers updated (this file + 00_MASTER_INDEX).

## Possible follow-up tasks
TASK-043 (scenarios), TASK-044 (alarm metrics: stale-adoption counter,
decode-failure counter, rewalk counter), TASK-017/018 (envelope `v` — the
decode-failure hook is the natural reject-and-alarm site).
