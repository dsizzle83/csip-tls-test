# TASK-055 — `"NaN"`-string bus JSON robustness + test

*Status: DONE (2026-07-05, lexa-hub 828f4d6, branch task/055-nan-bus) · Phase: P4 · Effort: S (≈2–3 h) · Difficulty: low · Risk: low*

**Closure note:** scope grep for lax decoders (`UseNumber`/`json.Number`/
`map[string]any`/`interface{}`/`ParseFloat`) found none on the bus/
measurement decode path — the task is exactly the pinning tests + defense-
in-depth described below, no additional lax-path closure needed.
`internal/bus/nan_reject_test.go` pins stdlib's existing bare/quoted
NaN/Infinity rejection; `Finite() error` added to every `*float64`-bearing
message type and wired into `mqttutil.Subscribe`; a `Finite()` failure and
a plain `Unmarshal` failure both now increment `bus.RecordDecodeFailure`
(sibling of `RejectAndAlarm`/`VersionRejects`), closing the silent-drop half
of GAP-09. `ActiveControl` NaN-limit safety case covered:
`TestActiveControlNaNLimitNeverReachesOptimizer`. `go test -race
./internal/... ./cmd/...` green in lexa-hub; producer-side `nan_test.go`
unchanged. Follow-up (noted, not done — outside this task's `internal/bus`
+ `internal/mqttutil` lane): sum `bus.DecodeFailures()` into each service's
`lexa_bus_decode_failures_total` metric in `cmd/*/main.go` (today only
`VersionRejects()` feeds it); optional rogue-publisher Mayhem probe.

## Objective
Make the bus decode layer explicitly reject `"NaN"`/`"Infinity"`/`"-Infinity"`
strings and bare `NaN`/`Inf` tokens in numeric fields (from a non-lexa
publisher or a version-skewed one), routing the failure to the
alarm-and-drop path (the TASK-042 decode hook / TASK-018 envelope alarm)
instead of silently admitting a NaN into a `*float64` or crashing a
consumer. Small, unit-tested, both robustness proof and a guard against
future decoders that are laxer than today's stdlib.

## Background
Repo `~/projects/lexa-hub`. Convention (both CLAUDE.mds): `math.NaN()` never
appears in JSON; absent values use `*float64` (nil). `TestBusMessagesNaNRoundTrip`
(`internal/bus/nan_test.go`) proves lexa PRODUCERS pass nil, not `&NaN`.
Review §9 value-domain: "NaN arriving in bus JSON despite the convention
(a non-lexa publisher or version skew — `*float64` nil is handled, `"NaN"`
string isn't)."

Current decode path: `mqttutil.Subscribe[T]` →
`json.Unmarshal(payload, &v)` (mqttutil.go:138), log-and-drop on error.
Go's `encoding/json` behavior (verify — it is the crux of scoping this task):
- Bare `NaN`/`Infinity` tokens are **invalid JSON** → `Unmarshal` already
  errors → already dropped (and, on the control topic post-042, alarmed).
- A **quoted** `"NaN"` into a `float64`/`*float64` field → `Unmarshal`
  already errors (`json: cannot unmarshal string into Go value of type
  float64`) → already dropped.
So stdlib ALREADY rejects both forms into typed numeric fields. The residual
risk is narrower and real:
1. **Laxer future decoders.** If any code path uses `json.Decoder` with
   `UseNumber()`, `interface{}`/`map[string]any` fields, or a third-party
   JSON lib, `"NaN"` can slip through as a string or a `json.Number` that a
   later `ParseFloat` turns into an actual NaN. Grep for these.
2. **`*float64` fields that a producer sets to `&NaN`** despite the
   convention — `json.Marshal` of a NaN pointer FAILS at the producer
   (that's what nan_test.go guards), but a NON-Go publisher can emit
   `{"w": NaN}` (some JS/Python encoders do with `allow_nan=True`) → bare
   token → stdlib rejects (case above) — good, but the DROP is silent on
   non-control topics.
The task therefore: (a) add an explicit, tested guard so the behavior is
PINNED (a regression to a lax decoder is caught), (b) make numeric-domain
decode failures alarm (not just log) via the TASK-018 envelope /042 hook,
(c) add a defensive check that any decoded `*float64` is finite, converting
a slipped-through NaN/Inf into a decode error + alarm rather than a live
value reaching the optimizer.

## Why this task exists
GAP-09 / §9 value-domain: the convention protects lexa publishers; a rogue
or skewed publisher isn't covered, and the failure is silent on
non-control topics. "The XML lesson, unlearned for the bus" (§8.3).

## Architecture review sections
§9 value-domain, §8.3 (bus versioning/robustness), item 18. Roadmap:
07 GAP-09 (validation: "decoder-level rejection + unit tests; rogue-publisher
Mayhem probe optional stretch"); 05 §2 ("never NaN in JSON"); 04 row 055
(depends 018).

## Prerequisites
TASK-018 DONE (bus envelope + reject-and-alarm path — the natural home for
the alarm). If run before 018, land the finite-check + tests now and route
the alarm through the TASK-042 decode hook / a log-counter, noting the
envelope wiring as a follow-up. Bench not required (unit-level).

## Files
- **Read first:**
  - `~/projects/lexa-hub/internal/mqttutil/mqttutil.go` (Subscribe, lines 135–154)
  - `~/projects/lexa-hub/internal/bus/messages.go` (all `*float64` fields) + `nan_test.go`
  - The TASK-018 envelope decode helper (wherever 018 put reject-and-alarm) and the TASK-042 `SubscribeDecodeErr` hook
  - `~/projects/lexa-hub/cmd/hub/state.go` (how decoded values reach the optimizer — `onMeasurement` etc.)
- **Modify:**
  - `~/projects/lexa-hub/internal/bus/` (add a `Validate()`/finite-check on the decoded message OR a decode wrapper; snake into the envelope decode from 018)
  - `~/projects/lexa-hub/internal/mqttutil/mqttutil.go` only if the finite-check belongs at the Subscribe seam (prefer bus-layer)
- **Create:**
  - `~/projects/lexa-hub/internal/bus/nan_reject_test.go`

## Blast radius
Bus decode layer — shared by all six services. The change must only REJECT
genuinely non-finite/malformed numeric input; valid messages (including the
nil-pointer absent-value convention) must decode byte-identically. This is a
tightening on the untrusted boundary; a false rejection would drop a valid
message.

## Implementation strategy
Grep for lax-decode risks first (scope check). Then add a finite-validation
step to the bus decode: after `json.Unmarshal`, walk the message's numeric
fields (or add a `Finite() error` method per message type that checks its
own `*float64`s) and, if any is NaN/±Inf, return a decode error routed to
alarm-and-drop. Prove with unit tests over every documented `"NaN"`/`Inf`
form and every message type; confirm stdlib's existing rejections stay
rejections (regression pins). Keep it small — this is an S task.

## Detailed steps
1. **Scope grep** (put results in the PR): 
   `grep -rn "UseNumber\|json.Number\|map\[string\]any\|interface{}\|ParseFloat" ~/projects/lexa-hub/internal ~/projects/lexa-hub/cmd --include=*.go`.
   Each hit near a bus/measurement path is a real slip risk to close;
   the pricing/tariff decode (messages.go uses typed ints, low risk) and
   any `map[string]float64` sim-adjacent code are the candidates. If none,
   the task is purely the pinning tests + the defensive finite-check.
2. **Finite check.** Add to `internal/bus` a helper
   `func finite(ps ...*float64) error` and per-type `Finite() error`
   methods for the messages carrying `*float64` (`Measurement`,
   `BattMetrics`, `EVSEState`, `ActiveControl` limits, `ComplianceAlert`
   float fields, `DERScheduleSlot`) returning an error naming the offending
   field on NaN/±Inf. (These fire only if a non-finite value SLIPPED past
   json — belt-and-suspenders; documented as defense-in-depth.)
3. **Wire into decode.** In the TASK-018 envelope decode path (or, absent
   018, in `mqttutil.Subscribe`'s decode wrapper via the 042 hook), after a
   successful `Unmarshal`, call the message's `Finite()` if it implements
   it (`interface{ Finite() error }` type assertion) — on error, treat it
   as a decode failure: log + alarm counter (`lexa_bus_decode_failures_total`
   from TASK-044) + drop; on the retained control topic, trigger the
   TASK-042 rewalk. Keep the plain-`Subscribe` default path behavior for
   callers that don't opt in (backward compatible).
4. **Tests** (`nan_reject_test.go`): table over payloads
   × message types:
   - bare `{"w": NaN}` → Unmarshal error (stdlib) → dropped (PIN today's
     behavior so a future lax decoder regression fails this test).
   - quoted `{"w": "NaN"}`, `{"w":"Infinity"}`, `{"w":"-Infinity"}` →
     Unmarshal error → dropped.
   - a value that decodes but is non-finite via a lax path (simulate by
     constructing the struct with `&NaN` and calling `Finite()`) → error
     naming the field.
   - valid `{"w": 4500}` and `{}` (nil pointers) → accepted, Finite() nil.
   - the whole `ActiveControl` with a NaN limit → rejected (a NaN export
     cap must NEVER reach the scheduler/optimizer — this is the safety
     payoff).
5. **Optional stretch (note, don't necessarily implement):** a
   rogue-publisher Mayhem probe via mqttproxy `/inject` of
   `{"source":"event","exp_lim_w":"NaN"}` retained — the hub must drop +
   alarm + keep last-good. If TASK-042/043 infra is present it's a few
   lines; otherwise leave as a follow-up (07 marks it optional).
6. `go test -race ./internal/... ./cmd/...`.

## Testing changes
New `internal/bus/nan_reject_test.go`; existing `nan_test.go` (producer
side) unchanged and still green. Run:
`cd ~/projects/lexa-hub && go test -race ./internal/bus/ ./internal/mqttutil/`
and the full `./internal/... ./cmd/...`.

## Documentation changes
- lexa-hub CLAUDE.md: strengthen the NaN invariant line — "…and the DECODE
  layer rejects non-finite numeric input (NaN/Inf, quoted or bare) with an
  alarm; a NaN limit never reaches the optimizer".
- 02 AD-006: note the finite-check as part of reject-and-alarm.
- 06 §3 row (GAP-09) status.

## Common mistakes to avoid
- Don't assume `"NaN"` slips through stdlib — it doesn't into typed fields;
  verify with a quick test first and SCOPE the task to the real residual
  (lax decoders + defense-in-depth + alarm-not-just-drop). Over-engineering
  a custom JSON scanner is wrong for an S task.
- The finite-check must not reject VALID messages: `{}` with all-nil
  pointers is valid (absent values) — `Finite()` skips nil pointers.
- Route to ALARM, not just the existing silent drop — the whole point
  (GAP-09) is that silent drops on non-control topics hide the skew.
- Keep the plain `Subscribe` path backward-compatible; only opted-in decode
  (envelope/hook) adds the finite-check + alarm, or existing callers change
  behavior unexpectedly.
- A NaN in an `ActiveControl` limit is the dangerous case — ensure that one
  is covered and results in the control being dropped (fail-closed to
  last-good), not adopted.

## Things that must NOT change
- Producer-side convention + `nan_test.go` (lexa publishers emit nil, never
  `&NaN`).
- Valid-message decode behavior byte-for-byte (absent-value nil pointers).
- `mqttutil.Subscribe` default semantics for non-opted-in callers.
- Mayhem `nan-sentinel`, `battery-nan-sentinel` verdicts (register-level
  sentinel handling — a different layer; this task is bus JSON, not SunSpec
  registers).
- Fail-closed control-plane discipline (a rejected control holds last-good).

## Acceptance criteria
- [x] Scope grep results in the PR; any lax-decode slip path closed or
      documented as absent.
- [x] `nan_reject_test.go` covers bare + quoted NaN/±Inf across all
      `*float64`-bearing message types, plus the `ActiveControl`-NaN-limit
      safety case; green under `-race`.
- [x] A non-finite value routed to alarm+drop (counter increments) instead
      of silent drop, on an opted-in decode path.
- [x] `go test -race ./internal/... ./cmd/...` green; `nan_test.go`
      unchanged and passing.
- [x] A NaN in an ActiveControl limit provably does NOT reach the
      scheduler/optimizer (dropped, last-good held).

## Regression checklist
- [x] `go test -race ./internal/...` (lexa-hub) green (+ `./cmd/...`)
- [x] Conformance logic tests: none (bus-internal)
- [x] Mayhem: none required (unit-level); optional rogue-publisher probe not
      built (noted as follow-up)
- [x] Producer-side `nan_test.go` untouched and green

## Mayhem scenarios affected
None required. Optional stretch adds a `bus-nan-injection` probe (via
mqttproxy) — if built, 10× solo before curation like any new scenario.

## Conformance implications
None to the wire protocol. Prevents a non-finite value from corrupting a
2030.5-derived control decision (a NaN cap) — strictly safer.

## Suggested commit message
`feat(bus): reject non-finite (NaN/Inf) numeric fields with alarm on decode (GAP-09, TASK-055)`

Trailer: `Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>`

## Suggested PR title & description
**Title:** Bus JSON NaN/Inf rejection + alarm (GAP-09, TASK-055)
**Description:** Pins stdlib's existing rejection of bare/quoted NaN/Inf,
closes any lax-decode slip path (grep results attached), adds a
defense-in-depth `Finite()` check routed to alarm-and-drop (not silent),
and proves a NaN ActiveControl limit never reaches the optimizer. Small,
unit-tested. Rollback: revert; opt-in decode path keeps default behavior.

## Code review checklist
- Scope grep actually run; residual risk closed or shown absent.
- Nil pointers (absent values) never rejected.
- Alarm path wired (counter), not just drop.
- ActiveControl-NaN-limit safety case present and passing.
- Default Subscribe path unchanged.

## Definition of done
Acceptance + regression checklists green; CLAUDE.md/02/06 updated; status
headers updated (this file + 00_MASTER_INDEX).

## Possible follow-up tasks
Optional rogue-publisher Mayhem probe; TASK-018 envelope hardening if not
yet landed; backlog: schema-level numeric range validation (plausibility
gates beyond finiteness).
