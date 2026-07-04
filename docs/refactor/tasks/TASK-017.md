# TASK-017 — Bus message envelope: `v` field + schema-check design (shared types)

*Status: DONE (2026-07-04, lexa-hub@76a0b9d) · Phase: P0 · Effort: M (≈4–6 h) · Difficulty: med · Risk: low*

## Objective
`internal/bus` owns a versioned-envelope convention: an `Envelope` type (`"v"` field)
embeddable in every bus message, a decode-side version check with an explicit
legacy-tolerance policy (absent `v` = v0, accepted during transition), a
reject-and-alarm mechanism (counter + structured log), and tests — designed and landed
as shared machinery **without** changing any live publisher/subscriber (that rollout is
TASK-018).

## Background
Review §8.3: "No schema/version field in bus messages … a rolling upgrade with a changed
JSON shape yields silent zero-values (the XML lesson, unlearned for the bus)." AD-006
decides the shape: every bus JSON carries `"v": N`; subscribers reject unknown majors,
alarm, and (for retained control-plane topics) will eventually trigger re-request
instead of running on zero-values (re-request is TASK-042, P3 — out of scope here).

Verified current state:
- `lexa-hub/internal/bus/messages.go` — ~30 message types (`Measurement`,
  `BattMetrics`, `ActiveControl`, `ComplianceAlert`, `BattCommand`, `SolarCommand`,
  `EVSEState`, `EVSECommand`, `PricingUpdate`+tariff tree, `BillingUpdate`+tree,
  `FlowReservation*`, `DERScheduleMsg`+tree, `PlanLog`/`PlanDecision`); **none** carries
  a version field. Conventions to preserve: `*float64` nil-for-absent, never NaN in
  JSON (`nan_test.go` pins it).
- Decode path: `mqttutil.Subscribe[T]` (mqttutil.go:135-154) json-unmarshals and calls
  the handler; malformed JSON is logged-and-dropped. Valid-JSON-wrong-shape currently
  yields zero-value fields silently — the exact hazard.
- The desired-state document (TASK-025, AD-002) must be "the first new schema born
  versioned" — this task's API is what it will consume; design with that consumer in
  mind (it needs: version constant per schema, not one global).
- Alarm surface: no metrics endpoint exists yet (TASK-044). Alarm = package-level
  atomic counters + one structured log line per (topic, version) signature with
  rate-limiting (don't log per message — a stuck publisher would spam; log on first
  occurrence and every Nth after).

Design decisions to make and record (in code comments + AD-006 update):
1. **Envelope shape:** `type Envelope struct { V int \`json:"v,omitempty"\` }` embedded
   by value in message structs. `omitempty` means v0 legacy publishers and v1 publishers
   are distinguishable (absent vs ≥1); v is never 0 explicitly.
2. **Compatibility policy:** absent `v` ⇒ v0 legacy, accepted while the transition flag
   is on (a package-level default, flipped by TASK-018's completion → later a config).
   `v` greater than the schema's supported version ⇒ reject + alarm. Same-major unknown
   fields ⇒ ignored (Go's default) — additive evolution stays cheap.
3. **Granularity:** per-schema version constants (e.g. `bus.MeasurementV = 1`), all 1 at
   birth; a single global would force lockstep bumps across unrelated schemas.

## Why this task exists
Review §8.3 risk 3 / §14 item 18; AD-006 (decided-pending-validation). Also a hard
prerequisite for the reconciler's desired-state schema (TASK-025) and the NaN-string
hardening (TASK-055).

## Architecture review sections
§8.3, §14 item 18; AD-006; RSK-10 (rolling upgrade); 05 §2 (bus messages are the real
interface); 07 GAP-09 context.

## Prerequisites
TASK-002 (CI). TASK-016 first is preferred (same helper files; avoids conflicts).

## Files
- **Read first:** `lexa-hub/internal/bus/messages.go`, `topics.go`, `nan_test.go`;
  `internal/mqttutil/mqttutil.go` `Subscribe[T]`; AD-006 in
  `docs/refactor/02_ARCHITECTURE_DECISIONS.md`; TASK-025's row in 04 (consumer
  awareness).
- **Modify:** nothing live — `internal/bus` additions only; AD-006 text (bench repo
  docs).
- **Create:** `lexa-hub/internal/bus/envelope.go`, `envelope_test.go`.

## Blast radius
None at runtime (no publisher/subscriber changes in this task — the new code is dead
until TASK-018 wires it). API surface: new exported names in `internal/bus`.

## Implementation strategy
Introduce-only step of introduce→rollout (018)→enforce (post-transition): land the
envelope type, the check function, the counters, and exhaustive table tests; validate
the design against its two imminent consumers (018's call sites, 025's desired-state
doc) on paper in the PR description; update AD-006 from 🔶 toward validated with the
decode-policy table.

## Detailed steps
1. Create `internal/bus/envelope.go`:
   - `type Envelope struct { V int \`json:"v,omitempty"\` }`.
   - Per-schema version constants block (all `= 1`), one per message family that will
     roll out in 018 (measurements, battmetrics, control cmds, evse state/cmd, csip
     control, pricing, billing, FR, schedule, plan log, compliance alert).
   - `func CheckVersion(topic string, payload []byte, supported int) error` — cheap
     peek (`json.Unmarshal` into `struct{ V int }` or a hand scanner; benchmark not
     required, correctness is): returns nil for absent-v while
     `LegacyV0Accepted` (exported package var, default `true`, documented as the
     transition switch), nil for `1 ≤ v ≤ supported`, and a typed
     `*VersionError{Topic, Got, Supported}` otherwise.
   - `func RejectAndAlarm(err *VersionError)` — increments an atomic per-topic counter
     (exported snapshot func `VersionRejects() map[string]uint64` for TASK-044 to
     scrape later) and emits a rate-limited structured log line
     (`[bus] REJECT unknown schema version topic=… v=… supported=…`; first + every
     100th per signature).
2. Tests (`envelope_test.go`, table-driven):
   - absent v / v=1 / v=supported / v=supported+1 / negative / non-integer v /
     malformed JSON (CheckVersion must not mask malformed-JSON — decide + pin: it
     returns nil and leaves malformed detection to the real unmarshal, OR flags it;
     document the choice — recommended: nil, single-responsibility).
   - `LegacyV0Accepted=false` flips absent-v to reject.
   - Counter/rate-limit behavior deterministic (inject a counter threshold or assert
     counts only).
   - JSON round-trip: a struct embedding `Envelope` marshals `"v":1` when set and omits
     when zero; verify no interference with the `*float64`/NaN conventions
     (extend nan-style assertions: an embedded envelope never introduces NaN).
3. Sanity-check the design against consumers (PR text, no code): (a) TASK-018 wiring —
   `mqttutil.Subscribe` will call `CheckVersion` before unmarshal (bus import into
   mqttutil is acyclic: bus imports only stdlib — verified); (b) TASK-025 desired-state
   doc embeds `Envelope` with its own constant, born at 1 with `LegacyV0Accepted`
   irrelevant (new topic, no legacy).
4. Update AD-006 in `docs/refactor/02_ARCHITECTURE_DECISIONS.md` (bench repo): fill in
   the decided decode-policy table (absent=v0-during-transition, unknown-major=
   reject+alarm, retained-control rejection ⇒ hold-last-good now / re-request at
   TASK-042), keep status 🔶 until 018's rolling-upgrade test validates it.
5. `go test -race ./internal/bus/` + full `make test`.

## Testing changes
`internal/bus/envelope_test.go` as above. Run: `go test -race ./internal/bus/`.

## Documentation changes
- AD-006 policy table (bench repo `docs/refactor/02_ARCHITECTURE_DECISIONS.md`).
- `internal/bus` package comment: one paragraph on the envelope convention.
- 00_MASTER_INDEX status.

## Common mistakes to avoid
- Wiring `CheckVersion` into `Subscribe` or stamping publishers here — that's TASK-018;
  this task must be a zero-behavior-change PR (verifiable: no diff outside
  internal/bus + docs).
- One global schema version — forces lockstep bumps; per-schema constants (design
  decision 3).
- `json:"v"` without `omitempty` — every legacy-shape comparison and golden test
  downstream would churn, and v0-vs-v1 becomes indistinguishable.
- Logging every rejected message — alarm fatigue + journald budget (TASK-009);
  rate-limit by signature.
- Designing rejection to drop retained control silently — the policy for control-plane
  topics is documented now (hold-last-good; re-request later) even though enforcement
  lands later; write it in the package comment so 018/042 implementers inherit it.

## Things that must NOT change
- Wire format of every existing message (this PR changes no bytes on the bus).
- `*float64`/no-NaN conventions (`nan_test.go` stays green).
- `mqttutil` behavior (untouched in this task).

## Acceptance criteria
- [x] `internal/bus/envelope.go` + tests merged; `go test -race ./internal/bus/` green.
- [x] Zero diffs outside `internal/bus` + docs (reviewer verifies).
- [x] AD-006 decode-policy table filled in and consistent with the code.
- [x] Design-vs-consumers check (018 wiring, 025 desired-state) written in the PR.

## Regression checklist
- [x] `go test -race ./internal/...` (lexa-hub) green
- [x] Conformance logic tests: unaffected
- [x] Mayhem: none (no runtime change)
- [x] `nan_test.go` untouched and green

## Design-vs-consumers check (written per step 3 of Implementation strategy)

**(a) TASK-018 wiring.** `mqttutil.Subscribe[T]` (mqttutil.go) will call
`bus.CheckVersion(topic, m.Payload(), <family>V)` before the existing
`json.Unmarshal(m.Payload(), &v)`; on a non-nil `*bus.VersionError` it calls
`bus.RejectAndAlarm(err)` and returns without invoking the handler (mirroring
today's malformed-JSON log-and-drop branch). `internal/bus` imports only
`encoding/json`, `fmt`, `log`, `sync`, `sync/atomic` — no import of
`mqttutil` or anything importing it, so `mqttutil → bus` stays acyclic.
Publishers gain one line: stamp `Envelope{V: bus.<Family>V}` into the
outgoing struct before `PublishJSON`/`PublishJSONQoS`. No signature changes
needed on either helper — `Envelope` is embedded by value, so it just adds
fields to the marshaled struct.

**(b) TASK-025 desired-state document.** The new schema embeds `Envelope`
with its own fresh constant (e.g. `bus.DesiredStateV = 1`) exactly like every
family above; `LegacyV0Accepted` is irrelevant to it on day one since there
is no legacy publisher for a brand-new topic — every message it ever emits
carries `v:1` from birth, so its subscriber can pass `supported=1` and never
exercise the absent-`v` branch until this schema's own v2 arrives.

## Mayhem scenarios affected
None yet. `mqtt-malformed-control` / `mqtt-stale-retained` become relevant at TASK-018.

## Conformance implications
None (bus-internal convention).

## Suggested commit message
`feat(bus): versioned message envelope + decode policy + reject-and-alarm machinery (AD-006, design only)`
`Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>`

## Suggested PR title & description
**Title:** Bus envelope: `v` field machinery (no call sites yet)
**Description:** Envelope type, per-schema constants, CheckVersion with v0-transition
tolerance, rate-limited reject counters. Zero behavior change (nothing wired). Policy
table mirrored into AD-006. Rollout = TASK-018; enforcement flip documented. Rollback:
delete the two files.

## Code review checklist
- Policy in code comments == AD-006 table == this task file.
- Per-schema constants, not global. `omitempty` present.
- Malformed-JSON responsibility decision documented in the CheckVersion comment.
- No stray call-site wiring.

## Definition of done
Acceptance criteria + regression checklist + AD-006 updated + status headers updated.

## Possible follow-up tasks
TASK-018 (rollout), TASK-025 (first born-versioned schema), TASK-042 (retained
re-request), TASK-044 (scrape `VersionRejects`), TASK-055 (NaN-string rejection joins
the same decode gate).
