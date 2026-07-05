# TASK-048 — Fuzz XML decode + bus JSON decode (both repos, CI nightly)

*Status: DONE (2026-07-05, csip-tls-test 84b262d / lexa-hub f3d6797) · Phase: P4 · Effort: M (≈4–6 h) · Difficulty: med · Risk: low*

**Landing note:** model types had moved from per-repo `internal/*/model` to
shared `lexa-proto/csipmodel` (TASK-023) and csip-tls-test's walker/scheduler
to `internal/csipref` (TASK-082, AD-003(f), deliberately independent from
lexa-hub) before this task ran — targets placed per the adapted layout: XML
targets live with the consumer that owns the plausibility gate they drive
(lexa-hub `internal/northbound/scheduler`) or, for the bench referee (no gate
exists there — see finding below), with the client-side decode step
(csip-tls-test `internal/csipref/discovery`). Findings (not fixed, filed for
follow-up): `Time.CurrentTime`/`ClockOffset` has no plausibility gate
anywhere in lexa-hub; `internal/csipref/scheduler` has no
plausibleControl-equivalent at all. Both fully detailed in
`06_TESTING_STRATEGY.md`. All 5 fuzz targets ran a clean 5 min locally (0
unresolved crashers); one real bug was found and fixed in the bus fuzz
target's own test helper (case-sensitive JSON key check vs encoding/json's
documented case-insensitive fallback) — see lexa-hub commit message.
5 min/target used instead of the 15 min this file specifies below, per
launch instructions (still ≥ the acceptance bar the launcher set); CI's
nightly jobs run the full 15m/target as this file originally specified.

## Objective
Fuzz the two remaining untrusted decode surfaces: IEEE 2030.5 XML
unmarshalling (product walker/model + bench csip model) and bus JSON
decoding (lexa-hub `internal/bus` types incl. the TASK-017/018 envelope
when present) — asserting not just "no panic" but that the known
namespace-or-zero-value hazard is caught downstream by plausibility gates.
Nightly CI jobs in both repos.

## Background
Two repos, three surfaces (verified):

1. **Product XML** (`~/projects/lexa-hub`): the walker decodes every
   utility response via `xml.Unmarshal(body, dest)` in
   `internal/northbound/discovery/walker.go:516` into types from
   `internal/northbound/model/` (`resources.go`, `der.go`, `pricing.go`,
   `billing.go`, `flowreservation.go`). Known hazard (both CLAUDE.mds):
   a root element missing `xmlns="urn:ieee:std:2030.5:ns"` unmarshals
   into **zero-value structs silently**. Review §10.3: Go's encoding/xml
   is billion-laughs safe (no entity expansion), and plausibility checks
   cover limits — but "zero-value structs from valid-namespace garbage
   still reach the scheduler; `plausibleControl` covers limits only".
   The downstream gate: `scheduler.plausibleControl`/`plausibleLimit`
   (internal/northbound/scheduler/scheduler.go:306–322,
   `maxPlausibleLimitW = 1e9`).
2. **Bench XML** (`~/projects/csip-tls-test`): the sibling model under
   `internal/csip/model/` (gridsim serves it; the conformance client
   parses it). Fuzz the client-side unmarshal there too — the bench is the
   reference implementation the product is tested against.
3. **Bus JSON** (`~/projects/lexa-hub`): every service decodes via
   `mqttutil.Subscribe[T]` → `json.Unmarshal` (mqttutil.go:135–143) into
   `internal/bus/messages.go` types (`ActiveControl`, `Measurement`,
   `BattMetrics`, `EVSEState`, `ComplianceAlert`, `DERScheduleMsg`, …).
   Decode failure is log-and-drop (alarmed on the control topic after
   TASK-042). The envelope `v` field (TASK-017/018) adds a version check —
   fuzz it when present; the target is written to tolerate its absence.

Fuzzing infra precedent: TASK-047 establishes the Makefile `fuzz` target +
nightly CI job shape in lexa-hub; TASK-003's CI hosts the bench repo job.

## Why this task exists
§10.3 (XML robustness caveats), §9 value-domain family, item 10, and the
"XML lesson, unlearned for the bus" (§8.3: no schema/version on bus
messages — 018 fixes, this task proves the decode layer). GAP-09's
`"NaN"`-string work (TASK-055) hardens values; this task hardens structure.

## Architecture review sections
§10.3, §8.3 (bus JSON shape risk), §9 self-confirmation caveat. Roadmap:
03 Phase 4 (nightly fuzz exit criterion); 05 §3 ("silent zero-values are
the enemy") + §7; 06 §3 row "valid-namespace garbage"; 04 row 048 (deps
002, 003).

## Prerequisites
TASK-002 + TASK-003 DONE (CI in both repos). TASK-047 recommended first
(job pattern). TASK-018 NOT required (envelope fuzz added opportunistically).

## Files
- **Read first:**
  - `~/projects/lexa-hub/internal/northbound/discovery/walker.go` (lines 500–530) and `internal/northbound/model/resources.go` (type inventory + doc comments)
  - `~/projects/lexa-hub/internal/northbound/scheduler/scheduler.go` (lines 92–98, 306–322)
  - `~/projects/lexa-hub/internal/bus/messages.go` + `nan_test.go`
  - `~/projects/csip-tls-test/internal/csip/model/` (bench model files)
  - `~/projects/lexa-hub/internal/tlsclient/testdata/` + TASK-047's corpus (real XML bodies to seed from)
- **Modify:**
  - lexa-hub Makefile + CI workflow (extend `fuzz` target/job)
  - csip-tls-test Makefile + CI workflow (add `fuzz` target/job)
- **Create:**
  - `~/projects/lexa-hub/internal/northbound/model/fuzz_test.go`
  - `~/projects/lexa-hub/internal/bus/fuzz_test.go`
  - `~/projects/csip-tls-test/internal/csip/model/fuzz_test.go` (mirror; adjust to the bench model's actual package layout — verify with `ls internal/csip/model/` first)
  - seed corpus dirs `testdata/fuzz/...` in each

## Blast radius
Test-only in both repos (fuzz targets + CI). Any product change comes only
from triaged crashers (each lands as its own reviewed fix with a regression
seed). No runtime behavior changes otherwise.

## Implementation strategy
Property-based fuzz targets around the real decode entry points. XML:
mutate from seeds of REAL 2030.5 documents (DeviceCapability,
DERControlList with events, DefaultDERControl, Time — extract bodies from
TASK-047's captured responses or gridsim directly). Two assertions beyond
no-panic: (a) wrong/absent namespace ⇒ decoded struct is zero-value ⇒ the
harness's "would the scheduler adopt this?" check must answer NO for
controls (drive `plausibleControl` + the scheduler's nil/empty handling);
(b) valid-namespace mutations that decode ⇒ either plausible or rejected —
count and report the "decoded, implausible, but not rejected by any gate"
class as findings (this is the review's stated residual risk; the fuzz
REPORTS it rather than asserts it away — assert only the gates that exist:
limits). Bus JSON: decode each message type from mutated JSON; assert
no-panic, and for types with `*float64` fields assert absent-vs-zero
distinction survives (nil stays nil for absent keys — the silent-zero
lesson applied to JSON).

## Detailed steps
1. **lexa-hub XML target.**
   ```go
   func FuzzUnmarshalDERControlList(f *testing.F)
   func FuzzUnmarshalDeviceCapability(f *testing.F)
   func FuzzUnmarshalTime(f *testing.F) // clock offset feeds utilitytime — high value
   ```
   Each: seeds from real docs + hand-mutants (namespace stripped, namespace
   right but fields garbage, huge multipliers, empty lists). Body:
   `xml.Unmarshal` → if err, done; if ok, run the plausibility pipeline the
   walker/scheduler would (build an `ActiveControl` via the same field
   arithmetic where practical, or call `plausibleLimit` on each
   ActivePower) and assert: namespace-stripped seeds yield zero-values
   (`reflect.DeepEqual(dest, zero)`), and no decoded control with
   |limit| > 1e9 passes `plausibleControl`.
2. **lexa-hub bus target.** `FuzzBusDecode(f *testing.F)` table-driven over
   the message types (one sub-fuzz per type or a type-tag byte prefix):
   `json.Unmarshal` → no panic; re-marshal → decode again → stable
   (round-trip idempotence for accepted inputs); absent numeric keys stay
   nil pointers. Seed with real payloads (copy shapes from messages.go doc
   comments + nan_test.go cases + a captured `lexa/csip/control` payload).
   If the 018 envelope has landed, include unknown-`v` seeds and assert
   reject path.
3. **csip-tls-test XML target.** Mirror step 1 against the bench model
   (`internal/csip/model`) for DERControlList + DeviceCapability. This
   catches PARSER divergence between the twins before P1's shared module
   lands (W3) — if a mutant decodes differently across repos, that is a
   finding; add a note comparing outputs for the shared seed corpus (a
   small cross-check test reading the same seeds committed to both repos).
4. **Local runs:** 15 min per target
   (`go test -fuzz=FuzzUnmarshalDERControlList -fuzztime=15m ./internal/northbound/model/` etc.).
   Triage: panics/OOMs = fix inline if trivial (with regression seed) or
   file; "decoded-but-implausible-and-ungated" = record in the PR as input
   to TASK-018/TASK-025 plausibility widening (do NOT widen gates ad hoc
   here — scheduler is radioactive).
5. **CI:** extend lexa-hub nightly fuzz job (TASK-047) with the two new
   targets; add the csip-tls-test nightly job (same shape) to TASK-003's
   workflow. `make test-fast` in the bench repo must remain <1 s —
   fuzz targets run only under `-fuzz`, their unit-mode seed checks are
   fast (verify).
6. Commit shared seed corpus to both repos
   (`testdata/fuzz/shared-2030_5/*.xml` — same files, lockstep note in both
   commit messages).

## Testing changes
All changes ARE tests: three fuzz files + corpora + CI jobs. Run commands:
- `cd ~/projects/lexa-hub && go test -fuzz=FuzzBusDecode -fuzztime=15m ./internal/bus/`
- `cd ~/projects/lexa-hub && go test -fuzz=FuzzUnmarshalDERControlList -fuzztime=15m ./internal/northbound/model/`
- `cd ~/projects/csip-tls-test && go test -fuzz=FuzzUnmarshalDERControlList -fuzztime=15m ./internal/csip/model/`
- Seed-only mode (CI PR lane): plain `go test ./...` runs seeds as unit
  cases.

## Documentation changes
- 06_TESTING_STRATEGY §3 row status; 02 AD-006 note if envelope fuzz
  landed. Record the "decoded-but-ungated" findings list location
  (PR link) in 07 GAP notes if any were found.

## Common mistakes to avoid
- Asserting plausibility gates that don't exist: `plausibleControl` covers
  the four `OpMod*LimW` limits ONLY (scheduler.go:306–312). Do not invent
  assertions about intervals/other fields — report those cases instead
  (the review explicitly flags them as residual).
- Fuzzing through the network/walker: the target is `xml.Unmarshal` + pure
  downstream checks — no fetcher, no CGo, no bench dependency.
- Zero-value comparison must use a FRESH zero of the exact dest type
  (watch embedded Link structs with pointers).
- Bench repo: `make test-fast` speed budget (<1 s) — keep seed corpora
  small (dozens, not thousands).
- Don't let `go test -fuzz` corpus writes (`testdata/fuzz/.../`) leak junk
  into commits — commit curated seeds + crashers only.
- Lockstep: the shared seed corpus ships to both repos in the same session
  (05 §11).

## Things that must NOT change
- Scheduler/walker/model production code untouched in this task (crasher
  fixes go in separate reviewed commits; scheduler is radioactive-zone).
- The namespace-or-zero-value behavior itself is NOT "fixed" here — it is
  the documented hazard the gates + this fuzz watch (CLAUDE.md invariant:
  "every 2030.5 root element needs xmlns=… or unmarshal silently yields
  zero-value structs").
- `mqttutil.Subscribe` decode semantics (log-and-drop + TASK-042 hook).
- Mayhem `malformed-csip`, `curve-attack`, `pricing-attack`,
  `mqtt-malformed-control` verdicts (same fault family at HIL level).

## Acceptance criteria
- [ ] Five fuzz targets total (3 lexa-hub, 2+ csip-tls-test) with committed
      seed corpora incl. real 2030.5 documents.
- [ ] 15 min/target locally: zero unresolved crashers (fixes have
      regression seeds + their own commits).
- [ ] Namespace-stripped seeds provably yield zero-values and are provably
      non-adoptable as controls (test assertion, not prose).
- [ ] Nightly CI jobs green in both repos; PR-lane seed checks add <5 s.
- [ ] Cross-repo shared-seed decode-equivalence check passes (or divergence
      filed as a W3 finding).

## Regression checklist
- [ ] `make test-fast` (csip-tls-test) still <1 s and green; `go test -race ./internal/...` (lexa-hub) green
- [ ] Conformance logic tests green (`go test ./tests/`) — same model types
- [ ] Mayhem: none (test-only), unless a crasher fix touched product code →
      targeted scenarios for that path
- [ ] No stray fuzz-generated corpus files in the diff

## Mayhem scenarios affected
None directly. `malformed-csip`/`curve-attack`/`pricing-attack` are the HIL
siblings; any crasher fix re-runs them.

## Conformance implications
Decode equivalence between product and bench models is a pre-P1 (W3/MTR-4)
early-warning — divergences found here feed TASK-020's reconciliation.

## Suggested commit message
Per repo:
`test(fuzz): 2030.5 XML + bus JSON fuzz targets, seeds, nightly CI (TASK-048)`
(bench) `test(fuzz): csip model XML fuzz + shared 2030.5 seed corpus (TASK-048)`

Trailer: `Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>`

## Suggested PR title & description
**Title:** Fuzz XML + bus JSON decode surfaces, nightly in CI (TASK-048)
**Description:** Paired PRs (lockstep seeds). Asserts the
namespace-zero-value hazard is gated for controls, bus decode never panics
and preserves absent-vs-zero, and product/bench parsers agree on shared
seeds. Findings: <list crashers/ungated-decodes>. Rollback: revert;
test-only.

## Code review checklist
- Assertions match gates that actually exist (no aspirational oracles).
- Seeds are real-document derived; provenance noted.
- CI time budget respected; PR lane fast.
- Paired PRs reference each other.

## Definition of done
Acceptance + regression checklists green; 06 updated; status headers
updated (this file + 00_MASTER_INDEX).

## Possible follow-up tasks
TASK-018 (reject-and-alarm envelope — consumes the ungated-decode findings),
TASK-020/023 (shared model kills the dual-parser problem), TASK-055
(value-level NaN hardening).
