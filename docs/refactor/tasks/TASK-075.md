# TASK-075 — Golden vendor register fixtures + third-party SunSpec referee

*Status: TODO · Phase: P6 · Effort: L (≈8 h + hardware lead time) · Difficulty: med · Risk: med*

## Objective
Byte-exact register images captured from real vendor hardware (≥2
inverters, +1 EVSE OCPP transcript) live as fixtures in the shared
protocol module (`lexa-proto`), replayed in CI against the shared SunSpec
codec; an independent third-party SunSpec implementation (pysunspec2)
cross-decodes the same fixtures as a referee on the bench-repo CI side.
Any divergence between our decode, the referee's decode, and the
datasheet is filed as a P1 bug against lexa-proto. This is the only cure
for the suite's self-confirmation blind spot.

## Background
- The blind spot (§9, GAP-13, RSK-16): the sims' SunSpec codecs and the
  product's SHARE LINEAGE (post-P1 they are literally one module). A
  register-map misunderstanding is bilaterally consistent — every one of
  the ~51 scenarios and all conformance suites pass while real hardware
  is misread. GS-1/MTR-1/MTR-4 audit findings were caught by HUMAN audit,
  not tests; this task builds the mechanical detector.
- Shared module: TASK-019/020/021 created `~/projects/lexa-proto`
  (does not exist yet as of this writing — it is a P1 deliverable; verify
  its layout when starting) holding `sunspec` + derbase layouts. Fixture
  home: `lexa-proto/sunspec/fixtures/` (or `testdata/` per Go convention
  — decide with the module owner; `testdata/` is compiler-ignored and
  idiomatic).
- Codec surface to validate (verified in lexa-hub
  internal/southbound/sunspec pre-extraction): model discovery
  (`HasModel`, layouts incl. 704/705/706 — `ModelDERVoltVar`,
  `ModelDERVoltWatt`), register decode paths (`ReadModel`,
  `Parse705Curve`), scale-factor/multiplier handling (the int16 wrap
  class, GS-1/MTR-1), N/A sentinel 0x8000 handling (scenario
  nan-sentinel exists because of it).
- Referee: `pysunspec2` (the SunSpec Alliance reference implementation,
  Python) — bench-side only dependency (desktop CI runner), never a
  product dependency.
- Hardware: order during P2 (04 §3 Track F; RSK-15 lead-time risk). This
  task file covers: capture procedure, fixture format, replay tests,
  referee harness — executable as soon as hardware arrives; the capture
  can also be EXERCISED against the bench sims immediately (useful
  plumbing test, but sim-derived fixtures prove nothing about the blind
  spot — label them clearly and keep them out of the "vendor" set).

## Why this task exists
GAP-13 ("the suite's deepest epistemic hole"), RSK-16, review item 16,
09 hard gate "Golden vendor fixtures green against shipping lexa-proto."

## Architecture review sections
§9 self-confirmation · GAP-13 · 08 RSK-16/RSK-15 · item 16 · 06 §2
"Hardware / vendor truth" · 09 Conformance.

## Prerequisites
TASK-021 DONE (sims consume shared sunspec — the codec under test is the
shared one). Vendor hardware on hand (ordered in P2). Python 3 on the
desktop CI runner.

## Files
- **Read first:** lexa-proto sunspec package (layouts, reader, models);
  csip-tls-test internal/southbound/sunspec history for GS-1/MTR-1
  context; sim/modsim-conformance (register-behavior expectations);
  docs/HARNESS_REVIEW.md audit notes if present.
- **Modify:** CI config (bench repo + lexa-proto) to run replay + referee
  jobs.
- **Create:** `lexa-proto/sunspec/testdata/vendors/<vendor>-<model>/`
  (raw dumps + metadata.json), capture tool
  `csip-tls-test/cmd/regdump/main.go` (small pure-Go Modbus reader using
  the same simonvetter/modbus dependency), replay test
  `lexa-proto/sunspec/golden_test.go`, referee harness
  `csip-tls-test/scripts/sunspec-referee.py` + CI hook, OCPP transcript
  fixture + replay under the shared ocppserver module (stretch — see
  step 8 gating).

## Blast radius
Test/CI additions only; no product runtime code. lexa-proto gains
testdata + one test file. Findings it produces may open P1 bugs (that is
the point — findings are separate fixes, never batched into this task).

## Implementation strategy
Capture RAW bytes, not interpretations: the fixture is the full SunSpec
address space image (base address sweep: 40000-region "SunS" header +
chained model blocks) plus device metadata (vendor, model, firmware,
datasheet register doc reference, capture date, capture tool version).
Replay = decode the image through lexa-proto and assert against a
HAND-TRANSCRIBED expectation file built from the vendor DATASHEET (the
independent truth), field by field for the models we consume (1, 103/7xx,
common DER models, storage). Referee = pysunspec2 decodes the same image;
a three-way compare (ours vs referee vs datasheet expectations) localizes
whether a mismatch is our bug, a referee quirk, or a vendor deviation.

## Detailed steps
1. `cmd/regdump`: CLI `-addr tcp://IP:502 -unit 1 -out dir/` — discovers
   the model chain (SunS marker, model id/length walk), dumps each model's
   registers as hex + a combined image; refuses to write registers
   (read-only tool); works against modsim first as a plumbing test.
2. Fixture format: `metadata.json` {vendor, model, fw, sunspec_models:[…],
   capture:{date,tool,operator}, datasheet_ref}; `image.bin` (raw
   registers) or per-model `.hex` — pick ONE, document it in the testdata
   README.
3. Expectations: `expected.json` per fixture — decoded field values
   (watts, scale factors, enums, curve points) transcribed from the
   datasheet BY A HUMAN, reviewed. This is the anti-self-confirmation
   step: it must NOT be generated by our codec.
4. `golden_test.go`: for each vendor dir: decode image → compare every
   expected field (exact for ints/enums; scaled floats via the multiplier
   rules); assert byte-exact re-ENCODE where the codec supports write
   paths (encode(decode(image)) == image for writable models — catches
   asymmetric codec bugs).
5. Referee: `sunspec-referee.py` decodes image.bin with pysunspec2, emits
   normalized JSON; a Go/CI step diffs it against our decode's normalized
   JSON (tolerances: none — register decode is exact; scale-factor
   application compared as (value, sf) pairs to avoid float formatting
   noise). Pin the pysunspec2 version in requirements or a vendored
   wheel; bench/CI-side only.
6. CI: lexa-proto job runs golden_test.go on every PR; csip-tls-test
   nightly job runs the referee (needs python — keep it out of the
   product repo's CI).
7. Hardware session (when units arrive): capture each inverter at ≥2
   operating points (idle + generating — some registers only populate
   under load); note per RSK-15 this is the long-lead item; the capture
   session should also feed TASK-064's real plant parameters (ramp/lag
   observations) — record timestamps for that reuse.
8. EVSE OCPP transcript (stretch, gate on time): record one full
   TransactionEvent session (Started/Updated×N/Ended + MeterValues) from
   a real charger against lexa-ocpp (wss per TASK-074); store as a
   replayable transcript test against the shared ocppserver decode. If
   hardware/time absent: file as backlog with the fixture format defined.
9. Any three-way mismatch: open a P1 issue against lexa-proto with the
   fixture + field; do NOT patch the codec in this task.

## Testing changes
golden_test.go (lexa-proto), referee CI job (bench), regdump plumbing
test vs modsim. Run: `go test ./...` in lexa-proto;
`python3 scripts/sunspec-referee.py --all` locally; existing
`sim/modsim-conformance` stays green (unchanged).

## Documentation changes
- testdata README: capture procedure, fixture format, expectations
  discipline ("never generated by our codec").
- 08 RSK-16: mark detection in place; RSK-15 status.
- 06 §2 hardware/vendor-truth row: link the fixtures.

## Common mistakes to avoid
- Generating expected.json from our own decoder (recreates the
  self-confirmation loop this task exists to break).
- Capturing only the sims and calling it done — sim fixtures are plumbing
  tests, clearly labeled, excluded from the 09 gate.
- Letting pysunspec2 become a product or lexa-proto module dependency
  (bench-side referee only; product stays pure Go).
- Fixture drift: images are immutable once captured; codec changes adapt
  the CODEC or (with datasheet justification) expected.json — never the
  image.
- Writing to vendor hardware with the capture tool (read-only enforced in
  code; a stray write to a grid-tied inverter is a safety incident).

## Things that must NOT change
- The shared codec's behavior EXCEPT via separately-reviewed P1 fixes
  that fixtures justify.
- modsim-conformance suites (still the sim-side regression net).
- MTR-4 lockstep discipline for any codec fix that lands (paired deploy).

## Acceptance criteria
- [ ] regdump captures modsim end-to-end (plumbing proof).
- [ ] ≥2 real-inverter fixture sets with human-transcribed expectations
  merged in lexa-proto; golden_test green.
- [ ] Referee job green in nightly CI with pinned pysunspec2; three-way
  compare wired.
- [ ] Any mismatches filed as P1 lexa-proto issues (list in PR).
- [ ] Capture procedure documented well enough to repeat on a third
  device without the author.

## Regression checklist
- [ ] lexa-proto `go test ./...` green
- [ ] `make test-fast` + `sim/modsim-conformance` (all three device
  types) green — codec-adjacent
- [ ] Mayhem: none (no runtime change); full campaign only if a codec
  P1 fix lands (separately)
- [ ] CI jobs green on both repos

## Mayhem scenarios affected
None directly. Indirectly de-risks every scenario (they all trust the
codec); nan-sentinel / solar-bad-scale semantics get vendor-anchored.

## Conformance implications
Strengthens SunSpec conformance claims with vendor-anchored evidence;
feeds the 09 gate and the third-party certification pre-audit (§15).

## Suggested commit message
lexa-proto: `test(sunspec): golden vendor fixtures + datasheet expectations (GAP-13)`
csip-tls-test: `ci(qa): pysunspec2 referee cross-decode + regdump capture tool`
(+ trailer both: `Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>`)

## Suggested PR title & description
**Title:** Golden vendor fixtures + third-party SunSpec referee
**Description:** Read-only capture tool, immutable raw fixtures,
human-transcribed expectations, byte-exact replay + re-encode tests,
pysunspec2 three-way referee in nightly CI. Risk: med (findings expected
— that's the point). Rollback: none needed (additive test surface).

## Code review checklist
- expected.json provenance audit (datasheet refs present, not
  codec-generated).
- regdump provably read-only.
- Referee version pinned; normalization rules exact.

## Definition of done
Acceptance criteria + regression checklist + docs updated + status headers
(this file + 00_MASTER_INDEX) updated.

## Possible follow-up tasks
P1 codec fixes from findings; EVSE transcript replay (if deferred);
TASK-064 plant-parameter values from the capture sessions; third-party
certification engagement (§15 / 09 field-readiness).
