# TASK-053 — Generative int16/scale-factor boundary sweep test

*Status: DONE (2026-07-05) · Phase: P4 · Effort: L (≈6–8 h) · Difficulty: med
· Risk: med*

**Commits (all on branch `task/053-int16-sweep`, unmerged — three-repo
lockstep, review pending):**
- `lexa-proto` 95ebde6 — canonical sweep + fuzz targets
- `lexa-hub` d6ea74a — vendored-copy wrapper test + encoder sweep/agreement
- `csip-tls-test` (this repo) — vendored-copy wrapper test + `apFromWatts` sweep

**Disposition note:** ran POST-021 (TASK-021 DONE — shared codec confirmed
live in both consumers via vendored `lexa-proto/sunspec`), so the dual-fork
equivalence-mode contingency (step 5) did not apply; no divergence to file.

lexa-proto is unhosted and has no CI of its own, so a literal "one test,
both CIs automatically" (the task's original framing) is not achievable
until it is hosted (tracked in 00_MASTER_INDEX P1 notes: "create
dsizzle83/lexa-proto"). `go mod vendor` correctly excludes a dependency's
`_test.go` files, and there is no remote for a hosted runner to check out.
Deviation: the canonical sweep lives in `lexa-proto/sunspec` as exported
`Sweep*` helpers (production file, vendorable) + `lexa-proto`'s own
`scale_sweep_test.go`; each consumer runs the identical contract against
its OWN vendored copy via a thin wrapper test package
(`internal/southbound/sunspecsweep`, this repo and lexa-hub). No CI/Makefile
step changes were needed to *execute* it — `scripts/qa-regression.sh` /
`make test-southbound` (this repo) and `make test-nocgo` (lexa-hub) already
glob the packages the new tests landed in (verified locally, see Testing
changes below); added documentation-only CI comments + a `make
sweep-sunspec` convenience target in both repos.

Step 3 (product watt-encoders, encode-scaling + cross-encoder agreement):
lexa-hub's `wattsToActivePower` (`cmd/hub/state.go`) /
`activePowerFromWatts` (`cmd/modbus/main.go`) swept 0..1e9 W each and proven
to agree via a shared golden expected-value table (the two functions live
in separate `package main`s — different binaries — so they cannot be
called from one test; matching the same literal table in both test files
is the cross-repo-style proof, computed once, not hand-derived per file).
This repo's own product-analogous encoder, `sim/gridsim.apFromWatts`, was
swept ±1e9 W on its own contract (integer-truncation precision bound, not
the hub's round-to-nearest) — there is no second encoder in this repo to
cross-check against.

Supplementary generative coverage: two native Go fuzz targets
(`FuzzScaleRoundTripSigned`, `FuzzScaleClampSigned`) added in lexa-proto,
run locally 5 minutes each — 32,881,421 and 32,555,416+ executions
respectively (~65M total), 0 crashers. Not wired into any CI (lexa-proto has
none) pending the hosting flip; the required PR-lane property stays the
deterministic sweep per the task's own "not -fuzz" guidance.

## Objective
Add a property-based generative test that sweeps the full int16 register
range × every plausible SunSpec scale factor against the SHARED sunspec
codec (post-TASK-021): encode→decode round-trips and wrap/clamp behavior,
catching the GS-1/MTR-1 boundary-overflow bug class that was found by audit,
not by test. Runs in both repos' CI.

## Background
Two repos share the SunSpec codec — the whole point of TASK-020/021's shared
module (`lexa-proto`). Until then the codec is duplicated and **already
diverged** (W3: `internal/southbound/sunspec/{der1547,models,reader}.go`
differ between repos; `layout.go`/`derlayout.go` product-only — confirmed by
`diff -rq`). The scale helpers (verified in
`~/projects/lexa-hub/internal/southbound/sunspec/scale.go`, mirrored in
`~/projects/csip-tls-test/internal/southbound/sunspec/scale.go`):
- `ApplyScaleSigned(raw uint16, sf int16) float64` — `int16(raw) × 10^sf`;
  returns NaN only when the SCALE FACTOR is the sentinel
  (`sf == notImplemented = int16(-32768)`). Raw `0x8000` at a normal sf is
  an ordinary value: `ApplyScaleSigned(0x8000, 0) == -32768.0`, not NaN.
- `ApplyScaleUint(raw uint16, sf int16) float64`.
- `RawFromScaleSigned(val float64, sf int16) uint16` — rounds, **clamps to
  int16 range** (MaxInt16/MinInt16).
- `RawFromScaleUint(val, sf) uint16` — clamps [0, MaxUint16], negatives → 0.

The bug class (GS-1/MTR-1, both CLAUDE.mds): "int16 watt fields wrap at
±32,767 — scale into the SunSpec multiplier, never raw-cast." The product's
`wattsToActivePower` (cmd/hub/state.go:397–404) and modbus'
`activePowerFromWatts` (cmd/modbus/main.go ~280–300) do the multiplier
scaling; the sunspec `RawFrom*` functions are the register-level codec. A
value that overflows int16 at a given scale must either scale up the
multiplier (encode side) or clamp predictably — never silently wrap to a
wrong sign/magnitude.

**Dependency on TASK-021:** the test targets the SHARED module so it can't
be bilaterally-consistent-but-wrong on divergent forks. Per 04, 053 depends
on 021. If run before 021 (both forks still exist), the test must run
against BOTH copies and assert they agree (a cross-fork equivalence sweep) —
which is itself valuable (it would have caught the current divergence).
State which mode in the PR.

Review §9 self-confirmation caveat: sim and product share codec lineage, so
this test proves round-trip/clamp CORRECTNESS of the codec, not that the
codec matches real hardware (that's golden fixtures, TASK-075). Scope this
test to codec self-consistency + the documented wrap/clamp contract.

## Why this task exists
GAP-07 / §9 value-domain family: "±32,767 W crossings under every scale
factor is exactly what a generative test proves and a human audit misses."
GS-1/MTR-1 were audit finds; this converts them to a standing property test.

## Architecture review sections
§9 value-domain family, W3 (shared codec), item 16-adjacent. Roadmap:
07 GAP-07 (validation: "encode→decode round-trip and clamp/multiplier
behavior across the full int16 range × scale factors; runs in CI");
04 row 053 (depends 021).

## Prerequisites
TASK-021 DONE (shared sunspec module) — else run in dual-fork equivalence
mode. Both repos' CI (TASK-002/003). No bench.

## Files
- **Read first:**
  - `~/projects/lexa-hub/internal/southbound/sunspec/scale.go` + `scale_test.go`
  - `~/projects/lexa-hub/internal/southbound/sunspec/der1547.go`, `models.go` (register encode/decode of power fields)
  - `~/projects/lexa-hub/cmd/hub/state.go` (`wattsToActivePower`, lines 397–404) and `cmd/modbus/main.go` (`activePowerFromWatts`, ~280–300)
  - `~/projects/csip-tls-test/internal/southbound/sunspec/scale.go` (the fork, for the dual-mode case)
  - the shared module location once TASK-019/021 create it (working name `lexa-proto`)
- **Modify:** CI workflows in both repos to run the sweep (fast — it's a
  property test with bounded iterations, not fuzz).
- **Create:**
  - the sweep test in the shared module's sunspec package
    (`scale_sweep_test.go`), OR — pre-021 — a `scale_sweep_test.go` in each
    repo's `internal/southbound/sunspec/` plus a cross-fork equivalence
    test.

## Blast radius
Test-only. Any product change comes solely from a bug the sweep uncovers
(each fixed in its own reviewed commit; the sunspec codec is
lockstep-sensitive — MTR-4). No runtime behavior otherwise.

## Implementation strategy
A table/loop generative test (not `go test -fuzz` — an exhaustive-ish
deterministic sweep is more appropriate and CI-fast): for every scale factor
in a realistic set (`sf ∈ [-3, +4]` covers watts/scaled-kW; include the
`notImplemented` sentinel as a special case) and a dense sample of the int16
domain (all 65536 raw values is cheap; or every value + boundary
neighborhoods), assert the codec's documented contract.

## Detailed steps
1. **Round-trip property** (signed + uint): for raw `r` across the full
   uint16 range and each `sf`:
   `decode = ApplyScaleSigned(r, sf)`; `re = RawFromScaleSigned(decode, sf)`;
   assert `re == r` **except** where `decode` is NaN (sentinel) or where the
   scaled value exceeds the representable range at that sf (document and
   assert the clamp instead). This pins that the codec is a faithful
   inverse where it claims to be.
2. **Wrap-guard property** (the GS-1/MTR-1 core): for a sweep of float watt
   values crossing ±32,767 at each sf, assert `RawFromScaleSigned`
   **clamps** (never wraps to the opposite sign): the decoded value of the
   result must have the same sign as the input and be monotonic-nondecreasing
   in |input| up to the clamp — never a sign flip. Explicitly include
   32767, 32768, 32769, -32768, -32769, 65535, 65536 at sf=0 and the
   scaled equivalents at other sfs.
3. **Encode-scaling property** (the product's watt→ActivePower path): sweep
   watt values from 0 to 1e9 through `wattsToActivePower` /
   `activePowerFromWatts` and assert `Value` stays in int16 and
   `Value × 10^Multiplier` reconstructs the input within half a scale step
   (the documented precision bound, state.go:395–396). Verify the two
   product encoders AGREE for shared inputs (they must — MTR-5/GS-1).
4. **Sentinel handling:** the sentinel applies to the sf argument:
   `ApplyScale*(anyRaw, -32768) == NaN` and `RawFromScale*(v, -32768) == 0`;
   raw `0x8000` at a normal sf decodes to −32768 and must round-trip
   exactly; value-level N/A handling lives above the scale helpers, not in
   them. Encoding NaN/±Inf must not produce a spurious sentinel or wrap —
   assert the encoders' behavior (they clamp; verify).
5. **Cross-fork equivalence (pre-021 only):** run the same sweep against
   both repos' `ApplyScale*`/`RawFrom*` and assert identical outputs; ANY
   divergence is a W3/MTR-4 finding — file it and reconcile via TASK-020
   (do not silently pick a side here).
6. Location: post-021, one test in the shared module runs in both repos' CI
   automatically. Pre-021, commit the sweep to both repos (lockstep,
   same session) + the equivalence test.
7. CI: ensure the sweep runs in the standard `go test ./...` lane (it is
   fast — bound iterations so it stays <1 s to respect `make test-fast`).

## Testing changes
The deliverable IS the test. Run:
- `cd ~/projects/lexa-hub && go test ./internal/southbound/sunspec/ -run Sweep`
- `cd ~/projects/csip-tls-test && go test ./internal/southbound/sunspec/ -run Sweep`
- (post-021) the shared module's `go test ./sunspec/`.
Keep runtime <1 s (the bench repo's `make test-fast` budget).

## Documentation changes
- 06_TESTING_STRATEGY §3 row status (GAP-07 covered).
- If cross-fork divergence is found, record it in the TASK-020 notes /
  02 as an input to reconciliation.
- CLAUDE.md GS-1/MTR-1 invariant lines: add "regression-swept by TASK-053".

## Common mistakes to avoid
- Do not "fix" a divergence by editing one fork to match the other in THIS
  task — codec changes are MTR-4 lockstep and belong to TASK-020's reviewed
  reconciliation; here you FIND and FILE.
- The round-trip is NOT a perfect bijection everywhere: at large sf, many
  raw values map to non-integer-reconstructable floats — assert the
  contract (clamp/round to nearest, documented precision), not naive
  equality; scale_test.go already encodes the expected rounding — align with
  it.
- The property test MUST NOT "fix" the scale helpers to treat raw 0x8000
  as NaN — the sentinel guards the sf argument only; raw 0x8000 at a
  normal sf IS an ordinary int16 (−32768) and both repos' codecs (and the
  register maps mirrored in lexa-hub) depend on that. Such a "fix" would be
  a bilateral register-semantics regression (MTR-4 lockstep).
- Keep it deterministic + fast (bounded loop), not `-fuzz` — this must run
  in every PR lane, not just nightly.
- uint vs signed: meter/inverter power fields are signed (import/export,
  charge/discharge); nameplate/capacity are unsigned — sweep both codecs
  with their correct signedness.
- Lockstep: pre-021, both repos' copies land in the same session.

## Things that must NOT change
- `scale.go` codec behavior (unless the sweep proves a bug — then a separate
  MTR-4-lockstep fix commit, not this test).
- The documented wrap/clamp/precision contract (this test PINS it).
- `wattsToActivePower` / `activePowerFromWatts` behavior (swept, not
  changed).
- GS-1/MTR-1/MTR-5 invariants (both CLAUDE.mds) — the test enforces them.

## Acceptance criteria
- [x] Sweep test present (shared module post-021); `lexa-proto/sunspec`
      runs in 0.02s, both consumers' vendored-copy wrapper tests run in
      ~1.1s each (dominated by `-race` build overhead, not sweep logic).
- [x] Round-trip, wrap-guard (no sign flip across ±32767 at every sf),
      encode-scaling, and sentinel properties each asserted — zero
      violations found (codec was already correct; no fix commit needed).
- [x] Product's two watt-encoders proven to agree on shared inputs (lexa-hub
      golden table, cmd/hub/state_test.go + cmd/modbus/control_test.go).
- [x] CI (both repos) runs the sweep on every PR, green — via existing
      globs (`make test-nocgo` / `scripts/qa-regression.sh` +
      `test-southbound`), verified locally; no codec bug found.
- [ ] Pre-021 mode: N/A — ran post-021 (TASK-021 already DONE at task start).

## Regression checklist
- [x] `make test-fast` (csip-tls-test) still <1 s and green (0.005s, unchanged)
- [x] `go test -race ./internal/southbound/...` (both repos) green
- [x] Conformance logic tests green (`go test ./tests/`) — codec-adjacent
- [x] Mayhem: none run — unit-level only, zero codec bugs found so no
      control path was touched (regression trigger condition not met)

## Mayhem scenarios affected
None directly. HIL siblings that exercise scale/sentinel handling:
`solar-bad-scale`, `nan-sentinel`, `battery-nan-sentinel`,
`ev-wrong-units` — re-run those if a codec fix results.

## Conformance implications
SunSpec register encoding correctness at boundaries is conformance-relevant
(GS-1/MTR-1). The sweep is a pre-audit for the golden-fixture work
(TASK-075) — but proves self-consistency only, NOT hardware fidelity
(§9 self-confirmation caveat; that gap is closed by 075).

## Suggested commit message
`test(sunspec): generative int16 × scale-factor boundary sweep (GAP-07, TASK-053)`

Trailer: `Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>`

## Suggested PR title & description
**Title:** Generative int16/scale-factor boundary sweep for the SunSpec codec (TASK-053)
**Description:** Standing property test over the full int16 range × scale
factors: round-trip, wrap-guard (no sign flip across ±32767), encode
scaling, sentinel handling — the GS-1/MTR-1 class as a test, not an audit.
Targets the shared codec (post-021) or both forks + equivalence (pre-021).
Fast, runs every PR. Findings: <list>. Rollback: revert; test-only (any
codec fix is a separate lockstep commit).

## Code review checklist
- Asserts the documented clamp/round contract, not naive bijection.
- Sentinel (sf == −32768) handled explicitly — on the sf argument, not raw
  values; signedness correct per field.
- Runtime <1 s; runs in PR lane not just nightly.
- Any codec divergence FILED, not silently reconciled.

## Definition of done
Acceptance + regression checklists green; 06/CLAUDE.md updated; status
headers updated (this file + 00_MASTER_INDEX).

## Possible follow-up tasks
TASK-020 (reconcile any divergence the sweep exposes), TASK-075 (golden
vendor fixtures — hardware fidelity the sweep cannot prove), backlog:
extend the sweep to VA/VAR/A derived registers (MTR-5).
