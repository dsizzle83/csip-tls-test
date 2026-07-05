# TASK-023 — Extract the IEEE 2030.5 CSIP data model into lexa-proto/csipmodel

*Status: **DONE (partial)** — csipmodel merged to lexa-proto (product-authoritative
union, zero unresolved conflicts) and both repos flipped; derbase moved +
`device.Measurements` resolved via option (a) type-alias (scope addendum).
Bench-dependent evidence (live gridsim↔hub walk, targeted Mayhem, conformance
regen — steps 6-8) deferred, no bench deploy this session per launch lane
(2026-07-05). lexa-proto `e038885`+`658bf8a`+`5062432`; lexa-hub `12d8893`+`4c030a9`;
csip-tls-test `8ceea12`+`d93174f`; disposition doc
`docs/refactor/notes/TASK-023-model-disposition.md`.
Phase: P1 · Effort: L (≈6–8 h) · Difficulty: high · Risk: med*

## Objective
One package of IEEE 2030.5 XML data-model types (`lexa-proto/csipmodel`) is consumed by
both repos; `lexa-hub/internal/northbound/model` and `csip-tls-test/internal/csip/model`
are deleted. Scope is the **data model only** — walkers, schedulers, identity, DNS-SD
stay repo-local. Client-side unmarshal (product) and server-side marshal (gridsim) both
work from the same structs, proven by both repos' XML round-trip tests and the CSIP
conformance logic suite.

## Background
The 2030.5 model is Go structs with XML tags carrying the mandatory namespace
(`const XMLNamespace = "urn:ieee:std:2030.5:ns"`, and per-type
`xml.Name` tags like `xml:"urn:ieee:std:2030.5:ns DeviceCapability"` —
`model/resources.go` in both repos). The two copies have diverged more than any other
shared package (review D1: the bench fork is stale):

| File | product (`internal/northbound/model`) | bench (`internal/csip/model`) | diff |
|---|---|---|---|
| resources.go | 561 lines | 527 lines | 92 diff lines |
| pricing.go | 161 | 123 | 152 diff lines |
| billing.go | 231 | 54 | 220 diff lines (bench is a stub subset) |
| der.go | 434 | — (absent) | product-only (curves, extended DER controls, status) |
| flowreservation.go | 111 | — (absent) | product-only |
| curves.go | — | 49 | bench-only, BUT its 3 types (`DERCurveData`,`DERCurve`,`DERCurveList`) exist near-identically inside product `der.go` (comment-only diffs verified) |
| resources_test.go | 667 | 348 | both are XML round-trip suites |

Product is richer and newer → product side is merge authority (AD-003). The bench types
are used to **marshal** (gridsim serves 2030.5 XML: `sim/gridsim/{server,extended,malform,
pricing,admin}.go`) while the product **unmarshals** — so any field the bench serializes
that the product model lacks, or any tag difference, will surface as gridsim compile
errors or as changed XML on the wire. Both must be caught here, not in the field.

Verified bench consumers of `internal/csip/model`: `sim/gridsim/*` (5 files),
`internal/csip/discovery/*`, `internal/csip/scheduler/*`, `internal/bridge/*`,
`internal/orchestrator/{model,optimizer,adapters}*` (monolith fork), `cmd/hub/*`
(monolith), `sim/conformance/main.go`, `sim/modsim-client/main.go`,
`tests/{csip_conformance_test,integration_test}.go`. Product consumers: effectively the
whole hub (northbound discovery/scheduler/schedule, cmd/{hub,modbus,northbound,telemetry},
orchestrator, southbound drivers, registry).

Silent-failure hazard: a 2030.5 root element without the namespace unmarshals to a
zero-value struct with **no error** — the XML lesson both CLAUDE.md files pin. Tag edits
are therefore the most dangerous possible diff in this task.

## Why this task exists
W3/D1/D4: the fork is stale and drifting; gridsim (the conformance oracle's server) and
the product (the client under test) parsing from different models undermines what
conformance runs prove. One model makes gridsim-vs-hub disagreements structural
impossibilities instead of latent bugs.

## Architecture review sections
W3, D1, D4, R2, §10.3 (XML robustness), §14 item 4; 02 AD-003; 08 RSK-02 (model variant).

## Prerequisites
- TASK-019 DONE. TASK-020 step 8 may have pre-moved `DERControlBase`/`ActivePower` slices
  into `csipmodel` with aliases — read its disposition doc first.
- TASK-010 status known (monolith consumers extant or gone).

## Files
- **Read first:** both `resources.go` (side-by-side), both `resources_test.go`,
  `sim/gridsim/malform.go` (constructs deliberately-broken XML — depends on model tags),
  `docs/refactor/notes/TASK-020-sunspec-disposition.md` (aliases, if any).
- **Modify:** every importer listed in Background (mechanical import rewrite after the
  merge); both repos' `go.mod`.
- **Create:** `lexa-proto/csipmodel/{resources,der,pricing,billing,flowreservation}.go` +
  merged `resources_test.go` (+ any test files that come along);
  `docs/refactor/notes/TASK-023-model-disposition.md`.
- **Delete:** `lexa-hub/internal/northbound/model/`, `csip-tls-test/internal/csip/model/`.

## Blast radius
The XML wire format between the utility server (real or gridsim) and lexa-northbound —
the product's most safety-relevant input path (fail-closed scheduler consumes what this
model parses). Also gridsim's served XML (the conformance oracle), the conformance
suites, and (transitively) `bus.ActiveControl` construction. No MQTT topics or configs.

## Implementation strategy
Field-level disposition doc first (like TASK-020, but per XML element/tag): product wins
by default; bench-only fields that gridsim actually serializes are ported into the merged
model (union). Then a mechanical move + two consumer-flip commits. XML round-trip tests
from BOTH repos are merged and must pass against the single model before any flip.

## Detailed steps
1. Build the disposition table per file: for each struct field either side has, record
   XML tag, type, and which repo(s) define it. Classify: `identical` / `product-only
   (keep)` / `bench-only (port iff a gridsim file references it — grep)` / `conflict
   (same field, different tag/type — resolve individually; tag conflicts are P1 findings
   because one side is producing/expecting wrong XML today)`.
2. Assemble `lexa-proto/csipmodel` from the product files (`resources.go`, `der.go`,
   `pricing.go`, `billing.go`, `flowreservation.go`), then apply the ported bench-only
   fields. Drop bench `curves.go` (types already in `der.go` — verify field identity,
   comments excepted). Absorb TASK-020 aliases if present.
3. Merge the two `resources_test.go` suites (union of cases; dedupe identical ones).
   `cd ~/projects/lexa-proto && CGO_ENABLED=0 go test ./csipmodel/` green.
4. Flip lexa-hub: rewrite all `lexa-hub/internal/northbound/model` imports to
   `lexa-proto/csipmodel`; delete the package (remove any TASK-020 alias file);
   `make test` green (this exercises walker/scheduler/failclosed/convergence suites —
   the real regression net). One commit.
5. Flip csip-tls-test: rewrite all `csip-tls-test/internal/csip/model` imports
   (gridsim, discovery/scheduler forks, conformance, tests, monolith remnants if
   present); delete the package; `make test-fast` + `go test ./tests/` green. One commit.
6. Wire-format proof: run the CSIP conformance logic suite (`go test ./tests/`) and, on
   the desktop, a live gridsim ↔ hub walk: restart gridsim + confirm
   `curl -s http://69.0.0.1:9100/status` shows an adopted control and
   `journalctl -u lexa-northbound` shows clean walks (no zero-value adoption).
7. Targeted Mayhem (CSIP parse/serve paths):
   `python3 scripts/mayhem.py --dashboard http://localhost:8080 --only malformed-csip,malform-missing-href,malform-empty-program,malform-huge-activepower,malform-bad-duration,malform-pagination,expired-control,conflicting-primacy,pricing-attack,curve-attack`
   — all at baseline verdicts.
8. Full evidence at phase exit: `scripts/run-conformance.sh` (layers 1–3) regenerated if
   this is the last P1 code task to land before TASK-024.

## Testing changes
Merged `csipmodel` round-trip suite (step 3) — the union is the new canonical XML test.
No other new tests. Commands: steps 3–8.

## Documentation changes
- `docs/refactor/notes/TASK-023-model-disposition.md` (the field table).
- Both repos' `CLAUDE.md` directory maps (`internal/csip/` loses `model`;
  `internal/northbound/` loses `model`). Lockstep prose: TASK-024.
- `lexa-proto/CLAUDE.md`: add the XML-namespace invariant prominently.

## Common mistakes to avoid
- Changing any XML tag while merging. A tag typo produces zero-value structs with no
  error at the client and wrong XML at gridsim — the exact silent failure mode this
  codebase already learned about the hard way.
- Widening scope into walker/scheduler: the bench `internal/csip/{discovery,scheduler}`
  are diverged FORKS of product code (D1) — they stay put; only their `model` import
  moves. Leftover fork disposal is TASK-082 (P1 addendum), not here.
- Forgetting `sim/gridsim/malform.go`: it intentionally serves broken XML; after the
  merge its constructions must still compile AND still be broken in the same way
  (the malform-* scenarios' oracles depend on it).
- Letting `gofmt`/field-reordering noise hide semantic diffs in the move commits.

## Things that must NOT change
- **Namespace invariant:** every root element carries `urn:ieee:std:2030.5:ns`
  (`XMLNamespace` const + per-type `xml.Name` tags). Pinned by both round-trip suites.
- Scheduler fail-closed semantics (`internal/northbound/scheduler/scheduler.go`
  last-known-good retention, clock-regression guards incl. the 2026-07-03
  default-fallback half at scheduler.go:196) — consumer code untouched, but its inputs
  come from this model; `failclosed_test.go` must stay green un-edited.
- gridsim's served-XML shape for valid resources (conformance evidence depends on it).
- `plausibleControl`-style limit validation downstream — unchanged.

## Acceptance criteria
- [ ] Disposition doc: zero unresolved `conflict` rows; each ported bench field names the
      gridsim file that needed it.
- [ ] Both model packages deleted; both repos green (`make test` / `make test-fast` +
      `go test ./tests/`).
- [ ] Merged round-trip suite green in lexa-proto.
- [ ] Live gridsim↔hub walk adopts a control (step 6 evidence).
- [ ] 10 targeted CSIP scenarios at baseline verdicts.

## Regression checklist
- [ ] `make test-fast` (csip-tls-test) / `go test -race ./internal/...` (lexa-hub) green
- [ ] Conformance logic tests green (**required** — protocol-adjacent)
- [ ] Mayhem: targeted CSIP set (step 7); full campaign at phase exit
- [ ] Scheduler `failclosed_test.go` green with zero edits

## Mayhem scenarios affected
`malformed-csip`, `malform-missing-href`, `malform-empty-program`,
`malform-huge-activepower`, `malform-bad-duration`, `malform-pagination`,
`expired-control`, `conflicting-primacy`, `pricing-attack`, `curve-attack` — verdicts
must not move.

## Conformance implications
Direct: the model IS the CSIP wire format. Regenerate conformance evidence at phase exit
(`scripts/run-conformance.sh`). Any disposition `conflict` row resolved against gridsim's
current behavior must be re-verified against the spec text, not just against gridsim.

## Suggested commit message
lexa-proto: `feat(csipmodel): merged IEEE 2030.5 data model (product-authoritative) (TASK-023)`
consumers: `refactor(model): consume lexa-proto/csipmodel; delete in-repo model package`
`Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>`

## Suggested PR title & description
**Title:** Phase 1: single 2030.5 data model in lexa-proto (client + server proven)
**Description:** Field-level disposition (linked), union model, merged round-trip suite,
gridsim↔hub live-walk + targeted-scenario evidence. Risk: silent zero-value XML on a tag
slip — mitigated by merged round-trip suite + failclosed suite + malform scenarios.
Rollback: revert either flip commit.

## Code review checklist
- Disposition table vs actual struct diff — no unrecorded field/tag changes.
- No walker/scheduler files touched beyond import lines.
- Round-trip suite covers every root element gridsim serves.
- malform.go still produces the same broken XML (scenario oracles).

## Definition of done
Acceptance criteria + regression checklist; disposition doc committed; status headers
(this file + 00_MASTER_INDEX) updated.

## Possible follow-up tasks
TASK-024 (pin gate); TASK-048 (XML fuzz now targets one model); TASK-082 (leftover fork
disposal — re-point driver forks/modsim-client, delete bench derbase, AD for the csip
discovery/scheduler forks); TASK-080 (curve-function scope — `der.go` curve types now
shared).
