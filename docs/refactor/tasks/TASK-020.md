# TASK-020 — Reconcile the diverged sunspec/derbase forks; extract to lexa-proto; lexa-hub consumes

*Status: TODO · Phase: P1 · Effort: L (≈6–8 h) · Difficulty: high · Risk: **high***

## Objective
One authoritative SunSpec codec (`sunspec` + its `modbus` Transport dependency) and one
CSIP→SunSpec translation layer (`derbase`) live in `lexa-proto`; `lexa-hub` imports them
via `go.work` and its in-repo copies are deleted; a written diff-inventory records, for
every divergent register/point/behavior between the two repos' forks, which side won and
why. The bench repo still uses its fork (flipped in TASK-021).

## Background
Both repos carry `internal/southbound/sunspec` and `internal/southbound/derbase`. They are
NOT the same code drifted a little — they are **two codec generations**:

- **Product (`~/projects/lexa-hub`)** — rewritten on a declarative layout engine:
  `layout.go` (430 lines) + `derlayout.go` (302) define register layouts; `der1547.go`
  (728) is typed parse/encode for SunSpec DER models 701–714 on top of them; `models.go`
  (313). Product-only tests: `der1547_roundtrip_test.go`, `derlayout_test.go`.
  `derbase/derbase.go` (738 lines) maps CSIP `DERControlBase` operating modes to model-704
  writes plus the §3.1.2 curve adopt workflow; `derbase_csip_test.go` is product-only.
- **Bench (`~/projects/csip-tls-test`)** — the older hand-rolled generation: `der1547.go`
  (948 lines) with per-model structs and offset helpers (`CurveBase705` etc.), `models.go`
  (611). `derbase/derbase.go` (737) is the older mapping (models 701–712, no curve adopt
  workflow documented).
- **Identical modulo import path** (verified by diff): `reader.go`, `scanner.go`,
  `reader_test.go`, `scale.go`, `scale_test.go`, and the whole
  `internal/southbound/modbus` package (`transport.go`, 79 lines) which `sunspec` imports.

History: bench fork last touched by `8b3bed7` ("Restructure sim/ layout and extend Modbus
stack to IEEE 1547-2018") and `b31e5e6`; product side by `31948ac` (both repos share the
"Debugging the hub after simulation results over 3 month time frame" QA-arc commit — under
different SHAs). Per AD-003 the **product side is merge authority**, but any register-map
semantic where the bench side disagrees may encode a real fix (the sims run against the
bench fork daily) — every disagreement needs an explicit disposition.

`derbase` imports the 2030.5 model package (`lexa-hub/internal/northbound/model`) for
`DERControlBase`/`ActivePower`. TASK-023 moves that model to `lexa-proto/csipmodel`; to
keep this task self-contained, `lexa-proto/derbase` may temporarily keep importing
`lexa-hub/internal/northbound/model` **only if** the module remains buildable — it does
not: a module cannot import another module's `internal/`. Therefore this task moves the
minimal model types `derbase` needs by moving `derbase` LAST (step 8) or doing TASK-023
first. The steps below handle it by extracting `sunspec`+`modbus` first (no model
dependency: verified — only `derbase` imports the model) and gating the `derbase` move on
TASK-023 if it lands first, else moving `DERControlBase`/`ActivePower` and friends into
`lexa-proto/csipmodel` as a forward slice of TASK-023.

## Why this task exists
W3/D4: the lockstep rule already failed; a one-sided register-map change misreads real
hardware (audit MTR-4) and, because sims and product share codec lineage, the misread is
bilaterally invisible (§9 self-confirmation, RSK-16). One shared codec kills the class.
RSK-02 names this task's specific hazard: a wrong-side merge.

## Architecture review sections
W3, D4, R2, §9 self-confirmation, §14 item 4; 02 AD-003; 08 RSK-02/RSK-16; 07 GAP-07/GAP-13.

## Prerequisites
- TASK-019 DONE (`lexa-proto` skeleton + go.work in both repos).
- Bench available for validation (FAST mode: `bash scripts/bench-up.sh --fast`).

## Files
- **Read first:**
  - `/home/dmitri/projects/lexa-hub/internal/southbound/sunspec/` (all files, esp. `layout.go`, `derlayout.go`, `der1547.go`)
  - `/home/dmitri/projects/csip-tls-test/internal/southbound/sunspec/der1547.go` and `models.go`
  - both repos' `internal/southbound/derbase/derbase.go`
  - `/home/dmitri/projects/lexa-hub/internal/southbound/CLAUDE.md` and the bench twin
- **Modify:** `lexa-hub/go.mod` (require lexa-proto), all lexa-hub importers of the moved
  packages: `internal/southbound/{battery,inverter,meter}/*.go`, `cmd/modbus/*` (via
  drivers), `internal/southbound/derbase` importers.
- **Create:** `lexa-proto/{modbus,sunspec,derbase}/*.go` (moved code);
  `docs/refactor/notes/TASK-020-sunspec-disposition.md` (the inventory, in csip-tls-test).
- **Delete:** `lexa-hub/internal/southbound/{sunspec,derbase,modbus}` (after flip).

## Blast radius
lexa-hub southbound stack: every Modbus register read/write the product performs goes
through the moved code (`registry` → drivers → `derbase` → `sunspec` → `modbus`). Bench
repo: no code change, but hub redeploy means hub↔sim interop is revalidated. Public APIs:
package import paths only. Config/topics: none.

## Implementation strategy
Inventory first, then a mechanical move of the product side, then consumer flip in one
commit — never editing codec logic and moving it in the same commit. Disposition of bench
divergences is a *review artifact*, not a code merge: the product generation wins
structurally; the review checks the bench fork for register-semantic fixes the product
lacks, and any found are ported as separate, individually-tested commits BEFORE the move.

## Detailed steps
1. Produce the raw diff evidence:
   `diff -rq ~/projects/lexa-hub/internal/southbound/sunspec ~/projects/csip-tls-test/internal/southbound/sunspec`
   and the same for `derbase`. Record in the disposition doc.
2. Build the semantic inventory (the real work). For each SunSpec model/point either side
   touches (103/121/123/802, 701–714), tabulate: register offset, scale-factor handling,
   sign convention, N/A-sentinel handling — product value vs bench value. Sources:
   product `derlayout.go`+`der1547.go`; bench `der1547.go`+`models.go`. Differences in
   *structure* (layout engine vs structs) are expected; flag only **semantic** disagreements
   (offset, scaling, enum meaning, write sequence).
3. For each semantic disagreement run `git log -p --follow` on both sides' file to find
   which change was a deliberate fix (QA-arc commits cite scenarios). Disposition column:
   `product` (default) / `port-from-bench` (bench encodes a fix) / `investigate`.
   Zero `investigate` rows may remain at the end.
4. Port any `port-from-bench` rows into the product code as individual commits in
   lexa-hub, each with a regression test in the product suite, BEFORE any move. Run
   `make test` after each.
5. Move `internal/southbound/modbus` → `lexa-proto/modbus` (git mv across repos: copy +
   delete; preserve the file content byte-exact apart from the package import path).
   Commit in lexa-proto.
6. Move `internal/southbound/sunspec` (product side, all 11 files) → `lexa-proto/sunspec`;
   rewrite its `lexa-hub/internal/southbound/modbus` import to `lexa-proto/modbus`.
   `cd ~/projects/lexa-proto && CGO_ENABLED=0 go test ./...` — the moved
   `reader_test.go`/`scale_test.go`/`derlayout_test.go`/`der1547_roundtrip_test.go` must pass.
7. Flip lexa-hub: add `require lexa-proto v0.0.0` (go.work resolves it), rewrite every
   `lexa-hub/internal/southbound/sunspec|modbus` import to `lexa-proto/...`, delete the two
   in-repo package dirs. One commit. `make test` green.
8. `derbase`: if TASK-023 is DONE, move product `derbase` to `lexa-proto/derbase`
   (imports `lexa-proto/{sunspec,csipmodel}`), flip lexa-hub, delete in-repo copy.
   If TASK-023 is NOT done, first move only the types `derbase` references
   (`DERControlBase`, `ActivePower`, and their direct field types — enumerate by compiler
   error) from `internal/northbound/model` into `lexa-proto/csipmodel` with type aliases
   left behind in the product model package (`type ActivePower = csipmodel.ActivePower`)
   so nothing else moves yet; then move `derbase`. Record the aliases in the disposition
   doc for TASK-023 to consume.
9. Bench validation: `cd ~/projects/lexa-hub && make build-arm64` (rebuild wolfSSL sysroot
   first if `/tmp/wolfssl-arm64-sysroot` is missing: `make wolfssl-arm64`), deploy
   `bash scripts/deploy-hub-pi.sh 69.0.0.1 dmitri`, then **re-run
   `bash ~/projects/csip-tls-test/scripts/hub-replay-tune.sh fast`** (deploy resets timing
   to STOCK). Verify `curl -s http://69.0.0.1:9100/status` shows plausible W/SoC for all
   three devices vs each sim's `curl -s http://69.0.0.x:60xx/state`.
10. Run bench conformance against all three sims (binaries from THIS repo, unchanged):
    `bin/modsim-conformance -server 69.0.0.10:5020 -device inverter` and battery (.11:5021)
    / meter (.12:5022) — device flag values: `inverter|battery|meter`.
11. Full Mayhem FAST campaign: `python3 scripts/mayhem.py --dashboard http://localhost:8080`.
    Compare against the V6 baseline (0.6 FAIL/cycle, 0 BLIND).

## Testing changes
Moved test files keep running inside lexa-proto (`CGO_ENABLED=0 go test ./...`). Any
`port-from-bench` fix lands with its own regression test. No bench-repo test changes.
Commands: as in steps 6/7/10/11 plus `cd ~/projects/lexa-hub && make test`.

## Documentation changes
- `docs/refactor/notes/TASK-020-sunspec-disposition.md` — the inventory + dispositions
  (this is TASK-024's and TASK-075's reference).
- `lexa-proto/CLAUDE.md`: note sunspec/derbase now live here; GS-1/MTR-1 multiplier rule.
- Do not edit the consumer CLAUDE.md lockstep prose yet (TASK-024).

## Common mistakes to avoid
- Merging bench code INTO product files hunk-by-hunk. The generations don't merge; port
  semantics, not text.
- Deploying the hub without redeploying/re-checking sims interop and without re-running
  `hub-replay-tune.sh fast` (deploy-hub-pi.sh resets timing to STOCK — campaign verdicts
  become garbage).
- Editing codec logic in the move commit. Moves are byte-identical + import rewrites only.
- Forgetting `internal/southbound/modbus` — `sunspec/reader.go` and `scanner.go` import it;
  the module cannot reach back into `lexa-hub/internal/`.
- Trusting green conformance as sufficient: sims share lineage with this codec (RSK-16) —
  it is necessary, not sufficient; golden fixtures arrive in TASK-075.

## Things that must NOT change
- **Register semantics**: int16 watt fields scale into the SunSpec multiplier, never
  raw-cast (GS-1/MTR-1; encoded in `activePowerFromWatts` in `cmd/modbus/main.go` and in
  the codec scale handling). The `solar-bad-scale` scenario pins the decode-plausibility
  behavior downstream of this codec.
- 0x8000 N/A-sentinel handling (pinned by `nan-sentinel`/`battery-nan-sentinel` PASS).
- `derbase` CSIP mapping table (opModMaxLimW → WMaxLimPct etc., documented in the product
  file header) — behavior identical before/after the move; `derbase_csip_test.go` proves it.
- lexa-hub stays `CGO_ENABLED=0` for modbus/hub/ocpp/api (05 §1); lexa-proto CGo-free.

## Acceptance criteria
- [ ] Disposition doc exists with zero `investigate` rows; every `port-from-bench` row has
      a commit + test reference.
- [ ] `lexa-hub/internal/southbound/{sunspec,derbase,modbus}` deleted; `make test` green.
- [ ] `CGO_ENABLED=0 go test ./...` green in lexa-proto.
- [ ] modsim-conformance passes for all three device types against the live sims.
- [ ] Full FAST campaign ≤ V6 baseline (0.6 FAIL/cycle, 0 BLIND).
- [ ] Hub `/status` vs sim `/state` power/SoC agree within normal jitter.

## Regression checklist
- [ ] `go test -race ./internal/...` (lexa-hub) green
- [ ] `make test-fast` (csip-tls-test) green — bench untouched, run anyway
- [ ] Conformance: modsim-conformance ×3 device types (step 10)
- [ ] Mayhem: **full FAST campaign** (radioactive-adjacent: entire southbound codec moved)
- [ ] Timing restored: `hub-replay-tune.sh fast` re-run after every hub deploy

## Mayhem scenarios affected
None *intended*. Watch especially: `solar-bad-scale`, `nan-sentinel`,
`battery-nan-sentinel`, `modbus-exception`, `battery-wrong-sign` (decode-path dependents).
Any verdict drift = stop and diff the codec disposition.

## Conformance implications
SunSpec register behavior must be bit-identical. The suite is the regression net until
golden vendor fixtures (TASK-075). CSIP conformance unaffected.

## Suggested commit message
lexa-proto: `feat(sunspec): import product sunspec/derbase/modbus codecs (TASK-020)`
lexa-hub: `refactor(southbound): consume lexa-proto sunspec/derbase; delete in-repo copies`
`Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>`

## Suggested PR title & description
**Title:** Phase 1: extract SunSpec codec + derbase to lexa-proto (product-authoritative)
**Description:** Semantic disposition inventory (linked), fixes ported first, mechanical
move, consumer flip. Risk: register misread (RSK-02) — mitigated by conformance ×3 +
full campaign evidence (attached). Rollback: revert the flip commit; go.work keeps both
paths importable. Pair-PR with lexa-proto.

## Code review checklist
- Disposition table row-by-row: does each `product` row really have no bench-side fix?
- Move commits are byte-identical modulo import paths (`git diff --find-copies`).
- No codec logic edits hidden in the flip commit.
- Campaign report attached and ≤ baseline.

## Definition of done
Acceptance criteria + regression checklist; disposition doc committed; status headers
(this file + 00_MASTER_INDEX) updated.

## Possible follow-up tasks
TASK-021 (bench consumes + deletes fork), TASK-023 (absorb the csipmodel forward slice if
step 8 created aliases), TASK-053 (generative int16 sweep vs the shared codec, GAP-07),
TASK-075 (golden fixtures, GAP-13).
