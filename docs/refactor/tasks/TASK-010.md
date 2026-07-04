# TASK-010 — Delete monolith `cmd/hub` + forked orchestrator/bridge/adapters

*Status: TODO · Phase: P0 · Effort: M (≈4–6 h) · Difficulty: med · Risk: low*

## Objective
The obsolete monolith and its maintained-by-accident forks are gone from csip-tls-test
(≈5k LOC), every remaining binary still builds, all suites stay green, and no Makefile
target, script, or doc references the deleted code.

## Background
`csip-tls-test/cmd/hub` is the pre-lexa-hub monolith ("reference only — never extend",
CLAUDE.md line 13). It drags live-compiled forks. Verified import map (via
`go list` / grep on 2026-07-04 — **re-run when implementing**):

**Delete list:**
- `cmd/hub/` — 8 files, 1,314 lines (`main.go`, `config.go`, `metrics.go`,
  `reconnect.go`, `response.go`, `telemetry.go`, `CLAUDE.md`, `hub-example.json`).
- `internal/orchestrator/` — stale fork (its `optimizer.go` is 1,237 lines vs the
  product's 2,329) + `internal/orchestrator/adapters/`. Importers: `cmd/hub`,
  `sim/orchestrator`, `internal/southbound/battery/metrics.go`.
- `internal/bridge/` — scheduler↔registry translation layer; imported by **nothing**
  outside its own tests (verified), but referenced by `make test-southbound`.
- `sim/orchestrator/` — "example wiring of the orchestration engine … Use cmd/hub for
  the full production stack" — monolith-era demo binary.
- `internal/southbound/battery/metrics.go` — implements
  `orchestrator.BatteryMetricsReader` for the fork; its only consumers are cmd/hub,
  sim/orchestrator, and the fork's adapters. (Check for a sibling metrics test file and
  for helpers it shares with `battery.go` — `readMetricsFrom713`/`readMetricsFrom802`
  live in metrics.go itself; verify nothing else calls them.)

**Keep list (verified used by the live bench):**
- `internal/csip/` — the 2030.5 model/scheduler/identity used by gridsim, sims, tests,
  and the southbound derbase (NOT deletable, despite the review's phrasing "csip fork").
- `internal/tlsclient/`, `internal/wolfssl/` — used by `sim/client`, `sim/conformance`,
  `sim/server`, `sim/tlsserver`, `tests/`.
- `internal/ocppserver/` — used by `sim/evsim` tests and `sim/server`.
- `internal/southbound/` everything else — sims + conformance runners.
- `internal/httpclient/` — `sim/client-http`, `tests/`.

**Reference cleanup (verified locations):**
- `Makefile`: targets `build-hub` (line ~70), `sync-hub-pi`, `pi-hub`, `pi-build`
  (hub build line), `pi-run`; `.PHONY` list; `help` text lines mentioning hub;
  `test-southbound` includes `./internal/bridge/`.
- `README.md`: lines ~13 (`[ Hub Pi — cmd/hub ]` diagram), 61, 72, 78 (build/run hub).
- `CLAUDE.md`: line 13 (monolith note) + directory map.
- No `*.service` files reference the monolith (only `sim/mqttproxy.service` exists in
  this repo — verified). `scripts/*.sh` contain no `cmd/hub` references (verified via
  grep; re-check).

## Why this task exists
Review D1/W3: "confuses every grep; silently diverging reference"; the fork is where a
future engineer reads the WRONG optimizer. R2's first, zero-risk installment.

## Architecture review sections
D1, W3, R2, §14 item 4 (partial). Roadmap: 03 P0 ("monolith deleted, −5k LOC");
04 row 010; 05 §1 (one owner per concept).

## Prerequisites
TASK-003 (CI proves every remaining binary builds after the cut). TASK-001 (clean tree).

## Files
- **Read first:** the import map above, re-verified:
  `go list -deps ./... | grep csip-tls-test/internal/orchestrator`,
  `grep -rl "internal/orchestrator\|internal/bridge\|cmd/hub" --include="*.go" .`,
  `grep -rn "cmd/hub\|bin/hub\|sim/orchestrator\|internal/bridge" Makefile scripts/ README.md CLAUDE.md .claude/ docs/BENCH.md`.
- **Modify:** `Makefile`, `README.md`, `CLAUDE.md`,
  `internal/southbound/battery/` (delete metrics.go; adjust tests if any reference it).
- **Create:** nothing.

## Blast radius
Bench repo only. Deleted packages had no production runtime on the bench (the live hub is
lexa-hub on 69.0.0.1). Risk concentrates in: (a) a missed importer breaking `go build
./...`; (b) `battery/metrics.go` sharing helpers with live battery code; (c) Makefile
`pi-*` targets someone still uses (they are marked deprecated/legacy — confirm with the
README rewrite).

## Implementation strategy
Grep-audit first, delete in one commit (revertible), fix references in the same commit,
then prove: full build of every remaining binary, all suites, and a bench smoke that the
deletion touched nothing live (sims/dashboard/gridsim were never linked to the monolith).

## Detailed steps
1. Re-run the import audit (Read-first commands). If any NEW importer of the delete-list
   packages appeared since 2026-07-04, stop and re-scope.
2. Delete: `git rm -r cmd/hub sim/orchestrator internal/orchestrator internal/bridge`
   and `git rm internal/southbound/battery/metrics.go`.
3. Fix `internal/southbound/battery`: run
   `go test ./internal/southbound/battery/` — if `battery_test.go` or others reference
   metrics symbols, delete those test cases (they tested the fork's interface). Confirm
   `battery.go` itself has no dangling references (e.g. `has713` is used by metrics —
   verify it's also used by battery.go proper; if it becomes unused, keep the field and
   its populate logic ONLY if other code reads it, else remove — compiler + `go vet`
   decide).
4. Makefile: remove `build-hub`, `sync-hub-pi`, `pi-hub`, `pi-run`, and the hub line in
   `pi-build`; scrub `.PHONY` and `help`; change `test-southbound` to
   `go test ./internal/southbound/...` (drop `./internal/bridge/`).
5. README.md: rewrite the architecture diagram/build sections to point at
   `~/projects/lexa-hub` for the hub; keep bench/sim content.
6. CLAUDE.md: delete the monolith sentence (line 13) and any directory-map row for
   `cmd/hub`; keep the `internal/csip` row (still live).
7. Full verification:
   - `go build ./...` (module-wide; needs the wolfSSL env for cgo dirs — desktop has it)
   - `make build build-modsim build-batsim build-metersim build-evsim build-dashboard`
   - `make test-fast && go test ./tests/ ./internal/southbound/... ./sim/southbound/...
     ./cmd/dashboard/... ./sim/gridsim/... ./sim/evsim/...`
   - `grep -rn "internal/orchestrator\|internal/bridge\|cmd/hub\b\|sim/orchestrator"
     --include="*.go" .` → empty;
     same grep over `Makefile scripts/ *.md .claude/` → only historical docs
     (`docs/HARNESS_REVIEW.md`, QA reports, `ARCHITECTURE_REVIEW.MD` — leave those).
8. Bench smoke (nothing should change): `curl -s http://69.0.0.20:8080` (dashboard up),
   one `scripts/mayhem.py --list`. No deploy needed — deleted code never ran on the
   bench.
9. Commit (single commit), PR with the −LOC count.

## Testing changes
No new tests; the deletion is proven by builds + existing suites (step 7 commands are
the acceptance evidence).

## Documentation changes
`README.md`, `CLAUDE.md` (this repo). Historical audit docs untouched.
00_MASTER_INDEX status.

## Common mistakes to avoid
- Deleting `internal/csip` or `internal/tlsclient` because the review said "forks" —
  they are LIVE dependencies of gridsim/sims/tests here (the review's deletable-fork
  claim is precise only for orchestrator/bridge/monolith; csip/tlsclient are originals
  the product forked FROM). The import audit is authoritative, not the prose.
- Leaving `battery/metrics.go` because it "looks southbound" — it exists solely to feed
  the fork's `BatteryMetricsReader`.
- Editing lexa-hub in this task — zero product-repo changes (its own
  `internal/orchestrator` is the live one).
- Breaking `make test-southbound` by forgetting the bridge reference.
- "Improving" anything while deleting — pure removal + reference fixes only.

## Things that must NOT change
- All sim binaries' behavior (modsim/batsim/metersim/evsim), gridsim, dashboard,
  conformance runners — byte-identical builds expected except for removed targets.
- `internal/southbound` live code paths used by sims (only `battery/metrics.go` goes).
- The MTR-4 lockstep pair (`internal/southbound/sunspec`, `internal/ocppserver`) —
  untouched; TASK-004's gate must stay green (this deletion doesn't touch either tree).

## Acceptance criteria
- [ ] `git rm` list matches Background exactly (or deviations justified in PR).
- [ ] `go build ./...` green; every `make build-*` target green.
- [ ] All step-7 suites green; greps return empty on live code/config.
- [ ] Diffstat shows ≈ −5k lines; no non-deletion logic changes.
- [ ] Dashboard + mayhem `--list` still functional on the bench.

## Regression checklist
- [ ] `make test-fast` green
- [ ] Conformance logic tests green (`go test ./tests/`)
- [ ] Mayhem: none required (no live-path change); `--list` smoke only
- [ ] TASK-004 lockstep gate still green

## Mayhem scenarios affected
None (the engine and sims don't import any deleted package — verified).

## Conformance implications
None — conformance runners (`sim/conformance`, `sim/modsim-conformance`, `tests/`) keep
their dependencies (tlsclient/csip/southbound remain).

## Suggested commit message
`chore: delete monolith cmd/hub + forked orchestrator/bridge/adapters + sim/orchestrator (D1, −5k LOC)`
`Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>`

## Suggested PR title & description
**Title:** Delete the monolith and its forks (D1/R2 first installment)
**Description:** Removes cmd/hub (1,314 LOC), the stale 1,237-line optimizer fork +
adapters, bridge, sim/orchestrator, battery/metrics.go; fixes Makefile/README/CLAUDE.md.
Import audit table included. Risk: build-only. Rollback: single revert.

## Code review checklist
- Reviewer re-runs the importer grep and the module build.
- No behavioral diffs hidden among deletions (`git diff --stat` is deletions + the four
  reference files).
- CLAUDE.md/README no longer promise a hub build in this repo.

## Definition of done
Acceptance criteria + regression checklist + docs + status headers updated.

## Possible follow-up tasks
TASK-011 (GUI/docs cleanup), TASK-019–024 (shared modules replace the remaining
duplication), backlog: retire deprecated `sync-pi`-era Makefile targets entirely.
