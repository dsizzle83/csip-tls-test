# TASK-082 — Bench fork endgame: driver forks, bench `derbase`, and the CSIP walker/scheduler fork decision

*Status: DONE (2026-07-05, fb52b16) · Phase: P1 · Effort: L (≈6–8 h) · Difficulty: med · Risk: med*

## Objective
Finish what R2 started: after the shared `lexa-proto` module exists
(TASK-020/021/023), dispose of the bench-repo forks that TASK-010's
import audit kept alive — re-point the SunSpec **driver** forks and
`sim/modsim-client` at the shared module, delete the bench `derbase`
fork, and record an explicit architecture decision (AD) for the bench
`internal/csip/{discovery,scheduler}` forks: keep-as-independent-referee
or extract. At the end of this task, no protocol-semantics code
(register maps, layouts, DERControl write sequencing) exists in two
copies anywhere, and every surviving duplicate is a *documented decision*
rather than an accident.

## Background
The program's Phase 1 (R2, review W3/D1/D4) extracts `sunspec`, `derbase`
layouts, `ocppserver`, and the 2030.5 model into a shared module
(`lexa-proto`) consumed by both `~/projects/lexa-hub` (product) and
`~/projects/csip-tls-test` (bench). TASK-010 deleted the obsolete monolith
(`cmd/hub`) and its orchestrator/bridge forks, but its import audit
produced a **keep-list**: several bench packages are live dependencies of
the sims, gridsim, and the conformance suites and could not be deleted in
P0. TASK-021 re-pointed the sim world model at the shared `sunspec` but
deferred the remaining fork disposal to "TASK-010's owner" — a circular
punt this task resolves.

The survivors (verify each with the import audit in step 1 — this list
was accurate at authoring time):
- `sim/modsim-client/main.go` imports the bench driver fork
  `internal/southbound/inverter`.
- Bench `internal/southbound/battery.go` / `inverter.go` driver forks
  import the **bench `derbase` fork** — derbase carries register-map and
  DERControl write-sequencing semantics, exactly the MTR-4
  ("a lone change misreads real hardware") bug class this program exists
  to kill. The product-side derbase moved to `lexa-proto` in
  TASK-020/023.
- Bench `internal/csip/discovery` and `internal/csip/scheduler` forks are
  imported by `sim/client`, `sim/client-http`, `sim/conformance`, and
  `tests/*`. These are *logic* forks (walker/scheduler), not just model
  types (the model types were extracted in TASK-023).

The csip walker/scheduler forks are a genuine design question, not just
cleanup: a conformance suite that exercises the product via an
**independent** client implementation has referee value (the
self-confirmation blind spot, review §9), whereas sharing one walker
means a walker bug passes conformance bilaterally. That decision must be
made deliberately and recorded — silence is the failure mode.

## Why this task exists
Review W3 says the lockstep duplication "has already failed"; R2's
endgame is "one codec." Cross-review of this program (2026-07-04) found
that without this task, the bench `derbase` fork and driver forks survive
the entire roadmap with neither a deletion task nor a recorded de-scope —
contradicting Phase 1's exit criterion ("`diff -rq` between repos finds
no duplicated protocol packages").

## Architecture review sections
W3, D1, D4, R2, §9 (self-confirmation). Roadmap: 02 AD-003, 03 Phase 1
exit criteria, 04 §4 risk 2, 07 GAP-13 (referee context).

## Prerequisites
TASK-020, TASK-021, TASK-023 DONE (`lexa-proto` exists with `sunspec`,
derbase layouts, and the 2030.5 model; sims already consume shared
sunspec). Bench in a runnable state (`make test-fast` green).

## Files
- **Read first:** TASK-010.md's keep-list section (in this directory);
  `~/projects/csip-tls-test/sim/modsim-client/main.go`;
  bench `internal/southbound/` (driver files + any remaining `derbase`);
  bench `internal/csip/discovery/` and `internal/csip/scheduler/`;
  `lexa-proto`'s package layout as landed by 020/023.
- **Modify:** `sim/modsim-client/main.go` (imports); bench
  `internal/southbound/battery.go`, `inverter.go` (imports); any other
  importers step 1 finds; both repos' CLAUDE.md directory maps;
  `docs/refactor/02_ARCHITECTURE_DECISIONS.md` (new AD).
- **Create:** none (deletions only, plus the AD entry).

## Blast radius
Packages: bench `internal/southbound/*` (drivers), bench `derbase` fork
(deleted), `sim/modsim-client`, potentially `sim/conformance`/`tests`
build lists. Public APIs: none. Config: none. Data structures: none —
this task is import-rewiring + deletion; any needed semantic change means
something diverged and must go through a reviewed lockstep commit instead
(stop and escalate).

## Implementation strategy
Import-audit first, then mechanical re-pointing with the compiler as the
guide, then deletion, with the conformance suites as the behavioral gate.
The csip walker/scheduler decision is a written AD either way — the
*default recommendation* is **keep-as-referee** (rename to
`internal/csipref` with a package comment stating the referee role) since
independence has test value and extraction has none until a second
consumer appears.

## Detailed steps
1. Re-run the import audit: `cd ~/projects/csip-tls-test && go list -deps
   ./... | grep -E 'southbound|derbase|internal/csip'` and
   `grep -rn "internal/southbound\|internal/csip" --include="*.go" sim/
   tests/ cmd/` — build the authoritative list of survivors and their
   importers. If the list differs from Background, the audit wins.
2. Re-point the driver forks (`battery.go`, `inverter.go`, and whatever
   step 1 adds) from the bench `derbase` fork to `lexa-proto`'s derbase
   layouts. If any call site does not compile against the shared API,
   **stop**: diff the semantics, and if the bench fork carried a real fix,
   land it in `lexa-proto` first as its own reviewed lockstep commit.
3. Re-point `sim/modsim-client` at the shared packages the same way.
4. Delete the bench `derbase` fork; `go build ./...` must succeed with
   zero references remaining.
5. Run the codec gates: `make test-fast`, `go test
   ./internal/southbound/...`, then `sim/modsim-conformance` for all
   three device types (`-device inverter|battery|meter`) against the
   rebuilt sims on the bench.
6. Decide the csip walker/scheduler fork question and write the AD in
   `02_ARCHITECTURE_DECISIONS.md` (extend AD-003): either
   (a) **keep-as-referee** — rename/move to a clearly-marked package,
   add a package comment stating it is deliberately independent of the
   product walker and must NOT be "synced", and add it to the CI
   divergence gate's allow-list (TASK-024) so the gate doesn't flag it;
   or (b) **extract** — only if a concrete consumer needs shared walker
   logic; then file the extraction as a follow-up task, do not do it here.
7. Update both CLAUDE.md directory maps and TASK-010's keep-list note
   ("resolved by TASK-082"). Update 03 Phase 1 exit criterion wording if
   the referee package is kept (the `diff -rq` criterion gains one
   documented exception).
8. MTR-4 lockstep: rebuild and deploy hub + all sims in the same session
   (`scripts/update-sim-pis.sh`, `deploy-hub-pi.sh` — then re-run
   `scripts/hub-replay-tune.sh fast`), and run a full Mayhem campaign.

## Testing changes
No new tests; the gates are the existing conformance suites + campaign.
If step 2 lands a semantic fix in `lexa-proto`, that fix needs its own
regression test in the module.

## Documentation changes
CLAUDE.md (both repos) directory maps; AD entry in 02; TASK-010 keep-list
annotation; 03 Phase 1 exit-criterion exception if (a) is chosen.

## Common mistakes to avoid
- Deploying only one side after touching register/write semantics
  (MTR-4) — hub + sims deploy in the same session, always.
- "Fixing" a compile error by editing the shared module's semantics
  inline — any semantic delta goes through its own reviewed commit.
- Forgetting `deploy-hub-pi.sh` resets hub timing to STOCK — re-run
  `hub-replay-tune.sh fast` before the campaign.
- Extracting the walker/scheduler "while you're in there" — option (b)
  is explicitly out of scope for this task.

## Things that must NOT change
- The conformance suites' verdicts (all three device types) — they gate
  this task precisely because the forks carry register semantics.
- The referee independence of the conformance client, unless the AD
  explicitly decides otherwise.
- Product-side behavior: this task must not require any lexa-hub source
  change (a needed one means undiscovered divergence — escalate).

## Acceptance criteria
- `grep -rn "derbase" ~/projects/csip-tls-test/internal/southbound/`
  returns no fork (only `lexa-proto` imports).
- `go build ./...` + `make test-fast` green in csip-tls-test.
- modsim-conformance PASS for inverter, battery, meter.
- AD recorded in 02 for the csip forks, with the CI allow-list updated
  if keep-as-referee.
- Full FAST Mayhem campaign ≤ baseline (0 BLIND, FAIL rate ≤ current).

## Regression checklist
- [x] `make test-fast` + `go test ./internal/southbound/...` green
- [x] modsim-conformance ×3 device types green (inverter 19/19, battery 22/22, meter 9/9 —
      exact TASK-021 baseline, against the live bench sims, unredeployed)
- [ ] Full FAST Mayhem campaign — **not run, deliberately** (see Implementation notes)
- [ ] Hub + sims deployed same session — **not needed** (no sim/hub code touched; see notes)
- [x] CI divergence/pin gate (TASK-024's predecessor, `scripts/ci/lockstep-check.sh`) green,
      0 new allow-list entries (none applicable — see AD-003(g) in 02)

## Mayhem scenarios affected
None targeted — the campaign is a pure regression gate here; any verdict
movement means a codec semantic changed and is a finding.

## Conformance implications
This task's whole point: SunSpec conformance evidence becomes valid for
"the one shared codec". CSIP conformance unaffected unless option (b).

## Suggested commit message
`refactor(bench): re-point driver forks to lexa-proto, delete derbase fork (R2 endgame, W3/D4)`

## Suggested PR title & description
**Title:** Bench fork endgame — one derbase, referee decision recorded
**Description:** Re-points sim/modsim-client and the southbound driver
forks at lexa-proto; deletes the bench derbase fork; records the AD for
the csip walker/scheduler forks (keep-as-referee). Gates: conformance ×3,
full FAST campaign ≤ baseline. Rollback: revert commit; go.work keeps
both import paths buildable until merge.

## Code review checklist
- Import audit output attached to the PR; zero semantic diffs smuggled
  into re-pointing commits.
- AD text actually decides (not "TBD"); CI allow-list matches it.
- Campaign report linked.

## Definition of done
Acceptance criteria + regression checklist + docs updated + status
headers (this file + 00_MASTER_INDEX) updated.

## Possible follow-up tasks
Walker/scheduler extraction (only if AD chose (b)); TASK-075 golden
fixtures (the referee question feeds it); backlog "second gridsim"
scenarios.

## Implementation notes (2026-07-05)

**Import audit (step 1) vs. the Background list.** The re-run audit matched the task's
Background almost exactly, with one addition and one correction:
- Addition: `internal/tlsclient/fetcher_test.go` also imports `internal/csip/discovery` —
  not named in Background (which only listed `sim/client(-http)`, `sim/conformance`,
  `tests/*`). Repointed along with the rest.
- Correction: of the bench driver forks, only `internal/southbound/inverter` has a live
  consumer (`sim/modsim-client`). `battery`, `meter`, and `registry` have **zero consumers**
  outside their own test files — `cmd/hub`/`sim/orchestrator` (their pre-TASK-010
  consumers) are deleted and nothing replaced them. Left in place (they build, they pass,
  deleting unreferenced-but-untasked code is scope creep) but flagged in
  `internal/southbound/CLAUDE.md` and AD-003(f) for visibility.

**Derbase decision: disposed, not kept-as-referee.** The task asked me to decide between
consuming `lexa-proto/derbase` or staying bench-local-by-design. Chose disposal (delete the
fork; `battery`/`inverter` now embed `lexa-proto/derbase.Base` directly) because, unlike the
csip walker/scheduler, there is no referee argument for the bench's own derbase: it's a
debug CLI helper (`sim/modsim-client`) driving the same sims the hub itself talks to, not an
independent spec-conformance check. TASK-020's disposition doc had already adjudicated every
behavioral difference product-authoritative (D1-D3, S1-S8), so re-pointing needed no new
semantic review — see AD-003(f) for the full reasoning, including the capability
`battery`/`inverter` gain for free (`OpModFixedW`, `GenLimW`/`LoadLimW`, reversion timers,
curve surface) and why that isn't an escalation trigger.

**csip discovery/scheduler: kept as referee, renamed to `internal/csipref`, per the task's
own default recommendation** (option a). See AD-003(g) in
`docs/refactor/02_ARCHITECTURE_DECISIONS.md` for the full record. The CI divergence gate
(`scripts/ci/lockstep-check.sh`) never scanned `internal/csip{,ref}` in the first place (its
`TREES` array only ever compared `internal/southbound/sunspec` and `internal/ocppserver`,
both already retired to `lexa-proto`) — there was no allow-list entry to add, since the gate
cannot flag a tree it doesn't compare. Added a comment at the `TREES` declaration recording
this so a future reader doesn't go hunting for a missing line.

**Reduced regression gate — deviation from the task's stated acceptance criteria, per
explicit launch-lane instruction.** The task file's acceptance criteria/regression checklist
call for a full FAST Mayhem campaign and a same-session hub+sim deploy. My launch
instructions (current as of 2026-07-05, superseding the task file's staler text) state: "if
your changes are import-repoints/deletions only, run make test-fast + go test ./tests/ + the
modsim-conformance ×3 locally... your changes don't redeploy sims unless you change sim
code — avoid that; if you must, MTR-4 lockstep + full campaign applies." No sim code
(`sim/southbound/*`) and no hub code was touched — `sim/modsim-conformance` itself doesn't
even import `battery`/`inverter`/`derbase` (confirmed by import audit: it talks
`lexa-proto/sunspec` directly), so this task's changes have zero exposure on the deployed
sims or hub. Ran the reduced gate instead: `go build ./...`, `go vet ./...`, `go test ./...`
(both `GOWORK` on and `GOWORK=off -mod=vendor`), and `modsim-conformance` ×3 against the
live (unredeployed) bench — all green, matching TASK-021's baseline exactly. No Mayhem
campaign run this session; flagging for the Principal Engineer to confirm this deviation is
acceptable, since it departs from the task file's own written acceptance criteria even
though it follows the more current launch-lane instruction.

**Branch-state note.** This branch's tip at commit time already carried three commits
(`6385ce7`, `d31c428`, `5ced67d`) from a concurrent TASK-047 session that landed on
`task/082-fork-endgame` before I committed — a shared-working-directory collision, not
something I caused or reverted (matches the "recovered from branch collision" pattern
already visible in this repo's merge history, e.g. TASK-021/025). One of those commits
(`d31c428`) incidentally already carried my `git mv`/`git rm` staged-index changes (the
`internal/csip` → `internal/csipref` rename and the `derbase.go` deletion) under an
unrelated commit message, since they were sitting staged in the shared index at the time.
Content is correct and verified (build+test green); flagging the collision for the
Principal Engineer to reconcile/re-message if desired.
