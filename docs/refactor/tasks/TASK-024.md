# TASK-024 — CI shared-module version-pinning gate; retire the CLAUDE.md lockstep prose

*Status: TODO · Phase: P1 · Effort: S (≈2–3 h) · Difficulty: low · Risk: low*

## Objective
CI in both repos fails whenever the two repos do not pin the **identical** `lexa-proto`
version; the raw shared-package diff check from TASK-004 is retired; the "lockstep rule"
prose in both CLAUDE.md files is replaced by a pointer to the module + gate; `go.work`
stops being the authority for what version builds ship.

## Background
Phase 1 state after TASK-020–023: `lexa-proto` holds `sunspec`, `derbase`, `modbus`,
`ocppserver`, `csipmodel`; both repos import it; the in-repo duplicates are gone. During
migration both repos build via committed `go.work` files pointing at the sibling checkout
— which means "what version am I actually building against?" is answered by whatever is
checked out in `~/projects/lexa-proto`, not by anything recorded in the consumer repo.
That is fine for a single dev machine and wrong for CI, deploys, and bisection.

TASK-019's AD-003 extension decided the pinning mechanism. Two possibilities it allowed:
- **Hosted module path** (if TASK-001 produced a remote): consumers carry a normal
  `require <path>/lexa-proto vX.Y.Z-…` line; the gate compares the two `go.mod` lines.
- **No remote yet:** each consumer commits a `proto.pin` file holding the required
  lexa-proto commit SHA; the gate compares the two files AND that a fresh
  `git -C ../lexa-proto rev-parse HEAD` (CI checks out the pinned SHA) matches.
Read the AD-003 extension and implement whichever was decided — do not re-decide here.

TASK-004 (Phase 0) added a report-only "lockstep-divergence" diff between the duplicated
package trees. Those trees no longer exist, so the check now compares nothing — it must
be replaced, not left green-by-vacuity.

The prose being retired (verified locations):
- `csip-tls-test/CLAUDE.md` — the "**Lockstep rule:**" paragraph ("register maps are
  duplicated in lexa-hub and must change in both repos together (audit MTR-4)").
- `lexa-hub/CLAUDE.md` — the intro paragraph "Two packages are duplicated across the
  repos and must change in lockstep: `internal/southbound/sunspec` … and
  `internal/ocppserver`."
- `docs/BENCH.md` — the "**MTR-4 lockstep**" deploy bullet stays but is reworded: the
  *code* lockstep is now CI-enforced; the *deploy* rule (hub + sims same session when the
  shared module version bumps) remains a real operational requirement.

## Why this task exists
W3: the old rule failed because it lived in prose with no enforcement. The gate converts
it to CI (03 Phase 1 exit criterion: "MTR-4 lockstep note in both CLAUDE.md files
replaced by the CI rule").

## Architecture review sections
W3, D4, R2, §13 (process), §14 items 2/4; 02 AD-003; 08 RSK-02 (recovery = "revert module
bump; both repos pin previous version" — this gate is what makes that recovery coherent).

## Prerequisites
- TASK-020, 021, 022, 023 DONE (no duplicated protocol packages remain).
- TASK-002/003 DONE (CI pipelines exist to host the gate). If CI is still absent, land
  the gate as a script both repos' `make test` targets call, and note it for the CI tasks.

## Files
- **Read first:** AD-003 extension in `docs/refactor/02_ARCHITECTURE_DECISIONS.md`;
  TASK-004's gate implementation (wherever TASK-003 put CI config — likely
  `.github/workflows/` or repo scripts); both root `CLAUDE.md` files.
- **Modify:** both repos' CI config (replace the diff job); `csip-tls-test/CLAUDE.md`,
  `lexa-hub/CLAUDE.md`, `docs/BENCH.md`; both repos' `go.mod`/`proto.pin` (first pinned
  version recorded); delete both `go.work` files from version control per AD-003
  (developers may keep local untracked ones — add `go.work` + `go.work.sum` to both
  `.gitignore`s).
- **Create:** `scripts/check-proto-pin.sh` in csip-tls-test (single implementation; the
  lexa-hub CI job invokes its own copy or fetches the sibling repo — match how TASK-004
  solved cross-repo visibility).

## Blast radius
CI/build plumbing and docs only. Runtime behavior: none. Developer workflow: builds stop
silently tracking the sibling checkout; bumping lexa-proto now requires paired commits in
both repos (05 §11 lockstep-PR rule).

## Implementation strategy
Implement the gate exactly as AD-003 decided; make one real divergence to prove it fails;
align both repos on the first pinned version; then swap the prose. Deleting the dead
TASK-004 diff job and landing the new gate happen in the same commit so there is no
window with neither check.

## Detailed steps
1. Read the AD-003 pinning decision. Write `scripts/check-proto-pin.sh`:
   - hosted-path mode: extract the lexa-proto require line from each repo's `go.mod`
     (CI fetches the peer repo's `go.mod` — reuse TASK-004's cross-repo access pattern);
     fail with a message naming both versions if they differ.
   - pin-file mode: compare both `proto.pin` contents; also verify the built tree uses
     that SHA (`git -C ../lexa-proto rev-parse HEAD` in CI's checkout step).
2. Record the current lexa-proto HEAD as the first pinned version in both repos.
3. Replace the TASK-004 diff job with the gate in both CI configs; delete the obsolete
   diff script.
4. Remove committed `go.work`/`go.work.sum`; gitignore them; confirm `GOWORK=off` (or a
   fresh clone) builds both repos against the pin (hosted mode: `go build ./...`;
   pin-file mode: CI clones lexa-proto at the pinned SHA into the sibling path first).
5. **Prove the gate fails:** bump the pin in one repo only on a branch; CI (or the
   script locally) must exit non-zero with a clear message. Revert.
6. Swap the prose (the three locations in Background). New text pattern:
   "Shared protocol code lives in `lexa-proto` (sunspec, derbase, modbus, ocppserver,
   csipmodel). Both repos must pin the same version — CI enforces it
   (`scripts/check-proto-pin.sh`). Version bumps ship as paired PRs and deploy hub + sims
   in the same session."
7. Run both repos' full local test targets to confirm nothing depended on go.work being
   committed.

## Testing changes
The gate itself is the test. Add a CI-level negative check only if the CI system supports
it cheaply; otherwise the step-5 manual proof, recorded in the PR, suffices.
Commands: `bash scripts/check-proto-pin.sh` (both pass and forced-fail runs),
`make test-fast`, `cd ~/projects/lexa-hub && make test`.

## Documentation changes
- Both `CLAUDE.md` files + `docs/BENCH.md` (step 6).
- `docs/refactor/02_ARCHITECTURE_DECISIONS.md`: mark the AD-003 open question ("one
  module or three") resolved-as-one if not already, and note the gate as landed.
- `00_MASTER_INDEX.md`: P1 exit row (this is the phase's last task).

## Common mistakes to avoid
- Leaving the vacuous TASK-004 diff job in place "for safety" — a green check that
  compares nothing trains people to ignore the column.
- Gating only one repo. The failure mode is asymmetric bumps; both sides must run it.
- Deleting the BENCH.md deploy rule entirely: code lockstep is solved, deploy lockstep
  (hub + sims same session on a module bump) is still real — MTR-4's operational half.
- Forgetting that removing `go.work` changes local dev ergonomics: document the
  "developers keep an untracked go.work" pattern in both CLAUDE.md replacements.

## Things that must NOT change
- Build outputs: binaries built at the pinned version must be identical to the last
  go.work builds (same lexa-proto SHA).
- The Phase 1 exit state: no duplicated protocol packages (`diff -rq` clean) — the gate
  protects it from here on.
- No preservation-ledger entries touched.

## Acceptance criteria
- [ ] Gate present in both repos' CI; step-5 forced-divergence run shown failing.
- [ ] Both repos build from a fresh clone (no committed go.work) at the pinned version.
- [ ] All three prose locations updated; grep for "lockstep" in both repos finds only the
      new pointer text and historical docs.
- [ ] TASK-004 diff job removed.

## Regression checklist
- [ ] `make test-fast` (csip-tls-test) / `go test -race ./internal/...` (lexa-hub) green
- [ ] Conformance logic tests green (`go test ./tests/`) — unchanged inputs, cheap proof
- [ ] Mayhem: **full FAST campaign** (Phase 1 exit gate per 03) + conformance evidence
      regenerated (`scripts/run-conformance.sh`) if not done in TASK-023
- [ ] Fresh-clone build proof archived

## Mayhem scenarios affected
None directly; the phase-exit campaign is run under this task as P1 closes.

## Conformance implications
None from the gate itself; the phase-exit conformance evidence regeneration lands here if
TASK-023 didn't already produce it.

## Suggested commit message
`ci(proto): version-pin gate for lexa-proto; retire lockstep prose (TASK-024)`
`Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>`

## Suggested PR title & description
**Title:** Phase 1 exit: lexa-proto version-pin CI gate replaces the lockstep rule
**Description:** Gate implementation per AD-003, forced-failure proof, go.work retired,
prose swapped in both repos + BENCH.md. Paired PRs. Rollback: restore go.work commits.

## Code review checklist
- Gate actually compares across repos (not a self-comparison).
- Negative test evidence present.
- Prose replacements keep the deploy-lockstep operational rule.
- First pinned version == the SHA the phase-exit campaign ran against.

## Definition of done
Acceptance criteria + regression checklist; phase-exit campaign + conformance evidence
referenced from 00_MASTER_INDEX; status headers updated.

## Possible follow-up tasks
TASK-005/006 interplay (govulncheck now also scans lexa-proto); backlog: automate paired
version-bump PRs; TASK-053/075 target the pinned module.
