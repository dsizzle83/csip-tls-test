# TASK-004 — CI lockstep-divergence gate (shared-package diff)

*Status: TODO · Phase: P0 · Effort: S (≈2–3 h) · Difficulty: low · Risk: low*

## Objective
A script (`scripts/ci/lockstep-check.sh` in csip-tls-test) diffs the duplicated protocol
packages between the two repos and runs in CI on every PR — **report-only** at first,
with today's known divergences recorded in an allowlist, flipping to enforcing after
Phase 1 replaces duplication with a shared module.

## Background
Two package trees are intentionally duplicated across repos and must change in lockstep
(audit finding MTR-4 — a lone change misreads real hardware):
- `internal/southbound/sunspec` (SunSpec register maps/codecs)
- `internal/ocppserver` (OCPP 2.0.1 CSMS)

The lockstep rule lives only in the two CLAUDE.md files, and it has **already failed**
(review W3). Verified divergence today (`diff -rq` between
`/home/dmitri/projects/csip-tls-test` and `/home/dmitri/projects/lexa-hub`):
- `sunspec`: `der1547.go`, `models.go`, `reader.go`, `reader_test.go`, `scanner.go`
  differ; `der1547_roundtrip_test.go`, `derlayout.go`, `derlayout_test.go`, `layout.go`
  exist only in the product repo.
- `ocppserver`: only `CLAUDE.md` and `simulator_test.go` differ (code files identical).

Phase 1 (TASK-019–024) extracts these into a shared module and TASK-024 replaces this
raw-diff gate with version pinning. Until then, the gate's job is: **no NEW divergence**
— any diff not in the allowlist fails the check; allowlisted diffs produce a visible
warning so the debt stays loud.

CI cross-repo access: the workflow lives in csip-tls-test and must check out
`dsizzle83/lexa-hub` too. Both repos are private under the same owner, so the default
`GITHUB_TOKEN` does NOT reach the second repo — a fine-grained PAT with read-only
contents scope on lexa-hub is required, stored as repo secret `LEXA_HUB_RO_TOKEN`.

## Why this task exists
Review W3/D4: "the lockstep duplication has already failed"; the rule must move from a
CLAUDE.md sentence into CI. Also protects TASK-020's reconciliation work from concurrent
drift.

## Architecture review sections
W3, D4, R2, §14 item 4 (this is its P0 down-payment). Roadmap: 03 P0 + P1; AD-003;
04 rows 004/024; RSK-02 context.

## Prerequisites
TASK-002 and TASK-003 (CI skeletons exist in both repos).

## Files
- **Read first:** both repos' `internal/southbound/sunspec/` and `internal/ocppserver/`
  trees; `docs/refactor/02_ARCHITECTURE_DECISIONS.md` AD-003.
- **Modify:** `/home/dmitri/projects/csip-tls-test/.github/workflows/ci.yml` (new job).
- **Create:** `/home/dmitri/projects/csip-tls-test/scripts/ci/lockstep-check.sh`,
  `/home/dmitri/projects/csip-tls-test/scripts/ci/lockstep-allowlist.txt`.

## Blast radius
None at runtime. CI + two new script files.

## Implementation strategy
Pure-bash comparator: for each shared tree, `diff -rq` the two checkouts, normalize the
output to relative paths, and compare against the allowlist. Exit 0 with warnings while
every diff is allowlisted; exit 1 on any unlisted path. A `--enforce` flag ignores the
allowlist entirely (Phase 1 flips CI to it; TASK-024 then retires the script for version
pinning).

## Detailed steps
1. Create `scripts/ci/` and write `lockstep-check.sh`:
   - Args: `--product <path-to-lexa-hub>` (default `../lexa-hub` for local use),
     `--enforce` (optional).
   - Trees compared: `internal/southbound/sunspec`, `internal/ocppserver`.
   - Output of `diff -rq` normalized to lines like `sunspec/models.go DIFFER` /
     `sunspec/layout.go PRODUCT-ONLY` / `<pkg>/<file> BENCH-ONLY`.
   - Without `--enforce`: unlisted lines → exit 1 (new divergence); listed lines →
     printed as `KNOWN-DIVERGENCE (P1 debt, see TASK-020/021)`; none → "in lockstep".
   - With `--enforce`: any line → exit 1.
2. Seed `lockstep-allowlist.txt` with exactly the verified divergences listed in
   Background (re-run the diff yourself when implementing — the trees may have moved
   since 2026-07-04; the allowlist must match reality on the day it lands). One line per
   file, `#` comments allowed, header comment: "Known W3 divergence. Additions FORBIDDEN
   without a paired-PR justification; the list only shrinks (TASK-020/021) until
   TASK-024 deletes it."
3. Add CI job `lockstep` to the csip-tls-test workflow: checkout self, checkout
   `dsizzle83/lexa-hub` (`actions/checkout` with `repository:` + `token:
   ${{ secrets.LEXA_HUB_RO_TOKEN }}` into `lexa-hub/`), run
   `bash scripts/ci/lockstep-check.sh --product lexa-hub`.
4. Create the fine-grained PAT (read-only, contents scope, lexa-hub only) and store it as
   secret `LEXA_HUB_RO_TOKEN`. Document the token's scope + expiry in the workflow
   comment.
5. Run the script locally against both working trees; verify it exits 0 today and that
   touching one side of `sunspec/decoder` (scratch edit, reverted) makes it exit 1.
6. Mark the job required on `main`. State in the script header, the allowlist header,
   and 00_MASTER_INDEX: **report-only until P1; TASK-021 shrinks the list; TASK-024
   replaces this gate with shared-module version pinning.**

## Testing changes
Script self-test: run once clean, once with an injected scratch divergence (must fail),
once with `--enforce` (must fail today). No Go tests.

## Documentation changes
- Both CLAUDE.md files: append to the lockstep rule: "enforced by
  `scripts/ci/lockstep-check.sh` in csip-tls-test CI" (same session, both repos —
  lockstep applies to its own documentation).
- 00_MASTER_INDEX status table.

## Common mistakes to avoid
- Do not "fix" any of the divergent files here — reconciliation is TASK-020/021 and is
  high-risk (RSK-02: either side may hold the real fix). This task only observes.
- Don't diff file contents semantically (gofmt etc.) — byte diff is the point; false
  positives are impossible by construction, false "same" is what kills.
- `GITHUB_TOKEN` cannot read the second private repo; without the PAT the job fails
  confusingly on checkout.
- Keep the default `--product ../lexa-hub` working so a developer can run it before a
  lockstep commit locally.

## Things that must NOT change
- The divergent files themselves (all of them — including both `reader.go`s and the
  product-only `layout.go`/`derlayout.go`).
- The MTR-4 deploy discipline (hub + sims same session) — the gate supplements, not
  replaces it.

## Acceptance criteria
- [ ] `bash scripts/ci/lockstep-check.sh` exits 0 on today's trees, printing each known divergence as a warning.
- [ ] Injected scratch divergence → exit 1 (verified, reverted).
- [ ] `--enforce` → exit 1 today.
- [ ] CI job green on a PR and marked required.

## Regression checklist
- [ ] `make test-fast` (csip-tls-test) / `go test -race ./internal/...` (lexa-hub) green
- [ ] Conformance logic tests: unaffected (no code change)
- [ ] Mayhem: none
- [ ] Allowlist content matches a fresh `diff -rq` run on landing day

## Mayhem scenarios affected
None.

## Conformance implications
Indirect: the gate protects the SunSpec codec (conformance suites' subject) from silent
one-sided drift until P1.

## Suggested commit message
`ci(lockstep): report-only sunspec/ocppserver divergence gate + known-divergence allowlist (W3)`
`Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>`

## Suggested PR title & description
**Title:** Lockstep divergence gate (report-only until P1)
**Description:** Byte-level cross-repo diff of the two lockstep trees; allowlist pins the
already-known W3 divergence so only NEW drift fails. Paired doc-line PR in lexa-hub.
Rollback: remove job + scripts.

## Code review checklist
- Allowlist exactly equals current reality (reviewer re-runs the diff).
- Script fails closed (unlisted → red), including on missing product checkout.
- PAT scope is read-only, single-repo, expiry documented.

## Definition of done
Acceptance criteria + regression checklist + both CLAUDE.md lines + status headers
updated.

## Possible follow-up tasks
TASK-019–021 (shrink allowlist), TASK-024 (replace with version pinning and delete this
script).
