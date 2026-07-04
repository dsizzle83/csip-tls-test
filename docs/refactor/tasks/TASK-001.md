# TASK-001 — Commit residual work; branch/PR workflow; hosting decision

*Status: TODO · Phase: P0 · Effort: S (≈2–3 h) · Difficulty: low · Risk: low*

## Objective
Both working trees are clean (`git status` empty), every 2026-07-03 QA-arc fix and the
refactor doc set is committed and pushed, `main` is protected in both GitHub repos, and
the branch/PR workflow plus the hosting decision are recorded as AD-012 in
`02_ARCHITECTURE_DECISIONS.md`.

## Background
Two repos, one system:
- **Product** `/home/dmitri/projects/lexa-hub` (module `lexa-hub`) — currently on branch
  `main`, remote `origin git@github.com:dsizzle83/lexa-hub.git`. Five modified files:
  `cmd/hub/actuators.go`, `cmd/hub/actuators_test.go`, `cmd/hub/main.go`,
  `internal/northbound/scheduler/scheduler.go`,
  `internal/northbound/scheduler/failclosed_test.go`.
- **Bench** `/home/dmitri/projects/csip-tls-test` (module `csip-tls-test`) — currently on
  branch `lexa-hub` (a work branch; `origin/lexa-hub` and `origin/main` both exist),
  remote `origin git@github.com:dsizzle83/csip-tls-test.git`. Three modified files:
  `cmd/dashboard/mayhem.go`, `sim/southbound/battery.go`, `sim/southbound/battery_test.go`;
  two untracked items: `ARCHITECTURE_REVIEW.MD` and `docs/refactor/`.

What the diffs are (read them yourself with `git diff` before committing — the commit
messages must describe them accurately):
- **lexa-hub, hub side**: breach-triggered `cmdDeduper.reset()` (`cmd/hub/actuators.go`)
  wired into the plan observer via a `dedupeResets []func()` slice in `cmd/hub/main.go`;
  fixes the 2026-07-03 finding where a 0 W solar ceiling stayed dedupe-suppressed for 30 s
  against an uncurtailed inverter while the hub posted CannotComply. Regression test
  `TestCmdDeduper_ResetForcesResend` in `actuators_test.go`.
- **lexa-hub, scheduler side**: clock-regression guard, default-fallback half in
  `internal/northbound/scheduler/scheduler.go` `failClosed()` — holds a still-served,
  unexpired, already-adopted event over a resolved `DefaultDERControl` when the server
  clock steps back before the event's start (V6 clock-jitter FAILs: enforcement flapped
  0 W ↔ 5 kW). Four new tests in `failclosed_test.go`
  (`TestEvaluate_ClockRegressionHoldsEventOverDefault` etc.).
- **csip-tls-test**: (a) battery sim gains an explicit `"Ena"` inject key
  (`sim/southbound/battery.go` + `TestInject_EnaOverride`) so the QA harness can hold the
  pack in "hub-controlled idle" instead of releasing it to the demo sinusoid;
  (b) `cmd/dashboard/mayhem.go` uses the two-step idle inject in `baseline()` /
  `resetForScenario()` (fixes the export-cap-full-battery INV-SOC ghost) and reworks the
  clock-jitter scenario (jitter starts at tick i≥10, 7 s offset cycle coprime with the
  5 s walk, `HoldS` 35→45).

All of these were validated on the bench 2026-07-03 (clock-jitter PASS,
export-cap-full-batt accepted DEGRADED). This is review debt item D10: "weeks of
safety-critical work uncommitted."

## Why this task exists
Review D10 / Top-20 item 1: the QA-arc fixes exist only in two working trees —
unreviewable, unbisectable, bus factor 1, and a due-diligence red flag. Process
discipline (05 §11 "nothing uncommitted overnight") starts here.

## Architecture review sections
D10, §13 (process), §14 item 1. Roadmap: 03 Phase 0 exit criteria; 05 §11; 02 (pre-drafted AD-012).

## Prerequisites
None. First task of the program. Bench access not required (commit/push only).

## Files
- **Read first:** `git diff` + `git status` in both repos; `docs/refactor/02_ARCHITECTURE_DECISIONS.md`;
  `docs/refactor/00_MASTER_INDEX.md` (status table).
- **Modify:** `docs/refactor/02_ARCHITECTURE_DECISIONS.md` (verify/amend the
  pre-drafted AD-012),
  `docs/refactor/00_MASTER_INDEX.md` (status table row P0).
- **Create:** commits only; no new source files.

## Blast radius
None at runtime — pure VCS/process. No source lines change beyond what is already in the
working trees.

## Implementation strategy
Verify the diffs still pass their tests, commit them as focused commits with messages
naming the QA findings, push, then commit the review + refactor docs. Verify the pre-drafted AD-012 (hosting =
private GitHub under `dsizzle83`) against reality and amend it if needed, enable branch
protection on `main` in both repos, and normalize the bench repo's odd `lexa-hub` branch.

## Detailed steps
1. In `/home/dmitri/projects/lexa-hub`: run `make test` (`go test -race ./internal/...`)
   and `go test ./cmd/...`. All green before committing.
2. Commit lexa-hub in two commits (they are independent fixes):
   - `fix(hub): breach-triggered actuator dedupe reset (QA 2026-07-03 0W-ceiling finding)`
     — `cmd/hub/actuators.go`, `cmd/hub/actuators_test.go`, `cmd/hub/main.go`.
   - `fix(scheduler): hold still-served event over DefaultDERControl on clock regression (QA v6 clock-jitter)`
     — `internal/northbound/scheduler/scheduler.go`, `failclosed_test.go`.
   Both with the trailer `Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>`.
3. `git push origin main` in lexa-hub.
4. In `/home/dmitri/projects/csip-tls-test`: run `make test-fast` and
   `go test ./sim/southbound/... ./cmd/dashboard/...`. All green.
5. Commit csip-tls-test in two commits on the current `lexa-hub` branch:
   - `fix(batsim): explicit Ena inject override for hub-controlled idle (QA v6 export-cap-full-battery)`
     — `sim/southbound/battery.go`, `battery_test.go`.
   - `fix(mayhem): idle-capture resets + clock-jitter starts post-adoption, 7s coprime cycle (QA v6)`
     — `cmd/dashboard/mayhem.go`.
6. Third commit: `docs: architecture review + V1.0 refactor program (phases, tasks, ADs)`
   adding `ARCHITECTURE_REVIEW.MD` and `docs/refactor/` (all files, including `tasks/`).
   Confirm `.gitignore` excludes nothing under `docs/refactor/` (`git status` must show
   them staged; the repo ignores only `*-key.pem` and build outputs).
7. Reconcile the bench repo's branches: `git push origin lexa-hub`, then merge
   `lexa-hub` → `main` (fast-forward or merge commit; check
   `git log --oneline main..lexa-hub` first — do NOT rebase published history) and push
   `main`. Keep future work on short-lived branches off `main`.
8. Verify the pre-drafted AD-012 in `docs/refactor/02_ARCHITECTURE_DECISIONS.md`
   matches what you actually did — **Hosting = private GitHub (`dsizzle83/lexa-hub`,
   `dsizzle83/csip-tls-test`)**, the branch-protection state, and the workflow
   (feature branch → PR → CI green → merge; lockstep changes = paired PRs referencing
   each other, 05 §11) — and amend it in place rather than appending a duplicate.
   Alternatives context (self-hosted Gitea on the desktop; new org — rejected for now:
   single maintainer, GitHub Actions needed by TASK-002/003; revisit if the air-gap
   policy ever extends to source hosting) should already be recorded there; add it if
   missing.
9. Enable branch protection on `main` in both repos (Settings → Branches, or
   `gh api -X PUT repos/dsizzle83/<repo>/branches/main/protection ...`): require PRs,
   require status checks (the checks arrive with TASK-002/003 — enable "require checks"
   then; today enable at minimum "require PR before merging"). Note in AD-012 that
   direct-push lockout takes effect for the human too.
10. Update the P0 row of `00_MASTER_INDEX.md` (TASK-001 done) and this file's Status header.

## Testing changes
No new tests. Run existing suites as gates:
```
cd /home/dmitri/projects/lexa-hub && make test
cd /home/dmitri/projects/csip-tls-test && make test-fast && go test ./sim/southbound/... ./cmd/dashboard/...
```

## Documentation changes
`02_ARCHITECTURE_DECISIONS.md` (AD-012), `00_MASTER_INDEX.md` status table. No CLAUDE.md
changes.

## Common mistakes to avoid
- Do not squash the four code commits into one — each fix maps to a distinct QA finding
  and must be independently revertible/bisectable.
- Do not rebase or force-push: `origin/lexa-hub` and `origin/main` already exist remotely.
- Do not commit anything matching `*-key.pem` (gitignored; `certs/client-staging/` holds
  real private keys — verify `git status` shows none).
- The bench repo's `docs/refactor/tasks/` directory must be committed complete — task
  files reference each other by ID.

## Things that must NOT change
- The diffs themselves ship as-is: they are bench-validated 2026-07-03 fixes. Guard ↔
  scenario mapping: dedupe reset ↔ the 0 W-ceiling/CannotComply finding
  (export-cap/reject-write class); scheduler default-fallback guard ↔ `clock-jitter`;
  batsim `Ena` + mayhem resets ↔ `export-cap-full-battery`.
- Existing git history on both remotes.

## Acceptance criteria
- [ ] `git status --short` empty in both repos; `git log origin/main -1` matches local in both.
- [ ] Four code commits + one docs commit exist with messages naming the QA findings and the trailer.
- [ ] Branch protection active on `main` of both GitHub repos (verify: direct push rejected).
- [ ] Pre-drafted AD-012 in `02_ARCHITECTURE_DECISIONS.md` verified against the actual
      remote/branch-protection/workflow state and amended if needed (no duplicate entry
      appended); 00 status table updated.

## Regression checklist
- [ ] `make test-fast` (csip-tls-test) / `go test -race ./internal/...` (lexa-hub) green
- [ ] Conformance logic tests: not protocol-adjacent — none
- [ ] Mayhem: none (no behavior change; code already bench-validated)
- [ ] `git log --oneline -6` in each repo reads as described above

## Mayhem scenarios affected
None (the committed harness changes are already live on the bench dashboard binary —
confirm `bin/dashboard` on the desktop was built from this tree; if unsure, rebuild with
`go build -o bin/dashboard ./cmd/dashboard` and restart `csip-dashboard`).

## Conformance implications
None.

## Suggested commit message
Multiple — see steps 2, 5, 6. All with
`Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>`.

## Suggested PR title & description
No PR (this task creates the PR discipline; committing directly to `main` one last time
is acceptable and stated in AD-012). All subsequent tasks go through PRs.

## Code review checklist
- Commit messages accurately describe each diff and name the QA scenario.
- No private key material staged; `docs/refactor/` complete.
- AD-012 records alternatives and the branch-protection state.

## Definition of done
Acceptance criteria + regression checklist pass; AD-012 merged; this file's status header
and `00_MASTER_INDEX.md` updated.

## Possible follow-up tasks
TASK-002/003 (CI, unblocked by this), TASK-004, TASK-005.
