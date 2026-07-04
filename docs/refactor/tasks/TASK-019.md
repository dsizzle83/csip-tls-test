# TASK-019 — Module-extraction ADR + `lexa-proto` skeleton + `go.work`

*Status: TODO · Phase: P1 · Effort: M (≈4–6 h) · Difficulty: med · Risk: low*

## Objective
A new shared-module repository `~/projects/lexa-proto` exists (git-initialized, empty
package skeleton, CGo-free, buildable), both consumer repos carry a committed `go.work`
that makes it importable, and `02_ARCHITECTURE_DECISIONS.md` AD-003 is extended with the
concrete module path, package layout, and version-pinning mechanism. No consumer code is
migrated yet (that is TASK-020…023).

## Background
Two repos duplicate protocol code today:
- **Product** `~/projects/lexa-hub` (module path `lexa-hub`, Go 1.21): the shared code is
  `internal/southbound/sunspec` (register codecs, incl. product-only `layout.go`/`derlayout.go`
  layout engine), `internal/southbound/derbase` (CSIP `DERControlBase` → SunSpec writes),
  `internal/southbound/modbus` (79-line `Transport` abstraction that `sunspec` imports),
  `internal/ocppserver` (OCPP 2.0.1 CSMS library), and `internal/northbound/model`
  (2030.5 XML structs).
- **Bench** `~/projects/csip-tls-test` (module path `csip-tls-test`, Go 1.21): forked copies at
  `internal/southbound/{sunspec,derbase,modbus}`, `internal/ocppserver`, `internal/csip/model`.

`diff -rq` shows the sunspec/derbase/model forks have **already diverged** (see TASK-020/023
for inventories); `ocppserver` and `southbound/modbus` differ only by import path. The
CLAUDE.md "lockstep rule" (audit MTR-4) failed to prevent this. AD-003 decided: one shared
module (working name `lexa-proto`), developed via `go.work`, consumed by both repos at a
pinned version, CI-enforced (TASK-024).

Neither repo has a `go.work` today, and `~/projects/lexa-proto` does not exist. Neither
repo has a hosted remote decided yet (TASK-001 makes the hosting decision) — this matters
because a bare module path like `lexa-proto` cannot be fetched by `go get`, which
constrains how "version pinning" can work until hosting exists.

## Why this task exists
W3: the intentional duplication diverged under a documented rule; the MTR-4 bug class
(one-sided register-map change misreads real hardware) recurs as long as two copies exist.
This task creates the destination and records the mechanics so TASK-020…023 are mechanical.

## Architecture review sections
W3, D4, R2, §14 item 4; roadmap: 02 AD-003, 03 Phase 1, 04 rows 019–024.

## Prerequisites
- TASK-001 DONE (residual work committed in both repos; hosting decision made — the ADR
  here must record whether a fetchable remote exists yet).
- Go 1.21 toolchain (do not assume TASK-006's refresh has happened).

## Files
- **Read first:**
  - `/home/dmitri/projects/csip-tls-test/docs/refactor/02_ARCHITECTURE_DECISIONS.md` (AD-003)
  - `/home/dmitri/projects/lexa-hub/internal/southbound/modbus/transport.go` (the dependency `sunspec` drags)
  - `/home/dmitri/projects/lexa-hub/go.mod`, `/home/dmitri/projects/csip-tls-test/go.mod`
- **Modify:** `docs/refactor/02_ARCHITECTURE_DECISIONS.md` (extend AD-003);
  `/home/dmitri/projects/lexa-hub/.gitignore` and `/home/dmitri/projects/csip-tls-test/.gitignore`
  only if a `go.work.sum` policy requires it.
- **Create:** `~/projects/lexa-proto/{go.mod,README.md,CLAUDE.md}` + empty package dirs
  `sunspec/`, `derbase/`, `modbus/`, `ocppserver/`, `csipmodel/` (each with a `doc.go`);
  `go.work` in both consumer repos; `~/projects/lexa-proto/scripts/check-cgo-free.sh`.

## Blast radius
No behavior change anywhere. Build graph: adding `go.work` changes how `go build`/`go test`
resolve modules in BOTH repos for every developer and CI — the workspace must list the
repo's own module first and `lexa-proto` second, and both repos must still build with the
skeleton present. Config, runtime, bench: none.

## Implementation strategy
Decide the naming/versioning questions in the ADR first, then create the skeleton to match,
then wire `go.work` and prove both repos still build and test green. Single introduce step —
nothing to dual-run. One package per protocol domain, one module total (AD-003 open
question "one module or three?" → one, split later only under versioning pressure).

## Detailed steps
1. Read AD-003 and TASK-001's hosting decision. Write the AD-003 extension covering:
   (a) **Module path**: use the hosted path if TASK-001 produced one (e.g.
   `github.com/<org>/lexa-proto`); otherwise use bare `lexa-proto` now and record that the
   path flips to the hosted one before TASK-024 lands.
   (b) **Package layout**: `sunspec` (codec + layout engine), `derbase` (imports `sunspec`,
   `csipmodel`), `modbus` (Transport; imported by `sunspec`), `ocppserver`, `csipmodel`.
   (c) **Pinning mechanism** for TASK-024: with a fetchable remote, normal go.mod
   pseudo-versions and the gate compares the two `go.mod` lines; without one, each consumer
   repo commits a `proto.pin` file holding the required lexa-proto commit SHA and the gate
   compares the two files (and that the local checkout matches). State which applies.
   (d) `go.work` is **committed** in both repos for the migration window and removed by
   TASK-024 when pinning becomes authoritative.
2. `mkdir ~/projects/lexa-proto && cd ~/projects/lexa-proto && git init`.
3. Create `go.mod` (chosen module path, `go 1.21` — match the consumers until TASK-006),
   `README.md` (what the module is, who consumes it, the lockstep-deployment note from
   MTR-4), and the five package dirs each containing only `doc.go` with a package comment
   naming the source package it will absorb and the migrating task ID.
4. Create `CLAUDE.md` with the invariants that follow the code here: SunSpec int16
   watt fields scale into the multiplier, never raw-cast (GS-1/MTR-1); every 2030.5 root
   element carries `xmlns="urn:ieee:std:2030.5:ns"`; OCPP sessions are TransactionEvent
   lifecycles, never bare MeterValues; module stays CGo-free.
5. Add `scripts/check-cgo-free.sh`: `CGO_ENABLED=0 go build ./... && CGO_ENABLED=0 go vet ./...`
   — run it; commit the skeleton.
6. In `~/projects/lexa-hub`: `go work init . ../lexa-proto`; commit `go.work`. Run
   `make test` (`go test -race ./internal/...`) — must be green and unaffected.
7. In `~/projects/csip-tls-test`: same (`go work init . ../lexa-proto`); run `make test-fast`
   and `go test ./tests/` — green.
8. If TASK-002/003 CI exists already, confirm CI checks out the sibling repo or vendors it;
   if CI cannot see `../lexa-proto` yet, record in the ADR extension that CI runs
   `GOFLAGS=-mod=mod GOWORK=off` until TASK-020 flips the first consumer (skeleton is
   unreferenced, so `GOWORK=off` builds still pass).

## Testing changes
No new tests. Prove no regression:
```bash
cd ~/projects/lexa-proto && bash scripts/check-cgo-free.sh
cd ~/projects/lexa-hub && make test
cd ~/projects/csip-tls-test && make test-fast && go test ./tests/
```

## Documentation changes
- `02_ARCHITECTURE_DECISIONS.md`: AD-003 extension (step 1) — this is a deliverable, not
  an afterthought.
- `lexa-proto/README.md`, `lexa-proto/CLAUDE.md` (created above).
- Do NOT touch the CLAUDE.md lockstep prose in the consumer repos yet — that is TASK-024's
  job, after the duplicates are actually gone.

## Common mistakes to avoid
- Inventing a hosted module path that doesn't exist: `go mod tidy` in a consumer will try
  to fetch it and fail. Bare path + `go.work` is fine until hosting is real.
- Adding a `replace` directive in the consumers' `go.mod` "just in case": with `go.work`
  it is redundant, and it will fight the TASK-024 pin gate later. Use one mechanism.
- Putting real code in the skeleton. TASK-020/022/023 own the moves; pre-copying creates a
  third divergent copy.
- Letting the module require CGo transitively — none of the five packages may import
  `internal/wolfssl` or `internal/tlsclient` (05 §1 CGo containment).

## Things that must NOT change
- Both consumer repos' test suites stay green with zero diffs to product/bench source.
- `lexa-hub` module path stays `lexa-hub`; `csip-tls-test` stays `csip-tls-test`
  (invariant in lexa-hub/CLAUDE.md — import paths across both repos depend on it).
- No preservation-ledger entries touched (no defensive code involved).

## Acceptance criteria
- [ ] `~/projects/lexa-proto` exists, `git log` shows the skeleton commit,
      `bash scripts/check-cgo-free.sh` exits 0.
- [ ] `go.work` committed in both repos; `go build ./...` green in both.
- [ ] `make test` (lexa-hub) and `make test-fast` + `go test ./tests/` (csip-tls-test) green.
- [ ] AD-003 extension answers module path, layout, pinning, and go.work-commit policy
      explicitly (no "TBD").

## Regression checklist
- [ ] `make test-fast` (csip-tls-test) / `go test -race ./internal/...` (lexa-hub) green
- [ ] Conformance logic tests: not protocol-adjacent — `go test ./tests/` run anyway (cheap)
- [ ] Mayhem: none (no runtime change)
- [ ] Both repos build with `GOWORK=off` (skeleton unreferenced)

## Mayhem scenarios affected
None.

## Conformance implications
None yet; the module will carry SunSpec/2030.5/OCPP codecs from TASK-020 onward.

## Suggested commit message
`feat(proto): lexa-proto module skeleton + go.work wiring + AD-003 mechanics`
(lexa-proto repo; matching chore commits in each consumer repo)
`Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>`

## Suggested PR title & description
**Title:** Phase 1: lexa-proto shared-module skeleton and workspace wiring
**Description:** Creates the shared protocol module destination (empty skeleton, CGo-free
gate), commits go.work in both consumer repos, and records module path / layout /
version-pinning mechanics in AD-003. No code moves; zero runtime change. Rollback: delete
go.work files. Paired PRs in lexa-hub and csip-tls-test per 05 §11.

## Code review checklist
- ADR extension actually decides (path/pinning), not defers.
- go.work lists the repo's own module before lexa-proto.
- Skeleton contains no logic; doc.go comments name source packages + migrating tasks.
- CGo-free script runs in whatever CI exists.

## Definition of done
Acceptance criteria + regression checklist pass; AD-003 updated; this file's status header
and `00_MASTER_INDEX.md` P1 row updated.

## Possible follow-up tasks
TASK-020 (sunspec/derbase move), TASK-022 (ocppserver), TASK-023 (csipmodel),
TASK-024 (pin gate). Backlog: split module if versioning pressure appears (AD-003).
