# TASK-002 — CI pipeline: lexa-hub (build, vet, `-race` tests)

*Status: DONE, partial (2026-07-04, 8a183c6 on `task/002-ci-pipeline`) —
required-checks registration + PR blocked on missing GitHub credential,
see notes · Phase: P0 · Effort: M (≈4–6 h) · Difficulty: med · Risk: low*

**Completion notes (2026-07-04):** `.github/workflows/ci.yml` created
(3 jobs split on the verified cgo boundary), `make test-nocgo` added,
CLAUDE.md Build note added. Branch `task/002-ci-pipeline` pushed to
origin; **not merged** — Principal reviews/merges. Validated live on
hosted Actions via a temporary `task/**` push trigger (reverted in
`8a183c6`): run 28722650437 (`8861ec5`) all 3 jobs green cold-cache
(vet-build-test 57 s, cgo 84 s incl. wolfSSL source build, cross 29 s);
run 28722700755 (`a231828`, deliberate failing test) red on
vet-build-test only, as designed; run 28722742942 (`4a185de`, revert)
all green warm-cache (cgo 38 s — wolfSSL build skipped on cache hit).
Local regression: `make test`, `make test-nocgo`, `make build`,
`make build-arm64` all green on the desktop. **Not completed (no
`gh`/API credential in the execution environment — same wall as
TASK-001):** opening the first PR (step 6) and marking the three checks
required in branch protection (step 7, final acceptance criterion).
Human follow-up: enable branch protection on `main` requiring status
checks `vet-build-test`, `cgo`, `cross` (names match job ids), then open
the PR from `task/002-ci-pipeline`.

## Objective
Every PR and every push to `main` of `dsizzle83/lexa-hub` runs a GitHub Actions pipeline:
`go vet`, cgo-free build of all six services, `go test -race` over all pure-Go packages,
and a cgo job that builds wolfSSL and compiles/tests the two cgo packages. The checks are
required by branch protection.

## Background
The product repo `/home/dmitri/projects/lexa-hub` (module `lexa-hub`, `go 1.21` in go.mod)
has six services under `cmd/{hub,northbound,modbus,ocpp,telemetry,api}` and no CI at all
(no `.github/` directory exists). The local test entrypoint is `make test` =
`go test -race ./internal/...`.

CGo topology (verified):
- Only `internal/wolfssl` (the cgo wrapper) and `internal/tlsclient` (imports it) need
  wolfSSL headers. Everything else, including `internal/northbound`,
  `internal/orchestrator`, `internal/bus`, `internal/mqttutil`, `internal/southbound`,
  `internal/ocppserver`, is pure Go.
- `CGO_ENABLED=0 go build ./...` fails only for `cmd/northbound` and `cmd/telemetry`
  (they import `internal/wolfssl`/`internal/tlsclient`).
- `internal/tlsclient`'s handshake tests (`client_test.go`, `fetcher_test.go`) are behind
  `//go:build integration` — plain `go test` compiles the package but runs no TLS.
- The desktop keeps an amd64 wolfSSL sysroot at `~/.local/wolfssl-amd64`; the Makefile
  auto-wires it into `CGO_CFLAGS`/`CGO_LDFLAGS` (static `libwolfssl.a` needs `-lm`).
  The Makefile's `wolfssl-arm64` target documents the exact wolfSSL build recipe
  (version `5.7.6-stable`, `--enable-tls13 --enable-aesccm --enable-tlsx
  --enable-certgen --enable-opensslall --enable-static --disable-shared`).

## Why this task exists
Review §13/§14 item 2: "no CI, no PR review evident." Without CI, branch protection
(TASK-001) protects nothing, and the entire refactor program's regression gates
(`-race`, later govulncheck and fuzzers) have nowhere to live.

## Architecture review sections
§13 (Process), §14 item 2, D10-adjacent. Roadmap: 03 P0; 05 §4 (`-race` non-negotiable),
§11; 06 §2 (Unit target state).

## Prerequisites
TASK-001 (remotes pushed, branch protection exists to attach checks to).

## Files
- **Read first:** `/home/dmitri/projects/lexa-hub/Makefile` (test target, wolfSSL recipe,
  sysroot wiring), `/home/dmitri/projects/lexa-hub/go.mod`.
- **Modify:** none of the Go source. Optionally add a `test-nocgo` Makefile target.
- **Create:** `/home/dmitri/projects/lexa-hub/.github/workflows/ci.yml`.

## Blast radius
None at runtime. Repo metadata + Makefile only.

## Implementation strategy
One workflow, three jobs. Job `vet-build-test` (ubuntu-latest, hosted): pure-Go surface —
fast, no wolfSSL. Job `cgo` (ubuntu-latest): builds wolfSSL 5.7.6 from source into a
cached sysroot, then builds the two cgo services and compiles `internal/tlsclient`'s
tests. Job `cross` : `CGO_ENABLED=0 GOOS=linux GOARCH=arm64` build of the four pure-Go
services (the deploy artifacts). Keep a documented self-hosted-runner fallback for the
day hosted runners are unacceptable (air-gap policy) — the desktop already has the
sysroot.

## Detailed steps
1. Create `.github/workflows/ci.yml` triggered on `pull_request` and
   `push: branches: [main]`. Use `actions/setup-go` with `go-version-file: go.mod` and
   built-in module caching.
2. Job **vet-build-test**:
   - `go vet $(go list ./... | grep -v -e internal/wolfssl -e internal/tlsclient -e cmd/northbound -e cmd/telemetry)`
   - `CGO_ENABLED=0 go build ./cmd/hub ./cmd/modbus ./cmd/ocpp ./cmd/api`
   - `go test -race $(go list ./internal/... | grep -v -e internal/wolfssl -e internal/tlsclient)`
     (this is `make test` minus the two cgo packages).
   - `go test -race $(go list ./cmd/... | grep -v -e cmd/northbound -e cmd/telemetry)`
     — the cmd-level suites (`cmd/hub` state/actuators/breach tests, `cmd/modbus`,
     `cmd/ocpp`, `cmd/api`) that `make test` never runs. The two wolfSSL-importing cmd
     packages are excluded here (`CGO_ENABLED=0`) and covered by the cgo job.
3. Job **cgo**:
   - Restore/`actions/cache` a wolfSSL install keyed on the version string; on miss,
     download `v5.7.6-stable`, `./configure` with the exact flag set from the Makefile's
     `wolfssl-arm64` target (host build, no `--host=`), `make install` to
     `$HOME/wolfssl-amd64`.
   - Export `CGO_CFLAGS=-I$HOME/wolfssl-amd64/include`,
     `CGO_LDFLAGS="-L$HOME/wolfssl-amd64/lib -lm"`.
   - `go build ./cmd/northbound ./cmd/telemetry` and
     `go test -race ./internal/tlsclient/ ./internal/wolfssl/ ./cmd/northbound/`
     (compiles cgo, runs the non-integration tests including northbound's
     `response_test.go`; the `integration`-tagged handshake tests stay
     desktop/bench-only via `make test-integration` in csip-tls-test).
4. Job **cross**: `CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build ./cmd/hub ./cmd/modbus
   ./cmd/ocpp ./cmd/api` (proves the deploy path stays cross-compilable — the arm64 cgo
   pair requires the aarch64 sysroot and remains a desktop-only `make build-arm64`).
5. Optionally add Makefile target `test-nocgo` mirroring step 2's test command so local
   and CI invocations stay identical; reference it from the workflow.
6. Push on a branch, open the repo's first PR, confirm all three jobs pass.
7. In GitHub branch protection for `main`, mark the three job names as required checks.
8. Document the self-hosted fallback in the workflow header comment: label
   `[self-hosted, desktop]`, sysroot `~/.local/wolfssl-amd64`, and why it exists
   (air-gap escape hatch; also the future home of bench-touching jobs).

## Testing changes
No new Go tests. The pipeline itself is the deliverable; prove it by a PR that (a) passes,
and (b) a deliberate scratch commit with a failing test is rejected (revert it after).

## Documentation changes
- `lexa-hub/CLAUDE.md`: add one line under Build: "CI: `.github/workflows/ci.yml` —
  vet + `-race` (pure-Go) + cgo build on every PR; required checks on `main`."
- 00_MASTER_INDEX status table.

## Common mistakes to avoid
- Do not run `go test -race ./internal/...` verbatim on a hosted runner — it compiles
  `internal/tlsclient` (cgo) and fails without wolfSSL headers. Split as in steps 2–3.
- The static `libwolfssl.a` needs `-lm` in `CGO_LDFLAGS` or the cgo job fails at link
  time with `pow`/`log` undefined (Makefile comment documents this).
- `go vet ./...` also compiles cgo packages — filter the same way.
- Don't pin `go-version: '1.21'` literally; use `go-version-file` so TASK-006's toolchain
  bump doesn't leave CI on an old compiler.
- Keep hosted CI away from anything bench-facing: no SSH, no 69.0.0.x, no secrets beyond
  `GITHUB_TOKEN`.

## Things that must NOT change
- `make test` semantics for developers (still `go test -race ./internal/...` on the
  desktop where the sysroot exists).
- wolfSSL version/flags: mirror the Makefile's `5.7.6-stable` recipe exactly — the cipher
  invariant `ECDHE-ECDSA-AES128-CCM-8` depends on `--enable-aesccm`.
- No source changes to any service in this task.

## Acceptance criteria
- [ ] A PR against lexa-hub `main` shows three green required checks.
- [ ] `go test -race` covers `./internal/...` AND `./cmd/...` across the two test jobs
      (pure-Go cmd suites in `vet-build-test`; `cmd/northbound` in `cgo`) — no test
      package left unrun.
- [ ] `vet-build-test` finishes in <3 min; `cgo` <8 min warm-cache.
- [ ] A commit with an intentionally failing unit test produces a red check (verified once, then reverted).
- [ ] Branch protection lists the checks as required.

## Regression checklist
- [ ] `go test -race ./internal/...` still green locally (desktop) — CI split changed nothing
- [ ] Conformance logic tests: not applicable (no product code touched)
- [ ] Mayhem: none (no runtime change)
- [ ] `make build && make build-arm64` still work on the desktop

## Mayhem scenarios affected
None.

## Conformance implications
None directly; CI later hosts the conformance smoke (TASK-003 covers the bench repo side).

## Suggested commit message
`ci(lexa-hub): GitHub Actions — vet, cgo-free -race tests, wolfSSL cgo build, arm64 cross`
`Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>`

## Suggested PR title & description
**Title:** CI pipeline for lexa-hub (vet + -race + cgo + cross-compile)
**Description:** Adds `.github/workflows/ci.yml` (3 jobs, split on the verified cgo
boundary: only `internal/wolfssl` + `internal/tlsclient` need wolfSSL). Risk: none at
runtime. Testing: PR checks themselves + local `make test`. Rollback: delete the workflow
file; branch protection check requirement removed in repo settings.

## Code review checklist
- cgo/pure-Go package split matches `grep -rl 'internal/wolfssl' --include='*.go'` reality.
- wolfSSL configure flags identical to the Makefile recipe.
- Workflow has no bench/SSH/secret access.
- Required-check names match job names exactly.

## Definition of done
Acceptance criteria + regression checklist + docs updated + status headers (this file +
00_MASTER_INDEX) updated.

## Possible follow-up tasks
TASK-004 (lockstep gate), TASK-005 (govulncheck job), TASK-047/048 (fuzz jobs), TASK-006
(toolchain bump rides on `go-version-file`).
