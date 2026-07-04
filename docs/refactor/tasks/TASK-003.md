# TASK-003 — CI pipeline: csip-tls-test (build, test-fast, conformance logic)

*Status: TODO · Phase: P0 · Effort: M (≈4–6 h) · Difficulty: med · Risk: low*

## Objective
Every PR and push to `main` of `dsizzle83/csip-tls-test` runs GitHub Actions: build of
every sim/dashboard binary, the fast unit suites, the southbound suites, the QA-harness
unit gate, and the protocol/conformance logic tests (`go test ./tests/`). Checks required
on `main`.

## Background
The bench repo `/home/dmitri/projects/csip-tls-test` (module `csip-tls-test`, `go 1.21`)
holds the gridsim server, four device sims, the dashboard (Mayhem + replay engines), and
the conformance suites. No `.github/` exists. Verified test surfaces:
- `make test-fast` = `go test ./sim/tlsserver/ ./internal/tlsclient/ ./internal/southbound/sunspec/`.
  **This compiles cgo** (`internal/tlsclient` imports `internal/wolfssl`) even though the
  TLS-handshake tests are `//go:build integration`-tagged — so the CI runner needs
  wolfSSL headers (same recipe as TASK-002).
- `go test ./tests/` — 2030.5 discovery/MUP/CSIP + in-process Modbus conformance logic.
  `tests/wolfssl_integration_test.go` is `integration`-tagged (excluded by default), but
  the package still needs cgo to compile? No — `tests/` imports `internal/httpclient`
  (pure Go) in the untagged files; the tagged file is excluded entirely. It compiles
  cgo-free. Verify with `CGO_ENABLED=0 go test -count=1 ./tests/` during implementation;
  if it fails, run it in the cgo job instead.
- `go test ./internal/southbound/... ./internal/bridge/...` (= `make test-southbound`
  first half; pure Go).
- QA-harness unit gate: `scripts/qa-regression.sh` unit mode =
  `go test ./sim/southbound/... ./sim/evsim/... ./sim/gridsim/... ./cmd/dashboard/...`.
- `make test-integration` (real mTLS handshakes) and everything touching the 69.0.0.x
  bench stay **out** of hosted CI.
- Test cert fixtures are auto-generated: the Makefile's `$(CA_CERT)` rule runs
  `scripts/gen-test-certs.sh` when missing. Some suites may rely on that make dependency;
  invoke test targets via `make` where fixtures matter.

## Why this task exists
Same as TASK-002 for the bench repo: review §13/§14 item 2. The harness is the
regression oracle for the whole refactor; its own logic must be CI-guarded before it
gates anything else.

## Architecture review sections
§13, §14 item 2, A-grade QA culture to protect (§3.2). Roadmap: 03 P0; 06 §1/§2.

## Prerequisites
TASK-001 (residuals committed; branch state normalized). TASK-002 first is convenient
(reuse the wolfSSL cache recipe) but not blocking.

## Files
- **Read first:** `/home/dmitri/projects/csip-tls-test/Makefile` (test targets, sysroot
  wiring, cert fixture rule), `scripts/qa-regression.sh`, `scripts/gen-test-certs.sh`.
- **Modify:** none of the Go source.
- **Create:** `/home/dmitri/projects/csip-tls-test/.github/workflows/ci.yml`.

## Blast radius
None at runtime. Repo metadata only.

## Implementation strategy
Two jobs. Job `pure-go`: everything that runs `CGO_ENABLED=0` — build all sim/dashboard
binaries, southbound + QA-harness + `tests/` suites. Job `cgo-fast`: wolfSSL cached build
(identical recipe to TASK-002), then `make test-fast` (which needs the sysroot env) and a
build of the cgo binaries (`sim/server`, `sim/conformance`, `sim/client`). Bench-touching
suites are explicitly out of scope and documented as such in the workflow header.

## Detailed steps
1. Create `.github/workflows/ci.yml` (triggers as in TASK-002; `go-version-file: go.mod`).
2. Job **pure-go** (`CGO_ENABLED=0` env for every step):
   - Build each pure-Go binary exactly as the Makefile does:
     `go build ./sim/modsim ./sim/batsim ./sim/metersim ./sim/evsim ./sim/modsim-client
     ./sim/modsim-conformance ./sim/httpsim ./cmd/dashboard ./cmd/mqttproxy`.
   - `go vet` over the same package set plus `./sim/southbound/... ./internal/southbound/...`.
   - `go test ./internal/southbound/... ./internal/bridge/...`
   - `go test ./sim/southbound/... ./sim/evsim/... ./sim/gridsim/... ./cmd/dashboard/...`
     (the qa-regression unit gate — run the script itself if it stays pure-Go:
     `bash scripts/qa-regression.sh`).
   - `go test ./tests/` (generate cert fixtures first if the suite needs them:
     `bash scripts/gen-test-certs.sh` — it must run headless; verify once locally).
3. Job **cgo-fast**: wolfSSL 5.7.6 cached install (copy the TASK-002 steps verbatim);
   export `CGO_CFLAGS`/`CGO_LDFLAGS` (with `-lm`); run `make test-fast` with
   `WOLFSSL_SYSROOT=$HOME/wolfssl-amd64` (the Makefile picks it up when
   `$(WOLFSSL_SYSROOT)/include` exists); then `go build ./sim/server ./sim/client
   ./sim/conformance`.
4. Note in the workflow header: `make test-integration`, `scripts/run-conformance.sh`,
   `make qa-bench`, and anything referencing 69.0.0.x are bench-only; the self-hosted
   desktop runner (label `[self-hosted, desktop]`) is the designated future home if a
   bench-in-the-loop job is ever wanted.
5. PR the workflow; verify both jobs green; add them as required checks on `main`.
6. Confirm `git status` stays clean after a CI-equivalent local run (cert fixture
   generation writes into `sim/tlsserver/testdata/certs/` and
   `internal/tlsclient/testdata/certs/` — both are gitignored artifacts; verify).

## Testing changes
No new Go tests. Deliverable is the pipeline. Prove red-on-failure once with a scratch
commit, then revert.

## Documentation changes
- `CLAUDE.md` (csip-tls-test) Commands section: add the CI one-liner.
- 00_MASTER_INDEX status table.

## Common mistakes to avoid
- `make test-fast` fails on a bare runner — `internal/tlsclient` is cgo. It belongs in
  the cgo job with the sysroot env, not the pure-go job.
- Cert fixtures: run `scripts/gen-test-certs.sh` before `./tests/` if any test opens
  them; the make rule normally handles this — calling `go test` directly bypasses it.
- Do not add bench IPs, SSH keys, or simapi calls to hosted CI.
- `cmd/hub` still exists until TASK-010: do NOT add it to the CI build matrix (it's
  cgo and slated for deletion); do not "fix" it if it breaks.
- The dashboard tests (`./cmd/dashboard/...`) include Mayhem engine unit tests — they run
  without a bench; if one requires network, that's a bug to report, not skip silently.

## Things that must NOT change
- `make test-fast` / `make test-integration` semantics for desktop use.
- The gitignore status of generated cert fixtures (`*-key.pem` never committed).
- The Mayhem engine and scenarios (`cmd/dashboard/mayhem.go`) — CI only runs their unit
  tests.

## Acceptance criteria
- [ ] PR shows both jobs green and required.
- [ ] `pure-go` job runs with `CGO_ENABLED=0` throughout (visible in logs).
- [ ] `go test ./tests/` passes in CI (conformance logic green).
- [ ] Deliberate failing-test commit turns the check red (verified, reverted).

## Regression checklist
- [ ] `make test-fast` green locally (desktop)
- [ ] Conformance logic tests green (`go test ./tests/`) — they ARE this task's payload
- [ ] Mayhem: none (no runtime change)
- [ ] `bash scripts/qa-regression.sh` (unit mode) green locally

## Mayhem scenarios affected
None (engine untouched; its unit tests gain a CI home).

## Conformance implications
Conformance *logic* tests now gate every PR. Full evidence regeneration
(`scripts/run-conformance.sh`) remains a bench/release activity (M0, 081).

## Suggested commit message
`ci(csip-tls-test): GitHub Actions — sims/dashboard build, southbound+QA+conformance-logic tests, cgo fast suite`
`Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>`

## Suggested PR title & description
**Title:** CI pipeline for csip-tls-test
**Description:** Two jobs (pure-Go / cgo-fast with cached wolfSSL 5.7.6). Bench-touching
suites explicitly excluded. Risk: none at runtime. Rollback: delete workflow, unrequire
checks.

## Code review checklist
- Package lists match the Makefile targets (no binary silently dropped).
- Fixture generation is headless and artifacts stay untracked.
- cgo split verified against imports, not guessed.

## Definition of done
Acceptance criteria + regression checklist + docs updated + status headers updated.

## Possible follow-up tasks
TASK-004 (lockstep gate lives in this repo's CI), TASK-005, TASK-015 (campaign wrapper
could later emit CI-readable artifacts).
