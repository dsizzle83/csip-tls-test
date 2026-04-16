Run the appropriate tests for the code that was most recently changed and report results concisely.

## Procedure

1. **Always run first**: `make test-fast` (unit tests, no network, <1 s)

2. **Run based on what changed**:
   - `internal/csip/` or `internal/tlsclient/` or `internal/tlsserver/` →
     `go test -tags=integration -v ./internal/tlsserver/ ./internal/tlsclient/`
   - `internal/csip/` or `internal/gridsim/` →
     `go test ./tests/`
   - `internal/southbound/` →
     `go test ./internal/southbound/...`
   - `cmd/` binaries →
     `go build ./...` (build check; no unit tests for binaries)

3. **Report format**
   - Show count of passing tests (one line).
   - For each failure: test name, file:line, exact error. Nothing else.
   - If all pass: "All N tests pass." Done.

4. **On failure**: read the failing test + the code it exercises. Identify root cause. Propose the minimal fix — do not refactor surrounding code.

## Do not
- Re-run a test that just passed to "double-check."
- Run `make test-integration` unless explicitly asked (requires wolfSSL on arm64 Pi).
- Suggest adding test coverage beyond what was broken.
