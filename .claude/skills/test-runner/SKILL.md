---
name: test-runner
description: Run the right tests for the most recently changed code and report results concisely. Use after any code change in this repo, before claiming work is done.
---

# Test runner

## Procedure

1. **Always run first**: `make test-fast` (unit tests, no network, <1 s).

2. **Then run based on what changed** (union of all that apply):
   | Changed | Run |
   |---|---|
   | `internal/csip/`, `sim/gridsim/` | `go test ./tests/ ./sim/gridsim/...` |
   | `internal/southbound/`, `sim/southbound/` | `go test ./internal/southbound/... ./sim/southbound/...` |
   | `sim/evsim/` | `go test ./sim/evsim/...` (the OCPP server is now shared `lexa-proto/ocppserver`, vendored — test the server itself in the lexa-proto module) |
   | `sim/simapi/` | `go test ./sim/simapi/...` |
   | `internal/tlsclient/`, `sim/tlsserver/` | `make test-integration` (wolfSSL; works on this desktop via the amd64 sysroot) |
   | `internal/mbtls/`, `sim/mbapsdev/` | `make test-integration` (cgo wolfSSL — mbaps handshake + loopback device-sim tests; `make test-fast` also compiles+runs their non-integration-tagged unit tests) |
   | `internal/aggregator/` | `make test-integration` (cgo wolfSSL — the mbaps emulator core/engine/probes vs a loopback authz server; `make test-fast` runs its pure-Go PKI/campaign/report tests) |
   | `sim/ssm-conformance/` | `make test-integration` (cgo wolfSSL — the full 62-requirement suite vs a loopback gateway + the "teeth" test; `make test-fast` runs the requirement-table/predicate/minting tests). Smoke the walker itself with `make ssm-conformance` (loopback, no bench). |
   | anything touching goroutines, locks, maps shared across goroutines | add `-race` to the relevant `go test` (the audit found two real races this would have caught) |
   | `cmd/dashboard/` | `go build ./cmd/dashboard` (SPA is embedded HTML — build check only) |
   | `cmd/` otherwise | `go build ./...` |

3. **Report format**
   - All pass: "All N tests pass." One line. Done.
   - Per failure: test name, file:line, exact error. Nothing else.

4. **On failure**: read the failing test + the code it exercises, identify root cause, propose the minimal fix. Do not refactor surrounding code.

## Do not
- Re-run a test that just passed to "double-check".
- Run Pi-only targets (`conformance-pi`, `smoke-pi`, anything `-pi`) unless asked — they SSH to the bench.
- Suggest adding coverage beyond what was broken.
- Touch `lexa-proto/sunspec` register constants without a paired proto bump — they're a single shared source now, not a hub-side twin fork; a change means editing lexa-proto and regenerating both repos' `proto.pin` in the same session (lockstep rule MTR-4, CI-enforced by `check-proto-pin.sh`).
