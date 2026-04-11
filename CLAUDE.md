# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
# Unit tests only (fast, sub-second, no network)
make test-fast
# or directly:
go test ./internal/tlsserver/ ./internal/tlsclient/

# Full integration tests (real TLS handshakes, auto-generates certs if missing)
make test-integration
# or:
go test -tags=integration -v ./internal/tlsserver/ ./internal/tlsclient/

# Milestone 3+ integration tests (no wolfSSL, uses Go net/http)
go test ./tests/

# Run a single test (example)
go test ./internal/tlsclient/ -run TestParseHTTPResponse

# Regenerate DCAP golden file after intentional format changes
make test-update-golden

# Build binaries (outputs to bin/)
make build

# Regenerate test cert fixtures
make gen-test-certs

# Pi hardware smoke test (NOT part of make test)
make smoke-pi
```

## Architecture

This project is a **CSIP / IEEE 2030.5 mTLS client** for DER devices (Raspberry Pi in dev, NXP i.MX 93 in production). The client talks to utility grid management servers using the cipher mandated by CSIP §5.2.1.1: `ECDHE-ECDSA-AES128-CCM-8`.

### Two parallel stacks

The codebase currently has two stacks in development that will converge:

**Milestone 2 stack — raw mTLS layer (wolfSSL)**
- `internal/wolfssl/` — the only cgo package. Wraps wolfSSL C API. Both client and server import this; nothing else touches cgo. `wolfSSL_Init` is process-global — must be called exactly once per process via a `TestMain` or `main()`.
- `internal/tlsclient/` — CSIP-compliant mTLS client. Lifecycle: `New` → `Dial` → `Get`/`FetchDCAP` → `Close`. `New` loads certs once; `Dial` opens the TCP+TLS session. After a `Get`, the connection is consumed (server sends `Connection: close`); callers must `Close` + `Dial` again to reuse.
- `internal/tlsserver/` — test fixture server (mTLS, same cipher enforcement). Used to validate the client.
- `client/main.go`, `server/main.go` — thin binaries for the Milestone 2 stack.

**Milestone 3+ stack — CSIP protocol layer (pure Go)**
- `internal/csip/model/` — Go structs for all IEEE 2030.5 resources (`DeviceCapability`, `EndDevice`, `DERProgram`, `DERControl`, etc.) with XML tags matching the 2030.5 schema. XML namespace `urn:ieee:std:2030.5:ns` is mandatory on root elements.
- `internal/csip/discovery/` — Link walker (`Walker`) that traverses the resource tree starting from `/dcap`. Follows links in XML responses to discover the client's `EndDevice` (by LFDI match), FSAs, DERPrograms, and controls. Never hardcodes URLs beyond `/dcap` — every other URL comes from link attributes. Accepts a `Fetcher` interface so it can be tested without a real server.
- `internal/csip/identity/` — Derives LFDI and SFDI from X.509 client certs per IEEE 2030.5-2018 §6.3.4. LFDI = leftmost 160 bits of SHA-256 over the cert's DER encoding.
- `internal/gridsim/` — Minimal IEEE 2030.5 server serving a static conformance test resource tree (CORE-010/CORE-012 setup). Uses Go's `net/http`, not wolfSSL. Used in tests and as a standalone simulator via `cmd/server/main.go`.
- `internal/httpclient/` — `Fetcher` implementation over Go's `net/http`. Bridge between the discovery walker and an actual HTTP server. Will be replaced by a wolfSSL-backed transport in a later milestone.
- `cmd/client/main.go`, `cmd/server/main.go` — Milestone 3+ binaries using `gridsim` and `httpclient`.
- `tests/integration_test.go` — End-to-end walk tests: spins up `gridsim` via `httptest.NewServer`, runs `discovery.Walker` through `httpclient.Fetcher`, validates the full resource tree.

### Test layering

1. **Unit tests** (no build tag): request building, response parsing, XML marshal/unmarshal. No network, no cgo calls. Run with `make test-fast`.
2. **Integration tests** (`-tags=integration`): real mTLS handshakes against an in-process wolfSSL server. Auto-generates cert fixtures on first run.
3. **Milestone 3 integration tests** (`tests/`): full discovery walk over `net/http` + `gridsim`.
4. **Hardware smoke test** (`make smoke-pi`): manual, cross-compiles for `arm64`, deploys to Pi. Not part of `go test`.

### Key constraints
- Production certs live in `certs/` (vault); test certs are in `internal/tlsserver/testdata/certs/` and `internal/tlsclient/testdata/certs/`.
- `wolfssl.RequireClientCert` is the call that enforces mTLS — without it, wolfSSL happily accepts unauthenticated clients regardless of loaded CAs.
- The `Fetcher` interface in `discovery` is deliberately minimal (`Get(path string) ([]byte, error)`) to keep discovery decoupled from TLS, HTTP, and connection management.
