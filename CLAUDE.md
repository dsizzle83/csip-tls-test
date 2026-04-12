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
# Build just the production mTLS server
go build -o bin/server ./server/

# Regenerate test cert fixtures
make gen-test-certs

# Issue a new client cert from the production CA (run from repo root)
make gen-client-cert                   # CN=csip-test-der-001 (default)
make gen-client-cert CN=csip-pi-002   # custom CN

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
- `internal/tlsclient/fetcher.go` — `WolfSSLFetcher` implements `discovery.Fetcher`. Wraps `*Client`; redials per `Get` call (redial-per-request strategy, accepted at Milestone 3 boundary). **DONE (Step B).**
- `internal/tlsserver/` — CSIP-compliant mTLS server. Set `srv.Handler = someHTTPHandler` to route requests through any `http.Handler` instead of the built-in static router. `dispatchHTTP` bridges raw wolfSSL bytes ↔ `http.Handler` via `http.ReadRequest` + `bufferedResponseWriter`.
- `client/main.go`, `server/main.go` — production mTLS binaries. `server/main.go` now reads `certs/client-cert.pem`, derives the client LFDI via `identity.FromCertificate`, boots `gridsim.NewServer(lfdi)`, and wires `sim.Handler()` into the wolfSSL server. **DONE (Step C).**

**Milestone 3+ stack — CSIP protocol layer (pure Go)**
- `internal/csip/model/` — Go structs for all IEEE 2030.5 resources (`DeviceCapability`, `EndDevice`, `DERProgram`, `DERControl`, etc.) with XML tags matching the 2030.5 schema. XML namespace `urn:ieee:std:2030.5:ns` is mandatory on root elements.
- `internal/csip/discovery/` — Link walker (`Walker`) that traverses the resource tree starting from `/dcap`. Follows links in XML responses to discover the client's `EndDevice` (by LFDI match), FSAs, DERPrograms, and controls. Never hardcodes URLs beyond `/dcap` — every other URL comes from link attributes. Accepts a `Fetcher` interface so it can be tested without a real server.
- `internal/csip/identity/` — Derives LFDI and SFDI from X.509 client certs per IEEE 2030.5-2018 §6.3.4. LFDI = leftmost 160 bits of SHA-256 over the cert's DER encoding.
- `internal/gridsim/` — IEEE 2030.5 simulator. Phase 2 features: **LFDI-gated /edev** (returns only the connecting device's EndDevice when `X-Peer-LFDI` header is present; 403 on `/edev/0` and `/edev/1`); **3 DERPrograms** (primacy 1/5/10) with rich DERControls (overlapping/superseded, cancelled, randomized, active list); **MirrorUsagePoint POST flow** (POST `/mup` → 201+Location, POST `/mup/{n}` → 204). `SetClientCertDER(der []byte)` is called once per connection to derive LFDI/SFDI from the live mTLS peer cert and rebuild `/edev`.
- `internal/httpclient/` — `Fetcher` over Go's `net/http`. Implements both `Get` and `Post(path, body, contentType) ([]byte, location, error)`. Bridge between the discovery walker and an HTTP server.
- `internal/tlsclient/fetcher.go` — `WolfSSLFetcher` implements `Get` and `Post` (same signature as httpclient). Redials per call.
- `tests/integration_test.go` — Full Phase 2 test suite: discovery walk (3 programs), DefaultDERControl fallback, MUP POST flow, LFDI-gated filtering, 403 guard.

### Milestone 3 — ALL DONE

| Step | Status |
|------|--------|
| A — LFDI from live peer cert | **DONE** — `wolfssl.PeerCertificateDER` + `OnClientCert` callback + `SetClientCertDER` |
| B — `WolfSSLFetcher` implements `Fetcher` | **DONE** — `internal/tlsclient/fetcher.go` |
| C — tlsserver routes through `gridsim.Handler()` | **DONE** — `srv.Handler` + `dispatchHTTP` bridge |
| D — Full-stack integration test | **DONE** — `tests/wolfssl_integration_test.go` |

### Phase 2 — ALL DONE

- LFDI-gated `/edev` filtering + 403 for non-client EndDevice paths
- 3 DERPrograms (primacy 1/5/10) with DefaultDERControl per program
- 4 DERControls in SP program: superseded, supersedes, cancelled, randomized
- Active DERControl list (currently executing event)
- MirrorUsagePoint POST flow: POST `/mup` → 201+Location, POST `/mup/{n}` → 204
- `Post` method on `WolfSSLFetcher` and `httpclient.Fetcher`
- Model types: `MirrorMeterReading`, `MirrorReadingSet`, `Reading`, `ReadingType`
- `X-Peer-LFDI` injected by `tlsserver.dispatchHTTP` for per-connection gating

### Test layering

1. **Unit tests** (no build tag): request building, response parsing, XML marshal/unmarshal. No network, no cgo calls. Run with `make test-fast`.
2. **Integration tests** (`-tags=integration`): real mTLS handshakes against an in-process wolfSSL server. Auto-generates cert fixtures on first run.
3. **Milestone 3 integration tests** (`tests/`): full discovery walk over `net/http` + `gridsim`.
4. **Hardware smoke test** (`make smoke-pi`): manual, deploys to Pi and runs against WSL2 server. Not part of `go test`.

### Key constraints
- Production certs live in `certs/` (vault); test certs are in `internal/tlsserver/testdata/certs/` and `internal/tlsclient/testdata/certs/`. Private keys are gitignored (`*-key.pem`). `certs/client-cert.pem` (public cert, no key) is tracked — this is what `server/main.go` reads to pre-compute the LFDI.
- `wolfssl.RequireClientCert` is the call that enforces mTLS — without it, wolfSSL happily accepts unauthenticated clients regardless of loaded CAs.
- The `Fetcher` interface in `discovery` is deliberately minimal (`Get(path string) ([]byte, error)`) to keep discovery decoupled from TLS, HTTP, and connection management.
- The wolfSSL binding (`internal/wolfssl/wolfssl.go`) is extended by the "add a Go wrapper around one C function" pattern whenever a new C API is needed. See `RequireClientCert` as the reference example.
- wolfSSL headers are not available for arm64 on WSL — build on the Pi natively. Use `git pull` on the Pi after pushing from WSL; `make gen-test-certs` regenerates the gitignored test fixtures on each machine.
