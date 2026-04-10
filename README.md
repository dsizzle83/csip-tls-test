# csip-tls-test

CSIP / IEEE 2030.5 mTLS client and server, built on wolfSSL.

The **client** is the product — it runs on DER devices (Raspberry Pi
during development, NXP i.MX 93 in production) and talks to utility
grid management servers using the cipher and protocol mandated by CSIP
§5.2.1.1. The **server** in this repo is a test fixture that simulates
a utility server, used to validate the client during development.

## Quick start

```bash
# First-time setup (auto-generates test certs)
make test

# Iterate on the client (fast feedback loop, sub-second)
make test-fast

# Full integration with real TLS handshakes
make test-integration

# Build deployable binaries
make build

# Validate against real hardware (Pi)
make smoke-pi
```

## Layout

```
csip-tls-test/
├── Makefile
├── go.mod
├── client/main.go              ← Thin client binary (deployed to Pi)
├── server/main.go              ← Thin server binary (runs on dev machine)
├── internal/
│   ├── wolfssl/                ← Shared cgo bridge — the only package
│   │                             that touches C. Both tlsclient and
│   │                             tlsserver import this.
│   ├── tlsclient/              ← Client logic (the product)
│   │   ├── client.go               Dial / Get / Close / Free
│   │   ├── request.go              Pure-Go HTTP request building
│   │   ├── response.go             Pure-Go HTTP response parsing
│   │   ├── dcap.go                 DCAP fetch + XML unmarshal
│   │   ├── parsing_test.go         Unit tests (no network)
│   │   ├── helpers_test.go         TestMain + in-process server fixture
│   │   ├── client_test.go          Integration tests (build tag)
│   │   └── testdata/certs/         Test cert fixtures
│   └── tlsserver/              ← Test fixture server
│       ├── server.go
│       ├── handlers.go             Pure-Go HTTP routing
│       ├── handlers_test.go        Unit tests + golden file
│       ├── helpers_test.go         TestMain + startTestServer
│       ├── testclient_test.go      Per-test wolfSSL client (for negative tests)
│       ├── server_test.go          Integration tests (build tag)
│       └── testdata/certs/         Test cert fixtures
└── scripts/
    ├── gen-test-certs.sh       Generates test cert fixtures
    └── smoke-pi.sh             Manual hardware validation
```

## Key design decisions

**The cgo bridge is shared.** Both client and server import
`internal/wolfssl`, which is the only package that touches C.
This eliminates the maintenance trap of having two slightly-divergent
copies of the same wolfSSL wrapper.

**Tests are layered.** Unit tests cover request building, response
parsing, and DCAP XML unmarshaling — pure Go, no network, runs in
milliseconds. Integration tests cover the full handshake stack —
cgo, real TLS, runs against an in-process server, completes in a
fraction of a second per test. Hardware validation is a separate
manual smoke test, NOT part of `go test`.

**Why no automated end-to-end Pi tests.** Baking the Pi into the test
framework would require Pi availability for every `go test` run, SSH
credential handling in test code, and identical hardware setup for
every developer. The in-process integration tests catch ~95% of bugs
at <1% of the friction. The `make smoke-pi` script catches the
remaining 5% (cross-compilation, real-network behavior) when run
deliberately.

**Negative tests are first-class.** Both packages have table-driven
rejection tests proving the server rejects unauthenticated clients,
clients with wrong CAs, and clients offering non-CSIP ciphers — and
proving the client rejects servers with wrong certs and refuses to
negotiate non-CSIP ciphers. Each rejection scenario is one row in a
struct table. Adding a new conformance requirement = adding one row.

**`TestMain` is mandatory.** `wolfSSL_Init` is process-global C state
and double-init is undefined behavior. Both `tlsclient` and `tlsserver`
have `TestMain` functions that call `wolfssl.Init()` exactly once per
test binary.

## Deploying to the Raspberry Pi

The client binary is what gets deployed. The Pi needs:

1. **The compiled binary** — either cross-compiled from WSL with
   `aarch64-linux-gnu-gcc` or natively built on the Pi.
2. **wolfSSL installed** — the same version as on WSL, with the same
   configure flags. The Pi already has this from earlier setup.
3. **The production cert vault** — `ca-cert.pem`, `client-cert.pem`,
   and `client-key.pem` in `/home/dmitri/csip-tls-test/certs/`. These
   were generated from the offline CA on WSL and SCP'd to the Pi.

Then:

```bash
# On the Pi
~/csip-tls-test/bin/client \
    -server 192.168.0.188:11111 \
    -ca   ~/csip-tls-test/certs/ca-cert.pem \
    -cert ~/csip-tls-test/certs/client-cert.pem \
    -key  ~/csip-tls-test/certs/client-key.pem
```

Or use `make smoke-pi` from WSL to do the whole thing in one shot.
