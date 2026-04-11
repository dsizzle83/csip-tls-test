# tests/ — context for Step D

## Current state

`tests/integration_test.go` tests the Milestone 3 pure-Go stack:
`gridsim` + `httpclient.Fetcher` + `discovery.Walker` over plain HTTP.
All passing. No wolfSSL involved.

## Step D goal

Add a test (or a standalone binary) that exercises the **full production stack**:

```
discovery.Walker
    └── WolfSSLFetcher          (tlsclient/fetcher.go)
            └── wolfSSL mTLS session
                    └── tlsserver  (with gridsim.Handler wired in)
```

This is the first test where all four layers touch each other simultaneously.

## Recommended approach

Add `tests/wolfssl_integration_test.go` with build tag `//go:build integration`:

```go
//go:build integration

package tests

func TestFullStack_WolfSSLFetcherWalksGridsim(t *testing.T) {
    // 1. Start an in-process tlsserver with sim.Handler() wired in.
    //    Reuse the startInProcessServer helper from tlsclient if accessible,
    //    or inline the setup here.
    // 2. Compute LFDI from the test CA's client cert so the EndDevice matches.
    // 3. Create a WolfSSLFetcher pointed at the server.
    // 4. Run discovery.NewWalker(fetcher, lfdi).Discover("/dcap").
    // 5. Assert tree.SelfDevice is non-nil, tree has DERPrograms, etc.
}
```

**The seams to watch:**
- `tlsserver` uses `internal/tlsserver/testdata/certs/` (test CA); these must
  match what `WolfSSLFetcher` loads. Both use `goodClientConfig(addr)` from
  the tlsclient test helpers — check that helper is still accessible or
  replicate it.
- `wolfssl.Init()` must be called exactly once. If the test binary imports
  both tlsclient and tlsserver, use a shared `TestMain` in the tests/ package.
- `dispatchHTTP` reads the full HTTP request in one 4096-byte read. A GET with
  typical headers is well under this limit, but if a test sends an unusually
  large request header block it will be truncated silently.

## Dependency note

`tests/` currently only imports pure-Go packages. Adding wolfSSL integration
here means the `go test ./tests/` command will require cgo and wolfSSL headers.
Consider a separate `//go:build integration` file so `go test ./tests/` (no
tag) stays fast/pure-Go, while `go test -tags=integration ./tests/` adds the
full-stack test.
