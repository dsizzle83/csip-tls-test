//go:build cgo

package main

// tls_cgo.go is this binary's relationship with wolfSSL's process-global state.
//
// It is split from main.go so `CGO_ENABLED=0 go build ./cmd/certify` still
// produces a working tool. That build cannot open a TLS session — internal/mbtls
// rides internal/wolfssl, which is cgo — and the suites already say so on every
// affected check rather than degrading to plaintext against a DUT that has no
// plaintext port. What a pure-Go build must NOT do is fail to link.
//
// Key-log export is split further still, into keylog_on.go and keylog_off.go,
// because the wolfSSL binding's key-log API is itself build-tagged: the
// ErrKeylogUnavailable sentinel exists only in the stub. Rather than reach
// around that with an untagged reference that breaks one of the two builds, each
// build gets the openKeylog it can actually honour — and the message a operator
// sees names the specific thing their binary is missing.

import "csip-tls-test/internal/wolfssl"

// tlsInit initialises wolfSSL's process-global C state. Exactly once per
// process is a hard invariant of this repository (CLAUDE.md): it is not
// reference-counted, and a second Init or an early Cleanup corrupts state for
// every session in flight.
func tlsInit() { wolfssl.Init() }

// tlsCleanup releases it.
func tlsCleanup() { wolfssl.Cleanup() }

// closeKeylog flushes and closes the key log. It is a no-op in a build that
// never opened one.
func closeKeylog() { wolfssl.CloseKeylog() }
