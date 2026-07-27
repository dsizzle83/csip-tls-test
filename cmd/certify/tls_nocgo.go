//go:build !cgo

package main

// tls_nocgo.go is the pure-Go build's stand-in for tls_cgo.go.
//
// A CGO_ENABLED=0 certify is a real and useful tool — it lists the catalog,
// dry-runs a plan, verifies a bundle, generates a submission report, and drives
// every plaintext-transport check — so this build must LINK. What it must never
// do is pretend to a capability it does not have, so opening a key log here is
// an error naming the build, not a no-op that leaves the operator believing the
// capture will decrypt.

import "fmt"

// tlsInit is a no-op: there is no wolfSSL in this build.
func tlsInit() {}

// tlsCleanup is a no-op for the same reason.
func tlsCleanup() {}

// openKeylog always fails here. See the file header.
func openKeylog(path string) error {
	return fmt.Errorf("-keylog %s: this is a CGO_ENABLED=0 build, which has no TLS stack and so no "+
		"session secrets to export — nothing in the capture would decrypt, and every encrypted "+
		"payload claim would be unverifiable. Build with cgo and the keylog tag against "+
		"~/.local/wolfssl-amd64-keylog (make certify-keylog)", path)
}

// closeKeylog is a no-op.
func closeKeylog() {}
