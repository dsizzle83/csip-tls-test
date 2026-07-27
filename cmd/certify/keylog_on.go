//go:build cgo && keylog

package main

// keylog_on.go is the evidence build: TLS session secrets are exported in NSS
// key-log format, so the run's capture can be decrypted afterwards and the
// mbaps / HTTPS payload claims become re-checkable rather than opaque.
//
// This file exists only when BOTH the cgo build and the `keylog` tag are in
// force, and the tag only compiles against a wolfSSL built with
// HAVE_SECRET_CALLBACK (~/.local/wolfssl-amd64-keylog). That is deliberate on
// the binding's part: a key log that silently produced nothing would yield
// undecryptable captures and an evidence bundle that looks complete until
// somebody tries to verify it.

import (
	"fmt"

	"csip-tls-test/internal/wolfssl"
)

// openKeylog starts exporting TLS secrets to path.
func openKeylog(path string) error {
	if err := wolfssl.OpenKeylog(path); err != nil {
		return fmt.Errorf("-keylog %s: %w", path, err)
	}
	return nil
}
