//go:build cgo && !keylog

package main

// keylog_off.go is the ORDINARY build's answer to -keylog: refuse, and say
// exactly what to change.
//
// The failure this prevents is the expensive one. A live conformance campaign
// costs a bench, an operator's afternoon, and a serialized slot nobody else can
// use. Accepting -keylog here and quietly exporting nothing would produce a
// bundle whose encrypted payload assertions can never be re-derived — and
// nobody would find out until a certification reviewer tried, days later. So
// this is a hard error before the capture starts, not a warning in a log.

import "fmt"

// openKeylog always fails in this build. See the file header.
func openKeylog(path string) error {
	return fmt.Errorf("-keylog %s: this binary was built WITHOUT TLS key export, so the capture would "+
		"not be decryptable. Rebuild against the keylog sysroot AND with the build tag:\n"+
		"    CGO_CFLAGS=\"-I$HOME/.local/wolfssl-amd64-keylog/include\" \\\n"+
		"    CGO_LDFLAGS=\"-L$HOME/.local/wolfssl-amd64-keylog/lib -lwolfssl -lm\" \\\n"+
		"    go build -tags keylog -o bin/certify-keylog ./cmd/certify      (make certify-keylog)\n"+
		"  Or drop -keylog and accept that encrypted payloads are not assertable in this run", path)
}
