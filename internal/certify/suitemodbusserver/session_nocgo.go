//go:build !cgo

package suitemodbusserver

// session_nocgo.go leaves mbapsDial nil in a pure-Go build.
//
// The bench's mbaps client rides internal/wolfssl, which is cgo. A
// CGO_ENABLED=0 build of this suite still compiles, still runs its unit tests,
// and still works against a plain Modbus/TCP DUT — it simply cannot open a TLS
// session, and openSession says exactly that rather than failing with a linker
// error or, worse, silently degrading to plaintext against a DUT that has no
// plaintext port.

func init() { mbapsDial = nil }
