// keylog_stub.go is the no-keylog build of the NSS key-log export API. See
// keylog.go for the real implementation and why it is tag-gated.
//
// The point of a stub rather than "just don't call it" is that the
// conformance tool wires key export into session setup unconditionally: the
// decision about whether a run can produce decryptable evidence belongs to
// the BUILD (which sysroot, which tag), not to scattered call sites. With the
// tag absent, arming a session succeeds and does nothing, but OPENING a key
// log fails loudly — an operator who asked for evidence and would silently
// have got an undecryptable capture is told immediately, at the start of the
// run rather than at analysis time.

//go:build !keylog

package wolfssl

import (
	"errors"
	"unsafe"
)

// ErrKeylogUnavailable is returned by OpenKeylog in a build without the
// `keylog` tag.
var ErrKeylogUnavailable = errors.New(
	"wolfssl: TLS key-log export not compiled in — rebuild with -tags keylog " +
		"against the keylog sysroot (see internal/wolfssl/keylog.go)")

// OpenKeylog always fails in this build. See ErrKeylogUnavailable.
func OpenKeylog(path string) error { return ErrKeylogUnavailable }

// CloseKeylog is a no-op in this build.
func CloseKeylog() {}

// KeylogPath always reports "" in this build.
func KeylogPath() string { return "" }

// EnableTLS13Keylog is a no-op in this build. It returns nil so session setup
// can call it unconditionally; OpenKeylog is where the absence is reported.
func EnableTLS13Keylog(ssl unsafe.Pointer) error { return nil }

// WriteTLS12Keylog is a no-op in this build, always reporting false.
func WriteTLS12Keylog(ssl unsafe.Pointer) bool { return false }

// EnableCtxKeylog is a no-op without the keylog build tag.
func EnableCtxKeylog(ctx unsafe.Pointer) {}
