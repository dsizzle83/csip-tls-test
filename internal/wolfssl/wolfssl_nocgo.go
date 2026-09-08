// wolfssl_nocgo.go is the CGO_ENABLED=0 build of this package's API.
//
// REV0907-E11: the pure-Go `go vet ./...` gate this repo advertises was in
// fact an enumerated package list, because this package (the only one that
// touches cgo directly, per CONTEXT.md) carried a `!cgo` stub for its keylog
// extras (keylog_stub.go) but no stub for the base API — so
// `CGO_ENABLED=0 go vet ./...` failed to typecheck internal/mbtls,
// internal/tlsclient and sim/tlsserver with "undefined: wolfssl.NewClientCtxTLS"
// and friends, and ci.yml's pure-go step had to name packages explicitly to
// dodge them. With this file in place ci.yml's pure-go step may use the
// unqualified `./...` (see internal/tlsprobe/spec.go's ErrUnavailable /
// session_nocgo.go for the same idiom already established in this repo).
//
// Every exported identifier the three cgo callers reference is declared here
// with the same signature as the cgo file (wolfssl.go), so those packages —
// and cmd/certify, which imports them — typecheck and link without cgo. Every
// function that can fail returns ErrNoCgo; every constructor returns
// (nil, ErrNoCgo); every accessor returns its zero value. Nothing here panics:
// a caller that mistakenly runs a full handshake attempt in a pure-Go binary
// gets a wrapped, inspectable error, not a crash (CODING_PRINCIPLES.md §1, no
// panics on I/O).
//
// Constants (TLS12Version, MFL512, ECCSecp256r1, ...) are real values, not
// stubbed — they are pure data (wire codes wolfSSL and the profile packages
// share) and cost nothing to keep genuine, so internal/mbtls's
// `TLS12 Version = wolfssl.TLS12Version` const declarations and its MFL
// selector validation keep working identically in both builds.
//
// keylog.go / keylog_stub.go are untouched: they are already gated on the
// separate `keylog` tag, independent of cgo, and stub every keylog identifier
// (OpenKeylog, CloseKeylog, KeylogPath, EnableTLS13Keylog, WriteTLS12Keylog,
// EnableCtxKeylog, ErrKeylogUnavailable) whenever that tag is absent — which is
// true of an ordinary CGO_ENABLED=0 build, so redeclaring them here would be a
// duplicate definition. This file covers everything keylog_stub.go does not.

//go:build !cgo

package wolfssl

import (
	"errors"
	"unsafe"
)

// ErrNoCgo is returned by every function in this package that would otherwise
// need to call into wolfSSL, when the binary was built with CGO_ENABLED=0.
// REV0907-E11: a caller that dials, listens, or otherwise drives a real
// handshake in a pure-Go binary gets this back rather than a link error or a
// nil-pointer panic, so cmd/certify's non-TLS surfaces (list, dry-run, verify,
// report) stay usable in that build while anything that needs a live session
// fails loudly and reports the reason.
var ErrNoCgo = errors.New("wolfssl: built without cgo")

// --- lifecycle ---------------------------------------------------------

// Init is a no-op in this build: there is no wolfSSL library to initialize.
func Init() {}

// Cleanup is a no-op in this build.
func Cleanup() {}

// --- CTX construction ---------------------------------------------------

// NewServerCtx always fails in this build. See ErrNoCgo.
func NewServerCtx() (unsafe.Pointer, error) { return nil, ErrNoCgo }

// NewClientCtx always fails in this build. See ErrNoCgo.
func NewClientCtx() (unsafe.Pointer, error) { return nil, ErrNoCgo }

// NewServerCtxTLS always fails in this build. See ErrNoCgo.
func NewServerCtxTLS() (unsafe.Pointer, error) { return nil, ErrNoCgo }

// NewClientCtxTLS always fails in this build. See ErrNoCgo.
func NewClientCtxTLS() (unsafe.Pointer, error) { return nil, ErrNoCgo }

// FreeCtx is a no-op in this build: no cgo build ever handed out a live ctx to
// free. Nil-safe, matching the cgo implementation's contract.
func FreeCtx(ctx unsafe.Pointer) {}

// --- CTX configuration ---------------------------------------------------

// SetCipherList always fails in this build. See ErrNoCgo.
func SetCipherList(ctx unsafe.Pointer, list string) error { return ErrNoCgo }

// UseCertFile always fails in this build. See ErrNoCgo.
func UseCertFile(ctx unsafe.Pointer, path string) error { return ErrNoCgo }

// UseCertChainFile always fails in this build. See ErrNoCgo.
func UseCertChainFile(ctx unsafe.Pointer, path string) error { return ErrNoCgo }

// UseKeyFile always fails in this build. See ErrNoCgo.
func UseKeyFile(ctx unsafe.Pointer, path string) error { return ErrNoCgo }

// LoadVerifyLocations always fails in this build. See ErrNoCgo.
func LoadVerifyLocations(ctx unsafe.Pointer, caFile string) error { return ErrNoCgo }

// RequireClientCert is a no-op in this build: there is no ctx to configure.
func RequireClientCert(ctx unsafe.Pointer) {}

// --- SSL (per-connection) -------------------------------------------------

// NewSSL always fails in this build. See ErrNoCgo.
func NewSSL(ctx unsafe.Pointer) (unsafe.Pointer, error) { return nil, ErrNoCgo }

// FreeSSL is a no-op in this build. Nil-safe, matching the cgo implementation.
func FreeSSL(ssl unsafe.Pointer) {}

// SetFD always fails in this build. See ErrNoCgo.
func SetFD(ssl unsafe.Pointer, fd int) error { return ErrNoCgo }

// PeerCertificateDER always reports no certificate in this build: no
// handshake ever ran to present one.
func PeerCertificateDER(ssl unsafe.Pointer) []byte { return nil }

// Accept always fails in this build. See ErrNoCgo.
func Accept(ssl unsafe.Pointer) error { return ErrNoCgo }

// Connect always fails in this build. See ErrNoCgo.
func Connect(ssl unsafe.Pointer) error { return ErrNoCgo }

// --- I/O error classification --------------------------------------------

// IOError exists in this build so callers that type-assert on it (e.g.
// internal/mbtls's read/write retry loop, via errors.As) compile identically
// in both builds. Nothing in this build ever constructs or returns one: Read
// and Write here return the bare ErrNoCgo, which errors.As never matches
// against *IOError, so a caller's retry loop takes its "not an IOError" path
// and reports ErrNoCgo directly instead of retrying — there is nothing to
// retry when no cgo handshake could ever have started.
type IOError struct {
	Op   string // "read" or "write"
	Ret  int
	Code int
}

func (e *IOError) Error() string {
	return "wolfssl: " + e.Op + ": " + ErrNoCgo.Error()
}

// Retryable always reports false in this build: this type is never
// constructed here, so there is no reason code to classify.
func (e *IOError) Retryable() bool { return false }

// PeerClosed always reports false in this build, for the same reason as
// Retryable.
func (e *IOError) PeerClosed() bool { return false }

// Read always fails in this build. See ErrNoCgo.
func Read(ssl unsafe.Pointer, buf []byte) (int, error) { return 0, ErrNoCgo }

// Write always fails in this build. See ErrNoCgo.
func Write(ssl unsafe.Pointer, buf []byte) (int, error) { return 0, ErrNoCgo }

// Shutdown is a no-op in this build: no live session ever exists to close.
func Shutdown(ssl unsafe.Pointer) {}

// CipherName always reports "" in this build: no handshake ever negotiated a
// cipher.
func CipherName(ssl unsafe.Pointer) string { return "" }

// Version always reports "" in this build: no handshake ever negotiated a
// protocol version.
func Version(ssl unsafe.Pointer) string { return "" }

// --- Secure SunSpec Modbus TLS profile extensions (T06.2) -----------------
//
// These constants are genuine values, not stubs: internal/mbtls declares its
// own exported Version/MFL constants directly in terms of them
// (`TLS12 Version = wolfssl.TLS12Version`, `MFLCode: wolfssl.MFL512`), so a
// placeholder value here would silently change the mbaps profile's Go-level
// constants in a pure-Go build. Keeping them identical to wolfssl.go's is what
// makes the two builds' profile data agree even though only one of them can
// ever actually drive wolfSSL with it.
const (
	TLS12Version = 0x0303 // TLS1_2_VERSION
	TLS13Version = 0x0304 // TLS1_3_VERSION
)

const (
	MFLDisabled = 0
	MFL512      = 1
	MFL1024     = 2
	MFL2048     = 3
	MFL4096     = 4
)

// ECCSecp256r1 is the RFC 4492 supported-groups identifier for NIST P-256.
// See wolfssl.go's copy for the full rationale; the value must match exactly
// (const-identity note above).
const ECCSecp256r1 = 23

// NewServerCtxTLS / NewClientCtxTLS are declared above with the base
// constructors; the remaining T06.2 extension functions follow.

// SetMinProtoVersion always fails in this build. See ErrNoCgo.
func SetMinProtoVersion(ctx unsafe.Pointer, version int) error { return ErrNoCgo }

// SetMaxProtoVersion always fails in this build. See ErrNoCgo.
func SetMaxProtoVersion(ctx unsafe.Pointer, version int) error { return ErrNoCgo }

// UseMaxFragment always fails in this build. See ErrNoCgo.
func UseMaxFragment(ctx unsafe.Pointer, code int) error { return ErrNoCgo }

// UseSupportedCurve always fails in this build. See ErrNoCgo.
func UseSupportedCurve(ctx unsafe.Pointer, curve int) error { return ErrNoCgo }

// SessionReused always reports false in this build: no handshake ever ran, so
// nothing was ever resumed.
func SessionReused(ssl unsafe.Pointer) bool { return false }

// NegotiatedMaxFragment always reports 0 (none) in this build.
func NegotiatedMaxFragment(ssl unsafe.Pointer) int { return 0 }

// Rehandshake always fails in this build. See ErrNoCgo.
func Rehandshake(ssl unsafe.Pointer) error { return ErrNoCgo }

// SetSessionCacheOff is a no-op in this build: there is no ctx to configure.
func SetSessionCacheOff(ctx unsafe.Pointer) {}

// SetNoTicketTLS12 always fails in this build. See ErrNoCgo.
func SetNoTicketTLS12(ctx unsafe.Pointer) error { return ErrNoCgo }

// SetNoTicketTLS13 always fails in this build. See ErrNoCgo.
func SetNoTicketTLS13(ctx unsafe.Pointer) error { return ErrNoCgo }

// --- Client session resumption (T06.8) ------------------------------------

// GetSession always reports no session available in this build.
func GetSession(ssl unsafe.Pointer) unsafe.Pointer { return nil }

// SetSession always fails in this build. See ErrNoCgo.
func SetSession(ssl unsafe.Pointer, sess unsafe.Pointer) error { return ErrNoCgo }

// FreeSession is a no-op in this build. Nil-safe, matching the cgo
// implementation.
func FreeSession(sess unsafe.Pointer) {}

// UseSecureRenegotiation always fails in this build. See ErrNoCgo.
func UseSecureRenegotiation(ctx unsafe.Pointer) error { return ErrNoCgo }

// --- Server-side peer identity across resumption (Wave 1, harness defect H-1) --

// PeerChainLeafDER always reports no chain held in this build.
func PeerChainLeafDER(ssl unsafe.Pointer) []byte { return nil }

// SessionID always reports no session identifier available in this build.
func SessionID(ssl unsafe.Pointer) []byte { return nil }
