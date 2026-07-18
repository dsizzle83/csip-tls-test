// Package wolfssl is a thin cgo wrapper around the subset of the
// wolfSSL C API used by both the tlsclient and tlsserver packages.
//
// This is the only package in the project that touches cgo directly.
// Everything else interacts with wolfSSL through the typed Go functions
// here, which keeps the cgo blast radius small and makes the rest of
// the codebase refactorable without worrying about C type universes.
//
// Lifecycle: Init() must be called exactly once per process before any
// other function. Cleanup() should be called once during process
// shutdown after all CTX/SSL handles are freed. Test binaries handle
// this in their TestMain; production binaries call Init from main.
package wolfssl

/*
#cgo LDFLAGS: -lwolfssl
#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include <stdlib.h>
*/
import "C"

import (
	"errors"
	"fmt"
	"unsafe"
)

// Success is the wolfSSL success sentinel (WOLFSSL_SUCCESS == 1).
// Hardcoded because cgo #define constants aren't always usable in Go
// const expressions, and the value has been stable across all wolfSSL
// versions.
const Success = 1

// Init initializes the wolfSSL library. Must be called exactly once
// per process before any other function in this package.
func Init() {
	if int(C.wolfSSL_Init()) != Success {
		panic("wolfSSL_Init failed")
	}
}

// Cleanup releases wolfSSL library-global resources.
func Cleanup() {
	C.wolfSSL_Cleanup()
}

// --- CTX construction -------------------------------------------------------

// NewServerCtx allocates a TLS 1.2 server context. The returned pointer
// is opaque to callers and must be freed with FreeCtx.
func NewServerCtx() (unsafe.Pointer, error) {
	method := C.wolfTLSv1_2_server_method()
	if method == nil {
		return nil, errors.New("wolfTLSv1_2_server_method returned nil")
	}
	ctx := C.wolfSSL_CTX_new(method)
	if ctx == nil {
		return nil, errors.New("wolfSSL_CTX_new returned nil")
	}
	return unsafe.Pointer(ctx), nil
}

// NewClientCtx allocates a TLS 1.2 client context.
func NewClientCtx() (unsafe.Pointer, error) {
	method := C.wolfTLSv1_2_client_method()
	if method == nil {
		return nil, errors.New("wolfTLSv1_2_client_method returned nil")
	}
	ctx := C.wolfSSL_CTX_new(method)
	if ctx == nil {
		return nil, errors.New("wolfSSL_CTX_new returned nil")
	}
	return unsafe.Pointer(ctx), nil
}

// FreeCtx releases a context allocated by NewServerCtx or NewClientCtx.
// Safe to call with nil.
func FreeCtx(ctx unsafe.Pointer) {
	if ctx == nil {
		return
	}
	C.wolfSSL_CTX_free((*C.WOLFSSL_CTX)(ctx))
}

// --- CTX configuration ------------------------------------------------------

// SetCipherList restricts the context to a specific OpenSSL-format
// cipher list. For CSIP compliance this should always be
// "ECDHE-ECDSA-AES128-CCM-8".
func SetCipherList(ctx unsafe.Pointer, list string) error {
	c := C.CString(list)
	defer C.free(unsafe.Pointer(c))
	if int(C.wolfSSL_CTX_set_cipher_list((*C.WOLFSSL_CTX)(ctx), c)) != Success {
		return fmt.Errorf("wolfSSL_CTX_set_cipher_list(%q) failed", list)
	}
	return nil
}

// UseCertFile loads a PEM-encoded certificate (server cert OR client
// cert depending on context type) into the context.
func UseCertFile(ctx unsafe.Pointer, path string) error {
	c := C.CString(path)
	defer C.free(unsafe.Pointer(c))
	if int(C.wolfSSL_CTX_use_certificate_file(
		(*C.WOLFSSL_CTX)(ctx), c, C.WOLFSSL_FILETYPE_PEM)) != Success {
		return fmt.Errorf("wolfSSL_CTX_use_certificate_file(%q) failed", path)
	}
	return nil
}

// UseCertChainFile loads a PEM file containing a full certificate chain —
// the leaf server (or client) certificate first, followed by the
// intermediate CA certificate(s) that link it up to (but not including) the
// trust anchor. This is the multi-certificate loader
// (wolfSSL_CTX_use_certificate_chain_file), as opposed to UseCertFile's
// single-leaf wolfSSL_CTX_use_certificate_file: a peer verifying a
// depth-3/4 chain (SERCA→MICA→leaf, SERCA→MCA→MICA→leaf) needs the
// intermediates presented in the handshake, which UseCertFile cannot do.
// Required for the COMM-004 004B/C/D/E/F chain-depth scenarios.
func UseCertChainFile(ctx unsafe.Pointer, path string) error {
	c := C.CString(path)
	defer C.free(unsafe.Pointer(c))
	if int(C.wolfSSL_CTX_use_certificate_chain_file(
		(*C.WOLFSSL_CTX)(ctx), c)) != Success {
		return fmt.Errorf("wolfSSL_CTX_use_certificate_chain_file(%q) failed", path)
	}
	return nil
}

// UseKeyFile loads the PEM-encoded private key matching the cert
// loaded by UseCertFile.
func UseKeyFile(ctx unsafe.Pointer, path string) error {
	c := C.CString(path)
	defer C.free(unsafe.Pointer(c))
	if int(C.wolfSSL_CTX_use_PrivateKey_file(
		(*C.WOLFSSL_CTX)(ctx), c, C.WOLFSSL_FILETYPE_PEM)) != Success {
		return fmt.Errorf("wolfSSL_CTX_use_PrivateKey_file(%q) failed", path)
	}
	return nil
}

// LoadVerifyLocations loads the PEM-encoded CA cert that will be used
// to verify the peer's certificate during handshake. For a client this
// is the CA that signs the server cert; for a server this is the CA
// that signs client certs.
func LoadVerifyLocations(ctx unsafe.Pointer, caFile string) error {
	c := C.CString(caFile)
	defer C.free(unsafe.Pointer(c))
	if int(C.wolfSSL_CTX_load_verify_locations(
		(*C.WOLFSSL_CTX)(ctx), c, nil)) != Success {
		return fmt.Errorf("wolfSSL_CTX_load_verify_locations(%q) failed", caFile)
	}
	return nil
}

// RequireClientCert enables full mTLS on a server context. Without
// this call, the server happily accepts unauthenticated clients
// regardless of what CAs are loaded — this is wolfSSL's default
// behavior and the entire reason this bridge exists (the function
// is not exposed by go-wolfssl).
func RequireClientCert(ctx unsafe.Pointer) {
	C.wolfSSL_CTX_set_verify(
		(*C.WOLFSSL_CTX)(ctx),
		C.WOLFSSL_VERIFY_PEER|C.WOLFSSL_VERIFY_FAIL_IF_NO_PEER_CERT,
		nil,
	)
}

// --- SSL (per-connection) ---------------------------------------------------

// NewSSL creates a per-connection SSL session from a context.
func NewSSL(ctx unsafe.Pointer) (unsafe.Pointer, error) {
	ssl := C.wolfSSL_new((*C.WOLFSSL_CTX)(ctx))
	if ssl == nil {
		return nil, errors.New("wolfSSL_new returned nil")
	}
	return unsafe.Pointer(ssl), nil
}

// FreeSSL releases an SSL session. Safe to call with nil.
func FreeSSL(ssl unsafe.Pointer) {
	if ssl == nil {
		return
	}
	C.wolfSSL_free((*C.WOLFSSL)(ssl))
}

// SetFD attaches an SSL session to an existing socket file descriptor.
func SetFD(ssl unsafe.Pointer, fd int) error {
	if int(C.wolfSSL_set_fd((*C.WOLFSSL)(ssl), C.int(fd))) != Success {
		return fmt.Errorf("wolfSSL_set_fd(%d) failed", fd)
	}
	return nil
}

// PeerCertificateDER returns the DER-encoded peer certificate presented
// during the handshake, or nil if no cert was presented.
// Only valid after a successful Accept or Connect call.
func PeerCertificateDER(ssl unsafe.Pointer) []byte {
	x509 := C.wolfSSL_get_peer_certificate((*C.WOLFSSL)(ssl))
	if x509 == nil {
		return nil
	}
	defer C.wolfSSL_X509_free(x509)

	var sz C.int
	der := C.wolfSSL_X509_get_der(x509, &sz)
	if der == nil || sz <= 0 {
		return nil
	}
	return C.GoBytes(unsafe.Pointer(der), sz)
}

// Accept performs the server-side TLS handshake.
func Accept(ssl unsafe.Pointer) error {
	ret := int(C.wolfSSL_accept((*C.WOLFSSL)(ssl)))
	if ret != Success {
		errCode := int(C.wolfSSL_get_error((*C.WOLFSSL)(ssl), C.int(ret)))
		return fmt.Errorf("wolfSSL_accept failed: ret=%d err=%d", ret, errCode)
	}
	return nil
}

// Connect performs the client-side TLS handshake.
func Connect(ssl unsafe.Pointer) error {
	ret := int(C.wolfSSL_connect((*C.WOLFSSL)(ssl)))
	if ret != Success {
		errCode := int(C.wolfSSL_get_error((*C.WOLFSSL)(ssl), C.int(ret)))
		return fmt.Errorf("wolfSSL_connect failed: ret=%d err=%d", ret, errCode)
	}
	return nil
}

// Read reads from an SSL session. Returns the number of bytes read,
// or an error if the read fails.
func Read(ssl unsafe.Pointer, buf []byte) (int, error) {
	if len(buf) == 0 {
		return 0, nil
	}
	n := int(C.wolfSSL_read(
		(*C.WOLFSSL)(ssl),
		unsafe.Pointer(&buf[0]),
		C.int(len(buf)),
	))
	if n < 0 {
		return 0, fmt.Errorf("wolfSSL_read returned %d", n)
	}
	return n, nil
}

// Write writes to an SSL session.
func Write(ssl unsafe.Pointer, buf []byte) (int, error) {
	if len(buf) == 0 {
		return 0, nil
	}
	n := int(C.wolfSSL_write(
		(*C.WOLFSSL)(ssl),
		unsafe.Pointer(&buf[0]),
		C.int(len(buf)),
	))
	if n < 0 {
		return 0, fmt.Errorf("wolfSSL_write returned %d", n)
	}
	return n, nil
}

// Shutdown initiates the TLS close-notify exchange.
func Shutdown(ssl unsafe.Pointer) {
	if ssl == nil {
		return
	}
	C.wolfSSL_shutdown((*C.WOLFSSL)(ssl))
}

// CipherName returns the negotiated cipher suite name.
func CipherName(ssl unsafe.Pointer) string {
	c := C.wolfSSL_get_cipher_name((*C.WOLFSSL)(ssl))
	if c == nil {
		return ""
	}
	return C.GoString(c)
}

// Version returns the negotiated TLS protocol version string.
func Version(ssl unsafe.Pointer) string {
	c := C.wolfSSL_get_version((*C.WOLFSSL)(ssl))
	if c == nil {
		return ""
	}
	return C.GoString(c)
}

// --- Secure SunSpec Modbus TLS profile extensions (T06.2) -------------------
//
// The functions below wrap the wolfSSL C API surface the mbaps profile needs
// beyond CSIP's TLS-1.2-only / CCM-8-only path: a version-negotiable method
// (TLS 1.2..1.3), min/max version pinning, RFC 6066 Maximum Fragment Length,
// RFC 4492 supported-curve advertisement, RFC 5746 secure renegotiation, and
// session-resumption inspection. They are strictly ADDITIVE — every function
// above is untouched, so the CSIP tlsclient/tlsserver keep their exact
// behaviour (extend, do not fork — CONTEXT.md).
//
// These require the bench's wolfSSL 5.7.6 sysroot to be built with
// --enable-tls13 / --enable-maxfragment / --enable-secure-renegotiation /
// --enable-session-ticket (design doc 01 §1.4). The amd64 desktop sysroot
// already carries them (options.h: WOLFSSL_TLS13, HAVE_MAX_FRAGMENT,
// HAVE_SECURE_RENEGOTIATION, HAVE_SESSION_TICKET, HAVE_AESGCM/AESCCM/CHACHA);
// building against a sysroot without them fails at compile/link, not silently.

// TLS wire protocol versions, for SetMinProtoVersion / SetMaxProtoVersion
// (these take the OpenSSL-compat numeric constants, not the WOLFSSL_TLSV1_*
// method enum).
const (
	TLS12Version = 0x0303 // TLS1_2_VERSION
	TLS13Version = 0x0304 // TLS1_3_VERSION
)

// Maximum Fragment Length negotiation codes (RFC 6066). The value is wolfSSL's
// exponent selector, NOT the byte count. MFL512 (2^9 = 512 bytes) is the mbaps
// profile default (SunSpecTCP-59/60).
const (
	MFLDisabled = 0 // WOLFSSL_MFL_DISABLED
	MFL512      = 1 // WOLFSSL_MFL_2_9  — 512 bytes
	MFL1024     = 2 // WOLFSSL_MFL_2_10 — 1024 bytes
	MFL2048     = 3 // WOLFSSL_MFL_2_11 — 2048 bytes
	MFL4096     = 4 // WOLFSSL_MFL_2_12 — 4096 bytes
)

// ECCSecp256r1 is the RFC 4492 supported-groups identifier for NIST P-256, the
// only curve the mbaps profile's ECDSA-only suites use (SunSpecTCP-42).
const ECCSecp256r1 = 23 // WOLFSSL_ECC_SECP256R1

// NewServerCtxTLS allocates a version-negotiable server context
// (wolfTLS_server_method: negotiate the highest mutually-supported version down
// to the configured floor). Pair with SetMinProtoVersion/SetMaxProtoVersion to
// bound the range — the mbaps profile requires TLS 1.2 and enables TLS 1.3.
func NewServerCtxTLS() (unsafe.Pointer, error) {
	method := C.wolfTLS_server_method()
	if method == nil {
		return nil, errors.New("wolfTLS_server_method returned nil")
	}
	ctx := C.wolfSSL_CTX_new(method)
	if ctx == nil {
		return nil, errors.New("wolfSSL_CTX_new (TLS server) returned nil")
	}
	return unsafe.Pointer(ctx), nil
}

// NewClientCtxTLS allocates a version-negotiable client context
// (wolfTLS_client_method).
func NewClientCtxTLS() (unsafe.Pointer, error) {
	method := C.wolfTLS_client_method()
	if method == nil {
		return nil, errors.New("wolfTLS_client_method returned nil")
	}
	ctx := C.wolfSSL_CTX_new(method)
	if ctx == nil {
		return nil, errors.New("wolfSSL_CTX_new (TLS client) returned nil")
	}
	return unsafe.Pointer(ctx), nil
}

// SetMinProtoVersion pins the lowest TLS version the context will negotiate
// (use TLS12Version to make TLS 1.2 the mandated floor — SunSpecTCP-4).
func SetMinProtoVersion(ctx unsafe.Pointer, version int) error {
	if int(C.wolfSSL_CTX_set_min_proto_version(
		(*C.WOLFSSL_CTX)(ctx), C.int(version))) != Success {
		return fmt.Errorf("wolfSSL_CTX_set_min_proto_version(0x%04x) failed", version)
	}
	return nil
}

// SetMaxProtoVersion pins the highest TLS version the context will negotiate
// (TLS13Version keeps 1.3 available — SunSpecTCP-5; TLS12Version caps at 1.2).
func SetMaxProtoVersion(ctx unsafe.Pointer, version int) error {
	if int(C.wolfSSL_CTX_set_max_proto_version(
		(*C.WOLFSSL_CTX)(ctx), C.int(version))) != Success {
		return fmt.Errorf("wolfSSL_CTX_set_max_proto_version(0x%04x) failed", version)
	}
	return nil
}

// UseMaxFragment requests RFC 6066 Maximum Fragment Length negotiation on the
// context. On a client context this makes every ClientHello carry the MFL
// extension (SunSpecTCP-59/60); a server honours a peer's request
// automatically, so servers need not call this. code is one of the MFL*
// constants; MFLDisabled is a no-op selector.
func UseMaxFragment(ctx unsafe.Pointer, code int) error {
	if code == MFLDisabled {
		return nil
	}
	if int(C.wolfSSL_CTX_UseMaxFragment(
		(*C.WOLFSSL_CTX)(ctx), C.uchar(code))) != Success {
		return fmt.Errorf("wolfSSL_CTX_UseMaxFragment(%d) failed", code)
	}
	return nil
}

// UseSupportedCurve advertises an ECC curve in the ClientHello supported_groups
// extension (RFC 4492). The mbaps client offers P-256 (ECCSecp256r1) so the
// ECDSA-only suites can complete (SunSpecTCP-43/44).
func UseSupportedCurve(ctx unsafe.Pointer, curve int) error {
	if int(C.wolfSSL_CTX_UseSupportedCurve(
		(*C.WOLFSSL_CTX)(ctx), C.word16(curve))) != Success {
		return fmt.Errorf("wolfSSL_CTX_UseSupportedCurve(%d) failed", curve)
	}
	return nil
}

// SessionReused reports whether this handshake resumed a prior session
// (SunSpecTCP-46). Valid after a successful Connect/Accept.
func SessionReused(ssl unsafe.Pointer) bool {
	return int(C.wolfSSL_session_reused((*C.WOLFSSL)(ssl))) == 1
}

// NegotiatedMaxFragment returns the MFL code agreed for this session (one of
// the MFL* constants, 0 = none), making the profile's 512-byte cap observable
// for conformance assertions (SunSpecTCP-59/60). The WOLFSSL_SESSION pointer is
// wolfSSL-internal (from get_session, not get1_session) and must not be freed.
//
// Reliability caveat: the SERVER (the honouring peer) reports the negotiated
// MFL in every version. The CLIENT reports it under TLS 1.2, but on a fresh
// TLS 1.3 session wolfSSL's get_session returns 0 for the MFL — the client's
// resumable session is not finalised with the fragment length until the
// post-handshake NewSessionTicket. For TLS 1.3, observe MFL from the server
// side (or from a packet capture — the T06.10 release gate).
func NegotiatedMaxFragment(ssl unsafe.Pointer) int {
	sess := C.wolfSSL_get_session((*C.WOLFSSL)(ssl))
	if sess == nil {
		return 0
	}
	return int(C.wolfSSL_SESSION_get_max_fragment_length(sess))
}

// Rehandshake drives a client-initiated secure renegotiation (RFC 5746). Used
// by the renegotiation-refusal probe (T06.8): a conformant mbaps server's
// policy for a mid-session renegotiation is asserted against the returned
// error. Requires the peer to have negotiated the renegotiation-info extension.
func Rehandshake(ssl unsafe.Pointer) error {
	ret := int(C.wolfSSL_Rehandshake((*C.WOLFSSL)(ssl)))
	if ret != Success {
		errCode := int(C.wolfSSL_get_error((*C.WOLFSSL)(ssl), C.int(ret)))
		return fmt.Errorf("wolfSSL_Rehandshake failed: ret=%d err=%d", ret, errCode)
	}
	return nil
}

// SetSessionCacheOff disables the server-side session cache on a context
// (WOLFSSL_SESS_CACHE_OFF). The mbaps profile defaults resumption ON
// (SunSpecTCP-46 SHOULD); this is the explicit opt-out.
func SetSessionCacheOff(ctx unsafe.Pointer) {
	C.wolfSSL_CTX_set_session_cache_mode(
		(*C.WOLFSSL_CTX)(ctx), C.WOLFSSL_SESS_CACHE_OFF)
}
