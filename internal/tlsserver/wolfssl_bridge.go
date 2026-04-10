// Package tlsserver implements a CSIP / IEEE 2030.5-compliant mTLS server
// using wolfSSL via cgo.
//
// This file is the only place in the package that touches cgo. It wraps
// every wolfSSL function we use into typed Go functions whose only
// pointer-shaped argument is unsafe.Pointer. The rest of the package
// never sees a C type, which keeps the cgo blast radius small and
// makes refactoring safe.
package tlsserver

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

// wolfSuccess is the success sentinel from wolfssl/ssl.h. We hardcode
// it because cgo #define constants aren't always usable in Go const
// expressions and the value has been stable across all wolfSSL versions.
const wolfSuccess = 1

// Init initializes the wolfSSL library. Must be called exactly once per
// process before any other tlsserver function. In tests this is handled
// automatically by TestMain in helpers_test.go. In production binaries,
// call from main() before tlsserver.New.
func Init() {
	if int(C.wolfSSL_Init()) != wolfSuccess {
		panic("wolfSSL_Init failed")
	}
}

// Cleanup releases wolfSSL library-global resources. Should be called
// once during process shutdown after all Server instances are Closed.
func Cleanup() {
	C.wolfSSL_Cleanup()
}

// --- CTX-level operations ---------------------------------------------------

func newServerCtx() (unsafe.Pointer, error) {
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

func newClientCtx() (unsafe.Pointer, error) {
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

func ctxFree(ctx unsafe.Pointer) {
	if ctx == nil {
		return
	}
	C.wolfSSL_CTX_free((*C.WOLFSSL_CTX)(ctx))
}

func ctxSetCipherList(ctx unsafe.Pointer, list string) error {
	c := C.CString(list)
	defer C.free(unsafe.Pointer(c))
	if int(C.wolfSSL_CTX_set_cipher_list((*C.WOLFSSL_CTX)(ctx), c)) != wolfSuccess {
		return fmt.Errorf("wolfSSL_CTX_set_cipher_list(%q) failed", list)
	}
	return nil
}

func ctxUseCertFile(ctx unsafe.Pointer, path string) error {
	c := C.CString(path)
	defer C.free(unsafe.Pointer(c))
	if int(C.wolfSSL_CTX_use_certificate_file(
		(*C.WOLFSSL_CTX)(ctx), c, C.WOLFSSL_FILETYPE_PEM)) != wolfSuccess {
		return fmt.Errorf("wolfSSL_CTX_use_certificate_file(%q) failed", path)
	}
	return nil
}

func ctxUseKeyFile(ctx unsafe.Pointer, path string) error {
	c := C.CString(path)
	defer C.free(unsafe.Pointer(c))
	if int(C.wolfSSL_CTX_use_PrivateKey_file(
		(*C.WOLFSSL_CTX)(ctx), c, C.WOLFSSL_FILETYPE_PEM)) != wolfSuccess {
		return fmt.Errorf("wolfSSL_CTX_use_PrivateKey_file(%q) failed", path)
	}
	return nil
}

func ctxLoadVerifyLocations(ctx unsafe.Pointer, caFile string) error {
	c := C.CString(caFile)
	defer C.free(unsafe.Pointer(c))
	if int(C.wolfSSL_CTX_load_verify_locations(
		(*C.WOLFSSL_CTX)(ctx), c, nil)) != wolfSuccess {
		return fmt.Errorf("wolfSSL_CTX_load_verify_locations(%q) failed", caFile)
	}
	return nil
}

// ctxRequireClientCert enables full mTLS on the server-side context.
// This is the function that go-wolfssl does not expose, and the entire
// reason this bridge exists. Without it, the server happily accepts
// unauthenticated clients regardless of what CAs are loaded.
func ctxRequireClientCert(ctx unsafe.Pointer) {
	C.wolfSSL_CTX_set_verify(
		(*C.WOLFSSL_CTX)(ctx),
		C.WOLFSSL_VERIFY_PEER|C.WOLFSSL_VERIFY_FAIL_IF_NO_PEER_CERT,
		nil,
	)
}

// --- SSL-level (per-connection) operations ----------------------------------

func newSSL(ctx unsafe.Pointer) (unsafe.Pointer, error) {
	ssl := C.wolfSSL_new((*C.WOLFSSL_CTX)(ctx))
	if ssl == nil {
		return nil, errors.New("wolfSSL_new returned nil")
	}
	return unsafe.Pointer(ssl), nil
}

func sslFree(ssl unsafe.Pointer) {
	if ssl == nil {
		return
	}
	C.wolfSSL_free((*C.WOLFSSL)(ssl))
}

func sslSetFD(ssl unsafe.Pointer, fd int) error {
	if int(C.wolfSSL_set_fd((*C.WOLFSSL)(ssl), C.int(fd))) != wolfSuccess {
		return fmt.Errorf("wolfSSL_set_fd(%d) failed", fd)
	}
	return nil
}

func sslAccept(ssl unsafe.Pointer) error {
	ret := int(C.wolfSSL_accept((*C.WOLFSSL)(ssl)))
	if ret != wolfSuccess {
		errCode := int(C.wolfSSL_get_error((*C.WOLFSSL)(ssl), C.int(ret)))
		return fmt.Errorf("wolfSSL_accept failed: ret=%d err=%d", ret, errCode)
	}
	return nil
}

func sslConnect(ssl unsafe.Pointer) error {
	ret := int(C.wolfSSL_connect((*C.WOLFSSL)(ssl)))
	if ret != wolfSuccess {
		errCode := int(C.wolfSSL_get_error((*C.WOLFSSL)(ssl), C.int(ret)))
		return fmt.Errorf("wolfSSL_connect failed: ret=%d err=%d", ret, errCode)
	}
	return nil
}

func sslRead(ssl unsafe.Pointer, buf []byte) (int, error) {
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

func sslWrite(ssl unsafe.Pointer, buf []byte) (int, error) {
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

func sslShutdown(ssl unsafe.Pointer) {
	if ssl == nil {
		return
	}
	C.wolfSSL_shutdown((*C.WOLFSSL)(ssl))
}

func sslGetCipherName(ssl unsafe.Pointer) string {
	c := C.wolfSSL_get_cipher_name((*C.WOLFSSL)(ssl))
	if c == nil {
		return ""
	}
	return C.GoString(c)
}

func sslGetVersion(ssl unsafe.Pointer) string {
	c := C.wolfSSL_get_version((*C.WOLFSSL)(ssl))
	if c == nil {
		return ""
	}
	return C.GoString(c)
}
