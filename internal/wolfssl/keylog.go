// keylog.go adds NSS key-log export to the bench's wolfSSL binding so that a
// packet capture taken during a conformance run can be DECRYPTED after the
// fact. That is what turns a capture from "a pile of ciphertext that proves a
// handshake happened" into evidence a third party can check at the application
// layer: the actual Modbus PDUs, the actual 2030.5 HTTP exchanges, the actual
// register values the DUT returned.
//
// # Why this lives here and not in the product
//
// Exporting TLS session secrets is, by construction, a break of the session's
// confidentiality. It belongs ONLY in the bench harness, whose whole job is to
// observe. The product's own TLS stack (lexa-platform/mbedtls) is deliberately
// NOT given this capability — the gateway under test must not be able to leak
// its own session keys, or the conformance evidence would be describing a
// device that is not the one that ships.
//
// Because every TLS session the bench captures has the BENCH as one of its two
// endpoints (the bench is the mbaps client driving the gateway's :802 server,
// and the bench is the 2030.5 server the gateway's CSIP client dials out to),
// exporting the bench side's secrets is sufficient to decrypt every capture.
// Nothing has to be extracted from the DUT.
//
// # Build requirement
//
// wolfSSL_set_tls13_secret_cb and wolfSSL_SESSION_get_master_key need a
// wolfSSL built with --enable-keylog-export (HAVE_SECRET_CALLBACK) and
// --enable-opensslall. The bench keeps a SEPARATE sysroot for this so the
// ordinary one is untouched:
//
//	~/.local/wolfssl-amd64-keylog     (built by scripts/build-wolfssl-keylog-sysroot.sh)
//
// Building against a sysroot WITHOUT HAVE_SECRET_CALLBACK is a compile error,
// not a silent no-op — a keylog that silently produced nothing would yield
// undecryptable captures and an evidence bundle that looks fine until someone
// tries to verify it.
//
// # Format
//
// The output is the NSS key-log format Wireshark and every other TLS analyzer
// consumes (one record per line, hex-encoded):
//
//	CLIENT_RANDOM <client_random> <master_secret>            # TLS 1.2
//	CLIENT_HANDSHAKE_TRAFFIC_SECRET <client_random> <secret> # TLS 1.3
//	SERVER_HANDSHAKE_TRAFFIC_SECRET <client_random> <secret>
//	CLIENT_TRAFFIC_SECRET_0 <client_random> <secret>
//	SERVER_TRAFFIC_SECRET_0 <client_random> <secret>
//	EXPORTER_SECRET <client_random> <secret>
//
// TLS 1.3 secrets arrive through a per-session callback as the key schedule
// advances, so EnableTLS13Keylog must be called on each WOLFSSL* BEFORE its
// handshake. TLS 1.2 has no such callback: its master secret is recovered
// from the session AFTER the handshake completes, which is what
// WriteTLS12Keylog does.
//
// # Build tag
//
// This file is behind `keylog` so the ordinary build — which links the stock
// sysroot without HAVE_SECRET_CALLBACK — is unaffected. keylog_stub.go
// provides the same API as loud no-ops when the tag is absent, so callers wire
// key export in unconditionally and only the BUILD decides whether a run can
// produce decryptable evidence. Build the evidence-producing binaries with:
//
//	CGO_CFLAGS="-I$HOME/.local/wolfssl-amd64-keylog/include" \
//	CGO_LDFLAGS="-L$HOME/.local/wolfssl-amd64-keylog/lib -lwolfssl -lm" \
//	go build -tags keylog ./...

//go:build keylog

package wolfssl

/*
#cgo LDFLAGS: -lwolfssl -lm
#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

#ifndef HAVE_SECRET_CALLBACK
#error "wolfSSL must be built with --enable-keylog-export (HAVE_SECRET_CALLBACK) for the bench keylog; point CGO_CFLAGS/CGO_LDFLAGS at the keylog sysroot"
#endif

// The key log is process-global because wolfSSL's TLS 1.3 secret callback
// carries only a void* ctx we would otherwise have to pin across the cgo
// boundary for the life of every session. A single append-only file guarded
// by a mutex is simpler and matches how every other TLS implementation does
// SSLKEYLOGFILE. Concurrent handshakes are expected (the conformance suite
// opens many sessions), hence the lock.
static FILE*           lexa_keylog_fp = NULL;
static pthread_mutex_t lexa_keylog_mu = PTHREAD_MUTEX_INITIALIZER;

static int lexa_keylog_open(const char* path) {
	int ok;
	pthread_mutex_lock(&lexa_keylog_mu);
	if (lexa_keylog_fp != NULL) {
		fclose(lexa_keylog_fp);
		lexa_keylog_fp = NULL;
	}
	lexa_keylog_fp = fopen(path, "a");
	ok = (lexa_keylog_fp != NULL);
	pthread_mutex_unlock(&lexa_keylog_mu);
	return ok;
}

static void lexa_keylog_close(void) {
	pthread_mutex_lock(&lexa_keylog_mu);
	if (lexa_keylog_fp != NULL) {
		fclose(lexa_keylog_fp);
		lexa_keylog_fp = NULL;
	}
	pthread_mutex_unlock(&lexa_keylog_mu);
}

// lexa_keylog_emit appends one NSS key-log record. It flushes on every line:
// a conformance run can be killed at any point (a negative test may abort the
// process under test, an operator may ^C), and a buffered secret that never
// reached disk means an undecryptable capture.
static void lexa_keylog_emit(const char* label,
                             const unsigned char* cr, int crLen,
                             const unsigned char* secret, int secretLen) {
	int i;
	if (label == NULL || cr == NULL || secret == NULL) return;
	if (crLen <= 0 || secretLen <= 0) return;
	pthread_mutex_lock(&lexa_keylog_mu);
	if (lexa_keylog_fp != NULL) {
		fputs(label, lexa_keylog_fp);
		fputc(' ', lexa_keylog_fp);
		for (i = 0; i < crLen; i++)     fprintf(lexa_keylog_fp, "%02x", cr[i]);
		fputc(' ', lexa_keylog_fp);
		for (i = 0; i < secretLen; i++) fprintf(lexa_keylog_fp, "%02x", secret[i]);
		fputc('\n', lexa_keylog_fp);
		fflush(lexa_keylog_fp);
	}
	pthread_mutex_unlock(&lexa_keylog_mu);
}

// lexa_tls13_secret_cb is wolfSSL's Tls13SecretCb. wolfSSL's own enum ids are
// mapped to the NSS label strings; note CLIENT_TRAFFIC_SECRET /
// SERVER_TRAFFIC_SECRET map to the "_0" NSS labels (wolfSSL does not surface
// a post-KeyUpdate generation through this callback, so generation 0 is the
// only one that can be named — see the KeyUpdate note in the Go doc).
static int lexa_tls13_secret_cb(WOLFSSL* ssl, int id,
                                const unsigned char* secret, int secretSz,
                                void* ctx) {
	const char* label = NULL;
	unsigned char cr[32];
	size_t n;
	(void)ctx;

	switch (id) {
	case CLIENT_EARLY_TRAFFIC_SECRET:     label = "CLIENT_EARLY_TRAFFIC_SECRET";     break;
	case CLIENT_HANDSHAKE_TRAFFIC_SECRET: label = "CLIENT_HANDSHAKE_TRAFFIC_SECRET"; break;
	case SERVER_HANDSHAKE_TRAFFIC_SECRET: label = "SERVER_HANDSHAKE_TRAFFIC_SECRET"; break;
	case CLIENT_TRAFFIC_SECRET:           label = "CLIENT_TRAFFIC_SECRET_0";         break;
	case SERVER_TRAFFIC_SECRET:           label = "SERVER_TRAFFIC_SECRET_0";         break;
	case EARLY_EXPORTER_SECRET:           label = "EARLY_EXPORTER_SECRET";           break;
	case EXPORTER_SECRET:                 label = "EXPORTER_SECRET";                 break;
	default:
		return 0; // unknown id: nothing to name it, so emit nothing
	}
	n = wolfSSL_get_client_random(ssl, cr, sizeof(cr));
	if (n != sizeof(cr)) return 0;
	lexa_keylog_emit(label, cr, (int)sizeof(cr), secret, secretSz);
	return 0;
}

static int lexa_enable_tls13_keylog(WOLFSSL* ssl) {
	return wolfSSL_set_tls13_secret_cb(ssl, lexa_tls13_secret_cb, NULL);
}

// lexa_keylog_cb is wolfSSL's OpenSSL-compatible key-log callback: wolfSSL
// hands it an already-formatted NSS line, for BOTH TLS versions and BOTH roles.
//
// It exists because the server side cannot reliably recover its own TLS 1.2
// master secret after the fact — wolfSSL_SESSION_get_master_key returns zeros
// for most server sessions. The callback is told the secret at the moment the
// key schedule produces it, so it never has to go looking for it later.
static void lexa_keylog_cb(const WOLFSSL* ssl, const char* line) {
	(void)ssl;
	if (line == NULL) return;
	pthread_mutex_lock(&lexa_keylog_mu);
	if (lexa_keylog_fp != NULL) {
		fputs(line, lexa_keylog_fp);
		fputc('\n', lexa_keylog_fp);
		fflush(lexa_keylog_fp);
	}
	pthread_mutex_unlock(&lexa_keylog_mu);
}

static void lexa_set_ctx_keylog(WOLFSSL_CTX* ctx) {
	if (ctx != NULL) wolfSSL_CTX_set_keylog_callback(ctx, lexa_keylog_cb);
}

// lexa_write_tls12_keylog recovers the TLS 1.2 master secret from the
// completed session. Returns 1 on success, 0 if the session has no master
// secret (TLS 1.3, or a handshake that did not complete).
static int lexa_write_tls12_keylog(WOLFSSL* ssl) {
	unsigned char cr[32];
	unsigned char ms[48];
	WOLFSSL_SESSION* sess;
	int mlen;
	size_t n;

	sess = wolfSSL_get_session(ssl);
	if (sess == NULL) return 0;
	mlen = wolfSSL_SESSION_get_master_key(sess, ms, (int)sizeof(ms));
	if (mlen <= 0) return 0;

	// An ALL-ZERO master secret is not a secret. It is this call reporting
	// that it had nothing to give while still returning a positive length,
	// which wolfSSL does on the SERVER side for a session whose secret the
	// session object does not hold.
	//
	// Emitting it anyway is far worse than emitting nothing. The line is
	// well-formed, so every downstream tool ACCEPTS the key log, matches the
	// client random, derives garbage keys, and reports "AEAD authentication
	// failed" — which reads as a corrupt capture or a broken DUT, not as a
	// missing secret. On 2026-07-28, 79 of 119 exported lines were zeros and
	// 112 conformance assertions failed to decrypt because of it.
	//
	// Refuse, so the caller can report a MISSING secret honestly.
	{
		int allzero = 1, k;
		for (k = 0; k < mlen; k++) { if (ms[k] != 0) { allzero = 0; break; } }
		if (allzero) return 0;
	}

	n = wolfSSL_get_client_random(ssl, cr, sizeof(cr));
	if (n != sizeof(cr)) return 0;
	lexa_keylog_emit("CLIENT_RANDOM", cr, (int)sizeof(cr), ms, mlen);
	return 1;
}
*/
import "C"

import (
	"fmt"
	"sync"
	"unsafe"
)

// keylogMu guards keylogPath so concurrent callers see a consistent view of
// whether export is on. The underlying file is locked in C.
var (
	keylogMu   sync.Mutex
	keylogPath string
)

// OpenKeylog begins NSS key-log export to path, appending if it already
// exists. Call it once, before any session is created. Passing an empty path
// is an error rather than a silent disable — an evidence run that meant to
// capture keys and did not is worse than one that fails loudly.
//
// Every subsequent EnableTLS13Keylog / WriteTLS12Keylog call writes here.
// Call CloseKeylog at shutdown so the file is closed cleanly; records are
// flushed per line regardless, so a killed process still leaves a usable log.
func OpenKeylog(path string) error {
	if path == "" {
		return fmt.Errorf("wolfssl: OpenKeylog: empty path")
	}
	cpath := C.CString(path)
	defer C.free(unsafe.Pointer(cpath))

	keylogMu.Lock()
	defer keylogMu.Unlock()
	if C.lexa_keylog_open(cpath) != 1 {
		return fmt.Errorf("wolfssl: OpenKeylog: cannot open %s for append", path)
	}
	keylogPath = path
	return nil
}

// CloseKeylog stops export and closes the file. Safe to call when export was
// never opened.
func CloseKeylog() {
	keylogMu.Lock()
	defer keylogMu.Unlock()
	C.lexa_keylog_close()
	keylogPath = ""
}

// KeylogPath reports the active key-log path, or "" when export is off.
func KeylogPath() string {
	keylogMu.Lock()
	defer keylogMu.Unlock()
	return keylogPath
}

// EnableTLS13Keylog arms TLS 1.3 secret export for one session. It MUST be
// called after the WOLFSSL* is created and BEFORE its handshake: the callback
// fires as the key schedule advances, and secrets derived before it is
// installed are gone.
//
// It is a no-op returning nil when export is not open, so callers can wire it
// unconditionally into their session setup.
//
// KeyUpdate limitation: wolfSSL surfaces only the generation-0 application
// traffic secrets through this callback, so a session that performs a
// post-handshake KeyUpdate will decrypt up to the update and no further. The
// conformance suite does not trigger KeyUpdate; a decryptor that hits one
// should report it rather than emit garbage.
func EnableTLS13Keylog(ssl unsafe.Pointer) error {
	if ssl == nil {
		return fmt.Errorf("wolfssl: EnableTLS13Keylog: nil ssl")
	}
	keylogMu.Lock()
	on := keylogPath != ""
	keylogMu.Unlock()
	if !on {
		return nil
	}
	if int(C.lexa_enable_tls13_keylog((*C.WOLFSSL)(ssl))) != Success {
		return fmt.Errorf("wolfssl: wolfSSL_set_tls13_secret_cb failed")
	}
	return nil
}

// WriteTLS12Keylog records the TLS 1.2 master secret for a COMPLETED session.
// Call it once, immediately after a successful handshake; before that the
// session has no master secret to read.
//
// It reports whether a record was written. false is not an error: a TLS 1.3
// session legitimately has no master secret here (its secrets came through
// EnableTLS13Keylog), and so does a handshake that failed. Callers that need
// to know a session is decryptable should check that at least one of the two
// paths produced output.
func WriteTLS12Keylog(ssl unsafe.Pointer) bool {
	if ssl == nil {
		return false
	}
	keylogMu.Lock()
	on := keylogPath != ""
	keylogMu.Unlock()
	if !on {
		return false
	}
	return int(C.lexa_write_tls12_keylog((*C.WOLFSSL)(ssl))) == 1
}

// EnableCtxKeylog registers wolfSSL's OpenSSL-compatible key-log callback on a
// context, so every session that context creates exports its secrets.
//
// Prefer this to WriteTLS12Keylog wherever the context is available, and
// ESPECIALLY on the server side. WriteTLS12Keylog has to go looking for the
// master secret in the finished session, and wolfSSL hands a server back zeros
// for most sessions; this is told the secret as the key schedule produces it.
//
// Safe to call on a client context too — the callback covers TLS 1.2 and 1.3
// and both roles, so it is simply the more reliable path.
func EnableCtxKeylog(ctx unsafe.Pointer) {
	if ctx == nil {
		return
	}
	C.lexa_set_ctx_keylog((*C.WOLFSSL_CTX)(ctx))
}
