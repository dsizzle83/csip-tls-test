package mbtls

import (
	"fmt"
	"net"
	"unsafe"

	"csip-tls-test/internal/wolfssl"
)

// Dial validates the profile, builds a version-negotiable client context, and
// performs the mbaps mTLS handshake to addr. The ClientHello carries the P-256
// supported-curve extension (TCP-43/44) and, when MFLCode is set, the RFC 6066
// Maximum Fragment Length extension (TCP-59/60); NULL compression and the
// renegotiation-indication extension come from the wolfSSL build (TCP-61/62).
//
// A profile with empty CertChainFile/KeyFile presents NO client certificate —
// the deliberate no-client-cert negative used to prove a conformant server
// fails the handshake closed (TCP-11/13). The returned Session owns its
// per-dial CTX and frees it on Close.
func Dial(addr string, p Profile) (*Session, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	ctx, err := wolfssl.NewClientCtxTLS()
	if err != nil {
		return nil, err
	}
	ok := false
	defer func() {
		if !ok {
			wolfssl.FreeCtx(ctx)
		}
	}()
	if err := configureCTX(ctx, p); err != nil {
		return nil, err
	}
	// P-256 in supported_groups so the ECDSA-only suites can complete
	// (SunSpecTCP-42/43/44).
	if err := wolfssl.UseSupportedCurve(ctx, wolfssl.ECCSecp256r1); err != nil {
		return nil, err
	}
	// Request the profile's Maximum Fragment Length (SunSpecTCP-59/60).
	if err := wolfssl.UseMaxFragment(ctx, p.MFLCode); err != nil {
		return nil, err
	}
	// Arm RFC 5746 secure renegotiation on the CLIENT so a mid-session
	// renegotiation is attemptable (the renegotiation-refusal probe, T06.8);
	// without it wolfSSL_Rehandshake fails at the client before anything reaches
	// the wire. This only ADDS the capability — the baseline renegotiation-
	// indication extension (TCP-62) rides every ClientHello from the wolfSSL build
	// regardless, and the initial handshake is unaffected.
	if err := wolfssl.UseSecureRenegotiation(ctx); err != nil {
		return nil, err
	}

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return nil, err
	}
	dialOK := false
	defer func() {
		if !dialOK {
			conn.Close()
		}
	}()
	tcpConn, isTCP := conn.(*net.TCPConn)
	if !isTCP {
		return nil, fmt.Errorf("mbtls: dialed non-TCP conn %T", conn)
	}
	file, err := tcpConn.File()
	if err != nil {
		return nil, fmt.Errorf("mbtls: dup dialed fd: %w", err)
	}
	fileOK := false
	defer func() {
		if !fileOK {
			file.Close()
		}
	}()

	ssl, err := wolfssl.NewSSL(ctx)
	if err != nil {
		return nil, err
	}
	if err := wolfssl.SetFD(ssl, int(file.Fd())); err != nil {
		wolfssl.FreeSSL(ssl)
		return nil, err
	}

	// Offer a cached session for resumption (TCP-46). Holding the cache lock
	// across SetSession keeps the handle from being freed by a concurrent Dial;
	// wolfSSL dups the session into ssl, so ssl is independent afterwards. A cache
	// miss leaves ssl to negotiate a full handshake. A SetSession that fails means
	// the cached handle could not be attached — drop it (evict) so it is not
	// retried, and fall back to a full handshake rather than carrying it forward.
	// (evict cannot run inside withSession — same mutex — so it is deferred to
	// after the locked region via setFailed.)
	key := clientCacheKey(addr, p)
	if p.SessionCache {
		setFailed := false
		clientSessions.withSession(key, func(sess unsafe.Pointer) {
			if sess != nil && wolfssl.SetSession(ssl, sess) != nil {
				setFailed = true
			}
		})
		if setFailed {
			clientSessions.evict(key)
		}
	}

	if err := wolfssl.Connect(ssl); err != nil {
		// A handshake that faulted (including a rejected resume attempt) drops the
		// cached session for this peer so a poisoned session is never replayed.
		if p.SessionCache {
			clientSessions.evict(key)
		}
		wolfssl.FreeSSL(ssl)
		return nil, fmt.Errorf("mbtls: client handshake failed: %w", err)
	}

	// Ownership transfers to the Session from here; disable the unwinders.
	ok, dialOK, fileOK = true, true, true
	s := newSession(ssl, ctx, conn, file, true)
	if p.SessionCache {
		s.cache = clientSessions
		s.cacheKey = key
		s.captureOnClose = true
	}
	return s, nil
}
