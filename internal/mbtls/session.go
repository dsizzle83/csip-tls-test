package mbtls

import (
	"net"
	"os"
	"sync"
	"unsafe"

	"csip-tls-test/internal/wolfssl"
)

// Session is one established mbaps connection. Conn is the decrypted stream to
// feed to lexa-proto/mbap; the remaining fields expose the handshake facts a
// conformance check asserts on (peer identity for role extraction, negotiated
// cipher/version, resumption). A Session is returned by Dial (client) and by
// Listener.Accept (server).
type Session struct {
	// Conn is the decrypted, framed-payload stream. Feed it to
	// lexa-proto/mbap; set read/write deadlines on it around each op (T06.4).
	Conn net.Conn
	// PeerDER is the peer leaf certificate in DER, for identity + role
	// assertion (RoleFromDER). nil if the peer presented no certificate.
	PeerDER []byte
	// Resumed reports whether this handshake resumed a cached session (TCP-46).
	Resumed bool
	// Cipher is the negotiated suite name (e.g. ECDHE-ECDSA-AES128-GCM-SHA256),
	// for suite-conformance assertions (TCP-17/18).
	Cipher string
	// TLSVer is the negotiated protocol version string (TLSv1.2 / TLSv1.3).
	TLSVer string
	// MFLCode is the negotiated Maximum Fragment Length selector (wolfssl.MFL*,
	// 0 = none), making the 512-byte cap observable (TCP-59/60).
	MFLCode int

	ssl  unsafe.Pointer // wolfSSL session handle
	ctx  unsafe.Pointer // owned CTX for client sessions; nil for server sessions (Listener owns it)
	raw  net.Conn       // underlying TCP conn (addrs, transport close)
	file *os.File       // dup'd fd wolfSSL drives; kept alive for the session's lifetime

	closeOnce sync.Once
}

// newSession fills the handshake-fact fields from a live wolfSSL handle and
// wires up the net.Conn adapter. ownCtx distinguishes a client session (which
// owns and frees its per-dial CTX) from a server session (whose CTX is shared,
// owned by the Listener).
func newSession(ssl, ctx unsafe.Pointer, raw net.Conn, file *os.File, ownCtx bool) *Session {
	s := &Session{
		PeerDER: wolfssl.PeerCertificateDER(ssl),
		Resumed: wolfssl.SessionReused(ssl),
		Cipher:  wolfssl.CipherName(ssl),
		TLSVer:  wolfssl.Version(ssl),
		MFLCode: wolfssl.NegotiatedMaxFragment(ssl),
		ssl:     ssl,
		raw:     raw,
		file:    file,
	}
	if ownCtx {
		s.ctx = ctx
	}
	s.Conn = &tlsConn{sess: s}
	return s
}

// Renegotiate drives a client-initiated secure renegotiation and re-reads the
// peer facts. Used by the renegotiation-refusal probe (T06.8): the mbaps
// server's policy for a mid-session renegotiation is asserted against the
// returned error, and any conformant server re-derives the client role on
// renegotiation (design doc 02 §1).
func (s *Session) Renegotiate() error {
	if err := wolfssl.Rehandshake(s.ssl); err != nil {
		return err
	}
	s.Resumed = wolfssl.SessionReused(s.ssl)
	s.Cipher = wolfssl.CipherName(s.ssl)
	s.TLSVer = wolfssl.Version(s.ssl)
	if der := wolfssl.PeerCertificateDER(s.ssl); der != nil {
		s.PeerDER = der
	}
	return nil
}

// Role extracts and returns this session's peer role via the bench's own
// independent parser (RoleFromDER). Convenience for callers that already hold a
// Session; equivalent to RoleFromDER(s.PeerDER) with a no-cert guard.
func (s *Session) Role() (string, error) {
	if len(s.PeerDER) == 0 {
		return "", ErrNoRole
	}
	return RoleFromDER(s.PeerDER)
}

// Close tears down the session exactly once: TLS close-notify, then the wolfSSL
// handle, then (for client sessions) the owned CTX, then the socket. Teardown
// order matters — the SSL handle must be freed before the fd it references.
func (s *Session) Close() error {
	s.closeOnce.Do(func() {
		if s.ssl != nil {
			wolfssl.Shutdown(s.ssl)
			wolfssl.FreeSSL(s.ssl)
			s.ssl = nil
		}
		if s.ctx != nil {
			wolfssl.FreeCtx(s.ctx)
			s.ctx = nil
		}
		if s.file != nil {
			_ = s.file.Close()
		}
		if s.raw != nil {
			_ = s.raw.Close()
		}
	})
	return nil
}
