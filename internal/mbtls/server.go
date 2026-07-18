package mbtls

import (
	"errors"
	"fmt"
	"net"
	"time"
	"unsafe"

	"csip-tls-test/internal/wolfssl"
)

// Listener is an mbaps server: a TCP listener plus a shared, profile-configured
// wolfSSL server context. Each Accept performs a full mTLS handshake and
// returns a Session, or an error if the client failed the profile (no client
// cert, wrong CA, no mutually-acceptable suite). Used by the mbapsdev device
// sim (T06.3) and by loopback conformance harnesses.
type Listener struct {
	lis net.Listener
	ctx unsafe.Pointer // shared across all Accepts; freed by Close
	p   Profile
}

// Listen validates the profile, builds a version-negotiable server context that
// ALWAYS demands a client certificate (RequireClientCert — SunSpecTCP-11/13:
// the CertificateRequest is unconditional and a missing client cert is a fatal
// handshake failure, never a silent accept), and binds addr. The server honours
// a client's MFL request automatically, so no MFL call is made here.
func Listen(addr string, p Profile) (*Listener, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	ctx, err := wolfssl.NewServerCtxTLS()
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
	// THE line that turns one-sided TLS into mTLS: demand + verify a client
	// cert, fail the handshake if none is presented (CLAUDE.md mTLS invariant;
	// SunSpecTCP-11/13/48).
	wolfssl.RequireClientCert(ctx)
	if !p.SessionCache {
		wolfssl.SetSessionCacheOff(ctx)
	}

	lis, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	ok = true
	return &Listener{lis: lis, ctx: ctx, p: p}, nil
}

// Addr returns the listener's network address (useful with :0 in tests).
func (l *Listener) Addr() net.Addr { return l.lis.Addr() }

// Accept waits for the next connection and completes its mTLS handshake. On a
// rejected handshake it returns a non-nil error and NO Session — and it
// sequences the socket close so the client can read the fatal TLS alert before
// the FIN, rather than racing a RST that would surface as a bare ECONNRESET
// (T00 ruling C12). net.ErrClosed is returned verbatim when the listener is
// closed, so callers can break their accept loop cleanly.
func (l *Listener) Accept() (*Session, error) {
	conn, err := l.lis.Accept()
	if err != nil {
		return nil, err
	}
	tcpConn, ok := conn.(*net.TCPConn)
	if !ok {
		conn.Close()
		return nil, fmt.Errorf("mbtls: accepted non-TCP conn %T", conn)
	}
	file, err := tcpConn.File()
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("mbtls: dup accepted fd: %w", err)
	}

	ssl, err := wolfssl.NewSSL(l.ctx)
	if err != nil {
		file.Close()
		conn.Close()
		return nil, err
	}
	if err := wolfssl.SetFD(ssl, int(file.Fd())); err != nil {
		wolfssl.FreeSSL(ssl)
		file.Close()
		conn.Close()
		return nil, err
	}
	if err := wolfssl.Accept(ssl); err != nil {
		// Rejected handshake (no client cert, wrong CA, no shared suite). Flush
		// the alert wolfSSL queued, then close gracefully so the peer reads the
		// real reason (C12). FreeSSL after the flush.
		sequenceRejectClose(ssl, conn)
		wolfssl.FreeSSL(ssl)
		file.Close()
		conn.Close()
		return nil, fmt.Errorf("mbtls: server handshake rejected: %w", err)
	}
	return newSession(ssl, nil, conn, file, false), nil
}

// Close stops accepting and frees the shared server context. Any Sessions
// already handed out remain valid until their own Close (they do not own the
// CTX). Safe to call once.
func (l *Listener) Close() error {
	err := l.lis.Close()
	if l.ctx != nil {
		wolfssl.FreeCtx(l.ctx)
		l.ctx = nil
	}
	return err
}

// sequenceRejectClose drains any inbound bytes with a short deadline so closing
// the socket sends a FIN rather than a RST (a RST would race ahead of the fatal
// alert wolfSSL already wrote, and the client would see ECONNRESET instead of
// the handshake_failure/certificate alert — T00 ruling C12). Best-effort and
// bounded; failures here are irrelevant to the reject verdict.
func sequenceRejectClose(ssl unsafe.Pointer, conn net.Conn) {
	// Nudge wolfSSL to emit any pending close-notify/alert.
	wolfssl.Shutdown(ssl)
	_ = conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	buf := make([]byte, 512)
	for {
		n, err := conn.Read(buf)
		if n == 0 || err != nil {
			return
		}
	}
}

// configureCTX applies the version range, cipher list, trust anchors, and (when
// provided) the leaf chain + key that are common to both server and client
// contexts. An empty CertChainFile/KeyFile is deliberately allowed on the
// client side — it drives the no-client-cert negative (the ClientHello then
// presents no certificate); a server with no cert cannot serve and will fail
// at handshake.
func configureCTX(ctx unsafe.Pointer, p Profile) error {
	minV, maxV := int(p.MinTLS), int(p.MaxTLS)
	if err := wolfssl.SetMinProtoVersion(ctx, minV); err != nil {
		return err
	}
	if err := wolfssl.SetMaxProtoVersion(ctx, maxV); err != nil {
		return err
	}
	if err := wolfssl.SetCipherList(ctx, p.WolfCipherList()); err != nil {
		return err
	}
	if err := wolfssl.LoadVerifyLocations(ctx, p.CAFile); err != nil {
		return err
	}
	if p.CertChainFile != "" {
		if err := wolfssl.UseCertChainFile(ctx, p.CertChainFile); err != nil {
			return err
		}
		if p.KeyFile == "" {
			return errors.New("mbtls: CertChainFile set but KeyFile empty")
		}
		if err := wolfssl.UseKeyFile(ctx, p.KeyFile); err != nil {
			return err
		}
	}
	return nil
}
