package tlsserver

import (
	"errors"
	"net"
	"sync"
	"unsafe"
)

// Server is a CSIP-compliant mTLS server.
//
// Lifecycle:
//
//  1. New(cfg)              — load certs, build wolfSSL context
//  2. Serve(listener)       — accept loop, returns nil on listener close
//  3. close the listener    — caller's responsibility
//  4. wait for Serve return — typically by reading from a channel
//  5. Close()               — wait for in-flight handlers, free wolfSSL ctx
//
// The startTestServer helper in helpers_test.go encapsulates this whole
// dance behind a single t.Cleanup.
type Server struct {
	cfg Config
	ctx unsafe.Pointer // *C.WOLFSSL_CTX, opaque to the rest of the package

	wg sync.WaitGroup

	// OnHandshake, if non-nil, is invoked once per successful handshake
	// with the negotiated TLS version and cipher name. Tests use this
	// to assert CSIP cipher compliance from the server side. Production
	// binaries can use it for structured logging.
	OnHandshake func(version, cipher string)
}

// New constructs a Server, loading certs and configuring mTLS. The
// caller is responsible for calling Init exactly once before any New,
// and Close on the returned Server before exit.
func New(cfg Config) (*Server, error) {
	if cfg.CipherList == "" {
		cfg.CipherList = DefaultCipherList
	}

	ctx, err := newServerCtx()
	if err != nil {
		return nil, err
	}

	// Unwind ctx on any error during configuration. This is the
	// idiomatic Go pattern for "constructor that does multiple
	// fallible setup steps and must clean up on partial failure."
	ok := false
	defer func() {
		if !ok {
			ctxFree(ctx)
		}
	}()

	if err := ctxSetCipherList(ctx, cfg.CipherList); err != nil {
		return nil, err
	}
	if err := ctxUseCertFile(ctx, cfg.ServerCertPath); err != nil {
		return nil, err
	}
	if err := ctxUseKeyFile(ctx, cfg.ServerKeyPath); err != nil {
		return nil, err
	}
	if err := ctxLoadVerifyLocations(ctx, cfg.CACertPath); err != nil {
		return nil, err
	}

	// THE line that turns one-sided TLS into mTLS. Without this call,
	// the server is happy to accept unauthenticated clients regardless
	// of what CAs are loaded.
	ctxRequireClientCert(ctx)

	ok = true
	return &Server{cfg: cfg, ctx: ctx}, nil
}

// Serve runs the accept loop until the listener is closed. It returns
// nil on clean listener closure (net.ErrClosed), or a non-nil error if
// Accept fails for any other reason.
//
// After Serve returns, call Close to wait for any in-flight handlers
// and release the wolfSSL context. Until Close is called, in-flight
// handlers may still be using the ctx, so freeing it here would race.
func (s *Server) Serve(lis net.Listener) error {
	for {
		conn, err := lis.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		s.wg.Add(1)
		go func(c net.Conn) {
			defer s.wg.Done()
			s.handleConn(c)
		}(conn)
	}
}

// Close waits for any in-flight handlers and releases the wolfSSL
// context. Must be called after Serve has returned. Idempotent and
// safe to call from a different goroutine than Serve.
func (s *Server) Close() {
	s.wg.Wait()
	ctxFree(s.ctx)
	s.ctx = nil
}

func (s *Server) handleConn(conn net.Conn) {
	defer conn.Close()

	tcpConn, ok := conn.(*net.TCPConn)
	if !ok {
		return
	}
	file, err := tcpConn.File()
	if err != nil {
		return
	}
	defer file.Close()

	ssl, err := newSSL(s.ctx)
	if err != nil {
		return
	}
	defer sslFree(ssl)

	if err := sslSetFD(ssl, int(file.Fd())); err != nil {
		return
	}

	if err := sslAccept(ssl); err != nil {
		// Failed handshake — could be no client cert, wrong CA, wrong
		// cipher, expired cert, etc. The client side will see the
		// connection drop with their own error. In production we'd log
		// this with structured fields; for now, silent rejection is
		// fine because the negative tests assert on the client-side
		// error rather than server-side log output.
		return
	}

	if s.OnHandshake != nil {
		s.OnHandshake(sslGetVersion(ssl), sslGetCipherName(ssl))
	}

	s.handleRequest(ssl)
	sslShutdown(ssl)
}

func (s *Server) handleRequest(ssl unsafe.Pointer) {
	buf := make([]byte, 4096)
	n, err := sslRead(ssl, buf)
	if err != nil || n == 0 {
		return
	}
	resp := route(buf[:n])
	_, _ = sslWrite(ssl, resp)
}
