package tlsserver

import (
	"errors"
	"net"
	"net/http"
	"sync"
	"unsafe"

	"csip-tls-test/internal/wolfssl"
)

// Server is a CSIP-compliant mTLS server.
//
// Lifecycle: New → Serve → close listener → Close.
type Server struct {
	cfg Config
	ctx unsafe.Pointer

	wg sync.WaitGroup

	// OnHandshake, if non-nil, is called once per successful handshake
	// with the negotiated TLS version and cipher name. Tests use this
	// to assert CSIP cipher compliance from the server side; production
	// binaries can use it for structured logging.
	OnHandshake func(version, cipher string)

	// Handler, if non-nil, is the http.Handler that serves every request.
	// Set this to sim.Handler() to route requests through gridsim instead
	// of the built-in static /dcap route. When nil, the built-in router
	// is used (safe for existing tests).
	Handler http.Handler

	// OnClientCert, if non-nil, is called once per successful handshake
	// with the DER-encoded peer certificate. Use this to extract the LFDI
	// from the live cert rather than pre-computing it from a file on disk
	// (Step A). Wired in production to gridsim.SetClientCertDER.
	OnClientCert func(der []byte)
}

// New constructs a Server, loading certs and configuring mTLS.
func New(cfg Config) (*Server, error) {
	if cfg.CipherList == "" {
		cfg.CipherList = DefaultCipherList
	}

	ctx, err := wolfssl.NewServerCtx()
	if err != nil {
		return nil, err
	}

	// Unwind ctx on any error during configuration.
	ok := false
	defer func() {
		if !ok {
			wolfssl.FreeCtx(ctx)
		}
	}()

	if err := wolfssl.SetCipherList(ctx, cfg.CipherList); err != nil {
		return nil, err
	}
	if err := wolfssl.UseCertFile(ctx, cfg.ServerCertPath); err != nil {
		return nil, err
	}
	if err := wolfssl.UseKeyFile(ctx, cfg.ServerKeyPath); err != nil {
		return nil, err
	}
	if err := wolfssl.LoadVerifyLocations(ctx, cfg.CACertPath); err != nil {
		return nil, err
	}

	// THE line that turns one-sided TLS into mTLS.
	wolfssl.RequireClientCert(ctx)

	ok = true
	return &Server{cfg: cfg, ctx: ctx}, nil
}

// Serve runs the accept loop until the listener is closed.
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

// Close waits for in-flight handlers and releases the wolfSSL context.
// Must be called after Serve has returned.
func (s *Server) Close() {
	s.wg.Wait()
	wolfssl.FreeCtx(s.ctx)
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

	ssl, err := wolfssl.NewSSL(s.ctx)
	if err != nil {
		return
	}
	defer wolfssl.FreeSSL(ssl)

	if err := wolfssl.SetFD(ssl, int(file.Fd())); err != nil {
		return
	}

	if err := wolfssl.Accept(ssl); err != nil {
		// Failed handshake — could be no client cert, wrong CA, wrong
		// cipher, etc. Negative tests assert on the client-side error
		// rather than server logs, so silent rejection is fine.
		return
	}

	if s.OnHandshake != nil {
		s.OnHandshake(wolfssl.Version(ssl), wolfssl.CipherName(ssl))
	}
	if s.OnClientCert != nil {
		if der := wolfssl.PeerCertificateDER(ssl); der != nil {
			s.OnClientCert(der)
		}
	}

	s.handleRequest(ssl)
	wolfssl.Shutdown(ssl)
}

func (s *Server) handleRequest(ssl unsafe.Pointer) {
	buf := make([]byte, 4096)
	n, err := wolfssl.Read(ssl, buf)
	if err != nil || n == 0 {
		return
	}
	var resp []byte
	if s.Handler != nil {
		resp = dispatchHTTP(s.Handler, buf[:n])
	} else {
		resp = route(buf[:n])
	}
	_, _ = wolfssl.Write(ssl, resp)
}
