package tlsserver

import (
	"bytes"
	"errors"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"unsafe"

	"csip-tls-test/internal/csip/identity"
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

	// Extract peer LFDI once per connection. Used for LFDI-gated resource
	// views (X-Peer-LFDI request header) and for the OnClientCert callback.
	var peerLFDI string
	if der := wolfssl.PeerCertificateDER(ssl); der != nil {
		if s.OnClientCert != nil {
			s.OnClientCert(der)
		}
		lfdi, _ := identity.FromCertificateDER(der)
		peerLFDI = lfdi.String()
	}

	s.handleRequest(ssl, peerLFDI)
	wolfssl.Shutdown(ssl)
}

func (s *Server) handleRequest(ssl unsafe.Pointer, peerLFDI string) {
	if s.Handler == nil {
		// Legacy static router: one request per connection (backward compat).
		raw := readHTTPMessage(ssl)
		if len(raw) > 0 {
			_, _ = wolfssl.Write(ssl, route(raw))
		}
		return
	}

	// Persistent-connection loop for real handlers.
	// Exits when the client sends Connection: close, disconnects, or an
	// I/O error occurs.
	for {
		raw := readHTTPMessage(ssl)
		if len(raw) == 0 {
			return // client closed connection
		}
		connClose := requestWantsClose(raw)
		resp := dispatchHTTP(s.Handler, raw, peerLFDI, connClose)
		if _, err := wolfssl.Write(ssl, resp); err != nil {
			return
		}
		if connClose {
			return
		}
	}
}

// requestWantsClose returns true when the HTTP request contains a
// Connection: close header. HTTP/1.1 defaults to keep-alive, so the
// absence of this header means the client wants to reuse the connection.
func requestWantsClose(raw []byte) bool {
	return bytes.Contains(bytes.ToLower(raw), []byte("connection: close"))
}

// readHTTPMessage reads a complete HTTP request from an open wolfSSL session.
// It reads until the full header block (\r\n\r\n) is present, parses
// Content-Length, then reads until the body is fully buffered.
// This handles TLS record fragmentation and POST bodies larger than 4 KB.
func readHTTPMessage(ssl unsafe.Pointer) []byte {
	const maxSize = 1 << 20 // 1 MB safety cap
	buf := make([]byte, 4096)
	var data []byte
	headerEnd := -1

	for len(data) < maxSize {
		n, err := wolfssl.Read(ssl, buf)
		if n > 0 {
			data = append(data, buf[:n]...)
			if headerEnd < 0 {
				if idx := bytes.Index(data, []byte("\r\n\r\n")); idx >= 0 {
					headerEnd = idx + 4
				}
			}
		}
		if err != nil || n == 0 {
			return data
		}
		if headerEnd >= 0 {
			need := headerEnd + parseContentLength(data[:headerEnd])
			if len(data) >= need {
				return data[:need]
			}
		}
	}
	return data
}

// parseContentLength extracts the Content-Length value from raw HTTP headers.
// Returns 0 if the header is absent or unparseable.
func parseContentLength(headers []byte) int {
	for _, line := range strings.Split(string(headers), "\r\n") {
		if len(line) > 15 && strings.EqualFold(line[:15], "content-length:") {
			n, _ := strconv.Atoi(strings.TrimSpace(line[15:]))
			return n
		}
	}
	return 0
}
