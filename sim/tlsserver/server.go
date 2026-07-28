package tlsserver

import (
	"bytes"
	"errors"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"csip-tls-test/internal/csip/identity"
	"csip-tls-test/internal/wolfssl"
)

// Server is a CSIP-compliant mTLS server.
//
// Lifecycle: New → Serve → close listener → Close.
type Server struct {
	cfg Config
	// chain holds the credential this server presents and the runtime lever
	// that changes it. There is deliberately no bare ctx field any more: WHICH
	// wolfSSL context a connection uses is decided at accept time and
	// reference-counted, so a chain swap can retire a context without pulling
	// it out from under a handshake already in flight. See chain.go.
	chain chainState

	wg sync.WaitGroup

	// OnHandshake, if non-nil, is called once per successful handshake
	// with the negotiated TLS version and cipher name. Tests use this
	// to assert CSIP cipher compliance from the server side; production
	// binaries can use it for structured logging.
	OnHandshake func(version, cipher string)

	// IdleTimeout, when non-zero, closes a connection that has gone this long
	// without a request. Zero keeps connections open indefinitely.
	//
	// WHY: a conformant 2030.5 client keeps ONE TLS session and reuses it for
	// every poll cycle — measured 2026-07-28, 14 walks over 2 handshakes. The
	// CSIP suite's [C]-half checks recover the DUT's session by finding its
	// ClientHello in the capture, so once that single session predates the
	// capture there is nothing left to observe and every such case SKIPs
	// forever. That is a limitation of the OBSERVATION, not a DUT fault: the
	// gateway is doing the better thing by not re-handshaking every cycle.
	//
	// The fix goes on the test server, where pollRate's went, leaving the
	// device in its shipping configuration. Set this BELOW the poll cadence
	// and ABOVE a single walk's duration (10s against a 60s cadence and ~1s
	// walks): the connection then dies between walks and each walk opens
	// exactly one fresh session carrying the whole walk.
	//
	// "One session per WALK" is the requirement, not merely "more sessions".
	// certify.Evidence.StreamOn refuses a test case with more than one
	// attributed conversation on a port ("cite one explicitly"), and
	// RecoverSession expects the entire discovery walk inside the session it
	// recovers. An earlier attempt closed after every RESPONSE, which produced
	// ~28 single-GET sessions per walk and failed both conditions at once.
	IdleTimeout time.Duration

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
//
// The credential itself — cipher list, chain, key, verify locations, the mTLS
// requirement, the ticket policy and the key-log export — is built by
// newCredential in chain.go, so that the chain a SwapChain installs at runtime
// is configured by exactly the same code as the one the process starts with.
// Two copies of that list is how a swapped-in chain quietly loses, say, key-log
// export, and leaves a hole in the evidence at the one handshake that mattered.
func New(cfg Config) (*Server, error) {
	if cfg.CipherList == "" {
		cfg.CipherList = DefaultCipherList
	}
	s := &Server{cfg: cfg}

	// Chain file (leaf + intermediates) takes precedence when configured, so
	// the server can present a depth-3/4 chain; otherwise the single leaf.
	certPath, chainLoader := cfg.ServerCertPath, false
	if cfg.ServerCertChainPath != "" {
		certPath, chainLoader = cfg.ServerCertChainPath, true
	}
	info, err := s.installChain("startup", certPath, cfg.ServerKeyPath, true, chainLoader)
	if err != nil {
		return nil, err
	}
	s.chain.mu.Lock()
	s.chain.orig, s.chain.origLoader = info, chainLoader
	s.chain.mu.Unlock()
	return s, nil
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
//
// Waiting first is what makes the free safe: every connection holds a reference
// to the credential it handshook with, so by the time Wait returns the only
// outstanding reference is the installed one, and dropping it here frees the
// last context. Any credential retired by an earlier swap was already freed by
// whichever connection closed last.
func (s *Server) Close() {
	s.wg.Wait()
	s.chain.mu.Lock()
	cur := s.chain.cur
	s.chain.cur = nil
	s.chain.mu.Unlock()
	if cur != nil {
		cur.release()
	}
}

func (s *Server) handleConn(conn net.Conn) {
	defer conn.Close()

	// Pin the credential for this connection's whole life. Everything after
	// this line is served under the chain that was installed at ACCEPT time,
	// which is what makes a mid-campaign swap safe: a chain that changes under
	// an open session would produce a capture nobody can interpret.
	cred := s.acquireCredential()
	if cred == nil {
		return // the server is closing
	}
	defer cred.release()

	tcpConn, ok := conn.(*net.TCPConn)
	if !ok {
		return
	}
	file, err := tcpConn.File()
	if err != nil {
		return
	}
	defer file.Close()

	ssl, err := wolfssl.NewSSL(cred.ctx)
	if err != nil {
		return
	}
	defer wolfssl.FreeSSL(ssl)

	if err := wolfssl.SetFD(ssl, int(file.Fd())); err != nil {
		return
	}

	// Arm key-log export before the handshake (TLS 1.3 secrets arrive through a
	// per-session callback as the key schedule advances, so it cannot be armed
	// afterwards). A no-op outside a -tags keylog evidence build.
	//
	// This is the SERVER half of the bench's evidence story. Every TLS session a
	// conformance run captures has the bench as one endpoint — the bench is the
	// mbaps client driving the gateway's :802, and the bench is the 2030.5
	// server the gateway's CSIP client dials out to. Only the first half was
	// ever wired up, so gateway->gridsim sessions stayed ciphertext and every
	// CSIP criterion about a RESPONSE BODY or STATUS LINE reported "the key log
	// holds no secret for this session's client random". Nothing is extracted
	// from the DUT: these are the bench's own secrets, for a session the bench
	// itself terminated.
	if err := wolfssl.EnableTLS13Keylog(ssl); err != nil {
		log.Printf("[tlsserver] arm key-log export: %v", err)
		return
	}

	if err := wolfssl.Accept(ssl); err != nil {
		// Failed handshake — could be no client cert, wrong CA, wrong
		// cipher, etc. Negative tests assert on the client-side error
		// rather than server logs, so silent rejection is fine.
		return
	}

	// TLS 1.2 has no key-schedule callback: its master secret is recoverable
	// only from the completed session, so it is written here rather than armed
	// above. The gateway negotiates TLS 1.2 northbound today, which makes this
	// line — not the one above it — the one that actually decrypts the capture.
	wolfssl.WriteTLS12Keylog(ssl)

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

	// Idle watchdog. It unblocks the read with shutdown(SHUT_RD) rather than
	// closing a descriptor: wolfSSL reads from the dup returned by
	// tcpConn.File(), so a deadline on conn would not reach it, and closing
	// the dup underneath a blocked read races descriptor reuse. SHUT_RD makes
	// the pending read return EOF and nothing else changes hands.
	//
	// SO_RCVTIMEO would be the other way to do this and is deliberately NOT
	// used: it hands the read an EINTR every time Go's async preemption fires
	// a SIGURG at it, which is the exact failure that cost hours on 2026-07-27.
	touch := func() {}
	if s.IdleTimeout > 0 {
		var last atomic.Int64
		last.Store(time.Now().UnixNano())
		touch = func() { last.Store(time.Now().UnixNano()) }
		fd := int(file.Fd())
		done := make(chan struct{})
		defer close(done)
		go func() {
			tk := time.NewTicker(time.Second)
			defer tk.Stop()
			for {
				select {
				case <-done:
					return
				case <-tk.C:
					if time.Since(time.Unix(0, last.Load())) >= s.IdleTimeout {
						_ = syscall.Shutdown(fd, syscall.SHUT_RD)
						return
					}
				}
			}
		}()
	}

	s.handleRequest(ssl, peerLFDI, touch)
	wolfssl.Shutdown(ssl)
}

func (s *Server) handleRequest(ssl unsafe.Pointer, peerLFDI string, touch func()) {
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
		touch()
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
