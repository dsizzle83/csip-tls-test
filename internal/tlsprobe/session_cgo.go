//go:build cgo

package tlsprobe

// session_cgo.go is the wolfSSL half: the only part of this package that cannot
// exist in a CGO_ENABLED=0 build, kept in one file behind one constraint so the
// pure-Go half above it stays compilable for `CGO_ENABLED=0 go build
// ./cmd/certify` (the certify gate's second step).

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"csip-tls-test/internal/wolfssl"
)

// initOnce initialises the wolfSSL library on first use.
//
// wolfSSL_Init must run exactly once per process before anything else in the
// library, and the sims do it from main(). cmd/certify has never linked wolfSSL
// at all, so there is no main() to put it in that would not also drag the
// library into every build of the tool. Doing it lazily here keeps the
// requirement local to the one package that needs it.
//
// Cleanup is deliberately never called: this package cannot know whether
// another part of the process still holds wolfSSL handles, and releasing
// library globals underneath them would be far worse than leaking them at
// exit.
var initOnce sync.Once

// keylogOnce guards the process-wide key log this package opens. wolfSSL's
// export is a process-global file, so opening it per session would be either a
// no-op or a truncation depending on the order — neither of which is what a
// caller asking for decryptable evidence means.
var (
	keylogMu   sync.Mutex
	keylogOpen string
	keylogWhy  string
)

// Session is one established mbaps session the probe owns.
type Session struct {
	spec Spec

	ssl, ctx unsafe.Pointer
	raw      net.Conn // the original TCP conn: addresses and transport close
	file     *os.File // the dup'd fd wolfSSL drives; kept alive for the session
	conn     *probeConn

	local, remote netip.AddrPort
	negotiated    Negotiated
	peerLeaf      []byte
	keylogPath    string
	keylogNote    string
	started       time.Time
	model1        ModelRead

	closeOnce sync.Once
}

// Dial opens one mbaps session, pinned to whatever the Spec pins.
//
// The Spec is validated before a socket is opened, and OnConnect runs after the
// TCP connect and BEFORE the handshake — see Spec.OnConnect for why that
// ordering is the whole point.
func Dial(ctx context.Context, spec Spec) (*Session, error) {
	if err := spec.validate(); err != nil {
		return nil, err
	}
	initOnce.Do(wolfssl.Init)

	deadline := spec.deadline()
	minV, maxV, _ := spec.versionRange()
	cipherList, offered := spec.offer()

	wctx, err := newClientCTX(spec, minV, maxV, cipherList)
	if err != nil {
		return nil, err
	}
	ctxOK := false
	defer func() {
		if !ctxOK {
			wolfssl.FreeCtx(wctx)
		}
	}()

	var d net.Dialer
	dctx, cancel := context.WithTimeout(ctx, deadline)
	defer cancel()
	raw, err := d.DialContext(dctx, "tcp", spec.Target)
	if err != nil {
		return nil, fmt.Errorf("tlsprobe: dial %s: %w", spec.Target, err)
	}
	rawOK := false
	defer func() {
		if !rawOK {
			_ = raw.Close()
		}
	}()

	s := &Session{spec: spec, raw: raw, started: time.Now()}
	s.local, _ = addrPortOf(raw.LocalAddr())
	s.remote, _ = addrPortOf(raw.RemoteAddr())

	// Register the connection BEFORE the handshake, so a handshake the DUT
	// REFUSES still has attributable frames.
	if spec.OnConnect != nil {
		if err := spec.OnConnect(raw); err != nil {
			return nil, fmt.Errorf("tlsprobe: the caller refused the connection to %s: %w", spec.Target, err)
		}
	}

	tcp, ok := raw.(*net.TCPConn)
	if !ok {
		return nil, fmt.Errorf("tlsprobe: dialled a non-TCP connection (%T)", raw)
	}
	file, err := tcp.File()
	if err != nil {
		return nil, fmt.Errorf("tlsprobe: duplicate the dialled socket: %w", err)
	}
	fileOK := false
	defer func() {
		if !fileOK {
			_ = file.Close()
		}
	}()
	s.file = file

	ssl, err := wolfssl.NewSSL(wctx)
	if err != nil {
		return nil, err
	}
	sslOK := false
	defer func() {
		if !sslOK {
			wolfssl.FreeSSL(ssl)
		}
	}()
	if err := wolfssl.SetFD(ssl, int(file.Fd())); err != nil {
		return nil, err
	}
	// Arm TLS 1.3 secret export BEFORE the handshake: the callback fires as the
	// key schedule advances and a secret derived before it is installed cannot
	// be recovered afterwards. A no-op when no key log is open.
	if err := wolfssl.EnableTLS13Keylog(ssl); err != nil {
		return nil, fmt.Errorf("tlsprobe: arm key-log export: %w", err)
	}
	// A bounded handshake. wolfSSL does blocking I/O on the dup'd fd, which the
	// Go poller no longer manages, so the socket's own timeout is what stops a
	// wedged DUT from hanging the campaign. Context cancellation is noticed
	// when that timeout expires rather than immediately, which is why the
	// timeout is bounded rather than generous.
	if err := armTimeouts(int(file.Fd()), deadline); err != nil {
		return nil, err
	}
	spec.log("tlsprobe: %s <> %s: offering %s over %s..%s", s.local, s.remote, cipherList, minV, maxV)
	if err := wolfssl.Connect(ssl); err != nil {
		he := &HandshakeError{
			Target: spec.Target, Requested: spec.Suite, Offered: offered,
			Local: s.local, Remote: s.remote, Err: err,
		}
		// Read the alert history while the session still lives — the deferred
		// FreeSSL has not run yet. A peer that refused us with a fatal alert
		// left it here; a peer that merely closed the socket left it empty.
		he.RxAlert, he.TxAlert, _ = wolfssl.AlertHistory(ssl)
		he.classify()
		return nil, he
	}
	// TLS 1.2 has no secret callback: its master secret exists on the session
	// only once the handshake completes.
	wolfssl.WriteTLS12Keylog(ssl)

	s.ssl, s.ctx = ssl, wctx
	s.peerLeaf = wolfssl.PeerCertificateDER(ssl)
	if len(s.peerLeaf) == 0 {
		s.peerLeaf = wolfssl.PeerChainLeafDER(ssl)
	}
	s.negotiated = Negotiated{
		VersionName: wolfssl.Version(ssl),
		SuiteName:   wolfssl.CipherName(ssl),
		Resumed:     wolfssl.SessionReused(ssl),
	}
	s.negotiated.Version = versionFromName(s.negotiated.VersionName)
	s.negotiated.Suite = suiteFromWolfName(s.negotiated.SuiteName)
	s.keylogPath, s.keylogNote = keylogState()
	s.conn = &probeConn{sess: s}

	ctxOK, rawOK, fileOK, sslOK = true, true, true, true
	spec.log("tlsprobe: %s <> %s: established %s", s.local, s.remote, s.negotiated)
	return s, nil
}

// newClientCTX builds the wolfSSL context for one probe.
func newClientCTX(spec Spec, minV, maxV Version, cipherList string) (unsafe.Pointer, error) {
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
	if err := wolfssl.SetMinProtoVersion(ctx, int(minV)); err != nil {
		return nil, err
	}
	if err := wolfssl.SetMaxProtoVersion(ctx, int(maxV)); err != nil {
		return nil, err
	}
	if err := wolfssl.SetCipherList(ctx, cipherList); err != nil {
		return nil, fmt.Errorf("tlsprobe: pin the offer to %q: %w (the wolfSSL build must carry every "+
			"mandated suite — AES-CCM included — or a mandated suite cannot be offered at all)",
			cipherList, err)
	}
	for _, ca := range spec.CAFiles {
		if err := wolfssl.LoadVerifyLocations(ctx, ca); err != nil {
			return nil, fmt.Errorf("tlsprobe: load trust anchor %s: %w", ca, err)
		}
	}
	if err := wolfssl.UseCertChainFile(ctx, spec.CertFile); err != nil {
		return nil, fmt.Errorf("tlsprobe: load client chain %s: %w", spec.CertFile, err)
	}
	if err := wolfssl.UseKeyFile(ctx, spec.KeyFile); err != nil {
		return nil, fmt.Errorf("tlsprobe: load client key %s: %w", spec.KeyFile, err)
	}
	// P-256 in supported_groups: the mandated suites are ECDSA-only and
	// SunSpecTCP-42 makes P-256 the curve, so without it an ECDSA-only offer
	// can fail for a reason that has nothing to do with the suite under test.
	if err := wolfssl.UseSupportedCurve(ctx, wolfssl.ECCSecp256r1); err != nil {
		return nil, err
	}
	// REV0907-E7: request the RFC 6066 Maximum Fragment Length the WORKING
	// mbaps client requests (internal/mbtls's Dial, DefaultClientProfile's
	// MFLCode) — MFL512, wire value 1. The board's Mbed TLS server carries the
	// SunSpec CCM MFL patches 0002-0006, and every mbaps session captured
	// against it negotiates MFL=1 on the wire; a ClientHello that omits the
	// extension is not the ClientHello shape that server has ever completed an
	// mbaps session against, which is this finding's "cannot complete mTLS to
	// the board".
	if err := wolfssl.UseMaxFragment(ctx, wolfssl.MFL512); err != nil {
		return nil, err
	}
	// REV0907-E7: arm RFC 5746 secure renegotiation on the client, matching
	// internal/mbtls's Dial exactly (see its own comment on the same call), so
	// this probe's ClientHello differs from the working client's ONLY in the
	// suite list this package deliberately varies. internal/mbtls's comment on
	// its own call states the renegotiation_info extension (0xff01) rides every
	// ClientHello from the wolfSSL build regardless of this call; against the
	// $WOLFSSL_SYSROOT this package is built with, that is NOT what this
	// package's own loopback capture shows (clienthello_wire_cgo_test.go,
	// mutation-verified) — removing this call removes the extension from this
	// build's ClientHello entirely, empty SCSV included. Whether that is a
	// build-config difference between sysroots or a stale claim, it makes this
	// call load-bearing for THIS build, not merely a capability addition: it is
	// the one knob that closes the ClientHello-shape gap this finding is about.
	if err := wolfssl.UseSecureRenegotiation(ctx); err != nil {
		return nil, err
	}
	// Every dial is a FULL handshake. A probe that silently resumed would
	// answer "did the DUT complete a handshake on this suite?" with evidence
	// from a session negotiated earlier, possibly on another suite entirely.
	wolfssl.SetSessionCacheOff(ctx)
	if err := openKeylog(spec.KeylogPath); err != nil {
		return nil, err
	}
	wolfssl.EnableCtxKeylog(ctx)
	ok = true
	return ctx, nil
}

// openKeylog opens the process-wide key log once, and records why it could not
// be opened when that is the answer.
//
// A failure is NOT fatal to the probe. The key log makes the session's
// application-layer records decryptable in the capture; without it the
// handshake facts are still on the wire in the clear and still citable. What
// must never happen is a silent gap, so the reason travels in the Report.
func openKeylog(path string) error {
	if path == "" {
		return nil
	}
	keylogMu.Lock()
	defer keylogMu.Unlock()
	if keylogOpen == path {
		return nil
	}
	if err := wolfssl.OpenKeylog(path); err != nil {
		keylogWhy = fmt.Sprintf("this session's TLS secrets were NOT exported to %s, so its encrypted "+
			"records are not decryptable in the capture: %v", path, err)
		return nil
	}
	keylogOpen, keylogWhy = path, ""
	return nil
}

func keylogState() (string, string) {
	keylogMu.Lock()
	defer keylogMu.Unlock()
	return keylogOpen, keylogWhy
}

// HandshakeError is a handshake that did not complete, carrying what was
// offered so the failure is attributable to the offer rather than to the bench.
type HandshakeError struct {
	Target        string
	Requested     Suite
	Offered       []Suite
	Local, Remote netip.AddrPort
	Err           error

	// Code is the wolfSSL reason code, when one could be recovered, and Reason
	// is the library's own rendering of it.
	Code   int
	Reason string
	// PeerRejectedByUs reports that the handshake failed because THIS SIDE
	// refused the peer's certificate — not because the peer refused what was
	// offered. Diagnosis says which check refused it. See reason_cgo.go for why
	// a cipher-suite procedure must not report the two the same way.
	PeerRejectedByUs bool
	Diagnosis        string

	// RxAlert and TxAlert are the last TLS alerts wolfSSL recorded on the
	// session — captured from wolfSSL_get_alert_history the instant the
	// handshake failed, before the session is torn down. RxAlert is the PEER's
	// stated reason for aborting, when it sent a fatal alert rather than simply
	// closing the socket; the difference is what turns a bare SOCKET_ERROR_E
	// (-308) into a real diagnosis. See wolfssl.AlertHistory.
	RxAlert, TxAlert wolfssl.Alert
}

func (e *HandshakeError) Error() string {
	what := "the mandated set"
	if e.Requested.Pinned() {
		what = "only " + e.Requested.String()
	}
	tail := e.Err.Error()
	if e.Reason != "" {
		tail += " (" + e.Reason + ")"
	}
	// Turn the bare reason code into what actually happened on the wire: the
	// peer's fatal alert when it sent one, or a plain statement that it aborted
	// at the transport layer when it did not. This is the instrumentation the
	// bench's -308 needed — "the DUT said bad_certificate" and "the DUT dropped
	// the connection" are different findings and must not read the same.
	if a := alertText(e.RxAlert); a != "" {
		tail += "; the peer sent a " + a + " — its stated reason for aborting the handshake"
	} else if e.transportClosed() {
		tail += "; the peer closed or reset the TCP connection during the handshake WITHOUT sending a TLS " +
			"alert — it aborted at the transport layer, not with a protocol rejection (so the cause is a " +
			"socket/record-level mismatch, not a cipher or certificate the peer named)"
	}
	if e.PeerRejectedByUs {
		return fmt.Sprintf("tlsprobe: the handshake to %s offering %s did not complete because THIS SIDE "+
			"refused the peer's certificate — %s. That is a fact about the bench's trust configuration or "+
			"the peer's PKI, not about the cipher suite offered: %s", e.Target, what, e.Diagnosis, tail)
	}
	return fmt.Sprintf("tlsprobe: the handshake to %s offering %s did not complete: %s", e.Target, what, tail)
}

func (e *HandshakeError) Unwrap() error { return e.Err }

// Refused reports whether err is a handshake the peer did not complete, and
// returns it. It is the shape a negative procedure asserts on: the DUT was
// offered something it must reject, and rejected it.
func Refused(err error) (*HandshakeError, bool) {
	var he *HandshakeError
	if errors.As(err, &he) {
		return he, true
	}
	return nil, false
}

// Conn returns the decrypted stream. Callers that want to drive their own
// protocol inside the tunnel use it; ReadModel1 is the one this package drives
// itself.
func (s *Session) Conn() net.Conn { return s.conn }

// Negotiated returns what the handshake settled on.
func (s *Session) Negotiated() Negotiated { return s.negotiated }

// ReadModel1 carries one SunSpec Common Model read inside the tunnel and
// records it on the session's report.
func (s *Session) ReadModel1() ModelRead {
	mc := &modbusConn{conn: s.conn}
	base := s.spec.base()
	if s.spec.Unit != 0 {
		s.model1 = readModel1(mc, s.spec.Unit, base)
		return s.model1
	}
	unit, m := findUnit(mc, base)
	if unit == 0 && m.Err != nil {
		m.Err = fmt.Errorf("no SunSpec chain answered on unit ids 1..8 (last: %w) — set Spec.Unit if the "+
			"populated unit is outside that range", m.Err)
	}
	s.model1 = m
	return m
}

// Report returns everything this probe established.
func (s *Session) Report() *Report {
	return &Report{
		Target:      s.spec.Target,
		Local:       s.local,
		Remote:      s.remote,
		Requested:   s.spec.Suite,
		Negotiated:  s.negotiated,
		PeerLeafDER: s.peerLeaf,
		KeylogPath:  s.keylogPath,
		KeylogNote:  s.keylogNote,
		Model1:      s.model1,
		Elapsed:     time.Since(s.started),
	}
}

// Close tears the session down exactly once, in the order the handles require:
// TLS close-notify, the wolfSSL session, the owned context, the dup'd fd, the
// socket. It reports the first of the fd/socket close errors, if either
// fails — REV0907-H2: a caller that checks Close's return value now gets a
// real close failure instead of a value that can never be non-nil. Complete
// (REV0907-E7) is one such caller: it records what Close reports here on the
// Report rather than folding it into its own return error, because by the
// time Complete calls Close the handshake-and-traffic criterion under test has
// already been decided.
func (s *Session) Close() error {
	var closeErr error
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
			if err := s.file.Close(); err != nil && closeErr == nil {
				closeErr = fmt.Errorf("tlsprobe: close dup'd socket: %w", err)
			}
		}
		if s.raw != nil {
			if err := s.raw.Close(); err != nil && closeErr == nil {
				closeErr = fmt.Errorf("tlsprobe: close raw connection: %w", err)
			}
		}
	})
	return closeErr
}

// Complete is the whole procedure step in one call: establish a session on the
// pinned suite, carry one SunSpec Model 1 read inside it, close cleanly, and
// report what was negotiated.
//
// It is what a cipher-suite check wants, because the criterion those procedures
// state is "the EUT-S successfully establishes a secure session using each of
// the mandatory cipher suites" (SSM-CONF-v0.8 §2.5.1.3) — a completed session
// carrying real traffic, not a ServerHello. REV0907-E7: that criterion is
// entirely about the handshake and the traffic carried on it, so a Close
// failure discovered AFTER both already succeeded is recorded on the Report
// (CloseErr) and logged, NOT returned as this function's error — returning it
// would let a bench-teardown fact (an fd or socket that failed to close AFTER
// the session was already proven) turn a successful probe into a reported
// failure, which is a false negative on the actual criterion under test. A
// Dial (connect/handshake) failure is unaffected: nothing was established, so
// its error is exactly what a caller must see.
func Complete(ctx context.Context, spec Spec) (*Report, error) {
	s, dialErr := Dial(ctx, spec)
	if dialErr != nil {
		return nil, dialErr
	}
	s.ReadModel1()
	return finishSession(s, spec), nil
}

// finishSession closes s and returns its Report, folding a teardown-only
// failure into Report.CloseErr instead of an error return — see Complete's
// doc comment (REV0907-E7). Split out from Complete so this fold is testable
// on its own, without a live wolfSSL handshake: session_close_cgo_test.go
// builds a Session whose Close is rigged to fail deterministically (the same
// helpers REV0907-H2's tests use) and asserts the failure lands on the Report,
// never in a returned error.
func finishSession(s *Session, spec Spec) *Report {
	report := s.Report()
	if closeErr := s.Close(); closeErr != nil {
		report.CloseErr = closeErr.Error()
		spec.log("tlsprobe: %s <> %s: session established and the criterion under test already evaluated, "+
			"but the teardown failed: %v", s.local, s.remote, closeErr)
	}
	return report
}

// versionFromName maps wolfSSL's own version string onto the wire code, so a
// report can carry both without this package guessing at either.
func versionFromName(name string) Version {
	switch name {
	case "TLSv1.2":
		return TLS12
	case "TLSv1.3":
		return TLS13
	default:
		return 0
	}
}

// suiteFromWolfName resolves the negotiated suite to a mandated one. A miss is
// meaningful: the DUT negotiated something outside the mandated set, and the
// zero Suite is how a caller sees that rather than a plausible-looking match.
func suiteFromWolfName(name string) Suite {
	for _, s := range append(append([]Suite{}, Mandatory13...), Mandatory12...) {
		if s.Wolf == name {
			return s
		}
	}
	return Suite{}
}

func addrPortOf(a net.Addr) (netip.AddrPort, bool) {
	ta, ok := a.(*net.TCPAddr)
	if !ok {
		return netip.AddrPort{}, false
	}
	ip, ok := netip.AddrFromSlice(ta.IP)
	if !ok {
		return netip.AddrPort{}, false
	}
	return netip.AddrPortFrom(ip.Unmap(), uint16(ta.Port)), true
}

// armTimeouts pushes a receive and send timeout onto the socket wolfSSL drives.
func armTimeouts(fd int, d time.Duration) error {
	for _, opt := range []int{syscall.SO_RCVTIMEO, syscall.SO_SNDTIMEO} {
		if err := setSockTimeout(fd, opt, time.Now().Add(d)); err != nil {
			return fmt.Errorf("tlsprobe: arm the socket timeout: %w", err)
		}
	}
	return nil
}

// setSockTimeout maps an absolute deadline onto SO_RCVTIMEO/SO_SNDTIMEO. A zero
// time clears the timeout; a deadline already past arms the smallest non-zero
// interval, because a zero timeval means "no timeout" to the kernel and would
// turn an expired deadline into an indefinite block.
func setSockTimeout(fd, opt int, t time.Time) error {
	var tv syscall.Timeval
	if !t.IsZero() {
		d := time.Until(t)
		if d < time.Microsecond {
			d = time.Microsecond
		}
		tv = syscall.NsecToTimeval(int64(d))
	}
	return syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, opt, &tv)
}
