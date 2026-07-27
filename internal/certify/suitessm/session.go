package suitessm

// session.go establishes real, completing mbaps sessions and drives Modbus
// inside them. Where probe.go proves what the EUT-S SAYS, this file proves what
// it DOES: which role it extracts, which register writes it permits, and what
// its denial responses look like byte for byte.
//
// Three design points that are not obvious:
//
// # 1. The peer is never verified by the library
//
// Every dial sets InsecureSkipVerify and does the X.509 path validation itself
// in VerifyPeerCertificate (analysis.verifyChain). That looks backwards for a
// security tool and is exactly right for a referee: a library that aborts the
// handshake on an untrusted peer destroys the evidence about WHY it was
// untrusted, and turns a reportable conformance observation into a dial error.
// The verification result is recorded on the Session and the check decides.
//
// # 2. Key material is exported on purpose
//
// The run's key log (certify.CaptureRef.KeyLogPath) receives this side's TLS
// secrets, so the capture in the bundle decrypts and the application-layer
// assertions — the MBAP header, the exception code, the nine-byte denial — are
// re-checkable by a third party rather than taken on this tool's word. Only the
// BENCH side's secrets are exported: the DUT never leaks its own, so the device
// under test is the device that ships.
//
// # 3. Modbus framing is shared, Modbus assertions are not
//
// Requests are built with lexa-proto/mbap because the wire format is the wire
// format and a divergent framing codec would produce bugs, not independent
// verification. Every DECISION about a response is made in analysis.go from the
// raw bytes, without mbap.Decode, because "did the DUT emit a conformant seven
// byte header" is not a question to ask a decoder that normalises.

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"sync"
	"time"

	"csip-tls-test/internal/certify"
	"lexa-proto/mbap"
)

// opDeadline bounds one Modbus request/response inside an established session.
// mbap.Client sets no deadlines; the caller owns them, and a wedged DUT must
// not be able to hang the run.
const opDeadline = 8 * time.Second

// connTap is a test seam, and the only one in this package. When set, every
// connection this file opens is wrapped, which lets the package's own tests
// record the exact bytes that crossed a loopback connection and synthesise a
// capture from them — proving the checks end to end through the real runner
// without dumpcap or a NIC. It is nil in every non-test build; see
// certify.Options.Capturer, which is the same idea one layer up.
var connTap func(net.Conn) net.Conn

// keylogMu serialises appends to the run's shared NSS key log. Checks run
// sequentially today, but a key log with interleaved partial lines decrypts
// nothing, and that failure would appear only at analysis time.
var keylogMu sync.Mutex

// dialOpts configures one mbaps session.
type dialOpts struct {
	// Cert is the client identity. A nil Cert presents NO client certificate,
	// which is TLSF-004's provocation; an EmptyCert presents a zero-length
	// Certificate message, which is the same provocation in its other legal
	// encoding.
	Cert *tls.Certificate
	// EmptyCert forces an empty (zero-certificate) Certificate message even
	// when the server asks, rather than omitting the message.
	EmptyCert bool
	// MinVersion / MaxVersion pin the offered TLS version range. Pinning to
	// TLS 1.2 is how a check gets the peer's Certificate and CertificateRequest
	// in the clear on the wire.
	MinVersion, MaxVersion uint16
	// CipherSuites restricts the TLS 1.2 offer. Empty means Go's default.
	CipherSuites []uint16
	// Roots is the trust anchor set this side validates the peer against.
	Roots *x509.CertPool
	// SessionCache enables resumption across dials that share it.
	SessionCache tls.ClientSessionCache
	// ServerName sets SNI; empty sends none.
	ServerName string
	// Wrap interposes on the raw TCP connection before TLS, which is how
	// TLSF-005 corrupts a record after the handshake.
	Wrap func(net.Conn) net.Conn
	// Note is the connection-claim note recorded in the bundle.
	Note string
}

// Session is a live mbaps session plus everything the checks need to describe
// it afterwards.
type Session struct {
	conn net.Conn
	tls  *tls.Conn

	// Local and Remote are captured at dial time; after Close the socket's
	// addresses are gone and the citation phase could not find the stream.
	Local, Remote netip.AddrPort
	// State is the completed handshake's parameters.
	State tls.ConnectionState
	// PeerChain is the DUT's certificate chain exactly as it was sent.
	PeerChain []*x509.Certificate
	// PeerVerifyErr is this side's own path validation result. It does NOT
	// abort the handshake; a check reports it.
	PeerVerifyErr error

	tid uint16
	// closeKeylog releases the run's key-log file. It is held for the whole
	// lifetime of the session, not just the handshake: TLS 1.3 emits further
	// secrets on a KeyUpdate, and a key log closed after the handshake would
	// silently lose them — leaving records in the capture that no reader could
	// decrypt and no assertion could honestly cite.
	closeKeylog func()
}

// Version returns the negotiated TLS version as a wire codepoint.
func (s *Session) Version() uint16 { return s.State.Version }

// Close shuts the session down.
func (s *Session) Close() {
	if s.tls != nil {
		_ = s.tls.Close()
	}
	if s.conn != nil {
		_ = s.conn.Close()
	}
	if s.closeKeylog != nil {
		s.closeKeylog()
		s.closeKeylog = nil
	}
}

// dial opens and claims an mbaps session to target.
//
// The connection is claimed on the check's window immediately after the TCP
// connect and BEFORE the TLS handshake, so a handshake the DUT rejects still
// produces attributable frames. A negative test whose frames were not
// attributed would have no evidence of the refusal it exists to prove.
func dial(ctx context.Context, rc *certify.RunCtx, target string, o dialOpts) (*Session, error) {
	var d net.Dialer
	raw, err := d.DialContext(ctx, "tcp", target)
	if err != nil {
		return nil, fmt.Errorf("suitessm: dial %s: %w", target, err)
	}
	note := o.Note
	if note == "" {
		note = "SSM mbaps session"
	}
	if err := rc.ClaimConn(raw, note); err != nil {
		_ = raw.Close()
		return nil, err
	}
	s := &Session{conn: raw}
	s.Local, _ = addrPortOf(raw.LocalAddr())
	s.Remote, _ = addrPortOf(raw.RemoteAddr())

	layered := raw
	if connTap != nil {
		layered = connTap(layered)
	}
	if o.Wrap != nil {
		layered = o.Wrap(layered)
	}

	cfg, closeKeylog, err := clientConfig(rc, o)
	if err != nil {
		_ = raw.Close()
		return nil, err
	}
	s.closeKeylog = closeKeylog

	cfg.VerifyPeerCertificate = func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		var chain []*x509.Certificate
		for _, der := range rawCerts {
			c, perr := x509.ParseCertificate(der)
			if perr != nil {
				s.PeerVerifyErr = fmt.Errorf("peer certificate %d does not parse: %w", len(chain), perr)
				return nil
			}
			chain = append(chain, c)
		}
		s.PeerChain = chain
		if o.Roots == nil {
			s.PeerVerifyErr = errors.New("no trust anchors were configured for this dial, so the peer was not path-validated")
			return nil
		}
		inter := x509.NewCertPool()
		for _, c := range chain[min(1, len(chain)):] {
			inter.AddCert(c)
		}
		var leaf *x509.Certificate
		if len(chain) > 0 {
			leaf = chain[0]
		}
		s.PeerVerifyErr = verifyChain(leaf, inter, o.Roots)
		// Never abort: the verification outcome is the observation.
		return nil
	}

	tc := tls.Client(layered, cfg)
	hctx, cancel := context.WithTimeout(ctx, opDeadline+4*time.Second)
	defer cancel()
	if err := tc.HandshakeContext(hctx); err != nil {
		_ = raw.Close()
		closeKeylog()
		s.closeKeylog = nil
		return nil, &handshakeError{Session: s, Err: err}
	}
	s.tls = tc
	s.State = tc.ConnectionState()
	return s, nil
}

// handshakeError carries the partially-observed session out of a failed dial.
// A negative test needs the DUT's certificate chain and this side's own
// verification result even when — especially when — the handshake did not
// complete.
type handshakeError struct {
	Session *Session
	Err     error
}

func (e *handshakeError) Error() string { return e.Err.Error() }
func (e *handshakeError) Unwrap() error { return e.Err }

// handshakeFailed reports whether err is a handshake rejection and, if so,
// returns the partial session.
func handshakeFailed(err error) (*Session, bool) {
	var he *handshakeError
	if errors.As(err, &he) {
		return he.Session, true
	}
	return nil, false
}

// clientConfig builds the tls.Config, including key-log export.
func clientConfig(rc *certify.RunCtx, o dialOpts) (*tls.Config, func(), error) {
	cfg := &tls.Config{
		// See the file comment: verification is done by this package so its
		// result can be reported instead of aborting.
		InsecureSkipVerify: true, //nolint:gosec // referee: verify in VerifyPeerCertificate, report the result
		MinVersion:         o.MinVersion,
		MaxVersion:         o.MaxVersion,
		CipherSuites:       o.CipherSuites,
		ClientSessionCache: o.SessionCache,
		ServerName:         o.ServerName,
	}
	if cfg.MinVersion == 0 {
		cfg.MinVersion = tls.VersionTLS12
	}
	switch {
	case o.EmptyCert:
		cfg.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			// An empty Certificate message: the wire shape TLSF-004 provokes.
			return &tls.Certificate{}, nil
		}
	case o.Cert != nil:
		c := *o.Cert
		cfg.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			// Returned unconditionally rather than filtered against the
			// CertificateRequest's acceptable CAs: a negative fixture whose
			// issuer the DUT does not list must still be PRESENTED, or the
			// provocation never reaches the DUT and the test proves nothing.
			return &c, nil
		}
	}

	closeFn := func() {}
	if p := rc.Capture.KeyLogPath; p != "" {
		f, err := os.OpenFile(p, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
		if err != nil {
			return nil, nil, fmt.Errorf("suitessm: open key log %s: %w", p, err)
		}
		cfg.KeyLogWriter = lockedWriter{f}
		closeFn = func() { _ = f.Close() }
	}
	return cfg, closeFn, nil
}

// lockedWriter serialises key-log lines. crypto/tls writes one whole line per
// call, so a mutex around Write is sufficient to keep the file parseable.
type lockedWriter struct{ w io.Writer }

func (l lockedWriter) Write(p []byte) (int, error) {
	keylogMu.Lock()
	defer keylogMu.Unlock()
	return l.w.Write(p)
}

// ── Modbus inside the tunnel ────────────────────────────────────────────────

// Exchange is one request/response pair with the exact bytes preserved. The
// bytes, not a decoded struct, are what the assertions are made from.
type Exchange struct {
	// Label describes the operation in report prose.
	Label string
	// Request and Response are the complete MBAP ADUs as written and read.
	Request, Response []byte
	// Err is a transport failure — the DUT closed, or the read timed out.
	// A Modbus EXCEPTION is not an error: it is a Response.
	Err error
}

// nextTID returns a fresh transaction identifier.
func (s *Session) nextTID() uint16 {
	s.tid++
	if s.tid == 0 {
		s.tid = 1
	}
	return s.tid
}

// request sends one MBAP ADU and reads one back.
func (s *Session) request(unit uint8, pdu []byte, label string) Exchange {
	ex := Exchange{Label: label}
	if s.tls == nil {
		ex.Err = errors.New("suitessm: the session is not established")
		return ex
	}
	adu := mbap.ADU{Header: mbap.Header{TID: s.nextTID(), UnitID: unit}, PDU: pdu}
	raw, err := mbap.Encode(adu)
	if err != nil {
		ex.Err = fmt.Errorf("encode request: %w", err)
		return ex
	}
	ex.Request = raw
	_ = s.tls.SetDeadline(time.Now().Add(opDeadline))
	if _, err := s.tls.Write(raw); err != nil {
		ex.Err = fmt.Errorf("write request: %w", err)
		return ex
	}
	ex.Response, ex.Err = readADU(s.tls)
	return ex
}

// readADU reads exactly one MBAP frame, header first, then Length-1 more bytes.
// It returns the raw bytes rather than a decoded ADU because the assertions are
// about the bytes.
func readADU(r io.Reader) ([]byte, error) {
	hdr := make([]byte, 7)
	if _, err := io.ReadFull(r, hdr); err != nil {
		return nil, fmt.Errorf("read MBAP header: %w", err)
	}
	length := binary.BigEndian.Uint16(hdr[4:6])
	if length < 2 || length > 254 {
		// Return what was read: a malformed Length is itself the finding.
		return hdr, fmt.Errorf("suitessm: MBAP Length field is %d, outside the legal 2..254", length)
	}
	body := make([]byte, int(length)-1)
	if _, err := io.ReadFull(r, body); err != nil {
		return hdr, fmt.Errorf("read %d-byte MBAP body: %w", len(body), err)
	}
	return append(hdr, body...), nil
}

// ReadHolding issues FC 0x03 Read Holding Registers.
func (s *Session) ReadHolding(unit uint8, addr, count uint16, label string) Exchange {
	pdu := []byte{0x03, byte(addr >> 8), byte(addr), byte(count >> 8), byte(count)}
	return s.request(unit, pdu, label)
}

// WriteMultiple issues FC 0x10 Write Multiple Registers.
func (s *Session) WriteMultiple(unit uint8, addr uint16, values []uint16, label string) Exchange {
	body := make([]byte, 0, 6+len(values)*2)
	body = append(body, 0x10, byte(addr>>8), byte(addr), byte(len(values)>>8), byte(len(values)), byte(len(values)*2))
	for _, v := range values {
		body = append(body, byte(v>>8), byte(v))
	}
	return s.request(unit, body, label)
}

// WriteSingle issues FC 0x06 Write Single Register.
func (s *Session) WriteSingle(unit uint8, addr, value uint16, label string) Exchange {
	pdu := []byte{0x06, byte(addr >> 8), byte(addr), byte(value >> 8), byte(value)}
	return s.request(unit, pdu, label)
}

// registers decodes an FC 0x03/0x04 response's register payload, or reports the
// exception. It is used for DISCOVERY, never for a verdict.
func registers(ex Exchange) ([]uint16, error) {
	if ex.Err != nil {
		return nil, ex.Err
	}
	v, err := parseMBAP(ex.Response)
	if err != nil {
		return nil, err
	}
	if len(v.PDU) < 2 {
		return nil, fmt.Errorf("suitessm: response PDU is %d byte(s)", len(v.PDU))
	}
	if v.PDU[0]&0x80 != 0 {
		return nil, fmt.Errorf("suitessm: modbus exception %d (%s)", v.PDU[1], exceptionName(v.PDU[1]))
	}
	n := int(v.PDU[1])
	if len(v.PDU) < 2+n {
		return nil, fmt.Errorf("suitessm: byte count %d exceeds the %d-byte PDU", n, len(v.PDU))
	}
	out := make([]uint16, 0, n/2)
	for i := 2; i+1 < 2+n; i += 2 {
		out = append(out, binary.BigEndian.Uint16(v.PDU[i:i+2]))
	}
	return out, nil
}

// ── SunSpec chain discovery ─────────────────────────────────────────────────

// sunspecBase is the SunSpec Modbus base address the gateway lays its chain out
// at, and the first of the three addresses the SunSpec specification permits.
const sunspecBase uint16 = 40000

// SunSMagic is "SunS" as two big-endian registers.
const (
	sunsMagic0 uint16 = 0x5375
	sunsMagic1 uint16 = 0x6E53
	endMarker  uint16 = 0xFFFF
)

// ModelBlock is one model in a discovered chain.
type ModelBlock struct {
	ID     uint16
	Length uint16 // in registers, excluding the 2-register header
	// Addr is the address of the model's ID register.
	Addr uint16
	// First is the address of the model's first DATA register.
	First uint16
}

// Chain is a discovered SunSpec model chain on one unit.
type Chain struct {
	Unit   uint8
	Models []ModelBlock
}

// Model returns the first block with the given id.
func (c *Chain) Model(id uint16) (ModelBlock, bool) {
	for _, m := range c.Models {
		if m.ID == id {
			return m, true
		}
	}
	return ModelBlock{}, false
}

// IDs lists the discovered model ids.
func (c *Chain) IDs() []uint16 {
	out := make([]uint16, 0, len(c.Models))
	for _, m := range c.Models {
		out = append(out, m.ID)
	}
	return out
}

// discoverChain walks the SunSpec chain on a unit: the "SunS" marker, then
// (id, length) headers until the 0xFFFF end marker.
//
// It is bounded twice — 64 models and a hard address ceiling — because a
// gateway that answers a header read with garbage would otherwise walk this
// loop until the run's timeout, and "the discovery loop hung" is a much worse
// diagnosis than "the chain header at 40122 was 0x1234/0xFFFF".
func discoverChain(s *Session, unit uint8) (*Chain, error) {
	hdr, err := registers(s.ReadHolding(unit, sunspecBase, 2, "SunSpec marker"))
	if err != nil {
		return nil, fmt.Errorf("read the SunSpec marker at %d on unit %d: %w", sunspecBase, unit, err)
	}
	if len(hdr) < 2 || hdr[0] != sunsMagic0 || hdr[1] != sunsMagic1 {
		return nil, fmt.Errorf("suitessm: unit %d has no SunSpec marker at %d (read 0x%04X 0x%04X, want 0x%04X 0x%04X)",
			unit, sunspecBase, hdr[0], hdr[1], sunsMagic0, sunsMagic1)
	}
	ch := &Chain{Unit: unit}
	addr := sunspecBase + 2
	for i := 0; i < 64; i++ {
		mh, err := registers(s.ReadHolding(unit, addr, 2, "model header"))
		if err != nil {
			return ch, fmt.Errorf("read the model header at %d: %w", addr, err)
		}
		if len(mh) < 2 {
			return ch, fmt.Errorf("suitessm: short model header at %d", addr)
		}
		if mh[0] == endMarker {
			return ch, nil
		}
		ch.Models = append(ch.Models, ModelBlock{ID: mh[0], Length: mh[1], Addr: addr, First: addr + 2})
		next := int(addr) + 2 + int(mh[1])
		if next > 0xFFFF || next <= int(addr) {
			return ch, fmt.Errorf("suitessm: model %d at %d declares length %d, which does not advance the chain",
				mh[0], addr, mh[1])
		}
		addr = uint16(next)
	}
	return ch, fmt.Errorf("suitessm: the chain on unit %d did not reach an end marker within 64 models", unit)
}

// readCommonModel is the "read the SunSpec Common Model (Model 1)" step that
// SSM-CONF-v0.8 attaches to almost every positive procedure as its proof that
// the secure channel actually carries Modbus.
//
// It returns the chain it discovered as well, because several procedures need
// to know which models the DUT exposes before they can choose a register to
// write to.
func readCommonModel(rc *certify.RunCtx, s *Session) (uint8, *Chain, Exchange, error) {
	unit, chain, err := findUnit(rc, s)
	if err != nil {
		return 0, nil, Exchange{}, err
	}
	m1, ok := chain.Model(1)
	if !ok {
		return unit, chain, Exchange{}, fmt.Errorf(
			"suitessm: unit %d's chain has no Model 1 (models present: %v); SunSpec requires the Common Model first",
			unit, chain.IDs())
	}
	// Model 1's data block is 66 registers on this DUT, but the chain header is
	// the authority: read exactly what the DUT declared.
	ex := s.ReadHolding(unit, m1.First, m1.Length, "SunSpec Common Model (Model 1) read")
	return unit, chain, ex, nil
}

// findUnit locates a unit id that answers the SunSpec marker read, so the
// checks do not have to be told which of the gateway's 1..246 southbound slots
// is populated. An operator can pin it with -param ssm.unit.
func findUnit(rc *certify.RunCtx, s *Session) (uint8, *Chain, error) {
	if v, ok := rc.Param("ssm.unit"); ok && v != "" {
		var u int
		if _, err := fmt.Sscanf(v, "%d", &u); err != nil || u < 1 || u > 246 {
			return 0, nil, fmt.Errorf("suitessm: -param ssm.unit=%q is not a unit id in 1..246", v)
		}
		ch, err := discoverChain(s, uint8(u))
		return uint8(u), ch, err
	}
	var last error
	for u := uint8(1); u <= 8; u++ {
		ch, err := discoverChain(s, u)
		if err == nil && len(ch.Models) > 0 {
			return u, ch, nil
		}
		last = err
	}
	return 0, nil, fmt.Errorf("suitessm: no SunSpec chain answered on unit ids 1..8 (last: %v) — "+
		"pass -param ssm.unit=<id> if the gateway's populated unit is outside that range", last)
}
