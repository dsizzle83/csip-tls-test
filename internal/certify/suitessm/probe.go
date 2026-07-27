package suitessm

// probe.go is the referee's ability to say things a conformant peer never
// would.
//
// Half of SSM-CONF-v0.8 is negative: offer only NULL-encryption suites, offer
// SHA-1 signature algorithms, offer the mandated suites in reversed preference
// order, offer a curve that is not P-256. No conformant TLS client library will
// emit those ClientHellos — internal/mbtls actively refuses to, and Go's
// crypto/tls has no API for it — because refusing is the correct behaviour for
// a peer whose job is to be conformant. It is the wrong behaviour for a peer
// whose job is to find out what the DUT does when it is provoked.
//
// So a Hello here is built from the RFC 5246 / RFC 8446 field layout directly,
// written to a plain TCP socket, and the server's answer is read back and
// handed to internal/evidence/tlsdis. The probe never completes a handshake: it
// stops at the end of the server's first flight (ServerHelloDone in TLS 1.2, the
// ServerHello in TLS 1.3) or at the first fatal alert. That is deliberate and
// it is the reason the probe is trustworthy — nothing about the server's answer
// depends on this file getting ECDHE arithmetic or the PRF right, only on it
// reading a length-prefixed byte stream correctly.
//
// What a probe can therefore evidence: the negotiated version, the selected
// cipher suite, the ServerHello extensions (max_fragment_length echo,
// renegotiation_info, supported_versions, key_share), the server's certificate
// chain as sent, the CertificateRequest, the ServerKeyExchange named curve, the
// order of the server's flight, and any alert. What it cannot: that a session
// was established. Checks that need the latter use session.go.

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"time"

	"csip-tls-test/internal/certify"
	"csip-tls-test/internal/evidence/tlsdis"
)

// probeDeadline bounds one probe. A DUT that neither answers nor closes must
// not be able to consume the whole run's budget; a check gets a timed-out probe
// back as an observation, not as a hang.
const probeDeadline = 8 * time.Second

// Named cipher suites the procedures reference by hex codepoint. They are
// transcribed from the IANA TLS Cipher Suite Registry and from the SunSpecTCP
// requirement tables quoted in SSM-CONF-v0.8 — not imported from any TLS
// library, so a library that mislabels a codepoint cannot make a wrong
// assertion look right.
const (
	// SunSpecTCP-17, the mandated TLS 1.2 suites in the mandated order.
	suiteECDHE_ECDSA_AES128_GCM_SHA256 uint16 = 0xC02B
	suiteECDHE_ECDSA_CHACHA20_POLY1305 uint16 = 0xCCA9
	suiteECDHE_ECDSA_AES128_CCM_8      uint16 = 0xC0AE

	// SunSpecTCP-18, the mandated TLS 1.3 suites in the mandated order.
	suiteTLS13_AES128_GCM_SHA256       uint16 = 0x1301
	suiteTLS13_CHACHA20_POLY1305_SHA25 uint16 = 0x1303
	suiteTLS13_AES128_CCM_SHA256       uint16 = 0x1304

	// Suites the procedures use as provocations.
	suiteRSA_AES128_CBC_SHA uint16 = 0x002F // CRYP-005: SHA-1 MAC
	// CRYP-007's NULL-encryption codepoints live in analysis.go's
	// nullEncryptionSuites, which is the single transcription of that part of
	// the registry; suiteRSA_NULL_SHA is repeated here only because the tests
	// build a synthetic ServerHello selecting it.
	suiteRSA_NULL_SHA              uint16 = 0x0002
	suiteRSA_3DES_EDE_CBC_SHA      uint16 = 0x000A // CRYP-003: IANA-discouraged
	suiteECDHE_RSA_AES128_CBC_SHA  uint16 = 0xC013
	suiteDHE_RSA_AES128_CBC_SHA256 uint16 = 0x0067
)

// mandated12 and mandated13 are the SunSpecTCP-17/18 orders, as codepoints.
var (
	mandated12 = []uint16{
		suiteECDHE_ECDSA_AES128_GCM_SHA256,
		suiteECDHE_ECDSA_CHACHA20_POLY1305,
		suiteECDHE_ECDSA_AES128_CCM_8,
	}
	mandated13 = []uint16{
		suiteTLS13_AES128_GCM_SHA256,
		suiteTLS13_CHACHA20_POLY1305_SHA25,
		suiteTLS13_AES128_CCM_SHA256,
	}
)

// Named groups and signature schemes the procedures reference.
const (
	groupSecp256r1 uint16 = 0x0017 // CRYP-004: the only mandatory curve
	groupSecp384r1 uint16 = 0x0018
	groupX25519    uint16 = 0x001D

	sigECDSAP256SHA256 uint16 = 0x0403
	sigECDSASHA1       uint16 = 0x0203 // CRYP-005 provocation: (sha1, ecdsa)
	sigRSAMD5          uint16 = 0x0101 // CRYP-005 provocation: (md5, rsa)
	sigRSAPSSSHA256    uint16 = 0x0804
	sigRSAPKCS1SHA256  uint16 = 0x0401
)

// mflCode512 is the RFC 6066 max_fragment_length code for 2^9 = 512 bytes,
// which SunSpecTCP-60 makes mandatory.
const mflCode512 uint8 = 1

// Hello is a ClientHello to be built byte for byte.
//
// Zero values mean "omit": an empty Groups slice sends no supported_groups
// extension at all, which is a materially different provocation from sending
// one that lists a curve the server does not have. Every field that has a
// sensible conformant default is filled in by conformantHello.
type Hello struct {
	// LegacyVersion is the ClientHello.legacy_version field. TLSF-001 requires
	// 0x0303 with NO supported_versions extension; TLSF-002 requires 0x0303
	// WITH one carrying 0x0304.
	LegacyVersion uint16
	// SupportedVersions, when non-empty, adds the RFC 8446 extension.
	SupportedVersions []uint16
	// Suites is the cipher_suites list, in the exact order it will appear.
	Suites []uint16
	// Compression is legacy_compression_methods. PROT-003 asserts that a
	// conformant peer offers only NULL (0x00); a probe can offer more.
	Compression []uint8
	// SessionID is legacy_session_id — non-empty drives the PKI-006 / TLSF-005
	// resumption attempts.
	SessionID []byte

	Groups       []uint16 // supported_groups (0x000A)
	PointFormats []uint8  // ec_point_formats (0x000B)
	SigAlgs      []uint16 // signature_algorithms (0x000D)

	// MaxFragmentLength, when set, adds the RFC 6066 extension (PROT-002).
	MaxFragmentLength *uint8
	// RenegotiationInfo adds the RFC 5746 empty extension (PROT-004).
	RenegotiationInfo bool
	// SessionTicket adds the RFC 5077 empty extension.
	SessionTicket bool
	// ExtendedMasterSecret adds RFC 7627's empty extension.
	ExtendedMasterSecret bool
	// ServerName, when set, adds the RFC 6066 SNI extension.
	ServerName string
	// KeyShareGroups, for TLS 1.3, generates a real ECDH share per group so the
	// server answers with a ServerHello rather than a HelloRetryRequest.
	KeyShareGroups []uint16
	// PSKModes adds psk_key_exchange_modes, which RFC 8446 requires alongside
	// a pre_shared_key and which servers expect on a 1.3 hello.
	PSKModes []uint8
}

// conformantHello is the baseline every probe starts from: a TLS 1.2 hello
// carrying the SunSpecTCP-17 suites in the mandated order, P-256 in
// supported_groups, the uncompressed point format, ECDSA-P256-SHA256 signature
// algorithms, NULL compression only, and the RFC 5746 renegotiation indication.
// Checks mutate one thing at a time from here, so a rejection is attributable
// to the one thing that changed.
func conformantHello() Hello {
	return Hello{
		LegacyVersion:        tlsdis.VersionTLS12,
		Suites:               append([]uint16(nil), mandated12...),
		Compression:          []uint8{0},
		Groups:               []uint16{groupSecp256r1},
		PointFormats:         []uint8{0},
		SigAlgs:              []uint16{sigECDSAP256SHA256, sigRSAPSSSHA256, sigRSAPKCS1SHA256},
		RenegotiationInfo:    true,
		ExtendedMasterSecret: true,
	}
}

// conformantHello13 is the TLS 1.3 baseline: legacy_version 0x0303 plus
// supported_versions 0x0304, the SunSpecTCP-18 suites, and a real P-256 key
// share so the exchange reaches a ServerHello in one round trip.
func conformantHello13() Hello {
	h := conformantHello()
	h.SupportedVersions = []uint16{tlsdis.VersionTLS13}
	h.Suites = append([]uint16(nil), mandated13...)
	h.KeyShareGroups = []uint16{groupSecp256r1}
	h.PSKModes = []uint8{1} // psk_dhe_ke
	return h
}

// Marshal renders the hello as a complete TLS handshake record.
func (h Hello) Marshal() ([]byte, error) {
	body := make([]byte, 0, 512)
	body = be16(body, h.LegacyVersion)

	var random [32]byte
	if _, err := rand.Read(random[:]); err != nil {
		return nil, fmt.Errorf("suitessm: client random: %w", err)
	}
	body = append(body, random[:]...)

	if len(h.SessionID) > 32 {
		return nil, fmt.Errorf("suitessm: legacy_session_id is %d bytes, the maximum is 32", len(h.SessionID))
	}
	body = append(body, uint8(len(h.SessionID)))
	body = append(body, h.SessionID...)

	if len(h.Suites) == 0 {
		return nil, errors.New("suitessm: a ClientHello with no cipher suites is not a probe, it is a bug")
	}
	body = be16(body, uint16(len(h.Suites)*2))
	for _, s := range h.Suites {
		body = be16(body, s)
	}

	comp := h.Compression
	if len(comp) == 0 {
		comp = []uint8{0}
	}
	body = append(body, uint8(len(comp)))
	body = append(body, comp...)

	exts, err := h.extensions()
	if err != nil {
		return nil, err
	}
	body = be16(body, uint16(len(exts)))
	body = append(body, exts...)

	msg := make([]byte, 0, len(body)+4)
	msg = append(msg, byte(tlsdis.HandshakeClientHello))
	msg = append(msg, byte(len(body)>>16), byte(len(body)>>8), byte(len(body)))
	msg = append(msg, body...)

	rec := make([]byte, 0, len(msg)+5)
	rec = append(rec, byte(tlsdis.ContentHandshake))
	// Record-layer version 0x0301 on the first flight is what every deployed
	// client sends for maximum middlebox compatibility (RFC 8446 appendix D.4);
	// the negotiated version comes from the body, not from here.
	rec = be16(rec, tlsdis.VersionTLS10)
	rec = be16(rec, uint16(len(msg)))
	rec = append(rec, msg...)
	return rec, nil
}

func (h Hello) extensions() ([]byte, error) {
	var out []byte
	add := func(t uint16, data []byte) {
		out = be16(out, t)
		out = be16(out, uint16(len(data)))
		out = append(out, data...)
	}

	if h.ServerName != "" {
		name := []byte(h.ServerName)
		var d []byte
		d = be16(d, uint16(len(name)+3))
		d = append(d, 0) // host_name
		d = be16(d, uint16(len(name)))
		d = append(d, name...)
		add(tlsdis.ExtServerName, d)
	}
	if h.MaxFragmentLength != nil {
		add(tlsdis.ExtMaxFragmentLength, []byte{*h.MaxFragmentLength})
	}
	if len(h.Groups) > 0 {
		var d []byte
		d = be16(d, uint16(len(h.Groups)*2))
		for _, g := range h.Groups {
			d = be16(d, g)
		}
		add(tlsdis.ExtSupportedGroups, d)
	}
	if len(h.PointFormats) > 0 {
		d := append([]byte{uint8(len(h.PointFormats))}, h.PointFormats...)
		add(tlsdis.ExtECPointFormats, d)
	}
	if len(h.SigAlgs) > 0 {
		var d []byte
		d = be16(d, uint16(len(h.SigAlgs)*2))
		for _, s := range h.SigAlgs {
			d = be16(d, s)
		}
		add(tlsdis.ExtSignatureAlgorithms, d)
	}
	if h.ExtendedMasterSecret {
		add(23, nil)
	}
	if h.SessionTicket {
		add(tlsdis.ExtSessionTicket, nil)
	}
	if len(h.SupportedVersions) > 0 {
		d := []byte{uint8(len(h.SupportedVersions) * 2)}
		for _, v := range h.SupportedVersions {
			d = be16(d, v)
		}
		add(tlsdis.ExtSupportedVersions, d)
	}
	if len(h.PSKModes) > 0 {
		d := append([]byte{uint8(len(h.PSKModes))}, h.PSKModes...)
		add(tlsdis.ExtPSKKeyExchangeModes, d)
	}
	if len(h.KeyShareGroups) > 0 {
		var entries []byte
		for _, g := range h.KeyShareGroups {
			pub, err := ephemeralShare(g)
			if err != nil {
				return nil, err
			}
			entries = be16(entries, g)
			entries = be16(entries, uint16(len(pub)))
			entries = append(entries, pub...)
		}
		var d []byte
		d = be16(d, uint16(len(entries)))
		d = append(d, entries...)
		add(tlsdis.ExtKeyShare, d)
	}
	if h.RenegotiationInfo {
		// RFC 5746: an initial handshake carries an EMPTY renegotiated_connection.
		add(tlsdis.ExtRenegotiationInfo, []byte{0})
	}
	return out, nil
}

// ephemeralShare produces a throwaway public key for a TLS 1.3 key_share. The
// private half is discarded: the probe never derives a shared secret, it only
// needs the server to accept the group and answer.
func ephemeralShare(group uint16) ([]byte, error) {
	var curve ecdh.Curve
	switch group {
	case groupSecp256r1:
		curve = ecdh.P256()
	case groupSecp384r1:
		curve = ecdh.P384()
	case groupX25519:
		curve = ecdh.X25519()
	default:
		return nil, fmt.Errorf("suitessm: no key share generator for group 0x%04x", group)
	}
	k, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("suitessm: generate key share for group 0x%04x: %w", group, err)
	}
	return k.PublicKey().Bytes(), nil
}

func be16(b []byte, v uint16) []byte { return binary.BigEndian.AppendUint16(b, v) }

// ProbeResult is what one raw probe observed, parsed from the bytes the peer
// actually sent. It is the LIVE view; the citation phase re-derives the same
// facts from the capture, and a disagreement between the two is reported.
type ProbeResult struct {
	// Label names the iteration in reports ("iteration 1: GCM only").
	Label string
	// Local and Remote are the 4-tuple halves, captured before Close so the
	// citation phase can find this probe's stream in the capture.
	Local, Remote netip.AddrPort

	// Sent is the ClientHello record as written, byte for byte.
	Sent []byte
	// Received is everything the peer sent back before the flight ended.
	Received []byte

	// Server is the parsed server direction. Never nil after a successful
	// Probe, even when the peer only sent an alert.
	Server *tlsdis.Direction
	// ParseErr records a record-layer or handshake parse failure, which for a
	// conformance run is itself a finding rather than a reason to give up.
	ParseErr error

	// ConnectErr is set when the TCP connection could not be made at all.
	ConnectErr error
	// ReadErr is set when the peer closed or timed out before the flight ended;
	// a fatal alert followed by a close is the EXPECTED outcome of every
	// negative probe, so this is an observation, not necessarily a failure.
	ReadErr error
	// Elapsed is how long the exchange took.
	Elapsed time.Duration
}

// ServerHello returns the parsed ServerHello, if the peer sent one.
func (p *ProbeResult) ServerHello() *tlsdis.ServerHello {
	m, ok := p.find(tlsdis.HandshakeServerHello)
	if !ok {
		return nil
	}
	return m.ServerHello
}

// Certificate returns the server's Certificate message, if it sent one in the
// clear (TLS 1.2 always; TLS 1.3 never).
func (p *ProbeResult) Certificate() *tlsdis.Certificate {
	m, ok := p.find(tlsdis.HandshakeCertificate)
	if !ok {
		return nil
	}
	return m.Certificate
}

// CertificateRequest returns the server's CertificateRequest, if sent in the clear.
func (p *ProbeResult) CertificateRequest() *tlsdis.CertificateRequest {
	m, ok := p.find(tlsdis.HandshakeCertificateRequest)
	if !ok {
		return nil
	}
	return m.CertificateRequest
}

// ServerKeyExchange returns the raw ServerKeyExchange body, whose first four
// bytes carry curve_type and named_curve for an ECDHE suite (RFC 4492 §5.4).
func (p *ProbeResult) ServerKeyExchange() []byte {
	m, ok := p.find(tlsdis.HandshakeServerKeyExchange)
	if !ok {
		return nil
	}
	return m.Body
}

// Flight is the ordered list of handshake message types the server sent in the
// clear, which TLSF-006 asserts on directly.
func (p *ProbeResult) Flight() []tlsdis.HandshakeType {
	if p.Server == nil || p.Server.Handshake == nil {
		return nil
	}
	return p.Server.Handshake.Types()
}

// FatalAlert returns the first fatal alert the server sent.
func (p *ProbeResult) FatalAlert() (tlsdis.Alert, bool) {
	if p.Server == nil {
		return tlsdis.Alert{}, false
	}
	return p.Server.FatalAlert()
}

// Alerts returns every alert RECORD the server sent, fatal or not — including
// the ones sent after a ChangeCipherSpec, whose bodies are ciphertext and whose
// Level and Description are therefore zero. Use PlainAlerts to report codepoints.
func (p *ProbeResult) Alerts() []tlsdis.Alert {
	if p.Server == nil {
		return nil
	}
	return p.Server.Alerts
}

// PlainAlerts returns the alerts whose level and description were readable.
func (p *ProbeResult) PlainAlerts() []tlsdis.Alert {
	if p.Server == nil {
		return nil
	}
	return p.Server.PlainAlerts()
}

func (p *ProbeResult) find(t tlsdis.HandshakeType) (tlsdis.HandshakeMessage, bool) {
	if p.Server == nil || p.Server.Handshake == nil {
		return tlsdis.HandshakeMessage{}, false
	}
	return p.Server.Handshake.Find(t)
}

// Summary is a one-line description for a report row.
func (p *ProbeResult) Summary() string {
	switch {
	case p.ConnectErr != nil:
		return "TCP connect failed: " + p.ConnectErr.Error()
	case p.ServerHello() != nil:
		sh := p.ServerHello()
		s := fmt.Sprintf("ServerHello version %s, cipher 0x%04X %s",
			tlsdis.VersionName(sh.NegotiatedVersion()), sh.CipherSuite,
			tlsdis.CipherSuiteName(sh.CipherSuite))
		if a, ok := p.FatalAlert(); ok {
			s += fmt.Sprintf("; then fatal alert %d (%s)", a.Description,
				tlsdis.AlertDescriptionName(a.Description))
		}
		return s
	case len(p.PlainAlerts()) > 0:
		a := p.PlainAlerts()[0]
		return fmt.Sprintf("no ServerHello; alert level %d description %d (%s)",
			a.Level, a.Description, tlsdis.AlertDescriptionName(a.Description))
	case len(p.Alerts()) > 0:
		return fmt.Sprintf("no ServerHello; %d encrypted alert record(s), whose level and description "+
			"this probe cannot read", len(p.Alerts()))
	case len(p.Received) == 0:
		return fmt.Sprintf("the peer sent nothing and the connection ended: %v", p.ReadErr)
	default:
		return fmt.Sprintf("%d bytes received, no ServerHello and no alert (parse: %v)",
			len(p.Received), p.ParseErr)
	}
}

// Probe dials target, sends the hello, reads the server's first flight, and
// parses it. It always returns a non-nil result: a refused connection is an
// observation the caller must be able to report.
//
// The connection is claimed on the check's window before a single byte is
// written, so the frames the hello causes are attributable even if the peer
// resets immediately.
func Probe(ctx context.Context, rc *certify.RunCtx, target, label string, h Hello) *ProbeResult {
	res := &ProbeResult{Label: label}
	started := time.Now()
	defer func() { res.Elapsed = time.Since(started) }()

	hello, err := h.Marshal()
	if err != nil {
		res.ConnectErr = err
		return res
	}
	res.Sent = hello

	conn, err := rc.DialTCP(ctx, target, "SSM probe: "+label)
	if err != nil {
		res.ConnectErr = err
		return res
	}
	defer func() { _ = conn.Close() }()
	res.Local, _ = addrPortOf(conn.LocalAddr())
	res.Remote, _ = addrPortOf(conn.RemoteAddr())

	deadline := time.Now().Add(probeDeadline)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	_ = conn.SetDeadline(deadline)

	// connTap is nil outside this package's own tests; see session.go.
	rw := conn
	if connTap != nil {
		rw = connTap(conn)
	}
	if _, err := rw.Write(hello); err != nil {
		res.ReadErr = fmt.Errorf("write ClientHello: %w", err)
		return res
	}
	res.Received, res.ReadErr = readFlight(rw)
	res.Server, res.ParseErr = tlsdis.ParseDirection(res.Received, nil)
	return res
}

// readFlight reads until the server's first flight is complete: a
// ServerHelloDone (TLS 1.2), a ServerHello that negotiated TLS 1.3 followed by
// at least one encrypted record, a fatal alert, or the peer closing.
//
// Reading "until the flight ends" rather than "for N milliseconds" matters:
// a fixed sleep either truncates a chain that spans several segments — turning
// a conformant server into a parse error — or adds seconds to every one of the
// suite's forty-odd probes.
func readFlight(conn net.Conn) ([]byte, error) {
	buf := make([]byte, 8192)
	var acc []byte
	for {
		n, err := conn.Read(buf)
		if n > 0 {
			acc = append(acc, buf[:n]...)
			if flightComplete(acc) {
				return acc, nil
			}
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				return acc, nil
			}
			return acc, err
		}
	}
}

// flightComplete reports whether the bytes so far end the server's first flight.
func flightComplete(acc []byte) bool {
	d, err := tlsdis.ParseDirection(acc, nil)
	if err != nil || d == nil {
		return false
	}
	if _, fatal := d.FatalAlert(); fatal {
		return true
	}
	if d.Handshake == nil {
		return false
	}
	for _, t := range d.Handshake.Types() {
		if t == tlsdis.HandshakeServerHelloDone {
			return true
		}
	}
	if sh, ok := d.Handshake.Find(tlsdis.HandshakeServerHello); ok && sh.ServerHello != nil {
		if sh.ServerHello.NegotiatedVersion() == tlsdis.VersionTLS13 &&
			(len(d.CCS) > 0 || len(d.AppData) > 0) {
			// TLS 1.3: everything after the ServerHello is encrypted, so the
			// plaintext flight is over as soon as an opaque record appears.
			return true
		}
	}
	return false
}

func addrPortOf(a net.Addr) (netip.AddrPort, error) {
	if a == nil {
		return netip.AddrPort{}, errors.New("suitessm: nil address")
	}
	ap, err := netip.ParseAddrPort(a.String())
	if err != nil {
		return netip.AddrPort{}, err
	}
	return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port()), nil
}
