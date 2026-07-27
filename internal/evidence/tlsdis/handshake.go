package tlsdis

import (
	"bytes"
	"fmt"
)

// HandshakeType is the handshake message type byte.
type HandshakeType uint8

// Handshake message types (RFC 5246 §7.4, RFC 8446 §4).
const (
	HandshakeHelloRequest        HandshakeType = 0
	HandshakeClientHello         HandshakeType = 1
	HandshakeServerHello         HandshakeType = 2
	HandshakeNewSessionTicket    HandshakeType = 4
	HandshakeEndOfEarlyData      HandshakeType = 5
	HandshakeEncryptedExtensions HandshakeType = 8
	HandshakeCertificate         HandshakeType = 11
	HandshakeServerKeyExchange   HandshakeType = 12
	HandshakeCertificateRequest  HandshakeType = 13
	HandshakeServerHelloDone     HandshakeType = 14
	HandshakeCertificateVerify   HandshakeType = 15
	HandshakeClientKeyExchange   HandshakeType = 16
	HandshakeFinished            HandshakeType = 20
	HandshakeKeyUpdate           HandshakeType = 24
	HandshakeMessageHash         HandshakeType = 254
)

// MaxHandshakeMessage bounds one handshake message. The wire format allows
// 2^24-1; nothing legitimate comes within two orders of magnitude of this, and
// a smaller ceiling keeps a corrupt length from making the verifier wait for
// sixteen megabytes that will never arrive.
const MaxHandshakeMessage = 1 << 20

// helloRetryRequestRandom is the fixed ServerHello.random that marks a
// HelloRetryRequest (RFC 8446 §4.1.3). TLS 1.3 has no separate message type
// for it: the same ServerHello structure carries this exact random instead.
var helloRetryRequestRandom = [32]byte{
	0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11, 0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
	0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E, 0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C,
}

// Fragment is one piece of a handshake byte stream as carried by one record.
//
// Fragments come from two places: the plaintext records of a direction
// (Direction.HandshakeFragments) and the decrypted inner-type-22 payloads that
// tlsdecrypt produces for TLS 1.3. Both feed the same parser, which is the
// point — the coalescing rule is identical whether or not the bytes were
// encrypted on the wire.
type Fragment struct {
	Data    []byte
	Record  int   // record index within the direction, -1 if synthetic
	Packets []int // capture frames carrying this fragment
}

// Options tunes version-dependent parsing.
type Options struct {
	// TLS13 forces the TLS 1.3 layout for the messages whose structure changed
	// (Certificate, CertificateRequest, NewSessionTicket). When false the
	// parser auto-detects, which is what the plaintext path needs: it has not
	// necessarily seen the ServerHello that settles the version.
	TLS13 bool
}

// HandshakeMessage is one parsed handshake message plus its provenance.
type HandshakeMessage struct {
	Type    HandshakeType
	Offset  int    // offset in the coalesced handshake stream
	Length  int    // body length from the wire header
	Raw     []byte // header + body, as fed to the transcript hash
	Body    []byte
	Records []int // record indices the message spans, ascending
	Packets []int // capture frames the message spans, ascending

	ClientHello        *ClientHello
	ServerHello        *ServerHello
	Certificate        *Certificate
	CertificateRequest *CertificateRequest
	NewSessionTicket   *NewSessionTicket
	KeyUpdate          *KeyUpdate

	// ParseError records a body that did not decode. The message is still
	// reported — "the DUT sent a malformed ClientHello in frame 12" is evidence,
	// and discarding it would be the worst possible reaction.
	ParseError string
}

func (m HandshakeMessage) String() string {
	return fmt.Sprintf("%s (%d bytes) frames=%v", HandshakeTypeName(m.Type), m.Length, m.Packets)
}

// HandshakeStream is the coalesced handshake byte stream of one direction.
type HandshakeStream struct {
	Messages []HandshakeMessage
	Buffer   []byte // the coalesced bytes, for transcript work
	// Truncated is set when the buffer ends inside a message; Need says by how
	// many bytes. This is the honest answer for a capture that stopped mid-
	// handshake, and it is NOT an error: the messages before it are still
	// evidence.
	Truncated bool
	Need      int
	Errors    []string

	spans []hsSpan
}

// hsSpan maps a range of the coalesced buffer back to the record it came from.
type hsSpan struct {
	start   int
	end     int
	record  int
	packets []int
}

// Find returns the first message of the given type.
func (h *HandshakeStream) Find(t HandshakeType) (HandshakeMessage, bool) {
	for _, m := range h.Messages {
		if m.Type == t {
			return m, true
		}
	}
	return HandshakeMessage{}, false
}

// Types lists the message types in order — the shape a conformance assertion
// checks when it claims "the server sent CertificateRequest before
// ServerHelloDone".
func (h *HandshakeStream) Types() []HandshakeType {
	out := make([]HandshakeType, len(h.Messages))
	for i, m := range h.Messages {
		out[i] = m.Type
	}
	return out
}

// ParseHandshake coalesces fragments into one byte stream and parses the
// messages out of THAT stream. See Direction.HandshakeFragments for why this
// order is not negotiable.
//
// The returned error is non-nil only for a structurally impossible stream (a
// message length past MaxHandshakeMessage). A truncated tail, or a body that
// fails to decode, is reported in the returned HandshakeStream instead, because
// both are things a real capture legitimately contains.
func ParseHandshake(frags []Fragment, opt Options) (*HandshakeStream, error) {
	h := &HandshakeStream{}
	for _, f := range frags {
		if len(f.Data) == 0 {
			continue
		}
		start := len(h.Buffer)
		h.Buffer = append(h.Buffer, f.Data...)
		h.spans = append(h.spans, hsSpan{start: start, end: len(h.Buffer), record: f.Record, packets: f.Packets})
	}

	off := 0
	for {
		if len(h.Buffer)-off < 4 {
			if len(h.Buffer)-off > 0 {
				h.Truncated = true
				h.Need = 4 - (len(h.Buffer) - off)
			}
			return h, nil
		}
		typ := HandshakeType(h.Buffer[off])
		length := int(h.Buffer[off+1])<<16 | int(h.Buffer[off+2])<<8 | int(h.Buffer[off+3])
		if length > MaxHandshakeMessage {
			err := fmt.Errorf("tlsdis: handshake message %s at offset %d declares %d bytes, over the %d-byte ceiling",
				HandshakeTypeName(typ), off, length, MaxHandshakeMessage)
			h.Errors = append(h.Errors, err.Error())
			return h, err
		}
		if len(h.Buffer)-off-4 < length {
			h.Truncated = true
			h.Need = 4 + length - (len(h.Buffer) - off)
			return h, nil
		}

		msg := HandshakeMessage{
			Type:   typ,
			Offset: off,
			Length: length,
			Raw:    h.Buffer[off : off+4+length],
			Body:   h.Buffer[off+4 : off+4+length],
		}
		msg.Records, msg.Packets = h.provenance(off, off+4+length)
		if err := parseBody(&msg, opt); err != nil {
			msg.ParseError = err.Error()
			h.Errors = append(h.Errors, fmt.Sprintf("%s at offset %d: %v", HandshakeTypeName(typ), off, err))
		}
		h.Messages = append(h.Messages, msg)
		off += 4 + length
	}
}

// provenance returns the record indices and capture frames covering the
// coalesced range [start,end).
func (h *HandshakeStream) provenance(start, end int) (records, packets []int) {
	seenRec := map[int]bool{}
	seenPkt := map[int]bool{}
	for _, s := range h.spans {
		if s.end <= start || s.start >= end {
			continue
		}
		if s.record >= 0 && !seenRec[s.record] {
			seenRec[s.record] = true
			records = append(records, s.record)
		}
		for _, p := range s.packets {
			if !seenPkt[p] {
				seenPkt[p] = true
				packets = append(packets, p)
			}
		}
	}
	return records, packets
}

func parseBody(m *HandshakeMessage, opt Options) error {
	switch m.Type {
	case HandshakeClientHello:
		ch, err := parseClientHello(m.Body)
		m.ClientHello = ch
		return err
	case HandshakeServerHello:
		sh, err := parseServerHello(m.Body)
		m.ServerHello = sh
		return err
	case HandshakeCertificate:
		c, err := parseCertificate(m.Body, opt)
		m.Certificate = c
		return err
	case HandshakeCertificateRequest:
		cr, err := parseCertificateRequest(m.Body, opt)
		m.CertificateRequest = cr
		return err
	case HandshakeNewSessionTicket:
		t, err := parseNewSessionTicket(m.Body, opt)
		m.NewSessionTicket = t
		return err
	case HandshakeKeyUpdate:
		if len(m.Body) != 1 {
			return fmt.Errorf("tlsdis: key_update body is %d bytes, want 1", len(m.Body))
		}
		m.KeyUpdate = &KeyUpdate{RequestUpdate: m.Body[0]}
		return nil
	case HandshakeServerHelloDone:
		if len(m.Body) != 0 {
			return fmt.Errorf("tlsdis: server_hello_done body is %d bytes, want 0", len(m.Body))
		}
		return nil
	case HandshakeEncryptedExtensions:
		c := newCursor(m.Body)
		_ = parseExtensions(c.vector16("encrypted_extensions"))
		return c.err
	}
	return nil
}

// ClientHello is a parsed ClientHello with its extensions decoded.
type ClientHello struct {
	LegacyVersion      uint16
	Random             [32]byte
	SessionID          []byte
	CipherSuites       []uint16
	CompressionMethods []uint8
	Extensions         []Extension

	// Decoded extensions. A nil slice/pointer means the extension was absent,
	// which several conformance rows assert directly (SunSpecTCP-43/44/59/62).
	SupportedVersions    []uint16
	SupportedGroups      []uint16
	ECPointFormats       []uint8
	SignatureAlgorithms  []uint16
	MaxFragmentLength    *uint8
	RenegotiationInfo    []byte
	HasRenegotiationInfo bool
	SessionTicket        []byte
	HasSessionTicket     bool
	ServerNames          []string
	ALPN                 []string
	KeyShares            []KeyShare
	PSKKeyExchangeModes  []uint8
}

// Extension returns the raw bytes of an extension by type.
func (ch *ClientHello) Extension(t uint16) ([]byte, bool) { return findExtension(ch.Extensions, t) }

// OffersSuite reports whether the ClientHello listed a cipher suite.
func (ch *ClientHello) OffersSuite(id uint16) bool {
	for _, s := range ch.CipherSuites {
		if s == id {
			return true
		}
	}
	return false
}

// MaxVersion returns the highest version offered, honouring supported_versions
// over the legacy field — the ordering RFC 8446 §4.2.1 mandates.
func (ch *ClientHello) MaxVersion() uint16 {
	best := ch.LegacyVersion
	for _, v := range ch.SupportedVersions {
		if IsGREASE(v) {
			continue
		}
		if v > best {
			best = v
		}
	}
	return best
}

func parseClientHello(body []byte) (*ClientHello, error) {
	c := newCursor(body)
	ch := &ClientHello{}
	ch.LegacyVersion = c.u16("client_hello.legacy_version")
	copy(ch.Random[:], c.take(32, "client_hello.random"))
	ch.SessionID = c.vector8("client_hello.session_id")
	ch.CipherSuites = c.u16List("client_hello.cipher_suites")
	ch.CompressionMethods = c.vector8("client_hello.compression_methods")
	if !c.empty() {
		ch.Extensions = parseExtensionsCursor(c, "client_hello.extensions")
	}
	if c.err != nil {
		return ch, c.err
	}
	if len(ch.CipherSuites) == 0 {
		return ch, fmt.Errorf("tlsdis: client_hello offers no cipher suites")
	}
	if len(ch.CompressionMethods) == 0 {
		return ch, fmt.Errorf("tlsdis: client_hello offers no compression methods")
	}
	decodeClientExtensions(ch)
	return ch, nil
}

func decodeClientExtensions(ch *ClientHello) {
	for _, e := range ch.Extensions {
		c := newCursor(e.Data)
		switch e.Type {
		case ExtSupportedVersions:
			// In a ClientHello this is a list behind a ONE-byte length; in a
			// ServerHello it is a bare u16. Getting this backwards is the
			// classic supported_versions bug.
			body := c.vector8("supported_versions")
			for i := 0; i+1 < len(body); i += 2 {
				ch.SupportedVersions = append(ch.SupportedVersions, uint16(body[i])<<8|uint16(body[i+1]))
			}
		case ExtSupportedGroups:
			ch.SupportedGroups = c.u16List("supported_groups")
		case ExtECPointFormats:
			ch.ECPointFormats = c.vector8("ec_point_formats")
		case ExtSignatureAlgorithms:
			ch.SignatureAlgorithms = c.u16List("signature_algorithms")
		case ExtMaxFragmentLength:
			if len(e.Data) == 1 {
				v := e.Data[0]
				ch.MaxFragmentLength = &v
			}
		case ExtRenegotiationInfo:
			ch.HasRenegotiationInfo = true
			ch.RenegotiationInfo = c.vector8("renegotiation_info")
		case ExtSessionTicket:
			ch.HasSessionTicket = true
			ch.SessionTicket = e.Data
		case ExtServerName:
			ch.ServerNames = parseServerNameList(e.Data)
		case ExtALPN:
			ch.ALPN = parseALPN(e.Data)
		case ExtKeyShare:
			ch.KeyShares = parseClientKeyShares(e.Data)
		case ExtPSKKeyExchangeModes:
			ch.PSKKeyExchangeModes = c.vector8("psk_key_exchange_modes")
		}
	}
}

// ServerHello is a parsed ServerHello.
type ServerHello struct {
	LegacyVersion     uint16
	Random            [32]byte
	SessionID         []byte
	CipherSuite       uint16
	CompressionMethod uint8
	Extensions        []Extension

	// SupportedVersion is the TLS 1.3 override: when present it, not
	// LegacyVersion, is the negotiated version (RFC 8446 §4.2.1). Zero means
	// the extension was absent.
	SupportedVersion uint16
	KeyShareGroup    uint16
	HasKeyShare      bool
	// IsHelloRetryRequest is set when Random equals the fixed HRR value.
	IsHelloRetryRequest  bool
	RenegotiationInfo    []byte
	HasRenegotiationInfo bool
	HasSessionTicket     bool
	MaxFragmentLength    *uint8
	ECPointFormats       []uint8
	ALPN                 []string
}

// NegotiatedVersion returns the version actually in force.
func (sh *ServerHello) NegotiatedVersion() uint16 {
	if sh.SupportedVersion != 0 {
		return sh.SupportedVersion
	}
	return sh.LegacyVersion
}

// Extension returns the raw bytes of an extension by type.
func (sh *ServerHello) Extension(t uint16) ([]byte, bool) { return findExtension(sh.Extensions, t) }

func parseServerHello(body []byte) (*ServerHello, error) {
	c := newCursor(body)
	sh := &ServerHello{}
	sh.LegacyVersion = c.u16("server_hello.legacy_version")
	copy(sh.Random[:], c.take(32, "server_hello.random"))
	sh.SessionID = c.vector8("server_hello.session_id")
	sh.CipherSuite = c.u16("server_hello.cipher_suite")
	sh.CompressionMethod = c.u8("server_hello.compression_method")
	if !c.empty() {
		sh.Extensions = parseExtensionsCursor(c, "server_hello.extensions")
	}
	if c.err != nil {
		return sh, c.err
	}
	sh.IsHelloRetryRequest = bytes.Equal(sh.Random[:], helloRetryRequestRandom[:])
	for _, e := range sh.Extensions {
		ec := newCursor(e.Data)
		switch e.Type {
		case ExtSupportedVersions:
			sh.SupportedVersion = ec.u16("supported_versions")
		case ExtKeyShare:
			sh.HasKeyShare = true
			sh.KeyShareGroup = ec.u16("key_share.group")
		case ExtRenegotiationInfo:
			sh.HasRenegotiationInfo = true
			sh.RenegotiationInfo = ec.vector8("renegotiation_info")
		case ExtSessionTicket:
			sh.HasSessionTicket = true
		case ExtMaxFragmentLength:
			if len(e.Data) == 1 {
				v := e.Data[0]
				sh.MaxFragmentLength = &v
			}
		case ExtECPointFormats:
			sh.ECPointFormats = ec.vector8("ec_point_formats")
		case ExtALPN:
			sh.ALPN = parseALPN(e.Data)
		}
	}
	return sh, nil
}

// Certificate is a parsed Certificate message: the chain as it was sent, in
// order, with each entry's DER preserved byte-for-byte.
//
// Byte-exact DER is a hard requirement, not a nicety: proving the SunSpec role
// extension (OID 1.3.6.1.4.1.50316.802.1) was presented on the wire means
// handing a third party the exact bytes and letting them parse it themselves.
type Certificate struct {
	// RequestContext is TLS 1.3's certificate_request_context; nil in TLS 1.2.
	RequestContext []byte
	// TLS13 records which layout was decoded.
	TLS13   bool
	Entries []CertEntry
}

// CertEntry is one certificate in a chain.
type CertEntry struct {
	DER        []byte
	Extensions []Extension // TLS 1.3 per-certificate extensions; nil in TLS 1.2
	Info       *CertInfo   // nil when the DER failed to parse; Err says why
	Err        string
}

// Leaf returns the first certificate in the chain, which by RFC 5246/8446 is
// the end-entity certificate.
func (c *Certificate) Leaf() *CertEntry {
	if c == nil || len(c.Entries) == 0 {
		return nil
	}
	return &c.Entries[0]
}

// DERChain returns the raw DER of every entry, in wire order.
func (c *Certificate) DERChain() [][]byte {
	out := make([][]byte, 0, len(c.Entries))
	for _, e := range c.Entries {
		out = append(out, e.DER)
	}
	return out
}

func parseCertificate(body []byte, opt Options) (*Certificate, error) {
	tls13 := opt.TLS13
	if !tls13 {
		tls13 = looksLikeTLS13Certificate(body)
	}
	c := newCursor(body)
	cert := &Certificate{TLS13: tls13}
	if tls13 {
		cert.RequestContext = c.vector8("certificate.certificate_request_context")
	}
	list := c.vector24("certificate.certificate_list")
	if c.err != nil {
		return cert, c.err
	}
	lc := newCursor(list)
	for !lc.empty() {
		der := lc.vector24("certificate.cert_data")
		if lc.err != nil {
			return cert, lc.err
		}
		entry := CertEntry{DER: der}
		if tls13 {
			entry.Extensions = parseExtensionsCursor(lc, "certificate.extensions")
			if lc.err != nil {
				return cert, lc.err
			}
		}
		info, err := ParseCertInfo(der)
		if err != nil {
			entry.Err = err.Error()
		}
		entry.Info = info
		cert.Entries = append(cert.Entries, entry)
	}
	if len(cert.Entries) == 0 && len(list) != 0 {
		return cert, fmt.Errorf("tlsdis: certificate_list is %d bytes but yielded no certificates", len(list))
	}
	return cert, nil
}

// looksLikeTLS13Certificate distinguishes the two Certificate layouts without
// needing to have seen the ServerHello. TLS 1.3 prefixes an opaque
// certificate_request_context (a zero-length vector in the common case); TLS
// 1.2 starts straight at the 3-byte list length. Checking which reading makes
// the outer length consume the whole body is exact, not a guess.
func looksLikeTLS13Certificate(body []byte) bool {
	if len(body) >= 3 {
		n := int(body[0])<<16 | int(body[1])<<8 | int(body[2])
		if n == len(body)-3 {
			return false // consistent as TLS 1.2
		}
	}
	if len(body) >= 4 {
		ctxLen := int(body[0])
		if len(body) >= 1+ctxLen+3 {
			n := int(body[1+ctxLen])<<16 | int(body[2+ctxLen])<<8 | int(body[3+ctxLen])
			if n == len(body)-4-ctxLen {
				return true
			}
		}
	}
	return false
}

// CertificateRequest is a parsed CertificateRequest.
//
// Its mere presence is the evidence for SunSpecTCP-11 ("the server MUST send
// CertificateRequest"), which is why the parser records the frames it spanned
// even when none of the fields matter.
type CertificateRequest struct {
	TLS13 bool
	// TLS 1.2 fields.
	CertificateTypes       []uint8
	SignatureAlgorithms    []uint16
	CertificateAuthorities [][]byte
	// TLS 1.3 fields.
	RequestContext []byte
	Extensions     []Extension
}

func parseCertificateRequest(body []byte, opt Options) (*CertificateRequest, error) {
	if opt.TLS13 || looksLikeTLS13CertificateRequest(body) {
		c := newCursor(body)
		cr := &CertificateRequest{TLS13: true}
		cr.RequestContext = c.vector8("certificate_request.context")
		cr.Extensions = parseExtensionsCursor(c, "certificate_request.extensions")
		if c.err != nil {
			return cr, c.err
		}
		for _, e := range cr.Extensions {
			if e.Type == ExtSignatureAlgorithms {
				ec := newCursor(e.Data)
				cr.SignatureAlgorithms = ec.u16List("signature_algorithms")
			}
		}
		return cr, nil
	}

	c := newCursor(body)
	cr := &CertificateRequest{}
	cr.CertificateTypes = c.vector8("certificate_request.certificate_types")
	cr.SignatureAlgorithms = c.u16List("certificate_request.supported_signature_algorithms")
	cas := c.vector16("certificate_request.certificate_authorities")
	if c.err != nil {
		return cr, c.err
	}
	cc := newCursor(cas)
	for !cc.empty() {
		dn := cc.vector16("certificate_request.distinguished_name")
		if cc.err != nil {
			return cr, cc.err
		}
		cr.CertificateAuthorities = append(cr.CertificateAuthorities, dn)
	}
	return cr, nil
}

// looksLikeTLS13CertificateRequest tests the TLS 1.2 layout for consistency and
// falls back to 1.3 when it does not hold.
func looksLikeTLS13CertificateRequest(body []byte) bool {
	c := newCursor(body)
	c.vector8("certificate_types")
	c.vector16("signature_algorithms")
	c.vector16("certificate_authorities")
	return c.err != nil || !c.empty()
}

// NewSessionTicket is a parsed NewSessionTicket. Ticket-based resumption is a
// MAY (SunSpecTCP-47) and its presence or absence is reportable either way.
type NewSessionTicket struct {
	TLS13        bool
	LifetimeHint uint32
	AgeAdd       uint32
	Nonce        []byte
	Ticket       []byte
	Extensions   []Extension
}

func parseNewSessionTicket(body []byte, opt Options) (*NewSessionTicket, error) {
	tls12 := func() (*NewSessionTicket, error) {
		c := newCursor(body)
		t := &NewSessionTicket{}
		t.LifetimeHint = c.u32("new_session_ticket.ticket_lifetime_hint")
		t.Ticket = c.vector16("new_session_ticket.ticket")
		if c.err != nil {
			return t, c.err
		}
		if !c.empty() {
			return t, fmt.Errorf("tlsdis: new_session_ticket has %d trailing bytes", c.remaining())
		}
		return t, nil
	}
	tls13 := func() (*NewSessionTicket, error) {
		c := newCursor(body)
		t := &NewSessionTicket{TLS13: true}
		t.LifetimeHint = c.u32("new_session_ticket.ticket_lifetime")
		t.AgeAdd = c.u32("new_session_ticket.ticket_age_add")
		t.Nonce = c.vector8("new_session_ticket.ticket_nonce")
		t.Ticket = c.vector16("new_session_ticket.ticket")
		t.Extensions = parseExtensionsCursor(c, "new_session_ticket.extensions")
		return t, c.err
	}
	if opt.TLS13 {
		return tls13()
	}
	if t, err := tls12(); err == nil {
		return t, nil
	}
	return tls13()
}

// KeyUpdate is a parsed TLS 1.3 KeyUpdate.
type KeyUpdate struct {
	RequestUpdate uint8 // 0 = update_not_requested, 1 = update_requested
}
