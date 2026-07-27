package tlsdis

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"net"
	"reflect"
	"strings"
	"testing"
)

// --- hand-crafted fixtures ------------------------------------------------

// canonicalClientHello is a ClientHello built byte by byte, so the parser's
// output can be asserted EXACTLY rather than "contains". The suite list is the
// Secure SunSpec Modbus §5.2 minimum set in specification order — the order is
// itself a requirement (SunSpecTCP-17/19), so a parser that returned a set
// instead of a list would silently make that row untestable.
func canonicalClientHello() []byte {
	suites := join(
		u16b(0xC02B), // TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
		u16b(0xCCA9), // TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
		u16b(0xC0AE), // TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8  ← the CSIP-mandatory suite
		u16b(0x0A0A), // GREASE
	)
	exts := join(
		ext(ExtServerName, vec16(join([]byte{0}, vec16([]byte("gateway.bench"))))),
		ext(ExtMaxFragmentLength, []byte{1}), // 512 bytes (SunSpecTCP-60)
		ext(ExtSupportedGroups, vec16(join(u16b(23), u16b(24), u16b(29)))),
		ext(ExtECPointFormats, vec8([]byte{0})),
		ext(ExtSignatureAlgorithms, vec16(join(u16b(0x0403), u16b(0x0503)))),
		ext(ExtALPN, vec16(join(vec8([]byte("h2")), vec8([]byte("http/1.1"))))),
		ext(ExtSessionTicket, nil),
		ext(ExtSupportedVersions, vec8(join(u16b(VersionTLS13), u16b(VersionTLS12)))),
		ext(ExtPSKKeyExchangeModes, vec8([]byte{1})),
		ext(ExtKeyShare, vec16(join(u16b(29), vec16(bytes.Repeat([]byte{0x42}, 32))))),
		ext(ExtRenegotiationInfo, vec8(nil)),
	)
	body := join(
		u16b(VersionTLS12),
		bytes.Repeat([]byte{0xA5}, 32),       // random
		vec8(bytes.Repeat([]byte{0x11}, 32)), // session id
		vec16(suites),
		vec8([]byte{0}), // compression: null only (SunSpecTCP-61)
		vec16(exts),
	)
	return hsMsg(HandshakeClientHello, body)
}

func TestParseClientHelloExact(t *testing.T) {
	data := rec(ContentHandshake, VersionTLS10, canonicalClientHello())
	d, err := ParseDirection(data, nil)
	if err != nil {
		t.Fatalf("ParseDirection: %v", err)
	}
	msg, ok := d.Handshake.Find(HandshakeClientHello)
	if !ok {
		t.Fatal("no ClientHello parsed")
	}
	if msg.ParseError != "" {
		t.Fatalf("ParseError = %s", msg.ParseError)
	}
	ch := msg.ClientHello

	wantSuites := []uint16{0xC02B, 0xCCA9, 0xC0AE, 0x0A0A}
	if !reflect.DeepEqual(ch.CipherSuites, wantSuites) {
		t.Errorf("CipherSuites = %v, want %v", ch.CipherSuites, wantSuites)
	}
	wantNames := []string{
		"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
		"TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
		"TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8",
		"GREASE(0x0A0A)",
	}
	if got := CipherSuiteNames(ch.CipherSuites); !reflect.DeepEqual(got, wantNames) {
		t.Errorf("suite names = %v, want %v", got, wantNames)
	}
	if !ch.OffersSuite(0xC0AE) {
		t.Error("OffersSuite(0xC0AE) = false")
	}
	if !reflect.DeepEqual(ch.CompressionMethods, []uint8{0}) {
		t.Errorf("CompressionMethods = %v, want [0]", ch.CompressionMethods)
	}

	wantExts := []uint16{
		ExtServerName, ExtMaxFragmentLength, ExtSupportedGroups, ExtECPointFormats,
		ExtSignatureAlgorithms, ExtALPN, ExtSessionTicket, ExtSupportedVersions,
		ExtPSKKeyExchangeModes, ExtKeyShare, ExtRenegotiationInfo,
	}
	if got := ExtensionTypes(ch.Extensions); !reflect.DeepEqual(got, wantExts) {
		t.Errorf("extension types = %v, want %v", got, wantExts)
	}

	if !reflect.DeepEqual(ch.SupportedVersions, []uint16{VersionTLS13, VersionTLS12}) {
		t.Errorf("SupportedVersions = %v", ch.SupportedVersions)
	}
	if ch.MaxVersion() != VersionTLS13 {
		t.Errorf("MaxVersion = %s, want TLS 1.3", VersionName(ch.MaxVersion()))
	}
	if !reflect.DeepEqual(ch.SupportedGroups, []uint16{23, 24, 29}) {
		t.Errorf("SupportedGroups = %v", ch.SupportedGroups)
	}
	if !reflect.DeepEqual(ch.ECPointFormats, []uint8{0}) {
		t.Errorf("ECPointFormats = %v", ch.ECPointFormats)
	}
	if !reflect.DeepEqual(ch.SignatureAlgorithms, []uint16{0x0403, 0x0503}) {
		t.Errorf("SignatureAlgorithms = %v", ch.SignatureAlgorithms)
	}
	if ch.MaxFragmentLength == nil || *ch.MaxFragmentLength != 1 {
		t.Fatalf("MaxFragmentLength = %v, want codepoint 1", ch.MaxFragmentLength)
	}
	if n, ok := MaxFragmentLengthBytes(*ch.MaxFragmentLength); !ok || n != 512 {
		t.Errorf("MaxFragmentLengthBytes = %d,%t; want 512,true", n, ok)
	}
	if !ch.HasRenegotiationInfo || len(ch.RenegotiationInfo) != 0 {
		t.Errorf("renegotiation_info: has=%t data=%v, want present and empty", ch.HasRenegotiationInfo, ch.RenegotiationInfo)
	}
	if !ch.HasSessionTicket {
		t.Error("HasSessionTicket = false")
	}
	if !reflect.DeepEqual(ch.ServerNames, []string{"gateway.bench"}) {
		t.Errorf("ServerNames = %v", ch.ServerNames)
	}
	if !reflect.DeepEqual(ch.ALPN, []string{"h2", "http/1.1"}) {
		t.Errorf("ALPN = %v", ch.ALPN)
	}
	if !reflect.DeepEqual(ch.PSKKeyExchangeModes, []uint8{1}) {
		t.Errorf("PSKKeyExchangeModes = %v", ch.PSKKeyExchangeModes)
	}
	if len(ch.KeyShares) != 1 || ch.KeyShares[0].Group != 29 || len(ch.KeyShares[0].Key) != 32 {
		t.Errorf("KeyShares = %+v", ch.KeyShares)
	}
	if raw, ok := ch.Extension(ExtALPN); !ok || len(raw) == 0 {
		t.Error("Extension(ALPN) should return the raw bytes")
	}
}

func TestParseServerHelloVersions(t *testing.T) {
	mk := func(suite uint16, exts []byte, random []byte) []byte {
		body := join(
			u16b(VersionTLS12),
			random,
			vec8(bytes.Repeat([]byte{0x11}, 32)),
			u16b(suite),
			[]byte{0},
		)
		if exts != nil {
			body = append(body, vec16(exts)...)
		}
		return rec(ContentHandshake, VersionTLS12, hsMsg(HandshakeServerHello, body))
	}

	t.Run("tls 1.2 without supported_versions", func(t *testing.T) {
		d, err := ParseDirection(mk(0xC0AE, nil, bytes.Repeat([]byte{0x5A}, 32)), nil)
		if err != nil {
			t.Fatalf("ParseDirection: %v", err)
		}
		msg, _ := d.Handshake.Find(HandshakeServerHello)
		sh := msg.ServerHello
		if sh.NegotiatedVersion() != VersionTLS12 {
			t.Errorf("NegotiatedVersion = %s", VersionName(sh.NegotiatedVersion()))
		}
		if sh.CipherSuite != 0xC0AE {
			t.Errorf("CipherSuite = 0x%04X", sh.CipherSuite)
		}
		if got, want := CipherSuiteName(sh.CipherSuite), "TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8"; got != want {
			t.Errorf("suite name = %q, want %q", got, want)
		}
		if sh.IsHelloRetryRequest {
			t.Error("IsHelloRetryRequest set on an ordinary ServerHello")
		}
	})

	t.Run("tls 1.3 supported_versions overrides the legacy field", func(t *testing.T) {
		exts := join(
			ext(ExtSupportedVersions, u16b(VersionTLS13)),
			ext(ExtKeyShare, join(u16b(29), vec16(bytes.Repeat([]byte{1}, 32)))),
		)
		d, err := ParseDirection(mk(0x1301, exts, bytes.Repeat([]byte{0x5A}, 32)), nil)
		if err != nil {
			t.Fatalf("ParseDirection: %v", err)
		}
		msg, _ := d.Handshake.Find(HandshakeServerHello)
		sh := msg.ServerHello
		if sh.LegacyVersion != VersionTLS12 {
			t.Errorf("LegacyVersion = 0x%04X, want 0x0303", sh.LegacyVersion)
		}
		if sh.NegotiatedVersion() != VersionTLS13 {
			t.Errorf("NegotiatedVersion = %s, want TLS 1.3", VersionName(sh.NegotiatedVersion()))
		}
		if !sh.HasKeyShare || sh.KeyShareGroup != 29 {
			t.Errorf("key_share = %t/%d", sh.HasKeyShare, sh.KeyShareGroup)
		}
	})

	t.Run("hello retry request", func(t *testing.T) {
		exts := ext(ExtSupportedVersions, u16b(VersionTLS13))
		d, err := ParseDirection(mk(0x1301, exts, helloRetryRequestRandom[:]), nil)
		if err != nil {
			t.Fatalf("ParseDirection: %v", err)
		}
		msg, _ := d.Handshake.Find(HandshakeServerHello)
		if !msg.ServerHello.IsHelloRetryRequest {
			t.Fatal("HelloRetryRequest not recognised: TLS 1.3 signals it with a fixed random, not a message type")
		}
	})
}

// TestHandshakeSpansRecords is REQUIREMENT ONE: the handshake is a byte stream
// over the record layer. This fragments a single Certificate message across
// three records — with one split INSIDE the four-byte message header — and
// demands the same parse as the unfragmented message, including byte-identical
// certificate DER.
func TestHandshakeSpansRecords(t *testing.T) {
	pki := newTestPKI(t)
	chain := join(vec24(pki.clientDER), vec24(pki.caDER))
	msg := hsMsg(HandshakeCertificate, vec24(chain))
	if len(msg) < 600 {
		t.Fatalf("fixture too small to be interesting: %d bytes", len(msg))
	}

	reference, err := ParseHandshake([]Fragment{{Data: msg, Record: 0}}, Options{})
	if err != nil {
		t.Fatalf("reference parse: %v", err)
	}

	// Split points: 2 bytes in (mid-header, so the 24-bit length is cut in
	// half) and again a few hundred bytes in.
	cuts := []int{2, 400}
	var stream []byte
	var frags []Fragment
	prev := 0
	for i, cut := range append(cuts, len(msg)) {
		part := msg[prev:cut]
		stream = append(stream, rec(ContentHandshake, VersionTLS12, part)...)
		frags = append(frags, Fragment{Data: part, Record: i, Packets: []int{i + 1}})
		prev = cut
	}

	got, err := ParseHandshake(frags, Options{})
	if err != nil {
		t.Fatalf("fragmented parse: %v", err)
	}
	if got.Truncated {
		t.Fatalf("fragmented parse reports truncation (need %d)", got.Need)
	}
	if len(got.Messages) != 1 {
		t.Fatalf("got %d messages, want 1", len(got.Messages))
	}
	m := got.Messages[0]
	if m.Type != HandshakeCertificate {
		t.Fatalf("type = %s", HandshakeTypeName(m.Type))
	}
	if m.Length != reference.Messages[0].Length {
		t.Fatalf("length = %d, want %d", m.Length, reference.Messages[0].Length)
	}
	if len(m.Certificate.Entries) != 2 {
		t.Fatalf("got %d certificates, want 2", len(m.Certificate.Entries))
	}
	if !bytes.Equal(m.Certificate.Entries[0].DER, pki.clientDER) {
		t.Fatal("leaf DER is not byte-identical to what was sent")
	}
	if !bytes.Equal(m.Certificate.Entries[1].DER, pki.caDER) {
		t.Fatal("issuer DER is not byte-identical to what was sent")
	}
	// Provenance must name every record and frame the message crossed.
	if !reflect.DeepEqual(m.Records, []int{0, 1, 2}) {
		t.Errorf("Records = %v, want [0 1 2]", m.Records)
	}
	if !reflect.DeepEqual(m.Packets, []int{1, 2, 3}) {
		t.Errorf("Packets = %v, want [1 2 3]", m.Packets)
	}

	// And the same thing again through the record layer, which is how a real
	// capture arrives.
	d, err := ParseDirection(stream, nil)
	if err != nil {
		t.Fatalf("ParseDirection: %v", err)
	}
	if len(d.Stream.Records) != 3 {
		t.Fatalf("got %d records, want 3", len(d.Stream.Records))
	}
	if len(d.Handshake.Messages) != 1 {
		t.Fatalf("got %d messages from the record layer, want 1", len(d.Handshake.Messages))
	}
	if !bytes.Equal(d.Handshake.Messages[0].Certificate.Entries[0].DER, pki.clientDER) {
		t.Fatal("leaf DER differs when parsed through the record layer")
	}
}

// TestPerRecordParsingWouldFail documents the failure mode requirement one
// exists to prevent: parsing each record independently reads the NEXT record's
// bytes as a length field and invents a message megabytes long.
func TestPerRecordParsingWouldFail(t *testing.T) {
	pki := newTestPKI(t)
	msg := hsMsg(HandshakeCertificate, vec24(join(vec24(pki.clientDER), vec24(pki.caDER))))
	first := msg[:400]

	naive, err := ParseHandshake([]Fragment{{Data: first, Record: 0}}, Options{})
	if err != nil {
		t.Fatalf("unexpected hard error: %v", err)
	}
	if !naive.Truncated {
		t.Fatal("a lone first fragment must be reported as truncated, not parsed as a whole message")
	}
	if len(naive.Messages) != 0 {
		t.Fatalf("got %d messages from an incomplete fragment, want 0", len(naive.Messages))
	}
	if naive.Need != len(msg)-400 {
		t.Errorf("Need = %d, want %d", naive.Need, len(msg)-400)
	}
}

func TestHandshakeAbsurdLengthIsRejected(t *testing.T) {
	body := join([]byte{byte(HandshakeCertificate)}, u24b(0xFFFFFF), []byte{0x00})
	h, err := ParseHandshake([]Fragment{{Data: body, Record: 0}}, Options{})
	if err == nil {
		t.Fatal("a 16 MiB handshake message must be rejected, not waited for")
	}
	if len(h.Errors) == 0 {
		t.Error("the stream should record the error too")
	}
}

// --- a real handshake -----------------------------------------------------

// tls12MutualHandshake runs a genuine mutually-authenticated TLS 1.2 handshake
// over net.Pipe and returns the exact bytes each side wrote — the same byte
// streams a capture of the same connection would reassemble.
func tls12MutualHandshake(t *testing.T, pki *testPKI, suite uint16) (clientStream, serverStream []byte) {
	t.Helper()
	c1, c2 := net.Pipe()
	clientRec := &recorder{Conn: c1}
	serverRec := &recorder{Conn: c2}

	serverCfg := &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{pki.serverDER, pki.caDER}, PrivateKey: pki.serverKey}},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    pki.pool,
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS12,
		CipherSuites: []uint16{suite},
	}
	clientCfg := &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{pki.clientDER, pki.caDER}, PrivateKey: pki.clientKey}},
		RootCAs:      pki.pool,
		ServerName:   "localhost",
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS12,
		CipherSuites: []uint16{suite},
	}

	done := make(chan error, 1)
	go func() {
		s := tls.Server(serverRec, serverCfg)
		if err := s.Handshake(); err != nil {
			done <- err
			return
		}
		buf := make([]byte, 16)
		if _, err := s.Read(buf); err != nil {
			done <- err
			return
		}
		_, err := s.Write([]byte("pong"))
		done <- err
	}()

	c := tls.Client(clientRec, clientCfg)
	if err := c.Handshake(); err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	if _, err := c.Write([]byte("ping")); err != nil {
		t.Fatalf("client write: %v", err)
	}
	buf := make([]byte, 16)
	if _, err := c.Read(buf); err != nil {
		t.Fatalf("client read: %v", err)
	}
	if err := <-done; err != nil {
		t.Fatalf("server: %v", err)
	}
	_ = c.Close()
	return clientRec.bytes(), serverRec.bytes()
}

func TestRealTLS12MutualHandshake(t *testing.T) {
	pki := newTestPKI(t)
	const suite = tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
	clientStream, serverStream := tls12MutualHandshake(t, pki, suite)

	client, err := ParseDirection(clientStream, fakeMapper{segment: 1400})
	if err != nil {
		t.Fatalf("client direction: %v", err)
	}
	server, err := ParseDirection(serverStream, fakeMapper{segment: 1400})
	if err != nil {
		t.Fatalf("server direction: %v", err)
	}

	// Client flight: ClientHello, then Certificate / ClientKeyExchange /
	// CertificateVerify before the ChangeCipherSpec.
	wantClient := []HandshakeType{
		HandshakeClientHello, HandshakeCertificate,
		HandshakeClientKeyExchange, HandshakeCertificateVerify,
	}
	if got := client.Handshake.Types(); !reflect.DeepEqual(got, wantClient) {
		t.Errorf("client handshake = %v, want %v", typeNames(got), typeNames(wantClient))
	}
	// Server flight: ServerHello, Certificate, ServerKeyExchange,
	// CertificateRequest, ServerHelloDone. The CertificateRequest is the
	// evidence for SunSpecTCP-11.
	wantServer := []HandshakeType{
		HandshakeServerHello, HandshakeCertificate, HandshakeServerKeyExchange,
		HandshakeCertificateRequest, HandshakeServerHelloDone,
	}
	if got := server.Handshake.Types(); !reflect.DeepEqual(got, wantServer) {
		t.Errorf("server handshake = %v, want %v", typeNames(got), typeNames(wantServer))
	}

	chMsg, _ := client.Handshake.Find(HandshakeClientHello)
	ch := chMsg.ClientHello
	if !reflect.DeepEqual(ch.CipherSuites, []uint16{suite}) {
		t.Errorf("offered suites = %v, want exactly [0x%04X]", CipherSuiteNames(ch.CipherSuites), suite)
	}
	if !reflect.DeepEqual(ch.CompressionMethods, []uint8{0}) {
		t.Errorf("compression methods = %v, want [null]", ch.CompressionMethods)
	}
	// Go always offers these three; they are the ones the Secure SunSpec Modbus
	// §5.4/§5.5 rows ask about (supported groups, point formats, and secure
	// renegotiation indication).
	for _, want := range []uint16{ExtSupportedGroups, ExtECPointFormats, ExtSignatureAlgorithms} {
		if _, ok := ch.Extension(want); !ok {
			t.Errorf("ClientHello is missing %s; extensions were %v", ExtensionName(want), ExtensionNames(ch.Extensions))
		}
	}
	if !ch.HasRenegotiationInfo {
		t.Error("ClientHello has no renegotiation_info (RFC 5746, SunSpecTCP-62)")
	}

	shMsg, _ := server.Handshake.Find(HandshakeServerHello)
	sh := shMsg.ServerHello
	if sh.CipherSuite != suite {
		t.Errorf("chosen suite = %s, want %s", CipherSuiteName(sh.CipherSuite), CipherSuiteName(suite))
	}
	if sh.NegotiatedVersion() != VersionTLS12 {
		t.Errorf("negotiated version = %s", VersionName(sh.NegotiatedVersion()))
	}
	if sh.CompressionMethod != 0 {
		t.Errorf("chosen compression = %d, want null", sh.CompressionMethod)
	}

	// The client's certificate chain must come back byte-exact, and the role
	// extension must be readable from it — this is the RBAC pass criterion.
	certMsg, ok := client.Handshake.Find(HandshakeCertificate)
	if !ok {
		t.Fatal("client sent no Certificate")
	}
	cc := certMsg.Certificate
	if cc.TLS13 {
		t.Error("TLS 1.2 Certificate decoded with the TLS 1.3 layout")
	}
	if len(cc.Entries) != 2 {
		t.Fatalf("client chain has %d certs, want 2", len(cc.Entries))
	}
	if !bytes.Equal(cc.Entries[0].DER, pki.clientDER) {
		t.Fatal("client leaf DER is not byte-identical to the issued certificate")
	}
	role, err := cc.Leaf().Info.SunSpecRole()
	if err != nil || role != testRole {
		t.Fatalf("SunSpecRole = %q, %v; want %q", role, err, testRole)
	}
	if len(certMsg.Packets) == 0 {
		t.Error("the Certificate message must cite the frames it spanned")
	}

	crMsg, ok := server.Handshake.Find(HandshakeCertificateRequest)
	if !ok {
		t.Fatal("server sent no CertificateRequest")
	}
	if crMsg.CertificateRequest.TLS13 {
		t.Error("TLS 1.2 CertificateRequest decoded with the TLS 1.3 layout")
	}
	if len(crMsg.CertificateRequest.SignatureAlgorithms) == 0 {
		t.Error("CertificateRequest lists no signature algorithms")
	}

	// Both sides changed cipher spec, and everything after that is opaque.
	if len(client.CCS) != 1 || len(server.CCS) != 1 {
		t.Errorf("CCS records: client=%v server=%v", client.CCS, server.CCS)
	}
	if len(client.Stream.Records) <= len(client.Handshake.Messages) {
		t.Error("expected encrypted records after the handshake")
	}
}

func TestRealTLS13Handshake(t *testing.T) {
	pki := newTestPKI(t)
	c1, c2 := net.Pipe()
	clientRec := &recorder{Conn: c1}
	serverRec := &recorder{Conn: c2}

	serverCfg := &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{pki.serverDER, pki.caDER}, PrivateKey: pki.serverKey}},
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
	}
	clientCfg := &tls.Config{
		RootCAs:    pki.pool,
		ServerName: "localhost",
		MinVersion: tls.VersionTLS13,
		MaxVersion: tls.VersionTLS13,
	}
	done := make(chan error, 1)
	go func() {
		s := tls.Server(serverRec, serverCfg)
		done <- s.Handshake()
	}()
	c := tls.Client(clientRec, clientCfg)
	if err := c.Handshake(); err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	if err := <-done; err != nil {
		t.Fatalf("server handshake: %v", err)
	}

	server, err := ParseDirection(serverRec.bytes(), nil)
	if err != nil {
		t.Fatalf("server direction: %v", err)
	}
	// In TLS 1.3 only the ServerHello is in the clear; everything that follows
	// is an application_data record even though it carries the handshake.
	if got := server.Handshake.Types(); !reflect.DeepEqual(got, []HandshakeType{HandshakeServerHello}) {
		t.Fatalf("plaintext server handshake = %v, want just server_hello", typeNames(got))
	}
	shMsg, _ := server.Handshake.Find(HandshakeServerHello)
	if shMsg.ServerHello.NegotiatedVersion() != VersionTLS13 {
		t.Errorf("negotiated version = %s", VersionName(shMsg.ServerHello.NegotiatedVersion()))
	}
	if !KnownCipherSuite(shMsg.ServerHello.CipherSuite) {
		t.Errorf("chosen suite 0x%04X is not in the IANA table", shMsg.ServerHello.CipherSuite)
	}
	if len(server.AppData) == 0 {
		t.Error("TLS 1.3 must show the encrypted handshake as application_data records")
	}
}

func TestRealHandshakeFatalAlert(t *testing.T) {
	pki := newTestPKI(t)
	c1, c2 := net.Pipe()
	clientRec := &recorder{Conn: c1}
	serverRec := &recorder{Conn: c2}

	serverCfg := &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{pki.serverDER, pki.caDER}, PrivateKey: pki.serverKey}},
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS12,
	}
	// No RootCAs: the client cannot verify the server and must abort with a
	// fatal alert. That alert is exactly the artefact the negative conformance
	// cases (SunSpecTCP-13/48) demand as evidence.
	clientCfg := &tls.Config{ServerName: "localhost", MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12}

	done := make(chan struct{})
	go func() {
		s := tls.Server(serverRec, serverCfg)
		_ = s.Handshake()
		close(done)
	}()
	c := tls.Client(clientRec, clientCfg)
	if err := c.Handshake(); err == nil {
		t.Fatal("handshake should have failed on an unverifiable server certificate")
	}
	<-done

	client, err := ParseDirection(clientRec.bytes(), fakeMapper{segment: 200})
	if err != nil {
		t.Fatalf("client direction: %v", err)
	}
	alert, ok := client.FatalAlert()
	if !ok {
		t.Fatalf("no fatal alert in the client's stream; alerts = %v", client.Alerts)
	}
	if got := AlertDescriptionName(alert.Description); got != "bad_certificate" && got != "unknown_ca" {
		t.Errorf("alert = %s, want a certificate-related fatal alert", got)
	}
	if len(alert.Packets) == 0 {
		t.Error("the alert must name the frames it was carried in")
	}
}

func typeNames(ts []HandshakeType) []string {
	out := make([]string, len(ts))
	for i, t := range ts {
		out[i] = HandshakeTypeName(t)
	}
	return out
}

func TestHandshakeMalformedBodiesAreReportedNotDropped(t *testing.T) {
	// A ClientHello whose cipher-suite vector runs past the message.
	body := join(u16b(VersionTLS12), bytes.Repeat([]byte{0}, 32), vec8(nil), u16b(40), []byte{0, 1, 2})
	data := rec(ContentHandshake, VersionTLS12, hsMsg(HandshakeClientHello, body))
	d, err := ParseDirection(data, nil)
	if err != nil {
		t.Fatalf("ParseDirection returned a hard error for a malformed body: %v", err)
	}
	if len(d.Handshake.Messages) != 1 {
		t.Fatalf("got %d messages, want the malformed one to still be reported", len(d.Handshake.Messages))
	}
	m := d.Handshake.Messages[0]
	if m.ParseError == "" {
		t.Fatal("ParseError is empty for a malformed ClientHello")
	}
	if !strings.Contains(m.ParseError, "cipher_suites") {
		t.Errorf("ParseError = %q, want it to name the field", m.ParseError)
	}
	if len(d.Handshake.Errors) != 1 {
		t.Errorf("stream Errors = %v", d.Handshake.Errors)
	}
}

func TestHandshakeTruncationSweep(t *testing.T) {
	pki := newTestPKI(t)
	full := join(
		rec(ContentHandshake, VersionTLS12, canonicalClientHello()),
		rec(ContentHandshake, VersionTLS12, hsMsg(HandshakeCertificate, vec24(vec24(pki.clientDER)))),
		rec(ContentAlert, VersionTLS12, []byte{2, 40}),
	)
	for n := 0; n <= len(full); n++ {
		d, err := ParseDirection(full[:n], nil)
		_ = err
		if d == nil || d.Handshake == nil {
			continue
		}
		for _, m := range d.Handshake.Messages {
			if m.Offset+4+m.Length > len(d.Handshake.Buffer) {
				t.Fatalf("prefix %d: message claims bytes past the buffer", n)
			}
		}
	}
}

func TestNewSessionTicketBothLayouts(t *testing.T) {
	t.Run("tls 1.2", func(t *testing.T) {
		body := join([]byte{0, 0, 0x0E, 0x10}, vec16(bytes.Repeat([]byte{9}, 48)))
		h, err := ParseHandshake([]Fragment{{Data: hsMsg(HandshakeNewSessionTicket, body), Record: 0}}, Options{})
		if err != nil {
			t.Fatal(err)
		}
		nst := h.Messages[0].NewSessionTicket
		if nst.TLS13 || nst.LifetimeHint != 3600 || len(nst.Ticket) != 48 {
			t.Fatalf("NewSessionTicket = %+v", nst)
		}
	})
	t.Run("tls 1.3", func(t *testing.T) {
		body := join([]byte{0, 0, 0x0E, 0x10}, []byte{1, 2, 3, 4}, vec8([]byte{0xAA}), vec16(bytes.Repeat([]byte{9}, 48)), vec16(nil))
		h, err := ParseHandshake([]Fragment{{Data: hsMsg(HandshakeNewSessionTicket, body), Record: 0}}, Options{TLS13: true})
		if err != nil {
			t.Fatal(err)
		}
		nst := h.Messages[0].NewSessionTicket
		if !nst.TLS13 || nst.LifetimeHint != 3600 || nst.AgeAdd != 0x01020304 || len(nst.Nonce) != 1 {
			t.Fatalf("NewSessionTicket = %+v", nst)
		}
	})
}

func TestKeyUpdateAndFinished(t *testing.T) {
	frags := []Fragment{{Data: join(
		hsMsg(HandshakeFinished, bytes.Repeat([]byte{0xF1}, 32)),
		hsMsg(HandshakeKeyUpdate, []byte{1}),
	), Record: 0}}
	h, err := ParseHandshake(frags, Options{TLS13: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(h.Messages) != 2 {
		t.Fatalf("got %d messages, want 2", len(h.Messages))
	}
	if h.Messages[1].KeyUpdate == nil || h.Messages[1].KeyUpdate.RequestUpdate != 1 {
		t.Fatalf("KeyUpdate = %+v", h.Messages[1].KeyUpdate)
	}
	if got := fmt.Sprint(h.Messages[0]); !strings.Contains(got, "finished") {
		t.Errorf("String() = %q", got)
	}
}
