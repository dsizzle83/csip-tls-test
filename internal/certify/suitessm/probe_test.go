package suitessm

// probe_test.go proves the hand-rolled ClientHello is actually the ClientHello
// the procedures describe.
//
// This matters more than it looks. Every negative check in the suite rests on
// the DUT having been provoked with a specific hello — a SHA-1 signature
// algorithm set, a NULL-only suite list, a curve list without P-256. If the
// encoder silently dropped an extension, the DUT would refuse for the wrong
// reason (or accept for the right one) and the row would report a conformance
// result about a provocation that never happened. So the encoder is round-
// tripped through internal/evidence/tlsdis — the same parser that reads the
// capture — and every field is checked against what was asked for.

import (
	"testing"

	"csip-tls-test/internal/certify"
	"csip-tls-test/internal/evidence/tlsdis"
)

// parseHello runs a marshalled hello back through the record and handshake
// parsers the citation phase uses.
func parseHello(t *testing.T, h Hello) *tlsdis.ClientHello {
	t.Helper()
	raw, err := h.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	d, err := tlsdis.ParseDirection(raw, nil)
	if err != nil {
		t.Fatalf("the encoder produced bytes the bench's own parser rejects: %v", err)
	}
	m, ok := d.Handshake.Find(tlsdis.HandshakeClientHello)
	if !ok {
		t.Fatalf("no ClientHello parsed back out of %d byte(s)", len(raw))
	}
	if m.ParseError != "" {
		t.Fatalf("ClientHello parse error: %s", m.ParseError)
	}
	return m.ClientHello
}

func TestConformantHelloIsWhatTheProceduresPrescribe(t *testing.T) {
	ch := parseHello(t, conformantHello())
	if ch.LegacyVersion != tlsdis.VersionTLS12 {
		t.Errorf("legacy_version = 0x%04X, want 0x0303", ch.LegacyVersion)
	}
	if len(ch.SessionID) != 0 {
		t.Errorf("session_id is %d byte(s); TLSF-001 requires length 0", len(ch.SessionID))
	}
	if len(ch.CipherSuites) != 3 || !inRelativeOrder(ch.CipherSuites, mandated12) {
		t.Errorf("cipher_suites = %v, want the SunSpecTCP-17 order %v", ch.CipherSuites, mandated12)
	}
	if len(ch.CompressionMethods) != 1 || ch.CompressionMethods[0] != 0 {
		t.Errorf("legacy_compression_methods = %v, want NULL only", ch.CompressionMethods)
	}
	if _, ok := ch.Extension(tlsdis.ExtSupportedVersions); ok {
		t.Error("the TLS 1.2 baseline must carry NO supported_versions extension (TLSF-001's observable)")
	}
	if v, obs := supportedGroupsVerdict(ch, "the bench's"); v.Severity() > 1 {
		t.Errorf("the baseline hello does not satisfy CRYP-004's setup criteria: %s", obs)
	}
	if !ch.HasRenegotiationInfo {
		t.Error("the baseline hello must carry the RFC 5746 renegotiation_info extension")
	}
	if len(weakSignatureAlgorithms(ch.SignatureAlgorithms)) != 0 {
		t.Errorf("the baseline hello offers an MD5/SHA-1 signature algorithm: %v", ch.SignatureAlgorithms)
	}
}

func TestConformantHello13CarriesSupportedVersionsAndARealKeyShare(t *testing.T) {
	ch := parseHello(t, conformantHello13())
	if ch.LegacyVersion != tlsdis.VersionTLS12 {
		t.Errorf("legacy_version = 0x%04X; RFC 8446 requires 0x0303 even for a 1.3 hello", ch.LegacyVersion)
	}
	found13 := false
	for _, v := range ch.SupportedVersions {
		if v == tlsdis.VersionTLS13 {
			found13 = true
		}
	}
	if !found13 {
		t.Errorf("supported_versions = %v, want it to contain 0x0304", ch.SupportedVersions)
	}
	if len(ch.CipherSuites) != 3 || ch.CipherSuites[0] != suiteTLS13_AES128_GCM_SHA256 {
		t.Errorf("cipher_suites = %v, want the SunSpecTCP-18 order %v", ch.CipherSuites, mandated13)
	}
	if len(ch.KeyShares) != 1 || ch.KeyShares[0].Group != groupSecp256r1 {
		t.Fatalf("key_share = %+v, want one secp256r1 entry", ch.KeyShares)
	}
	// An uncompressed P-256 point is 0x04 followed by two 32-byte coordinates.
	if n := len(ch.KeyShares[0].Key); n != 65 {
		t.Errorf("the P-256 key share is %d bytes, want 65 — a malformed share would draw a "+
			"HelloRetryRequest and the probe would never see a real ServerHello", n)
	}
	if len(ch.PSKKeyExchangeModes) == 0 {
		t.Error("a TLS 1.3 hello should carry psk_key_exchange_modes")
	}
}

func TestProvocationHellosCarryExactlyWhatTheyClaim(t *testing.T) {
	t.Run("NULL encryption only", func(t *testing.T) {
		h := conformantHello()
		h.SupportedVersions = nil
		h.Suites = nullEncryptionOffer()
		ch := parseHello(t, h)
		if len(nullSuitesIn(ch.CipherSuites)) != len(ch.CipherSuites) {
			t.Errorf("the provocation leaked a non-NULL suite: %v", ch.CipherSuites)
		}
	})

	t.Run("SHA-1 and MD5 signature algorithms", func(t *testing.T) {
		h := conformantHello()
		h.SupportedVersions = nil
		h.Suites = []uint16{suiteRSA_AES128_CBC_SHA}
		h.SigAlgs = []uint16{sigECDSASHA1, sigRSAMD5}
		ch := parseHello(t, h)
		weak := weakSignatureAlgorithms(ch.SignatureAlgorithms)
		if len(weak) != 2 {
			t.Errorf("CRYP-005's provocation must actually reach the wire as (sha1, ecdsa) and (md5, rsa): %v", weak)
		}
		if len(ch.CipherSuites) != 1 || ch.CipherSuites[0] != suiteRSA_AES128_CBC_SHA {
			t.Errorf("cipher_suites = %v, want only 0x002F", ch.CipherSuites)
		}
	})

	t.Run("secp384r1 without P-256", func(t *testing.T) {
		h := conformantHello()
		h.SupportedVersions = nil
		h.Groups = []uint16{groupSecp384r1}
		ch := parseHello(t, h)
		for _, g := range ch.SupportedGroups {
			if g == groupSecp256r1 {
				t.Fatal("CRYP-004's negative iteration must NOT offer P-256")
			}
		}
		if len(ch.SupportedGroups) != 1 {
			t.Errorf("supported_groups = %v, want secp384r1 alone", ch.SupportedGroups)
		}
	})

	t.Run("DEFLATE ahead of NULL", func(t *testing.T) {
		h := conformantHello()
		h.SupportedVersions = nil
		h.Compression = []uint8{1, 0}
		ch := parseHello(t, h)
		if v, obs := compressionVerdict(ch, "the probe's"); v != certify.Fail {
			t.Errorf("the probe's own compression list should be judged non-conformant: %s (%s)", v, obs)
		}
	})

	t.Run("max_fragment_length 512", func(t *testing.T) {
		code := mflCode512
		h := conformantHello()
		h.SupportedVersions = nil
		h.MaxFragmentLength = &code
		ch := parseHello(t, h)
		if ch.MaxFragmentLength == nil || *ch.MaxFragmentLength != mflCode512 {
			t.Errorf("max_fragment_length = %v, want code 1 (512 bytes)", ch.MaxFragmentLength)
		}
	})
}

func TestMarshalRefusesAnEmptySuiteListAndAnOversizeSessionID(t *testing.T) {
	h := conformantHello()
	h.Suites = nil
	if _, err := h.Marshal(); err == nil {
		t.Error("a ClientHello with no cipher suites is a bug in the check, and must be refused loudly")
	}
	h = conformantHello()
	h.SessionID = make([]byte, 33)
	if _, err := h.Marshal(); err == nil {
		t.Error("a 33-byte legacy_session_id exceeds the wire encoding and must be refused")
	}
}

func TestFlightCompleteStopsAtTheRightMoment(t *testing.T) {
	// A bare, incomplete ServerHello record must NOT end the read: the chain
	// that follows can span several segments, and stopping early would turn a
	// conformant server into a parse error.
	partial := []byte{0x16, 0x03, 0x03, 0x00, 0x04, 0x02, 0x00, 0x00}
	if flightComplete(partial) {
		t.Error("a truncated record must not be treated as a finished flight")
	}

	// A fatal alert ends it immediately, which is what every negative probe
	// relies on for a prompt result.
	alert := []byte{0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 40}
	if !flightComplete(alert) {
		t.Error("a fatal alert must end the read at once")
	}

	// ServerHelloDone ends a TLS 1.2 flight.
	done := []byte{0x16, 0x03, 0x03, 0x00, 0x04, byte(tlsdis.HandshakeServerHelloDone), 0x00, 0x00, 0x00}
	if !flightComplete(done) {
		t.Error("ServerHelloDone must end a TLS 1.2 flight")
	}
}
