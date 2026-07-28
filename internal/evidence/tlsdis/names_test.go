package tlsdis

import (
	"strings"
	"testing"
)

// TestMandatorySuiteName pins the one name a conformance verdict is written
// against. CSIP §5.2.1.1 and the bench's own profile both name this suite, and
// a typo here would put the wrong string in a certification report.
func TestMandatorySuiteName(t *testing.T) {
	if got, want := CipherSuiteName(0xC0AE), "TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8"; got != want {
		t.Fatalf("CipherSuiteName(0xC0AE) = %q, want %q", got, want)
	}
	if !KnownCipherSuite(0xC0AE) {
		t.Fatal("0xC0AE must be recognised as an IANA-registered suite (SunSpecTCP-15)")
	}
}

func TestCipherSuiteNames(t *testing.T) {
	for _, tc := range []struct {
		id   uint16
		want string
	}{
		{0x1301, "TLS_AES_128_GCM_SHA256"},
		{0x1302, "TLS_AES_256_GCM_SHA384"},
		{0x1303, "TLS_CHACHA20_POLY1305_SHA256"},
		{0x1304, "TLS_AES_128_CCM_SHA256"},
		{0x1305, "TLS_AES_128_CCM_8_SHA256"},
		{0xC02B, "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"},
		{0xC02F, "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"},
		{0xC0AC, "TLS_ECDHE_ECDSA_WITH_AES_128_CCM"},
		{0xC0AF, "TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8"},
		{0xC0A8, "TLS_PSK_WITH_AES_128_CCM_8"},
		{0xCCA9, "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256"},
		{0xD003, "TLS_ECDHE_PSK_WITH_AES_128_CCM_8_SHA256"},
		{0x009C, "TLS_RSA_WITH_AES_128_GCM_SHA256"},
		{0x0004, "TLS_RSA_WITH_RC4_128_MD5"},
		{0x00FF, "TLS_EMPTY_RENEGOTIATION_INFO_SCSV"},
		{0x5600, "TLS_FALLBACK_SCSV"},
	} {
		if got := CipherSuiteName(tc.id); got != tc.want {
			t.Errorf("CipherSuiteName(0x%04X) = %q, want %q", tc.id, got, tc.want)
		}
	}
}

// TestUnknownCodepointsArePrinted is the reporting contract: an unrecognised
// value must be visible in the report, because "the DUT offered something we
// have never seen" is a finding, and a table that dropped it would report an
// absence instead.
func TestUnknownCodepointsArePrinted(t *testing.T) {
	if got := CipherSuiteName(0xFF42); got != "UNKNOWN(0xFF42)" {
		t.Errorf("CipherSuiteName = %q", got)
	}
	if KnownCipherSuite(0xFF42) {
		t.Error("KnownCipherSuite(0xFF42) = true")
	}
	if got := NamedGroupName(0x9999); got != "UNKNOWN(0x9999)" {
		t.Errorf("NamedGroupName = %q", got)
	}
	if got := SignatureSchemeName(0x9999); got != "UNKNOWN(0x9999)" {
		t.Errorf("SignatureSchemeName = %q", got)
	}
	if got := ExtensionName(0x9999); got != "UNKNOWN(0x9999)" {
		t.Errorf("ExtensionName = %q", got)
	}
	if got := VersionName(0x9999); got != "UNKNOWN(0x9999)" {
		t.Errorf("VersionName = %q", got)
	}
	if got := AlertDescriptionName(199); got != "UNKNOWN(199)" {
		t.Errorf("AlertDescriptionName = %q", got)
	}
	if got := HandshakeTypeName(HandshakeType(99)); got != "UNKNOWN(99)" {
		t.Errorf("HandshakeTypeName = %q", got)
	}
	if got := ContentTypeName(ContentType(99)); got != "UNKNOWN(99)" {
		t.Errorf("ContentTypeName = %q", got)
	}
	if got := CompressionMethodName(99); got != "UNKNOWN(99)" {
		t.Errorf("CompressionMethodName = %q", got)
	}
	if got := ECPointFormatName(99); got != "UNKNOWN(99)" {
		t.Errorf("ECPointFormatName = %q", got)
	}
	if got := PSKKeyExchangeModeName(99); got != "UNKNOWN(99)" {
		t.Errorf("PSKKeyExchangeModeName = %q", got)
	}
	if got := AlertLevelName(99); got != "UNKNOWN(99)" {
		t.Errorf("AlertLevelName = %q", got)
	}
}

func TestGREASE(t *testing.T) {
	for _, v := range []uint16{0x0A0A, 0x1A1A, 0x2A2A, 0x3A3A, 0x4A4A, 0x5A5A, 0x6A6A, 0x7A7A,
		0x8A8A, 0x9A9A, 0xAAAA, 0xBABA, 0xCACA, 0xDADA, 0xEAEA, 0xFAFA} {
		if !IsGREASE(v) {
			t.Errorf("IsGREASE(0x%04X) = false", v)
		}
		if got := CipherSuiteName(v); !strings.HasPrefix(got, "GREASE") {
			t.Errorf("CipherSuiteName(0x%04X) = %q, want a GREASE label", v, got)
		}
	}
	for _, v := range []uint16{0x0A0B, 0x1A2A, 0xC0AE, 0x1301, 0x0000} {
		if IsGREASE(v) {
			t.Errorf("IsGREASE(0x%04X) = true", v)
		}
	}
}

// TestIsSCSV pins the two signalling values apart from real cipher suites.
// They ARE in the IANA registry — KnownCipherSuite says so, and that is
// correct — but RFC 5746 §3.3 and RFC 7507 §3 both say they are not cipher
// suites and cannot be negotiated, so any census that classifies a codepoint by
// its key exchange has to know to leave them out.
func TestIsSCSV(t *testing.T) {
	if SCSVEmptyRenegotiationInfo != 0x00FF || SCSVFallback != 0x5600 {
		t.Fatalf("the SCSV codepoints moved: 0x%04X / 0x%04X", SCSVEmptyRenegotiationInfo, SCSVFallback)
	}
	for _, v := range []uint16{SCSVEmptyRenegotiationInfo, SCSVFallback} {
		if !IsSCSV(v) {
			t.Errorf("IsSCSV(0x%04X) = false", v)
		}
		if !KnownCipherSuite(v) {
			t.Errorf("0x%04X is a registered codepoint and must stay in the transcription", v)
		}
	}
	// Neighbours, real suites and a GREASE value must all be excluded.
	for _, v := range []uint16{0xC0AE, 0x1301, 0xCCA9, 0x00FE, 0x0100, 0x5601, 0x55FF, 0x0A0A} {
		if IsSCSV(v) {
			t.Errorf("IsSCSV(0x%04X) = true", v)
		}
	}
}

func TestVersionAndGroupNames(t *testing.T) {
	for _, tc := range []struct {
		v    uint16
		want string
	}{
		{0x0301, "TLS 1.0"}, {0x0302, "TLS 1.1"}, {0x0303, "TLS 1.2"},
		{0x0304, "TLS 1.3"}, {0x0300, "SSL 3.0"}, {0xFEFD, "DTLS 1.2"},
	} {
		if got := VersionName(tc.v); got != tc.want {
			t.Errorf("VersionName(0x%04X) = %q, want %q", tc.v, got, tc.want)
		}
	}
	for _, tc := range []struct {
		g    uint16
		want string
	}{
		{23, "secp256r1"}, {24, "secp384r1"}, {25, "secp521r1"},
		{29, "x25519"}, {30, "x448"}, {256, "ffdhe2048"}, {4588, "X25519MLKEM768"},
	} {
		if got := NamedGroupName(tc.g); got != tc.want {
			t.Errorf("NamedGroupName(%d) = %q, want %q", tc.g, got, tc.want)
		}
	}
	for _, tc := range []struct {
		s    uint16
		want string
	}{
		{0x0403, "ecdsa_secp256r1_sha256"},
		{0x0804, "rsa_pss_rsae_sha256"},
		{0x0201, "rsa_pkcs1_sha1"},
		{0x0807, "ed25519"},
	} {
		if got := SignatureSchemeName(tc.s); got != tc.want {
			t.Errorf("SignatureSchemeName(0x%04X) = %q, want %q", tc.s, got, tc.want)
		}
	}
}

func TestAlertNames(t *testing.T) {
	for _, tc := range []struct {
		d    uint8
		want string
	}{
		{0, "close_notify"}, {40, "handshake_failure"}, {42, "bad_certificate"},
		{48, "unknown_ca"}, {80, "internal_error"}, {116, "certificate_required"},
	} {
		if got := AlertDescriptionName(tc.d); got != tc.want {
			t.Errorf("AlertDescriptionName(%d) = %q, want %q", tc.d, got, tc.want)
		}
	}
	if AlertLevelName(1) != "warning" || AlertLevelName(2) != "fatal" {
		t.Error("alert level names are wrong")
	}
}

func TestMaxFragmentLengthCodepoints(t *testing.T) {
	for code, want := range map[uint8]int{1: 512, 2: 1024, 3: 2048, 4: 4096} {
		got, ok := MaxFragmentLengthBytes(code)
		if !ok || got != want {
			t.Errorf("MaxFragmentLengthBytes(%d) = %d,%t; want %d,true", code, got, ok, want)
		}
	}
	for _, bad := range []uint8{0, 5, 255} {
		if _, ok := MaxFragmentLengthBytes(bad); ok {
			t.Errorf("MaxFragmentLengthBytes(%d) accepted an out-of-range codepoint", bad)
		}
	}
}

// TestSuiteTableIntegrity guards against transcription slips in a table nobody
// reads end to end: no two codepoints may share a name, and every name must
// look like an IANA registry entry.
func TestSuiteTableIntegrity(t *testing.T) {
	seen := make(map[string]uint16, len(cipherSuites))
	for id, name := range cipherSuites {
		if prev, dup := seen[name]; dup {
			t.Errorf("name %q is used by both 0x%04X and 0x%04X", name, prev, id)
		}
		seen[name] = id
		if !strings.HasPrefix(name, "TLS_") {
			t.Errorf("0x%04X = %q does not look like an IANA suite name", id, name)
		}
		if strings.Contains(name, "-") {
			t.Errorf("0x%04X = %q looks like an OpenSSL spelling, not the IANA name", id, name)
		}
	}
	if len(cipherSuites) < 150 {
		t.Errorf("the suite table has only %d entries; the registry ranges in play are larger", len(cipherSuites))
	}
	for _, must := range []uint16{0x1301, 0x1302, 0x1303, 0x1304, 0x1305} {
		if !KnownCipherSuite(must) {
			t.Errorf("TLS 1.3 suite 0x%04X is missing from the table", must)
		}
	}
}

func TestExtensionNaming(t *testing.T) {
	e := Extension{Type: ExtRenegotiationInfo}
	if e.Name() != "renegotiation_info" {
		t.Errorf("Name() = %q", e.Name())
	}
	exts := []Extension{{Type: ExtServerName}, {Type: ExtKeyShare}}
	if got := ExtensionNames(exts); got[0] != "server_name" || got[1] != "key_share" {
		t.Errorf("ExtensionNames = %v", got)
	}
	if got := ExtensionTypes(exts); got[0] != 0 || got[1] != 51 {
		t.Errorf("ExtensionTypes = %v", got)
	}
	if _, ok := findExtension(exts, ExtALPN); ok {
		t.Error("findExtension found an absent extension")
	}
}
