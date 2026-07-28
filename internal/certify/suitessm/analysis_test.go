package suitessm

// analysis_test.go proves the suite's teeth.
//
// Every function in analysis.go is fed a NON-CONFORMANT input and required to
// say FAIL, and a conformant one and required to say PASS. That is the whole
// point: a conformance tool that only ever sees a conformant DUT has never
// demonstrated that it can detect a non-conformant one, and its PASS rows mean
// nothing. None of these tests opens a socket or reads the bench.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"strings"
	"testing"
	"time"

	"csip-tls-test/internal/certify"
	"csip-tls-test/internal/evidence/tlsdis"
)

// ── helpers ─────────────────────────────────────────────────────────────────

// testCA mints a throwaway root, exactly as sim/ssm-conformance's loopback
// tests do, so nothing here depends on certs/mbaps being present.
func testCA(t *testing.T, cn string) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c, key
}

// certMessage wraps DER chains into the tlsdis.Certificate a check would see.
func certMessage(t *testing.T, ders ...[]byte) *tlsdis.Certificate {
	t.Helper()
	c := &tlsdis.Certificate{}
	for _, der := range ders {
		info, err := tlsdis.ParseCertInfo(der)
		if err != nil {
			t.Fatalf("the test's own certificate does not parse: %v", err)
		}
		c.Entries = append(c.Entries, tlsdis.CertEntry{DER: der, Info: info})
	}
	return c
}

func dirWith(msgs ...tlsdis.HandshakeMessage) *tlsdis.Direction {
	return &tlsdis.Direction{
		Stream:    &tlsdis.RecordStream{},
		Handshake: &tlsdis.HandshakeStream{Messages: msgs},
	}
}

func serverHelloMsg(sh *tlsdis.ServerHello) tlsdis.HandshakeMessage {
	return tlsdis.HandshakeMessage{Type: tlsdis.HandshakeServerHello, ServerHello: sh}
}

// ── cipher-suite policy ─────────────────────────────────────────────────────

func TestSelectedSuiteRejectsTheWrongSuiteAndTheMissingHello(t *testing.T) {
	sh := &tlsdis.ServerHello{LegacyVersion: tlsdis.VersionTLS12, CipherSuite: suiteECDHE_ECDSA_AES128_GCM_SHA256}
	if v, obs := selectedSuiteFromHello(sh, suiteECDHE_ECDSA_AES128_GCM_SHA256, ""); v != certify.Pass {
		t.Errorf("a matching selection is %s: %s", v, obs)
	}
	// A DUT that ignores the offer and picks its own favourite.
	if v, obs := selectedSuiteFromHello(sh, suiteECDHE_ECDSA_AES128_CCM_8, ""); v != certify.Fail {
		t.Errorf("a MISMATCHED selection must FAIL, got %s: %s", v, obs)
	} else if !strings.Contains(obs, "0xC0AE") {
		t.Errorf("the observation must name the suite that was wanted: %q", obs)
	}
	// A DUT that answers nothing.
	if v, _ := selectedSuiteFromHello(nil, suiteECDHE_ECDSA_AES128_GCM_SHA256, "the peer closed"); v != certify.Fail {
		t.Errorf("no ServerHello must FAIL, got %s", v)
	}
}

func TestRefusalFromDirectionAcceptsEveryConformantRefusalAndOnlyThose(t *testing.T) {
	fatal := &tlsdis.Direction{
		Stream:    &tlsdis.RecordStream{},
		Handshake: &tlsdis.HandshakeStream{},
		Alerts:    []tlsdis.Alert{{Level: 2, Description: 40}},
	}
	if v, obs := refusalFromDirection(fatal, "a provocation", ""); v != certify.Pass {
		t.Errorf("a fatal alert is a conformant refusal, got %s: %s", v, obs)
	}

	silent := dirWith()
	if v, _ := refusalFromDirection(silent, "a provocation", "nothing arrived"); v != certify.Pass {
		t.Errorf("closing with no ServerHello is a conformant refusal, got %s", v)
	}

	warning := &tlsdis.Direction{
		Stream:    &tlsdis.RecordStream{},
		Handshake: &tlsdis.HandshakeStream{},
		Alerts:    []tlsdis.Alert{{Level: 1, Description: 90}},
	}
	if v, _ := refusalFromDirection(warning, "a provocation", ""); v != certify.Warn {
		t.Errorf("a non-fatal alert must WARN rather than pass silently, got %s", v)
	}

	// The failure that matters: the DUT accepted the provocation.
	accepted := dirWith(serverHelloMsg(&tlsdis.ServerHello{
		LegacyVersion: tlsdis.VersionTLS12, CipherSuite: suiteRSA_NULL_SHA,
	}))
	v, obs := refusalFromDirection(accepted, "a NULL-encryption offer", "")
	if v != certify.Fail {
		t.Fatalf("an ACCEPTED provocation must FAIL, got %s: %s", v, obs)
	}
	if !strings.Contains(obs, "ACCEPTED") {
		t.Errorf("the observation must say the provocation was accepted: %q", obs)
	}
}

func TestNullEncryptionSetIsBroaderThanTheFourCodepointsTheProcedureNames(t *testing.T) {
	offer := nullEncryptionOffer()
	for _, named := range []uint16{0x0001, 0x0002, 0xC001, 0xC002} {
		if named == 0xC002 {
			continue // 0xC002 is TLS_ECDH_ECDSA_WITH_RC4_128_SHA, not a NULL suite
		}
		found := false
		for _, id := range offer {
			if id == named {
				found = true
			}
		}
		if !found {
			t.Errorf("the offer omits 0x%04X, which CRYP-007 names explicitly", named)
		}
	}
	if len(offer) < 10 {
		t.Errorf("the offer is %d suites; CRYP-007's own notes say the four it prints are not exhaustive", len(offer))
	}
	if nulls := nullSuitesIn([]uint16{suiteECDHE_ECDSA_AES128_GCM_SHA256}); len(nulls) != 0 {
		t.Errorf("a mandated AEAD suite was classified as NULL-encryption: %v", nulls)
	}
	if nulls := nullSuitesIn([]uint16{suiteECDHE_ECDSA_AES128_GCM_SHA256, 0xC006}); len(nulls) != 1 {
		t.Errorf("a NULL suite hidden among conformant ones must be found: %v", nulls)
	}
}

func TestWeakSignatureAlgorithmsFindsTheExactCodesTheProcedureNames(t *testing.T) {
	got := weakSignatureAlgorithms([]uint16{sigECDSAP256SHA256, sigECDSASHA1, sigRSAMD5})
	if len(got) != 2 {
		t.Fatalf("expected (sha1, ecdsa) and (md5, rsa) to be flagged, got %v", got)
	}
	if len(weakSignatureAlgorithms([]uint16{sigECDSAP256SHA256, sigRSAPSSSHA256})) != 0 {
		t.Error("a conformant signature_algorithms list must produce no findings")
	}
}

func TestCertificateBasedSuiteClassification(t *testing.T) {
	for _, tc := range []struct {
		id   uint16
		want bool
	}{
		{suiteECDHE_ECDSA_AES128_GCM_SHA256, true},
		{suiteTLS13_AES128_GCM_SHA256, true},
		{0x008C, false}, // TLS_PSK_WITH_AES_128_CBC_SHA
		{0xFAFA, false}, // unregistered
	} {
		got, why := certificateBasedSuite(tc.id)
		if got != tc.want {
			t.Errorf("0x%04X: certificate-based = %t, want %t (%s)", tc.id, got, tc.want, why)
		}
	}
}

func TestSHA256PRFSuiteKnowsCCM8DespiteItsName(t *testing.T) {
	if !sha256PRFSuite(suiteECDHE_ECDSA_AES128_CCM_8) {
		t.Error("RFC 6655 fixes the CCM-8 suite's PRF at SHA-256 even though its name does not say so")
	}
	if sha256PRFSuite(suiteRSA_AES128_CBC_SHA) {
		t.Error("a SHA-1 suite must not be reported as SHA-256 PRF")
	}
}

// ── certificate policy ──────────────────────────────────────────────────────

func TestChainDeliveryFailsALeafOnlyAndASelfSignedChain(t *testing.T) {
	root, rootKey := testCA(t, "ssm-test-root")
	leaf, err := mintLeaf(root, rootKey, mintOpts{CommonName: "leaf", Role: "ReadOnlySunSpec"})
	if err != nil {
		t.Fatal(err)
	}

	full := certMessage(t, leaf.Certificate[0], root.Raw)
	if v, obs := chainDelivery(full, "EUT-S"); v != certify.Pass {
		t.Errorf("leaf + issuing CA must PASS, got %s: %s", v, obs)
	}

	leafOnly := certMessage(t, leaf.Certificate[0])
	v, obs := chainDelivery(leafOnly, "EUT-S")
	if v != certify.Fail {
		t.Fatalf("a leaf with no intermediate must FAIL SunSpecTCP-51, got %s: %s", v, obs)
	}
	if !strings.Contains(obs, "only its leaf") {
		t.Errorf("the observation must say what was missing: %q", obs)
	}

	selfSigned, err := mintLeaf(nil, nil, mintOpts{CommonName: "self", SelfSigned: true})
	if err != nil {
		t.Fatal(err)
	}
	if v, _ := chainDelivery(certMessage(t, selfSigned.Certificate[0]), "EUT-S"); v != certify.Fail {
		t.Errorf("a lone self-signed certificate must FAIL, got %s", v)
	}
	if v, _ := chainDelivery(nil, "EUT-S"); v != certify.Fail {
		t.Error("an absent Certificate message must FAIL")
	}
}

func TestRFC5280FindingsCatchEachRequiredField(t *testing.T) {
	root, rootKey := testCA(t, "ssm-test-root")
	good, err := mintLeaf(root, rootKey, mintOpts{CommonName: "conformant", Role: "ReadOnlySunSpec"})
	if err != nil {
		t.Fatal(err)
	}
	info, err := tlsdis.ParseCertInfo(good.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if f := rfc5280Findings(info, true); len(f) != 0 {
		t.Fatalf("a conformant leaf produced findings: %v", f)
	}

	// A leaf with no KeyUsage, no BasicConstraints and no SKI — the profile
	// violations PKI-007 names.
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	bare := &x509.Certificate{
		SerialNumber: big.NewInt(7),
		Subject:      pkix.Name{CommonName: "bare"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, bare, root, &key.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	bi, err := tlsdis.ParseCertInfo(der)
	if err != nil {
		t.Fatal(err)
	}
	findings := rfc5280Findings(bi, true)
	joined := strings.Join(findings, " | ")
	for _, want := range []string{"KeyUsage", "BasicConstraints", "SubjectKeyIdentifier"} {
		if !strings.Contains(joined, want) {
			t.Errorf("a certificate missing %s produced no finding about it: %v", want, findings)
		}
	}

	// A whole-chain verdict must fail when any member fails.
	if v, _ := certProfileVerdict(certMessage(t, der, root.Raw), "EUT-S"); v != certify.Fail {
		t.Error("a chain containing a non-conformant certificate must FAIL")
	}
	if v, obs := certProfileVerdict(certMessage(t, good.Certificate[0], root.Raw), "EUT-S"); v != certify.Pass {
		t.Errorf("a conformant chain must PASS: %s", obs)
	}
}

func TestRoleExtensionVerdictDistinguishesAbsentWrongOIDAndBadEncoding(t *testing.T) {
	root, rootKey := testCA(t, "ssm-test-root")

	good, err := mintLeaf(root, rootKey, mintOpts{CommonName: "good", Role: "ReadOnlySunSpec"})
	if err != nil {
		t.Fatal(err)
	}
	gi, _ := tlsdis.ParseCertInfo(good.Certificate[0])
	if v, obs := roleExtensionVerdict(gi, "ReadOnlySunSpec"); v != certify.Pass {
		t.Errorf("the mandated encoding must PASS, got %s: %s", v, obs)
	}
	if v, _ := roleExtensionVerdict(gi, "SuperAdministratorSunSpec"); v != certify.Fail {
		t.Error("the wrong role value must FAIL")
	}

	none, err := mintLeaf(root, rootKey, mintOpts{CommonName: "none"})
	if err != nil {
		t.Fatal(err)
	}
	ni, _ := tlsdis.ParseCertInfo(none.Certificate[0])
	if v, obs := roleExtensionVerdict(ni, ""); v != certify.Fail {
		t.Errorf("a certificate with no role extension must FAIL, got %s: %s", v, obs)
	}

	wrongOID, err := mintLeaf(root, rootKey, mintOpts{
		CommonName: "wrong-oid", Role: "ReadOnlySunSpec", RoleOID: wrongRoleOIDValue,
	})
	if err != nil {
		t.Fatal(err)
	}
	wi, _ := tlsdis.ParseCertInfo(wrongOID.Certificate[0])
	v, obs := roleExtensionVerdict(wi, "")
	if v != certify.Fail {
		t.Fatalf("a role under a non-compliant OID must FAIL, got %s", v)
	}
	if !strings.Contains(obs, wrongRoleOIDValue.String()) {
		t.Errorf("the observation must name the OID that WAS present: %q", obs)
	}

	ia5, err := mintLeaf(root, rootKey, mintOpts{
		CommonName: "ia5", Role: "ReadOnlySunSpec", RoleTag: tagIA5String,
	})
	if err != nil {
		t.Fatal(err)
	}
	ii, _ := tlsdis.ParseCertInfo(ia5.Certificate[0])
	if v, obs := roleExtensionVerdict(ii, ""); v != certify.Fail {
		t.Errorf("an IA5String-encoded role must FAIL SunSpecTCP-30, got %s: %s", v, obs)
	}

	// Two role extensions at the same OID: SunSpecTCP-31.
	two, err := mintLeaf(root, rootKey, mintOpts{
		CommonName: "two", Role: "ReadOnlySunSpec",
		ExtraExtensions: []pkix.Extension{roleExtension(roleOIDValue, "SuperAdministratorSunSpec", tagUTF8String)},
	})
	if err != nil {
		t.Fatal(err)
	}
	// crypto/x509 refuses a certificate with duplicate extension OIDs, which is
	// precisely why tlsdis walks the extensions itself; ParseCertInfo therefore
	// returns both a populated CertInfo and an error here, and the role verdict
	// must still be reached from the extension walk.
	ti, tiErr := tlsdis.ParseCertInfo(two.Certificate[0])
	if tiErr == nil {
		t.Log("note: crypto/x509 accepted the duplicate-OID fixture in this Go version")
	}
	v, obs = roleExtensionVerdict(ti, "ReadOnlySunSpec")
	if v != certify.Fail {
		t.Errorf("two role extensions must FAIL SunSpecTCP-31, got %s: %s", v, obs)
	}
	if !strings.Contains(obs, "does not decode as a single ASN.1 UTF8String") {
		t.Errorf("the observation must say the encoding rule that was broken: %q", obs)
	}
}

func TestCASignedVerdictCatchesASelfSignedLeaf(t *testing.T) {
	root, rootKey := testCA(t, "ssm-test-root")
	ca, err := mintLeaf(root, rootKey, mintOpts{CommonName: "ca-signed", Role: "ReadOnlySunSpec"})
	if err != nil {
		t.Fatal(err)
	}
	if v, obs := caSignedVerdict(certMessage(t, ca.Certificate[0], root.Raw), "bench"); v != certify.Pass {
		t.Errorf("a CA-signed leaf must PASS, got %s: %s", v, obs)
	}
	self, err := mintLeaf(nil, nil, mintOpts{CommonName: "self", Role: "ReadOnlySunSpec", SelfSigned: true})
	if err != nil {
		t.Fatal(err)
	}
	v, obs := caSignedVerdict(certMessage(t, self.Certificate[0]), "bench")
	if v != certify.Fail {
		t.Fatalf("a self-signed leaf must FAIL SunSpecTCP-50, got %s: %s", v, obs)
	}
	if !strings.Contains(obs, "self-signed") {
		t.Errorf("the observation must say so: %q", obs)
	}
}

func TestCorruptSignatureChangesOnlyTheSignature(t *testing.T) {
	root, rootKey := testCA(t, "ssm-test-root")
	good, err := mintLeaf(root, rootKey, mintOpts{CommonName: "good", Role: "ReadOnlySunSpec"})
	if err != nil {
		t.Fatal(err)
	}
	bad, err := corruptSignature(good)
	if err != nil {
		t.Fatal(err)
	}
	if len(bad.Certificate) != len(good.Certificate) {
		t.Fatalf("the chain length changed: %d vs %d", len(bad.Certificate), len(good.Certificate))
	}
	badLeaf, err := x509.ParseCertificate(bad.Certificate[0])
	if err != nil {
		t.Fatalf("the corrupted certificate must still PARSE — only its signature may be wrong: %v", err)
	}
	goodLeaf, _ := x509.ParseCertificate(good.Certificate[0])
	if !badLeaf.Equal(goodLeaf) && string(badLeaf.RawTBSCertificate) != string(goodLeaf.RawTBSCertificate) {
		t.Error("the tbsCertificate must be untouched, so the signature is the only thing wrong")
	}
	if err := badLeaf.CheckSignatureFrom(root); err == nil {
		t.Fatal("the corrupted certificate still verifies against its issuer — the fixture proves nothing")
	}
	if err := goodLeaf.CheckSignatureFrom(root); err != nil {
		t.Fatalf("the uncorrupted control does not verify: %v", err)
	}
}

// ── extension policy ────────────────────────────────────────────────────────

func TestCompressionVerdict(t *testing.T) {
	if v, _ := compressionVerdict(&tlsdis.ClientHello{CompressionMethods: []uint8{0}}, "the gateway's"); v != certify.Pass {
		t.Error("NULL-only compression must PASS")
	}
	v, obs := compressionVerdict(&tlsdis.ClientHello{CompressionMethods: []uint8{1, 0}}, "the gateway's")
	if v != certify.Fail {
		t.Fatalf("offering DEFLATE must FAIL SunSpecTCP-61, got %s: %s", v, obs)
	}
	if !strings.Contains(obs, "CRIME") {
		t.Errorf("the observation should say why it matters: %q", obs)
	}
	if v, _ := compressionVerdict(&tlsdis.ClientHello{}, "the gateway's"); v != certify.Fail {
		t.Error("an empty compression_methods field is not a legal encoding and must FAIL")
	}
	if v, _ := compressionVerdict(nil, "the gateway's"); v != certify.Skip {
		t.Error("no observed hello must SKIP, not pass")
	}
}

func TestSupportedGroupsVerdict(t *testing.T) {
	ok := &tlsdis.ClientHello{
		SupportedGroups: []uint16{groupSecp256r1},
		Extensions: []tlsdis.Extension{
			{Type: tlsdis.ExtSupportedGroups}, {Type: tlsdis.ExtECPointFormats},
		},
	}
	if v, obs := supportedGroupsVerdict(ok, "the bench's"); v != certify.Pass {
		t.Errorf("P-256 plus point formats must PASS: %s (%s)", v, obs)
	}
	noP256 := &tlsdis.ClientHello{
		SupportedGroups: []uint16{groupSecp384r1},
		Extensions: []tlsdis.Extension{
			{Type: tlsdis.ExtSupportedGroups}, {Type: tlsdis.ExtECPointFormats},
		},
	}
	if v, obs := supportedGroupsVerdict(noP256, "the bench's"); v != certify.Fail {
		t.Errorf("a hello without secp256r1 must FAIL: %s (%s)", v, obs)
	}
	noPointFmt := &tlsdis.ClientHello{
		SupportedGroups: []uint16{groupSecp256r1},
		Extensions:      []tlsdis.Extension{{Type: tlsdis.ExtSupportedGroups}},
	}
	if v, _ := supportedGroupsVerdict(noPointFmt, "the bench's"); v != certify.Fail {
		t.Error("a missing ec_point_formats extension must FAIL RFC 4492 §5.1.2")
	}
}

func TestServerKeyExchangeCurveDecoding(t *testing.T) {
	// curve_type = named_curve (3), NamedCurve = secp256r1 (0x0017).
	if v, obs := serverCurveVerdict([]byte{3, 0x00, 0x17, 0x41}, groupSecp256r1); v != certify.Pass {
		t.Errorf("a P-256 ServerKeyExchange must PASS: %s (%s)", v, obs)
	}
	if v, obs := serverCurveVerdict([]byte{3, 0x00, 0x18}, groupSecp256r1); v != certify.Fail {
		t.Errorf("a P-384 key exchange must FAIL the P-256 criterion: %s (%s)", v, obs)
	}
	// curve_type = explicit_prime (1): no NamedCurve is asserted at all.
	if v, _ := serverCurveVerdict([]byte{1, 0x00, 0x17}, groupSecp256r1); v != certify.Fail {
		t.Error("a non-named curve_type must FAIL")
	}
	if v, _ := serverCurveVerdict(nil, groupSecp256r1); v != certify.Skip {
		t.Error("no ServerKeyExchange (TLS 1.3) must SKIP with the reason, not FAIL")
	}
}

func TestMFLEchoVerdict(t *testing.T) {
	code := mflCode512
	if v, obs := mflEchoVerdict(&tlsdis.ServerHello{MaxFragmentLength: &code}, mflCode512); v != certify.Pass {
		t.Errorf("an echoed code 1 must PASS: %s (%s)", v, obs)
	}
	other := uint8(4)
	v, obs := mflEchoVerdict(&tlsdis.ServerHello{MaxFragmentLength: &other}, mflCode512)
	if v != certify.Fail {
		t.Fatalf("echoing a DIFFERENT code must FAIL: %s (%s)", v, obs)
	}
	if v, obs := mflEchoVerdict(&tlsdis.ServerHello{}, mflCode512); v != certify.Fail {
		t.Errorf("no echo at all must FAIL SunSpecTCP-59/60: %s (%s)", v, obs)
	}
}

// TestRenegotiationInfoVerdict covers the SERVER half, where RFC 5746 §3.6
// allows exactly one wire form. The SCSV is a client signal — §3.3 says it
// "cannot be negotiated" — so there is no second form to admit here, and
// accepting one would be accepting a ServerHello no conformant server sends.
func TestRenegotiationInfoVerdict(t *testing.T) {
	if v, _ := renegotiationInfoVerdict(&tlsdis.ServerHello{HasRenegotiationInfo: true}); v != certify.Pass {
		t.Error("an empty renegotiation_info on an initial handshake must PASS")
	}
	if v, _ := renegotiationInfoVerdict(&tlsdis.ServerHello{}); v != certify.Fail {
		t.Error("a missing renegotiation_info must FAIL SunSpecTCP-62")
	}
	nonEmpty := &tlsdis.ServerHello{HasRenegotiationInfo: true, RenegotiationInfo: []byte{1, 2, 3}}
	if v, _ := renegotiationInfoVerdict(nonEmpty); v != certify.Warn {
		t.Error("a non-empty renegotiated_connection on an INITIAL handshake violates RFC 5746 §3.6 and must WARN")
	}
	// A ServerHello that SELECTED the SCSV is non-conformant, not exempt: both
	// RFC 5746 §3.3 and RFC 7507 §3 forbid negotiating a signalling value.
	if ok, _ := certificateBasedSuite(tlsdis.SCSVEmptyRenegotiationInfo); ok {
		t.Error("a negotiated TLS_EMPTY_RENEGOTIATION_INFO_SCSV must not be classified as a valid " +
			"certificate-based suite: it cannot be negotiated at all")
	}
}

// TestRenegotiationIndicationVerdict covers the CLIENT half, where RFC 5746
// §3.4 admits TWO wire forms and lets the client choose:
//
//	"The client MUST include either an empty 'renegotiation_info' extension,
//	 or the TLS_EMPTY_RENEGOTIATION_INFO_SCSV signaling cipher suite value in
//	 the ClientHello. Including both is NOT RECOMMENDED."
//
// Both are exercised because the bench has seen both: a wolfSSL-linked gateway
// sends the extension, a mbed TLS-linked one signals with the SCSV, and a check
// that knew only the first would report a library migration as a SunSpecTCP-62
// regression.
func TestRenegotiationIndicationVerdict(t *testing.T) {
	// Form 1 — the empty extension (wolfSSL's default).
	ext := &tlsdis.ClientHello{HasRenegotiationInfo: true, CipherSuites: mandated12}
	if v, obs := renegotiationIndicationVerdict(ext, "the DUT's"); v != certify.Pass {
		t.Errorf("the empty renegotiation_info extension must PASS: %s (%s)", v, obs)
	}

	// Form 2 — the SCSV and NO extension (mbed TLS's default). This is the
	// regression the migration would have produced.
	scsv := &tlsdis.ClientHello{
		CipherSuites: append([]uint16{tlsdis.SCSVEmptyRenegotiationInfo}, mandated12...),
	}
	v, obs := renegotiationIndicationVerdict(scsv, "the DUT's")
	if v != certify.Pass {
		t.Errorf("TLS_EMPTY_RENEGOTIATION_INFO_SCSV alone must PASS SunSpecTCP-62 — RFC 5746 §3.4 "+
			"admits it as an alternative to the extension: %s (%s)", v, obs)
	}
	if !strings.Contains(obs, "0x00FF") {
		t.Errorf("the observation does not name the codepoint it rests on: %q", obs)
	}

	// Both — NOT RECOMMENDED by §3.4, but the indication is unambiguously there.
	both := &tlsdis.ClientHello{
		HasRenegotiationInfo: true,
		CipherSuites:         append([]uint16{tlsdis.SCSVEmptyRenegotiationInfo}, mandated12...),
	}
	if v, obs := renegotiationIndicationVerdict(both, "the DUT's"); v != certify.Pass {
		t.Errorf("both forms present must still PASS: %s (%s)", v, obs)
	}

	// Neither — the only failing case.
	none := &tlsdis.ClientHello{CipherSuites: mandated12}
	if v, obs := renegotiationIndicationVerdict(none, "the DUT's"); v != certify.Fail {
		t.Errorf("neither form present must FAIL SunSpecTCP-62: %s (%s)", v, obs)
	}
	if v, _ := renegotiationIndicationVerdict(nil, "the DUT's"); v != certify.Fail {
		t.Error("no ClientHello at all must FAIL, not pass by absence")
	}

	// A non-empty renegotiated_connection on an initial hello is a §3.4
	// violation of its own, and must not be laundered into a PASS.
	dirty := &tlsdis.ClientHello{
		HasRenegotiationInfo: true, RenegotiationInfo: []byte{1, 2, 3}, CipherSuites: mandated12,
	}
	if v, obs := renegotiationIndicationVerdict(dirty, "the DUT's"); v != certify.Warn {
		t.Errorf("a non-empty renegotiated_connection on an initial ClientHello must WARN: %s (%s)", v, obs)
	}
}

// TestOfferedSuiteCensusExcludesSignallingValues pins the other half of the
// SCSV problem. CRYP-006's client census asks "is every offered suite
// certificate-based?", and an SCSV has no key exchange to answer with — so
// before this rule a mbed TLS gateway failed SunSpecTCP-15/16 for providing the
// SunSpecTCP-62 indication in the form RFC 5746 §3.4 allows.
func TestOfferedSuiteCensusExcludesSignallingValues(t *testing.T) {
	withSCSV := &tlsdis.ClientHello{
		CipherSuites: append([]uint16{tlsdis.SCSVEmptyRenegotiationInfo, tlsdis.SCSVFallback}, mandated12...),
	}
	v, obs := offeredSuiteCensusVerdict(withSCSV, "gateway")
	if v != certify.Pass {
		t.Fatalf("signalling values must not fail the certificate-based census: %s (%s)", v, obs)
	}
	if !strings.Contains(obs, "SIGNALLING") {
		t.Errorf("the excluded codepoints are not reported to the reviewer: %q", obs)
	}

	// The census must still have teeth: a genuinely anonymous suite fails.
	anon := &tlsdis.ClientHello{
		CipherSuites: append([]uint16{tlsdis.SCSVEmptyRenegotiationInfo, 0x0034}, mandated12...),
	}
	if v, obs := offeredSuiteCensusVerdict(anon, "gateway"); v != certify.Fail {
		t.Errorf("TLS_DH_anon_WITH_AES_128_CBC_SHA offered alongside an SCSV must still FAIL: %s (%s)", v, obs)
	}
	if v, _ := offeredSuiteCensusVerdict(nil, "gateway"); v != certify.Fail {
		t.Error("no ClientHello at all must FAIL, not pass by absence")
	}
}

func TestCertificateRequestVerdict(t *testing.T) {
	good := &tlsdis.CertificateRequest{
		CertificateTypes:    []uint8{64},
		SignatureAlgorithms: []uint16{sigECDSAP256SHA256},
	}
	if v, obs := certificateRequestVerdict(good); v != certify.Pass {
		t.Errorf("a well-formed CertificateRequest must PASS: %s (%s)", v, obs)
	}
	if v, _ := certificateRequestVerdict(nil); v != certify.Fail {
		t.Error("no CertificateRequest means no mutual authentication and must FAIL SunSpecTCP-11")
	}
	if v, _ := certificateRequestVerdict(&tlsdis.CertificateRequest{SignatureAlgorithms: []uint16{sigECDSAP256SHA256}}); v != certify.Fail {
		t.Error("an empty certificate_types must FAIL")
	}
	if v, _ := certificateRequestVerdict(&tlsdis.CertificateRequest{CertificateTypes: []uint8{64}}); v != certify.Fail {
		t.Error("an empty supported_signature_algorithms must FAIL for TLS 1.2")
	}
}

func TestServerFlightVerdictRequiresTheExactOrder(t *testing.T) {
	ordered := []tlsdis.HandshakeType{
		tlsdis.HandshakeServerHello, tlsdis.HandshakeCertificate, tlsdis.HandshakeServerKeyExchange,
		tlsdis.HandshakeCertificateRequest, tlsdis.HandshakeServerHelloDone,
	}
	if v, obs := serverFlightVerdict(ordered); v != certify.Pass {
		t.Errorf("the prescribed order must PASS: %s (%s)", v, obs)
	}
	swapped := []tlsdis.HandshakeType{
		tlsdis.HandshakeServerHello, tlsdis.HandshakeCertificate, tlsdis.HandshakeCertificateRequest,
		tlsdis.HandshakeServerKeyExchange, tlsdis.HandshakeServerHelloDone,
	}
	if v, _ := serverFlightVerdict(swapped); v != certify.Fail {
		t.Error("CertificateRequest before ServerKeyExchange must FAIL the ordering criterion")
	}
	noCertReq := []tlsdis.HandshakeType{
		tlsdis.HandshakeServerHello, tlsdis.HandshakeCertificate,
		tlsdis.HandshakeServerKeyExchange, tlsdis.HandshakeServerHelloDone,
	}
	if v, _ := serverFlightVerdict(noCertReq); v != certify.Fail {
		t.Error("a flight with no CertificateRequest must FAIL")
	}
}

func TestAbbreviatedHandshakeVerdictAcceptsBothDocumentedOutcomes(t *testing.T) {
	// RFC 5077 §3.4, and the shape run 20260726T225512 actually captured: a
	// ticket-issuing server sends an EMPTY session id on the initial handshake,
	// the client generates its own for the resumption attempt, and the server
	// echoes THAT one.
	offered := []byte{0x5e, 0xef, 0x32, 0x8f}
	initial := resumptionPair{
		FirstServerHello: &tlsdis.ServerHello{SessionID: nil},
		FirstFlight: []tlsdis.HandshakeType{
			tlsdis.HandshakeServerHello, tlsdis.HandshakeCertificate, tlsdis.HandshakeNewSessionTicket,
		},
	}

	resumed := initial
	resumed.SecondClientHello = &tlsdis.ClientHello{SessionID: offered}
	resumed.SecondServerHello = &tlsdis.ServerHello{SessionID: offered}
	resumed.SecondFlight = []tlsdis.HandshakeType{tlsdis.HandshakeServerHello, tlsdis.HandshakeNewSessionTicket}
	if v, obs := abbreviatedHandshakeVerdict(resumed); v != certify.Pass {
		t.Errorf("a correct RFC 5077 ticket resumption must PASS — the echo is against the SECOND "+
			"ClientHello, not the first ServerHello: %s (%s)", v, obs)
	}

	full := initial
	full.SecondClientHello = &tlsdis.ClientHello{SessionID: offered}
	full.SecondServerHello = &tlsdis.ServerHello{SessionID: []byte{9, 9}}
	full.SecondFlight = []tlsdis.HandshakeType{
		tlsdis.HandshakeServerHello, tlsdis.HandshakeCertificate, tlsdis.HandshakeCertificateRequest,
	}
	if v, obs := abbreviatedHandshakeVerdict(full); v != certify.Pass {
		t.Errorf("falling back to a full handshake is also conformant and must PASS: %s (%s)", v, obs)
	}

	// The one non-conformant shape: skipped the certificate exchange WITHOUT
	// echoing the session id its peer offered.
	bogus := initial
	bogus.SecondClientHello = &tlsdis.ClientHello{SessionID: offered}
	bogus.SecondServerHello = &tlsdis.ServerHello{SessionID: []byte{7, 7}}
	bogus.SecondFlight = []tlsdis.HandshakeType{tlsdis.HandshakeServerHello}
	if v, obs := abbreviatedHandshakeVerdict(bogus); v != certify.Fail {
		t.Errorf("an abbreviated handshake echoing a session id nobody offered must FAIL: %s (%s)", v, obs)
	}

	// And the old defect, pinned: an empty initial ServerHello session id is
	// what a ticket-issuing server is RECOMMENDED to send. It must not, on its
	// own, make a correct resumption fail.
	noCH := resumed
	noCH.SecondClientHello = nil
	if v, _ := abbreviatedHandshakeVerdict(noCH); v != certify.Skip {
		t.Errorf("without the resumption ClientHello there is nothing to compare against; want SKIP, got %s", v)
	}
}

// ── MBAP / Modbus policy ────────────────────────────────────────────────────

func TestParseMBAPRejectsMalformedFrames(t *testing.T) {
	good := []byte{0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0x01, 0x03, 0x00, 0x00, 0x00, 0x02}
	v, err := parseMBAP(good)
	if err != nil {
		t.Fatalf("a well-formed ADU did not parse: %v", err)
	}
	if v.TID != 1 || v.PID != 0 || v.Length != 6 || v.UnitID != 1 || len(v.PDU) != 5 || len(v.Trailing) != 0 {
		t.Errorf("fields decoded wrongly: %s", v)
	}
	if _, err := parseMBAP(good[:6]); err == nil {
		t.Error("a truncated header must be an error, not a guess")
	}
	short := []byte{0, 1, 0, 0, 0, 1, 1, 3}
	if _, err := parseMBAP(short); err == nil {
		t.Error("a Length that cannot cover Unit ID + function code must be an error")
	}
}

func TestMBAPIntegrityVerdictCatchesEveryHeaderDefect(t *testing.T) {
	req := []byte{0x00, 0x2A, 0x00, 0x00, 0x00, 0x06, 0x01, 0x03, 0x9C, 0x40, 0x00, 0x02}
	rsp := []byte{0x00, 0x2A, 0x00, 0x00, 0x00, 0x07, 0x01, 0x03, 0x04, 0x53, 0x75, 0x6E, 0x53}
	if v, obs := mbapIntegrityVerdict(req, rsp); v != certify.Pass {
		t.Fatalf("a conformant exchange must PASS: %s (%s)", v, obs)
	}

	for name, mutate := range map[string]func([]byte) []byte{
		"non-zero Protocol ID": func(b []byte) []byte { c := clone(b); c[2] = 0x01; return c },
		"Transaction ID not echoed": func(b []byte) []byte {
			c := clone(b)
			c[1] = 0x99
			return c
		},
		"Unit ID not echoed": func(b []byte) []byte { c := clone(b); c[6] = 0x05; return c },
		"trailing bytes after the ADU": func(b []byte) []byte {
			return append(clone(b), 0xDE, 0xAD)
		},
	} {
		v, obs := mbapIntegrityVerdict(req, mutate(rsp))
		if v != certify.Fail {
			t.Errorf("%s must FAIL SunSpecTCP-9, got %s: %s", name, v, obs)
		}
	}
}

func clone(b []byte) []byte { return append([]byte(nil), b...) }

func TestExceptionAndNormalResponseVerdicts(t *testing.T) {
	denial := []byte{0x00, 0x01, 0x00, 0x00, 0x00, 0x03, 0x01, 0x90, 0x01}
	if v, obs := exceptionVerdict(denial, 1); v != certify.Pass {
		t.Errorf("an exception-01 denial must PASS the denial criterion: %s (%s)", v, obs)
	}
	if v, _ := exceptionVerdict(denial, 2); v != certify.Fail {
		t.Error("the wrong exception code must FAIL")
	}
	normal := []byte{0x00, 0x01, 0x00, 0x00, 0x00, 0x04, 0x01, 0x03, 0x02, 0x00}
	if v, obs := exceptionVerdict(normal, 1); v != certify.Fail {
		t.Errorf("a NORMAL response where a denial was required must FAIL: %s (%s)", v, obs)
	}
	if v, _ := normalResponseVerdict(normal); v != certify.Pass {
		t.Error("a normal response must PASS the grant criterion")
	}
	if v, _ := normalResponseVerdict(denial); v != certify.Fail {
		t.Error("a denial where a grant was required must FAIL")
	}
}

func TestLeakageVerdictIsExactlyNineBytes(t *testing.T) {
	clean := []byte{0x00, 0x07, 0x00, 0x00, 0x00, 0x03, 0x01, 0x90, 0x01}
	if v, obs := leakageVerdict(clean); v != certify.Pass {
		t.Fatalf("a nine-byte denial must PASS RBAC-009: %s (%s)", v, obs)
	}
	leaky := append(clone(clean), 'n', 'o', 't', ' ', 'a', 'l', 'l', 'o', 'w', 'e', 'd')
	v, obs := leakageVerdict(leaky)
	if v != certify.Fail {
		t.Fatalf("diagnostic text after the exception code must FAIL: %s (%s)", v, obs)
	}
	if !strings.Contains(obs, "follow the exception code") {
		t.Errorf("the observation must name the leaked bytes: %q", obs)
	}
	// A denial padded inside the declared Length is just as much a leak.
	padded := []byte{0x00, 0x07, 0x00, 0x00, 0x00, 0x06, 0x01, 0x90, 0x01, 0xAA, 0xBB, 0xCC}
	if v, _ := leakageVerdict(padded); v != certify.Fail {
		t.Error("a denial whose PDU carries extra bytes must FAIL")
	}
}

func TestTwoRoleVerdictAcceptsBothPermittedOutcomes(t *testing.T) {
	denial := []byte{0x00, 0x01, 0x00, 0x00, 0x00, 0x03, 0x01, 0x83, 0x01}
	normal := []byte{0x00, 0x01, 0x00, 0x00, 0x00, 0x04, 0x01, 0x03, 0x02, 0x00}
	if v, _ := twoRoleVerdict(denial); v != certify.Pass {
		t.Error("a denial is one of the two outcomes SunSpecTCP-31 permits")
	}
	if v, _ := twoRoleVerdict(normal); v != certify.Pass {
		t.Error("a normal response is the other outcome SunSpecTCP-31 permits")
	}
	odd := []byte{0x00, 0x01, 0x00, 0x00, 0x00, 0x03, 0x01, 0x83, 0x02}
	if v, obs := twoRoleVerdict(odd); v != certify.Fail {
		t.Errorf("an exception code other than 01 is neither permitted outcome: %s (%s)", v, obs)
	}
}

func TestOutcomeAndDistinctWritePermissions(t *testing.T) {
	allow := Exchange{Response: []byte{0, 1, 0, 0, 0, 4, 1, 0x10, 0x9C, 0x40}}
	deny := Exchange{Response: []byte{0, 1, 0, 0, 0, 3, 1, 0x90, 0x01}}
	if outcome(allow) != "allow" || outcome(deny) != "deny(1)" {
		t.Fatalf("outcome tokens are %q / %q", outcome(allow), outcome(deny))
	}
	same := []cell{
		{Role: "A", Model: 1, Write: deny}, {Role: "B", Model: 1, Write: deny},
	}
	if n := distinctWritePermissions(same); n != 1 {
		t.Errorf("identical profiles must collapse to one, got %d", n)
	}
	differ := []cell{
		{Role: "A", Model: 704, Write: deny}, {Role: "B", Model: 704, Write: allow},
	}
	if n := distinctWritePermissions(differ); n != 2 {
		t.Errorf("differing profiles must be counted separately, got %d", n)
	}
}

// ── small predicates ────────────────────────────────────────────────────────

func TestInRelativeOrder(t *testing.T) {
	want := mandated12
	if !inRelativeOrder([]uint16{0x00FF, 0xC02B, 0x1301, 0xCCA9, 0xC0AE}, want) {
		t.Error("the mandated suites interleaved with others are still in relative order")
	}
	if inRelativeOrder([]uint16{0xCCA9, 0xC02B, 0xC0AE}, want) {
		t.Error("a reordered list must not be reported as in relative order")
	}
	if inRelativeOrder([]uint16{0xC02B, 0xCCA9}, want) {
		t.Error("a list missing a mandated suite must not pass the ordering check")
	}
}

func TestMissingSuites(t *testing.T) {
	got := missingSuites([]uint16{suiteECDHE_ECDSA_AES128_GCM_SHA256}, mandated12)
	if len(got) != 2 {
		t.Fatalf("two mandated suites are missing, got %v", got)
	}
	if len(missingSuites(mandated12, mandated12)) != 0 {
		t.Error("a complete offer must report nothing missing")
	}
}

func TestRoleOIDConstantsAgree(t *testing.T) {
	if roleOIDValue.String() != roleOID {
		t.Fatalf("the string and ASN.1 forms of the role OID disagree: %q vs %q", roleOIDValue.String(), roleOID)
	}
	if wrongRoleOIDValue.String() == roleOID {
		t.Fatal("the non-compliant OID must differ from the mandated one")
	}
	// The provocation must be a SIBLING arc, so a prefix match would not save
	// a non-conformant implementation.
	if !strings.HasPrefix(wrongRoleOIDValue.String(), "1.3.6.1.4.1.50316.802.") {
		t.Errorf("the non-compliant OID should share the Modbus.org PEN prefix: %s", wrongRoleOIDValue)
	}
	var _ asn1.ObjectIdentifier = roleOIDValue
}

// TestCurveExclusivityIsWarnNotFail pins the CRYP-004 step 7 deviation.
//
// SunSpecTCP-42 requires support for "at least" P-256. A DUT that also supports
// P-384, and completes ECDHE over it when that is all the client offered, has
// done more than the requirement asks and exactly what RFC 4492 §5.1 says to
// do. Run 20260726T225512 reported that as a FAIL against the gateway.
func TestCurveExclusivityIsWarnNotFail(t *testing.T) {
	accepted := certify.Fail
	obs := "the EUT-S ACCEPTED a ClientHello whose supported_groups omitted the mandatory P-256 curve: " +
		"ServerHello selected 0xC02B TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 over TLS 1.2"
	v, got := curveExclusivityVerdict(accepted, obs)
	if v != certify.Warn {
		t.Fatalf("verdict = %s, want WARN: nothing normative requires refusing a non-mandatory curve", v)
	}
	if !strings.Contains(got, "at least") {
		t.Errorf("observation = %q, want it to carry the SunSpecTCP-42 rationale", got)
	}
	if !strings.Contains(got, obs) {
		t.Error("the original observation must survive; the deviation is about the VERDICT, not about hiding what happened")
	}
	// A DUT that really did refuse is still a PASS — refusing is permitted too.
	if v, _ := curveExclusivityVerdict(certify.Pass, "refused"); v != certify.Pass {
		t.Errorf("a genuine refusal must stay PASS, got %s", v)
	}
	if v, _ := curveExclusivityVerdict(certify.Skip, "unreachable"); v != certify.Skip {
		t.Errorf("a SKIP must stay SKIP, got %s", v)
	}
	// And the rationale must name the requirement it rests on, so a lab reading
	// the bundle sees the argument rather than an assertion of authority.
	for _, want := range []string{"SunSpecTCP-42", "AT LEAST", "RFC 4492", "MBR-61"} {
		if !strings.Contains(curveExclusivityRationale, want) {
			t.Errorf("the deviation note does not mention %q", want)
		}
	}
}
