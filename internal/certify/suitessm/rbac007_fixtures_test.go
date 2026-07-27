package suitessm

// rbac007_fixtures_test.go covers the two bench defects that made RBAC-007 a
// FAIL against the gateway in run 20260726T225512, neither of which the DUT had
// anything to do with:
//
//	the ENCODING — §2.7.7.1 step 2 prescribes an IA5String (ASN.1 tag 0x16). The
//	               committed fixture is a PrintableString (0x13), and the check
//	               then failed the DUT for the bench not having presented what
//	               the procedure asked for;
//	the LOADING  — the two-role fixture cannot be read by tls.LoadX509KeyPair,
//	               because crypto/x509 rejects duplicate extension OIDs — which
//	               is exactly the shape SunSpecTCP-31 exists to test. No session
//	               was established, steps 6-9 were never exercised, and the case
//	               reported a FAIL about the device anyway.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"strings"
	"testing"
	"time"
)

// testIssuer mints a throwaway CA to sign the fixtures with.
func testIssuer(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "rbac007 test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert, key
}

// roleExtDER finds the role extension's raw DER value in a leaf, without
// x509.ParseCertificate — the two-role fixture does not parse.
func roleExtDER(t *testing.T, der []byte) []byte {
	t.Helper()
	if cert, err := x509.ParseCertificate(der); err == nil {
		for _, e := range cert.Extensions {
			if e.Id.String() == roleOID {
				return e.Value
			}
		}
		return nil
	}
	return nil
}

// TestIA5RoleFixtureUsesTheTagTheProcedurePrescribes pins ASN.1 tag 0x16.
// PrintableString (0x13) is a different non-conformance and is not what
// §2.7.7.1 step 2 asks the bench to present.
func TestIA5RoleFixtureUsesTheTagTheProcedurePrescribes(t *testing.T) {
	issuer, key := testIssuer(t)
	cert, err := mintLeaf(issuer, key, mintOpts{
		CommonName: "ssm-ia5-role-probe",
		Role:       "GridServiceSunSpec",
		RoleTag:    tagIA5String,
	})
	if err != nil {
		t.Fatalf("mintLeaf: %v", err)
	}
	value := roleExtDER(t, cert.Certificate[0])
	if len(value) == 0 {
		t.Fatal("the minted fixture carries no role extension at " + roleOID)
	}
	if value[0] != tagIA5String {
		t.Fatalf("role extension ASN.1 tag = 0x%02X (%s), want 0x16 (IA5String) — 0x13 PrintableString is a "+
			"different encoding and not the one §2.7.7.1 step 2 prescribes", value[0], asn1TagName(value[0]))
	}
	if got := string(value[2:]); got != "GridServiceSunSpec" {
		t.Errorf("role value = %q", got)
	}
}

// TestTwoRoleFixtureIsPresentableWithoutParsing is the loading half. The
// fixture is deliberately unparseable — two extensions with the same OID — and
// must still reach the wire: crypto/tls presents a hand-built chain with a nil
// Leaf without re-parsing it.
func TestTwoRoleFixtureIsPresentableWithoutParsing(t *testing.T) {
	issuer, key := testIssuer(t)
	cert, err := mintLeaf(issuer, key, mintOpts{
		CommonName: "ssm-two-role-probe",
		Role:       "GridServiceSunSpec",
		ExtraExtensions: []pkix.Extension{
			roleExtension(roleOIDValue, "ReadOnlySunSpec", tagUTF8String),
		},
	})
	if err != nil {
		t.Fatalf("mintLeaf: %v", err)
	}
	if len(cert.Certificate) == 0 || len(cert.Certificate[0]) == 0 {
		t.Fatal("no DER to present")
	}
	// The premise: this certificate does NOT parse, and that is the fixture
	// working. tls.LoadX509KeyPair would have failed here — which is how run
	// 20260726T225512 came to report a DUT FAIL for a probe it never launched.
	if _, perr := x509.ParseCertificate(cert.Certificate[0]); perr == nil {
		t.Fatal("the two-role fixture parsed cleanly; it is supposed to carry duplicate extension OIDs")
	} else if !strings.Contains(perr.Error(), "duplicate extension") {
		t.Fatalf("unexpected parse error %v — the fixture should fail on the duplicate OID", perr)
	}
	if cert.Leaf != nil {
		t.Error("Leaf must be left nil for an unparseable fixture; a parsed Leaf that disagreed with the " +
			"bytes would be a lie in the other direction")
	}
	if cert.PrivateKey == nil {
		t.Fatal("the fixture carries no private key, so it cannot answer a CertificateRequest")
	}
	// And it is usable as a client identity exactly as the dialer supplies it.
	c := cert
	cfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
		GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			return &c, nil
		},
	}
	got, err := cfg.GetClientCertificate(&tls.CertificateRequestInfo{})
	if err != nil || got == nil || len(got.Certificate) == 0 {
		t.Fatalf("the hand-built certificate is not presentable: %v", err)
	}
	// Both role values must be on the wire, or SunSpecTCP-31 is not provoked.
	der := got.Certificate[0]
	for _, want := range []string{"GridServiceSunSpec", "ReadOnlySunSpec"} {
		if !strings.Contains(string(der), want) {
			t.Errorf("the presented DER does not carry the role %q; the two-role provocation is incomplete", want)
		}
	}
}
