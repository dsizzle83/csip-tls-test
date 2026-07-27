package suitepki

// mint_test.go proves the precondition toolkit other suites will build their
// negative tests on.
//
// The load-bearing test is TestOtherNameRoundTrip: the minter and the parser
// are the two halves of every identity verdict in this suite, and if they agree
// with each other on a WRONG encoding, every PASS in checks_identity.go is
// worthless. It is therefore checked against crypto/x509's own SAN handling as
// well — a third opinion that shares no code with either half.

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"strings"
	"testing"
	"time"
)

// TestOtherNameRoundTrip: what marshalOtherName writes, parseOtherNames must
// read back, and crypto/x509 must not choke on the certificate carrying it.
func TestOtherNameRoundTrip(t *testing.T) {
	spec := &DeviceIdentitySpec{
		HWType: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 13, 1},
		Serial: "1234",
	}
	san, err := marshalSAN(spec, []string{"example.invalid"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	names := parseOtherNames(san)
	if len(names) != 1 {
		t.Fatalf("otherNames = %d, want 1 (the dNSName must be skipped, not misread): %+v", len(names), names)
	}
	if names[0].Err != "" {
		t.Fatalf("otherName error %q — the [0] IMPLICIT tag is almost certainly wrong", names[0].Err)
	}
	id, why := deviceIdentity(names)
	if id == nil {
		t.Fatalf("identity not recovered: %s", why)
	}
	if !id.HWType.Equal(spec.HWType) || id.Serial != spec.Serial {
		t.Errorf("round trip = %v, want hwType=%v serial=%q", id, spec.HWType, spec.Serial)
	}
	if !id.SerialIsOctetString {
		t.Errorf("serial tag = 0x%02x, want OCTET STRING", id.SerialTag)
	}

	// The third opinion. crypto/x509 discards otherName but it does parse the
	// SAN extension, so a structurally broken GeneralNames would be rejected
	// here even though both of our halves agreed on it.
	h := testHierarchy(t)
	leaf, err := h.Mint(ShapeSERCAMICADevice, LeafSpec{
		Name: "roundtrip", Identity: spec, DNSNames: []string{"example.invalid"}, Server: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(leaf.DER)
	if err != nil {
		t.Fatalf("crypto/x509 rejects the SAN this package assembled: %v", err)
	}
	if len(cert.DNSNames) != 1 || cert.DNSNames[0] != "example.invalid" {
		t.Errorf("crypto/x509 read DNSNames %v, want [example.invalid] — the GeneralNames sequence is "+
			"malformed even though our own parser accepted it", cert.DNSNames)
	}
}

// TestChainAssemblyOmitsTheRoot: SunSpecTCP-51 and RFC 5246 both put the leaf
// first and leave the trust anchor out. Sending the root would also make the
// presented depth mean something different from what PKI-19's observable says.
func TestChainAssemblyOmitsTheRoot(t *testing.T) {
	h := testHierarchy(t)
	for _, tc := range []struct {
		shape ChainShape
		depth int
	}{
		{ShapeSERCADevice, 1},
		{ShapeSERCAMICADevice, 2},
		{ShapeSERCAMCAMICADevice, 3},
	} {
		leaf, err := h.Mint(tc.shape, LeafSpec{Name: string(tc.shape), CommonName: string(tc.shape), Client: true})
		if err != nil {
			t.Fatalf("%s: %v", tc.shape, err)
		}
		chain := leaf.ChainDER()
		if len(chain) != tc.depth {
			t.Errorf("%s: presented %d certificate(s), want %d", tc.shape, len(chain), tc.depth)
		}
		for i, der := range chain {
			if i > 0 && string(der) == string(h.SERCA.DER) {
				t.Errorf("%s: the root was included at position %d", tc.shape, i)
			}
		}
		facts, err := InspectChain(chain)
		if err != nil {
			t.Fatal(err)
		}
		if facts.Shape != tc.shape {
			t.Errorf("%s: dissected as %s", tc.shape, facts.Shape)
		}
		// Every chain must verify against the root that anchors it.
		if err := verifyAgainst(chain, h.SERCA.Pool()); err != nil {
			t.Errorf("%s: does not verify against its own root: %v", tc.shape, err)
		}
	}
}

func verifyAgainst(chain [][]byte, roots *x509.CertPool) error {
	leaf, err := x509.ParseCertificate(chain[0])
	if err != nil {
		return err
	}
	inter := x509.NewCertPool()
	for _, der := range chain[1:] {
		c, err := x509.ParseCertificate(der)
		if err != nil {
			return err
		}
		inter.AddCert(c)
	}
	_, err = leaf.Verify(x509.VerifyOptions{
		Roots: roots, Intermediates: inter,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	return err
}

// TestHierarchyUnderAnAdoptedRoot is the mechanism PKI-3, PKI-19 and PKI-20
// depend on: material minted under the root the DUT already trusts, so an
// acceptance can be demanded rather than only a refusal.
func TestHierarchyUnderAnAdoptedRoot(t *testing.T) {
	origin := testHierarchy(t)
	dir := t.TempDir()
	writeFile(t, dir+"/ca-cert.pem", origin.SERCA.CertPEM())
	key, err := origin.SERCA.KeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, dir+"/ca-key.pem", key)

	adopted, err := AdoptCAFromFiles("adopted", dir+"/ca-cert.pem", dir+"/ca-key.pem")
	if err != nil {
		t.Fatal(err)
	}
	if !adopted.IsRoot() {
		t.Error("an adopted root reports a parent")
	}
	h, err := HierarchyUnder(adopted, "adopted")
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := h.Mint(ShapeSERCAMCAMICADevice, LeafSpec{Name: "under-adopted", CommonName: "x", Client: true})
	if err != nil {
		t.Fatal(err)
	}
	// The point of the exercise: it verifies against the ORIGINAL root, which
	// is what makes it acceptable to a DUT configured with that anchor.
	if err := verifyAgainst(leaf.ChainDER(), origin.SERCA.Pool()); err != nil {
		t.Fatalf("material minted under the adopted root does not verify against the original: %v", err)
	}
}

// TestAdoptCARejectsAMismatchedKey: silently adopting a CA whose key does not
// match would produce material nothing can verify, and the failure would surface
// as an unexplained DUT refusal.
func TestAdoptCARejectsAMismatchedKey(t *testing.T) {
	a, b := testHierarchy(t), testHierarchy(t)
	dir := t.TempDir()
	writeFile(t, dir+"/ca-cert.pem", a.SERCA.CertPEM())
	key, err := b.SERCA.KeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, dir+"/ca-key.pem", key)
	if _, err := AdoptCAFromFiles("mismatched", dir+"/ca-cert.pem", dir+"/ca-key.pem"); err == nil {
		t.Fatal("a CA certificate and an unrelated private key were adopted together")
	}
}

// TestNegativeFixturesHaveTheDefectsTheyClaim walks the whole matrix and checks
// each fixture against the property its name promises. A negative fixture that
// is not actually broken turns a negative test into a vacuous one.
func TestNegativeFixturesHaveTheDefectsTheyClaim(t *testing.T) {
	h := testHierarchy(t)
	mica, err := h.IssuerFor(ShapeSERCAMICADevice)
	if err != nil {
		t.Fatal(err)
	}
	set, err := NegativeFixtures(mica, "negatives")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()

	check := map[string]func(t *testing.T, f Fixture, facts *CertFacts){
		"expired": func(t *testing.T, f Fixture, facts *CertFacts) {
			if !facts.Info.NotAfter.Before(now) {
				t.Errorf("NotAfter = %s is not in the past", facts.Info.NotAfter)
			}
		},
		"not-yet-valid": func(t *testing.T, f Fixture, facts *CertFacts) {
			if !facts.Info.NotBefore.After(now) {
				t.Errorf("NotBefore = %s is not in the future", facts.Info.NotBefore)
			}
		},
		"wrong-ca": func(t *testing.T, f Fixture, facts *CertFacts) {
			if err := verifyAgainst(f.Leaf.ChainDER(), h.SERCA.Pool()); err == nil {
				t.Error("the wrong-ca fixture verifies against the hierarchy's own root")
			}
			if err := verifyAgainst(f.Leaf.ChainDER(), set.Foreign.Pool()); err != nil {
				t.Errorf("the wrong-ca fixture does not verify against its own foreign root either: %v", err)
			}
		},
		"no-role": func(t *testing.T, f Fixture, facts *CertFacts) {
			if facts.RoleErr == "" {
				t.Errorf("role = %q with no error; want an absent-role error", facts.Role)
			}
		},
		"two-role": func(t *testing.T, f Fixture, facts *CertFacts) {
			if !strings.Contains(facts.RoleErr, "multiple") {
				t.Errorf("RoleErr = %q, want a multiple-roles error", facts.RoleErr)
			}
		},
		"empty-role": func(t *testing.T, f Fixture, facts *CertFacts) {
			// Structurally valid; unauthorized at the AuthZ layer, not the
			// parser. The fixture exists precisely to prove that distinction.
			if facts.RoleErr != "" || facts.Role != "" {
				t.Errorf("role = %q / err %q; want an empty role and NO parse error", facts.Role, facts.RoleErr)
			}
		},
		"oversize-role": func(t *testing.T, f Fixture, facts *CertFacts) {
			if len(facts.Role) != 1024 {
				t.Errorf("role length = %d, want 1024", len(facts.Role))
			}
		},
		"bad-encoding": func(t *testing.T, f Fixture, facts *CertFacts) {
			if facts.RoleErr == "" {
				t.Errorf("a PrintableString role parsed cleanly as %q", facts.Role)
			}
		},
	}

	if len(set.Fixtures) != len(check) {
		t.Errorf("fixtures = %d, want %d", len(set.Fixtures), len(check))
	}
	for _, f := range set.Fixtures {
		t.Run(f.Name, func(t *testing.T) {
			facts, err := InspectDER(f.Leaf.DER)
			if err != nil {
				t.Fatalf("fixture does not dissect: %v", err)
			}
			fn, ok := check[f.Name]
			if !ok {
				t.Fatalf("unexpected fixture %q", f.Name)
			}
			fn(t, f, facts)
			if f.Defect == "" {
				t.Error("fixture carries no defect description, so a report could not say what is wrong with it")
			}
		})
	}

	// The classification a negative test hangs on: chain/validity defects are
	// fatal to the handshake, role defects are not.
	fatal := map[string]bool{}
	for _, f := range set.HandshakeFatal() {
		fatal[f.Name] = true
	}
	for name, want := range map[string]bool{
		"expired": true, "not-yet-valid": true, "wrong-ca": true,
		"no-role": false, "two-role": false, "empty-role": false,
		"oversize-role": false, "bad-encoding": false,
	} {
		if fatal[name] != want {
			t.Errorf("%s: FatalToHandshake = %v, want %v — misclassifying this makes the negative test "+
				"assert the wrong outcome", name, fatal[name], want)
		}
	}
	if _, err := set.Fixture("no-such-fixture"); err == nil {
		t.Error("an unknown fixture name was accepted")
	}
}

// TestRoleEncodingIsHonoured: the bad-encoding fixture must actually differ in
// its ASN.1 string type, not merely in its value.
func TestRoleEncodingIsHonoured(t *testing.T) {
	utf8, err := marshalRoleValue("ReadOnlySunSpec", RoleUTF8String)
	if err != nil {
		t.Fatal(err)
	}
	printable, err := marshalRoleValue("ReadOnlySunSpec", RolePrintableString)
	if err != nil {
		t.Fatal(err)
	}
	if utf8[0] != byte(asn1.TagUTF8String) {
		t.Errorf("UTF8String encoding starts with tag 0x%02x", utf8[0])
	}
	if printable[0] != byte(asn1.TagPrintableString) {
		t.Errorf("PrintableString encoding starts with tag 0x%02x", printable[0])
	}
}

// TestMintedMaterialLoadsIntoCryptoTLS closes the loop: everything minted here
// has to be presentable by a real TLS stack, or the negative tests never reach
// the peer.
func TestMintedMaterialLoadsIntoCryptoTLS(t *testing.T) {
	h := testHierarchy(t)
	leaf, err := h.Mint(ShapeSERCAMCAMICADevice, LeafSpec{
		Name: "tls", CommonName: "tls client", Roles: []string{"ReadOnlySunSpec"}, Client: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	tc := leaf.TLSCertificate()
	if len(tc.Certificate) != 3 {
		t.Errorf("tls.Certificate carries %d certificate(s), want 3", len(tc.Certificate))
	}
	if tc.PrivateKey == nil {
		t.Error("no private key")
	}
	if _, err := tls.X509KeyPair(leaf.CertPEM(), mustKeyPEM(t, leaf)); err != nil {
		t.Errorf("the PEM rendering does not load: %v", err)
	}
}

func mustKeyPEM(t *testing.T, l *Leaf) []byte {
	t.Helper()
	b, err := l.KeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestIssuerForRejectsAnUnknownShape keeps a typo from silently issuing under
// the wrong tier.
func TestIssuerForRejectsAnUnknownShape(t *testing.T) {
	h := testHierarchy(t)
	if _, err := h.IssuerFor(ShapeUnknown); err == nil {
		t.Error("ShapeUnknown produced an issuer")
	}
	if _, err := Mint(nil, LeafSpec{Name: "x"}); err == nil {
		t.Error("Mint accepted a nil issuer")
	}
	if _, err := HierarchyUnder(nil, "x"); err == nil {
		t.Error("HierarchyUnder accepted a nil root")
	}
	if _, err := NegativeFixtures(nil, "x"); err == nil {
		t.Error("NegativeFixtures accepted a nil issuer")
	}
}
