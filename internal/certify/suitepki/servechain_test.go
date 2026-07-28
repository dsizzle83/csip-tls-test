package suitepki

// servechain_test.go asserts the COMM-004 rejection fixtures are defective in
// the EXACT way the row that presents them names — read back out of the DER by
// an independent walk, not by trusting the constructor.
//
// This matters more than usual. A fixture that is merely broken produces a
// rejection too, and a check that credited it would report a PASS for a defect
// the device never saw. So each test names the clause, finds the extension by
// OID, and checks both its criticality and its content.

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"strings"
	"testing"
)

func mintFixture(t *testing.T, defect MICADefect, serca *CA) *ServerChain {
	t.Helper()
	sc, err := MintServerChain(defect, serca, ServerLeafSpec{
		CommonName:  "bench 2030.5 server",
		DNSNames:    []string{"gridsim.bench"},
		IPAddresses: []string{"69.0.0.20"},
	})
	if err != nil {
		t.Fatalf("MintServerChain(%s): %v", defect, err)
	}
	return sc
}

// chainCerts decodes a fixture's PEM into parsed certificates, leaf first.
func chainCerts(t *testing.T, sc *ServerChain) []*x509.Certificate {
	t.Helper()
	var out []*x509.Certificate
	rest := sc.CertPEM
	for {
		var blk *pem.Block
		blk, rest = pem.Decode(rest)
		if blk == nil {
			break
		}
		c, err := x509.ParseCertificate(blk.Bytes)
		if err != nil {
			t.Fatalf("%s: certificate %d does not parse: %v", sc.Defect, len(out), err)
		}
		out = append(out, c)
	}
	if len(out) == 0 {
		t.Fatalf("%s: the fixture PEM holds no certificate", sc.Defect)
	}
	return out
}

func findExt(certs []*x509.Certificate, i int, oid asn1.ObjectIdentifier) (pkix.Extension, bool) {
	if i >= len(certs) {
		return pkix.Extension{}, false
	}
	for _, e := range certs[i].Extensions {
		if e.Id.Equal(oid) {
			return e, true
		}
	}
	return pkix.Extension{}, false
}

func TestInvalidMICA_EKUIsCriticalAndMeaningless(t *testing.T) {
	serca, err := NewCA("test SERCA", nil, 2)
	if err != nil {
		t.Fatal(err)
	}
	sc := mintFixture(t, MICAEKUCritical, serca)
	if sc.ChainLen != 2 {
		t.Fatalf("chain has %d certificate(s), want leaf + MICA = 2", sc.ChainLen)
	}
	certs := chainCerts(t, sc)

	ext, ok := findExt(certs, 1, OIDExtKeyUsage)
	if !ok {
		t.Fatal("the MICA carries no extendedKeyUsage extension at all")
	}
	if !ext.Critical {
		t.Error("the extendedKeyUsage is NOT critical; the sub-test is about a CRITICAL one (RFC 5280 §4.2)")
	}
	var purposes []asn1.ObjectIdentifier
	if _, err := asn1.Unmarshal(ext.Value, &purposes); err != nil {
		t.Fatalf("the extendedKeyUsage value does not decode as a SEQUENCE OF OID: %v", err)
	}
	if len(purposes) != 1 || !purposes[0].Equal(OIDInvalidPurpose) {
		t.Errorf("extendedKeyUsage purposes = %v, want exactly the meaningless %v", purposes, OIDInvalidPurpose)
	}
	// The point of the defect: a serverAuth leaf beneath a MICA that permits
	// only this purpose cannot be validated by an EKU-chaining verifier.
	for _, p := range purposes {
		if p.Equal(asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 1}) {
			t.Error("the MICA permits id-kp-serverAuth, so the leaf beneath it is perfectly usable")
		}
	}
	if sc.AnchorSubject != serca.Cert.Subject.String() {
		t.Errorf("AnchorSubject = %q, want the SERCA's %q", sc.AnchorSubject, serca.Cert.Subject)
	}
}

func TestInvalidMICA_NameConstraintsAreNonCritical(t *testing.T) {
	serca, err := NewCA("test SERCA", nil, 2)
	if err != nil {
		t.Fatal(err)
	}
	certs := chainCerts(t, mintFixture(t, MICANameNonCritical, serca))

	ext, ok := findExt(certs, 1, OIDNameConstraints)
	if !ok {
		t.Fatal("the MICA carries no nameConstraints extension")
	}
	if ext.Critical {
		t.Error("nameConstraints is critical; the defect is that it is NOT (RFC 5280 §4.2.1.10 requires it)")
	}
	// The constraint really is present and really does exclude the leaf.
	if len(certs[1].PermittedDNSDomains) != 1 || certs[1].PermittedDNSDomains[0] != "invalid.example" {
		t.Errorf("permittedSubtrees = %v, want the single dNSName invalid.example",
			certs[1].PermittedDNSDomains)
	}
	for _, name := range certs[0].DNSNames {
		if name == "invalid.example" {
			t.Error("the leaf falls inside the permitted subtree, so the constraint constrains nothing")
		}
	}
}

func TestInvalidMICA_PolicyMappingIsNonCriticalAndMapsAnyPolicy(t *testing.T) {
	serca, err := NewCA("test SERCA", nil, 2)
	if err != nil {
		t.Fatal(err)
	}
	certs := chainCerts(t, mintFixture(t, MICAPolicyMapping, serca))

	ext, ok := findExt(certs, 1, OIDPolicyMappings)
	if !ok {
		t.Fatal("the MICA carries no policyMappings extension")
	}
	if ext.Critical {
		t.Error("policyMappings is critical; the defect is that it is NOT (RFC 5280 §4.2.1.5)")
	}
	var mappings []struct{ Issuer, Subject asn1.ObjectIdentifier }
	if _, err := asn1.Unmarshal(ext.Value, &mappings); err != nil {
		t.Fatalf("the policyMappings value does not decode: %v", err)
	}
	if len(mappings) != 1 {
		t.Fatalf("policyMappings holds %d mapping(s), want 1", len(mappings))
	}
	if !mappings[0].Issuer.Equal(OIDAnyPolicy) {
		t.Errorf("issuerDomainPolicy = %v, want anyPolicy %v — mapping FROM anyPolicy is what §4.2.1.5 "+
			"forbids outright", mappings[0].Issuer, OIDAnyPolicy)
	}
	if !mappings[0].Subject.Equal(OIDInvalidPolicy) {
		t.Errorf("subjectDomainPolicy = %v, want %v", mappings[0].Subject, OIDInvalidPolicy)
	}
}

func TestSelfSignedFixture_IssuesItselfAndChainsToNothing(t *testing.T) {
	sc := mintFixture(t, SelfSignedLeaf, nil)
	if sc.ChainLen != 1 {
		t.Fatalf("the self-signed fixture presents %d certificate(s), want exactly 1", sc.ChainLen)
	}
	if sc.AnchorSubject != "" {
		t.Errorf("AnchorSubject = %q; the self-signed fixture expects the peer to hold no anchor", sc.AnchorSubject)
	}
	certs := chainCerts(t, sc)
	leaf := certs[0]
	if leaf.Subject.String() != leaf.Issuer.String() {
		t.Errorf("subject %q != issuer %q, so the certificate is not self-issued", leaf.Subject, leaf.Issuer)
	}
	// CheckSignature, not CheckSignatureFrom: the latter also applies Go's
	// path-building policy and refuses with "parent certificate cannot sign
	// this kind of certificate", because the parent here is an END-ENTITY
	// certificate. That refusal is the fixture working — it is precisely the
	// defect COMM-004 G is about — so the assertion is the narrower one that
	// the signature really was made by this certificate's own key.
	if err := leaf.CheckSignature(leaf.SignatureAlgorithm, leaf.RawTBSCertificate, leaf.Signature); err != nil {
		t.Errorf("the certificate is not signed by its own key: %v", err)
	}
	if leaf.IsCA {
		t.Error("the fixture is a CA certificate; the sub-test is about a self-signed DEVICE certificate")
	}
	if err := leaf.CheckSignatureFrom(leaf); err == nil {
		t.Error("a strict path check ACCEPTED this certificate as its own issuer; the whole point of the " +
			"fixture is that it cannot be a valid link in any chain")
	}
	if sc.LeafSHA256 != SHA256Hex(leaf.Raw) {
		t.Errorf("LeafSHA256 %s does not match the DER it names", sc.LeafSHA256)
	}
}

// TestMintServerChain_RefusesAnUnanchoredInvalidMICA guards the methodological
// trap: minting D/E/F under a root the DUT has never heard of would produce a
// rejection for the wrong reason and a PASS the sub-test did not earn.
func TestMintServerChain_RefusesAnUnanchoredInvalidMICA(t *testing.T) {
	for _, d := range []MICADefect{MICAEKUCritical, MICANameNonCritical, MICAPolicyMapping} {
		if !d.NeedsAnchor() {
			t.Errorf("%s reports it needs no anchor", d)
		}
		if _, err := MintServerChain(d, nil, ServerLeafSpec{}); err == nil {
			t.Errorf("%s: MintServerChain minted a fixture with no trust anchor", d)
		}
	}
	if SelfSignedLeaf.NeedsAnchor() {
		t.Error("the self-signed fixture reports it needs an anchor; chaining to nothing is its whole defect")
	}
}

// TestEveryDefectDescribesItself keeps the reporting prose honest: every defect
// the catalog can present has a description naming the document that condemns
// it, because that sentence is what a reviewer reads in the bundle.
func TestEveryDefectDescribesItself(t *testing.T) {
	for _, d := range AllMICADefects {
		got := d.Description()
		if got == "" || got == string(d) {
			t.Errorf("%s has no description", d)
		}
		if d != SelfSignedLeaf && !strings.Contains(got, "RFC 5280") {
			t.Errorf("%s's description cites no clause: %s", d, got)
		}
	}
}
