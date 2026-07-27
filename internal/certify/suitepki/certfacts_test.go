package suitepki

// certfacts_test.go proves the certificate dissection, which is where every
// verdict in this suite ultimately comes from.
//
// The tests are written as pairs wherever a criterion can pass or fail, because
// a check that can only ever produce one answer measures nothing. The pattern
// throughout: mint a certificate with a known property, dissect it with the
// SAME code the checks use, and assert the dissection says what the property
// is.

import (
	"crypto/x509"
	"encoding/asn1"
	"strings"
	"testing"
	"time"
)

func testHierarchy(t *testing.T) *Hierarchy {
	t.Helper()
	h, err := NewHierarchy("test")
	if err != nil {
		t.Fatal(err)
	}
	return h
}

// TestConformantIdentityIsRecognised is the positive half of PKI-4/6/7: a leaf
// built the way IEEE 2030.5-2018 requires must dissect as conformant on every
// criterion. Without this the FAIL the suite reports against the DUT would be
// indistinguishable from a parser that cannot find an identity at all.
func TestConformantIdentityIsRecognised(t *testing.T) {
	h := testHierarchy(t)
	leaf, err := h.Mint(ShapeSERCAMICADevice, conformantLeafSpec("conformant"))
	if err != nil {
		t.Fatal(err)
	}
	f, err := InspectDER(leaf.DER)
	if err != nil {
		t.Fatal(err)
	}

	if !f.SubjectEmpty {
		t.Errorf("SubjectEmpty = false (Subject %q, %d RDNs), want an empty Subject", f.Subject(), f.SubjectRDNs)
	}
	if f.Identity == nil {
		t.Fatalf("no device identity found; SAN present=%v, otherNames=%d, err=%q",
			f.SANPresent, len(f.OtherNames), f.IdentityErr)
	}
	want := conformantIdentity()
	if !f.Identity.HWType.Equal(want.HWType) {
		t.Errorf("hwType = %v, want %v", f.Identity.HWType, want.HWType)
	}
	if f.Identity.Serial != want.Serial {
		t.Errorf("hwSerialNum = %q, want %q", f.Identity.Serial, want.Serial)
	}
	if !f.Identity.SerialIsOctetString {
		t.Errorf("serial tag = 0x%02x, want OCTET STRING (0x04)", f.Identity.SerialTag)
	}
	if !f.Identity.SerialIsUTF8 {
		t.Error("serial contents are not reported as UTF-8")
	}
	pen, ok := f.Identity.PEN()
	if !ok || pen != "50316" {
		t.Errorf("PEN = %q, %v; want 50316, true", pen, ok)
	}
	if got := f.Identity.String(); !strings.Contains(got, "hwType=") || !strings.Contains(got, "hwSerialNum=") {
		t.Errorf("rendering %q does not match the openssl form the procedure's expected output uses", got)
	}
}

// TestDUTShapedLeafFailsEveryIdentityCriterion is the negative half, and it is
// the finding this suite exists to produce: a leaf shaped the way the DUT's
// actually is must come back with no identity at all, and a non-empty Subject.
func TestDUTShapedLeafFailsEveryIdentityCriterion(t *testing.T) {
	h := testHierarchy(t)
	leaf, err := h.Mint(ShapeSERCAMICADevice, dutShapedLeafSpec("dut-shaped"))
	if err != nil {
		t.Fatal(err)
	}
	f, err := InspectDER(leaf.DER)
	if err != nil {
		t.Fatal(err)
	}
	if f.SubjectEmpty {
		t.Error("a leaf with a Subject CN was reported as having an empty Subject")
	}
	if f.Identity != nil {
		t.Errorf("identity = %v, want none", f.Identity)
	}
	if f.IdentityErr != "" {
		t.Errorf("IdentityErr = %q; an ABSENT identity must not be reported as a malformed one — the two "+
			"are different findings", f.IdentityErr)
	}
	if !f.SANPresent {
		t.Error("the DUT-shaped leaf carries dNSName/iPAddress entries, so a SAN must be reported present; " +
			"reporting it absent would hide that the SAN exists and simply lacks the identity")
	}
	if _, ok := f.Identity.PEN(); ok {
		t.Error("PEN reported on a nil identity")
	}
}

// TestSerialWithWrongTagIsReportedNotCoerced proves PKI-7 can fail for the
// reason PKI-7 is about. A parser that accepted a UTF8String where IEEE 2030.5
// demands an OCTET STRING would make the row unfailable.
func TestSerialWithWrongTagIsReportedNotCoerced(t *testing.T) {
	h := testHierarchy(t)
	spec := conformantLeafSpec("wrong-serial-tag")
	spec.Identity.SerialTag = asn1.TagUTF8String
	leaf, err := h.Mint(ShapeSERCAMICADevice, spec)
	if err != nil {
		t.Fatal(err)
	}
	f, err := InspectDER(leaf.DER)
	if err != nil {
		t.Fatal(err)
	}
	if f.Identity == nil {
		t.Fatalf("identity not found at all (err %q); a wrongly TAGGED serial is still an identity and must "+
			"be reported as one so the finding names the real defect", f.IdentityErr)
	}
	if f.Identity.SerialIsOctetString {
		t.Error("a UTF8String-tagged serial was reported as an OCTET STRING")
	}
	if f.Identity.SerialTag != asn1.TagUTF8String {
		t.Errorf("SerialTag = %d, want %d (UTF8String)", f.Identity.SerialTag, asn1.TagUTF8String)
	}
	if f.Identity.Serial != conformantIdentity().Serial {
		t.Errorf("serial = %q, want the value verbatim regardless of its tag", f.Identity.Serial)
	}
}

// TestHWTypeOutsideThePENArcIsReported covers PKI-6's other failure mode: an
// identity that exists but is not rooted at an IANA Private Enterprise Number.
func TestHWTypeOutsideThePENArcIsReported(t *testing.T) {
	h := testHierarchy(t)
	spec := conformantLeafSpec("no-pen")
	spec.Identity.HWType = asn1.ObjectIdentifier{2, 999, 1, 2}
	leaf, err := h.Mint(ShapeSERCAMICADevice, spec)
	if err != nil {
		t.Fatal(err)
	}
	f, err := InspectDER(leaf.DER)
	if err != nil {
		t.Fatal(err)
	}
	if f.Identity == nil {
		t.Fatal("identity not found")
	}
	if pen, ok := f.Identity.PEN(); ok {
		t.Errorf("PEN = %q reported for hwType %v, which is not under 1.3.6.1.4.1", pen, f.Identity.HWType)
	}
}

// TestRoleExtensionIsSeenAsAPrivateEnterpriseOID underpins PKI-6's second
// assertion: the product publishes a PEN-rooted OID today (the SunSpec role
// extension), so the gap is a missing model OID, not a missing PEN.
func TestRoleExtensionIsSeenAsAPrivateEnterpriseOID(t *testing.T) {
	h := testHierarchy(t)
	leaf, err := h.Mint(ShapeSERCAMICADevice, LeafSpec{
		Name: "role", CommonName: "role client", Roles: []string{"GridServiceSunSpec"}, Client: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	f, err := InspectDER(leaf.DER)
	if err != nil {
		t.Fatal(err)
	}
	if f.Role != "GridServiceSunSpec" || f.RoleErr != "" {
		t.Errorf("role = %q / %q, want GridServiceSunSpec / no error", f.Role, f.RoleErr)
	}
	found := false
	for _, oid := range f.PrivateEnterpriseOIDs {
		if oid == OIDSunSpecRole.String() {
			found = true
		}
	}
	if !found {
		t.Errorf("private-enterprise OIDs = %v, want the role OID %s among them",
			f.PrivateEnterpriseOIDs, OIDSunSpecRole)
	}
}

// TestMalformedIdentityIsAFindingNotSilence: an id-on-hardwareModuleName
// otherName whose value does not decode must be reported as malformed, because
// "the DUT emitted a broken identity" and "the DUT emitted no identity" are
// different conformance findings.
func TestMalformedIdentityIsAFindingNotSilence(t *testing.T) {
	broken, err := marshalOtherName(OIDHardwareModuleName, []byte{0x05, 0x00}) // NULL, not a SEQUENCE
	if err != nil {
		t.Fatal(err)
	}
	san, err := asn1.Marshal(asn1.RawValue{
		Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true, Bytes: broken,
	})
	if err != nil {
		t.Fatal(err)
	}
	names := parseOtherNames(san)
	if len(names) != 1 || !names[0].TypeID.Equal(OIDHardwareModuleName) {
		t.Fatalf("otherNames = %+v", names)
	}
	id, why := deviceIdentity(names)
	if id != nil {
		t.Fatalf("a NULL-valued hardwareModuleName decoded as an identity: %v", id)
	}
	if why == "" {
		t.Fatal("a malformed hardwareModuleName produced no reason, so it is indistinguishable from absence")
	}
}

// TestChainLinkageIsCheckedThreeWays proves the chain analysis reports the
// issuer DN, the key identifiers and the signature separately — the distinction
// that tells a mis-assembled chain from an untrusted one.
func TestChainLinkageIsCheckedThreeWays(t *testing.T) {
	h := testHierarchy(t)
	leaf, err := h.Mint(ShapeSERCAMCAMICADevice, conformantLeafSpec("deep"))
	if err != nil {
		t.Fatal(err)
	}
	chain, err := InspectChain(leaf.ChainDER())
	if err != nil {
		t.Fatal(err)
	}
	if chain.Depth != 3 {
		t.Fatalf("depth = %d, want 3 (leaf + MICA + MCA, root anchored out of band)", chain.Depth)
	}
	if chain.Shape != ShapeSERCAMCAMICADevice {
		t.Errorf("shape = %s, want %s", chain.Shape, ShapeSERCAMCAMICADevice)
	}
	if len(chain.Links) != 2 {
		t.Fatalf("links = %d, want 2", len(chain.Links))
	}
	for _, l := range chain.Links {
		if !l.OK() {
			t.Errorf("link %d->%d does not hold: DN=%v keyid=%v(present %v) sig=%v %s",
				l.Child, l.Issuer, l.IssuerDNMatches, l.KeyIDMatches, l.KeyIDPresent, l.SignatureValid, l.SignatureErr)
		}
		if !l.KeyIDPresent {
			t.Error("no authority/subject key identifier pair was found; the minted CAs should carry one")
		}
	}
	if len(chain.Problems) != 0 {
		t.Errorf("problems = %v, want none", chain.Problems)
	}
	if chain.TopSelfIssued {
		t.Error("TopSelfIssued is set although ChainDER omits the root")
	}
}

// TestMisAssembledChainIsRejectedByTheLinkCheck is the counterpart: a chain
// whose intermediate did not issue the leaf must fail, and must fail on the
// signature rather than only on the DN.
func TestMisAssembledChainIsRejectedByTheLinkCheck(t *testing.T) {
	h := testHierarchy(t)
	leaf, err := h.Mint(ShapeSERCAMICADevice, conformantLeafSpec("mis-assembled"))
	if err != nil {
		t.Fatal(err)
	}
	// Present the MCA where the leaf's real issuer (MICADirect) belongs.
	chain, err := InspectChain([][]byte{leaf.DER, h.MCA.DER})
	if err != nil {
		t.Fatal(err)
	}
	if len(chain.Links) != 1 {
		t.Fatalf("links = %d", len(chain.Links))
	}
	l := chain.Links[0]
	if l.OK() {
		t.Fatal("a chain whose intermediate did not issue the leaf was reported as holding")
	}
	if l.SignatureValid {
		t.Error("the signature check passed against the wrong issuer")
	}
	if len(chain.Problems) == 0 {
		t.Error("a broken link produced no problem entry, so a report would not mention it")
	}
}

// TestSelfIssuedTopIsReported: a peer that ships its own root in-band changes
// what the presented depth means, and the analysis has to say so rather than
// silently counting it as another tier.
func TestSelfIssuedTopIsReported(t *testing.T) {
	h := testHierarchy(t)
	leaf, err := h.Mint(ShapeSERCAMICADevice, conformantLeafSpec("with-root"))
	if err != nil {
		t.Fatal(err)
	}
	chain, err := InspectChain(leaf.ChainDERWithRoot())
	if err != nil {
		t.Fatal(err)
	}
	if !chain.TopSelfIssued {
		t.Fatal("a chain including its own self-signed root was not flagged")
	}
	if len(chain.Problems) == 0 || !strings.Contains(chain.Problems[0], "self-issued") {
		t.Errorf("problems = %v, want one naming the in-band trust anchor", chain.Problems)
	}
}

// TestChainDigestIdentifiesTheChain underpins PKI-8: two different chains must
// digest differently, and the same chain must digest the same twice.
func TestChainDigestIdentifiesTheChain(t *testing.T) {
	h := testHierarchy(t)
	a, err := h.Mint(ShapeSERCAMICADevice, conformantLeafSpec("a"))
	if err != nil {
		t.Fatal(err)
	}
	b, err := h.Mint(ShapeSERCAMICADevice, conformantLeafSpec("b"))
	if err != nil {
		t.Fatal(err)
	}
	fa, err := InspectChain(a.ChainDER())
	if err != nil {
		t.Fatal(err)
	}
	fa2, err := InspectChain(a.ChainDER())
	if err != nil {
		t.Fatal(err)
	}
	fb, err := InspectChain(b.ChainDER())
	if err != nil {
		t.Fatal(err)
	}
	if fa.SHA256 != fa2.SHA256 {
		t.Error("the same chain digested differently twice")
	}
	if fa.SHA256 == fb.SHA256 {
		t.Error("two different chains share a digest")
	}
	if !SameChain(fa, fa2) || SameChain(fa, fb) {
		t.Error("SameChain disagrees with the digests")
	}
}

// TestExpiredFixtureIsStillDissectable: the certificates most worth reporting
// on are the ones a strict consumer rejects, so validity must never stop the
// dissection.
func TestExpiredFixtureIsStillDissectable(t *testing.T) {
	h := testHierarchy(t)
	now := time.Now().UTC()
	leaf, err := h.Mint(ShapeSERCAMICADevice, LeafSpec{
		Name: "expired", CommonName: "expired leaf",
		NotBefore: now.AddDate(-2, 0, 0), NotAfter: now.AddDate(-1, 0, 0),
	})
	if err != nil {
		t.Fatal(err)
	}
	f, err := InspectDER(leaf.DER)
	if err != nil {
		t.Fatalf("an expired certificate did not dissect: %v", err)
	}
	if f.Info.NotAfter.After(now) {
		t.Errorf("NotAfter = %s, want a past date", f.Info.NotAfter)
	}
	if f.Subject() == "" {
		t.Error("subject lost")
	}
}

// TestPEMRoundTrip exercises the bridge from the committed fixture tree.
func TestPEMRoundTrip(t *testing.T) {
	h := testHierarchy(t)
	leaf, err := h.Mint(ShapeSERCAMCAMICADevice, conformantLeafSpec("pem"))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	certPath, keyPath, err := leaf.WritePEM(dir, "pem")
	if err != nil {
		t.Fatal(err)
	}
	chain, err := InspectPEMFile(certPath)
	if err != nil {
		t.Fatal(err)
	}
	if chain.Depth != 3 {
		t.Errorf("depth from PEM = %d, want 3", chain.Depth)
	}
	if chain.Leaf().Identity == nil {
		t.Error("the identity did not survive the PEM round trip")
	}
	if _, err := loadKeyPair(certPath, keyPath); err != nil {
		t.Errorf("crypto/tls cannot load the written pair: %v", err)
	}
}

// TestInspectDERRefusesNonCertificates keeps the "never error on a merely
// non-conformant certificate" rule from becoming "never error at all".
func TestInspectDERRefusesNonCertificates(t *testing.T) {
	if _, err := InspectDER(nil); err == nil {
		t.Error("empty input accepted")
	}
	if _, err := InspectDER([]byte("not der")); err == nil {
		t.Error("garbage accepted as a certificate")
	}
	if _, err := InspectChain(nil); err == nil {
		t.Error("empty chain accepted")
	}
}

// TestRDNCountRefusesToCallAnUnreadableSubjectEmpty: an unparseable Subject
// must not accidentally satisfy PKI-4's empty-Subject criterion.
func TestRDNCountRefusesToCallAnUnreadableSubjectEmpty(t *testing.T) {
	if n, empty := rdnCount([]byte{0xff, 0xff}); empty || n != 0 {
		t.Errorf("rdnCount(garbage) = %d, %v; want 0, false", n, empty)
	}
	empty, err := asn1.Marshal(asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true})
	if err != nil {
		t.Fatal(err)
	}
	if n, isEmpty := rdnCount(empty); !isEmpty || n != 0 {
		t.Errorf("rdnCount(empty SEQUENCE) = %d, %v; want 0, true", n, isEmpty)
	}
}

// x509 sanity: the conformant leaf this suite mints must still be a certificate
// the standard parser accepts, or a real DUT would never negotiate with it.
func TestConformantLeafParsesWithCryptoX509(t *testing.T) {
	h := testHierarchy(t)
	leaf, err := h.Mint(ShapeSERCAMICADevice, conformantLeafSpec("stdlib"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := x509.ParseCertificate(leaf.DER); err != nil {
		t.Fatalf("crypto/x509 rejects the conformant leaf: %v", err)
	}
}

// TestPENObservationDistinguishesTheTwoGaps: "no PEN at all" and "a PEN but no
// model OID under it" are different findings, and PKI-6's second assertion
// exists only to keep them apart.
func TestPENObservationDistinguishesTheTwoGaps(t *testing.T) {
	h := testHierarchy(t)

	conformant, err := h.Mint(ShapeSERCAMICADevice, conformantLeafSpec("pen-hwtype"))
	if err != nil {
		t.Fatal(err)
	}
	roleOnly, err := h.Mint(ShapeSERCAMICADevice, LeafSpec{
		Name: "pen-role", CommonName: "role only", Roles: []string{"ReadOnlySunSpec"}, Client: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	bare, err := h.Mint(ShapeSERCAMICADevice, LeafSpec{Name: "bare", CommonName: "bare", Server: true})
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name     string
		der      []byte
		want     string
		contains string
	}{
		{"hwType under a PEN", conformant.DER, "PASS", "rooted at PEN 50316"},
		{"role OID but no hwType", roleOnly.DER, "PASS", "what is missing is a model OID"},
		{"nothing under 1.3.6.1.4.1", bare.DER, "WARN", "evidences no PEN allocation"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, err := InspectDER(tc.der)
			if err != nil {
				t.Fatal(err)
			}
			v, observed := penObservation(f)
			if string(v) != tc.want {
				t.Errorf("verdict = %s, want %s (observed %q)", v, tc.want, observed)
			}
			if !strings.Contains(observed, tc.contains) {
				t.Errorf("observed = %q, want it to mention %q", observed, tc.contains)
			}
		})
	}
}
