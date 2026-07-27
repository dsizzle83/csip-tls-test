package suitepki

// suite_test.go runs the suite through the REAL runner, over the REAL committed
// catalog, against an in-process peer, with a capture synthesised from the bytes
// that actually crossed the loopback socket — and then verifies the bundle.
//
// The pair that matters most is TestIdentityRowsFailAgainstADUTShapedPeer and
// TestIdentityRowsPassAgainstAConformantPeer. They run THE SAME registered
// checks against two peers that differ only in their certificate, and demand
// opposite verdicts. That is what makes the FAIL this suite reports against the
// real gateway a measurement rather than an opinion: the same code, given a
// conformant certificate, says PASS.

import (
	"strings"
	"testing"

	"csip-tls-test/internal/certify"
	"csip-tls-test/internal/evidence/bundle"
)

// registeredUIDs is the set this suite claims. Keeping it here, checked against
// the registry, means adding a check without deciding what it covers — or
// dropping one silently — fails the build rather than the audit.
var registeredUIDs = []string{
	UIDMandatoryTLS, UIDCrossIssuer, UIDIdentitySAN, UIDIdentityUnique,
	UIDModelOIDPEN, UIDSerialEncoding, UIDSingleChain, UIDDeepestChain,
	UIDCAHierarchy, UIDErrorCerts,
}

// TestRegistrationMatchesTheCatalog: every uid registered must exist in the
// committed catalog, or the runner refuses to run at all (orphan detection).
func TestRegistrationMatchesTheCatalog(t *testing.T) {
	cat, err := certify.LoadDefault()
	if err != nil {
		t.Skipf("no committed catalog: %v", err)
	}
	reg := certify.NewRegistry()
	Register(reg)

	if reg.Len() != len(registeredUIDs) {
		t.Errorf("registry holds %d checks, want %d", reg.Len(), len(registeredUIDs))
	}
	for _, uid := range registeredUIDs {
		if _, ok := reg.Lookup(uid); !ok {
			t.Errorf("%s is not registered", uid)
		}
		if _, ok := cat.ByUID(uid); !ok {
			t.Errorf("%s is not in the catalog", uid)
		}
	}
	cov := reg.Coverage(cat, certify.Filter{})
	if len(cov.Orphans) != 0 {
		t.Fatalf("orphaned registrations: %v", cov.Orphans)
	}
	if s := reg.Suites(); len(s) != 1 || s[0] != Suite {
		t.Errorf("suites = %v, want [%s]", s, Suite)
	}
}

// TestEveryApplicableRowIsAddressed is the suite's own acceptance bar: no
// applicable SS-TEST-PKI case may be left with no implementation. An
// unimplemented applicable row reads as an oversight; a registered row that
// SKIPs with a reason reads as an engineering judgement, and this suite is
// required to produce only the second kind.
func TestEveryApplicableRowIsAddressed(t *testing.T) {
	cat, err := certify.LoadDefault()
	if err != nil {
		t.Skipf("no committed catalog: %v", err)
	}
	reg := certify.NewRegistry()
	Register(reg)
	cov := reg.Coverage(cat, certify.Filter{Docs: []string{"SS-TEST-PKI"}})
	if len(cov.Docs) != 1 {
		t.Fatalf("coverage covers %d documents", len(cov.Docs))
	}
	doc := cov.Docs[0]
	if !doc.Complete() {
		names := make([]string, 0, len(doc.Unimplemented))
		for _, e := range doc.Unimplemented {
			names = append(names, e.UID)
		}
		t.Fatalf("applicable rows with no implementation: %v", names)
	}
	if doc.Total != 21 {
		t.Errorf("SS-TEST-PKI total = %d, want 21", doc.Total)
	}
	if doc.Applicable != 6 {
		t.Errorf("applicable = %d, want 6 (the rest are the SunSpec-package and key-import rows)", doc.Applicable)
	}
	if len(doc.Implemented) != len(registeredUIDs) {
		t.Errorf("implemented = %d, want %d", len(doc.Implemented), len(registeredUIDs))
	}
	// The eleven that stay unimplemented must all carry the catalog's reason,
	// so COVERAGE.md explains every omission rather than merely recording it.
	if len(doc.Inapplicable) != doc.Total-len(registeredUIDs) {
		t.Errorf("inapplicable = %d, want %d", len(doc.Inapplicable), doc.Total-len(registeredUIDs))
	}
	for _, e := range doc.Inapplicable {
		if strings.TrimSpace(e.Reason) == "" {
			t.Errorf("%s is omitted with no reason", e.UID)
		}
	}
}

// identityRows are the four rows the IEEE 2030.5 device identification profile
// turns on.
var identityRows = []string{UIDIdentitySAN, UIDIdentityUnique, UIDModelOIDPEN, UIDSerialEncoding}

// TestIdentityRowsFailAgainstADUTShapedPeer is the finding. A peer whose leaf
// is shaped like the DUT's — Subject CN, no SAN otherName — must FAIL all four,
// and each FAIL must carry a citation a third party can re-derive from the
// capture.
func TestIdentityRowsFailAgainstADUTShapedPeer(t *testing.T) {
	h := testHierarchy(t)
	leaf, err := h.Mint(ShapeSERCAMICADevice, dutShapedLeafSpec("dut"))
	if err != nil {
		t.Fatal(err)
	}
	rec := newRecorder()
	p := startPeer(t, rec, leaf.TLSCertificate(), h.SERCA.Pool())
	out := runSuite(t, p, benchPKIDir(t, h), identityRows)

	for _, uid := range identityRows {
		c := out.result(t, uid)
		if c.Verdict != certify.Fail {
			t.Errorf("%s: verdict = %s, want FAIL against a peer with no 2030.5 identity\n%s",
				uid, c.Verdict, describeAssertions(c))
			continue
		}
		if !c.Citable() {
			t.Errorf("%s FAILED with no re-checkable citation, which is exactly the shape of an unevidenced "+
				"verdict this tool exists to prevent\n%s", uid, describeAssertions(c))
		}
	}

	// The specific claims, so a rewording of the check cannot quietly turn the
	// finding into something weaker.
	assertClaim(t, out.result(t, UIDIdentitySAN), claimEmptySubject, certify.Fail, "relative distinguished name")
	assertClaim(t, out.result(t, UIDIdentitySAN), claimSANIdentity, certify.Fail, "no IEEE 2030.5 device identity")
	assertClaim(t, out.result(t, UIDIdentityUnique), claimIdentityTuple, certify.Fail, "no (hwType, hwSerialNum)")
	assertClaim(t, out.result(t, UIDIdentityUnique), claimIdentityUnique, certify.Skip, "property of a population")
	assertClaim(t, out.result(t, UIDModelOIDPEN), claimModelOIDPEN, certify.Fail, "no hwType")
	assertClaim(t, out.result(t, UIDModelOIDPEN), claimPENPublished, certify.Warn, "evidences no PEN allocation")
	assertClaim(t, out.result(t, UIDSerialEncoding), claimSerialOctetString, certify.Fail, "no hwSerialNum")
	assertClaim(t, out.result(t, UIDSerialEncoding), claimSerialUTF8, certify.Skip, "no OCTET STRING to inspect")

	verifyBundle(t, out)
}

// TestIdentityRowsPassAgainstAConformantPeer is the control. Same checks, same
// runner, a peer whose leaf follows the profile — all four must PASS.
func TestIdentityRowsPassAgainstAConformantPeer(t *testing.T) {
	h := testHierarchy(t)
	leaf, err := h.Mint(ShapeSERCAMICADevice, conformantLeafSpec("conformant-dut"))
	if err != nil {
		t.Fatal(err)
	}
	rec := newRecorder()
	p := startPeer(t, rec, leaf.TLSCertificate(), h.SERCA.Pool())
	out := runSuite(t, p, benchPKIDir(t, h), identityRows)

	for _, uid := range identityRows {
		c := out.result(t, uid)
		if c.Verdict != certify.Pass {
			t.Errorf("%s: verdict = %s, want PASS against a conformant peer — if the checks cannot pass, "+
				"the FAIL they report against the DUT measures nothing\n%s", uid, c.Verdict, describeAssertions(c))
		}
	}
	assertClaim(t, out.result(t, UIDIdentitySAN), claimEmptySubject, certify.Pass, "empty SEQUENCE")
	assertClaim(t, out.result(t, UIDIdentitySAN), claimSANIdentity, certify.Pass, "othername: hwType=")
	assertClaim(t, out.result(t, UIDModelOIDPEN), claimModelOIDPEN, certify.Pass, "PEN 50316")
	assertClaim(t, out.result(t, UIDModelOIDPEN), claimPENPublished, certify.Pass, "rooted at PEN 50316")
	assertClaim(t, out.result(t, UIDSerialEncoding), claimSerialOctetString, certify.Pass, "OCTET STRING")
	assertClaim(t, out.result(t, UIDSerialEncoding), claimSerialUTF8, certify.Pass, "250905000023")

	verifyBundle(t, out)
}

// TestTransportAndChainRows exercises the six rows that drive the DUT rather
// than only inspecting its certificate, including the two that need the bench
// root's private key.
func TestTransportAndChainRows(t *testing.T) {
	h := testHierarchy(t)
	leaf, err := h.Mint(ShapeSERCAMICADevice, dutShapedLeafSpec("dut"))
	if err != nil {
		t.Fatal(err)
	}
	rec := newRecorder()
	p := startPeer(t, rec, leaf.TLSCertificate(), h.SERCA.Pool())
	out := runSuite(t, p, benchPKIDir(t, h),
		[]string{UIDMandatoryTLS, UIDSingleChain, UIDDeepestChain, UIDCAHierarchy, UIDCrossIssuer, UIDErrorCerts})

	// PKI-1: TLS on both sides, mutual authentication, nothing outside the
	// tunnel.
	tlsRow := out.result(t, UIDMandatoryTLS)
	if tlsRow.Verdict != certify.Pass {
		t.Errorf("PKI-1: verdict = %s, want PASS\n%s", tlsRow.Verdict, describeAssertions(tlsRow))
	}
	assertClaim(t, tlsRow, claimConnectionIsTLS, certify.Pass, "ClientHello")
	assertClaim(t, tlsRow, claimAllBytesInTLS, certify.Pass, "outside the record layer")
	assertClaim(t, tlsRow, claimDUTPresentsCert, certify.Pass, "chain of")
	assertClaim(t, tlsRow, claimDUTDemandsCert, certify.Pass, "CertificateRequest")
	assertClaim(t, tlsRow, claimCSIPLegIsTLS, certify.Skip, "never holds that socket")

	// PKI-8: the peer is stable, the framework varies.
	single := out.result(t, UIDSingleChain)
	if single.Verdict != certify.Pass {
		t.Errorf("PKI-8: verdict = %s, want PASS\n%s", single.Verdict, describeAssertions(single))
	}
	assertClaim(t, single, claimDUTChainStable, certify.Pass, "on all 3 connections")
	assertClaim(t, single, claimFrameworkVaries, certify.Pass, "distinct chains")

	// PKI-11: the peer is on a two-deep chain, which is a WARN with the reason,
	// not a DUT failure.
	deep := out.result(t, UIDDeepestChain)
	if deep.Verdict != certify.Warn {
		t.Errorf("PKI-11: verdict = %s, want WARN (the bench PKI is two-tier)\n%s",
			deep.Verdict, describeAssertions(deep))
	}
	assertClaim(t, deep, claimDeepestChain, certify.Warn, "mca-mica-dev is 3")
	assertClaim(t, deep, claimChainLinksHold, certify.Pass, "signature true")

	// PKI-19: the presented chain is one of the three valid shapes, and the
	// peer accepts a leaf at each depth.
	hier := out.result(t, UIDCAHierarchy)
	if hier.Verdict != certify.Pass {
		t.Errorf("PKI-19: verdict = %s, want PASS\n%s", hier.Verdict, describeAssertions(hier))
	}
	assertClaim(t, hier, claimHierarchyShape, certify.Pass, string(ShapeSERCAMICADevice))
	assertClaim(t, hier, claimAcceptsAllDepths, certify.Pass, "serca-mca-mica-device")

	// PKI-3: a peer chain under a second intermediate is validated.
	cross := out.result(t, UIDCrossIssuer)
	if cross.Verdict != certify.Pass {
		t.Errorf("PKI-3: verdict = %s, want PASS\n%s", cross.Verdict, describeAssertions(cross))
	}
	assertClaim(t, cross, claimIntermediatesDiffer, certify.Pass, "different certificates")
	assertClaim(t, cross, claimCrossIssuerAccepted, certify.Pass, "the DUT accepted the chain")

	// PKI-20: every error certificate is refused.
	errs := out.result(t, UIDErrorCerts)
	if errs.Verdict != certify.Pass {
		t.Errorf("PKI-20: verdict = %s, want PASS\n%s", errs.Verdict, describeAssertions(errs))
	}
	assertClaim(t, errs, claimErrorCertsRefused, certify.Pass, "expired")
	assertClaim(t, errs, claimAlertCode, certify.Skip, "defines neither which errors")

	verifyBundle(t, out)
}

// TestErrorCertificateRowFailsWhenThePeerAcceptsThem is the negative control for
// PKI-20: against a peer that does not verify client certificates, the row must
// FAIL. Without this the PASS above could mean "the fixtures never reached the
// peer".
func TestErrorCertificateRowFailsWhenThePeerAcceptsThem(t *testing.T) {
	h := testHierarchy(t)
	leaf, err := h.Mint(ShapeSERCAMICADevice, dutShapedLeafSpec("permissive"))
	if err != nil {
		t.Fatal(err)
	}
	rec := newRecorder()
	// clientRoots nil: the peer demands a certificate but verifies nothing —
	// exactly the non-conformance PKI-20 exists to catch.
	p := startPeer(t, rec, leaf.TLSCertificate(), nil)
	out := runSuite(t, p, benchPKIDir(t, h), []string{UIDErrorCerts})

	c := out.result(t, UIDErrorCerts)
	if c.Verdict != certify.Fail {
		t.Fatalf("PKI-20 against a peer that accepts expired and untrusted certificates: verdict = %s, "+
			"want FAIL\n%s", c.Verdict, describeAssertions(c))
	}
	assertClaim(t, c, claimErrorCertsRefused, certify.Fail, "ACCEPTED")
}

// TestCrossIssuerRowSkipsWithoutTheRootKey: a check that needs material the
// bench cannot mint must SKIP with the reason, never pass by default.
func TestCrossIssuerRowSkipsWithoutTheRootKey(t *testing.T) {
	h := testHierarchy(t)
	leaf, err := h.Mint(ShapeSERCAMICADevice, dutShapedLeafSpec("dut"))
	if err != nil {
		t.Fatal(err)
	}
	dir := benchPKIDir(t, h)
	removeFile(t, dir+"/ca-key.pem")

	rec := newRecorder()
	p := startPeer(t, rec, leaf.TLSCertificate(), h.SERCA.Pool())
	out := runSuite(t, p, dir, []string{UIDCrossIssuer, UIDCAHierarchy})

	cross := out.result(t, UIDCrossIssuer)
	if cross.Verdict != certify.Skip {
		t.Errorf("PKI-3 without the root key: verdict = %s, want SKIP\n%s", cross.Verdict, describeAssertions(cross))
	}
	if !strings.Contains(cross.Notes, "private key") {
		t.Errorf("PKI-3 notes = %q, want the missing-key reason", cross.Notes)
	}
	// PKI-19 keeps its presenter half and skips only the verifier half, which
	// is the point of splitting it.
	hier := out.result(t, UIDCAHierarchy)
	assertClaim(t, hier, claimHierarchyShape, certify.Pass, string(ShapeSERCAMICADevice))
	assertClaim(t, hier, claimAcceptsAllDepths, certify.Skip, "private key")
}

// TestUnreachableDUTIsNotAPass: a check that could not be carried out must be
// recorded as a failure with no conformance conclusion, never as a SKIP that a
// reader could mistake for "nothing wrong here".
func TestUnreachableDUTIsNotAPass(t *testing.T) {
	h := testHierarchy(t)
	leaf, err := h.Mint(ShapeSERCAMICADevice, dutShapedLeafSpec("dut"))
	if err != nil {
		t.Fatal(err)
	}
	rec := newRecorder()
	p := startPeer(t, rec, leaf.TLSCertificate(), h.SERCA.Pool())
	addr := p.addr()
	_ = p.lis.Close() // nothing is listening any more

	dead := &peer{lis: closedListener{addr: addr}, rec: rec}
	out := runSuite(t, dead, benchPKIDir(t, h), []string{UIDIdentitySAN})
	c := out.result(t, UIDIdentitySAN)
	if c.Verdict != certify.Fail {
		t.Fatalf("verdict = %s, want FAIL for a check that could not be carried out\n%s",
			c.Verdict, describeAssertions(c))
	}
	if c.Err == nil {
		t.Error("no error recorded")
	}
	found := false
	for _, a := range c.Assertions {
		if strings.Contains(a.Note, "no conformance conclusion") {
			found = true
		}
	}
	if !found {
		t.Errorf("no assertion says the row supports no conformance conclusion\n%s", describeAssertions(c))
	}
}

// TestWithoutACaptureNothingPasses: with -no-capture every wire-cited row must
// lose its PASS, because nothing in it is re-checkable.
func TestWithoutACaptureNothingPasses(t *testing.T) {
	h := testHierarchy(t)
	leaf, err := h.Mint(ShapeSERCAMICADevice, conformantLeafSpec("conformant-dut"))
	if err != nil {
		t.Fatal(err)
	}
	rec := newRecorder()
	p := startPeer(t, rec, leaf.TLSCertificate(), h.SERCA.Pool())
	out := runSuiteNoCapture(t, p, benchPKIDir(t, h), identityRows)

	for _, uid := range identityRows {
		c := out.result(t, uid)
		if c.Verdict == certify.Pass {
			t.Errorf("%s PASSED with no capture: nothing in it is re-checkable\n%s", uid, describeAssertions(c))
		}
	}
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// assertClaim finds an assertion by claim and checks its verdict and a
// substring of what it observed, so a check cannot silently stop asserting
// something or start asserting it for a different reason.
func assertClaim(t *testing.T, c *certify.CaseResult, claim string, want certify.Verdict, observedContains string) {
	t.Helper()
	for _, a := range c.Assertions {
		if a.Claim != claim {
			continue
		}
		if a.Verdict != want {
			t.Errorf("%s: claim %q verdict = %s, want %s (observed: %s)", c.Case.UID, claim, a.Verdict, want, a.Observed)
		}
		if observedContains != "" && !strings.Contains(a.Observed, observedContains) {
			t.Errorf("%s: claim %q observed = %q, want it to mention %q",
				c.Case.UID, claim, a.Observed, observedContains)
		}
		if want != certify.Skip && !a.Citable() {
			t.Errorf("%s: claim %q carries no re-checkable digest", c.Case.UID, claim)
		}
		return
	}
	t.Errorf("%s: no assertion for claim %q\n%s", c.Case.UID, claim, describeAssertions(c))
}

func verifyBundle(t *testing.T, out *runOutcome) {
	t.Helper()
	vr, err := bundle.Verify(out.dir)
	if err != nil {
		t.Fatalf("bundle.Verify: %v", err)
	}
	if !vr.OK {
		t.Fatalf("the bundle this suite produced does not verify:\n%s", vr.String())
	}
}
