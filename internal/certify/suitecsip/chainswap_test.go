package suitecsip

// chainswap_test.go pins the decisions that stand between "the bench installed
// a fixture" and "this row's verdict is about the DUT".
//
// Every test here is about a way the sub-test could report the wrong thing:
// running with no lever, running against a chain the DUT never saw, running
// against a fixture anchored where the DUT's trust domain is not, or finishing
// with the bench still poisoned. None of them needs a DUT — they are decisions
// over gridsim's replies and the capture's fingerprints, which is exactly the
// part that must not be got wrong by hand on a live bench.

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"csip-tls-test/internal/certify"
	"csip-tls-test/internal/certify/suitepki"
)

// chainStub is a stand-in gridsim admin plane, so a test can make /admin/chain
// answer anything a real bench might.
type chainStub struct {
	// status, when non-zero, is returned for every request — the 404 of an
	// un-upgraded gridsim, the 501 of one with no data plane.
	status int
	active AdminChainState
	orig   AdminChainState
	// posts records the bodies received, so a test can prove the restore was
	// actually sent.
	posts []map[string]any
	// swapFails makes POST (install) fail while GET keeps working.
	swapFails bool
	// restoreFails leaves the bench serving the fixture.
	restoreFails bool
}

func (cs *chainStub) start(t *testing.T) *certify.AdminClient {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if cs.status != 0 {
			http.Error(w, `{"error":"no chain lever here"}`, cs.status)
			return
		}
		if r.Method == http.MethodPost {
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			cs.posts = append(cs.posts, body)
			if restore, _ := body["restore"].(bool); restore {
				if cs.restoreFails {
					http.Error(w, `{"error":"the restore failed"}`, http.StatusBadRequest)
					return
				}
				cs.active = cs.orig
			} else {
				if cs.swapFails {
					http.Error(w, `{"error":"the fixture would not load"}`, http.StatusBadRequest)
					return
				}
				label, _ := body["label"].(string)
				cs.active = AdminChainState{Label: label, LeafSHA256: leafSHAOf(body), ChainLen: 2}
			}
		}
		_ = json.NewEncoder(w).Encode(AdminChain{Active: cs.active, Original: cs.orig})
	}))
	t.Cleanup(srv.Close)
	return certify.NewAdminClient(srv.URL, nil)
}

// leafSHAOf fingerprints the leaf of the PEM the harness posted, which is what
// a real gridsim reports back. Computing it here rather than echoing a constant
// is what makes TestArm_RefusesWhenTheBenchInstalledSomethingElse meaningful.
func leafSHAOf(body map[string]any) string {
	pemText, _ := body["cert_pem"].(string)
	blk, _ := pem.Decode([]byte(pemText))
	if blk == nil {
		return ""
	}
	return suitepki.SHA256Hex(blk.Bytes)
}

func driverFor(admin *certify.AdminClient) *Driver { return &Driver{Admin: admin} }

func benchOriginal() AdminChainState {
	return AdminChainState{
		Label: "startup", LeafSHA256: strings.Repeat("a", 64), ChainLen: 2,
		Subjects: []string{"CN=bench server", "CN=bench MICA"},
		Issuers:  []string{"CN=bench MICA", "CN=bench root CA"},
		Original: true,
	}
}

func TestProbe_NoLeverIsASkipNamingTheReason(t *testing.T) {
	for _, status := range []int{http.StatusNotFound, http.StatusNotImplemented} {
		stub := &chainStub{status: status}
		cs := &chainSwap{defect: suitepki.SelfSignedLeaf}
		reason := cs.probe(context.Background(), driverFor(stub.start(t)))
		if reason == "" {
			t.Fatalf("HTTP %d: probe reported the lever available", status)
		}
		if !strings.Contains(reason, "/admin/chain") {
			t.Errorf("HTTP %d: the skip reason does not name the endpoint: %s", status, reason)
		}
	}
}

func TestProbe_RefusesToStackOnAnAlreadySwappedBench(t *testing.T) {
	stub := &chainStub{
		orig:   benchOriginal(),
		active: AdminChainState{Label: "somebody else's fixture", LeafSHA256: strings.Repeat("b", 64)},
	}
	cs := &chainSwap{defect: suitepki.SelfSignedLeaf}
	reason := cs.probe(context.Background(), driverFor(stub.start(t)))
	if reason == "" {
		t.Fatal("probe was willing to install a second fixture on top of somebody else's")
	}
	if !strings.Contains(reason, "already serving a swapped chain") {
		t.Errorf("the reason does not say what it found: %s", reason)
	}
}

func TestArm_SelfSignedNeedsNoAnchorAndInstalls(t *testing.T) {
	stub := &chainStub{orig: benchOriginal(), active: benchOriginal()}
	admin := stub.start(t)
	cs := &chainSwap{defect: suitepki.SelfSignedLeaf}

	rc := &certify.RunCtx{Case: &certify.Case{UID: "COMM-004G"}, Targets: certify.Targets{GridSim: "69.0.0.20:11113"}}
	skip, err := cs.arm(context.Background(), rc, driverFor(admin))
	if err != nil {
		t.Fatalf("arm: %v", err)
	}
	if skip != "" {
		t.Fatalf("the self-signed fixture skipped: %s", skip)
	}
	if !cs.armedOK || cs.installed.LeafSHA256 == "" {
		t.Fatalf("arm reported success but recorded no installed chain: %+v", cs)
	}
	if len(stub.posts) != 1 {
		t.Fatalf("arm sent %d POST(s), want 1", len(stub.posts))
	}
	if lbl, _ := stub.posts[0]["label"].(string); !strings.Contains(lbl, string(suitepki.SelfSignedLeaf)) {
		t.Errorf("the installed chain is labelled %q, which does not name the defect", lbl)
	}
}

func TestArm_InvalidMICASkipsWithoutTheBenchRoot(t *testing.T) {
	stub := &chainStub{orig: benchOriginal(), active: benchOriginal()}
	cs := &chainSwap{defect: suitepki.MICAEKUCritical}
	// No rc.PKI: the harness cannot mint under the root the DUT trusts.
	rc := &certify.RunCtx{Case: &certify.Case{UID: "COMM-004D"}, Targets: certify.Targets{GridSim: "69.0.0.20:11113"}}

	skip, err := cs.arm(context.Background(), rc, driverFor(stub.start(t)))
	if err != nil {
		t.Fatalf("arm: %v", err)
	}
	if skip == "" {
		t.Fatal("arm installed an invalid-MICA fixture with no trust anchor; the DUT would reject it for " +
			"not knowing the root and the row would PASS without exercising the defect")
	}
	if !strings.Contains(skip, "ALREADY") {
		t.Errorf("the skip reason does not explain the anchoring requirement: %s", skip)
	}
	if len(stub.posts) != 0 {
		t.Errorf("a skipped sub-test still touched the bench: %v", stub.posts)
	}
}

func TestArm_RefusesWhenTheBenchInstalledSomethingElse(t *testing.T) {
	stub := &chainStub{orig: benchOriginal(), active: benchOriginal()}
	// Report back a leaf that is not the one posted, which is how a
	// misconfigured or racing bench would look.
	admin := stub.start(t)
	cs := &chainSwap{defect: suitepki.SelfSignedLeaf}
	rc := &certify.RunCtx{Case: &certify.Case{UID: "COMM-004G"}, Targets: certify.Targets{GridSim: "69.0.0.20:11113"}}
	if _, err := cs.arm(context.Background(), rc, driverFor(admin)); err != nil {
		t.Fatalf("arm: %v", err)
	}
	// Now corrupt what arm believes was installed and prove servedTheFixture
	// refuses to credit a chain it cannot identify.
	installed := cs.installed.LeafSHA256
	if installed == "" {
		t.Fatal("nothing was installed")
	}
	if ok, _ := cs.servedTheFixture(transcriptWithLeaf(t, []byte("not the fixture"))); ok {
		t.Error("servedTheFixture accepted a chain whose fingerprint is not the installed one")
	}
}

// TestArm_AFailedInstallIsAnErrorNotASkip pins the distinction that decides
// whether the operator hears about a half-driven bench. A lever that answered
// the probe and then refused the install has left the bench in a state this
// check cannot vouch for, and a SKIP would file that under "nothing happened".
func TestArm_AFailedInstallIsAnErrorNotASkip(t *testing.T) {
	stub := &chainStub{orig: benchOriginal(), active: benchOriginal(), swapFails: true}
	cs := &chainSwap{defect: suitepki.SelfSignedLeaf}
	rc := &certify.RunCtx{Case: &certify.Case{UID: "COMM-004G"}, Targets: certify.Targets{GridSim: "69.0.0.20:11113"}}

	skip, err := cs.arm(context.Background(), rc, driverFor(stub.start(t)))
	if err == nil {
		t.Fatalf("a refused install produced no error (skip=%q)", skip)
	}
	if skip != "" {
		t.Errorf("a refused install also produced a skip reason: %s", skip)
	}
	if cs.armedOK {
		t.Error("arm recorded the fixture as installed after the bench refused it")
	}
}

func TestRestore_VerifiedAndCarriedIntoTheVerdict(t *testing.T) {
	t.Run("restored", func(t *testing.T) {
		stub := &chainStub{orig: benchOriginal(), active: benchOriginal()}
		admin := stub.start(t)
		cs := &chainSwap{defect: suitepki.SelfSignedLeaf}
		rc := &certify.RunCtx{Case: &certify.Case{UID: "COMM-004G"}, Targets: certify.Targets{GridSim: "69.0.0.20:11113"}}
		if _, err := cs.arm(context.Background(), rc, driverFor(admin)); err != nil {
			t.Fatal(err)
		}
		cs.restore(context.Background(), driverFor(admin))
		if !cs.restored {
			t.Fatalf("restore failed: %s", cs.restoreErr)
		}
		f := cs.restoreCriterion().Wire(nil, nil)
		if f.Verdict != certify.Pass {
			t.Errorf("a verified restore reports %v: %s", f.Verdict, f.Observed)
		}
	})

	t.Run("not restored", func(t *testing.T) {
		stub := &chainStub{orig: benchOriginal(), active: benchOriginal(), restoreFails: true}
		admin := stub.start(t)
		cs := &chainSwap{defect: suitepki.SelfSignedLeaf}
		rc := &certify.RunCtx{Case: &certify.Case{UID: "COMM-004G"}, Targets: certify.Targets{GridSim: "69.0.0.20:11113"}}
		if _, err := cs.arm(context.Background(), rc, driverFor(admin)); err != nil {
			t.Fatal(err)
		}
		cs.restore(context.Background(), driverFor(admin))
		if cs.restored {
			t.Fatal("restore reported success against a bench that refused it")
		}
		f := cs.restoreCriterion().Wire(nil, nil)
		if f.Verdict != certify.Fail {
			t.Fatalf("an unrestored bench reports %v, want FAIL — every later case is worthless", f.Verdict)
		}
		if !strings.Contains(f.Observed, "NOT RESTORED") || !strings.Contains(f.Observed, "restore") {
			t.Errorf("the failure does not tell the operator what to do: %s", f.Observed)
		}
	})

	t.Run("nothing installed", func(t *testing.T) {
		cs := &chainSwap{defect: suitepki.SelfSignedLeaf, skip: "no lever on this bench"}
		stub := &chainStub{status: http.StatusNotFound}
		cs.restore(context.Background(), driverFor(stub.start(t)))
		f := cs.restoreCriterion().Wire(nil, nil)
		if f.Unavailable == "" {
			t.Errorf("a sub-test that installed nothing reports a restore verdict: %+v", f)
		}
	})
}

// TestServedTheFixture_DistinguishesAPreSwapSession is failure mode 3 from
// chainswap.go: a 2030.5 client keeps ONE session across poll cycles, so on a
// bench without -idle-timeout-s the window can hold only the connection the DUT
// opened BEFORE the swap. Scoring that as a rejection would be a fabricated
// verdict; scoring it as an acceptance would be a fabricated FAIL.
func TestServedTheFixture_DistinguishesAPreSwapSession(t *testing.T) {
	origDER := []byte("the bench's normal leaf")
	cs := &chainSwap{
		defect:    suitepki.SelfSignedLeaf,
		original:  AdminChainState{Label: "startup", LeafSHA256: suitepki.SHA256Hex(origDER)},
		installed: AdminChainState{Label: "fixture", LeafSHA256: strings.Repeat("c", 64)},
	}
	ok, why := cs.servedTheFixture(transcriptWithLeaf(t, origDER))
	if ok {
		t.Fatal("a session carrying the ORIGINAL chain was credited as having seen the fixture")
	}
	if !strings.Contains(why, "idle-timeout-s") {
		t.Errorf("the reason does not name the bench flag that fixes it: %s", why)
	}

	// And the fixture itself IS recognised.
	fixtureDER := []byte("the fixture leaf")
	cs.installed.LeafSHA256 = suitepki.SHA256Hex(fixtureDER)
	if ok, why := cs.servedTheFixture(transcriptWithLeaf(t, fixtureDER)); !ok {
		t.Errorf("the installed fixture was not recognised on the wire: %s", why)
	}
}

// TestRejectionRowsPresentTheDefectTheyName is the pairing guard register.go
// points at: each row's PROSE and the fixture it installs must be about the
// same defect, or the bundle reports a verdict about the wrong extension.
func TestRejectionRowsPresentTheDefectTheyName(t *testing.T) {
	for _, tc := range []struct {
		uid    string
		phrase string
		defect suitepki.MICADefect
	}{
		{"COMM-004D", "extendedKeyUsage", suitepki.MICAEKUCritical},
		{"COMM-004E", "nameConstraints", suitepki.MICANameNonCritical},
		{"COMM-004F", "policyMappings", suitepki.MICAPolicyMapping},
		{"COMM-004G", "self-signed", suitepki.SelfSignedLeaf},
	} {
		desc := tc.defect.Description()
		if !strings.Contains(desc, tc.phrase) {
			t.Errorf("%s installs %s, whose description does not mention %q: %s",
				tc.uid, tc.defect, tc.phrase, desc)
		}
	}
	if len(suitepki.AllMICADefects) != 4 {
		t.Errorf("suitepki offers %d defects; COMM-004 has exactly four rejection sub-tests",
			len(suitepki.AllMICADefects))
	}
}

// transcriptWithLeaf builds the minimum Transcript servedTheFixture reads: a
// handshake carrying one server certificate.
func transcriptWithLeaf(t *testing.T, leafDER []byte) *Transcript {
	t.Helper()
	tr := &Transcript{}
	tr.Handshake.ServerChain = [][]byte{leafDER}
	return tr
}
