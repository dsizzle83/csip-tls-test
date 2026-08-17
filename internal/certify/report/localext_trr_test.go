package report

// localext_trr_test.go — the ordering pin for MapVerdict's two exclusion tests.

import (
	"strings"
	"testing"

	"csip-tls-test/internal/evidence/bundle"
)

// TestMapVerdict_NoCertBasisOutranksUnrouted pins the order the local-extension
// family depends on.
//
// GATE FINDING D1-a: NoCertificationBasis was checked AFTER the DocCertType
// routing test, so a document in the first map and not the second could never
// reach its own reason. LOCAL-EXT-v1 is precisely that document, and every
// extension verdict filed as GapUnrouted — "no Results Reporting specification
// governs document ...", which reads as a harness misconfiguration a reviewer
// should chase, when the truth is a deliberate posture.
func TestMapVerdict_NoCertBasisOutranksUnrouted(t *testing.T) {
	c := bundle.TestCaseResult{ID: "local-ext-v1::EXT-001", Verdict: bundle.Fail}
	tv, gap := MapVerdict(c, nil, "run")
	if tv != nil {
		t.Fatalf("an extension row earned a Test row in the submission: %+v", tv)
	}
	if gap == nil {
		t.Fatal("no gap recorded for an extension row")
	}
	if gap.Kind != GapNoCertBasis {
		t.Errorf("gap kind = %q, want %q — an unrouted gap reads as a misconfiguration to close, not as "+
			"a family nobody certifies", gap.Kind, GapNoCertBasis)
	}
	// The reviewer must get the POSTURE, in the words the family states it in.
	for _, want := range []string{"not a specification", "certifiable=false", "no certification for them to be a result OF"} {
		if !strings.Contains(gap.Reason, want) {
			t.Errorf("the gap reason does not carry %q:\n%s", want, gap.Reason)
		}
	}
}

// TestMapVerdict_ReorderingChangedOnlyTheExtensionFamily is the
// behaviour-preserving half. The two maps are NOT disjoint, so the claim that
// moving one above the other is safe rests on the three shared keys already
// resolving to no-certification-basis under the old order — which they did,
// because they are routed and therefore fell through the routing test.
func TestMapVerdict_ReorderingChangedOnlyTheExtensionFamily(t *testing.T) {
	// Shared keys: routed AND no-certification-basis. Unchanged by the move.
	for _, uid := range []string{
		"ssm-conf-v0.8::CRYP-001",
		"ss-modbus-client-conf-v1.1::READ-1",
		"ss-test-pki::PKI-4",
	} {
		_, gap := MapVerdict(bundle.TestCaseResult{ID: uid, Verdict: bundle.Pass}, nil, "run")
		if gap == nil || gap.Kind != GapNoCertBasis {
			t.Errorf("%s: gap = %+v, want kind %q — this document was already excluded on this ground "+
				"before the reorder and must still be", uid, gap, GapNoCertBasis)
		}
	}
	// Routed and certifiable: still produces a real Test row.
	tv, gap := MapVerdict(bundle.TestCaseResult{ID: "csip-conf-v1.3::BASIC-006", Verdict: bundle.Pass}, nil, "run")
	if gap != nil || tv == nil || tv.Verdict != "PASS" {
		t.Errorf("a routed, certifiable PASS no longer files a Test row: tv=%+v gap=%+v", tv, gap)
	}
	// Neither routed nor excluded: still unrouted.
	_, gap = MapVerdict(bundle.TestCaseResult{ID: "made-up-doc::X-1", Verdict: bundle.Pass}, nil, "run")
	if gap == nil || gap.Kind != GapUnrouted {
		t.Errorf("an unknown document no longer reports as unrouted: %+v", gap)
	}
}
