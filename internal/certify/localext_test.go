package certify

// localext_test.go — the ORACLE for the LOCAL EXTENSION family's one guarantee:
// a row no published procedure covers can be measured, bundled and verified, and
// can NEVER turn a conformance campaign red.
//
// The guarantee has two halves and both matter. If an EXT FAIL flipped the exit
// criterion, a bench row measuring an axis nobody certifies would fail the
// campaign — and the row would have to be deleted to get a clean run, which is
// how coverage gets lost. If an EXT row were merely SKIPPED, the evidence would
// not exist at all and the axis would stay unmeasured, which is the gap the
// family was created to close.

import (
	"testing"
)

func ptrBool(b bool) *bool { return &b }

// TestBearsOnClaim_SeparatesTheSpecificationFromTheProduct pins the one
// definition every tally reads.
func TestBearsOnClaim_SeparatesTheSpecificationFromTheProduct(t *testing.T) {
	for _, tc := range []struct {
		name        string
		c           *Case
		wantOnClaim bool
	}{
		{"a published procedure that applies", &Case{Applicable: true}, true},
		{"a published procedure that does not apply to this product",
			&Case{Applicable: false}, false},
		{"an axis that applies, covered by no procedure",
			&Case{Applicable: true, Certifiable: ptrBool(false)}, false},
		{"an explicit certifiable:true is the same as absent",
			&Case{Applicable: true, Certifiable: ptrBool(true)}, true},
		{"nil case", nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.c.BearsOnClaim(); got != tc.wantOnClaim {
				t.Errorf("BearsOnClaim() = %v, want %v", got, tc.wantOnClaim)
			}
		})
	}
}

// TestNonCertifiableFailDoesNotFlipTheExitCriterion is the guarantee itself, and
// the reason the field exists. `applicable:false` alone never did this — the old
// OK() aggregated every FAIL — so an informative row's failure took the process
// exit code with it.
func TestNonCertifiableFailDoesNotFlipTheExitCriterion(t *testing.T) {
	clean := &RunReport{Cases: []CaseResult{
		{Case: &Case{UID: "doc-a::A-001", Applicable: true}, Verdict: Pass},
	}}
	if !clean.OK() {
		t.Fatal("a run with one passing certifiable case is not OK")
	}

	withExtFail := &RunReport{Cases: []CaseResult{
		{Case: &Case{UID: "doc-a::A-001", Applicable: true}, Verdict: Pass},
		{Case: &Case{UID: "local-ext-v1::EXT-001", Applicable: true,
			Certifiable: ptrBool(false)}, Verdict: Fail},
	}}
	if !withExtFail.OK() {
		t.Error("a FAIL on a row NO PUBLISHED PROCEDURE COVERS turned the campaign red. The zero-FAIL " +
			"criterion is stated over a specification; a row that specification does not contain cannot " +
			"decide it")
	}

	// …and the failure is still fully visible, or the exclusion would be a
	// silent one.
	_, fail, _, _, _ := withExtFail.Counts()
	if fail != 1 {
		t.Errorf("Counts() reports %d FAIL, want 1: the exclusion must re-attribute the failure, not hide it", fail)
	}
	app, inf := withExtFail.CountsByClaim()
	if app.Fail != 0 || inf.Fail != 1 {
		t.Errorf("CountsByClaim = applicable %d FAIL / informative %d FAIL, want 0 / 1", app.Fail, inf.Fail)
	}
}

// TestCertifiableFailStillFlipsTheExitCriterion is the teeth. An exclusion that
// swallowed a real conformance failure would be far worse than the gap it
// closes.
func TestCertifiableFailStillFlipsTheExitCriterion(t *testing.T) {
	r := &RunReport{Cases: []CaseResult{
		{Case: &Case{UID: "doc-a::A-001", Applicable: true}, Verdict: Fail},
		{Case: &Case{UID: "local-ext-v1::EXT-001", Applicable: true,
			Certifiable: ptrBool(false)}, Verdict: Pass},
	}}
	if r.OK() {
		t.Fatal("a FAIL on a published, applicable procedure did NOT turn the campaign red")
	}
}

// TestTheCommittedCatalogsExtensionFamilyIsNonCertifiable pins the shipped data,
// not just the mechanism. A family whose catalog record forgot the marker would
// be an ordinary conformance case wearing an EXT- name, and its FAIL would count.
func TestTheCommittedCatalogsExtensionFamilyIsNonCertifiable(t *testing.T) {
	path, perr := DefaultCatalogPath()
	if perr != nil {
		t.Skipf("committed catalog not locatable here: %v", perr)
	}
	cat, err := Load(path)
	if err != nil {
		t.Skipf("committed catalog not loadable here: %v", err)
	}
	var seen int
	for _, c := range cat.All() {
		if c.Doc != "LOCAL-EXT-v1" {
			continue
		}
		seen++
		if c.Certifiable == nil || *c.Certifiable {
			t.Errorf("%s is in the local-extension family and is not marked certifiable:false, so its "+
				"FAIL would count as a certification failure", c.UID)
		}
		if c.BearsOnClaim() {
			t.Errorf("%s bears on the certification claim", c.UID)
		}
		// The posture has to be stated where a reader of the bundle meets it.
		if c.Notes == "" {
			t.Errorf("%s carries no notes stating why it is not a conformance procedure", c.UID)
		}
	}
	if seen == 0 {
		t.Fatal("the committed catalog has no LOCAL-EXT-v1 cases, so this row proves nothing")
	}
	// And every OTHER case must be untouched by the new field.
	for _, c := range cat.All() {
		if c.Doc != "LOCAL-EXT-v1" && c.Certifiable != nil {
			t.Errorf("%s carries an explicit certifiable marker; published procedures should leave it "+
				"absent so their meaning is unchanged", c.UID)
		}
	}
}
