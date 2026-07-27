package certify

import (
	"context"
	"strings"
	"testing"
)

func noopCheck(context.Context, *RunCtx) (Result, error) { return Skipped("noop"), nil }

func TestRegisterRejectsDuplicates(t *testing.T) {
	r := NewRegistry()
	r.Register("doc-a::A-001", "tls", noopCheck)
	defer func() {
		v := recover()
		if v == nil {
			t.Fatal("registering the same uid twice did not panic")
		}
		if !strings.Contains(strings.ToLower(pstr(v)), "registered twice") {
			t.Errorf("panic = %v", v)
		}
	}()
	r.Register("doc-a::A-001", "rbac", noopCheck)
}

func TestRegisterRejectsMalformedRegistrations(t *testing.T) {
	for _, tc := range []struct {
		name string
		fn   func(*Registry)
	}{
		{"empty uid", func(r *Registry) { r.Register("", "s", noopCheck) }},
		{"empty suite", func(r *Registry) { r.Register("u", "", noopCheck) }},
		{"nil check", func(r *Registry) { r.Register("u", "s", nil) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				if recover() == nil {
					t.Error("did not panic")
				}
			}()
			tc.fn(NewRegistry())
		})
	}
}

// Coverage is the deliverable: it must name what is NOT implemented, not just
// count what is.
func TestCoverageNamesTheGaps(t *testing.T) {
	cat := loadTestCatalog(t)
	r := NewRegistry()
	r.Register("doc-a::A-001", "tls", noopCheck)
	r.Register("doc-a::A-003", "agg", noopCheck) // an inapplicable case, implemented anyway

	cov := r.Coverage(cat, Filter{})
	if len(cov.Docs) != 2 {
		t.Fatalf("docs = %d", len(cov.Docs))
	}
	total, applicable, implemented, missing := cov.Totals()
	if total != 4 || applicable != 3 || implemented != 2 || missing != 2 {
		t.Errorf("totals = %d/%d/%d/%d, want 4/3/2/2", total, applicable, implemented, missing)
	}
	if cov.Complete() {
		t.Error("Complete() is true while A-002 and B-001 have no implementation")
	}

	docA := cov.Docs[0]
	if docA.Doc != "DOC-A" {
		t.Fatalf("first doc = %s", docA.Doc)
	}
	if len(docA.Unimplemented) != 1 || docA.Unimplemented[0].ID != "A-002" {
		t.Errorf("DOC-A unimplemented = %+v, want just A-002", docA.Unimplemented)
	}
	// A-003 is inapplicable BUT implemented, so it counts as implemented and
	// does not appear as an unexplained gap.
	if len(docA.Inapplicable) != 0 {
		t.Errorf("DOC-A inapplicable = %+v, want none (A-003 has a check)", docA.Inapplicable)
	}
	if len(docA.Implemented) != 2 {
		t.Errorf("DOC-A implemented = %d, want 2", len(docA.Implemented))
	}
	if docA.Implemented[0].Suite != "tls" {
		t.Errorf("A-001 suite = %q", docA.Implemented[0].Suite)
	}
}

// An inapplicable case with no implementation is explained, not counted as a
// gap: the reason travels with it.
func TestCoverageExplainsInapplicableCases(t *testing.T) {
	cat := loadTestCatalog(t)
	cov := NewRegistry().Coverage(cat, Filter{})
	var found *CoverageEntry
	for i, e := range cov.Docs[0].Inapplicable {
		if e.ID == "A-003" {
			found = &cov.Docs[0].Inapplicable[i]
		}
	}
	if found == nil {
		t.Fatal("A-003 is not listed as inapplicable")
	}
	if !strings.Contains(found.Reason, "Aggregator-client profile") {
		t.Errorf("reason = %q, want the catalog's applicability_reason", found.Reason)
	}
	for _, d := range cov.Docs {
		for _, e := range d.Unimplemented {
			if e.ID == "A-003" {
				t.Error("an inapplicable case was reported as an unimplemented gap")
			}
		}
	}
}

// A registration for a uid the catalog does not contain means the suite and the
// specification have diverged. Coverage must surface it even when the filter
// excludes everything else.
func TestCoverageReportsOrphans(t *testing.T) {
	cat := loadTestCatalog(t)
	r := NewRegistry()
	r.Register("doc-a::A-001", "tls", noopCheck)
	r.Register("doc-z::GONE-001", "tls", noopCheck)

	cov := r.Coverage(cat, Filter{Docs: []string{"DOC-B"}})
	if len(cov.Orphans) != 1 || cov.Orphans[0] != "doc-z::GONE-001" {
		t.Fatalf("orphans = %v", cov.Orphans)
	}
	if cov.Complete() {
		t.Error("Complete() is true despite an orphaned registration")
	}
}

func TestCoverageRespectsTheFilter(t *testing.T) {
	cat := loadTestCatalog(t)
	r := NewRegistry()
	r.Register("doc-b::B-001", "csip", noopCheck)

	cov := r.Coverage(cat, Filter{Docs: []string{"DOC-B"}})
	if len(cov.Docs) != 1 || cov.Docs[0].Doc != "DOC-B" {
		t.Fatalf("docs = %+v", cov.Docs)
	}
	if !cov.Complete() {
		t.Errorf("DOC-B is fully implemented but Complete() = false: %+v", cov.Docs[0])
	}
}

func TestMissingCapabilities(t *testing.T) {
	reg := Registration{UID: "u", Suite: "s", Requires: []string{"keylog", "gridsim", "bench"}}
	got := reg.MissingCapabilities(map[string]bool{"bench": true, "gridsim": false})
	if strings.Join(got, ",") != "gridsim,keylog" {
		t.Errorf("missing = %v", got)
	}
	if n := reg.MissingCapabilities(map[string]bool{"keylog": true, "gridsim": true, "bench": true}); len(n) != 0 {
		t.Errorf("missing = %v, want none", n)
	}
}

func TestResultRollUpTakesTheWorst(t *testing.T) {
	tests := []struct {
		name string
		res  Result
		want Verdict
	}{
		{"empty is a skip", Result{}, Skip},
		{"declared pass with a failing assertion", Result{
			Verdict:    Pass,
			Assertions: []Assertion{{Verdict: Pass}, {Verdict: Fail}},
		}, Fail},
		{"declared fail with passing assertions", Result{
			Verdict:    Fail,
			Assertions: []Assertion{{Verdict: Pass}},
		}, Fail},
		{"warn beats pass", Result{Assertions: []Assertion{{Verdict: Pass}, {Verdict: Warn}}}, Warn},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.res.rollUp(); got != tc.want {
				t.Errorf("rollUp = %s, want %s", got, tc.want)
			}
		})
	}
}

func pstr(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	if e, ok := v.(error); ok {
		return e.Error()
	}
	return ""
}
