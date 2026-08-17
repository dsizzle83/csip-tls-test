package certify

// paramscope_test.go — the ORACLE for PER-CASE procedure parameters
// (RunCtx.Param's scope resolution and New's typo refusal).
//
// # The gap these rows close
//
// The RC0 §9.5 bench battery could not certify row 12 ("full CSIP suite with
// zero applicable FAIL") in one run, and the reason was the parameter surface
// rather than the DUT (raw/SUITES.md):
//
//	"BASIC-029, CORE-022 and CORE-023 need per-run -param csip.wait and were
//	 NOT given it: the preflight doc records that setting csip.wait globally
//	 turned a 2 h campaign into 25 h, and the recorded driver runs them as three
//	 separate single--uid invocations. Not run here. BASIC-029 reconciled to
//	 PASS in this run and CORE-022 to WARN, but NEITHER VERDICT IS THE
//	 CERTIFIABLE ONE."
//
// -param was a FLAT GLOBAL MAP, so a wait budget three cases need was a wait
// budget all seventy-nine paid. The operator's only escapes were both bad:
// pay it everywhere (25 h) or split the campaign into separate invocations —
// which produces separate bundles, separate captures, and a row 12 nobody can
// point at one document for.
//
// A scope is the whole fix, and it is deliberately tiny: one lookup order in
// RunCtx.Param, plus a refusal for a scope naming a case the catalog does not
// have.

import (
	"strings"
	"testing"
)

// caseOf builds a RunCtx bound to one catalog case, which is the only state
// scope resolution reads.
func caseOf(t *testing.T, cat *Catalog, uid string, params map[string]string) *RunCtx {
	t.Helper()
	c, ok := cat.ByUID(uid)
	if !ok {
		t.Fatalf("the test catalog has no case %q", uid)
	}
	return &RunCtx{Case: c, Params: params}
}

// TestParamScopedToACaseBeatsTheGlobalOne is the row the bench needed: one run,
// one bundle, and a wait budget that only the cases that need it pay for.
func TestParamScopedToACaseBeatsTheGlobalOne(t *testing.T) {
	cat := loadTestCatalog(t)
	params := map[string]string{
		"csip.wait":           "30s",
		"doc-a::A-001:csip.wait": "8m",
	}

	scoped := caseOf(t, cat, "doc-a::A-001", params)
	if got, ok := scoped.Param("csip.wait"); !ok || got != "8m" {
		t.Errorf("the scoped case reads csip.wait = %q (ok=%v), want 8m — the whole point is that this "+
			"case, and only this case, gets the long budget", got, ok)
	}

	other := caseOf(t, cat, "doc-b::B-001", params)
	if got, ok := other.Param("csip.wait"); !ok || got != "30s" {
		t.Errorf("an unscoped case reads csip.wait = %q (ok=%v), want the global 30s — a scope that "+
			"leaked would re-create the 25-hour campaign it exists to avoid", got, ok)
	}
}

// TestParamScopeAcceptsEitherFormOfTheCaseName follows -uid's own convention:
// Filter.Matches accepts the globally unique uid OR the bare in-document id, so
// a scope that accepted only one of them would make the two flags disagree
// about what a case is called on the same command line.
func TestParamScopeAcceptsEitherFormOfTheCaseName(t *testing.T) {
	cat := loadTestCatalog(t)
	for _, form := range []string{"doc-a::A-001", "A-001", "a-001"} {
		rc := caseOf(t, cat, "doc-a::A-001", map[string]string{form + ":csip.wait": "8m"})
		if got, ok := rc.Param("csip.wait"); !ok || got != "8m" {
			t.Errorf("-param %s:csip.wait=8m was not honoured (got %q, ok=%v)", form, got, ok)
		}
	}
}

// TestParamScopeIsPreferredOverTheGlobalEvenWhenEmpty pins the precedence rule
// at its one ambiguous point. An operator who scopes a parameter to the EMPTY
// string is turning it off for that case; falling back to the global there
// would make "off" unexpressible, and RequireParam — which treats empty as
// absent — is the reason the distinction has to be decided here rather than
// left to each caller.
func TestParamScopeIsPreferredOverTheGlobalEvenWhenEmpty(t *testing.T) {
	cat := loadTestCatalog(t)
	rc := caseOf(t, cat, "doc-a::A-001", map[string]string{
		"csip.wait":              "30s",
		"doc-a::A-001:csip.wait": "",
	})
	got, ok := rc.Param("csip.wait")
	if !ok || got != "" {
		t.Errorf("Param = (%q, %v), want (\"\", true): a scope set to empty is an explicit override", got, ok)
	}
	if _, err := rc.RequireParam("csip.wait"); err == nil {
		t.Error("RequireParam accepted a parameter this case explicitly emptied")
	}
}

// TestRequireParamHonoursTheScope — every suite reads parameters through Param
// or RequireParam, so scope resolution living in those two functions is what
// makes the feature reach all of them at once. If RequireParam were left out,
// exactly the checks that DEMAND a parameter would be the ones that could not
// be scoped.
func TestRequireParamHonoursTheScope(t *testing.T) {
	cat := loadTestCatalog(t)
	rc := caseOf(t, cat, "doc-a::A-001", map[string]string{"A-001:ssm.unit": "7"})
	got, err := rc.RequireParam("ssm.unit")
	if err != nil || got != "7" {
		t.Fatalf("RequireParam = (%q, %v), want (7, nil)", got, err)
	}
}

// TestUnscopedParamsAreUnchanged is the compatibility row: every parameter on
// every recorded bench command line is unscoped, and none of them may change
// meaning.
func TestUnscopedParamsAreUnchanged(t *testing.T) {
	cat := loadTestCatalog(t)
	rc := caseOf(t, cat, "doc-a::A-001", map[string]string{"nameplate_w": "5000"})
	if got, ok := rc.Param("nameplate_w"); !ok || got != "5000" {
		t.Errorf("Param(nameplate_w) = (%q, %v), want (5000, true)", got, ok)
	}
	if _, ok := rc.Param("absent"); ok {
		t.Error("Param reported a parameter nobody set")
	}
	// A RunCtx with no Case at all — the shape several unit rigs build — must
	// still resolve globals rather than panic on the scope lookup.
	bare := &RunCtx{Params: map[string]string{"nameplate_w": "5000"}}
	if got, ok := bare.Param("nameplate_w"); !ok || got != "5000" {
		t.Errorf("a case-less RunCtx reads nameplate_w = (%q, %v), want (5000, true)", got, ok)
	}
}

// TestNewRefusesAParamScopedToACaseNobodyHas is the teeth.
//
// A mistyped scope is INVISIBLE without this: the run completes, the case takes
// the global value, and the bundle records a verdict the operator believes was
// measured under a budget that was never applied. That is the same silent-typo
// failure Catalog.Validate refuses for -doc and -uid and unknownSuites refuses
// for -suite, and it is refused here for the same reason and in the same place.
func TestNewRefusesAParamScopedToACaseNobodyHas(t *testing.T) {
	cat := catalogFile(t)
	reg := NewRegistry()

	for _, tc := range []struct {
		name, key string
	}{
		{"a case id that does not exist", "A-999:csip.wait"},
		{"a plausible typo of one that does", "A-O01:csip.wait"},
		{"a uid from another catalog", "csip-conf-v1.3::BASIC-029:csip.wait"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			opts := DefaultOptions()
			opts.Params = map[string]string{tc.key: "8m"}
			_, err := New(reg, cat, opts)
			if err == nil {
				t.Fatalf("-param %s=8m was accepted; a scope naming no case silently does nothing", tc.key)
			}
			if !strings.Contains(err.Error(), tc.key) {
				t.Errorf("the refusal does not name the offending parameter: %v", err)
			}
		})
	}

	// And the valid forms are accepted, or the refusal would be worse than the
	// gap it closes.
	for _, key := range []string{"doc-a::A-001:csip.wait", "A-001:csip.wait", "csip.wait", "nameplate_w"} {
		opts := DefaultOptions()
		opts.Params = map[string]string{key: "8m"}
		if _, err := New(reg, cat, opts); err != nil {
			t.Errorf("-param %s=8m was refused: %v", key, err)
		}
	}
}
