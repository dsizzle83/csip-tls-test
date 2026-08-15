package bundle

// loadbearing_test.go — the silent-skip class, closed structurally.
//
// The property under test is an arithmetic one and it is the whole reason the
// marker exists: Skip is severity 0, every roll-up here takes a maximum, and a
// maximum can only be RAISED — so before this change a case whose "did the
// device actually do it" assertion skipped rolled up to whatever its supporting
// wire assertions said, which on a healthy bench is PASS. Absence of
// measurement, reported as success, with nothing anywhere saying so.

import (
	"bytes"
	"encoding/json"
	"testing"
)

func assertion(v Verdict, loadBearing bool) Assertion {
	return Assertion{Claim: "c", Method: "m", Verdict: v, LoadBearing: loadBearing}
}

func marshalAssertionForTest(a Assertion) ([]byte, error) { return json.Marshal(a) }

func containsKey(b []byte, key string) bool { return bytes.Contains(b, []byte(`"`+key+`"`)) }

// THE DEFECT, and the fix. Same assertion set, one bool apart.
func TestRollUp_ASkipOnALoadBearingAssertionCapsTheCase(t *testing.T) {
	supporting := []Assertion{
		assertion(Pass, false), // the DUT fetched the control list
		assertion(Pass, false), // the control carried the mode
	}

	unmarked := TestCaseResult{Assertions: append(append([]Assertion{}, supporting...),
		assertion(Skip, false))}
	if got := unmarked.RollUp(); got != Pass {
		t.Fatalf("an UNMARKED skip rolls up to %s; the pre-existing behaviour is PASS and this test is "+
			"the record of what the marker changes", got)
	}

	marked := TestCaseResult{Assertions: append(append([]Assertion{}, supporting...),
		assertion(Skip, true))}
	if got := marked.RollUp(); got != Warn {
		t.Fatalf("a case whose LOAD-BEARING assertion skipped rolls up to %s, want WARN. Skip is "+
			"severity 0 and this roll-up takes a maximum, so without the cap the case passes on its "+
			"supporting wire assertions alone — which is absence of measurement reading as success", got)
	}
}

// The cap is a FLOOR, never a ceiling: a real failure must not be softened into
// a warning because some other assertion also skipped.
func TestRollUp_TheCapNeverLowersARealVerdict(t *testing.T) {
	for _, tc := range []struct {
		name string
		as   []Assertion
		want Verdict
	}{
		{"a FAIL beside an unmeasured load-bearing skip",
			[]Assertion{assertion(Fail, false), assertion(Skip, true)}, Fail},
		{"a load-bearing FAIL",
			[]Assertion{assertion(Pass, false), assertion(Fail, true)}, Fail},
		{"a WARN beside an unmeasured load-bearing skip",
			[]Assertion{assertion(Warn, false), assertion(Skip, true)}, Warn},
		{"a load-bearing assertion that DECIDED is not capped",
			[]Assertion{assertion(Pass, false), assertion(Pass, true)}, Pass},
		{"no assertions at all is still Skip",
			nil, Skip},
		{"every assertion skipped, none load-bearing",
			[]Assertion{assertion(Skip, false)}, Skip},
		{"every assertion skipped, one load-bearing",
			[]Assertion{assertion(Skip, false), assertion(Skip, true)}, Warn},
	} {
		if got := (TestCaseResult{Assertions: tc.as}).RollUp(); got != tc.want {
			t.Errorf("%s: RollUp = %s, want %s", tc.name, got, tc.want)
		}
	}
}

// Unmeasured is the predicate both roll-ups share, so it is asserted directly
// rather than only through them: the runner's worstOf and this file's RollUp
// must cap on exactly the same shape or a bundle would carry a case whose own
// assertions do not roll up to its stated verdict.
func TestAssertion_UnmeasuredIsSkipAndLoadBearingAndNothingElse(t *testing.T) {
	for _, tc := range []struct {
		v    Verdict
		lb   bool
		want bool
	}{
		{Skip, true, true},
		{Skip, false, false},
		{Pass, true, false},
		{Fail, true, false},
		{Warn, true, false},
	} {
		if got := assertion(tc.v, tc.lb).Unmeasured(); got != tc.want {
			t.Errorf("Assertion{%s, loadBearing=%t}.Unmeasured() = %t, want %t", tc.v, tc.lb, got, tc.want)
		}
	}
}

// The field is additive on the wire: a bundle written before the marker existed
// still loads, and a bundle whose assertions are all unmarked serialises without
// the key at all — so no pre-existing bundle's bytes, and therefore no
// pre-existing MANIFEST digest, is disturbed by this change.
func TestAssertion_LoadBearingIsOmittedWhenFalse(t *testing.T) {
	b, err := marshalAssertionForTest(assertion(Pass, false))
	if err != nil {
		t.Fatal(err)
	}
	if containsKey(b, "load_bearing") {
		t.Errorf("an unmarked assertion serialises the key: %s\nEvery bundle written before this field "+
			"existed would then differ from one written after it, for no change of content", b)
	}
	b, err = marshalAssertionForTest(assertion(Skip, true))
	if err != nil {
		t.Fatal(err)
	}
	if !containsKey(b, "load_bearing") {
		t.Errorf("a MARKED assertion does not serialise the key, so the cap would not survive a "+
			"round-trip through a bundle: %s", b)
	}
}
