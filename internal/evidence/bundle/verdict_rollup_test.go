package bundle

// verdict_rollup_test.go — the case verdict, re-derived from its own assertions.
//
// Verify used to re-check every citation and never the arithmetic on top of
// them (IW15 M2). A bundle whose stored verdict had been edited — FAIL rewritten
// to PASS, the manifest refreshed to cover it — verified clean while its own
// REPORT.md still printed the FAIL assertion under the PASS heading. Every
// citation in that bundle was true; the sentence a reader acts on was not.
//
// The rule under test is an INEQUALITY, not an equality, and the two tests that
// matter most here are the ones that pin each side of it: a stored verdict may
// be STRICTER than its assertions (the runner downgrades an uncited PASS, and a
// run with no capture, on purpose) and may never be WEAKER. See
// verifyCaseVerdicts for the derivation of that rule from
// internal/certify/runner.go's finalise and citeWithoutCapture.

import (
	"strings"
	"testing"
)

// THE FINDING: a stored verdict that its own assertions do not support.
func TestVerifyRefusesAVerdictWeakerThanItsAssertions(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(*Bundle)
		want []string
	}{
		{
			name: "a FAIL assertion under a PASS heading",
			edit: func(b *Bundle) {
				b.Cases[0].Assertions[1].Verdict = Fail
				b.Cases[0].Verdict = Pass
			},
			want: []string{"records verdict PASS", "roll up to FAIL", "RBAC-004"},
		},
		{
			name: "a WARN laundered into a PASS",
			edit: func(b *Bundle) {
				b.Cases[0].Assertions[0].Verdict = Warn
				b.Cases[0].Verdict = Pass
			},
			want: []string{"records verdict PASS", "roll up to WARN"},
		},
		{
			name: "a load-bearing skip laundered into a PASS",
			edit: func(b *Bundle) {
				// The silent-skip class: nobody measured the case's whole
				// subject, so RollUp caps it at WARN. A stored PASS over it is
				// absence of measurement reported as success.
				b.Cases[0].Assertions[1].Verdict = Skip
				b.Cases[0].Assertions[1].LoadBearing = true
				b.Cases[0].Verdict = Pass
			},
			want: []string{"records verdict PASS", "roll up to WARN", "load-bearing, unmeasured"},
		},
		{
			name: "a verdict outside the four this package defines",
			edit: func(b *Bundle) { b.Cases[0].Verdict = Verdict("PASSED") },
			want: []string{"not one of PASS/FAIL/SKIP/WARN"},
		},
		{
			name: "a verdict erased entirely",
			edit: func(b *Bundle) { b.Cases[0].Verdict = Verdict("") },
			want: []string{"not one of PASS/FAIL/SKIP/WARN"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir, _, _ := buildBundle(t)
			editBundle(t, dir, tc.edit)
			rep, err := Verify(dir)
			if err != nil {
				t.Fatal(err)
			}
			if rep.OK {
				t.Fatalf("verification passed a case verdict its own assertions contradict:\n%s", rep)
			}
			joined := strings.Join(rep.Problems, "\n")
			for _, want := range tc.want {
				if !strings.Contains(joined, want) {
					t.Errorf("problems do not say %q:\n%s", want, joined)
				}
			}
		})
	}
}

// THE OTHER SIDE OF THE RULE, and the reason it is not an equality: the runner
// records verdicts STRICTER than the raw roll-up on purpose, and the archive is
// full of them. runs/tail-fullsuite-20260801T173831 carries eighteen — sixteen
// WARN over a PASS roll-up (finalise's uncited-PASS downgrade) and two WARN over
// a SKIP one. A verifier demanding equality would call that clean bundle
// tampered, which is the failure mode this test exists to prevent.
func TestVerifyAcceptsTheRunnersOwnDowngrades(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(*Bundle)
	}{
		{
			name: "WARN stored over a PASS roll-up — the uncited-PASS downgrade",
			edit: func(b *Bundle) {
				b.Cases[0].Verdict = Warn
				b.Cases[0].Notes = "PASS downgraded to WARN: no assertion carries a digest the bundle's " +
					"verifier can re-derive from the capture"
			},
		},
		{
			name: "WARN stored over a SKIP roll-up — the no-capture downgrade",
			edit: func(b *Bundle) {
				for i := range b.Cases[0].Assertions {
					b.Cases[0].Assertions[i].Verdict = Skip
				}
				b.Cases[0].Verdict = Warn
			},
		},
		{
			name: "FAIL stored over a PASS roll-up — a case failed for a reason outside its assertions",
			edit: func(b *Bundle) { b.Cases[0].Verdict = Fail },
		},
		{
			name: "PASS stored on a case with no assertions at all",
			edit: func(b *Bundle) {
				b.Cases[2].Assertions = nil
				b.Cases[2].Verdict = Pass
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir, _, _ := buildBundle(t)
			editBundle(t, dir, tc.edit)
			rep, err := Verify(dir)
			if err != nil {
				t.Fatal(err)
			}
			if !rep.OK {
				t.Fatalf("a verdict STRICTER than its assertions is the framework being honest about "+
					"weak evidence, and must verify: %v", rep.Problems)
			}
		})
	}
}

// The re-derivation runs on every case, and says so, so a reader can tell the
// check happened rather than inferring it from the absence of complaints.
func TestVerifyCountsEveryCaseItRolledUp(t *testing.T) {
	dir, _, _ := buildBundle(t)
	rep, err := Verify(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !rep.OK {
		t.Fatalf("fixture bundle does not verify: %v", rep.Problems)
	}
	if rep.CasesRolledUp != 3 {
		t.Errorf("re-derived %d case verdicts, want 3", rep.CasesRolledUp)
	}
	if !strings.Contains(rep.String(), "case verdict(s) re-derived from their own assertions") {
		t.Errorf("the verify report does not mention the re-derivation:\n%s", rep.String())
	}
}

// A bundle with no capture at all still gets its arithmetic checked. The
// citation phase has nothing to do there, and that is precisely the bundle in
// which a laundered verdict would otherwise be invisible.
func TestVerdictRollUpIsCheckedWithoutACapture(t *testing.T) {
	dir, _, _ := buildBundle(t)
	editBundle(t, dir, func(b *Bundle) {
		b.Files.Capture = ""
		b.Cases[0].Assertions[1].Verdict = Fail
		b.Cases[0].Verdict = Pass
	})
	rep, err := Verify(dir)
	if err != nil {
		t.Fatal(err)
	}
	if rep.OK {
		t.Fatal("a capture-less bundle must still have its verdicts re-derived")
	}
	if !strings.Contains(strings.Join(rep.Problems, "\n"), "roll up to FAIL") {
		t.Errorf("problems = %v", rep.Problems)
	}
}
