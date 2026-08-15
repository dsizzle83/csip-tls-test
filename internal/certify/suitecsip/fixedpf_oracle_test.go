package suitecsip

// fixedpf_oracle_test.go — teeth for the fixed-PF DIRECTION oracle, and the
// red proof against the product's excitation inversion.

import (
	"strings"
	"testing"

	"csip-tls-test/internal/certify"
	"lexa-proto/sunspec"
)

// TestFixedPFDirection_TheTranscribedPolarityIsTheStandardsOwn pins the one
// negation in this suite against the sentence it comes from.
//
// Everything else in this file depends on wantExt being right, and "right" here
// is counter-intuitive: "excitation on" sounds like more field and therefore
// over-excited, and the standard says the opposite. This tree stated the
// polarity in four places and got it wrong in all four (IW15-030 finding 2),
// so the mapping is asserted against the quoted sentence rather than against
// anybody's summary of it.
func TestFixedPFDirection_TheTranscribedPolarityIsTheStandardsOwn(t *testing.T) {
	// The sentence must say what this suite thinks it says.
	for _, want := range []string{
		"True when DER is absorbing reactive power (under-excited)",
		"false when DER is injecting reactive power (over-excited)",
	} {
		if !strings.Contains(excitationSentence, want) {
			t.Fatalf("the transcribed 2018 p.258 sentence does not contain %q: %q", want, excitationSentence)
		}
	}
	// TRUE = absorbing = under-excited = SunSpec's UnderExcited(1).
	if reg, words := wantExt(true); reg != sunspec.M704_Ext_UnderExcited ||
		!strings.Contains(words, "under-excited") {
		t.Errorf("excitation=true maps to Ext=%d (%q); 2018 p.258 makes TRUE the absorbing, "+
			"under-excited direction, which SunSpec model 704 numbers %d",
			reg, words, sunspec.M704_Ext_UnderExcited)
	}
	// FALSE = injecting = over-excited = OverExcited(0).
	if reg, words := wantExt(false); reg != sunspec.M704_Ext_OverExcited ||
		!strings.Contains(words, "over-excited") {
		t.Errorf("excitation=false maps to Ext=%d (%q); 2018 p.258 makes FALSE the injecting, "+
			"over-excited direction, which SunSpec model 704 numbers %d",
			reg, words, sunspec.M704_Ext_OverExcited)
	}
	// The two enum values are genuinely distinct, or the whole comparison is
	// vacuous.
	if sunspec.M704_Ext_OverExcited == sunspec.M704_Ext_UnderExcited {
		t.Fatal("model 704's Ext enumeration has collapsed to one value")
	}
	// And the row-side helper agrees with the oracle-side transcription. They
	// are derived independently — FixedPFSettings.OverExcited() negates for the
	// SunSpec vocabulary, wantExt selects a register — and if they ever
	// disagree, one of them has re-introduced the missing negation.
	for _, excitation := range []bool{true, false} {
		s := FixedPFSettings{Displacement: 900, Excitation: excitation, Multiplier: -3}
		reg, _ := wantExt(excitation)
		wantOver := reg == sunspec.M704_Ext_OverExcited
		if s.OverExcited() != wantOver {
			t.Errorf("excitation=%t: FixedPFSettings.OverExcited()=%t but wantExt selects %s",
				excitation, s.OverExcited(), extWords(reg))
		}
	}
}

// figure8Applied is model 704 as a CORRECT gateway leaves it for
// figure8FixedPF — 0.900 with excitation=false, which 2018 p.258 makes the
// injecting, OVER-excited direction, i.e. Ext=0.
func figure8Applied() sunspec.ACControls {
	return sunspec.ACControls{
		PFWInjEna: true, PFWInjPF: 0.9, PFWInjExt: sunspec.M704_Ext_OverExcited,
	}
}

// figure8AsTheProductLeavesIt is model 704 as lexa-gw leaves it with the
// INVERTED conversion — the generation this red proof was taken against.
//
// The chain: lexa-gw's internal/northbound/publish/publish.go builds the bus
// intent from the decoded element, and at gw commit cb5b89a — the last COMMITTED
// product state when this proof was taken — it read
//
//	OverExcited: pf.Excitation
//
// with no negation. csipmodel's Excitation is 2030.5's flag (TRUE = absorbing =
// under-excited); bus.FixedPF.OverExcited is the SunSpec-side sense; so for
// Figure 8's excitation=FALSE the gateway computed OverExcited=false, and
// derbase.SetFixedPF wrote M704_Ext_UnderExcited(1) — the opposite of the
// commanded direction, at exactly the right magnitude.
//
// THE FIX WAS IN FLIGHT AS THIS LANDED, uncommitted in the gw working tree
// (`OverExcited: !pf.Excitation`). No line number is cited above because it has
// already moved once; the COMMIT is the durable coordinate, and this fixture
// does not depend on either — it pins the REGISTER STATE that conversion
// produced, which is what a conformance oracle grades and what stays true about
// generation 1 forever.
//
// PINNED, not read from the product, on this suite's standing rule: a teeth
// fixture that tracked the product would go green the moment the product was
// fixed and take the evidence of its own teeth with it. When lexa-gw's negation
// lands, TestFixedPFDirection_GreenAgainstACorrectGateway is what turns green;
// this stays red forever, as the record of what was wrong.
func figure8AsTheProductLeavesIt() sunspec.ACControls {
	return sunspec.ACControls{
		PFWInjEna: true, PFWInjPF: 0.9, PFWInjExt: sunspec.M704_Ext_UnderExcited,
	}
}

// TestFixedPFDirection_RedProofAgainstTheProductsExcitationInversion is the red
// proof IW15-030 finding 1's harness half exists to produce.
//
// It is red against the product build that exists as this is written
// (GENERATION 1: publish.go:745's un-negated conversion). It flips green on the
// gw fix + re-vendor — not by editing this test, but because
// TestFixedPFDirection_GreenAgainstACorrectGateway already asserts the corrected
// register and will start describing the shipping build instead of a
// hypothetical one.
func TestFixedPFDirection_RedProofAgainstTheProductsExcitationInversion(t *testing.T) {
	got := gradeFixedPFDirection(fixedPFInjectAxis, figure8FixedPF, figure8AsTheProductLeavesIt(), 0.001)
	if got.Verdict != certify.Fail {
		t.Fatalf("a DER holding the commanded magnitude in the OPPOSITE direction graded %s. That is "+
			"the whole defect: the magnitude round-trips perfectly, so a magnitude-only referee reports "+
			"this device compliant while it exports vars the head end asked it to import.\n%s",
			got.Verdict, got.Observed)
	}
	for _, want := range []string{
		"WRONG DIRECTION",
		"PFWInj_Ext=UnderExcited(1)",
		"OverExcited(0)",
		"excitation=false",
		"absorbing reactive power (under-excited), false when DER is injecting",
		"p.258",
	} {
		if !strings.Contains(got.Observed, want) {
			t.Errorf("the direction FAIL omits %q:\n%s", want, got.Observed)
		}
	}
	// The magnitude must be reported as CORRECT in the same finding, or a
	// reader cannot see that the two halves came apart — which is the shape of
	// this bug and the reason it survived.
	if !strings.Contains(got.Observed, "MAGNITUDE exactly") {
		t.Errorf("the FAIL does not say the magnitude was right, so it reads like an ordinary "+
			"mismatch:\n%s", got.Observed)
	}
	t.Logf("RED PROOF (product generation 1 — publish.go:745's un-negated conversion), verbatim:\n%s",
		got.Observed)
}

// TestFixedPFDirection_GreenAgainstACorrectGateway is the other side, and it is
// what the gw fix turns from a description of a hypothetical gateway into a
// description of the shipping one.
func TestFixedPFDirection_GreenAgainstACorrectGateway(t *testing.T) {
	got := gradeFixedPFDirection(fixedPFInjectAxis, figure8FixedPF, figure8Applied(), 0.001)
	if got.Verdict != certify.Pass {
		t.Fatalf("a DER holding Figure 8's command in both parts graded %s:\n%s", got.Verdict, got.Observed)
	}
	for _, want := range []string{"BOTH of its parts", "PFWInj_PF=0.9", "OverExcited(0)", "PFWInjEna"} {
		if !strings.Contains(got.Observed, want) {
			t.Errorf("the PASS omits %q:\n%s", want, got.Observed)
		}
	}
	t.Logf("GREEN (a gateway that negates correctly), verbatim:\n%s", got.Observed)
}

// TestFixedPFDirection_TheOtherShapes covers the failures that are not the
// inversion, so the oracle cannot pass one of them off as another.
func TestFixedPFDirection_TheOtherShapes(t *testing.T) {
	t.Run("axis not enabled", func(t *testing.T) {
		got := gradeFixedPFDirection(fixedPFInjectAxis, figure8FixedPF, sunspec.ACControls{
			PFWInjPF: 0.9, PFWInjExt: sunspec.M704_Ext_OverExcited,
		}, 0.001)
		if got.Verdict != certify.Fail || !strings.Contains(got.Observed, "PFWInjEna is CLEAR") {
			t.Errorf("a written-but-not-enabled axis = %s: %s", got.Verdict, got.Observed)
		}
		// Right registers, function off: the finding must say the values are
		// beside the point rather than reporting them as a match.
		if !strings.Contains(got.Observed, "never applied") {
			t.Errorf("the disabled-axis FAIL does not say the row was not applied: %s", got.Observed)
		}
	})

	t.Run("wrong magnitude, right direction", func(t *testing.T) {
		bad := figure8Applied()
		bad.PFWInjPF = 0.95
		got := gradeFixedPFDirection(fixedPFInjectAxis, figure8FixedPF, bad, 0.001)
		if got.Verdict != certify.Fail || !strings.Contains(got.Observed, "WRONG magnitude") {
			t.Errorf("a wrong magnitude at the right direction = %s: %s", got.Verdict, got.Observed)
		}
	})

	t.Run("both wrong", func(t *testing.T) {
		bad := figure8AsTheProductLeavesIt()
		bad.PFWInjPF = 0.95
		got := gradeFixedPFDirection(fixedPFInjectAxis, figure8FixedPF, bad, 0.001)
		if got.Verdict != certify.Fail || !strings.Contains(got.Observed, "NEITHER half") {
			t.Errorf("both halves wrong = %s: %s", got.Verdict, got.Observed)
		}
	})

	t.Run("an undefined Ext value is reported as itself", func(t *testing.T) {
		// A device holding 7 in a two-valued enumeration is a real reading and
		// must not be flattened into one of the legal ones — that would report a
		// direction the device never claimed.
		bad := figure8Applied()
		bad.PFWInjExt = 7
		got := gradeFixedPFDirection(fixedPFInjectAxis, figure8FixedPF, bad, 0.001)
		if got.Verdict != certify.Fail {
			t.Fatalf("an out-of-enumeration Ext graded %s: %s", got.Verdict, got.Observed)
		}
		if !strings.Contains(got.Observed, "does not define") {
			t.Errorf("the finding flattened an undefined Ext into a legal direction: %s", got.Observed)
		}
	})

	t.Run("the absorb axis is a different sync group", func(t *testing.T) {
		// Reading the wrong axis's registers would be the substitution this
		// suite refuses, one model over: PFWInj and PFWAbs are separate sync
		// groups commanding separate active-power directions.
		absorbCmd := FixedPFSettings{Displacement: 950, Excitation: true, Multiplier: -3}
		got := gradeFixedPFDirection(fixedPFAbsorbAxis, absorbCmd, sunspec.ACControls{
			PFWAbsEna: true, PFWAbsPF: 0.95, PFWAbsExt: sunspec.M704_Ext_UnderExcited,
			// The INJECT group holds something else entirely; it must not be read.
			PFWInjEna: true, PFWInjPF: 0.5, PFWInjExt: sunspec.M704_Ext_OverExcited,
		}, 0.001)
		if got.Verdict != certify.Pass {
			t.Fatalf("the absorb axis graded %s while its own registers matched:\n%s",
				got.Verdict, got.Observed)
		}
		for _, want := range []string{"PFWAbs_Ext", "opModFixedPFAbsorbW", "UnderExcited(1)"} {
			if !strings.Contains(got.Observed, want) {
				t.Errorf("the absorb PASS omits %q:\n%s", want, got.Observed)
			}
		}
		if strings.Contains(got.Observed, "PFWInj") {
			t.Errorf("the absorb verdict quotes the INJECT sync group:\n%s", got.Observed)
		}
	})
}
