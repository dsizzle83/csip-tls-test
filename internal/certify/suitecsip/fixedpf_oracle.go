package suitecsip

// fixedpf_oracle.go — the DIRECTION half of a fixed-power-factor row.
//
// # The blindness this closes
//
// A displacement power factor is two facts: a MAGNITUDE and a DIRECTION. Until
// IW15-030 this suite asserted only the first. Nothing anywhere read model 704's
// PFWInj_Ext / PFWAbs_Ext — the registers that say which way the reactive power
// goes — so a gateway could reverse every fixed-PF command it was given and
// every row would stay green.
//
// It was not hypothetical. lexa-gw's publish.go converted IEEE 2030.5's
// `excitation` into SunSpec's `OverExcited` with
//
//	OverExcited: pf.Excitation
//
// and the two are OPPOSITE polarities of the same fact: 2018 p.258 makes
// excitation TRUE mean absorbing/under-excited, while SunSpec's
// M704_Ext_OverExcited is 0 and UnderExcited is 1. A missing negation, on a line
// that reads correctly, invisible from either end — because the magnitude
// round-trips perfectly and the magnitude was all anyone checked.
//
// THE HARNESS HAD THE SAME BUG IN PROSE, four times over, which is why it could
// not have caught the product's: sim/gridsim/fixedpf.go stated the polarity in
// both directions and got it wrong in both. A referee that had transcribed the
// sentence correctly would have had to notice.
//
// # What this grades
//
// One question the magnitude cannot answer: did the DER end up pointing the way
// the document said? The expectation is derived from 2018 p.258's sentence and
// SunSpec's own enumeration, with the negation performed ONCE (here) and named,
// rather than being spread across call sites where a sign can go missing again.
//
//	IEEE 2030.5 excitation=true   absorbing, under-excited   M704 Ext = 1
//	IEEE 2030.5 excitation=false  injecting, over-excited    M704 Ext = 0
//
// It is deliberately NOT derived from lexa-proto's derbase or from lexa-gw: both
// sit on the product's side of this comparison, and an oracle that computed its
// expectation with the product's own conversion would agree with the inversion
// it exists to catch — the IW15-011 shared-oracle rule, one boolean down.

import (
	"fmt"

	"csip-tls-test/internal/certify"
	"lexa-proto/sunspec"
)

// excitationSentence is IEEE Std 2030.5-2018 p.258, verbatim. Quoted rather than
// paraphrased because paraphrasing it is exactly what went wrong: every wrong
// statement of this polarity in this tree was someone's summary of it.
const excitationSentence = "True when DER is absorbing reactive power (under-excited), false when DER " +
	"is injecting reactive power (over-excited)."

// wantExt is the M704 excitation register a conformant DER must hold for a given
// IEEE 2030.5 excitation flag, and the words for each.
//
// THE NEGATION LIVES HERE AND NOWHERE ELSE in this suite. 2030.5 names the
// ABSORBING direction true; SunSpec names the OVER-EXCITED direction 0. They are
// the same fact stated from opposite ends, so exactly one negation is correct
// and any second one silently restores the bug.
func wantExt(excitation bool) (reg uint16, words string) {
	if excitation {
		return sunspec.M704_Ext_UnderExcited, "absorbing reactive power (under-excited)"
	}
	return sunspec.M704_Ext_OverExcited, "injecting reactive power (over-excited)"
}

// extWords renders whatever the device actually holds, including a value the
// enumeration does not define — which is a real reading and must not be
// flattened into one of the two legal ones.
func extWords(reg uint16) string {
	switch reg {
	case sunspec.M704_Ext_OverExcited:
		return "OverExcited(0) — injecting reactive power"
	case sunspec.M704_Ext_UnderExcited:
		return "UnderExcited(1) — absorbing reactive power"
	}
	return fmt.Sprintf("%d, which SunSpec model 704's Ext enumeration does not define (it declares only "+
		"OverExcited=0 and UnderExcited=1)", reg)
}

// fixedPFAxis names which of 704's two fixed-PF sync groups a row commands.
type fixedPFAxis struct {
	// Element is the IEEE 2030.5 name, as the catalog's Figures print it.
	Element string
	// EnaName/PFName/ExtName are the model 704 points of this axis's sync group.
	EnaName, PFName, ExtName string
	// ext reads the decoded 704 snapshot for this axis.
	ext func(sunspec.ACControls) uint16
	// ena/pf likewise.
	ena func(sunspec.ACControls) bool
	pf  func(sunspec.ACControls) float64
}

var (
	fixedPFInjectAxis = fixedPFAxis{
		Element: "opModFixedPFInjectW",
		EnaName: "PFWInjEna", PFName: "PFWInj_PF", ExtName: "PFWInj_Ext",
		ext: func(c sunspec.ACControls) uint16 { return c.PFWInjExt },
		ena: func(c sunspec.ACControls) bool { return c.PFWInjEna },
		pf:  func(c sunspec.ACControls) float64 { return c.PFWInjPF },
	}
	fixedPFAbsorbAxis = fixedPFAxis{
		Element: "opModFixedPFAbsorbW",
		EnaName: "PFWAbsEna", PFName: "PFWAbs_PF", ExtName: "PFWAbs_Ext",
		ext: func(c sunspec.ACControls) uint16 { return c.PFWAbsExt },
		ena: func(c sunspec.ACControls) bool { return c.PFWAbsEna },
		pf:  func(c sunspec.ACControls) float64 { return c.PFWAbsPF },
	}
)

// gradeFixedPFDirection compares what a row COMMANDED against what model 704
// HOLDS, on both axes of the comparison a power factor has.
//
// The magnitude is checked too, but the direction is the point: a magnitude-only
// referee passes a device pointing the wrong way, and pointing the wrong way is
// not a small error. At PF 0.9 a 60 kW inverter is the difference between
// exporting about 29 kvar and importing about 29 kvar — a ~58 kvar swing at the
// point of common coupling, from one boolean.
func gradeFixedPFDirection(axis fixedPFAxis, want FixedPFSettings, got sunspec.ACControls,
	pfTol float64) Finding {
	if !axis.ena(got) {
		return Finding{Verdict: certify.Fail, Observed: fmt.Sprintf(
			"the DER's model 704 %s is CLEAR, so this row's %s was never applied: the device is running "+
				"no fixed power factor on this axis at all, whatever %s and %s happen to hold",
			axis.EnaName, axis.Element, axis.PFName, axis.ExtName)}
	}

	wantReg, wantWords := wantExt(want.Excitation)
	gotReg := axis.ext(got)
	gotPF := axis.pf(got)
	magnitudeOK := abs(gotPF-want.PF()) <= pfTol

	switch {
	case gotReg != wantReg && !magnitudeOK:
		return Finding{Verdict: certify.Fail, Observed: fmt.Sprintf(
			"the DER's model 704 holds NEITHER half of this row's %s: %s=%s where the control commanded "+
				"%s (excitation=%t — IEEE Std 2030.5-2018 p.258: %q), and %s=%s where it commanded %s",
			axis.Element, axis.ExtName, extWords(gotReg), extWords(wantReg), want.Excitation,
			excitationSentence, axis.PFName, trimNum(gotPF), trimNum(want.PF()))}

	case gotReg != wantReg:
		// THE FINDING THIS FILE EXISTS FOR. The magnitude is perfect and the
		// device is pointing the other way.
		return Finding{Verdict: certify.Fail, Observed: fmt.Sprintf(
			"the DER's model 704 holds this row's power-factor MAGNITUDE exactly (%s=%s) and the WRONG "+
				"DIRECTION: %s=%s where the control commanded %s. This row published excitation=%t, and "+
				"IEEE Std 2030.5-2018 p.258 defines that flag as %q — so a conformant DER is %s. "+
				"Direction is not a detail of a power factor, it is half of it: at PF %s the reactive "+
				"power is the same magnitude and the opposite SIGN, so a DER reversed here is exporting "+
				"vars where the head end asked it to import them. A referee that compared only the "+
				"magnitude would report this device as compliant, which is what every fixed-PF row in "+
				"this suite did before IW15-030",
			axis.PFName, trimNum(gotPF), axis.ExtName, extWords(gotReg), extWords(wantReg),
			want.Excitation, excitationSentence, wantWords, trimNum(want.PF()))}

	case !magnitudeOK:
		return Finding{Verdict: certify.Fail, Observed: fmt.Sprintf(
			"the DER's model 704 points the way this row's %s commanded (%s=%s) at the WRONG magnitude: "+
				"%s=%s where the control commanded %s",
			axis.Element, axis.ExtName, extWords(gotReg), axis.PFName, trimNum(gotPF),
			trimNum(want.PF()))}
	}

	return Finding{Verdict: certify.Pass, Observed: fmt.Sprintf(
		"the DER's model 704 holds this row's %s in BOTH of its parts: %s=%s (the commanded magnitude) "+
			"and %s=%s (the commanded direction — the control published excitation=%t and IEEE Std "+
			"2030.5-2018 p.258 defines that as %q). %s is set, so the axis is applied rather than merely "+
			"written",
		axis.Element, axis.PFName, trimNum(gotPF), axis.ExtName, extWords(gotReg), want.Excitation,
		excitationSentence, axis.EnaName)}
}

func abs(v float64) float64 {
	if v < 0 {
		return -v
	}
	return v
}
