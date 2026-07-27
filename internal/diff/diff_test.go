package diff

// diff_test.go is the teeth for the differential layer.
//
// A differential harness has a specific failure mode that ordinary tests do not
// catch: it can quietly stop comparing. A refactor drops a family from the
// catalogue, a fixture stops loading, a comparator starts returning SKIP for a
// shape it used to adjudicate — and the run still prints a green summary,
// because "no disagreement was found" and "nothing was compared" produce the
// same colour. Every test below exists to make one of those silences audible.
//
// The tests come in three groups.
//
// CONTROL — the "reg" family must PASS. An independently transcribed offset
// table agreeing with the product's layout tables across hundreds of points is
// what earns this package the right to be believed when it reports a
// disagreement elsewhere. A differential that fails everywhere is not finding
// bugs, it is broken, and TestRegCatalog_IsTheControl is what tells the two
// apart.
//
// COMPARATOR TEETH — the adjudicators must FAIL when handed a disagreement.
// These are the tests that would have caught audit BR-02, whose scale-factor
// cross-check passed by construction because it derived its tolerance from the
// value under test. Asserting that a comparison passes is nearly worthless
// here; asserting that a DELIBERATELY WRONG pair fails is the whole point.
//
// REGRESSION LOCKS — each defect class this package confirmed against the
// shipping product is pinned by a test. These are deliberately written to fail
// LOUDLY and with instructions if the product is fixed, because a differential
// finding that silently stops reproducing is indistinguishable from a
// differential that stopped looking.

import (
	"context"
	"strings"
	"testing"

	"csip-tls-test/internal/invariant"
)

// ── control ──────────────────────────────────────────────────────────────────

// TestRegCatalog_IsTheControl asserts the register-interpretation family agrees
// with the product completely.
//
// This is the test that gives the rest of the package its credibility. The
// referee in regview.go transcribes 701/702/704 offsets, widths, signedness and
// scale-factor associations by hand, from the field ordering, with its own
// arithmetic — and then reads real register images through both its own decoder
// and the product's. If those two disagreed, every other finding in this
// package would be suspect, because the obvious explanation would be that the
// referee simply cannot read a register bank.
func TestRegCatalog_IsTheControl(t *testing.T) {
	r := NewReport(7)
	RunRegCatalog(context.Background(), r, 3)
	sum := r.Summary()

	if sum.Compared == 0 {
		t.Fatal("the reg family evaluated ZERO comparisons: the control is not comparing anything, " +
			"so its PASS means nothing")
	}
	if sum.Verdict != Pass {
		t.Errorf("the reg family is the control and must agree with the product; got %s over %d comparisons",
			sum.Verdict, sum.Compared)
		for _, c := range r.Cases {
			for _, cmp := range c.Comparisons {
				if cmp.Verdict == Fail {
					t.Errorf("  %s %s: %s", c.ID, cmp.Key, cmp.Reason)
				}
			}
		}
	}
	// A control that compares three points proves much less than one that
	// compares hundreds. Pin the order of magnitude so a fixture that quietly
	// stops loading is caught.
	if sum.Compared < 100 {
		t.Errorf("the control evaluated only %d comparisons; it used to evaluate several hundred, "+
			"which suggests a register image or a model stopped loading rather than that the "+
			"product changed", sum.Compared)
	}
}

// ── comparator teeth ─────────────────────────────────────────────────────────

// TestCompareQuantity_ToleranceIsTakenFromTheRefereeNotTheProduct is the
// anti-BR-02 test.
//
// Audit BR-02 found the existing scale-factor cross-check tautological: it
// derived its tolerance from the value it was checking, so a wrong value
// brought a proportionally wrong tolerance with it and the check passed by
// construction. The fix is that the relative tolerance is a fraction of the
// REFEREE's value only, and the way to prove the fix is real is to construct a
// pair where the two choices give opposite verdicts.
//
// With rel=2.0, product=100000 and referee=1: a referee-derived slack is 2 and
// the comparison must FAIL. A product-derived slack would be 200000 and it
// would PASS. The verdict therefore identifies which value the tolerance came
// from, and no amount of reading the code can be substituted for it.
func TestCompareQuantity_ToleranceIsTakenFromTheRefereeNotTheProduct(t *testing.T) {
	tol := invariant.Tolerance{Rel: 2.0}

	wrong := CompareQuantity("t",
		Q(ProductSide.Name, "t", invariant.Q(100000, invariant.UnitWatt)),
		Q(RefereeSide.Name, "t", invariant.Q(1, invariant.UnitWatt)),
		tol)
	if wrong.Verdict != Fail {
		t.Fatalf("product 100000 W against referee 1 W at rel=2.0 must FAIL — a slack of 200000 "+
			"could only have come from the PRODUCT's value, which is exactly the BR-02 tautology; got %s (%s)",
			wrong.Verdict, wrong.Reason)
	}

	// The mirror image: the same numbers swapped must PASS, because now the
	// referee is the large one and rel=2.0 of it genuinely admits the product's
	// answer. If this also failed, the tolerance would be symmetric (e.g. taken
	// from the larger, or from the delta) rather than anchored to the referee.
	swapped := CompareQuantity("t",
		Q(ProductSide.Name, "t", invariant.Q(1, invariant.UnitWatt)),
		Q(RefereeSide.Name, "t", invariant.Q(100000, invariant.UnitWatt)),
		tol)
	if swapped.Verdict != Pass {
		t.Fatalf("product 1 W against referee 100000 W at rel=2.0 must PASS — the tolerance is "+
			"anchored to the referee and 2x100000 admits it; got %s (%s). The asymmetry is the "+
			"property under test", swapped.Verdict, swapped.Reason)
	}
}

// TestCompareQuantity_RefusesToCompareAcrossUnits is the anti-BR-01 test.
//
// BR-01 was an absolute var count written into a percent-of-rated field: 80
// meaning "80 %" and 80 meaning "80 var" are the same bare number and every
// check that compares bare numbers waves it through. A differential built to
// catch that class must not itself compare across units, so this asserts the
// comparator reports a DISAGREEMENT rather than converting, and that it says
// so in terms a reader can act on.
func TestCompareQuantity_RefusesToCompareAcrossUnits(t *testing.T) {
	cmp := CompareQuantity("opModFixedVar",
		Q(ProductSide.Name, "opModFixedVar", invariant.Q(80, invariant.UnitPercent)),
		Q(RefereeSide.Name, "opModFixedVar", invariant.Q(80, invariant.UnitVar)),
		invariant.Tolerance{Rel: 0.01})

	if cmp.Verdict != Fail {
		t.Fatalf("80 %% against 80 var must FAIL: the numbers are equal and the quantities are not. "+
			"Got %s", cmp.Verdict)
	}
	if !strings.Contains(cmp.Reason, "DIFFERENT UNITS") {
		t.Errorf("the reason must name the unit mismatch as the cause, so a reader is not left "+
			"comparing 80 with 80 and wondering; got %q", cmp.Reason)
	}
}

// TestCompareQuantity_SkipsRatherThanInventsWhenTheRefereeCannotResolve asserts
// the one asymmetry that must NOT become a failure. If the referee cannot work
// out what a control means on a given device, the product's answer is
// unadjudicated — not wrong. Reporting FAIL there would manufacture findings
// out of the referee's own gaps, which is the fastest way to get a differential
// harness switched off.
func TestCompareQuantity_SkipsRatherThanInventsWhenTheRefereeCannotResolve(t *testing.T) {
	cmp := CompareQuantity("x",
		Q(ProductSide.Name, "x", invariant.Q(42, invariant.UnitWatt)),
		Claim{Side: RefereeSide.Name, Key: "x"}.WithNote("the device serves no M702"),
		invariant.Tolerance{Rel: 0.01})

	if cmp.Verdict != Skip {
		t.Fatalf("a referee that resolved nothing leaves the product UNADJUDICATED, not wrong; got %s", cmp.Verdict)
	}
	if !strings.Contains(cmp.Reason, "M702") {
		t.Errorf("the skip must carry the referee's own reason so the gap is visible; got %q", cmp.Reason)
	}
}

// TestCompareQuantity_FailsWhenTheProductProducedNothing is the converse. The
// referee resolved a quantity and the product did not produce one at all: that
// IS a disagreement, because the document asked for something and the device
// path yielded nothing.
func TestCompareQuantity_FailsWhenTheProductProducedNothing(t *testing.T) {
	cmp := CompareQuantity("x",
		Claim{Side: ProductSide.Name, Key: "x"}.WithNote("no register was written"),
		Q(RefereeSide.Name, "x", invariant.Q(5000, invariant.UnitWatt)),
		invariant.Tolerance{Rel: 0.01})

	if cmp.Verdict != Fail {
		t.Fatalf("the referee resolved 5000 W and the product produced nothing: that is a "+
			"disagreement, not a skip; got %s", cmp.Verdict)
	}
}

// ── the assertion floor ──────────────────────────────────────────────────────

// TestFloor_ARunThatComparedNothingCannotPass is the honesty floor, and it is
// the test most likely to matter in a year.
//
// This is the same defect Wave 1 fixed in gw-mayhem, where the documented
// default invocation injected zero faults and still printed GATE PASS. The
// shape recurs in every harness: the code path that produces "nothing went
// wrong" is also the code path that runs when nothing was tried.
func TestFloor_ARunThatComparedNothingCannotPass(t *testing.T) {
	r := NewReport(0)
	c := Case{ID: "T-1", Family: "test", Title: "a case that could not compare anything"}
	c.Compare(SkipComparison("k", "the fixture device was unreachable"))
	c.Finalize("nothing was reachable to compare")
	r.Add(c)

	sum := r.Summary()
	if sum.Verdict == Pass {
		t.Fatal("a run whose every comparison SKIPped reported PASS: the floor is not holding")
	}
	if sum.Compared != 0 {
		t.Fatalf("a skipped comparison must not count towards the compared total; got %d", sum.Compared)
	}
	if sum.Floor == "" {
		t.Error("the floor must be stated in the artifact, not only in the exit code, or a reader " +
			"of REPORT.md cannot tell an empty run from a clean one")
	}
}

// TestFloor_AdvisoryRowsDoNotSatisfyTheFloor closes the obvious way around it.
//
// Advisory rows are the harness talking about itself — the standing warning
// that both sides read the same shared enum, for instance. If those counted
// towards the assertion floor, a family could satisfy the floor purely by
// emitting its own disclaimers, and the floor would certify nothing. That is a
// more insidious failure than no floor at all, because it looks like rigour.
func TestFloor_AdvisoryRowsDoNotSatisfyTheFloor(t *testing.T) {
	r := NewReport(0)
	c := Case{ID: "T-2", Family: "test", Title: "a case carrying only its own caveats"}
	c.Compare(Comparison{
		Key:      "enum-independence",
		Verdict:  Warn,
		Reason:   "both sides read the same shared constants",
		Advisory: true,
	})
	c.Finalize("only advisory rows were produced")
	r.Add(c)

	if got := c.Checked(); got != 0 {
		t.Fatalf("an advisory row counted as a comparison (Checked=%d); a family could then satisfy "+
			"the floor with its own disclaimers", got)
	}
	if sum := r.Summary(); sum.Verdict == Pass {
		t.Fatal("a case of pure advisories reported PASS")
	}
}

// TestComparison_ValidateRequiresAReasonForEveryNonPass asserts the rule that
// keeps SKIP honest. An unexplained SKIP and a comparator that forgot to run
// are the same row in the artifact, and only one of them is acceptable.
func TestComparison_ValidateRequiresAReasonForEveryNonPass(t *testing.T) {
	for _, v := range []Verdict{Fail, Skip, Warn} {
		if err := (Comparison{Key: "k", Verdict: v}).Validate(); err == nil {
			t.Errorf("a %s with no reason was accepted into a report", v)
		}
	}
	if err := (Comparison{Key: "k", Verdict: Pass}).Validate(); err != nil {
		t.Errorf("a PASS needs no reason; got %v", err)
	}
	// A case must not be able to smuggle an invalid comparison past Compare.
	var c Case
	c.Compare(Comparison{Key: "k", Verdict: Skip})
	if c.Comparisons[0].Verdict != Fail {
		t.Error("Compare must reject a malformed comparison rather than record it as given")
	}
}

// ── regression locks on the confirmed defect classes ─────────────────────────

// findingClasses returns the set of finding-ID suffixes a report produced. The
// suffix is the defect CLASS ("dropped-limit", "non-terminating"), which is the
// stable half of the identifier — case numbers move as the catalogue grows,
// classes do not.
func findingClasses(sum Summary) map[string]int {
	out := map[string]int{}
	for _, f := range sum.Findings {
		if i := strings.LastIndex(f.ID, "/"); i >= 0 {
			out[f.ID[i+1:]]++
		}
	}
	return out
}

// requireClass asserts a defect class still reproduces, and explains what to do
// if it does not. The "or the product was fixed" branch is not politeness: a
// regression lock that fails without saying why sends the next reader hunting
// for a harness bug that may not exist.
func requireClass(t *testing.T, classes map[string]int, class, what string) {
	t.Helper()
	if classes[class] == 0 {
		t.Errorf("the %q class no longer reproduces (%s).\n"+
			"Either the product was FIXED — in which case delete this lock and record the fix — "+
			"or this package stopped looking, which is a harness defect. Do not simply delete the "+
			"assertion to get green.", class, what)
	}
}

// TestCtlCatalog_ConfirmedDefectClassesStillReproduce pins every control-path
// disagreement this package confirmed against the shipping product by reading
// lexa-proto/derbase.ApplyControl.
func TestCtlCatalog_ConfirmedDefectClassesStillReproduce(t *testing.T) {
	r := NewReport(0)
	if err := RunCtlCatalog(context.Background(), r); err != nil {
		t.Fatalf("catalogue: %v", err)
	}
	sum := r.Summary()
	if sum.Compared == 0 {
		t.Fatal("the ctl catalogue evaluated zero comparisons")
	}
	classes := findingClasses(sum)

	requireClass(t, classes, "magnitude",
		"opModFixedVar.RefType is declared at csipmodel/resources.go:316 and read nowhere; "+
			"SetConstantVar hardcodes VarSetMod=VarMaxPct, so every refType resolves against the same base")
	requireClass(t, classes, "dropped-limit",
		"ApplyControl uses firstNonNil(OpModExpLimW, OpModMaxLimW, OpModGenLimW) — 'first non-nil wins' — "+
			"so a tighter simultaneous limit is discarded")
	requireClass(t, classes, "kind",
		"opModImpLimW/opModLoadLimW are ceilings applied through SetActivePowerWatts, a WSet setpoint")
	requireClass(t, classes, "silent-clamp",
		"SetActivePowerWatts clamps to +/-WMax and returns nil, so the head-end is told success")
	requireClass(t, classes, "partial-apply",
		"ApplyControl applies modes sequentially and returns on first error, leaving earlier writes in force")
	requireClass(t, classes, "uninterpretable-applied",
		"a percentage is written even when the device publishes no rating to resolve it against")

	// The catalogue must also contain cases that AGREE. A differential in which
	// everything disagrees is measuring its own referee, not the product.
	if sum.ByVerdict[string(Pass)] == 0 {
		t.Error("no ctl case passed: a referee that disagrees with the product everywhere is more " +
			"likely wrong than the product is")
	}
}

// TestChainCatalog_UnboundedWalkStillReproduces pins the model-chain findings.
//
// lexa-proto/sunspec.scanModels is `for { ... cursor += 2 + length }` with no
// iteration cap, no check that the declared length fits the address space, and
// a uint16 cursor that WRAPS. Its only exits are the 0xFFFF end marker and a
// read error, so a device answering zeros walks it forever.
func TestChainCatalog_UnboundedWalkStillReproduces(t *testing.T) {
	r := NewReport(1)
	RunChainCatalog(context.Background(), r)
	sum := r.Summary()
	if sum.Compared == 0 {
		t.Fatal("the chain catalogue evaluated zero comparisons")
	}
	classes := findingClasses(sum)

	requireClass(t, classes, "non-terminating",
		"scanModels has no iteration bound and a uint16 cursor that wraps; only 0xFFFF or a read "+
			"error ends the walk")
	requireClass(t, classes, "accepted-hostile-chain",
		"a model declaring a length that runs past the end of the address space is recorded as a block")

	if sum.ByVerdict[string(Pass)] == 0 {
		t.Error("no chain case passed: the referee's bounds are probably wrong, not the product's walker")
	}
}

// TestSFCatalog_UnboundedScaleFactorStillReproduces pins the scale-factor
// findings. sunspec.ApplyScaleSigned checks only for the 0x8000
// not-implemented sentinel and then evaluates math.Pow10(int(sf)) for any
// int16, so a hostile scale-factor register yields +Inf or a denormal and the
// value flows downstream looking like a number.
func TestSFCatalog_UnboundedScaleFactorStillReproduces(t *testing.T) {
	r := NewReport(1)
	RunSFCatalog(context.Background(), r, 0)
	sum := r.Summary()
	if sum.Compared == 0 {
		t.Fatal("the sf catalogue evaluated zero comparisons")
	}
	classes := findingClasses(sum)

	requireClass(t, classes, "illegal-sf-accepted",
		"ApplyScaleSigned applies math.Pow10 to any int16 outside the sunssf [-10,+10] range")
	requireClass(t, classes, "silent-saturation",
		"RawFromScaleSigned clamps an unrepresentable value to the int16 edge with no signal to the caller")

	if sum.ByVerdict[string(Pass)] == 0 {
		t.Error("no sf case passed: the referee's decimal arithmetic disagrees with the product " +
			"everywhere, which points at the referee")
	}
}

// TestEveryFamilyStatesWhatItCannotCatch asserts the limitations survive into
// the artifact. The honest boundary of a differential is the surface the two
// sides share, and a report that omits it invites the reader to conclude more
// than the run established — in particular that shared enum values and shared
// wire types were somehow tested.
func TestEveryFamilyStatesWhatItCannotCatch(t *testing.T) {
	r := NewReport(0)
	if len(r.Limitations) == 0 {
		t.Fatal("a report carries no limitations; the shared-surface caveats are not reaching the artifact")
	}
	md := r.Markdown()
	if !strings.Contains(md, "What this run cannot catch") {
		t.Error("the rendered report omits the limitations section")
	}
	for _, want := range []string{"mbap", "enum", "layout"} {
		found := false
		for _, l := range r.Limitations {
			if strings.Contains(strings.ToLower(l), want) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("no limitation mentions %q; the shared surfaces must each be named", want)
		}
	}
}
