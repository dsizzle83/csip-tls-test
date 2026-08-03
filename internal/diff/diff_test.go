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
	"errors"
	"strings"
	"testing"

	"csip-tls-test/internal/invariant"
	"lexa-proto/sunspec"
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
	// NOTE: "partial-apply" used to be locked here. It was FIXED in lexa-proto
	// b760d5a and is now pinned in the other direction by
	// TestCtlCatalog_WholeRequestPreflightIsAtomic below.
	requireClass(t, classes, "uninterpretable-applied",
		"a percentage is written even when the device publishes no rating to resolve it against")

	// The catalogue must also contain cases that AGREE. A differential in which
	// everything disagrees is measuring its own referee, not the product.
	if sum.ByVerdict[string(Pass)] == 0 {
		t.Error("no ctl case passed: a referee that disagrees with the product everywhere is more " +
			"likely wrong than the product is")
	}
}

// TestCtlCatalog_WholeRequestPreflightIsAtomic pins the FIX for the
// "partial-apply" finding TestCtlCatalog_ConfirmedDefectClassesStillReproduce
// used to lock — the same shape as
// TestChainCatalog_BoundedWalkTerminatesWithSentinel above, and for the same
// reason: a defect lock that is deleted rather than inverted stops being
// evidence of anything.
//
// derbase.ApplyControl used to validate each control axis AS IT REACHED IT and
// write as it went. A request whose SECOND axis the device could not execute
// was therefore rejected as a whole — after the FIRST axis had already been
// written. The head end is told CannotComply while the device sits holding a
// fragment of an instruction nobody ever decided was safe, which is exactly
// what checkAtomicity (ctl.go) adjudicates and what invariant I10 forbids.
//
// lexa-proto b760d5a fixed it (LXR-012): ApplyControl now PREFLIGHTS every
// present axis — model presence, declared capability, value domain, nameplate
// — and returns before issuing a single write if any of them cannot be
// executed. It also reordered execution restrictive-first (cease/disconnect →
// limits and setpoints → connect-on/energize-on), which is a separate
// improvement this catalogue does not measure: the referee's atomicity
// question is only about whether registers moved.
//
// This package's referee is unchanged — "error ⇒ 0 registers changed" is what
// checkAtomicity has always asserted — so what moved is the PRODUCT, from
// "fails having written part of it" to "refuses having written nothing".
//
// A regression back to lazy per-axis validation re-opens the disagreement: the
// finding class reappears (checked first) AND the per-comparison sweep below
// finds a Fail, so it cannot go quiet.
func TestCtlCatalog_WholeRequestPreflightIsAtomic(t *testing.T) {
	r := NewReport(0)
	if err := RunCtlCatalog(context.Background(), r); err != nil {
		t.Fatalf("catalogue: %v", err)
	}
	sum := r.Summary()
	if sum.Compared == 0 {
		t.Fatal("the ctl catalogue evaluated zero comparisons")
	}

	if n := findingClasses(sum)["partial-apply"]; n != 0 {
		t.Errorf("%d case(s) still report 'partial-apply' — ApplyControl is supposed to preflight the "+
			"WHOLE request and write nothing when any axis is unexecutable, as of lexa-proto b760d5a "+
			"(LXR-012). A control that fails must leave the device untouched. Check proto.pin and "+
			"vendor/lexa-proto/derbase.", n)
	}

	// The per-comparison sweep. The finding count alone is not enough: it would
	// also read zero if the catalogue stopped producing failing applications at
	// all, which would silently retire the question instead of answering it.
	var pass, fail, exercised int
	var failed []string
	for _, c := range r.Cases {
		for _, cmp := range c.Comparisons {
			if cmp.Key != "atomicity" {
				continue
			}
			switch cmp.Verdict {
			case Pass:
				pass++
				exercised++
			case Fail:
				fail++
				exercised++
				failed = append(failed, c.ID+": "+cmp.Reason)
			}
		}
	}
	if exercised == 0 {
		t.Fatal("no ctl case exercised the atomicity question — every application in the catalogue " +
			"SUCCEEDED, so nothing adjudicated whether a FAILED one leaves registers moved. That retires " +
			"the question rather than answering it; the catalogue needs a case the device refuses.")
	}
	if fail != 0 {
		t.Errorf("%d of %d failed control applications left registers moved:\n  %s",
			fail, exercised, strings.Join(failed, "\n  "))
	}
	if pass == 0 {
		t.Errorf("atomicity was exercised %d time(s) but never passed", exercised)
	}
}

// TestChainCatalog_BoundedWalkTerminatesWithSentinel pins the FIX for the
// model-chain findings TestChainCatalog_UnboundedWalkStillReproduces used to
// pin.
//
// lexa-proto/sunspec.scanModels used to be `for { ... cursor += 2 + length }`
// with no iteration cap, no check that the declared length fits the address
// space, and a uint16 cursor that WRAPPED. Its only exits were the 0xFFFF end
// marker and a read error, so a device answering zeros was walked forever.
//
// lexa-proto commit 8788796 fixed it: cursor is now a uint32, both a model's
// header and its declared data are checked against the 16-bit address space,
// the walk is capped at maxScanModels=256 steps, and either bound now returns
// the sentinel error sunspec.ErrChainOverrun instead of looping or silently
// accepting an unwalkable chain. This package's own referee (chain.go's
// walk()) already enforced the identical bound — maxChainSteps=256, checked
// in the same place in the loop (once per header read, counting the read
// that would have found the End marker) — from before this fix landed, so
// the fix does not change what the REFEREE concludes about these fixtures; it
// changes what the PRODUCT concludes, from "accepted" or "never stops" to
// "refuses, agreeing with the referee".
//
// The four hostile fixtures that used to produce "non-terminating" (no end
// marker: DIFF-CHAIN-002) and "accepted-hostile-chain" (a declared length or
// cursor that runs past the address space: DIFF-CHAIN-004, DIFF-CHAIN-005; a
// chain long enough to trip the step cap before its own end marker:
// DIFF-CHAIN-010) now AGREE instead: both walkers refuse, and the product's
// error wraps sunspec.ErrChainOverrun. A regression back to unbounded
// scanModels reopens the disagreement — the old finding classes reappear
// (checked first, below) AND the direct per-fixture ErrChainOverrun checks
// fail outright, so this cannot regress silently.
func TestChainCatalog_BoundedWalkTerminatesWithSentinel(t *testing.T) {
	r := NewReport(1)
	RunChainCatalog(context.Background(), r)
	sum := r.Summary()
	if sum.Compared == 0 {
		t.Fatal("the chain catalogue evaluated zero comparisons")
	}
	classes := findingClasses(sum)

	// The old defect classes must NOT reproduce any more. WHEN LEXA-PROTO
	// REGRESSES scanModels back to unbounded, one or both of these will fire
	// again — that is the loud failure this test exists to guarantee, not a
	// reason to delete the check.
	if n := classes["non-terminating"]; n != 0 {
		t.Errorf("%d case(s) still report 'non-terminating' — scanModels is supposed to be bounded "+
			"(maxScanModels=256, sunspec.ErrChainOverrun) as of lexa-proto 8788796; a device with no end "+
			"marker must now be REFUSED, not walked forever. Check proto.pin and vendor/lexa-proto/sunspec.",
			n)
	}
	if n := classes["accepted-hostile-chain"]; n != 0 {
		t.Errorf("%d case(s) still report 'accepted-hostile-chain' — scanModels is supposed to check both "+
			"a model header and its declared data against the 16-bit address space as of lexa-proto "+
			"8788796; a chain that runs past it must now be REFUSED, matching the referee's pre-existing "+
			"bounds, not recorded as a block list.", n)
	}

	if sum.ByVerdict[string(Pass)] == 0 {
		t.Error("no chain case passed: the referee's bounds are probably wrong, not the product's walker")
	}

	// Directly confirm each hostile fixture (the fixtures themselves are
	// untouched — see ChainCatalog() in chain.go): the product now refuses,
	// wrapping ErrChainOverrun, and the report-level Case for it records
	// agreement (Pass) rather than the old disagreement.
	hostile := map[string]string{
		"DIFF-CHAIN-002": "no end marker at all",
		"DIFF-CHAIN-004": "a model declaring 65535 registers",
		"DIFF-CHAIN-005": "runs off the top of the address space",
		"DIFF-CHAIN-010": "a thousand zero-length models, past the 256-step cap",
	}
	found := map[string]bool{}
	for _, c := range ChainCatalog() {
		why, want := hostile[c.ID]
		if !want {
			continue
		}
		found[c.ID] = true
		dev := &chainDevice{regs: c.Regs, limit: 4096}
		_, err := sunspec.ScanAt(dev, c.Base)
		if err == nil {
			t.Errorf("%s (%s): sunspec.ScanAt accepted a hostile chain with no error", c.ID, why)
			continue
		}
		if !errors.Is(err, sunspec.ErrChainOverrun) {
			t.Errorf("%s (%s): ScanAt refused with %v, which does not wrap sunspec.ErrChainOverrun",
				c.ID, why, err)
		}
	}
	for id, why := range hostile {
		if !found[id] {
			t.Errorf("%s (%s) is no longer in ChainCatalog() — this test names specific fixture IDs; "+
				"if the ID changed, update this test rather than letting the check silently stop running",
				id, why)
		}
	}

	for _, c := range r.Cases {
		if _, want := hostile[c.ID]; !want {
			continue
		}
		if c.Verdict != Pass {
			t.Errorf("%s: report-level Case.Verdict = %s, want Pass — product and referee are supposed to "+
				"agree (both refuse) on this fixture now; comparisons: %+v", c.ID, c.Verdict, c.Comparisons)
		}
	}
}

// TestChainWalk_ProductAndRefereeAgreeAtTheBoundary asserts the product's
// maxScanModels and the referee's maxChainSteps are not merely both 256 by
// coincidence, but checked in the same PLACE: a chain of exactly
// maxScanModels-1 (255) models immediately followed by an End marker succeeds
// on both sides (256 header reads total: 255 model headers + the End
// marker), while a chain of maxScanModels (256) models trips the cap on the
// read that would have found the End marker, on both sides — even though
// that End marker is genuinely present in the register image, it is never
// reached. Neither maxScanModels (unexported in lexa-proto/sunspec) nor
// maxChainSteps (unexported here) can be compared by value from outside
// their packages, so this test proves they agree by BEHAVIOUR at the one
// input where a one-off difference between them would show up. If the two
// bounds ever drift apart — a constant changed on only one side, or an
// off-by-one in where the check is placed — this is the test that catches
// it; nothing else in this package probes exactly at the edge.
func TestChainWalk_ProductAndRefereeAgreeAtTheBoundary(t *testing.T) {
	const base = 40000

	okRegs := manyZeroLengthModels(base, 255)
	prodBlocks, prodErr := sunspec.ScanAt(&chainDevice{regs: okRegs, limit: 4096}, base)
	if prodErr != nil {
		t.Fatalf("product: 255 models + End marker should succeed, got %v", prodErr)
	}
	if len(prodBlocks) != 255 {
		t.Fatalf("product: got %d blocks, want 255", len(prodBlocks))
	}
	refBlocks, refErr := walk(&chainDevice{regs: okRegs, limit: 4096}, base)
	if refErr != nil {
		t.Fatalf("referee: 255 models + End marker should succeed, got %v", refErr)
	}
	if len(refBlocks) != 255 {
		t.Fatalf("referee: got %d blocks, want 255", len(refBlocks))
	}

	// 256 models, THEN an End marker: the marker exists in the register image
	// but is never reached — the cap must trip on the read attempt that would
	// have found it, on both walkers.
	capRegs := manyZeroLengthModels(base, 256)
	_, prodErrAt256 := sunspec.ScanAt(&chainDevice{regs: capRegs, limit: 4096}, base)
	if prodErrAt256 == nil {
		t.Fatal("product: 256 models should trip the step cap even though an End marker follows in the " +
			"register image — the cap must fire on the read that would have reached it")
	}
	if !errors.Is(prodErrAt256, sunspec.ErrChainOverrun) {
		t.Fatalf("product: refused 256 models with %v, which does not wrap sunspec.ErrChainOverrun", prodErrAt256)
	}
	if _, refErrAt256 := walk(&chainDevice{regs: capRegs, limit: 4096}, base); refErrAt256 == nil {
		t.Fatal("referee: 256 models should also trip maxChainSteps — if this now succeeds, the referee's " +
			"own bound moved and no longer matches the product's")
	}
}

// TestSFCatalog_IllegalScaleFactorsAreRefused is the INVERTED form of the
// scale-factor lock (LXR-004 / LXR-028).
//
// It used to require the "illegal-sf-accepted" class to keep reproducing:
// sunspec.ApplyScaleSigned checked only the 0x8000 not-implemented sentinel
// and then evaluated math.Pow10(int(sf)) for any int16, so a hostile
// scale-factor register yielded +Inf or a denormal and the value flowed
// downstream looking like a number. requireClass's own instruction on that
// day was: "Either the product was FIXED — in which case delete this lock and
// record the fix".
//
// The product WAS fixed (lexa-proto 1bda02c): the sunssf domain [-10,+10] is
// enforced at every codec entry, so the referee and the product now agree to
// REFUSE. This asserts that agreement, which is the property the differential
// exists to establish — and it goes red again the moment the product starts
// producing numbers from illegal scale factors.
func TestSFCatalog_IllegalScaleFactorsAreRefused(t *testing.T) {
	r := NewReport(1)
	RunSFCatalog(context.Background(), r, 0)
	sum := r.Summary()
	if sum.Compared == 0 {
		t.Fatal("the sf catalogue evaluated zero comparisons")
	}
	classes := findingClasses(sum)

	if n := classes["illegal-sf-accepted"]; n > 0 {
		t.Errorf("LXR-004 regressed: %d case(s) where the product produced a NUMBER from a scale "+
			"factor outside the sunssf [-10,+10] range. A corrupt or hostile SF register must "+
			"decode to NaN, not to a plausible-looking value.", n)
	}
	// "silent-saturation" was the OTHER half of LXR-004, and it is now pinned in
	// the same inverted form by TestSFCatalog_SaturationIsReportedToTheCaller.
	if sum.ByVerdict[string(Pass)] == 0 {
		t.Error("no sf case passed: the referee's decimal arithmetic disagrees with the product " +
			"everywhere, which points at the referee")
	}
}

// TestSFCatalog_SaturationIsReportedToTheCaller is the INVERTED form of the
// OTHER half of the scale-factor lock (LXR-004), and the last of the four
// inversions in this file.
//
// The product's encoder used to be `RawFromScaleSigned(float64, int16) uint16`
// and nothing else. A value that did not fit the register at the chosen scale
// factor was clamped onto the edge and returned as a bare word, so a caller
// could not distinguish "applied" from "applied as something else", and this
// family raised a P2 "silent-saturation" finding on every such value.
//
// lexa-proto 1bda02c (LXR-004) fixed it: EncodeScaleSigned/Uint return
// (uint16, EncodeOutcome); the outcome separates EncodeExact from
// EncodeSaturatedHigh/Low, EncodeNotImplemented and EncodeBadSF; and derbase's
// writers act on it. RawFromScale* survives only as an explicitly
// outcome-discarding round-trip wrapper for sweeps and simulators.
//
// csip-tls-test 8f17f1c inverted the illegal-SF half of LXR-004 and left this
// one standing, reasoning that the catalogue drove the wrapper, "which by
// contract still clamps silently". That reasoning was correct about the wrapper
// and is exactly why the finding had stopped being about the product: it
// reproduced only because the referee kept dialling the deprecated number.
// compareEncode now puts the question to the command-writer entry point, so what
// this test asserts is the AGREEMENT the fix produced — and a regression to a
// signal-less encoder reopens the disagreement, because the finding class
// reappears (checked first) AND the per-comparison sweep below finds a Fail.
//
// The seed and generated count match cmd/gw-diff's defaults, so this test sees
// the same probes an operator's `make diff` does.
func TestSFCatalog_SaturationIsReportedToTheCaller(t *testing.T) {
	r := NewReport(1)
	RunSFCatalog(context.Background(), r, 64)
	sum := r.Summary()
	if sum.Compared == 0 {
		t.Fatal("the sf catalogue evaluated zero comparisons")
	}

	if n := findingClasses(sum)["silent-saturation"]; n != 0 {
		t.Errorf("%d case(s) still report 'silent-saturation' — sunspec.EncodeScale* is supposed to "+
			"return an EncodeOutcome naming the clamp, as of lexa-proto 1bda02c (LXR-004). A value the "+
			"register cannot carry must reach the caller as a SIGNAL, not merely as a different number. "+
			"Check proto.pin and vendor/lexa-proto/sunspec/scale.go.", n)
	}

	// The per-comparison sweep. The finding count alone is not enough: it would
	// also read zero if the catalogue stopped encoding unrepresentable values,
	// which retires the question instead of answering it.
	var pass, fail, exercised int
	var failed []string
	for _, c := range r.Cases {
		for _, cmp := range c.Comparisons {
			if cmp.Key != "sf.saturation-visible" {
				continue
			}
			switch cmp.Verdict {
			case Pass:
				pass++
				exercised++
			case Fail:
				fail++
				exercised++
				failed = append(failed, c.ID+": "+cmp.Reason)
			}
		}
	}
	if exercised == 0 {
		t.Fatal("no sf case put an unrepresentable value to the encoder — every value in the catalogue " +
			"FIT its register, so nothing adjudicated whether a clamp is signalled. That retires the " +
			"question rather than answering it; the catalogue needs a value the register cannot carry.")
	}
	if fail != 0 {
		t.Errorf("%d of %d clamped encodes reached the caller with no signal:\n  %s",
			fail, exercised, strings.Join(failed, "\n  "))
	}
	if pass == 0 {
		t.Errorf("saturation was exercised %d time(s) and never passed", exercised)
	}

	// The converse row, and the reason it is a WARN rather than a finding. The
	// product answers the unsigned DOMAIN question before rounding, so it reports
	// a saturation the referee's round-first rule does not see; both sides still
	// produce the same raw word. That is the product being STRICTER, which is
	// never a defect in this direction — but it must not silently become a FAIL
	// either, because a referee that scores conservatism as a defect trains
	// people to ignore it.
	for _, c := range r.Cases {
		for _, cmp := range c.Comparisons {
			if cmp.Key == "sf.representable" && cmp.Verdict == Fail {
				t.Errorf("%s: a value the referee found representable was scored FAIL (%s); an "+
					"over-reported saturation is the safe direction and belongs in a WARN",
					c.ID, cmp.Reason)
			}
		}
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
