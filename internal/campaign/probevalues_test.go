package campaign

// probevalues_test.go — the probe values and I3's comparison tolerance, pinned
// against each other.
//
// Gate #19: the hand-picked list cleared the comparison by 0.16 PERCENTAGE
// POINTS at its closest pair. The spacing is derived from the tolerance now,
// and this file is the coupling — it fails when either side moves against the
// other, which is the only way a derived constant stays derived.

import (
	"math"
	"testing"

	"csip-tls-test/internal/invariant"
)

// twoBandMargin is the room between two values AFTER both of their comparison
// bands are taken out. It is the number gate #19 measured, and it is the number
// that matters: the refused value carries a band, and so does the accepted
// neighbour that actually landed on the device.
func twoBandMargin(lo, hi float64, tol invariant.Tolerance) float64 {
	slack := func(v float64) float64 { return math.Max(math.Abs(v)*tol.Rel, 0.5) }
	return (hi - lo) - (slack(lo) + slack(hi))
}

// NOTE ON SCOPE: this pins the shipping list against DefaultTolerance(), which
// is what a campaign uses today because nothing overrides it. Params.Tol is
// settable, and probeValues is built once at init from the default — so a
// caller that set a looser Tol at run time would not move this list. See
// probeValueSpacing's doc for what closing that would take; the companion test
// below demonstrates what a looser tolerance would cost.
func TestProbeValuesOutrunTheComparisonTolerance(t *testing.T) {
	tol := invariant.DefaultTolerance()
	vals := probeValues
	// The bench builds twelve credentials — five role certs plus seven negative
	// fixtures — and a run that exhausts the list stops asserting
	// distinctiveness on the remainder, which I3 then SKIPs. Headroom is the
	// point: matching the count exactly loses coverage the first time somebody
	// adds a fixture.
	const benchCredentials = 12
	if len(vals) <= benchCredentials {
		t.Fatalf("%d probe values for %d credentials leaves no headroom; the next fixture added to the "+
			"bench silently costs a probe its distinctiveness", len(vals), benchCredentials)
	}
	worst := math.Inf(1)
	for i := 0; i+1 < len(vals); i++ {
		if vals[i+1] <= vals[i] {
			t.Fatalf("the values are not ascending at %d: %v", i, vals)
		}
		if m := twoBandMargin(vals[i], vals[i+1], tol); m < worst {
			worst = m
		}
	}
	// The property: every pair is separated by more than both of their bands,
	// with the safety factor's worth of room to spare.
	if worst <= 0 {
		t.Fatalf("two probe values are within I3's comparison slack of each other (worst margin %.2f pp). "+
			"An ACCEPTED neighbour then satisfies sameValue for a REFUSED value and manufactures a false "+
			"P1 — the exhausted-list failure from the other end", worst)
	}
	required := probeValueSpacing(tol) - 2*math.Max(probeValueMax*tol.Rel, 0.5)
	if worst < required {
		t.Errorf("worst two-band margin %.2f pp is below the %.2f pp the safety factor asks for", worst, required)
	}
	t.Logf("%d values, worst two-band margin %.2f pp (the hand-picked list's was 0.16)", len(vals), worst)

	// Every value odd — so none is a multiple of ten, and none is 50/25/75,
	// which is the unroundness the distinctiveness argument actually needs.
	for _, v := range vals {
		if math.Mod(v, 2) == 0 {
			t.Errorf("probe value %g is even; the construction is an odd start with an even step", v)
		}
	}
}

// THE COUPLING. Loosen the tolerance and the required spacing must GROW — a
// derived constant that ignores its input is a literal with extra steps.
func TestProbeSpacingFollowsTheToleranceItIsDerivedFrom(t *testing.T) {
	tight := invariant.Tolerance{Rel: 0.01}
	loose := invariant.Tolerance{Rel: 0.05}

	if probeValueSpacing(loose) <= probeValueSpacing(tight) {
		t.Fatalf("spacing did not grow with the tolerance: %.2f at Rel=0.01, %.2f at Rel=0.05 — the "+
			"derivation is not reading its argument", probeValueSpacing(tight), probeValueSpacing(loose))
	}

	// And the SHIPPING list, judged against the loosened tolerance, must be
	// shown insufficient — otherwise this test would pass on a list that had
	// simply been made very sparse and the coupling would be untested.
	worst := math.Inf(1)
	for i := 0; i+1 < len(probeValues); i++ {
		if m := twoBandMargin(probeValues[i], probeValues[i+1], loose); m < worst {
			worst = m
		}
	}
	needed := probeValueSpacing(loose) - 2*math.Max(probeValueMax*loose.Rel, 0.5)
	if worst >= needed {
		t.Errorf("the shipping list still clears a 5%% tolerance by %.2f pp against a %.2f pp "+
			"requirement; this assertion is meant to demonstrate that the list is tolerance-SPECIFIC, "+
			"so either the range or the safety factor has drifted", worst, needed)
	}
	t.Logf("at Rel=0.05 the shipping list's worst margin is %.2f pp against a %.2f pp requirement — "+
		"the list is specific to the tolerance it was built for", worst, needed)
}

// The old hand-picked list, kept as the would-have-caught record: this test
// fails if the checker above stops catching what gate #19 caught.
func TestProbeValueCheckWouldHaveCaughtTheHandPickedList(t *testing.T) {
	handPicked := []float64{
		13, 17, 19, 21, 23, 27, 29, 31, 33, 37, 39, 41, 43, 47, 49,
		53, 59, 61, 63, 67, 69, 71, 73, 77, 79, 83, 87, 89, 91, 93,
	}
	tol := invariant.DefaultTolerance()
	worst := math.Inf(1)
	var lo, hi float64
	for i := 0; i+1 < len(handPicked); i++ {
		if m := twoBandMargin(handPicked[i], handPicked[i+1], tol); m < worst {
			worst, lo, hi = m, handPicked[i], handPicked[i+1]
		}
	}
	if worst > 1 {
		t.Fatalf("the two-band margin check does not reproduce gate #19's finding: it measures %.2f pp "+
			"on the list that shipped, where the gate measured 0.16", worst)
	}
	t.Logf("would-have-caught: the hand-picked list's closest pair (%g, %g) cleared the comparison by "+
		"%.2f pp", lo, hi, worst)
}
