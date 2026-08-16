package suitecsip

// loadbearing_test.go — the marker, and the rule it enforces.
//
// doc.go names three families of criterion written with NO Skip path, because a
// Skip on a criterion that carries a row's whole subject cannot dent the case
// verdict and therefore cannot hold a release. That is per-criterion discipline
// and it works; what it is not is ENFORCED. This file is the enforcement: every
// criterion in those families must carry the LoadBearing marker, and no
// load-bearing criterion may carry a Skip reason, so a future edit that
// reintroduces one fails here instead of in a bundle.

import (
	"testing"
)

// releaseEnforcingCriteria is the list doc.go describes, built with arguments
// that exercise the shapes each one is written for.
//
// It is stated here as a LIST rather than discovered by reflection on purpose:
// the property under test is "somebody decided this criterion carries its row's
// subject", which is a judgement and not something a program can infer. A new
// criterion joining the family has to be added here, and the reviewer adding it
// has to say so.
func releaseEnforcingCriteria(t *testing.T) map[string]criterion {
	t.Helper()
	empty := &Observation{Params: map[string]string{}}
	curve := rowByID(t, "BASIC-006").mode.Curve
	refusal := rowByID(t, "BASIC-014").mode.Refusal
	hold := rowByID(t, "BASIC-010").mode.Hold
	direct := rowByID(t, "BASIC-008").mode.Direct
	// The ride-through rows carry their apparatus outside controlMode, so this
	// one comes from the shipping row's own binding rather than from rowByID.
	trip := rideThroughRows()[0].row.binding

	return map[string]criterion{
		"critDEREffectViaSouthboundOracle":    critDEREffectViaSouthboundOracle("a subject", empty),
		"critDEREffectViaCurveOracle":         critDEREffectViaCurveOracle("a subject", curve, empty),
		"critRefusedAxisNoSouthboundTrace":    critRefusedAxisNoSouthboundTrace(refusal, empty),
		"critModeUnauthorable":                critModeUnauthorable("a subject", "opModX", "why"),
		"critEffectBlockedByAuthoringGap":     critEffectBlockedByAuthoringGap("a subject", "opModX"),
		"critDERValueRemainedAcrossTheWindow": critDERValueRemainedAcrossTheWindow("a subject", hold, empty),
		"critDEREffectViaDirectOracle":        critDEREffectViaDirectOracle("a subject", direct, empty),
		"critDEREffectViaTripOracle":          critDEREffectViaTripOracle("a subject", trip, empty),
	}
}

// TestReleaseEnforcingCriteriaAreMarkedLoadBearing is the marker's own
// construction test.
func TestReleaseEnforcingCriteriaAreMarkedLoadBearing(t *testing.T) {
	for name, c := range releaseEnforcingCriteria(t) {
		if !c.LoadBearing {
			t.Errorf("%s carries a row's whole subject and is not marked LoadBearing, so a Skip on it "+
				"would vanish into a maximum-taking roll-up and the case would pass on its supporting "+
				"wire assertions alone", name)
		}
	}
}

// TestLoadBearingCriteriaHaveNoSkipPath is the rule the marker exists beside.
//
// A criterion cannot be both: the marker says "a Skip here must cap the case",
// and a Skip STRING says "when nothing decides, record this reason and move on".
// Carrying both means the author expected the criterion to skip, which is
// precisely what the release-enforcing families are written not to do — and the
// cap would then fire on every captureless run, turning a structural guard into
// noise nobody reads.
func TestLoadBearingCriteriaHaveNoSkipPath(t *testing.T) {
	for name, c := range releaseEnforcingCriteria(t) {
		if c.LoadBearing && c.Skip != "" {
			t.Errorf("%s is marked LoadBearing AND carries a Skip reason (%q). A criterion that carries "+
				"its row's whole subject must DECIDE — see doc.go's release-enforcing families — and one "+
				"that is expected to skip must not be marked", name, c.Skip)
		}
	}
}

// The marker has to reach the minted assertion, or the cap can never fire. mint
// sets it in one place for exactly this reason; this proves that place is on
// the path every arm takes.
func TestMintCarriesTheLoadBearingMarkerOntoTheAssertion(t *testing.T) {
	for name, c := range releaseEnforcingCriteria(t) {
		// A criterion whose evaluators cannot run (no transcript, no server)
		// falls through to the SkipAssertion arm, which is the ONLY arm the cap
		// ever fires on — so it is the arm worth proving.
		obs := &Observation{Params: map[string]string{}}
		as, err := mint(nil, obs, []criterion{c})
		if err != nil {
			t.Fatalf("%s: mint: %v", name, err)
		}
		if len(as) != 1 {
			t.Fatalf("%s: mint produced %d assertions", name, len(as))
		}
		if !as[0].LoadBearing {
			t.Errorf("%s: the minted assertion is not marked load-bearing, so bundle.RollUp and the "+
				"runner's worstOf can never cap on it and the marker is decorative", name)
		}
	}
}
