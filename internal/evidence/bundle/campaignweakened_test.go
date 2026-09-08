package bundle

// campaignweakened_test.go pins REV0907-E3's other half: a bundle may not
// claim both campaign.gating=true and a non-empty campaign.weakened. The
// runner in internal/certify never writes both together by construction (a
// GATING campaign refuses every weakening switch outright, and the one
// remaining override, -allow-dirty, drops the run out of Gating the moment it
// actually waves something through), so this exercises the defensive check
// Verify still runs for every bundle it did not itself just write — a
// hand-edited one, or an old bundle.json.

import (
	"strings"
	"testing"
)

func gatingWeakenedBundle(t *testing.T, gating bool, weakened []string) *Bundle {
	t.Helper()
	b := &Bundle{Run: RunMeta{Campaign: &CampaignRecord{
		Name: "csip", Gating: gating, Weakened: weakened,
	}}}
	dir := writeBundleDir(t, b)
	loaded, err := Load(dir)
	if err != nil {
		t.Fatalf("Load() = %v", err)
	}
	return loaded
}

// The contradiction this file exists for: GATING claims this evidence may
// decide a release; WEAKENED claims a precondition that decision rests on was
// only asserted. Both together must FAIL, loudly, naming both facts.
func TestVerifyRefusesGatingWithWeakenedEvidence(t *testing.T) {
	loaded := gatingWeakenedBundle(t, true, []string{"skip-preflight"})
	rep := &VerifyReport{OK: true}
	verifyCampaignWeakening(loaded, rep)

	if rep.OK {
		t.Fatal("a bundle claiming gating=true AND weakened evidence verified clean")
	}
	if len(rep.Problems) != 1 {
		t.Fatalf("problems = %v, want exactly one", rep.Problems)
	}
	for _, want := range []string{"csip", "gating=true", "skip-preflight", "may not claim both"} {
		if !strings.Contains(rep.Problems[0], want) {
			t.Errorf("problem does not mention %q: %s", want, rep.Problems[0])
		}
	}
}

// A GATING bundle that weakened nothing is exactly what the runner is meant to
// produce, and must verify clean on this leg.
func TestVerifyAcceptsGatingWithoutWeakenedEvidence(t *testing.T) {
	loaded := gatingWeakenedBundle(t, true, nil)
	rep := &VerifyReport{OK: true}
	verifyCampaignWeakening(loaded, rep)
	if !rep.OK || len(rep.Problems) != 0 {
		t.Errorf("a clean gating bundle was flagged: ok=%v problems=%v", rep.OK, rep.Problems)
	}
}

// An EXPLORATORY bundle that recorded a weakening switch is exactly what an
// operator's development run is meant to produce — WEAKENED alone, with
// GATING already false, is disclosure, not contradiction.
func TestVerifyAcceptsExploratoryWithWeakenedEvidence(t *testing.T) {
	loaded := gatingWeakenedBundle(t, false, []string{"allow-dirty"})
	rep := &VerifyReport{OK: true}
	verifyCampaignWeakening(loaded, rep)
	if !rep.OK || len(rep.Problems) != 0 {
		t.Errorf("an exploratory bundle recording a weakening was flagged: ok=%v problems=%v", rep.OK, rep.Problems)
	}
}

// A bundle carrying no campaign record at all — every bundle written before
// campaigns existed — has nothing for this check to say anything about.
func TestVerifyIgnoresABundleWithNoCampaignRecord(t *testing.T) {
	b := &Bundle{}
	dir := writeBundleDir(t, b)
	loaded, err := Load(dir)
	if err != nil {
		t.Fatalf("Load() = %v", err)
	}
	rep := &VerifyReport{OK: true}
	verifyCampaignWeakening(loaded, rep)
	if !rep.OK || len(rep.Problems) != 0 {
		t.Errorf("a campaign-less bundle was flagged: ok=%v problems=%v", rep.OK, rep.Problems)
	}
}
