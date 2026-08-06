package suitemodbusclient

// writelever_test.go pins WR-1/WR-2's divergence lever against the simapi
// encoding defect it used to fall into, and against the fix (RMD-046).
//
// The two rows' entire provocation is "move the server's ceiling register away
// from what the DUT last wrote, then put it back". With the OLD 0.5/1.0
// workaround pair (chosen to cancel the sim's OLD `val*100` double-scale)
// neither half happened once the sim's encoding was corrected out from under
// them: `POST /inject {"WMaxLimPct_pct": N}` now encodes
// `RawFromScaleSigned(N, SF)` against SF = −2 directly, so 0.5/1.0 would
// silently collapse to raw 50/100 (0.50 %/1.00 %) — still a divergence, but
// not the 50.00 %/100.00 % the check's own prose claims to write. divergePct
// and restorePct are plain 50 and 100 now; this file is the arithmetic pin
// that keeps them that way.
//
// This is arithmetic, so it is tested as arithmetic: no bench, no sim, no
// harness. The point is that a future edit reintroducing a `*100` (or
// reverting the constants to the old 0.5/1.0 workaround) fails here with the
// reason attached, rather than silently breaking two write rows again.

import (
	"testing"

	"lexa-proto/sunspec"
)

// injectSF is the scale factor both sims write for M123's WMaxLimPct
// (sim/southbound/sim.go and battery.go: `sfN(-2)`).
const injectSF int16 = -2

// asSimEncodes reproduces the sims' current (fixed) POST /inject arithmetic
// for the "WMaxLimPct_pct" key, verbatim: RawFromScaleSigned(val, SF). See
// sim/southbound/battery.go and solar.go's Inject, case "WMaxLimPct_pct".
func asSimEncodes(pct float64) uint16 {
	return sunspec.RawFromScaleSigned(pct, injectSF)
}

// asOldBuggySimEncoded reproduces the PRE-RMD-046 arithmetic — the double
// scale this file used to work around — purely so the contrast below can be
// asserted rather than just claimed in prose.
func asOldBuggySimEncoded(pct float64) uint16 {
	return sunspec.RawFromScaleSigned(pct*100, injectSF)
}

func TestDivergenceLeverActuallyDivergesAndActuallyRestores(t *testing.T) {
	const saturated = 0x7FFF // EncodeScaleSigned's positive saturation word

	div, res := asSimEncodes(divergePct), asSimEncodes(restorePct)

	if div == res {
		t.Fatalf("the divergence and the restore encode to the same register (%d): the teardown restores "+
			"nothing, and the second write row's divergence is a no-op against the first row's leftovers",
			div)
	}
	if div == saturated || res == saturated {
		t.Fatalf("divergence=%d restore=%d — a saturated word means the ceiling commanded is not the "+
			"ceiling written down (0x7FFF at SF -2 reads as 327.67 %%)", div, res)
	}
	// And they must mean what the check's own prose says they mean: 50.00 %
	// and 100.00 % at SF −2 are raw 5000 and raw 10000. 10000 is also the
	// sim's own power-on ceiling (SolarServer.powerOnReset).
	if div != 5000 {
		t.Errorf("divergePct encodes to %d, want 5000 (= 50.00 %% at SF -2), which is what the "+
			"injection's stated rationale claims it writes", div)
	}
	if res != 10000 {
		t.Errorf("restorePct encodes to %d, want 10000 (= 100.00 %% at SF -2, the sim's power-on "+
			"ceiling)", res)
	}
}

// TestDivergePctAndRestorePctArePlainPercentages pins the RMD-046 migration
// itself: divergePct/restorePct must be the plain 50/100 the check's prose
// describes, not the 0.5/1.0 workaround the old double-scaled sim needed.
func TestDivergePctAndRestorePctArePlainPercentages(t *testing.T) {
	if divergePct != 50 {
		t.Errorf("divergePct = %v, want 50 — the sim now encodes WMaxLimPct_pct directly (no *100 "+
			"double scale), so the honest way to command a 50%% ceiling is to pass 50, not a fractional "+
			"workaround", divergePct)
	}
	if restorePct != 100 {
		t.Errorf("restorePct = %v, want 100 — see divergePct", restorePct)
	}
}

// TestTheOldDoubleScaledEncodingWouldHaveSaturated demonstrates the FIXED
// defect rather than asserting its absence, so the reason divergePct/
// restorePct changed from 0.5/1.0 to 50/100 is checkable rather than merely
// claimed. It exercises asOldBuggySimEncoded (the old arithmetic, reproduced
// inline) against the CURRENT constants, not any code path the sims still
// run — sim/southbound/battery.go and solar.go no longer multiply by 100 (see
// their Inject, case "WMaxLimPct_pct"), so this is a historical record, not a
// live behaviour pin.
func TestTheOldDoubleScaledEncodingWouldHaveSaturated(t *testing.T) {
	old50, old100 := asOldBuggySimEncoded(50), asOldBuggySimEncoded(100)
	if old50 != old100 {
		t.Fatalf("the old val*100 arithmetic no longer saturates 50%%%% and 100%%%% to the same word "+
			"(%d vs %d) — this test's premise has changed; re-derive it against whatever "+
			"RawFromScaleSigned now does at large inputs", old50, old100)
	}
	if old50 != 0x7FFF {
		t.Errorf("the old-arithmetic value encoded to %d, not the saturation word — this test's premise "+
			"no longer holds and should be re-derived", old50)
	}
}
