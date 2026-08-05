package suitemodbusclient

// writelever_test.go pins WR-1/WR-2's divergence lever against the recorded
// simapi encoding defect it used to fall into.
//
// The two rows' entire provocation is "move the server's ceiling register away
// from what the DUT last wrote, then put it back". With the old 50/100 pair
// neither half happened: `POST /inject {"WMaxLimPct_pct": N}` encodes
// RawFromScaleSigned(N*100, SF) against SF = −2, i.e. N × 10000, so both
// numbers saturated to the same word. The divergence and the restore wrote the
// identical register, which means the teardown restored nothing and WR-2 —
// running after WR-1 had already parked the register at the saturation — was
// provoking with a value that was already there.
//
// This is arithmetic, so it is tested as arithmetic: no bench, no sim, no
// harness. The point is that a future edit "tidying" 0.5 back to 50 fails here
// with the reason attached, rather than silently restoring two no-op rows.

import (
	"testing"

	"lexa-proto/sunspec"
)

// injectSF is the scale factor both sims write for M123's WMaxLimPct
// (sim/southbound/sim.go and battery.go: `sfN(-2)`).
const injectSF int16 = -2

// asSimEncodes reproduces the sims' POST /inject arithmetic for the
// "WMaxLimPct_pct" key, verbatim: RawFromScaleSigned(val*100, SF).
func asSimEncodes(pct float64) uint16 {
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

// TestTheOldWriteLeverValuesWereBothTheSameSaturatedWord is the other half of
// the pin: it demonstrates the defect rather than asserting its absence, so the
// reason the constants look wrong is checkable rather than merely claimed.
func TestTheOldWriteLeverValuesWereBothTheSameSaturatedWord(t *testing.T) {
	old50, old100 := asSimEncodes(50), asSimEncodes(100)
	if old50 != old100 {
		t.Fatalf("50%%%% and 100%%%% now encode differently (%d vs %d) — the repo-wide WMaxLimPct_pct "+
			"encoding defect recorded in sim/southbound/battery_pack.go's injectPackDispatch has been "+
			"fixed. Re-read divergePct/restorePct's comment: the workaround they encode is no longer "+
			"needed and should be reverted to plain 50 and 100", old50, old100)
	}
	if old50 != 0x7FFF {
		t.Errorf("the old lever value encoded to %d, not the saturation word — this test's premise "+
			"no longer holds and its sibling above should be re-derived", old50)
	}
}
