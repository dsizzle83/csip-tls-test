package sim

import (
	"math"
	"testing"
)

// TestClampToSoC verifies the battery sim won't report power the pack can't
// physically deliver — the phantom-energy bug a full 92-day replay exposed,
// where an empty pack kept "discharging" thousands of ticks at 0% SoC.
func TestClampToSoC(t *testing.T) {
	const cap = 10000.0 // 10 kWh
	const dt = 5.0      // 5 s tick

	// A 5 kW discharge over 5 s removes 5000*5/3600 = 6.94 Wh = 0.069% of 10 kWh.
	step := 5000.0 * dt / 3600.0 / cap * 100 // ≈ 0.0694 %

	tests := []struct {
		name             string
		w, soc           float64
		wantW, wantSocLo float64
		wantSocHi        float64
	}{
		{"discharge at empty → zero power", 5000, 0, 0, 0, 0},
		{"charge at full → zero power", -5000, 100, 0, 100, 100},
		{"normal discharge mid-SoC unchanged", 5000, 50, 5000, 50 - step - 1e-6, 50 - step + 1e-6},
		{"normal charge mid-SoC unchanged", -5000, 50, -5000, 50 + step - 1e-6, 50 + step + 1e-6},
		{"discharge near empty is partially clamped", 5000, step / 2, 2500, 0, 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gotW, gotSoc := clampToSoC(tc.w, tc.soc, cap, dt)
			// Clamped power must never exceed the command magnitude or flip sign.
			if math.Abs(gotW) > math.Abs(tc.w)+1e-6 {
				t.Errorf("clamped |w|=%.1f exceeds command |w|=%.1f", gotW, tc.w)
			}
			if math.Abs(gotW-tc.wantW) > 1.0 {
				t.Errorf("w = %.1f, want ≈ %.1f", gotW, tc.wantW)
			}
			if gotSoc < tc.wantSocLo || gotSoc > tc.wantSocHi {
				t.Errorf("soc = %.4f, want in [%.4f, %.4f]", gotSoc, tc.wantSocLo, tc.wantSocHi)
			}
			if gotSoc < -1e-9 || gotSoc > 100+1e-9 {
				t.Errorf("soc = %.4f out of [0,100]", gotSoc)
			}
		})
	}
}
