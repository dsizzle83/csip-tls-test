package sim

import (
	"math"
	"testing"

	"lexa-proto/sunspec"
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

// TestInject_EnaOverride pins the two-step "hub-controlled idle" inject the QA
// harness relies on between scenarios: {"WMaxLimPct_pct": 0} zeroes the
// setpoint but RELEASES the pack (Ena=0 → free-running demo sinusoid); a
// follow-up {"Ena": 1} re-captures it so hubBatteryW reads a held 0 W instead
// of NaN. Without the override, a cycle-boundary battery free-ran a ±4 kW
// sinusoid into scenario 1 for up to 60 s (the hub's identical idle command
// was dedupe-suppressed) — QA v6: export-cap-full-battery INV-SOC FAIL.
func TestInject_EnaOverride(t *testing.T) {
	const wmaxKwh, wmaxW = 10.0, 5000.0
	r := &RegisterMap{regs: make(map[uint16]uint16)}
	b := populateBattery(r, wmaxKwh, wmaxW)
	bs := &BatteryServer{Server: &Server{Regs: r}, bases: b, wmaxW: wmaxW, wmaxKwh: wmaxKwh}
	r.Set(b.M123Base+sunspec.M123_Conn, 1)

	// pct-0 inject alone releases the pack: hubBatteryW = NaN (animation runs).
	if err := bs.Inject([]byte(`{"WMaxLimPct_pct": 0}`)); err != nil {
		t.Fatalf("inject pct 0: %v", err)
	}
	if w := hubBatteryW(r, b.M123Base, wmaxW); !math.IsNaN(w) {
		t.Fatalf("after pct-0 inject, hubBatteryW = %v, want NaN (released)", w)
	}

	// Ena override re-captures it at the held 0 W setpoint.
	if err := bs.Inject([]byte(`{"Ena": 1}`)); err != nil {
		t.Fatalf("inject Ena 1: %v", err)
	}
	if w := hubBatteryW(r, b.M123Base, wmaxW); w != 0 {
		t.Fatalf("after Ena override, hubBatteryW = %v, want held 0 W", w)
	}
}
