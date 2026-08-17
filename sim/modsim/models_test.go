package main

import "testing"

// TestResolveDERModels pins the compatibility rule between the two knobs: a run
// that says nothing about -der-models must serve exactly what -advanced has
// always served, and a typo must stop the sim rather than silently start a
// different device.
func TestResolveDERModels(t *testing.T) {
	for _, tc := range []struct {
		flag     string
		advanced bool
		want     derModelSet
		wantErr  bool
	}{
		{"", false, modelsLegacy, false},
		{"", true, modelsAdvanced, false},
		{"legacy", true, modelsLegacy, false}, // explicit beats the old boolean
		{"advanced", false, modelsAdvanced, false},
		{"full", false, modelsFull, false},
		{"full", true, modelsFull, false},
		{"legacy-curves", false, modelsLegacyCurves, false},
		// The legacy-curve profile is NOT reachable through -advanced and is
		// not folded into "full": it is the OTHER generation, serving no 7xx
		// model at all, so an operator has to ask for it by name.
		{"legacy-curves", true, modelsLegacyCurves, false},
		{"legacy_curves", false, modelsLegacy, true}, // underscore is not the spelling
		{"7xx", true, modelsLegacy, true},
		{"FULL", false, modelsLegacy, true}, // case-sensitive on purpose
	} {
		got, err := resolveDERModels(tc.flag, tc.advanced)
		if (err != nil) != tc.wantErr {
			t.Errorf("resolveDERModels(%q, %v) error = %v, wantErr %v", tc.flag, tc.advanced, err, tc.wantErr)
			continue
		}
		if err == nil && got != tc.want {
			t.Errorf("resolveDERModels(%q, %v) = %v, want %v", tc.flag, tc.advanced, got, tc.want)
		}
	}
}

// TestResolveCurveVSF pins the lever's parsing rule, which is where "empty is
// not zero" has to hold: 0 is the WHOLE-PERCENT device an operator deliberately
// asks for, so an unset flag has to be distinguishable from it. It also pins the
// refusals — a typo or an unservable resolution must stop the sim rather than
// start a device with a different declared granularity than the one asked for,
// because every curve row's verdict then reads as a product finding.
func TestResolveCurveVSF(t *testing.T) {
	for _, tc := range []struct {
		flag    string
		wantSet bool
		want    int16
		wantErr bool
	}{
		{"", false, 0, false},   // unset — the built-in default
		{"0", true, 0, false},   // the coarse device, asked for by name
		{"-2", true, -2, false}, // the default, stated explicitly
		{"-1", true, -1, false},
		{"2", true, 2, false},
		{"-3", false, 0, true},  // legal sunssf, unservable on a uint16 %VNom axis
		{"11", false, 0, true},  // outside the sunssf domain
		{"-11", false, 0, true}, // ditto
		{"x", false, 0, true},   // typo
		{" 0", false, 0, true},  // no lenient whitespace: a shell quoting slip is an error
		{"0.0", false, 0, true}, // a scale factor is an integer
		{"", false, 0, false},   // repeated deliberately: empty stays empty
	} {
		got, err := resolveCurveVSF(tc.flag)
		if tc.wantErr {
			if err == nil {
				t.Errorf("resolveCurveVSF(%q) = %+v, want an error", tc.flag, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("resolveCurveVSF(%q): %v", tc.flag, err)
			continue
		}
		if tc.wantSet != (got.CurveVoltageSF != nil) {
			t.Errorf("resolveCurveVSF(%q) set=%v, want set=%v", tc.flag, got.CurveVoltageSF != nil, tc.wantSet)
			continue
		}
		if tc.wantSet && *got.CurveVoltageSF != tc.want {
			t.Errorf("resolveCurveVSF(%q) = %d, want %d", tc.flag, *got.CurveVoltageSF, tc.want)
		}
		// The resolved default must be the sim's, not a number restated here.
		if !tc.wantSet && got.CurveVoltageSFOrDefault() == 0 {
			t.Errorf("resolveCurveVSF(%q) resolves to a whole-percent axis by default; the CTP's "+
				"own Figure-6 values are unrepresentable there", tc.flag)
		}
	}
}

// TestModelsName pins the spelling the -der-curve-vsf refusal quotes back to the
// operator: a diagnostic that names a model set the flag does not accept would
// send them to the wrong fix.
func TestModelsName(t *testing.T) {
	for _, tc := range []struct {
		set  derModelSet
		want string
	}{
		{modelsLegacy, "legacy"},
		{modelsAdvanced, "advanced"},
		{modelsFull, "full"},
		{modelsLegacyCurves, "legacy-curves"},
	} {
		if got := modelsName(tc.set); got != tc.want {
			t.Errorf("modelsName(%v) = %q, want %q", tc.set, got, tc.want)
		}
		// It must round-trip through the flag parser it quotes.
		if back, err := resolveDERModels(tc.want, false); err != nil || back != tc.set {
			t.Errorf("resolveDERModels(%q) = %v, %v — modelsName produced a spelling "+
				"-der-models does not accept", tc.want, back, err)
		}
	}
}
