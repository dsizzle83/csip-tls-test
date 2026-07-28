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
