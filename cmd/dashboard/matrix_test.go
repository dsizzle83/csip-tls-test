package main

import (
	"reflect"
	"strings"
	"testing"
)

// The fault matrix is each curated cell crossed with {no jitter, jitter}, so the
// count is even and every base id appears twice (plain and +jitter), with the
// right diagnoser routed per fault.
func TestMatrixScenarios_CrossAndRouting(t *testing.T) {
	d := &mayhemDriver{pvHighW: 4800}
	scs := d.matrixScenarios()
	if len(scs) == 0 || len(scs)%2 != 0 {
		t.Fatalf("matrix produced %d scenarios, want a positive even count", len(scs))
	}

	plain, jit := 0, 0
	for _, sc := range scs {
		if !strings.HasPrefix(sc.ID, "matrix/") {
			t.Errorf("scenario %q is not namespaced under matrix/", sc.ID)
		}
		if sc.setup == nil || sc.evaluate == nil {
			t.Errorf("%s missing setup/evaluate", sc.ID)
		}
		if strings.Contains(sc.ID, "+jitter") {
			jit++
		} else {
			plain++
		}
	}
	if plain != jit {
		t.Errorf("uneven jitter cross: %d plain vs %d jitter", plain, jit)
	}

	// Spot-check diagnoser routing on representative cells.
	want := map[string]func(*mayScenario, *activeConstraint, []maySample) mayFinding{
		"matrix/genlimit-reject":     diagnoseConverge,
		"matrix/exportcap-wrongsign": diagnoseSOC,
		"matrix/genlimit-clean":      diagnoseConstraint,
		"matrix/importcap-socrefuse": diagnoseConstraint,
	}
	byID := map[string]*mayScenario{}
	for _, sc := range scs {
		byID[sc.ID] = sc
	}
	for id, fn := range want {
		sc, ok := byID[id]
		if !ok {
			t.Errorf("missing matrix cell %q", id)
			continue
		}
		if reflect.ValueOf(sc.evaluate).Pointer() != reflect.ValueOf(fn).Pointer() {
			t.Errorf("%s: wrong diagnoser routed", id)
		}
	}
}
