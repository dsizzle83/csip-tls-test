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

// A chaos run is reproducible: the same seed yields the same scenario sequence
// (so any failure is replayable), and a different seed explores a different one.
func TestChaosScenarios_Deterministic(t *testing.T) {
	d := &mayhemDriver{pvHighW: 4800}
	a := d.chaosScenarios(42, 6)
	b := d.chaosScenarios(42, 6)
	if len(a) != 6 || len(b) != 6 {
		t.Fatalf("chaos produced %d/%d scenarios, want 6", len(a), len(b))
	}
	for i := range a {
		if a[i].ID != b[i].ID {
			t.Fatalf("seed 42 not deterministic at %d: %q vs %q", i, a[i].ID, b[i].ID)
		}
		if a[i].evaluate == nil || a[i].setup == nil {
			t.Errorf("chaos scenario %d missing setup/evaluate", i)
		}
	}
	c := d.chaosScenarios(7, 6)
	same := true
	for i := range a {
		if a[i].ID != c[i].ID {
			same = false
			break
		}
	}
	if same {
		t.Error("seed 7 produced the same sequence as seed 42 — not actually seeded")
	}
}
