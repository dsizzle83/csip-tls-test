package main

// Hardening plan Q8 (audit MAY-6): per-scenario bench health gates. A dead
// sim must produce an INFRA verdict — a test-infrastructure fault distinct
// from every hub verdict — never a spurious hub PASS/FAIL/BLIND (the modsim
// HTTP-500 class that invalidated a soak batch on 2026-07-16).

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// newFlakyStateServer is a recording-server variant whose GET /state can be
// flipped dead (HTTP 500) at runtime — POSTs (control/inject/fault) always
// succeed, mimicking finding E's failure shape: process up, ground-truth
// endpoint broken.
func newFlakyStateServer(t *testing.T, dead *atomic.Bool) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodGet && r.URL.Path == "/state" && dead.Load() {
			http.Error(w, "json: unsupported value: NaN", http.StatusInternalServerError)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{})
	}))
	t.Cleanup(srv.Close)
	return srv
}

// newInfraTestDriver wires healthy recording servers for every backend except
// solar, which gets the flippable /state server.
func newInfraTestDriver(t *testing.T, solarDead *atomic.Bool) *mayhemDriver {
	t.Helper()
	backends := map[string]string{"solar": newFlakyStateServer(t, solarDead).URL}
	for _, n := range []string{"gridsim", "meter", "battery", "ev"} {
		backends[n] = newRecordingServer(t, &callLog{}).URL
	}
	d := newMayhemDriver(backends)
	d.pvHighW = 4800
	return d
}

func infraTestScenario(setupCalled *bool, verdict string) *mayScenario {
	return &mayScenario{
		ID: "infra-probe-test", Name: "n", Category: "c", Hypothesis: "h", Expected: "e",
		HoldS: 0, // ticks clamp to 1; with 1 ms sampling the hold is ~1 ms
		setup: func(d *mayhemDriver) (*activeConstraint, error) {
			*setupCalled = true
			return nil, nil
		},
		evaluate: func(sc *mayScenario, cons *activeConstraint, s []maySample) mayFinding {
			return mayFinding{ID: sc.ID, Name: sc.Name, Verdict: verdict, Headline: "hub looked fine"}
		},
	}
}

// A sim that is already dead at the pre-scenario probe: the scenario must not
// even arm (its premise cannot hold), and the verdict is INFRA, not
// INCONCLUSIVE/FAIL.
func TestRun_PreflightDeadSim_INFRASkipsScenario(t *testing.T) {
	var dead atomic.Bool
	dead.Store(true)
	d := newInfraTestDriver(t, &dead)

	setupCalled := false
	d.run(context.Background(), []*mayScenario{infraTestScenario(&setupCalled, "PASS")}, time.Millisecond)

	if setupCalled {
		t.Error("setup must not run against a dead bench")
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if n := len(d.status.Findings); n != 1 {
		t.Fatalf("findings = %d, want 1", n)
	}
	f := d.status.Findings[0]
	if f.Verdict != "INFRA" {
		t.Fatalf("verdict = %q, want INFRA", f.Verdict)
	}
	if !strings.Contains(strings.Join(f.Diagnosis, " "), "solar") {
		t.Errorf("diagnosis must name the dead backend, got %v", f.Diagnosis)
	}
	if d.status.Summary.Infra != 1 || d.status.Summary.Pass != 0 || d.status.Summary.Inconclusive != 0 {
		t.Errorf("summary = %+v, want exactly one INFRA", d.status.Summary)
	}
	if !d.status.Finished {
		t.Error("an INFRA scenario must not stop the run from finishing cleanly")
	}
}

// A sim that dies DURING the scenario invalidates the verdict in both
// directions — even a PASS must be reclassified INFRA, with the original
// verdict preserved for the operator.
func TestRun_SimDiesMidScenario_ReclassifiedINFRA(t *testing.T) {
	var dead atomic.Bool
	d := newInfraTestDriver(t, &dead)

	sc := &mayScenario{
		ID: "infra-midrun-test", Name: "n", Category: "c", Hypothesis: "h", Expected: "e",
		HoldS: 0,
		setup: func(d *mayhemDriver) (*activeConstraint, error) {
			dead.Store(true) // the sim crashes mid-scenario
			return nil, nil
		},
		evaluate: func(sc *mayScenario, cons *activeConstraint, s []maySample) mayFinding {
			return mayFinding{ID: sc.ID, Name: sc.Name, Verdict: "PASS", Headline: "hub looked fine"}
		},
	}
	d.run(context.Background(), []*mayScenario{sc}, time.Millisecond)

	d.mu.Lock()
	defer d.mu.Unlock()
	if n := len(d.status.Findings); n != 1 {
		t.Fatalf("findings = %d, want 1", n)
	}
	f := d.status.Findings[0]
	if f.Verdict != "INFRA" {
		t.Fatalf("verdict = %q, want INFRA (a PASS against a dead sim is untrustworthy)", f.Verdict)
	}
	if !strings.Contains(f.Headline, "PASS") {
		t.Errorf("headline must preserve the original verdict, got %q", f.Headline)
	}
	if d.status.Summary.Infra != 1 || d.status.Summary.Pass != 0 {
		t.Errorf("summary = %+v, want the PASS reclassified to INFRA", d.status.Summary)
	}
}

// A healthy bench must pass both probes untouched — no false INFRA against
// the standard recording fixtures.
func TestRun_HealthyBench_NoFalseINFRA(t *testing.T) {
	d, _ := newTestDriver(t, "gridsim", "solar", "meter", "battery", "ev")
	setupCalled := false
	d.run(context.Background(), []*mayScenario{infraTestScenario(&setupCalled, "PASS")}, time.Millisecond)

	d.mu.Lock()
	defer d.mu.Unlock()
	if !setupCalled {
		t.Error("healthy bench: setup must run")
	}
	if d.status.Summary.Infra != 0 || d.status.Summary.Pass != 1 {
		t.Errorf("summary = %+v, want one clean PASS and zero INFRA", d.status.Summary)
	}
}
