package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// handleScenarios must serve the catalogue scripts/mayhem.py consumes: a
// {"scenarios":[{id,name,...}]} object with one entry per curated scenario, so
// the Python runner can drop its mirrored copy and not drift.
func TestHandleScenarios(t *testing.T) {
	d := newMayhemDriver(map[string]string{})
	rr := httptest.NewRecorder()
	d.handleScenarios(rr, httptest.NewRequest(http.MethodGet, "/api/qa/scenarios", nil))

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	var body struct {
		Scenarios []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"scenarios"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("response is not valid JSON: %v", err)
	}
	if len(body.Scenarios) != len(d.scenarios()) {
		t.Errorf("served %d scenarios, want %d (one per curated scenario)", len(body.Scenarios), len(d.scenarios()))
	}
	for _, s := range body.Scenarios {
		if s.ID == "" || s.Name == "" {
			t.Errorf("scenario missing id/name: %+v", s)
		}
	}
}

// escalateForAudit must fail-escalate a cross-cutting safety violation the
// scenario's own oracle would otherwise let PASS, while riding out 1–2 sample
// transients and never downgrading a FAIL/INCONCLUSIVE.
func TestEscalateForAudit(t *testing.T) {
	conn := []invViolation{{Inv: "INV-CONNECT", T: 40, Detail: "back-feed 900 W"}}
	soc3 := []invViolation{{Inv: "INV-SOC", Detail: "drain"}, {Inv: "INV-SOC"}, {Inv: "INV-SOC"}}
	soc2 := []invViolation{{Inv: "INV-SOC", Detail: "drain"}, {Inv: "INV-SOC"}}
	evmax3 := []invViolation{{Inv: "INV-EVMAX", Detail: "6000A"}, {Inv: "INV-EVMAX"}, {Inv: "INV-EVMAX"}}
	exp3 := []invViolation{{Inv: "INV-EXPIRED", Detail: "stale"}, {Inv: "INV-EXPIRED"}, {Inv: "INV-EXPIRED"}}

	cases := []struct {
		name    string
		verdict string
		audit   []invViolation
		want    string
	}{
		{"connect any escalates PASS", "PASS", conn, "FAIL"},
		{"connect any escalates DEGRADED", "DEGRADED", conn, "FAIL"},
		{"soc sustained fails", "PASS", soc3, "FAIL"},
		{"soc transient ignored", "PASS", soc2, "PASS"},
		{"evmax sustained fails", "PASS", evmax3, "FAIL"},
		{"expired sustained degrades a PASS", "PASS", exp3, "DEGRADED"},
		{"expired leaves DEGRADED", "DEGRADED", exp3, "DEGRADED"},
		{"never downgrades a FAIL", "FAIL", conn, "FAIL"},
		{"never touches INCONCLUSIVE", "INCONCLUSIVE", soc3, "INCONCLUSIVE"},
		{"no audit, no change", "PASS", nil, "PASS"},
	}
	for _, c := range cases {
		got, hl := escalateForAudit(c.verdict, c.audit)
		if got != c.want {
			t.Errorf("%s: escalateForAudit(%q) verdict = %q, want %q", c.name, c.verdict, got, c.want)
		}
		if got != c.verdict && hl == "" {
			t.Errorf("%s: escalation should carry a headline", c.name)
		}
	}
}

// hubReactedSample must recognise the lever appropriate to each constraint, not
// only solar curtailment — the import-cap battery-discharge case is the gap the
// review flagged.
func TestHubReactedSample(t *testing.T) {
	exp := exportCons()     // exportCap
	imp := importCons1000() // importCap

	cases := []struct {
		name string
		cons *activeConstraint
		smp  maySample
		want bool
	}{
		{"export: solar curtailed", exp, maySample{SolarOK: true, SolarPossibleW: 6000, SolarW: 4000}, true},
		{"export: battery charging (sim)", exp, maySample{SolarOK: true, SolarPossibleW: 6000, SolarW: 6000, BatterySimOK: true, BatterySimW: -2000}, true},
		{"export: idle, no reaction", exp, maySample{SolarOK: true, SolarPossibleW: 6000, SolarW: 6000}, false},
		{"import: battery discharging (sim)", imp, maySample{BatterySimOK: true, BatterySimW: 2000}, true},
		{"import: battery charging is not a reaction", imp, maySample{BatterySimOK: true, BatterySimW: -2000}, false},
		{"import: falls back to hub W when no sim", imp, maySample{BatteryW: 2000}, true},
		{"import: solar curtailment also counts", imp, maySample{SolarOK: true, SolarPossibleW: 6000, SolarW: 3000}, true},
	}
	for _, c := range cases {
		if got := hubReactedSample(c.cons, c.smp); got != c.want {
			t.Errorf("%s: hubReactedSample = %v, want %v", c.name, got, c.want)
		}
	}
}
