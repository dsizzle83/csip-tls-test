package gwmayhem

// loader_test.go proves the suite assembly + the Mayhem collision rule + the RBAC
// contract table, all without a live gateway (make test-fast).

import (
	"os"
	"path/filepath"
	"testing"
)

// TestGoScenarioIDsUnique guards against two Go scenarios claiming the same id (the
// collision rule can only protect specs if the Go set is itself clean).
func TestGoScenarioIDsUnique(t *testing.T) {
	seen := map[string]bool{}
	for _, sc := range goScenarios() {
		if seen[sc.ID] {
			t.Errorf("duplicate Go scenario id %q", sc.ID)
		}
		seen[sc.ID] = true
		if _, ok := oracleRegistry[sc.oracle]; !ok {
			t.Errorf("scenario %q names unregistered oracle %q", sc.ID, sc.oracle)
		}
	}
}

// TestShippedSpecsLoad proves every committed qa/gw-scenarios/*.json spec loads
// clean (no schema error, no id collision with a Go scenario).
func TestShippedSpecsLoad(t *testing.T) {
	scenarios, errs := AllScenarios(filepath.Join("..", "..", "qa", "gw-scenarios"))
	for _, e := range errs {
		t.Errorf("shipped spec load error: %v", e)
	}
	// The 5 Go families plus at least the two shipped specs.
	if len(scenarios) < len(goScenarios())+2 {
		t.Errorf("loaded %d scenarios, want at least %d", len(scenarios), len(goScenarios())+2)
	}
	specs := 0
	for _, sc := range scenarios {
		if sc.Source == SourceSpec {
			specs++
		}
	}
	if specs < 2 {
		t.Errorf("loaded %d spec scenarios, want at least 2", specs)
	}
}

// TestSpecCollisionIsLoadError proves a spec whose id collides with a Go scenario is
// rejected at load — a load error, and NOT added to the suite (never a silent
// shadow), while a valid sibling spec in the same dir still loads.
func TestSpecCollisionIsLoadError(t *testing.T) {
	dir := t.TempDir()
	// Colliding spec: same id as the Go matrix scenario.
	writeSpec(t, dir, "collide.json", `{
      "camp_v": 1, "id": "authz-role-denial-matrix", "name": "shadow attempt",
      "role": "ReadOnlySunSpec", "target": "gateway",
      "steps": [{"do": "expect_exception", "unit": 2, "model": 704, "point": "WMaxLimPct", "value": 25, "expect_code": 1}],
      "oracle": {"name": "denyExpected"}, "expected_verdicts": ["PASS"]
    }`)
	// A clean sibling that must still load.
	writeSpec(t, dir, "ok.json", `{
      "camp_v": 1, "id": "authz-loader-test-ok", "name": "loads fine",
      "role": "ReadOnlySunSpec", "target": "gateway",
      "steps": [{"do": "expect_exception", "unit": 2, "model": 704, "point": "WMaxLimPct", "value": 25, "expect_code": 1}],
      "oracle": {"name": "denyExpected"}, "expected_verdicts": ["PASS"]
    }`)

	scenarios, errs := AllScenarios(dir)
	if len(errs) != 1 {
		t.Fatalf("want exactly 1 load error (the collision), got %d: %v", len(errs), errs)
	}
	got := map[string]string{}
	for _, sc := range scenarios {
		got[sc.ID] = sc.Source
	}
	// The colliding id stays the Go scenario, never the shadow spec.
	if got["authz-role-denial-matrix"] != SourceGo {
		t.Errorf("collision let the spec shadow the Go scenario (source=%q)", got["authz-role-denial-matrix"])
	}
	if got["authz-loader-test-ok"] != SourceSpec {
		t.Errorf("the clean sibling spec did not load (a collision must not block another file)")
	}
}

// TestRBACContract pins the load-bearing cells of the contract table, including the
// non-obvious NetworkAdmin one.
func TestRBACContract(t *testing.T) {
	for _, role := range contractRoles() {
		for _, op := range opClasses() {
			if _, ok := expectedGrant(role, op); !ok {
				t.Errorf("contract missing cell %s / %s", role, op)
			}
		}
		// Every role reads both measurement and control points.
		if g, _ := expectedGrant(role, opReadMeas); g != grantAllow {
			t.Errorf("%s read-meas = %s, want grant", role, g)
		}
		if g, _ := expectedGrant(role, opReadCtl); g != grantAllow {
			t.Errorf("%s read-ctl = %s, want grant", role, g)
		}
	}
	writeCells := map[string]grant{
		"ReadOnlySunSpec":             grantDeny,
		"LexaVoltReadOnly":            grantDeny,
		"NetworkAdministratorSunSpec": grantDeny, // the non-obvious one
		"GridServiceSunSpec":          grantAllow,
		"SuperAdministratorSunSpec":   grantAllow,
	}
	for role, want := range writeCells {
		if g, _ := expectedGrant(role, opWriteCtl); g != want {
			t.Errorf("%s write-ctl = %s, want %s", role, g, want)
		}
	}
}

// TestFilterOnly proves --only selection.
func TestFilterOnly(t *testing.T) {
	all := goScenarios()
	got := filterOnly(all, []string{"authz-cert-negatives", "nonexistent"})
	if len(got) != 1 || got[0].ID != "authz-cert-negatives" {
		t.Errorf("filterOnly = %v, want just authz-cert-negatives", ids(got))
	}
	if len(filterOnly(all, nil)) != len(all) {
		t.Errorf("empty --only should select everything")
	}
}

func writeSpec(t *testing.T, dir, name, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
}

func ids(scs []gwScenario) []string {
	out := make([]string, len(scs))
	for i, s := range scs {
		out[i] = s.ID
	}
	return out
}
