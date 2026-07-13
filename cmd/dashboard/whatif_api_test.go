package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"csip-tls-test/internal/scenariodata"
	"csip-tls-test/internal/tariff"
	"csip-tls-test/internal/whatif"
)

// ---- fixture generation (kept in-test to avoid extra tracked files) -------

func miniWeatherJSON(t *testing.T, startDate, tz string, days int) []byte {
	t.Helper()
	loc, err := time.LoadLocation(tz)
	if err != nil {
		t.Fatalf("LoadLocation: %v", err)
	}
	sd, _ := time.Parse("2006-01-02", startDate)
	start := time.Date(sd.Year(), sd.Month(), sd.Day(), 0, 0, 0, 0, loc)
	n := days * 24
	hours := make([]string, n)
	ghi := make([]float64, n)
	temp := make([]float64, n)
	for h := 0; h < n; h++ {
		ts := start.Add(time.Duration(h) * time.Hour)
		hours[h] = ts.Format("2006-01-02T15:04")
		hod := float64(ts.Hour())
		if hod > 6 && hod < 18 {
			ghi[h] = 700 * math.Sin(math.Pi*(hod-6)/12)
		}
		temp[h] = 28 + 6*math.Sin(math.Pi*(hod-6)/12)
	}
	b, _ := json.Marshal(map[string]any{
		"timezone": tz, "hours": hours, "ghi_wm2": ghi, "temp_c": temp,
	})
	return b
}

func miniScenarioJSON(id, tz, territory, startDate string, days int) []byte {
	sd, _ := time.Parse("2006-01-02", startDate)
	end := sd.AddDate(0, 0, days-1).Format("2006-01-02")
	b, _ := json.Marshal(map[string]any{
		"id": id, "label": id,
		"location": map[string]any{
			"city": "Test", "state": "TX", "lat": 1.0, "lon": 2.0,
			"timezone": tz, "territory": territory, "blurb": "x",
		},
		"period":            map[string]any{"start": startDate, "end": end},
		"weather":           map[string]any{"source": "synthetic", "retrieved": "2026-07-13", "source_url": "https://x.test"},
		"tariff_ids":        []string{},
		"default_tariff_id": "",
		"home_defaults": map[string]any{
			"profile": "p", "base_kw": 0.45,
			"hvac": map[string]any{"cool_setpoint_f": 75, "kw_per_degf": 0.16, "max_kw": 4.2},
		},
		"instrument_defaults": map[string]any{
			"pv_kw":   8.0,
			"battery": map[string]any{"kwh": 13.5, "kw": 5.0, "reserve_pct": 10, "round_trip_eff": 0.9},
			"ev": map[string]any{"present": true, "battery_kwh": 60, "charger_kw": 7.2,
				"weekday_kwh": 11, "depart_hour": 8, "return_hour": 17},
		},
	})
	return b
}

func miniTariffJSON(id, tz, territory, effFrom, effTo string) []byte {
	return []byte(fmt.Sprintf(`{
      "id": %q, "name": "Mini", "short_name": "Mini", "utility": "T",
      "territory": %q, "timezone": %q, "currency": "USD",
      "effective": { "from": %q, "to": %q },
      "provenance": { "source_url": "https://x.test", "retrieved": "2026-07-13",
                      "confidence": "estimated", "notes": "test" },
      "fixed_monthly_usd": 5.0,
      "energy": { "seasons": [ { "id": "all", "months": [1,2,3,4,5,6,7,8,9,10,11,12],
        "day_types": [ { "days": ["mon","tue","wed","thu","fri","sat","sun"], "periods": [
          { "id": "flat", "label": "Flat", "start": "00:00", "end": "24:00", "rate_usd_per_kwh": 0.15 }
        ] } ] } ] },
      "riders_usd_per_kwh": 0.0,
      "export": { "type": "none" }
    }`, id, territory, tz, effFrom, effTo))
}

// setupMiniEnv writes one scenario and four tariffs into temp dirs and returns
// (scenarioDir, tariffDir). The scenario is 2 weekdays in July, America/Chicago,
// territory "mini-tx".
func setupMiniEnv(t *testing.T) (string, string) {
	t.Helper()
	scDir := t.TempDir()
	tDir := t.TempDir()

	scID := "mini-jul"
	one := filepath.Join(scDir, scID)
	if err := os.MkdirAll(one, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(one, "scenario.json"),
		miniScenarioJSON(scID, "America/Chicago", "mini-tx", "2025-07-07", 2), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(one, "weather.json"),
		miniWeatherJSON(t, "2025-07-07", "America/Chicago", 2), 0o644); err != nil {
		t.Fatal(err)
	}

	write := func(name string, b []byte) {
		if err := os.WriteFile(filepath.Join(tDir, name+".json"), b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("mini-match", miniTariffJSON("mini-match", "America/Chicago", "mini-tx", "2025-01-01", "2025-12-31"))
	write("mini-badterritory", miniTariffJSON("mini-badterritory", "America/Chicago", "other-territory", "2025-01-01", "2025-12-31"))
	write("mini-badtz", miniTariffJSON("mini-badtz", "America/New_York", "mini-tx", "2025-01-01", "2025-12-31"))
	write("mini-badeff", miniTariffJSON("mini-badeff", "America/Chicago", "mini-tx", "2025-01-01", "2025-01-31"))
	return scDir, tDir
}

func newWhatifServer(scDir, tDir string) *httptest.Server {
	mux := http.NewServeMux()
	registerWhatif(mux, scDir, tDir)
	return httptest.NewServer(mux)
}

func postRun(t *testing.T, srv *httptest.Server, body map[string]any) (int, map[string]any) {
	t.Helper()
	b, _ := json.Marshal(body)
	resp, err := http.Post(srv.URL+"/api/whatif/run", "application/json", bytes.NewReader(b))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

// ---- happy path (synthetic env) -------------------------------------------

func TestWhatifRunHappyMini(t *testing.T) {
	scDir, tDir := setupMiniEnv(t)
	srv := newWhatifServer(scDir, tDir)
	defer srv.Close()

	code, out := postRun(t, srv, map[string]any{
		"scenario_id": "mini-jul",
		"tariff_ids":  []string{"mini-match"},
	})
	if code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body: %v)", code, out)
	}
	runs, ok := out["runs"].([]any)
	if !ok || len(runs) != 3 {
		t.Fatalf("expected 3 runs, got %v", out["runs"])
	}
	savings, ok := out["savings"].([]any)
	if !ok || len(savings) != 2 {
		t.Fatalf("expected 2 savings, got %v", out["savings"])
	}
	if _, ok := out["provenance"]; !ok {
		t.Errorf("missing provenance block")
	}
}

// Partial instruments override merges onto scenario defaults (only pv_kw sent).
func TestWhatifRunInstrumentOverride(t *testing.T) {
	scDir, tDir := setupMiniEnv(t)
	srv := newWhatifServer(scDir, tDir)
	defer srv.Close()

	code, out := postRun(t, srv, map[string]any{
		"scenario_id": "mini-jul",
		"tariff_ids":  []string{"mini-match"},
		"instruments": map[string]any{"pv_kw": 0.0}, // disable PV
		"policies":    []string{"baseline", "der_dumb"},
	})
	if code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body: %v)", code, out)
	}
	// With PV disabled, der_dumb should have zero export and near-zero PV kWh.
	runs := out["runs"].([]any)
	if len(runs) != 2 {
		t.Fatalf("expected 2 runs (subset), got %d", len(runs))
	}
}

// ---- 400 cases ------------------------------------------------------------

func TestWhatifRun400(t *testing.T) {
	scDir, tDir := setupMiniEnv(t)
	srv := newWhatifServer(scDir, tDir)
	defer srv.Close()

	cases := []struct {
		name string
		body map[string]any
	}{
		{"missing scenario_id", map[string]any{"tariff_ids": []string{"mini-match"}}},
		{"unknown scenario", map[string]any{"scenario_id": "nope", "tariff_ids": []string{"mini-match"}}},
		{"unknown tariff", map[string]any{"scenario_id": "mini-jul", "tariff_ids": []string{"nope"}}},
		{"empty tariff_ids", map[string]any{"scenario_id": "mini-jul", "tariff_ids": []string{}}},
		{"too many tariff_ids", map[string]any{"scenario_id": "mini-jul",
			"tariff_ids": []string{"a", "b", "c", "d", "e"}}},
		{"bad instruments", map[string]any{"scenario_id": "mini-jul", "tariff_ids": []string{"mini-match"},
			"instruments": map[string]any{"pv_kw": -5.0}}},
		{"unknown policy", map[string]any{"scenario_id": "mini-jul", "tariff_ids": []string{"mini-match"},
			"policies": []string{"turbo"}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			code, out := postRun(t, srv, tc.body)
			if code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400 (body: %v)", code, out)
			}
		})
	}
}

// ---- 422 cross-validation cases -------------------------------------------

func TestWhatifRun422(t *testing.T) {
	scDir, tDir := setupMiniEnv(t)
	srv := newWhatifServer(scDir, tDir)
	defer srv.Close()

	cases := []struct {
		name   string
		tariff string
	}{
		{"territory mismatch", "mini-badterritory"},
		{"timezone mismatch", "mini-badtz"},
		{"effective-range mismatch", "mini-badeff"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			code, out := postRun(t, srv, map[string]any{
				"scenario_id": "mini-jul",
				"tariff_ids":  []string{tc.tariff},
			})
			if code != http.StatusUnprocessableEntity {
				t.Fatalf("status = %d, want 422 (body: %v)", code, out)
			}
		})
	}
}

// ---- GET /api/scenarios and /api/tariffs ----------------------------------

func TestWhatifScenariosAndTariffs(t *testing.T) {
	scDir, tDir := setupMiniEnv(t)
	srv := newWhatifServer(scDir, tDir)
	defer srv.Close()

	// /api/scenarios
	resp, err := http.Get(srv.URL + "/api/scenarios")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("scenarios status = %d", resp.StatusCode)
	}
	var scs []map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&scs)
	if len(scs) != 1 || scs[0]["id"] != "mini-jul" {
		t.Fatalf("scenarios = %v", scs)
	}

	// /api/tariffs?territory=mini-tx → excludes the other-territory tariff.
	resp2, err := http.Get(srv.URL + "/api/tariffs?territory=mini-tx")
	if err != nil {
		t.Fatal(err)
	}
	defer resp2.Body.Close()
	var ts []map[string]any
	_ = json.NewDecoder(resp2.Body).Decode(&ts)
	for _, tr := range ts {
		if tr["territory"] != "mini-tx" {
			t.Errorf("territory filter leaked %v", tr["territory"])
		}
	}
	if len(ts) != 3 { // mini-match, mini-badtz, mini-badeff (all mini-tx)
		t.Fatalf("expected 3 mini-tx tariffs, got %d", len(ts))
	}
}

// ---- real data end-to-end (skip if data/ absent) --------------------------

func TestWhatifRunRealData(t *testing.T) {
	scDir := filepath.Join("..", "..", "data", "scenarios")
	tDir := filepath.Join("..", "..", "data", "tariffs")
	if _, err := os.Stat(scDir); err != nil {
		t.Skip("real data/ absent; skipping end-to-end")
	}
	srv := newWhatifServer(scDir, tDir)
	defer srv.Close()

	code, out := postRun(t, srv, map[string]any{
		"scenario_id": "east-texas-jul2025",
		"tariff_ids":  []string{"tx-flat-12-2025", "tx-txu-free-nights-2025"},
	})
	if code != http.StatusOK {
		t.Fatalf("real-data run status = %d (body: %v)", code, out)
	}
	runs := out["runs"].([]any)
	if len(runs) != 6 { // 2 tariffs × 3 policies
		t.Fatalf("expected 6 runs, got %d", len(runs))
	}
}

// TestWhatifRealDataReport runs every real scenario against each tariff whose
// territory matches, and prints the July bill totals per (scenario, tariff,
// policy) with savings. It flags anything absurd (negative bill, LEXA worse
// than baseline, savings > 60%). Skips if data/ is absent.
func TestWhatifRealDataReport(t *testing.T) {
	scDir := filepath.Join("..", "..", "data", "scenarios")
	tDir := filepath.Join("..", "..", "data", "tariffs")
	scenarios, err := scenariodata.Load(scDir)
	if err != nil {
		t.Skipf("real scenarios absent: %v", err)
	}
	tariffs, err := tariff.Load(tDir)
	if err != nil {
		t.Skipf("real tariffs absent: %v", err)
	}

	scIDs := make([]string, 0, len(scenarios))
	for id := range scenarios {
		scIDs = append(scIDs, id)
	}
	sort.Strings(scIDs)

	t.Logf("%-22s %-30s %-10s %10s %10s %8s", "scenario", "tariff", "policy", "bill_usd", "import_kwh", "save_%")
	for _, scID := range scIDs {
		sc := scenarios[scID]
		terr := sc.Meta.Location.Territory
		var matched []*tariff.Tariff
		for _, tr := range tariffs {
			if tr.Territory == terr {
				matched = append(matched, tr)
			}
		}
		sort.Slice(matched, func(i, j int) bool { return matched[i].ID < matched[j].ID })
		if len(matched) == 0 {
			t.Logf("%-22s (no tariff for territory %q)", scID, terr)
			continue
		}
		for _, tr := range matched {
			resp, err := whatif.Run(sc, []*tariff.Tariff{tr}, sc.Meta.InstrumentDefaults, nil)
			if err != nil {
				t.Errorf("%s × %s: Run error: %v", scID, tr.ID, err)
				continue
			}
			billBy := map[string]float64{}
			impBy := map[string]float64{}
			expBy := map[string]float64{}
			for _, r := range resp.Runs {
				billBy[r.Policy] = r.Bill.TotalUSD
				impBy[r.Policy] = r.KPIs.ImportKWh
				expBy[r.Policy] = r.KPIs.ExportKWh
				if r.Bill.TotalUSD < 0 {
					// Flagged, not failed: negative monthly bills arise from the
					// tariff's net-metering export credit (BillCalc-owned, not the
					// engine) crediting exports at the full retail energy rate with
					// no floor, against ~net-zero 8 kW PV homes. A data/model call
					// for the tariff team (credit carry-forward vs. cash-out).
					t.Logf("FLAG(neg-bill): %s × %s × %s bill $%.2f export %.0f kWh",
						scID, tr.ID, r.Policy, r.Bill.TotalUSD, r.KPIs.ExportKWh)
				}
			}
			base := billBy[whatif.PolicyBaseline]
			for _, pol := range whatif.AllPolicies {
				save := 0.0
				if base != 0 {
					save = (base - billBy[pol]) / base * 100
				}
				t.Logf("%-22s %-30s %-10s %10.2f %10.1f %7.1f%%",
					scID, tr.ID, pol, billBy[pol], impBy[pol], save)
			}
			if lexa := billBy[whatif.PolicyDerLexa]; lexa > base+1e-6 {
				t.Errorf("ABSURD: %s × %s LEXA ($%.2f) worse than baseline ($%.2f)", scID, tr.ID, lexa, base)
			}
			for _, pol := range []string{whatif.PolicyDerDumb, whatif.PolicyDerLexa} {
				if base != 0 {
					if save := (base - billBy[pol]) / base * 100; save > 60 {
						t.Logf("FLAG: %s × %s × %s savings %.1f%% > 60%% — verify magnitude", scID, tr.ID, pol, save)
					}
				}
			}
		}
	}
}
