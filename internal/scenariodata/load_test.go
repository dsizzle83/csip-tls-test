package scenariodata

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// readFixture loads the small synthetic scenario/weather pair under
// testdata/good/ as generic maps so table-driven cases below can mutate
// individual fields before writing them out to a fresh temp dir.
func readFixture(t *testing.T) (meta, weather map[string]any) {
	t.Helper()
	mb, err := os.ReadFile(filepath.Join("testdata", "good", "scenario.json"))
	if err != nil {
		t.Fatalf("read fixture scenario.json: %v", err)
	}
	if err := json.Unmarshal(mb, &meta); err != nil {
		t.Fatalf("unmarshal fixture scenario.json: %v", err)
	}
	wb, err := os.ReadFile(filepath.Join("testdata", "good", "weather.json"))
	if err != nil {
		t.Fatalf("read fixture weather.json: %v", err)
	}
	if err := json.Unmarshal(wb, &weather); err != nil {
		t.Fatalf("unmarshal fixture weather.json: %v", err)
	}
	return meta, weather
}

// writeScenario marshals meta/weather back to JSON and writes them under
// root/dirName/{scenario.json,weather.json}, mimicking a data/scenarios/<id>/
// pair.
func writeScenario(t *testing.T, root, dirName string, meta, weather map[string]any) {
	t.Helper()
	dir := filepath.Join(root, dirName)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", dir, err)
	}
	mb, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		t.Fatalf("marshal meta: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "scenario.json"), mb, 0o644); err != nil {
		t.Fatalf("write scenario.json: %v", err)
	}
	wb, err := json.MarshalIndent(weather, "", "  ")
	if err != nil {
		t.Fatalf("marshal weather: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "weather.json"), wb, 0o644); err != nil {
		t.Fatalf("write weather.json: %v", err)
	}
}

func TestLoad_TableDriven(t *testing.T) {
	cases := []struct {
		name          string
		dirName       string // defaults to the fixture's id ("test-scenario") if empty
		mutate        func(meta, weather map[string]any)
		wantErrSubstr string // empty => expect success
	}{
		{
			name: "valid fixture loads cleanly",
		},
		{
			name:          "id does not match directory name",
			dirName:       "some-other-dir",
			wantErrSubstr: "does not match directory name",
		},
		{
			name: "array length mismatch",
			mutate: func(_, w map[string]any) {
				arr := w["ghi_wm2"].([]any)
				w["ghi_wm2"] = arr[:len(arr)-1]
			},
			wantErrSubstr: "array length mismatch",
		},
		{
			name: "null value in temp_c",
			mutate: func(_, w map[string]any) {
				arr := w["temp_c"].([]any)
				arr[5] = nil
			},
			wantErrSubstr: "null value in temp_c",
		},
		{
			name: "null value in ghi_wm2",
			mutate: func(_, w map[string]any) {
				arr := w["ghi_wm2"].([]any)
				arr[7] = nil
			},
			wantErrSubstr: "null value in ghi_wm2",
		},
		{
			name: "non-contiguous hours",
			mutate: func(_, w map[string]any) {
				hrs := w["hours"].([]any)
				hrs[10] = "2099-01-01T00:00" // well-formed but breaks the +1h sequence
			},
			wantErrSubstr: "non-contiguous",
		},
		{
			name: "malformed hour string",
			mutate: func(_, w map[string]any) {
				hrs := w["hours"].([]any)
				hrs[3] = "not-a-timestamp"
			},
			wantErrSubstr: "unparseable hour",
		},
		{
			name: "hour count short of period",
			mutate: func(_, w map[string]any) {
				for _, key := range []string{"hours", "ghi_wm2", "temp_c"} {
					arr := w[key].([]any)
					w[key] = arr[:len(arr)-1]
				}
			},
			wantErrSubstr: "expected 48 hours",
		},
		{
			name: "unparseable location timezone",
			mutate: func(m, _ map[string]any) {
				loc := m["location"].(map[string]any)
				loc["timezone"] = "Not/AZone"
			},
			wantErrSubstr: "location.timezone",
		},
		{
			name: "weather timezone disagrees with scenario location",
			mutate: func(_, w map[string]any) {
				w["timezone"] = "America/Chicago"
			},
			wantErrSubstr: "does not match scenario.json",
		},
		{
			name: "period end before period start",
			mutate: func(m, _ map[string]any) {
				p := m["period"].(map[string]any)
				p["start"] = "2025-01-05"
				p["end"] = "2025-01-01"
			},
			wantErrSubstr: "before period.start",
		},
		{
			name:    "empty id",
			dirName: "empty-id-dir", // must be set explicitly: mutate empties meta["id"],
			// which the default dirName fallback below reads from
			mutate: func(m, _ map[string]any) {
				m["id"] = ""
			},
			wantErrSubstr: "id is empty",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			meta, weather := readFixture(t)
			if tc.mutate != nil {
				tc.mutate(meta, weather)
			}
			dirName := tc.dirName
			if dirName == "" {
				dirName = meta["id"].(string)
			}

			root := t.TempDir()
			writeScenario(t, root, dirName, meta, weather)

			got, err := Load(root)
			if tc.wantErrSubstr == "" {
				if err != nil {
					t.Fatalf("Load: unexpected error: %v", err)
				}
				sc, ok := got["test-scenario"]
				if !ok {
					t.Fatalf("Load: missing expected scenario id in result: %v", keysOf(got))
				}
				if sc.Meta.Label != "Test Scenario" {
					t.Errorf("Meta.Label = %q, want %q", sc.Meta.Label, "Test Scenario")
				}
				if len(sc.Weather.Hours) != 48 || len(sc.Weather.TempC) != 48 || len(sc.Weather.GHIWm2) != 48 {
					t.Errorf("got %d/%d/%d hours/temp/ghi, want 48/48/48",
						len(sc.Weather.Hours), len(sc.Weather.TempC), len(sc.Weather.GHIWm2))
				}
				if sc.Weather.Hours[0] != "2025-01-01T00:00" {
					t.Errorf("Weather.Hours[0] = %q, want 2025-01-01T00:00", sc.Weather.Hours[0])
				}
				return
			}

			if err == nil {
				t.Fatalf("Load: expected error containing %q, got success: %v", tc.wantErrSubstr, keysOf(got))
			}
			if !strings.Contains(err.Error(), tc.wantErrSubstr) {
				t.Fatalf("Load error = %q, want substring %q", err.Error(), tc.wantErrSubstr)
			}
		})
	}
}

// TestLoad_SkipsNonDirEntries ensures a stray file sitting next to the
// scenario subdirectories (e.g. a README) doesn't break Load.
func TestLoad_SkipsNonDirEntries(t *testing.T) {
	meta, weather := readFixture(t)
	root := t.TempDir()
	writeScenario(t, root, meta["id"].(string), meta, weather)

	if err := os.WriteFile(filepath.Join(root, "README.md"), []byte("not a scenario\n"), 0o644); err != nil {
		t.Fatalf("write stray file: %v", err)
	}
	if err := os.Mkdir(filepath.Join(root, ".hidden"), 0o755); err != nil {
		t.Fatalf("mkdir hidden: %v", err)
	}

	got, err := Load(root)
	if err != nil {
		t.Fatalf("Load: unexpected error: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("Load: got %d scenarios, want 1: %v", len(got), keysOf(got))
	}
}

func TestLoad_MissingWeatherFile(t *testing.T) {
	meta, _ := readFixture(t)
	root := t.TempDir()
	dir := filepath.Join(root, meta["id"].(string))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	mb, _ := json.MarshalIndent(meta, "", "  ")
	if err := os.WriteFile(filepath.Join(dir, "scenario.json"), mb, 0o644); err != nil {
		t.Fatalf("write scenario.json: %v", err)
	}
	// weather.json intentionally absent.

	if _, err := Load(root); err == nil {
		t.Fatal("Load: expected error for missing weather.json, got nil")
	}
}

func TestLoad_NonexistentDir(t *testing.T) {
	if _, err := Load(filepath.Join(t.TempDir(), "does-not-exist")); err == nil {
		t.Fatal("Load: expected error for nonexistent dir, got nil")
	}
}

// TestLoad_RealData loads the actual data/scenarios dataset checked into the
// repo (produced by scripts/fetch-scenario-data.py) and sanity-checks the
// three July 2025 scenarios. Skipped when the dataset hasn't been fetched
// (e.g. a fresh checkout, or an environment without network access at
// fetch time) — this test intentionally does not fetch anything itself.
func TestLoad_RealData(t *testing.T) {
	dir := filepath.Join("..", "..", "data", "scenarios")
	if _, err := os.Stat(dir); err != nil {
		t.Skipf("real data/scenarios dir not present (%v) — run scripts/fetch-scenario-data.py --all first", err)
	}

	scenarios, err := Load(dir)
	if err != nil {
		t.Fatalf("Load(%s): %v", dir, err)
	}

	wantIDs := []string{"east-texas-jul2025", "los-angeles-jul2025", "haverhill-jul2025"}
	for _, id := range wantIDs {
		sc, ok := scenarios[id]
		if !ok {
			t.Errorf("missing expected scenario id %q (got %v)", id, keysOf(scenarios))
			continue
		}
		if len(sc.Weather.Hours) != 744 {
			t.Errorf("%s: got %d hours, want 744 (31 days x 24h)", id, len(sc.Weather.Hours))
		}
		if sc.Meta.Period.Start != "2025-07-01" || sc.Meta.Period.End != "2025-07-31" {
			t.Errorf("%s: period = %s..%s, want 2025-07-01..2025-07-31",
				id, sc.Meta.Period.Start, sc.Meta.Period.End)
		}
	}
}

func keysOf(m map[string]*Scenario) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	return ks
}
