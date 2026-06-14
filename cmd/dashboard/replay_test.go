package main

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

func TestReplayRate_MatchesHubTOUModel(t *testing.T) {
	cases := []struct {
		hour float64
		want float64
	}{
		{0, rateOff}, {6.75, rateOff}, {7, ratePartial}, {15.75, ratePartial},
		{16, ratePeak}, {20.75, ratePeak}, {21, rateOff}, {23.75, rateOff},
	}
	for _, c := range cases {
		if got := replayRate(c.hour); got != c.want {
			t.Errorf("replayRate(%v) = %v, want %v", c.hour, got, c.want)
		}
	}
}

// fakeBench serves just enough of the meter and hub APIs for sampleTick.
func fakeBench(t *testing.T, meterW, solarW float64) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/state", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `{"measurements":{"W_W":%g}}`, meterW)
	})
	mux.HandleFunc("/status", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `{"power":{"solar_W":%g,"battery_W":0},"devices":{},"evse_stations":[],"last_plan":{"decisions":[]}}`, solarW)
	})
	return httptest.NewServer(mux)
}

// fakeBenchFull also serves battery/EV power and SOC in the hub /status payload.
func fakeBenchFull(t *testing.T, meterW, solarW, batteryW, batSOC, evSOC float64) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/state", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `{"measurements":{"W_W":%g}}`, meterW)
	})
	mux.HandleFunc("/status", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `{"power":{"solar_W":%g,"battery_W":%g},`+
			`"devices":{"bat":{"role":"battery","soc_pct":%g}},`+
			`"evse_stations":[{"power_W":7000,"soc_pct":%g}],`+
			`"last_plan":{"decisions":[]}}`, solarW, batteryW, batSOC, evSOC)
	})
	return httptest.NewServer(mux)
}

func TestSampleTick_CostAndCompliance(t *testing.T) {
	srv := fakeBench(t, 2000, 0) // importing 2 kW
	defer srv.Close()
	d := newReplayDriver(map[string]string{"meter": srv.URL, "hub": srv.URL})
	d.status.TotalTicks = 96
	d.status.TickMs = 1000

	// Peak-hour import over a 1.5 kW import cap → cost at peak rate + violation.
	d.sampleTick(68, 17.0, "6/1 17:00", &activeCap{typ: "importCap", limW: 1500}, tickEnv{})

	m := d.status.Measured
	wantCost := 2.0 * replayDTHours * ratePeak // 2 kW × 0.25 h × $0.38
	if math.Abs(m.CostUSD-wantCost) > 1e-9 {
		t.Errorf("CostUSD = %v, want %v", m.CostUSD, wantCost)
	}
	if m.PeakImpKWh != 0.5 || m.ImportKWh != 0.5 {
		t.Errorf("ImportKWh/PeakImpKWh = %v/%v, want 0.5/0.5", m.ImportKWh, m.PeakImpKWh)
	}
	if m.ConsTicks != 1 || m.Violations != 1 {
		t.Errorf("ConsTicks/Violations = %d/%d, want 1/1", m.ConsTicks, m.Violations)
	}

	// Off-peak import within the cap (tolerance applies) → no new violation.
	d.sampleTick(8, 2.0, "6/1 02:00", &activeCap{typ: "importCap", limW: 1900}, tickEnv{})
	if m := d.status.Measured; m.Violations != 1 || m.ConsTicks != 2 {
		t.Errorf("after tolerant tick: ConsTicks/Violations = %d/%d, want 2/1", m.ConsTicks, m.Violations)
	}
	if d.status.Measured.Compliance != 50 {
		t.Errorf("Compliance = %v, want 50", d.status.Measured.Compliance)
	}
}

func TestSampleTick_ExportCreditAndGenLimit(t *testing.T) {
	srv := fakeBench(t, -3000, 6000) // exporting 3 kW, solar at 6 kW
	defer srv.Close()
	d := newReplayDriver(map[string]string{"meter": srv.URL, "hub": srv.URL})
	d.status.TotalTicks = 96
	d.status.TickMs = 1000

	d.sampleTick(48, 12.0, "6/1 12:00", &activeCap{typ: "exportCap", limW: 2000}, tickEnv{})
	m := d.status.Measured
	if math.Abs(m.CreditUSD-3.0*replayDTHours*exportCredit) > 1e-9 {
		t.Errorf("CreditUSD = %v", m.CreditUSD)
	}
	if m.Violations != 1 {
		t.Errorf("export over cap should violate; Violations = %d", m.Violations)
	}

	// genLimit judged against solar output, not grid flow.
	d.sampleTick(49, 12.25, "6/1 12:15", &activeCap{typ: "genLimit", limW: 4000}, tickEnv{})
	if d.status.Measured.Violations != 2 {
		t.Errorf("solar 6 kW over 4 kW genLimit should violate; Violations = %d", d.status.Measured.Violations)
	}
}

func TestTickLog_WritesPerDERRow(t *testing.T) {
	// Hub reports 3 kW solar (curtailed from a 5 kW potential), 1 kW battery
	// discharge; meter shows 2 kW import.
	srv := fakeBenchFull(t, 2000, 3000, 1000, 47.5, 62.0)
	defer srv.Close()

	dir := t.TempDir()
	d := newReplayDriver(map[string]string{"meter": srv.URL, "hub": srv.URL})
	d.checkpointPath = dir + "/cp.json"
	d.status.TotalTicks = 96
	d.status.TickMs = 1000

	// Open the log in the temp dir so the test doesn't litter the repo.
	cwd, _ := os.Getwd()
	defer os.Chdir(cwd)
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	d.openTickLog()

	env := tickEnv{possibleSolarW: 5000, siteLoadW: 4000, evConnected: true}
	d.sampleTick(48, 12.0, "6/1 12:00", &activeCap{typ: "genLimit", limW: 4000}, env)
	d.closeTickLog()

	f, err := os.Open(dir + "/" + d.status.TickLogPath)
	if err != nil {
		t.Fatalf("tick log not written: %v", err)
	}
	defer f.Close()
	rows, err := csv.NewReader(f).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 {
		t.Fatalf("want header + 1 data row, got %d rows", len(rows))
	}
	if len(rows[0]) != len(tickLogHeader) {
		t.Fatalf("header has %d cols, want %d", len(rows[0]), len(tickLogHeader))
	}
	got := map[string]string{}
	for i, h := range tickLogHeader {
		got[h] = rows[1][i]
	}
	checks := map[string]string{
		"solar_kW":               "3.000",
		"solar_possible_kW":      "5.000",
		"solar_curtailed_kW":     "2.000", // 5 − 3 kW clipped by the hub
		"battery_kW(+dis/-chg)":  "1.000",
		"ev_connected":           "1",
		"net_grid_kW(+imp/-exp)": "2.000",
		"site_load_kW":           "4.000",
	}
	for col, want := range checks {
		if got[col] != want {
			t.Errorf("col %q = %q, want %q", col, got[col], want)
		}
	}
}

func TestHandleStart_RejectsBadEnv(t *testing.T) {
	d := newReplayDriver(map[string]string{})
	body, _ := json.Marshal(replayStartReq{
		Seed: 1, TickMs: 8000,
		Env: replayEnvData{Pv: make([]float64, 96), Load: make([]float64, 95)}, // mismatched
	})
	req := httptest.NewRequest("POST", "/api/replay/start", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	d.handleStart(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("mismatched env: got %d, want 400", rec.Code)
	}
}
