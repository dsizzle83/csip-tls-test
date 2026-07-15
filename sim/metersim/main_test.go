package main

import (
	"encoding/json"
	"math"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TASK-014 (W7, AD-008): metersim's linked-mode EV term reads the hub's
// /status via -hub-api; once lexa-api requires a bearer token, metersim must
// present it (and must not send a bogus header when no token is configured —
// the staged-rollout default, matching an unauthenticated hub).

func hubStatusServer(t *testing.T, wantAuth string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != wantAuth {
			t.Errorf("Authorization header = %q, want %q", got, wantAuth)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"evse_stations": []map[string]any{
				{"power_W": 1500.0},
				{"power_W": 2500.0},
			},
		})
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestFetchHubEVW_PresentsTokenWhenConfigured(t *testing.T) {
	srv := hubStatusServer(t, "Bearer sekrit")
	got := fetchHubEVW(srv.URL, "sekrit")
	if got != 4000 {
		t.Errorf("fetchHubEVW = %v, want 4000 (sum of EVSE power_W)", got)
	}
}

func TestFetchHubEVW_NoTokenSendsNoHeader(t *testing.T) {
	srv := hubStatusServer(t, "")
	got := fetchHubEVW(srv.URL, "")
	if got != 4000 {
		t.Errorf("fetchHubEVW = %v, want 4000", got)
	}
}

// The diurnal residential baseload must (a) average the configured mean over a
// full local day, (b) be evening-peaked and non-flat, (c) disable at avg<=0,
// (d) be overridable by a fixed pin, and (e) be deterministic. Its shape mirrors
// the hub's diurnalLoadForecast so the meter's live load tracks the hub's plan.

func TestResidentialLoadW_MeanMatchesAverage(t *testing.T) {
	const avgW = 2000.0
	// Sample every 5 min across a full local day (288 steps, the hub's
	// resolution); the mean must equal avgW.
	base := time.Date(2026, 7, 15, 0, 0, 0, 0, time.Local)
	const n = 288
	sum := 0.0
	for i := 0; i < n; i++ {
		sum += residentialLoadW(base.Add(time.Duration(i)*5*time.Minute), avgW)
	}
	if mean := sum / n; math.Abs(mean-avgW) > 1e-3 {
		t.Errorf("24h mean = %.6f W, want %.1f W", mean, avgW)
	}
}

func TestResidentialLoadW_EveningPeakedNonFlat(t *testing.T) {
	const avgW = 2000.0
	day := time.Date(2026, 7, 15, 0, 0, 0, 0, time.Local)
	at := func(h int) float64 { return residentialLoadW(day.Add(time.Duration(h)*time.Hour), avgW) }
	overnight := at(3)
	evening := at(19) // near the 19.5 evening peak
	if overnight <= 0 {
		t.Errorf("overnight base load must be positive, got %.0f W", overnight)
	}
	if evening < overnight*1.5 {
		t.Errorf("curve too flat: overnight=%.0f W evening=%.0f W (want a real evening peak)", overnight, evening)
	}
}

func TestResidentialLoadW_ZeroAvgDisables(t *testing.T) {
	if got := residentialLoadW(time.Now(), 0); got != 0 {
		t.Errorf("avgW<=0 must yield 0 (curve disabled), got %v", got)
	}
}

func TestCurrentLoadW_PinOverridesCurve(t *testing.T) {
	pin := 3500.0
	if got := currentLoadW(time.Now(), &pin, 2000); got != pin {
		t.Errorf("pinned load = %v W, want %v W", got, pin)
	}
	// A nil pin falls through to the diurnal curve (non-zero at a 2 kW mean).
	if got := currentLoadW(time.Now(), nil, 2000); got <= 0 {
		t.Errorf("unpinned diurnal load = %v W, want > 0", got)
	}
}

func TestResidentialLoadW_Deterministic(t *testing.T) {
	ts := time.Date(2026, 7, 15, 19, 30, 0, 0, time.Local)
	if a, b := residentialLoadW(ts, 2000), residentialLoadW(ts, 2000); a != b {
		t.Errorf("non-deterministic: %v != %v", a, b)
	}
}
