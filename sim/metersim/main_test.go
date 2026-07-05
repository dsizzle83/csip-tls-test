package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
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
