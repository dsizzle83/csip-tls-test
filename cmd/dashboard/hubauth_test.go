package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

// TASK-014 (W7, AD-008): the dashboard presents lexa-api's bearer token only
// on the "hub" backend. These tests pin loadHubToken's staged-rollout
// tolerance and setHubAuth's scoping — the two properties the task's common
// mistakes list calls out explicitly (don't leak the token to every sim;
// don't refuse to start when the token isn't distributed yet).

func withHubToken(t *testing.T, tok string) {
	t.Helper()
	old := hubToken
	hubToken = tok
	t.Cleanup(func() { hubToken = old })
}

func TestSetHubAuth_OnlyHubGetsTheHeader(t *testing.T) {
	withHubToken(t, "s3cret-token")

	for _, name := range []string{"gridsim", "solar", "battery", "meter", "ev", "mqttproxy", "grid"} {
		req, _ := http.NewRequest(http.MethodGet, "http://example.invalid/x", nil)
		setHubAuth(req, name)
		if got := req.Header.Get("Authorization"); got != "" {
			t.Errorf("backend %q got Authorization header %q, want none (token must be scoped to hub only)", name, got)
		}
	}

	req, _ := http.NewRequest(http.MethodGet, "http://example.invalid/x", nil)
	setHubAuth(req, "hub")
	if got, want := req.Header.Get("Authorization"), "Bearer s3cret-token"; got != want {
		t.Errorf("hub backend Authorization = %q, want %q", got, want)
	}
}

func TestSetHubAuth_EmptyTokenSetsNoHeaderEvenForHub(t *testing.T) {
	withHubToken(t, "")
	req, _ := http.NewRequest(http.MethodGet, "http://example.invalid/x", nil)
	setHubAuth(req, "hub")
	if got := req.Header.Get("Authorization"); got != "" {
		t.Errorf("empty hubToken: got Authorization header %q, want none (staged rollout: no token configured yet)", got)
	}
}

func TestLoadHubToken_EmptyPathIsNoop(t *testing.T) {
	tok, err := loadHubToken("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tok != "" {
		t.Fatalf("got %q, want empty (no -hub-token-file given)", tok)
	}
}

func TestLoadHubToken_ReadsAndTrims(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "hub-api.token")
	if err := os.WriteFile(path, []byte("  abc123\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	tok, err := loadHubToken(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tok != "abc123" {
		t.Fatalf("got %q, want %q", tok, "abc123")
	}
}

// A configured-but-missing token file returns an error to the caller (so
// main.go can log it), but main.go treats it as non-fatal — the dashboard
// must keep serving against a hub that hasn't been given a token to
// distribute yet (staged rollout). This test only pins loadHubToken's own
// contract: it surfaces the error rather than silently swallowing it.
func TestLoadHubToken_MissingFileReturnsError(t *testing.T) {
	if _, err := loadHubToken(filepath.Join(t.TempDir(), "nope.token")); err == nil {
		t.Fatal("expected an error for a missing token file, got nil")
	}
}

// authRecordingServer records the Authorization header seen on each request,
// keyed by request path, and returns "{}" for every GET so getJSON succeeds.
func authRecordingServer(t *testing.T) (*httptest.Server, map[string]string) {
	t.Helper()
	seen := make(map[string]string)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen[r.URL.Path] = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte("{}"))
	}))
	t.Cleanup(srv.Close)
	return srv, seen
}

// End-to-end proof (not just the isolated setHubAuth func) that the two
// driver types' shared HTTP helpers present the token for the "hub" backend
// name and nowhere else — this is the exact property TASK-014's "common
// mistakes" list warns about (leaking the token to every sim backend).
func TestMayhemDriver_GetJSONAndPost_TokenScopedToHub(t *testing.T) {
	withHubToken(t, "mayhem-tok")
	srv, seen := authRecordingServer(t)

	d := newMayhemDriver(map[string]string{"hub": srv.URL, "gridsim": srv.URL})

	var out map[string]any
	if err := d.getJSON("hub", "/status", &out); err != nil {
		t.Fatalf("getJSON hub: %v", err)
	}
	if err := d.getJSON("gridsim", "/admin/alerts", &out); err != nil {
		t.Fatalf("getJSON gridsim: %v", err)
	}
	if err := d.post("hub", "/status-post", map[string]any{}); err != nil {
		t.Fatalf("post hub: %v", err)
	}
	if err := d.post("gridsim", "/admin/control-post", map[string]any{}); err != nil {
		t.Fatalf("post gridsim: %v", err)
	}

	if got, want := seen["/status"], "Bearer mayhem-tok"; got != want {
		t.Errorf("hub getJSON Authorization = %q, want %q", got, want)
	}
	if got := seen["/admin/alerts"]; got != "" {
		t.Errorf("gridsim getJSON Authorization = %q, want none", got)
	}
	if got, want := seen["/status-post"], "Bearer mayhem-tok"; got != want {
		t.Errorf("hub post Authorization = %q, want %q", got, want)
	}
	if got := seen["/admin/control-post"]; got != "" {
		t.Errorf("gridsim post Authorization = %q, want none", got)
	}
}

func TestReplayDriver_GetJSONAndPost_TokenScopedToHub(t *testing.T) {
	withHubToken(t, "replay-tok")
	srv, seen := authRecordingServer(t)

	d := newReplayDriver(map[string]string{"hub": srv.URL, "gridsim": srv.URL})

	var out map[string]any
	if err := d.getJSON("hub", "/status", &out); err != nil {
		t.Fatalf("getJSON hub: %v", err)
	}
	if err := d.getJSON("gridsim", "/admin/alerts", &out); err != nil {
		t.Fatalf("getJSON gridsim: %v", err)
	}
	if err := d.post("hub", "/status-post", map[string]any{}); err != nil {
		t.Fatalf("post hub: %v", err)
	}
	if err := d.post("gridsim", "/admin/control-post", map[string]any{}); err != nil {
		t.Fatalf("post gridsim: %v", err)
	}

	if got, want := seen["/status"], "Bearer replay-tok"; got != want {
		t.Errorf("hub getJSON Authorization = %q, want %q", got, want)
	}
	if got := seen["/admin/alerts"]; got != "" {
		t.Errorf("gridsim getJSON Authorization = %q, want none", got)
	}
	if got, want := seen["/status-post"], "Bearer replay-tok"; got != want {
		t.Errorf("hub post Authorization = %q, want %q", got, want)
	}
	if got := seen["/admin/control-post"]; got != "" {
		t.Errorf("gridsim post Authorization = %q, want none", got)
	}
}

// The reverse-proxy mount for "/api/hub/" must inject the token; other
// mounts (built with plain stripProxy) must not. This exercises
// stripHubAuthProxy's Director end to end.
func TestStripHubAuthProxy_InjectsToken(t *testing.T) {
	withHubToken(t, "proxy-tok")
	srv, seen := authRecordingServer(t)

	hubProxy := stripHubAuthProxy("/api/hub", srv.URL)
	req := httptest.NewRequest(http.MethodGet, "/api/hub/status", nil)
	rec := httptest.NewRecorder()
	hubProxy.ServeHTTP(rec, req)
	if got, want := seen["/status"], "Bearer proxy-tok"; got != want {
		t.Errorf("hub proxy Authorization = %q, want %q", got, want)
	}

	// A plain stripProxy mount (what every non-hub target uses) must never
	// see the header, even with a token configured.
	delete(seen, "/status")
	plainProxy := stripProxy("/api/gridsim", srv.URL)
	req2 := httptest.NewRequest(http.MethodGet, "/api/gridsim/status", nil)
	rec2 := httptest.NewRecorder()
	plainProxy.ServeHTTP(rec2, req2)
	if got := seen["/status"]; got != "" {
		t.Errorf("plain (gridsim) proxy Authorization = %q, want none", got)
	}
}
