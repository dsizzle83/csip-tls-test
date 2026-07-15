package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
)

func newTestServer(t *testing.T) (*Server, *httptest.Server) {
	t.Helper()
	s := New("http://vtn.test")
	ts := httptest.NewServer(s.Handler())
	t.Cleanup(ts.Close)
	return s, ts
}

func doJSON(t *testing.T, client *http.Client, method, url string, body any) *http.Response {
	t.Helper()
	var rdr *bytes.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal body: %v", err)
		}
		rdr = bytes.NewReader(b)
	} else {
		rdr = bytes.NewReader(nil)
	}
	req, err := http.NewRequest(method, url, rdr)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, url, err)
	}
	return resp
}

// ── /admin/programs + GET /programs ─────────────────────────────────────────

func TestPrograms_AdminSeedThenList(t *testing.T) {
	_, ts := newTestServer(t)
	client := ts.Client()

	resp := doJSON(t, client, http.MethodPost, ts.URL+"/admin/programs", Program{ID: "prog-1", ProgramName: "CP Tariff"})
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("POST /admin/programs status = %d, want 204", resp.StatusCode)
	}
	resp.Body.Close()

	resp = doJSON(t, client, http.MethodGet, ts.URL+"/programs", nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /programs status = %d, want 200", resp.StatusCode)
	}
	var got []Program
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(got) != 1 || got[0].ID != "prog-1" {
		t.Fatalf("GET /programs = %+v, want one program prog-1", got)
	}
}

func TestPrograms_AdminMissingIDRejected(t *testing.T) {
	_, ts := newTestServer(t)
	client := ts.Client()
	resp := doJSON(t, client, http.MethodPost, ts.URL+"/admin/programs", Program{ProgramName: "no id"})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 for a program with no id", resp.StatusCode)
	}
}

func TestPrograms_AdminDelete(t *testing.T) {
	_, ts := newTestServer(t)
	client := ts.Client()
	doJSON(t, client, http.MethodPost, ts.URL+"/admin/programs", Program{ID: "p1"}).Body.Close()
	doJSON(t, client, http.MethodDelete, ts.URL+"/admin/programs", map[string]string{"id": "p1"}).Body.Close()

	resp := doJSON(t, client, http.MethodGet, ts.URL+"/programs", nil)
	defer resp.Body.Close()
	var got []Program
	json.NewDecoder(resp.Body).Decode(&got)
	if len(got) != 0 {
		t.Fatalf("programs after delete = %+v, want empty", got)
	}
}

// ── /events filtering + pagination ──────────────────────────────────────────

func TestEvents_FilteredByProgramID(t *testing.T) {
	_, ts := newTestServer(t)
	client := ts.Client()
	doJSON(t, client, http.MethodPost, ts.URL+"/admin/events", Event{ID: "e1", ProgramID: "progA"}).Body.Close()
	doJSON(t, client, http.MethodPost, ts.URL+"/admin/events", Event{ID: "e2", ProgramID: "progB"}).Body.Close()

	resp := doJSON(t, client, http.MethodGet, ts.URL+"/events?programID=progA", nil)
	defer resp.Body.Close()
	var got []Event
	json.NewDecoder(resp.Body).Decode(&got)
	if len(got) != 1 || got[0].ID != "e1" {
		t.Fatalf("events filtered by programID=progA = %+v, want just e1", got)
	}
}

func TestEvents_MissingProgramIDRejected(t *testing.T) {
	_, ts := newTestServer(t)
	client := ts.Client()
	resp := doJSON(t, client, http.MethodPost, ts.URL+"/admin/events", Event{ID: "e1"})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 for an event with no programID", resp.StatusCode)
	}
}

// TestPagination_RespectsLimit pins the exact contract
// internal/openadr/client.go's getPaged relies on: a page never exceeds
// "limit" items, so the client's own "len(items) < limit ⇒ last page" loop
// terminates. Seeds 5 programs, pages by 2.
func TestPagination_RespectsLimit(t *testing.T) {
	_, ts := newTestServer(t)
	client := ts.Client()
	for i := 0; i < 5; i++ {
		id := "p" + strconv.Itoa(i)
		doJSON(t, client, http.MethodPost, ts.URL+"/admin/programs", Program{ID: id}).Body.Close()
	}

	var all []Program
	skip := 0
	for page := 0; page < 10; page++ {
		u := ts.URL + "/programs?" + url.Values{"skip": {strconv.Itoa(skip)}, "limit": {"2"}}.Encode()
		resp := doJSON(t, client, http.MethodGet, u, nil)
		var got []Program
		json.NewDecoder(resp.Body).Decode(&got)
		resp.Body.Close()
		if len(got) > 2 {
			t.Fatalf("page returned %d items, want <= limit(2)", len(got))
		}
		all = append(all, got...)
		if len(got) < 2 {
			break
		}
		skip += 2
	}
	if len(all) != 5 {
		t.Fatalf("paged through %d programs total, want 5", len(all))
	}
}

func TestPagination_SkipBeyondEndIsEmpty(t *testing.T) {
	_, ts := newTestServer(t)
	client := ts.Client()
	doJSON(t, client, http.MethodPost, ts.URL+"/admin/programs", Program{ID: "only"}).Body.Close()

	resp := doJSON(t, client, http.MethodGet, ts.URL+"/programs?skip=50&limit=10", nil)
	defer resp.Body.Close()
	var got []Program
	json.NewDecoder(resp.Body).Decode(&got)
	if len(got) != 0 {
		t.Fatalf("skip past the end returned %+v, want empty (not an error)", got)
	}
}

// ── /vens (EnsureVen's GET-then-POST idempotency) ───────────────────────────

func TestVens_RegisterThenLookupByName(t *testing.T) {
	_, ts := newTestServer(t)
	client := ts.Client()

	resp := doJSON(t, client, http.MethodGet, ts.URL+"/vens?venName=lexa-hub", nil)
	var got []Ven
	json.NewDecoder(resp.Body).Decode(&got)
	resp.Body.Close()
	if len(got) != 0 {
		t.Fatalf("GET /vens on an empty store = %+v, want none", got)
	}

	resp = doJSON(t, client, http.MethodPost, ts.URL+"/vens", Ven{VenName: "lexa-hub"})
	var created Ven
	json.NewDecoder(resp.Body).Decode(&created)
	resp.Body.Close()
	if created.ID == "" || created.VenName != "lexa-hub" {
		t.Fatalf("POST /vens = %+v, want an assigned id and venName lexa-hub", created)
	}

	resp = doJSON(t, client, http.MethodGet, ts.URL+"/vens?venName=lexa-hub", nil)
	json.NewDecoder(resp.Body).Decode(&got)
	resp.Body.Close()
	if len(got) != 1 || got[0].ID != created.ID {
		t.Fatalf("GET /vens after registration = %+v, want the just-created ven", got)
	}
}

func TestVens_EmptyNameRejected(t *testing.T) {
	_, ts := newTestServer(t)
	client := ts.Client()
	resp := doJSON(t, client, http.MethodPost, ts.URL+"/vens", Ven{})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 for an empty venName", resp.StatusCode)
	}
}

// ── /reports ─────────────────────────────────────────────────────────────────

func TestReports_PostIsRecorded(t *testing.T) {
	s, ts := newTestServer(t)
	client := ts.Client()
	resp := doJSON(t, client, http.MethodPost, ts.URL+"/reports", Report{
		ProgramID: "progA", EventID: "e1", ClientName: "lexa-hub",
	})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("POST /reports status = %d, want 201", resp.StatusCode)
	}

	s.mu.Lock()
	n := len(s.reports)
	s.mu.Unlock()
	if n != 1 {
		t.Fatalf("recorded %d reports, want 1", n)
	}
}

// ── OAuth2 client-credentials ────────────────────────────────────────────────

func TestAuth_ServerDiscoveryPointsAtTokenEndpoint(t *testing.T) {
	_, ts := newTestServer(t)
	resp := doJSON(t, ts.Client(), http.MethodGet, ts.URL+"/auth/server", nil)
	defer resp.Body.Close()
	var out map[string]string
	json.NewDecoder(resp.Body).Decode(&out)
	if !strings.HasSuffix(out["token_url"], "/auth/token") {
		t.Fatalf("token_url = %q, want it to end in /auth/token", out["token_url"])
	}
}

func TestAuth_TokenGrantWithoutCredentialsWhenUnauthenticated(t *testing.T) {
	_, ts := newTestServer(t)
	client := ts.Client()
	form := url.Values{"grant_type": {"client_credentials"}}
	resp, err := client.PostForm(ts.URL+"/auth/token", form)
	if err != nil {
		t.Fatalf("POST /auth/token: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 for an unauthenticated VTN", resp.StatusCode)
	}
	var out struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int64  `json:"expires_in"`
	}
	json.NewDecoder(resp.Body).Decode(&out)
	if out.AccessToken == "" || out.ExpiresIn <= 0 {
		t.Fatalf("token response = %+v, want a non-empty access_token and positive expires_in", out)
	}
}

func TestAuth_RequireAuthGatesResourcesAndTokenGrantsAccess(t *testing.T) {
	_, ts := newTestServer(t)
	client := ts.Client()

	doJSON(t, client, http.MethodPost, ts.URL+"/admin/auth", map[string]any{
		"enable": true, "client_id": "ven1", "client_secret": "s3cr3t",
	}).Body.Close()

	// Unauthenticated GET /programs must now 401.
	resp := doJSON(t, client, http.MethodGet, ts.URL+"/programs", nil)
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthenticated GET /programs status = %d, want 401 once auth is required", resp.StatusCode)
	}

	// Wrong credentials must be rejected at the token endpoint.
	badForm := url.Values{"grant_type": {"client_credentials"}, "client_id": {"ven1"}, "client_secret": {"wrong"}}
	resp, err := client.PostForm(ts.URL+"/auth/token", badForm)
	if err != nil {
		t.Fatalf("POST /auth/token: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("wrong-credential token grant status = %d, want 401", resp.StatusCode)
	}

	// Correct credentials mint a token that then authorizes /programs.
	goodForm := url.Values{"grant_type": {"client_credentials"}, "client_id": {"ven1"}, "client_secret": {"s3cr3t"}}
	resp, err = client.PostForm(ts.URL+"/auth/token", goodForm)
	if err != nil {
		t.Fatalf("POST /auth/token: %v", err)
	}
	var tok struct {
		AccessToken string `json:"access_token"`
	}
	json.NewDecoder(resp.Body).Decode(&tok)
	resp.Body.Close()
	if tok.AccessToken == "" {
		t.Fatalf("expected a non-empty access_token with correct credentials")
	}

	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/programs", nil)
	req.Header.Set("Authorization", "Bearer "+tok.AccessToken)
	resp, err = client.Do(req)
	if err != nil {
		t.Fatalf("authenticated GET /programs: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("authenticated GET /programs status = %d, want 200", resp.StatusCode)
	}
}

// ── /admin/reset + /admin/state ──────────────────────────────────────────────

func TestAdminReset_ClearsProgramsEventsVensReportsNotAuth(t *testing.T) {
	_, ts := newTestServer(t)
	client := ts.Client()
	doJSON(t, client, http.MethodPost, ts.URL+"/admin/programs", Program{ID: "p1"}).Body.Close()
	doJSON(t, client, http.MethodPost, ts.URL+"/admin/events", Event{ID: "e1", ProgramID: "p1"}).Body.Close()
	doJSON(t, client, http.MethodPost, ts.URL+"/vens", Ven{VenName: "v1"}).Body.Close()
	doJSON(t, client, http.MethodPost, ts.URL+"/admin/auth", map[string]any{"enable": true}).Body.Close()

	doJSON(t, client, http.MethodPost, ts.URL+"/admin/reset", nil).Body.Close()

	resp := doJSON(t, client, http.MethodGet, ts.URL+"/admin/state", nil)
	defer resp.Body.Close()
	var st adminState
	json.NewDecoder(resp.Body).Decode(&st)
	if len(st.Programs) != 0 || len(st.Events) != 0 || len(st.Vens) != 0 || len(st.Reports) != 0 {
		t.Fatalf("state after reset = %+v, want everything cleared", st)
	}
	if !st.RequireAuth {
		t.Fatalf("admin/reset must not clear the auth posture — RequireAuth = false, want true")
	}
}

// ── method guards ────────────────────────────────────────────────────────────

func TestMethodNotAllowed(t *testing.T) {
	_, ts := newTestServer(t)
	client := ts.Client()
	resp := doJSON(t, client, http.MethodPost, ts.URL+"/programs", nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("POST /programs status = %d, want 405 (GET-only resource)", resp.StatusCode)
	}
}
