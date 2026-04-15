package httpclient_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"csip-tls-test/internal/httpclient"
)

// ── Get ───────────────────────────────────────────────────────────────────────

func TestFetcher_Get_HappyPath(t *testing.T) {
	body := `<DeviceCapability xmlns="urn:ieee:std:2030.5:ns"/>`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/dcap" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/sep+xml")
		w.Write([]byte(body))
	}))
	defer srv.Close()

	f := httpclient.NewFetcher(srv.URL, nil)
	got, err := f.Get("/dcap")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if string(got) != body {
		t.Errorf("body = %q, want %q", got, body)
	}
}

func TestFetcher_Get_SendsAcceptHeader(t *testing.T) {
	var gotAccept string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAccept = r.Header.Get("Accept")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	f := httpclient.NewFetcher(srv.URL, nil)
	f.Get("/anything") //nolint — we only care about the header
	if gotAccept != "application/sep+xml" {
		t.Errorf("Accept header = %q, want application/sep+xml", gotAccept)
	}
}

func TestFetcher_Get_Non200_ReturnsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "forbidden", http.StatusForbidden)
	}))
	defer srv.Close()

	f := httpclient.NewFetcher(srv.URL, nil)
	_, err := f.Get("/restricted")
	if err == nil {
		t.Fatal("expected error for 403, got nil")
	}
	if !strings.Contains(err.Error(), "403") {
		t.Errorf("error should mention 403, got: %v", err)
	}
}

func TestFetcher_Get_404_ReturnsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer srv.Close()

	f := httpclient.NewFetcher(srv.URL, nil)
	_, err := f.Get("/nonexistent")
	if err == nil {
		t.Fatal("expected error for 404, got nil")
	}
}

func TestFetcher_Get_ServerDown_ReturnsError(t *testing.T) {
	f := httpclient.NewFetcher("http://127.0.0.1:1", nil)
	_, err := f.Get("/dcap")
	if err == nil {
		t.Fatal("expected connection error, got nil")
	}
}

// ── Post ──────────────────────────────────────────────────────────────────────

func TestFetcher_Post_201_Created(t *testing.T) {
	const location = "/mup/42"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Location", location)
		w.WriteHeader(http.StatusCreated)
	}))
	defer srv.Close()

	f := httpclient.NewFetcher(srv.URL, nil)
	_, loc, err := f.Post("/mup", []byte("<MirrorUsagePoint/>"), "application/sep+xml")
	if err != nil {
		t.Fatalf("Post: %v", err)
	}
	if loc != location {
		t.Errorf("Location = %q, want %q", loc, location)
	}
}

func TestFetcher_Post_204_NoContent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	f := httpclient.NewFetcher(srv.URL, nil)
	body, loc, err := f.Post("/mup/42", []byte("<MirrorMeterReading/>"), "application/sep+xml")
	if err != nil {
		t.Fatalf("Post: %v", err)
	}
	if len(body) != 0 {
		t.Errorf("expected empty body for 204, got %q", body)
	}
	if loc != "" {
		t.Errorf("expected empty Location for 204, got %q", loc)
	}
}

func TestFetcher_Post_SendsContentType(t *testing.T) {
	var gotCT string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotCT = r.Header.Get("Content-Type")
		w.WriteHeader(http.StatusCreated)
	}))
	defer srv.Close()

	f := httpclient.NewFetcher(srv.URL, nil)
	f.Post("/mup", []byte("payload"), "application/sep+xml")
	if gotCT != "application/sep+xml" {
		t.Errorf("Content-Type = %q, want application/sep+xml", gotCT)
	}
}

func TestFetcher_Post_SendsBody(t *testing.T) {
	var gotBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buf := make([]byte, 512)
		n, _ := r.Body.Read(buf)
		gotBody = buf[:n]
		w.WriteHeader(http.StatusCreated)
	}))
	defer srv.Close()

	payload := []byte("<MirrorUsagePoint>data</MirrorUsagePoint>")
	f := httpclient.NewFetcher(srv.URL, nil)
	f.Post("/mup", payload, "application/sep+xml")
	if string(gotBody) != string(payload) {
		t.Errorf("body sent = %q, want %q", gotBody, payload)
	}
}

func TestFetcher_Post_Non201_ReturnsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "conflict", http.StatusConflict)
	}))
	defer srv.Close()

	f := httpclient.NewFetcher(srv.URL, nil)
	_, _, err := f.Post("/mup", nil, "application/sep+xml")
	if err == nil {
		t.Fatal("expected error for 409, got nil")
	}
	if !strings.Contains(err.Error(), "409") {
		t.Errorf("error should mention 409, got: %v", err)
	}
}

func TestFetcher_Post_ServerDown_ReturnsError(t *testing.T) {
	f := httpclient.NewFetcher("http://127.0.0.1:1", nil)
	_, _, err := f.Post("/mup", nil, "application/sep+xml")
	if err == nil {
		t.Fatal("expected connection error, got nil")
	}
}

// ── NewFetcher with nil client uses default ───────────────────────────────────

func TestFetcher_NilClient_UsesDefault(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	// Should not panic.
	f := httpclient.NewFetcher(srv.URL, nil)
	_, err := f.Get("/")
	if err != nil {
		t.Fatalf("unexpected error with nil client: %v", err)
	}
}
