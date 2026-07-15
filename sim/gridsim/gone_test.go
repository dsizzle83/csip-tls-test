package gridsim

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestGone_ArmedPathReturns410AndCounts(t *testing.T) {
	s := &Server{}
	s.SetGone("/derp/0/derc", 2) // two 410s, then it heals

	// First two GETs of the armed path answer 410.
	for i := 0; i < 2; i++ {
		w := httptest.NewRecorder()
		if !s.goneIntercept(w, "/derp/0/derc") {
			t.Fatalf("hit %d: armed gone did not intercept", i)
		}
		if w.Code != http.StatusGone {
			t.Errorf("hit %d: got %d, want 410", i, w.Code)
		}
	}
	// Third GET heals — serves normally.
	if s.goneIntercept(httptest.NewRecorder(), "/derp/0/derc") {
		t.Error("gone did not heal after its count was exhausted")
	}
}

func TestGone_UnmatchedPathServesNormally(t *testing.T) {
	s := &Server{}
	s.SetGone("/dcap", -1)
	if s.goneIntercept(httptest.NewRecorder(), "/tm") {
		t.Error("gone fired on a non-armed path")
	}
	// The armed path still 410s (and, being unlimited, keeps 410ing).
	for i := 0; i < 5; i++ {
		if !s.goneIntercept(httptest.NewRecorder(), "/dcap") {
			t.Fatalf("unlimited gone stopped firing at hit %d", i)
		}
	}
}

func TestGone_ClearDisarms(t *testing.T) {
	s := &Server{}
	s.SetGone("/dcap", -1)
	s.SetGone("", 0) // disarm
	if s.goneIntercept(httptest.NewRecorder(), "/dcap") {
		t.Error("cleared gone still intercepting")
	}
}

func TestGone_AdminEndpointArmsAndClears(t *testing.T) {
	s := NewServer("")
	h := s.AdminHandler()

	arm := func(body string) {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest("POST", "/admin/gone", bytes.NewReader([]byte(body))))
		if rec.Code != http.StatusNoContent {
			t.Fatalf("POST /admin/gone %s = %d, want 204", body, rec.Code)
		}
	}

	arm(`{"path":"/derp/0/derc","count":-1}`)
	// A GET of the armed resource over the CSIP handler now 410s.
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/derp/0/derc", nil))
	if rec.Code != http.StatusGone {
		t.Fatalf("GET /derp/0/derc after arm = %d, want 410", rec.Code)
	}

	arm(`{"clear":true}`)
	rec = httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/derp/0/derc", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /derp/0/derc after clear = %d, want 200", rec.Code)
	}
}
