package gridsim

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
)

// armRedirect POSTs /admin/redirect and asserts 204.
func armRedirect(t *testing.T, s *Server, body string) {
	t.Helper()
	rec := httptest.NewRecorder()
	s.AdminHandler().ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/admin/redirect", bytes.NewReader([]byte(body))))
	if rec.Code != http.StatusNoContent {
		t.Fatalf("POST /admin/redirect = %d, want 204; body: %s", rec.Code, rec.Body)
	}
}

// Default off: GET /dcap serves 200 until the redirect mode is armed.
func TestRedirect_DefaultOff(t *testing.T) {
	s := NewServer("")
	if rec := serveHTTP(t, s, http.MethodGet, "/dcap", ""); rec.Code != http.StatusOK {
		t.Fatalf("GET /dcap (unarmed) = %d, want 200", rec.Code)
	}
}

// Armed for N GETs: the first N answer 302 + Location, then the path serves
// 200 again — the "first N GETs redirect" behaviour ERR-001 needs.
func TestRedirect_FirstNThenServes(t *testing.T) {
	s := NewServer("")
	armRedirect(t, s, `{"path":"/dcap","code":302,"count":2}`)

	for i := 0; i < 2; i++ {
		rec := serveHTTP(t, s, http.MethodGet, "/dcap", "")
		if rec.Code != http.StatusFound {
			t.Fatalf("redirect %d: GET /dcap = %d, want 302", i, rec.Code)
		}
		if loc := rec.Header().Get("Location"); loc != "/dcap" {
			t.Errorf("redirect %d: Location = %q, want /dcap (self)", i, loc)
		}
	}
	// N exhausted → normal 200.
	if rec := serveHTTP(t, s, http.MethodGet, "/dcap", ""); rec.Code != http.StatusOK {
		t.Errorf("after N redirects: GET /dcap = %d, want 200", rec.Code)
	}
}

// A configured Location and 301 code are honoured, and only the configured
// path is redirected (a different path serves normally).
func TestRedirect_LocationCodeAndPathScope(t *testing.T) {
	s := NewServer("")
	armRedirect(t, s, `{"path":"/dcap","location":"/dcap-moved","code":301,"count":1}`)

	rec := serveHTTP(t, s, http.MethodGet, "/dcap", "")
	if rec.Code != http.StatusMovedPermanently {
		t.Fatalf("GET /dcap = %d, want 301", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "/dcap-moved" {
		t.Errorf("Location = %q, want /dcap-moved", loc)
	}
	// A different path is untouched even while armed.
	if rec := serveHTTP(t, s, http.MethodGet, "/tm", ""); rec.Code != http.StatusOK {
		t.Errorf("GET /tm while armed = %d, want 200", rec.Code)
	}
}

// clear disarms; a bad code is rejected.
func TestRedirect_ClearAndBadCode(t *testing.T) {
	s := NewServer("")
	armRedirect(t, s, `{"path":"/dcap","count":5}`)
	armRedirect(t, s, `{"clear":true}`)
	if rec := serveHTTP(t, s, http.MethodGet, "/dcap", ""); rec.Code != http.StatusOK {
		t.Errorf("after clear: GET /dcap = %d, want 200", rec.Code)
	}

	rec := httptest.NewRecorder()
	s.AdminHandler().ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/admin/redirect",
		bytes.NewReader([]byte(`{"path":"/dcap","code":307,"count":1}`))))
	if rec.Code != http.StatusBadRequest {
		t.Errorf("bad code 307 = %d, want 400", rec.Code)
	}
}
