package gridsim

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// serveHTTP drives one request through the mTLS resource handler (s.Handler())
// and returns the recorder.
func serveHTTP(t *testing.T, s *Server, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, bytes.NewReader([]byte(body)))
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	return rec
}

// A well-formed DER* report PUT to each of the four DER sub-resource hrefs must
// be accepted (204) and stored for inspection (WP-4 / CORE-009 PUT half).
func TestDERPut_AcceptsAndStoresAllFour(t *testing.T) {
	s := NewServer("")

	cases := []struct {
		path string
		root string
		body string
	}{
		{"/edev/2/der/0/dercap", "DERCapability",
			`<DERCapability xmlns="urn:ieee:std:2030.5:ns"><type>80</type><rtgMaxW><multiplier>0</multiplier><value>9000</value></rtgMaxW></DERCapability>`},
		{"/edev/2/der/0/derset", "DERSettings",
			`<DERSettings xmlns="urn:ieee:std:2030.5:ns"><setMaxW><multiplier>0</multiplier><value>9000</value></setMaxW></DERSettings>`},
		{"/edev/2/der/0/derstat", "DERStatus",
			`<DERStatus xmlns="urn:ieee:std:2030.5:ns"><readingTime>1</readingTime></DERStatus>`},
		{"/edev/2/der/0/deravail", "DERAvailability",
			`<DERAvailability xmlns="urn:ieee:std:2030.5:ns"><readingTime>1</readingTime></DERAvailability>`},
	}

	for _, c := range cases {
		rec := serveHTTP(t, s, http.MethodPut, c.path, c.body)
		if rec.Code != http.StatusNoContent {
			t.Fatalf("PUT %s = %d, want 204; body: %s", c.path, rec.Code, rec.Body)
		}
	}

	puts := s.ReceivedDERPuts()
	if len(puts) != 4 {
		t.Fatalf("stored %d DER PUTs, want 4", len(puts))
	}
	for _, c := range cases {
		p, ok := puts[c.path]
		if !ok {
			t.Fatalf("no stored PUT for %s", c.path)
		}
		if p.Resource != c.root {
			t.Errorf("%s: stored resource = %q, want %q", c.path, p.Resource, c.root)
		}
		if p.Body != c.body {
			t.Errorf("%s: stored body not verbatim", c.path)
		}
	}
}

// The last body per resource wins (a re-PUT overwrites).
func TestDERPut_LastBodyWins(t *testing.T) {
	s := NewServer("")
	path := "/edev/2/der/0/derstat"
	first := `<DERStatus xmlns="urn:ieee:std:2030.5:ns"><readingTime>1</readingTime></DERStatus>`
	second := `<DERStatus xmlns="urn:ieee:std:2030.5:ns"><readingTime>2</readingTime></DERStatus>`

	if rec := serveHTTP(t, s, http.MethodPut, path, first); rec.Code != http.StatusNoContent {
		t.Fatalf("first PUT = %d", rec.Code)
	}
	if rec := serveHTTP(t, s, http.MethodPut, path, second); rec.Code != http.StatusNoContent {
		t.Fatalf("second PUT = %d", rec.Code)
	}
	if got := s.ReceivedDERPuts()[path].Body; got != second {
		t.Errorf("stored body = %q, want the second PUT", got)
	}
}

// Garbage and mis-namespaced bodies are 400 and are NOT stored.
func TestDERPut_RejectsGarbageAndBadNamespace(t *testing.T) {
	s := NewServer("")
	path := "/edev/2/der/0/dercap"

	bad := []struct {
		name string
		body string
	}{
		{"not xml", `this is not xml at all`},
		{"truncated", `<DERCapability xmlns="urn:ieee:std:2030.5:ns"><type>80`},
		{"missing xmlns", `<DERCapability><type>80</type><rtgMaxW><value>1</value></rtgMaxW></DERCapability>`},
		{"wrong namespace", `<DERCapability xmlns="urn:example:wrong"><type>80</type></DERCapability>`},
	}
	for _, b := range bad {
		rec := serveHTTP(t, s, http.MethodPut, path, b.body)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%s: PUT = %d, want 400", b.name, rec.Code)
		}
	}
	if len(s.ReceivedDERPuts()) != 0 {
		t.Errorf("rejected PUTs must not be stored, got %d", len(s.ReceivedDERPuts()))
	}
}

// A DERStatus body PUT to the dercap href is 400 (wrong root element for the
// target), and a PUT to a non-DER path is 405.
func TestDERPut_WrongRootAndNonDERPath(t *testing.T) {
	s := NewServer("")

	rec := serveHTTP(t, s, http.MethodPut, "/edev/2/der/0/dercap",
		`<DERStatus xmlns="urn:ieee:std:2030.5:ns"><readingTime>1</readingTime></DERStatus>`)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("mismatched root PUT = %d, want 400", rec.Code)
	}

	rec = serveHTTP(t, s, http.MethodPut, "/dcap",
		`<DERStatus xmlns="urn:ieee:std:2030.5:ns"><readingTime>1</readingTime></DERStatus>`)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("PUT /dcap = %d, want 405", rec.Code)
	}
}

// GET /admin/derputs surfaces the stored PUTs for the dashboard/bench.
func TestAdminDERPuts_SurfacesStored(t *testing.T) {
	s := NewServer("")
	path := "/edev/2/der/0/derstat"
	body := `<DERStatus xmlns="urn:ieee:std:2030.5:ns"><readingTime>42</readingTime></DERStatus>`
	if rec := serveHTTP(t, s, http.MethodPut, path, body); rec.Code != http.StatusNoContent {
		t.Fatalf("PUT = %d", rec.Code)
	}

	rec := httptest.NewRecorder()
	s.AdminHandler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/admin/derputs", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /admin/derputs = %d, want 200", rec.Code)
	}
	var out struct {
		DERPuts map[string]DERPut `json:"der_puts"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if out.DERPuts[path].Resource != "DERStatus" {
		t.Errorf("/admin/derputs missing DERStatus for %s: %+v", path, out.DERPuts)
	}
}

// The DER resource must advertise the DERAvailabilityLink so the walker
// discovers the fourth report target, and GET must serve the baseline resource.
func TestDER_ServesAvailabilityLinkAndResource(t *testing.T) {
	s := NewServer("")
	rec := serveHTTP(t, s, http.MethodGet, "/edev/2/der", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /edev/2/der = %d", rec.Code)
	}
	if !bytes.Contains(rec.Body.Bytes(), []byte("/edev/2/der/0/deravail")) {
		t.Errorf("DERList missing DERAvailabilityLink: %s", rec.Body)
	}
	if rec := serveHTTP(t, s, http.MethodGet, "/edev/2/der/0/deravail", ""); rec.Code != http.StatusOK {
		t.Errorf("GET /edev/2/der/0/deravail = %d, want 200", rec.Code)
	}
}
