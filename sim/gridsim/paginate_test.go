package gridsim

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	model "lexa-proto/csipmodel"
)

// getList issues a GET through the main handler and unmarshals a DERProgramList.
func getProgList(t *testing.T, h http.Handler, path string) *model.DERProgramList {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", path, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET %s: status %d, want 200", path, rec.Code)
	}
	var l model.DERProgramList
	if err := xml.Unmarshal(rec.Body.Bytes(), &l); err != nil {
		t.Fatalf("GET %s: unmarshal: %v", path, err)
	}
	return &l
}

// TestPaginate_ArmedListPagesWithHonestAll proves an armed list serves one page
// per s/l with all=<full> and results=<page>, and that walking the pages
// reassembles every entry exactly once.
func TestPaginate_ArmedListPagesWithHonestAll(t *testing.T) {
	s := NewServer("")
	h := s.Handler()
	const derp = "/edev/2/fsa/0/derp" // the default tree has 3 programs here

	whole := getProgList(t, h, derp)
	if len(whole.DERProgram) != 3 {
		t.Fatalf("precondition: default program list has %d entries, want 3", len(whole.DERProgram))
	}

	s.SetPaginate(1, derp) // one program per page, scoped to this list

	seen := map[string]bool{}
	var pages int
	for start := 0; ; start += 1 {
		l := getProgList(t, h, fmt.Sprintf("%s?s=%d&l=1", derp, start))
		if l.All != 3 {
			t.Errorf("page at s=%d: all=%d, want the honest full count 3", start, l.All)
		}
		if len(l.DERProgram) == 0 {
			break
		}
		if l.Results != uint32(len(l.DERProgram)) {
			t.Errorf("page at s=%d: results=%d but carried %d entries", start, l.Results, len(l.DERProgram))
		}
		if len(l.DERProgram) > 1 {
			t.Errorf("page at s=%d: served %d entries, want at most page_size=1", start, len(l.DERProgram))
		}
		for _, p := range l.DERProgram {
			if seen[p.Href] {
				t.Errorf("duplicate program %s across pages", p.Href)
			}
			seen[p.Href] = true
		}
		pages++
		if pages > 10 {
			t.Fatal("pagination did not terminate")
		}
	}
	if len(seen) != 3 {
		t.Errorf("assembled %d distinct programs across pages, want all 3", len(seen))
	}
	if pages < 3 {
		t.Errorf("served %d non-empty pages for 3 entries at page_size 1 — not actually paginating", pages)
	}
}

// TestPaginate_Disarmed serves the whole list (historical behaviour).
func TestPaginate_Disarmed(t *testing.T) {
	s := NewServer("")
	h := s.Handler()
	// Not armed: s/l are ignored, full list served.
	l := getProgList(t, h, "/edev/2/fsa/0/derp?s=0&l=1")
	if len(l.DERProgram) != 3 || l.Results != 3 {
		t.Errorf("disarmed: served %d entries (results=%d), want the whole list of 3", len(l.DERProgram), l.Results)
	}
}

// TestPaginate_PathFilterScopesToOneList proves an armed path filter pages only
// that list and leaves every other list whole.
func TestPaginate_PathFilterScopesToOneList(t *testing.T) {
	s := NewServer("")
	h := s.Handler()
	s.SetPaginate(1, "/derp/0/derc") // page ONLY the program-0 control list

	// The program list (a different path) is untouched — still whole.
	if l := getProgList(t, h, "/edev/2/fsa/0/derp?s=0&l=1"); len(l.DERProgram) != 3 {
		t.Errorf("path-scoped pagination leaked onto /derp: served %d, want 3", len(l.DERProgram))
	}

	// The scoped control list pages: page 0 (s=0) carries 1 of 4 controls.
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/derp/0/derc?s=0&l=1", nil))
	var cl model.DERControlList
	if err := xml.Unmarshal(rec.Body.Bytes(), &cl); err != nil {
		t.Fatalf("unmarshal /derp/0/derc: %v", err)
	}
	if cl.All != 4 || cl.Results != 1 || len(cl.DERControl) != 1 {
		t.Errorf("scoped control page: all=%d results=%d entries=%d, want 4/1/1", cl.All, cl.Results, len(cl.DERControl))
	}
}

// TestPaginate_AdminArmsAndClears exercises the /admin/paginate endpoint.
func TestPaginate_AdminArmsAndClears(t *testing.T) {
	s := NewServer("")
	h := s.AdminHandler()
	main := s.Handler()

	post := func(body string) {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest("POST", "/admin/paginate", bytes.NewReader([]byte(body))))
		if rec.Code != http.StatusNoContent {
			t.Fatalf("POST /admin/paginate %s: status %d", body, rec.Code)
		}
	}

	post(`{"page_size":2,"path":"/edev/2/fsa/0/derp"}`)
	if l := getProgList(t, main, "/edev/2/fsa/0/derp?s=0&l=5"); len(l.DERProgram) != 2 {
		t.Errorf("armed page_size 2: served %d, want 2 (server caps the client's l=5)", len(l.DERProgram))
	}
	post(`{"clear":true}`)
	if l := getProgList(t, main, "/edev/2/fsa/0/derp?s=0&l=5"); len(l.DERProgram) != 3 {
		t.Errorf("after clear: served %d, want the whole list of 3", len(l.DERProgram))
	}
}

// TestPaginate_NonListPassesThrough proves a non-list resource is never sliced.
func TestPaginate_NonListPassesThrough(t *testing.T) {
	s := NewServer("")
	h := s.Handler()
	s.SetPaginate(1, "") // all lists

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/tm?s=0&l=1", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /tm: status %d", rec.Code)
	}
	var tm model.Time
	if err := xml.Unmarshal(rec.Body.Bytes(), &tm); err != nil {
		t.Fatalf("GET /tm under global pagination should still serve a valid Time: %v", err)
	}
}
