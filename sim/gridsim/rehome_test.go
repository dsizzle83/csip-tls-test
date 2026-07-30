package gridsim

// rehome_test.go covers the CORE-009/CORE-014 re-home lever: RehomeDER moves a
// DER's DERCapability/DERSettings hrefs, the OLD hrefs stop answering (GET and
// PUT alike), the NEW hrefs are what the DERList advertises and what a PUT is
// accepted against, and the move is deterministic across calls.

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// derCapPutBody / derSetPutBody are minimal well-formed 2030.5 bodies for the
// two resources RehomeDER moves.
const derCapPutBody = `<DERCapability xmlns="urn:ieee:std:2030.5:ns"><type>80</type>` +
	`<rtgMaxW><multiplier>0</multiplier><value>9000</value></rtgMaxW></DERCapability>`
const derSetPutBody = `<DERSettings xmlns="urn:ieee:std:2030.5:ns"><setMaxW><multiplier>0</multiplier>` +
	`<value>9000</value></setMaxW></DERSettings>`

// TestRehomeDER_MovesHrefsAndOldOnesStop404 is the deliverable's core claim:
// after RehomeDER, a GET of either OLD href 404s and a GET of either NEW href
// serves the resource, carrying the new href in its own body too.
func TestRehomeDER_MovesHrefsAndOldOnesStop404(t *testing.T) {
	s := NewServer("")

	oldCap, oldSet := "/edev/2/der/0/dercap", "/edev/2/der/0/derset"
	if rec := serveHTTP(t, s, http.MethodGet, oldCap, ""); rec.Code != http.StatusOK {
		t.Fatalf("baseline GET %s = %d, want 200", oldCap, rec.Code)
	}

	newCap, newSet, err := s.RehomeDER(2, 0)
	if err != nil {
		t.Fatalf("RehomeDER: %v", err)
	}
	if newCap == oldCap || newSet == oldSet {
		t.Fatalf("RehomeDER did not change the hrefs: cap=%s set=%s", newCap, newSet)
	}

	// The OLD hrefs are gone: GET 404s for both.
	for _, p := range []string{oldCap, oldSet} {
		rec := serveHTTP(t, s, http.MethodGet, p, "")
		if rec.Code != http.StatusNotFound {
			t.Errorf("GET the OLD href %s = %d, want 404 (server should no longer serve it)", p, rec.Code)
		}
	}

	// The NEW hrefs serve the resource, and each payload carries its OWN new
	// href — a client that reads <href> out of the body itself, not only the
	// DERList's link, must see the same new path there too.
	rec := serveHTTP(t, s, http.MethodGet, newCap, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET the NEW DERCapability href %s = %d, want 200", newCap, rec.Code)
	}
	if !bytes.Contains(rec.Body.Bytes(), []byte(`href="`+newCap+`"`)) {
		t.Errorf("DERCapability body does not carry its own new href %s: %s", newCap, rec.Body.String())
	}
	rec = serveHTTP(t, s, http.MethodGet, newSet, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET the NEW DERSettings href %s = %d, want 200", newSet, rec.Code)
	}
	if !bytes.Contains(rec.Body.Bytes(), []byte(`href="`+newSet+`"`)) {
		t.Errorf("DERSettings body does not carry its own new href %s: %s", newSet, rec.Body.String())
	}
}

// TestRehomeDER_DERListAdvertisesTheNewHrefs is the half of the deliverable
// that matters most: a discovery walk reads the DER's links from the
// DERList, and after a re-home that list must point at the NEW hrefs, not
// the old ones — that is what makes the DUT's NEXT walk notice the change at
// all.
func TestRehomeDER_DERListAdvertisesTheNewHrefs(t *testing.T) {
	s := NewServer("")
	newCap, newSet, err := s.RehomeDER(2, 0)
	if err != nil {
		t.Fatalf("RehomeDER: %v", err)
	}

	rec := serveHTTP(t, s, http.MethodGet, "/edev/2/der", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /edev/2/der = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, newCap) {
		t.Errorf("DERList does not advertise the new DERCapabilityLink %s: %s", newCap, body)
	}
	if !strings.Contains(body, newSet) {
		t.Errorf("DERList does not advertise the new DERSettingsLink %s: %s", newSet, body)
	}
	if strings.Contains(body, "/edev/2/der/0/dercap\"") || strings.Contains(body, "/edev/2/der/0/derset\"") {
		t.Errorf("DERList still advertises an ORIGINAL href after re-homing: %s", body)
	}
}

// TestRehomeDER_PUTAcceptedAtNewHrefRejectedAtOld proves the two halves of
// "gridsim MUST accept PUTs at the new hrefs" and "old hrefs 404": a DUT that
// discovered the new hrefs can report there, and a DUT (or a stale test) that
// still tries the vacated address gets the same "not here" answer a GET
// would.
func TestRehomeDER_PUTAcceptedAtNewHrefRejectedAtOld(t *testing.T) {
	s := NewServer("")
	oldCap, oldSet := "/edev/2/der/0/dercap", "/edev/2/der/0/derset"
	newCap, newSet, err := s.RehomeDER(2, 0)
	if err != nil {
		t.Fatalf("RehomeDER: %v", err)
	}

	if rec := serveHTTP(t, s, http.MethodPut, newCap, derCapPutBody); rec.Code != http.StatusNoContent {
		t.Errorf("PUT the NEW DERCapability href %s = %d, want 204", newCap, rec.Code)
	}
	if rec := serveHTTP(t, s, http.MethodPut, newSet, derSetPutBody); rec.Code != http.StatusNoContent {
		t.Errorf("PUT the NEW DERSettings href %s = %d, want 204", newSet, rec.Code)
	}
	puts := s.ReceivedDERPuts()
	if _, ok := puts[newCap]; !ok {
		t.Errorf("the PUT to the new DERCapability href was not recorded: %+v", puts)
	}
	if _, ok := puts[newSet]; !ok {
		t.Errorf("the PUT to the new DERSettings href was not recorded: %+v", puts)
	}

	// The OLD hrefs are vacated: a PUT there 404s exactly as a GET would,
	// rather than silently accepting a report at an address the tree no
	// longer names.
	if rec := serveHTTP(t, s, http.MethodPut, oldCap, derCapPutBody); rec.Code != http.StatusNotFound {
		t.Errorf("PUT the OLD DERCapability href %s = %d, want 404", oldCap, rec.Code)
	}
	if rec := serveHTTP(t, s, http.MethodPut, oldSet, derSetPutBody); rec.Code != http.StatusNotFound {
		t.Errorf("PUT the OLD DERSettings href %s = %d, want 404", oldSet, rec.Code)
	}
}

// TestRehomeDER_IsDeterministicAndRepeatable proves the "deterministic"
// requirement: the generation counter advances by exactly one per call
// (reproducible from the call count alone), a second re-home moves the
// resource AGAIN (away from the first re-home's hrefs, not back to the
// original), and two freshly built servers driven through the same call
// sequence land on byte-identical hrefs.
func TestRehomeDER_IsDeterministicAndRepeatable(t *testing.T) {
	s1 := NewServer("")
	cap1, set1, err := s1.RehomeDER(2, 0)
	if err != nil {
		t.Fatalf("RehomeDER (1st, server 1): %v", err)
	}
	cap2, set2, err := s1.RehomeDER(2, 0)
	if err != nil {
		t.Fatalf("RehomeDER (2nd, server 1): %v", err)
	}
	if cap1 == cap2 || set1 == set2 {
		t.Fatalf("a second re-home did not move the resource again: %s / %s", cap2, set2)
	}

	// A second, independently built server driven through the identical call
	// sequence reaches the identical hrefs — the naming scheme is a pure
	// function of the call count, not of wall-clock time or any other
	// process-external state.
	s2 := NewServer("")
	cap1b, set1b, err := s2.RehomeDER(2, 0)
	if err != nil {
		t.Fatalf("RehomeDER (1st, server 2): %v", err)
	}
	cap2b, set2b, err := s2.RehomeDER(2, 0)
	if err != nil {
		t.Fatalf("RehomeDER (2nd, server 2): %v", err)
	}
	if cap1 != cap1b || set1 != set1b {
		t.Errorf("first re-home is not reproducible: server1=%s/%s server2=%s/%s", cap1, set1, cap1b, set1b)
	}
	if cap2 != cap2b || set2 != set2b {
		t.Errorf("second re-home is not reproducible: server1=%s/%s server2=%s/%s", cap2, set2, cap2b, set2b)
	}
}

// TestRehomeDER_UnknownDERIsAnErrorNotAPanic guards the caller-argument path:
// an out-of-range DER index or a nonexistent EndDevice's DERList is a plain
// error naming the mistake, never a panic or a silent no-op.
func TestRehomeDER_UnknownDERIsAnErrorNotAPanic(t *testing.T) {
	s := NewServer("")
	if _, _, err := s.RehomeDER(2, 5); err == nil {
		t.Error("RehomeDER(2, 5): want an error, DERList /edev/2/der serves only DER[0]")
	}
	if _, _, err := s.RehomeDER(9, 0); err == nil {
		t.Error("RehomeDER(9, 0): want an error, there is no DERList at /edev/9/der")
	}
}

// TestAdminRehome_PostRehomesTheDUTsOwnDER covers the admin HTTP surface: the
// endpoint every CORE-009/CORE-014 check actually calls through Driver.
func TestAdminRehome_PostRehomesTheDUTsOwnDER(t *testing.T) {
	s := NewServer("")
	srv := httptest.NewServer(s.AdminHandler())
	defer srv.Close()

	rec := httptest.NewRecorder()
	s.AdminHandler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/admin/rehome", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET /admin/rehome = %d, want 405", rec.Code)
	}

	resp, err := http.Post(srv.URL+"/admin/rehome", "application/json", nil)
	if err != nil {
		t.Fatalf("POST /admin/rehome: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST /admin/rehome = %d, want 200", resp.StatusCode)
	}
	var out struct {
		DERCapabilityHref string `json:"der_capability_href"`
		DERSettingsHref   string `json:"der_settings_href"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if out.DERCapabilityHref == "" || out.DERSettingsHref == "" {
		t.Fatalf("POST /admin/rehome returned an empty href: %+v", out)
	}
	if out.DERCapabilityHref == "/edev/2/der/0/dercap" || out.DERSettingsHref == "/edev/2/der/0/derset" {
		t.Errorf("POST /admin/rehome did not move the resource: %+v", out)
	}

	// The endpoint's own effect is visible through the ordinary CSIP surface:
	// the new href it returned now serves the resource.
	rec2 := serveHTTP(t, s, http.MethodGet, out.DERCapabilityHref, "")
	if rec2.Code != http.StatusOK {
		t.Errorf("GET the href /admin/rehome returned (%s) = %d, want 200", out.DERCapabilityHref, rec2.Code)
	}
}
