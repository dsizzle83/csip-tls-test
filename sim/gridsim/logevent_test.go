package gridsim

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	model "lexa-proto/csipmodel"
)

// logEventXML builds a well-formed CSIP LogEvent body.
func logEventXML(code uint8, id uint16) string {
	return fmt.Sprintf(`<LogEvent xmlns="urn:ieee:std:2030.5:ns">`+
		`<createdDateTime>1000</createdDateTime><functionSet>11</functionSet>`+
		`<logEventCode>%d</logEventCode><logEventID>%d</logEventID>`+
		`<logEventPEN>37244</logEventPEN><profileID>2</profileID></LogEvent>`, code, id)
}

// The EndDevice must advertise LogEventListLink so the client discovers where
// to POST DER alarms (WP-6 / BASIC-027).
func TestLogEvent_EndDeviceAdvertisesLink(t *testing.T) {
	s := NewServer("")
	rec := serveHTTP(t, s, http.MethodGet, "/edev", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /edev = %d", rec.Code)
	}
	if !bytes.Contains(rec.Body.Bytes(), []byte("/edev/2/lev")) {
		t.Errorf("EndDeviceList missing LogEventListLink: %s", rec.Body)
	}
	// The list resource itself is served.
	if rec := serveHTTP(t, s, http.MethodGet, "/edev/2/lev", ""); rec.Code != http.StatusOK {
		t.Errorf("GET /edev/2/lev = %d, want 200", rec.Code)
	}
}

// POST LogEvent → 201 + Location, kept in a time-ordered, inspectable list; a
// subsequent GET of the list reflects the count.
func TestLogEvent_PostCreatesAndLists(t *testing.T) {
	s := NewServer("")

	rec := serveHTTP(t, s, http.MethodPost, "/edev/2/lev", logEventXML(1, 10))
	if rec.Code != http.StatusCreated {
		t.Fatalf("POST /edev/2/lev = %d, want 201; body: %s", rec.Code, rec.Body)
	}
	if loc := rec.Header().Get("Location"); loc != "/edev/2/lev/0" {
		t.Errorf("Location = %q, want /edev/2/lev/0", loc)
	}
	// Second event → next id and preserved order.
	rec = serveHTTP(t, s, http.MethodPost, "/edev/2/lev", logEventXML(2, 11))
	if rec.Code != http.StatusCreated {
		t.Fatalf("second POST = %d", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "/edev/2/lev/1" {
		t.Errorf("second Location = %q, want /edev/2/lev/1", loc)
	}

	events := s.ReceivedLogEvents()
	if len(events) != 2 {
		t.Fatalf("ReceivedLogEvents = %d, want 2", len(events))
	}
	if events[0].LogEventCode != 1 || events[1].LogEventCode != 2 {
		t.Errorf("events out of order: %d then %d", events[0].LogEventCode, events[1].LogEventCode)
	}

	// GET the list — All/Results reflect the two POSTs.
	rec = serveHTTP(t, s, http.MethodGet, "/edev/2/lev", "")
	var lel model.LogEventList
	if err := xml.Unmarshal(rec.Body.Bytes(), &lel); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	if lel.All != 2 || len(lel.LogEvent) != 2 {
		t.Errorf("LogEventList all=%d len=%d, want 2/2", lel.All, len(lel.LogEvent))
	}

	// The individual event is retrievable at its Location.
	if rec := serveHTTP(t, s, http.MethodGet, "/edev/2/lev/0", ""); rec.Code != http.StatusOK {
		t.Errorf("GET /edev/2/lev/0 = %d, want 200", rec.Code)
	}
}

// A malformed LogEvent body is 400 and not recorded.
func TestLogEvent_RejectsGarbage(t *testing.T) {
	s := NewServer("")
	rec := serveHTTP(t, s, http.MethodPost, "/edev/2/lev", `not xml`)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("garbage POST = %d, want 400", rec.Code)
	}
	if len(s.ReceivedLogEvents()) != 0 {
		t.Errorf("garbage must not be recorded")
	}
}

// GET /admin/logevents surfaces the list for the dashboard/bench.
func TestAdminLogEvents_Surfaces(t *testing.T) {
	s := NewServer("")
	if rec := serveHTTP(t, s, http.MethodPost, "/edev/2/lev", logEventXML(7, 99)); rec.Code != http.StatusCreated {
		t.Fatalf("POST = %d", rec.Code)
	}
	rec := httptest.NewRecorder()
	s.AdminHandler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/admin/logevents", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /admin/logevents = %d, want 200", rec.Code)
	}
	var out struct {
		LogEvents []model.LogEvent `json:"log_events"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(out.LogEvents) != 1 || out.LogEvents[0].LogEventCode != 7 {
		t.Errorf("/admin/logevents = %+v, want one event code=7", out.LogEvents)
	}
}
