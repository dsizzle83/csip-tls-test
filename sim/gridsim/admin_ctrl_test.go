package gridsim

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	model "lexa-proto/csipmodel"
)

// postCtrl POSTs a control body to /admin/control and fails the test on a
// non-201.
func postCtrl(t *testing.T, h http.Handler, body string) {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("POST", "/admin/control", bytes.NewReader([]byte(body))))
	if rec.Code != http.StatusCreated {
		t.Fatalf("POST /admin/control %s = %d, want 201; body: %s", body, rec.Code, rec.Body)
	}
}

func derc0(t *testing.T, s *Server) *model.DERControlList {
	t.Helper()
	list, ok := s.resources["/derp/0/derc"].(*model.DERControlList)
	if !ok {
		t.Fatalf("/derp/0/derc is not a *DERControlList")
	}
	return list
}

// A server-cancel is a two-step: post a control, let the hub receive it, then
// flip its currentStatus→6 on the SAME mRID. The seam must UPDATE in place
// (one control, new status), not add a second control — otherwise the hub sees
// an already-cancelled new event and drops it silently (never posts 6).
func TestAdminControl_ExplicitMRIDUpdatesInPlace(t *testing.T) {
	s := NewServer("")
	h := s.AdminHandler()

	postCtrl(t, h, `{"program":0,"mrid":"DERC-CANCEL-ME","exp_lim_W":4000,"duration_s":300,"activate":true}`)
	if list := derc0(t, s); len(list.DERControl) != 1 || list.DERControl[0].MRID != "DERC-CANCEL-ME" {
		t.Fatalf("after first post: derc = %+v, want single DERC-CANCEL-ME", list.DERControl)
	}

	// Flip the SAME mRID to Cancelled(6).
	postCtrl(t, h, `{"program":0,"mrid":"DERC-CANCEL-ME","current_status":6,"exp_lim_W":4000,"duration_s":300}`)
	list := derc0(t, s)
	if len(list.DERControl) != 1 {
		t.Fatalf("in-place cancel added a control: derc has %d, want 1", len(list.DERControl))
	}
	if es := list.DERControl[0].EventStatus; es == nil || es.CurrentStatus != 6 {
		t.Fatalf("cancel flip: EventStatus = %+v, want CurrentStatus 6", es)
	}
}

// A within-program supersede needs two overlapping controls whose creationTime
// ordering is deterministic (later wins) and the loser marked
// potentiallySuperseded — exactly what a scenario arms to drive the hub's
// Superseded(7) emission.
func TestAdminControl_SupersedePairFields(t *testing.T) {
	s := NewServer("")
	h := s.AdminHandler()

	postCtrl(t, h, `{"program":0,"mrid":"DERC-SUP-LOSER","exp_lim_W":3000,"duration_s":300,"activate":true,"potentially_superseded":true,"creation_offset_s":-5}`)
	postCtrl(t, h, `{"program":0,"mrid":"DERC-SUP-WINNER","exp_lim_W":2500,"duration_s":300,"creation_offset_s":0}`)

	list := derc0(t, s)
	if len(list.DERControl) != 2 {
		t.Fatalf("supersede pair: derc has %d controls, want 2", len(list.DERControl))
	}
	byMRID := map[string]model.DERControl{}
	for _, c := range list.DERControl {
		byMRID[c.MRID] = c
	}
	loser, winner := byMRID["DERC-SUP-LOSER"], byMRID["DERC-SUP-WINNER"]
	if loser.EventStatus == nil || !loser.EventStatus.PotentiallySuperseded {
		t.Errorf("loser.potentiallySuperseded = false, want true")
	}
	if !(winner.CreationTime > loser.CreationTime) {
		t.Errorf("creationTime ordering: winner=%d loser=%d, want winner > loser", winner.CreationTime, loser.CreationTime)
	}
}

func TestAdminControl_RandomizeDurationServed(t *testing.T) {
	s := NewServer("")
	h := s.AdminHandler()

	postCtrl(t, h, `{"program":0,"mrid":"DERC-RAND","exp_lim_W":4000,"duration_s":240,"activate":true,"randomize_duration":-60}`)

	list := derc0(t, s)
	if len(list.DERControl) != 1 {
		t.Fatalf("derc has %d controls, want 1", len(list.DERControl))
	}
	rd := list.DERControl[0].RandomizeDuration
	if rd == nil || *rd != -60 {
		t.Fatalf("RandomizeDuration = %v, want -60", rd)
	}

	// It must also reach the wire: GET the list and confirm the element serves.
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/derp/0/derc", nil))
	if !strings.Contains(rec.Body.String(), "randomizeDuration") {
		t.Errorf("served /derp/0/derc XML has no randomizeDuration element:\n%s", rec.Body.String())
	}
}

// /admin/responses must expose EVERY Response status — including the
// server-driven Cancelled(6)/Superseded(7) acks that /admin/alerts (which is
// CannotComply-only) deliberately omits.
func TestAdminResponses_ExposesAllLifecycleAcks(t *testing.T) {
	s := NewServer("")

	feed := func(subject string, status uint8) {
		body := fmt.Sprintf(`<Response xmlns="urn:ieee:std:2030.5:ns"><endDeviceLFDI>ABCDEF</endDeviceLFDI><status>%d</status><subject>%s</subject></Response>`, status, subject)
		s.handleResponsePost(httptest.NewRecorder(),
			httptest.NewRequest("POST", "/rsps/0/r", bytes.NewReader([]byte(body))), "/rsps/0/r")
	}
	feed("DERC-SUP-LOSER", model.ResponseEventSuperseded) // 7
	feed("DERC-CANCEL-ME", model.ResponseEventCancelled)  // 6
	feed("DERC-BREACH", model.ResponseCannotComply)       // 0xF0 (an alert)

	var out struct {
		Responses []AdminResponse `json:"responses"`
	}
	rec := httptest.NewRecorder()
	s.AdminHandler().ServeHTTP(rec, httptest.NewRequest("GET", "/admin/responses", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /admin/responses = %d, want 200", rec.Code)
	}
	if err := json.NewDecoder(rec.Body).Decode(&out); err != nil {
		t.Fatalf("decode /admin/responses: %v", err)
	}

	seen := map[string]uint8{}
	for _, r := range out.Responses {
		seen[r.Subject] = r.Status
	}
	if seen["DERC-SUP-LOSER"] != 7 {
		t.Errorf("Superseded(7) not exposed: %+v", out.Responses)
	}
	if seen["DERC-CANCEL-ME"] != 6 {
		t.Errorf("Cancelled(6) not exposed: %+v", out.Responses)
	}
	if len(out.Responses) != 3 {
		t.Errorf("/admin/responses returned %d, want all 3 recorded", len(out.Responses))
	}

	// /admin/alerts stays CannotComply-only (6/7 are not alerts).
	alerts := s.ComplianceAlerts()
	if len(alerts) != 1 || alerts[0].Subject != "DERC-BREACH" {
		t.Errorf("/admin/alerts = %+v, want only the CannotComply", alerts)
	}
}
