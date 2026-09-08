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
// flip its currentStatus to Cancelled (2, IEEE Std 2030.5-2018 Annex B,
// p.159-160 — REV0907-B1: not 6, Table 27's Response status for "event
// cancelled", a different enumeration) on the SAME mRID via the "cancel"
// lever. The seam must UPDATE in place (one control, new status), not add a
// second control — otherwise the hub sees an already-cancelled new event and
// drops it silently (never posts Response 6).
//
// IW27-005: the second POST no longer re-sends exp_lim_W — a conformant
// server-cancel changes EventStatus and nothing else (IEEE Std 2030.5-2018
// §10.2.3.3 c)), and this is the DEFAULT (non-nonconformant) path, so a
// content field alongside current_status is refused by adminCtrlPost's guard.
// The control base's own persistence across the flip is covered separately by
// TestAdminControl_StatusUpdatePreservesCreationTimeAndInterval.
func TestAdminControl_ExplicitMRIDUpdatesInPlace(t *testing.T) {
	s := NewServer("")
	h := s.AdminHandler()

	postCtrl(t, h, `{"program":0,"mrid":"DERC-CANCEL-ME","exp_lim_W":4000,"duration_s":300,"activate":true}`)
	if list := derc0(t, s); len(list.DERControl) != 1 || list.DERControl[0].MRID != "DERC-CANCEL-ME" {
		t.Fatalf("after first post: derc = %+v, want single DERC-CANCEL-ME", list.DERControl)
	}

	// Flip the SAME mRID to Cancelled(2) — status only, via the cancel lever.
	postCtrl(t, h, `{"program":0,"mrid":"DERC-CANCEL-ME","cancel":true,"duration_s":300}`)
	list := derc0(t, s)
	if len(list.DERControl) != 1 {
		t.Fatalf("in-place cancel added a control: derc has %d, want 1", len(list.DERControl))
	}
	if es := list.DERControl[0].EventStatus; es == nil || es.CurrentStatus != model.EventStatusCancelled {
		t.Fatalf("cancel flip: EventStatus = %+v, want CurrentStatus %d (Cancelled)", es, model.EventStatusCancelled)
	}
	if list.DERControl[0].DERControlBase.OpModExpLimW == nil {
		t.Fatalf("cancel flip: DERControlBase = %+v, want opModExpLimW still carried through from the "+
			"ORIGINAL post (it is inherited, not re-authored — buildBase is not even reached on this path)",
			list.DERControl[0].DERControlBase)
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

// An admin-created control must carry replyTo/responseRequired so the DUT is
// actually asked for the Response lifecycle CORE-022/CORE-023 grade — before
// this, admin-created controls carried neither attribute, which made a
// spec-compliant DUT's status=2 (Event started) unobservable by
// construction (IEEE 2030.5 never has a client volunteer a Response nobody
// requested).
func TestAdminControl_ResponseRequiredDefaultsOn(t *testing.T) {
	s := NewServer("")
	h := s.AdminHandler()

	postCtrl(t, h, `{"program":0,"mrid":"DERC-RESPREQ","exp_lim_W":4000,"duration_s":300,"activate":true}`)

	list := derc0(t, s)
	if len(list.DERControl) != 1 {
		t.Fatalf("derc has %d controls, want 1", len(list.DERControl))
	}
	ctrl := list.DERControl[0]
	if ctrl.ReplyTo != "/rsps/0/r" {
		t.Errorf("ReplyTo = %q, want /rsps/0/r (gridsim's own advertised default ResponseSet)", ctrl.ReplyTo)
	}
	if ctrl.ResponseRequired == nil {
		t.Fatal("ResponseRequired is nil, want present by default")
	}
	// F7/#18: compares against the constant, not a re-typed literal, so this
	// stays correct across a bump (0x03 -> 0x07) without drifting like the
	// raw-wire "03" string below once did.
	if got := uint8(*ctrl.ResponseRequired); got != uint8(adminDefaultResponseRequired) {
		t.Errorf("ResponseRequired = %#02x, want %#02x (adminDefaultResponseRequired)",
			got, uint8(adminDefaultResponseRequired))
	}

	// It must also reach the wire: GET the list and confirm both attributes serve.
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/derp/0/derc", nil))
	body := rec.Body.String()
	if !strings.Contains(body, `replyTo="/rsps/0/r"`) {
		t.Errorf("served /derp/0/derc XML has no replyTo attribute:\n%s", body)
	}
	if !strings.Contains(body, `responseRequired="07"`) {
		t.Errorf("served /derp/0/derc XML has no responseRequired=\"07\" attribute:\n%s", body)
	}
}

// A scenario proving the DUT correctly WITHHOLDS a Response when none was
// requested needs a lever to ask gridsim for exactly that — response_required:0
// overrides the default.
//
// This is also the gridsim-side half of the audit 2026-07-31 wire-format
// regression lock (run evidence runs/final-core022-20260731T232047, mRID
// CERT-CORE022-038e3a26 carrying responseRequired=00 on the wire): an
// explicit override must reach the actual served XML as "00", not merely the
// in-memory model.DERControl, and an ABSENT override (TestAdminControl_
// ResponseRequiredDefaultsOn, above) must reach it as "03" — the two must be
// distinguishable end-to-end, not just at the adminCtrlReq struct boundary.
func TestAdminControl_ResponseRequiredOverride(t *testing.T) {
	s := NewServer("")
	h := s.AdminHandler()

	postCtrl(t, h, `{"program":0,"mrid":"DERC-RESPREQ-OFF","exp_lim_W":4000,"duration_s":300,"activate":true,"response_required":0}`)

	list := derc0(t, s)
	if len(list.DERControl) != 1 {
		t.Fatalf("derc has %d controls, want 1", len(list.DERControl))
	}
	ctrl := list.DERControl[0]
	if ctrl.ResponseRequired == nil {
		t.Fatal("ResponseRequired is nil, want present-and-zero (an explicit request for silence), not absent")
	}
	if got := uint8(*ctrl.ResponseRequired); got != 0 {
		t.Errorf("ResponseRequired = %#02x, want 0x00 (override honored)", got)
	}

	// It must also reach the wire as an explicit "00", not be silently
	// dropped (which would read, to a client, as "absent" — a different
	// wire meaning per the hexBinary8/RespondableResource semantics: absent
	// is "no server instruction", present-and-zero is "explicitly no
	// response wanted").
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/derp/0/derc", nil))
	body := rec.Body.String()
	if !strings.Contains(body, `responseRequired="00"`) {
		t.Errorf("served /derp/0/derc XML has no responseRequired=\"00\" attribute:\n%s", body)
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

// IW14 adversarial finding 4: an out-of-domain admin percent must be a 400,
// never a silent uint16/int16 wraparound onto the wire (max_lim_W:-100 would
// otherwise become 65436 — a control the operator never authored, recorded in
// the pcap as if they had). In-domain-but-over-product-range values remain
// accepted: sending 20000 (200%) to a DUT is a legitimate rejection test.
func TestAdminControl_PercentDomainRejected(t *testing.T) {
	s := NewServer("")
	h := s.AdminHandler()

	post := func(path, body string) int {
		t.Helper()
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest("POST", path, bytes.NewReader([]byte(body))))
		return rec.Code
	}

	seeded := len(derc0(t, s).DERControl) // NewServer pre-seeds baseline controls

	for _, tc := range []struct {
		name, path, body string
		want             int
	}{
		{"negative max_lim_W wraps — reject", "/admin/control", `{"program":0,"max_lim_W":-100,"duration_s":60}`, http.StatusBadRequest},
		{"max_lim_W above uint16 wraps — reject", "/admin/control", `{"program":0,"max_lim_W":100000,"duration_s":60}`, http.StatusBadRequest},
		{"fixed_W below int16 wraps — reject", "/admin/control", `{"program":0,"fixed_W":-40000,"duration_s":60}`, http.StatusBadRequest},
		{"fixed_W above int16 wraps — reject", "/admin/control", `{"program":0,"fixed_W":40000,"duration_s":60}`, http.StatusBadRequest},
		{"in-domain over product range — accepted", "/admin/control", `{"program":0,"max_lim_W":20000,"duration_s":60}`, http.StatusCreated},
		{"default control gets the same screen", "/admin/default", `{"program":0,"base":{"max_lim_W":-1}}`, http.StatusBadRequest},
	} {
		if got := post(tc.path, tc.body); got != tc.want {
			t.Fatalf("%s: POST %s %s = %d, want %d", tc.name, tc.path, tc.body, got, tc.want)
		}
	}

	// The rejected controls must not have landed: exactly one added.
	if list := derc0(t, s); len(list.DERControl) != seeded+1 {
		t.Fatalf("derc grew from %d to %d controls, want exactly the one accepted (20000)", seeded, len(list.DERControl))
	}
}

// IEEE Std 2030.5-2018 §10.2.3.3 c) — "Editing Events SHALL NOT be allowed
// except for updating status. Service providers SHALL cancel Events that they
// wish clients to not act upon and/or provide new superseding Events."
//
// IW27-005: this test used to be TestAdminControl_StatusUpdatePreservesCreationTimeAndInterval
// and asserted the OPPOSITE of what it is named here — that gen_lim_W
// accompanying a status flip on an EXISTING mRID was silently carried
// through, re-authored from the update's own request body. Preserving
// creationTime/interval while still letting the control BASE be re-authored
// from the request is only half of rule c): the base is just as much an
// "Event" element as the window is, and a fixture that could freely
// re-describe one could author server behaviour no conformant service
// provider could ever produce. The DEFAULT path now refuses the whole
// request — before anything is stored — the moment it carries a content
// field alongside an existing mRID.
//
// TestAdminControl_ExplicitMRIDUpdatesInPlace (above) covers the conformant
// replacement: a status-only flip that carries NO content gets the ORIGINAL
// control's content back, unchanged, by inheritance rather than
// re-authorship. TestAdminControl_NonconformantContentEditReauthorsExistingMRID
// (below) covers the deliberate-violation escape hatch this test used to
// exercise unconditionally.
func TestAdminControl_ContentEditOnExistingMRIDIsRejectedByDefault(t *testing.T) {
	s := NewServer("")
	h := s.AdminHandler()

	postCtrl(t, h, `{"program":0,"mrid":"DERC-CANCEL-ME","gen_lim_W":2000,"duration_s":600,"activate":true}`)
	before := derc0(t, s).DERControl[0]

	// The cancel lever, alongside gen_lim_W — a request that, pre-fix, would
	// otherwise also author a completely different window (start 300s out,
	// 900s long) on the same mRID.
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/admin/control", bytes.NewReader([]byte(
		`{"program":0,"mrid":"DERC-CANCEL-ME","cancel":true,"gen_lim_W":2000,"duration_s":900,"start_offset_s":300}`)))
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("POST /admin/control (status flip + gen_lim_W on an existing mRID) = %d, want 400: %s",
			rec.Code, rec.Body)
	}
	if !strings.Contains(rec.Body.String(), "gen_lim_W") {
		t.Errorf("the 400 does not name the offending field:\n%s", rec.Body)
	}

	// The rejected request must not have changed the stored control in any
	// respect — not even the parts it was not, itself, complaining about.
	after := derc0(t, s).DERControl[0]
	if after != before {
		t.Errorf("a rejected update still changed the stored control:\nbefore: %+v\nafter:  %+v", before, after)
	}
}

// The nonconformant escape hatch is what this test used to exercise
// unconditionally, on every same-mRID update: a caller that explicitly opts
// in still gets the OLD behaviour — the control base re-authored from the
// request — so a scenario testing a DUT's handling of a non-conformant
// server that re-describes its own events loses no coverage.
func TestAdminControl_NonconformantContentEditReauthorsExistingMRID(t *testing.T) {
	s := NewServer("")
	h := s.AdminHandler()

	postCtrl(t, h, `{"program":0,"mrid":"DERC-CANCEL-ME","gen_lim_W":2000,"duration_s":600,"activate":true}`)

	postCtrl(t, h, `{"program":0,"mrid":"DERC-CANCEL-ME","cancel":true,"gen_lim_W":3000,"duration_s":600,`+
		`"nonconformant":{"allow_content_edit":true}}`)

	list := derc0(t, s)
	if len(list.DERControl) != 1 {
		t.Fatalf("in-place cancel added a control: derc has %d, want 1", len(list.DERControl))
	}
	after := list.DERControl[0]
	if es := after.EventStatus; es == nil || es.CurrentStatus != model.EventStatusCancelled {
		t.Fatalf("cancel flip: EventStatus = %+v, want CurrentStatus %d (Cancelled)", es, model.EventStatusCancelled)
	}
	if after.DERControlBase.OpModGenLimW == nil || after.DERControlBase.OpModGenLimW.Value != 3000 {
		t.Fatalf("nonconformant.allow_content_edit: DERControlBase = %+v, want the re-authored "+
			"opModGenLimW=3000 from THIS request, not the original 2000", after.DERControlBase)
	}
}

// The escape hatch stays open: a caller that explicitly asks for a creationTime
// (creation_offset_s — how the deterministic-winner scenarios author their
// pairs) still gets the one it asked for, on an existing mRID as on a new one,
// PROVIDED it is named as the deliberate violation it is
// (nonconformant.allow_creation_time_move) — IW27-005 closed the SILENT path
// this used to take by default; see
// TestAdminControl_CreationOffsetOnExistingMRIDIsRejectedByDefault below for
// that half.
func TestAdminControl_NonconformantCreationOffsetMovesCreationTimeOnExistingMRID(t *testing.T) {
	s := NewServer("")
	h := s.AdminHandler()

	postCtrl(t, h, `{"program":0,"mrid":"DERC-REDATE","gen_lim_W":2000,"duration_s":600,"activate":true}`)
	before := derc0(t, s).DERControl[0]

	postCtrl(t, h, `{"program":0,"mrid":"DERC-REDATE","creation_offset_s":120,`+
		`"nonconformant":{"allow_creation_time_move":true}}`)
	after := derc0(t, s).DERControl[0]

	if after.CreationTime <= before.CreationTime {
		t.Errorf("explicit creation_offset_s=120 (nonconformant, armed): creationTime %d -> %d, want it to move later",
			before.CreationTime, after.CreationTime)
	}
	if after.Interval != before.Interval {
		t.Errorf("interval moved: %+v -> %+v; only creationTime was asked for", before.Interval, after.Interval)
	}
	// The rest of the control's content still comes through by inheritance —
	// the nonconformant flag armed here is ONLY allow_creation_time_move, not
	// allow_content_edit, so gen_lim_W (omitted from this request) must still
	// read as the ORIGINAL value, not vanish.
	if after.DERControlBase.OpModGenLimW == nil || after.DERControlBase.OpModGenLimW.Value != before.DERControlBase.OpModGenLimW.Value {
		t.Errorf("DERControlBase = %+v, want opModGenLimW unchanged from before: %+v",
			after.DERControlBase, before.DERControlBase)
	}
}

// The DEFAULT path half of the creationTime rule: without the nonconformant
// escape hatch, creation_offset_s on an EXISTING mRID is refused outright
// (400) rather than silently ignored — a caller who asked for a specific
// creationTime and got a different one with no complaint would have no way to
// notice the request did not do what it asked.
func TestAdminControl_CreationOffsetOnExistingMRIDIsRejectedByDefault(t *testing.T) {
	s := NewServer("")
	h := s.AdminHandler()

	postCtrl(t, h, `{"program":0,"mrid":"DERC-REDATE2","gen_lim_W":2000,"duration_s":600,"activate":true}`)
	before := derc0(t, s).DERControl[0]

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/admin/control", bytes.NewReader([]byte(
		`{"program":0,"mrid":"DERC-REDATE2","creation_offset_s":120}`)))
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("POST /admin/control (creation_offset_s on an existing mRID, no nonconformant flag) = %d, "+
			"want 400: %s", rec.Code, rec.Body)
	}
	if !strings.Contains(rec.Body.String(), "creation_offset_s") {
		t.Errorf("the 400 does not name creation_offset_s:\n%s", rec.Body)
	}

	after := derc0(t, s).DERControl[0]
	if after != before {
		t.Errorf("a rejected update still changed the stored control:\nbefore: %+v\nafter:  %+v", before, after)
	}
}

// ── REV0907-B1: event-lifecycle status levers ──────────────────────────────

// TestAdminControl_CancelWithRandomizationServesStatusThree pins the
// cancel_with_randomization lever: it must serve currentStatus=3 (Cancelled
// with Randomization — IEEE Std 2030.5-2018 Annex B, p.159-160), not leave
// the caller to type the raw number.
func TestAdminControl_CancelWithRandomizationServesStatusThree(t *testing.T) {
	s := NewServer("")
	h := s.AdminHandler()

	postCtrl(t, h, `{"program":0,"mrid":"DERC-RANDCANCEL","exp_lim_W":4000,"duration_s":300,"activate":true,`+
		`"randomize_start":0,"randomize_duration":90}`)
	postCtrl(t, h, `{"program":0,"mrid":"DERC-RANDCANCEL","cancel_with_randomization":true,"duration_s":300}`)

	es := derc0(t, s).DERControl[0].EventStatus
	if es == nil || es.CurrentStatus != model.EventStatusCancelledWithRandomization {
		t.Fatalf("cancel_with_randomization flip: EventStatus = %+v, want CurrentStatus %d (Cancelled with "+
			"Randomization)", es, model.EventStatusCancelledWithRandomization)
	}
}

// TestAdminControl_MarkSupersededRequiresARealSupersedingControl pins the
// mark_superseded lever's validation: IEEE Std 2030.5-2018 Annex B (p.159-160)
// defines currentStatus=4 (Superseded) in terms of a REAL new event actually
// commencing ("commence execution of the new event immediately"), so the
// lever must refuse to author one when no such control is scheduled on the
// same program — a mark_superseded that could conjure a Superseded status
// with nothing superseding it would license exactly the kind of currentStatus
// the standard does not, which is the class of defect REV0907-B1 closes.
func TestAdminControl_MarkSupersededRequiresARealSupersedingControl(t *testing.T) {
	s := NewServer("")
	h := s.AdminHandler()

	postCtrl(t, h, `{"program":0,"mrid":"DERC-LOSER","exp_lim_W":4000,"duration_s":300,"activate":true}`)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/admin/control", bytes.NewReader([]byte(
		`{"program":0,"mrid":"DERC-LOSER","mark_superseded":"DERC-DOES-NOT-EXIST","duration_s":300}`)))
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("mark_superseded naming a non-existent control = %d, want 400: %s", rec.Code, rec.Body)
	}
	if !strings.Contains(rec.Body.String(), "DERC-DOES-NOT-EXIST") {
		t.Errorf("the 400 does not name the missing superseding mrid:\n%s", rec.Body)
	}

	// The control under test must be UNCHANGED by the rejected request.
	es := derc0(t, s).DERControl[0].EventStatus
	if es != nil && es.CurrentStatus == model.EventStatusSuperseded {
		t.Errorf("a rejected mark_superseded still marked the control Superseded: %+v", es)
	}
}

// TestAdminControl_MarkSupersededWithARealSupersedingControlServesStatusFour
// is the positive half: naming a control that really is scheduled on the SAME
// program serves currentStatus=4.
func TestAdminControl_MarkSupersededWithARealSupersedingControlServesStatusFour(t *testing.T) {
	s := NewServer("")
	h := s.AdminHandler()

	postCtrl(t, h, `{"program":0,"mrid":"DERC-LOSER","exp_lim_W":4000,"duration_s":300,"activate":true}`)
	postCtrl(t, h, `{"program":0,"mrid":"DERC-WINNER","gen_lim_W":3000,"duration_s":300}`)

	postCtrl(t, h, `{"program":0,"mrid":"DERC-LOSER","mark_superseded":"DERC-WINNER","duration_s":300}`)

	list := derc0(t, s)
	var loser *model.DERControl
	for i := range list.DERControl {
		if list.DERControl[i].MRID == "DERC-LOSER" {
			loser = &list.DERControl[i]
		}
	}
	if loser == nil {
		t.Fatal("DERC-LOSER vanished from the scheduled list")
	}
	if loser.EventStatus == nil || loser.EventStatus.CurrentStatus != model.EventStatusSuperseded {
		t.Fatalf("mark_superseded flip: EventStatus = %+v, want CurrentStatus %d (Superseded)",
			loser.EventStatus, model.EventStatusSuperseded)
	}
}

// TestAdminControl_LeverAndRawOverrideAreMutuallyExclusive pins that a
// request cannot combine a named lever with the raw current_status override:
// CurrentStatus is reserved for a negative test serving a value the standard
// reserves, and letting it silently coexist with a named lever would make it
// ambiguous which value the request actually meant to test.
func TestAdminControl_LeverAndRawOverrideAreMutuallyExclusive(t *testing.T) {
	s := NewServer("")
	h := s.AdminHandler()
	postCtrl(t, h, `{"program":0,"mrid":"DERC-AMBIG","exp_lim_W":4000,"duration_s":300,"activate":true}`)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/admin/control", bytes.NewReader([]byte(
		`{"program":0,"mrid":"DERC-AMBIG","cancel":true,"current_status":6,"duration_s":300}`)))
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("cancel + current_status combined = %d, want 400: %s", rec.Code, rec.Body)
	}
}

// TestAdminControl_AtMostOneLever pins that the three levers are themselves
// mutually exclusive — a request cannot ask gridsim to serve two different
// currentStatus values from one POST.
func TestAdminControl_AtMostOneLever(t *testing.T) {
	s := NewServer("")
	h := s.AdminHandler()
	postCtrl(t, h, `{"program":0,"mrid":"DERC-TWOLEVERS","exp_lim_W":4000,"duration_s":300,"activate":true}`)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/admin/control", bytes.NewReader([]byte(
		`{"program":0,"mrid":"DERC-TWOLEVERS","cancel":true,"cancel_with_randomization":true,"duration_s":300}`)))
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("cancel + cancel_with_randomization combined = %d, want 400: %s", rec.Code, rec.Body)
	}
}
