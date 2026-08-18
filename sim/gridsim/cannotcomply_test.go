package gridsim

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	model "lexa-proto/csipmodel"
)

// postResponseStatus POSTs a Response with the given status to /rsps/0/r.
func postResponseStatus(t *testing.T, s *Server, status uint8) {
	t.Helper()
	body := fmt.Sprintf(`<Response xmlns="urn:ieee:std:2030.5:ns">`+
		`<endDeviceLFDI>ABC</endDeviceLFDI><status>%d</status><subject>EVT-%d</subject></Response>`,
		status, status)
	rec := httptest.NewRecorder()
	s.handleResponsePost(rec, httptest.NewRequest(http.MethodPost, "/rsps/0/r", bytes.NewReader([]byte(body))), "/rsps/0/r")
	if rec.Code != http.StatusCreated {
		t.Fatalf("POST Response(status=%d) = %d, want 201", status, rec.Code)
	}
}

// classifyResponseStatus must recognise the legacy 0xF0 extension AND the
// SD-02-corrected Table 27 taxonomy (4/5 lifecycle acks, 8/10 end-of-event
// partials, 252/253/254 receipt rejections), reject normal lifecycle acks,
// and tag each Table27 alert with its SD-02 class.
//
// The 4/5 cases are the class this test did NOT cover before SD-02: 4/5's
// own lexa-proto constants were themselves transposed at the time
// (docs/design/SD02_RESPONSE_SEMANTICS_RC0_2026-08-17.md, lexa-gw), so this
// table never had a wantAlert=true case at 4 or 5 to catch the omission —
// classifyResponseStatus fell through to alert=false, "" for both. That is
// exactly the "your own suites go red for the wrong reason" failure SD-02
// warns about: a corrected product's opt-out admission would have vanished
// from /admin/alerts entirely, and every downstream check keyed on
// "some alert was recorded" would have misread it as silent non-compliance.
//
// F10: 0xF1-0xFB and 0xFF must classify as NEITHER vocabulary. Before this
// sweep classifyResponseStatus used "status >= alertStatusFloor" (0xF0), so
// the ENTIRE 0xF0-0xFF span — including Table 27's own RESERVED values this
// product has never assigned any meaning to — registered as the legacy
// extension. 0xF0 is the only value the extension has ever spoken (see
// model.ResponseCannotComply's own doc, vendor/lexa-proto/csipmodel/
// resources.go); the standard defines no manufacturer range at all (Table 27
// reserves 15-251 and 255, with no carve-out for a vendor to use). A DUT
// that sends 0xF1-0xFB/0xFF is speaking a status this product has never
// defined, standard or legacy, and that must surface as unclassified, not be
// silently folded into the one wire mode the product actually implements.
func TestClassifyResponseStatus(t *testing.T) {
	cases := []struct {
		status    uint8
		wantAlert bool
		wantVocab string
		wantClass string
	}{
		{model.ResponseCannotComply, true, VocabLegacy, ""},                         // 0xF0 — the ONLY legacy value
		{0xF1, false, "", ""},                                                       // F10: reserved, NOT legacy
		{0xFB, false, "", ""},                                                       // F10: reserved, NOT legacy
		{0xFF, false, "", ""},                                                       // F10: reserved (Table 27 p.74-76), NOT legacy
		{model.ResponseOptOut, true, VocabTable27, ClassOptOut},                     // 4  — SD-02: preference-driven opt-out
		{model.ResponseOptIn, true, VocabTable27, ClassOptIn},                       // 5  — SD-02: opt-in / recovery
		{model.ResponsePartialOptOut, true, VocabTable27, ClassEndOfEventPartial},   // 8  — EffectiveEndTime-only
		{model.ResponseNoParticipation, true, VocabTable27, ClassEndOfEventPartial}, // 10 — EffectiveEndTime-only
		{model.ResponseRejectedInvalid, true, VocabTable27, ClassReceiptRejection},  // 253 — receipt reject
		{model.ResponseRejectedParam, true, VocabTable27, ClassReceiptRejection},    // 252
		{model.ResponseRejectedExpired, true, VocabTable27, ClassReceiptRejection},  // 254
		{model.ResponseEventReceived, false, "", ""},                                // 1
		{model.ResponseEventStarted, false, "", ""},                                 // 2
		{model.ResponseEventCompleted, false, "", ""},                               // 3 — clean end-of-event
		{model.ResponseEventCancelled, false, "", ""},                               // 6
		{model.ResponseEventSuperseded, false, "", ""},                              // 7
	}
	for _, c := range cases {
		gotAlert, gotVocab, gotClass := classifyResponseStatus(c.status)
		if gotAlert != c.wantAlert || gotVocab != c.wantVocab || gotClass != c.wantClass {
			t.Errorf("classify(%d) = (%v,%q,%q), want (%v,%q,%q)",
				c.status, gotAlert, gotVocab, gotClass, c.wantAlert, c.wantVocab, c.wantClass)
		}
	}
}

// Legacy 0xF0 and every SD-02 Table27 class register as compliance alerts,
// and gridsim records which vocabulary AND class arrived so a test can assert
// the WP-7 flip and the corrected taxonomy. Normal lifecycle acks do not
// alert.
func TestCannotComply_BothVocabulariesRecorded(t *testing.T) {
	s := NewServer("")

	postResponseStatus(t, s, model.ResponseEventStarted)    // 2  — not an alert
	postResponseStatus(t, s, model.ResponseCannotComply)    // 0xF0 legacy
	postResponseStatus(t, s, model.ResponseOptOut)          // 4   table27 opt-out (SD-02)
	postResponseStatus(t, s, model.ResponsePartialOptOut)   // 8   table27 end-of-event partial
	postResponseStatus(t, s, model.ResponseRejectedInvalid) // 253 table27 receipt-reject
	postResponseStatus(t, s, model.ResponseEventCompleted)  // 3  — not an alert

	alerts := s.ComplianceAlerts()
	if len(alerts) != 4 {
		t.Fatalf("got %d compliance alerts, want 4 (0xF0 + 4 + 8 + 253)", len(alerts))
	}

	byStatus := map[uint8]ComplianceAlert{}
	for _, a := range alerts {
		byStatus[a.Status] = a
	}
	if byStatus[model.ResponseCannotComply].Vocab != VocabLegacy {
		t.Errorf("0xF0 vocab = %q, want %q", byStatus[model.ResponseCannotComply].Vocab, VocabLegacy)
	}
	if got := byStatus[model.ResponseOptOut]; got.Vocab != VocabTable27 || got.Class != ClassOptOut {
		t.Errorf("code-4 (vocab,class) = (%q,%q), want (%q,%q)", got.Vocab, got.Class, VocabTable27, ClassOptOut)
	}
	if got := byStatus[model.ResponsePartialOptOut]; got.Vocab != VocabTable27 || got.Class != ClassEndOfEventPartial {
		t.Errorf("code-8 (vocab,class) = (%q,%q), want (%q,%q)", got.Vocab, got.Class, VocabTable27, ClassEndOfEventPartial)
	}
	if got := byStatus[model.ResponseRejectedInvalid]; got.Vocab != VocabTable27 || got.Class != ClassReceiptRejection {
		t.Errorf("code-253 (vocab,class) = (%q,%q), want (%q,%q)", got.Vocab, got.Class, VocabTable27, ClassReceiptRejection)
	}

	// Every POSTed Response — alert or not — is still captured for inspection.
	if got := len(s.ReceivedResponses()); got != 6 {
		t.Errorf("ReceivedResponses = %d, want 6 (all statuses recorded)", got)
	}
}
