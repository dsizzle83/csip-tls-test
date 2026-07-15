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

// classifyResponseStatus must recognise BOTH the legacy 0xF0 extension and the
// WP-7 Table 27 CannotComply-family codes, and reject normal lifecycle acks.
func TestClassifyResponseStatus(t *testing.T) {
	cases := []struct {
		status    uint8
		wantAlert bool
		wantVocab string
	}{
		{model.ResponseCannotComply, true, VocabLegacy},     // 0xF0
		{0xFF, true, VocabLegacy},                           // top of the extension range
		{model.ResponsePartialOptOut, true, VocabTable27},   // 8  — onset
		{model.ResponseNoParticipation, true, VocabTable27}, // 10 — end-of-event no participation
		{model.ResponseRejectedInvalid, true, VocabTable27}, // 253 — receipt reject
		{model.ResponseRejectedParam, true, VocabTable27},   // 252
		{model.ResponseRejectedExpired, true, VocabTable27}, // 254
		{model.ResponseEventReceived, false, ""},            // 1
		{model.ResponseEventStarted, false, ""},             // 2
		{model.ResponseEventCompleted, false, ""},           // 3 — clean end-of-event
		{model.ResponseEventCancelled, false, ""},           // 6
		{model.ResponseEventSuperseded, false, ""},          // 7
	}
	for _, c := range cases {
		gotAlert, gotVocab := classifyResponseStatus(c.status)
		if gotAlert != c.wantAlert || gotVocab != c.wantVocab {
			t.Errorf("classify(%d) = (%v,%q), want (%v,%q)",
				c.status, gotAlert, gotVocab, c.wantAlert, c.wantVocab)
		}
	}
}

// Legacy 0xF0 and the new Table 27 onset code both register as compliance
// alerts, and gridsim records which vocabulary arrived so a test can assert
// the WP-7 flip. Normal lifecycle acks do not alert.
func TestCannotComply_BothVocabulariesRecorded(t *testing.T) {
	s := NewServer("")

	postResponseStatus(t, s, model.ResponseEventStarted)    // 2  — not an alert
	postResponseStatus(t, s, model.ResponseCannotComply)    // 0xF0 legacy
	postResponseStatus(t, s, model.ResponsePartialOptOut)   // 8   table27 onset
	postResponseStatus(t, s, model.ResponseRejectedInvalid) // 253 table27 receipt-reject
	postResponseStatus(t, s, model.ResponseEventCompleted)  // 3  — not an alert

	alerts := s.ComplianceAlerts()
	if len(alerts) != 3 {
		t.Fatalf("got %d compliance alerts, want 3 (0xF0 + 8 + 253)", len(alerts))
	}

	byStatus := map[uint8]ComplianceAlert{}
	for _, a := range alerts {
		byStatus[a.Status] = a
	}
	if byStatus[model.ResponseCannotComply].Vocab != VocabLegacy {
		t.Errorf("0xF0 vocab = %q, want %q", byStatus[model.ResponseCannotComply].Vocab, VocabLegacy)
	}
	if byStatus[model.ResponsePartialOptOut].Vocab != VocabTable27 {
		t.Errorf("code-8 vocab = %q, want %q", byStatus[model.ResponsePartialOptOut].Vocab, VocabTable27)
	}
	if byStatus[model.ResponseRejectedInvalid].Vocab != VocabTable27 {
		t.Errorf("code-253 vocab = %q, want %q", byStatus[model.ResponseRejectedInvalid].Vocab, VocabTable27)
	}

	// Every POSTed Response — alert or not — is still captured for inspection.
	if got := len(s.ReceivedResponses()); got != 5 {
		t.Errorf("ReceivedResponses = %d, want 5 (all statuses recorded)", got)
	}
}
