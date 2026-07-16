package simapi

// server_test.go — the /state and WS encoding paths must DEGRADE, never fail,
// when the state payload contains non-finite floats (audit E1: a poisoned
// SunSpec register bank decodes to NaN, which previously made GET /state 500
// permanently and the WS broadcast skip silently forever).

import (
	"encoding/json"
	"math"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// nanState mimics a sim state snapshot whose decoded registers contain NaN.
type nanState struct {
	Good   float64 `json:"good"`
	Bad    float64 `json:"bad"`
	Inf    float64 `json:"inf"`
	Nested struct {
		PF float64 `json:"pf"`
	} `json:"nested"`
}

func TestWriteJSON_NonFiniteDegradesTo200(t *testing.T) {
	var v nanState
	v.Good = 42.5
	v.Bad = math.NaN()
	v.Inf = math.Inf(1)
	v.Nested.PF = math.NaN()

	rec := httptest.NewRecorder()
	writeJSON(rec, v)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (GET /state must never 500 on corrupted ground truth)", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
	var got map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("body is not valid JSON: %v (body %q)", err, rec.Body.String())
	}
	if got["good"] != 42.5 {
		t.Errorf("good = %v, want 42.5 (finite values must survive intact)", got["good"])
	}
	for _, key := range []string{"bad", "inf"} {
		val, present := got[key]
		if !present || val != nil {
			t.Errorf("%s = %v (present=%v), want null", key, val, present)
		}
	}
	nested, ok := got["nested"].(map[string]any)
	if !ok {
		t.Fatalf("nested = %T, want object", got["nested"])
	}
	if pf, present := nested["pf"]; !present || pf != nil {
		t.Errorf("nested.pf = %v (present=%v), want null", pf, present)
	}
}

func TestBroadcastOnce_SanitizesInsteadOfSkip(t *testing.T) {
	s := &Server{
		stateFn: func() any {
			return struct {
				W float64 `json:"w"`
			}{math.NaN()}
		},
		clients: make(map[chan []byte]struct{}),
	}
	ch := make(chan []byte, 1)
	s.clients[ch] = struct{}{}

	s.broadcastOnce()

	select {
	case msg := <-ch:
		var got map[string]any
		if err := json.Unmarshal(msg, &got); err != nil {
			t.Fatalf("broadcast frame is not valid JSON: %v (frame %q)", err, msg)
		}
		if w, present := got["w"]; !present || w != nil {
			t.Errorf("w = %v (present=%v), want null", w, present)
		}
	default:
		t.Fatal("broadcastOnce sent nothing — the silent-skip E1 regression (WS feed goes permanently mute)")
	}
}

// TestSanitizeNonFinite_PreservesCleanSubtrees pins that only the failing
// leaves degrade: custom marshalers (time.Time), omitempty, and finite
// values encode exactly as the plain encoder would.
func TestSanitizeNonFinite_PreservesCleanSubtrees(t *testing.T) {
	type payload struct {
		TS   time.Time `json:"ts"`
		Vals []float64 `json:"vals"`
		Omit *int      `json:"omit,omitempty"`
	}
	ts := time.Date(2026, 7, 16, 12, 0, 0, 0, time.UTC)
	p := payload{TS: ts, Vals: []float64{1.5, math.NaN()}}

	b, err := json.Marshal(SanitizeNonFinite(p))
	if err != nil {
		t.Fatalf("sanitized marshal: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("sanitized output is not valid JSON: %v", err)
	}
	if got["ts"] != "2026-07-16T12:00:00Z" {
		t.Errorf("ts = %v, want RFC3339 string (time.Time's own marshaler must be preserved)", got["ts"])
	}
	vals, ok := got["vals"].([]any)
	if !ok || len(vals) != 2 || vals[0] != 1.5 || vals[1] != nil {
		t.Errorf("vals = %v, want [1.5, null]", got["vals"])
	}
	if _, present := got["omit"]; present {
		t.Errorf("omit present in sanitized output, want omitted (omitempty must be honoured)")
	}
}
