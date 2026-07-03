package gridsim

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestOutage_DownFailsCSIPRequestsFast(t *testing.T) {
	s := &Server{}
	if err := s.SetOutage(OutageDown, 0, 0); err != nil {
		t.Fatalf("arm: %v", err)
	}
	w := httptest.NewRecorder()
	if !s.outageIntercept(w) {
		t.Fatal("armed 'down' outage did not intercept the request")
	}
	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("mode down: got %d, want 503", w.Code)
	}

	// Clearing restores normal service.
	if err := s.SetOutage("", 0, 0); err != nil {
		t.Fatalf("clear: %v", err)
	}
	if s.outageIntercept(httptest.NewRecorder()) {
		t.Error("cleared outage still intercepting")
	}
}

func TestOutage_HangStallsThenFails(t *testing.T) {
	s := &Server{}
	if err := s.SetOutage(OutageHang, 0, 1); err != nil { // 1 s stall for the test
		t.Fatalf("arm: %v", err)
	}
	w := httptest.NewRecorder()
	start := time.Now()
	if !s.outageIntercept(w) {
		t.Fatal("armed 'hang' outage did not intercept the request")
	}
	if elapsed := time.Since(start); elapsed < 900*time.Millisecond {
		t.Errorf("hang returned after %v, want ≥ ~1s stall", elapsed)
	}
	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("mode hang: got %d, want 503", w.Code)
	}
}

func TestOutage_AutoClearAndSupersede(t *testing.T) {
	s := &Server{}
	if err := s.SetOutage(OutageDown, 1, 0); err != nil { // auto-clear after 1 s
		t.Fatalf("arm: %v", err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for s.outageIntercept(httptest.NewRecorder()) {
		if time.Now().After(deadline) {
			t.Fatal("outage did not auto-clear within its duration")
		}
		time.Sleep(100 * time.Millisecond)
	}

	// A newer arm must not be clobbered by the previous arm's pending auto-clear.
	if err := s.SetOutage(OutageDown, 1, 0); err != nil {
		t.Fatalf("re-arm: %v", err)
	}
	if err := s.SetOutage(OutageDown, 0, 0); err != nil { // supersede: no auto-clear
		t.Fatalf("supersede: %v", err)
	}
	time.Sleep(1500 * time.Millisecond) // the first arm's timer fires in here
	if !s.outageIntercept(httptest.NewRecorder()) {
		t.Error("superseding arm was cleared by the stale auto-clear timer")
	}
}

func TestOutage_UnknownModeRejected(t *testing.T) {
	s := &Server{}
	if err := s.SetOutage("explode", 0, 0); err == nil {
		t.Error("unknown outage mode accepted")
	}
}
