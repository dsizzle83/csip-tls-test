package suitessm

// helpers_test.go tests the shared client-half machinery in helpers.go.
//
// watchClientHalfForced is the fix for census 20260731T234821's
// CRYP-001#7/CRYP-002#6/CRYP-004#4/CRYP-006#3/PROT-002#4/PROT-004#3/RBAC-011#1:
// a plain watchClientHalf almost never catches a fresh gateway ClientHello
// once the mbaps session it is waiting on is already long-lived, so this
// helper arms mbapsdev's drop_session fault first to force the reconnect.
// This test drives it through the real runner (NoCapture, no real DUT) and
// checks the one thing a unit test of the decision logic alone cannot: that
// the HTTP arm/clear sequence actually happens, in that order, around the
// observation wait.

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"csip-tls-test/internal/certify"
)

// faultCall is one POST /fault this test's fake mbapsdev simapi observed.
type faultCall struct {
	Kind  string `json:"kind"`
	Clear bool   `json:"clear,omitempty"`
}

// fakeMBAPSDevAPI is a minimal stand-in for mbapsdev's simapi sidecar
// (sim/mbapsdev/faults.go), recording every POST /fault body it receives.
type fakeMBAPSDevAPI struct {
	mu    sync.Mutex
	calls []faultCall
}

func (f *fakeMBAPSDevAPI) server() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/fault" || r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		var body bytes.Buffer
		if _, err := body.ReadFrom(r.Body); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		var call faultCall
		if err := json.Unmarshal(body.Bytes(), &call); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		f.mu.Lock()
		f.calls = append(f.calls, call)
		f.mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
}

func (f *fakeMBAPSDevAPI) snapshot() []faultCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]faultCall(nil), f.calls...)
}

// TestWatchClientHalfForcedArmsAndClearsDropSession drives RBAC-011 — the
// simplest of the seven fixed call sites, since it needs no southbound mbaps
// server of its own — through the real runner against a fake mbapsdev
// simapi, and checks that the drop_session fault this suite is now supposed
// to arm before the wait is actually armed, and cleared afterward.
func TestWatchClientHalfForcedArmsAndClearsDropSession(t *testing.T) {
	const uid = "ssm-conf-v0.8::RBAC-011"

	fake := &fakeMBAPSDevAPI{}
	srv := fake.server()
	defer srv.Close()

	opts := certify.DefaultOptions()
	opts.UIDs = []string{uid}
	opts.NoCapture = true
	opts.OutDir = t.TempDir()
	opts.Log = certify.DiscardLogger
	console := &bytes.Buffer{}
	opts.Out = console
	// No real DUT dials the fake mbaps endpoint in this harness; a short wait
	// keeps the test fast without changing what is being proven — that the
	// arm/clear calls happen, not that a ClientHello is caught.
	opts.Params = map[string]string{"ssm.client_wait": "10ms"}
	opts.Targets.MBAPSDev = "127.0.0.1:1"
	opts.Targets.MBAPSDevAPI = srv.URL

	run, err := certify.New(registry(t), loadCatalog(t), opts)
	if err != nil {
		t.Fatal(err)
	}
	rep, err := run.Run(context.Background())
	if err != nil {
		t.Fatalf("Run: %v\n%s", err, console.String())
	}
	var found bool
	for _, c := range rep.Cases {
		if c.Case.UID == uid {
			found = true
		}
	}
	if !found {
		t.Fatalf("%s did not appear in the run report\n%s", uid, console.String())
	}

	calls := fake.snapshot()
	if len(calls) < 2 {
		t.Fatalf("watchClientHalfForced should arm then clear drop_session on mbapsdev; got %d call(s): %+v\n%s",
			len(calls), calls, console.String())
	}
	arm := calls[0]
	if arm.Kind != forcedReconnectFault || arm.Clear {
		t.Errorf("first call = %+v, want an unclear arm of %q", arm, forcedReconnectFault)
	}
	last := calls[len(calls)-1]
	if last.Kind != forcedReconnectFault || !last.Clear {
		t.Errorf("last call = %+v, want a clear of %q", last, forcedReconnectFault)
	}
}

// TestWatchClientHalfForcedFallsBackWithoutMBAPSDevAPI proves the helper
// degrades to a plain passive wait, rather than erroring or panicking, when
// no mbapsdev simapi is configured — the same shape of run every OTHER
// suitessm loopback test in this package exercises today.
func TestWatchClientHalfForcedFallsBackWithoutMBAPSDevAPI(t *testing.T) {
	const uid = "ssm-conf-v0.8::RBAC-011"

	opts := certify.DefaultOptions()
	opts.UIDs = []string{uid}
	opts.NoCapture = true
	opts.OutDir = t.TempDir()
	opts.Log = certify.DiscardLogger
	console := &bytes.Buffer{}
	opts.Out = console
	opts.Params = map[string]string{"ssm.client_wait": "10ms"}
	// MBAPSDevAPI deliberately left empty: rc.Sim("mbapsdev") must fail, and
	// watchClientHalfForced must fall back to watchClientHalf rather than
	// treating that as a run-ending error.
	opts.Targets.MBAPSDev = "127.0.0.1:1"

	run, err := certify.New(registry(t), loadCatalog(t), opts)
	if err != nil {
		t.Fatal(err)
	}
	rep, err := run.Run(context.Background())
	if err != nil {
		t.Fatalf("Run: %v\n%s", err, console.String())
	}
	for _, c := range rep.Cases {
		if c.Case.UID == uid {
			if c.Verdict == certify.Fail {
				t.Fatalf("a missing mbapsdev simapi should SKIP or WARN, not FAIL: %s\n%s", c.Notes, console.String())
			}
			return
		}
	}
	t.Fatalf("%s did not appear in the run report\n%s", uid, console.String())
}
