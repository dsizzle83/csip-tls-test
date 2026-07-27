package suitecsip

// observe_test.go covers the live phase: reading gridsim's server-side view,
// differencing it against a baseline, and waiting for the DUT.
//
// The baseline arithmetic is the part with real consequences. gridsim
// accumulates Responses, DER PUTs and LogEvents across a whole campaign, so a
// check that counted them absolutely would pass on evidence some other test
// case — or some other agent — produced. Every test below that touches ServerView
// is really a test of that boundary.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"csip-tls-test/internal/certify"
)

func TestParseRequestLogReadsGridsimsLines(t *testing.T) {
	lines := []string{
		"2026/07/26 12:00:00 [gridsim] GET /dcap (peer=abc123)",
		"2026/07/26 12:00:01 [gridsim] GET /edev?l=255 (peer=abc123)",
		"2026/07/26 12:00:02 [gridsim] PUT /edev/2/der/0/derstat (peer=abc123)",
		"2026/07/26 12:00:03 [gridsim] 404: no resource at /nope",
		"2026/07/26 12:00:04 [gridsim] client identity from cert: LFDI=abc123 SFDI=1",
		"a line from some other component entirely",
	}
	got := parseRequestLog(lines)
	if len(got) != 3 {
		t.Fatalf("parsed %d request(s), want 3: %+v", len(got), got)
	}
	if got[0].Method != "GET" || got[0].Path != "/dcap" || got[0].Peer != "abc123" {
		t.Errorf("first request = %+v", got[0])
	}
	// The query string must be stripped: a criterion asking "did the DUT fetch
	// the EndDeviceList" is not asking about paging parameters.
	if got[1].Path != "/edev" {
		t.Errorf("query string was not stripped: %q", got[1].Path)
	}
	if got[0].At.IsZero() {
		t.Error("the log line's timestamp was not parsed")
	}
	if got[2].Method != "PUT" {
		t.Errorf("third request = %+v", got[2])
	}

	v := ServerView{Requests: got}
	if n := v.GETs("/dcap"); n != 1 {
		t.Errorf("GETs(/dcap) = %d, want 1", n)
	}
	if n := v.GETs("/derp"); n != 0 {
		t.Errorf("GETs(/derp) = %d, want 0", n)
	}
}

// TestServerViewBaselineExcludesPriorEvidence is the guard against a check
// passing on another test case's Responses.
func TestServerViewBaselineExcludesPriorEvidence(t *testing.T) {
	base := ServerView{
		Responses: []AdminResponse{{Subject: "OLD", Status: 1}},
		DERPuts:   []AdminDERPut{{Resource: "DERStatus"}},
		Requests:  []ServerRequest{{Method: "GET", Path: "/dcap"}},
	}
	now := ServerView{
		Available: true,
		Responses: []AdminResponse{{Subject: "OLD", Status: 1}, {Subject: "NEW", Status: 2}},
		DERPuts:   []AdminDERPut{{Resource: "DERStatus"}, {Resource: "DERSettings"}},
		Requests: []ServerRequest{{Method: "GET", Path: "/dcap"}, {Method: "GET", Path: "/dcap"},
			{Method: "GET", Path: "/edev"}},
	}
	d := now.Since(base)
	if len(d.Responses) != 1 || d.Responses[0].Subject != "NEW" {
		t.Errorf("differenced responses = %+v, want only NEW", d.Responses)
	}
	if len(d.DERPuts) != 1 || d.DERPuts[0].Resource != "DERSettings" {
		t.Errorf("differenced DER PUTs = %+v", d.DERPuts)
	}
	if n := d.GETs("/dcap"); n != 1 {
		t.Errorf("differenced GETs(/dcap) = %d, want 1", n)
	}
	if len(d.ResponsesFor("OLD")) != 0 {
		t.Error("a prior test case's Response survived the baseline difference")
	}
	if !d.HasResponse("NEW", 2) {
		t.Error("the new Response did not survive the baseline difference")
	}

	// A log ring that rolled over between the baseline and now must not produce
	// a negative slice or panic.
	rolled := ServerView{Responses: nil, DERPuts: nil, Requests: nil}
	_ = rolled.Since(base)
}

// gridsimStub is a minimal stand-in for the admin API, including the SSE log.
func gridsimStub(t *testing.T, state *stubState) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/admin/status", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, AdminStatus{Programs: []AdminProgram{{ID: 0, MRID: "P0", Primacy: 1}}, ServerTime: 1})
	})
	mux.HandleFunc("/admin/responses", func(w http.ResponseWriter, r *http.Request) {
		state.mu(func() { writeJSON(w, map[string]any{"responses": state.responses}) })
	})
	mux.HandleFunc("/admin/derputs", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]any{"der_puts": []AdminDERPut{{Path: "/p", Resource: "DERStatus", Body: "<x/>"}}})
	})
	mux.HandleFunc("/admin/logevents", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]any{"log_events": []map[string]any{{"logEventCode": 1}}})
	})
	mux.HandleFunc("/admin/control", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		var req ControlRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		state.mu(func() { state.posted = append(state.posted, req) })
		writeJSON(w, map[string]any{"mrid": req.MRID})
	})
	mux.HandleFunc("/admin/redirect", func(w http.ResponseWriter, r *http.Request) {
		var req map[string]any
		_ = json.NewDecoder(r.Body).Decode(&req)
		state.mu(func() { state.faults = append(state.faults, req) })
		w.WriteHeader(http.StatusNoContent)
	})
	for _, p := range []string{"/admin/gone", "/admin/outage", "/admin/paginate", "/admin/malform"} {
		mux.HandleFunc(p, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) })
	}
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

type stubState struct {
	lock      chan struct{}
	responses []AdminResponse
	posted    []ControlRequest
	faults    []map[string]any
}

func newStubState() *stubState { return &stubState{lock: make(chan struct{}, 1)} }

func (s *stubState) mu(f func()) {
	s.lock <- struct{}{}
	defer func() { <-s.lock }()
	f()
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func TestDriverSnapshotCollectsEverything(t *testing.T) {
	state := newStubState()
	state.responses = []AdminResponse{{Subject: "M1", Status: 1, LFDI: "ab"}}
	srv := gridsimStub(t, state)

	d := &Driver{
		rc:    &certify.RunCtx{Case: &certify.Case{UID: "x"}},
		Admin: certify.NewAdminClient(srv.URL, nil),
		LogReader: func(ctx context.Context, base string) ([]string, error) {
			return []string{"2026/07/26 12:00:00 [gridsim] GET /dcap (peer=ab)"}, nil
		},
	}
	v := d.Snapshot(context.Background())
	if !v.Available {
		t.Fatalf("snapshot reports unavailable: %v", v.Errors)
	}
	if len(v.Errors) != 0 {
		t.Errorf("snapshot errors: %v", v.Errors)
	}
	if len(v.Responses) != 1 || v.Responses[0].Subject != "M1" {
		t.Errorf("responses = %+v", v.Responses)
	}
	if len(v.PutsFor("DERStatus")) != 1 {
		t.Errorf("DER PUTs = %+v", v.DERPuts)
	}
	if len(v.LogEvents) != 1 {
		t.Errorf("log events = %+v", v.LogEvents)
	}
	if v.GETs("/dcap") != 1 {
		t.Errorf("request log = %+v", v.Requests)
	}
	if len(v.Status.Programs) != 1 {
		t.Errorf("status = %+v", v.Status)
	}
}

// TestDriverSnapshotSurvivesAPartialOutage: one endpoint failing must not cost
// the check the others, or a transient 500 on the log endpoint would take down
// a test case whose verdict rests on the Response record.
func TestDriverSnapshotSurvivesAPartialOutage(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/admin/responses", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]any{"responses": []AdminResponse{{Subject: "M1", Status: 3}}})
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	d := &Driver{
		rc: &certify.RunCtx{Case: &certify.Case{UID: "x"}}, Admin: certify.NewAdminClient(srv.URL, nil),
		LogReader: func(ctx context.Context, base string) ([]string, error) { return nil, context.DeadlineExceeded },
	}
	v := d.Snapshot(context.Background())
	if !v.HasResponse("M1", 3) {
		t.Error("the Response record was lost because other endpoints failed")
	}
	if len(v.Errors) == 0 {
		t.Error("a partial view must record what could not be collected")
	}
}

func TestDriverAwaitReturnsWhenThePredicateHolds(t *testing.T) {
	state := newStubState()
	srv := gridsimStub(t, state)
	d := &Driver{
		rc: &certify.RunCtx{Case: &certify.Case{UID: "x"}}, Admin: certify.NewAdminClient(srv.URL, nil),
		LogReader: func(ctx context.Context, base string) ([]string, error) { return nil, nil },
	}
	// Already satisfied: Await must return immediately rather than sleeping.
	state.responses = []AdminResponse{{Subject: "M1", Status: 1}}
	start := time.Now()
	v, waited, ok := d.Await(context.Background(), 30*time.Second,
		func(v ServerView) bool { return v.HasResponse("M1", 1) })
	if !ok {
		t.Fatal("Await did not see an already-satisfied predicate")
	}
	if time.Since(start) > 2*time.Second {
		t.Errorf("Await slept for %s on an already-satisfied predicate", waited)
	}
	if !v.Available {
		t.Error("the returned view is unavailable")
	}

	// Never satisfied: Await must give up at the deadline and report that,
	// rather than erroring — "the DUT did not do it in time" is a finding the
	// check phrases, not a failure of the wait.
	_, _, ok = d.Await(context.Background(), 10*time.Millisecond,
		func(v ServerView) bool { return v.HasResponse("NOPE", 9) })
	if ok {
		t.Error("Await reported satisfaction of a predicate that never held")
	}
}

func TestDriverLeversPostWhatTheyClaim(t *testing.T) {
	state := newStubState()
	srv := gridsimStub(t, state)
	d := &Driver{rc: &certify.RunCtx{Case: &certify.Case{UID: "x"}}, Admin: certify.NewAdminClient(srv.URL, nil)}

	mrid, err := d.PostControl(context.Background(), ControlRequest{
		Program: 0, MRID: "M1", MaxLimW: ptr(int64(6000)), DurationS: 60,
	})
	if err != nil {
		t.Fatal(err)
	}
	if mrid != "M1" {
		t.Errorf("PostControl returned mRID %q", mrid)
	}
	state.mu(func() {
		if len(state.posted) != 1 || state.posted[0].MaxLimW == nil || *state.posted[0].MaxLimW != 6000 {
			t.Errorf("gridsim received %+v", state.posted)
		}
	})

	if err := d.ArmRedirect(context.Background(), "/dcap", "/dcap", 302, 1); err != nil {
		t.Fatal(err)
	}
	state.mu(func() {
		if len(state.faults) != 1 || state.faults[0]["path"] != "/dcap" {
			t.Errorf("gridsim received %+v", state.faults)
		}
	})

	// An unbounded outage must be refused before it reaches the shared bench:
	// it would push the DUT into its 15-minute retry backoff and invalidate
	// every test case that follows.
	if err := d.ArmOutage(context.Background(), "down", 0); err == nil {
		t.Fatal("an unbounded outage was accepted")
	} else if !strings.Contains(err.Error(), "backoff") {
		t.Errorf("the refusal does not explain why: %v", err)
	}
	if err := d.ArmOutage(context.Background(), "down", 30); err != nil {
		t.Errorf("a bounded outage was refused: %v", err)
	}

	if errs := d.ClearFaults(context.Background()); len(errs) != 0 {
		t.Errorf("ClearFaults: %v", errs)
	}
}

// TestReadSSEBacklogTakesTheBacklogAndLetsGo proves the log reader does not
// hang on an endpoint that streams forever.
func TestReadSSEBacklogTakesTheBacklogAndLetsGo(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		fl := w.(http.Flusher)
		for _, l := range []string{"[gridsim] GET /dcap (peer=ab)", "[gridsim] GET /edev (peer=ab)"} {
			_, _ = w.Write([]byte("data: " + l + "\n\n"))
		}
		fl.Flush()
		<-r.Context().Done() // stream forever, like the real endpoint
	}))
	t.Cleanup(srv.Close)

	start := time.Now()
	lines, err := readSSEBacklog(context.Background(), srv.URL, 300*time.Millisecond)
	if err != nil {
		t.Fatalf("readSSEBacklog: %v", err)
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Errorf("readSSEBacklog took %s against a never-ending stream", elapsed)
	}
	if len(lines) != 2 {
		t.Fatalf("read %d line(s): %v", len(lines), lines)
	}
	if got := parseRequestLog(lines); len(got) != 2 || got[1].Path != "/edev" {
		t.Errorf("parsed %+v", got)
	}
}
