package suitecsip

// cleanup_test.go pins the suite's TEARDOWN, which had never once worked.
//
// Driver.ClearControls and Driver.ClearCurves both issued their DELETE with a
// NIL body, while gridsim's adminCtrlDelete and adminCurveDelete both begin by
// decoding {"program":N} out of the request BODY and answer 400 on the io.EOF
// that a nil body produces — before touching a single resource. Every call site
// wrote `_ = d.ClearX(...)`, so nothing ever reported it.
//
// The consequence is evidence contamination rather than a cosmetic bug: every
// control and curve row left its event live on the bench for every row after
// it, which is precisely how an unrelated control ends up in a later row's
// capture window (IW15-004 — see fixedw_correlation_test.go, where an
// IW14-BAT-SMOKE-1 control satisfied BASIC-013's own wire criterion).

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"csip-tls-test/internal/certify"
	"csip-tls-test/sim/gridsim"
)

// cleanupDriver wires a Driver to a real in-process gridsim, so the teardown
// assertions below are about what the SERVER holds afterwards rather than about
// what the client believes it sent.
func cleanupDriver(t *testing.T) *Driver {
	t.Helper()
	srv := httptest.NewServer(gridsim.NewServer(benchLFDI).AdminHandler())
	t.Cleanup(srv.Close)
	return NewDriver(&certify.RunCtx{
		Case:    &certify.Case{UID: "test::cleanup"},
		GridSim: certify.NewAdminClient(srv.URL, http.DefaultClient),
		Targets: certify.Targets{GridSimAdmin: srv.URL},
	})
}

// programControls reports what gridsim itself says is on program p, active and
// scheduled together — the server's own view, not the client's.
func programControls(t *testing.T, d *Driver, p int) []AdminControl {
	t.Helper()
	view := d.Snapshot(context.Background())
	if !view.Available {
		t.Fatal("gridsim's admin status was not reachable")
	}
	for _, prog := range view.Status.Programs {
		if prog.ID == p {
			return append(append([]AdminControl{}, prog.Active...), prog.Scheduled...)
		}
	}
	t.Fatalf("gridsim serves no program %d", p)
	return nil
}

// TestClearControls_ActuallyRemovesTheControl is the direct proof the teardown
// does what its name says. Before the body fix it did nothing at all and said
// nothing about it.
func TestClearControls_ActuallyRemovesTheControl(t *testing.T) {
	d := cleanupDriver(t)
	ctx := context.Background()

	if _, err := d.PostControl(ctx, ControlRequest{
		Program: 0, MRID: "CERT-CLEANUP-1", Description: "cleanup fixture",
		StartOffset: 0, DurationS: 600, MaxLimW: ptr(int64(6000)),
	}); err != nil {
		t.Fatalf("PostControl: %v", err)
	}
	if got := programControls(t, d, 0); len(got) == 0 {
		t.Fatal("gridsim holds no control after PostControl — the fixture never armed anything")
	}

	if err := d.ClearControls(ctx, 0); err != nil {
		t.Fatalf("ClearControls returned %v — the DELETE must carry {\"program\":N} in its BODY, which is "+
			"where gridsim's adminCtrlDelete reads it from; a nil body is answered 400 before any resource "+
			"is touched", err)
	}
	if got := programControls(t, d, 0); len(got) != 0 {
		t.Fatalf("gridsim still holds %d control(s) after ClearControls: %+v — this row's event is live for "+
			"every row that follows it", len(got), got)
	}
	if errs := d.CleanupErrors(); len(errs) != 0 {
		t.Errorf("a successful teardown recorded errors: %v", errs)
	}
}

// TestClearCurves_ActuallyRemovesTheCurveControl is the same proof on the curve
// path, which is the one the sub-audit found first: four BASIC rows and two
// CORE rows publish curve-bound controls, and none of them was ever cleaned up.
func TestClearCurves_ActuallyRemovesTheCurveControl(t *testing.T) {
	d := cleanupDriver(t)
	ctx := context.Background()

	if _, err := d.PostCurve(ctx, CurveRequest{
		Program: 0, Mode: "volt_var", Description: "cleanup fixture",
		Points:      []CurvePoint{{X: 92, Y: 60}, {X: 108, Y: -60}},
		YRefType:    3,
		DurationS:   600,
		StartOffset: 0,
		Activate:    true,
	}); err != nil {
		t.Fatalf("PostCurve: %v", err)
	}
	before := programControls(t, d, 0)
	if len(before) == 0 {
		t.Fatal("gridsim holds no control after PostCurve — the fixture never armed anything")
	}
	var curved bool
	for _, c := range before {
		curved = curved || c.Curve != ""
	}
	if !curved {
		t.Fatalf("no curve-bound control appears in gridsim's own status: %+v", before)
	}

	if err := d.ClearCurves(ctx, 0); err != nil {
		t.Fatalf("ClearCurves returned %v — same defect as ClearControls: gridsim's adminCurveDelete reads "+
			"the program from the request BODY", err)
	}
	if got := programControls(t, d, 0); len(got) != 0 {
		t.Fatalf("gridsim still holds %d control(s) after ClearCurves: %+v", len(got), got)
	}
}

// recordingRT captures the requests a client makes, so a test can assert on
// what went on the wire rather than on the effect at the far end.
type recordingRT struct {
	inner  http.RoundTripper
	method []string
	path   []string
	body   []string
}

func (r *recordingRT) Do(req *http.Request) (*http.Response, error) {
	body := ""
	if req.Body != nil && req.GetBody != nil {
		if rc, err := req.GetBody(); err == nil {
			b, _ := io.ReadAll(rc)
			_ = rc.Close()
			body = string(b)
		}
	}
	r.method = append(r.method, req.Method)
	r.path = append(r.path, req.URL.Path)
	r.body = append(r.body, body)
	return r.inner.RoundTrip(req)
}

// TestClearRequestsCarryTheProgramInTheBody pins the exact shape of the defect
// so it cannot come back in a form the effect-level tests above would miss —
// a future refactor that put the program in a query string again would leave
// those tests passing against a gridsim that had grown a query-string fallback,
// and failing on the bench that had not.
//
// gridsim's own curve_test.go sends the body; this is the client side of the
// same contract.
func TestClearRequestsCarryTheProgramInTheBody(t *testing.T) {
	srv := httptest.NewServer(gridsim.NewServer(benchLFDI).AdminHandler())
	t.Cleanup(srv.Close)
	rec := &recordingRT{inner: http.DefaultTransport}
	d := NewDriver(&certify.RunCtx{
		Case:    &certify.Case{UID: "test::cleanup-body"},
		GridSim: certify.NewAdminClient(srv.URL, rec),
		Targets: certify.Targets{GridSimAdmin: srv.URL},
	})
	ctx := context.Background()
	if err := d.ClearControls(ctx, 2); err != nil {
		t.Fatalf("ClearControls: %v", err)
	}
	if err := d.ClearCurves(ctx, 1); err != nil {
		t.Fatalf("ClearCurves: %v", err)
	}
	if len(rec.body) != 2 {
		t.Fatalf("recorded %d request(s), want 2", len(rec.body))
	}
	for i, want := range []string{`{"program":2}`, `{"program":1}`} {
		if rec.method[i] != http.MethodDelete {
			t.Errorf("request %d method = %s, want DELETE", i, rec.method[i])
		}
		if rec.body[i] != want {
			t.Errorf("request %d (%s) body = %q, want %q — a nil or empty body is decoded as io.EOF and "+
				"answered 400 before gridsim touches any resource, which is the bug this pins dead",
				i, rec.path[i], rec.body[i], want)
		}
		if strings.Contains(rec.path[i], "?") {
			t.Errorf("request %d path = %q still carries a query string; gridsim reads the program from "+
				"the body and a query string is a second, ignored source of truth", i, rec.path[i])
		}
	}
}

// TestCleanupFailureReachesTheRowsNotes is the second half of the fix: a
// teardown that fails must be VISIBLE. It was discarded at every call site
// (`_ = d.ClearControls(...)`), which is why a total failure of the mechanism
// went unnoticed for as long as it existed.
func TestCleanupFailureReachesTheRowsNotes(t *testing.T) {
	// An admin endpoint that refuses everything: the shape of a gridsim that
	// has restarted, or of the 400 the nil body used to produce.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete {
			http.Error(w, "program must be 0, 1, or 2", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"programs":[]}`))
	}))
	t.Cleanup(srv.Close)
	d := NewDriver(&certify.RunCtx{
		Case:    &certify.Case{UID: "test::cleanup-fail"},
		GridSim: certify.NewAdminClient(srv.URL, http.DefaultClient),
		Targets: certify.Targets{GridSimAdmin: srv.URL},
	})
	if err := d.ClearControls(context.Background(), 0); err == nil {
		t.Fatal("a refused teardown returned no error")
	}
	note := cleanupNote(d)
	if note == "" {
		t.Fatal("a failed teardown left no note for the row, so the bundle cannot disclose that the bench " +
			"is not in the state this row believes it left behind")
	}
	for _, want := range []string{"TEARDOWN INCOMPLETE", "program 0", "400"} {
		if !strings.Contains(note, want) {
			t.Errorf("the note does not mention %q: %s", want, note)
		}
	}
	if got := joinNotes("poll-cycle window: 2m30s", note); !strings.HasPrefix(got, "poll-cycle window") ||
		!strings.Contains(got, "TEARDOWN INCOMPLETE") {
		t.Errorf("joinNotes dropped or reordered the row's own prose: %q", got)
	}
	// A bench with no admin API at all has nothing to have leaked, and must not
	// manufacture a note saying otherwise.
	quiet := NewDriver(&certify.RunCtx{Case: &certify.Case{UID: "test::no-admin"}})
	if err := quiet.ClearControls(context.Background(), 0); err != nil {
		t.Errorf("clearing on a bench with no admin API returned %v, want a quiet no-op", err)
	}
	if n := cleanupNote(quiet); n != "" {
		t.Errorf("a run with no gridsim produced a teardown note: %s", n)
	}
}
