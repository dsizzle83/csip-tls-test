package metricscrape

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// fakeDUT is an exposition-format server whose body the test swaps between the
// two readings, which is the only thing a measurement window can actually
// observe about a device. It also stands in for the failure modes: a status
// other than 200, a body that is not the format, and (via Close) an endpoint
// that is simply not there.
type fakeDUT struct {
	mu     sync.Mutex
	body   string
	status int
	srv    *httptest.Server
}

func newFakeDUT(t *testing.T, body string) *fakeDUT {
	t.Helper()
	d := &fakeDUT{body: body, status: http.StatusOK}
	d.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		d.mu.Lock()
		defer d.mu.Unlock()
		if r.URL.Path != DefaultPath {
			// The product serves exactly one route; a scraper that asked for
			// another one and got a 404 should learn so from the status, not by
			// parsing an error page as metrics.
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		w.WriteHeader(d.status)
		_, _ = w.Write([]byte(d.body))
	}))
	t.Cleanup(d.srv.Close)
	return d
}

func (d *fakeDUT) set(body string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.body = body
}

func (d *fakeDUT) setStatus(code int) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.status = code
}

func (d *fakeDUT) endpoint() string { return d.srv.URL }

// window runs one open/close cycle against the fake, swapping the body in
// between, and returns the record.
func window(t *testing.T, d *fakeDUT, closeBody string, sels ...Selector) Record {
	t.Helper()
	src, err := NewHTTPSource(d.endpoint())
	if err != nil {
		t.Fatalf("NewHTTPSource: %v", err)
	}
	s, err := New(src, sels...)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	w := s.Open(context.Background(), "TEST-001")
	d.set(closeBody)
	return w.Close(context.Background())
}

func mustDelta(t *testing.T, rec Record, sel Selector) Delta {
	t.Helper()
	d, ok := rec.Find(sel)
	if !ok {
		t.Fatalf("record has no reading for %s (has %v)", sel, rec.Selectors)
	}
	return d
}

const ignored = ignoredContentMetric

func body(lines ...string) string { return strings.Join(lines, "\n") + "\n" }

// The load-bearing pair: a counter that is present and ZERO throughout is an
// UNCHANGED reading with a real value, and a counter that is not exported at
// all is ABSENT. A scraper that conflated them would let a disclosure oracle
// pass on a gateway that never disclosed anything.
func TestPresentAndZeroIsNotAbsent(t *testing.T) {
	zero := body("# TYPE "+ignored+" counter", ignored+" 0")
	d := newFakeDUT(t, zero)
	rec := window(t, d, zero, Sel(ignored))
	got := mustDelta(t, rec, Sel(ignored))
	if got.Outcome != OutcomeUnchanged {
		t.Fatalf("outcome = %s, want %s (%s)", got.Outcome, OutcomeUnchanged, got.Detail)
	}
	if !got.OpenPresent || !got.ClosePresent {
		t.Error("a zero-valued counter must be recorded as PRESENT at both ends")
	}
	if !got.Sound() || got.Delta != 0 {
		t.Errorf("a present, unmoved counter is a sound zero delta: %+v", got)
	}
	if got.Moved() {
		t.Error("Moved() is true for a counter that did not move")
	}

	// Same window, a counter this DUT does not export at all.
	other := window(t, d, zero, Sel("lexa_nb_no_such_counter_total"))
	abs := mustDelta(t, other, Sel("lexa_nb_no_such_counter_total"))
	if abs.Outcome != OutcomeAbsent {
		t.Fatalf("outcome = %s, want %s", abs.Outcome, OutcomeAbsent)
	}
	if abs.OpenPresent || abs.ClosePresent {
		t.Error("an absent counter must not be recorded as present")
	}
	if abs.Sound() {
		t.Error("an absent counter must not yield a sound delta — that is the reading that would " +
			"let a disclosure oracle pass on a silent DUT")
	}
	if !strings.Contains(abs.Detail, "NOT a reading of zero") {
		t.Errorf("the ABSENT detail must say what it is not: %q", abs.Detail)
	}
}

func TestCounterAdvancesInsideTheWindow(t *testing.T) {
	d := newFakeDUT(t, body("# TYPE "+ignored+" counter", ignored+" 7"))
	rec := window(t, d, body("# TYPE "+ignored+" counter", ignored+" 9"), Sel(ignored))
	got := mustDelta(t, rec, Sel(ignored))
	if got.Outcome != OutcomeIncreased || got.Delta != 2 {
		t.Fatalf("got %+v, want INCREASED by 2", got)
	}
	if !got.Moved() || !got.Sound() {
		t.Error("an increase is both moved and sound")
	}
	if !strings.Contains(got.Observed(), "open=7") || !strings.Contains(got.Observed(), "close=9") {
		t.Errorf("Observed must state the values the delta rests on: %q", got.Observed())
	}
	if rec.Endpoint != d.endpoint()+DefaultPath {
		t.Errorf("endpoint recorded as %q, want the URL actually requested", rec.Endpoint)
	}
	if !strings.Contains(rec.Source(), "TEST-001") || !strings.Contains(rec.Source(), rec.Endpoint) {
		t.Errorf("Source must name the window and the endpoint: %q", rec.Source())
	}
	if rec.Open.BodySHA256 == "" || rec.Close.BodySHA256 == "" {
		t.Error("each reading must digest the body it was taken from")
	}
	if rec.Open.BodySHA256 == rec.Close.BodySHA256 {
		t.Error("two different bodies must not share a digest")
	}
}

// A restart inside the window makes the subtraction meaningless. Reporting it
// as a negative delta — or worse, as UNCHANGED because the numbers happen to
// match after a reset — would be a false reading of the DUT's behaviour.
func TestCounterWentBackwards(t *testing.T) {
	d := newFakeDUT(t, body("# TYPE "+ignored+" counter", ignored+" 41"))
	rec := window(t, d, body("# TYPE "+ignored+" counter", ignored+" 2"), Sel(ignored))
	got := mustDelta(t, rec, Sel(ignored))
	if got.Outcome != OutcomeBackwards {
		t.Fatalf("outcome = %s, want %s", got.Outcome, OutcomeBackwards)
	}
	if got.Delta != 0 || got.Sound() || got.Moved() {
		t.Errorf("a backwards counter must yield no usable delta: %+v", got)
	}
	if got.OpenValue != 41 || got.CloseValue != 2 {
		t.Errorf("both readings must still be recorded: %+v", got)
	}
	if !strings.Contains(got.Detail, "restarted") {
		t.Errorf("the detail must name the cause a reader has to act on: %q", got.Detail)
	}
}

func TestSeriesAppearsAndVanishes(t *testing.T) {
	empty := body("# TYPE lexa_up gauge", "lexa_up 1")
	full := body("# TYPE lexa_up gauge", "lexa_up 1", "# TYPE "+ignored+" counter", ignored+" 3")

	d := newFakeDUT(t, empty)
	app := mustDelta(t, window(t, d, full, Sel(ignored)), Sel(ignored))
	if app.Outcome != OutcomeAppeared {
		t.Fatalf("outcome = %s, want %s", app.Outcome, OutcomeAppeared)
	}
	if app.Sound() {
		t.Error("APPEARED must not be a sound delta: how much of the 3 happened inside the window " +
			"is exactly what is unknown")
	}
	if app.CloseValue != 3 || app.OpenPresent {
		t.Errorf("%+v", app)
	}

	d2 := newFakeDUT(t, full)
	van := mustDelta(t, window(t, d2, empty, Sel(ignored)), Sel(ignored))
	if van.Outcome != OutcomeVanished || van.Sound() {
		t.Fatalf("got %+v, want %s and not sound", van, OutcomeVanished)
	}
}

func TestLabelledSelectorIsolatesOneKind(t *testing.T) {
	open := body(
		"# TYPE "+ignored+" counter",
		ignored+`{kind="autonomous-vref"} 1`,
		ignored+`{kind="target_var"} 5`)
	closed := body(
		"# TYPE "+ignored+" counter",
		ignored+`{kind="autonomous-vref"} 2`,
		ignored+`{kind="target_var"} 40`)

	vref := Sel(ignored).WithLabel("kind", KindAutonomousVRef)
	d := newFakeDUT(t, open)
	rec := window(t, d, closed, vref, Sel(ignored))

	got := mustDelta(t, rec, vref)
	if got.Outcome != OutcomeIncreased || got.Delta != 1 {
		t.Fatalf("labelled reading = %+v, want INCREASED by 1 — not the 34 the other kind moved", got)
	}

	// The same body read through the BARE name is ambiguous, because the name
	// alone now matches two series. Answering it with either one would be
	// choosing which series to believe.
	amb := mustDelta(t, rec, Sel(ignored))
	if amb.Outcome != OutcomeAmbiguous {
		t.Fatalf("bare-name reading = %s, want %s", amb.Outcome, OutcomeAmbiguous)
	}
	if amb.Sound() {
		t.Error("an ambiguous reading is not a sound delta")
	}
}

func TestMalformedBodyIsRecordedNotThrown(t *testing.T) {
	d := newFakeDUT(t, body("# TYPE "+ignored+" counter", ignored+" 1"))
	rec := window(t, d, "lexa_nb_ignored_control_content_total not-a-number\n", Sel(ignored))
	if rec.Close.Status != StatusMalformed {
		t.Fatalf("close status = %s, want %s", rec.Close.Status, StatusMalformed)
	}
	if !strings.Contains(rec.Close.Error, "is not a number") {
		t.Errorf("the parse error must survive into the record: %q", rec.Close.Error)
	}
	if rec.Close.BodyBytes == 0 || rec.Close.BodySHA256 == "" {
		t.Error("a malformed body is still evidence and must still be recorded and digested")
	}
	got := mustDelta(t, rec, Sel(ignored))
	if got.Outcome != OutcomeUnreadable || got.Sound() {
		t.Fatalf("got %+v, want %s", got, OutcomeUnreadable)
	}
	if !strings.Contains(got.Detail, "closing") {
		t.Errorf("the detail must say WHICH end failed: %q", got.Detail)
	}
	if rec.Readable() {
		t.Error("Readable() must be false when a reading did not parse")
	}
}

func TestNonOKStatusIsRecordedNotThrown(t *testing.T) {
	d := newFakeDUT(t, body("# TYPE "+ignored+" counter", ignored+" 1"))
	d.setStatus(http.StatusServiceUnavailable)
	rec := window(t, d, body("# TYPE "+ignored+" counter", ignored+" 1"), Sel(ignored))
	if rec.Open.Status != StatusHTTPStatus || rec.Open.HTTPStatus != http.StatusServiceUnavailable {
		t.Fatalf("open = %+v, want %s carrying 503", rec.Open, StatusHTTPStatus)
	}
	got := mustDelta(t, rec, Sel(ignored))
	if got.Outcome != OutcomeUnreadable {
		t.Fatalf("outcome = %s, want %s", got.Outcome, OutcomeUnreadable)
	}
	if !strings.Contains(got.Detail, "503") {
		t.Errorf("the detail must carry the status a bench operator has to chase: %q", got.Detail)
	}
}

func TestUnreachableEndpointIsRecordedNotThrown(t *testing.T) {
	d := newFakeDUT(t, body("# TYPE "+ignored+" counter", ignored+" 1"))
	src, err := NewHTTPSource(d.endpoint())
	if err != nil {
		t.Fatal(err)
	}
	s, err := New(src, Sel(ignored))
	if err != nil {
		t.Fatal(err)
	}
	d.srv.Close() // the endpoint is gone before the window even opens
	w := s.Open(context.Background(), "TEST-DOWN")
	rec := w.Close(context.Background())

	if rec.Open.Status != StatusUnreachable || rec.Close.Status != StatusUnreachable {
		t.Fatalf("open=%s close=%s, want both %s", rec.Open.Status, rec.Close.Status, StatusUnreachable)
	}
	if rec.Open.Error == "" {
		t.Error("the transport error must be preserved verbatim")
	}
	got := mustDelta(t, rec, Sel(ignored))
	if got.Outcome != OutcomeUnreadable {
		t.Fatalf("outcome = %s, want %s", got.Outcome, OutcomeUnreadable)
	}
	if !strings.Contains(got.Detail, "neither") {
		t.Errorf("both ends failed and the detail should say so: %q", got.Detail)
	}
	// A window against a dead endpoint is still a record: that is the point.
	if len(rec.Series) != 1 || rec.Label != "TEST-DOWN" {
		t.Errorf("a failed window must still produce a complete record: %+v", rec)
	}
}

func TestNonFiniteValueCannotBeSubtracted(t *testing.T) {
	d := newFakeDUT(t, body("# TYPE weird gauge", "weird NaN"))
	rec := window(t, d, body("# TYPE weird gauge", "weird 3"), Sel("weird"))
	got := mustDelta(t, rec, Sel("weird"))
	if got.Outcome != OutcomeNonFinite || got.Sound() {
		t.Fatalf("got %+v, want %s", got, OutcomeNonFinite)
	}
	if got.OpenValue != 0 || got.CloseValue != 0 {
		t.Errorf("non-finite values must not reach the numeric fields (bundle.json cannot encode "+
			"them): %+v", got)
	}
	if !strings.Contains(got.Detail, "NaN") {
		t.Errorf("the literal belongs in the detail: %q", got.Detail)
	}
}

// The re-derivation Verify depends on: the same bodies, run back through the
// same comparison, must give the same readings.
func TestRederiveReproducesTheRecord(t *testing.T) {
	d := newFakeDUT(t, body("# TYPE "+ignored+" counter", ignored+" 1"))
	rec := window(t, d, body("# TYPE "+ignored+" counter", ignored+" 4"), Sel(ignored), Sel("lexa_up"))
	again, err := Rederive(rec)
	if err != nil {
		t.Fatalf("Rederive: %v", err)
	}
	if len(again) != len(rec.Series) {
		t.Fatalf("re-derived %d readings, record has %d", len(again), len(rec.Series))
	}
	for i := range again {
		if again[i] != rec.Series[i] {
			t.Errorf("reading %d re-derives differently:\n got %+v\nwant %+v", i, again[i], rec.Series[i])
		}
	}
	if err := rec.Open.CheckBody(); err != nil {
		t.Errorf("CheckBody on a good reading: %v", err)
	}
	// A record that claims OK over a body that does not parse is the shape of a
	// hand-edited bundle, and must not pass.
	tampered := rec.Open
	tampered.Body = []byte("not exposition format!\n")
	if err := tampered.CheckBody(); err == nil {
		t.Error("CheckBody accepted an OK reading whose body does not parse")
	}
}

func TestNewRefusesOurOwnMistakes(t *testing.T) {
	src := FuncSource{Description: "test", Fn: func(context.Context) (Fetch, error) {
		return Fetch{}, errors.New("never called")
	}}
	if _, err := New(nil, Sel("x")); err == nil {
		t.Error("New accepted a nil source")
	}
	if _, err := New(src); err == nil {
		t.Error("New accepted a scrape that names no counter")
	}
	if _, err := New(src, Selector{Name: "not a name"}); err == nil {
		t.Error("New accepted a malformed selector — it would have read as an absent counter")
	}
	if _, err := New(src, Sel("x"), Sel("x")); err == nil {
		t.Error("New accepted the same selector twice")
	}
}

func TestHTTPSourceResolvesTheEndpointSpellings(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"69.0.0.2:9102", "http://69.0.0.2:9102/metrics"},
		{"69.0.0.2:9102/metrics", "http://69.0.0.2:9102/metrics"},
		{"http://69.0.0.2:9102", "http://69.0.0.2:9102/metrics"},
		{"http://127.0.0.1:9102/metrics", "http://127.0.0.1:9102/metrics"},
		{" 69.0.0.2:9102 ", "http://69.0.0.2:9102/metrics"},
	} {
		s, err := NewHTTPSource(tc.in)
		if err != nil {
			t.Fatalf("NewHTTPSource(%q): %v", tc.in, err)
		}
		if s.Describe() != tc.want {
			t.Errorf("NewHTTPSource(%q) = %q, want %q", tc.in, s.Describe(), tc.want)
		}
	}
	if _, err := NewHTTPSource(""); err == nil {
		t.Error("NewHTTPSource accepted an empty endpoint")
	}
}

// A non-HTTP transport — the ssh-forward or run-a-reader-on-the-DUT case the
// loopback default forces — must need nothing from this package but a Source.
func TestFuncSourceCarriesAnArbitraryTransport(t *testing.T) {
	bodies := []string{
		body("# TYPE "+ignored+" counter", ignored+" 0"),
		body("# TYPE "+ignored+" counter", ignored+" 1"),
	}
	n := 0
	src := FuncSource{
		Description: "ssh cc93 -- lexa-metrics-reader",
		Fn: func(context.Context) (Fetch, error) {
			b := bodies[n]
			n++
			return Fetch{Body: []byte(b)}, nil
		},
	}
	s, err := New(src, Sel(ignored))
	if err != nil {
		t.Fatal(err)
	}
	rec := s.Open(context.Background(), "SSH-1").Close(context.Background())
	if rec.Endpoint != "ssh cc93 -- lexa-metrics-reader" {
		t.Errorf("endpoint = %q", rec.Endpoint)
	}
	got := mustDelta(t, rec, Sel(ignored))
	if got.Outcome != OutcomeIncreased || got.Delta != 1 {
		t.Fatalf("got %+v", got)
	}
	// No HTTP status exists for this transport, and inventing a 200 would be a
	// claim nobody made.
	if rec.Open.HTTPStatus != 0 {
		t.Errorf("a non-HTTP source must record no HTTP status, got %d", rec.Open.HTTPStatus)
	}
}

// TestNewSSHSource_FetchesThroughTheRunner is IW27-004's unit-level proof: the
// Source built by NewSSHSource must read its body from the Runner's stdout, by
// running wget against the given URL, and must record the URL (not a bare
// "ssh" description) so a bundle reader can see what was actually asked for.
func TestNewSSHSource_FetchesThroughTheRunner(t *testing.T) {
	const url = "http://127.0.0.1:9102/metrics"
	var gotArgs []string
	run := func(_ context.Context, args ...string) ([]byte, error) {
		gotArgs = append([]string(nil), args...)
		return []byte(body("# TYPE "+ignored+" counter", ignored+" 3")), nil
	}
	src := NewSSHSource(run, url)
	if !strings.Contains(src.Describe(), url) {
		t.Errorf("Describe() = %q, want it to name the endpoint %q", src.Describe(), url)
	}
	f, err := src.Fetch(context.Background())
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if len(gotArgs) != 3 || gotArgs[0] != "wget" || gotArgs[2] != url {
		t.Errorf("runner args = %v, want [wget -qO- %s]", gotArgs, url)
	}
	if !strings.Contains(string(f.Body), ignored) {
		t.Errorf("Fetch body = %q, want the runner's stdout", f.Body)
	}
	if f.HTTPStatus != http.StatusOK {
		t.Errorf("HTTPStatus = %d, want 200 (wget only returns on success — see the doc comment's caveat)",
			f.HTTPStatus)
	}
}

// A Runner failure (wget exits non-zero: connection refused, timeout, ssh
// itself failing, or the DUT answering non-200) must come back as a Fetch
// error, so scrape.go's read() classifies it StatusUnreachable rather than a
// panic or a fabricated empty-but-OK reading.
func TestNewSSHSource_RunnerFailureIsAFetchError(t *testing.T) {
	wantErr := errors.New("ssh: connect to host cc93 port 22: Connection refused")
	run := func(context.Context, ...string) ([]byte, error) { return nil, wantErr }
	src := NewSSHSource(run, "http://127.0.0.1:9102/metrics")
	if _, err := src.Fetch(context.Background()); !errors.Is(err, wantErr) {
		t.Errorf("Fetch err = %v, want %v", err, wantErr)
	}
}
