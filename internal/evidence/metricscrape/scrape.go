package metricscrape

// scrape.go is the measurement window: two readings of the same named series,
// and an honest account of everything that could have gone wrong between them.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// DefaultPath is the route every lexa service serves its registry on
// (lexa-platform/metrics.Serve; lexa-api mounts the same handler at the same
// path on its ordinary listener, cmd/api/main.go:447).
const DefaultPath = "/metrics"

// NorthboundMetricsPort is lexa-northbound's Prometheus port: 9102, from
// lexa-gw cmd/northbound/config.go:440-442 (default "127.0.0.1:9102") and
// configs/northbound.json:13. It is loopback in the product default and bound
// to the LAN IP on this bench (docs/BENCH.md §Metrics, AD-008), which is a
// deployment choice — the PORT is the part that is the same either way, so the
// port is what is named here and the host is the caller's.
const NorthboundMetricsPort = 9102

// maxBodyBytes caps one scrape. The DUT's whole registry is a few kilobytes
// (~40 series, no histograms); a body orders of magnitude larger than that is
// not this endpoint answering, and reading it into an evidence bundle would be
// the harness's problem rather than the DUT's.
const maxBodyBytes = 4 << 20

// defaultTimeout bounds one scrape when the caller sets none.
const defaultTimeout = 5 * time.Second

// Fetch is one transport-level result: whatever came back, plus the HTTP status
// when the transport has one.
//
// The Body is kept even for a non-200, because an unexpected body IS the
// evidence about what answered — a 404 page from the wrong service on a reused
// port says far more than "non-200" alone.
type Fetch struct {
	Body       []byte
	HTTPStatus int // 0 when the transport has no status code
}

// Source is where an exposition body comes from.
//
// It is an interface so that the two ways to reach a loopback-bound endpoint —
// an ssh local forward (still a plain HTTP GET, so still HTTPSource) and
// shelling a reader out onto the DUT (FuncSource over an SSH runner) — are both
// expressible without this package knowing anything about ssh.
type Source interface {
	// Fetch reads the exposition body once. A transport failure is returned as
	// an error and becomes StatusUnreachable in the record; it is not a panic
	// and never aborts the window.
	Fetch(ctx context.Context) (Fetch, error)
	// Describe names the source in the evidence — a URL, or a command line.
	Describe() string
}

// HTTPSource scrapes a plain-HTTP endpoint.
//
// Plain HTTP is not an oversight: the DUT's endpoint has no TLS and no
// authentication (see the package doc's endpoint section for the file:line
// provenance). If that ever changes, this is the type that grows a client
// configuration; nothing else in the package knows the transport.
type HTTPSource struct {
	// URL is the fully-resolved endpoint, as returned by Describe.
	URL string
	// Client is the HTTP client; nil uses a package default with no keep-alive
	// (an evidence scrape is two requests minutes apart — a pooled connection
	// held across the window is a socket the DUT is keeping open on our
	// account, and reconnecting proves the endpoint is still answering at
	// close rather than that a stale connection is).
	Client *http.Client
}

// NewHTTPSource resolves an endpoint written any of the ways an operator writes
// one — "69.0.0.2:9102", "69.0.0.2:9102/metrics", "http://69.0.0.2:9102/metrics"
// — into one URL, so that the string a bundle records is the string that was
// actually requested.
func NewHTTPSource(endpoint string) (*HTTPSource, error) {
	e := strings.TrimSpace(endpoint)
	if e == "" {
		return nil, fmt.Errorf("metricscrape: no metrics endpoint given")
	}
	if !strings.Contains(e, "://") {
		e = "http://" + e
	}
	u, err := url.Parse(e)
	if err != nil {
		return nil, fmt.Errorf("metricscrape: %q is not a metrics endpoint: %w", endpoint, err)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("metricscrape: %q names no host", endpoint)
	}
	if u.Path == "" || u.Path == "/" {
		u.Path = DefaultPath
	}
	return &HTTPSource{URL: u.String()}, nil
}

// Describe returns the URL that will be requested.
func (h *HTTPSource) Describe() string { return h.URL }

// Fetch performs the GET.
func (h *HTTPSource) Fetch(ctx context.Context) (Fetch, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, h.URL, nil)
	if err != nil {
		return Fetch{}, err
	}
	// Ask for the format we parse. The DUT's handler ignores Accept and always
	// writes text/plain 0.0.4, but a scraper that does not say what it wants
	// has no complaint if something else answers.
	req.Header.Set("Accept", "text/plain;version=0.0.4")
	c := h.Client
	if c == nil {
		c = defaultHTTPClient
	}
	resp, err := c.Do(req)
	if err != nil {
		return Fetch{}, err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes+1))
	if err != nil {
		return Fetch{HTTPStatus: resp.StatusCode}, err
	}
	if len(body) > maxBodyBytes {
		return Fetch{HTTPStatus: resp.StatusCode, Body: body[:maxBodyBytes]},
			fmt.Errorf("body exceeds %d bytes", maxBodyBytes)
	}
	return Fetch{Body: body, HTTPStatus: resp.StatusCode}, nil
}

var defaultHTTPClient = &http.Client{
	Transport: &http.Transport{DisableKeepAlives: true},
}

// FuncSource adapts any body-producing function into a Source: an ssh command,
// a file the operator captured out of band, a test fake.
type FuncSource struct {
	// Description is what the bundle records as the endpoint.
	Description string
	Fn          func(ctx context.Context) (Fetch, error)
}

// Describe returns the caller's description.
func (f FuncSource) Describe() string { return f.Description }

// Fetch calls the function.
func (f FuncSource) Fetch(ctx context.Context) (Fetch, error) { return f.Fn(ctx) }

// Status is how one READING went — the transport half of the outcome.
type Status string

// The reading statuses. Each is a different thing to have gone wrong, and a
// criterion may legitimately grade them differently (an unreachable endpoint is
// a bench fault; a 200 carrying HTML is somebody else answering on that port).
const (
	// StatusOK — a 200 whose body parsed.
	StatusOK Status = "OK"
	// StatusUnreachable — the transport never produced a usable response:
	// connection refused, DNS failure, timeout, ssh error, or a body too large
	// to be this endpoint's (the read is capped; see maxBodyBytes). Error
	// carries the transport's own words, which is where the distinction lives.
	StatusUnreachable Status = "UNREACHABLE"
	// StatusHTTPStatus — something answered, with a status other than 200.
	StatusHTTPStatus Status = "HTTP-STATUS"
	// StatusMalformed — a 200 whose body is not the exposition format. The
	// body is still recorded; Error says which line failed.
	StatusMalformed Status = "MALFORMED"
)

// Outcome is what a whole window says about ONE selector.
type Outcome string

// The outcomes. The vocabulary is deliberately wider than "up/down": each value
// is a distinct fact, and collapsing any two of them would let a criterion pass
// on a run that did not establish what it claims.
const (
	// OutcomeIncreased — present at both ends, close > open. For the
	// ignored-content family this is the observable that says the disclosure
	// happened inside the window.
	OutcomeIncreased Outcome = "INCREASED"
	// OutcomeUnchanged — present at both ends, close == open. The counter
	// exists and did not move: a NEGATIVE observation, and a sound one.
	OutcomeUnchanged Outcome = "UNCHANGED"
	// OutcomeAbsent — no such series at either end. NOT zero: see the package
	// doc. Nothing can be concluded about the behaviour the counter would have
	// reported, only about the DUT's instrumentation.
	OutcomeAbsent Outcome = "ABSENT"
	// OutcomeAppeared — absent at open, present at close. Its value is not a
	// delta: the series was not being exported when the window opened, so how
	// much of it happened inside the window is unknown. (lexa-platform's
	// registry registers a counter the first time its Collect hook runs, so on
	// that DUT this is the shape of "the first scrape of a freshly restarted
	// process", not a normal reading.)
	OutcomeAppeared Outcome = "APPEARED"
	// OutcomeVanished — present at open, absent at close. The endpoint stopped
	// exporting the series mid-window; whatever the delta would have been is
	// not recoverable.
	OutcomeVanished Outcome = "VANISHED"
	// OutcomeBackwards — present at both ends, close < open. A monotonic
	// counter cannot decrease, so the process behind it restarted (or the port
	// is now answered by a different one) and the SUBTRACTION IS MEANINGLESS —
	// which is exactly why it is not reported as a negative delta.
	OutcomeBackwards Outcome = "BACKWARDS"
	// OutcomeAmbiguous — the selector matched more than one series at one of
	// the ends. Naming the reading would mean choosing which series to believe.
	OutcomeAmbiguous Outcome = "AMBIGUOUS"
	// OutcomeNonFinite — the matched series carried NaN or ±Inf. Legal in the
	// format, meaningless as a counter, and unrepresentable in JSON, so the
	// literal is preserved in Detail and the numeric fields stay zero.
	OutcomeNonFinite Outcome = "NON-FINITE"
	// OutcomeUnreadable — one or both readings did not produce a parsed body,
	// so nothing at all is known about this series. Read the ScrapeResult for
	// which end failed and why.
	OutcomeUnreadable Outcome = "UNREADABLE"
)

// ScrapeResult is one reading of the endpoint.
//
// It carries the raw Body in memory but NOT into bundle.json: the body is
// written into the bundle as its own artefact and covered by the manifest, and
// BodyFile/BodySHA256 are the link between the summary and the bytes it was
// derived from. bundle.Verify re-parses that file and re-derives every value in
// the record from it, so a record whose numbers do not follow from its own
// recorded body fails verification.
type ScrapeResult struct {
	At         time.Time `json:"at"`
	Status     Status    `json:"status"`
	HTTPStatus int       `json:"http_status,omitempty"`
	// Error is the reason for any status other than OK, verbatim.
	Error string `json:"error,omitempty"`
	// BodyBytes and BodySHA256 describe the body as read, whether or not it
	// parsed.
	BodyBytes  int    `json:"body_bytes"`
	BodySHA256 string `json:"body_sha256,omitempty"`
	// BodyFile is where the body was written inside the evidence bundle,
	// relative to the bundle directory. It is filled in by the bundle writer,
	// which is what decides the layout; empty in a record that has not been
	// written into a bundle.
	BodyFile string `json:"body_file,omitempty"`
	// Body is the bytes themselves, for the bundle writer. json:"-" because
	// bundle.json is a summary and the body is an artefact — inlining a
	// kilobyte of exposition text per reading into the summary would make the
	// document unreadable and duplicate the artefact it points at.
	Body []byte `json:"-"`
}

// OK reports whether this reading produced a parsed body.
func (r ScrapeResult) OK() bool { return r.Status == StatusOK }

// Delta is one selector's result across the window.
type Delta struct {
	// Selector is the rendered selector (Selector.String), the stable key a
	// criterion looks a reading up by.
	Selector string  `json:"selector"`
	Outcome  Outcome `json:"outcome"`
	// OpenPresent/ClosePresent are the load-bearing pair: false is "the DUT
	// does not export this series", which is NOT the same fact as a Value of 0.
	OpenPresent  bool    `json:"open_present"`
	OpenValue    float64 `json:"open_value"`
	ClosePresent bool    `json:"close_present"`
	CloseValue   float64 `json:"close_value"`
	// Delta is close − open, and is meaningful ONLY when Sound reports true.
	// It is zero in every other outcome so that a caller which ignores Outcome
	// gets the harmless answer rather than a plausible one.
	Delta float64 `json:"delta"`
	// Detail says, in prose, what a reader needs in order not to over-read the
	// outcome. Always set for anything other than INCREASED/UNCHANGED.
	Detail string `json:"detail,omitempty"`
}

// Sound reports whether Delta is a number anything may be concluded from: the
// series was present at both ends and did not go backwards.
func (d Delta) Sound() bool { return d.Outcome == OutcomeIncreased || d.Outcome == OutcomeUnchanged }

// Moved reports whether the counter demonstrably advanced inside the window.
// This is the positive observable — the one a disclosure criterion asserts on.
func (d Delta) Moved() bool { return d.Outcome == OutcomeIncreased }

// Observed renders the reading for an assertion's Observed field: one sentence
// that states the outcome AND the values it rests on, so a reader never has to
// open bundle.json to know whether a zero was a zero or an absence.
func (d Delta) Observed() string {
	val := func(present bool, v float64) string {
		if !present {
			return "absent"
		}
		return strconv.FormatFloat(v, 'g', -1, 64)
	}
	s := fmt.Sprintf("%s: %s (open=%s, close=%s)", d.Selector, d.Outcome,
		val(d.OpenPresent, d.OpenValue), val(d.ClosePresent, d.CloseValue))
	if d.Sound() {
		s += fmt.Sprintf(", delta=%s", strconv.FormatFloat(d.Delta, 'g', -1, 64))
	}
	if d.Detail != "" {
		s += " — " + d.Detail
	}
	return s
}

// Record is one window's evidence: what was asked for, both readings, and what
// each selector did. It is what goes into bundle.json.
type Record struct {
	// Label names the window. It is the case UID in a conformance run, and it
	// is also what the bundle's artefact filenames are derived from, so two
	// windows in one run must not share one.
	Label string `json:"label"`
	// Endpoint is Source.Describe() — the URL or command the readings came
	// from.
	Endpoint string `json:"endpoint"`
	// Selectors are the series that were asked for, rendered, in the order
	// they were asked for.
	Selectors []string     `json:"selectors"`
	Open      ScrapeResult `json:"open"`
	Close     ScrapeResult `json:"close"`
	Series    []Delta      `json:"series"`
}

// Find returns the reading for a selector.
func (r Record) Find(sel Selector) (Delta, bool) { return r.FindKey(sel.String()) }

// FindKey returns the reading for a rendered selector key.
func (r Record) FindKey(key string) (Delta, bool) {
	for _, d := range r.Series {
		if d.Selector == key {
			return d, true
		}
	}
	return Delta{}, false
}

// Readable reports whether both ends produced a parsed body. When it is false,
// every Delta in the record is OutcomeUnreadable and the record's evidentiary
// value is the RECORD OF THE FAILURE, which is still worth having.
func (r Record) Readable() bool { return r.Open.OK() && r.Close.OK() }

// Source renders the provenance line for an assertion's source field. It names
// the endpoint and both instants deliberately: a counter delta means nothing
// without the window it was measured over, and a bundle that printed only the
// number would be inviting the reader to over-read it.
func (r Record) Source() string {
	return fmt.Sprintf("DUT metrics scrape of %s over window %q (%s → %s)",
		r.Endpoint, r.Label, stamp(r.Open.At), stamp(r.Close.At))
}

// stamp renders a window bound to the millisecond rather than the second the
// rest of the bundle's prose uses. The extra digits are not decoration: a
// window whose two readings landed in the same second is one where the
// stimulus may not have finished before the closing scrape, and a reader who
// cannot see that cannot question it. Full precision is in bundle.json either
// way.
func stamp(t time.Time) string {
	if t.IsZero() {
		return "—"
	}
	return t.UTC().Format("2006-01-02T15:04:05.000Z07:00")
}

// Rederive recomputes a record's Series from the bodies its two ScrapeResults
// carry, using the selector keys the record itself recorded.
//
// This is the third-party-checkable half of the channel. bundle.Verify reloads
// each reading's body from the artefact file in the bundle, re-hashes it, hands
// the record back here, and compares field for field: a record whose numbers do
// not FOLLOW from the exposition text shipped beside them fails verification.
// The comparison logic is not duplicated for that purpose — this runs the same
// compare the window ran, which is the only way the re-check can be worth
// anything.
//
// It returns an error only when a recorded selector key is not a selector,
// which means the bundle was hand-edited: an authoring path cannot produce one.
func Rederive(rec Record) ([]Delta, error) {
	out := make([]Delta, 0, len(rec.Selectors))
	for _, key := range rec.Selectors {
		sel, err := ParseSelector(key)
		if err != nil {
			return nil, err
		}
		out = append(out, compare(sel, rec.Open, rec.Close))
	}
	return out, nil
}

// CheckBody reports whether a reading's recorded Status is consistent with the
// body recorded beside it.
//
// Only two of the four statuses are checkable from a file: a reading that
// claims OK must carry a body that parses, and one that claims MALFORMED must
// carry a body that does not. UNREACHABLE and HTTP-STATUS are facts about a
// transport that no longer exists by the time anybody verifies, and this says
// so by checking nothing rather than by inventing a check.
func (r ScrapeResult) CheckBody() error {
	switch r.Status {
	case StatusOK:
		if _, err := Parse(r.Body); err != nil {
			return fmt.Errorf("reading is recorded %s but its body does not parse: %w", StatusOK, err)
		}
	case StatusMalformed:
		if _, err := Parse(r.Body); err == nil {
			return fmt.Errorf("reading is recorded %s but its body parses cleanly", StatusMalformed)
		}
	}
	return nil
}

// Scraper reads a fixed set of selectors from one source.
type Scraper struct {
	// Timeout bounds ONE reading; zero uses defaultTimeout. It is per-reading,
	// not per-window: a window is held open by the test, not by this package.
	Timeout time.Duration

	src  Source
	sels []Selector
}

// New builds a scraper for the named selectors.
//
// It returns an error only for faults that are OURS — no source, no selectors,
// a selector that is not a well-formed metric name. Everything that can go
// wrong with the DUT or the network is recorded, not returned: see the package
// doc.
func New(src Source, sels ...Selector) (*Scraper, error) {
	if src == nil {
		return nil, fmt.Errorf("metricscrape: no source")
	}
	if len(sels) == 0 {
		return nil, fmt.Errorf("metricscrape: no selectors — a scrape that names no counter " +
			"would record a body nobody asked a question of")
	}
	seen := map[string]bool{}
	for _, s := range sels {
		if err := s.Validate(); err != nil {
			return nil, err
		}
		k := s.String()
		if seen[k] {
			return nil, fmt.Errorf("metricscrape: selector %s named twice", k)
		}
		seen[k] = true
	}
	return &Scraper{src: src, sels: append([]Selector(nil), sels...)}, nil
}

// Endpoint is what the readings will be taken from.
func (s *Scraper) Endpoint() string { return s.src.Describe() }

// Window is an open measurement window: the opening reading, held until Close
// takes the second one.
type Window struct {
	s     *Scraper
	label string
	open  ScrapeResult
}

// Open takes the first reading and returns the window.
//
// It cannot fail. An endpoint that is down at open produces a window whose
// Close returns a record full of OutcomeUnreadable — which is a true statement
// about the run, and is what a criterion should grade on. Aborting here would
// leave the run with no evidence of why.
func (s *Scraper) Open(ctx context.Context, label string) *Window {
	return &Window{s: s, label: label, open: s.read(ctx)}
}

// OpenResult exposes the opening reading before the window closes, for a caller
// that wants to log or abort early on an endpoint that is already unreachable.
func (w *Window) OpenResult() ScrapeResult { return w.open }

// Close takes the second reading and returns the window's record.
func (w *Window) Close(ctx context.Context) Record {
	closeRes := w.s.read(ctx)
	rec := Record{
		Label:    w.label,
		Endpoint: w.s.src.Describe(),
		Open:     w.open,
		Close:    closeRes,
	}
	for _, sel := range w.s.sels {
		rec.Selectors = append(rec.Selectors, sel.String())
		rec.Series = append(rec.Series, compare(sel, w.open, closeRes))
	}
	return rec
}

// read takes one reading, classifying every failure rather than returning it.
func (s *Scraper) read(ctx context.Context) ScrapeResult {
	to := s.Timeout
	if to <= 0 {
		to = defaultTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, to)
	defer cancel()

	res := ScrapeResult{At: time.Now().UTC()}
	f, err := s.src.Fetch(ctx)
	res.HTTPStatus = f.HTTPStatus
	res.Body = f.Body
	res.BodyBytes = len(f.Body)
	if len(f.Body) > 0 {
		sum := sha256.Sum256(f.Body)
		res.BodySHA256 = hex.EncodeToString(sum[:])
	}
	switch {
	case err != nil:
		res.Status = StatusUnreachable
		res.Error = err.Error()
		return res
	case f.HTTPStatus != 0 && f.HTTPStatus != http.StatusOK:
		res.Status = StatusHTTPStatus
		res.Error = fmt.Sprintf("endpoint answered HTTP %d", f.HTTPStatus)
		return res
	}
	if _, perr := Parse(f.Body); perr != nil {
		res.Status = StatusMalformed
		res.Error = perr.Error()
		return res
	}
	res.Status = StatusOK
	return res
}

// reading is one end's answer for one selector, after parsing.
type reading struct {
	present bool
	value   float64
	matches int
}

// readingFor resolves a selector against one already-parsed body. It returns an
// error only for a body that will not parse, which the caller has already
// classified — it is re-parsed here rather than cached so that VERIFY, which
// has only the file, runs the identical code path this did.
func readingFor(sel Selector, res ScrapeResult) (reading, error) {
	e, err := Parse(res.Body)
	if err != nil {
		return reading{}, err
	}
	got := e.Select(sel)
	switch len(got) {
	case 0:
		return reading{matches: 0}, nil
	default:
		return reading{present: len(got) == 1, value: got[0].Value, matches: len(got)}, nil
	}
}

// compare turns two readings into one Delta, applying the outcome table in the
// order that keeps the most specific failure visible: an unreadable end hides
// everything below it, an ambiguous match cannot be valued, a non-finite value
// cannot be subtracted, and only then do presence and direction decide.
func compare(sel Selector, openRes, closeRes ScrapeResult) Delta {
	d := Delta{Selector: sel.String()}

	if !openRes.OK() || !closeRes.OK() {
		d.Outcome = OutcomeUnreadable
		switch {
		case !openRes.OK() && !closeRes.OK():
			d.Detail = fmt.Sprintf("neither reading is usable (open: %s — %s; close: %s — %s)",
				openRes.Status, openRes.Error, closeRes.Status, closeRes.Error)
		case !openRes.OK():
			d.Detail = fmt.Sprintf("the opening reading is not usable (%s — %s)", openRes.Status, openRes.Error)
		default:
			d.Detail = fmt.Sprintf("the closing reading is not usable (%s — %s)", closeRes.Status, closeRes.Error)
		}
		return d
	}

	o, oerr := readingFor(sel, openRes)
	c, cerr := readingFor(sel, closeRes)
	if oerr != nil || cerr != nil {
		// Unreachable in practice — both bodies parsed once already, in read —
		// but a silent misreading here would be the worst kind, so it is stated.
		d.Outcome = OutcomeUnreadable
		d.Detail = fmt.Sprintf("a recorded body stopped parsing between reading and comparison (open: %v, close: %v)", oerr, cerr)
		return d
	}

	if o.matches > 1 || c.matches > 1 {
		d.Outcome = OutcomeAmbiguous
		d.Detail = fmt.Sprintf("the selector matches %d series at open and %d at close; "+
			"a reading would have to choose which one to believe", o.matches, c.matches)
		return d
	}

	d.OpenPresent, d.ClosePresent = o.present, c.present
	switch {
	case !o.present && !c.present:
		d.Outcome = OutcomeAbsent
		d.Detail = "the endpoint exports no such series — this is NOT a reading of zero, and says " +
			"nothing about the behaviour the counter would have reported"
		return d
	case o.present && nonFinite(o.value), c.present && nonFinite(c.value):
		d.Outcome = OutcomeNonFinite
		d.Detail = fmt.Sprintf("the series carries a non-finite value (open %s, close %s), which no "+
			"subtraction can use", literal(o), literal(c))
		return d
	}

	d.OpenValue, d.CloseValue = o.value, c.value
	switch {
	case !o.present:
		d.Outcome = OutcomeAppeared
		d.OpenValue = 0
		d.Detail = fmt.Sprintf("absent when the window opened and %s at close, so how much of it "+
			"happened inside the window is unknown", strconv.FormatFloat(c.value, 'g', -1, 64))
	case !c.present:
		d.Outcome = OutcomeVanished
		d.CloseValue = 0
		d.Detail = "present when the window opened and gone at close; the endpoint stopped exporting it mid-window"
	case c.value < o.value:
		d.Outcome = OutcomeBackwards
		d.Detail = fmt.Sprintf("a monotonic counter went backwards (%s → %s): the process behind it "+
			"restarted inside the window, so the difference is not a delta",
			strconv.FormatFloat(o.value, 'g', -1, 64), strconv.FormatFloat(c.value, 'g', -1, 64))
	case c.value == o.value:
		d.Outcome = OutcomeUnchanged
	default:
		d.Outcome = OutcomeIncreased
		d.Delta = c.value - o.value
	}
	return d
}

func nonFinite(v float64) bool { return math.IsNaN(v) || math.IsInf(v, 0) }

func literal(r reading) string {
	if !r.present {
		return "absent"
	}
	return strconv.FormatFloat(r.value, 'g', -1, 64)
}
