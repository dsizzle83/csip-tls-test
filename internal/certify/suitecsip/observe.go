package suitecsip

// observe.go is the live phase: the levers this suite pulls on the bench's
// 2030.5 server, and the server-side observations it collects while waiting for
// the DUT to notice.
//
// # The shape of every CSIP check
//
// The DUT dials out on its own schedule, so a check cannot make it do anything
// directly. It can only change what the DUT will find, and then wait. Waiting
// is the expensive part and the part that goes wrong quietly, so the Driver
// makes three things explicit:
//
//	1. WHAT it is waiting for is a predicate over the SERVER's own view, not a
//	   sleep. "The DUT has POSTed a Response for mRID X" is checkable; "wait 90
//	   seconds and hope" is not.
//	2. HOW LONG it waited is returned and printed, so a bundle reader can tell a
//	   conformant-but-slow DUT from a non-conformant one.
//	3. WHAT WAS ALREADY THERE is captured first. gridsim accumulates Responses,
//	   DER PUTs and LogEvents across the whole campaign; a check that counted
//	   them absolutely would pass on evidence another agent's check produced.
//	   Every wait is therefore expressed against a BASELINE taken at the start.
//
// # The backoff trap
//
// The gateway backs off to a 15-minute retry after sustained northbound
// failure. Any check that arms a fault must bound it (duration_s) or clear it
// before waiting for recovery, or it is measuring backoff state rather than
// conformance. Driver.Arm* all take a bounded duration for exactly that reason,
// and Driver.ClearFaults is safe to call unconditionally.

import (
	"bufio"
	"context"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"csip-tls-test/internal/certify"
)

// pollInterval is how often a wait re-reads the server's view. It is short
// relative to the DUT's poll cycle (minutes) but long enough not to hammer a
// shared bench.
const pollInterval = 3 * time.Second

// logTailBudget bounds the SSE read of gridsim's request log. The endpoint
// replays its backlog immediately and then streams forever, so a reader must
// take the backlog and let go.
const logTailBudget = 2 * time.Second

// ServerRequest is one line of gridsim's request log: what the DUT asked for,
// as the server recorded it.
type ServerRequest struct {
	// At is the log line's own timestamp when the line carried one. It is the
	// SERVER's clock, not the capture's, and is therefore never used for a
	// timing criterion — only for ordering and for reporting.
	At     time.Time
	Method string
	Path   string
	Peer   string
	Raw    string
}

// AdminResponse mirrors gridsim's GET /admin/responses entry.
type AdminResponse struct {
	Subject string `json:"subject"`
	Status  uint8  `json:"status"`
	LFDI    string `json:"lfdi"`
}

// AdminDERPut mirrors gridsim's GET /admin/derputs entry.
type AdminDERPut struct {
	Path       string `json:"path"`
	Resource   string `json:"resource"`
	Body       string `json:"body"`
	ReceivedAt int64  `json:"received_at"`
}

// AdminControl mirrors one control in gridsim's GET /admin/status.
type AdminControl struct {
	MRID        string `json:"mrid"`
	Description string `json:"description"`
	Start       int64  `json:"start"`
	DurationS   int    `json:"duration_s"`
	Status      int    `json:"status"`
	Curve       string `json:"curve,omitempty"`
}

// AdminProgram mirrors one program in gridsim's GET /admin/status.
type AdminProgram struct {
	ID          int            `json:"id"`
	MRID        string         `json:"mrid"`
	Description string         `json:"description"`
	Primacy     int            `json:"primacy"`
	Active      []AdminControl `json:"active"`
	Scheduled   []AdminControl `json:"scheduled"`
}

// AdminStatus mirrors gridsim's GET /admin/status.
type AdminStatus struct {
	Programs   []AdminProgram `json:"programs"`
	ServerTime int64          `json:"server_time"`

	// Fleet and Subscription are the two DER AGGREGATOR CLIENT capabilities the
	// simulator can be started with. They are read, not assumed, and that is
	// the whole point of them being on the wire: a run against a bench without
	// the fixture and a run against a bench with it are different measurements,
	// and nothing else in the capture distinguishes them.
	Fleet        AdminFleetStatus        `json:"fleet"`
	Subscription AdminSubscriptionStatus `json:"subscription"`
}

// AdminFleetStatus mirrors the fleet block of gridsim's GET /admin/status.
type AdminFleetStatus struct {
	Enabled        bool     `json:"enabled"`
	Size           int      `json:"size"`
	Devices        []string `json:"devices,omitempty"`
	AggregatorHref string   `json:"aggregator_href,omitempty"`
}

// AdminSubscriptionStatus mirrors the subscription block of GET /admin/status.
type AdminSubscriptionStatus struct {
	Enabled       bool `json:"enabled"`
	Subscriptions int  `json:"subscriptions"`
	Notifications int  `json:"notifications"`
}

// AdminSubscription mirrors one entry of gridsim's GET /admin/subscriptions.
//
// NotificationURI is the field that matters here and it is the reason the
// endpoint is read at all: a Notification arrives on a connection the SERVER
// dials to an address only the DUT knows, and this is where the server — which
// was told — publishes it.
type AdminSubscription struct {
	ID                 int    `json:"id"`
	Href               string `json:"href"`
	EndDevice          string `json:"end_device"`
	SubscribedResource string `json:"subscribed_resource"`
	NotificationURI    string `json:"notification_uri"`
	// Limit is the <limit> the DUT asked for. MAINT-001's pass criterion is
	// explicit that "the notification resource body for the EndDeviceList was
	// correctly formed using the limit parameter requested by the Client in the
	// original subscription request", so the number the client asked for has to
	// travel with the subscription for that to be checkable at all.
	Limit         uint32 `json:"limit,omitempty"`
	Notifications int    `json:"notifications"`
}

// AdminFleetDevice mirrors one entry of gridsim's GET /admin/fleet.
//
// LFDI is why this endpoint is read at all. Every per-EndDevice pass criterion
// of the CTP's aggregator rows is stated about a device by its CTP NAME ("for
// EDA1 and EDA2, POSTs response with status 2"), and the only thing that name
// corresponds to on the wire is the <endDeviceLFDI> of a Response POST. The
// mapping between the two is a fact the SERVER holds — it derived the four
// LFDIs when it built the fixture — and nothing in the capture states it. A
// harness that guessed it from /edev ordering would be asserting a bench
// convention; this reads it from the party that decided it.
type AdminFleetDevice struct {
	Name      string   `json:"name"`
	Node      string   `json:"node"`
	Href      string   `json:"href"`
	LFDI      string   `json:"lfdi"`
	SFDI      uint64   `json:"sfdi"`
	PIN       uint32   `json:"pin"`
	ManagedBy string   `json:"managed_by"`
	Programs  []string `json:"programs"`
}

// AdminNotification mirrors one entry of gridsim's GET /admin/notifications:
// one Notification POST attempt and what came back.
//
// HTTPStatus is the DUT's answer, and Error is why there was none. The pair is
// what separates the three outcomes a notification criterion must never
// conflate: the DUT answered (a finding about the DUT), the server could not
// deliver (a finding about the BENCH's transport), and the server pushed
// nothing at all (a finding about neither).
type AdminNotification struct {
	At                 int64  `json:"at"`
	SubscriptionHref   string `json:"subscription_href"`
	SubscribedResource string `json:"subscribed_resource"`
	NotificationURI    string `json:"notification_uri"`
	Status             uint8  `json:"notification_status"`
	HTTPStatus         int    `json:"http_status"`
	Bytes              int    `json:"bytes"`
	Error              string `json:"error,omitempty"`
}

// Delivered reports whether the client answered this Notification at all.
// HTTPStatus 0 means the POST never got an answer — either the transport
// refused to dial it (Error names the reason) or the connection failed.
func (n AdminNotification) Delivered() bool { return n.HTTPStatus != 0 }

// ServerView is the tier-3 record: everything the bench's 2030.5 server saw.
//
// It is a real observation of the DUT — made by its peer — but it is not the
// wire, so every assertion resting on it is a Narrative naming gridsim as the
// source. See the package doc's tier discussion.
type ServerView struct {
	Available bool
	BaseURL   string

	Requests  []ServerRequest
	Responses []AdminResponse
	DERPuts   []AdminDERPut
	LogEvents []map[string]any
	Status    AdminStatus

	// RunDERPuts is the DER self-report PUTs the server recorded since the RUN
	// began, not just since this check's baseline. It exists because the DER
	// self-reports (DERStatus, DERCapability, DERSettings) are cadence- and
	// change-driven: the DUT emits them on its own schedule, so the one a case
	// is written to observe routinely lands earlier in the run than that case's
	// narrow window. DERPuts answers "in THIS window"; RunDERPuts answers "in
	// this run" — which is the observable a "the DUT self-reports X" claim
	// actually rests on. It is scoped to the run (see the run baseline in
	// check.go), so it never credits a report a previous campaign's DUT made.
	RunDERPuts []AdminDERPut

	// Notifications is the server's own log of what it pushed and what came
	// back. Like Responses it is append-only, so Since deltas it by length.
	Notifications []AdminNotification

	// Fleet and Subscriptions are STATE, not logs: the fixture the server is
	// serving right now and the subscriptions the DUT holds right now. Since
	// carries them through unchanged, because "the fleet as it was at the
	// baseline minus the fleet as it is now" is not a meaningful quantity.
	Fleet         []AdminFleetDevice
	Subscriptions []AdminSubscription

	// Errors records what could not be collected, so a partial view is never
	// mistaken for a complete one.
	Errors []string

	// rawLines is the server's request log exactly as read, and rawFirstSeq is
	// the absolute sequence number of rawLines[0]. Since deltas these, NOT the
	// parsed Requests slice and NOT by length: the server's log is a bounded
	// ring, so once it wraps a length-based delta reports nothing happened.
	rawLines    []string
	rawFirstSeq uint64
	// logApproximate marks a view whose log was read without a cursor. Its
	// deltas can under-report and Since says so instead of guessing.
	logApproximate bool
}

// Since returns the view's entries that are new relative to a baseline taken
// earlier in the same run. Baselines are how a check avoids passing on evidence
// another agent's test case produced.
// The Responses/DERPuts/LogEvents endpoints serve unbounded append-only
// arrays, so a length delta is exact for those. The REQUEST LOG is a bounded
// ring and is delta'd by absolute sequence instead — see rawFirstSeq.
func (v ServerView) Since(base ServerView) ServerView {
	out := v
	out.Responses = v.Responses[min(len(base.Responses), len(v.Responses)):]
	out.DERPuts = v.DERPuts[min(len(base.DERPuts), len(v.DERPuts)):]
	out.LogEvents = v.LogEvents[min(len(base.LogEvents), len(v.LogEvents)):]
	out.Notifications = v.Notifications[min(len(base.Notifications), len(v.Notifications)):]

	switch {
	case len(v.rawLines) == 0 && len(base.rawLines) == 0:
		// Neither view came from a log read: Requests were supplied directly
		// (a synthetic view, or a test fixture). There is no ring involved, so
		// the slice really is append-only and the length delta is exact.
		out.Requests = v.Requests[min(len(base.Requests), len(v.Requests)):]
	case v.logApproximate || base.logApproximate:
		// No cursor available. Fall back to the old length delta, but say so:
		// this is the mode that can silently under-report.
		out.Requests = v.Requests[min(len(base.Requests), len(v.Requests)):]
		out.Errors = append(out.Errors, "the request-log delta is approximate: the simulator served no "+
			"cursor endpoint (/admin/logs.json), so entries evicted from its ring are invisible here and "+
			"this view may under-report what the DUT did")
	case base.rawFirstSeq+uint64(len(base.rawLines)) < v.rawFirstSeq:
		// The baseline's position fell out of the ring before we read again.
		// The window is genuinely unobservable; saying "nothing happened"
		// would be the false-FAIL bug all over again.
		lost := v.rawFirstSeq - (base.rawFirstSeq + uint64(len(base.rawLines)))
		out.Requests = parseRequestLog(v.rawLines)
		out.Errors = append(out.Errors, fmt.Sprintf("the simulator's request log evicted %d line(s) "+
			"between the baseline and this read, so this window cannot be reconstructed; treat the "+
			"request list as incomplete rather than as evidence the DUT was idle", lost))
	default:
		baseEnd := base.rawFirstSeq + uint64(len(base.rawLines))
		out.Requests = parseRequestLog(v.rawLines[baseEnd-v.rawFirstSeq:])
	}
	return out
}

// ResponsesFor returns the Responses whose subject is the given mRID.
func (v ServerView) ResponsesFor(mrid string) []AdminResponse {
	var out []AdminResponse
	for _, r := range v.Responses {
		if strings.EqualFold(r.Subject, mrid) {
			out = append(out, r)
		}
	}
	return out
}

// HasResponse reports whether a Response with the given subject and status was
// received.
func (v ServerView) HasResponse(mrid string, status uint8) bool {
	for _, r := range v.ResponsesFor(mrid) {
		if r.Status == status {
			return true
		}
	}
	return false
}

// ResponseStatuses lists the statuses received for an mRID, ascending, for an
// Observed field.
func (v ServerView) ResponseStatuses(mrid string) []int {
	var out []int
	for _, r := range v.ResponsesFor(mrid) {
		out = append(out, int(r.Status))
	}
	sort.Ints(out)
	return out
}

// GETs counts the request-log lines that are a GET of path.
func (v ServerView) GETs(path string) int {
	n := 0
	for _, r := range v.Requests {
		if r.Method == "GET" && r.Path == path {
			n++
		}
	}
	return n
}

// SessionEstablished reports whether this view holds ANY evidence that the DUT
// completed a 2030.5 session with the bench server in the window it covers.
//
// gridsim writes a request-log line, a Response, a DER PUT, a LogEvent or a
// Notification exchange only AFTER the mutually-authenticated TLS handshake it
// requires has completed and the DUT has spoken 2030.5 over it. Any one of them
// is therefore proof a session established; the total absence of all of them is
// the only server-side state consistent with a DUT that never completed a
// handshake. (A conformant 2030.5 client opens its walk with GET /dcap, so a
// window in which a session established but the request log is empty does not
// arise from a well-behaved run; the other logs are folded in so the signal
// survives the request log's bounded ring evicting a window's lines.)
//
// It exists so a tier-3 evaluator can tell "the DUT reached the server but did
// not do the specific thing this row wants" (a real FAIL about the DUT) apart
// from "the DUT did nothing here at all" (unavailable — the log's emptiness is
// not attributable to the DUT). See noSessionUnavailable.
func (v ServerView) SessionEstablished() bool {
	return len(v.Requests) > 0 || len(v.Responses) > 0 || len(v.DERPuts) > 0 ||
		len(v.LogEvents) > 0 || len(v.Notifications) > 0
}

// ResponsesFrom returns the Responses whose endDeviceLFDI is lfdi, whatever
// they were about. It is the per-device half of the aggregator rows' pass
// criteria: ResponsesFor answers "which device", ResponsesFrom answers "which
// event", and a fan-out criterion needs both at once.
func (v ServerView) ResponsesFrom(lfdi string) []AdminResponse {
	var out []AdminResponse
	for _, r := range v.Responses {
		if lfdi != "" && strings.EqualFold(r.LFDI, lfdi) {
			out = append(out, r)
		}
	}
	return out
}

// FleetDeviceNamed returns the managed EndDevice the CTP calls name.
func (v ServerView) FleetDeviceNamed(name string) (AdminFleetDevice, bool) {
	for _, d := range v.Fleet {
		if strings.EqualFold(d.Name, name) {
			return d, true
		}
	}
	return AdminFleetDevice{}, false
}

// NotificationsFor returns the Notifications pushed for one subscribed
// resource href, query string and trailing slash ignored.
func (v ServerView) NotificationsFor(href string) []AdminNotification {
	var out []AdminNotification
	for _, n := range v.Notifications {
		if trimHref(n.SubscribedResource) == trimHref(href) {
			out = append(out, n)
		}
	}
	return out
}

// trimHref is the suite's copy of the server's own href normalisation: a
// subscription posted against "/derp/0/derc?l=10" is about the same resource as
// a change to "/derp/0/derc", and a criterion that compared them literally
// would report a server that never notified.
func trimHref(h string) string {
	if i := strings.IndexByte(h, '?'); i >= 0 {
		h = h[:i]
	}
	if len(h) > 1 {
		h = strings.TrimSuffix(h, "/")
	}
	return h
}

// PutsFor returns the DER report PUTs whose recorded root element matches,
// scoped to this view's window (the check's baseline delta).
func (v ServerView) PutsFor(resource string) []AdminDERPut {
	return putsFor(v.DERPuts, resource)
}

// PutsForInRun returns the DER report PUTs for a resource anywhere in the run,
// not just this check's window. It falls back to the window when the run-scoped
// slice is absent (a synthetic view that set only DERPuts), so a caller can ask
// this question unconditionally.
func (v ServerView) PutsForInRun(resource string) []AdminDERPut {
	if v.RunDERPuts == nil {
		return v.PutsFor(resource)
	}
	return putsFor(v.RunDERPuts, resource)
}

func putsFor(puts []AdminDERPut, resource string) []AdminDERPut {
	var out []AdminDERPut
	for _, p := range puts {
		if p.Resource == resource {
			out = append(out, p)
		}
	}
	return out
}

// The run baseline in the DER self-report log.
//
// gridsim's der_puts log is append-only and NOT reset between campaigns, so the
// whole log is "since gridsim booted", which is broader than "this run". A
// campaign is one process, so the number of PUTs the log already held when this
// run first looked is the run's start line: everything after it is this run's.
// Captured once, on the first snapshot; see markRunBaseline / derPutsInRun.
var (
	runDERBaselineMu  sync.Mutex
	runDERBaselineSet bool
	runDERBaselineN   int
)

// markRunBaseline records, once per process, how many DER PUTs the server's log
// already held — the split between a previous campaign's reports and this run's.
func markRunBaseline(v ServerView) {
	runDERBaselineMu.Lock()
	defer runDERBaselineMu.Unlock()
	if !runDERBaselineSet && v.Available {
		runDERBaselineN = len(v.DERPuts)
		runDERBaselineSet = true
	}
}

// derPutsInRun returns the DER PUTs recorded since the run baseline. The log is
// append-only, so the baseline COUNT is the split point. If the log is somehow
// shorter than the baseline (gridsim restarted mid-run and its log truncated)
// the whole current log is returned rather than nothing: under-reporting the
// run would resurrect the false-FAIL this scoping exists to prevent.
func derPutsInRun(v ServerView) []AdminDERPut {
	runDERBaselineMu.Lock()
	n, set := runDERBaselineN, runDERBaselineSet
	runDERBaselineMu.Unlock()
	if !set || n > len(v.DERPuts) {
		return v.DERPuts
	}
	return v.DERPuts[n:]
}

// resetRunBaseline clears the process-wide run baseline. It exists for tests
// that exercise the baseline directly; the runner never calls it.
func resetRunBaseline() {
	runDERBaselineMu.Lock()
	runDERBaselineSet, runDERBaselineN = false, 0
	runDERBaselineMu.Unlock()
}

// Observation is everything a check's decision logic is handed. Keeping it a
// value with no bench handles is what makes every evaluator in this suite
// unit-testable from synthetic input.
type Observation struct {
	Case *certify.Case

	// Transcript is the recovered session, or nil when none was; NoSession then
	// says why.
	Transcript *Transcript
	NoSession  string

	// Server is the server-side view, already differenced against the check's
	// baseline where the check took one.
	Server ServerView

	// Waited is how long the live phase waited for the DUT, and Satisfied
	// reports whether the wait's predicate came true. A check whose predicate
	// never came true must not report a conformance failure on that basis alone
	// without saying how long it gave the DUT.
	Waited    time.Duration
	Satisfied bool

	// Params carries per-check facts the live phase established (an mRID it
	// posted, a PIN it configured) into the citation phase.
	Params map[string]string

	// NotifyEndpoints are the DUT's inbound Notification listeners this check
	// successfully claimed, taken from the <notificationURI> of the
	// Subscriptions the server recorded. They are carried here because the
	// citation phase has to recover a SECOND conversation — the one the server
	// dialled — and the address is not knowable before the live phase ran.
	// Empty means either no subscription, or none whose listener could be
	// claimed; obs.Param(notifyClaimParam) says which.
	NotifyEndpoints []netip.AddrPort

	notes map[string][]string
}

// note records why an evaluator could not answer, so the eventual SKIP carries
// the whole story rather than only the last sentence.
func (o *Observation) note(claim, reason string) {
	if o.notes == nil {
		o.notes = map[string][]string{}
	}
	o.notes[claim] = append(o.notes[claim], reason)
}

func (o *Observation) notesFor(claim string) []string { return o.notes[claim] }

// Param reads a value the live phase stashed.
func (o *Observation) Param(key string) string {
	if o.Params == nil {
		return ""
	}
	return o.Params[key]
}

// Driver is the live-phase handle: gridsim's admin API plus the wait loop.
type Driver struct {
	rc    *certify.RunCtx
	Admin *certify.AdminClient

	// LogReader fetches gridsim's request-log backlog. It is a field so a test
	// can substitute one without a listener; nil uses the real SSE reader.
	LogReader func(ctx context.Context, baseURL string) ([]string, error)
}

// NewDriver builds a driver from the check's run context.
func NewDriver(rc *certify.RunCtx) *Driver {
	return &Driver{rc: rc, Admin: rc.GridSim}
}

// Available reports whether gridsim's admin API was configured for this run.
func (d *Driver) Available() bool { return d.Admin.Available() }

// Snapshot collects the server-side view.
//
// A failure to collect one part is recorded and the rest is still returned: a
// missing request log must not cost a check the Response record that would have
// decided it.
func (d *Driver) Snapshot(ctx context.Context) ServerView {
	v := ServerView{BaseURL: d.Admin.BaseURL}
	if !d.Admin.Available() {
		v.Errors = append(v.Errors, "no gridsim admin URL was configured (-gridsim-admin)")
		return v
	}
	v.Available = true

	var st AdminStatus
	if err := d.Admin.Status(ctx, &st); err != nil {
		v.Errors = append(v.Errors, "GET /admin/status: "+err.Error())
	} else {
		v.Status = st
	}
	var rs struct {
		Responses []AdminResponse `json:"responses"`
	}
	if err := d.Admin.Responses(ctx, &rs); err != nil {
		v.Errors = append(v.Errors, "GET /admin/responses: "+err.Error())
	} else {
		v.Responses = rs.Responses
	}
	var dp struct {
		DERPuts []AdminDERPut `json:"der_puts"`
	}
	if err := d.Admin.DERPuts(ctx, &dp); err != nil {
		v.Errors = append(v.Errors, "GET /admin/derputs: "+err.Error())
	} else {
		v.DERPuts = dp.DERPuts
	}
	var le struct {
		LogEvents []map[string]any `json:"log_events"`
	}
	if err := d.Admin.LogEvents(ctx, &le); err != nil {
		v.Errors = append(v.Errors, "GET /admin/logevents: "+err.Error())
	} else {
		v.LogEvents = le.LogEvents
	}

	// The three DER AGGREGATOR CLIENT surfaces. A simulator that serves none of
	// them is a bench without the fixture, not a broken one, so a missing
	// endpoint is recorded and the view is still returned — the criteria that
	// need it will SKIP naming the lever, which is the honest answer, whereas
	// an Errors entry per check would make an intentional configuration look
	// like a fault.
	var fl struct {
		Devices []AdminFleetDevice `json:"devices"`
	}
	if err := d.Admin.Get(ctx, "fleet", &fl); err == nil {
		v.Fleet = fl.Devices
	}
	var nt struct {
		Notifications []AdminNotification `json:"notifications"`
	}
	if err := d.Admin.Get(ctx, "notifications", &nt); err == nil {
		v.Notifications = nt.Notifications
	}
	var sb struct {
		Subscriptions []AdminSubscription `json:"subscriptions"`
	}
	if err := d.Admin.Get(ctx, "subscriptions", &sb); err == nil {
		v.Subscriptions = sb.Subscriptions
	}

	lr, err := d.readLog(ctx)
	if err != nil {
		v.Errors = append(v.Errors, "GET /admin/logs: "+err.Error())
	} else {
		// Keep the RAW lines and their absolute sequence: Since deltas the raw
		// lines and parses the delta, so the cursor arithmetic never has to
		// survive parseRequestLog's filtering.
		v.rawLines, v.rawFirstSeq, v.logApproximate = lr.lines, lr.firstSeq, lr.approximate
		v.Requests = parseRequestLog(lr.lines)
	}
	return v
}

// logRead is what the server's request log looked like at one instant, with
// enough information to take an EXACT delta against an earlier read.
type logRead struct {
	lines []string
	// firstSeq is the absolute sequence number of lines[0]. Deltas are taken
	// against this, never against len(lines): the server's ring evicts, so
	// len() stops growing while events keep arriving, and a length-based delta
	// silently collapses to empty. That is what reported a healthy gateway as
	// having "done nothing in this window" 22 times on 2026-07-28.
	firstSeq uint64
	// approximate is set when sequence numbers had to be synthesised because
	// the server offered no cursor endpoint. A delta from an approximate read
	// can under-report, and says so rather than being trusted silently.
	approximate bool
}

func (d *Driver) readLog(ctx context.Context) (logRead, error) {
	if d.LogReader != nil {
		lines, err := d.LogReader(ctx, d.Admin.BaseURL)
		return logRead{lines: lines, approximate: true}, err
	}

	// Cursor endpoint (preferred). since=0 returns everything the ring still
	// holds plus the absolute cursor just past it, which is what makes the
	// delta exact across an eviction.
	var got struct {
		Lines   []string `json:"lines"`
		Next    uint64   `json:"next"`
		Dropped uint64   `json:"dropped"`
	}
	err := d.Admin.Logs(ctx, 0, &got)
	if err == nil {
		return logRead{lines: got.Lines, firstSeq: got.Next - uint64(len(got.Lines))}, nil
	}

	// Older simulator without the cursor endpoint: fall back to the SSE replay,
	// but mark the read approximate so its delta cannot pass as exact.
	lines, serr := readSSEBacklog(ctx, d.Admin.BaseURL+"/admin/logs", logTailBudget)
	if serr != nil {
		return logRead{}, fmt.Errorf("cursor read failed (%v) and SSE fallback failed: %w", err, serr)
	}
	return logRead{lines: lines, approximate: true}, nil
}

// readSSEBacklog reads the replayed backlog of an SSE endpoint and returns.
//
// gridsim's /admin/logs streams forever, so an ordinary GET-and-read-all would
// block until the client's timeout and then throw the body away. This reads
// lines until the stream goes quiet for a moment, which is exactly when the
// backlog has been replayed and the live tail has not yet produced anything.
func readSSEBacklog(ctx context.Context, url string, budget time.Duration) ([]string, error) {
	ctx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "text/event-stream")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	var out []string
	sc := bufio.NewScanner(resp.Body)
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		if v, ok := strings.CutPrefix(line, "data: "); ok {
			out = append(out, v)
		}
	}
	// The deadline firing is the expected way out, not a failure.
	if err := sc.Err(); err != nil && ctx.Err() == nil {
		return out, err
	}
	return out, nil
}

// requestLinePrefix is what gridsim's per-request log line looks like after the
// standard logger's date/time prefix: "[gridsim] GET /dcap (peer=<lfdi>)".
const requestLinePrefix = "[gridsim] "

// parseRequestLog extracts the DUT's requests from gridsim's log lines.
func parseRequestLog(lines []string) []ServerRequest {
	var out []ServerRequest
	for _, ln := range lines {
		at, rest := splitLogTimestamp(ln)
		i := strings.Index(rest, requestLinePrefix)
		if i < 0 {
			continue
		}
		body := rest[i+len(requestLinePrefix):]
		fields := strings.Fields(body)
		if len(fields) < 2 || !isHTTPMethod(fields[0]) || !strings.HasPrefix(fields[1], "/") {
			continue
		}
		r := ServerRequest{At: at, Method: fields[0], Path: fields[1], Raw: ln}
		if j := strings.Index(body, "(peer="); j >= 0 {
			if k := strings.IndexByte(body[j:], ')'); k > 0 {
				r.Peer = body[j+len("(peer=") : j+k]
			}
		}
		if q := strings.IndexByte(r.Path, '?'); q >= 0 {
			r.Path = r.Path[:q]
		}
		out = append(out, r)
	}
	return out
}

func isHTTPMethod(s string) bool {
	switch s {
	case "GET", "HEAD", "PUT", "POST", "DELETE", "OPTIONS", "PATCH":
		return true
	}
	return false
}

// splitLogTimestamp peels the standard logger's "2026/07/26 12:00:00" prefix
// off a line, returning the parsed time (zero if absent) and the remainder.
func splitLogTimestamp(ln string) (time.Time, string) {
	const layout = "2006/01/02 15:04:05"
	if len(ln) < len(layout) {
		return time.Time{}, ln
	}
	t, err := time.ParseInLocation(layout, ln[:len(layout)], time.Local)
	if err != nil {
		return time.Time{}, ln
	}
	return t, strings.TrimSpace(ln[len(layout):])
}

// Await polls the server view until want reports satisfied or the deadline
// expires. It returns the last view, how long it waited, and whether the
// predicate came true.
//
// It never returns an error for "the DUT did not do it in time": that is a
// finding for the check to phrase, and one whose right verdict depends on
// whether the procedure states a deadline.
func (d *Driver) Await(ctx context.Context, timeout time.Duration, want func(ServerView) bool) (ServerView, time.Duration, bool) {
	// Defensive: a nil predicate has no business reaching here (the caller routes
	// it to AwaitWalk — see specWant), but treating it as "never satisfied" turns
	// a would-be panic into a plain window wait, which is the safe degradation.
	if want == nil {
		want = func(ServerView) bool { return false }
	}
	start := time.Now()
	view := d.Snapshot(ctx)
	if !view.Available {
		return view, 0, false
	}
	if want(view) {
		return view, time.Since(start), true
	}
	deadline := start.Add(timeout)
	for time.Now().Before(deadline) {
		if err := d.rc.Sleep(ctx, pollInterval); err != nil {
			return view, time.Since(start), false
		}
		view = d.Snapshot(ctx)
		if want(view) {
			return view, time.Since(start), true
		}
	}
	return view, time.Since(start), false
}

// AwaitWalk waits for the DUT to complete at least one fresh discovery walk,
// detected as a new GET of the discovery root in gridsim's request log.
//
// The request log is a bounded ring (400 lines) and one walk produces dozens of
// lines, so on a busy bench the baseline can roll out from under this. That is
// why the predicate is "strictly more /dcap GETs than the baseline" rather than
// an exact count: an undercount makes the check wait longer, never pass early.
func (d *Driver) AwaitWalk(ctx context.Context, base ServerView, timeout time.Duration) (ServerView, time.Duration, bool) {
	want := base.GETs(DiscoveryRoot) + 1
	return d.Await(ctx, timeout, func(v ServerView) bool { return v.GETs(DiscoveryRoot) >= want })
}

// DiscoveryRoot is the only path a 2030.5 client may hard-code; every other URL
// it uses must come from a link in a resource it fetched.
const DiscoveryRoot = "/dcap"

// ── levers ───────────────────────────────────────────────────────────────────

// ControlRequest is the body of gridsim's POST /admin/control. Only the fields
// this suite uses are modelled; gridsim owns the schema and the framework's
// AdminClient deliberately passes bodies through untyped.
type ControlRequest struct {
	Program     int    `json:"program"`
	Description string `json:"description"`
	StartOffset int    `json:"start_offset_s"`
	DurationS   int    `json:"duration_s"`
	Activate    bool   `json:"activate"`

	MRID                  string `json:"mrid,omitempty"`
	PotentiallySuperseded *bool  `json:"potentially_superseded,omitempty"`
	CurrentStatus         *uint8 `json:"current_status,omitempty"`
	CreationOffsetS       *int   `json:"creation_offset_s,omitempty"`
	RandomizeStart        *int32 `json:"randomize_start,omitempty"`
	RandomizeDuration     *int32 `json:"randomize_duration,omitempty"`

	ExpLimW        *int64 `json:"exp_lim_W,omitempty"`
	MaxLimW        *int64 `json:"max_lim_W,omitempty"`
	ImpLimW        *int64 `json:"imp_lim_W,omitempty"`
	GenLimW        *int64 `json:"gen_lim_W,omitempty"`
	LoadLimW       *int64 `json:"load_lim_W,omitempty"`
	FixedW         *int64 `json:"fixed_W,omitempty"`
	Connect        *bool  `json:"connect,omitempty"`
	Energize       *bool  `json:"energize,omitempty"`
	FixedPFInjectW *int64 `json:"fixed_pf_inject_pct,omitempty"`
	FixedPFAbsorbW *int64 `json:"fixed_pf_absorb_pct,omitempty"`
	FixedVarPct    *int64 `json:"fixed_var_pct,omitempty"`
}

// PostControl publishes a DERControl and returns the mRID gridsim assigned.
func (d *Driver) PostControl(ctx context.Context, req ControlRequest) (string, error) {
	var out struct {
		MRID string `json:"mrid"`
	}
	if err := d.Admin.Control(ctx, req, &out); err != nil {
		return "", err
	}
	if out.MRID == "" {
		out.MRID = req.MRID
	}
	return out.MRID, nil
}

// CurveRequest is the body of gridsim's POST /admin/curve: a DER curve bound
// into an active DERControl, which is the only way a curve-based mode
// (Volt-VAr, Volt-Watt, Freq-Watt, Watt-PF) reaches the DUT.
type CurveRequest struct {
	Program     int          `json:"program"`
	Mode        string       `json:"mode"`
	Points      []CurvePoint `json:"points"`
	VRef        int16        `json:"vref,omitempty"`
	XMult       int8         `json:"x_mult,omitempty"`
	YMult       int8         `json:"y_mult,omitempty"`
	XRefType    uint8        `json:"x_ref_type,omitempty"`
	YRefType    uint8        `json:"y_ref_type,omitempty"`
	Description string       `json:"description,omitempty"`
	DurationS   int          `json:"duration_s,omitempty"`
	StartOffset int          `json:"start_offset_s,omitempty"`
	Activate    bool         `json:"activate"`
}

// CurvePoint is one (x, y) breakpoint.
type CurvePoint struct {
	X float64 `json:"x"`
	Y float64 `json:"y"`
}

// PostCurve publishes a curve-linked control and returns its mRID.
func (d *Driver) PostCurve(ctx context.Context, req CurveRequest) (string, error) {
	var out struct {
		MRID string `json:"mrid"`
	}
	if err := d.Admin.Post(ctx, "curve", req, &out); err != nil {
		return "", err
	}
	return out.MRID, nil
}

// Subscriptions reads the subscriptions the DUT currently holds on the bench's
// 2030.5 server, with the notificationURI it registered for each.
//
// It returns an empty slice and no error against a simulator that serves no
// such endpoint: an older gridsim is a bench without the function set, not a
// failure, and treating it as one would turn a capability gap into a run error.
func (d *Driver) Subscriptions(ctx context.Context) []AdminSubscription {
	if !d.Admin.Available() {
		return nil
	}
	var out struct {
		Subscriptions []AdminSubscription `json:"subscriptions"`
	}
	if err := d.Admin.Get(ctx, "subscriptions", &out); err != nil {
		return nil
	}
	return out.Subscriptions
}

// Fleet reads the CTP Figure-15 devices the server is currently serving, with
// the LFDI it derived for each. An older simulator serves no such endpoint and
// that is a bench without the fixture, not an error.
func (d *Driver) Fleet(ctx context.Context) []AdminFleetDevice {
	if !d.Admin.Available() {
		return nil
	}
	var out struct {
		Devices []AdminFleetDevice `json:"devices"`
	}
	if err := d.Admin.Get(ctx, "fleet", &out); err != nil {
		return nil
	}
	return out.Devices
}

// RebindDevice changes which aggregator a managed EndDevice belongs to, which
// is how MAINT-001's out-of-band agreement ("EDA1X is no longer being managed
// by the aggregator and needs to be deleted from its list") is driven. lfdi ==
// "-" detaches the device; the server rebuilds the EndDeviceList and pushes a
// Notification for it.
//
// It is a MUTATION of the shared bench and every caller must undo it, which is
// why the rows that use it do so from a Change hook whose Cleanup restores the
// binding unconditionally.
func (d *Driver) RebindDevice(ctx context.Context, device, lfdi string) error {
	return d.Admin.Post(ctx, "fleet", map[string]any{"device": device, "managed_by": lfdi}, nil)
}

// CancelSubscription makes the server push the status=1 "Subscription canceled,
// no additional information" Notification that CORE-019 step 11 and ERR-002
// step 5 are about, and forget the subscription.
//
// The DUT is expected to re-establish its subscription on its next walk; per
// Annex A seq 38 it is NOT required to re-POST one immediately, and no
// criterion in this suite waits for it.
func (d *Driver) CancelSubscription(ctx context.Context, href string) error {
	_, err := d.Admin.Raw(ctx, http.MethodDelete, "/admin/subscriptions?href="+url.QueryEscape(href), nil)
	return err
}

// ClearControls removes the admin-posted controls from a program, so a check
// leaves the bench as it found it.
func (d *Driver) ClearControls(ctx context.Context, program int) error {
	_, err := d.Admin.Raw(ctx, http.MethodDelete, "/admin/control?program="+strconv.Itoa(program), nil)
	return err
}

// ClearCurves removes admin-posted curve controls from a program.
func (d *Driver) ClearCurves(ctx context.Context, program int) error {
	_, err := d.Admin.Raw(ctx, http.MethodDelete, "/admin/curve?program="+strconv.Itoa(program), nil)
	return err
}

// ArmRedirect makes the next count GETs of path answer 301/302 with a Location.
func (d *Driver) ArmRedirect(ctx context.Context, path, location string, code, count int) error {
	return d.Admin.Post(ctx, "redirect", map[string]any{
		"path": path, "location": location, "code": code, "count": count,
	}, nil)
}

// ClearRedirect disarms redirect injection.
func (d *Driver) ClearRedirect(ctx context.Context) error {
	return d.Admin.Post(ctx, "redirect", map[string]any{"clear": true}, nil)
}

// ArmGone makes GETs of path answer 410. count > 0 heals after that many.
func (d *Driver) ArmGone(ctx context.Context, path string, count int) error {
	return d.Admin.Post(ctx, "gone", map[string]any{"path": path, "count": count}, nil)
}

// ClearGone disarms 410 injection.
func (d *Driver) ClearGone(ctx context.Context) error {
	return d.Admin.Post(ctx, "gone", map[string]any{"clear": true}, nil)
}

// ArmOutage answers every CSIP request 503 for durationS seconds. The duration
// is mandatory here (unlike gridsim's API, where it is optional) because an
// unbounded outage on a shared bench pushes the DUT into its 15-minute backoff
// and poisons every later test case in the campaign.
func (d *Driver) ArmOutage(ctx context.Context, mode string, durationS int) error {
	if durationS <= 0 {
		return fmt.Errorf("suitecsip: an outage must be bounded (durationS > 0): an unbounded northbound " +
			"failure drives the DUT into its 15-minute retry backoff and invalidates every later test case")
	}
	return d.Admin.Post(ctx, "outage", map[string]any{"mode": mode, "duration_s": durationS}, nil)
}

// ClearOutage clears an armed outage.
func (d *Driver) ClearOutage(ctx context.Context) error {
	return d.Admin.Post(ctx, "outage", map[string]any{"clear": true}, nil)
}

// ArmPaginate makes list resources honour ?s=&l= and serve pageSize entries at
// a time, with honest all/results — the positive pagination case CORE-004's
// client-side twin needs.
func (d *Driver) ArmPaginate(ctx context.Context, pageSize int, path string) error {
	return d.Admin.Post(ctx, "paginate", map[string]any{"page_size": pageSize, "path": path}, nil)
}

// ClearPaginate disarms pagination.
func (d *Driver) ClearPaginate(ctx context.Context) error {
	return d.Admin.Post(ctx, "paginate", map[string]any{"clear": true}, nil)
}

// ArmMalform serves a deliberately non-conformant variant of one resource.
func (d *Driver) ArmMalform(ctx context.Context, kind string) error {
	return d.Admin.Post(ctx, "malform", map[string]any{"kind": kind}, nil)
}

// ClearMalform disarms malformed-resource injection.
func (d *Driver) ClearMalform(ctx context.Context) error {
	return d.Admin.Post(ctx, "malform", map[string]any{"clear": true}, nil)
}

// SetClock warps gridsim's 2030.5 clock by an offset in seconds, which is how a
// check reaches a scheduled event's start without waiting for it.
func (d *Driver) SetClock(ctx context.Context, offsetS int64) error {
	return d.Admin.Clock(ctx, map[string]any{"offset_s": offsetS}, nil)
}

// ClearFaults disarms every fault mode this suite can arm. It is called from a
// check's cleanup path unconditionally: leaving the shared bench's 2030.5
// server in an injected-fault state would corrupt every test case that follows,
// including other agents'.
func (d *Driver) ClearFaults(ctx context.Context) []error {
	var errs []error
	for _, f := range []func(context.Context) error{
		d.ClearRedirect, d.ClearGone, d.ClearOutage, d.ClearPaginate, d.ClearMalform,
	} {
		if err := f(ctx); err != nil {
			errs = append(errs, err)
		}
	}
	return errs
}
