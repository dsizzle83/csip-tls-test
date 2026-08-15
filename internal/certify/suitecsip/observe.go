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

// sortedDERPuts turns the map GET /admin/derputs serves (keyed by resource
// path, one entry per path — see the comment at its call site in Snapshot)
// into the chronologically ordered slice ServerView's Since/PutsFor machinery
// needs, sorted by ReceivedAt ascending so the LAST element really is the most
// recent PUT. gridsim's ReceivedAt is second-granularity server time, so two
// PUTs landing in the same wall-clock second tie; the path is the tiebreak,
// which is deterministic but not guaranteed to match true arrival order for
// that rare case — strictly better than a Go map's randomised iteration
// order, which is what this replaces.
func sortedDERPuts(m map[string]AdminDERPut) []AdminDERPut {
	out := make([]AdminDERPut, 0, len(m))
	for _, p := range m {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].ReceivedAt != out[j].ReceivedAt {
			return out[i].ReceivedAt < out[j].ReceivedAt
		}
		return out[i].Path < out[j].Path
	})
	return out
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

	// PID is the simulator process serving this view, and it is read for one
	// reason: the request log's sequence numbers are only comparable WITHIN a
	// process. A gridsim that restarted between a check's baseline and its next
	// read starts counting from zero again, and arithmetic that assumed one
	// monotonic sequence then compares two different number lines — which is
	// how a restart became an out-of-range slice panic (see ringDelta). A
	// gridsim predating this field reports 0, which reads as "unknown" and
	// falls back to detecting the reset from the sequence itself.
	PID int `json:"pid"`

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

// AdminMUP mirrors one entry of gridsim's GET /admin/mups: the durable record
// of a MirrorUsagePoint the DUT registered.
//
// It is STATE, not a log — like Fleet and Subscriptions, Since carries it
// through unchanged rather than deltaing it (see ServerView.Since) — and it is
// read at all because registration is a ONE-TIME event that ordinarily
// predates a case's own window: BASIC-029 has no Setup that forces a fresh
// one, so by the time its window opens the request log (a bounded ring) has
// often already moved past the one POST that mattered. This is gridsim's
// answer to a question the log cannot: not "did THIS WINDOW see a
// registration POST" but "does a MirrorUsagePoint bearing the DUT's LFDI
// exist right now". See critMUPRegistered.
type AdminMUP struct {
	Href         string  `json:"href"`
	LFDI         string  `json:"lfdi"`
	ReadingTypes []uint8 `json:"reading_types,omitempty"` // uom values, 2030.5 Table 11 (38 = W, real power)
	Readings     int     `json:"readings"`
	CreatedAt    int64   `json:"created_at"`
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

	// Fleet, Subscriptions and MUPs are STATE, not logs: the fixture the server
	// is serving right now, the subscriptions the DUT holds right now, and the
	// MirrorUsagePoints the DUT has registered so far. Since carries them
	// through unchanged, because "the fleet (or MUP list) as it was at the
	// baseline minus as it is now" is not a meaningful quantity — a case whose
	// window opened long after the DUT's one-time MUP registration needs to see
	// that registration too, not have it deltaed away. See AdminMUP.
	Fleet         []AdminFleetDevice
	Subscriptions []AdminSubscription
	MUPs          []AdminMUP

	// Errors records what could not be collected, so a partial view is never
	// mistaken for a complete one.
	Errors []string

	// RequestLogGap is non-empty when Since() could not reconstruct this
	// window's Requests reliably — the ring wrapped past the baseline, or no
	// cursor endpoint was available to delta against at all (see Since). A
	// criterion that grades "zero matches in Requests" as a FAIL about the DUT
	// without checking this first repeats the exact false-FAIL bug Since's own
	// doc warns about: gridsim's request log, unlike Responses/DERPuts/
	// LogEvents/Notifications, is a bounded ring, so an empty count can mean
	// "the DUT did nothing" or "the log no longer remembers" and only this
	// field tells the two apart.
	RequestLogGap string

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

	reqs, _, gap := v.requestsSince(base)
	out.Requests = reqs
	if gap != "" {
		out.RequestLogGap = gap
		out.Errors = append(out.Errors, gap)
	}
	return out
}

// logReach says how far a request-log delta can be trusted. It exists because
// "how many /dcap GETs arrived since the baseline" has three possible honest
// answers and only one of them is a number.
type logReach int

const (
	// logExact: every line written after the baseline is present. A count is
	// the count.
	logExact logReach = iota
	// logPartial: lines were evicted, but everything still retained is strictly
	// NEWER than the baseline. A count is therefore a LOWER BOUND — enough to
	// prove the DUT did something, never enough to prove it did nothing.
	logPartial
	// logIncomparable: the sequence space changed under the check (the
	// simulator restarted, or the admin API is answered by a different process
	// than the one that served the baseline). The two reads are not positions
	// on one number line, so no count relates them and none may be reported as
	// though it did.
	logIncomparable
)

// logPos is where one view's request-log read sits in the simulator's absolute,
// append-only sequence — and which process's sequence it is.
type logPos struct {
	firstSeq uint64 // absolute sequence number of rawLines[0]
	n        int    // how many lines were retained
	pid      int    // the process that served them; 0 when it did not say
}

func (v ServerView) logPos() logPos {
	return logPos{firstSeq: v.rawFirstSeq, n: len(v.rawLines), pid: v.Status.PID}
}

// ringDelta answers "which of cur's retained log lines arrived after base was
// read", as an index into cur's lines, plus how far the answer can be trusted.
//
// All of the difficulty is that the simulator's log is a BOUNDED RING
// (sim/simapi/logs.go, 4000 lines) read whole on every poll. The absolute
// sequence numbers are what make the question answerable at all, and there are
// exactly three positions the two reads can be in:
//
//  1. The ordinary one: the baseline's end is still inside cur's retained
//     window, so the new lines are the ones past it. Note this holds whether or
//     not the ring was ALREADY FULL when the baseline was taken — saturation
//     moves firstSeq, and the arithmetic is in absolute sequence, so it simply
//     does not care. That is the whole point of doing it this way, and the
//     reason the old absolute-COUNT predicates broke: a saturated ring retains
//     a constant number of /dcap lines forever, so "more /dcap than the
//     baseline had" stops being reachable while the DUT polls perfectly.
//  2. The ring wrapped past the baseline DURING the wait. Every line still
//     retained is newer than the baseline — eviction only happens on append —
//     so counting all of them is sound, but some new lines are gone, so the
//     count under-reports: logPartial.
//  3. The sequence went BACKWARDS, which cannot happen within one process.
//     Either gridsim restarted or the admin API is being answered by a
//     different process than the one that served the baseline (the
//     orphan-and-replacement shape certify's preflight warns about). Its log
//     may hold traffic that predates this check entirely, so counting it would
//     manufacture evidence: logIncomparable.
//
// A declared PID that CHANGED is case 3 on its own authority, without waiting
// for the sequence to betray it — a replacement process that had already logged
// more lines than the original would otherwise look like ordinary progress.
func ringDelta(base, cur logPos) (int, logReach, string) {
	baseEnd := base.firstSeq + uint64(base.n)
	curEnd := cur.firstSeq + uint64(cur.n)

	if base.pid != 0 && cur.pid != 0 && base.pid != cur.pid {
		return 0, logIncomparable, fmt.Sprintf("the 2030.5 simulator serving this check changed process "+
			"between the baseline and this read (pid %d, was pid %d): its request log is a different "+
			"sequence entirely, so nothing in it can be dated relative to this check's baseline and it is "+
			"not evidence about this window either way", cur.pid, base.pid)
	}
	if curEnd < baseEnd {
		return 0, logIncomparable, fmt.Sprintf("the 2030.5 simulator's request log went BACKWARDS between "+
			"the baseline and this read (its sequence ended at %d, having reached %d), which one process "+
			"cannot do: it restarted, or a different process is answering. Its log cannot be dated relative "+
			"to this check's baseline", curEnd, baseEnd)
	}
	if cur.firstSeq > baseEnd {
		return 0, logPartial, fmt.Sprintf("the simulator's request log evicted %d line(s) between the "+
			"baseline and this read, so this window cannot be fully reconstructed; what remains is all "+
			"newer than the baseline, so treat the request list as INCOMPLETE rather than as evidence the "+
			"DUT was idle", cur.firstSeq-baseEnd)
	}
	// base.firstSeq <= baseEnd <= curEnd and cur.firstSeq <= baseEnd, so the
	// offset is inside [0, cur.n] and the slice below cannot go out of range.
	// The old code computed this same offset without the two guards above and
	// panicked outright on a restart.
	return int(baseEnd - cur.firstSeq), logExact, ""
}

// requestsSince returns the request-log entries v recorded after base was read,
// how far that answer can be trusted, and the sentence explaining any shortfall.
//
// It is the ONE implementation of the delta: ServerView.Since renders it into a
// window's Requests, and GETsSince counts it for the wait predicates. They used
// to disagree — Since was sequence-aware from the day the ring bug was found,
// while the predicates went on comparing absolute counts — and that disagreement
// is exactly the defect this closes.
func (v ServerView) requestsSince(base ServerView) ([]ServerRequest, logReach, string) {
	switch {
	case len(v.rawLines) == 0 && len(base.rawLines) == 0:
		// Neither view came from a log read: Requests were supplied directly
		// (a synthetic view, or a test fixture). There is no ring involved, so
		// the slice really is append-only and the length delta is exact.
		return v.Requests[min(len(base.Requests), len(v.Requests)):], logExact, ""
	case v.logApproximate || base.logApproximate:
		// No cursor available. Fall back to the old length delta, but say so:
		// this is the mode that can silently under-report.
		return v.Requests[min(len(base.Requests), len(v.Requests)):], logPartial,
			"the request-log delta is approximate: the simulator served no cursor endpoint " +
				"(/admin/logs.json), so entries evicted from its ring are invisible here and this view may " +
				"under-report what the DUT did"
	}
	lo, reach, gap := ringDelta(base.logPos(), v.logPos())
	if reach == logIncomparable {
		// Not "no requests" — requests that cannot be dated. Handing back the
		// unrelated process's lines as though they were this window's is the
		// one answer that would be worse than none.
		return nil, reach, gap
	}
	return parseRequestLog(v.rawLines[lo:]), reach, gap
}

// GETsSince counts the GETs of path the simulator logged AFTER base was read,
// and reports how far that count can be trusted.
//
// Use this, NOT GETs against a baseline count, for anything that decides
// "has the DUT polled yet". GETs counts the whole retained ring, and on a ring
// that has saturated — which gridsim's does within about two hours of walk
// traffic, and it is not restarted between soak cycles — that total stops
// growing while the DUT keeps polling perfectly. Every predicate written as
// "v.GETs(p) >= base.GETs(p)+1" therefore becomes permanently unsatisfiable,
// and the check burns its whole window and reports the DUT did nothing. That is
// the 2026-08-07 soak's "gridsim's request log records no GET /dcap from the DUT
// in this window", on rows whose DUT was polling on time throughout.
func (v ServerView) GETsSince(base ServerView, path string) (int, logReach) {
	reqs, reach, _ := v.requestsSince(base)
	if reach == logIncomparable {
		return 0, reach
	}
	n := 0
	for _, r := range reqs {
		if r.Method == "GET" && r.Path == path {
			n++
		}
	}
	return n, reach
}

// PolledSince reports whether the DUT made at least want GETs of path after
// base was read — the shared spelling of "the DUT polled again", and the only
// one the wait predicates should use.
//
// A count that cannot be dated to this check's baseline (logIncomparable) is
// never "satisfied": a restarted simulator has lost whatever the check's Setup
// published, so a predicate that closed the window on its traffic would be
// reporting a poll for a change that no longer exists. The window stays open,
// the run log carries the reason, and the criteria grade what is honestly
// there — with RequestLogGap saying why it is thin.
func (v ServerView) PolledSince(base ServerView, path string, want int) bool {
	n, reach := v.GETsSince(base, path)
	return reach != logIncomparable && n >= want
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

// WantNewResponse builds an Await predicate satisfied only by a Response for
// mrid posted AFTER v (the baseline the Want closure was handed), not one
// already sitting in gridsim's Responses log from an earlier run that
// happened to reuse the same — typically hardcoded — mRID.
//
// This is the fix for a real false-early-exit bug (audit 2026-07-30,
// runs/perphase-core022-v3-20260730T223828 and
// runs/perphase-core023-v3-20260730T223829): several Want closures wrote
// `return func(v ServerView) bool { return len(v.ResponsesFor(mrid)) > 0 }`,
// checking the RAW view Await polls with, which is never diffed against the
// baseline the way obs.Server eventually is (see Since). gridsim's Responses
// log is unbounded and cross-campaign (deliberately — see ServerView's own
// doc), so the SECOND time a case with a hardcoded mRID runs against the same
// long-lived gridsim process — exactly what re-running one case's own focused
// bundle does — that predicate was ALREADY true on the very first Snapshot,
// before Setup's fresh control had any chance to reach the DUT: Await
// returned "satisfied" after waiting ~0s, the capture window closed within a
// second of opening, and the whole check graded on evidence from a PRIOR
// run's DUT interaction, not this one's. Both of the runs above finished in
// about a second, with the capture (perphase-core023-v3-20260730T223829)
// happening to catch literally zero frames — a `capture integrity: ZERO
// frames` fault printed alongside the otherwise-unremarkable SKIP that
// resulted.
//
// v's own ResponsesFor(mrid) count becomes the floor a later Snapshot's count
// must exceed, so a Response already present at baseline time no longer
// short-circuits the wait — only a genuinely new one satisfies it.
func (v ServerView) WantNewResponse(mrid string) func(ServerView) bool {
	baseline := len(v.ResponsesFor(mrid))
	return func(later ServerView) bool { return len(later.ResponsesFor(mrid)) > baseline }
}

// WantResponseAtLeast builds an Await predicate satisfied only by a NEW
// Response for mrid (posted after v, the baseline — same staleness guard as
// WantNewResponse, and for the same reason: only entries beyond the baseline
// COUNT are ever inspected, never the whole history) whose status is at least
// min.
//
// This is the fix for CORE-022's false-early-exit bug (audit 2026-07-31,
// runs/final-core022-20260731T232047, mRID CERT-CORE022-038e3a26):
// coreResponsesSpec's Want used to be base.WantNewResponse(mrid) alone, which
// is satisfied by the FIRST fresh Response for the mRID — status=1 (Event
// received), which a DUT may legitimately post the moment it parses the
// event, independent of whether the event's own interval has started yet.
// That closed the observation window (and, shortly after, the capture) before
// the DUT had any chance to reach the event's start time and report status=2
// (Event started) — the exact half of the lifecycle critResponseStarted
// (criteria_2030.go) grades. A DUT that would have posted status=2 a few
// polls later got no chance to: the run's own capture window was already
// gone. Requiring status>=2 among the NEW Responses gives the DUT that
// chance; a status=1-only Response is a real observation but not, on its
// own, enough to call the wait done.
func (v ServerView) WantResponseAtLeast(mrid string, min uint8) func(ServerView) bool {
	baseline := len(v.ResponsesFor(mrid))
	return func(later ServerView) bool {
		got := later.ResponsesFor(mrid)
		if len(got) <= baseline {
			return false
		}
		for _, r := range got[baseline:] {
			if r.Status >= min {
				return true
			}
		}
		return false
	}
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

// RegisteredMUP returns the durable MirrorUsagePoint state critMUPRegistered's
// tier-3b needs: a MirrorUsagePoint that carries a deviceLFDI and at least one
// ReadingType, taken from GET /admin/mups — gridsim's registration STORE,
// which (unlike its request log) is never evicted. It exists because
// registration is a ONE-TIME event that ordinarily predates a case's own
// window, so "no POST in this window" is not evidence of non-registration
// when the store shows one exists.
//
// This bench serializes its live runs and gridsim serves one DUT per run, so
// the oldest qualifying entry is unambiguously the DUT's — the same
// single-client assumption this package states everywhere it claims frames by
// remote endpoint rather than by 4-tuple.
func (v ServerView) RegisteredMUP() (AdminMUP, bool) {
	for _, m := range v.MUPs {
		if m.LFDI != "" && len(m.ReadingTypes) > 0 {
			return m, true
		}
	}
	return AdminMUP{}, false
}

// PendingMUP returns a durable MUP record that carries the DUT's LFDI but no
// ReadingType yet: registered, but the evidence critMUPRegistered's own claim
// needs (a MirrorMeterReading/ReadingType) has not arrived. On this bench the
// registration POST itself carries no ReadingType — only the DUT's first
// MirrorMeterReading does, at the postRate the registration advertised
// (bench default 300s, see handleMUPReadings/mergeUOMs in sim/gridsim) — so a
// window that closes before that first reading lands finds exactly this: an
// LFDI-bound MUP with Readings == 0 and ReadingTypes empty.
//
// It exists so a FAIL grade can say "registered, still waiting on its first
// reading" instead of the same words a genuine non-registration gets (audit
// 2026-07-30, runs/perphase-basic029-v4-20260730T232105 assertion 2: the
// admin snapshot at grade time held exactly this shape —
// {href:/mup/0, lfdi:8E5E2FEE…, readings:0} — and the old Server tier's FAIL
// text read "records no MirrorUsagePoint carrying a deviceLFDI and a
// ReadingType either", which is defensible in isolation but reads, to a
// bundle reviewer, exactly like "the DUT never registered". It didn't:
// registration happened 51s before the window closed, which is nowhere near
// the ~300s a reading needs). Call only after RegisteredMUP has already
// returned false: PendingMUP does not itself require ReadingTypes to be
// empty, so an entry satisfying RegisteredMUP would satisfy this too.
func (v ServerView) PendingMUP() (AdminMUP, bool) {
	for _, m := range v.MUPs {
		if m.LFDI != "" {
			return m, true
		}
	}
	return AdminMUP{}, false
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

	// BaselineAt is when this check took its server-side baseline — the floor
	// of everything ServerView reports, because Since() deltas against the
	// snapshot taken at that instant. It is recorded so a criterion that
	// reasons about WHERE ITS WINDOW SITS can state that floor rather than
	// assume it.
	BaselineAt time.Time

	// Published is when this check's own live phase created each DERControl,
	// keyed by the mRID gridsim assigned (Driver.PostControl records it). It
	// is what lets a criterion say that an event did not EXIST when the
	// window opened, which is the only honest ground for reading a missing
	// discovery-time Response as the DUT's behaviour rather than the window's
	// placement.
	Published map[string]time.Time

	notes map[string][]string
}

// PublishedAt reports when this check published the control with this mRID,
// and whether it published one at all.
func (o *Observation) PublishedAt(mrid string) (time.Time, bool) {
	if o == nil || o.Published == nil {
		return time.Time{}, false
	}
	for m, at := range o.Published {
		if strings.EqualFold(m, mrid) {
			return at, true
		}
	}
	return time.Time{}, false
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

	// published records when each DERControl this driver created was accepted
	// by the server, keyed by mRID. run() carries it into the Observation.
	// The map is written only from PostControl, which the live phase calls
	// from one goroutine, and read only after the live phase has finished.
	published map[string]time.Time

	// cleanupErrs records every teardown call that did NOT do what it said.
	//
	// A discarded cleanup error is invisible evidence contamination: the caller
	// writes `_ = d.ClearControls(...)` in a deferred Cleanup, the request
	// fails, the control stays live on a shared bench, and the NEXT row grades
	// a DUT that is still executing this row's event. That was not hypothetical
	// — DELETE /admin/control and DELETE /admin/curve both sent a nil body
	// while gridsim reads {"program":N} from the request BODY, so every clear
	// this suite issued was answered 400 before touching anything, and every
	// control and curve row leaked into the rest of the run.
	//
	// Written only from the teardown helpers below (one goroutine, after the
	// live phase) and read by run()'s deferred Cleanup, which appends it to the
	// row's notes — so a failed teardown lands in the bundle instead of in a
	// discarded return value.
	cleanupErrs []string
}

// Published returns a copy of when this check published each control.
func (d *Driver) Published() map[string]time.Time {
	if len(d.published) == 0 {
		return nil
	}
	out := make(map[string]time.Time, len(d.published))
	for m, at := range d.published {
		out[m] = at
	}
	return out
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
	// gridsim's GET /admin/derputs serves a MAP keyed by resource path — it
	// keeps only the latest body PER PATH, not an append-only history (see
	// DERPut.Path / TestDERPut_LastBodyWins in derput_test.go) — so decoding it
	// straight into a slice here would either fail outright or, decoded into a
	// map and used unsorted, hand PutsFor/Since a Go map's ITERATION order,
	// which is randomised per read. Since's positional delta and "the LAST
	// entry is the most recent" (critDERPut's Server evaluator) both need a
	// stable arrival order a bare map cannot provide, so this decodes the map
	// and sorts it (sortedDERPuts) before it becomes ServerView.DERPuts. A
	// re-home (rehome.go) is exactly the scenario that makes the distinction
	// matter: the DUT's PUT to its ORIGINAL href and its later PUT to the
	// RE-HOMED href are two different map keys, and both must survive — in the
	// order they actually arrived — for a "most recent" read to mean anything.
	var dp struct {
		DERPuts map[string]AdminDERPut `json:"der_puts"`
	}
	if err := d.Admin.DERPuts(ctx, &dp); err != nil {
		v.Errors = append(v.Errors, "GET /admin/derputs: "+err.Error())
	} else {
		v.DERPuts = sortedDERPuts(dp.DERPuts)
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
	// /admin/mups (audit 2026-07-30): the durable MUP registration STATE
	// critMUPRegistered's tier-3b falls back to. Read the same lenient way as
	// the three surfaces above — not because it is an optional fixture, but
	// because a gridsim process that has not yet been restarted onto the build
	// carrying this endpoint answers 404 for it, and that must degrade to "no
	// state to fall back on" (the criterion's older, request-log-only
	// behaviour), not to a bundle-wide Errors entry on every run against it.
	var mp struct {
		MUPs []AdminMUP `json:"mups"`
	}
	if err := d.Admin.Get(ctx, "mups", &mp); err == nil {
		v.MUPs = mp.MUPs
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
// "New" is decided by SEQUENCE POSITION, not by comparing totals. gridsim's
// request log is a bounded ring (sim/simapi/logs.go, 4000 lines) read whole on
// every poll, and one walk is dozens of lines, so on a bench that has been
// running for a couple of hours the ring is permanently saturated: the number
// of /dcap lines it retains stops growing no matter how faithfully the DUT
// polls. This predicate used to read "strictly more /dcap GETs than the
// baseline had", which on a saturated ring is a condition that can never come
// true again — every row using it then waited out its entire window and
// reported that the DUT had not polled. See GETsSince.
func (d *Driver) AwaitWalk(ctx context.Context, base ServerView, timeout time.Duration) (ServerView, time.Duration, bool) {
	return d.Await(ctx, timeout, func(v ServerView) bool {
		return v.PolledSince(base, DiscoveryRoot, 1)
	})
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
	// ResponseRequired overrides gridsim's default responseRequired bitmap
	// for this control (adminDefaultResponseRequired — bit 0x01|0x02, see
	// sim/gridsim/admin.go). A check that needs to prove graceful
	// degradation — a status=2 criterion going Unavailable/Skip rather than
	// FAIL when the control never asked for a specific response — passes 0
	// here.
	ResponseRequired *uint8 `json:"response_required,omitempty"`

	// IW13-001 (docs/design/IW13_ACTIVE_POWER_UNITS_2026-08-12.md §4.2):
	// MaxLimW/FixedW carry HUNDREDTHS OF A PERCENT (opModMaxLimW/opModFixedW's
	// real wire unit), not watts — matches sim/gridsim/admin.go's
	// adminCtrlReq, whose JSON shape this struct mirrors exactly (POSTed
	// straight through). ExpLimW/ImpLimW/GenLimW/LoadLimW are unaffected
	// (§1.2 — still genuine watts).
	ExpLimW  *int64 `json:"exp_lim_W,omitempty"`
	MaxLimW  *int64 `json:"max_lim_W,omitempty"` // hundredths of a percent (IW13-001)
	ImpLimW  *int64 `json:"imp_lim_W,omitempty"`
	GenLimW  *int64 `json:"gen_lim_W,omitempty"`
	LoadLimW *int64 `json:"load_lim_W,omitempty"`
	FixedW   *int64 `json:"fixed_W,omitempty"` // hundredths of a percent, signed (IW13-001)
	// TargetW is opModTargetW (genuine watts, ActivePower — §1.1, already
	// correct) on the EXTENDED control base — added by §4.2 for BASIC-014,
	// which has no other request-surface lever for this axis.
	TargetW        *int64 `json:"target_W,omitempty"`
	Connect        *bool  `json:"connect,omitempty"`
	Energize       *bool  `json:"energize,omitempty"`
	FixedPFInjectW *int64 `json:"fixed_pf_inject_pct,omitempty"`
	FixedPFAbsorbW *int64 `json:"fixed_pf_absorb_pct,omitempty"`
	FixedVarPct    *int64 `json:"fixed_var_pct,omitempty"`
	// FreqDroop is the inline opModFreqDroop element (curve plan #32). Like
	// TargetW it lives only on the extended control base, and gridsim widens
	// this control's storage to carry it.
	FreqDroop *FreqDroopSettings `json:"freq_droop,omitempty"`
}

// PostControl publishes a DERControl and returns the mRID gridsim assigned.
//
// It records WHEN the server accepted the control, because that instant is the
// earliest the DUT could possibly have discovered the event: a criterion about
// a discovery-time Response can only read its absence as the DUT's behaviour
// if its own window opened before this moment. See Observation.Published and
// lifecycleReach.
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
	if out.MRID != "" {
		if d.published == nil {
			d.published = map[string]time.Time{}
		}
		// First publication wins: a case that re-posts the same mRID has not
		// moved the instant the DUT could first have seen that event.
		if _, seen := d.published[out.MRID]; !seen {
			d.published[out.MRID] = time.Now().UTC()
		}
	}
	return out.MRID, nil
}

// CurveRequest is the body of gridsim's POST /admin/curve: a DER curve bound
// into an active DERControl, which is the only way a curve-based mode
// (Volt-VAr, Volt-Watt, Freq-Watt, Watt-PF) reaches the DUT.
type CurveRequest struct {
	Program int          `json:"program"`
	Mode    string       `json:"mode"`
	Points  []CurvePoint `json:"points"`
	VRef    int16        `json:"vref,omitempty"`
	XMult   int8         `json:"x_mult,omitempty"`
	YMult   int8         `json:"y_mult,omitempty"`
	// No XRefType: sep 2.0.4 declares no xRefType element on DERCurve, so
	// gridsim no longer accepts or serves one (it answers 400 to a request that
	// carries the field). See sim/gridsim/curve.go's adminCurveReq.
	YRefType uint8 `json:"y_ref_type,omitempty"`
	// OpenLoopTms is the DERCurve's own openLoopTms (hundredths of a second,
	// 0 = "no limit"). A pointer because 0 is a real value a Figure could
	// prescribe; nil omits the element. See sim/gridsim/curve.go for why this is
	// the only DERCurve scalar with a lever.
	OpenLoopTms *uint16 `json:"open_loop_tms,omitempty"`
	// FreqDroop rides along as an inline opModFreqDroop on the SAME control that
	// carries the curve link — the shape Figure 12 prescribes for BASIC-012.
	FreqDroop   *FreqDroopSettings `json:"freq_droop,omitempty"`
	Description string             `json:"description,omitempty"`
	DurationS   int                `json:"duration_s,omitempty"`
	StartOffset int                `json:"start_offset_s,omitempty"`
	Activate    bool               `json:"activate"`
}

// FreqDroopSettings is sep 2.0.4's FreqDroopType as gridsim's admin API takes
// it: all five children, in the schema's own units, every one required.
//
// The five are VALUES, not pointers, and the JSON tags carry no omitempty —
// which is the opposite of every other optional field on these requests and is
// deliberate. FreqDroopType declares all five minOccurs="1", gridsim answers a
// partial element 400 rather than completing it with zeros (sim/gridsim/
// freqdroop.go), and 0 is a meaningful value for each of them; a struct that
// could omit one would let a caller construct exactly the half-authored control
// the server exists to refuse. Presence of the ELEMENT is carried by the
// pointer to this struct, not by its fields.
type FreqDroopSettings struct {
	DBOF        uint32 `json:"dbof"`          // dead band, over-frequency, thousandths of Hz
	DBUF        uint32 `json:"dbuf"`          // dead band, under-frequency, thousandths of Hz
	KOF         uint16 `json:"kof"`           // over-frequency droop gain, thousandths, unitless
	KUF         uint16 `json:"kuf"`           // under-frequency droop gain, thousandths, unitless
	OpenLoopTms uint16 `json:"open_loop_tms"` // open-loop response time, hundredths of a second
}

// CurvePoint is one (x, y) breakpoint.
type CurvePoint struct {
	X float64 `json:"x"`
	Y float64 `json:"y"`
}

// CurvePublication is what the server minted for a POST /admin/curve: the
// control's mRID, the DERCurve resource's own mRID, and the href the control
// LINKS the curve at.
//
// All three matter to a curve row (IW15-008). The control mRID is the one every
// wire criterion binds to (critDERControlCarriesModeFrom) — and it is the
// SERVER's, not the caller's: gridsim mints "DERC-SP-CURVE-<epoch>" and ignores
// any mRID the request carried, so a row that assumed its own synthetic mRID
// was binding to a string that never existed on any wire. The href is what the
// DUT has to resolve before any curve content can reach it at all, which is a
// separate thing to be able to say about a failing row.
type CurvePublication struct {
	MRID      string `json:"mrid"`
	CurveMRID string `json:"curve_mrid"`
	CurveHref string `json:"curve_href"`
}

// PostCurve publishes a curve-linked control and returns its mRID.
func (d *Driver) PostCurve(ctx context.Context, req CurveRequest) (string, error) {
	pub, err := d.PostCurveDetail(ctx, req)
	return pub.MRID, err
}

// PostCurveDetail is PostCurve with everything the server minted.
func (d *Driver) PostCurveDetail(ctx context.Context, req CurveRequest) (CurvePublication, error) {
	var out CurvePublication
	if err := d.Admin.Post(ctx, "curve", req, &out); err != nil {
		return CurvePublication{}, err
	}
	if out.MRID != "" {
		if d.published == nil {
			d.published = map[string]time.Time{}
		}
		if _, seen := d.published[out.MRID]; !seen {
			d.published[out.MRID] = time.Now().UTC()
		}
	}
	return out, nil
}

// RehomeDER re-homes the DUT's DERCapability and DERSettings hrefs via
// gridsim's admin lever (sim/gridsim/rehome.go), so that a discovery walk
// AFTER this call finds them at hrefs different from the ones any walk before
// it saw.
//
// This is CORE-009/CORE-014's trigger for the DUT's on-change PUT: CSIP IG
// §6.3.5.2 has the client PUT DERCapability/DERSettings "at device start-up
// and on any changes", and lexa-gw's northbound reporter treats a moved
// CAPABILITY or SETTINGS href as exactly such a change (derreport.go,
// updateDERsLocked) — it re-PUTs to the new href even though the content
// itself did not change. Calling this mid-case, after the initial discovery
// walk has already been observed at the ORIGINAL hrefs, is what lets these
// checks catch the on-change PUT within their own window instead of relying
// on a start-up event this run's capture likely missed.
//
// It returns the two new hrefs, for the case's narrative and for a citation
// that wants to name the exact path the PUT is now expected against.
func (d *Driver) RehomeDER(ctx context.Context) (capHref, setHref string, err error) {
	var out struct {
		DERCapabilityHref string `json:"der_capability_href"`
		DERSettingsHref   string `json:"der_settings_href"`
	}
	if err := d.Admin.Post(ctx, "rehome", nil, &out); err != nil {
		return "", "", err
	}
	return out.DERCapabilityHref, out.DERSettingsHref, nil
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
	return d.adminClear(ctx, "/admin/control", "the admin-posted DERControls", program)
}

// ClearCurves removes admin-posted curve controls from a program.
func (d *Driver) ClearCurves(ctx context.Context, program int) error {
	return d.adminClear(ctx, "/admin/curve", "the admin-posted curve controls", program)
}

// adminClear is the one definition of a teardown DELETE, and it exists because
// the two above were silently broken in the same way.
//
// The program travels in the JSON BODY, not in a query string. gridsim's
// adminCtrlDelete (sim/gridsim/admin.go) and adminCurveDelete (curve.go) both
// begin with json.NewDecoder(r.Body).Decode(&struct{Program int}) and answer
// 400 on the io.EOF a nil body produces — before touching a single resource.
// Both clears therefore did nothing at all, on every row, for as long as they
// have existed, and the callers' `_ = d.ClearX(...)` hid it. gridsim's own
// curve_test.go sends the body; this now matches it.
//
// The failure is RECORDED as well as returned (see Driver.cleanupErrs): a
// teardown that failed leaves the next row grading a bench this row is still
// driving, which is the kind of contamination that must appear in the bundle.
// Nothing is recorded when there is no admin API at all — a run with no gridsim
// never armed anything, so there is nothing to have leaked and the "no base URL
// configured" error is a statement about the bench, not about this row.
func (d *Driver) adminClear(ctx context.Context, path, what string, program int) error {
	if !d.Available() {
		return nil
	}
	_, err := d.Admin.Raw(ctx, http.MethodDelete, path, map[string]any{"program": program})
	if err != nil {
		d.cleanupErrs = append(d.cleanupErrs,
			fmt.Sprintf("could not clear %s on program %d (DELETE %s): %v", what, program, path, err))
	}
	return err
}

// CleanupErrors returns what teardown could not undo, for the row's notes. It
// is read after the deferred Cleanup has run.
func (d *Driver) CleanupErrors() []string { return d.cleanupErrs }

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
