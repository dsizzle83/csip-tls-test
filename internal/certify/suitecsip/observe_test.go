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

// TestSinceFlagsARequestLogRingEviction pins RequestLogGap: when the
// baseline's position in gridsim's request-log ring has already fallen out of
// it by the time a check reads again, Since must say so structurally (not
// just in free-text Errors a criterion has to grep for), because a criterion
// that reports "zero matches" from a log the ring has already forgotten is
// the exact false-FAIL bug this method's own doc warns about.
func TestSinceFlagsARequestLogRingEviction(t *testing.T) {
	base := ServerView{rawLines: []string{"line0", "line1"}, rawFirstSeq: 0}
	later := ServerView{Available: true, rawLines: []string{"line500", "line501"}, rawFirstSeq: 500}

	d := later.Since(base)
	if d.RequestLogGap == "" {
		t.Fatal("a ring that wrapped past the baseline must set RequestLogGap")
	}
	if !strings.Contains(d.RequestLogGap, "evicted") {
		t.Errorf("RequestLogGap should name the eviction: %q", d.RequestLogGap)
	}
	found := false
	for _, e := range d.Errors {
		if e == d.RequestLogGap {
			found = true
		}
	}
	if !found {
		t.Error("RequestLogGap must also land in Errors, for callers that still only look there")
	}

	// The ordinary case — no cursor gap at all — must leave RequestLogGap
	// empty, or every criterion that checks it would degrade to unavailable
	// on every run.
	closeBase := ServerView{rawLines: []string{"a", "b"}, rawFirstSeq: 0}
	closeNow := ServerView{Available: true, rawLines: []string{"a", "b", "c"}, rawFirstSeq: 0}
	if g := closeNow.Since(closeBase).RequestLogGap; g != "" {
		t.Errorf("an ordinary (non-evicting) delta must not set RequestLogGap: %q", g)
	}
}

// TestCritMUPRegistered_RequestLogGapIsUnavailableNotFail is BASIC-029's
// regression lock: runs/perphase-basic029-20260730T200339 FAILed this
// criterion's Server tier from a window that opened ~98 minutes and a whole
// campaign's worth of other cases after the DUT's ONE-TIME MirrorUsagePoint
// registration — long enough for gridsim's bounded request-log ring to have
// no memory of it left. A count of zero from a log that itself says it
// cannot be trusted for this window is not evidence the DUT skipped
// registering; it is evidence the window came too late to see it happen.
func TestCritMUPRegistered_RequestLogGapIsUnavailableNotFail(t *testing.T) {
	c := critMUPRegistered()
	v := &ServerView{
		Available: true,
		// A session existed (a GET, so SessionEstablished is true and this
		// doesn't soften to noSessionUnavailable for the wrong reason), but no
		// POST to /mup in this window — and the log itself flags why that
		// can't be trusted.
		Requests:      []ServerRequest{{Method: "GET", Path: "/mup"}},
		RequestLogGap: "the simulator's request log evicted 4000 line(s) between the baseline and this read",
	}
	f := c.Server(v)
	if f.Unavailable == "" {
		t.Fatalf("a flagged request-log gap must be unavailable, not a verdict: got %s (%q)",
			f.Verdict, f.Observed)
	}
	if !strings.Contains(f.Unavailable, "evicted") {
		t.Errorf("the unavailable reason should carry the log's own gap explanation: %q", f.Unavailable)
	}
}

// TestCritMUPRegistered_NoGapStillFails proves the fix is narrowly targeted:
// an empty /mup POST count with NO RequestLogGap (the log is trusted for this
// window) is still a real FAIL, exactly as before.
func TestCritMUPRegistered_NoGapStillFails(t *testing.T) {
	c := critMUPRegistered()
	v := &ServerView{Available: true, Requests: []ServerRequest{{Method: "GET", Path: "/mup"}}}
	f := c.Server(v)
	if f.Verdict != certify.Fail {
		t.Fatalf("no gap, no POST: verdict = %s (%s), want FAIL", f.Verdict, f.Observed)
	}
}

// TestCritMUPRegistered_PostsStillPass proves the RequestLogGap check never
// shadows a genuine PASS: when the log DOES show a /mup POST, that is graded
// exactly as before regardless of whether RequestLogGap happens to be set.
func TestCritMUPRegistered_PostsStillPass(t *testing.T) {
	c := critMUPRegistered()
	v := &ServerView{Available: true, Requests: []ServerRequest{{Method: "POST", Path: "/mup"}}}
	f := c.Server(v)
	if f.Verdict != certify.Pass {
		t.Fatalf("a recorded /mup POST: verdict = %s (%s), want PASS", f.Verdict, f.Observed)
	}
}

// TestCritMUPRegistered_ReadingPOSTDoesNotMasqueradeAsRegistration is the
// regression lock for the audit's third finding (2026-07-30,
// runs/stamped-basic029-20260730T073518 assertion 2): the request-log tier
// used to match any path with the "/mup" PREFIX, which also matches the
// READING endpoint "/mup/{n}". A DUT posting readings every 300s but never
// registering would rack up a POST count under the old code and PASS on
// evidence that was never a registration — that run's own Wire tier found no
// MirrorUsagePoint POST in the transcript at all, yet the Server tier
// reported "36 POST(s) to the MirrorUsagePoint tree" and PASSed. A reading
// POST alone, with no exact "/mup" POST and no MUP state to fall back on,
// must FAIL, not PASS.
func TestCritMUPRegistered_ReadingPOSTDoesNotMasqueradeAsRegistration(t *testing.T) {
	c := critMUPRegistered()
	v := &ServerView{Available: true, Requests: []ServerRequest{
		{Method: "POST", Path: "/mup/0"},
		{Method: "POST", Path: "/mup/0"},
	}}
	f := c.Server(v)
	if f.Verdict != certify.Fail {
		t.Fatalf("reading POSTs only, no registration POST, no state: verdict = %s (%s), want FAIL",
			f.Verdict, f.Observed)
	}
	if strings.Contains(f.Observed, "36 POST") || strings.Contains(f.Observed, "registers") {
		t.Errorf("Observed should not credit reading POSTs as registrations: %q", f.Observed)
	}
}

// TestCritMUPRegistered_StateFallsBackWhenWindowMissedRegistration is
// BASIC-029's tier-3 regression lock (audit 2026-07-30,
// runs/perphase-basic029-v3-20260730T223730 assertion 2): registration is a
// ONE-TIME event that ordinarily predates a case's own window, and unlike
// runs/perphase-basic029-20260730T200339 (the ring-eviction case above) this
// is NOT a ring gap — Since reconstructed the window correctly and it
// legitimately holds no registration POST, because the DUT registered before
// the window opened and gridsim's bounded ring, while intact, simply doesn't
// reach back that far. The durable /admin/mups STATE is exactly what still
// remembers a fact that old, and grading against it (rather than FAILing a
// DUT that in fact registered) is the whole point of the tier.
func TestCritMUPRegistered_StateFallsBackWhenWindowMissedRegistration(t *testing.T) {
	c := critMUPRegistered()
	v := &ServerView{
		Available: true,
		// A session existed (a GET), no in-window registration POST, and no
		// RequestLogGap: the log is trusted for this window and genuinely
		// has nothing — the old code would FAIL here.
		Requests: []ServerRequest{{Method: "GET", Path: "/mup"}},
		MUPs: []AdminMUP{
			{Href: "/mup/0", LFDI: "8E5E2FEE3190F4058B54692EE57A2D673D347586", ReadingTypes: []uint8{38}, CreatedAt: 1753900000},
		},
	}
	f := c.Server(v)
	if f.Verdict != certify.Pass {
		t.Fatalf("registration predates the window but MUP state confirms it: verdict = %s (%s), want PASS",
			f.Verdict, f.Observed)
	}
	if !strings.Contains(f.Observed, "/admin/mups") || !strings.Contains(f.Observed, "/mup/0") {
		t.Errorf("Observed must cite the admin snapshot and the MUP's href: %q", f.Observed)
	}
	if !strings.Contains(f.Observed, "this window opened after") {
		t.Errorf("Observed must narrate that registration predated the window: %q", f.Observed)
	}
}

// TestCritMUPRegistered_StateRequiresLFDIAndReadingType proves the state
// tier does not credit a MUP entry that is missing either the LFDI binding it
// to the DUT or a ReadingType — an incomplete registration is not the fact
// this criterion claims, so it must fall through to the next tier rather than
// PASS on a partial match.
func TestCritMUPRegistered_StateRequiresLFDIAndReadingType(t *testing.T) {
	c := critMUPRegistered()
	v := &ServerView{
		Available: true,
		Requests:  []ServerRequest{{Method: "GET", Path: "/mup"}},
		MUPs:      []AdminMUP{{Href: "/mup/0", LFDI: "", ReadingTypes: []uint8{38}}},
	}
	f := c.Server(v)
	if f.Verdict != certify.Fail {
		t.Fatalf("a MUP with no LFDI must not satisfy the state tier: verdict = %s (%s), want FAIL",
			f.Verdict, f.Observed)
	}

	v2 := &ServerView{
		Available: true,
		Requests:  []ServerRequest{{Method: "GET", Path: "/mup"}},
		MUPs:      []AdminMUP{{Href: "/mup/0", LFDI: "abc123"}},
	}
	f2 := c.Server(v2)
	if f2.Verdict != certify.Fail {
		t.Fatalf("a MUP with no ReadingType must not satisfy the state tier: verdict = %s (%s), want FAIL",
			f2.Verdict, f2.Observed)
	}
}

// TestCritMUPRegistered_PendingStateFAILsWithPreciseWording is the regression
// lock for runs/perphase-basic029-v4-20260730T232105 assertion 2: gridsim's
// /admin/mups held {href:/mup/0, lfdi:8E5E2FEE…, readings:0} at grade time —
// the DUT HAD registered, 24s before the run even started, but its
// registration POST on this bench carries no ReadingType; only its first
// MirrorMeterReading does, at the 300s postRate gridsim advertised, and the
// window closed 52s after registration. The old FAIL wording ("records no
// MirrorUsagePoint carrying a deviceLFDI and a ReadingType either") is
// technically accurate but, to a bundle reader, indistinguishable from "the
// DUT never registered". PendingMUP's tier must name the registration it
// actually found and say plainly that the reading, not the registration, is
// what's missing — while the verdict itself stays FAIL: the claim's
// ReadingType genuinely is not in evidence.
func TestCritMUPRegistered_PendingStateFAILsWithPreciseWording(t *testing.T) {
	c := critMUPRegistered()
	v := &ServerView{
		Available: true,
		Requests:  []ServerRequest{{Method: "GET", Path: "/mup"}},
		MUPs: []AdminMUP{{
			Href: "/mup/0", LFDI: "8E5E2FEE3190F4058B54692EE57A2D673D347586",
			ReadingTypes: nil, Readings: 0, CreatedAt: 1785453642,
		}},
	}
	f := c.Server(v)
	if f.Verdict != certify.Fail {
		t.Fatalf("an LFDI-bound MUP with 0 readings and the window expired: verdict = %s (%s), want FAIL",
			f.Verdict, f.Observed)
	}
	if !strings.Contains(f.Observed, "/mup/0") || !strings.Contains(f.Observed, "8E5E2FEE") {
		t.Errorf("Observed must cite the specific MUP the durable store found: %q", f.Observed)
	}
	if !strings.Contains(f.Observed, "not that it never registered") {
		t.Errorf("Observed must distinguish 'registered, reading pending' from 'never registered': %q", f.Observed)
	}
	if strings.Contains(f.Observed, "carrying a deviceLFDI at all") {
		t.Errorf("the generic never-registered wording must not be used when a pending registration was found "+
			"in the store: %q", f.Observed)
	}
}

// TestCritMUPRegistered_RingGapIsStillLastResortWhenStateIsAlsoEmpty proves
// the state tier does not shadow the ring-gap Unavailable (e186056) when the
// state has nothing either — e.g. an older gridsim predating /admin/mups, or
// one that was restarted since the DUT registered and honestly lost its
// state. The evidence chain in that case is: no in-window POST, no state,
// and the log itself says it cannot be trusted — which is still unavailable,
// not a FAIL.
func TestCritMUPRegistered_RingGapIsStillLastResortWhenStateIsAlsoEmpty(t *testing.T) {
	c := critMUPRegistered()
	v := &ServerView{
		Available:     true,
		Requests:      []ServerRequest{{Method: "GET", Path: "/mup"}},
		RequestLogGap: "the simulator's request log evicted 4000 line(s) between the baseline and this read",
	}
	f := c.Server(v)
	if f.Unavailable == "" {
		t.Fatalf("no state and a flagged ring gap must be unavailable, not a verdict: got %s (%q)",
			f.Verdict, f.Observed)
	}
}

// TestServerView_RegisteredMUP covers the helper directly: it must require
// BOTH a non-empty LFDI and at least one ReadingType, and return the first
// qualifying entry.
func TestServerView_RegisteredMUP(t *testing.T) {
	v := ServerView{MUPs: []AdminMUP{
		{Href: "/mup/0", LFDI: "", ReadingTypes: []uint8{38}},
		{Href: "/mup/1", LFDI: "abc123", ReadingTypes: nil},
		{Href: "/mup/2", LFDI: "abc123", ReadingTypes: []uint8{38, 63}},
	}}
	got, ok := v.RegisteredMUP()
	if !ok {
		t.Fatal("expected a qualifying MUP")
	}
	if got.Href != "/mup/2" {
		t.Errorf("RegisteredMUP returned %q, want the first entry with BOTH an LFDI and a ReadingType (/mup/2)", got.Href)
	}

	empty := ServerView{MUPs: []AdminMUP{{Href: "/mup/0", LFDI: "", ReadingTypes: []uint8{38}}}}
	if _, ok := empty.RegisteredMUP(); ok {
		t.Error("a MUP list with no entry carrying both an LFDI and a ReadingType must not qualify")
	}
}

// TestServerView_PendingMUP covers the fallback helper directly: unlike
// RegisteredMUP it requires only the LFDI, because on this bench the
// registration POST itself carries no ReadingType — only the DUT's first
// MirrorMeterReading does (see PendingMUP's doc) — so an entry can be
// genuinely, honestly "registered" long before it qualifies for
// RegisteredMUP.
func TestServerView_PendingMUP(t *testing.T) {
	v := ServerView{MUPs: []AdminMUP{
		{Href: "/mup/0", LFDI: "", ReadingTypes: nil},
		{Href: "/mup/1", LFDI: "abc123", ReadingTypes: nil, Readings: 0},
	}}
	got, ok := v.PendingMUP()
	if !ok {
		t.Fatal("expected a pending (LFDI-bound, no ReadingType yet) MUP")
	}
	if got.Href != "/mup/1" {
		t.Errorf("PendingMUP returned %q, want the first LFDI-bound entry (/mup/1)", got.Href)
	}

	empty := ServerView{MUPs: []AdminMUP{{Href: "/mup/0", LFDI: ""}}}
	if _, ok := empty.PendingMUP(); ok {
		t.Error("a MUP list with no LFDI-bound entry at all must not qualify as pending")
	}

	// An entry that ALSO qualifies for RegisteredMUP (LFDI + ReadingType)
	// still satisfies PendingMUP too — callers are expected to try
	// RegisteredMUP first, as critMUPRegistered's Server tier does.
	complete := ServerView{MUPs: []AdminMUP{{Href: "/mup/2", LFDI: "abc123", ReadingTypes: []uint8{38}}}}
	if _, ok := complete.PendingMUP(); !ok {
		t.Error("PendingMUP should not itself exclude a complete registration; tier ordering is the caller's job")
	}
}

// TestServerView_WantNewResponse is the regression lock for the harness bug
// found while diagnosing runs/perphase-core022-v3-20260730T223828 and
// runs/perphase-core023-v3-20260730T223829: both focused re-runs finished in
// about a second (CORE-023's capture caught literally zero frames) because
// their Want predicates read `len(v.ResponsesFor(mrid)) > 0` against the RAW
// view Await polls with — never diffed against the baseline the way
// obs.Server eventually is. gridsim's Responses log is unbounded and
// cross-campaign by design, so a Response the SAME hardcoded mRID already
// earned in an EARLIER run against the same long-lived gridsim process made
// that predicate true on the very first Snapshot, before Setup's freshly
// posted control had any chance to reach the DUT. WantNewResponse must
// require a count STRICTLY GREATER than the baseline's own, so a Response
// already present when the baseline was taken can never satisfy it alone.
func TestServerView_WantNewResponse(t *testing.T) {
	// The exact shape of the bug: the baseline ALREADY carries a Response for
	// this mRID (left over from an earlier run), and the "later" view handed
	// to the predicate is that SAME baseline — nothing new happened. The old
	// code (`len(v.ResponsesFor(mrid))>0`) would return true here; this must not.
	base := ServerView{Responses: []AdminResponse{{Subject: "CERT-CORE023-LOSE", Status: 7}}}
	want := base.WantNewResponse("CERT-CORE023-LOSE")
	if want(base) {
		t.Fatal("a Response already present at baseline time must not satisfy WantNewResponse on its own")
	}

	// A genuinely NEW Response for the same mRID — one more than the
	// baseline held — must satisfy it.
	later := ServerView{Responses: []AdminResponse{
		{Subject: "CERT-CORE023-LOSE", Status: 7},
		{Subject: "CERT-CORE023-LOSE", Status: 7},
	}}
	if !want(later) {
		t.Error("a Response count exceeding the baseline's must satisfy WantNewResponse")
	}

	// An empty baseline (the ordinary, non-stale case) still fires on the
	// very first matching Response — unchanged behaviour for a fresh mRID.
	fresh := ServerView{}.WantNewResponse("CERT-CORE022")
	if fresh(ServerView{Responses: []AdminResponse{{Subject: "CERT-CORE022", Status: 1}}}) == false {
		t.Error("an empty baseline must still be satisfied by the first matching Response")
	}
}

// TestAggWant_IgnoresStaleResponseFromEarlierRun proves the fix at the
// aggregator Want-builder level: a scenario whose baseline already holds a
// Response for its first lifecycle's mRID (a focused re-run against a
// gridsim process that already answered this exact mRID once today) must NOT
// report satisfied against that same baseline — only a genuinely new
// Response should.
func TestAggWant_IgnoresStaleResponseFromEarlierRun(t *testing.T) {
	sc := aggScenario{Lifecycles: []aggLifecycle{{MRID: "M1"}}}
	stale := ServerView{Responses: []AdminResponse{{Subject: "M1", Status: 1}}}
	p := aggWant(sc)(stale)
	if p == nil {
		t.Fatal("a lifecycle-bearing scenario must still produce a predicate")
	}
	if p(stale) {
		t.Error("the predicate must not be satisfied by a Response already present at baseline time")
	}
	newer := ServerView{Responses: []AdminResponse{
		{Subject: "M1", Status: 1},
		{Subject: "M1", Status: 2},
	}}
	if !p(newer) {
		t.Error("the predicate must be satisfied once a Response beyond the baseline's count arrives")
	}
}

// TestCoreSupersedingWant_WaitsForWinnerTooNotJustLoser is the regression lock
// for runs/perphase-core023-v4-20260730T235854: coreSuperseding's Want used to
// be base.WantNewResponse(loser) alone. gridsim resolves the loser to
// Superseded(7) at arbitration time — the first walk after Setup — regardless
// of either control's own StartOffset, so a loser-only predicate is satisfied
// (and, with it, the live phase and shortly after the capture window end)
// long before the winner's own interval has run its course. CORE-023's own
// assertions 1/2 (critResponsePosted / critResponseStarted) grade the WINNER,
// so a window that closes on the loser's Response alone can never contain the
// evidence those assertions need, independent of what the DUT actually does.
func TestCoreSupersedingWant_WaitsForWinnerTooNotJustLoser(t *testing.T) {
	const winner, loser = "CERT-CORE023-WIN", "CERT-CORE023-LOSE"
	base := ServerView{}
	p := coreSupersedingWant(winner, loser)(base)

	// The old bug's exact shape: the loser earns its Superseded(7) — gridsim's
	// arbitration-time resolution — but the winner has posted nothing at all
	// yet. The old predicate (loser alone) would already report satisfied here.
	loserOnly := ServerView{Responses: []AdminResponse{{Subject: loser, Status: 7}}}
	if p(loserOnly) {
		t.Fatal("the predicate must not be satisfied while the winner has posted no Response of its own — " +
			"this is exactly the shape that let runs/perphase-core023-v4-20260730T235854's capture close " +
			"before the winner had any chance to be on the wire")
	}

	// Symmetric sanity: the winner alone, loser still silent, must not
	// satisfy it either — CORE-023 grades a superseding PAIR.
	winnerOnly := ServerView{Responses: []AdminResponse{{Subject: winner, Status: 1}}}
	if p(winnerOnly) {
		t.Fatal("the predicate must not be satisfied while the loser has posted no Response of its own")
	}

	// Both mRIDs have earned a fresh Response beyond the baseline: satisfied.
	both := ServerView{Responses: []AdminResponse{
		{Subject: loser, Status: 7},
		{Subject: winner, Status: 1},
	}}
	if !p(both) {
		t.Error("the predicate must be satisfied once BOTH winner and loser have a Response beyond the baseline")
	}

	// Staleness guard at the composed level: a baseline that already carries
	// Responses for BOTH mRIDs (a focused re-run against a gridsim process
	// that already answered this exact pair earlier today — the hardcoded-mRID
	// staleness class WantNewResponse itself guards against) must not read
	// "satisfied" against that same baseline.
	staleBase := ServerView{Responses: []AdminResponse{
		{Subject: loser, Status: 7},
		{Subject: winner, Status: 1},
	}}
	staleP := coreSupersedingWant(winner, loser)(staleBase)
	if staleP(staleBase) {
		t.Error("Responses already present at baseline time must not satisfy the predicate on their own")
	}
}

// TestBasicMUPWant_WaitsForReadingTypeNotJustAPoll is the regression lock for
// runs/perphase-basic029-v4-20260730T232105: BASIC-029 had no Want of its
// own, so it fell back to AwaitWalk — satisfied by the DUT's very next /dcap
// poll, whatever that poll happens to be for. A run with -param csip.wait=12m
// finished in ~28s because that poll landed 25s into the window purely by
// coincidence of when the run started relative to the DUT's own 60s-cadence
// boundary, and grading then found the durable MUP state short of what
// critMUPRegistered's own tier needs: an LFDI-bound MUP is not enough, it
// also needs a ReadingType (ServerView.RegisteredMUP) — and on this bench the
// registration POST itself carries none; only the DUT's first
// MirrorMeterReading does, ~300s later. basicMUPWant must not be satisfied by
// a fresh discovery walk alone: that is the exact shape of the old bug for
// this row.
func TestBasicMUPWant_WaitsForReadingTypeNotJustAPoll(t *testing.T) {
	base := ServerView{Requests: []ServerRequest{{Method: "GET", Path: DiscoveryRoot}}}
	want := basicMUPWant(base)

	// The DUT's next /dcap poll landed — the old AwaitWalk-only behaviour
	// would call this satisfied — but no MUP registration exists at all yet.
	walkOnlyNothingRegistered := ServerView{Requests: []ServerRequest{
		{Method: "GET", Path: DiscoveryRoot}, {Method: "GET", Path: DiscoveryRoot},
	}}
	if want(walkOnlyNothingRegistered) {
		t.Fatal("a fresh discovery walk alone must not satisfy basicMUPWant: it proves nothing about the " +
			"MirrorUsagePoint registration this check actually grades")
	}

	// The MUP IS registered but its ReadingType has not landed yet — the
	// exact {lfdi, readings:0} shape gridsim's /admin/mups held in the
	// audited run. Must still wait: this is precisely the evidence
	// critMUPRegistered's own tier 3 requires and does not yet have.
	walkPlusPendingRegistration := ServerView{
		Requests: []ServerRequest{{Method: "GET", Path: DiscoveryRoot}, {Method: "GET", Path: DiscoveryRoot}},
		MUPs: []AdminMUP{{Href: "/mup/0", LFDI: "8E5E2FEE3190F4058B54692EE57A2D673D347586",
			ReadingTypes: nil, Readings: 0}},
	}
	if want(walkPlusPendingRegistration) {
		t.Fatal("an LFDI-bound MUP with no ReadingType yet (registered, reading pending) must not satisfy " +
			"basicMUPWant")
	}

	// Once the ReadingType lands (the first MirrorMeterReading POST merges
	// it into the durable record), the predicate is satisfied.
	walkPlusCompleteRegistration := ServerView{
		Requests: []ServerRequest{{Method: "GET", Path: DiscoveryRoot}, {Method: "GET", Path: DiscoveryRoot}},
		MUPs: []AdminMUP{{Href: "/mup/0", LFDI: "8E5E2FEE3190F4058B54692EE57A2D673D347586",
			ReadingTypes: []uint8{38}, Readings: 1}},
	}
	if !want(walkPlusCompleteRegistration) {
		t.Error("a fresh discovery walk plus a ReadingType-bearing MUP registration must satisfy basicMUPWant")
	}
}

// TestBasicMUPWant_AlreadyRegisteredStillNeedsItsOwnWalk proves the fix does
// not regress the ordinary, steady-state case (a DUT whose registration,
// ReadingType included, completed well before this run started) while also
// pinning that the fresh-walk requirement is not dropped just because the MUP
// state already qualifies: the walk is what guarantees the capture window
// spans at least one /dcap exchange, which the DeviceCapability criterion
// (assertion 1 of BASIC-029) needs evidence from — the same guarantee
// AwaitWalk gave every other Setup-less row.
//
// This is NOT the WantNewResponse staleness bug (audit 2026-07-30,
// CORE-022/CORE-023): RegisteredMUP reads durable, one-time STATE, not a
// per-run delta, so an already-complete registration is supposed to satisfy
// it — there is nothing here for an earlier run's evidence to spuriously
// satisfy the wrong way.
func TestBasicMUPWant_AlreadyRegisteredStillNeedsItsOwnWalk(t *testing.T) {
	base := ServerView{Requests: []ServerRequest{{Method: "GET", Path: DiscoveryRoot}}}
	want := basicMUPWant(base)

	// MUP state already qualifies, but no fresh walk has been observed yet
	// (the view still equals the baseline's own GETs(DiscoveryRoot) count).
	registeredButNoFreshWalk := ServerView{
		Requests: []ServerRequest{{Method: "GET", Path: DiscoveryRoot}}, // same count as base
		MUPs:     []AdminMUP{{Href: "/mup/0", LFDI: "abc123", ReadingTypes: []uint8{38}, Readings: 3}},
	}
	if want(registeredButNoFreshWalk) {
		t.Fatal("basicMUPWant must still wait for its own fresh discovery walk even when the MUP state " +
			"already qualifies — this guarantees assertion 1's /dcap evidence is captured in-window")
	}

	// Once that walk is also observed, an already-complete registration is
	// graded promptly, exactly as tier 3 has always allowed.
	registeredAndFreshWalk := ServerView{
		Requests: []ServerRequest{{Method: "GET", Path: DiscoveryRoot}, {Method: "GET", Path: DiscoveryRoot}},
		MUPs:     []AdminMUP{{Href: "/mup/0", LFDI: "abc123", ReadingTypes: []uint8{38}, Readings: 3}},
	}
	if !want(registeredAndFreshWalk) {
		t.Error("an already-complete registration must satisfy basicMUPWant as soon as the guaranteed fresh " +
			"discovery walk is also seen")
	}
}

// TestZeroLifecycleScenarioDoesNotPanic pins Bug #3 from
// runs/shakedown-20260729T003843: AGG-002 has no lifecycles, so its Want yields
// a nil predicate, and handing that nil to Await dereferenced it — a panic. The
// fix routes a nil predicate to AwaitWalk (specWant) and guards Await defensively.
func TestZeroLifecycleScenarioDoesNotPanic(t *testing.T) {
	// A zero-lifecycle scenario (AGG-002's shape) produces NO wait predicate.
	sc := aggScenario{}
	if want := aggWant(sc)(ServerView{}); want != nil {
		t.Fatal("a zero-lifecycle scenario produced a non-nil wait predicate")
	}

	// specWant must collapse that to nil so the caller takes the AwaitWalk path —
	// for both a Want that returns nil AND a spec with no Want at all.
	if p := specWant(spec{Want: aggWant(sc)}, ServerView{}); p != nil {
		t.Error("specWant did not collapse a nil-returning Want to nil")
	}
	if p := specWant(spec{}, ServerView{}); p != nil {
		t.Error("specWant of a Want-less spec was not nil")
	}

	// A lifecycle-bearing scenario still yields a predicate that fires on the
	// first lifecycle's Response.
	sc2 := aggScenario{Lifecycles: []aggLifecycle{{MRID: "M1"}}}
	p := specWant(spec{Want: aggWant(sc2)}, ServerView{})
	if p == nil {
		t.Fatal("a lifecycle-bearing scenario produced no wait predicate")
	}
	if !p(ServerView{Responses: []AdminResponse{{Subject: "M1"}}}) {
		t.Error("the predicate did not fire on the first lifecycle's Response")
	}

	// The deref site itself is guarded: Await must not panic on a nil predicate,
	// even though the caller never hands it one. Against a live stub it reaches
	// the pre-loop want(view) call, which is precisely where it used to panic.
	srv := gridsimStub(t, newStubState())
	d := &Driver{rc: &certify.RunCtx{Case: &certify.Case{UID: "x"}}, Admin: certify.NewAdminClient(srv.URL, nil)}
	if _, _, satisfied := d.Await(context.Background(), time.Millisecond, nil); satisfied {
		t.Error("a nil predicate reported the wait satisfied")
	}
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
		// gridsim's real GET /admin/derputs serves a MAP keyed by resource path
		// (derput.go's handleAdminDERPuts encodes ReceivedDERPuts()'s
		// map[string]DERPut directly), not a list — this stub used to fake a
		// list, which meant Snapshot's decode was never actually exercised
		// against the shape gridsim serves and TestDriverSnapshotCollectsEverything
		// passed while the real Driver.Snapshot silently failed to decode every
		// DER PUT gridsim ever reported (see sortedDERPuts in observe.go).
		writeJSON(w, map[string]any{
			"der_puts": map[string]AdminDERPut{"/p": {Path: "/p", Resource: "DERStatus", Body: "<x/>"}},
		})
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
