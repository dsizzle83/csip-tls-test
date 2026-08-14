package suitecsip

// teeth_agg_test.go is teeth_test.go's discipline applied to the criteria the
// DER AGGREGATOR CLIENT profile added on 2026-07-28: every one driven twice,
// once with input that satisfies it and once with input that does not, and the
// second case is the assertion.
//
// These rows carry a third obligation the direct-client rows do not, and it is
// the one most of the tests below are really about. Every aggregator row is
// written against a fixture this bench does not build — four EndDevices, a
// Subscription/Notification function set — and the tempting shortcut is to let
// the missing fixture produce a verdict. It must not. A missing fixture is a
// fact about the BENCH, and the only honest answers are Unavailable (which
// becomes a SKIP naming the gap) or, where the procedure's own words say the
// artefact does not exist on any wire, a declared Skip. Never FAIL. A false
// FAIL on a bench gap is the worst outcome available here, because it looks
// exactly like diligence and would be believed.

import (
	"net/textproto"
	"strings"
	"testing"
	"time"

	"csip-tls-test/internal/certify"
)

// post builds a POST exchange carrying a sep+xml request body.
func post(path, body string, status int, respHdr ...string) Exchange {
	req := msg(Request, "POST", path, 0, body)
	resp := &Message{Kind: Response, Status: status, Header: textproto.MIMEHeader{},
		Time: time.Unix(1001, 0), Frames: []int{2}, CipherStart: 0, CipherEnd: 10}
	for i := 0; i+1 < len(respHdr); i += 2 {
		resp.Header.Set(respHdr[i], respHdr[i+1])
	}
	return Exchange{Req: req, Resp: resp}
}

// responsePOST builds the DERControlResponse POST a DUT sends for an event.
// itoa is teeth_test.go's.
func responsePOST(mrid string, status int) Exchange {
	return post("/rsps/0/r", `<DERControlResponse xmlns="`+Namespace+`">`+
		`<subject>`+mrid+`</subject><status>`+itoa(int64(status))+`</status></DERControlResponse>`, 201)
}

const edevListWithFleet = `<EndDeviceList xmlns="` + Namespace + `" all="5" results="5">
 <EndDevice href="/edev/0"><lFDI>aa</lFDI><SubscriptionListLink href="/edev/0/sub" all="0"/>
   <FunctionSetAssignmentsListLink href="/edev/0/fsa"/><DERListLink href="/edev/0/der"/></EndDevice>
 <EndDevice href="/edev/1"><lFDI>bb</lFDI>
   <FunctionSetAssignmentsListLink href="/edev/1/fsa"/><DERListLink href="/edev/1/der"/></EndDevice>
 <EndDevice href="/edev/2"><lFDI>cc</lFDI>
   <FunctionSetAssignmentsListLink href="/edev/2/fsa"/><DERListLink href="/edev/2/der"/></EndDevice>
 <EndDevice href="/edev/3"><lFDI>dd</lFDI>
   <FunctionSetAssignmentsListLink href="/edev/3/fsa"/><DERListLink href="/edev/3/der"/></EndDevice>
 <EndDevice href="/edev/4"><lFDI>ee</lFDI>
   <FunctionSetAssignmentsListLink href="/edev/4/fsa"/><DERListLink href="/edev/4/der"/></EndDevice>
</EndDeviceList>`

// The bench's actual shape: one EndDevice, no subscription function set.
const edevListOneDevice = `<EndDeviceList xmlns="` + Namespace + `" all="1" results="1">
 <EndDevice href="/edev/0"><lFDI>aa</lFDI>
   <FunctionSetAssignmentsListLink href="/edev/0/fsa"/><DERListLink href="/edev/0/der"/></EndDevice>
</EndDeviceList>`

// TestFleetCriterionSkipsRatherThanFailsOnAShortList is the single most
// important test in this file.
//
// gridsim serves one EndDevice. If critAggregatorFleet answered that with FAIL,
// every aggregator row would report a conformance failure on every run of a
// perfectly conformant gateway, and the twenty-two rows the re-scope added
// would be worse than useless: they would be actively misleading.
func TestFleetCriterionSkipsRatherThanFailsOnAShortList(t *testing.T) {
	short := synthTranscript(get("/edev", 200, edevListOneDevice))
	f := critAggregatorFleet().Wire(nil, short)
	if f.Unavailable != "" {
		t.Fatalf("the fleet criterion declined to decide: %s", f.Unavailable)
	}
	if f.Verdict != certify.Skip {
		t.Fatalf("verdict on a one-EndDevice bench = %s, want SKIP — how many EndDevices the SERVER "+
			"publishes is a fact about the bench, never a finding about the DUT (observed: %s)",
			f.Verdict, f.Observed)
	}
	for _, want := range []string{"served 1 EndDevice", "EDA1", "sim/gridsim"} {
		if !strings.Contains(f.Observed, want) {
			t.Errorf("the SKIP does not mention %q, so it is not a work item: %s", want, f.Observed)
		}
	}

	// The full fixture passes...
	full := synthTranscript(get("/edev", 200, edevListWithFleet))
	wantVerdict(t, "fleet (Figure-15 fixture served)", critAggregatorFleet(), full, certify.Pass)

	// ...and a fixture of the right SIZE whose devices lack the links the
	// AGG-001 setup requires is a real FAIL, because that is a server serving
	// the wrong thing rather than a bench serving too little.
	crippled := strings.ReplaceAll(edevListWithFleet, `<DERListLink href="/edev/3/der"/>`, "")
	wantVerdict(t, "fleet (a managed EndDevice with no DERListLink)",
		critAggregatorFleet(), synthTranscript(get("/edev", 200, crippled)), certify.Fail)

	// No EndDeviceList at all is "we could not tell", not a verdict.
	wantUnavailable(t, "fleet (no EndDeviceList)", critAggregatorFleet(), synthTranscript())
}

// TestSubscriptionPostedDistinguishesBenchGapFromDUTFault is the other half of
// the same principle, and the more interesting half: here the criterion CAN
// fail the DUT, but only once the bench has offered it the function set.
func TestSubscriptionPostedDistinguishesBenchGapFromDUTFault(t *testing.T) {
	c := critSubscriptionPosted("EndDeviceList", "the aggregator EndDevice's SubscriptionListLink")

	// The bench never offered subscription: unavailable, naming the gap.
	//
	// What the gap IS changed at 4d2d551 and the reason had to change with it.
	// sim/gridsim implements the function set now, so a SKIP saying it did not
	// would send a reader off to write code that already exists; what the SKIP
	// means today is that the SWITCH IS OFF, and it has to name the switch to be
	// worth printing at all.
	noOffer := synthTranscript(get("/edev", 200, edevListOneDevice))
	reason := wantUnavailable(t, "subscription (server offers none)", c, noOffer)
	for _, want := range []string{"no SubscriptionListLink", "-subscription", "SIM_FLEET=4"} {
		if !strings.Contains(reason, want) {
			t.Errorf("the reason does not name the lever that is off (%q): %s", want, reason)
		}
	}
	if strings.Contains(reason, "implements no Subscription") {
		t.Errorf("the reason still claims gridsim implements no Subscription resource; it has since "+
			"4d2d551, and a SKIP describing work that is already done is worse than no SKIP: %s", reason)
	}

	// The bench DID offer it and the DUT ignored it: that is a real finding.
	offered := synthTranscript(get("/edev", 200, edevListWithFleet))
	f := wantVerdict(t, "subscription (offered, not taken)", c, offered, certify.Fail)
	if !strings.Contains(f.Observed, "POSTed no Subscription") {
		t.Errorf("the FAIL does not say what the DUT failed to do: %s", f.Observed)
	}

	// The DUT subscribed properly.
	good := synthTranscript(
		get("/edev", 200, edevListWithFleet),
		post("/edev/0/sub", `<Subscription xmlns="`+Namespace+`">`+
			`<subscribedResource>/edev</subscribedResource></Subscription>`, 201,
			"Location", "/edev/0/sub/1"),
	)
	wantVerdict(t, "subscription (posted correctly)", c, good, certify.Pass)

	// A 201 with no Location names nothing the client can cancel later.
	noLoc := synthTranscript(
		get("/edev", 200, edevListWithFleet),
		post("/edev/0/sub", `<Subscription xmlns="`+Namespace+`">`+
			`<subscribedResource>/edev</subscribedResource></Subscription>`, 201),
	)
	wantVerdict(t, "subscription (201 without Location)", c, noLoc, certify.Fail)

	// And the server answering something other than 201.
	wrong := synthTranscript(
		get("/edev", 200, edevListWithFleet),
		post("/edev/0/sub", `<Subscription xmlns="`+Namespace+`">`+
			`<subscribedResource>/edev</subscribedResource></Subscription>`, 200,
			"Location", "/edev/0/sub/1"),
	)
	wantVerdict(t, "subscription (answered 200)", c, wrong, certify.Fail)
}

// TestSupersessionStatusHasTeethBothWays is the errata's teeth.
//
// Annex A seq 5/6 change AGG-007 and AGG-008 from the printed status 7 to
// status 14. Two failures are possible and both are tested: a DUT that reports
// 7 where 14 is required must FAIL, and a DUT that reports 14 where 7 is
// required (AGG-009) must FAIL too. A criterion accepting "7 or 14" would pass
// both and assert nothing at all — which is precisely what CORE-023's criterion
// does, correctly, because CORE-023 does not pin which of the two applies.
func TestSupersessionStatusHasTeethBothWays(t *testing.T) {
	const mrid = "CERT-AGG007SY"
	c14 := critSupersessionStatus(mrid, 14, "Event Superseded from another program", "because reasons")
	c7 := critSupersessionStatus(mrid, 7, "Event Superseded", "because other reasons")

	got14 := synthTranscript(responsePOST(mrid, 1), responsePOST(mrid, 14))
	got7 := synthTranscript(responsePOST(mrid, 1), responsePOST(mrid, 7))

	wantVerdict(t, "AGG-007 shape, DUT reports 14", c14, got14, certify.Pass)
	f := wantVerdict(t, "AGG-007 shape, DUT reports 7", c14, got7, certify.Fail)
	if !strings.Contains(f.Observed, "requires 14") {
		t.Errorf("the FAIL does not say which status the row requires: %s", f.Observed)
	}

	wantVerdict(t, "AGG-009 shape, DUT reports 7", c7, got7, certify.Pass)
	wantVerdict(t, "AGG-009 shape, DUT reports 14", c7, got14, certify.Fail)

	// A Response for some OTHER control must not satisfy the criterion.
	other := synthTranscript(responsePOST("CERT-SOMETHING-ELSE", 14))
	wantUnavailable(t, "supersession (no Response for this mRID)", c14, other)
}

// TestNoSupersessionCriterionRequiresEvidenceOfAbsence pins the discriminating
// criterion of the INDEPENDENT-control family — and the trap in every absence
// claim, which is that "nothing was seen" and "the thing was absent" are not
// the same statement.
func TestNoSupersessionCriterionRequiresEvidenceOfAbsence(t *testing.T) {
	mrids := []string{"CERT-AGG010SY", "CERT-AGG010TFA"}
	c := critNoSupersession(mrids)

	// A silent window proves nothing: the DUT may simply not have got there.
	wantUnavailable(t, "no-supersession (no Responses at all)", c, synthTranscript())

	// Lifecycle Responses with no 7 and no 14: the claim is supported.
	clean := synthTranscript(
		responsePOST(mrids[0], 1), responsePOST(mrids[0], 2),
		responsePOST(mrids[1], 1), responsePOST(mrids[1], 2),
	)
	wantVerdict(t, "no-supersession (independent modes coexist)", c, clean, certify.Pass)

	// A supersession Response for EITHER control falsifies it.
	for _, bad := range []int{7, 14} {
		dirty := synthTranscript(
			responsePOST(mrids[0], 1), responsePOST(mrids[0], bad),
			responsePOST(mrids[1], 1),
		)
		f := wantVerdict(t, "no-supersession (status "+itoa(int64(bad))+" seen)", c, dirty, certify.Fail)
		if !strings.Contains(f.Observed, "INDEPENDENT") {
			t.Errorf("the FAIL does not explain why the status is wrong here: %s", f.Observed)
		}
	}
}

// ── event lifecycle ──────────────────────────────────────────────────────────

// lifecycleMRID is the mRID every lifecycle test below publishes. It carries a
// run nonce because the suite's own rows now do (aggScenario.withNonce): the
// hardware AGG-011 FAIL these tests were written from turned on a STATIC mRID
// that earlier campaigns had already acknowledged, and a fixture that kept
// using the static string would be testing a shape the harness can no longer
// produce.
var lifecycleMRID = withRunNonce("CERT-AGG011TFA", "5eeded01")

// lifecycleObs builds the two facts a lifecycle criterion weighs its window
// against: when this check took its baseline, and when it created the event.
//
// spanningObs is the ordinary shape, and since the nonce it is the ONLY shape a
// live aggregator row produces — the check opens its window, then publishes an
// mRID nothing has ever seen, so the event cannot predate the window. The tests
// that want the other shape say so explicitly, because "the window opened after
// the DUT could first have seen this event" is exactly the fact the grade turns
// on and it must never be arrived at by accident.
func lifecycleObs(published time.Time) *Observation {
	base := time.Date(2026, 8, 13, 11, 20, 0, 0, time.UTC)
	return &Observation{BaselineAt: base,
		Published: map[string]time.Time{lifecycleMRID: published}}
}

func spanningObs() *Observation {
	return lifecycleObs(time.Date(2026, 8, 13, 11, 20, 1, 0, time.UTC))
}

// lifecycleEvidence is a capture window whose attributed frames begin at t.
func lifecycleEvidence(t time.Time) *certify.Evidence {
	return &certify.Evidence{Set: &certify.FrameSet{Start: t}}
}

// spanningWindow is the frame floor that matches spanningObs: open before the
// event existed.
func spanningWindow() *certify.Evidence {
	return lifecycleEvidence(time.Date(2026, 8, 13, 11, 20, 0, 0, time.UTC))
}

// wireVerdict is wantVerdict with the evidence handed in, because the lifecycle
// criterion reads the window's floor off it.
func wireVerdict(t *testing.T, name string, c criterion, ev *certify.Evidence,
	tr *Transcript, want certify.Verdict) Finding {
	t.Helper()
	f := c.Wire(ev, tr)
	if f.Unavailable != "" {
		t.Fatalf("%s: evaluator could not decide: %s", name, f.Unavailable)
	}
	if f.Verdict != want {
		t.Fatalf("%s: verdict = %s, want %s (observed: %s)", name, f.Verdict, want, f.Observed)
	}
	return f
}

// TestEventLifecycleReportsAShortWindowAsAMeasurement pins the distinction a
// timing criterion has to make: a DUT that never acknowledged the event at all
// FAILs, but a DUT that got as far as the harness's window allowed is a short
// MEASUREMENT, not a finding.
func TestEventLifecycleReportsAShortWindowAsAMeasurement(t *testing.T) {
	mrid := lifecycleMRID
	c := critEventLifecycle(spanningObs(), mrid, "TFA", 180)
	ev := spanningWindow()

	full := synthTranscript(responsePOST(mrid, 1), responsePOST(mrid, 2), responsePOST(mrid, 3))
	wireVerdict(t, "lifecycle (complete)", c, ev, full, certify.Pass)

	partial := synthTranscript(responsePOST(mrid, 1), responsePOST(mrid, 2))
	f := wireVerdict(t, "lifecycle (window shorter than the interval)", c, ev, partial, certify.Warn)
	if !strings.Contains(f.Observed, waitParam) {
		t.Errorf("the WARN does not tell the operator how to close it out: %s", f.Observed)
	}

	// Statuses but never a 1, in a window that was open before the event
	// existed: the procedure requires status 1 on discovery, the window can
	// carry the finding, so this one really is a finding.
	noReceived := synthTranscript(responsePOST(mrid, 2), responsePOST(mrid, 3))
	f = wireVerdict(t, "lifecycle (no Event Received)", c, ev, noReceived, certify.Fail)
	if !strings.Contains(f.Observed, "status 1") {
		t.Errorf("the FAIL does not name the missing status: %s", f.Observed)
	}
	if !strings.Contains(f.Observed, "whole opportunity") {
		t.Errorf("the FAIL does not justify that its window could carry the finding: %s", f.Observed)
	}

	wantUnavailable(t, "lifecycle (no Responses)", c, synthTranscript())
}

// TestEventLifecycleWindowPlacementIsNotADUTFailure is the AGG-011 regression
// (lexa-gw known_issues AGG-011-received-ordering), re-derived for per-run
// mRIDs.
//
// The hardware shape: csip-conf-v1.3::AGG-011 in
// runs/compliance-a78887f-20260813b caught ONE Response in its frame window —
// status 2 (Started) for the then-STATIC CERT-AGG011TFA — and graded the absent
// status 1 as "the DUT … never POSTed status 1 (Event Received)". gridsim's own
// log (runs/gridsim-iw13-20260813T113648Z.log) holds that event's status 1
// twice, at 09:26:28 and 09:34:26, from the earlier runs that re-published the
// same mRID — two hours before this case's window opened. The DUT had
// acknowledged the event; the harness had graded its own window placement.
//
// The mRID is per-run now, so the FIXTURE half of that shape is gone: an event
// minted this run cannot have been acknowledged two hours ago. What is tested
// here is the reasoning that remains, stated in the only terms this check can
// verify for itself — WHEN it created the event, against WHERE its own window
// opened. Nothing below consults gridsim's cross-campaign log, and that is the
// point: an undated, LFDI-blind match on <subject> could excuse a DUT with a
// Response from a different identity in a different campaign, and once it had,
// the FAIL was unreachable for that mRID forever (F3/F4).
func TestEventLifecycleWindowPlacementIsNotADUTFailure(t *testing.T) {
	mrid := lifecycleMRID
	started := synthTranscript(responsePOST(mrid, 2))

	// (a) THE TEETH, and the case a live aggregator row now always produces: a
	// fresh mRID, published after this window opened, and a DUT that POSTed a
	// Started without ever POSTing a Received. Nothing can excuse that, and it
	// is exactly the regression the pre-2026-08-14 code could not report.
	c := critEventLifecycle(spanningObs(), mrid, "TFA", 240)
	f := wireVerdict(t, "lifecycle (regressed DUT, fresh mRID, spanning window)", c,
		spanningWindow(), started, certify.Fail)
	if !strings.Contains(f.Observed, "never status 1") {
		t.Errorf("the FAIL does not name the missing status: %s", f.Observed)
	}
	if !strings.Contains(f.Observed, "whole opportunity") || !strings.Contains(f.Observed, mrid) {
		t.Errorf("the FAIL does not justify that its window could carry the finding: %s", f.Observed)
	}

	// The same shape at the SERVER tier, whose floor is the baseline snapshot
	// rather than the capture window: same verdict, for the same reason.
	sf := c.Server(&ServerView{Available: true, Responses: []AdminResponse{{Subject: mrid, Status: 2}}})
	if sf.Verdict != certify.Fail {
		t.Fatalf("server tier: verdict = %s, want FAIL (observed: %s)", sf.Verdict, sf.Observed)
	}

	// (b) the surviving backstop: a window that opened AFTER this check created
	// the event cannot convict, because the status 1 may have been POSTed below
	// its own floor. This is the [2]-only shape that used to be excused by
	// gridsim's log; it is excused here by a dated fact this check recorded
	// itself, and the finding says which.
	late := lifecycleEvidence(time.Date(2026, 8, 13, 11, 22, 0, 0, time.UTC))
	f = wireVerdict(t, "lifecycle (window opened after the event existed)", c, late, started, certify.Warn)
	for _, want := range []string{"[2]", "NOT adjudicable", "below this window's floor", mrid} {
		if !strings.Contains(f.Observed, want) {
			t.Errorf("the WARN does not name %q: %s", want, f.Observed)
		}
	}

	// (c) an event this check never created is the other unadjudicable shape —
	// it may have existed, and been acknowledged, before the window opened.
	orphan := critEventLifecycle(&Observation{BaselineAt: spanningObs().BaselineAt}, mrid, "TFA", 240)
	f = wireVerdict(t, "lifecycle (this check did not publish the event)", orphan,
		spanningWindow(), started, certify.Warn)
	if !strings.Contains(f.Observed, "did not record creating") {
		t.Errorf("the WARN does not name why the window cannot adjudicate: %s", f.Observed)
	}

	// (d) an INVERSION — a Received that follows the event's start — is the
	// DUT's behaviour ONLY where the window saw the whole of its opportunity to
	// acknowledge. With a spanning window it is a FAIL...
	inverted := synthTranscript(responsePOST(mrid, 2), responsePOST(mrid, 1))
	f = wireVerdict(t, "lifecycle (2 then 1, spanning window)", c, spanningWindow(), inverted, certify.Fail)
	if !strings.Contains(f.Observed, "only AFTER status 2") {
		t.Errorf("the FAIL does not name the inversion: %s", f.Observed)
	}

	// ...and with a LATE window it must not be, because the identical statuses
	// are what a DUT that acknowledged below the floor and then RE-POSTed its
	// Received on retry leaves in the window. Convicting there would be the
	// window-placement grading this whole criterion exists to stop, aimed at
	// the one shape it was introduced to excuse.
	f = wireVerdict(t, "lifecycle (2 then 1, late window)", c, late, inverted, certify.Warn)
	if strings.Contains(f.Observed, "only AFTER") {
		t.Errorf("a window that opened after the event existed convicted the DUT of an inversion it "+
			"cannot distinguish from a retried Received: %s", f.Observed)
	}

	// A DUT that RE-POSTs its Received after the start is not an inversion even
	// with a spanning window: the acknowledgment still came first.
	retry := synthTranscript(responsePOST(mrid, 1), responsePOST(mrid, 2), responsePOST(mrid, 1))
	f = wireVerdict(t, "lifecycle (1, 2, 1 retry)", c, spanningWindow(), retry, certify.Warn)
	if strings.Contains(f.Observed, "only AFTER") {
		t.Errorf("a re-POSTed Received was graded as an inversion: %s", f.Observed)
	}

	// (e) the full lifecycle is unchanged by any of this.
	full := synthTranscript(responsePOST(mrid, 1), responsePOST(mrid, 2), responsePOST(mrid, 3))
	wireVerdict(t, "lifecycle (complete, late window)", c, late, full, certify.Pass)
	wireVerdict(t, "lifecycle (complete, spanning window)", c, spanningWindow(), full, certify.Pass)
}

// TestEventLifecycleDefersToTheServerWhenTheFramesMissedTheReceived pins the
// other half of window-awareness: gridsim recorded the status 1 INSIDE this
// check's window and no frame carrying it was attributed to the case. The
// capture cannot decide that, so the wire tier steps aside (mint then asks the
// server) rather than reporting a frame-attribution gap as a DUT failure.
func TestEventLifecycleDefersToTheServerWhenTheFramesMissedTheReceived(t *testing.T) {
	mrid := lifecycleMRID
	obs := spanningObs()
	obs.Server = ServerView{Available: true,
		Responses: []AdminResponse{{Subject: mrid, Status: 1}, {Subject: mrid, Status: 2}}}
	c := critEventLifecycle(obs, mrid, "TFA", 240)

	f := c.Wire(spanningWindow(), synthTranscript(responsePOST(mrid, 2)))
	if f.Unavailable == "" {
		t.Fatalf("verdict = %s (%s), want the wire tier to step aside", f.Verdict, f.Observed)
	}
	if !strings.Contains(f.Unavailable, "no frame carrying that POST was attributed") {
		t.Errorf("the reason does not name the attribution gap: %s", f.Unavailable)
	}
	// The server's own record then decides, and it has the whole lifecycle
	// prefix: a WARN about the window's length, not a FAIL about the DUT.
	sf := c.Server(&obs.Server)
	if sf.Verdict != certify.Warn {
		t.Fatalf("server tier: verdict = %s, want WARN (observed: %s)", sf.Verdict, sf.Observed)
	}
}

// TestControlDeliveryCatchesTheWrongMode guards the property AGG-010, AGG-011
// and AGG-012 rest on entirely: their two controls must carry DIFFERENT modes.
// A bench that published the same mode twice would turn all three rows into
// AGG-007's shape while still reporting them by their own names.
func TestControlDeliveryCatchesTheWrongMode(t *testing.T) {
	sc := aggScenarios()["AGG-010"]
	c := critAggControlsDelivered(sc)

	list := func(pairs ...[2]string) string {
		var b strings.Builder
		b.WriteString(`<DERControlList xmlns="` + Namespace + `" all="2" results="2">`)
		for _, p := range pairs {
			b.WriteString(`<DERControl><mRID>` + p[0] + `</mRID><DERControlBase><` + p[1] +
				`>1</` + p[1] + `></DERControlBase></DERControl>`)
		}
		b.WriteString(`</DERControlList>`)
		return b.String()
	}

	good := synthTranscript(get("/derp/0/derc", 200, list(
		[2]string{"CERT-AGG010SY", "opModFixedPFInjectW"},
		[2]string{"CERT-AGG010TFA", "opModFixedW"},
	)))
	wantVerdict(t, "delivery (both controls, correct modes)", c, good, certify.Pass)

	sameMode := synthTranscript(get("/derp/0/derc", 200, list(
		[2]string{"CERT-AGG010SY", "opModFixedPFInjectW"},
		[2]string{"CERT-AGG010TFA", "opModFixedPFInjectW"},
	)))
	f := wantVerdict(t, "delivery (the independent row's controls share a mode)", c, sameMode, certify.Fail)
	if !strings.Contains(f.Observed, "opModFixedW") {
		t.Errorf("the FAIL does not name the mode that should have been there: %s", f.Observed)
	}

	missing := synthTranscript(get("/derp/0/derc", 200, list(
		[2]string{"CERT-AGG010SY", "opModFixedPFInjectW"},
	)))
	wantVerdict(t, "delivery (one control never arrived)", c, missing, certify.Fail)

	wantUnavailable(t, "delivery (no DERControlList)", c, synthTranscript())
}

// TestNewControlAcquiredHasTeeth covers MAINT-004's one real lever: the added
// DERControl's interval and its "no randomization" requirement.
func TestNewControlAcquiredHasTeeth(t *testing.T) {
	const mrid = "CERT-MAINT004"
	c := critNewControlAcquired(mrid, 900, 300)

	derc := func(inner string) string {
		return `<DERControlList xmlns="` + Namespace + `" all="1" results="1">` +
			`<DERControl><mRID>` + mrid + `</mRID>` + inner + `</DERControl></DERControlList>`
	}

	wantVerdict(t, "added control (correct interval, no randomization)", c,
		synthTranscript(get("/derp/0/derc", 200, derc(`<interval><duration>300</duration></interval>`))),
		certify.Pass)

	wantVerdict(t, "added control (wrong duration)", c,
		synthTranscript(get("/derp/0/derc", 200, derc(`<interval><duration>60</duration></interval>`))),
		certify.Fail)

	wantVerdict(t, "added control (randomized where the procedure says not to)", c,
		synthTranscript(get("/derp/0/derc", 200,
			derc(`<interval><duration>300</duration></interval><randomizeStart>30</randomizeStart>`))),
		certify.Fail)

	wantVerdict(t, "added control (no interval at all)", c,
		synthTranscript(get("/derp/0/derc", 200, derc(``))), certify.Fail)

	wantUnavailable(t, "added control (not yet acquired)", c,
		synthTranscript(get("/derp/0/derc", 200,
			`<DERControlList xmlns="`+Namespace+`" all="0" results="0"/>`)))
}

// TestSubscriptionAdvertisedIsABenchCriterion pins that the precondition every
// subscription row opens with reports the BENCH's state and never fails the DUT
// for it.
func TestSubscriptionAdvertisedIsABenchCriterion(t *testing.T) {
	c := critSubscriptionAdvertised()

	f := c.Wire(nil, synthTranscript(get("/edev", 200, edevListOneDevice)))
	if f.Unavailable != "" {
		t.Fatalf("declined to decide where an EndDeviceList was present: %s", f.Unavailable)
	}
	if f.Verdict != certify.Skip {
		t.Fatalf("verdict with no SubscriptionListLink = %s, want SKIP", f.Verdict)
	}

	// Advertised, and the FSAList unconditionally subscribable: the precondition
	// really is met.
	fsa := `<FunctionSetAssignmentsList xmlns="` + Namespace + `" subscribable="1" all="1" results="1">` +
		`<FunctionSetAssignments href="/edev/0/fsa/0"><DERProgramListLink href="/derp"/>` +
		`<TimeLink href="/tm"/></FunctionSetAssignments></FunctionSetAssignmentsList>`
	ok := synthTranscript(get("/edev", 200, edevListWithFleet), get("/edev/0/fsa", 200, fsa))
	wantVerdict(t, "precondition (advertised and subscribable)", c, ok, certify.Pass)

	// Advertised but the FSAList is not subscribable: still the bench's setup,
	// still a SKIP.
	notSub := strings.Replace(fsa, `subscribable="1"`, `subscribable="0"`, 1)
	f = c.Wire(nil, synthTranscript(get("/edev", 200, edevListWithFleet), get("/edev/0/fsa", 200, notSub)))
	if f.Verdict != certify.Skip {
		t.Errorf("verdict with subscribable=0 = %s, want SKIP — the setup is the server's job", f.Verdict)
	}

	wantUnavailable(t, "precondition (no EndDeviceList)", c, synthTranscript())
}

// TestDeclaredSkipsNeverProduceAVerdict is the belt-and-braces check on the two
// criterion families that STILL exist purely to be honest about what was not
// measured. A declared Skip has no evaluators at all, so it cannot accidentally
// start passing when somebody adds one.
//
// The list is short now, and its shortness is the point of this change: the
// per-device Response bullets and every notification criterion grew real
// evaluators. What remains here is what no bench lever can reach — a
// DefaultDERControl's activation, which IEEE 2030.5 defines no acknowledgment
// for, and the per-device bullets whose subject is the client's internal state.
func TestDeclaredSkipsNeverProduceAVerdict(t *testing.T) {
	for name, c := range map[string]criterion{
		"fan-out":     critPerDeviceFanOut("something happens", "EDA1 and EDA2", "because of a named reason"),
		"out-of-band": critDefaultControlOutOfBand("TFA"),
	} {
		if c.Wire != nil || c.Server != nil {
			t.Errorf("%s: has an evaluator; it is supposed to be a declared SKIP with a reason", name)
		}
		if c.Skip == "" {
			t.Errorf("%s: SKIPs without saying why", name)
		}
		if c.Claim == "" {
			t.Errorf("%s: has no claim, so the bundle would not say what went unmeasured", name)
		}
	}

	// A per-device SKIP may no longer blame the fleet. The fixture exists, so a
	// reason that sent a reader to build it would send them after the wrong
	// thing entirely.
	if got := critPerDeviceFanOut("x", "EDA1", noWireArtefact).Skip; strings.Contains(got, "-fleet 4") {
		t.Errorf("a declared per-device SKIP still blames the missing fleet: %q", got)
	}

	// The notification criterion's claim must carry the accepted statuses, since
	// that is the whole errata-sensitive part of it.
	if got := critNotificationAnswered(emptyObservation(), []int{201, 204}, "why").Claim; !strings.Contains(got, "201 or 204") {
		t.Errorf("the notification claim does not carry its accepted statuses: %q", got)
	}
}

// emptyObservation is the Observation a criterion constructor is handed when a
// test cares only about the criterion's SHAPE — its claim, its declared reason —
// and not about what a run observed.
func emptyObservation() *Observation {
	return &Observation{Case: &certify.Case{}, Params: map[string]string{}}
}
