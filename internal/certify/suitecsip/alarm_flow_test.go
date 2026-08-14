package suitecsip

// alarm_flow_test.go drives BASIC-027's arm/await/clear flow against a REAL
// in-process gridsim AND a REAL in-process advanced solar sim (the same
// southbound.SolarServer modsim/mbapsdev embed), the same sim-backed pattern
// rehome_flow_test.go uses for CORE-014's re-home lever: nothing about
// either the SERVER or the SOUTHBOUND DEVICE side is synthesised. What
// stands in for the DUT/hub — there is no cgo/mTLS stack or MQTT broker in
// this suite's unit tests, so a live southbound-fault-to-LogEvent pipeline
// is out of scope here exactly as a real DUT's own behaviour is in
// rehome_flow_test.go — is a direct read of the sim's own register state
// (proving the fault this case's Change hook arms really lands) and a plain
// POST of a LogEvent to gridsim's LogEventList (proving the exact
// Server-tier evaluators BASIC-027's Criteria list uses grade a real
// admin-recorded LogEvent correctly), mirroring doPUT's role in
// TestCORE014Flow_RehomeThenPUTToNewHrefIsObserved.

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"csip-tls-test/internal/certify"
	"csip-tls-test/sim/gridsim"
	southbound "csip-tls-test/sim/southbound"
)

// alarmFlowBench starts a gridsim (CSIP + admin listeners) and a real
// advanced solar sim fronted by a POST /fault endpoint standing in for
// modsim's simapi (sim/simapi's handleFault: 204 on a successful
// ApplyFault, 400 with the error body otherwise — replicated here exactly
// so SimClient.Fault's contract is exercised for real), then wires a Driver
// whose rc.Sims["modsim"] reaches it — the same shape cmd/certify wires from
// -modsim-api on a live bench.
func alarmFlowBench(t *testing.T) (csipURL string, ss *southbound.SolarServer, d *Driver) {
	t.Helper()
	s := gridsim.NewServer("")
	csip := httptest.NewServer(s.Handler())
	t.Cleanup(csip.Close)
	admin := httptest.NewServer(s.AdminHandler())
	t.Cleanup(admin.Close)

	var err error
	ss, err = southbound.NewSolarServerAdvanced("tcp://127.0.0.1:0", 5000, "")
	if err != nil {
		t.Fatalf("NewSolarServerAdvanced: %v", err)
	}
	t.Cleanup(ss.Stop)

	modsimAPI := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/fault" || r.Method != http.MethodPost {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if err := ss.ApplyFault(body); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(modsimAPI.Close)

	rc := &certify.RunCtx{
		Case:    &certify.Case{UID: "csip-conf-v1.3::BASIC-027"},
		GridSim: certify.NewAdminClient(admin.URL, http.DefaultClient),
		Targets: certify.Targets{GridSimAdmin: admin.URL},
		Sims: map[string]*certify.SimClient{
			alarmSimName: certify.NewSimClient(alarmSimName, modsimAPI.URL, http.DefaultClient),
		},
	}
	return csip.URL, ss, NewDriver(rc)
}

// TestBASIC027Flow_ArmAwaitClearIsObserved is the deliverable's end-to-end
// proof, the same shape as TestCORE014Flow_RehomeThenPUTToNewHrefIsObserved:
// arming the fault through the EXACT path Change uses (d.rc.Sim(alarmSimName)
// -> SimClient.Fault) lands a real, threshold-violating voltage reading on
// the sim's 701 model (not just a bit — see solar_adv.go's
// advCoupledVoltHz); a simulated LogEvent POST — standing in for the DUT's
// hub-alarm-detector-to-northbound-poster pipeline, which is out of reach of
// this suite's unit tests — is graded PASS by the SAME Server-tier
// evaluators (logEventsPostedFinding, logEventCodesFinding) BASIC-027's
// Criteria list uses; and clearing through the EXACT path Cleanup uses
// restores the sim to its no-fault state.
func TestBASIC027Flow_ArmAwaitClearIsObserved(t *testing.T) {
	ctx := context.Background()
	csipURL, ss, d := alarmFlowBench(t)

	baseline := d.Snapshot(ctx)
	if got := baseline.LogEvents; len(got) != 0 {
		t.Fatalf("baseline already carries LogEvent(s): %+v", got)
	}
	if alrm := ss.Snapshot().Advanced.Alrm; alrm != 0 {
		t.Fatalf("sim already alarming before this case armed anything: Alrm=%#x", alrm)
	}

	// Arm exactly as basicAlarms' Change hook does.
	sim, err := d.rc.Sim(alarmSimName)
	if err != nil {
		t.Fatalf("d.rc.Sim(%q): %v", alarmSimName, err)
	}
	if err := sim.Fault(ctx, map[string]any{"kind": "raise_alarm", "bits": alarmFaultBits}, nil); err != nil {
		t.Fatalf("arm raise_alarm: %v", err)
	}

	// ss is a REAL, RUNNING animated sim (unlike solar_adv_test.go's bare
	// newAdvSolar fixture), so the armed bits only reach the 701 register
	// block on the animation's own 5 s tick (advMirror701, called from
	// animateSolarAdvanced) — there is no exported way to force one from
	// outside package sim. Poll rather than sleep a fixed 5 s so the test
	// is not flaky right at that boundary.
	const wantAlrm = uint32(1 << 11) // AC_UNDER_VOLT
	var adv *southbound.SolarAdvancedState
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		adv = ss.Snapshot().Advanced
		if adv.Alrm == wantAlrm {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if adv.Alrm != wantAlrm {
		t.Fatalf("Alrm after arming (waited up to 8s for an animation tick) = %#x, want %#x", adv.Alrm, wantAlrm)
	}
	if adv.Meas701.W_W < 0 {
		t.Errorf("sanity: W_W = %v, want non-negative", adv.Meas701.W_W)
	}

	// Simulate the DUT's resulting LogEvent POST (functionSet 11 = DER,
	// logEventCode 4 = bus.LogEventDERUnderVoltage per lexa-hub's
	// alrm701ToTable14, profileID 2 = CSIP, logEventPEN 0 = standard-defined
	// per lexa-gw's logEventPENStandard) to the EndDevice's known
	// LogEventList target (sim/gridsim/server.go's fixed "/edev/2/lev").
	body := `<LogEvent xmlns="urn:ieee:std:2030.5:ns"><createdDateTime>1700000000</createdDateTime>` +
		`<functionSet>11</functionSet><logEventCode>4</logEventCode><logEventID>1</logEventID>` +
		`<logEventPEN>0</logEventPEN><profileID>2</profileID></LogEvent>`
	req, err := http.NewRequest(http.MethodPost, csipURL+"/edev/2/lev", strings.NewReader(body))
	if err != nil {
		t.Fatalf("build LogEvent POST: %v", err)
	}
	req.Header.Set("Content-Type", "application/sep+xml")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST LogEvent: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("POST LogEvent = %d, want 201", resp.StatusCode)
	}

	view := d.Snapshot(ctx).Since(baseline)
	if len(view.LogEvents) != 1 {
		t.Fatalf("view.LogEvents = %+v, want exactly 1", view.LogEvents)
	}

	// The exact evaluators BASIC-027's Criteria list uses must grade this a
	// PASS from the ServerView tier.
	o := &Observation{Params: map[string]string{alarmArmedAtParam: time.Now().UTC().Format(time.RFC3339)}}
	if f := logEventsPostedFinding(o)(&view); f.Verdict != certify.Pass {
		t.Errorf("logEventsPostedFinding on the post-arm window = %s (%s)", f.Verdict, f.Observed)
	}
	if f := logEventCodesFinding(&view); f.Verdict != certify.Pass || !strings.Contains(f.Observed, "4") {
		t.Errorf("logEventCodesFinding on the post-arm window = %s (%s), want PASS naming code 4",
			f.Verdict, f.Observed)
	}

	// Clear exactly as basicAlarms' Cleanup hook does.
	if err := sim.Fault(ctx, map[string]any{"kind": "raise_alarm", "clear": true}, nil); err != nil {
		t.Fatalf("clear raise_alarm: %v", err)
	}
	deadline = time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		adv = ss.Snapshot().Advanced
		if adv.Alrm == 0 {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if adv.Alrm != 0 {
		t.Errorf("Alrm after clear (waited up to 8s for an animation tick) = %#x, want 0", adv.Alrm)
	}
}

// TestBASIC027Flow_NoAlarmReasonDistinguishesCauses pins noAlarmReason's
// three distinct explanations for an empty LogEvents view — armed-but-not-
// yet-observed, could-not-arm (a bench gap), and never-attempted (no
// gridsim admin) — so a reader of a SKIP verdict is told which one happened
// rather than the pre-fix "outside this suite's read-only reach", which
// stopped being true the moment this case started arming the fault itself.
func TestBASIC027Flow_NoAlarmReasonDistinguishesCauses(t *testing.T) {
	cases := []struct {
		name   string
		params map[string]string
		want   string
	}{
		{"armed, not yet observed", map[string]string{alarmArmedAtParam: "2026-08-01T12:00:00Z"},
			"armed a southbound AC_UNDER_VOLT fault"},
		{"could not arm", map[string]string{changeFailed: "sim %q is not configured"},
			"could not arm the fault"},
		{"never attempted", map[string]string{}, "gridsim's admin API was not available"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := noAlarmReason(&Observation{Params: c.params})
			if !strings.Contains(got, c.want) {
				t.Errorf("noAlarmReason(%+v) = %q, want it to contain %q", c.params, got, c.want)
			}
		})
	}
}

// TestBASIC027Flow_AlarmNoteRendersScriptedAction is alarmNote's regression
// lock, the same convention TestCORE014Flow_RehomeNoteCarriesTimeAndHrefs
// pins for rehomeNote: after Change stashes alarm_armed_at in an
// Observation's Params, the narrative must name the scripted action, the
// bits armed, the sim it was armed on, and that it is a TEST FIXTURE action,
// not a DUT perturbation — and must be silent when Change never ran.
func TestBASIC027Flow_AlarmNoteRendersScriptedAction(t *testing.T) {
	note := alarmNote(&Observation{Params: map[string]string{alarmArmedAtParam: "2026-08-01T12:00:00Z"}})
	for _, want := range []string{"2026-08-01T12:00:00Z", "0x800", alarmSimName, "SCRIPTED", "not a DUT perturbation"} {
		if !strings.Contains(note, want) {
			t.Errorf("alarmNote is missing %q: %s", want, note)
		}
	}

	if got := alarmNote(&Observation{Params: map[string]string{}}); got != "" {
		t.Errorf("alarmNote with no alarm_armed_at should be empty, got %q", got)
	}

	failNote := alarmNote(&Observation{Params: map[string]string{changeFailed: "sim not configured"}})
	if !strings.Contains(failNote, "sim not configured") || !strings.Contains(failNote, "BENCH gap") {
		t.Errorf("alarmNote on a failed Change should explain the bench gap: %q", failNote)
	}
}

// ── wire tier: the churn-relocated-answer regression (answerTo) ───────────────
//
// These are FIXTURE tests: they synthesise a decrypted transcript with the
// exact shape the false FAIL had — a LogEvent POST on a SECOND conversation the
// DUT owns, whose 201 the per-conversation index pairing left off the
// exchange's Resp — and assert BASIC-027's assertion 2 (critLogEventPosted) now
// PASSes, while a genuinely-unanswered or non-201 POST still FAILs. No bench.

// leWire is the body BASIC-027's LogEvent-POST criterion recognises: a complete
// DER LogEvent (functionSet 11, logEventCode 4) carrying all six elements the
// wire criterion requires.
const leWire = `<LogEvent xmlns="urn:ieee:std:2030.5:ns"><createdDateTime>1700000000</createdDateTime>` +
	`<functionSet>11</functionSet><logEventCode>4</logEventCode><logEventID>1</logEventID>` +
	`<logEventPEN>0</logEventPEN><profileID>2</profileID></LogEvent>`

// framed overrides a synthetic message's capture frames — msg() defaults every
// message to frame 1, and answerTo matches by frame ORDER, so the tests below
// set frames explicitly and return the message for chaining.
func framed(m *Message, frames ...int) *Message {
	m.Frames = frames
	return m
}

// discWalk is a minimal selected session (the discovery walk) carrying a /dcap
// GET and no POST, so the LogEvent POST can only be found on a sibling.
func discWalk() *Transcript {
	return synthTranscript(get("/dcap", 200, `<DeviceCapability xmlns="urn:ieee:std:2030.5:ns"/>`))
}

// siblingPOST builds the second conversation the DUT opened alongside the
// discovery walk. The POST rides it; resp, when non-nil, is present in the
// conversation's Responses but is deliberately NOT paired onto the exchange —
// exactly the index skew answerTo has to see through. Every message remembers
// its conversation via Message.In, as a recovered one does.
func siblingPOST(post, resp *Message) *Transcript {
	conv := &Transcript{Decrypted: true, Exchanges: []Exchange{{Req: post}}}
	post.In = conv
	if resp != nil {
		conv.Responses = []*Message{resp}
		resp.In = conv
	}
	return conv
}

func TestBASIC027Wire_LogEventAnswerRecoveredFromAChurnedSibling(t *testing.T) {
	crit := critLogEventPosted(&Observation{Params: map[string]string{}})

	post := framed(msg(Request, "POST", "/edev/2/lev", 0, leWire), 20)
	created := framed(msg(Response, "", "", 201, "", "Location", "/edev/2/lev/1"), 21)

	disc := discWalk()
	disc.Others = []*Transcript{siblingPOST(post, created)}

	f := crit.Wire(nil, disc)
	if f.Unavailable != "" {
		t.Fatalf("evaluator declined to decide: %s", f.Unavailable)
	}
	if f.Verdict != certify.Pass {
		t.Fatalf("verdict = %s, want PASS (the 201 IS in the capture on the sibling conversation): %s",
			f.Verdict, f.Observed)
	}
	if !strings.Contains(f.Observed, "201 Created") || !strings.Contains(f.Observed, "/edev/2/lev/1") {
		t.Errorf("Observed should cite the recovered 201 and its Location: %s", f.Observed)
	}
	// Both halves of the recovered exchange must be cited, not just the request.
	if !containsInt(f.Frames, 20) || !containsInt(f.Frames, 21) {
		t.Errorf("Frames should cite the POST (20) and its 201 (21): %v", f.Frames)
	}
}

// A POST whose answer really is nowhere in the capture must still FAIL: the fix
// must not turn a genuinely-unanswered POST into a pass.
func TestBASIC027Wire_UnansweredLogEventStillFails(t *testing.T) {
	crit := critLogEventPosted(&Observation{Params: map[string]string{}})

	post := framed(msg(Request, "POST", "/edev/2/lev", 0, leWire), 20)
	disc := discWalk()
	disc.Others = []*Transcript{siblingPOST(post, nil)}

	f := crit.Wire(nil, disc)
	if f.Verdict != certify.Fail {
		t.Fatalf("verdict = %s, want FAIL for a POST with no answer anywhere: %s", f.Verdict, f.Observed)
	}
	if !strings.Contains(f.Observed, "never answered") {
		t.Errorf("Observed should say the POST was never answered: %s", f.Observed)
	}
}

// The recovered answer is the ACTUAL response to the POST, not a cherry-picked
// 201: a non-201 answer must FAIL on the status, proving the assertion keeps
// its teeth through the order-based matcher.
func TestBASIC027Wire_Non201AnswerFailsOnStatus(t *testing.T) {
	crit := critLogEventPosted(&Observation{Params: map[string]string{}})

	post := framed(msg(Request, "POST", "/edev/2/lev", 0, leWire), 20)
	rejected := framed(msg(Response, "", "", 500, ""), 21)

	disc := discWalk()
	disc.Others = []*Transcript{siblingPOST(post, rejected)}

	f := crit.Wire(nil, disc)
	if f.Verdict != certify.Fail {
		t.Fatalf("verdict = %s, want FAIL for a 500 answer: %s", f.Verdict, f.Observed)
	}
	if !strings.Contains(f.Observed, "201 Created") { // the requirement it names
		t.Errorf("Observed should name the 201-Created requirement: %s", f.Observed)
	}
}

// answerTo must never reach across to another TCP connection for an answer: a
// 201 sitting on the discovery conversation is NOT the answer to a POST on a
// different conversation, even when it happens to be later in the capture.
func TestBASIC027Wire_AnswerDoesNotCrossConversations(t *testing.T) {
	crit := critLogEventPosted(&Observation{Params: map[string]string{}})

	// The POST is on its own sibling, unanswered there. A 201 exists — but on
	// the discovery walk, a different connection.
	post := framed(msg(Request, "POST", "/edev/2/lev", 0, leWire), 20)
	strayCreated := framed(msg(Response, "", "", 201, "", "Location", "/edev/2/lev/9"), 99)

	disc := discWalk()
	disc.Exchanges = append(disc.Exchanges, Exchange{
		Req:  framed(msg(Request, "GET", "/edev", 0, ""), 98),
		Resp: strayCreated,
	})
	for i := range disc.Exchanges {
		disc.Exchanges[i].Req.In = disc
		if disc.Exchanges[i].Resp != nil {
			disc.Exchanges[i].Resp.In = disc
		}
	}
	disc.Responses = []*Message{strayCreated}
	disc.Others = []*Transcript{siblingPOST(post, nil)}

	f := crit.Wire(nil, disc)
	if f.Verdict != certify.Fail || !strings.Contains(f.Observed, "never answered") {
		t.Fatalf("verdict = %s (%s), want FAIL never-answered: a 201 on another connection is not this "+
			"POST's answer", f.Verdict, f.Observed)
	}
}

// ── wire tier: the second-instance churn regression (BASIC-027-triage.md) ────
//
// runs/soak-20260806T041607-leg1/csip/BASIC-027-triage.md caught the shape
// none of the fixtures above cover: TWO genuine LogEvent-bodied POSTs, both
// on connections this case owns, because the DUT itself retried — it picked
// a pooled connection gridsim had already idle-closed, got an immediate RST,
// and opened a fresh connection for the same LogEvent 28ms later, which WAS
// answered 201. The old evaluator committed to the first candidate's lack of
// an answer and FAILed without ever looking at the second.

// A DUT that finds its pooled connection dead and retries on a fresh one —
// ordinary HTTP/1.1 client behavior, not a defect — must still PASS this
// case: the second attempt's 201 is graded and cited, and the first attempt's
// dead connection is named as observed retry behavior, not as the verdict.
func TestBASIC027Wire_SecondAttemptAnsweredAfterFirstWasRSTd(t *testing.T) {
	crit := critLogEventPosted(&Observation{Params: map[string]string{}})

	deadPost := framed(msg(Request, "POST", "/edev/2/lev", 0, leWire), 20)
	retryPost := framed(msg(Request, "POST", "/edev/2/lev", 0, leWire), 30)
	created := framed(msg(Response, "", "", 201, "", "Location", "/edev/2/lev/1"), 31)

	disc := discWalk()
	disc.Others = []*Transcript{siblingPOST(deadPost, nil), siblingPOST(retryPost, created)}

	f := crit.Wire(nil, disc)
	if f.Unavailable != "" {
		t.Fatalf("evaluator declined to decide: %s", f.Unavailable)
	}
	if f.Verdict != certify.Pass {
		t.Fatalf("verdict = %s, want PASS (the retry on the second connection WAS answered): %s",
			f.Verdict, f.Observed)
	}
	if !strings.Contains(f.Observed, "201 Created") || !strings.Contains(f.Observed, "/edev/2/lev/1") {
		t.Errorf("Observed should cite the answered retry's 201 and its Location: %s", f.Observed)
	}
	if !containsInt(f.Frames, 30) || !containsInt(f.Frames, 31) {
		t.Errorf("Frames should cite the answered retry's POST (30) and its 201 (31): %v", f.Frames)
	}
	if containsInt(f.Frames, 20) {
		t.Errorf("Frames should NOT cite the dead first attempt (20) — it never got an answer: %v", f.Frames)
	}
	if !strings.Contains(f.Observed, "unanswered") {
		t.Errorf("Observed should name the earlier unanswered attempt as observed retry behavior, not a "+
			"defect: %s", f.Observed)
	}
}

// When NEITHER of a case's two owned LogEvent POST attempts ever gets an
// answer, the fix must not paper over a genuine gap: the case still FAILs.
func TestBASIC027Wire_BothAttemptsUnansweredStillFails(t *testing.T) {
	crit := critLogEventPosted(&Observation{Params: map[string]string{}})

	firstPost := framed(msg(Request, "POST", "/edev/2/lev", 0, leWire), 20)
	secondPost := framed(msg(Request, "POST", "/edev/2/lev", 0, leWire), 30)

	disc := discWalk()
	disc.Others = []*Transcript{siblingPOST(firstPost, nil), siblingPOST(secondPost, nil)}

	f := crit.Wire(nil, disc)
	if f.Verdict != certify.Fail {
		t.Fatalf("verdict = %s, want FAIL when NEITHER LogEvent attempt got an answer: %s",
			f.Verdict, f.Observed)
	}
	if !strings.Contains(f.Observed, "never answered") {
		t.Errorf("Observed should say the POST was never answered: %s", f.Observed)
	}
	if !containsInt(f.Frames, 20) {
		t.Errorf("Frames should cite the first unanswered attempt (20): %v", f.Frames)
	}
}

// ── wire tier: assertion 1 (EndDevice) shares the same recovery ──────────────

// The EndDevice fetch, when it IS in-window on a churned sibling whose 200 the
// index pairing missed, is now recovered too (critAlarmEndDevice via answerTo).
func TestBASIC027Wire_EndDeviceRecoveredFromUnpairedAnswer(t *testing.T) {
	crit := critAlarmEndDevice()

	edBody := `<EndDevice xmlns="urn:ieee:std:2030.5:ns"><LogEventListLink href="/edev/2/lev"/></EndDevice>`
	getReq := framed(msg(Request, "GET", "/edev/2", 0, ""), 10)
	edResp := framed(msg(Response, "", "", 200, edBody), 11)

	conv := &Transcript{Decrypted: true, Exchanges: []Exchange{{Req: getReq}}}
	getReq.In, edResp.In = conv, conv
	conv.Responses = []*Message{edResp}

	disc := discWalk()
	disc.Others = []*Transcript{conv}

	f := crit.Wire(nil, disc)
	if f.Unavailable != "" {
		t.Fatalf("evaluator declined to decide: %s", f.Unavailable)
	}
	if f.Verdict != certify.Pass {
		t.Fatalf("verdict = %s, want PASS (the EndDevice 200 IS on the sibling): %s", f.Verdict, f.Observed)
	}
	if !strings.Contains(f.Observed, "LogEventListLink present") {
		t.Errorf("Observed should confirm the LogEventListLink: %s", f.Observed)
	}
}

// When the DUT never re-fetches its EndDevice in-window (the ordinary case: it
// cached the LogEventListLink before the fault was armed), assertion 1 SKIPs —
// it does NOT FAIL, so the case is unaffected. This is the observed shape in
// the passing tail-csip baseline, and the reason answerTo is not enough to make
// assertion 1 PASS on every run.
func TestBASIC027Wire_EndDeviceAbsentIsSkipNotFail(t *testing.T) {
	crit := critAlarmEndDevice()

	f := crit.Wire(nil, discWalk())
	if f.Unavailable == "" {
		t.Fatalf("verdict = %s (%s), want a SKIP (unavailable) when no in-window EndDevice fetch exists",
			f.Verdict, f.Observed)
	}
	if !strings.Contains(f.Unavailable, "no EndDevice") {
		t.Errorf("SKIP reason should name the missing EndDevice: %s", f.Unavailable)
	}
}

// containsInt used to live here; it is criteria_agg.go's now (the lifecycle
// criterion needs the same membership test in the product path), and a second
// copy in the test build would not compile.
