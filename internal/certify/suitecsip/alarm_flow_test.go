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
