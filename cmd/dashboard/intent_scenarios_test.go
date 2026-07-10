package main

import (
	"encoding/json"
	"strings"
	"testing"
)

// ── Payload builders ─────────────────────────────────────────────────────────

func TestModeIntentPayload_ShapeAndFields(t *testing.T) {
	var m map[string]any
	if err := json.Unmarshal([]byte(modeIntentPayload("gateway", "id-1", 1720000000)), &m); err != nil {
		t.Fatalf("mode intent payload is not valid JSON: %v", err)
	}
	if m["v"].(float64) != 1 {
		t.Errorf("v = %v, want 1 (born-at-1 envelope)", m["v"])
	}
	if m["mode"] != "gateway" || m["id"] != "id-1" || m["origin"] != "cloud" {
		t.Errorf("unexpected fields: %v", m)
	}
	if _, ok := m["issued_at"]; !ok {
		t.Error("issued_at missing")
	}
}

func TestReserveIntentPayload_ShapeAndFields(t *testing.T) {
	var m map[string]any
	if err := json.Unmarshal([]byte(reserveIntentPayload(20, "r-1", 1720000000)), &m); err != nil {
		t.Fatalf("reserve intent payload is not valid JSON: %v", err)
	}
	if m["v"].(float64) != 1 {
		t.Errorf("v = %v, want 1", m["v"])
	}
	if m["reserve_pct"].(float64) != 20 {
		t.Errorf("reserve_pct = %v, want 20", m["reserve_pct"])
	}
	if m["id"] != "r-1" {
		t.Errorf("id = %v, want r-1", m["id"])
	}
}

func TestScanRequestPayload_ShapeAndFields(t *testing.T) {
	var m map[string]any
	if err := json.Unmarshal([]byte(scanRequestPayload("s-1", 1720000000)), &m); err != nil {
		t.Fatalf("scan request payload is not valid JSON: %v", err)
	}
	if m["v"].(float64) != 1 || m["id"] != "s-1" {
		t.Errorf("unexpected fields: %v", m)
	}
	if _, ok := m["ts"]; !ok {
		t.Error("ts missing")
	}
}

func TestMayhemIntentID_Unique(t *testing.T) {
	a := mayhemIntentID("flood", 1)
	b := mayhemIntentID("flood", 2)
	if a == b {
		t.Errorf("ids must be unique per injection: %q == %q", a, b)
	}
	if !strings.HasPrefix(a, "mayhem-flood-") {
		t.Errorf("id %q missing prefix", a)
	}
}

// ── SSH command builders ─────────────────────────────────────────────────────

func TestJournalEventCountCommand(t *testing.T) {
	cmd := journalEventCountCommand("mode_change")
	for _, want := range []string{`grep -c '"type":"mode_change"'`, hubJournalGlob, "; true"} {
		if !strings.Contains(cmd, want) {
			t.Errorf("journalEventCountCommand missing %q: %s", want, cmd)
		}
	}
	// The NDJSON journal is 0644 — no sudo needed to read it.
	if strings.Contains(cmd, "sudo") {
		t.Errorf("journalEventCountCommand must not sudo (0644 journal): %s", cmd)
	}
}

func TestJournaldLinesSinceCommand(t *testing.T) {
	cmd := journaldLinesSinceCommand("lexa-hub", 123456)
	for _, want := range []string{"sudo journalctl -u lexa-hub", "--since @123456", "wc -l"} {
		if !strings.Contains(cmd, want) {
			t.Errorf("journaldLinesSinceCommand missing %q: %s", want, cmd)
		}
	}
}

func TestIntentResultSubCommand(t *testing.T) {
	cmd := intentResultSubCommand("reserve", 15)
	for _, want := range []string{qaInjectPassFile, "timeout 15", "-t lexa/intent/result", `grep -c '"kind":"reserve"'`, "exit 1"} {
		if !strings.Contains(cmd, want) {
			t.Errorf("intentResultSubCommand missing %q: %s", want, cmd)
		}
	}
}

func TestRetainedBatteryDesiredCommand(t *testing.T) {
	cmd := retainedBatteryDesiredCommand()
	for _, want := range []string{"lexa/desired/battery/+", "-C 1", qaInjectPassFile} {
		if !strings.Contains(cmd, want) {
			t.Errorf("retainedBatteryDesiredCommand missing %q: %s", want, cmd)
		}
	}
}

func TestParseCount(t *testing.T) {
	cases := []struct {
		in   string
		want int
		ok   bool
	}{
		{"5\n", 5, true},
		{"0", 0, true},
		{"  42  ", 42, true},
		{"", 0, false},
		{"abc", 0, false},
		{"note\n7", 7, true}, // last field wins (grep-warning-then-count shape)
	}
	for _, c := range cases {
		n, ok := parseCount(c.in)
		if ok != c.ok || (ok && n != c.want) {
			t.Errorf("parseCount(%q) = (%d,%v), want (%d,%v)", c.in, n, ok, c.want, c.ok)
		}
	}
}

// ── Sample fixtures ──────────────────────────────────────────────────────────

// exportBreachSamples: sustained post-settling export past a 0 W cap.
func exportBreachSamples() []maySample {
	return mkSamples(40, func(i int, s *maySample) { s.RealGridW = -4000; s.HubGridW = -4000 })
}

// cleanSamples: net grid at 0 — no export breach.
func cleanSamples() []maySample {
	return mkSamples(40, func(i int, s *maySample) { s.RealGridW = 0; s.HubGridW = 0 })
}

// socBreachSamples: pack sustained discharging below the reserve floor.
func socBreachSamples() []maySample {
	return mkSamples(40, func(i int, s *maySample) {
		s.BatterySimOK = true
		if i > 30 {
			s.BatterySimW = 300 // discharging
			s.BatSimSOC = 6     // below the 10% reserve floor
		} else {
			s.BatSimSOC = 60
		}
	})
}

// socSafeSamples: pack present (ground truth) and never past a bound.
func socSafeSamples() []maySample {
	return mkSamples(40, func(i int, s *maySample) {
		s.BatterySimOK = true
		s.BatSimSOC = 60
	})
}

// ── diagnoseModeFlipUnderEvent ───────────────────────────────────────────────

func healthyModeObs() modeFlipObs {
	return modeFlipObs{
		gatewaySeen: true, optimizerRestored: true,
		gatewayMetricSeen: true, metricOK: true,
		heartbeatSeen: true, heartbeatEverStalled: false,
		modeChangeDelta: 2, journalOK: true,
	}
}

func TestDiagnoseModeFlipUnderEvent_Pass(t *testing.T) {
	f := diagnoseModeFlipUnderEvent(healthyModeObs())(scFor("mfe"), exportCons(), cleanSamples())
	if f.Verdict != "PASS" {
		t.Fatalf("verdict = %s, want PASS (%s)", f.Verdict, f.Headline)
	}
	assertDiag(t, f, "both ways")
}

func TestDiagnoseModeFlipUnderEvent_FailOnExportBreach(t *testing.T) {
	f := diagnoseModeFlipUnderEvent(healthyModeObs())(scFor("mfe"), exportCons(), exportBreachSamples())
	if f.Verdict != "FAIL" {
		t.Fatalf("verdict = %s, want FAIL", f.Verdict)
	}
	assertDiag(t, f, "INV-EXPORT")
}

func TestDiagnoseModeFlipUnderEvent_DegradedOnHeartbeatStall(t *testing.T) {
	o := healthyModeObs()
	o.heartbeatEverStalled = true
	f := diagnoseModeFlipUnderEvent(o)(scFor("mfe"), exportCons(), cleanSamples())
	if f.Verdict != "DEGRADED" {
		t.Fatalf("verdict = %s, want DEGRADED", f.Verdict)
	}
	assertDiag(t, f, "heartbeat")
}

func TestDiagnoseModeFlipUnderEvent_DegradedWhenFlipNeverEngaged(t *testing.T) {
	o := healthyModeObs()
	o.gatewaySeen = false
	o.optimizerRestored = false
	o.gatewayMetricSeen = false
	o.modeChangeDelta = 0
	f := diagnoseModeFlipUnderEvent(o)(scFor("mfe"), exportCons(), cleanSamples())
	if f.Verdict != "DEGRADED" {
		t.Fatalf("verdict = %s, want DEGRADED", f.Verdict)
	}
	assertDiag(t, f, "could not exercise the flip")
}

func TestDiagnoseModeFlipUnderEvent_InconclusiveNoSamples(t *testing.T) {
	f := diagnoseModeFlipUnderEvent(healthyModeObs())(scFor("mfe"), exportCons(), nil)
	if f.Verdict != "INCONCLUSIVE" {
		t.Fatalf("verdict = %s, want INCONCLUSIVE", f.Verdict)
	}
}

// A missing detection signal must degrade to an INCONCLUSIVE note, never a
// silent PASS-with-no-evidence (duplicate-client-id precedent).
func TestDiagnoseModeFlipUnderEvent_PassNotesInconclusiveDetection(t *testing.T) {
	o := modeFlipObs{gatewaySeen: true, optimizerRestored: true} // metric/journal/heartbeat all unavailable
	f := diagnoseModeFlipUnderEvent(o)(scFor("mfe"), exportCons(), cleanSamples())
	if f.Verdict != "PASS" {
		t.Fatalf("verdict = %s, want PASS", f.Verdict)
	}
	assertDiag(t, f, "INCONCLUSIVE")
}

// ── diagnoseModeFlipUnderFault ───────────────────────────────────────────────

func healthyFaultObs() modeFlipFaultObs {
	return modeFlipFaultObs{
		modeFlipObs:       healthyModeObs(),
		desiredDocPresent: true, desiredReadOK: true,
		packRecovered: true, hadGroundTruth: true,
	}
}

func TestDiagnoseModeFlipUnderFault_Pass(t *testing.T) {
	f := diagnoseModeFlipUnderFault(healthyFaultObs())(scFor("mff"), noneCons(), socSafeSamples())
	if f.Verdict != "PASS" {
		t.Fatalf("verdict = %s, want PASS (%s)", f.Verdict, f.Headline)
	}
	assertDiag(t, f, "reassert-on-reconnect evidenced")
}

func TestDiagnoseModeFlipUnderFault_FailOnSOCBreach(t *testing.T) {
	f := diagnoseModeFlipUnderFault(healthyFaultObs())(scFor("mff"), noneCons(), socBreachSamples())
	if f.Verdict != "FAIL" {
		t.Fatalf("verdict = %s, want FAIL", f.Verdict)
	}
	assertDiag(t, f, "INV-SOC")
}

func TestDiagnoseModeFlipUnderFault_DegradedWhenPackNotRecovered(t *testing.T) {
	o := healthyFaultObs()
	o.packRecovered = false
	f := diagnoseModeFlipUnderFault(o)(scFor("mff"), noneCons(), socSafeSamples())
	if f.Verdict != "DEGRADED" {
		t.Fatalf("verdict = %s, want DEGRADED", f.Verdict)
	}
	assertDiag(t, f, "did not re-establish a coherent battery reading")
}

func TestDiagnoseModeFlipUnderFault_DegradedOnHeartbeatStall(t *testing.T) {
	o := healthyFaultObs()
	o.heartbeatEverStalled = true
	f := diagnoseModeFlipUnderFault(o)(scFor("mff"), noneCons(), socSafeSamples())
	if f.Verdict != "DEGRADED" {
		t.Fatalf("verdict = %s, want DEGRADED", f.Verdict)
	}
	assertDiag(t, f, "heartbeat")
}

func TestDiagnoseModeFlipUnderFault_InconclusiveNoSamples(t *testing.T) {
	f := diagnoseModeFlipUnderFault(healthyFaultObs())(scFor("mff"), noneCons(), nil)
	if f.Verdict != "INCONCLUSIVE" {
		t.Fatalf("verdict = %s, want INCONCLUSIVE", f.Verdict)
	}
}

// ── diagnoseScanRefused ──────────────────────────────────────────────────────

func looseExportCons() *activeConstraint {
	return &activeConstraint{Typ: "exportCap", LimW: 4000, MRID: "M-scan"}
}

func TestDiagnoseScanRefused_PassWithinWindow(t *testing.T) {
	o := scanRefusedObs{refusedSeen: true, scanEndpointOK: true, refusedLatencyS: 4}
	f := diagnoseScanRefused(o)(scFor("scan"), looseExportCons(), cleanSamples())
	if f.Verdict != "PASS" {
		t.Fatalf("verdict = %s, want PASS (%s)", f.Verdict, f.Headline)
	}
	assertDiag(t, f, "refused")
}

func TestDiagnoseScanRefused_DegradedWhenSlow(t *testing.T) {
	o := scanRefusedObs{refusedSeen: true, scanEndpointOK: true, refusedLatencyS: 15}
	f := diagnoseScanRefused(o)(scFor("scan"), looseExportCons(), cleanSamples())
	if f.Verdict != "DEGRADED" {
		t.Fatalf("verdict = %s, want DEGRADED", f.Verdict)
	}
}

func TestDiagnoseScanRefused_FailWhenNeverRefused(t *testing.T) {
	o := scanRefusedObs{refusedSeen: false, scanEndpointOK: true, refusedLatencyS: -1}
	f := diagnoseScanRefused(o)(scFor("scan"), looseExportCons(), cleanSamples())
	if f.Verdict != "FAIL" {
		t.Fatalf("verdict = %s, want FAIL", f.Verdict)
	}
	assertDiag(t, f, "never showed a phase")
}

func TestDiagnoseScanRefused_FailWhenControlDisturbed(t *testing.T) {
	// Even with a refusal, an export breach coincident with the scan is a FAIL.
	s := mkSamples(40, func(i int, s *maySample) { s.RealGridW = -8000; s.HubGridW = -8000 })
	o := scanRefusedObs{refusedSeen: true, scanEndpointOK: true, refusedLatencyS: 3}
	f := diagnoseScanRefused(o)(scFor("scan"), looseExportCons(), s)
	if f.Verdict != "FAIL" {
		t.Fatalf("verdict = %s, want FAIL", f.Verdict)
	}
	assertDiag(t, f, "INV-EXPORT")
}

func TestDiagnoseScanRefused_InconclusiveWhenEndpointDown(t *testing.T) {
	o := scanRefusedObs{scanEndpointOK: false, refusedLatencyS: -1}
	f := diagnoseScanRefused(o)(scFor("scan"), looseExportCons(), cleanSamples())
	if f.Verdict != "INCONCLUSIVE" {
		t.Fatalf("verdict = %s, want INCONCLUSIVE", f.Verdict)
	}
}

// ── diagnoseIntentFlood ──────────────────────────────────────────────────────

func healthyFloodObs() intentFloodObs {
	return intentFloodObs{
		intentsFired:  50,
		appliedBefore: 10, appliedAfter: 60, appliedOK: true,
		overrunsBefore: 2, overrunsAfter: 2, overrunsOK: true,
		serviceStartDelta: 0, journalOK: true,
		resultCount: 50, resultSubOK: true,
		journaldLines: 40, journaldOK: true,
		heartbeatSeen: true,
	}
}

func TestDiagnoseIntentFlood_Pass(t *testing.T) {
	f := diagnoseIntentFlood(healthyFloodObs())(scFor("flood"), noneCons(), cleanSamples())
	if f.Verdict != "PASS" {
		t.Fatalf("verdict = %s, want PASS (%s)", f.Verdict, f.Headline)
	}
	assertDiag(t, f, "advanced by 50")
}

func TestDiagnoseIntentFlood_FailOnRestart(t *testing.T) {
	o := healthyFloodObs()
	o.serviceStartDelta = 1
	f := diagnoseIntentFlood(o)(scFor("flood"), noneCons(), cleanSamples())
	if f.Verdict != "FAIL" {
		t.Fatalf("verdict = %s, want FAIL", f.Verdict)
	}
	assertDiag(t, f, "service_start event landed")
}

func TestDiagnoseIntentFlood_FailWhenUnreachableAtTail(t *testing.T) {
	s := cleanSamples()
	s[len(s)-1].HubReachable = false
	f := diagnoseIntentFlood(healthyFloodObs())(scFor("flood"), noneCons(), s)
	if f.Verdict != "FAIL" {
		t.Fatalf("verdict = %s, want FAIL", f.Verdict)
	}
	assertDiag(t, f, "did not answer on the final sample")
}

func TestDiagnoseIntentFlood_DegradedOnTickOverruns(t *testing.T) {
	o := healthyFloodObs()
	o.overrunsAfter = o.overrunsBefore + 3
	f := diagnoseIntentFlood(o)(scFor("flood"), noneCons(), cleanSamples())
	if f.Verdict != "DEGRADED" {
		t.Fatalf("verdict = %s, want DEGRADED", f.Verdict)
	}
	assertDiag(t, f, "overruns_total advanced by 3")
}

func TestDiagnoseIntentFlood_DegradedOnJournaldStorm(t *testing.T) {
	o := healthyFloodObs()
	o.journaldLines = intentFloodJournaldBudget + 200
	f := diagnoseIntentFlood(o)(scFor("flood"), noneCons(), cleanSamples())
	if f.Verdict != "DEGRADED" {
		t.Fatalf("verdict = %s, want DEGRADED", f.Verdict)
	}
	assertDiag(t, f, "journald")
}

func TestDiagnoseIntentFlood_DegradedOnMissingResults(t *testing.T) {
	o := healthyFloodObs()
	o.resultCount = 5 // only 5 of 50 answered
	f := diagnoseIntentFlood(o)(scFor("flood"), noneCons(), cleanSamples())
	if f.Verdict != "DEGRADED" {
		t.Fatalf("verdict = %s, want DEGRADED", f.Verdict)
	}
}

func TestDiagnoseIntentFlood_InconclusiveNoSamples(t *testing.T) {
	f := diagnoseIntentFlood(healthyFloodObs())(scFor("flood"), noneCons(), nil)
	if f.Verdict != "INCONCLUSIVE" {
		t.Fatalf("verdict = %s, want INCONCLUSIVE", f.Verdict)
	}
}

// ── Catalogue registration ───────────────────────────────────────────────────

// TestIntentScenarios_CataloguePresent locks the acceptance criterion "--list
// shows the four new scenarios": intentScenarios() (folded into scenarios() and
// thus /api/qa/scenarios) must contain exactly the four IDs, each with a unique
// ID and every stage wired.
func TestIntentScenarios_CataloguePresent(t *testing.T) {
	d := newMayhemDriver(map[string]string{"hub": "http://69.0.0.1:9100"})
	scs := d.intentScenarios()

	want := map[string]bool{
		"mode-flip-under-active-event":     false,
		"mode-flip-under-fault":            false,
		"scan-during-live-control-refused": false,
		"intent-flood-rate-limit":          false,
	}
	seen := map[string]int{}
	for _, sc := range scs {
		seen[sc.ID]++
		if _, ok := want[sc.ID]; ok {
			want[sc.ID] = true
		}
		if sc.HoldS <= 0 {
			t.Errorf("%s: HoldS = %d, want > 0", sc.ID, sc.HoldS)
		}
		if sc.setup == nil || sc.perTick == nil || sc.evaluate == nil || sc.teardown == nil {
			t.Errorf("%s: every stage (setup/perTick/evaluate/teardown) must be wired", sc.ID)
		}
		if sc.Category == "" || sc.Hypothesis == "" || sc.Expected == "" || sc.Fix == "" {
			t.Errorf("%s: metadata (Category/Hypothesis/Expected/Fix) must be set", sc.ID)
		}
	}
	for id, present := range want {
		if !present {
			t.Errorf("intentScenarios() missing %q", id)
		}
	}
	for id, n := range seen {
		if n > 1 {
			t.Errorf("duplicate scenario ID %q (%d copies)", id, n)
		}
	}
	if len(scs) != 4 {
		t.Errorf("intentScenarios() returned %d scenarios, want 4", len(scs))
	}
}

// TestScenarios_NoDuplicateIDsWithIntentScenarios guards against an ID
// collision between the new intent scenarios and any existing Go scenario or
// loaded spec (loadSpecScenarios would skip a colliding spec, but a Go-vs-Go
// collision must be caught here). Uses a driver with no scenario dir so only
// the Go catalogue is exercised.
func TestScenarios_NoDuplicateIDsWithIntentScenarios(t *testing.T) {
	d := newMayhemDriver(map[string]string{"hub": "http://69.0.0.1:9100"})
	seen := map[string]int{}
	for _, sc := range d.scenarios() {
		seen[sc.ID]++
	}
	for _, id := range []string{
		"mode-flip-under-active-event", "mode-flip-under-fault",
		"scan-during-live-control-refused", "intent-flood-rate-limit",
	} {
		if seen[id] != 1 {
			t.Errorf("scenarios() must contain exactly one %q, got %d", id, seen[id])
		}
	}
}
