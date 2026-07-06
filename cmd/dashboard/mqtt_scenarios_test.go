package main

import (
	"strings"
	"testing"
)

// ── parseMQTTClientIDLine (TASK-049) ────────────────────────────────────────

func TestParseMQTTClientIDLine_OK(t *testing.T) {
	cases := []struct {
		line string
		want string
	}{
		{`"mqtt_client_id": "lexa-hub-2"`, "lexa-hub-2"},
		{`"mqtt_client_id":"lexa-hub-2"`, "lexa-hub-2"},
		{`"mqtt_client_id"   :   "custom-id"`, "custom-id"},
	}
	for _, c := range cases {
		got, err := parseMQTTClientIDLine(c.line)
		if err != nil {
			t.Errorf("parseMQTTClientIDLine(%q): unexpected error: %v", c.line, err)
			continue
		}
		if got != c.want {
			t.Errorf("parseMQTTClientIDLine(%q) = %q, want %q", c.line, got, c.want)
		}
	}
}

func TestParseMQTTClientIDLine_Errors(t *testing.T) {
	cases := []string{
		"",
		"garbage no colon",
		`"mqtt_client_id": ""`,
	}
	for _, line := range cases {
		if _, err := parseMQTTClientIDLine(line); err == nil {
			t.Errorf("parseMQTTClientIDLine(%q): expected an error, got none", line)
		}
	}
}

// ── diagnoseDuplicateClientID (TASK-049) ────────────────────────────────────

func TestDiagnoseDuplicateClientID_PassWithDetectionProven(t *testing.T) {
	s := mkSamples(90, func(i int, s *maySample) { s.RealGridW = 0; s.HubGridW = 0 })
	f := diagnoseDuplicateClientID(3, 9, true)(scFor("duplicate-client-id"), exportCons(), s)
	if f.Verdict != "PASS" {
		t.Fatalf("verdict = %s, want PASS (%s / %v)", f.Verdict, f.Headline, f.Diagnosis)
	}
	assertDiag(t, f, "detection proven")
}

func TestDiagnoseDuplicateClientID_DegradedWhenCounterAvailableButFlat(t *testing.T) {
	// Cap held cleanly, but TASK-044 is present and the counter never moved —
	// the safety half passed, the detection half did not, and that must be
	// visible rather than a silent PASS.
	s := mkSamples(90, func(i int, s *maySample) { s.RealGridW = 0; s.HubGridW = 0 })
	f := diagnoseDuplicateClientID(5, 5, true)(scFor("duplicate-client-id"), exportCons(), s)
	if f.Verdict != "DEGRADED" {
		t.Fatalf("verdict = %s, want DEGRADED (%s)", f.Verdict, f.Headline)
	}
	if !containsFold(f.Headline, "undetected") {
		t.Errorf("headline = %q, want it to call out the storm going undetected", f.Headline)
	}
}

func TestDiagnoseDuplicateClientID_PassWithDetectionInconclusive(t *testing.T) {
	// TASK-044 not deployed (counterOK=false): safety oracles still judged,
	// detection noted INCONCLUSIVE, verdict stays PASS on a clean cap.
	s := mkSamples(90, func(i int, s *maySample) { s.RealGridW = 0; s.HubGridW = 0 })
	f := diagnoseDuplicateClientID(0, 0, false)(scFor("duplicate-client-id"), exportCons(), s)
	if f.Verdict != "PASS" {
		t.Fatalf("verdict = %s, want PASS (%s)", f.Verdict, f.Headline)
	}
	assertDiag(t, f, "INCONCLUSIVE")
}

func TestDiagnoseDuplicateClientID_FailsOnSustainedExportBreach(t *testing.T) {
	s := mkSamples(90, func(i int, s *maySample) { s.RealGridW = -4000; s.HubGridW = -4000 })
	f := diagnoseDuplicateClientID(3, 9, true)(scFor("duplicate-client-id"), exportCons(), s)
	if f.Verdict != "FAIL" {
		t.Fatalf("verdict = %s, want FAIL (%s)", f.Verdict, f.Headline)
	}
	assertDiag(t, f, "INV-EXPORT")
}

func TestDiagnoseDuplicateClientID_FailsOnBackfeedDuringDisconnect(t *testing.T) {
	cons := &activeConstraint{Typ: "connect"}
	s := mkSamples(90, func(i int, s *maySample) {
		s.DisconnectActive = true
		s.SolarW = 3000 // still energizing during a cease-to-energize
	})
	f := diagnoseDuplicateClientID(3, 9, true)(scFor("duplicate-client-id"), cons, s)
	if f.Verdict != "FAIL" {
		t.Fatalf("verdict = %s, want FAIL (%s)", f.Verdict, f.Headline)
	}
	assertDiag(t, f, "INV-CONNECT")
}

func TestDiagnoseDuplicateClientID_NoSamplesInconclusive(t *testing.T) {
	f := diagnoseDuplicateClientID(0, 0, true)(scFor("duplicate-client-id"), exportCons(), nil)
	if f.Verdict != "INCONCLUSIVE" {
		t.Errorf("verdict = %s, want INCONCLUSIVE", f.Verdict)
	}
}

// ── diagnoseMqttStorm (TASK-051) ─────────────────────────────────────────────

func TestDiagnoseMqttStorm_PassWithOverflowCounted(t *testing.T) {
	s := mkSamples(80, func(i int, s *maySample) { s.RealGridW = 0; s.HubGridW = 0 })
	f := diagnoseMqttStorm("lexa_mqtt_publish_failures_total", 10, 42, true)(scFor("mqtt-storm"), exportCons(), s)
	if f.Verdict != "PASS" {
		t.Fatalf("verdict = %s, want PASS (%s)", f.Verdict, f.Headline)
	}
	assertDiag(t, f, "overflow surfaced")
}

func TestDiagnoseMqttStorm_PassWithQueueAbsorbing(t *testing.T) {
	// Counter available but flat AND the cap held — the queue absorbed the
	// flood without a counted drop, which the task explicitly calls
	// acceptable (not every flood must overflow the queue to be handled).
	s := mkSamples(80, func(i int, s *maySample) { s.RealGridW = 0; s.HubGridW = 0 })
	f := diagnoseMqttStorm("lexa_mqtt_publish_failures_total", 10, 10, true)(scFor("mqtt-storm"), exportCons(), s)
	if f.Verdict != "PASS" {
		t.Fatalf("verdict = %s, want PASS (%s)", f.Verdict, f.Headline)
	}
	assertDiag(t, f, "absorbed")
}

func TestDiagnoseMqttStorm_SilentWedgeEscalatesToFail(t *testing.T) {
	// Base diagnoseConstraint would call this DEGRADED (CannotComply posted
	// outranks the other branches) — but with the overflow counter flat, a
	// sustained breach is the silent-wedge case the task calls out
	// explicitly, and it must escalate to FAIL even though the base ladder's
	// own reason (an admitted CannotComply) would otherwise read as OK.
	s := mkSamples(80, func(i int, s *maySample) {
		s.RealGridW, s.HubGridW = -4000, -4000
		s.CannotComply = true
	})
	f := diagnoseMqttStorm("lexa_mqtt_publish_failures_total", 10, 10, true)(scFor("mqtt-storm"), exportCons(), s)
	if f.Verdict != "FAIL" {
		t.Fatalf("verdict = %s, want FAIL (%s)", f.Verdict, f.Headline)
	}
	if !containsFold(f.Headline, "silent wedge") {
		t.Errorf("headline = %q, want it to call out the silent wedge", f.Headline)
	}
}

func TestDiagnoseMqttStorm_DetectionInconclusiveWithoutTask044(t *testing.T) {
	s := mkSamples(80, func(i int, s *maySample) { s.RealGridW = 0; s.HubGridW = 0 })
	f := diagnoseMqttStorm("lexa_mqtt_publish_failures_total", 0, 0, false)(scFor("mqtt-storm"), exportCons(), s)
	if f.Verdict != "PASS" {
		t.Fatalf("verdict = %s, want PASS (%s)", f.Verdict, f.Headline)
	}
	assertDiag(t, f, "INCONCLUSIVE")
}

// ── Broker persistence fault helpers (GAP-01/02, TASK-043) ─────────────────

// TestBrokerSnapshotCommand_CleanStopThenCopyThenStart locks the property the
// task's "store copy is only valid via clean stop" note depends on: the
// remote command must STOP (flush-on-shutdown) before copying the store, and
// must restart afterward — never snapshot a live/running store file.
func TestBrokerSnapshotCommand_CleanStopThenCopyThenStart(t *testing.T) {
	cmd := brokerSnapshotCommand()
	stopIdx := strings.Index(cmd, "systemctl stop mosquitto")
	cpIdx := strings.Index(cmd, "cp "+mosquittoStorePath+" "+mayhemStoreTmpPath)
	startIdx := strings.Index(cmd, "systemctl start mosquitto")
	if stopIdx < 0 || cpIdx < 0 || startIdx < 0 {
		t.Fatalf("brokerSnapshotCommand() missing a required step: %q", cmd)
	}
	if !(stopIdx < cpIdx && cpIdx < startIdx) {
		t.Errorf("brokerSnapshotCommand() must stop, then copy, then start (got %q)", cmd)
	}
	if strings.Contains(cmd, "kill") {
		t.Errorf("brokerSnapshotCommand() must be a CLEAN stop, not a kill: %q", cmd)
	}
}

// TestBrokerUncleanRollbackCommand_SIGKILLNotStop locks the property that
// makes this scenario a genuine power-cut analogue: the rollback must
// SIGKILL (bypassing the on-shutdown flush), never a clean stop, and must be
// idempotent against an already-dead broker (a retried/aborted run must not
// fail here).
func TestBrokerUncleanRollbackCommand_SIGKILLNotStop(t *testing.T) {
	cmd := brokerUncleanRollbackCommand()
	if !strings.Contains(cmd, "kill -s SIGKILL mosquitto") {
		t.Errorf("brokerUncleanRollbackCommand() must SIGKILL mosquitto: %q", cmd)
	}
	if strings.Contains(cmd, "systemctl stop mosquitto") {
		t.Errorf("brokerUncleanRollbackCommand() must not do a clean stop (that would defeat the power-cut analogue): %q", cmd)
	}
	killIdx := strings.Index(cmd, "kill -s SIGKILL mosquitto")
	cpIdx := strings.Index(cmd, "cp "+mayhemStoreTmpPath+" "+mosquittoStorePath)
	startIdx := strings.Index(cmd, "systemctl start mosquitto")
	if cpIdx < 0 || startIdx < 0 {
		t.Fatalf("brokerUncleanRollbackCommand() missing restore-copy or restart step: %q", cmd)
	}
	if !(killIdx < cpIdx && cpIdx < startIdx) {
		t.Errorf("brokerUncleanRollbackCommand() must kill, then restore the snapshot, then start (got %q)", cmd)
	}
	if !strings.Contains(cmd, "|| true") {
		t.Errorf("brokerUncleanRollbackCommand() must tolerate an already-dead broker (idempotent retry): %q", cmd)
	}
}

func TestBrokerCleanupCommand(t *testing.T) {
	cmd := brokerCleanupCommand()
	if !strings.Contains(cmd, "rm -f") || !strings.Contains(cmd, mayhemStoreTmpPath) {
		t.Errorf("brokerCleanupCommand() = %q, want an idempotent rm -f of %q", cmd, mayhemStoreTmpPath)
	}
}

// TestBrokerRetainedControlCommand_AuthenticatesAndGuardsMissingCreds locks
// the TASK-013 dependency: the read-back must authenticate as qa-inject (the
// broker no longer allows anonymous reads) and must refuse loudly, not
// silently, when the credential file is absent.
func TestBrokerRetainedControlCommand_AuthenticatesAndGuardsMissingCreds(t *testing.T) {
	cmd := brokerRetainedControlCommand()
	for _, want := range []string{qaInjectPassFile, "-u qa-inject", "mosquitto_sub", topicCSIPControl, "exit 1"} {
		if !strings.Contains(cmd, want) {
			t.Errorf("brokerRetainedControlCommand() = %q, want it to contain %q", cmd, want)
		}
	}
}

// ── parseRetainedExpLimW ─────────────────────────────────────────────────────

func TestParseRetainedExpLimW(t *testing.T) {
	cases := []struct {
		payload string
		want    float64
		wantOK  bool
	}{
		{`{"source":"event","exp_lim_w":5000,"ts":123}`, 5000, true},
		{`{"source":"event","exp_lim_W":0}`, 0, true},
		{`{ "exp_lim_w" : 1234.5 }`, 1234.5, true},
		{`{"exp_lim_w":-100}`, -100, true},
		{`{"source":"event","exp_lim_w":`, 0, false}, // the truncated payload the scenario injects
		{`{"source":"none","ts":1}`, 0, false},       // no exp_lim_w field at all
		{``, 0, false},
	}
	for _, c := range cases {
		got, ok := parseRetainedExpLimW(c.payload)
		if ok != c.wantOK {
			t.Errorf("parseRetainedExpLimW(%q) ok = %v, want %v", c.payload, ok, c.wantOK)
			continue
		}
		if ok && got != c.want {
			t.Errorf("parseRetainedExpLimW(%q) = %v, want %v", c.payload, got, c.want)
		}
	}
}

// ── diagnosePowerCutRollback (GAP-01) ────────────────────────────────────────

func TestDiagnosePowerCutRollback_PassWhenNeverBreached(t *testing.T) {
	s := mkSamples(90, func(i int, s *maySample) { s.RealGridW = 0; s.HubGridW = 0 })
	f := diagnosePowerCutRollback(scFor("power-cut-retained-rollback"), exportCons(), s)
	if f.Verdict != "PASS" {
		t.Fatalf("verdict = %s, want PASS (%s / %v)", f.Verdict, f.Headline, f.Diagnosis)
	}
}

func TestDiagnosePowerCutRollback_FailsWhenEnforcingStaleAToTheEnd(t *testing.T) {
	s := mkSamples(90, func(i int, s *maySample) {
		s.RealGridW, s.HubGridW = -4000, -4000 // sustained breach of cap B (0 W) to the tail
		if i >= 40 {
			s.HubAdopted, s.AdoptedTyp, s.AdoptedLimW = true, "exportCap", 5000 // stuck on resurrected stale cap A
		}
	})
	f := diagnosePowerCutRollback(scFor("power-cut-retained-rollback"), exportCons(), s)
	if f.Verdict != "FAIL" {
		t.Fatalf("verdict = %s, want FAIL (%s / %v)", f.Verdict, f.Headline, f.Diagnosis)
	}
	if !containsFold(f.Headline, "stale cap a") {
		t.Errorf("headline = %q, want it to call out enforcing the stale cap A", f.Headline)
	}
	assertDiag(t, f, "INV-EXPORT")
}

func TestDiagnosePowerCutRollback_DegradedWhenStaleEnforcementRecovers(t *testing.T) {
	s := mkSamples(90, func(i int, s *maySample) {
		if i < 50 {
			s.RealGridW, s.HubGridW = -4000, -4000
			s.HubAdopted, s.AdoptedTyp, s.AdoptedLimW = true, "exportCap", 5000 // transiently stuck on A
		} else {
			s.RealGridW, s.HubGridW = 0, 0
			s.HubAdopted, s.AdoptedTyp, s.AdoptedLimW = true, "exportCap", 0 // recovered onto B well before the tail
		}
	})
	f := diagnosePowerCutRollback(scFor("power-cut-retained-rollback"), exportCons(), s)
	if f.Verdict != "DEGRADED" {
		t.Fatalf("verdict = %s, want DEGRADED (%s / %v)", f.Verdict, f.Headline, f.Diagnosis)
	}
}

func TestDiagnosePowerCutRollback_FailsOnSustainedBreachNeverRecovering(t *testing.T) {
	s := mkSamples(90, func(i int, s *maySample) {
		s.RealGridW, s.HubGridW = -4000, -4000 // sustained breach, hub never even shows adoption of anything
	})
	f := diagnosePowerCutRollback(scFor("power-cut-retained-rollback"), exportCons(), s)
	if f.Verdict != "FAIL" {
		t.Fatalf("verdict = %s, want FAIL (%s / %v)", f.Verdict, f.Headline, f.Diagnosis)
	}
	if !containsFold(f.Headline, "never recovered") {
		t.Errorf("headline = %q, want it to call out the unrecovered breach", f.Headline)
	}
}

func TestDiagnosePowerCutRollback_NoSamplesInconclusive(t *testing.T) {
	f := diagnosePowerCutRollback(scFor("power-cut-retained-rollback"), exportCons(), nil)
	if f.Verdict != "INCONCLUSIVE" {
		t.Errorf("verdict = %s, want INCONCLUSIVE", f.Verdict)
	}
}

// ── Catalogue presence (acceptance: "both scenarios listed by --list") ─────

// TestMqttScenarios_PowerCutAndCorruptedRetainedPresent locks the acceptance
// criterion that scripts/mayhem.py --list shows both new IDs exactly once,
// with no collision against any existing scenario ID in this file.
func TestMqttScenarios_PowerCutAndCorruptedRetainedPresent(t *testing.T) {
	d := newMayhemDriver(map[string]string{"hub": "http://69.0.0.1:9100"})
	scs := d.mqttScenarios()

	seen := map[string]int{}
	for _, sc := range scs {
		seen[sc.ID]++
	}
	for _, id := range []string{"power-cut-retained-rollback", "corrupted-retained-control"} {
		if seen[id] != 1 {
			t.Errorf("mqttScenarios() must contain exactly one %q, got %d", id, seen[id])
		}
	}
	for id, n := range seen {
		if n > 1 {
			t.Errorf("duplicate scenario ID %q (%d copies) — every ID must be unique", id, n)
		}
	}
}

// TestScenarios_NoIDCollisionAcrossFullSuite guards the task's "Scenario IDs
// must not collide with existing ones" note across the WHOLE curated suite
// (mayhem.go + mayhem_world.go + mqtt_scenarios.go), not just this file.
func TestScenarios_NoIDCollisionAcrossFullSuite(t *testing.T) {
	d := newMayhemDriver(map[string]string{
		"hub": "http://69.0.0.1:9100", "gridsim": "http://69.0.0.20:11112",
		"solar": "http://69.0.0.10:6020", "battery": "http://69.0.0.11:6021",
		"meter": "http://69.0.0.12:6022", "ev": "http://69.0.0.14:6024",
	})
	seen := map[string]int{}
	for _, sc := range d.scenarios() {
		seen[sc.ID]++
	}
	for id, n := range seen {
		if n > 1 {
			t.Errorf("duplicate scenario ID %q (%d copies) across the full curated suite", id, n)
		}
	}
	for _, id := range []string{"power-cut-retained-rollback", "corrupted-retained-control"} {
		if seen[id] != 1 {
			t.Errorf("full suite must contain exactly one %q, got %d", id, seen[id])
		}
	}
}
