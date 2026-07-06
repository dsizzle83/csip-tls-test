package main

import "testing"

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
