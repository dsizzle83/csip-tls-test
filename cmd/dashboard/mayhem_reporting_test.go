package main

import (
	"encoding/xml"
	"fmt"
	"testing"

	model "lexa-proto/csipmodel"
)

// ── pure parsers ─────────────────────────────────────────────────────────────

func TestParseRegistrationPINLine_OK(t *testing.T) {
	cases := []struct {
		line     string
		wantPIN  uint32
		wantPres bool
	}{
		{`"registration_pin": 654321`, 654321, true},
		{`"registration_pin":0`, 0, true},
		{`"registration_pin"   :   111115`, 111115, true},
	}
	for _, c := range cases {
		pin, present, err := parseRegistrationPINLine(c.line)
		if err != nil {
			t.Errorf("parseRegistrationPINLine(%q): unexpected error: %v", c.line, err)
			continue
		}
		if pin != c.wantPIN || present != c.wantPres {
			t.Errorf("parseRegistrationPINLine(%q) = (%d, %v), want (%d, %v)", c.line, pin, present, c.wantPIN, c.wantPres)
		}
	}
}

func TestParseRegistrationPINLine_EmptyIsAbsentNotError(t *testing.T) {
	pin, present, err := parseRegistrationPINLine("")
	if err != nil || present || pin != 0 {
		t.Errorf("parseRegistrationPINLine(\"\") = (%d, %v, %v), want (0, false, nil)", pin, present, err)
	}
}

func TestParseRegistrationPINLine_Errors(t *testing.T) {
	cases := []string{"garbage no colon", `"registration_pin": notanumber`}
	for _, line := range cases {
		if _, _, err := parseRegistrationPINLine(line); err == nil {
			t.Errorf("parseRegistrationPINLine(%q): expected an error, got none", line)
		}
	}
}

func TestPinOKStr(t *testing.T) {
	tru, fal := true, false
	if got := pinOKStr(nil); got != "nil" {
		t.Errorf("pinOKStr(nil) = %q, want %q", got, "nil")
	}
	if got := pinOKStr(&tru); got != "true" {
		t.Errorf("pinOKStr(&true) = %q, want %q", got, "true")
	}
	if got := pinOKStr(&fal); got != "false" {
		t.Errorf("pinOKStr(&false) = %q, want %q", got, "false")
	}
}

// ── diagnoseDERReportRoundtrip ───────────────────────────────────────────────

// derCapBody/derStatusBody build well-formed 2030.5 XML bodies matching what
// internal/northbound/derreport actually marshals (buildCapability/
// buildStatus), so the oracle's xml.Unmarshal exercises the same shape a
// live hub would PUT.
func derCapBody(t *testing.T, value int16, mult int8) string {
	t.Helper()
	full := model.DERCapabilityFull{
		Type:           83,
		ModesSupported: 0,
		RtgMaxW:        model.ActivePower{Value: value, Multiplier: mult},
	}
	body, err := xml.Marshal(&full)
	if err != nil {
		t.Fatalf("marshal DERCapabilityFull: %v", err)
	}
	return string(body)
}

func derStatusBody(t *testing.T, socPct *int16) string {
	t.Helper()
	full := model.DERStatusFull{ReadingTime: 1000}
	if socPct != nil {
		full.StateOfChargeStatus = &struct {
			DateTime int64 `xml:"dateTime"`
			Value    int16 `xml:"value"`
		}{DateTime: 1000, Value: *socPct}
	}
	body, err := xml.Marshal(&full)
	if err != nil {
		t.Fatalf("marshal DERStatusFull: %v", err)
	}
	return string(body)
}

func derSettingsBody(t *testing.T) string {
	t.Helper()
	full := model.DERSettingsFull{UpdatedTime: 1000}
	body, err := xml.Marshal(&full)
	if err != nil {
		t.Fatalf("marshal DERSettingsFull: %v", err)
	}
	return string(body)
}

func derAvailBody(t *testing.T) string {
	t.Helper()
	full := model.DERAvailability{ReadingTime: 1000}
	body, err := xml.Marshal(&full)
	if err != nil {
		t.Fatalf("marshal DERAvailability: %v", err)
	}
	return string(body)
}

func fullDERPuts(t *testing.T, socPct int16) map[string]derPutEntry {
	t.Helper()
	return map[string]derPutEntry{
		"/edev/2/der/1/dercap":   {Path: "/edev/2/der/1/dercap", Resource: "DERCapability", Body: derCapBody(t, 5000, 0), ReceivedAt: 100},
		"/edev/2/der/1/derset":   {Path: "/edev/2/der/1/derset", Resource: "DERSettings", Body: derSettingsBody(t), ReceivedAt: 100},
		"/edev/2/der/1/derstat":  {Path: "/edev/2/der/1/derstat", Resource: "DERStatus", Body: derStatusBody(t, &socPct), ReceivedAt: 200},
		"/edev/2/der/1/deravail": {Path: "/edev/2/der/1/deravail", Resource: "DERAvailability", Body: derAvailBody(t), ReceivedAt: 200},
	}
}

func TestDiagnoseDERReportRoundtrip_Pass(t *testing.T) {
	s := mkSamples(10, func(i int, smp *maySample) {})
	puts := fullDERPuts(t, 5000) // 50.00%
	f := diagnoseDERReportRoundtrip(scFor("der-pass"), s, puts, nil)
	if f.Verdict != "PASS" {
		t.Fatalf("verdict = %s, want PASS (%s): %v", f.Verdict, f.Headline, f.Diagnosis)
	}
}

func TestDiagnoseDERReportRoundtrip_MissingResource(t *testing.T) {
	s := mkSamples(10, func(i int, smp *maySample) {})
	puts := fullDERPuts(t, 5000)
	delete(puts, "/edev/2/der/1/derstat")
	f := diagnoseDERReportRoundtrip(scFor("der-missing"), s, puts, nil)
	if f.Verdict != "FAIL" {
		t.Fatalf("verdict = %s, want FAIL", f.Verdict)
	}
	assertDiag(t, f, "DERStatus")
}

func TestDiagnoseDERReportRoundtrip_ZeroRtgMaxW(t *testing.T) {
	s := mkSamples(10, func(i int, smp *maySample) {})
	puts := fullDERPuts(t, 5000)
	puts["/edev/2/der/1/dercap"] = derPutEntry{Resource: "DERCapability", Body: derCapBody(t, 0, 0), ReceivedAt: 100}
	f := diagnoseDERReportRoundtrip(scFor("der-zerocap"), s, puts, nil)
	if f.Verdict != "FAIL" {
		t.Fatalf("verdict = %s, want FAIL (%s)", f.Verdict, f.Headline)
	}
	assertDiag(t, f, "rtgMaxW")
}

func TestDiagnoseDERReportRoundtrip_NoSoC(t *testing.T) {
	s := mkSamples(10, func(i int, smp *maySample) {})
	puts := fullDERPuts(t, 5000)
	puts["/edev/2/der/1/derstat"] = derPutEntry{Resource: "DERStatus", Body: derStatusBody(t, nil), ReceivedAt: 200}
	f := diagnoseDERReportRoundtrip(scFor("der-nosoc"), s, puts, nil)
	if f.Verdict != "FAIL" {
		t.Fatalf("verdict = %s, want FAIL (%s)", f.Verdict, f.Headline)
	}
	assertDiag(t, f, "stateOfChargeStatus")
}

func TestDiagnoseDERReportRoundtrip_AvailabilityAbsentIsDegraded(t *testing.T) {
	s := mkSamples(10, func(i int, smp *maySample) {})
	puts := fullDERPuts(t, 5000)
	delete(puts, "/edev/2/der/1/deravail")
	f := diagnoseDERReportRoundtrip(scFor("der-noavail"), s, puts, nil)
	if f.Verdict != "DEGRADED" {
		t.Fatalf("verdict = %s, want DEGRADED (%s)", f.Verdict, f.Headline)
	}
	assertDiag(t, f, "G27")
}

func TestDiagnoseDERReportRoundtrip_FetchErrInconclusive(t *testing.T) {
	s := mkSamples(10, func(i int, smp *maySample) {})
	f := diagnoseDERReportRoundtrip(scFor("der-fetcherr"), s, nil, fmt.Errorf("connection refused"))
	if f.Verdict != "INCONCLUSIVE" {
		t.Fatalf("verdict = %s, want INCONCLUSIVE", f.Verdict)
	}
}

func TestDiagnoseDERReportRoundtrip_NoSamplesInconclusive(t *testing.T) {
	f := diagnoseDERReportRoundtrip(scFor("der-nosamples"), nil, fullDERPuts(t, 5000), nil)
	if f.Verdict != "INCONCLUSIVE" {
		t.Fatalf("verdict = %s, want INCONCLUSIVE", f.Verdict)
	}
}

func TestDiagnoseDERReportRoundtrip_HubUnreachableInconclusive(t *testing.T) {
	s := mkSamples(10, func(i int, smp *maySample) { smp.HubReachable = false })
	f := diagnoseDERReportRoundtrip(scFor("der-unreachable"), s, fullDERPuts(t, 5000), nil)
	if f.Verdict != "INCONCLUSIVE" {
		t.Fatalf("verdict = %s, want INCONCLUSIVE", f.Verdict)
	}
}

// ── diagnosePinFreeze ────────────────────────────────────────────────────────

func falseTimeline(n int) []*bool {
	out := make([]*bool, n)
	for i := range out {
		f := false
		out[i] = &f
	}
	return out
}

func TestDiagnosePinFreeze_PassSilentEgress(t *testing.T) {
	s := mkSamples(60, func(i int, smp *maySample) {})
	before := map[string]derPutEntry{"/p/derstat": {Resource: "DERStatus", ReceivedAt: 100}}
	after := map[string]derPutEntry{"/p/derstat": {Resource: "DERStatus", ReceivedAt: 100}}
	f := diagnosePinFreeze(scFor("pin-pass"), s, falseTimeline(30), before, after, nil, nil, 2, 2, 3, 3)
	if f.Verdict != "PASS" {
		t.Fatalf("verdict = %s, want PASS (%s): %v", f.Verdict, f.Headline, f.Diagnosis)
	}
}

func TestDiagnosePinFreeze_FailDERPutAdvanced(t *testing.T) {
	s := mkSamples(60, func(i int, smp *maySample) {})
	before := map[string]derPutEntry{"/p/derstat": {Resource: "DERStatus", ReceivedAt: 100}}
	after := map[string]derPutEntry{"/p/derstat": {Resource: "DERStatus", ReceivedAt: 250}}
	f := diagnosePinFreeze(scFor("pin-fail-der"), s, falseTimeline(30), before, after, nil, nil, 2, 2, 3, 3)
	if f.Verdict != "FAIL" {
		t.Fatalf("verdict = %s, want FAIL (%s)", f.Verdict, f.Headline)
	}
	assertDiag(t, f, "DER* PUT")
}

func TestDiagnosePinFreeze_FailAlertsGrew(t *testing.T) {
	s := mkSamples(60, func(i int, smp *maySample) {})
	before := map[string]derPutEntry{}
	after := map[string]derPutEntry{}
	f := diagnosePinFreeze(scFor("pin-fail-alerts"), s, falseTimeline(30), before, after, nil, nil, 2, 3, 3, 3)
	if f.Verdict != "FAIL" {
		t.Fatalf("verdict = %s, want FAIL (%s)", f.Verdict, f.Headline)
	}
	assertDiag(t, f, "/admin/alerts")
}

func TestDiagnosePinFreeze_FailLogEventsGrew(t *testing.T) {
	s := mkSamples(60, func(i int, smp *maySample) {})
	before := map[string]derPutEntry{}
	after := map[string]derPutEntry{}
	f := diagnosePinFreeze(scFor("pin-fail-logs"), s, falseTimeline(30), before, after, nil, nil, 2, 2, 3, 5)
	if f.Verdict != "FAIL" {
		t.Fatalf("verdict = %s, want FAIL (%s)", f.Verdict, f.Headline)
	}
	assertDiag(t, f, "/admin/logevents")
}

func TestDiagnosePinFreeze_InconclusiveNeverFalse(t *testing.T) {
	s := mkSamples(60, func(i int, smp *maySample) {})
	timeline := make([]*bool, 5) // all nil — every probe failed
	f := diagnosePinFreeze(scFor("pin-neverfalse"), s, timeline, map[string]derPutEntry{}, map[string]derPutEntry{}, nil, nil, 0, 0, 0, 0)
	if f.Verdict != "INCONCLUSIVE" {
		t.Fatalf("verdict = %s, want INCONCLUSIVE (%s)", f.Verdict, f.Headline)
	}
}

func TestDiagnosePinFreeze_InconclusiveFlippedBack(t *testing.T) {
	s := mkSamples(60, func(i int, smp *maySample) {})
	fals, tru := false, true
	timeline := []*bool{&fals, &fals, &tru}
	f := diagnosePinFreeze(scFor("pin-flip"), s, timeline, map[string]derPutEntry{}, map[string]derPutEntry{}, nil, nil, 0, 0, 0, 0)
	if f.Verdict != "INCONCLUSIVE" {
		t.Fatalf("verdict = %s, want INCONCLUSIVE (%s)", f.Verdict, f.Headline)
	}
	if !containsFold(f.Headline, "flipped back") {
		t.Errorf("headline = %q, want it to mention pin_ok flipping back", f.Headline)
	}
}

func TestDiagnosePinFreeze_InconclusiveDERPutFetchErr(t *testing.T) {
	s := mkSamples(60, func(i int, smp *maySample) {})
	f := diagnosePinFreeze(scFor("pin-fetcherr"), s, falseTimeline(10), nil, nil, fmt.Errorf("boom"), nil, 0, 0, 0, 0)
	if f.Verdict != "INCONCLUSIVE" {
		t.Fatalf("verdict = %s, want INCONCLUSIVE", f.Verdict)
	}
}

// ── diagnoseLogEventAlarmPair ────────────────────────────────────────────────

func TestDiagnoseLogEventAlarmPair_Pass(t *testing.T) {
	s := mkSamples(75, func(i int, smp *maySample) {})
	before := []model.LogEvent{}
	after := []model.LogEvent{
		{LogEventCode: 6, CreatedDateTime: 100},
		{LogEventCode: 7, CreatedDateTime: 500},
	}
	f := diagnoseLogEventAlarmPair(scFor("lev-pass"), s, before, after, nil, nil, 6, 7)
	if f.Verdict != "PASS" {
		t.Fatalf("verdict = %s, want PASS (%s): %v", f.Verdict, f.Headline, f.Diagnosis)
	}
}

func TestDiagnoseLogEventAlarmPair_FailNoEvents(t *testing.T) {
	s := mkSamples(75, func(i int, smp *maySample) {})
	f := diagnoseLogEventAlarmPair(scFor("lev-none"), s, nil, nil, nil, nil, 6, 7)
	if f.Verdict != "FAIL" {
		t.Fatalf("verdict = %s, want FAIL", f.Verdict)
	}
}

func TestDiagnoseLogEventAlarmPair_FailOnlyAlarmNoRTN(t *testing.T) {
	s := mkSamples(75, func(i int, smp *maySample) {})
	after := []model.LogEvent{{LogEventCode: 6, CreatedDateTime: 100}}
	f := diagnoseLogEventAlarmPair(scFor("lev-onlyalarm"), s, nil, after, nil, nil, 6, 7)
	if f.Verdict != "FAIL" {
		t.Fatalf("verdict = %s, want FAIL", f.Verdict)
	}
	if !containsFold(f.Headline, "no RTN") {
		t.Errorf("headline = %q, want it to mention no RTN followed", f.Headline)
	}
}

func TestDiagnoseLogEventAlarmPair_FailOnlyRTNNoAlarm(t *testing.T) {
	s := mkSamples(75, func(i int, smp *maySample) {})
	after := []model.LogEvent{{LogEventCode: 7, CreatedDateTime: 100}}
	f := diagnoseLogEventAlarmPair(scFor("lev-onlyrtn"), s, nil, after, nil, nil, 6, 7)
	if f.Verdict != "FAIL" {
		t.Fatalf("verdict = %s, want FAIL", f.Verdict)
	}
	if !containsFold(f.Headline, "no preceding alarm") {
		t.Errorf("headline = %q, want it to mention no preceding alarm", f.Headline)
	}
}

func TestDiagnoseLogEventAlarmPair_FailOutOfOrder(t *testing.T) {
	s := mkSamples(75, func(i int, smp *maySample) {})
	after := []model.LogEvent{
		{LogEventCode: 7, CreatedDateTime: 100},
		{LogEventCode: 6, CreatedDateTime: 500},
	}
	f := diagnoseLogEventAlarmPair(scFor("lev-order"), s, nil, after, nil, nil, 6, 7)
	if f.Verdict != "FAIL" {
		t.Fatalf("verdict = %s, want FAIL (%s)", f.Verdict, f.Headline)
	}
	if !containsFold(f.Headline, "not time-ordered") {
		t.Errorf("headline = %q, want it to mention out-of-order arrival", f.Headline)
	}
}

func TestDiagnoseLogEventAlarmPair_IsolatesFromPriorScenario(t *testing.T) {
	s := mkSamples(75, func(i int, smp *maySample) {})
	// A prior scenario already left a code-6/7 pair in gridsim's list; THIS
	// run's own events (after len(before)) contain none — must not credit
	// the leftover pair as this run's.
	before := []model.LogEvent{
		{LogEventCode: 6, CreatedDateTime: 10},
		{LogEventCode: 7, CreatedDateTime: 20},
	}
	after := before // nothing new this run
	f := diagnoseLogEventAlarmPair(scFor("lev-isolate"), s, before, after, nil, nil, 6, 7)
	if f.Verdict != "FAIL" {
		t.Fatalf("verdict = %s, want FAIL (leftover pair must not count) — got %s: %v", f.Verdict, f.Headline, f.Diagnosis)
	}
}

func TestDiagnoseLogEventAlarmPair_FetchErrInconclusive(t *testing.T) {
	s := mkSamples(75, func(i int, smp *maySample) {})
	f := diagnoseLogEventAlarmPair(scFor("lev-fetcherr"), s, nil, nil, fmt.Errorf("boom"), nil, 6, 7)
	if f.Verdict != "INCONCLUSIVE" {
		t.Fatalf("verdict = %s, want INCONCLUSIVE", f.Verdict)
	}
}

// ── diagnoseCannotComplyVocab ────────────────────────────────────────────────

func exportCons0() *activeConstraint {
	return &activeConstraint{Typ: "exportCap", LimW: 0, MRID: "M-cc-table27"}
}

// TestDiagnoseCannotComplyVocab_AdmittedBreach_Table27 covers the realistic
// "genuinely could not comply, and admitted it correctly" case: a sustained
// EXPORT overage (negative RealGridW — see breachOver's exportCap sign
// convention, mayhem.go) with CannotComply reported. diagnoseConverge's own
// base verdict for a ReportedCannot breach is DEGRADED ("device did not
// honour the ACKed write; hub flagged it" — an honest admission, not a full
// PASS), which this oracle passes through unchanged; it only adds the vocab
// classification on top.
func TestDiagnoseCannotComplyVocab_AdmittedBreach_Table27(t *testing.T) {
	cons := exportCons0()
	s := mkSamples(75, func(i int, smp *maySample) {
		smp.RealGridW, smp.HubGridW = -3000, -3000 // sustained export overage, never converges
		smp.CannotComply = true
		smp.CannotComplyCount = 1
	})
	f := diagnoseCannotComplyVocab(scFor("cc-pass"), cons, s, []string{"table27"}, true)
	if f.Verdict != "DEGRADED" {
		t.Fatalf("verdict = %s, want DEGRADED (%s): %v", f.Verdict, f.Headline, f.Diagnosis)
	}
	assertDiag(t, f, "table27")
}

func TestDiagnoseCannotComplyVocab_FailLegacy(t *testing.T) {
	cons := exportCons0()
	s := mkSamples(75, func(i int, smp *maySample) {
		smp.RealGridW, smp.HubGridW = -3000, -3000
		smp.CannotComply = true
		smp.CannotComplyCount = 1
	})
	f := diagnoseCannotComplyVocab(scFor("cc-legacy"), cons, s, []string{"legacy"}, true)
	if f.Verdict != "FAIL" {
		t.Fatalf("verdict = %s, want FAIL (%s)", f.Verdict, f.Headline)
	}
	assertDiag(t, f, "legacy")
}

func TestDiagnoseCannotComplyVocab_NoCannotComplyPassthrough(t *testing.T) {
	cons := exportCons0()
	// Converges cleanly — no breach, no CannotComply. diagnoseConverge's own
	// base verdict (PASS) should pass straight through with no vocab claim.
	s := mkSamples(75, func(i int, smp *maySample) { smp.RealGridW, smp.HubGridW = 0, 0 })
	f := diagnoseCannotComplyVocab(scFor("cc-none"), cons, s, nil, true)
	if f.Verdict != "PASS" {
		t.Fatalf("verdict = %s, want PASS (%s)", f.Verdict, f.Headline)
	}
}

func TestDiagnoseCannotComplyVocab_VocabsUnreachableInconclusive(t *testing.T) {
	cons := exportCons0()
	s := mkSamples(75, func(i int, smp *maySample) {
		smp.RealGridW, smp.HubGridW = -3000, -3000
		smp.CannotComply = true
		smp.CannotComplyCount = 1
	})
	f := diagnoseCannotComplyVocab(scFor("cc-vocabunreach"), cons, s, nil, false)
	if f.Verdict != "INCONCLUSIVE" {
		t.Fatalf("verdict = %s, want INCONCLUSIVE (%s)", f.Verdict, f.Headline)
	}
}

// ── diagnoseRedirectSurvival ─────────────────────────────────────────────────

func TestDiagnoseRedirectSurvival_Pass(t *testing.T) {
	cons := exportCons()
	s := mkSamples(75, func(i int, smp *maySample) {
		smp.HubReachable = true
		smp.RealGridW, smp.HubGridW = 0, 0
	})
	f := diagnoseRedirectSurvival(scFor("redir-pass"), cons, s)
	if f.Verdict != "PASS" {
		t.Fatalf("verdict = %s, want PASS (%s): %v", f.Verdict, f.Headline, f.Diagnosis)
	}
}

func TestDiagnoseRedirectSurvival_FailUnreachable(t *testing.T) {
	cons := exportCons()
	s := mkSamples(75, func(i int, smp *maySample) { smp.HubReachable = false })
	f := diagnoseRedirectSurvival(scFor("redir-unreachable"), cons, s)
	if f.Verdict != "FAIL" {
		t.Fatalf("verdict = %s, want FAIL", f.Verdict)
	}
	if !containsFold(f.Headline, "stopped responding") {
		t.Errorf("headline = %q, want it to mention the hub not responding", f.Headline)
	}
}

func TestDiagnoseRedirectSurvival_FailUnseated(t *testing.T) {
	cons := exportCons()
	s := mkSamples(75, func(i int, smp *maySample) {
		smp.HubReachable = true
		smp.RealGridW, smp.HubGridW = -3000, -3000 // sustained export overage, never recovers
	})
	f := diagnoseRedirectSurvival(scFor("redir-unseated"), cons, s)
	if f.Verdict != "FAIL" {
		t.Fatalf("verdict = %s, want FAIL (%s)", f.Verdict, f.Headline)
	}
	if !containsFold(f.Headline, "unseated") {
		t.Errorf("headline = %q, want it to mention the control being unseated", f.Headline)
	}
}

func TestDiagnoseRedirectSurvival_DegradedTransientRecovered(t *testing.T) {
	cons := exportCons()
	s := mkSamples(75, func(i int, smp *maySample) {
		smp.HubReachable = true
		if i < 40 {
			smp.RealGridW, smp.HubGridW = -3000, -3000
		} else {
			smp.RealGridW, smp.HubGridW = 0, 0
		}
	})
	f := diagnoseRedirectSurvival(scFor("redir-degraded"), cons, s)
	if f.Verdict != "DEGRADED" {
		t.Fatalf("verdict = %s, want DEGRADED (%s)", f.Verdict, f.Headline)
	}
}

func TestDiagnoseRedirectSurvival_NoSamplesInconclusive(t *testing.T) {
	f := diagnoseRedirectSurvival(scFor("redir-nosamples"), exportCons(), nil)
	if f.Verdict != "INCONCLUSIVE" {
		t.Fatalf("verdict = %s, want INCONCLUSIVE", f.Verdict)
	}
}

// ── scenario construction sanity ─────────────────────────────────────────────

// TestReportingScenarios_WellFormed catches the cheap mistakes (duplicate
// IDs, empty Hypothesis/Expected/Fix, a nil setup/evaluate) that go build
// itself cannot — mirrors any existing scenario-battery smoke test's shape,
// none of which touches a live bench.
func TestReportingScenarios_WellFormed(t *testing.T) {
	d := &mayhemDriver{}
	seen := map[string]bool{}
	for _, sc := range d.reportingScenarios() {
		if sc.ID == "" {
			t.Fatalf("scenario with empty ID: %+v", sc)
		}
		if seen[sc.ID] {
			t.Errorf("duplicate scenario ID %q", sc.ID)
		}
		seen[sc.ID] = true
		if sc.Hypothesis == "" || sc.Expected == "" || sc.Fix == "" {
			t.Errorf("%s: Hypothesis/Expected/Fix must not be empty", sc.ID)
		}
		if sc.HoldS < 60 || sc.HoldS > 90 {
			t.Errorf("%s: HoldS = %d, want in [60,90] per the task's hold_s convention", sc.ID, sc.HoldS)
		}
		if sc.setup == nil {
			t.Errorf("%s: setup must not be nil", sc.ID)
		}
		if sc.evaluate == nil {
			t.Errorf("%s: evaluate must not be nil", sc.ID)
		}
		if sc.teardown == nil {
			t.Errorf("%s: teardown must not be nil", sc.ID)
		}
	}
	wantIDs := []string{
		"der-report-roundtrip", "pin-freeze-egress-halt", "logevent-alarm-pair",
		"cannotcomply-table27", "dcap-redirect", "redirect-storm",
	}
	for _, id := range wantIDs {
		if !seen[id] {
			t.Errorf("reportingScenarios() missing expected ID %q", id)
		}
	}
}
