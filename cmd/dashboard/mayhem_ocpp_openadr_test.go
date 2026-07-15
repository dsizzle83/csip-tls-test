package main

import (
	"math"
	"strings"
	"testing"
)

// ── pure parsers ─────────────────────────────────────────────────────────────

func TestEvsimProtoFromPS(t *testing.T) {
	cases := []struct {
		line      string
		wantProto string
		wantOK    bool
	}{
		{"", "", false},
		{"dmitri 1234 0.0 0.1 /usr/local/bin/evsim -csms ws://69.0.0.1:8887/ocpp -id evse-001", "2.0.1", true},
		{"dmitri 1234 0.0 0.1 /usr/local/bin/evsim -csms ws://69.0.0.1:8886/ocpp -proto 1.6 -id evse-001", "1.6", true},
		{"dmitri 1234 0.0 0.1 /usr/local/bin/evsim -csms ws://69.0.0.1:8886/ocpp -proto=1.6 -id evse-001", "1.6", true},
		{"dmitri 1234 0.0 0.1 /usr/local/bin/evsim -proto 1.6j -id evse-001", "1.6", true},
	}
	for _, c := range cases {
		proto, ok := evsimProtoFromPS(c.line)
		if ok != c.wantOK || proto != c.wantProto {
			t.Errorf("evsimProtoFromPS(%q) = (%q, %v), want (%q, %v)", c.line, proto, ok, c.wantProto, c.wantOK)
		}
	}
}

func TestParsePairingModeLine_OK(t *testing.T) {
	cases := []struct{ line, want string }{
		{`"pairing_mode": "gated"`, "gated"},
		{`"pairing_mode":"open"`, "open"},
		{`"pairing_mode"   :   "gated"`, "gated"},
	}
	for _, c := range cases {
		got, err := parsePairingModeLine(c.line)
		if err != nil {
			t.Errorf("parsePairingModeLine(%q): unexpected error: %v", c.line, err)
			continue
		}
		if got != c.want {
			t.Errorf("parsePairingModeLine(%q) = %q, want %q", c.line, got, c.want)
		}
	}
}

func TestParsePairingModeLine_Errors(t *testing.T) {
	cases := []string{"", "garbage no colon", `"pairing_mode": ""`}
	for _, line := range cases {
		if _, err := parsePairingModeLine(line); err == nil {
			t.Errorf("parsePairingModeLine(%q): expected an error, got none", line)
		}
	}
}

func TestParseConfiguredStationIDs(t *testing.T) {
	out := "\"id\": \"cs-001\"\n\"id\":\"evse-002\"\n\n   \n"
	got := parseConfiguredStationIDs(out)
	want := []string{"cs-001", "evse-002"}
	if len(got) != len(want) {
		t.Fatalf("parseConfiguredStationIDs = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("parseConfiguredStationIDs[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestParseConfiguredStationIDs_Empty(t *testing.T) {
	if got := parseConfiguredStationIDs(""); len(got) != 0 {
		t.Errorf("parseConfiguredStationIDs(\"\") = %v, want empty", got)
	}
}

// ── diagnoseOCPP16Obey ───────────────────────────────────────────────────────

func TestDiagnoseOCPP16Obey_Pass(t *testing.T) {
	cons := importCons1000()
	s := mkSamples(80, func(i int, smp *maySample) {
		smp.RealGridW, smp.HubGridW = 800, 800
		smp.HubAdopted, smp.AdoptedTyp = true, "importCap"
		smp.EvSimOK = true
		if i < 45 {
			smp.EvSimA = 3
		} else {
			smp.EvSimA = 8
		}
	})
	f := diagnoseOCPP16Obey(scFor("ocpp16-pass"), cons, s, 45)
	if f.Verdict != "PASS" {
		t.Fatalf("verdict = %s, want PASS (%s): %v", f.Verdict, f.Headline, f.Diagnosis)
	}
}

func TestDiagnoseOCPP16Obey_FailNeverHeld(t *testing.T) {
	cons := importCons1000()
	s := mkSamples(80, func(i int, smp *maySample) {
		smp.RealGridW, smp.HubGridW = 1800, 1800
		smp.HubAdopted, smp.AdoptedTyp = true, "importCap"
		smp.EvSimOK, smp.EvSimA = true, 8
	})
	f := diagnoseOCPP16Obey(scFor("ocpp16-fail"), cons, s, 45)
	if f.Verdict != "FAIL" {
		t.Fatalf("verdict = %s, want FAIL", f.Verdict)
	}
	assertDiag(t, f, "bridge16.go")
}

func TestDiagnoseOCPP16Obey_FailStuckAfterRelease(t *testing.T) {
	cons := importCons1000()
	s := mkSamples(80, func(i int, smp *maySample) {
		smp.RealGridW, smp.HubGridW = 800, 800
		smp.HubAdopted, smp.AdoptedTyp = true, "importCap"
		smp.EvSimOK, smp.EvSimA = true, 3 // never rises, even after release
	})
	f := diagnoseOCPP16Obey(scFor("ocpp16-stuck"), cons, s, 45)
	if f.Verdict != "FAIL" {
		t.Fatalf("verdict = %s, want FAIL (%s)", f.Verdict, f.Headline)
	}
	if !strings.Contains(f.Headline, "pinned") {
		t.Errorf("headline = %q, want it to mention the charger staying pinned", f.Headline)
	}
	assertDiag(t, f, "release-semantics gap")
}

func TestDiagnoseOCPP16Obey_BlindNoPostProbe(t *testing.T) {
	cons := importCons1000()
	s := mkSamples(80, func(i int, smp *maySample) {
		smp.RealGridW, smp.HubGridW = 800, 800
		smp.HubAdopted, smp.AdoptedTyp = true, "importCap"
		if i < 45 {
			smp.EvSimOK, smp.EvSimA = true, 3
		} else {
			smp.EvSimOK = false
		}
	})
	f := diagnoseOCPP16Obey(scFor("ocpp16-blind"), cons, s, 45)
	if f.Verdict != "BLIND" {
		t.Fatalf("verdict = %s, want BLIND (%s)", f.Verdict, f.Headline)
	}
}

func TestDiagnoseOCPP16Obey_InconclusiveNeverReleased(t *testing.T) {
	cons := importCons1000()
	s := mkSamples(10, func(i int, smp *maySample) {})
	f := diagnoseOCPP16Obey(scFor("ocpp16-inc"), cons, s, -1)
	if f.Verdict != "INCONCLUSIVE" {
		t.Fatalf("verdict = %s, want INCONCLUSIVE", f.Verdict)
	}
}

func TestDiagnoseOCPP16Obey_InconclusiveNoSamples(t *testing.T) {
	f := diagnoseOCPP16Obey(scFor("ocpp16-nosamples"), importCons1000(), nil, -1)
	if f.Verdict != "INCONCLUSIVE" {
		t.Fatalf("verdict = %s, want INCONCLUSIVE", f.Verdict)
	}
}

// ── diagnoseOCPP16Release ────────────────────────────────────────────────────

func TestDiagnoseOCPP16Release_Pass(t *testing.T) {
	s := mkSamples(95, func(i int, smp *maySample) {
		smp.EvMaxA = 32
		smp.EvSimOK = true
		if i < 60 {
			smp.EvSimA = 3
		} else {
			smp.EvSimA = 25 // >= 60% of 32A
		}
	})
	f := diagnoseOCPP16Release(scFor("rel-pass"), noneCons(), s, 60)
	if f.Verdict != "PASS" {
		t.Fatalf("verdict = %s, want PASS (%s): %v", f.Verdict, f.Headline, f.Diagnosis)
	}
}

func TestDiagnoseOCPP16Release_FailStuck(t *testing.T) {
	s := mkSamples(95, func(i int, smp *maySample) {
		smp.EvMaxA = 32
		smp.EvSimOK, smp.EvSimA = true, 3 // never climbs back
	})
	f := diagnoseOCPP16Release(scFor("rel-fail"), noneCons(), s, 60)
	if f.Verdict != "FAIL" {
		t.Fatalf("verdict = %s, want FAIL (%s)", f.Verdict, f.Headline)
	}
	assertDiag(t, f, "never reclaimed")
}

func TestDiagnoseOCPP16Release_BlindNoMaxCurrent(t *testing.T) {
	s := mkSamples(95, func(i int, smp *maySample) {
		smp.EvSimOK, smp.EvSimA = true, 3
	})
	f := diagnoseOCPP16Release(scFor("rel-blind-max"), noneCons(), s, 60)
	if f.Verdict != "BLIND" {
		t.Fatalf("verdict = %s, want BLIND (%s)", f.Verdict, f.Headline)
	}
}

func TestDiagnoseOCPP16Release_BlindNoPreProbe(t *testing.T) {
	s := mkSamples(95, func(i int, smp *maySample) {
		smp.EvMaxA = 32
		if i >= 60 {
			smp.EvSimOK, smp.EvSimA = true, 25
		}
	})
	f := diagnoseOCPP16Release(scFor("rel-blind-pre"), noneCons(), s, 60)
	if f.Verdict != "BLIND" {
		t.Fatalf("verdict = %s, want BLIND (%s)", f.Verdict, f.Headline)
	}
}

func TestDiagnoseOCPP16Release_InconclusiveNeverReleased(t *testing.T) {
	s := mkSamples(10, func(i int, smp *maySample) {})
	f := diagnoseOCPP16Release(scFor("rel-inc"), noneCons(), s, -1)
	if f.Verdict != "INCONCLUSIVE" {
		t.Fatalf("verdict = %s, want INCONCLUSIVE", f.Verdict)
	}
}

// ── diagnosePairingHold ──────────────────────────────────────────────────────

func TestDiagnosePairingHold_Pass(t *testing.T) {
	s := mkSamples(30, func(i int, smp *maySample) {
		smp.EvSimOK, smp.EvSimA, smp.EvSimW = true, 10, 2300
		smp.EvW = 0 // hub never folds this station's power into plant
	})
	f := diagnosePairingHold(scFor("pair-pass"), noneCons(), s)
	if f.Verdict != "PASS" {
		t.Fatalf("verdict = %s, want PASS (%s): %v", f.Verdict, f.Headline, f.Diagnosis)
	}
}

func TestDiagnosePairingHold_FailLeaked(t *testing.T) {
	s := mkSamples(30, func(i int, smp *maySample) {
		smp.EvSimOK, smp.EvSimA, smp.EvSimW = true, 10, 2300
		smp.EvW = 2300 // hub folded the pending station's power into plant
	})
	f := diagnosePairingHold(scFor("pair-fail"), noneCons(), s)
	if f.Verdict != "FAIL" {
		t.Fatalf("verdict = %s, want FAIL (%s)", f.Verdict, f.Headline)
	}
	assertDiag(t, f, "folded")
}

func TestDiagnosePairingHold_InconclusiveNeverCharged(t *testing.T) {
	s := mkSamples(30, func(i int, smp *maySample) {
		smp.EvSimOK, smp.EvSimA = true, 0
	})
	f := diagnosePairingHold(scFor("pair-inc"), noneCons(), s)
	if f.Verdict != "INCONCLUSIVE" {
		t.Fatalf("verdict = %s, want INCONCLUSIVE (%s)", f.Verdict, f.Headline)
	}
}

func TestDiagnosePairingHold_FailHubDown(t *testing.T) {
	s := mkSamples(30, func(i int, smp *maySample) {
		smp.HubReachable = false
	})
	f := diagnosePairingHold(scFor("pair-down"), noneCons(), s)
	if f.Verdict != "FAIL" {
		t.Fatalf("verdict = %s, want FAIL", f.Verdict)
	}
}

// ── diagnoseEVSetpointClamp ──────────────────────────────────────────────────

func TestDiagnoseEVSetpointClamp_Pass(t *testing.T) {
	s := mkSamples(70, func(i int, smp *maySample) {
		smp.EvSimOK, smp.EvSimA = true, 5
	})
	f := diagnoseEVSetpointClamp(scFor("clamp-pass"), noneCons(), s, 20, 0, true)
	if f.Verdict != "PASS" {
		t.Fatalf("verdict = %s, want PASS (%s)", f.Verdict, f.Headline)
	}
}

func TestDiagnoseEVSetpointClamp_FailNegativeWire(t *testing.T) {
	s := mkSamples(70, func(i int, smp *maySample) {
		smp.EvSimOK, smp.EvSimA = true, 0
	})
	f := diagnoseEVSetpointClamp(scFor("clamp-fail"), noneCons(), s, 20, -8.7, true)
	if f.Verdict != "FAIL" {
		t.Fatalf("verdict = %s, want FAIL (%s)", f.Verdict, f.Headline)
	}
	assertDiag(t, f, "negative")
}

func TestDiagnoseEVSetpointClamp_FailPhysicalNegative(t *testing.T) {
	s := mkSamples(70, func(i int, smp *maySample) {
		smp.EvSimOK, smp.EvSimA = true, -1
	})
	f := diagnoseEVSetpointClamp(scFor("clamp-physical"), noneCons(), s, 20, 0, true)
	if f.Verdict != "FAIL" {
		t.Fatalf("verdict = %s, want FAIL (%s)", f.Verdict, f.Headline)
	}
	assertDiag(t, f, "physically")
}

func TestDiagnoseEVSetpointClamp_BlindNoProfileObserved(t *testing.T) {
	s := mkSamples(70, func(i int, smp *maySample) {
		smp.EvSimOK, smp.EvSimA = true, 5
	})
	f := diagnoseEVSetpointClamp(scFor("clamp-blind"), noneCons(), s, 20, math.Inf(1), false)
	if f.Verdict != "BLIND" {
		t.Fatalf("verdict = %s, want BLIND (%s)", f.Verdict, f.Headline)
	}
}

func TestDiagnoseEVSetpointClamp_InconclusiveNeverInjected(t *testing.T) {
	s := mkSamples(10, func(i int, smp *maySample) {})
	f := diagnoseEVSetpointClamp(scFor("clamp-inc"), noneCons(), s, -1, math.Inf(1), false)
	if f.Verdict != "INCONCLUSIVE" {
		t.Fatalf("verdict = %s, want INCONCLUSIVE", f.Verdict)
	}
}

// ── diagnoseOpenADRBind ──────────────────────────────────────────────────────

func openADRExportCons() *activeConstraint {
	return &activeConstraint{Typ: "exportCap", LimW: 1000, MRID: ""}
}

func csipTighterCons() *activeConstraint {
	return &activeConstraint{Typ: "exportCap", LimW: 0, MRID: "M-csip-tighter-1"}
}

func TestDiagnoseOpenADRBind_PassNoMRID(t *testing.T) {
	s := mkSamples(20, func(i int, smp *maySample) { smp.RealGridW, smp.HubGridW = -900, -900 })
	f := diagnoseOpenADRBind(5, 5, true)(scFor("oa-pass"), openADRExportCons(), s)
	if f.Verdict != "PASS" {
		t.Fatalf("verdict = %s, want PASS (%s)", f.Verdict, f.Headline)
	}
}

func TestDiagnoseOpenADRBind_PassWithMRID(t *testing.T) {
	s := mkSamples(20, func(i int, smp *maySample) { smp.RealGridW, smp.HubGridW = 0, 0 })
	f := diagnoseOpenADRBind(2, 2, true)(scFor("oa-pass-mrid"), csipTighterCons(), s)
	if f.Verdict != "PASS" {
		t.Fatalf("verdict = %s, want PASS (%s)", f.Verdict, f.Headline)
	}
}

func TestDiagnoseOpenADRBind_FailMisattributed(t *testing.T) {
	s := mkSamples(20, func(i int, smp *maySample) { smp.RealGridW, smp.HubGridW = -900, -900 })
	f := diagnoseOpenADRBind(5, 6, true)(scFor("oa-misattr"), openADRExportCons(), s)
	if f.Verdict != "FAIL" {
		t.Fatalf("verdict = %s, want FAIL (%s)", f.Verdict, f.Headline)
	}
	assertDiag(t, f, "DERControl mRID")
}

func TestDiagnoseOpenADRBind_FailNeverHeld(t *testing.T) {
	s := mkSamples(20, func(i int, smp *maySample) { smp.RealGridW, smp.HubGridW = -3000, -3000 })
	f := diagnoseOpenADRBind(5, 5, true)(scFor("oa-neverheld"), openADRExportCons(), s)
	if f.Verdict != "FAIL" {
		t.Fatalf("verdict = %s, want FAIL (%s)", f.Verdict, f.Headline)
	}
	assertDiag(t, f, "never adopted it")
}

func TestDiagnoseOpenADRBind_DegradedAttributedBreach(t *testing.T) {
	s := mkSamples(20, func(i int, smp *maySample) {
		smp.RealGridW, smp.HubGridW = -2000, -2000
		smp.CannotComply = true
		smp.CannotComplyCount = 3
	})
	f := diagnoseOpenADRBind(0, 3, true)(scFor("oa-degraded"), csipTighterCons(), s)
	if f.Verdict != "DEGRADED" {
		t.Fatalf("verdict = %s, want DEGRADED (%s)", f.Verdict, f.Headline)
	}
}

func TestDiagnoseOpenADRBind_BlindAlertsProbeUnreachable(t *testing.T) {
	s := mkSamples(20, func(i int, smp *maySample) { smp.RealGridW, smp.HubGridW = -900, -900 })
	f := diagnoseOpenADRBind(0, 0, false)(scFor("oa-blind"), openADRExportCons(), s)
	if f.Verdict != "BLIND" {
		t.Fatalf("verdict = %s, want BLIND (%s)", f.Verdict, f.Headline)
	}
}

func TestDiagnoseOpenADRBind_InconclusiveNoSamples(t *testing.T) {
	f := diagnoseOpenADRBind(0, 0, true)(scFor("oa-nosamples"), openADRExportCons(), nil)
	if f.Verdict != "INCONCLUSIVE" {
		t.Fatalf("verdict = %s, want INCONCLUSIVE", f.Verdict)
	}
}
