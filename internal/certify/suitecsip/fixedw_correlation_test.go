package suitecsip

// fixedw_correlation_test.go is IW15-004's test set: the row under test must be
// bound to ITS OWN control, by mRID and by the exact value and sign it
// commanded, at every point where evidence enters — the wire criterion here,
// and the prescribed-default sequence in inverter_control_lifecycle_test.go.
//
// The defect these guard against is not hypothetical and not subtle. The
// 2026-08-14 BASIC-013 report cited, as proof that the DUT received this row's
// set-active-power command, a DERControl with mRID=IW14-BAT-SMOKE-1 carrying
// <opModFixedW>-6000</opModFixedW>: a leftover control, from another session, on
// the opposite sign. The criterion had asked "did ANY control in the window
// carry opModFixedW?" and the honest answer to that question was yes.

import (
	"fmt"
	"strings"
	"testing"

	"csip-tls-test/internal/certify"
)

// dercListXML builds a DERControlList carrying an arbitrary number of controls,
// which the single-control dercXML cannot express — and "another control is
// also in the list" is precisely the shape this file is about.
func dercListXML(controls ...string) string {
	return `<?xml version="1.0" encoding="UTF-8"?>` +
		fmt.Sprintf(`<DERControlList xmlns="urn:ieee:std:2030.5:ns" href="/derp/0/derc" all="%d" results="%d">`,
			len(controls), len(controls)) +
		strings.Join(controls, "") + `</DERControlList>`
}

// dercEntry is one <DERControl> for dercListXML.
func dercEntry(mrid, mode, value string) string {
	return fmt.Sprintf(`<DERControl href="/derp/0/derc/%s"><mRID>%s</mRID>`+
		`<creationTime>100</creationTime>`+
		`<EventStatus><currentStatus>1</currentStatus><dateTime>100</dateTime></EventStatus>`+
		`<interval><duration>120</duration><start>200</start></interval>`+
		`<DERControlBase><%s>%s</%s></DERControlBase></DERControl>`, mrid, mrid, mode, value, mode)
}

func hundredths(v int64) *int64 { return &v }

// TestDERControlModeCriterion_BindsTheRowsOwnMRIDAndValue is the whole IW15-004
// correlation contract, one row per way the binding can be broken.
func TestDERControlModeCriterion_BindsTheRowsOwnMRIDAndValue(t *testing.T) {
	const row = "CERT-BASIC-013"
	for _, c := range []struct {
		name     string
		body     string
		want     *int64
		verdict  certify.Verdict
		contains []string
	}{
		{
			name:    "this row's own control at exactly the commanded value: PASS",
			body:    dercListXML(dercEntry(row, "opModFixedW", "6000")),
			want:    hundredths(6000),
			verdict: certify.Pass,
			// The citation must say it was THIS row's control, or the assertion
			// reads the same as the unbound one it replaced.
			contains: []string{row, "6000", "THIS row's own"},
		},
		{
			name:     "another row's control carrying the same mode: FAIL",
			body:     dercListXML(dercEntry("IW14-BAT-SMOKE-1", "opModFixedW", "6000")),
			want:     hundredths(6000),
			verdict:  certify.Fail,
			contains: []string{"IW14-BAT-SMOKE-1", row, "unrelated control"},
		},
		{
			name: "the wire's own defect, verbatim: an unrelated control on the OPPOSITE sign",
			body: dercListXML(dercEntry("IW14-BAT-SMOKE-1", "opModFixedW", "-6000")),
			want: hundredths(6000),
			// -6000 is a CHARGE command. Accepting it as evidence for a +6000
			// discharge row is the report the review quoted.
			verdict:  certify.Fail,
			contains: []string{"IW14-BAT-SMOKE-1", "-6000"},
		},
		{
			name: "this row's control, WRONG value: FAIL naming both numbers",
			body: dercListXML(dercEntry(row, "opModFixedW", "4000")),
			want: hundredths(6000),
			// The 40% the ladder used to substitute. It reached the DUT under
			// the right mRID and it is still not this row's test value.
			verdict:  certify.Fail,
			contains: []string{"4000", "6000", "not the value under test"},
		},
		{
			name:     "this row's control, WRONG sign: FAIL",
			body:     dercListXML(dercEntry(row, "opModFixedW", "-6000")),
			want:     hundredths(6000),
			verdict:  certify.Fail,
			contains: []string{"-6000", "6000"},
		},
		{
			name: "this row's control among unrelated ones: PASS on its own, ignoring the neighbours",
			body: dercListXML(
				dercEntry("IW14-BAT-SMOKE-1", "opModFixedW", "-6000"),
				dercEntry(row, "opModFixedW", "6000"),
				dercEntry("CERT-BASIC-013-DEFAULT", "opModFixedW", "5000")),
			want:     hundredths(6000),
			verdict:  certify.Pass,
			contains: []string{row, "6000"},
		},
		{
			name: "the row's own PRESCRIBED default must not satisfy the row",
			body: dercListXML(dercEntry("CERT-BASIC-013-DEFAULT", "opModFixedW", "5000")),
			want: hundredths(6000),
			// The default is published by this row, under a deliberately
			// different mRID, and carries the value the procedure prescribes as
			// the STARTING state. It is not the command under test.
			verdict:  certify.Fail,
			contains: []string{"CERT-BASIC-013-DEFAULT", "5000"},
		},
		{
			name:     "mRID bound, value unbound (a structured mode): this row's control passes",
			body:     dercListXML(dercEntry(row, "opModConnect", "false")),
			want:     nil,
			verdict:  certify.Pass,
			contains: []string{row},
		},
	} {
		t.Run(c.name, func(t *testing.T) {
			mode := "opModFixedW"
			if strings.Contains(c.body, "opModConnect") {
				mode = "opModConnect"
			}
			crit := critDERControlCarriesModeFrom(mode, "claim", row, c.want)
			f := crit.Wire(nil, synthTranscript(get("/derp/0/derc", 200, c.body)))
			if f.Unavailable != "" {
				t.Fatalf("the criterion declined to decide (%q) where the mode WAS on the wire — an "+
					"unavailable here reads as a bench gap and skips past a real correlation failure",
					f.Unavailable)
			}
			if f.Verdict != c.verdict {
				t.Fatalf("verdict = %s, want %s (observed: %s)", f.Verdict, c.verdict, f.Observed)
			}
			for _, want := range c.contains {
				if !strings.Contains(f.Observed, want) {
					t.Errorf("the finding does not mention %q, so a reader cannot check the correlation "+
						"themselves: %s", want, f.Observed)
				}
			}
		})
	}
}

// TestDERControlModeCriterion_AbsentModeStaysUnavailable pins the one branch
// that must NOT become a failure: a mode that appears nowhere in the transcript
// is the bench having no lever for it, which is a gap with an owner and not a
// finding about the DUT. IW15-004 tightened correlation; it did not turn every
// bench limitation into a DUT defect.
func TestDERControlModeCriterion_AbsentModeStaysUnavailable(t *testing.T) {
	body := dercListXML(dercEntry("CERT-BASIC-013", "opModFixedW", "6000"))
	reason := wantUnavailable(t, "mode absent",
		critDERControlCarriesModeFrom("opModVoltVar", "claim", "CERT-BASIC-006", hundredths(1)),
		synthTranscript(get("/derp/0/derc", 200, body)))
	if !strings.Contains(reason, "opModFixedW") {
		t.Errorf("the reason does not report the modes that WERE present: %q", reason)
	}
}

// TestDERControlModeCriterion_UnboundCallersUnchanged is the
// behaviour-preservation half: the callers that do not mint their own control
// (core.go's and aggregator.go's power-factor criteria) pass an empty mRID and
// must keep matching any control carrying the mode.
func TestDERControlModeCriterion_UnboundCallersUnchanged(t *testing.T) {
	body := dercListXML(dercEntry("SOMEONE-ELSES-MRID", "opModFixedPFInjectW", "95"))
	f := wantVerdict(t, "unbound", critDERControlCarriesMode("opModFixedPFInjectW", "claim"),
		synthTranscript(get("/derp/0/derc", 200, body)), certify.Pass)
	if !strings.Contains(f.Observed, "SOMEONE-ELSES-MRID") {
		t.Errorf("the unbound criterion no longer names the control it matched: %s", f.Observed)
	}
}

// TestInverterControlSpec_CriteriaBindTheRowsOwnControl proves the binding
// reaches the ROW, not merely the criterion: it builds the real spec, hands it
// the params the live phase would have written, and evaluates the criterion the
// row actually mints against a transcript carrying somebody else's control.
func TestInverterControlSpec_CriteriaBindTheRowsOwnControl(t *testing.T) {
	m := withOracle(scalarModeOracledDefaultFirst("opModFixedW", 5000, 6000,
		func(r *ControlRequest, h int64) { r.FixedW = ptr(h) }), oracleFixedW)
	s := inverterControlSpec(m, "a set-active-power command", "CERT-BASIC-013")

	obs := &Observation{Params: map[string]string{
		"mrid":                 "CERT-BASIC-013",
		oracleCommandedParam:   "6000",
		oracleVerdictParam:     string(certify.Pass),
		oraclePreVerdictParam:  string(certify.Fail),
		oraclePreObservedParam: "the DER's own WSet resolves to 4000.0 W",
		oracleObservedParam:    "the DER's own WSet resolves to 4800.0 W",
	}}
	crit := modeCriterion(t, s, obs)

	// The row's own control is missing; an unrelated FixedW is present. This is
	// the ece6499 transcript, reduced to its essentials.
	f := crit.Wire(nil, synthTranscript(get("/derp/0/derc", 200,
		dercListXML(dercEntry("IW14-BAT-SMOKE-1", "opModFixedW", "-6000")))))
	if f.Verdict != certify.Fail {
		t.Fatalf("the row's own wire criterion = %+v against a capture holding only an UNRELATED "+
			"opModFixedW; want FAIL — this is the assertion the release-lock review found passing", f)
	}
	// And the same row passes on its own control at its own value.
	f = crit.Wire(nil, synthTranscript(get("/derp/0/derc", 200,
		dercListXML(dercEntry("CERT-BASIC-013", "opModFixedW", "6000")))))
	if f.Verdict != certify.Pass {
		t.Fatalf("the row's own wire criterion = %+v against its OWN control at its OWN value; want PASS", f)
	}
}

// TestInverterControlSpec_LadderValueIsWhatTheCriterionRequires keeps the value
// binding honest for the row that still HAS a ladder (BASIC-010): the criterion
// must require what Setup actually commanded, not what the catalog states, or a
// legitimate ladder departure would fail its own wire criterion.
func TestInverterControlSpec_LadderValueIsWhatTheCriterionRequires(t *testing.T) {
	s := inverterControlSpec(basic010Mode(), "a maximum active power limit", "CERT-BASIC-010")
	obs := &Observation{Params: map[string]string{
		"mrid":               "CERT-BASIC-010",
		oracleCommandedParam: "4000", // the ladder alternate this run departed to
	}}
	crit := modeCriterion(t, s, obs)

	f := crit.Wire(nil, synthTranscript(get("/derp/0/derc", 200,
		dercListXML(dercEntry("CERT-BASIC-010", "opModMaxLimW", "4000")))))
	if f.Verdict != certify.Pass {
		t.Fatalf("a row that departed to a ladder alternate = %+v against a control carrying THAT "+
			"alternate; want PASS — the criterion must bind what was SENT", f)
	}
	f = crit.Wire(nil, synthTranscript(get("/derp/0/derc", 200,
		dercListXML(dercEntry("CERT-BASIC-010", "opModMaxLimW", "6000")))))
	if f.Verdict != certify.Fail {
		t.Fatalf("a row that commanded 4000 = %+v against a control carrying 6000; want FAIL", f)
	}
}

// modeCriterion finds the "the DUT fetched a DERControl carrying ..." criterion
// a spec mints, so a test asserts on the row's real criterion rather than on
// its position in the slice.
func modeCriterion(t *testing.T, s spec, obs *Observation) criterion {
	t.Helper()
	for _, c := range s.Criteria(obs) {
		if strings.HasPrefix(c.Claim, "the DUT fetched a DERControl carrying") {
			return c
		}
	}
	t.Fatal("the spec mints no DERControl-carries-mode criterion")
	return criterion{}
}
