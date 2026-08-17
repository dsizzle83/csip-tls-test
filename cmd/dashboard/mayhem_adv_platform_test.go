package main

// mayhem_adv_platform_test.go — the DRIFT TRAP for the two contracts this
// package hand-mirrors: bus.CurveSetContentHash's canonicalization and the
// DesiredAdvanced envelope version.
//
// # Why a trap was needed
//
// advCurveSetContentHash is a deliberate independent re-implementation — see
// its doc for why importing the gateway's own function would make the check
// vacuous — and independence without a trap is just drift waiting to happen.
// It duly drifted TWO GENERATIONS: five tokens against the platform's seven (no
// vRef, no openLoopTms), while every injected document stamped v=1 against a
// DesiredAdvancedMinV of 4. The adv mayhem drives were injecting documents the
// DUT refuses at the version gate, and nothing in this repo could notice.
//
// # What each row buys, and why BOTH are here
//
//	the differential rows   run this package's mirror and lexa-platform's own
//	                        bus.CurveSetContentHash over the same vectors and
//	                        require them to agree. This is what makes the NEXT
//	                        platform move fail THIS repo's suite. A golden
//	                        vector alone could not: it pins our implementation
//	                        to a value, so it stays green while the platform
//	                        walks away from it.
//	the golden row          pins the exact canonical BYTES and digest here. It
//	                        is what makes a change to either implementation
//	                        legible — the differential rows would go red without
//	                        saying which side moved, and the canonical line is
//	                        the thing a reader of a captured document needs.
//
// THE FORM IS OWNED BY lexa-platform bus/curves.go CurveSetContentHash, and the
// version by bus/envelope.go DesiredAdvancedV / DesiredAdvancedMinV. Nothing
// here is authoritative; these rows exist to keep the copy honest and to say
// out loud where the original lives. The platform commit these were written
// against is recorded in this repo's platform.pin.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"lexa-platform/bus"
)

// TestAdvCurveSetContentHashMatchesThePlatform is the differential oracle.
//
// The vectors deliberately exercise every token that can vary, INCLUDING the
// two whose absence was the defect: a curve with a vRef and a curve with an
// openLoopTms must hash differently from the same curve without them, and each
// must agree with the platform.
func TestAdvCurveSetContentHashMatchesThePlatform(t *testing.T) {
	olt := func(v uint16) *uint16 { return &v }
	for _, tc := range []struct {
		name  string
		entry bus.CurveSetEntry
	}{
		{"the drives' own volt-var curve", bus.CurveSetEntry{
			Mode: "volt_var", CurveType: advCurveTypeTest, XMult: advCurveXMult, YMult: advCurveYMult,
			Points: []bus.CurvePoint{{X: 100, Y: 50}, {X: 200, Y: -50}},
		}},
		{"a yRefType that is not zero", bus.CurveSetEntry{
			Mode: "volt_var", CurveType: 11, YRefType: 3,
			Points: []bus.CurvePoint{{X: 9570, Y: 30}},
		}},
		{"multipliers, both signs", bus.CurveSetEntry{
			Mode: "watt_var", CurveType: 14, XMult: -2, YMult: 1,
			Points: []bus.CurvePoint{{X: -5, Y: 7}, {X: 0, Y: 0}},
		}},
		{"a vRef — invisible to the five-token mirror", bus.CurveSetEntry{
			Mode: "volt_var", CurveType: 11, VRef: 10500,
			Points: []bus.CurvePoint{{X: 9570, Y: 30}},
		}},
		{"an openLoopTms — likewise", bus.CurveSetEntry{
			Mode: "volt_var", CurveType: 11, OpenLoopTms: olt(500),
			Points: []bus.CurvePoint{{X: 9570, Y: 30}},
		}},
		{"openLoopTms ZERO, which is not the same as absent", bus.CurveSetEntry{
			Mode: "volt_var", CurveType: 11, OpenLoopTms: olt(0),
			Points: []bus.CurvePoint{{X: 9570, Y: 30}},
		}},
		{"every token at once", bus.CurveSetEntry{
			Mode: "volt_var", CurveType: 11, XMult: -2, YMult: 0, YRefType: 3,
			VRef: 10500, OpenLoopTms: olt(500),
			Points: []bus.CurvePoint{{X: 9570, Y: 30}, {X: 10430, Y: -30}},
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pts := make([][2]int32, len(tc.entry.Points))
			for i, p := range tc.entry.Points {
				pts[i] = [2]int32{p.X, p.Y}
			}
			mine := advCurveSetContentHash(tc.entry.Mode, tc.entry.CurveType, tc.entry.XMult,
				tc.entry.YMult, tc.entry.YRefType, tc.entry.VRef, tc.entry.OpenLoopTms, pts)
			theirs := bus.CurveSetContentHash([]bus.CurveSetEntry{tc.entry})
			if mine != theirs {
				t.Fatalf("this package's mirror and lexa-platform's bus.CurveSetContentHash disagree:\n"+
					"  mirror   %s\n  platform %s\n"+
					"The FORM IS OWNED BY bus/curves.go. Re-derive advCurveSetContentHash from it (and "+
					"update the golden row below), then re-pin platform.pin.", mine, theirs)
			}
		})
	}
}

// TestAdvCurveSetContentHashGoldenVector pins the exact canonical bytes.
//
// The line is spelled out here so a reader with a captured document can
// reproduce the digest by hand, and so a diff that changes it is legible as a
// change to the CONTRACT rather than as an opaque hash churn.
func TestAdvCurveSetContentHashGoldenVector(t *testing.T) {
	// mode|curveType|xMult|yMult|yRefType|vRef|openLoopTms| then the points.
	const canonical = "volt_var|1|0|0|0|0|-|100,50;200,-50;\n"
	sum := sha256.Sum256([]byte(canonical))
	want := hex.EncodeToString(sum[:])

	got := advCurveSetContentHash("volt_var", advCurveTypeTest, advCurveXMult, advCurveYMult, 0,
		advCurveVRefNone, advCurveOpenLoopTmsNone, advCurveTestPoints())
	if got != want {
		t.Fatalf("the drives' volt-var curve hashes to\n  %s\nbut the canonical line\n  %q\nis\n  %s",
			got, canonical, want)
	}
	// And the platform agrees that this is the line — otherwise the golden
	// would pin a form only this repo believes in.
	if theirs := bus.CurveSetContentHash([]bus.CurveSetEntry{{
		Mode: "volt_var", CurveType: advCurveTypeTest, XMult: advCurveXMult, YMult: advCurveYMult,
		Points: []bus.CurvePoint{{X: 100, Y: 50}, {X: 200, Y: -50}},
	}}); theirs != want {
		t.Fatalf("lexa-platform hashes the same curve to %s, so the canonical line above is stale", theirs)
	}
}

// TestDesiredAdvPayloadsPassThePlatformVersionGate is the INJECTION-ACCEPTED
// witness at the payload level: every document these drives publish must clear
// the very gate that was silently rejecting them.
//
// bus.CheckVersionAtLeast is the gateway's own gate, called with the gateway's
// own floor and ceiling, so this row cannot pass on a version the DUT would
// refuse. It is the cheap half of the witness; the live half is the drive's own
// assertion that the DUT acted on the document (advInjectionAccepted).
func TestDesiredAdvPayloadsPassThePlatformVersionGate(t *testing.T) {
	const device = "inv-plain"
	topic := desiredAdvTopic(device)
	for _, tc := range []struct{ name, payload string }{
		{"volt-var curve", desiredAdvVoltVarPayload(device, "M-1", 1700000000)},
		{"fixed PF", desiredAdvFixedPFPayload(device, "M-2", 0.95, true, 1700000000)},
		{"teardown release", desiredAdvReleasePayload(device, 1700000001)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := bus.CheckVersionAtLeast(topic, []byte(tc.payload), bus.DesiredAdvancedMinV,
				bus.DesiredAdvancedV); err != nil {
				t.Fatalf("the gateway's own version gate REFUSES this injected document: %v\npayload: %s",
					err, tc.payload)
			}
			// It must also still decode into the document the gateway reads —
			// a version stamp that clears the gate on a body the reader cannot
			// parse would move the refusal one layer down, not remove it.
			var doc bus.DesiredAdvanced
			if err := json.Unmarshal([]byte(tc.payload), &doc); err != nil {
				t.Fatalf("the injected document does not decode as bus.DesiredAdvanced: %v", err)
			}
			if doc.DeviceID != device {
				t.Errorf("decoded device_id = %q, want %q", doc.DeviceID, device)
			}
		})
	}
}

// TestDesiredAdvVersionTracksThePlatform fails the moment the platform bumps
// the envelope without this package following — which is exactly how the v=1
// stamp survived three bumps.
func TestDesiredAdvVersionTracksThePlatform(t *testing.T) {
	if desiredAdvancedV != bus.DesiredAdvancedV {
		t.Fatalf("this package stamps DesiredAdvanced v=%d; lexa-platform is at DesiredAdvancedV=%d "+
			"(floor %d). Update desiredAdvancedV, re-check the payload shapes for fields the bump added, "+
			"and re-pin platform.pin.", desiredAdvancedV, bus.DesiredAdvancedV, bus.DesiredAdvancedMinV)
	}
	if desiredAdvancedV < bus.DesiredAdvancedMinV {
		t.Fatalf("this package stamps v=%d, below the gateway's floor of %d — every injected document "+
			"is refused at the version gate", desiredAdvancedV, bus.DesiredAdvancedMinV)
	}
}

// TestSilentInjectionIsNotReportedAsAnSSHGap is the third leg of the
// injection-accepted witness: the drives' own diagnosis must tell "we could not
// look" apart from "we looked and the DUT did nothing".
//
// Before advReportOutcome both produced the same INCONCLUSIVE headline —
// "could not read the retained reconciler report over SSH ... a detection gap,
// not a compliance finding" — which is where a document refused at the bus
// version gate went to hide for three platform bumps.
func TestSilentInjectionIsNotReportedAsAnSSHGap(t *testing.T) {
	s := []maySample{{}}
	sc := scFor("curve-adopt-readback-divergence")

	silent := diagnoseCurveAdoptDivergence(sc, s, "volt_var", advReportSilent, advReportMsg{}, nil)
	unreadable := diagnoseCurveAdoptDivergence(sc, s, "volt_var", advReportUnreadable, advReportMsg{}, errFakeSSH)

	if silent.Headline == unreadable.Headline {
		t.Fatalf("a DUT that ignored the injection and an SSH failure produce the SAME headline (%q) — "+
			"which is exactly how an injection nothing accepted reads as an observation gap",
			silent.Headline)
	}
	if !strings.Contains(strings.ToLower(silent.Headline), "never acted") {
		t.Errorf("the silent-injection headline does not say the DUT never acted on the document: %q",
			silent.Headline)
	}
	// And it must point at the version gate, since that is the mechanism that
	// produced the silence the last time.
	joined := strings.Join(silent.Diagnosis, " ")
	if !strings.Contains(joined, "version") {
		t.Errorf("the silent-injection diagnosis does not name the version gate:\n%s", joined)
	}
	if !strings.Contains(joined, fmt.Sprint(desiredAdvancedV)) {
		t.Errorf("the silent-injection diagnosis does not state the version this drive stamps (%d):\n%s",
			desiredAdvancedV, joined)
	}
}
