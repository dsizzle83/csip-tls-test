package suitecsip

// oracle_test.go hermetically exercises the IW13-001 §4.3 southbound oracle
// (oracleMaxLimW/oracleFixedW) — the one CSIP-suite unit path this design's
// task explicitly asks for, given the rest of the suite needs a live gridsim
// + DUT + capture pipeline this environment cannot run.
//
// Each test drives a REAL derbase.Base.ApplyControl against a REAL in-memory
// SunSpec fixture (csip-tls-test/internal/diff's own Device/Bench702, the
// same fixture the ctl family's differential runs against), so the oracle is
// proven against the identical register-writing code path production uses —
// not a hand-crafted register map that could silently drift from what a real
// device actually holds. The fixture's register snapshot is then served over
// a real HTTP server (mimicking the simapi sidecar internal/invariant.
// SimAPIDER reads in production, gw-campaign, and gw-mayhem), and the
// oracleXxx closures are run against it exactly as basicInverterControl's
// Setup phase runs them live.
//
// This is also the concrete proof of the design's own headline claim: a
// conformant <opModFixedW>6000</opModFixedW> decodes to 60% (not zero, the
// pre-fix bug) and converts to the right watts per the device's own
// nameplate — TestOracleFixedW_PassOnConformantRegister pins exactly that,
// end to end through the real derbase write path.

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"csip-tls-test/internal/certify"
	"csip-tls-test/internal/diff"
	model "lexa-proto/csipmodel"
	"lexa-proto/derbase"
	"lexa-proto/sunspec"
)

// oracleFixture builds a Bench702-shaped device (60 kW active, matching
// diff.Bench702's own fixture) with derbase initialised against it, so a test
// can drive a REAL ApplyControl before serving the resulting register state.
func oracleFixture(t *testing.T) (*diff.Device, *derbase.Base) {
	t.Helper()
	dev := diff.NewDevice(diff.Bench702())
	rdr, err := sunspec.NewReader(dev)
	if err != nil {
		t.Fatalf("sunspec.NewReader on the Bench702 fixture: %v", err)
	}
	base, err := derbase.Init(rdr, "oracle-test")
	if err != nil {
		t.Fatalf("derbase.Init on the Bench702 fixture: %v", err)
	}
	return dev, &base
}

// oracleTestRunCtx serves dev's current register snapshot at /registers (the
// simapi sidecar shape internal/invariant.SimAPIDER reads) and returns a
// *certify.RunCtx whose Sims[oracleSimName] points at it — the minimal
// fixture oracleUnitView needs, with no gridsim/DUT/capture pipeline at all.
func oracleTestRunCtx(t *testing.T, dev *diff.Device) *certify.RunCtx {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/registers", func(w http.ResponseWriter, r *http.Request) {
		snap := dev.Snapshot()
		out := make(map[string]uint16, len(snap))
		for addr, v := range snap {
			out[fmt.Sprintf("%d", addr)] = v
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(out)
	})
	mux.HandleFunc("/state", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"paused": false, "sessions": []any{}})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return &certify.RunCtx{
		Case: &certify.Case{UID: "test::oracle"},
		Sims: map[string]*certify.SimClient{
			oracleSimName: certify.NewSimClient(oracleSimName, srv.URL, http.DefaultClient),
		},
	}
}

// TestOracleMaxLimW_PassOnConformantRegister is the design's own headline
// proof: a conformant <opModMaxLimW>6000</opModMaxLimW> — PerCent, bare
// chardata — decodes to 60% (not zero, the pre-fix bug: the OLD ActivePower
// typing decoded the identical document to Multiplier:0,Value:0) and is
// independently confirmed on the DER's own WMaxLimPct register.
func TestOracleMaxLimW_PassOnConformantRegister(t *testing.T) {
	dev, base := oracleFixture(t)
	pc := model.PerCent{Value: 6000} // 60.00%, the wire's own hundredths unit
	if err := base.ApplyControl(model.DERControlBase{OpModMaxLimW: &pc}, "oracle-test"); err != nil {
		t.Fatalf("ApplyControl(opModMaxLimW=6000): %v", err)
	}
	rc := oracleTestRunCtx(t, dev)
	f := oracleMaxLimW(6000)(context.Background(), rc)
	if f.Verdict != certify.Pass {
		t.Fatalf("oracleMaxLimW(6000) after ApplyControl(60%%) = %+v, want Pass", f)
	}
}

// TestOracleMaxLimW_FailOnMismatchedCommand proves the oracle actually
// discriminates: the device genuinely holds 60%, but the row claims to have
// commanded a different percent (40%) — a real product/harness bug shape
// (wrong axis reached the register, or the wrong value was sent) — and the
// oracle must FAIL, not silently agree.
func TestOracleMaxLimW_FailOnMismatchedCommand(t *testing.T) {
	dev, base := oracleFixture(t)
	pc := model.PerCent{Value: 6000} // device actually holds 60%
	if err := base.ApplyControl(model.DERControlBase{OpModMaxLimW: &pc}, "oracle-test"); err != nil {
		t.Fatalf("ApplyControl(opModMaxLimW=6000): %v", err)
	}
	rc := oracleTestRunCtx(t, dev)
	f := oracleMaxLimW(4000)(context.Background(), rc) // row claims 40% was commanded
	if f.Verdict != certify.Fail {
		t.Fatalf("oracleMaxLimW(4000) against a device holding 60%% = %+v, want Fail", f)
	}
}

// TestOracleMaxLimW_UnavailableWhenSimUnreachable proves the oracle SKIPs
// (Unavailable), never silently Passes or Fails, when it cannot reach the DER
// at all — an unreachable independent oracle must not be indistinguishable
// from a satisfied one.
func TestOracleMaxLimW_UnavailableWhenSimUnreachable(t *testing.T) {
	rc := &certify.RunCtx{Case: &certify.Case{UID: "test::oracle"}, Sims: map[string]*certify.SimClient{}}
	f := oracleMaxLimW(6000)(context.Background(), rc)
	if f.Unavailable == "" {
		t.Fatalf("oracleMaxLimW with no sim configured = %+v, want Unavailable set", f)
	}
	if f.Verdict == certify.Pass || f.Verdict == certify.Fail {
		t.Fatalf("an unreachable oracle must never carry a decided Verdict, got %+v", f)
	}
}

// TestOracleMaxLimW_EffectBasedResolvesToWatts pins the IW13-005 shape change:
// the oracle now judges the DER's RESOLVED active-power ceiling in WATTS (like
// oracleFixedW), not the raw WMaxLimPct percent register the pre-fix oracle
// read. A conformant 60% ceiling on the 60 kW Bench702 fixture must resolve to
// a 36,000 W ceiling and PASS, and the Observed string must REPORT that
// resolved-watts ceiling — the visible signature that the comparison is
// effect-based (watts against the DER's own WMax), not percent-to-percent.
func TestOracleMaxLimW_EffectBasedResolvesToWatts(t *testing.T) {
	dev, base := oracleFixture(t)
	pc := model.PerCent{Value: 6000} // 60.00%
	if err := base.ApplyControl(model.DERControlBase{OpModMaxLimW: &pc}, "oracle-test"); err != nil {
		t.Fatalf("ApplyControl(opModMaxLimW=6000): %v", err)
	}
	rc := oracleTestRunCtx(t, dev)
	f := oracleMaxLimW(6000)(context.Background(), rc)
	if f.Verdict != certify.Pass {
		t.Fatalf("oracleMaxLimW(6000) after ApplyControl(60%%) = %+v, want Pass", f)
	}
	// 60% of the Bench702 fixture's 60 kW WMax = 36,000 W. The message must name
	// the resolved watts ceiling, or the judgment is not the effect-based one.
	if !strings.Contains(f.Observed, "36000") {
		t.Fatalf("oracleMaxLimW Observed = %q, want it to report the resolved 36000 W ceiling — proof the "+
			"judgment resolves WMaxLimPct against the DER's own WMax (watts), not the bare percent", f.Observed)
	}
	if !strings.Contains(f.Observed, "W") || strings.Contains(f.Observed, "register reads") {
		t.Fatalf("oracleMaxLimW Observed = %q, want a watts-ceiling message, not the pre-fix "+
			"percent-register-read message", f.Observed)
	}
}

// TestOracleMaxLimW_FailOnCeilingWattsMismatch is the effect-based twin of the
// discrimination proof: the DER's WMaxLimPct genuinely holds 60% (36,000 W on
// this 60 kW fixture), the row claims 30% (18,000 W) was commanded, and the
// oracle must FAIL on the resolved-watts gap, never silently agree.
func TestOracleMaxLimW_FailOnCeilingWattsMismatch(t *testing.T) {
	dev, base := oracleFixture(t)
	pc := model.PerCent{Value: 6000} // device holds a 60% / 36,000 W ceiling
	if err := base.ApplyControl(model.DERControlBase{OpModMaxLimW: &pc}, "oracle-test"); err != nil {
		t.Fatalf("ApplyControl(opModMaxLimW=6000): %v", err)
	}
	rc := oracleTestRunCtx(t, dev)
	f := oracleMaxLimW(3000)(context.Background(), rc) // row claims 30% / 18,000 W
	if f.Verdict != certify.Fail {
		t.Fatalf("oracleMaxLimW(3000) against a device holding a 60%% ceiling = %+v, want Fail", f)
	}
}

// TestOracleFixedW_PassOnConformantRegister mirrors TestOracleMaxLimW's proof
// for the signed axis: opModFixedW=6000 (60%) on a 60 kW device resolves to
// 36,000 W, and the independent oracle confirms it from the DER's own WSet
// register — computed via internal/invariant, never lexa-proto/csipmodel or
// derbase.
//
// The reference here is the NAMEPLATE, and for a stated reason rather than by
// default: diff.Bench702 is a PV inverter publishing the not-implemented
// sentinel for both rate ratings, which is exactly the shape in which a signed
// percent has nothing directional to be a percentage of (IW14-001/F5). The
// per-sign case is TestOracleFixedW_PerSignReferenceOnAnAsymmetricPack.
func TestOracleFixedW_PassOnConformantRegister(t *testing.T) {
	dev, base := oracleFixture(t)
	spc := model.SignedPerCent{Value: 6000} // 60.00% discharge
	if err := base.ApplyControl(model.DERControlBase{OpModFixedW: &spc}, "oracle-test"); err != nil {
		t.Fatalf("ApplyControl(opModFixedW=6000): %v", err)
	}
	rc := oracleTestRunCtx(t, dev)
	f := oracleFixedW(6000)(context.Background(), rc)
	if f.Verdict != certify.Pass {
		t.Fatalf("oracleFixedW(6000) after ApplyControl(60%% discharge) = %+v, want Pass", f)
	}
}

// TestOracleFixedW_SignedNegativeChargePassOnConformantRegister proves the
// oracle's sign handling on a device that declares NO rate rating for either
// direction: a negative opModFixedW (charge) then falls back to the nameplate
// — derbase's own rule for the unimplemented sentinel — and must independently
// confirm against the DER's own negative WSet.
//
// It also pins that the fallback is NAMED. A finding that printed a bare
// expected watts figure would leave a reader unable to tell a nameplate
// fallback from a rate rating that happened to equal the nameplate, which is
// the ambiguity IW14-001/F5 was hiding in.
func TestOracleFixedW_SignedNegativeChargePassOnConformantRegister(t *testing.T) {
	dev, base := oracleFixture(t)
	spc := model.SignedPerCent{Value: -3000} // 30.00% charge
	if err := base.ApplyControl(model.DERControlBase{OpModFixedW: &spc}, "oracle-test"); err != nil {
		t.Fatalf("ApplyControl(opModFixedW=-3000): %v", err)
	}
	rc := oracleTestRunCtx(t, dev)
	f := oracleFixedW(-3000)(context.Background(), rc)
	if f.Verdict != certify.Pass {
		t.Fatalf("oracleFixedW(-3000) after ApplyControl(30%% charge) = %+v, want Pass", f)
	}
	if !strings.Contains(f.Observed, "WMax") || !strings.Contains(f.Observed, "implements no WChaRteMaxRtg") {
		t.Errorf("the PASS does not name the reference it used or say why: %s", f.Observed)
	}
}

// packOracleFixture is oracleFixture on the STORAGE shape: diff.AsymmetricPack,
// a 5 kW pack rated 2 kW charging and 4.5 kW discharging, mirroring the bench's
// own sim/southbound pack. Its three candidate references (charge rating,
// discharge rating, nameplate) are three different numbers, which is what makes
// the oracle's arithmetic testable rather than merely exercised.
func packOracleFixture(t *testing.T) (*diff.Device, *derbase.Base) {
	t.Helper()
	dev := diff.NewDevice(diff.AsymmetricPack())
	rdr, err := sunspec.NewReader(dev)
	if err != nil {
		t.Fatalf("sunspec.NewReader on the AsymmetricPack fixture: %v", err)
	}
	base, err := derbase.Init(rdr, "oracle-test")
	if err != nil {
		t.Fatalf("derbase.Init on the AsymmetricPack fixture: %v", err)
	}
	return dev, &base
}

// packWSet reads the pack's own WSet register back in watts, so a test can say
// what the DER actually holds instead of only what the oracle concluded.
func packWSet(t *testing.T, dev *diff.Device) float64 {
	t.Helper()
	regs, ok := dev.Model(704)
	if !ok {
		t.Fatal("the fixture serves no model 704")
	}
	return sunspec.L704.View(regs).Float("WSet")
}

// writeWSetWatts overwrites the pack's WSet register directly, leaving every
// other 704 point (WSetEna, WSetMod) exactly as the last real control left it.
// It is how a test models a WRITER that resolved the commanded percent against
// the wrong reference: same axis, same enables, one wrong number.
func writeWSetWatts(t *testing.T, dev *diff.Device, w float64) {
	t.Helper()
	regs, ok := dev.Model(704)
	if !ok {
		t.Fatal("the fixture serves no model 704")
	}
	sunspec.L704.View(regs).SetFloat("WSet", w)
	off := sunspec.L704.Offset("WSet")
	if off < 0 || off+1 >= len(regs) {
		t.Fatal("the 704 layout has no WSet point")
	}
	// WSet is Tint32: BOTH registers, or the write silently lands on the high
	// word alone and leaves the value it meant to replace in place.
	if err := dev.WriteHolding(dev.Bases[704]+uint16(off), []uint16{regs[off], regs[off+1]}); err != nil {
		t.Fatalf("write WSet=%g: %v", w, err)
	}
}

// TestOracleFixedW_PerSignReferenceOnAnAsymmetricPack is IW14-001/F5's
// end-to-end proof, driven through the PRODUCT's own writer.
//
// derbase resolves opModFixedW against the rating for the direction commanded
// (fixedWReference), so on this pack −60.00 % is −1200 W and +60.00 % is
// +2700 W. The oracle used to resolve BOTH signs against WMax and want ±3000 W,
// which had two heads: it reported this correct write as "not applied", and it
// would have PASSED a writer that resolved the percent against the nameplate.
// The test therefore asserts the register the product wrote as well as the
// verdict — a matching pair of wrong numbers would otherwise agree.
func TestOracleFixedW_PerSignReferenceOnAnAsymmetricPack(t *testing.T) {
	for _, c := range []struct {
		name       string
		hundredths int64
		wantW      float64
		wantRef    string
	}{
		{"charge: 60% of the 2000 W charge rating", -6000, -1200, "WChaRteMaxRtg"},
		{"discharge: 60% of the 4500 W discharge rating", +6000, +2700, "WDisChaRteMaxRtg"},
	} {
		t.Run(c.name, func(t *testing.T) {
			dev, base := packOracleFixture(t)
			spc := model.SignedPerCent{Value: int16(c.hundredths)}
			if err := base.ApplyControl(model.DERControlBase{OpModFixedW: &spc}, "oracle-test"); err != nil {
				t.Fatalf("ApplyControl(opModFixedW=%d): %v", c.hundredths, err)
			}
			if got := packWSet(t, dev); math.Abs(got-c.wantW) > 1 {
				t.Fatalf("the product wrote WSet=%g W, want %g W — the fixture is not exercising the "+
					"per-sign reference this test is about", got, c.wantW)
			}
			f := oracleFixedW(c.hundredths)(context.Background(), oracleTestRunCtx(t, dev))
			if f.Verdict != certify.Pass {
				t.Fatalf("oracleFixedW(%d) against a DER holding the CORRECT %g W = %+v, want Pass",
					c.hundredths, c.wantW, f)
			}
			if !strings.Contains(f.Observed, c.wantRef) {
				t.Errorf("the finding does not name the reference it resolved against (%s): %s", c.wantRef, f.Observed)
			}
			if strings.Contains(f.Observed, "3000") {
				t.Errorf("the finding still quotes the nameplate-resolved ±3000 W: %s", f.Observed)
			}
		})
	}
}

// TestOracleFixedW_CatchesTheNameplateFallbackWriter is the other head of the
// same defect: a gateway that resolves −60.00 % against the 5000 W NAMEPLATE
// writes −3000 W, and the pre-fix oracle — wanting exactly that — called it
// applied. It must now be a decided FAIL that names BOTH references, because
// "the DER holds −3000 W" is only diagnosable next to "the nameplate is 5000 W
// and 60 % of it is −3000 W".
func TestOracleFixedW_CatchesTheNameplateFallbackWriter(t *testing.T) {
	dev, base := packOracleFixture(t)
	spc := model.SignedPerCent{Value: -6000}
	if err := base.ApplyControl(model.DERControlBase{OpModFixedW: &spc}, "oracle-test"); err != nil {
		t.Fatalf("ApplyControl(opModFixedW=-6000): %v", err)
	}
	writeWSetWatts(t, dev, -3000) // the reference-confusing writer's number

	f := oracleFixedW(-6000)(context.Background(), oracleTestRunCtx(t, dev))
	t.Logf("the FAIL this row would report: %s", f.Observed)
	if f.Unavailable != "" {
		t.Fatalf("oracleFixedW against a DER holding the wrong value = Unavailable(%q); a wrong number is a "+
			"finding about the DER", f.Unavailable)
	}
	if f.Verdict != certify.Fail {
		t.Fatalf("oracleFixedW(-6000) against a DER holding -3000 W = %+v, want Fail: -3000 W is 60%% of the "+
			"NAMEPLATE, not of this device's 2000 W charge rating", f)
	}
	for _, want := range []string{"WChaRteMaxRtg", "-1200", "-3000", "WMax", "5000"} {
		if !strings.Contains(f.Observed, want) {
			t.Errorf("the FAIL does not name %q — a reference confusion is only diagnosable when the report "+
				"carries both references and both numbers: %s", want, f.Observed)
		}
	}
}

// TestOracleFixedW_NoEnabledAxisIsAFail pins IW14-003's re-classification of the
// oracles' last terminal: a DER whose own 704 image carries NO enabled setpoint
// on the commanded axis is a decided FAIL, not an Unavailable.
//
// The distinction is the whole finding. "No enabled WSet/WSetPct" is a statement
// about what the DER holds — the same class as "it holds the wrong value" — and
// it is the commonest real failure there is: the DUT never actuated the axis at
// all. Reported as Unavailable it became a criterion SKIP that could not dent a
// verdict, AND it was excluded from the settle poll's retry, so the one reading
// that most needs the propagation window was the one reading that never got it.
//
// This is also IW14-004's case (e): nothing enabled anywhere is the exact 704
// image the ece6499 bench serves BEFORE a board's write lands, so it must stay
// a decided FAIL — the ceiling rung widened what COUNTS as an actuation, not
// what counts as none — and the registers it lists must be the ones it read
// (see TestCommandSummary_PrintsTheRegistersItRead for the zero-print defect
// that line carried).
func TestOracleFixedW_NoEnabledAxisIsAFail(t *testing.T) {
	dev, _ := oracleFixture(t) // nothing applied: no enabled setpoint on any axis
	rc := oracleTestRunCtx(t, dev)
	f := oracleFixedW(6000)(context.Background(), rc)
	if f.Unavailable != "" {
		t.Fatalf("oracleFixedW against a DER with no enabled setpoint = Unavailable(%q); an empty axis is a "+
			"finding about the DER, not an unavailability of the bench", f.Unavailable)
	}
	if f.Verdict != certify.Fail {
		t.Fatalf("oracleFixedW against a DER with no enabled setpoint = %+v, want Fail", f)
	}
	t.Logf("the FAIL this row would report: %s", f.Observed)
	for _, want := range []string{"NO enabled", "WSet/WSetPct", "60.00%",
		// Both accepted actuations are named, so the FAIL says what it
		// looked for rather than only the half the pre-IW14-004 oracle knew.
		"WMaxLimPct generation ceiling",
		// And what it actually read, per point, in the register's own unit.
		"WMaxLimPct=0 % = 0 W (disabled)"} {
		if !strings.Contains(f.Observed, want) {
			t.Errorf("the FAIL does not mention %q, so a reader cannot tell what was looked for and what "+
				"was found: %q", want, f.Observed)
		}
	}
	// The same terminal on the ceiling axis, so neither oracle can drift back.
	if g := oracleMaxLimW(6000)(context.Background(), rc); g.Verdict != certify.Fail || g.Unavailable != "" {
		t.Fatalf("oracleMaxLimW against a DER with no enabled WMaxLimPct = %+v, want a decided Fail", g)
	}
}

// ── IW14-004: the solar ceiling fold ────────────────────────────────────────
//
// The five cases below are the acceptance set for oracleFixedW's second rung.
// They exist because the 2026-08-14 ece6499 bench run FAILed BASIC-013 against
// a gateway that had executed the control correctly: the board folded a
// non-negative opModFixedW into the DER's generation ceiling (its
// PICS-documented solar behaviour — lexa-gw internal/authority/csipin.go), the
// oracle knew only the battery setpoint actuation, and the row was reported as
// "the DER reports NO enabled WSet/WSetPct".

// solarCeiling puts an ENABLED WMaxLimPct at pctHundredths on the PV fixture,
// through the product's own writer, and leaves WSet/WSetPct untouched and
// disabled — the exact register shape the bench board produces when it folds a
// non-negative opModFixedW into the solar ceiling.
func solarCeiling(t *testing.T, pctHundredths uint16) *diff.Device {
	t.Helper()
	dev, base := oracleFixture(t)
	pc := model.PerCent{Value: pctHundredths}
	if err := base.ApplyControl(model.DERControlBase{OpModMaxLimW: &pc}, "oracle-test"); err != nil {
		t.Fatalf("ApplyControl(opModMaxLimW=%d): %v", pctHundredths, err)
	}
	return dev
}

// TestOracleFixedW_PassOnSolarCeilingFold is case (a): the DER executed the
// commanded 60.00% as a maximum-generation limit, and that is a PASS whose
// finding NAMES the actuation and the register it read.
//
// The naming is not decoration. A bundle that reported only "PASS" would leave
// a reader unable to tell the ceiling fold from the setpoint actuation, and
// those are different physical instructions on any device that can absorb.
func TestOracleFixedW_PassOnSolarCeilingFold(t *testing.T) {
	dev := solarCeiling(t, 6000) // 60.00% of the fixture's 60 kW WMax = 36,000 W
	f := oracleFixedW(6000)(context.Background(), oracleTestRunCtx(t, dev))
	if f.Unavailable != "" {
		t.Fatalf("oracleFixedW against a DER holding the commanded ceiling = Unavailable(%q)", f.Unavailable)
	}
	if f.Verdict != certify.Pass {
		t.Fatalf("oracleFixedW(6000) against a DER holding a 60%% GENERATION CEILING = %+v, want Pass: a "+
			"non-negative opModFixedW is a percent of maximum active power, and a PV DER's actuation of it "+
			"is a maximum-generation limit", f)
	}
	t.Logf("the PASS this row would report: %s", f.Observed)
	for _, want := range []string{"GENERATION CEILING", "WMaxLimPct", "60.00%", "36000"} {
		if !strings.Contains(f.Observed, want) {
			t.Errorf("the PASS does not name %q, so the bundle cannot say WHICH actuation was observed or "+
				"on which register: %s", want, f.Observed)
		}
	}
	if strings.Contains(f.Observed, "SETPOINT") {
		t.Errorf("the PASS reports a setpoint actuation for a ceiling register: %s", f.Observed)
	}
}

// TestOracleFixedW_FailOnCeilingAtTheWrongPercent is case (b): the ceiling rung
// has teeth. A DER holding an ENABLED ceiling at a percent that is NOT the one
// commanded is a decided FAIL naming both numbers — otherwise the fold would
// degrade into "any enabled ceiling passes", which would certify a gateway that
// wrote the wrong number just as readily as one that wrote the right one.
func TestOracleFixedW_FailOnCeilingAtTheWrongPercent(t *testing.T) {
	dev := solarCeiling(t, 4000) // the DER holds 40.00%, the row commanded 60.00%
	f := oracleFixedW(6000)(context.Background(), oracleTestRunCtx(t, dev))
	if f.Unavailable != "" {
		t.Fatalf("a wrong ceiling percent is a finding about the DER, got Unavailable(%q)", f.Unavailable)
	}
	if f.Verdict != certify.Fail {
		t.Fatalf("oracleFixedW(6000) against a DER holding a 40%% ceiling = %+v, want Fail", f)
	}
	t.Logf("the FAIL this row would report: %s", f.Observed)
	for _, want := range []string{"40.00%", "60.00%", "WMaxLimPct"} {
		if !strings.Contains(f.Observed, want) {
			t.Errorf("the FAIL does not name %q — a wrong percent is only diagnosable when the report "+
				"carries both the value read and the value commanded: %s", want, f.Observed)
		}
	}
}

// TestOracleFixedW_SetpointActuationUnchangedByTheFold is case (c): the battery
// semantics IW14-001/F5 established are untouched. A −60.00% command against
// the asymmetric pack's 2000 W CHARGE rating is −1200 W on WSet, and that still
// PASSes — reported as a SETPOINT actuation, never as a ceiling.
func TestOracleFixedW_SetpointActuationUnchangedByTheFold(t *testing.T) {
	dev, base := packOracleFixture(t)
	spc := model.SignedPerCent{Value: -6000}
	if err := base.ApplyControl(model.DERControlBase{OpModFixedW: &spc}, "oracle-test"); err != nil {
		t.Fatalf("ApplyControl(opModFixedW=-6000): %v", err)
	}
	if got := packWSet(t, dev); math.Abs(got-(-1200)) > 1 {
		t.Fatalf("the product wrote WSet=%g W, want -1200 W — the fixture is not exercising the per-sign "+
			"reference this case is about", got)
	}
	f := oracleFixedW(-6000)(context.Background(), oracleTestRunCtx(t, dev))
	if f.Verdict != certify.Pass {
		t.Fatalf("oracleFixedW(-6000) against a pack holding the correct -1200 W = %+v, want Pass — the "+
			"ceiling rung must not have disturbed the setpoint rung", f)
	}
	t.Logf("the PASS this row would report: %s", f.Observed)
	for _, want := range []string{"SETPOINT", "WSet", "WChaRteMaxRtg", "-1200"} {
		if !strings.Contains(f.Observed, want) {
			t.Errorf("the PASS does not name %q: %s", want, f.Observed)
		}
	}
	if strings.Contains(f.Observed, "CEILING") {
		t.Errorf("a setpoint actuation is being reported as a ceiling: %s", f.Observed)
	}
}

// TestOracleFixedW_CeilingIsNotAChargeActuation is case (d), and it is the one
// that keeps the fold honest: a NEGATIVE opModFixedW commands the DER to
// ABSORB, and a maximum-GENERATION limit says nothing whatever about charging.
// A DER holding an enabled 60% ceiling and no charge setpoint has NOT executed
// a −60.00% command, and accepting it would let a gateway that silently dropped
// the charge half of the axis pass on a register it never wrote.
func TestOracleFixedW_CeilingIsNotAChargeActuation(t *testing.T) {
	dev := solarCeiling(t, 6000) // an enabled 60% GENERATION ceiling, nothing else
	f := oracleFixedW(-6000)(context.Background(), oracleTestRunCtx(t, dev))
	if f.Unavailable != "" {
		t.Fatalf("a missing charge actuation is a finding about the DER, got Unavailable(%q)", f.Unavailable)
	}
	if f.Verdict != certify.Fail {
		t.Fatalf("oracleFixedW(-6000) against a DER whose only enabled point is a 60%% GENERATION ceiling "+
			"= %+v, want Fail: a ceiling cannot express a charge setpoint", f)
	}
	t.Logf("the FAIL this row would report: %s", f.Observed)
	for _, want := range []string{"NO enabled", "WSet/WSetPct", "NOT considered an acceptable actuation"} {
		if !strings.Contains(f.Observed, want) {
			t.Errorf("the FAIL does not say %q, so a reader cannot tell why the enabled ceiling was "+
				"refused: %s", want, f.Observed)
		}
	}
	// And the refusal must not be a silent one: the reading it declined to
	// accept has to appear in the register listing.
	if !strings.Contains(f.Observed, "WMaxLimPct=60 %") {
		t.Errorf("the FAIL does not list the enabled ceiling it read: %s", f.Observed)
	}
}

// TestCommandSummary_PrintsTheRegistersItRead is the direct regression guard on
// the zero-printing defect, stated as the bundle would have shown it: a DER
// holding an ENABLED 60% ceiling must be REPORTED as holding 60%.
//
// The pre-fix listing read "WMaxLimPct=0 (enabled)" on hardware whose ceiling
// was 60.00% and whose measured output had converged on the 4800 W that percent
// implies (runs/verify-ece6499-20260814T063817Z). That line invented a second
// defect for every reader of the bundle.
func TestCommandSummary_PrintsTheRegistersItRead(t *testing.T) {
	dev := solarCeiling(t, 6000)
	uv, err := oracleUnitView(context.Background(), oracleTestRunCtx(t, dev), oracleSimName)
	if err != nil {
		t.Fatalf("read the fixture's own register image: %v", err)
	}
	got := commandSummary(uv)
	if !strings.Contains(got, "WMaxLimPct=60 % = 36000 W (enabled)") {
		t.Errorf("commandSummary = %q, want it to report the enabled 60%% ceiling the DER actually holds", got)
	}
	if !strings.Contains(got, "WSet=0 W (disabled)") {
		t.Errorf("commandSummary = %q, want the disabled points reported in their own registers' units "+
			"too, so a reader can see the whole axis and not just the one point that was enabled", got)
	}
	if strings.Contains(got, "WMaxLimPct=0 ") {
		t.Fatalf("commandSummary still prints the zero-value Physical for a register holding 60%%: %q", got)
	}
}

// TestOracleFixedW_LadderSeesTheCeilingActuation proves the fold reaches the
// part of the row that decides what to COMMAND, not only the part that judges.
//
// oracleBinding.alternate asks this row's own Judge whether the DER already
// holds a candidate value (basic.go). With the ceiling actuation accepted, a
// DER already parked at the commanded 60% — exactly what BASIC-010's own row
// leaves behind on the shared bench inverter — is now correctly seen as
// "already holds it", so BASIC-013 departs to a ladder alternate the DER
// provably does not hold and its post-read has somewhere to MOVE to. Without
// this, the pre-read would have said "does not hold it", the row would have
// commanded 60% into a register already at 60%, and the transition binding
// would have been satisfied by a DER that never moved.
func TestOracleFixedW_LadderSeesTheCeilingActuation(t *testing.T) {
	dev := solarCeiling(t, 6000)
	rc := oracleTestRunCtx(t, dev)
	b := &oracleBinding{Commanded: 6000, Ladder: oracleValueLadder, Judge: oracleFixedW}

	if pre := b.Judge(b.Commanded)(context.Background(), rc); pre.Verdict != certify.Pass {
		t.Fatalf("the pre-read of a DER already holding the commanded 60%% ceiling = %+v, want Pass — "+
			"Setup would otherwise never know it has to depart from the catalog's value", pre)
	}
	alt, altPre, ok := b.alternate(context.Background(), rc, b.Commanded)
	if !ok {
		t.Fatal("no ladder alternate was available on a DER holding only a 60% ceiling")
	}
	if alt != 4000 {
		t.Errorf("the ladder chose %d, want the first entry the DER provably does not hold (4000)", alt)
	}
	if altPre.Verdict != certify.Fail {
		t.Errorf("the alternate's baseline = %+v, want the decided Fail that PROVES the DER does not hold "+
			"it", altPre)
	}
}

// TestOracleFixedW_FailOnMismatchedCommand is oracleMaxLimW's discrimination
// proof, mirrored for the setpoint axis.
func TestOracleFixedW_FailOnMismatchedCommand(t *testing.T) {
	dev, base := oracleFixture(t)
	spc := model.SignedPerCent{Value: 6000} // device actually holds 60%
	if err := base.ApplyControl(model.DERControlBase{OpModFixedW: &spc}, "oracle-test"); err != nil {
		t.Fatalf("ApplyControl(opModFixedW=6000): %v", err)
	}
	rc := oracleTestRunCtx(t, dev)
	f := oracleFixedW(2000)(context.Background(), rc) // row claims 20% was commanded
	if f.Verdict != certify.Fail {
		t.Fatalf("oracleFixedW(2000) against a device holding 60%% = %+v, want Fail", f)
	}
}
