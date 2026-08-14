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
	for _, want := range []string{"NO enabled", "WSet/WSetPct", "60.00%"} {
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
