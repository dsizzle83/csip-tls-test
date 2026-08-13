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
	"net/http"
	"net/http/httptest"
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

// TestOracleFixedW_PassOnConformantRegister mirrors TestOracleMaxLimW's proof
// for the signed, nameplate-resolved axis: opModFixedW=6000 (60%) on a 60 kW
// device resolves to 36,000 W (Phase 1: symmetric WMax reference), and the
// independent oracle confirms it from the DER's own WSet register — computed
// via internal/invariant, never lexa-proto/csipmodel or derbase.
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
// oracle's sign handling: a negative opModFixedW (charge) resolves through
// the SAME symmetric-WMax reference (Phase 1) and must independently confirm
// against the DER's own negative WSet.
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
