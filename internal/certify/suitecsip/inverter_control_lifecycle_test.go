package suitecsip

// inverter_control_lifecycle_test.go pins the IW13-005 timing fix: the
// independent southbound oracle (controlMode.Oracle, wired to BASIC-010 and
// BASIC-013 by register.go) must fire in inverterControlSpec's PostWait, not
// its Setup.
//
// oracle_test.go already proves the oracle CLOSURES themselves are correct —
// oracleMaxLimW/oracleFixedW read the right register and compare it right,
// hermetically, against a real derbase.ApplyControl write. What that file
// cannot show is the bug this one guards against: even a perfectly correct
// oracle closure produces a false SKIP if it is invoked before the DUT could
// possibly have applied the control it was just asked to fetch. That is a
// property of WHEN inverterControlSpec calls m.Oracle relative to the
// check.go run() phases (Setup -> wait for the DUT's poll cycle -> PostWait),
// not of the oracle's own arithmetic — so it has to be proven at the
// spec/Setup/PostWait level, against a Driver wired to a real gridsim, the
// same way nonce_test.go's gridsimDriver drives coreResponsesSpec/
// coreSupersedingSpec directly.
//
// The DUT itself is not in this test's loop (there is no live DUT on this
// bench's CI), so "the DUT fetched and applied the control" is stood in for
// by driving the SAME real derbase.ApplyControl write oracle_test.go uses,
// timed by hand between calling Setup and calling PostWait — which is exactly
// the timing check.go's own wait is meant to buy the real DUT.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"csip-tls-test/internal/certify"
	"csip-tls-test/internal/diff"
	"csip-tls-test/sim/gridsim"
	model "lexa-proto/csipmodel"
)

// inverterControlLifecycleRunCtx wires ONE *certify.RunCtx to two in-process
// fixtures: a real gridsim admin API (so Setup's m.Publish — a live
// d.PostControl round trip — has something to publish to, exactly as
// gridsimDriver in nonce_test.go sets up for coreResponsesSpec), and a
// simapi-shaped register server reading dev's live snapshot (the same shape
// oracle_test.go's oracleTestRunCtx builds, so PostWait's m.Oracle(ctx, d.rc)
// has a real DER register image to read). Both live behind the SAME RunCtx
// because inverterControlSpec's PostWait closure reads d.rc, the identical
// object Setup's d.PostControl used.
func inverterControlLifecycleRunCtx(t *testing.T, dev *diff.Device) (*certify.RunCtx, *Driver) {
	t.Helper()

	gs := gridsim.NewServer(benchLFDI)
	gsSrv := httptest.NewServer(gs.AdminHandler())
	t.Cleanup(gsSrv.Close)

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
	oracleSrv := httptest.NewServer(mux)
	t.Cleanup(oracleSrv.Close)

	rc := &certify.RunCtx{
		Case:    &certify.Case{UID: "csip-conf-v1.3::BASIC-010", ID: "BASIC-010"},
		GridSim: certify.NewAdminClient(gsSrv.URL, http.DefaultClient),
		Targets: certify.Targets{GridSimAdmin: gsSrv.URL},
		Sims: map[string]*certify.SimClient{
			oracleSimName: certify.NewSimClient(oracleSimName, oracleSrv.URL, http.DefaultClient),
		},
	}
	return rc, NewDriver(rc)
}

// TestInverterControlSpec_OracleFiresPostWaitNotSetup is the lifecycle proof
// the review asked for: it drives inverterControlSpec's Setup and PostWait
// directly, in that order, against a register view that is EMPTY at Setup
// time and correct only afterward — proving the fix flips a real Skip into a
// real Pass, not just that Setup and PostWait are wired to different funcs.
func TestInverterControlSpec_OracleFiresPostWaitNotSetup(t *testing.T) {
	dev, base := oracleFixture(t) // Bench702 fixture; no control applied yet
	rc, d := inverterControlLifecycleRunCtx(t, dev)
	ctx := context.Background()

	m := withOracle(scalarMode("opModMaxLimW", func(r *ControlRequest) {
		r.MaxLimW = ptr(int64(6000))
	}), oracleMaxLimW(6000))
	subject := "a maximum active power limit"
	s := inverterControlSpec(m, subject, "CERT-LIFECYCLE-BASIC010")

	// --- Setup: publishes the control, must NOT touch the oracle at all ---
	params := map[string]string{}
	if err := s.Setup(ctx, d, params); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	if params["mrid"] != "CERT-LIFECYCLE-BASIC010" {
		t.Fatalf("Setup did not stash mrid: params = %v", params)
	}
	if v, ok := params[oracleVerdictParam]; ok {
		t.Fatalf("Setup populated %s=%q — the oracle fired during Setup, before the DUT could have "+
			"applied anything (the exact IW13-005 bug this test guards against)", oracleVerdictParam, v)
	}
	if v, ok := params[oracleUnavailableParam]; ok {
		t.Fatalf("Setup populated %s=%q — the oracle must not fire during Setup at all, unavailable "+
			"or otherwise", oracleUnavailableParam, v)
	}

	// Prove what firing the SAME oracle closure at Setup-time actually would
	// have found: Unavailable, because the DER's own register is still
	// empty. Run the production criterion over that exact finding and
	// confirm it degrades to the honest Skip shape (no Wire evaluator) —
	// this is what "operationally identical to the old hard SKIP" meant
	// before the fix.
	early := m.Oracle(ctx, rc)
	if early.Unavailable == "" {
		t.Fatalf("the oracle evaluated at Setup-time (before the DUT could apply the control) = %+v, "+
			"want Unavailable — the DER's own register genuinely holds nothing yet", early)
	}
	earlyObs := &Observation{Params: map[string]string{oracleUnavailableParam: early.Unavailable}}
	earlyCrit := critDEREffectViaSouthboundOracle(subject, earlyObs)
	if earlyCrit.Skip == "" {
		t.Fatalf("critDEREffectViaSouthboundOracle at Setup-time = %+v, want a non-empty Skip "+
			"(the pre-fix degrade-to-SKIP shape)", earlyCrit)
	}
	if earlyCrit.Wire != nil {
		t.Fatal("a Skip-shaped criterion must carry no Wire evaluator — mint() would otherwise try to " +
			"grade it against the transcript instead of honoring the Skip")
	}

	// --- Simulate the DUT's poll cycle: it fetched the control and applied
	// it southbound. Drive the SAME real derbase write path oracle_test.go
	// uses, so the register the oracle reads next is genuinely conformant,
	// not a hand-set field. ---
	pc := model.PerCent{Value: 6000} // 60.00%, matching m's MaxLimW=6000
	if err := base.ApplyControl(model.DERControlBase{OpModMaxLimW: &pc}, "lifecycle-test"); err != nil {
		t.Fatalf("ApplyControl(opModMaxLimW=6000): %v", err)
	}

	// --- PostWait: this is where the fix says the oracle must fire ---
	if err := s.PostWait(ctx, d, params); err != nil {
		t.Fatalf("PostWait: %v", err)
	}
	if params[oracleVerdictParam] != string(certify.Pass) {
		t.Fatalf("after PostWait, %s = %q, want %q — PostWait must read the DER's registers AFTER the "+
			"simulated poll cycle, not before", oracleVerdictParam, params[oracleVerdictParam], certify.Pass)
	}
	if _, unavailable := params[oracleUnavailableParam]; unavailable {
		t.Fatalf("after PostWait, %s is still set (%q) even though the register now genuinely holds the "+
			"commanded value", oracleUnavailableParam, params[oracleUnavailableParam])
	}

	// Finally, the production criterion itself — the thing a bundle reader
	// actually sees — must resolve to a real Pass off PostWait's params, not
	// the Skip it produced one paragraph up.
	postObs := &Observation{Params: params}
	postCrit := critDEREffectViaSouthboundOracle(subject, postObs)
	f := wantVerdict(t, "DER effect via oracle (post-wait)", postCrit, nil, certify.Pass)
	t.Logf("post-wait oracle criterion: %s", f.Observed)
}

// TestInverterControlSpec_NonOracleRowUnaffected is the behavior-preservation
// check for the far more common shape (every BASIC-004..015 row except
// BASIC-010/013): no Oracle at all, so this fix must not add a PostWait hook
// that did not exist before, and Setup's shape (publish, stash mrid, nothing
// else) is unchanged.
func TestInverterControlSpec_NonOracleRowUnaffected(t *testing.T) {
	dev, _ := oracleFixture(t)
	_, d := inverterControlLifecycleRunCtx(t, dev)
	ctx := context.Background()

	m := scalarMode("opModFixedPFInjectW", func(r *ControlRequest) {
		r.FixedPFInjectW = ptr(int64(95))
	})
	s := inverterControlSpec(m, "a fixed power factor while injecting", "CERT-LIFECYCLE-BASIC008")

	if s.PostWait != nil {
		t.Fatal("a controlMode with no Oracle must not get a PostWait hook at all")
	}
	params := map[string]string{}
	if err := s.Setup(ctx, d, params); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	if params["mrid"] != "CERT-LIFECYCLE-BASIC008" {
		t.Fatalf("Setup did not stash mrid: params = %v", params)
	}
	if len(params) != 1 {
		t.Fatalf("a non-oracle row's Setup should leave params holding only mrid, got %v", params)
	}
}

// TestInverterControlSpec_UnreachableRowUnaffected pins the Publish==nil shape
// (the six ride-through/ramp-rate rows): no Setup, no PostWait, no Cleanup —
// unchanged by this fix, which only touches the m.Publish != nil branch.
func TestInverterControlSpec_UnreachableRowUnaffected(t *testing.T) {
	m := unreachableMode("opModLVRTMustTrip", "no lever on this bench")
	s := inverterControlSpec(m, "the low/high voltage ride-through settings", "CERT-LIFECYCLE-BASIC004")
	if s.Setup != nil {
		t.Fatal("an unreachable mode (Publish == nil) must not get a Setup hook")
	}
	if s.PostWait != nil {
		t.Fatal("an unreachable mode (Publish == nil) must not get a PostWait hook")
	}
	if s.Cleanup != nil {
		t.Fatal("an unreachable mode (Publish == nil) must not get a Cleanup hook")
	}
	if s.RequiresGridSim {
		t.Fatal("an unreachable mode must not claim RequiresGridSim — it has nothing to publish")
	}
}
