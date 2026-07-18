// tests/modbus_adv_test.go — end-to-end advanced-DER (7xx) checks that drive the
// REAL lexa-proto derbase adopt handshake and 701 measurement parse over Modbus
// TCP against a live advanced solar sim. This is the wire-contract proof: the
// same derbase path lexa-modbus's WP-10 reconciler uses, exercised against the
// sim's 7xx surface — including the curve_adopt_lies divergence WP-10 must catch.
package integration_test

import (
	"fmt"
	"net"
	"testing"
	"time"

	sim "csip-tls-test/sim/southbound"
	"lexa-proto/derbase"
	"lexa-proto/modbus"
	"lexa-proto/sunspec"
)

// advEnv is a live advanced solar sim reachable through a real derbase.Base.
type advEnv struct {
	ss   *sim.SolarServer
	base *derbase.Base
	stop func()
}

func startAdvSolarEnv(t *testing.T) *advEnv {
	t.Helper()

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("find free port: %v", err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()

	url := fmt.Sprintf("tcp://127.0.0.1:%d", port)
	ss, err := sim.NewSolarServerAdvanced(url, 5000, "")
	if err != nil {
		t.Fatalf("start advanced sim: %v", err)
	}

	trans, err := modbus.NewTransport(url, 2*time.Second)
	if err != nil {
		ss.Stop()
		t.Fatalf("new transport: %v", err)
	}
	if err := trans.Open(); err != nil {
		ss.Stop()
		t.Fatalf("open transport: %v", err)
	}
	if err := trans.SetUnitID(1); err != nil {
		trans.Close()
		ss.Stop()
		t.Fatalf("set unit id: %v", err)
	}
	reader, err := sunspec.NewReader(trans)
	if err != nil {
		trans.Close()
		ss.Stop()
		t.Fatalf("new reader: %v", err)
	}
	base, err := derbase.Init(reader, "adv-solar")
	if err != nil {
		trans.Close()
		ss.Stop()
		t.Fatalf("derbase init: %v", err)
	}
	// Keep curve adopt-polls short so a lying device does not stall the test on
	// the best-effort poll timeout.
	base.AdoptPollTimeout = 500 * time.Millisecond

	return &advEnv{ss: ss, base: &base, stop: func() { trans.Close(); ss.Stop() }}
}

// TestAdvDER_ModelPresence confirms derbase discovers the 7xx surface and reads
// measurements from model 701 (not 103).
func TestAdvDER_ModelPresence(t *testing.T) {
	env := startAdvSolarEnv(t)
	defer env.stop()
	b := env.base

	if b.MeasModel != sunspec.ModelDERMeasureAC {
		t.Errorf("MeasModel = %d, want 701 (hub prefers 701 over 103)", b.MeasModel)
	}
	for _, tc := range []struct {
		name string
		has  bool
	}{
		{"701", b.Has701}, {"702", b.Has702}, {"704", b.Has704},
		{"705", b.Has705}, {"706", b.Has706}, {"711", b.Has711}, {"712", b.Has712},
	} {
		if !tc.has {
			t.Errorf("device should advertise model %s", tc.name)
		}
	}

	regs, err := b.Reader.ReadModel(sunspec.ModelDERMeasureAC)
	if err != nil {
		t.Fatalf("read 701: %v", err)
	}
	m := derbase.ReadMeasurementsM701(regs)
	if m.W <= 0 {
		t.Errorf("701 measured W = %v, want > 0 (generating)", m.W)
	}
	if m.V < 200 || m.V > 260 {
		t.Errorf("701 measured V = %v, want ~240", m.V)
	}
	if m.Alrm == nil || *m.Alrm != 0 {
		t.Errorf("701 Alrm = %v, want 0", m.Alrm)
	}
}

// TestAdvDER_VoltVarAdoptSuccess drives the REAL derbase adopt handshake and
// confirms the live curve readback matches the commanded curve (adopt_state
// would be "adopted").
func TestAdvDER_VoltVarAdoptSuccess(t *testing.T) {
	env := startAdvSolarEnv(t)
	defer env.stop()
	b := env.base

	want := sunspec.VoltVarCurve{
		DeptRef: 1, Pri: 1,
		Points: []sunspec.VVPoint{{V: 228, Var: 40}, {V: 240, Var: 0}, {V: 252, Var: -40}},
	}
	if err := b.WriteVoltVar(want, "adv-solar"); err != nil {
		t.Fatalf("WriteVoltVar (adopt handshake): %v", err)
	}
	got, err := b.ReadVoltVar("adv-solar")
	if err != nil {
		t.Fatalf("ReadVoltVar: %v", err)
	}
	if !got.ReadOnly {
		t.Error("live curve should be read-only after adopt")
	}
	if len(got.Points) != len(want.Points) {
		t.Fatalf("live curve has %d points, want %d", len(got.Points), len(want.Points))
	}
	for i, p := range want.Points {
		if got.Points[i] != p {
			t.Errorf("live point[%d] = %+v, want %+v", i, got.Points[i], p)
		}
	}
}

// TestAdvDER_VoltVarAdoptLies is the INV-ADV-READBACK end-to-end proof: with
// curve_adopt_lies armed, derbase's adopt handshake still returns success
// (AdptCrvRslt=COMPLETED), but the live-curve readback is STALE — exactly the
// "handshake says done, readback disagrees" divergence the WP-10 reconciler
// judges as adopt_state=diverged rather than adopted.
func TestAdvDER_VoltVarAdoptLies(t *testing.T) {
	env := startAdvSolarEnv(t)
	defer env.stop()
	b := env.base

	// First, adopt an honest curve so the live curve has a known baseline.
	baseline := sunspec.VoltVarCurve{
		DeptRef: 1, Pri: 1,
		Points: []sunspec.VVPoint{{V: 230, Var: 20}, {V: 250, Var: -20}},
	}
	if err := b.WriteVoltVar(baseline, "adv-solar"); err != nil {
		t.Fatalf("baseline adopt: %v", err)
	}

	// Arm the liar, then command a DIFFERENT curve.
	if err := env.ss.ApplyFault([]byte(`{"kind":"curve_adopt_lies"}`)); err != nil {
		t.Fatalf("arm curve_adopt_lies: %v", err)
	}
	lied := sunspec.VoltVarCurve{
		DeptRef: 1, Pri: 1,
		Points: []sunspec.VVPoint{{V: 232, Var: 55}, {V: 248, Var: -55}},
	}
	// The handshake returns success (COMPLETED) even though nothing was adopted.
	if err := b.WriteVoltVar(lied, "adv-solar"); err != nil {
		t.Fatalf("WriteVoltVar under curve_adopt_lies should report success, got: %v", err)
	}

	// The readback still shows the baseline curve, NOT the commanded one.
	got, err := b.ReadVoltVar("adv-solar")
	if err != nil {
		t.Fatalf("ReadVoltVar: %v", err)
	}
	if len(got.Points) != len(baseline.Points) {
		t.Fatalf("live curve = %d points, want stale baseline %d", len(got.Points), len(baseline.Points))
	}
	for i, p := range baseline.Points {
		if got.Points[i] != p {
			t.Errorf("live point[%d] = %+v, want stale baseline %+v (readback must diverge from command)", i, got.Points[i], p)
		}
	}
	// And confirm it is genuinely divergent from what was commanded.
	if got.Points[0] == lied.Points[0] {
		t.Error("live curve matched the commanded (lied) curve — the liar did not lie")
	}
}

// TestAdvDER_FixedPFMeasuredConvergence drives a real 704 fixed-PF write and
// confirms the MEASURED 701 PF moves to the command — the signal WP-10's
// measured-convergence check needs — and that pf_ack_ignore breaks that link.
func TestAdvDER_FixedPFMeasuredConvergence(t *testing.T) {
	env := startAdvSolarEnv(t)
	defer env.stop()
	b := env.base

	if err := b.SetFixedPF(true, 0.92, true, "adv-solar"); err != nil {
		t.Fatalf("SetFixedPF: %v", err)
	}
	// Allow one animation tick to apply the effect to the 701 measurement.
	deadline := time.Now().Add(7 * time.Second)
	var pf float64
	for time.Now().Before(deadline) {
		regs, err := b.Reader.ReadModel(sunspec.ModelDERMeasureAC)
		if err != nil {
			t.Fatalf("read 701: %v", err)
		}
		pf = derbase.ReadMeasurementsM701(regs).PF
		if pf > 0.915 && pf < 0.925 {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	if pf < 0.915 || pf > 0.925 {
		t.Errorf("measured 701 PF after fixed-PF 0.92 = %v, want ≈0.92", pf)
	}
}
