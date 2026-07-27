package invariant

// peer_test.go is the end-to-end half of the teeth: a REAL device on a real
// socket, read over real Modbus/TCP by the real source, driven into a real
// nameplate violation.
//
// The injected-state tests in teeth_test.go prove the checkers are right. They
// cannot prove the path into them is: a source that decoded the wrong register,
// scanned the wrong block, or dropped a scale factor would make every one of
// those tests pass and every live run useless. So this file stands up
// sim/southbound's advanced solar inverter — the same simulator the bench polls
// — reads it through [ModbusDER] exactly as a campaign would, and then reaches
// into its register bank to write a value no conformant head-end would ever
// command. If I1 fires on the injected state and not on this one, the decode
// path is broken and this test says so.
//
// The device is bound on 127.0.0.1 with an ephemeral port, so the test needs no
// bench and touches nothing shared.

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	sim "csip-tls-test/sim/southbound"
	"lexa-proto/sunspec"
)

func TestI1_AgainstARealModbusPeer(t *testing.T) {
	if testing.Short() {
		t.Skip("binds a loopback TCP port; skipped under -short")
	}
	const (
		wMaxW  = 60_000.0
		devUnt = 1
	)
	url := fmt.Sprintf("tcp://127.0.0.1:%d", freeLoopbackPort(t))
	srv, err := sim.NewSolarServerAdvanced(url, wMaxW, "SN-INVARIANT-TEETH")
	if err != nil {
		t.Fatalf("start the device sim: %v", err)
	}
	defer srv.Stop()
	// Freeze the animation so the register world does not move under the test.
	srv.Pause()

	src := NewModbusDER("inv-plain", url, devUnt, 3*time.Second)
	defer src.Close()
	w := NewWorld(Sources{DERs: map[string]DERSource{"inv-plain": src}}, nil, nil, DefaultParams())
	inv := NewI1(DefaultParams())

	// ── 1. The unmodified device must pass ────────────────────────────────
	obs := observeOrFail(t, w)
	der := obs.DERs["inv-plain"]
	if !der.Reachable {
		t.Fatalf("the device sim was not readable over Modbus: %s", der.Err)
	}
	if !der.Unit.Has(702) || !der.Unit.Has(704) {
		t.Fatalf("the device sim did not serve 702/704; models = %v (the source's decode path is broken, "+
			"not the device)", der.Unit.Models)
	}
	np := der.Unit.Nameplate(der.Source)
	if !np.Present || !np.WMax.Known() {
		t.Fatalf("the nameplate did not decode from the live device: %+v", np)
	}
	t.Logf("live nameplate: WMax=%s VarMaxInj=%s VAMax=%s", np.WMax, np.VarMaxInj, np.VAMax)

	res, err := inv.Check(context.Background(), w)
	if err != nil {
		t.Fatalf("I1 error: %v", err)
	}
	if res.Verdict == Fail {
		t.Fatalf("I1 failed an unmodified device sim — the fixture, not the device, is wrong: %s", res.Reason)
	}
	if res.Checked == 0 {
		t.Fatal("I1 asserted nothing against a live device that serves 702 and 704 — the decode path is broken")
	}

	// ── 2. Drive the device into a genuine BR-01 state ────────────────────
	// The writes go straight into the register bank, which is the state a
	// mis-scaled gateway write would leave on the wire.
	base704, ok704 := der.Unit.Base[704]
	base702, ok702 := der.Unit.Base[702]
	if !ok704 || !ok702 {
		t.Fatal("the source did not record the 702/704 block base addresses, so a violation cannot be injected")
	}
	set := func(layout *sunspec.Layout, base uint16, point string, val uint16) {
		srv.Regs.Set(base+uint16(layout.Offset(point)), val)
	}

	// Commission the device as a reactive-poor unit: 2 kvar of injection
	// against its 60 kW active rating. That is an ordinary product — a PV
	// inverter with a narrow reactive envelope — and it is the configuration in
	// which a percentage taken against the wrong base stops being merely wrong
	// and becomes a 24× overcommand.
	varSF, okVarSF := sunspec.L702.View(der.Unit.Regs[702]).SF("Var_SF")
	if !okVarSF {
		t.Fatal("the live device published no Var scale factor")
	}
	varRaw := uint16(2_000 / pow10(int(varSF)))
	set(sunspec.L702, base702, "VarMaxInjRtg", varRaw)
	set(sunspec.L702, base702, "VarMaxInj", varRaw)

	// Now command 80% — of WMax, as the device's own VarSetMod will declare.
	pctSF, okPctSF := sunspec.L704.View(der.Unit.Regs[704]).SF("VarSetPct_SF")
	if !okPctSF {
		t.Fatal("the live device published no VarSetPct scale factor")
	}
	set(sunspec.L704, base704, "VarSetEna", 1)
	set(sunspec.L704, base704, "VarSetMod", uint16(sunspec.M704_VarSetMod_WMaxPct))
	set(sunspec.L704, base704, "VarSetPct", uint16(int16(80/pow10(int(pctSF)))))

	obs2 := observeOrFail(t, w)
	der2 := obs2.DERs["inv-plain"]
	cmd, found := commandOf(der2.Unit.Commands(der2.Source), "VarSetPct")
	if !found || !cmd.Enabled {
		t.Fatalf("the injected setpoint did not read back as enabled (%+v) — the write did not land where "+
			"the decoder looks", cmd)
	}

	res2, err := inv.Check(context.Background(), w)
	if err != nil {
		t.Fatalf("I1 error: %v", err)
	}
	if res2.Verdict != Fail {
		t.Fatalf("I1 = %s against a live device commanded 80%% of a %s base as reactive power, against a %s "+
			"reactive rating\nreason: %s", res2.Verdict, np.WMax, np.VarMaxInj, res2.Reason)
	}
	t.Logf("live finding: %s", res2.Reason)
}

// TestModbusDER_RecoversFromADeadPeer covers the source contract that matters
// most during a chaos campaign: a device that goes away must be reported
// unreachable, and must be observed correctly again when it returns rather than
// staying dead because the transport was cached.
func TestModbusDER_RecoversFromADeadPeer(t *testing.T) {
	if testing.Short() {
		t.Skip("binds a loopback TCP port; skipped under -short")
	}
	port := freeLoopbackPort(t)
	url := fmt.Sprintf("tcp://127.0.0.1:%d", port)
	srv, err := sim.NewSolarServerAdvanced(url, 50_000, "SN-RECOVER")
	if err != nil {
		t.Fatalf("start the device sim: %v", err)
	}
	srv.Pause()

	src := NewModbusDER("inv", url, 1, time.Second)
	defer src.Close()

	if v, err := src.Observe(context.Background()); err != nil || !v.Reachable {
		srv.Stop()
		t.Fatalf("first observation failed: %v / %+v", err, v)
	}
	srv.Stop()
	if v, err := src.Observe(context.Background()); err == nil && v.Reachable {
		t.Fatal("the source reported a stopped device as reachable")
	}

	srv2, err := sim.NewSolarServerAdvanced(url, 50_000, "SN-RECOVER")
	if err != nil {
		t.Fatalf("restart the device sim: %v", err)
	}
	defer srv2.Stop()
	srv2.Pause()

	var last error
	for i := 0; i < 20; i++ {
		v, err := src.Observe(context.Background())
		if err == nil && v.Reachable {
			return
		}
		last = err
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("the source never re-observed the returned device (last error: %v) — a cached transport is "+
		"reporting a live device dead", last)
}

func observeOrFail(t *testing.T, w *World) *Observation {
	t.Helper()
	obs, err := w.Observe(context.Background())
	if err != nil {
		t.Fatalf("observe: %v", err)
	}
	return obs
}

func freeLoopbackPort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("find a free port: %v", err)
	}
	p := l.Addr().(*net.TCPAddr).Port
	_ = l.Close()
	return p
}

func pow10(n int) float64 {
	out := 1.0
	for ; n > 0; n-- {
		out *= 10
	}
	for ; n < 0; n++ {
		out /= 10
	}
	return out
}
