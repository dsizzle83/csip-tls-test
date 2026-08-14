package sim

// battery_pack_test.go — unit tests for the BENCH BATTERY PACK
// (battery_pack.go), in the sim idiom: a real register bank driven through the
// real Modbus handler and the real per-tick step function, with no live
// listener (mirrors battery_adv_test.go's newAdvBattery and solar_test.go's
// direct solarStep driving).
//
// The rows here are the ones lexa-gw's BENCH-000 (e)-(h)/(j) name, expressed
// against the simulator rather than the gateway: a setpoint that reaches
// physical effect in BOTH directions, a pack that is measurably not yet
// converged while it ramps, a cease that collapses power and a reconnect that
// restores it, rate ratings that bound what the pack will actually do, and the
// two false-Applied fault shapes (an ACKed setpoint that never latched, an
// ACKed cease that never opened the contactor).

import (
	"encoding/json"
	"math"
	"testing"

	modbuslib "github.com/simonvetter/modbus"
	"lexa-proto/sunspec"
)

// ── Rig ──────────────────────────────────────────────────────────────────────

const (
	testPackKwh  = 10.0
	testPackWmax = 5000.0
	// packWTol is the round-trip tolerance for a watt value that has been
	// through the 123 signed-percent mirror (percent at SF −2 ⇒ 0.01 % of
	// nameplate = 0.5 W here) and the M103 integer-watt register. Anything
	// larger than this is a real disagreement, not encoding.
	packWTol = 2.0
)

// newTestPack builds a pack register bank + BatteryServer wired exactly as the
// constructor wires it, but WITHOUT a live Modbus listener.
func newTestPack(t *testing.T, shape BatteryPackShape) *BatteryServer {
	t.Helper()
	r := &RegisterMap{regs: make(map[uint16]uint16)}
	bases, pk, end := populateBatteryPack(r, testPackKwh, testPackWmax, shape)
	bs := &BatteryServer{
		Server: &Server{Regs: r}, bases: bases, wmaxW: testPackWmax, wmaxKwh: testPackKwh,
		pack: pk, regEnd: end, advanced: pk.has704, adv: pk.adv,
	}
	bs.faults.label = "battery"
	bs.faults.configureGate(bases.M123Base + sunspec.M123_WMaxLimPct_Ena)
	bs.faults.configureScale(bases.M103Base + sunspec.M103_W_SF)
	r.OnWrite = bs.packOnWrite
	r.OnWriteAttempt = bs.interceptWrite
	r.OnRead = bs.faults.transportRead
	bs.installBatteryLies()
	return bs
}

// packTicks drives n animation ticks through the real per-tick step, at a
// fixed simulation time so the environmental wander is not a variable.
func packTicks(bs *BatteryServer, st *packAnimState, n int) {
	for i := 0; i < n; i++ {
		batteryPackStep(bs.Regs, bs.bases, bs.pack, bs.wmaxW, bs.wmaxKwh, st,
			&bs.pendingSoC, &bs.faults, 0, packTickSeconds)
	}
}

func newPackAnim() *packAnimState { return &packAnimState{socPct: 55.0} }

// packMeasuredW reads the pack's measured active power off M103.
func packMeasuredW(bs *BatteryServer) float64 {
	return sunspec.ApplyScaleSigned(bs.Regs.Get(bs.bases.M103Base+sunspec.M103_W),
		int16(bs.Regs.Get(bs.bases.M103Base+sunspec.M103_W_SF)))
}

// mbWrite performs a Modbus write through the real handler, so every hook the
// wire path has (OnWriteAttempt, the lying layer, OnWrite) fires.
func mbWrite(t *testing.T, bs *BatteryServer, addr uint16, vals ...uint16) {
	t.Helper()
	if _, err := bs.Regs.HandleHoldingRegisters(&modbuslib.HoldingRegistersRequest{
		UnitId: 1, Addr: addr, Quantity: uint16(len(vals)), IsWrite: true, Args: vals,
	}); err != nil {
		t.Fatalf("modbus write at %d: %v", addr, err)
	}
}

// mbRead performs a Modbus read through the real handler, so the read-path
// lies are applied exactly as a client would see them.
func mbRead(t *testing.T, bs *BatteryServer, addr uint16, n uint16) []uint16 {
	t.Helper()
	got, err := bs.Regs.HandleHoldingRegisters(&modbuslib.HoldingRegistersRequest{
		UnitId: 1, Addr: addr, Quantity: n,
	})
	if err != nil {
		t.Fatalf("modbus read at %d: %v", addr, err)
	}
	return got
}

// writeWSet writes a watts setpoint into 704 the way derbase does — the whole
// block, read-modify-written, with WSetMod=Watts and WSetEna set.
func writeWSet(t *testing.T, bs *BatteryServer, w float64) {
	t.Helper()
	m704 := bs.pack.adv.M704
	regs := mbRead(t, bs, m704, uint16(sunspec.L704.Len()))
	v := sunspec.L704.View(regs)
	v.SetBool("WSetEna", true)
	v.SetEnum("WSetMod", sunspec.M704_WSetMod_Watts)
	v.SetFloat("WSet", w)
	mbWrite(t, bs, m704, regs...)
}

// writeLegacyDispatch writes the bench's legacy signed-percent dispatch into
// M123 — the only active-power command the cease shape can express.
func writeLegacyDispatch(t *testing.T, bs *BatteryServer, w float64) {
	t.Helper()
	b := bs.bases
	sf := int16(bs.Regs.Get(b.M123Base + sunspec.M123_WMaxLimPct_SF))
	mbWrite(t, bs, b.M123Base+sunspec.M123_WMaxLimPct,
		sunspec.RawFromScaleSigned(100.0*w/bs.wmaxW, sf))
	mbWrite(t, bs, b.M123Base+sunspec.M123_WMaxLimPct_Ena, 1)
}

func modelChain(t *testing.T, r *RegisterMap) []uint16 {
	t.Helper()
	base := uint16(sunspec.SunSpecBase)
	if r.Get(base) != sunspec.SunSMagic0 || r.Get(base+1) != sunspec.SunSMagic1 {
		t.Fatalf("no SunS magic at base %d", base)
	}
	cur := base + 2
	var out []uint16
	for i := 0; i < 64; i++ {
		id := r.Get(cur)
		if id == sunspec.EndMarker {
			return out
		}
		out = append(out, id)
		cur += 2 + r.Get(cur+1)
	}
	t.Fatalf("model chain did not terminate within 64 models")
	return nil
}

func sameChain(a, b []uint16) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// ── The two shapes ───────────────────────────────────────────────────────────

// TestPackSetpointShapeServesTheSetpointChain pins the 704-capable pack's
// model chain and the three facts lexa-gw's admission gate
// (internal/southbound/admission's BatterySetpointRefusal) measures before it
// will admit a battery under the setpoint-zero posture: M704 is present, M702
// is present, and M702's CtrlModes POSITIVELY declares FIXED_W. A pack failing
// any of them would be admitted under the CEASE posture instead — the wrong
// device for the row it was launched for, and a mismatch that would read as a
// gateway bug.
func TestPackSetpointShapeServesTheSetpointChain(t *testing.T) {
	bs := newTestPack(t, PackShapeSetpoint)
	want := []uint16{
		sunspec.ModelCommon, sunspec.ModelNameplate, sunspec.ModelBasicSettings,
		sunspec.ModelInverterThreePh, sunspec.ModelImmediateCtrl, sunspec.ModelLithiumBattery,
		sunspec.ModelDERMeasureAC, sunspec.ModelDERCapacity, sunspec.ModelDEREnterService,
		sunspec.ModelDERCtlAC, sunspec.ModelDERStorageCap,
	}
	if got := modelChain(t, bs.Regs); !sameChain(got, want) {
		t.Fatalf("model chain = %v, want %v", got, want)
	}

	cap702 := sunspec.Parse702(readSlice(bs.Regs, bs.pack.m702, sunspec.L702.Len()))
	if cap702.CtrlModes&sunspec.M702_CtrlMode_FixedW == 0 {
		t.Errorf("M702 CtrlModes = %#x, want the FIXED_W bit set — without it the gateway "+
			"refuses the setpoint chain and admits this pack under the CEASE posture", cap702.CtrlModes)
	}
	if cap702.CtrlModes&sunspec.M702_CtrlMode_VoltVar != 0 {
		t.Errorf("M702 CtrlModes = %#x declares VOLT_VAR, but this pack publishes no 705 — "+
			"a capability claim with no model behind it is the contradiction advSimCtrlModes forbids",
			cap702.CtrlModes)
	}
	// M123 Conn stays implemented on this shape too: a 704 pack still has a
	// connect axis, and the setpoint posture must be shown to be PREFERRED
	// where both chains exist rather than picked because the other was absent.
	if conn := bs.Regs.Get(bs.bases.M123Base + sunspec.M123_Conn); conn == 0xFFFF {
		t.Errorf("M123 Conn = 0xFFFF on the setpoint shape; want an implemented connect axis")
	}
}

// TestPackCeaseShapeIsGenuinely704Less is the other half: the cease shape must
// serve NO 7xx model at all. A pack that quietly kept a 704 would be admitted
// under the setpoint posture and rows (e)/(f) would silently measure the wrong
// containment — the exact confusion BENCH-000 records for the inverter fleet
// ("the 704-less shape exists on the bench only as an INVERTER").
func TestPackCeaseShapeIsGenuinely704Less(t *testing.T) {
	bs := newTestPack(t, PackShapeCease)
	want := []uint16{
		sunspec.ModelCommon, sunspec.ModelNameplate, sunspec.ModelBasicSettings,
		sunspec.ModelInverterThreePh, sunspec.ModelImmediateCtrl, sunspec.ModelLithiumBattery,
	}
	got := modelChain(t, bs.Regs)
	if !sameChain(got, want) {
		t.Fatalf("model chain = %v, want %v", got, want)
	}
	if bs.pack.has704 || bs.advanced {
		t.Errorf("cease shape reports has704=%v advanced=%v; want both false", bs.pack.has704, bs.advanced)
	}
	// The cease chain's own admission predicate (derbase newM123ConnPlan, moved
	// earlier in time by the gate): M123 present, block long enough to contain
	// Conn, Conn not at the not-implemented sentinel.
	if conn := bs.Regs.Get(bs.bases.M123Base + sunspec.M123_Conn); conn != 1 {
		t.Errorf("M123 Conn = %d at rest, want 1 (a pack powers on in service)", conn)
	}
}

// TestPackRateRatingsAreRealAsymmetricAndBelowNameplate is the storage fork
// solar_adv.go's populate702 doc defers to a profile like this one. Real
// (never the sentinel), ASYMMETRIC (charge strictly below discharge — since
// IW14-001 the gateway resolves each opModFixedW sign against its own rating,
// and only asymmetry makes the per-sign references distinguishable from each
// other and from the nameplate), and both STRICTLY below the nameplate — the
// last part being what makes the rating bound reachable at all, since
// checkSetpointWithinNameplate runs first and would otherwise always be the
// refusal that fires.
func TestPackRateRatingsAreRealAsymmetricAndBelowNameplate(t *testing.T) {
	bs := newTestPack(t, PackShapeSetpoint)
	c := sunspec.Parse702(readSlice(bs.Regs, bs.pack.m702, sunspec.L702.Len()))

	if math.IsNaN(c.WChaRteMaxRtg) || math.IsNaN(c.WDisChaRteMaxRtg) {
		t.Fatalf("rate ratings unimplemented (cha=%v discha=%v) — a storage profile must declare them",
			c.WChaRteMaxRtg, c.WDisChaRteMaxRtg)
	}
	if c.WChaRteMaxRtg >= c.WDisChaRteMaxRtg {
		t.Errorf("rate ratings not asymmetric: cha=%v discha=%v; charge must be strictly below discharge "+
			"so the per-sign FixedW references are mutually distinguishable", c.WChaRteMaxRtg, c.WDisChaRteMaxRtg)
	}
	for name, v := range map[string]float64{"charge": c.WChaRteMaxRtg, "discharge": c.WDisChaRteMaxRtg} {
		if v <= 0 || v >= testPackWmax {
			t.Errorf("%s rate rating %v is not strictly inside (0, nameplate=%v) — the rating bound "+
				"is then unreachable behind the nameplate bound and ships untested", name, v, testPackWmax)
		}
	}
	// The APPARENT-power rate ratings stay honestly absent.
	if !math.IsNaN(c.VAChaRteMaxRtg) || !math.IsNaN(c.VADisChaRteMaxRtg) {
		t.Errorf("VA rate ratings = %v/%v, want the not-implemented sentinel: an implemented zero is a "+
			"positive declaration that this pack cannot charge/discharge at all", c.VAChaRteMaxRtg, c.VADisChaRteMaxRtg)
	}
	// Every model that carries the rate agrees about it — per direction.
	b := bs.bases
	for _, e := range []struct {
		name string
		got  uint16
		want float64
	}{
		{"M120 MaxChaRte", bs.Regs.Get(b.M120Base + sunspec.M120_MaxChaRte), c.WChaRteMaxRtg},
		{"M120 MaxDisChaRte", bs.Regs.Get(b.M120Base + sunspec.M120_MaxDisChaRte), c.WDisChaRteMaxRtg},
		{"M802 WChaRteMax", bs.Regs.Get(b.M802Base + uint16(sunspec.M802_WChaRteMax)), c.WChaRteMaxRtg},
		{"M802 WDisChaRteMax", bs.Regs.Get(b.M802Base + uint16(sunspec.M802_WDisChaRteMax)), c.WDisChaRteMaxRtg},
	} {
		if float64(e.got) != e.want {
			t.Errorf("%s = %d, want %v — a device contradicting itself across models is a fault to "+
				"inject deliberately, never to ship", e.name, e.got, e.want)
		}
	}
}

// ── The WSet bridge ──────────────────────────────────────────────────────────

// TestPackWSetReachesPhysicalEffectInBothDirections is THE row this whole file
// exists for: a 704 WSet write commands the pack, and the animation drives
// measured power (M103 and its 701 mirror) to it — discharging AND charging,
// with SoC integrating the right way for each. battery_adv.go's 704 does none
// of this by design; that is what made every setpoint-convergence bench row
// unrunnable.
func TestPackWSetReachesPhysicalEffectInBothDirections(t *testing.T) {
	bs := newTestPack(t, PackShapeSetpoint)
	st := newPackAnim()

	for _, tc := range []struct {
		name string
		w    float64
	}{
		{"discharge", +3000},
		// Charge magnitude kept inside the (asymmetric, 2000 W) charge rating —
		// clamping AT the rating is TestPackHonoursItsDeclaredRateRatings' row,
		// not this one's.
		{"charge", -1500},
		{"discharge again, across zero", +1500},
	} {
		t.Run(tc.name, func(t *testing.T) {
			socBefore := packCurrentSoC(bs.Regs, bs.bases)
			writeWSet(t, bs, tc.w)

			// Ten ticks is well past the ramp's needs (a full-scale swing is
			// three) and is deliberately not the exact number: the assertion is
			// convergence, not a stopwatch.
			packTicks(bs, st, 10)

			if got := packMeasuredW(bs); math.Abs(got-tc.w) > packWTol {
				t.Fatalf("measured W = %.1f after convergence, want %.1f (±%.0f)", got, tc.w, packWTol)
			}
			m701 := sunspec.Parse701(readSlice(bs.Regs, bs.pack.adv.M701, bs.pack.adv.M701Len))
			if math.Abs(m701.W-tc.w) > packWTol {
				t.Errorf("701 W = %.1f, want %.1f — the advanced measurement model must mirror the "+
					"same physical state 103 reports, in the same tick", m701.W, tc.w)
			}
			socAfter := packCurrentSoC(bs.Regs, bs.bases)
			if tc.w > 0 && socAfter >= socBefore {
				t.Errorf("SoC %.3f -> %.3f while DISCHARGING; want a fall", socBefore, socAfter)
			}
			if tc.w < 0 && socAfter <= socBefore {
				t.Errorf("SoC %.3f -> %.3f while CHARGING; want a rise", socBefore, socAfter)
			}
		})
	}
}

// TestPackWSetHonoursWSetMod proves the bridge reads the MODE and not just the
// value: the same physical command expressed as percent-of-max must land in
// the same watts. A device that understood only one spelling would mis-scale
// the other by wmax/100 and report a plausible, wrong number.
func TestPackWSetHonoursWSetMod(t *testing.T) {
	bs := newTestPack(t, PackShapeSetpoint)
	st := newPackAnim()

	m704 := bs.pack.adv.M704
	regs := mbRead(t, bs, m704, uint16(sunspec.L704.Len()))
	v := sunspec.L704.View(regs)
	v.SetBool("WSetEna", true)
	v.SetEnum("WSetMod", sunspec.M704_WSetMod_MaxPct)
	v.SetFloat("WSetPct", 40) // 40 % of 5000 W = 2000 W discharge
	mbWrite(t, bs, m704, regs...)

	packTicks(bs, st, 10)
	if got := packMeasuredW(bs); math.Abs(got-2000) > packWTol {
		t.Fatalf("measured W = %.1f for WSetPct=40%% of %.0f W, want 2000", got, testPackWmax)
	}
}

// TestPackIdleCommandedDischargeDivergesUntilTheAnimationMoves is the row that
// makes the gateway's pending/converged/diverged machinery testable at all. An
// idle pack given a discharge setpoint is COMMANDED at once (the register bank
// shows it) and MEASURED at zero, which is a genuine divergence a sampler
// would see; only after the animation has run does the measurement agree. A
// device that jumped would be permanently, uselessly converged.
func TestPackIdleCommandedDischargeDivergesUntilTheAnimationMoves(t *testing.T) {
	bs := newTestPack(t, PackShapeSetpoint)
	st := newPackAnim()

	// Start from a genuinely held idle: commanded zero, measured zero.
	writeWSet(t, bs, 0)
	packTicks(bs, st, 2)
	if got := packMeasuredW(bs); math.Abs(got) > packWTol {
		t.Fatalf("pack is not idle before the row starts: measured W = %.1f", got)
	}

	writeWSet(t, bs, 4000)

	// Sampled NOW — after the ACK, before any animation — the pack is
	// commanded 4000 W and measuring 0 W.
	snap := bs.Snapshot()
	if snap.Pack == nil {
		t.Fatal("GET /state carries no pack ground truth")
	}
	if snap.Pack.CommandedW == nil || math.Abs(*snap.Pack.CommandedW-4000) > packWTol {
		t.Fatalf("commanded_W = %v immediately after the write, want 4000", snap.Pack.CommandedW)
	}
	if math.Abs(snap.Pack.MeasuredW) > packWTol {
		t.Fatalf("measured_W = %.1f immediately after the write, want ~0 — the pack must RAMP, "+
			"not jump, or 'not yet converged' is a state the bench can never observe", snap.Pack.MeasuredW)
	}

	// One tick: moving, but still short of the command.
	packTicks(bs, st, 1)
	mid := packMeasuredW(bs)
	if mid <= 0 || mid >= 4000-packWTol {
		t.Fatalf("measured W = %.1f after ONE tick, want strictly between 0 and 4000 "+
			"(ramp bound is %.0f W/tick)", mid, bs.pack.rampW)
	}

	// Enough ticks: converged.
	packTicks(bs, st, 10)
	if got := packMeasuredW(bs); math.Abs(got-4000) > packWTol {
		t.Fatalf("measured W = %.1f after the animation ran, want 4000", got)
	}
}

// TestPackHonoursItsDeclaredRateRatings: the M702 numbers are a fact about the
// pack, not a claim in a register. A setpoint inside the nameplate but past
// the declared rate rating is executed AT the rating — so a direct write that
// never went through a gateway's validateSetpointW still meets a device that
// does what it said it could do and no more.
func TestPackHonoursItsDeclaredRateRatings(t *testing.T) {
	bs := newTestPack(t, PackShapeSetpoint)
	st := newPackAnim()

	for _, tc := range []struct {
		name       string
		commanded  float64
		wantSigned float64
	}{
		{"discharge past the rating", testPackWmax, bs.pack.disChaRteMaxW},
		{"charge past the rating", -testPackWmax, -bs.pack.chaRteMaxW},
	} {
		t.Run(tc.name, func(t *testing.T) {
			writeWSet(t, bs, tc.commanded)
			packTicks(bs, st, 12)
			if got := packMeasuredW(bs); math.Abs(got-tc.wantSigned) > packWTol {
				t.Fatalf("commanded %.0f W (nameplate), measured %.1f W, want the declared rate "+
					"rating %.1f W", tc.commanded, got, tc.wantSigned)
			}
		})
	}
}

// TestPackIdlesAtZeroWhenFullOrEmpty: idle-at-zero must be expressible without
// a fault. A full pack asked to charge, and an empty pack asked to discharge,
// both hold a genuine 0 W — and report it as FULL/EMPTY rather than the
// HOLDING that means "nobody asked", which is the distinction a hub needs to
// tell "this pack is refusing" from "this pack is uncommanded".
func TestPackIdlesAtZeroWhenFullOrEmpty(t *testing.T) {
	for _, tc := range []struct {
		name      string
		soc       float64
		command   float64
		wantChaSt uint16
	}{
		{"full pack commanded to charge", 100, -4000, m802ChaStFull},
		{"empty pack commanded to discharge", 0, 4000, m802ChaStEmpty},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bs := newTestPack(t, PackShapeSetpoint)
			st := newPackAnim()
			if err := bs.Inject([]byte(`{"SoC_pct":` + jsonNum(tc.soc) + `}`)); err != nil {
				t.Fatalf("inject SoC: %v", err)
			}
			writeWSet(t, bs, tc.command)
			packTicks(bs, st, 6)

			if got := packMeasuredW(bs); math.Abs(got) > packWTol {
				t.Errorf("measured W = %.1f, want a genuine 0 — a pack at %.0f%% SoC cannot deliver "+
					"%.0f W and must not report that it does", got, tc.soc, tc.command)
			}
			if got := bs.Regs.Get(bs.bases.M802Base + uint16(sunspec.M802_ChaSt)); got != tc.wantChaSt {
				t.Errorf("802 ChaSt = %d, want %d (%s)", got, tc.wantChaSt, chaStText(int(tc.wantChaSt)))
			}
		})
	}
}

func jsonNum(f float64) string {
	b, _ := json.Marshal(f)
	return string(b)
}

// TestPackCommandedWInjectWorksOnBothShapes pins the shape-agnostic bench
// lever, and its contrast with the historical "WMaxLimPct_pct" spelling.
//
// The contrast half used to be a defect finding: before RMD-046,
// WMaxLimPct_pct encoded val*100 at SF −2 — val×10000 — so an injected 80
// SATURATED the register at 32767 and commanded 327.67 % of nameplate rather
// than 80 %. That has been fixed (sim/southbound/battery.go and solar.go's
// Inject, case "WMaxLimPct_pct", now encode val directly and clamp to
// [0,100]); this test now pins the FIXED encoding instead, and still exists
// to stop the pack's own recipes from reaching for the unsigned, clamped
// "WMaxLimPct_pct" key when they need a signed charge/discharge lever — see
// injectPackDispatch's doc for why CommandedW_W is that lever.
func TestPackCommandedWInjectWorksOnBothShapes(t *testing.T) {
	for _, shape := range []BatteryPackShape{PackShapeCease, PackShapeSetpoint} {
		t.Run(string(shape), func(t *testing.T) {
			bs := newTestPack(t, shape)
			st := newPackAnim()
			if err := bs.Inject([]byte(`{"CommandedW_W":4000}`)); err != nil {
				t.Fatalf("inject CommandedW_W: %v", err)
			}
			packTicks(bs, st, 10)
			if got := packMeasuredW(bs); math.Abs(got-4000) > packWTol {
				t.Fatalf("measured W = %.1f, want 4000", got)
			}
			// And the reverse direction, through the same key. Magnitude inside
			// the asymmetric 2000 W charge rating — the clamp has its own test.
			if err := bs.Inject([]byte(`{"CommandedW_W":-1500}`)); err != nil {
				t.Fatalf("inject CommandedW_W: %v", err)
			}
			packTicks(bs, st, 12)
			if got := packMeasuredW(bs); math.Abs(got+1500) > packWTol {
				t.Fatalf("measured W = %.1f, want -1500", got)
			}
		})
	}

	t.Run("the historical WMaxLimPct_pct spelling now encodes correctly (RMD-046)", func(t *testing.T) {
		bs := newTestPack(t, PackShapeCease)
		if err := bs.Inject([]byte(`{"WMaxLimPct_pct":80}`)); err != nil {
			t.Fatalf("inject: %v", err)
		}
		if err := bs.Inject([]byte(`{"Ena":1}`)); err != nil {
			t.Fatalf("inject: %v", err)
		}
		raw := bs.Regs.Get(bs.bases.M123Base + sunspec.M123_WMaxLimPct)
		if raw != 8000 {
			t.Fatalf("M123 WMaxLimPct = %d for an injected 80%%, want 8000 (= 80.00%% at SF -2) — if "+
				"this is back to the saturated 32767, the RMD-046 fix (removing Inject's val*100 double "+
				"scale) has regressed", raw)
		}
		// 8000 at SF −2 reads as 80.00 % of nameplate — the pack cannot reach it
		// on a 5 kW rig with an 80 % ceiling above its own rate rating, so this
		// pins "correctly-scaled ceiling", not "hits exactly 80 %".
		if got := hubBatteryW(bs.Regs, bs.bases.M123Base, bs.wmaxW); got > bs.wmaxW {
			t.Errorf("hubBatteryW = %.0f from an 80%% ceiling, want at or under nameplate (%.0f) — an "+
				"in-range percent must never command a wildly over-nameplate power; that was the whole "+
				"shape of the pre-RMD-046 defect", got, bs.wmaxW)
		} else if want := 0.8 * bs.wmaxW; math.Abs(got-want) > 1.0 {
			t.Errorf("hubBatteryW = %.0f, want %.0f (80%% of nameplate %.0f)", got, want, bs.wmaxW)
		}
	})

	t.Run("WMaxLimPct_pct clamps out-of-range percentages to [0,100]", func(t *testing.T) {
		bs := newTestPack(t, PackShapeCease)
		if err := bs.Inject([]byte(`{"WMaxLimPct_pct":150}`)); err != nil {
			t.Fatalf("inject: %v", err)
		}
		if raw := bs.Regs.Get(bs.bases.M123Base + sunspec.M123_WMaxLimPct); raw != 10000 {
			t.Errorf("M123 WMaxLimPct = %d for an injected 150%%, want 10000 (clamped to 100.00%%) — "+
				"WMaxLimPct is 0-100%% per the DER model", raw)
		}
		if err := bs.Inject([]byte(`{"WMaxLimPct_pct":-40}`)); err != nil {
			t.Fatalf("inject: %v", err)
		}
		if raw := bs.Regs.Get(bs.bases.M123Base + sunspec.M123_WMaxLimPct); raw != 0 {
			t.Errorf("M123 WMaxLimPct = %d for an injected -40%%, want 0 (clamped to 0.00%%) — "+
				"WMaxLimPct_pct is unsigned; a signed dispatch belongs on CommandedW_W instead", raw)
		}
	})
}

// ── Cease and reconnect ──────────────────────────────────────────────────────

// TestPackCeaseCollapsesPowerAndReconnectRestores is BENCH-000 rows (e) and
// (f) against the simulator: a running 704-less pack, ceased through M123
// Conn, must satisfy BOTH sides of the connect axis's two-sided standard — the
// DER's own state reads disconnected AND measured power lands inside the
// cessation band — and the release must put it back in service on the same
// axis. Both shapes are exercised: a 704 pack still has a connect axis, and
// BENCH-000 (h) is the row that its setpoint posture is unaffected by this.
func TestPackCeaseCollapsesPowerAndReconnectRestores(t *testing.T) {
	for _, shape := range []BatteryPackShape{PackShapeCease, PackShapeSetpoint} {
		t.Run(string(shape), func(t *testing.T) {
			bs := newTestPack(t, shape)
			st := newPackAnim()
			b := bs.bases

			// A running pack: discharging 4 kW, the state RMD-025's pre-fix
			// capture was taken in.
			if shape == PackShapeSetpoint {
				writeWSet(t, bs, 4000)
			} else {
				writeLegacyDispatch(t, bs, 4000)
			}
			packTicks(bs, st, 10)
			if got := packMeasuredW(bs); math.Abs(got-4000) > packWTol {
				t.Fatalf("pack not running before the cease: measured W = %.1f", got)
			}

			// CEASE. A contactor is not a ramp: this must land on the write.
			mbWrite(t, bs, b.M123Base+sunspec.M123_Conn, 0)

			if got := packMeasuredW(bs); math.Abs(got) > packWTol {
				t.Errorf("measured W = %.1f immediately after Conn=0, want inside the cessation band — "+
					"a cease that slews would look like a slow one inside the gateway's settle window", got)
			}
			if got := bs.Regs.Get(b.M123Base + sunspec.M123_Conn); got != 0 {
				t.Errorf("M123 Conn read-back = %d, want 0", got)
			}
			if got := bs.Regs.Get(b.M802Base + uint16(sunspec.M802_State)); got != m802StateDisconnected {
				t.Errorf("802 State = %d, want %d (DISCONNECTED)", got, m802StateDisconnected)
			}
			if got := bs.Regs.Get(b.M802Base + uint16(sunspec.M802_ChaSt)); got != m802ChaStOff {
				t.Errorf("802 ChaSt = %d, want %d (OFF) — a pack at 0 W with an open contactor is not "+
					"a pack idling at 0 W", got, m802ChaStOff)
			}
			if got := bs.Regs.Get(b.M103Base + sunspec.M103_St); got != 1 {
				t.Errorf("103 St = %d, want 1 (OFF)", got)
			}
			if shape == PackShapeSetpoint {
				m701 := sunspec.Parse701(readSlice(bs.Regs, bs.pack.adv.M701, bs.pack.adv.M701Len))
				if m701.ConnSt != 0 || m701.St != 0 {
					t.Errorf("701 St=%d ConnSt=%d after the cease, want 0/0 — the DER's own state is "+
						"half of the two-sided proof", m701.St, m701.ConnSt)
				}
				if math.Abs(m701.W) > packWTol {
					t.Errorf("701 W = %.1f after the cease, want ~0", m701.W)
				}
			}
			// The cease holds across ticks; it is not a one-frame artefact.
			packTicks(bs, st, 5)
			if got := packMeasuredW(bs); math.Abs(got) > packWTol {
				t.Errorf("measured W = %.1f five ticks into the cease, want ~0", got)
			}

			// RELEASE. The standing dispatch was never withdrawn, so the pack
			// returns to it — via the ramp, because reclosing a contactor onto
			// an inverter does not instantly restore its output.
			mbWrite(t, bs, b.M123Base+sunspec.M123_Conn, 1)
			packTicks(bs, st, 10)
			if got := packMeasuredW(bs); math.Abs(got-4000) > packWTol {
				t.Fatalf("measured W = %.1f after the reconnect, want the standing 4000 W back", got)
			}
			if got := bs.Regs.Get(b.M802Base + uint16(sunspec.M802_State)); got != m802StateConnected {
				t.Errorf("802 State = %d after the reconnect, want %d (CONNECTED)", got, m802StateConnected)
			}
		})
	}
}

// TestPackStartDisconnectedNeverAnnouncesItselfInService is the
// pre-disconnected-pack-at-boot fixture (BENCH-000 row (j)): the pack is open
// before any client can dial, and it says so consistently on every surface a
// gateway reads — the connect register, its own operating state, and its
// measured power.
func TestPackStartDisconnectedNeverAnnouncesItselfInService(t *testing.T) {
	bs := newTestPack(t, PackShapeCease)
	bs.StartDisconnected()

	if got := bs.Regs.Get(bs.bases.M123Base + sunspec.M123_Conn); got != 0 {
		t.Fatalf("M123 Conn = %d after StartDisconnected, want 0", got)
	}
	if got := packMeasuredW(bs); math.Abs(got) > packWTol {
		t.Errorf("measured W = %.1f on a pack that starts open, want ~0", got)
	}
	snap := bs.Snapshot()
	if snap.Pack == nil || snap.Pack.Connected {
		t.Errorf("GET /state reports connected=%v, want false", snap.Pack != nil && snap.Pack.Connected)
	}
}

// ── Faults ───────────────────────────────────────────────────────────────────

// TestPackAckNoApplyOnWSetIsAFalseApplied: the ACKed setpoint that never
// latched. The write succeeds at the protocol level and the pack keeps doing
// exactly what it was doing — which is the one failure mode a write-then-read
// gateway must catch, and which could not be armed against a battery before
// this file existed.
func TestPackAckNoApplyOnWSetIsAFalseApplied(t *testing.T) {
	bs := newTestPack(t, PackShapeSetpoint)
	st := newPackAnim()

	// A pack genuinely held at zero, so "nothing happened" is unambiguous.
	writeWSet(t, bs, 0)
	packTicks(bs, st, 2)

	if err := bs.ApplyFault([]byte(`{"kind":"ack_no_apply","fields":["WSet","WSetEna"]}`)); err != nil {
		t.Fatalf("arm ack_no_apply: %v", err)
	}

	writeWSet(t, bs, 4000) // ACKs — mbWrite fails the test on a protocol error
	packTicks(bs, st, 10)

	if got := packMeasuredW(bs); math.Abs(got) > packWTol {
		t.Fatalf("measured W = %.1f after an ACKed-but-dropped setpoint, want the pack still at 0", got)
	}
	v := sunspec.L704.View(readSlice(bs.Regs, bs.pack.adv.M704, sunspec.L704.Len()))
	if w := v.Float("WSet"); math.Abs(w) > 1 {
		t.Errorf("704 WSet = %v in the bank; ack_no_apply must store nothing (ground truth stays honest)", w)
	}
	if fired := bs.lies.Stats().Fired[string(FaultAckNoApply)]; fired == 0 {
		t.Error("ack_no_apply never fired — the row proved nothing")
	}
}

// TestPackAckNoApplyOnConnIsACeaseThatNeverOpened: the same lie on the connect
// axis. The gateway is told the disconnect landed; the pack is still
// exporting. This is the direction that matters — a satisfied cease on a DER
// that never ceased — and it is why the connect axis's proof is two-sided.
func TestPackAckNoApplyOnConnIsACeaseThatNeverOpened(t *testing.T) {
	bs := newTestPack(t, PackShapeCease)
	st := newPackAnim()

	writeLegacyDispatch(t, bs, 4000)
	packTicks(bs, st, 10)

	if err := bs.ApplyFault([]byte(`{"kind":"ack_no_apply","fields":["Conn"]}`)); err != nil {
		t.Fatalf("arm ack_no_apply: %v", err)
	}
	mbWrite(t, bs, bs.bases.M123Base+sunspec.M123_Conn, 0) // ACKs

	if got := bs.Regs.Get(bs.bases.M123Base + sunspec.M123_Conn); got != 1 {
		t.Fatalf("M123 Conn = %d; the write was supposed to be swallowed", got)
	}
	packTicks(bs, st, 3)
	if got := packMeasuredW(bs); math.Abs(got-4000) > packWTol {
		t.Fatalf("measured W = %.1f after the swallowed cease, want the pack still exporting 4000 W — "+
			"an ACKed cease that never opened the contactor is a DER measurably past the cessation "+
			"band while the gateway believes it is contained", got)
	}
	if fired := bs.lies.Stats().Fired[string(FaultAckNoApply)]; fired == 0 {
		t.Error("ack_no_apply never fired — the row proved nothing")
	}
}

// TestPackSentinelFieldCanUnimplementConn builds the admission-refusal fixture
// (BENCH-000 row (g)) out of a fault instead of a third register image: over
// Modbus the pack leaves M123 Conn at the not-implemented sentinel, so its
// connect state can never be proven — while the bank itself stays honest, so
// the QA oracle can still see what the pack really is.
func TestPackSentinelFieldCanUnimplementConn(t *testing.T) {
	bs := newTestPack(t, PackShapeCease)
	if err := bs.ApplyFault([]byte(`{"kind":"sentinel_field","fields":["Conn"],"value":65535}`)); err != nil {
		t.Fatalf("arm sentinel_field: %v", err)
	}
	got := mbRead(t, bs, bs.bases.M123Base, 23)
	if got[sunspec.M123_Conn] != 0xFFFF {
		t.Fatalf("Modbus read of M123 Conn = %d, want the 0xFFFF not-implemented sentinel", got[sunspec.M123_Conn])
	}
	if bank := bs.Regs.Get(bs.bases.M123Base + sunspec.M123_Conn); bank != 1 {
		t.Errorf("register bank Conn = %d, want 1 — ground truth must stay honest or the lie is "+
			"undetectable by anyone, referee included", bank)
	}
}

// TestPackFreezeBlockServesAStaleMeasurement: the pack's measurement window is
// snapshot-able like the inverter's, on whichever model this shape publishes.
// Ground truth keeps moving underneath, which is what makes the staleness
// externally checkable rather than assumed.
func TestPackFreezeBlockServesAStaleMeasurement(t *testing.T) {
	for _, tc := range []struct {
		shape BatteryPackShape
		model string
	}{
		{PackShapeCease, "103"},
		{PackShapeSetpoint, "701"},
	} {
		t.Run(string(tc.shape)+"/"+tc.model, func(t *testing.T) {
			bs := newTestPack(t, tc.shape)
			st := newPackAnim()
			if tc.shape == PackShapeSetpoint {
				writeWSet(t, bs, 0)
			} else {
				writeLegacyDispatch(t, bs, 0)
			}
			packTicks(bs, st, 2)

			if err := bs.ApplyFault([]byte(`{"kind":"freeze_block","models":["` + tc.model + `"]}`)); err != nil {
				t.Fatalf("arm freeze_block: %v", err)
			}
			base, count := bs.bases.M103Base, uint16(50)
			if tc.model == "701" {
				base, count = bs.pack.adv.M701, uint16(bs.pack.adv.M701Len)
			}
			frozen := mbRead(t, bs, base, count)

			// Move the pack for real.
			if tc.shape == PackShapeSetpoint {
				writeWSet(t, bs, 3500)
			} else {
				writeLegacyDispatch(t, bs, 3500)
			}
			packTicks(bs, st, 10)

			after := mbRead(t, bs, base, count)
			if !sameChain(frozen, after) {
				t.Fatalf("frozen window moved on the wire; freeze_block did not hold model %s", tc.model)
			}
			if got := packMeasuredW(bs); math.Abs(got-3500) > packWTol {
				t.Fatalf("ground truth measured W = %.1f, want 3500 — the pack must keep MOVING "+
					"underneath the frozen read or there is nothing to diverge from", got)
			}
		})
	}
}

// TestPackRebootForgetClosesTheContactor: a power-cycled pack comes back on
// its own local defaults, which for a battery means the contactor CLOSED and
// no standing dispatch. That is RMD-025's DER-reboot-to-defaults row, and the
// direction that matters is that a commanded cease does NOT survive it — a
// gateway treating "the pack is back" as "the pack is still ceased" is running
// an uncontained battery.
func TestPackRebootForgetClosesTheContactor(t *testing.T) {
	bs := newTestPack(t, PackShapeSetpoint)
	st := newPackAnim()
	writeWSet(t, bs, 4000)
	packTicks(bs, st, 10)
	mbWrite(t, bs, bs.bases.M123Base+sunspec.M123_Conn, 0)

	if err := bs.ApplyFault([]byte(`{"kind":"reboot_forget"}`)); err != nil {
		t.Fatalf("arm reboot_forget: %v", err)
	}
	if got := bs.Regs.Get(bs.bases.M123Base + sunspec.M123_Conn); got != 1 {
		t.Errorf("M123 Conn = %d after a reboot, want 1 — a pack powers on in service", got)
	}
	v := sunspec.L704.View(readSlice(bs.Regs, bs.pack.adv.M704, sunspec.L704.Len()))
	if v.Bool("WSetEna") {
		t.Errorf("704 WSetEna still set after a reboot; the commanded setpoint must be gone")
	}
	if got := bs.Regs.Get(bs.bases.M123Base + sunspec.M123_WMaxLimPct_Ena); got != 0 {
		t.Errorf("M123 WMaxLimPct_Ena = %d after a reboot, want 0", got)
	}
}

// TestPackEffectTimeBatteryFaultsStillShapeA704Setpoint: faults.go's
// effect-time vocabulary (soc_refuse and the two directional refusals) reaches
// a power commanded through 704, because the bridge puts BOTH command routes
// through one physics. A setpoint that bypassed shapeBatteryW would have
// silently made the pack's oldest fault family inapplicable to its newest
// control axis.
func TestPackEffectTimeBatteryFaultsStillShapeA704Setpoint(t *testing.T) {
	bs := newTestPack(t, PackShapeSetpoint)
	st := newPackAnim()
	writeWSet(t, bs, 3000)
	packTicks(bs, st, 10)
	if got := packMeasuredW(bs); math.Abs(got-3000) > packWTol {
		t.Fatalf("pack not at the setpoint before the fault: %.1f", got)
	}

	if err := bs.ApplyFault([]byte(`{"kind":"discharge_disabled"}`)); err != nil {
		t.Fatalf("arm discharge_disabled: %v", err)
	}
	packTicks(bs, st, 10)
	if got := packMeasuredW(bs); math.Abs(got) > packWTol {
		t.Fatalf("measured W = %.1f with discharge_disabled armed against a 704 setpoint, want 0", got)
	}
}

// ── The historical images are untouched ──────────────────────────────────────

// TestHistoricalBatteryImagesCarryNoPackSurface: batsim's default and
// mbapsdev's battery mode must be exactly what they were. No pack object on
// GET /state, no lying-device layer, and a lie kind refused BY NAME rather
// than silently accepted — because a scenario must be able to tell "we never
// asked" from "the device passed".
func TestHistoricalBatteryImagesCarryNoPackSurface(t *testing.T) {
	r := &RegisterMap{regs: make(map[uint16]uint16)}
	bases := populateBattery(r, testPackKwh, testPackWmax)
	bs := &BatteryServer{Server: &Server{Regs: r}, bases: bases, wmaxW: testPackWmax, wmaxKwh: testPackKwh}
	bs.faults.label = "battery"

	if bs.pack != nil || bs.lies != nil {
		t.Fatal("the historical battery image grew a pack profile or a lying layer")
	}
	if snap := bs.Snapshot(); snap.Pack != nil {
		t.Error("GET /state grew a \"pack\" object on the historical image")
	}
	if err := bs.ApplyFault([]byte(`{"kind":"ack_no_apply"}`)); err == nil {
		t.Error("the historical image accepted a lying-device fault kind it does not implement")
	}
	if err := bs.Inject([]byte(`{"WSet_W":1000}`)); err == nil {
		t.Error("the historical image accepted a 704 setpoint inject with no M704 to put it in")
	}
	// The advanced (mbapsdev T06.3) battery chain must not have grown 702/703.
	ar := &RegisterMap{regs: make(map[uint16]uint16)}
	abases, cursor := populateBatteryCore(ar, testPackKwh, testPackWmax)
	_ = abases
	_, cursor = populateBattery7xx(ar, cursor, testPackKwh, testPackWmax)
	ar.Set(cursor, sunspec.EndMarker)
	ar.Set(cursor+1, 0)
	want := []uint16{
		sunspec.ModelCommon, sunspec.ModelNameplate, sunspec.ModelBasicSettings,
		sunspec.ModelInverterThreePh, sunspec.ModelImmediateCtrl, sunspec.ModelLithiumBattery,
		sunspec.ModelDERMeasureAC, sunspec.ModelDERCtlAC, sunspec.ModelDERStorageCap,
	}
	if got := modelChain(t, ar); !sameChain(got, want) {
		t.Errorf("advanced battery chain = %v, want %v — adding 702/703 there would lengthen the "+
			"chain every mbapsdev T06.3 scenario walks", got, want)
	}
}

// ── IW15-002: the rate SETTINGS are physics, the RATINGS are declarations ────

// TestPackRateSettingIsHonouredLive is the pack half of IW15-002. The pack has
// always CLAMPED to its rate limits — but to Go floats captured at
// construction, so the M702 WChaRteMax/WDisChaRteMax SETTINGS were a claim in a
// register that nothing read. Writing one had no consequence, which is the
// ack_no_apply shape wearing a capacity block's clothes.
//
// After IW15-002 the clamp reads the live setting, the RATING stays where it
// was, and /state reports both so a row can prove which one a gateway resolved
// its reference against.
func TestPackRateSettingIsHonouredLive(t *testing.T) {
	bs := newTestPack(t, PackShapeSetpoint)
	st := newPackAnim()
	ratingCha := bs.pack.chaRteMaxW // 2000 W at the 5 kW fixture

	// A configured charge limit BELOW the declared rating.
	if err := bs.Inject([]byte(`{"WChaRteMax_W":800}`)); err != nil {
		t.Fatalf("inject WChaRteMax_W: %v", err)
	}
	if got := bs.pack.clampToRateRating(bs.Regs, -testPackWmax); math.Abs(got+800) > 0.5 {
		t.Fatalf("clamp of a full-nameplate charge = %.1f W, want -800 W (the live SETTING). "+
			"%.0f W would mean the physics is still reading the construction float", got, -ratingCha)
	}

	// And the machine really does it, through the real bridge and the real step.
	writeWSet(t, bs, -testPackWmax)
	packTicks(bs, st, 12)
	if got := packMeasuredW(bs); math.Abs(got+800) > packWTol {
		t.Fatalf("measured = %.1f W after a full-nameplate charge command, want -800 W (the configured limit)", got)
	}

	// /state shows the setting the pack is HONOURING beside the rating it
	// DECLARES — the divergence, without a Modbus client.
	pk := bs.Snapshot().Pack
	if math.Abs(pk.WChaRteMaxW-800) > 0.5 {
		t.Errorf("/state w_cha_rte_max_W = %v, want 800 (the honoured setting)", pk.WChaRteMaxW)
	}
	if math.Abs(pk.WChaRteMaxRtgW-ratingCha) > 0.5 {
		t.Errorf("/state w_cha_rte_max_rtg_W = %v, want %v (the declared rating, untouched by a SETTING inject)",
			pk.WChaRteMaxRtgW, ratingCha)
	}
	// The nameplate model carries the RATING, so a setting inject leaves it alone.
	if got := float64(bs.Regs.Get(bs.bases.M120Base + sunspec.M120_MaxChaRte)); math.Abs(got-ratingCha) > 0.5 {
		t.Errorf("M120 MaxChaRte = %v after a setting inject, want %v (the rating)", got, ratingCha)
	}
	// The discharge direction was never commanded and must not have moved.
	if math.Abs(pk.WDisChaRteMaxW-bs.pack.disChaRteMaxW) > 0.5 {
		t.Errorf("/state w_discha_rte_max_W = %v, want %v — the two directions are separately settable",
			pk.WDisChaRteMaxW, bs.pack.disChaRteMaxW)
	}
}

// TestPackRateRatingInjectMirrorsTheNameplateModel: a RATING is one fact, so
// every model that carries it says the same number (populateBatteryPack's rule
// — a device contradicting itself across models is a fault to inject
// deliberately, never to ship). A rating inject must not, however, change what
// the pack HONOURS: that is the setting's job.
func TestPackRateRatingInjectMirrorsTheNameplateModel(t *testing.T) {
	bs := newTestPack(t, PackShapeSetpoint)
	settingBefore, _ := bs.pack.rateLimits(bs.Regs)

	if err := bs.Inject([]byte(`{"WChaRteMaxRtg_W":1234}`)); err != nil {
		t.Fatalf("inject WChaRteMaxRtg_W: %v", err)
	}
	v := sunspec.L702.View(readSlice(bs.Regs, bs.pack.m702, sunspec.L702.Len()))
	if got := v.Float("WChaRteMaxRtg"); got != 1234 {
		t.Errorf("702 WChaRteMaxRtg = %v, want 1234", got)
	}
	if got := float64(bs.Regs.Get(bs.bases.M120Base + sunspec.M120_MaxChaRte)); got != 1234 {
		t.Errorf("M120 MaxChaRte = %v, want 1234 — the nameplate mirror of the same rating fact", got)
	}
	if got := v.Float("WChaRteMax"); got != settingBefore {
		t.Errorf("702 WChaRteMax = %v after a RATING inject, want %v: the setting is a separate number",
			got, settingBefore)
	}
	if got, _ := bs.pack.rateLimits(bs.Regs); got != settingBefore {
		t.Errorf("honoured charge limit = %v after a RATING inject, want %v", got, settingBefore)
	}
}

// TestPackRateSettingSentinelFallsBackToTheConstructionFloat: a
// not-implemented point is "absent", never "zero". A pack whose 702 has been
// blanked (the nan_sentinel shape, or a whole-block write-back of garbage) must
// fall back to what it physically is rather than clamp every command to 0 W.
func TestPackRateSettingSentinelFallsBackToTheConstructionFloat(t *testing.T) {
	bs := newTestPack(t, PackShapeSetpoint)
	bs.Regs.Set(bs.pack.m702+uint16(sunspec.L702.Offset("WChaRteMax")), 0xFFFF)
	bs.Regs.Set(bs.pack.m702+uint16(sunspec.L702.Offset("WDisChaRteMax")), 0xFFFF)

	cha, discha := bs.pack.rateLimits(bs.Regs)
	if cha != bs.pack.chaRteMaxW || discha != bs.pack.disChaRteMaxW {
		t.Fatalf("limits under the sentinel = %v/%v, want the construction floats %v/%v",
			cha, discha, bs.pack.chaRteMaxW, bs.pack.disChaRteMaxW)
	}

	// An explicit ZERO is a different claim and IS honoured: "this pack may not
	// charge" is a thing a configured device says.
	if err := bs.Inject([]byte(`{"WChaRteMax_W":0}`)); err != nil {
		t.Fatalf("inject WChaRteMax_W 0: %v", err)
	}
	if got := bs.pack.clampToRateRating(bs.Regs, -1000); got != 0 {
		t.Fatalf("clamp with a zero charge setting = %v, want 0 — an implemented zero is a positive "+
			"declaration of incapacity, not an absence", got)
	}
}

// TestPackCapacityInjectRefusedWithoutA702: the cease shape serves no DER
// capacity model, so the key is refused BY NAME instead of quietly storing
// nothing.
func TestPackCapacityInjectRefusedWithoutA702(t *testing.T) {
	bs := newTestPack(t, PackShapeCease)
	for _, key := range []string{"WMax_W", "WChaRteMax_W", "WDisChaRteMaxRtg_W"} {
		if err := bs.Inject([]byte(`{"` + key + `":1000}`)); err == nil {
			t.Errorf("cease shape accepted %q, but it serves no M702", key)
		}
	}
}
