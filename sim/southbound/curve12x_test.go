package sim

// curve12x_test.go — the four things that have to be true about the legacy
// (12x) curve family.
//
//  1. What the sim ENCODES is what a conformant reader DECODES. Every
//     assertion below reads the block back through lexa-proto's own
//     ReadLegacyCurveGeometry / ParseLegacy*Curve — the same functions the
//     gateway and the conformance referee use — never by re-deriving offsets
//     here. A sim that agreed only with itself would serve a device nobody else
//     can read, and every verdict taken against it would be measuring the
//     fixture.
//
//  2. The COMMIT SEMANTICS are the legacy ones, not the 7xx ones borrowed. No
//     adopt handshake, a 1-based ActCrv that selects, a ModEna BITFIELD whose
//     bit 0 enables, and per-bank write protection at an offset that is per
//     model.
//
//  3. Each fault kind subverts EXACTLY ONE of those rules, and the unarmed
//     device does the conformant thing. A device that could not be made to lie
//     about ActCrv is a device against which "the gateway verifies its ActCrv
//     read-back" is untestable.
//
//  4. The geometry gate has a real test target. The short-block posture builds
//     a device that is internally coherent and whose geometry is wrong in the
//     one way L arithmetic can catch.

import (
	"encoding/json"
	"testing"

	modbuslib "github.com/simonvetter/modbus"

	"lexa-proto/sunspec"
)

// newLegacyCurveSim builds a legacy-curve device with no listener, the same
// shape newAdvSolarModels uses for the 7xx one.
func newLegacyCurveSim(t *testing.T, wmax float64, opt LegacyCurveOptions) *SolarServer {
	t.Helper()
	r := &RegisterMap{regs: make(map[uint16]uint16)}
	bases, cursor := populateSolarCore(r, wmax, "")
	layer, cursor := populateLegacyCurves(r, cursor, wmax, opt)
	r.Set(cursor, sunspec.EndMarker)
	r.Set(cursor+1, 0)
	ss := &SolarServer{Server: &Server{Regs: r}, bases: bases, wmaxW: wmax, legacy: layer}
	ss.faults.label = "solar-legacy-curves"
	// The same two write hooks the constructor installs. Without them a test
	// would be writing straight into the map and proving nothing about the
	// device a client meets.
	r.OnWriteAttempt = ss.interceptWrite
	ss.chainLegacyWriteError(r)
	return ss
}

// legacyBlockOf returns the served descriptor for a model id.
func (ss *SolarServer) legacyBlockOf(t *testing.T, id uint16) legacyBankBlock {
	t.Helper()
	for _, b := range ss.legacy.blocks {
		if b.id == id {
			return b
		}
	}
	t.Fatalf("the sim serves no legacy curve model %d", id)
	return legacyBankBlock{}
}

// legacyBody reads a model's whole body the way sunspec.Reader.ReadModel would,
// which is what every lexa-proto legacy accessor requires: len(regs) IS the
// device's declared L, and a sub-slice makes the geometry incoherent.
func (ss *SolarServer) legacyBody(t *testing.T, id uint16) []uint16 {
	t.Helper()
	b := ss.legacyBlockOf(t, id)
	return readSlice(ss.Regs, b.base, b.dataLen)
}

// TestLegacyCurveGeometryIsCoherentForEveryModel is the gate this whole family
// depends on: for every served model the device-declared L, NCrv and the spec
// block length agree, so an offset may be computed at all.
func TestLegacyCurveGeometryIsCoherentForEveryModel(t *testing.T) {
	for _, ncrv := range []int{1, 2, 3} {
		ss := newLegacyCurveSim(t, 5000, LegacyCurveOptions{NCrv: ncrv})
		for _, spec := range legacyCurveSpecs {
			regs := ss.legacyBody(t, spec.id)
			g, err := sunspec.LegacyCurveGeometryOf(spec.id, len(regs), regs)
			if err != nil {
				t.Fatalf("NCrv=%d M%d geometry: %v", ncrv, spec.id, err)
			}
			if g.BlockLen != spec.blockLen {
				t.Errorf("NCrv=%d M%d block length %d, want the spec's %d",
					ncrv, spec.id, g.BlockLen, spec.blockLen)
			}
			if g.NCrv != ncrv {
				t.Errorf("NCrv=%d M%d declares NCrv=%d", ncrv, spec.id, g.NCrv)
			}
			if g.NPt != legacyNPt {
				t.Errorf("NCrv=%d M%d declares NPt=%d, want %d", ncrv, spec.id, g.NPt, legacyNPt)
			}
			if g.ActCrv != 1 {
				t.Errorf("NCrv=%d M%d ActCrv=%d, want bank 1 selected", ncrv, spec.id, g.ActCrv)
			}
		}
	}
}

// TestLegacyCurveDefaultsRoundTripThroughTheShippedParser asserts the seeded
// curves against the numbers this file states, not against legacyCurveSpecs.
// Asserting a block against the table that wrote it proves only that the copy
// succeeded.
func TestLegacyCurveDefaultsRoundTripThroughTheShippedParser(t *testing.T) {
	ss := newLegacyCurveSim(t, 5000, LegacyCurveOptions{})

	vv, err := sunspec.ParseLegacy126Curve(ss.legacyBody(t, 126), 1)
	if err != nil {
		t.Fatalf("parse M126 bank 1: %v", err)
	}
	if vv.DeptRef != 1 {
		t.Errorf("M126 DeptRef=%d, want the LEGACY 1-based %%WMax code 1", vv.DeptRef)
	}
	if len(vv.Pts) != 2 || vv.Pts[0].X != 95 || vv.Pts[0].Y != 30 || vv.Pts[1].X != 105 || vv.Pts[1].Y != -30 {
		t.Errorf("M126 bank 1 holds %v, want (95,30) (105,-30)", vv.Pts)
	}
	if vv.ReadOnly {
		t.Error("M126 bank 1 is READONLY; a legacy device with no writable bank has no safe write at all")
	}

	fw, err := sunspec.ParseLegacy134Curve(ss.legacyBody(t, 134), 1)
	if err != nil {
		t.Fatalf("parse M134 bank 1: %v", err)
	}
	if len(fw.Pts) != 3 || fw.Pts[0].X != 59.5 || fw.Pts[2].X != 62 {
		t.Errorf("M134 bank 1 holds %v, want absolute Hz (59.5,100) (60.5,100) (62,20)", fw.Pts)
	}
	if fw.SnptW {
		t.Error("M134 SnptW is set: the curve's power base would be the instantaneous output at trigger " +
			"time, not WRef, and a CSIP opModFreqWatt curve is defined against a FIXED base")
	}
	if fw.WRefW != 5000 {
		t.Errorf("M134 WRef=%g W, want the device's WMax 5000 W", fw.WRefW)
	}

	// The ride-through banks carry the IEEE 1547-2018 Table 11 Category III
	// must-disconnect defaults, TIME FIRST — the legacy block's own order.
	lv, err := sunspec.ParseLegacy129Curve(ss.legacyBody(t, 129), 1)
	if err != nil {
		t.Fatalf("parse M129 bank 1: %v", err)
	}
	if len(lv.Pts) != 2 || lv.Pts[0].X != 2 || lv.Pts[0].Y != 50 || lv.Pts[1].X != 21 || lv.Pts[1].Y != 88 {
		t.Errorf("M129 bank 1 holds %v, want (2 s, 50 %%V) (21 s, 88 %%V)", lv.Pts)
	}

	// Watt-PF is the one axis whose honest scale factor is not zero.
	pf, err := sunspec.ParseLegacy131Curve(ss.legacyBody(t, 131), 1)
	if err != nil {
		t.Fatalf("parse M131 bank 1: %v", err)
	}
	if len(pf.Pts) != 2 || pf.Pts[1].Y != 0.90 {
		t.Errorf("M131 bank 1 holds %v, want a power factor near 1 (PF_SF = -2)", pf.Pts)
	}
}

// TestLegacyCurveHeaderIsSelectionNotHandshake pins the semantic difference
// from the 7xx family: ActCrv SELECTS and ModEna is a BITFIELD.
func TestLegacyCurveHeaderIsSelectionNotHandshake(t *testing.T) {
	ss := newLegacyCurveSim(t, 5000, LegacyCurveOptions{})
	b := ss.legacyBlockOf(t, 126)

	h, err := sunspec.ParseLegacyCurveHeader(126, ss.legacyBody(t, 126))
	if err != nil {
		t.Fatalf("parse M126 header: %v", err)
	}
	if h.ActCrv != 1 || h.ModEna {
		t.Fatalf("M126 starts ActCrv=%d ModEna=%v, want bank 1 selected and the function OFF",
			h.ActCrv, h.ModEna)
	}

	// A device that sets a RESERVED bit alongside bit 0 is still enabled. A
	// reader comparing the whole word against 1 would call this disabled, which
	// is the enum16/bitfield16 confusion §1.1 of the design names.
	ss.Regs.Set(b.base+uint16(b.modEnaOff), 0x8001)
	h, err = sunspec.ParseLegacyCurveHeader(126, ss.legacyBody(t, 126))
	if err != nil {
		t.Fatalf("re-parse M126 header: %v", err)
	}
	if !h.ModEna {
		t.Error("ModEna=0x8001 decoded as disabled: bit 0 is the enable, the rest are the vendor's")
	}
	if h.ModEnaRaw != 0x8001 {
		t.Errorf("ModEnaRaw=%#04x, want the whole word preserved", h.ModEnaRaw)
	}
}

// writeRegs drives a Modbus write through the sim's real handler, so the
// interception, the write protection and the exception path are all the ones a
// client meets.
func (ss *SolarServer) writeRegs(addr uint16, vals []uint16) error {
	_, err := ss.Regs.HandleHoldingRegisters(&modbuslib.HoldingRegistersRequest{
		IsWrite: true, Addr: addr, Args: vals,
	})
	return err
}

// TestLegacyReadOnlyBankRefusesAndTheFaultMakesItAccept is the pair: the
// conformant device refuses a write into a READONLY bank with a Modbus
// exception and nothing lands, and legacy_read_only_ignored makes exactly that
// write land silently.
func TestLegacyReadOnlyBankRefusesAndTheFaultMakesItAccept(t *testing.T) {
	ss := newLegacyCurveSim(t, 5000, LegacyCurveOptions{NCrv: 2})
	b := ss.legacyBlockOf(t, 126)
	if err := ss.SetLegacyBankReadOnly(126, 2, true); err != nil {
		t.Fatalf("mark bank 2 read-only: %v", err)
	}
	// The bank's ActPt register: inside the bank, not the ReadOnly flag itself.
	target := b.bankBase(2) + uint16(b.bank.Offset("ActPt"))
	before := ss.Regs.Get(target)

	err := ss.writeRegs(target, []uint16{7})
	if err != modbuslib.ErrIllegalDataAddress {
		t.Errorf("a write into a READONLY bank answered %v, want an illegal-data-address exception", err)
	}
	if got := ss.Regs.Get(target); got != before {
		t.Errorf("the refused write LANDED: %d -> %d", before, got)
	}

	if err := ss.ApplyFault([]byte(`{"kind":"legacy_read_only_ignored"}`)); err != nil {
		t.Fatalf("arm legacy_read_only_ignored: %v", err)
	}
	if err := ss.writeRegs(target, []uint16{7}); err != nil {
		t.Errorf("with the fault armed the device still refused: %v", err)
	}
	if got := ss.Regs.Get(target); got != 7 {
		t.Errorf("legacy_read_only_ignored: the write did not land (%d)", got)
	}
}

// TestLegacyReadOnlyFlagIsNeverWritable pins that the per-bank ReadOnly
// register is the DEVICE's declaration about its own banks. A gateway that
// could clear it could grant itself permission the device withheld.
func TestLegacyReadOnlyFlagIsNeverWritable(t *testing.T) {
	ss := newLegacyCurveSim(t, 5000, LegacyCurveOptions{NCrv: 2})
	b := ss.legacyBlockOf(t, 126)
	if err := ss.SetLegacyBankReadOnly(126, 2, true); err != nil {
		t.Fatalf("mark bank 2 read-only: %v", err)
	}
	ro := b.bankBase(2) + uint16(b.roOff)
	_ = ss.writeRegs(ro, []uint16{legacyBankReadWrite})
	if got := ss.Regs.Get(ro); got != legacyBankReadOnly {
		t.Errorf("a Modbus write cleared the bank's own ReadOnly declaration (now %d)", got)
	}
}

// TestLegacyActCrvIgnoredFault pins the fault that makes "the gateway verifies
// its ActCrv read-back" a testable claim.
func TestLegacyActCrvIgnoredFault(t *testing.T) {
	ss := newLegacyCurveSim(t, 5000, LegacyCurveOptions{NCrv: 2})
	b := ss.legacyBlockOf(t, 126)
	actCrv := b.base + uint16(b.actCrvOff)

	if err := ss.writeRegs(actCrv, []uint16{2}); err != nil {
		t.Fatalf("select bank 2: %v", err)
	}
	if got := ss.Regs.Get(actCrv); got != 2 {
		t.Fatalf("unarmed, an ActCrv write must land: ActCrv=%d", got)
	}

	if err := ss.ApplyFault([]byte(`{"kind":"legacy_actcrv_ignored"}`)); err != nil {
		t.Fatalf("arm legacy_actcrv_ignored: %v", err)
	}
	if err := ss.writeRegs(actCrv, []uint16{1}); err != nil {
		t.Fatalf("write ActCrv under the fault: %v", err)
	}
	if got := ss.Regs.Get(actCrv); got != 2 {
		t.Errorf("legacy_actcrv_ignored: ActCrv moved to %d — the fault is supposed to ACK and not move", got)
	}
}

// TestLegacyModEnaStickyFault pins that the fault blocks a CLEAR and not a SET:
// a device that refused to be enabled would be a different (and much less
// dangerous) machine than one that refuses to be switched off.
func TestLegacyModEnaStickyFault(t *testing.T) {
	ss := newLegacyCurveSim(t, 5000, LegacyCurveOptions{})
	b := ss.legacyBlockOf(t, 126)
	modEna := b.base + uint16(b.modEnaOff)

	if err := ss.ApplyFault([]byte(`{"kind":"legacy_modena_sticky"}`)); err != nil {
		t.Fatalf("arm legacy_modena_sticky: %v", err)
	}
	if err := ss.writeRegs(modEna, []uint16{1}); err != nil {
		t.Fatalf("enable: %v", err)
	}
	if got := ss.Regs.Get(modEna); got&1 == 0 {
		t.Fatalf("legacy_modena_sticky blocked the ENABLE (%#04x); it must block only the clear", got)
	}
	if err := ss.writeRegs(modEna, []uint16{0}); err != nil {
		t.Fatalf("disable: %v", err)
	}
	if got := ss.Regs.Get(modEna); got&1 == 0 {
		t.Error("legacy_modena_sticky: ModEna bit 0 cleared, so a release would appear to succeed")
	}
}

// TestLegacySnptWStuckFault pins model 134's snapshot-mode trap.
func TestLegacySnptWStuckFault(t *testing.T) {
	ss := newLegacyCurveSim(t, 5000, LegacyCurveOptions{})
	b := ss.legacyBlockOf(t, 134)
	snptW := b.bankBase(1) + uint16(b.snptWOff)

	if err := ss.writeRegs(snptW, []uint16{0}); err != nil {
		t.Fatalf("clear SnptW: %v", err)
	}
	if got := ss.Regs.Get(snptW); got&1 != 0 {
		t.Fatalf("unarmed, SnptW=0 must stick (%#04x)", got)
	}
	if err := ss.ApplyFault([]byte(`{"kind":"legacy_snptw_stuck"}`)); err != nil {
		t.Fatalf("arm legacy_snptw_stuck: %v", err)
	}
	if err := ss.writeRegs(snptW, []uint16{0}); err != nil {
		t.Fatalf("clear SnptW under the fault: %v", err)
	}
	if got := ss.Regs.Get(snptW); got&1 == 0 {
		t.Error("legacy_snptw_stuck: SnptW cleared, so a writer that read it back would be reassured")
	}
}

// TestLegacyShortBlockDefeatsOffsetArithmeticAndTheGateCatchesIt is the
// geometry gate's test target. The device is internally coherent — the header,
// the declared L and the stride all agree — and its block length is not the
// model's spec one, which is the ONLY thing L arithmetic can see.
func TestLegacyShortBlockDefeatsOffsetArithmeticAndTheGateCatchesIt(t *testing.T) {
	ss := newLegacyCurveSim(t, 5000, LegacyCurveOptions{NCrv: 2, ShortBlockModel: 126})

	regs := ss.legacyBody(t, 126)
	if _, err := sunspec.LegacyCurveGeometryOf(126, len(regs), regs); err == nil {
		t.Fatal("the short-block device passed the geometry gate: every offset computed on it lands in " +
			"the wrong register, of a bank the device may currently be executing")
	}
	// The pathology is precisely that a BOUNDS CHECK would not catch it: the
	// declared length divides exactly by NCrv and every spec offset is inside
	// the slice, so only the comparison against the spec block length fires.
	body := len(regs) - sunspec.L126Hdr.Len()
	if body%2 != 0 {
		t.Fatalf("the short block does not divide by NCrv=2 (body=%d) — this test is not exercising the "+
			"arithmetic it claims to", body)
	}

	// Every OTHER model on the same device is still coherent, so a gateway must
	// refuse one axis rather than the whole DER.
	for _, spec := range legacyCurveSpecs {
		if spec.id == 126 {
			continue
		}
		other := ss.legacyBody(t, spec.id)
		if _, err := sunspec.LegacyCurveGeometryOf(spec.id, len(other), other); err != nil {
			t.Errorf("M%d geometry broke alongside the short-block M126: %v", spec.id, err)
		}
	}
}

// TestLegacyCurvesDoNotDisturbTheLegacyBaseImage is the mirror of
// TestTripModelsDoNotDisturbTheDefaultAdvancedImage: the legacy curve models
// are APPENDED, so every register the plain legacy sim serves keeps the address
// it has always had.
func TestLegacyCurvesDoNotDisturbTheLegacyBaseImage(t *testing.T) {
	plain := &RegisterMap{regs: make(map[uint16]uint16)}
	populateSolar(plain, 5000, "")

	withCurves := newLegacyCurveSim(t, 5000, LegacyCurveOptions{})

	base := uint16(sunspec.SunSpecBase)
	for addr := base; addr <= base+254; addr++ {
		want := plain.Get(addr)
		got := withCurves.Regs.Get(addr)
		if want == sunspec.EndMarker {
			// The end marker is the ONE register that legitimately moves: the
			// chain is longer. Everything before it must be identical.
			break
		}
		if got != want {
			t.Fatalf("register %d differs: plain legacy %d, legacy-curves %d", addr, want, got)
		}
	}
}

// TestLegacyCurvesServeNo7xxModel pins the generation split. A device serving
// both 705 and 126 would make every per-generation conformance binding
// ambiguous, so this profile must serve exactly one of the two families.
func TestLegacyCurvesServeNo7xxModel(t *testing.T) {
	ss := newLegacyCurveSim(t, 5000, LegacyCurveOptions{})
	for _, m := range []uint16{701, 702, 703, 704, 705, 706, 711, 712} {
		if ss.Regs.Get(ss.legacy.end) == m {
			t.Fatalf("the legacy-curve profile serves 7xx model %d", m)
		}
	}
	// Walk the served chain and assert the model set outright.
	got := map[uint16]bool{}
	addr := uint16(sunspec.SunSpecBase) + 2
	for i := 0; i < 64; i++ {
		id := ss.Regs.Get(addr)
		if id == sunspec.EndMarker {
			break
		}
		got[id] = true
		addr += 2 + ss.Regs.Get(addr+1)
	}
	for _, m := range []uint16{701, 702, 703, 704, 705, 706, 707, 708, 709, 710, 711, 712} {
		if got[m] {
			t.Errorf("the legacy-curve profile serves 7xx model %d", m)
		}
	}
	for _, m := range []uint16{1, 103, 120, 121, 122, 123, 126, 127, 128, 129, 130, 131, 132, 134, 160} {
		if !got[m] {
			t.Errorf("the legacy-curve profile does NOT serve model %d", m)
		}
	}
}

// TestLegacySnapshotDecodesThroughTheShippedParser pins that /state and the
// wire cannot disagree: the snapshot is decoded, never re-derived.
func TestLegacySnapshotDecodesThroughTheShippedParser(t *testing.T) {
	ss := newLegacyCurveSim(t, 5000, LegacyCurveOptions{NCrv: 2})
	st := ss.legacySnapshot()
	if st == nil || len(st.Curves) != len(legacyCurveSpecs) {
		t.Fatalf("snapshot carries %v curve models, want %d", st, len(legacyCurveSpecs))
	}
	for _, cs := range st.Curves {
		if cs.Geometry != "ok" {
			t.Errorf("M%d snapshot geometry: %s", cs.Model, cs.Geometry)
		}
		if cs.ActCrv != 1 || len(cs.Banks) != 2 {
			t.Errorf("M%d snapshot ActCrv=%d banks=%d", cs.Model, cs.ActCrv, len(cs.Banks))
		}
		if !cs.Banks[0].Live || cs.Banks[1].Live {
			t.Errorf("M%d snapshot marks the wrong bank live", cs.Model)
		}
	}
	if len(st.MPPT) != legacyMPPTModules {
		t.Errorf("model 160 reports %d MPPT modules, want %d", len(st.MPPT), legacyMPPTModules)
	}
	if _, err := json.Marshal(st); err != nil {
		t.Errorf("the legacy snapshot does not marshal: %v", err)
	}
}
