package sim

// shortblock_test.go — the ORACLE for the RUNTIME short-block lever
// (curve12x.go's SetLegacyShortBlock / the legacy_short_block fault kind).
//
// # What was not exercisable before
//
// The RC0 §9.5 bench battery recorded row 8 (five legacy-curve fault
// injections, one of them the short block) BLOCKED, and added a structural note
// for whoever runs it next:
//
//	"short block has no runtime lever — -der-legacy-shortblock 126 is a startup
//	 flag only, so that sub-case needs its own modsim restart."
//
// A restart is not a neutral act on a bench: it drops the gateway's southbound
// session, re-runs adoption, and re-enters the device into the inventory, so
// the fault the row wants to observe — a device presenting an incoherent
// geometry MID-SESSION, to a gateway that has already adopted it — is not the
// fault the restart produces.
//
// # What the lever has to do, and why these rows check it that way
//
// LegacyCurveOptions.ShortBlockModel's own doc explains why it was a
// constructor posture, and it is right: "the pathology is a whole-image
// property: a device that publishes short blocks declares an L that matches
// them, and every register after that model moves. Arming it at run time would
// either leave the chain incoherent (an L that lies about a full-size layout,
// which is a DIFFERENT defect) or require re-laying the image under a live
// Modbus server."
//
// The lever takes the second option, so these rows check exactly the property
// the first option would have broken: after the lever fires the device is
// INTERNALLY COHERENT and wrong in only the one way the fail-closed geometry
// gate can catch. Every assertion below is taken THROUGH THE MODBUS HANDLER, by
// walking the chain the way a client does, because a re-lay that satisfied the
// Go descriptors and not the wire would be the exact defect being avoided.

import (
	"fmt"
	"strings"
	"testing"

	"lexa-proto/sunspec"
)

// legacyRegionDump renders every non-zero register of the served legacy-curve
// region as one comparable string, so a row can assert that clearing the lever
// restored the image BYTE FOR BYTE rather than merely restoring its shape.
//
// The region only — not the whole map — because the animation owns the
// measurement registers ahead of it, and a whole-map comparison would be
// asserting that time had not passed.
func legacyRegionDump(ss *SolarServer) string {
	geom := ss.legacy.layout()
	var b strings.Builder
	for a := uint32(ss.legacy.start); a <= uint32(geom.end); a++ {
		if v := ss.Regs.Get(uint16(a)); v != 0 {
			fmt.Fprintf(&b, "%d=%d;", a, v)
		}
	}
	return b.String()
}

// walkChain reads the SunSpec model chain off the wire and returns, in order,
// the (model id, declared L, data-block base) of every model — the walk a
// gateway's discovery does, and the only view of the device that matters here.
func walkChain(t *testing.T, r *RegisterMap) []struct {
	ID, L, Base uint16
} {
	t.Helper()
	var out []struct{ ID, L, Base uint16 }
	// SunSpecBase+0..1 is the "SunS" marker; the first model header is at +2.
	cursor := uint16(sunspec.SunSpecBase) + 2
	for i := 0; i < 64; i++ {
		hdr := mbReadMap(t, r, cursor, 2)
		if hdr[0] == sunspec.EndMarker {
			return out
		}
		out = append(out, struct{ ID, L, Base uint16 }{hdr[0], hdr[1], cursor + 2})
		cursor += 2 + hdr[1]
	}
	t.Fatalf("the model chain did not terminate within 64 models — the re-lay left the image incoherent")
	return nil
}

// chainModel finds one model in a walk.
func chainModel(t *testing.T, chain []struct{ ID, L, Base uint16 }, id uint16) (uint16, uint16) {
	t.Helper()
	for _, m := range chain {
		if m.ID == id {
			return m.L, m.Base
		}
	}
	t.Fatalf("model %d is not on the wire (chain: %v)", id, chain)
	return 0, 0
}

// TestLegacyShortBlockLeverRelaysTheImageAtRuntime is row 8's missing lever.
func TestLegacyShortBlockLeverRelaysTheImageAtRuntime(t *testing.T) {
	ss, _ := newRevSolarLegacyCurves(t, 8000)
	r := ss.Regs

	before := walkChain(t, r)
	beforeImage := legacyRegionDump(ss)

	// The device starts coherent: (L − hdr) / NCrv IS model 126's spec block
	// length, which is what makes every offset a gateway computes correct.
	l126, _ := chainModel(t, before, sunspec.ModelVoltVarLegacy)
	hdrLen := sunspec.L126Hdr.Len()
	if got := (int(l126) - hdrLen) / legacyNCrvDefault; got != sunspec.Blk126 {
		t.Fatalf("before the lever, 126's bank stride is %d, want the spec %d", got, sunspec.Blk126)
	}

	// ── Arm, mid-session, through the same POST /fault surface as the other
	// four legacy-curve kinds.
	if err := ss.ApplyFault([]byte(`{"kind":"legacy_short_block","model":126}`)); err != nil {
		t.Fatalf("arm legacy_short_block: %v", err)
	}

	after := walkChain(t, r)
	l126b, base126 := chainModel(t, after, sunspec.ModelVoltVarLegacy)
	if l126b == l126 {
		t.Fatalf("126's declared length is still %d after the lever — nothing was re-laid", l126b)
	}
	// THE PATHOLOGY, exactly: the arithmetic divides cleanly and gives the
	// WRONG stride. A device whose L did not divide cleanly would be a
	// different (and much easier) defect.
	stride := (int(l126b) - hdrLen)
	if stride%legacyNCrvDefault != 0 {
		t.Fatalf("(L−hdr) = %d does not divide by NCrv = %d; the point of the posture is that the "+
			"arithmetic SUCCEEDS and is wrong", stride, legacyNCrvDefault)
	}
	if stride/legacyNCrvDefault == sunspec.Blk126 {
		t.Fatalf("126's bank stride is still the spec %d after the lever", sunspec.Blk126)
	}
	// The header still declares the real NCrv/NPt — the device is coherent
	// with itself, which is what "wrong in exactly one way" means.
	if got := mbReadMap(t, r, base126+uint16(sunspec.L126Hdr.Offset("NCrv")), 1)[0]; int(got) != legacyNCrvDefault {
		t.Errorf("126 NCrv = %d after the re-lay, want %d", got, legacyNCrvDefault)
	}
	if got := mbReadMap(t, r, base126+uint16(sunspec.L126Hdr.Offset("NPt")), 1)[0]; int(got) != legacyNPt {
		t.Errorf("126 NPt = %d after the re-lay, want %d", got, legacyNPt)
	}

	// EVERY MODEL AFTER IT MOVED, and every one of them is still coherent —
	// this is the half a runtime lever gets wrong if it patches one header.
	for _, m := range after {
		if m.ID == sunspec.ModelVoltVarLegacy {
			continue
		}
		var bl int
		switch m.ID {
		case sunspec.ModelLVRTLegacy:
			bl = sunspec.Blk129
		case sunspec.ModelHVRTLegacy:
			bl = sunspec.Blk130
		case sunspec.ModelWattPFLegacy:
			bl = sunspec.Blk131
		case sunspec.ModelVoltWattLegacy:
			bl = sunspec.Blk132
		case sunspec.ModelFreqWattLegacy:
			bl = sunspec.Blk134
		default:
			continue
		}
		if got := (int(m.L) - hdrLen) / legacyNCrvDefault; got != bl {
			t.Errorf("model %d's stride is %d after the re-lay, want the spec %d — only the NAMED "+
				"model may be short", m.ID, got, bl)
		}
	}
	moved := 0
	for _, b := range before {
		for _, a := range after {
			if a.ID == b.ID && a.Base != b.Base {
				moved++
			}
		}
	}
	if moved == 0 {
		t.Error("no model moved after the re-lay; shortening 126 must shift everything after it")
	}

	// ── Clear: the device goes back to the image it served before, byte for
	// byte over its whole legacy region. A lever that could not be undone would
	// make the rest of the row unrunnable without the restart it exists to
	// avoid.
	if err := ss.ApplyFault([]byte(`{"kind":"legacy_short_block","clear":true}`)); err != nil {
		t.Fatalf("clear legacy_short_block: %v", err)
	}
	if got := legacyRegionDump(ss); got != beforeImage {
		t.Errorf("clearing the lever did not restore the served image:\n before: %s\n  after: %s",
			beforeImage, got)
	}
}

// TestLegacyShortBlockLeverRefusesAModelItDoesNotServe pins the input domain. A
// lever that accepted 705 on a 12x device, or a typo'd 1266, would silently
// re-lay the image with no short block at all and the row would report a
// geometry PASS it never tested.
func TestLegacyShortBlockLeverRefusesAModelItDoesNotServe(t *testing.T) {
	ss, _ := newRevSolarLegacyCurves(t, 8000)
	for _, body := range []string{
		`{"kind":"legacy_short_block","model":705}`,
		`{"kind":"legacy_short_block","model":1266}`,
		`{"kind":"legacy_short_block"}`,
	} {
		if err := ss.ApplyFault([]byte(body)); err == nil {
			t.Errorf("%s was accepted; a short block must name a legacy curve model this device serves", body)
		}
	}

	// And on a sim that serves no legacy curve family at all, it is refused BY
	// NAME rather than falling through to "unknown kind" — the same
	// offered/refused-by-name discipline modsim's relay layers use, so a
	// scenario can report SKIP-with-reason instead of mistaking "we never
	// asked" for "the device passed".
	adv, _ := newRevSolarAdvanced(t, 8000)
	err := adv.ApplyFault([]byte(`{"kind":"legacy_short_block","model":126}`))
	if err == nil {
		t.Fatal("an advanced 7xx sim accepted a legacy short block")
	}
	if got := err.Error(); got == "" {
		t.Fatal("the refusal carries no reason")
	}
}

// TestLegacyShortBlockLeverRearmsTheReversionTimers is the row that catches the
// coupling a reviewer would look for: a reversion timer descriptor carries a
// BASE ADDRESS, and the re-lay moves five of the six legacy curve models. A
// lever that re-laid the image and left the timer table pointing at the old
// addresses would count a 129 timer down against 130's registers.
func TestLegacyShortBlockLeverRearmsTheReversionTimers(t *testing.T) {
	ss, tb := newRevSolarLegacyCurves(t, 8000)
	r := ss.Regs

	if err := ss.ApplyFault([]byte(`{"kind":"legacy_short_block","model":126}`)); err != nil {
		t.Fatalf("arm legacy_short_block: %v", err)
	}

	chain := walkChain(t, r)
	_, base134 := chainModel(t, chain, sunspec.ModelFreqWattLegacy)

	hdr := mbReadMap(t, r, base134, uint16(sunspec.L134Hdr.Len()))
	hv := sunspec.L134Hdr.View(hdr)
	hv.SetU16At(sunspec.L134Hdr.Offset("ActCrv"), 1)
	hv.SetU16At(sunspec.L134Hdr.Offset("ModEna"), 1)
	hv.SetU16At(sunspec.L134Hdr.Offset("RvrtTms"), 30)
	mbWriteMap(t, r, base134, hdr...)

	tb.Advance(30 * 1e9) // 30 s, in nanoseconds
	fired := ss.reversionStep()
	if len(fired) != 1 || fired[0] != fmt.Sprintf("%d", sunspec.ModelFreqWattLegacy) {
		t.Fatalf("expired timers = %v, want exactly [%d] — the timer table must follow the re-lay",
			fired, sunspec.ModelFreqWattLegacy)
	}
	if got := mbReadMap(t, r, base134+uint16(sunspec.L134Hdr.Offset("ActCrv")), 1)[0]; got != 0 {
		t.Errorf("134 ActCrv = %d after expiry at its NEW base, want 0", got)
	}
}
