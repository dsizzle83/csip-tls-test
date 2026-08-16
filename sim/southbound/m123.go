package sim

// m123.go — model 123 (Immediate Inverter Controls), laid down from the LAYOUT
// rather than from hand offsets.
//
// ── Why this file exists, and why it exists as ONE function ────────────────
//
// Three sims built their own model-123 block — solar.go, battery.go, sim.go —
// each with its own `const m123Len = 23` and its own list of `r.Set(base +
// sunspec.M123_X, v)` calls. That length was wrong (the published model has 24
// data registers) and so was every offset it was paired with, because
// lexa-proto's M123_* constants were a hand transcription that had never been
// compared to the standard: it led with WMaxLimPct where the published model
// leads with the Conn group, so every point sat between 1 and 9 registers away
// from where a conformant device holds it.
//
// NOTHING CAUGHT IT FOR AS LONG AS IT LASTED, and the reason is this file's
// whole justification. The product wrote through those same constants, so the
// bench and the product agreed with each other and both disagreed with the
// standard — the classic shared-oracle blindness, with a fixture on one side
// instead of a second decoder. A conformant legacy DER met by that gateway
// would have had its failsafe CEASE land on VArPct_WinTms and stay energized,
// with the L1 echo proof re-reading the same wrong register and reporting the
// disconnect as PROVEN. lexa-proto 32150e1 fixed the map; this closes the
// fixture half.
//
// The constants are correct now, so the mechanical fix would have been to leave
// three copies alone and change three `23`s to `24`. That is declined on
// purpose. Three copies of a register map is three chances to drift, and the
// defect this file is cleaning up is exactly what drift looks like when nothing
// compares the copy to the source. So there is one populator, it derives every
// offset from sunspec.L123 BY NAME through the layout's own View, and it never
// mentions a numeric offset at all — a future re-ordering of the model moves
// this fixture with it, silently and correctly, which is precisely what the old
// code could not do.

import "lexa-proto/sunspec"

// M123Defaults is the resting state a sim's immediate-controls block is
// published in. Zero values are meaningful here and are the intended resting
// state for every point the caller does not name.
type M123Defaults struct {
	// WMaxLimPctRaw is the active-power limit register's RAW value, paired with
	// WMaxLimPctSF. It is raw rather than a percentage because the two sims
	// disagree about the resting value on purpose: the solar inverter rests at
	// 10000 (=100.00 %, "no curtailment") with the enable SET, and the battery
	// rests at 0 with the enable CLEAR so the gateway's first write is what
	// takes control.
	WMaxLimPctRaw uint16
	// WMaxLimPctSF is the limit's scale factor, as a signed power of ten.
	WMaxLimPctSF int16
	// WMaxLimEna is the limit's enable enum (1 = the limit governs).
	WMaxLimEna uint16
	// Conn is the connect register: 1 = connected, 0 = disconnected. This is
	// the register the product's failsafe CEASE writes on a 704-less pack.
	Conn uint16
}

// m123OutPFSetSF / m123VArPctSF are the scale factors this fixture publishes
// for the two function groups it does not command.
//
// They are published rather than left zero because a scale factor of 0 is a
// LEGAL reading meaning 10^0, not an absent one — a consumer scaling by it gets
// a wrong number rather than a refusal. -3 on a power factor gives the
// thousandths every SunSpec PF point uses, and -2 on the reactive percentages
// matches the limit's own hundredths.
var (
	m123OutPFSetSF int16 = -3
	m123VArPctSF   int16 = -2
)

// m123UnityPF is the resting OutPFSet: a displacement power factor of 1.000 at
// SF -3. Zero would be a legal encoding of a power factor of zero — a machine
// pushing pure reactive power — which is not a resting state, and is the shape
// of fixture value that gets read as a device characteristic later.
const m123UnityPF = 1000

// M123VArPctModVArMax is VArPct_Mod's selector for the VArMaxPct member of the
// reactive trio (per cent of VArMax).
//
// THE REACTIVE VALUE IS A MODE-SELECTED TRIO and that is half of how a 24-point
// model became a 23-point one: the old transcription collapsed VArWMaxPct,
// VArMaxPct and VArAvalPct into one "M123_VArPct" and lost a register doing it.
// The device publishes all three and names which one it applies:
//
//	VArPct_Mod = 1 (WMax)    → VArWMaxPct
//	VArPct_Mod = 2 (VArMax)  → VArMaxPct
//	VArPct_Mod = 3 (VArAval) → VArAvalPct
//
// This fixture rests at 2, which is the mode the one real consumer writes
// (lexa-gw's reconciler pairs VArPct_Mod = 2 with the VArMaxPct register, which
// is why lexa-proto's M123_VArPct compatibility alias is defined as VArMaxPct
// and is correct only under that pairing). Publishing a mode selector that
// disagreed with the register the fixture populates would hand every reader a
// device whose own two statements about itself conflict.
const M123VArPctModVArMax = 2

// PopulateM123 writes a published-shape model-123 block — header and data — at
// addr, and returns the number of registers it consumed.
//
// Every point is addressed through sunspec.L123 by NAME. The block's length is
// the layout's own Len(), so a fixture can no longer declare a length the model
// does not have; that mismatch is what a reader of a short block sees first and
// is the signature the referee's own decoder keys its "this is NOT that model"
// disclosure on (internal/invariant's legacyctl.go, M123Short).
func PopulateM123(r *RegisterMap, addr uint16, d M123Defaults) uint16 {
	body := make([]uint16, sunspec.L123.Len())
	v := sunspec.L123.View(body)

	// ── The connect group ──
	//
	// Conn is the point the whole map was wrong about, and it leads the model.
	// The two timing companions rest at 0: no connect window and no reversion,
	// so nothing in this block counts down on its own. That matters to a
	// refusal row, whose fingerprint spans the whole block and would move on a
	// live timer with no write having happened.
	v.SetEnum("Conn", d.Conn)
	v.SetEnum("Conn_WinTms", 0)
	v.SetEnum("Conn_RvrtTms", 0)

	// ── The active-power limit group ──
	v.SetEnum("WMaxLimPct", d.WMaxLimPctRaw)
	v.SetEnum("WMaxLimPct_SF", uint16(d.WMaxLimPctSF))
	// The published point is spelled WMaxLim_Ena, with no "Pct" — the layout
	// carries the spec's spelling even though lexa-proto's constant keeps the
	// old one for its callers' sake. Naming it the layout's way here is what
	// makes this a lookup against the standard rather than against a habit.
	v.SetEnum("WMaxLim_Ena", d.WMaxLimEna)
	v.SetEnum("WMaxLimPct_WinTms", 0)
	v.SetEnum("WMaxLimPct_RvrtTms", 0)
	v.SetEnum("WMaxLimPct_RmpTms", 0)

	// ── The fixed power-factor group, published and not commanded ──
	v.SetEnum("OutPFSet", m123UnityPF)
	v.SetEnum("OutPFSet_SF", uint16(m123OutPFSetSF))
	v.SetEnum("OutPFSet_Ena", 0)
	v.SetEnum("OutPFSet_WinTms", 0)
	v.SetEnum("OutPFSet_RvrtTms", 0)
	v.SetEnum("OutPFSet_RmpTms", 0)

	// ── The reactive trio, all three, with the mode that selects between them ──
	v.SetEnum("VArWMaxPct", 0)
	v.SetEnum("VArMaxPct", 0)
	v.SetEnum("VArAvalPct", 0)
	v.SetEnum("VArPct_Mod", M123VArPctModVArMax)
	v.SetEnum("VArPct_Ena", 0)
	v.SetEnum("VArPct_SF", uint16(m123VArPctSF))
	v.SetEnum("VArPct_WinTms", 0)
	v.SetEnum("VArPct_RvrtTms", 0)
	v.SetEnum("VArPct_RmpTms", 0)

	r.Set(addr, sunspec.ModelImmediateCtrl)
	r.Set(addr+1, uint16(len(body)))
	for i, w := range body {
		r.Set(addr+2+uint16(i), w)
	}
	return uint16(2 + len(body))
}

// M123Len is the model's data-block length, from the layout. Callers that need
// to bound an address range against the block (the battery's write hook) take
// it from here rather than restating a number.
func M123Len() uint16 { return uint16(sunspec.L123.Len()) }
