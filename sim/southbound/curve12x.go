package sim

// curve12x.go — the LEGACY SunSpec curve family: models 126/127/128/129/130/
// 131/132/134 and the 160 MPPT extension, served with their REAL register
// semantics.
//
// WHY THIS FILE EXISTS
//
// Until now `-der-models legacy` meant "no curves at all": the sim served
// 1/120/121/122/103/123 and nothing that stores a curve, and the 7xx surface
// (solar_adv.go) served 705/706/711/712. So the product's decision to answer
// `adopt_state=unsupported` for a legacy curve axis had NO falsifiable bench —
// there was no device on which the axis could have been executed, so a row that
// measured nothing and a row that measured a correct refusal read identically.
// This file is the device that makes the difference visible.
//
// THE TWO IDIOMS ARE NOT THE SAME SHAPE, AND THAT IS THE WHOLE POINT
//
// The 7xx curve models this sim already serves share one geometry and one
// commit protocol: nested Crv[NCrv]{Pt[NPt]}, a read-only live curve at index
// 0, a writable staging curve, and the §3.1.2 AdptCrvReq/AdptCrvRslt handshake
// that promotes one into the other. `populateCurveModel` encodes exactly that.
// The legacy 12x family agrees with none of it:
//
//	 1. The repeat is FLAT. One fixed-size block per bank (54 registers on
//	    126/131/132, 50 on 129/130, 58 on 134), with the points inlined as
//	    parallel arrays V1..V20 / VAr1..VAr20 — twenty slots ALWAYS, whatever
//	    the device's NPt says.
//	 2. There is NO staging bank and NO adopt handshake. `ActCrv` selects which
//	    bank is live, by 1-based index, and `ModEna` bit 0 switches the function
//	    on. A curve write is therefore DESTRUCTIVE to a live bank, which is why
//	    the write sequencing (lexa-proto derbase.WriteLegacyCurve) has a Case A
//	    and a Case B at all.
//	 3. `ModEna` is a bitfield16, not an enum16. It coincides numerically with
//	    the 7xx `Ena` at the value 1 and differs in TYPE: a device that sets a
//	    reserved bit is still enabled, and a reader that compares the whole word
//	    against 1 reads it as disabled.
//	 4. `DeptRef` is 1-BASED here (126: 1 %WMax, 2 %VArMax, 3 %VArAval; 132:
//	    1 %WMax, 2 %WAvail) against the 7xx enum's 0-based one. It is a
//	    translation in both directions, never a copy.
//	 5. Every bank carries its own `ReadOnly` flag, at an offset that is per
//	    MODEL and not per block length: +53 on 126 and 132, +49 on 129/130, +52
//	    on 131 (which puts its Pad last), +57 on 134. Nothing here transcribes
//	    those numbers — every offset comes from lexa-proto's declarative
//	    Layouts, which its own TestLayoutsMatchVendoredSpec binds to the
//	    vendored SunSpec JSON.
//
// Bending `curveModelSpec` around that would have made the common path harder
// to read for the four models it already serves correctly, so — exactly as
// trip1547.go did for the 707-710 geometry — the legacy family gets its own
// populator, its own descriptor and its own commit semantics.
//
// NO CURVE PHYSICS. A volt-var curve installed here moves no measured var, the
// same constraint the 7xx curve models have always had (RC0_PLAN §D2). Every
// oracle over this device is therefore a REGISTER and SELECTION-STATE oracle:
// which bank holds what, which bank ActCrv names, whether ModEna bit 0 is set.
// A caller that wants "the DER's output followed the curve" is asking a
// question this bench cannot answer and must say so rather than answer a
// different one.
//
// THE FIXTURE'S SCALE-FACTOR CONVENTION, STATED SO IT IS NOT MISTAKEN FOR A
// CLAIM ABOUT FIELD DEVICES. Curve-point scale factors are seeded so that the
// device's ENGINEERING value equals the number a conformance row publishes on
// the wire: V_SF = 0 (%VRef in whole percent), DeptRef_SF = 0, W_SF = 0,
// PF_SF = −2 (a power factor of 0.95 is register 95), Hz_SF = −2 (60.00 Hz is
// register 6000). populateCurveModel already makes the same choice for
// 705/706/712 and for the same reason: the southbound referee compares raw
// published values against device engineering values with NO axis
// re-interpretation of its own (see suitecsip's critDEREffectViaCurveOracle),
// so a fixture whose units disagreed with the wire would make every curve row
// fail for a reason that is about the fixture. A real 126 with V_SF = −1 is a
// perfectly conformant device and this file's geometry handles it; it is the
// scale-factor VALUES that are a fixture choice, not the plumbing.

import (
	"encoding/json"
	"fmt"
	"log"
	"sync"
	"sync/atomic"

	modbuslib "github.com/simonvetter/modbus"

	"lexa-proto/sunspec"
)

const (
	// legacyNPt is the device's declared NPt for every legacy curve model: how
	// many of the twenty physical point slots it supports. Ten matches advNPt
	// (the 7xx sim's), so a curve that fits one generation fits the other and a
	// row re-bound from 705 to 126 is not silently re-sized on the way.
	legacyNPt = 10

	// legacyNCrvDefault is the default number of banks. TWO, not one, so the
	// PREFERRED write sequence (Case A: write an idle bank, then switch ActCrv
	// atomically) is the one a default bench exercises. NCrv = 1 — the
	// field-common and genuinely harder case, where the live bank must be
	// rewritten in place — is reachable with -der-legacy-ncrv 1.
	legacyNCrvDefault = 2

	// The per-bank ReadOnly enum, spelled out so a reader of this file does not
	// have to remember which way round it is.
	legacyBankReadWrite uint16 = 0
	legacyBankReadOnly  uint16 = 1
)

// legacyCurveSpec is the static description of one legacy curve model.
//
// blockLen is NOT derived from the layout here: it is lexa-proto's own Blk*
// constant, which that package's spec test binds to the vendored JSON. Deriving
// it would give this fixture a second opinion about a number the decoder
// already owns, and a sim whose stride disagreed with the parser serves a block
// that round-trips through nothing.
type legacyCurveSpec struct {
	id        uint16
	hdr, bank *sunspec.Layout
	blockLen  int
	npt       int
	sfs       map[string]int16

	// seed writes this model's DEFAULT curve into bank i. It goes through
	// lexa-proto's own encoder rather than poking registers, for the same
	// reason populateTripModel does: a fixture that encoded a block the shipped
	// parser cannot read would be a fixture nobody else can see.
	//
	// The seeded content is deliberately DIFFERENT from anything a conformance
	// row commands, so an ActCrv switch or a bank rewrite is observable as a
	// change rather than as a coincidence — the same trick populateCurveModel
	// plays with its index-0 default.
	seed func(regs []uint16, bank int) error
}

// legacyCurveSpecs is the legacy curve-model table.
//
// 129 and 130 carry the IEEE 1547-2018 Category III must-disconnect defaults
// (Table 11: UV2 0.50 pu / 2 s, UV1 0.88 pu / 21 s; OV1 1.10 pu / 13 s,
// OV2 1.20 pu / 0.16 s) — the same numbers trip1547.go transcribes for
// 707/708, in the legacy block's own (time-FIRST) point order. The shaping
// models carry deliberately-uncommanded curves.
var legacyCurveSpecs = []legacyCurveSpec{
	{
		id: sunspec.ModelVoltVarLegacy, hdr: sunspec.L126Hdr, bank: sunspec.L126Crv,
		blockLen: sunspec.Blk126, npt: legacyNPt,
		// V_SF / DeptRef_SF = -2. The CSIP CTP curve settings are stated in
		// HUNDREDTHS (Figure 6's 9570 with xMultiplier -2 is 95.70 %VRef), and
		// the legacy encoders are the CHECKED tier: a value the device's own
		// scale factor cannot represent is REFUSED, never silently rounded. A
		// fixture at SF 0 would therefore make every conformant curve
		// unwritable and blame the writer for the fixture's granularity.
		sfs: map[string]int16{"V_SF": -2, "DeptRef_SF": -2, "RmpIncDec_SF": 0},
		seed: func(regs []uint16, bank int) error {
			_, _, err := sunspec.EncodeLegacy126Curve(regs, bank, sunspec.LegacyVoltVarCurve{
				DeptRef: 1, // %WMax — the legacy 1-based numbering
				CrvNam:  "SIMDFLT",
				Pts: []sunspec.LegacyCurvePoint{
					{X: 95, Y: 30}, {X: 105, Y: -30},
				},
			})
			return err
		},
	},
	{
		id: sunspec.ModelLVRTLegacy, hdr: sunspec.L129Hdr, bank: sunspec.L129Crv,
		blockLen: sunspec.Blk129, npt: legacyNPt,
		sfs: map[string]int16{"Tms_SF": -2, "V_SF": 0},
		seed: func(regs []uint16, bank int) error {
			_, _, err := sunspec.EncodeLegacy129Curve(regs, bank, sunspec.LegacyRideThroughCurve{
				CrvNam: "SIMLVRT",
				// (must-disconnect duration s, %VRef) — TIME FIRST, which is the
				// opposite order from CSIP's opModLVRTMustTrip (x = duration,
				// y = voltage) only by accident of naming.
				Pts: []sunspec.LegacyCurvePoint{{X: 2, Y: 50}, {X: 21, Y: 88}},
			})
			return err
		},
	},
	{
		id: sunspec.ModelHVRTLegacy, hdr: sunspec.L130Hdr, bank: sunspec.L130Crv,
		blockLen: sunspec.Blk130, npt: legacyNPt,
		sfs: map[string]int16{"Tms_SF": -2, "V_SF": 0},
		seed: func(regs []uint16, bank int) error {
			_, _, err := sunspec.EncodeLegacy130Curve(regs, bank, sunspec.LegacyRideThroughCurve{
				CrvNam: "SIMHVRT",
				Pts:    []sunspec.LegacyCurvePoint{{X: 13, Y: 110}, {X: 0.16, Y: 120}},
			})
			return err
		},
	},
	{
		id: sunspec.ModelWattPFLegacy, hdr: sunspec.L131Hdr, bank: sunspec.L131Crv,
		blockLen: sunspec.Blk131, npt: legacyNPt,
		// PF_SF = −2: a power factor is a number near 1, so the register holds
		// hundredths. This is the ONE legacy curve axis whose honest scale
		// factor is not zero, and the conformance row that targets it publishes
		// yMultiplier = −2 to match.
		sfs: map[string]int16{"W_SF": 0, "PF_SF": -2, "RmpIncDec_SF": 0},
		seed: func(regs []uint16, bank int) error {
			_, _, err := sunspec.EncodeLegacy131Curve(regs, bank, sunspec.LegacyWattPFCurve{
				CrvNam: "SIMWPF",
				Pts: []sunspec.LegacyCurvePoint{
					{X: 20, Y: 1.00}, {X: 80, Y: 0.90},
				},
			})
			return err
		},
	},
	{
		id: sunspec.ModelVoltWattLegacy, hdr: sunspec.L132Hdr, bank: sunspec.L132Crv,
		blockLen: sunspec.Blk132, npt: legacyNPt,
		sfs: map[string]int16{"V_SF": -2, "DeptRef_SF": -2, "RmpIncDec_SF": 0},
		seed: func(regs []uint16, bank int) error {
			_, _, err := sunspec.EncodeLegacy132Curve(regs, bank, sunspec.LegacyVoltWattCurve{
				DeptRef: 1, // %WMax
				CrvNam:  "SIMVW",
				// TWO points, where the conformance row that targets 132
				// publishes three. The seeded default has to be distinguishable
				// from a commanded curve by more than the oracle's per-point
				// tolerance (1 % of the value plus half a unit), or a row would
				// fail on the second breakpoint while the first "matched" a
				// curve nobody commanded — a FAIL for very nearly the wrong
				// reason. A different POINT COUNT cannot be absorbed by any
				// tolerance, which is why every seed is shaped that way.
				Pts: []sunspec.LegacyCurvePoint{
					{X: 103, Y: 100}, {X: 114, Y: 20},
				},
			})
			return err
		},
	},
	{
		id: sunspec.ModelFreqWattLegacy, hdr: sunspec.L134Hdr, bank: sunspec.L134Crv,
		blockLen: sunspec.Blk134, npt: legacyNPt,
		// Hz_SF = −2: 60.00 Hz is register 6000. The curve's x values are
		// ABSOLUTE frequency; WRefStrHz/WRefStopHz in the same block are
		// DEVIATIONS from nominal. Two conventions inside one block, and this
		// fixture honours both.
		sfs:  map[string]int16{"Hz_SF": -2, "W_SF": 0, "RmpIncDec_SF": 0},
		seed: nil, // seeded by populateLegacyCurveModel, which knows WRef
	},
}

// legacyBankBlock describes one served legacy curve model, for the write
// interception and the snapshot.
type legacyBankBlock struct {
	id        uint16
	base      uint16 // data-block base address
	hdr, bank *sunspec.Layout
	blockLen  int
	hdrLen    int
	ncrv      int
	npt       int
	dataLen   int

	actCrvOff int // hdr offset of ActCrv
	modEnaOff int // hdr offset of ModEna
	roOff     int // per-bank offset of ReadOnly
	snptWOff  int // per-bank offset of SnptW (134 only; −1 elsewhere)
}

// bankBase returns the register address of bank i (1-based).
func (b legacyBankBlock) bankBase(i int) uint16 {
	return b.base + uint16(b.hdrLen+b.blockLen*(i-1))
}

// bankOf reports which 1-based bank an absolute register address falls in, and
// false for an address in the header or outside the model.
func (b legacyBankBlock) bankOf(addr uint16) (int, bool) {
	if addr < b.base || addr >= b.base+uint16(b.dataLen) {
		return 0, false
	}
	off := int(addr - b.base)
	if off < b.hdrLen {
		return 0, false
	}
	return (off-b.hdrLen)/b.blockLen + 1, true
}

// LegacyCurveOptions configures the legacy-curve DER profile.
type LegacyCurveOptions struct {
	// NCrv is the number of banks every curve model declares. 0 means
	// legacyNCrvDefault (2). One bank is the field-common Case-B shape.
	NCrv int

	// ShortBlockModel, when non-zero, lays THAT model's banks out at a block
	// length sized to its own NPt instead of the spec's fixed twenty slots —
	// the geometry pathology §1.8 of the design describes and the fail-closed
	// gate exists to refuse.
	//
	// It is a CONSTRUCTOR posture rather than a runtime fault on purpose. The
	// pathology is a whole-image property: a device that publishes short blocks
	// declares an L that matches them, and every register after that model
	// moves. Arming it at run time would either leave the chain incoherent (an
	// L that lies about a full-size layout, which is a DIFFERENT defect) or
	// require re-laying the image under a live Modbus server. Built at
	// construction, the served device is internally consistent and wrong in
	// exactly the one way the gate must catch: (L − 10) / NCrv is a whole
	// number and is not the model's spec block length.
	ShortBlockModel uint16
}

// NCrvOrDefault resolves the configured bank count, applying the default.
func (o LegacyCurveOptions) NCrvOrDefault() int {
	if o.NCrv <= 0 {
		return legacyNCrvDefault
	}
	return o.NCrv
}

// ── The legacy fault layer ───────────────────────────────────────────────────

// legacyFaults holds the armed state of the legacy-curve fault kinds. Each one
// exists to make a specific product-side check FALSIFIABLE — a check nothing
// can break is a check nobody has tested.
type legacyFaults struct {
	mu sync.Mutex
	// actCrvIgnored: a write to ActCrv ACKs and the register does not move, so
	// a gateway that trusts its own write instead of verifying the read-back
	// believes it switched banks and did not.
	actCrvIgnored bool
	// modEnaSticky: ModEna bit 0 cannot be CLEARED, so a release — and the
	// Case-B abort, which must disable before it rewrites the live bank —
	// cannot complete.
	modEnaSticky bool
	// readOnlyIgnored: a bank flagged READONLY silently ACCEPTS writes. A
	// gateway that relies on the device to refuse, rather than on its own
	// ReadOnly preflight, overwrites a bank it was told not to touch.
	readOnlyIgnored bool
	// snptWStuck: model 134's SnptW reads back 1 however it is written, so the
	// curve's power base is the instantaneous output at trigger time rather
	// than WRef — a curve whose delivered shape depends on irradiance.
	snptWStuck bool
}

func (f *legacyFaults) snapshot() (actCrv, modEna, readOnly, snptW bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.actCrvIgnored, f.modEnaSticky, f.readOnlyIgnored, f.snptWStuck
}

// legacyFaultKinds are the fault kinds a legacy-curve sim advertises, on top of
// the plain solar set.
var legacyFaultKinds = map[FaultKind]bool{
	FaultLegacyActCrvIgnored:   true,
	FaultLegacyModEnaSticky:    true,
	FaultLegacyReadOnlyIgnored: true,
	FaultLegacySnptWStuck:      true,
}

// solarLegacyCurveFaultKinds is the full advertised set for a legacy-curve sim.
var solarLegacyCurveFaultKinds = func() map[FaultKind]bool {
	m := make(map[FaultKind]bool, len(solarFaultKinds)+len(legacyFaultKinds))
	for k := range solarFaultKinds {
		m[k] = true
	}
	for k := range legacyFaultKinds {
		m[k] = true
	}
	return m
}()

// parseShortBlockFault recognises a legacy_short_block body. It is separate
// from legacyFaults.apply because that layer holds BOOLEAN flags consulted on
// the write path, and this kind is not one: it re-lays the served register
// image, which only the SolarServer can do. Returning ok=true for a body of
// this kind — whatever else is wrong with it — is what lets ApplyFault refuse
// it BY NAME on a sim that serves no legacy curves, instead of letting it fall
// through to the fault controller and be reported as an unknown kind.
func parseShortBlockFault(body []byte) (FaultSpec, bool) {
	var spec FaultSpec
	if err := json.Unmarshal(body, &spec); err != nil {
		return FaultSpec{}, false // not ours to reject; the next layer will report it
	}
	return spec, spec.Kind == FaultLegacyShortBlock
}

// apply arms or clears a legacy fault. handled is false for a kind this layer
// does not own, so ApplyFault can pass it on rather than calling it unknown.
func (f *legacyFaults) apply(body []byte) (handled bool, err error) {
	var spec FaultSpec
	if err := json.Unmarshal(body, &spec); err != nil {
		return false, nil // not ours to reject; the next layer will report it
	}
	if !legacyFaultKinds[spec.Kind] {
		return false, nil
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	on := !spec.Clear
	switch spec.Kind {
	case FaultLegacyActCrvIgnored:
		f.actCrvIgnored = on
	case FaultLegacyModEnaSticky:
		f.modEnaSticky = on
	case FaultLegacyReadOnlyIgnored:
		f.readOnlyIgnored = on
	case FaultLegacySnptWStuck:
		f.snptWStuck = on
	}
	log.Printf("[fault] %s: legacy-curves armed=%v", spec.Kind, on)
	return true, nil
}

// ── The legacy curve layer ───────────────────────────────────────────────────

// legacyLayout is the CURRENT geometry of the served legacy-curve region:
// which model sits where, how wide its banks are, and where the region ends.
//
// It is a value that gets REPLACED WHOLE rather than a set of fields that get
// mutated, and it is read through an atomic pointer, because the runtime
// short-block lever re-lays the region while the Modbus goroutine is resolving
// writes against it. A reader that had picked up the old block table and the
// new base addresses would write into the gap between two models.
type legacyLayout struct {
	blocks []legacyBankBlock

	m127, m128, m160 uint16 // data-block bases, 0 when not served
	m160N            int
	end              uint16 // last register the legacy curve models occupy

	// shortBlockModel is the model whose banks are laid out short, or 0. It
	// rides on the geometry rather than beside it so that "which image is
	// served" is one atomically-swapped fact.
	shortBlockModel uint16
}

// legacyCurveLayer is the served legacy curve family plus its fault state. It
// hangs off SolarServer and is nil on every sim that does not serve the family,
// so nothing here can change the behaviour of an existing profile.
type legacyCurveLayer struct {
	faults legacyFaults

	// geom is the live geometry (see legacyLayout). Never nil after
	// construction.
	geom atomic.Pointer[legacyLayout]

	// The construction inputs a re-lay has to reproduce. Immutable after
	// construction, so they need no lock.
	start uint16  // first register of the legacy-curve region
	wmaxW float64 // model 134's WRef
	ncrv  int     // resolved bank count

	// relay serialises re-lays against each other. The atomic pointer makes a
	// re-lay invisible to READERS; this makes two concurrent re-lays impossible.
	relay sync.Mutex
}

// layout returns the live geometry.
func (l *legacyCurveLayer) layout() *legacyLayout { return l.geom.Load() }

// blockAt returns the block containing addr.
func (l *legacyCurveLayer) blockAt(addr uint16) (legacyBankBlock, bool) {
	for _, b := range l.layout().blocks {
		if addr >= b.base && addr < b.base+uint16(b.dataLen) {
			return b, true
		}
	}
	return legacyBankBlock{}, false
}

// bankIsReadOnly reads a bank's own ReadOnly declaration.
func (l *legacyCurveLayer) bankIsReadOnly(r *RegisterMap, b legacyBankBlock, i int) bool {
	if i < 1 || i > b.ncrv {
		return true
	}
	return r.Get(b.bankBase(i)+uint16(b.roOff)) == legacyBankReadOnly
}

// interceptWrite is the legacy family's half of SolarServer.interceptWrite.
//
// It takes responsibility for every write that lands anywhere in a legacy curve
// model, and applies it REGISTER BY REGISTER under the device's own rules:
// a bank the device declares READONLY refuses (nothing lands, and
// legacyWriteError turns that into a Modbus exception in the same transaction);
// the ReadOnly declaration itself is never writable, because it is the DEVICE's
// statement about its own banks and not a field a gateway owns; and each armed
// fault subverts exactly one of those rules.
//
// handled=false for an address outside the family, so every other write reaches
// the fault controller exactly as before.
func (l *legacyCurveLayer) interceptWrite(r *RegisterMap, start uint16, vals []uint16) (apply, handled bool) {
	if len(vals) == 0 {
		return true, false
	}
	if _, ok := l.blockAt(start); !ok {
		if _, ok := l.blockAt(start + uint16(len(vals)) - 1); !ok {
			return true, false
		}
	}
	actCrvIgnored, modEnaSticky, readOnlyIgnored, snptWStuck := l.faults.snapshot()

	for i, v := range vals {
		addr := start + uint16(i)
		b, ok := l.blockAt(addr)
		if !ok {
			r.Set(addr, v) // a straddling write: the part outside the family lands
			continue
		}
		off := int(addr - b.base)
		if bank, inBank := b.bankOf(addr); inBank {
			// The device's own write protection. Applied BEFORE the fault
			// checks so that "read-only bank" is the default answer and
			// readOnlyIgnored is visibly the exception.
			if l.bankIsReadOnly(r, b, bank) && !readOnlyIgnored {
				continue
			}
			bankOff := off - b.hdrLen - b.blockLen*(bank-1)
			if bankOff == b.roOff {
				continue // ReadOnly is the device's declaration, never a target
			}
			if snptWStuck && b.snptWOff >= 0 && bankOff == b.snptWOff {
				r.Set(addr, v|1) // written, and bit 0 comes back set anyway
				continue
			}
			r.Set(addr, v)
			continue
		}
		switch off {
		case b.actCrvOff:
			if actCrvIgnored {
				continue // ACKed, unmoved
			}
		case b.modEnaOff:
			if modEnaSticky && v&1 == 0 && r.Get(addr)&1 != 0 {
				continue // bit 0 cannot be cleared
			}
		}
		r.Set(addr, v)
	}
	return false, true
}

// legacyWriteError is the OnWriteError half of the read-only bank rule: the
// write above did not land, and the client is told so with a Modbus exception.
//
// A device that silently dropped the write would be modelling the
// readOnlyIgnored FAULT, not a conformant device — which is precisely the
// distinction the two must keep, so the honest device raises here and the fault
// suppresses it.
func (l *legacyCurveLayer) legacyWriteError(r *RegisterMap, start uint16, vals []uint16) error {
	if _, _, readOnlyIgnored, _ := l.faults.snapshot(); readOnlyIgnored {
		return nil
	}
	for i := range vals {
		addr := start + uint16(i)
		b, ok := l.blockAt(addr)
		if !ok {
			continue
		}
		if bank, inBank := b.bankOf(addr); inBank && l.bankIsReadOnly(r, b, bank) {
			return modbuslib.ErrIllegalDataAddress
		}
	}
	return nil
}

// ── Populate ─────────────────────────────────────────────────────────────────

// NewSolarServerLegacyCurves creates an animated PV inverter that serves the
// LEGACY curve family — 126/127/128/129/130/131/132/134 and the 160 MPPT
// extension — on top of the plain legacy models (1/103/120/121/122/123).
//
// It serves NO 7xx model, and that is deliberate rather than incidental: this
// is a device of the OTHER generation, and a conformance row that resolves its
// southbound target from the DER's own model chain has to be able to tell the
// two apart. A chimera serving 705 AND 126 is not a machine anyone ships, and
// on it every per-generation binding would be ambiguous.
func NewSolarServerLegacyCurves(listenURL string, wmaxW float64, serial string,
	opt LegacyCurveOptions) (*SolarServer, error) {
	regs := &RegisterMap{regs: make(map[uint16]uint16)}
	bases, cursor := populateSolarCore(regs, wmaxW, serial)
	layer := newLegacyCurveLayer(regs, cursor, wmaxW, opt)

	ss := &SolarServer{bases: bases, wmaxW: wmaxW, legacy: layer}
	ss.faults.label = "solar-legacy-curves"
	ss.faults.configureGate(bases.M123Base + sunspec.M123_WMaxLimPct_Ena)
	ss.faults.configureScale(bases.M103Base + sunspec.M103_W_SF)

	srv, err := newAnimatedServer(listenURL, regs, func(s *Server, r *RegisterMap, stop <-chan struct{}) {
		animateSolar(s, r, wmaxW, bases, ss.Cloud, ss.Becalmed, &ss.faults, stop)
	})
	if err != nil {
		return nil, err
	}
	ss.Server = srv
	regs.OnWriteAttempt = ss.interceptWrite
	regs.OnRead = ss.faults.transportRead
	ss.installLies() // the lying-device layer, in front of the fault hooks
	ss.chainLegacyWriteError(regs)
	ss.initSolarReversion(regs)
	go ss.reversionLoop(srv.stop)
	return ss, nil
}

// chainLegacyWriteError puts the read-only bank's honest refusal in FRONT of
// whatever else owns OnWriteError.
//
// installLies takes that hook for its own exception_on_applied_write kind,
// whose whole content is "the device DID the thing and says it did not". This
// device refuses FIRST, so the lying layer only ever gets to speak about a
// write that actually landed — which is the only kind of write its fault is
// about.
//
// It is a method rather than four lines inside the constructor because the
// hermetic fixtures wire the same rules onto a listener-less register map, and
// a test that exercised a write path the served device does not have would be
// testing nothing.
func (ss *SolarServer) chainLegacyWriteError(regs *RegisterMap) {
	layer := ss.legacy
	prev := regs.OnWriteError
	regs.OnWriteError = func(start uint16, vals []uint16) error {
		if err := layer.legacyWriteError(regs, start, vals); err != nil {
			return err
		}
		if prev != nil {
			return prev(start, vals)
		}
		return nil
	}
}

// newLegacyCurveLayer lays the legacy-curve region down at cursor and returns
// the layer that owns it, END MARKER INCLUDED.
//
// The end marker is written here rather than by the caller because a re-lay
// (SetLegacyShortBlock) MOVES it — shortening a model's banks shortens the
// whole region — and a marker written at one call site and moved at another is
// a marker that will one day be left at the old address, which is a chain that
// never terminates.
func newLegacyCurveLayer(r *RegisterMap, cursor uint16, wmaxW float64,
	opt LegacyCurveOptions) *legacyCurveLayer {
	l := &legacyCurveLayer{start: cursor, wmaxW: wmaxW, ncrv: opt.NCrvOrDefault()}
	l.geom.Store(populateLegacyCurves(r, cursor, wmaxW, opt))
	return l
}

// populateLegacyCurves appends the legacy curve family at cursor, writes the
// chain's end marker after it, and returns the resulting geometry.
func populateLegacyCurves(r *RegisterMap, cursor uint16, wmaxW float64,
	opt LegacyCurveOptions) *legacyLayout {
	l := &legacyLayout{shortBlockModel: opt.ShortBlockModel}
	ncrv := opt.NCrvOrDefault()

	for _, spec := range legacyCurveSpecs {
		var b legacyBankBlock
		b, cursor = populateLegacyCurveModel(r, cursor, spec, ncrv, wmaxW, opt.ShortBlockModel == spec.id)
		l.blocks = append(l.blocks, b)
	}
	l.m127, cursor = populate127(r, cursor)
	l.m128, cursor = populate128(r, cursor)
	l.m160, l.m160N, cursor = populate160(r, cursor, wmaxW)
	r.Set(cursor, sunspec.EndMarker)
	r.Set(cursor+1, 0)
	l.end = cursor + 1

	// Scale factors are read-only device constants (protect.go). Curve-model
	// SFs live in the header layouts only.
	for _, b := range l.blocks {
		protectLayoutSFs(r, b.base, b.hdr)
	}
	protectLayoutSFs(r, l.m127, sunspec.L127)
	protectLayoutSFs(r, l.m128, sunspec.L128)
	protectLayoutSFs(r, l.m160, sunspec.L160Hdr)
	return l
}

// populateLegacyCurveModel writes one legacy curve model: the ten-register
// header, NCrv fixed-size banks, and a default curve in bank 1.
//
// ORDER MATTERS AND IT IS THE SAME ORDER populateTripModel NEEDS. The header
// (NCrv, NPt and the scale factors) is written into the buffer BEFORE any bank
// is encoded, because lexa-proto's encoders run the fail-closed geometry gate
// on the buffer they are handed: they read len(regs) as the device's declared
// L, divide by NCrv, and refuse if the result is not the model's spec block
// length. Encoding first would refuse against a zero NCrv.
//
// shortBlock lays the banks out at a length sized to NPt instead of the spec's
// twenty slots. The header, the declared L and the stride all agree with each
// other — this is a coherent device with a WRONG geometry, which is the only
// kind the L-arithmetic gate can catch and the only kind worth building.
func populateLegacyCurveModel(r *RegisterMap, cursor uint16, spec legacyCurveSpec, ncrv int,
	wmaxW float64, shortBlock bool) (legacyBankBlock, uint16) {
	blockLen := spec.blockLen
	if shortBlock {
		// Twenty slots minus the slots past NPt, two registers per slot.
		blockLen -= 2 * (sunspec.LegacyCurveSlots - spec.npt)
	}
	hdrLen := spec.hdr.Len()
	dataLen := hdrLen + blockLen*ncrv
	base, next := writeModelHeader(r, cursor, spec.id, dataLen)

	regs := make([]uint16, dataLen)
	h := spec.hdr.View(regs)
	h.SetU16At(spec.hdr.Offset("NCrv"), uint16(ncrv))
	h.SetU16At(spec.hdr.Offset("NPt"), uint16(spec.npt))
	h.SetU16At(spec.hdr.Offset("ActCrv"), 1) // bank 1 is selected
	h.SetU16At(spec.hdr.Offset("ModEna"), 0) // and the function is OFF
	h.SetU16At(spec.hdr.Offset("WinTms"), 0)
	h.SetU16At(spec.hdr.Offset("RvrtTms"), 0)
	h.SetU16At(spec.hdr.Offset("RmpTms"), 0)
	for name, sf := range spec.sfs {
		setSF(regs, spec.hdr, name, sf)
	}

	// Every bank is READWRITE. A legacy device has no staging slot, so a
	// gateway's only safe move is to write a bank that is not the live one —
	// which requires at least one writable bank that is not ActCrv. A fixture
	// that shipped read-only banks would make every Case-A path untestable; the
	// read-only rule is exercised by SetLegacyBankReadOnly and by the
	// legacy_read_only_ignored fault instead.
	roOff := spec.bank.Offset("ReadOnly")
	for i := 1; i <= ncrv; i++ {
		h.SetU16At(hdrLen+blockLen*(i-1)+roOff, legacyBankReadWrite)
	}

	// Model 134's WRef is the active-power reference its W<n> percentages are
	// answered against, and SnptW=0 is what makes that reference a FIXED one.
	// Both are seeded before the points because the encoder writes the whole
	// bank in one atomic plan.
	seed := spec.seed
	if spec.id == sunspec.ModelFreqWattLegacy {
		seed = func(regs []uint16, bank int) error {
			_, _, err := sunspec.EncodeLegacy134Curve(regs, bank, sunspec.LegacyFreqWattCurve{
				CrvNam: "SIMFW",
				// Absolute Hz, three points where the freq-watt row publishes
				// four — see the 132 seed for why the COUNT is what differs.
				// Shape: flat through the deadband, then a droop above it.
				Pts: []sunspec.LegacyCurvePoint{
					{X: 59.5, Y: 100}, {X: 60.5, Y: 100}, {X: 62, Y: 20},
				},
				SnptW:      false,
				WRefW:      wmaxW,
				WRefStrHz:  0.5,
				WRefStopHz: 0.2,
			})
			return err
		}
	}

	// A short-block device has an UNKNOWN geometry by construction, so the
	// encoders refuse it — correctly, and that refusal is the whole point of
	// the posture. The bank is left at its zero value in that case, which is
	// what a gateway will find when its own gate refuses to compute an offset.
	if seed != nil && !shortBlock {
		if err := seed(regs, 1); err != nil {
			panic(fmt.Sprintf("sim: model %d default legacy curve does not fit its own geometry "+
				"(NCrv=%d NPt=%d blockLen=%d): %v", spec.id, ncrv, spec.npt, blockLen, err))
		}
	}

	writeSlice(r, base, regs)

	snptW := -1
	if spec.bank.Has("SnptW") {
		snptW = spec.bank.Offset("SnptW")
	}
	return legacyBankBlock{
		id: spec.id, base: base, hdr: spec.hdr, bank: spec.bank,
		blockLen: blockLen, ncrv: ncrv, npt: spec.npt, dataLen: dataLen, hdrLen: hdrLen,
		actCrvOff: spec.hdr.Offset("ActCrv"),
		modEnaOff: spec.hdr.Offset("ModEna"),
		roOff:     roOff,
		snptWOff:  snptW,
	}, next
}

// populate127 writes model 127 (Parameterized Frequency-Watt) with a
// IEEE 1547-typical droop: 40 % of PM per Hz, constraining from 0.036 Hz above
// nominal and releasing at 0.0 Hz, with a 20 %/min release ramp.
//
// 127 is a DIFFERENT function from 134 and the two are deliberately served
// together: 127 is a parametric droop with no breakpoint table, 134 is a
// breakpoint curve. A gateway that answered an opModFreqWatt CURVE by writing
// 127's gradient would be substituting one for the other, and a bench on which
// only one of them exists cannot show the difference.
func populate127(r *RegisterMap, cursor uint16) (base, next uint16) {
	dataLen := sunspec.L127.Len()
	base, next = writeModelHeader(r, cursor, sunspec.ModelFreqWattParam, dataLen)
	regs := make([]uint16, dataLen)
	setSF(regs, sunspec.L127, "WGra_SF", -2)
	setSF(regs, sunspec.L127, "HzStrStop_SF", -3)
	setSF(regs, sunspec.L127, "RmpIncDec_SF", -2)
	v := sunspec.L127.View(regs)
	v.SetFloat("WGra", 40)
	v.SetFloat("HzStr", 0.036)
	v.SetFloat("HzStop", 0.0)
	v.SetFloat("HzStopWGra", 20)
	writeSlice(r, base, regs)
	return base, next
}

// populate128 writes model 128 (Dynamic Reactive Current) with a plausible
// edge-mode gradient and a deadband around nominal.
//
// It carries ELEVEN writable points and NO write path is ever built for it.
// That is a PRODUCT decision with a standards reason, not a property of the
// model: IEEE 2030.5 has no opMod* element and no DERControlType bit for
// dynamic reactive current, so there is no northbound intent for a writer to
// serve. The registers are here so discovery, decode and read-only exposure can
// be exercised; a row that tried to command it would have to invent both the
// control and its semantics.
func populate128(r *RegisterMap, cursor uint16) (base, next uint16) {
	dataLen := sunspec.L128.Len()
	base, next = writeModelHeader(r, cursor, sunspec.ModelReactiveCurrent, dataLen)
	regs := make([]uint16, dataLen)
	setSF(regs, sunspec.L128, "ArGra_SF", -2)
	setSF(regs, sunspec.L128, "VRefPct_SF", -2)
	v := sunspec.L128.View(regs)
	v.SetU16At(sunspec.L128.Offset("ArGraMod"), 0) // EDGE
	v.SetFloat("ArGraSag", 150)
	v.SetFloat("ArGraSwell", 150)
	v.SetFloat("DbVMin", 92)
	v.SetFloat("DbVMax", 108)
	v.SetFloat("BlkZnV", 50)
	v.SetFloat("HysBlkZnV", 55)
	v.SetU16At(sunspec.L128.Offset("BlkZnTmms"), 20)
	v.SetU16At(sunspec.L128.Offset("HoldTmms"), 500)
	v.SetU16At(sunspec.L128.Offset("FilTms"), 5)
	writeSlice(r, base, regs)
	return base, next
}

// legacyMPPTModules is how many DC inputs model 160 declares.
const legacyMPPTModules = 2

// populate160 writes model 160 (Multiple MPPT) with two DC inputs sharing the
// inverter's rating. It is TELEMETRY: no point in the vendored JSON declares an
// access key at all, and SunSpec's default for an undeclared point is
// read-only, so the model declares no RW point. There is no writer and no axis.
func populate160(r *RegisterMap, cursor uint16, wmaxW float64) (base uint16, n int, next uint16) {
	n = legacyMPPTModules
	dataLen := sunspec.L160Hdr.Len() + n*sunspec.Blk160
	base, next = writeModelHeader(r, cursor, sunspec.ModelMPPT, dataLen)
	regs := make([]uint16, dataLen)
	setSF(regs, sunspec.L160Hdr, "DCA_SF", -1)
	setSF(regs, sunspec.L160Hdr, "DCV_SF", 0)
	setSF(regs, sunspec.L160Hdr, "DCW_SF", 0)
	setSF(regs, sunspec.L160Hdr, "DCWH_SF", 0)
	h := sunspec.L160Hdr.View(regs)
	h.SetU16At(sunspec.L160Hdr.Offset("N"), uint16(n))
	h.SetU16At(sunspec.L160Hdr.Offset("TmsPer"), 1)
	for i := 0; i < n; i++ {
		mbase := sunspec.MPPTModuleOffset(i)
		h.SetU16At(mbase+sunspec.L160Mod.Offset("ID"), uint16(i+1))
		writeLegacyString(regs, sunspec.L160Mod, mbase, fmt.Sprintf("STR%d", i+1))
		h.SetScaledUintAt(mbase+sunspec.L160Mod.Offset("DCV"), 380, "DCV_SF")
		h.SetScaledUintAt(mbase+sunspec.L160Mod.Offset("DCA"), wmaxW/2/380, "DCA_SF")
		h.SetScaledUintAt(mbase+sunspec.L160Mod.Offset("DCW"), wmaxW/2, "DCW_SF")
		h.SetU16At(mbase+sunspec.L160Mod.Offset("DCSt"), 4) // MPPT
	}
	writeSlice(r, base, regs)
	return base, n, next
}

// writeLegacyString writes a fixed-width SunSpec string point, big-endian two
// characters per register, space-padded — the encoding lexa-proto's own
// readLayoutString reads back.
func writeLegacyString(regs []uint16, l *sunspec.Layout, base int, s string) {
	f, ok := l.FieldOf("IDStr")
	if !ok {
		return
	}
	off := base + l.Offset("IDStr")
	for i := 0; i < f.Len; i++ {
		var hi, lo byte = ' ', ' '
		if 2*i < len(s) {
			hi = s[2*i]
		}
		if 2*i+1 < len(s) {
			lo = s[2*i+1]
		}
		if off+i < len(regs) {
			regs[off+i] = uint16(hi)<<8 | uint16(lo)
		}
	}
}

// ── Test/bench levers ────────────────────────────────────────────────────────

// SetLegacyBankReadOnly flips one bank's own ReadOnly declaration.
//
// It is a sim-internal Set, not a Modbus write, because ReadOnly is the
// DEVICE's statement about its banks: a gateway cannot write it (the write
// interception above refuses), so a bench that needs a read-only bank has to
// reach for the device's own configuration. That is what a real inverter's
// installer menu is.
func (ss *SolarServer) SetLegacyBankReadOnly(model uint16, bank int, ro bool) error {
	if ss.legacy == nil {
		return fmt.Errorf("sim: this device serves no legacy curve models")
	}
	for _, b := range ss.legacy.layout().blocks {
		if b.id != model {
			continue
		}
		if bank < 1 || bank > b.ncrv {
			return fmt.Errorf("sim: M%d has banks 1..%d, not %d", model, b.ncrv, bank)
		}
		val := legacyBankReadWrite
		if ro {
			val = legacyBankReadOnly
		}
		ss.Regs.Set(b.bankBase(bank)+uint16(b.roOff), val)
		return nil
	}
	return fmt.Errorf("sim: this device does not serve M%d", model)
}

// SetLegacyShortBlock RE-LAYS the served legacy-curve region so that model
// `model`'s banks are sized to its own NPt instead of the SunSpec fixed twenty
// point slots — the geometry pathology the fail-closed gate exists to refuse —
// or, with model = 0, restores the spec layout.
//
// # Why this is a re-lay and not a patched header
//
// LegacyCurveOptions.ShortBlockModel's doc records why the posture was
// constructor-only, and it is right about the constraint: "the pathology is a
// whole-image property: a device that publishes short blocks declares an L that
// matches them, and every register after that model moves. Arming it at run
// time would either leave the chain incoherent (an L that lies about a
// full-size layout, which is a DIFFERENT defect) or require re-laying the image
// under a live Modbus server."
//
// This takes the second option, because the first is a different defect and the
// bench needs THIS one. §9.5 row 8 asks for a device that presents the fault
// MID-SESSION — to a gateway that has already adopted it — and the only other
// way to get there is a modsim restart, which drops the southbound session and
// re-runs adoption, i.e. does not produce the situation under test.
//
// # How it stays atomic
//
// The new region is built into a DETACHED register map first, so every
// populate* function runs exactly as it does at construction, and is then
// spliced into the live map under the map's own write lock (spliceRegion). A
// Modbus request therefore sees the whole old image or the whole new one, never
// a half-laid chain — the same guarantee relocate.go's shiftAll gives, for the
// same reason.
//
// # What moves, and what deliberately does not
//
// Everything from this region's start to the end marker is rewritten, so five
// of the six curve models plus 127/128/160 and the marker itself move. NOTHING
// BEFORE THE REGION MOVES — models 1/103/120/121/122/123 are laid down by
// populateSolarCore ahead of it — which is why SolarBases and the fault
// controller's configured gate/scale addresses (both computed against 123 and
// 103) stay valid. That is the property that makes a partial re-lay safe here
// and would not make one safe in relocate.go, whose own doc records the same
// limitation from the other side.
//
// The reversion timer table IS rebuilt, because a timer descriptor carries a
// base address; every armed countdown is dropped with it. See
// rebuildSolarReversionTimers.
//
// Client-written curve content in the region is NOT preserved: a re-lay is the
// device re-publishing its model map, and carrying a bank across a stride change
// would mean deciding which registers of the old geometry correspond to which of
// the new — a mapping that does not exist, which is exactly what makes the
// pathology worth testing.
func (ss *SolarServer) SetLegacyShortBlock(model uint16) error {
	l := ss.legacy
	if l == nil {
		return fmt.Errorf("sim: this device serves no legacy curve models, so it has no curve block to "+
			"shorten (%s serves the 7xx generation)", ss.faults.label)
	}
	if model != 0 {
		known := false
		for _, spec := range legacyCurveSpecs {
			if spec.id == model {
				known = true
			}
		}
		if !known {
			return fmt.Errorf("sim: M%d is not a legacy curve model this device serves; the short-block "+
				"target must be one of 126/129/130/131/132/134", model)
		}
	}

	l.relay.Lock()
	defer l.relay.Unlock()
	old := l.layout()
	if old.shortBlockModel == model {
		return nil // idempotent, like Relocator.Relocate
	}

	scratch := &RegisterMap{regs: make(map[uint16]uint16)}
	geom := populateLegacyCurves(scratch, l.start, l.wmaxW, LegacyCurveOptions{
		NCrv: l.ncrv, ShortBlockModel: model,
	})

	// Clear as far as the LONGER of the two images reaches, so a shrink leaves
	// no stale registers past the new end marker for a walker that overruns it
	// to find.
	clearTo := old.end
	if geom.end > clearTo {
		clearTo = geom.end
	}

	// GEOMETRY FIRST, THEN CONTENT, and the order is the whole of what makes the
	// crossover safe.
	//
	// The two cannot be swapped atomically against a concurrent Modbus write:
	// HandleHoldingRegisters releases the map lock BEFORE calling the write
	// interceptor (deliberately, so an interceptor may call Get/Set), so no lock
	// this function could take would serialise the descriptor swap against a
	// write already in the interceptor. What is available is the CHOICE OF
	// FAILURE, and the two orders differ:
	//
	//	geometry first  a write in the window resolves NEW bases against OLD
	//	                content, lands in the region, and is then overwritten by
	//	                the splice — the write is LOST, which is what a re-lay
	//	                does to client-written curve content anyway.
	//	content first   a write in the window resolves OLD bases against NEW
	//	                content, lands at an address that now belongs to a
	//	                different model, and SURVIVES — silent corruption of a
	//	                model nobody wrote to.
	//
	// A lost write during a deliberate geometry change is honest; a write that
	// lands in the wrong model is not.
	l.geom.Store(geom)
	ss.Regs.spliceRegion(l.start, clearTo, scratch)
	ss.rebuildSolarReversionTimers(ss.Regs)

	if model == 0 {
		log.Printf("[fault] legacy_short_block: cleared — the legacy curve region was re-laid at the "+
			"spec block lengths (M%d's banks are full-size again); every armed reversion timer was dropped",
			old.shortBlockModel)
		return nil
	}
	log.Printf("[fault] legacy_short_block: M%d's banks re-laid SHORT (NPt-sized, not the twenty spec "+
		"slots) — the chain is internally coherent and every model after M%d has moved; every armed "+
		"reversion timer was dropped", model, model)
	return nil
}

// ── Snapshot ─────────────────────────────────────────────────────────────────

// legacyBankState is one bank's ground truth on GET /state.
type legacyBankState struct {
	Bank     int          `json:"bank"`
	Live     bool         `json:"live"`
	ReadOnly bool         `json:"read_only"`
	ActPt    int          `json:"act_pt"`
	DeptRef  uint16       `json:"dept_ref,omitempty"`
	CrvNam   string       `json:"crv_nam,omitempty"`
	SnptW    *bool        `json:"snpt_w,omitempty"`
	WRefW    *float64     `json:"wref_W,omitempty"`
	Points   [][2]float64 `json:"points"`
}

// legacyCurveState is one legacy curve model's ground truth on GET /state, so a
// QA oracle can read the selection state without a Modbus client.
//
// ActCrv and ModEna are reported SEPARATELY and ModEna is reported raw as well
// as decoded, because they answer different questions and the raw word is the
// only way to see a device that sets reserved bits: "which bank is live" and
// "is the function switched on" are independent on this generation, and a bank
// holding a perfect curve under ActCrv pointing elsewhere commands nothing.
type legacyCurveState struct {
	Model     uint16            `json:"model"`
	ActCrv    int               `json:"act_crv"`
	ModEna    bool              `json:"mod_ena"`
	ModEnaRaw uint16            `json:"mod_ena_raw"`
	NCrv      int               `json:"ncrv"`
	NPt       int               `json:"npt"`
	BlockLen  int               `json:"block_len"`
	DeclLen   int               `json:"decl_len"`
	Geometry  string            `json:"geometry"`
	Banks     []legacyBankState `json:"banks"`
}

// SolarLegacyCurveState is the legacy family's whole ground truth.
type SolarLegacyCurveState struct {
	Curves []legacyCurveState `json:"curves"`
	// MPPT is model 160's per-module telemetry.
	MPPT []legacyMPPTState `json:"mppt,omitempty"`
	// ShortBlockModel names the curve model currently laid out at a short block
	// length, or is omitted when the image is at spec geometry. It is on /state
	// because the pathology is otherwise only visible as arithmetic a reader
	// has to do on the declared L — and a bench that armed the lever needs its
	// evidence to say so without that step.
	ShortBlockModel uint16 `json:"short_block_model,omitempty"`
}

type legacyMPPTState struct {
	ID    int     `json:"id"`
	IDStr string  `json:"id_str"`
	DCV   float64 `json:"DCV_V"`
	DCA   float64 `json:"DCA_A"`
	DCW   float64 `json:"DCW_W"`
}

// legacySnapshot decodes the legacy curve family through lexa-proto's OWN
// parsers — never by walking the registers here — so the snapshot and the wire
// agree by construction. A block this fixture encoded that the shipped parser
// cannot read shows up immediately as a geometry string instead of as a curve
// nobody else can see.
func (ss *SolarServer) legacySnapshot() *SolarLegacyCurveState {
	if ss.legacy == nil {
		return nil
	}
	r := ss.Regs
	out := &SolarLegacyCurveState{}
	// ONE geometry read for the whole snapshot: a re-lay swaps the pointer, and
	// a snapshot that re-loaded it per model could describe half of one image
	// and half of another.
	geom := ss.legacy.layout()
	out.ShortBlockModel = geom.shortBlockModel
	for _, b := range geom.blocks {
		regs := readSlice(r, b.base, b.dataLen)
		cs := legacyCurveState{Model: b.id, DeclLen: b.dataLen, Geometry: "ok"}
		hdr, err := sunspec.ParseLegacyCurveHeader(b.id, regs)
		if err != nil {
			cs.Geometry = err.Error()
			out.Curves = append(out.Curves, cs)
			continue
		}
		cs.ActCrv, cs.ModEna, cs.ModEnaRaw = hdr.ActCrv, hdr.ModEna, hdr.ModEnaRaw
		cs.NCrv, cs.NPt = hdr.NCrv, hdr.NPt
		g, gerr := sunspec.LegacyCurveGeometryOf(b.id, len(regs), regs)
		if gerr != nil {
			cs.Geometry = gerr.Error()
			out.Curves = append(out.Curves, cs)
			continue
		}
		cs.BlockLen = g.BlockLen
		for i := 1; i <= g.NCrv; i++ {
			cs.Banks = append(cs.Banks, legacyBankSnapshot(b.id, regs, i, i == g.ActCrv))
		}
		out.Curves = append(out.Curves, cs)
	}
	if geom.m160 != 0 {
		regs := readSlice(r, geom.m160,
			sunspec.L160Hdr.Len()+geom.m160N*sunspec.Blk160)
		if st, err := sunspec.ParseLegacy160(regs); err == nil {
			for _, m := range st.Modules {
				out.MPPT = append(out.MPPT, legacyMPPTState{
					ID: m.ID, IDStr: m.IDStr, DCV: m.DCV, DCA: m.DCA, DCW: m.DCW,
				})
			}
		}
	}
	return out
}

func legacyBankSnapshot(model uint16, regs []uint16, i int, live bool) legacyBankState {
	st := legacyBankState{Bank: i, Live: live}
	pts := func(in []sunspec.LegacyCurvePoint) [][2]float64 {
		out := make([][2]float64, len(in))
		for j, p := range in {
			out[j] = [2]float64{p.X, p.Y}
		}
		return out
	}
	switch model {
	case sunspec.ModelVoltVarLegacy:
		c, err := sunspec.ParseLegacy126Curve(regs, i)
		if err != nil {
			return st
		}
		st.ActPt, st.ReadOnly, st.DeptRef, st.CrvNam = c.ActPt, c.ReadOnly, c.DeptRef, c.CrvNam
		st.Points = pts(c.Pts)
	case sunspec.ModelVoltWattLegacy:
		c, err := sunspec.ParseLegacy132Curve(regs, i)
		if err != nil {
			return st
		}
		st.ActPt, st.ReadOnly, st.DeptRef, st.CrvNam = c.ActPt, c.ReadOnly, c.DeptRef, c.CrvNam
		st.Points = pts(c.Pts)
	case sunspec.ModelWattPFLegacy:
		c, err := sunspec.ParseLegacy131Curve(regs, i)
		if err != nil {
			return st
		}
		st.ActPt, st.ReadOnly, st.CrvNam = c.ActPt, c.ReadOnly, c.CrvNam
		st.Points = pts(c.Pts)
	case sunspec.ModelFreqWattLegacy:
		c, err := sunspec.ParseLegacy134Curve(regs, i)
		if err != nil {
			return st
		}
		st.ActPt, st.ReadOnly, st.CrvNam = c.ActPt, c.ReadOnly, c.CrvNam
		snpt, wref := c.SnptW, c.WRefW
		st.SnptW, st.WRefW = &snpt, &wref
		st.Points = pts(c.Pts)
	case sunspec.ModelLVRTLegacy:
		c, err := sunspec.ParseLegacy129Curve(regs, i)
		if err != nil {
			return st
		}
		st.ActPt, st.ReadOnly, st.CrvNam = c.ActPt, c.ReadOnly, c.CrvNam
		st.Points = pts(c.Pts)
	case sunspec.ModelHVRTLegacy:
		c, err := sunspec.ParseLegacy130Curve(regs, i)
		if err != nil {
			return st
		}
		st.ActPt, st.ReadOnly, st.CrvNam = c.ActPt, c.ReadOnly, c.CrvNam
		st.Points = pts(c.Pts)
	}
	return st
}
