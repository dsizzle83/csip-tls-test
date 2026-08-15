package sunspec

// Typed parse/encode for the legacy curve family (126/127/128/129/130/131/132/
// 134/160), built on the declarative layouts in legacycurve.go.
//
// The shape mirrors der1547.go's 7xx parsers — engineering units throughout,
// NaN for anything the device does not implement — with three rules that are
// not negotiable and are the reason this file exists at all:
//
//  1. Bounds are checked BEFORE any register is touched: base + BlockLen must
//     fit inside the register slice.
//  2. ActPt is CLAMPED to min(NPt, 20). A device reporting ActPt = 200 must not
//     walk off the end of its own block.
//  3. Point access goes through the ABSOLUTE-offset accessors (ScaleUintAt,
//     ScaleSignedAt, U16At …) because the scale factors live in the model
//     header and a base-shifted sub-View cannot see them.
//
// Encoders use the CHECKED scale tier (EncodeScaleUint/EncodeScaleSigned) and
// refuse a value they cannot represent — see ErrNotRepresentable for why the
// legacy path does not inherit the 7xx encoders' silent clamp.

import (
	"fmt"
	"math"
)

// writeString packs a Go string into a SunSpec fixed-length string field
// (2 chars per register, NUL-padded). Characters beyond the field are dropped.
func writeString(regs []uint16, off, regLen int, s string) {
	b := []byte(s)
	for i := 0; i < regLen; i++ {
		if off+i < 0 || off+i >= len(regs) {
			return
		}
		var hi, lo byte
		if 2*i < len(b) {
			hi = b[2*i]
		}
		if 2*i+1 < len(b) {
			lo = b[2*i+1]
		}
		regs[off+i] = uint16(hi)<<8 | uint16(lo)
	}
}

// ── Shared types ─────────────────────────────────────────────────────────────

// LegacyCurvePoint is one breakpoint of a legacy curve bank in engineering
// units. What X and Y MEAN is per model and is documented on each curve type —
// they are not interchangeable across models.
type LegacyCurvePoint struct{ X, Y float64 }

// LegacyCurveHeader is the ActCrv-family header shared by 126/129/130/131/132/
// 134.
type LegacyCurveHeader struct {
	ActCrv int  // live bank, 1-based; 0 = no active curve
	ModEna bool // bit 0 of the ModEna BITFIELD — not an enum comparison
	// ModEnaRaw is the whole ModEna word. A writer that toggles bit 0 must
	// preserve the vendor's reserved bits, which requires the original word.
	ModEnaRaw uint16
	WinTmsS   int // randomisation window, s
	RvrtTmsS  int // curve-SELECTION timeout, s (there is no RvrtRem and no
	// RvrtCrv on legacy: expiry returns ActCrv to the device's own default,
	// which the gateway can neither name nor read back)
	RmpTmsS int // mode-transition ramp, s (PT1 to 95 %)
	NCrv    int
	NPt     int
}

// LegacyVoltVarCurve is one bank of model 126 (Static Volt-VAR).
// X = % VRef, Y = SIGNED % of whatever DeptRef names.
type LegacyVoltVarCurve struct {
	ActPt        int
	DeptRef      uint16 // 1 %WMax, 2 %VArMax, 3 %VArAval — LEGACY 1-based numbering
	Pts          []LegacyCurvePoint
	CrvNam       string
	RmpTmsS      float64
	RmpDecPctMin float64
	RmpIncPctMin float64
	ReadOnly     bool
}

// LegacyVoltWattCurve is one bank of model 132 (Volt-Watt).
// X = % VRef, Y = active power as % of whatever DeptRef names.
type LegacyVoltWattCurve struct {
	ActPt        int
	DeptRef      uint16 // 1 %WMax, 2 %WAvail — LEGACY 1-based numbering
	Pts          []LegacyCurvePoint
	CrvNam       string
	RmpPt1TmsS   float64 // 132 spells this RmpPt1Tms; 131/134 spell it RmpPT1Tms
	RmpDecPctMin float64
	RmpIncPctMin float64
	ReadOnly     bool
}

// LegacyWattPFCurve is one bank of model 131 (Watt-PF).
// X = % WMax, Y = power factor in EEI cos() notation.
type LegacyWattPFCurve struct {
	ActPt        int
	Pts          []LegacyCurvePoint
	CrvNam       string
	RmpPT1TmsS   float64
	RmpDecPctMin float64
	RmpIncPctMin float64
	ReadOnly     bool
}

// LegacyFreqWattCurve is one bank of model 134 (Curve-Based Frequency-Watt).
// X = ABSOLUTE frequency in Hz, Y = active power as % of WRef (NOT % WMax).
type LegacyFreqWattCurve struct {
	ActPt         int
	Pts           []LegacyCurvePoint
	CrvNam        string
	RmpPT1TmsS    float64
	RmpDecPctMin  float64
	RmpIncPctMin  float64
	RmpRsUpPctMin float64
	// SnptW enables snapshot mode: the curve's power base becomes the
	// instantaneous output when WRefStrHz was crossed instead of WRef. A CSIP
	// opModFreqWatt curve is defined against a FIXED base, so a writer serving
	// one must write this false and read it back.
	SnptW bool
	// WRefW is the reference active power in engineering WATTS (default WMax).
	WRefW float64
	// WRefStrHz / WRefStopHz are frequency DEVIATIONS from nominal, unlike the
	// curve points, which are absolute. Two conventions inside one block.
	WRefStrHz  float64
	WRefStopHz float64
	ReadOnly   bool
}

// LegacyRideThroughCurve is one bank of model 129 (LVRT) or 130 (HVRT).
// X = must-disconnect duration in seconds, Y = % VRef.
//
// A bank expresses exactly ONE region — the must-disconnect boundary. There is
// no momentary-cessation region and no may-trip region, unlike 707/708 which
// carry all three inside a single Crv.
type LegacyRideThroughCurve struct {
	ActPt    int
	Pts      []LegacyCurvePoint
	CrvNam   string
	ReadOnly bool
}

// FreqWattParam is model 127 (Parameterized Frequency-Watt) — a droop
// gradient, not a breakpoint curve.
type FreqWattParam struct {
	WGraPctPMPerHz   float64 // % of PM per Hz
	HzStrHz          float64 // Hz DEVIATION at which to start constraining
	HzStopHz         float64 // Hz DEVIATION at which to stop
	HzStopWGraPctMin float64 // release ramp, % WMax/min
	HysEna           bool
	ModEna           bool
	HysEnaRaw        uint16
	ModEnaRaw        uint16
}

// DynReactiveCurrent is model 128 (Dynamic Reactive Current). Decoded and
// exposed; deliberately never written — see L128's doc comment.
type DynReactiveCurrent struct {
	ArGraMod   uint16 // 0 EDGE, 1 CENTER
	ArGraSag   float64
	ArGraSwell float64
	DbVMin     float64
	DbVMax     float64
	BlkZnV     float64
	HysBlkZnV  float64
	BlkZnTmms  int
	HoldTmms   int
	FilTms     int
	ModEna     bool
	ModEnaRaw  uint16
}

// MPPTModule is one DC input of model 160.
type MPPTModule struct {
	ID    int
	IDStr string
	DCA   float64
	DCV   float64
	DCW   float64
	DCWH  float64
	TmsS  uint32
	TmpC  float64
	DCSt  uint16
	DCEvt uint32
}

// MPPTStatus is a full model 160 decode.
type MPPTStatus struct {
	Evt     uint32
	N       int
	TmsPerS int
	Modules []MPPTModule
}

// ── Header ───────────────────────────────────────────────────────────────────

// ParseLegacyCurveHeader decodes the ActCrv-family header of a legacy curve
// model from its body registers.
func ParseLegacyCurveHeader(modelID uint16, regs []uint16) (LegacyCurveHeader, error) {
	hdr, _, _, ok := LegacyCurveLayouts(modelID)
	if !ok {
		return LegacyCurveHeader{}, fmt.Errorf("sunspec: model %d is not a legacy curve model", modelID)
	}
	if len(regs) < hdr.Len() {
		return LegacyCurveHeader{}, fmt.Errorf("sunspec: M%d too short for header (%d < %d)",
			modelID, len(regs), hdr.Len())
	}
	v := hdr.View(regs)
	raw := v.U16At(hdr.Offset("ModEna"))
	return LegacyCurveHeader{
		ActCrv: int(v.U16At(hdr.Offset("ActCrv"))),
		// ModEna is a bitfield16, not an enum16: bit 0 is ENABLED. Comparing
		// the whole word against 1 would read a device that sets any reserved
		// bit as disabled.
		ModEna:    raw&1 != 0,
		ModEnaRaw: raw,
		WinTmsS:   int(v.U16At(hdr.Offset("WinTms"))),
		RvrtTmsS:  int(v.U16At(hdr.Offset("RvrtTms"))),
		RmpTmsS:   int(v.U16At(hdr.Offset("RmpTms"))),
		NCrv:      int(v.U16At(hdr.Offset("NCrv"))),
		NPt:       int(v.U16At(hdr.Offset("NPt"))),
	}, nil
}

// bankView bounds-checks bank i (1-based) of a legacy curve model and returns a
// header-bound View (so scale factors resolve), the bank's base offset, and the
// clamped active-point count.
func bankView(modelID uint16, regs []uint16, i int) (v View, base, actPt int, err error) {
	hdr, bank, blockLen, ok := LegacyCurveLayouts(modelID)
	if !ok {
		return View{}, 0, 0, fmt.Errorf("sunspec: model %d is not a legacy curve model", modelID)
	}
	if len(regs) < hdr.Len() {
		return View{}, 0, 0, fmt.Errorf("sunspec: M%d too short for header (%d < %d)",
			modelID, len(regs), hdr.Len())
	}
	base, ok = LegacyCurveOffset(modelID, i)
	if !ok {
		return View{}, 0, 0, fmt.Errorf("sunspec: M%d bank index %d is not 1-based-valid", modelID, i)
	}
	if base+blockLen > len(regs) {
		return View{}, 0, 0, fmt.Errorf("sunspec: M%d too short for bank %d (need %d registers, have %d)",
			modelID, i, base+blockLen, len(regs))
	}
	v = hdr.View(regs)
	npt := int(v.U16At(hdr.Offset("NPt")))
	if npt > LegacyCurveSlots {
		npt = LegacyCurveSlots
	}
	if npt < 0 {
		npt = 0
	}
	actPt = int(v.U16At(base + bank.Offset("ActPt")))
	if actPt > npt {
		actPt = npt
	}
	if actPt < 0 {
		actPt = 0
	}
	return v, base, actPt, nil
}

// pointOffsets returns the absolute offsets of slot n (1-based) of a bank:
// the x register and the y register, which are adjacent and interleaved.
func pointOffsets(bank *Layout, base, n int, xName, yName string) (xo, yo int) {
	s := itoa(n)
	return base + bank.Offset(xName+s), base + bank.Offset(yName+s)
}

// itoa avoids pulling strconv into the hot path for 1..20.
func itoa(n int) string {
	if n >= 0 && n < 10 {
		return string(rune('0' + n))
	}
	return string(rune('0'+n/10)) + string(rune('0'+n%10))
}

// ── Model 126: Static Volt-VAR ───────────────────────────────────────────────

// ParseLegacy126Curve decodes bank i (1-based, ActCrv numbering) of a 126 block.
func ParseLegacy126Curve(regs []uint16, i int) (LegacyVoltVarCurve, error) {
	v, base, actPt, err := bankView(ModelVoltVarLegacy, regs, i)
	if err != nil {
		return LegacyVoltVarCurve{}, err
	}
	b := L126Crv
	c := LegacyVoltVarCurve{
		ActPt:        actPt,
		DeptRef:      v.U16At(base + b.Offset("DeptRef")),
		CrvNam:       readString(regs, base+b.Offset("CrvNam"), 8),
		RmpTmsS:      float64(v.U16At(base + b.Offset("RmpTms"))),
		RmpDecPctMin: v.ScaleUintAt(base+b.Offset("RmpDecTmm"), "RmpIncDec_SF"),
		RmpIncPctMin: v.ScaleUintAt(base+b.Offset("RmpIncTmm"), "RmpIncDec_SF"),
		ReadOnly:     v.U16At(base+b.Offset("ReadOnly")) == 1,
		Pts:          make([]LegacyCurvePoint, actPt),
	}
	for n := 1; n <= actPt; n++ {
		xo, yo := pointOffsets(b, base, n, "V", "VAr")
		c.Pts[n-1] = LegacyCurvePoint{
			X: v.ScaleUintAt(xo, "V_SF"),
			Y: v.ScaleSignedAt(yo, "DeptRef_SF"),
		}
	}
	return c, nil
}

// EncodeLegacy126Curve writes c into bank i (1-based) of regs and returns the
// modified register range [start,end).
//
// end EXCLUDES the bank's ReadOnly register (and, on 131, the trailing Pad):
// ReadOnly is the DEVICE's declaration of whether the bank may be written, not
// a field the gateway owns. The 7xx encoders write ReadOnly = 0; the legacy
// ones must not.
//
// Scale factors must already be present in regs (they are read-only device
// constants, so this is satisfied by encoding into a freshly-read block).
func EncodeLegacy126Curve(regs []uint16, i int, c LegacyVoltVarCurve) (start, end int, err error) {
	v, base, _, err := bankView(ModelVoltVarLegacy, regs, i)
	if err != nil {
		return 0, 0, err
	}
	b := L126Crv
	if err := checkPointCount(ModelVoltVarLegacy, v, len(c.Pts)); err != nil {
		return 0, 0, err
	}
	if err := encU16(v, ModelVoltVarLegacy, base+b.Offset("RmpDecTmm"), "RmpDecTmm", c.RmpDecPctMin, "RmpIncDec_SF"); err != nil {
		return 0, 0, err
	}
	if err := encU16(v, ModelVoltVarLegacy, base+b.Offset("RmpIncTmm"), "RmpIncTmm", c.RmpIncPctMin, "RmpIncDec_SF"); err != nil {
		return 0, 0, err
	}
	for n := 1; n <= len(c.Pts); n++ {
		p := c.Pts[n-1]
		xo, yo := pointOffsets(b, base, n, "V", "VAr")
		if err := encU16(v, ModelVoltVarLegacy, xo, "V"+itoa(n), p.X, "V_SF"); err != nil {
			return 0, 0, err
		}
		if err := encI16(v, ModelVoltVarLegacy, yo, "VAr"+itoa(n), p.Y, "DeptRef_SF"); err != nil {
			return 0, 0, err
		}
	}
	v.SetU16At(base+b.Offset("ActPt"), uint16(len(c.Pts)))
	v.SetU16At(base+b.Offset("DeptRef"), c.DeptRef)
	setOptU16(v, base+b.Offset("RmpTms"), c.RmpTmsS)
	if c.CrvNam != "" {
		writeString(regs, base+b.Offset("CrvNam"), 8, c.CrvNam)
	}
	return base, base + b.Offset("ReadOnly"), nil
}

// ── Models 129 / 130: LVRT / HVRT must-disconnect ────────────────────────────

func parseLegacyRideThrough(modelID uint16, bank *Layout, regs []uint16, i int) (LegacyRideThroughCurve, error) {
	v, base, actPt, err := bankView(modelID, regs, i)
	if err != nil {
		return LegacyRideThroughCurve{}, err
	}
	c := LegacyRideThroughCurve{
		ActPt:    actPt,
		CrvNam:   readString(regs, base+bank.Offset("CrvNam"), 8),
		ReadOnly: v.U16At(base+bank.Offset("ReadOnly")) == 1,
		Pts:      make([]LegacyCurvePoint, actPt),
	}
	for n := 1; n <= actPt; n++ {
		xo, yo := pointOffsets(bank, base, n, "Tms", "V")
		c.Pts[n-1] = LegacyCurvePoint{
			X: v.ScaleUintAt(xo, "Tms_SF"),
			Y: v.ScaleUintAt(yo, "V_SF"),
		}
	}
	return c, nil
}

func encodeLegacyRideThrough(modelID uint16, bank *Layout, regs []uint16, i int, c LegacyRideThroughCurve) (start, end int, err error) {
	v, base, _, err := bankView(modelID, regs, i)
	if err != nil {
		return 0, 0, err
	}
	if err := checkPointCount(modelID, v, len(c.Pts)); err != nil {
		return 0, 0, err
	}
	for n := 1; n <= len(c.Pts); n++ {
		p := c.Pts[n-1]
		xo, yo := pointOffsets(bank, base, n, "Tms", "V")
		if err := encU16(v, modelID, xo, "Tms"+itoa(n), p.X, "Tms_SF"); err != nil {
			return 0, 0, err
		}
		if err := encU16(v, modelID, yo, "V"+itoa(n), p.Y, "V_SF"); err != nil {
			return 0, 0, err
		}
	}
	v.SetU16At(base+bank.Offset("ActPt"), uint16(len(c.Pts)))
	if c.CrvNam != "" {
		writeString(regs, base+bank.Offset("CrvNam"), 8, c.CrvNam)
	}
	return base, base + bank.Offset("ReadOnly"), nil
}

// ParseLegacy129Curve decodes bank i of a 129 (LVRT must-disconnect) block.
func ParseLegacy129Curve(regs []uint16, i int) (LegacyRideThroughCurve, error) {
	return parseLegacyRideThrough(ModelLVRTLegacy, L129Crv, regs, i)
}

// ParseLegacy130Curve decodes bank i of a 130 (HVRT must-disconnect) block.
func ParseLegacy130Curve(regs []uint16, i int) (LegacyRideThroughCurve, error) {
	return parseLegacyRideThrough(ModelHVRTLegacy, L130Crv, regs, i)
}

// EncodeLegacy129Curve writes c into bank i of a 129 block.
func EncodeLegacy129Curve(regs []uint16, i int, c LegacyRideThroughCurve) (start, end int, err error) {
	return encodeLegacyRideThrough(ModelLVRTLegacy, L129Crv, regs, i, c)
}

// EncodeLegacy130Curve writes c into bank i of a 130 block.
func EncodeLegacy130Curve(regs []uint16, i int, c LegacyRideThroughCurve) (start, end int, err error) {
	return encodeLegacyRideThrough(ModelHVRTLegacy, L130Crv, regs, i, c)
}

// ── Model 131: Watt-PF ───────────────────────────────────────────────────────

// ParseLegacy131Curve decodes bank i of a 131 block.
func ParseLegacy131Curve(regs []uint16, i int) (LegacyWattPFCurve, error) {
	v, base, actPt, err := bankView(ModelWattPFLegacy, regs, i)
	if err != nil {
		return LegacyWattPFCurve{}, err
	}
	b := L131Crv
	c := LegacyWattPFCurve{
		ActPt:        actPt,
		CrvNam:       readString(regs, base+b.Offset("CrvNam"), 8),
		RmpPT1TmsS:   float64(v.U16At(base + b.Offset("RmpPT1Tms"))),
		RmpDecPctMin: v.ScaleUintAt(base+b.Offset("RmpDecTmm"), "RmpIncDec_SF"),
		RmpIncPctMin: v.ScaleUintAt(base+b.Offset("RmpIncTmm"), "RmpIncDec_SF"),
		ReadOnly:     v.U16At(base+b.Offset("ReadOnly")) == 1,
		Pts:          make([]LegacyCurvePoint, actPt),
	}
	for n := 1; n <= actPt; n++ {
		xo, yo := pointOffsets(b, base, n, "W", "PF")
		c.Pts[n-1] = LegacyCurvePoint{
			X: v.ScaleSignedAt(xo, "W_SF"),
			Y: v.ScaleSignedAt(yo, "PF_SF"),
		}
	}
	return c, nil
}

// EncodeLegacy131Curve writes c into bank i of a 131 block.
func EncodeLegacy131Curve(regs []uint16, i int, c LegacyWattPFCurve) (start, end int, err error) {
	v, base, _, err := bankView(ModelWattPFLegacy, regs, i)
	if err != nil {
		return 0, 0, err
	}
	b := L131Crv
	if err := checkPointCount(ModelWattPFLegacy, v, len(c.Pts)); err != nil {
		return 0, 0, err
	}
	if err := encU16(v, ModelWattPFLegacy, base+b.Offset("RmpDecTmm"), "RmpDecTmm", c.RmpDecPctMin, "RmpIncDec_SF"); err != nil {
		return 0, 0, err
	}
	if err := encU16(v, ModelWattPFLegacy, base+b.Offset("RmpIncTmm"), "RmpIncTmm", c.RmpIncPctMin, "RmpIncDec_SF"); err != nil {
		return 0, 0, err
	}
	for n := 1; n <= len(c.Pts); n++ {
		p := c.Pts[n-1]
		xo, yo := pointOffsets(b, base, n, "W", "PF")
		if err := encI16(v, ModelWattPFLegacy, xo, "W"+itoa(n), p.X, "W_SF"); err != nil {
			return 0, 0, err
		}
		if err := encI16(v, ModelWattPFLegacy, yo, "PF"+itoa(n), p.Y, "PF_SF"); err != nil {
			return 0, 0, err
		}
	}
	v.SetU16At(base+b.Offset("ActPt"), uint16(len(c.Pts)))
	setOptU16(v, base+b.Offset("RmpPT1Tms"), c.RmpPT1TmsS)
	if c.CrvNam != "" {
		writeString(regs, base+b.Offset("CrvNam"), 8, c.CrvNam)
	}
	return base, base + b.Offset("ReadOnly"), nil
}

// ── Model 132: Volt-Watt ─────────────────────────────────────────────────────

// ParseLegacy132Curve decodes bank i of a 132 block.
func ParseLegacy132Curve(regs []uint16, i int) (LegacyVoltWattCurve, error) {
	v, base, actPt, err := bankView(ModelVoltWattLegacy, regs, i)
	if err != nil {
		return LegacyVoltWattCurve{}, err
	}
	b := L132Crv
	c := LegacyVoltWattCurve{
		ActPt:        actPt,
		DeptRef:      v.U16At(base + b.Offset("DeptRef")),
		CrvNam:       readString(regs, base+b.Offset("CrvNam"), 8),
		RmpPt1TmsS:   float64(v.U16At(base + b.Offset("RmpPt1Tms"))),
		RmpDecPctMin: v.ScaleUintAt(base+b.Offset("RmpDecTmm"), "RmpIncDec_SF"),
		RmpIncPctMin: v.ScaleUintAt(base+b.Offset("RmpIncTmm"), "RmpIncDec_SF"),
		ReadOnly:     v.U16At(base+b.Offset("ReadOnly")) == 1,
		Pts:          make([]LegacyCurvePoint, actPt),
	}
	for n := 1; n <= actPt; n++ {
		xo, yo := pointOffsets(b, base, n, "V", "W")
		c.Pts[n-1] = LegacyCurvePoint{
			X: v.ScaleUintAt(xo, "V_SF"),
			Y: v.ScaleSignedAt(yo, "DeptRef_SF"),
		}
	}
	return c, nil
}

// EncodeLegacy132Curve writes c into bank i of a 132 block.
func EncodeLegacy132Curve(regs []uint16, i int, c LegacyVoltWattCurve) (start, end int, err error) {
	v, base, _, err := bankView(ModelVoltWattLegacy, regs, i)
	if err != nil {
		return 0, 0, err
	}
	b := L132Crv
	if err := checkPointCount(ModelVoltWattLegacy, v, len(c.Pts)); err != nil {
		return 0, 0, err
	}
	if err := encU16(v, ModelVoltWattLegacy, base+b.Offset("RmpDecTmm"), "RmpDecTmm", c.RmpDecPctMin, "RmpIncDec_SF"); err != nil {
		return 0, 0, err
	}
	if err := encU16(v, ModelVoltWattLegacy, base+b.Offset("RmpIncTmm"), "RmpIncTmm", c.RmpIncPctMin, "RmpIncDec_SF"); err != nil {
		return 0, 0, err
	}
	for n := 1; n <= len(c.Pts); n++ {
		p := c.Pts[n-1]
		xo, yo := pointOffsets(b, base, n, "V", "W")
		if err := encU16(v, ModelVoltWattLegacy, xo, "V"+itoa(n), p.X, "V_SF"); err != nil {
			return 0, 0, err
		}
		if err := encI16(v, ModelVoltWattLegacy, yo, "W"+itoa(n), p.Y, "DeptRef_SF"); err != nil {
			return 0, 0, err
		}
	}
	v.SetU16At(base+b.Offset("ActPt"), uint16(len(c.Pts)))
	v.SetU16At(base+b.Offset("DeptRef"), c.DeptRef)
	setOptU16(v, base+b.Offset("RmpPt1Tms"), c.RmpPt1TmsS)
	if c.CrvNam != "" {
		writeString(regs, base+b.Offset("CrvNam"), 8, c.CrvNam)
	}
	return base, base + b.Offset("ReadOnly"), nil
}

// ── Model 134: Curve-Based Frequency-Watt ────────────────────────────────────

// ParseLegacy134Curve decodes bank i of a 134 block.
func ParseLegacy134Curve(regs []uint16, i int) (LegacyFreqWattCurve, error) {
	v, base, actPt, err := bankView(ModelFreqWattLegacy, regs, i)
	if err != nil {
		return LegacyFreqWattCurve{}, err
	}
	b := L134Crv
	c := LegacyFreqWattCurve{
		ActPt:         actPt,
		CrvNam:        readString(regs, base+b.Offset("CrvNam"), 8),
		RmpPT1TmsS:    float64(v.U16At(base + b.Offset("RmpPT1Tms"))),
		RmpDecPctMin:  v.ScaleUintAt(base+b.Offset("RmpDecTmm"), "RmpIncDec_SF"),
		RmpIncPctMin:  v.ScaleUintAt(base+b.Offset("RmpIncTmm"), "RmpIncDec_SF"),
		RmpRsUpPctMin: v.ScaleUintAt(base+b.Offset("RmpRsUp"), "RmpIncDec_SF"),
		SnptW:         v.U16At(base+b.Offset("SnptW"))&1 != 0, // bitfield16, bit 0
		WRefW:         v.ScaleUintAt(base+b.Offset("WRef"), "W_SF"),
		WRefStrHz:     v.ScaleUintAt(base+b.Offset("WRefStrHz"), "Hz_SF"),
		WRefStopHz:    v.ScaleUintAt(base+b.Offset("WRefStopHz"), "Hz_SF"),
		ReadOnly:      v.U16At(base+b.Offset("ReadOnly")) == 1,
		Pts:           make([]LegacyCurvePoint, actPt),
	}
	for n := 1; n <= actPt; n++ {
		xo, yo := pointOffsets(b, base, n, "Hz", "W")
		c.Pts[n-1] = LegacyCurvePoint{
			X: v.ScaleUintAt(xo, "Hz_SF"),
			Y: v.ScaleSignedAt(yo, "W_SF"),
		}
	}
	return c, nil
}

// EncodeLegacy134Curve writes c into bank i of a 134 block.
//
// SnptW is written unconditionally from c.SnptW, preserving the device's
// reserved bits: a writer serving a CSIP opModFreqWatt curve MUST set it false
// (the CSIP curve is defined against a fixed base) and read it back.
func EncodeLegacy134Curve(regs []uint16, i int, c LegacyFreqWattCurve) (start, end int, err error) {
	v, base, _, err := bankView(ModelFreqWattLegacy, regs, i)
	if err != nil {
		return 0, 0, err
	}
	b := L134Crv
	if err := checkPointCount(ModelFreqWattLegacy, v, len(c.Pts)); err != nil {
		return 0, 0, err
	}
	for name, val := range map[string]float64{
		"RmpDecTmm": c.RmpDecPctMin,
		"RmpIncTmm": c.RmpIncPctMin,
		"RmpRsUp":   c.RmpRsUpPctMin,
	} {
		if err := encU16(v, ModelFreqWattLegacy, base+b.Offset(name), name, val, "RmpIncDec_SF"); err != nil {
			return 0, 0, err
		}
	}
	if err := encU16(v, ModelFreqWattLegacy, base+b.Offset("WRef"), "WRef", c.WRefW, "W_SF"); err != nil {
		return 0, 0, err
	}
	if err := encU16(v, ModelFreqWattLegacy, base+b.Offset("WRefStrHz"), "WRefStrHz", c.WRefStrHz, "Hz_SF"); err != nil {
		return 0, 0, err
	}
	if err := encU16(v, ModelFreqWattLegacy, base+b.Offset("WRefStopHz"), "WRefStopHz", c.WRefStopHz, "Hz_SF"); err != nil {
		return 0, 0, err
	}
	for n := 1; n <= len(c.Pts); n++ {
		p := c.Pts[n-1]
		xo, yo := pointOffsets(b, base, n, "Hz", "W")
		if err := encU16(v, ModelFreqWattLegacy, xo, "Hz"+itoa(n), p.X, "Hz_SF"); err != nil {
			return 0, 0, err
		}
		if err := encI16(v, ModelFreqWattLegacy, yo, "W"+itoa(n), p.Y, "W_SF"); err != nil {
			return 0, 0, err
		}
	}
	v.SetU16At(base+b.Offset("ActPt"), uint16(len(c.Pts)))
	setOptU16(v, base+b.Offset("RmpPT1Tms"), c.RmpPT1TmsS)
	snpt := v.U16At(base+b.Offset("SnptW")) &^ uint16(1) // preserve reserved bits
	if c.SnptW {
		snpt |= 1
	}
	v.SetU16At(base+b.Offset("SnptW"), snpt)
	if c.CrvNam != "" {
		writeString(regs, base+b.Offset("CrvNam"), 8, c.CrvNam)
	}
	return base, base + b.Offset("ReadOnly"), nil
}

// ── Models 127 / 128 / 160: no curve bank ────────────────────────────────────

// ParseLegacy127 decodes model 127 (Parameterized Frequency-Watt).
func ParseLegacy127(regs []uint16) (FreqWattParam, error) {
	if len(regs) < L127.Len() {
		return FreqWattParam{}, fmt.Errorf("sunspec: M127 too short (%d < %d)", len(regs), L127.Len())
	}
	v := L127.View(regs)
	hys := v.U16At(L127.Offset("HysEna"))
	mod := v.U16At(L127.Offset("ModEna"))
	return FreqWattParam{
		WGraPctPMPerHz:   v.Float("WGra"),
		HzStrHz:          v.Float("HzStr"),
		HzStopHz:         v.Float("HzStop"),
		HzStopWGraPctMin: v.Float("HzStopWGra"),
		HysEna:           hys&1 != 0,
		ModEna:           mod&1 != 0,
		HysEnaRaw:        hys,
		ModEnaRaw:        mod,
	}, nil
}

// ParseLegacy128 decodes model 128 (Dynamic Reactive Current).
func ParseLegacy128(regs []uint16) (DynReactiveCurrent, error) {
	if len(regs) < L128.Len() {
		return DynReactiveCurrent{}, fmt.Errorf("sunspec: M128 too short (%d < %d)", len(regs), L128.Len())
	}
	v := L128.View(regs)
	mod := v.U16At(L128.Offset("ModEna"))
	arGraMod, _ := v.Enum("ArGraMod")
	return DynReactiveCurrent{
		ArGraMod:   arGraMod,
		ArGraSag:   v.Float("ArGraSag"),
		ArGraSwell: v.Float("ArGraSwell"),
		DbVMin:     v.Float("DbVMin"),
		DbVMax:     v.Float("DbVMax"),
		BlkZnV:     v.Float("BlkZnV"),
		HysBlkZnV:  v.Float("HysBlkZnV"),
		BlkZnTmms:  int(v.U16At(L128.Offset("BlkZnTmms"))),
		HoldTmms:   int(v.U16At(L128.Offset("HoldTmms"))),
		FilTms:     int(v.U16At(L128.Offset("FilTms"))),
		ModEna:     mod&1 != 0,
		ModEnaRaw:  mod,
	}, nil
}

// ParseLegacy160 decodes model 160 (Multiple MPPT) including every module the
// register block actually carries. N is the device's declared module count;
// modules beyond the end of the block are dropped rather than fabricated.
func ParseLegacy160(regs []uint16) (MPPTStatus, error) {
	if len(regs) < L160Hdr.Len() {
		return MPPTStatus{}, fmt.Errorf("sunspec: M160 too short for header (%d < %d)",
			len(regs), L160Hdr.Len())
	}
	h := L160Hdr.View(regs)
	n := int(h.U16At(L160Hdr.Offset("N")))
	st := MPPTStatus{
		Evt:     h.Bitfield32("Evt"),
		N:       n,
		TmsPerS: int(h.U16At(L160Hdr.Offset("TmsPer"))),
	}
	for i := 0; i < n; i++ {
		base := MPPTModuleOffset(i)
		if base+Blk160 > len(regs) {
			break
		}
		mo := func(p string) int { return base + L160Mod.Offset(p) }
		st.Modules = append(st.Modules, MPPTModule{
			ID:    int(h.U16At(mo("ID"))),
			IDStr: readString(regs, mo("IDStr"), 8),
			DCA:   h.ScaleUintAt(mo("DCA"), "DCA_SF"),
			DCV:   h.ScaleUintAt(mo("DCV"), "DCV_SF"),
			DCW:   h.ScaleUintAt(mo("DCW"), "DCW_SF"),
			DCWH:  scaleAcc32At(h, mo("DCWH"), "DCWH_SF"),
			TmsS:  h.U32At(mo("Tms")),
			// Tmp is degrees C with NO scale factor in the spec.
			TmpC:  float64(h.I16At(mo("Tmp"))),
			DCSt:  h.U16At(mo("DCSt")),
			DCEvt: h.U32At(mo("DCEvt")),
		})
	}
	return st, nil
}

// scaleAcc32At reads an acc32 at an absolute offset and applies the named SF.
// Accumulators reserve 0 (not 0xFFFFFFFF) as their sentinel, so the full-scale
// value is real data and only a bad scale factor yields NaN.
func scaleAcc32At(v View, o int, sfName string) float64 {
	s, ok := v.SF(sfName)
	if !ok {
		return math.NaN()
	}
	return float64(v.U32At(o)) * math.Pow10(int(s))
}

// ── Checked encode helpers ───────────────────────────────────────────────────

// checkPointCount refuses a curve with more points than the device supports,
// before any register moves.
func checkPointCount(modelID uint16, v View, npts int) error {
	hdr, _, _, _ := LegacyCurveLayouts(modelID)
	npt := int(v.U16At(hdr.Offset("NPt")))
	if npt > LegacyCurveSlots {
		npt = LegacyCurveSlots
	}
	if npts > npt {
		return fmt.Errorf("sunspec: M%d curve has %d points, device supports %d", modelID, npts, npt)
	}
	return nil
}

// quantises reports whether val loses information when encoded at sf — i.e. the
// scaled value is not (within float tolerance) a whole register count.
//
// EncodeScaleUint/Signed round silently and report EncodeExact, so this check
// is what makes the legacy encoders' contract "the device receives the value
// that was commanded, or the write is refused" rather than "…or something
// close". The tolerance is relative: 0.36 Hz at Hz_SF = −2 is 36 registers in
// exact arithmetic but 35.999999999999996 in float64.
func quantises(val float64, sf int16) bool {
	scaled := val / math.Pow10(int(sf))
	diff := math.Abs(scaled - math.Round(scaled))
	return diff > 1e-9*math.Max(1, math.Abs(scaled))
}

// encU16 encodes an engineering value into an unsigned point at an absolute
// offset. It refuses — with a *NotRepresentableError, never a silent clamp or
// a silent round — any value that the device would not receive exactly. A NaN
// value means "not commanded" and leaves the register untouched, so a
// read-modify-write keeps the device's own setting.
func encU16(v View, modelID uint16, off int, point string, val float64, sfName string) error {
	if math.IsNaN(val) {
		return nil
	}
	sf, ok := v.SF(sfName)
	if !ok {
		return &NotRepresentableError{ModelID: modelID, Point: point, Value: val, Outcome: EncodeBadSF}
	}
	raw, out := EncodeScaleUint(val, sf)
	if !out.Representable() {
		return &NotRepresentableError{ModelID: modelID, Point: point, Value: val, SF: sf, Outcome: out}
	}
	if quantises(val, sf) {
		return &NotRepresentableError{ModelID: modelID, Point: point, Value: val, SF: sf,
			Outcome: out, Quantised: true}
	}
	v.SetU16At(off, raw)
	return nil
}

// encI16 is encU16 for a signed point.
func encI16(v View, modelID uint16, off int, point string, val float64, sfName string) error {
	if math.IsNaN(val) {
		return nil
	}
	sf, ok := v.SF(sfName)
	if !ok {
		return &NotRepresentableError{ModelID: modelID, Point: point, Value: val, Outcome: EncodeBadSF}
	}
	raw, out := EncodeScaleSigned(val, sf)
	if !out.Representable() {
		return &NotRepresentableError{ModelID: modelID, Point: point, Value: val, SF: sf, Outcome: out}
	}
	if quantises(val, sf) {
		return &NotRepresentableError{ModelID: modelID, Point: point, Value: val, SF: sf,
			Outcome: out, Quantised: true}
	}
	v.SetU16At(off, raw)
	return nil
}

// setOptU16 writes an UNSCALED optional whole-second field, leaving it untouched
// when the caller passes NaN ("not commanded") and clamping a finite value onto
// the max-valid edge rather than onto the reserved 0xFFFF sentinel.
func setOptU16(v View, off int, val float64) {
	if math.IsNaN(val) {
		return
	}
	r := math.Round(val)
	if r < 0 {
		r = 0
	}
	if r > maxValidU16 {
		r = maxValidU16
	}
	v.SetU16At(off, uint16(r))
}
