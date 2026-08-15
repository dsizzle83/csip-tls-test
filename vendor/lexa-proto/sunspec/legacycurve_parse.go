package sunspec

// Typed parse/encode for the legacy curve family (126/127/128/129/130/131/132/
// 134/160), built on the declarative layouts in legacycurve.go.
//
// The shape mirrors der1547.go's 7xx parsers — engineering units throughout,
// NaN for anything the device does not implement — with four rules that are not
// negotiable and are the reason this file exists at all:
//
//  1. EVERY bank access goes through the geometry gate first. A device whose
//     declared L, NCrv and NPt do not agree with the model's spec block length
//     has a register map this package cannot compute offsets in, so it is
//     unreadable AND unwritable (ErrGeometryUnknown) rather than best-effort.
//     Bounds-checking the slice is not a substitute: a device that publishes a
//     SHORT block sized to its own NPt passes every bounds check and every
//     computed offset lands in the wrong register.
//  2. Scale-factor bindings, point widths and offsets are DERIVED FROM THE
//     LAYOUT, never restated here as string literals. The layout is the one
//     place a binding is proven against the vendored spec; a literal repeated
//     in a reader and a writer is a wrong binding that round-trips green.
//  3. ActPt is CLAMPED to min(NPt, 20). A device reporting ActPt = 200 must not
//     walk off the end of its own block.
//  4. Point access uses the ABSOLUTE-offset accessors because the scale factors
//     live in the model header and a base-shifted sub-View cannot see them.
//
// Encoders refuse — never silently clamp and never silently round — any value
// the device would not receive exactly. See ErrNotRepresentable.

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

// ── Layout-derived accessors ─────────────────────────────────────────────────
//
// Everything below reads a point's OFFSET, WIDTH, SIGNEDNESS and SCALE-FACTOR
// BINDING out of the Layout. No call site in this file names a scale factor.

// readScaled reads a scaled point by name, applying the scale factor the LAYOUT
// binds it to, with signedness taken from the layout's declared type. NaN when
// the point is absent from the layout, unimplemented on the device, or bound to
// a scale factor outside the sunssf domain.
func readScaled(v View, l *Layout, base int, point string) float64 {
	f, ok := l.FieldOf(point)
	if !ok {
		return math.NaN()
	}
	o := base + l.Offset(point)
	switch f.Type {
	case Tint16:
		return v.ScaleSignedAt(o, f.SF)
	case Tuint16, Tenum16:
		return v.ScaleUintAt(o, f.SF)
	case Tuint32:
		return v.ScaleU32At(o, f.SF)
	case Tacc32:
		// Accumulators reserve 0, not 0xFFFFFFFF, so full scale is real data
		// and only a bad scale factor yields NaN.
		s, ok := v.SF(f.SF)
		if !ok {
			return math.NaN()
		}
		return float64(v.U32At(o)) * math.Pow10(int(s))
	}
	return math.NaN()
}

// readRaw16 reads a single unscaled register by point name.
func readRaw16(v View, l *Layout, base int, point string) uint16 {
	o := l.Offset(point)
	if o < 0 {
		return 0
	}
	return v.U16At(base + o)
}

// readRaw32 reads an unscaled 32-bit point by name.
func readRaw32(v View, l *Layout, base int, point string) uint32 {
	o := l.Offset(point)
	if o < 0 {
		return 0
	}
	return v.U32At(base + o)
}

// readLayoutString reads a fixed-length string point, taking its width from the
// layout rather than from a second literal at the call site (the width defect
// that already bit model 701's MnAlrmInfo).
func readLayoutString(regs []uint16, l *Layout, base int, point string) string {
	f, ok := l.FieldOf(point)
	if !ok || f.Type != Tstring {
		return ""
	}
	return readString(regs, base+l.Offset(point), f.Len)
}

// stringWords packs a string into the register words of a fixed-length string
// field, so a planned write can carry it without touching the buffer.
func stringWords(s string, regLen int) []uint16 {
	out := make([]uint16, regLen)
	b := []byte(s)
	for i := 0; i < regLen; i++ {
		var hi, lo byte
		if 2*i < len(b) {
			hi = b[2*i]
		}
		if 2*i+1 < len(b) {
			lo = b[2*i+1]
		}
		out[i] = uint16(hi)<<8 | uint16(lo)
	}
	return out
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

// regWrite is one planned register write: an absolute body offset and the word
// to put there.
type regWrite struct {
	off int
	val uint16
}

// bankWriter plans a whole bank encode and applies it only if every part of it
// succeeded.
//
// THE ENCODE IS ATOMIC ON THE CALLER'S BUFFER, and that is a contract, not a
// nicety. §2.4's preflight rule is "all of these refuse before any register
// moves": an encoder that writes points 1-4 and then refuses point 5 has left a
// half-written curve in a buffer whose owner believes the operation failed. The
// current callers all discard the buffer on error, so today the damage is
// theoretical — but "it is safe because every caller happens to throw the
// evidence away" is exactly the reasoning that stops being true the first time
// someone retries a write in place, or hashes the block for a read-back
// comparison after a refusal.
//
// Errors are sticky: the first failure is kept and every later call is a no-op,
// so a caller can plan a whole bank and check once.
type bankWriter struct {
	v       View
	l       *Layout
	modelID uint16
	base    int
	w       []regWrite
	err     error
}

func newBankWriter(v View, l *Layout, modelID uint16, base int) *bankWriter {
	return &bankWriter{v: v, l: l, modelID: modelID, base: base}
}

// scaled plans an engineering value into a point by NAME, taking the register
// offset, the signedness and the scale-factor binding from the layout.
//
// It refuses — with a *NotRepresentableError, never a silent clamp and never a
// silent round — any value the device would not receive exactly. A NaN value
// means "not commanded" and plans nothing, so a read-modify-write keeps the
// device's own setting. A point with no scale factor is encoded at SF = 0,
// which still refuses a fractional value rather than truncating it.
func (b *bankWriter) scaled(point string, val float64) {
	if b.err != nil || math.IsNaN(val) {
		return
	}
	f, ok := b.l.FieldOf(point)
	if !ok {
		b.err = fmt.Errorf("sunspec: M%d has no point %s", b.modelID, point)
		return
	}
	sf := int16(0)
	if f.SF != "" {
		s, ok := b.v.SF(f.SF)
		if !ok {
			b.err = &NotRepresentableError{ModelID: b.modelID, Point: point, Value: val, Outcome: EncodeBadSF}
			return
		}
		sf = s
	}
	var (
		raw uint16
		out EncodeOutcome
	)
	switch f.Type {
	case Tint16:
		raw, out = EncodeScaleSigned(val, sf)
	case Tuint16, Tenum16:
		raw, out = EncodeScaleUint(val, sf)
	default:
		b.err = fmt.Errorf("sunspec: M%d point %s is type %v, not a 16-bit scalar", b.modelID, point, f.Type)
		return
	}
	if !out.Representable() {
		b.err = &NotRepresentableError{ModelID: b.modelID, Point: point, Value: val, SF: sf, Outcome: out}
		return
	}
	if quantises(val, sf) {
		b.err = &NotRepresentableError{ModelID: b.modelID, Point: point, Value: val, SF: sf,
			Outcome: out, Quantised: true}
		return
	}
	b.plan(point, raw)
}

// raw plans an unscaled single-register write by point name.
func (b *bankWriter) raw(point string, val uint16) {
	if b.err == nil {
		b.plan(point, val)
	}
}

// bit0 plans a bitfield write that sets or clears bit 0 while PRESERVING the
// device's reserved bits — reading the current word, never assuming it.
func (b *bankWriter) bit0(point string, on bool) {
	if b.err != nil {
		return
	}
	o := b.l.Offset(point)
	if o < 0 {
		b.err = fmt.Errorf("sunspec: M%d has no point %s", b.modelID, point)
		return
	}
	word := b.v.U16At(b.base+o) &^ uint16(1)
	if on {
		word |= 1
	}
	b.plan(point, word)
}

// str plans a fixed-length string write, taking the width from the layout. An
// empty string plans nothing: "no name given" must not blank the device's.
func (b *bankWriter) str(point, s string) {
	if b.err != nil || s == "" {
		return
	}
	f, ok := b.l.FieldOf(point)
	if !ok || f.Type != Tstring {
		b.err = fmt.Errorf("sunspec: M%d has no string point %s", b.modelID, point)
		return
	}
	o := b.base + b.l.Offset(point)
	for i, word := range stringWords(s, f.Len) {
		b.w = append(b.w, regWrite{off: o + i, val: word})
	}
}

// points plans the bank's (x,y) slots. Slots beyond len(pts) are LEFT AS READ:
// ActPt bounds what the device uses, and rewriting the tail would change
// registers the command says nothing about.
func (b *bankWriter) points(pts []LegacyCurvePoint, xAxis, yAxis string) {
	for n := 1; n <= len(pts); n++ {
		b.scaled(ptName(xAxis, n), pts[n-1].X)
		b.scaled(ptName(yAxis, n), pts[n-1].Y)
	}
}

func (b *bankWriter) plan(point string, val uint16) {
	o := b.l.Offset(point)
	if o < 0 {
		b.err = fmt.Errorf("sunspec: M%d has no point %s", b.modelID, point)
		return
	}
	b.w = append(b.w, regWrite{off: b.base + o, val: val})
}

// apply commits the planned writes, or none of them. It returns the modified
// range [start,end), which ends at the bank's ReadOnly register: ReadOnly is the
// DEVICE's declaration of whether the bank may be written, not a field the
// gateway owns. (The 7xx encoders write ReadOnly = 0; the legacy ones must not.)
func (b *bankWriter) apply() (start, end int, err error) {
	if b.err != nil {
		return 0, 0, b.err
	}
	for _, w := range b.w {
		b.v.SetU16At(w.off, w.val)
	}
	return b.base, b.base + b.l.Offset("ReadOnly"), nil
}

// ── Header ───────────────────────────────────────────────────────────────────

// ParseLegacyCurveHeader decodes the ActCrv-family header of a legacy curve
// model from its body registers.
//
// This is deliberately the ONE accessor that does not run the geometry gate:
// the header is the gate's INPUT (NCrv, NPt and ActCrv all live in it), so
// gating it would make a geometry-unknown device undiagnosable. It reads header
// registers only and computes no bank offset, so it cannot land in the wrong
// place. Every accessor that computes a bank offset does run the gate.
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
	raw := readRaw16(v, hdr, 0, "ModEna")
	return LegacyCurveHeader{
		ActCrv: int(readRaw16(v, hdr, 0, "ActCrv")),
		// ModEna is a bitfield16, not an enum16: bit 0 is ENABLED. Comparing
		// the whole word against 1 would read a device that sets any reserved
		// bit as disabled.
		ModEna:    raw&1 != 0,
		ModEnaRaw: raw,
		WinTmsS:   int(readRaw16(v, hdr, 0, "WinTms")),
		RvrtTmsS:  int(readRaw16(v, hdr, 0, "RvrtTms")),
		RmpTmsS:   int(readRaw16(v, hdr, 0, "RmpTms")),
		NCrv:      int(readRaw16(v, hdr, 0, "NCrv")),
		NPt:       int(readRaw16(v, hdr, 0, "NPt")),
	}, nil
}

// bankView runs the fail-closed geometry gate and returns a header-bound View
// (so scale factors resolve), the bank's base offset, and the clamped active-
// point count.
//
// regs MUST be the whole model body as ReadModel returns it, because len(regs)
// is what the gate reads as the device's declared L. Passing a sub-slice makes
// the geometry incoherent and is refused — the fail-closed direction.
//
// THE GATE IS NOT OPTIONAL AND A BOUNDS CHECK IS NOT A SUBSTITUTE. Field
// firmware exists that publishes a curve block sized to its own NPt instead of
// the spec's fixed 20 slots. Such a device satisfies every bounds check: the
// slice is long enough, the offsets are inside it, and the write lands — in the
// wrong registers, of a bank the device may currently be executing.
func bankView(modelID uint16, regs []uint16, i int) (v View, base, actPt int, err error) {
	hdr, bank, _, ok := LegacyCurveLayouts(modelID)
	if !ok {
		return View{}, 0, 0, fmt.Errorf("sunspec: model %d is not a legacy curve model", modelID)
	}
	g, err := LegacyCurveGeometryOf(modelID, len(regs), regs)
	if err != nil {
		return View{}, 0, 0, err
	}
	base, ok = g.BankOffset(i)
	if !ok {
		return View{}, 0, 0, &GeometryError{ModelID: modelID, Detail: fmt.Sprintf(
			"bank %d is not addressable: banks are 1-based and this device declares NCrv=%d", i, g.NCrv)}
	}
	if base+g.BlockLen > len(regs) {
		return View{}, 0, 0, &GeometryError{ModelID: modelID, Detail: fmt.Sprintf(
			"bank %d needs registers up to %d but only %d were read", i, base+g.BlockLen, len(regs))}
	}
	v = hdr.View(regs)
	actPt = int(readRaw16(v, bank, base, "ActPt"))
	if npt := g.UsablePoints(); actPt > npt {
		actPt = npt
	}
	if actPt < 0 {
		actPt = 0
	}
	return v, base, actPt, nil
}

// ptName is the spec point name of slot n (1-based) on an axis: "V3", "VAr12".
func ptName(axis string, n int) string { return axis + itoa(n) }

// itoa avoids pulling strconv into the hot path for 1..20.
func itoa(n int) string {
	if n >= 0 && n < 10 {
		return string(rune('0' + n))
	}
	return string(rune('0'+n/10)) + string(rune('0'+n%10))
}

// readPoints decodes the first actPt slots of a bank on the two named axes.
func readPoints(v View, l *Layout, base, actPt int, xAxis, yAxis string) []LegacyCurvePoint {
	pts := make([]LegacyCurvePoint, actPt)
	for n := 1; n <= actPt; n++ {
		pts[n-1] = LegacyCurvePoint{
			X: readScaled(v, l, base, ptName(xAxis, n)),
			Y: readScaled(v, l, base, ptName(yAxis, n)),
		}
	}
	return pts
}

// checkPointCount refuses a curve with more points than the device supports,
// before any register moves.
func checkPointCount(modelID uint16, regs []uint16, npts int) error {
	g, err := LegacyCurveGeometryOf(modelID, len(regs), regs)
	if err != nil {
		return err
	}
	if npts > g.UsablePoints() {
		return fmt.Errorf("sunspec: M%d curve has %d points, device supports %d",
			modelID, npts, g.UsablePoints())
	}
	return nil
}

// ── Model 126: Static Volt-VAR ───────────────────────────────────────────────

// ParseLegacy126Curve decodes bank i (1-based, ActCrv numbering) of a 126 block.
func ParseLegacy126Curve(regs []uint16, i int) (LegacyVoltVarCurve, error) {
	v, base, actPt, err := bankView(ModelVoltVarLegacy, regs, i)
	if err != nil {
		return LegacyVoltVarCurve{}, err
	}
	b := L126Crv
	return LegacyVoltVarCurve{
		ActPt:        actPt,
		DeptRef:      readRaw16(v, b, base, "DeptRef"),
		CrvNam:       readLayoutString(regs, b, base, "CrvNam"),
		RmpTmsS:      float64(readRaw16(v, b, base, "RmpTms")),
		RmpDecPctMin: readScaled(v, b, base, "RmpDecTmm"),
		RmpIncPctMin: readScaled(v, b, base, "RmpIncTmm"),
		ReadOnly:     readRaw16(v, b, base, "ReadOnly") == 1,
		Pts:          readPoints(v, b, base, actPt, "V", "VAr"),
	}, nil
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
	if err := checkPointCount(ModelVoltVarLegacy, regs, len(c.Pts)); err != nil {
		return 0, 0, err
	}
	w := newBankWriter(v, L126Crv, ModelVoltVarLegacy, base)
	w.scaled("RmpTms", c.RmpTmsS)
	w.scaled("RmpDecTmm", c.RmpDecPctMin)
	w.scaled("RmpIncTmm", c.RmpIncPctMin)
	w.points(c.Pts, "V", "VAr")
	w.raw("ActPt", uint16(len(c.Pts)))
	w.raw("DeptRef", c.DeptRef)
	w.str("CrvNam", c.CrvNam)
	return w.apply()
}

// ── Models 129 / 130: LVRT / HVRT must-disconnect ────────────────────────────

func parseLegacyRideThrough(modelID uint16, bank *Layout, regs []uint16, i int) (LegacyRideThroughCurve, error) {
	v, base, actPt, err := bankView(modelID, regs, i)
	if err != nil {
		return LegacyRideThroughCurve{}, err
	}
	return LegacyRideThroughCurve{
		ActPt:    actPt,
		CrvNam:   readLayoutString(regs, bank, base, "CrvNam"),
		ReadOnly: readRaw16(v, bank, base, "ReadOnly") == 1,
		Pts:      readPoints(v, bank, base, actPt, "Tms", "V"),
	}, nil
}

func encodeLegacyRideThrough(modelID uint16, bank *Layout, regs []uint16, i int, c LegacyRideThroughCurve) (start, end int, err error) {
	v, base, _, err := bankView(modelID, regs, i)
	if err != nil {
		return 0, 0, err
	}
	if err := checkPointCount(modelID, regs, len(c.Pts)); err != nil {
		return 0, 0, err
	}
	w := newBankWriter(v, bank, modelID, base)
	w.points(c.Pts, "Tms", "V")
	w.raw("ActPt", uint16(len(c.Pts)))
	w.str("CrvNam", c.CrvNam)
	return w.apply()
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
	return LegacyWattPFCurve{
		ActPt:        actPt,
		CrvNam:       readLayoutString(regs, b, base, "CrvNam"),
		RmpPT1TmsS:   float64(readRaw16(v, b, base, "RmpPT1Tms")),
		RmpDecPctMin: readScaled(v, b, base, "RmpDecTmm"),
		RmpIncPctMin: readScaled(v, b, base, "RmpIncTmm"),
		ReadOnly:     readRaw16(v, b, base, "ReadOnly") == 1,
		Pts:          readPoints(v, b, base, actPt, "W", "PF"),
	}, nil
}

// EncodeLegacy131Curve writes c into bank i of a 131 block.
func EncodeLegacy131Curve(regs []uint16, i int, c LegacyWattPFCurve) (start, end int, err error) {
	v, base, _, err := bankView(ModelWattPFLegacy, regs, i)
	if err != nil {
		return 0, 0, err
	}
	if err := checkPointCount(ModelWattPFLegacy, regs, len(c.Pts)); err != nil {
		return 0, 0, err
	}
	w := newBankWriter(v, L131Crv, ModelWattPFLegacy, base)
	w.scaled("RmpPT1Tms", c.RmpPT1TmsS)
	w.scaled("RmpDecTmm", c.RmpDecPctMin)
	w.scaled("RmpIncTmm", c.RmpIncPctMin)
	w.points(c.Pts, "W", "PF")
	w.raw("ActPt", uint16(len(c.Pts)))
	w.str("CrvNam", c.CrvNam)
	return w.apply()
}

// ── Model 132: Volt-Watt ─────────────────────────────────────────────────────

// ParseLegacy132Curve decodes bank i of a 132 block.
func ParseLegacy132Curve(regs []uint16, i int) (LegacyVoltWattCurve, error) {
	v, base, actPt, err := bankView(ModelVoltWattLegacy, regs, i)
	if err != nil {
		return LegacyVoltWattCurve{}, err
	}
	b := L132Crv
	return LegacyVoltWattCurve{
		ActPt:        actPt,
		DeptRef:      readRaw16(v, b, base, "DeptRef"),
		CrvNam:       readLayoutString(regs, b, base, "CrvNam"),
		RmpPt1TmsS:   float64(readRaw16(v, b, base, "RmpPt1Tms")),
		RmpDecPctMin: readScaled(v, b, base, "RmpDecTmm"),
		RmpIncPctMin: readScaled(v, b, base, "RmpIncTmm"),
		ReadOnly:     readRaw16(v, b, base, "ReadOnly") == 1,
		Pts:          readPoints(v, b, base, actPt, "V", "W"),
	}, nil
}

// EncodeLegacy132Curve writes c into bank i of a 132 block.
func EncodeLegacy132Curve(regs []uint16, i int, c LegacyVoltWattCurve) (start, end int, err error) {
	v, base, _, err := bankView(ModelVoltWattLegacy, regs, i)
	if err != nil {
		return 0, 0, err
	}
	if err := checkPointCount(ModelVoltWattLegacy, regs, len(c.Pts)); err != nil {
		return 0, 0, err
	}
	w := newBankWriter(v, L132Crv, ModelVoltWattLegacy, base)
	w.scaled("RmpPt1Tms", c.RmpPt1TmsS)
	w.scaled("RmpDecTmm", c.RmpDecPctMin)
	w.scaled("RmpIncTmm", c.RmpIncPctMin)
	w.points(c.Pts, "V", "W")
	w.raw("ActPt", uint16(len(c.Pts)))
	w.raw("DeptRef", c.DeptRef)
	w.str("CrvNam", c.CrvNam)
	return w.apply()
}

// ── Model 134: Curve-Based Frequency-Watt ────────────────────────────────────

// ParseLegacy134Curve decodes bank i of a 134 block.
func ParseLegacy134Curve(regs []uint16, i int) (LegacyFreqWattCurve, error) {
	v, base, actPt, err := bankView(ModelFreqWattLegacy, regs, i)
	if err != nil {
		return LegacyFreqWattCurve{}, err
	}
	b := L134Crv
	return LegacyFreqWattCurve{
		ActPt:         actPt,
		CrvNam:        readLayoutString(regs, b, base, "CrvNam"),
		RmpPT1TmsS:    float64(readRaw16(v, b, base, "RmpPT1Tms")),
		RmpDecPctMin:  readScaled(v, b, base, "RmpDecTmm"),
		RmpIncPctMin:  readScaled(v, b, base, "RmpIncTmm"),
		RmpRsUpPctMin: readScaled(v, b, base, "RmpRsUp"),
		SnptW:         readRaw16(v, b, base, "SnptW")&1 != 0, // bitfield16, bit 0
		WRefW:         readScaled(v, b, base, "WRef"),
		WRefStrHz:     readScaled(v, b, base, "WRefStrHz"),
		WRefStopHz:    readScaled(v, b, base, "WRefStopHz"),
		ReadOnly:      readRaw16(v, b, base, "ReadOnly") == 1,
		Pts:           readPoints(v, b, base, actPt, "Hz", "W"),
	}, nil
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
	if err := checkPointCount(ModelFreqWattLegacy, regs, len(c.Pts)); err != nil {
		return 0, 0, err
	}
	w := newBankWriter(v, L134Crv, ModelFreqWattLegacy, base)
	w.scaled("RmpPT1Tms", c.RmpPT1TmsS)
	w.scaled("RmpDecTmm", c.RmpDecPctMin)
	w.scaled("RmpIncTmm", c.RmpIncPctMin)
	w.scaled("RmpRsUp", c.RmpRsUpPctMin)
	w.scaled("WRef", c.WRefW)
	w.scaled("WRefStrHz", c.WRefStrHz)
	w.scaled("WRefStopHz", c.WRefStopHz)
	w.points(c.Pts, "Hz", "W")
	w.raw("ActPt", uint16(len(c.Pts)))
	w.bit0("SnptW", c.SnptW)
	w.str("CrvNam", c.CrvNam)
	return w.apply()
}

// ── Models 127 / 128 / 160: no curve bank ────────────────────────────────────

// ParseLegacy127 decodes model 127 (Parameterized Frequency-Watt).
func ParseLegacy127(regs []uint16) (FreqWattParam, error) {
	if len(regs) < L127.Len() {
		return FreqWattParam{}, fmt.Errorf("sunspec: M127 too short (%d < %d)", len(regs), L127.Len())
	}
	v := L127.View(regs)
	hys := readRaw16(v, L127, 0, "HysEna")
	mod := readRaw16(v, L127, 0, "ModEna")
	// View.Float resolves each point's scale factor from the layout itself, so
	// these are already single-sourced.
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
	mod := readRaw16(v, L128, 0, "ModEna")
	arGraMod, _ := v.Enum("ArGraMod")
	return DynReactiveCurrent{
		ArGraMod:   arGraMod,
		ArGraSag:   v.Float("ArGraSag"),
		ArGraSwell: v.Float("ArGraSwell"),
		DbVMin:     v.Float("DbVMin"),
		DbVMax:     v.Float("DbVMax"),
		BlkZnV:     v.Float("BlkZnV"),
		HysBlkZnV:  v.Float("HysBlkZnV"),
		BlkZnTmms:  int(readRaw16(v, L128, 0, "BlkZnTmms")),
		HoldTmms:   int(readRaw16(v, L128, 0, "HoldTmms")),
		FilTms:     int(readRaw16(v, L128, 0, "FilTms")),
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
	n := int(readRaw16(h, L160Hdr, 0, "N"))
	st := MPPTStatus{
		Evt:     h.Bitfield32("Evt"),
		N:       n,
		TmsPerS: int(readRaw16(h, L160Hdr, 0, "TmsPer")),
	}
	for i := 0; i < n; i++ {
		base := MPPTModuleOffset(i)
		if base+Blk160 > len(regs) {
			break
		}
		m := L160Mod
		st.Modules = append(st.Modules, MPPTModule{
			ID:    int(readRaw16(h, m, base, "ID")),
			IDStr: readLayoutString(regs, m, base, "IDStr"),
			DCA:   readScaled(h, m, base, "DCA"),
			DCV:   readScaled(h, m, base, "DCV"),
			DCW:   readScaled(h, m, base, "DCW"),
			DCWH:  readScaled(h, m, base, "DCWH"),
			TmsS:  readRaw32(h, m, base, "Tms"),
			// Tmp is degrees C with NO scale factor in the spec, so it is read
			// raw rather than through readScaled.
			TmpC:  float64(int16(readRaw16(h, m, base, "Tmp"))),
			DCSt:  readRaw16(h, m, base, "DCSt"),
			DCEvt: readRaw32(h, m, base, "DCEvt"),
		})
	}
	return st, nil
}
