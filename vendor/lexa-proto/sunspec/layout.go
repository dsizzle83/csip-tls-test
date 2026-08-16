// Package sunspec — declarative model-layout engine.
//
// SunSpec information models are ordered lists of typed points. Computing
// register offsets by hand is error-prone for the larger DER models (701/702/704
// have 60-110 points spanning a mix of 16-, 32-, and 64-bit values), so this file
// describes each model as an ordered []Field and derives offsets, total length,
// and typed accessors from that description.
//
// All multi-register values are big-endian (most-significant register first),
// per the SunSpec Modbus specification. Each numeric type has a documented
// "not implemented" sentinel; accessors return math.NaN() (for scaled floats)
// or report !ok (for integer getters) when a point is unimplemented on a device,
// so callers never mistake a sentinel for a real value on real hardware.
package sunspec

import "math"

// FieldType enumerates the SunSpec point data types this engine understands.
type FieldType uint8

const (
	Tuint16 FieldType = iota
	Tint16
	Tenum16
	Tbitfield16
	Tsunssf // int16 scale factor
	Tuint32
	Tint32
	Tenum32
	Tbitfield32
	Tacc32 // 32-bit accumulator (sentinel is 0, not 0xFFFFFFFF)
	Tuint64
	Tint64
	Tacc64
	Tstring // Field.Len registers, 2 chars each
	Tpad    // reserved register(s); ignored
)

// regs returns the number of 16-bit registers a field of this type occupies.
// strLen is the declared register length used only for Tstring/Tpad.
func (t FieldType) regs(strLen int) int {
	switch t {
	case Tuint16, Tint16, Tenum16, Tbitfield16, Tsunssf:
		return 1
	case Tuint32, Tint32, Tenum32, Tbitfield32, Tacc32:
		return 2
	case Tuint64, Tint64, Tacc64:
		return 4
	case Tstring, Tpad:
		return strLen
	}
	return 1
}

// Access is a point's spec-declared write access.
//
// The vendored SunSpec model JSON declares access with a single key that is
// EITHER "RW" or ABSENT — across all 31 vendored models there is no literal
// "r" anywhere (checked: the only two access values present in the corpus are
// "RW" and nothing at all). Read-only is the SunSpec default for an
// undeclared point, so the only sound comparison is RW vs not-RW; a layout
// that asserted the string "r" would false-fail against every read-only point
// in the corpus. AccUnset means "this layout does not declare access" — the
// 7xx layouts predate the annotation and are compared on geometry only.
type Access uint8

const (
	AccUnset Access = iota // layout makes no access claim
	AccR                   // read-only (spec: access key absent)
	AccRW                  // read/write (spec: "access": "RW")
)

// Presence is a point's spec-declared mandatory/optional status. Same shape as
// Access: the JSON carries "mandatory": "M" or nothing at all.
type Presence uint8

const (
	PresUnset     Presence = iota // layout makes no mandatory/optional claim
	PresOptional                  // spec: mandatory key absent
	PresMandatory                 // spec: "mandatory": "M"
)

// Field describes a single point in a model layout.
type Field struct {
	Name string
	Type FieldType
	SF   string // name of this point's scale-factor field; "" if unscaled
	Len  int    // register count for Tstring / Tpad only

	// Acc and Pres carry the vendored spec's access / mandatory declarations
	// so TestLayoutsMatchVendoredSpec can prove them against the JSON rather
	// than against a second hand-written table. Both are optional: a layout
	// that leaves them Unset is compared on geometry alone.
	Acc  Access
	Pres Presence
}

// F is a terse constructor for an unscaled field.
func F(name string, t FieldType) Field { return Field{Name: name, Type: t} }

// FS is a terse constructor for a scaled field (SF names another Tsunssf field).
func FS(name string, t FieldType, sf string) Field { return Field{Name: name, Type: t, SF: sf} }

// FStr is a terse constructor for a fixed-length string field.
func FStr(name string, regs int) Field { return Field{Name: name, Type: Tstring, Len: regs} }

// FPad is a terse constructor for a reserved (pad) field of regs registers.
// Tpad takes its width from Field.Len, so a pad built with F() would be zero
// registers wide and would silently shift every point after it.
func FPad(name string, regs int) Field { return Field{Name: name, Type: Tpad, Len: regs} }

// RW / R / M / O annotate a field with the spec's access and mandatory
// declarations. They return a copy, so they chain onto the F/FS/FStr/FPad
// constructors: F("NCrv", Tuint16).R().M().
func (f Field) RW() Field { f.Acc = AccRW; return f }
func (f Field) R() Field  { f.Acc = AccR; return f }
func (f Field) M() Field  { f.Pres = PresMandatory; return f }
func (f Field) O() Field  { f.Pres = PresOptional; return f }

// Layout is a compiled, offset-indexed model description.
type Layout struct {
	Fields []Field
	off    map[string]int
	typ    map[string]Field
	total  int

	// name is the human label this layout's refusals cite, e.g. "M704". It is
	// metadata for error messages ONLY — nothing dispatches on it — but a
	// refusal that cannot name its model ("cannot encode 80: scale factor
	// WMaxLimPct_SF is unreadable") sends an operator hunting across four
	// models for one register, and unattributed divergence is the exact
	// failure SetFloat's error path exists to end.
	//
	// Set with As(). Every layout defined in THIS package is named, enforced
	// structurally by TestEveryLayoutInThisPackageIsNamed. A layout built by a
	// CONSUMER (lexa-gw's regmap flattens curve models into ad-hoc layouts via
	// the exported NewLayout) may leave it empty, and ScaleFactorError then
	// degrades to point + scale-factor register rather than printing an empty
	// label — which is why As is a chained option and not a NewLayout
	// parameter: a required parameter would break every consumer at re-vendor
	// for a field that only decorates an error string.
	name string
}

// NewLayout compiles an ordered field list into an offset-indexed Layout.
// Offsets are 0-based from the start of the model's data block (after the
// ID and L registers, which ReadModel already strips).
func NewLayout(fields ...Field) *Layout {
	l := &Layout{
		Fields: fields,
		off:    make(map[string]int, len(fields)),
		typ:    make(map[string]Field, len(fields)),
	}
	o := 0
	for _, f := range fields {
		if _, dup := l.off[f.Name]; dup && f.Name != "" {
			panic("sunspec: duplicate field " + f.Name)
		}
		l.off[f.Name] = o
		l.typ[f.Name] = f
		o += f.Type.regs(f.Len)
	}
	l.total = o
	return l
}

// As labels a layout for the refusals it will raise ("M704", "M126Crv") and
// returns it, so it chains onto NewLayout at the var declaration. Purely
// cosmetic — see Layout.name.
func (l *Layout) As(name string) *Layout { l.name = name; return l }

// Name is the layout's label, or "" for a layout that was never labelled.
func (l *Layout) Name() string { return l.name }

// Len is the total register count of one instance of this layout.
func (l *Layout) Len() int { return l.total }

// Has reports whether the layout defines a point with this name.
func (l *Layout) Has(name string) bool { _, ok := l.off[name]; return ok }

// Offset returns the 0-based register offset of a named point (-1 if absent).
func (l *Layout) Offset(name string) int {
	if o, ok := l.off[name]; ok {
		return o
	}
	return -1
}

// FieldOf returns the layout's own declaration of a named point — its type, its
// scale-factor binding and its width.
//
// It exists so decode and encode can DERIVE a point's scale factor from the
// layout instead of restating it as a string literal at each call site. A
// restated binding is a defect class a round-trip test structurally cannot see:
// if the reader and the writer name the same WRONG scale factor, the value
// round-trips green and only the device receives a curve that is wrong by a
// power of ten. The layout is the one place a binding is proven against the
// vendored spec (TestLayoutsMatchVendoredSpec), so it is the one place a
// binding may be stated.
func (l *Layout) FieldOf(name string) (Field, bool) {
	f, ok := l.typ[name]
	return f, ok
}

// View binds a layout to a register slice for reading and writing.
func (l *Layout) View(regs []uint16) View { return View{regs: regs, l: l, base: 0} }

// ViewAt binds a layout to a register slice with a base offset, used for
// repeating sub-groups (e.g. one curve within a curve list).
func (l *Layout) ViewAt(regs []uint16, base int) View { return View{regs: regs, l: l, base: base} }

// View is a typed cursor over a register slice for one layout instance.
type View struct {
	regs []uint16
	l    *Layout
	base int
}

// in-bounds register read; returns 0 when out of range so partial models
// (a device that implements fewer optional points) never panic.
func (v View) reg(o int) uint16 {
	i := v.base + o
	if i >= 0 && i < len(v.regs) {
		return v.regs[i]
	}
	return 0
}

func (v View) setReg(o int, val uint16) {
	i := v.base + o
	if i >= 0 && i < len(v.regs) {
		v.regs[i] = val
	}
}

func (v View) fieldOff(name string) (int, Field, bool) {
	o, ok := v.l.off[name]
	if !ok {
		return 0, Field{}, false
	}
	return o, v.l.typ[name], true
}

// Present reports whether the field exists in the layout AND its registers are
// within the bound slice (i.e. the device actually implements this far).
func (v View) Present(name string) bool {
	o, f, ok := v.fieldOff(name)
	if !ok {
		return false
	}
	return v.base+o+f.Type.regs(f.Len) <= len(v.regs)
}

// rawU32/rawU64 assemble multi-register values big-endian (high word first).
func (v View) rawU32(o int) uint32 { return uint32(v.reg(o))<<16 | uint32(v.reg(o+1)) }
func (v View) rawU64(o int) uint64 {
	return uint64(v.reg(o))<<48 | uint64(v.reg(o+1))<<32 | uint64(v.reg(o+2))<<16 | uint64(v.reg(o+3))
}

// ── Sentinels ────────────────────────────────────────────────────────────────

const (
	sentU16 = uint16(0xFFFF)
	sentI16 = uint16(0x8000)
	sentU32 = uint32(0xFFFFFFFF)
	sentI32 = uint32(0x80000000)
	sentU64 = uint64(0xFFFFFFFFFFFFFFFF)
	sentI64 = uint64(0x8000000000000000)
)

// ── Max-valid clamp edges (audit SUN-004) ────────────────────────────────────
//
// The largest-magnitude value a point of each type may carry as REAL data: the
// full type range MINUS the single bit pattern the SunSpec spec reserves as the
// "not implemented / unknown" sentinel. A finite, in-service value that merely
// exceeds the range clamps to THESE edges, never onto the reserved sentinel —
// encoding a real measurement/command AS 0x8000 / 0xFFFF / 0x80000000 /
// 0xFFFFFFFF would corrupt it into "not implemented" on the wire.
//
// Signed types reserve the negative extreme (0x8000 / 0x80000000), so their
// max-valid LOW edge is one above the type minimum (−32767 / −2147483647), NOT
// the type MIN itself. Accumulators (Tacc*) instead reserve 0 as their
// sentinel, so their full-scale maximum (0xFFFFFFFF) is valid data — they are
// deliberately NOT listed here and take a plain clamp to the type maximum.
const (
	maxValidI16 = float64(32767)       // hi 0x7FFF     (0x8000     reserved sentinel)
	minValidI16 = float64(-32767)      // lo 0x8001     (0x8000     reserved sentinel)
	maxValidU16 = float64(65534)       // hi 0xFFFE     (0xFFFF     reserved sentinel)
	maxValidI32 = float64(2147483647)  // hi 0x7FFFFFFF (0x80000000 reserved sentinel)
	minValidI32 = float64(-2147483647) // lo 0x80000001 (0x80000000 reserved sentinel)
	maxValidU32 = float64(4294967294)  // hi 0xFFFFFFFE (0xFFFFFFFF reserved sentinel)
)

// notImpl reports whether the raw value of a field equals its type's
// "not implemented" sentinel.
func (v View) notImpl(o int, f Field) bool {
	switch f.Type {
	case Tuint16, Tenum16, Tbitfield16:
		return v.reg(o) == sentU16
	case Tint16, Tsunssf:
		return v.reg(o) == sentI16
	case Tuint32, Tenum32, Tbitfield32:
		return v.rawU32(o) == sentU32
	case Tint32:
		return v.rawU32(o) == sentI32
	case Tuint64:
		return v.rawU64(o) == sentU64
	case Tint64:
		return v.rawU64(o) == sentI64
	}
	// Accumulators have no NaN sentinel; 0 is a valid (un-accumulated) value.
	return false
}

// ReadLooksCorrupt reports whether a register block just READ for this layout
// looks like a failed or partial read that must NOT be written back (audit E2).
// A whole-block read-modify-write trusts its own read; if that read returned
// sentinel garbage (a device rebooting mid-poll, or a fault-injected all-0x8000
// read), writing it back programs junk — sentinel setpoints, spurious sync-group
// enables — into the device's control registers.
//
// Two signals, in priority order:
//
//  1. A scale-factor field (Tsunssf) reads the 0x8000 sentinel or any value
//     outside the legal sunssf domain [-10,+10] (LXR-004). Scale factors are
//     read-only device constants; a healthy SunSpec block ALWAYS carries
//     valid ones, so an illegal SF is a low-false-positive corruption signal
//     and is authoritative when the layout defines any SF fields.
//  2. Only when the layout has NO scale factors to check: the block is
//     saturated with the int16 not-implemented sentinel (≥ half its registers) —
//     the all-0x8000 shape of a failed read.
//
// It reads only; the caller decides what to do (derbase's writers refuse the
// write-back and return an error).
func (v View) ReadLooksCorrupt() bool {
	hasSF := false
	for _, f := range v.l.Fields {
		if f.Type != Tsunssf {
			continue
		}
		hasSF = true
		if v.Present(f.Name) && !ValidSF(int16(v.reg(v.l.off[f.Name]))) {
			return true
		}
	}
	if hasSF {
		return false // scale factors present and sane ⇒ the read is real
	}
	// No SF fields — fall back to whole-block sentinel saturation.
	n := v.l.Len()
	if n == 0 {
		return false
	}
	sent := 0
	for o := 0; o < n; o++ {
		if v.reg(o) == sentI16 {
			sent++
		}
	}
	return sent*2 >= n
}

// ── Integer getters (ok=false on absent or sentinel) ─────────────────────────

func (v View) Enum(name string) (uint16, bool) {
	o, f, ok := v.fieldOff(name)
	if !ok || !v.Present(name) || v.notImpl(o, f) {
		return 0, false
	}
	return v.reg(o), true
}

func (v View) Bool(name string) bool {
	val, ok := v.Enum(name)
	return ok && val == 1
}

// Bitfield32 reads a bitfield32 point, collapsing "absent" and "not
// implemented" onto the EMPTY bitfield.
//
// That collapse is correct for a STATUS bitfield — a device that does not
// implement its alarm word is raising no alarms — and it is a laundering
// hazard for a CAPABILITY one, because a caller that reads an empty capability
// word as "the device stated no restrictions" has turned an explicit NOT
// IMPLEMENTED into permission for everything (2026-08-03 audit finding 4).
// Any bitfield that GRANTS something must be read through Bitfield32OK, which
// keeps the three states apart.
func (v View) Bitfield32(name string) uint32 {
	val, _ := v.Bitfield32OK(name)
	return val
}

// Bitfield32OK reads a bitfield32 point and reports whether the device
// IMPLEMENTS it: ok=false when the point is absent from the block or carries
// the bitfield32 not-implemented sentinel (0xFFFFFFFF).
//
// This is the deny-by-default reader. It exists so a capability consumer can
// tell the three states apart — implemented-and-set, implemented-and-clear,
// and absent/not-implemented — instead of receiving the same zero for the last
// two and having to guess which one it holds.
func (v View) Bitfield32OK(name string) (uint32, bool) {
	o, f, ok := v.fieldOff(name)
	if !ok || !v.Present(name) || v.notImpl(o, f) {
		return 0, false
	}
	return v.rawU32(o), true
}

func (v View) U32(name string) (uint32, bool) {
	o, f, ok := v.fieldOff(name)
	if !ok || !v.Present(name) || v.notImpl(o, f) {
		return 0, false
	}
	return v.rawU32(o), true
}

func (v View) U64(name string) (uint64, bool) {
	o, f, ok := v.fieldOff(name)
	if !ok || !v.Present(name) || v.notImpl(o, f) {
		return 0, false
	}
	return v.rawU64(o), true
}

// SF returns the int16 scale-factor value of a named sunssf field. ok=false
// when absent, unimplemented, or outside the legal sunssf domain [-10,+10]
// (LXR-004): a hostile or corrupt scale-factor register must never reach
// math.Pow10 — every scaled read through this View becomes NaN and every
// scaled write becomes a refusal instead of garbage arithmetic.
func (v View) SF(name string) (int16, bool) {
	o, f, ok := v.fieldOff(name)
	if !ok || !v.Present(name) || f.Type != Tsunssf || !ValidSF(int16(v.reg(o))) {
		return 0, false
	}
	return int16(v.reg(o)), true
}

// Raw returns a point's RAW register content as an unsigned integer — the bits
// exactly as they arrived on the wire, with NO scale factor applied and no
// sign extension — and reports whether the device IMPLEMENTS the point.
//
// It exists for consumers that compare a point against ITSELF across reads
// rather than interpreting its value: derbase's liveness digest asks "did these
// registers move between two polls", and for that question the engineering
// value is strictly worse than the raw word. Two different raw words can scale
// onto the same float64 (rounding), and a scale factor is a device constant
// that must not participate in the comparison at all — so a digest built from
// Float() would be both less sensitive and coupled to a register the digest
// deliberately excludes.
//
// ok=false when the point is absent from the layout, beyond the bound register
// slice, carries its type's not-implemented sentinel, or is a string/pad field
// (which have no numeric content). Accumulators (Tacc*) have no sentinel — 0 is
// a valid un-accumulated value — so they read ok=true at zero, exactly as
// Float does.
func (v View) Raw(name string) (uint64, bool) {
	o, f, ok := v.fieldOff(name)
	if !ok || !v.Present(name) || v.notImpl(o, f) {
		return 0, false
	}
	switch f.Type {
	case Tuint16, Tint16, Tenum16, Tbitfield16, Tsunssf:
		return uint64(v.reg(o)), true
	case Tuint32, Tint32, Tenum32, Tbitfield32, Tacc32:
		return uint64(v.rawU32(o)), true
	case Tuint64, Tint64, Tacc64:
		return v.rawU64(o), true
	}
	return 0, false // Tstring / Tpad carry no numeric content
}

// ── Scaled float getter ──────────────────────────────────────────────────────

// Float reads a numeric point and applies its scale factor, returning the
// engineering value. Returns NaN when the point or its scale factor is absent
// or carries a not-implemented sentinel. Signed vs unsigned is taken from the
// field's declared type. PF-style ×100 fields are NOT special-cased here; the
// caller divides by 100 where the spec uses centi-units.
func (v View) Float(name string) float64 {
	o, f, ok := v.fieldOff(name)
	if !ok || !v.Present(name) || v.notImpl(o, f) {
		return math.NaN()
	}
	sf := int16(0)
	if f.SF != "" {
		s, ok := v.SF(f.SF)
		if !ok {
			return math.NaN()
		}
		sf = s
	}
	var raw float64
	switch f.Type {
	case Tint16, Tsunssf:
		raw = float64(int16(v.reg(o)))
	case Tuint16, Tenum16:
		raw = float64(v.reg(o))
	case Tint32:
		raw = float64(int32(v.rawU32(o)))
	case Tuint32, Tacc32:
		raw = float64(v.rawU32(o))
	case Tint64:
		raw = float64(int64(v.rawU64(o)))
	case Tuint64, Tacc64:
		raw = float64(v.rawU64(o))
	default:
		return math.NaN()
	}
	return raw * math.Pow10(int(sf))
}

// ── Setters ──────────────────────────────────────────────────────────────────

// SetEnum writes a uint16/enum16 point.
func (v View) SetEnum(name string, val uint16) {
	if o, _, ok := v.fieldOff(name); ok {
		v.setReg(o, val)
	}
}

// SetBool writes 1 (true) or 0 (false) to an enable point.
func (v View) SetBool(name string, b bool) {
	if b {
		v.SetEnum(name, 1)
	} else {
		v.SetEnum(name, 0)
	}
}

// SetU32 writes a big-endian uint32 point.
func (v View) SetU32(name string, val uint32) {
	if o, _, ok := v.fieldOff(name); ok {
		v.setReg(o, uint16(val>>16))
		v.setReg(o+1, uint16(val))
	}
}

// SetFloat writes an engineering value to a scaled point, encoding it with the
// point's scale factor (read live from the slice). A finite out-of-range value
// clamps to the field's MAX-VALID representable edge, never onto the reserved
// not-implemented sentinel (audit SUN-004).
//
// # It REFUSES rather than silently dropping a commanded value (IW15-022)
//
// When the point declares a scale factor and View.SF cannot read it — the
// register is absent, carries the 0x8000 not-implemented sentinel, or sits
// outside the sunssf domain [−10,+10] (LXR-004) — SetFloat returns a
// *ScaleFactorError naming the point, the model and the scale-factor register,
// and writes NOTHING.
//
// It used to return silently there, which is the scalar half of the defect the
// 7xx curve encoders closed in 11e8b7d: the register kept whatever it held, the
// writer reported success, and the surrounding actuation proceeded as if the
// value had landed. The independent read-back axes still caught the divergence,
// but as a device that would not converge rather than as "your WSet_SF register
// is unreadable" — an unattributed failure the operator cannot act on.
//
// The refusal happens BEFORE any register moves, so a caller's buffer is never
// left half-written (asserted by TestSetFloatRefusalMovesNoRegister). Multi-
// point encoders that write into a buffer they did not allocate must still plan
// before they apply — check every point, then write — because SetFloat's own
// atomicity says nothing about the write that preceded it; Encode703 is the
// worked example.
//
// # What stays silent, deliberately
//
//   - A NaN value is NOT commanded — there is nothing to write and nothing to
//     refuse. A device is entitled not to implement a scale factor for a point
//     nobody is writing.
//   - A name this layout does not declare is a no-op returning nil, unchanged.
//     Consumers depend on it: lexa-gw's regmap feeds a name set spanning
//     several model revisions into one layout and relies on the unknown ones
//     falling away. Turning that into an error would convert a documented
//     idiom into a flood of refusals at re-vendor, and it is not this defect —
//     a name absent from the LAYOUT is a fact about the code, knowable without
//     a device, whereas an unreadable scale factor is a fact about the machine
//     that only shows up in the field.
//   - An unscaled point (Field.SF == "") cannot fail: it never consults SF.
//     That is why derbase's writeWRmp/writeVarRmp can never raise this.
//
// # Why refusing is right even though a CONFORMANT device can trip it
//
// IW15-022 recorded that every 7xx scale factor is declared MANDATORY, so that
// only a non-conformant device could ever be refused. That holds for the CURVE
// models (705-712) and is false for the scalar ones: 702, 703 and 704 declare
// all fifteen of their scale factors OPTIONAL, measured by
// TestScalarModelScaleFactorsAreOptionalUnlikeTheCurves. So the pre-fix silent
// skip did not need a broken machine — a conformant 704 that does not
// implement WSet_SF dropped every WSet written to it and reported success.
//
// Refusing is still the only truthful answer, because a scaled point whose
// scale factor is unimplemented has no encoding at all: there is no register
// content on that device that means "3500 W". A device that omits WSet_SF is
// saying it does not do WSet, and a named refusal is what the operator can act
// on. For a scale factor that is present but hostile or corrupt, refusing is
// additionally the fail-closed answer LXR-004 requires.
func (v View) SetFloat(name string, val float64) error {
	o, f, ok := v.fieldOff(name)
	if !ok || math.IsNaN(val) {
		return nil
	}
	sf := int16(0)
	if f.SF != "" {
		s, ok := v.SF(f.SF)
		if !ok {
			return &ScaleFactorError{Model: v.l.name, Point: name, SFName: f.SF, Value: val}
		}
		sf = s
	}
	scaled := math.Round(val / math.Pow10(int(sf)))
	switch f.Type {
	case Tint16, Tsunssf:
		v.setReg(o, uint16(int16(clamp(scaled, minValidI16, maxValidI16))))
	case Tuint16, Tenum16:
		v.setReg(o, uint16(clamp(scaled, 0, maxValidU16)))
	case Tint32:
		x := int32(clamp(scaled, minValidI32, maxValidI32))
		v.setReg(o, uint16(uint32(x)>>16))
		v.setReg(o+1, uint16(uint32(x)))
	case Tacc32:
		// Accumulator: the not-implemented sentinel is 0, so the full-scale
		// 0xFFFFFFFF is valid data — plain clamp to the type maximum.
		x := uint32(clamp(scaled, 0, math.MaxUint32))
		v.setReg(o, uint16(x>>16))
		v.setReg(o+1, uint16(x))
	case Tuint32:
		x := uint32(clamp(scaled, 0, maxValidU32))
		v.setReg(o, uint16(x>>16))
		v.setReg(o+1, uint16(x))
	default:
		// The name IS declared and the caller DID command a value, but this
		// type has no arm above (Tuint64/Tint64/Tacc64/Tstring/Tpad) — so the
		// write vanished. Same defect class as the scale-factor skip and
		// refused for the same reason; it is the unknown-NAME case that stays
		// silent, not this one. No caller in this module can reach it (every
		// SetFloat target in 702/703/704 is 16- or 32-bit), which is precisely
		// why it went unnoticed.
		return &PointTypeError{Model: v.l.name, Point: name, Value: val}
	}
	return nil
}

func clamp(v, lo, hi float64) float64 {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

// ── Absolute-offset accessors (for repeating curve / port groups) ────────────
//
// Repeating sub-groups (curve points, DC ports) reference scale factors that
// live in the model header, so they cannot use a base-shifted sub-View. These
// helpers read/write a raw register at an absolute model offset and apply a
// scale factor resolved by name from the (full-model) View.

func (v View) U16At(o int) uint16         { return v.reg(o) }
func (v View) I16At(o int) int16          { return int16(v.reg(o)) }
func (v View) U32At(o int) uint32         { return v.rawU32(o) }
func (v View) U64At(o int) uint64         { return v.rawU64(o) }
func (v View) SetU16At(o int, val uint16) { v.setReg(o, val) }

// ScaleSignedAt reads an int16 at offset o and scales it by the named SF.
func (v View) ScaleSignedAt(o int, sfName string) float64 {
	s, ok := v.SF(sfName)
	if !ok || v.reg(o) == sentI16 {
		return math.NaN()
	}
	return float64(int16(v.reg(o))) * math.Pow10(int(s))
}

// ScaleUintAt reads a uint16 at offset o and scales it by the named SF.
func (v View) ScaleUintAt(o int, sfName string) float64 {
	s, ok := v.SF(sfName)
	if !ok || v.reg(o) == sentU16 {
		return math.NaN()
	}
	return float64(v.reg(o)) * math.Pow10(int(s))
}

// ScaleU32At reads a uint32 at offset o (e.g. frequency points) and scales it.
func (v View) ScaleU32At(o int, sfName string) float64 {
	s, ok := v.SF(sfName)
	if !ok || v.rawU32(o) == sentU32 {
		return math.NaN()
	}
	return float64(v.rawU32(o)) * math.Pow10(int(s))
}

// SetScaledSignedAt encodes val as an int16 at offset o using the named SF.
func (v View) SetScaledSignedAt(o int, val float64, sfName string) {
	s, ok := v.SF(sfName)
	if !ok || math.IsNaN(val) {
		return
	}
	r := math.Round(val / math.Pow10(int(s)))
	v.setReg(o, uint16(int16(clamp(r, minValidI16, maxValidI16))))
}

// SetScaledUintAt encodes val as a uint16 at offset o using the named SF.
func (v View) SetScaledUintAt(o int, val float64, sfName string) {
	s, ok := v.SF(sfName)
	if !ok || math.IsNaN(val) {
		return
	}
	r := math.Round(val / math.Pow10(int(s)))
	v.setReg(o, uint16(clamp(r, 0, maxValidU16)))
}

// SetScaledU32At encodes val as a big-endian uint32 at offset o using the SF.
func (v View) SetScaledU32At(o int, val float64, sfName string) {
	s, ok := v.SF(sfName)
	if !ok || math.IsNaN(val) {
		return
	}
	x := uint32(clamp(math.Round(val/math.Pow10(int(s))), 0, maxValidU32))
	v.setReg(o, uint16(x>>16))
	v.setReg(o+1, uint16(x))
}
