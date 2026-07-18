package aggregator

import (
	"fmt"
	"math"

	"lexa-proto/mbap"
	"lexa-proto/sunspec"
)

// Control + denial primitives. These are the building blocks the scenario-
// campaign (T06.6), readback-verification (T06.7), and role-denial-matrix
// (T06.8) tasks compose; the core provides a correct typed write, a typed read,
// and a denial probe — no oracle/verdict logic (that is the campaign engine's).

// fixedLayouts maps the fixed-shape SunSpec DER models (single Layout, no
// repeating sub-groups) to their layout. Only these are safe for the point-
// addressed WritePoint/ReadPoint: the curve/port models (705-712, 714) have
// runtime-strided repeating groups whose per-point offsets are not a single
// static layout, so writing a point in one needs the group-aware encoders that
// belong to a later task.
var fixedLayouts = map[uint16]*sunspec.Layout{
	701: sunspec.L701,
	702: sunspec.L702,
	703: sunspec.L703,
	704: sunspec.L704,
	713: sunspec.L713,
}

// layoutFor returns the fixed-shape layout for a model id.
func layoutFor(model uint16) (*sunspec.Layout, error) {
	l, ok := fixedLayouts[model]
	if !ok {
		return nil, fmt.Errorf("aggregator: model %d has no fixed-shape layout (curve/port models need group-aware writes — later task)", model)
	}
	return l, nil
}

// fieldFor finds a named field in a layout and returns its width in registers.
// The width mirrors the codec's own FieldType→register mapping (stable spec
// data); it is duplicated here rather than reached through the codec's private
// helper so WritePoint can address exactly the point's registers.
func fieldFor(l *sunspec.Layout, point string) (sunspec.Field, int, error) {
	for _, f := range l.Fields {
		if f.Name == point {
			return f, fieldRegs(f), nil
		}
	}
	return sunspec.Field{}, 0, fmt.Errorf("aggregator: point %q not in layout", point)
}

// fieldRegs returns the register width of a SunSpec field type.
func fieldRegs(f sunspec.Field) int {
	switch f.Type {
	case sunspec.Tuint16, sunspec.Tint16, sunspec.Tenum16, sunspec.Tbitfield16, sunspec.Tsunssf:
		return 1
	case sunspec.Tuint32, sunspec.Tint32, sunspec.Tenum32, sunspec.Tbitfield32, sunspec.Tacc32:
		return 2
	case sunspec.Tuint64, sunspec.Tint64, sunspec.Tacc64:
		return 4
	case sunspec.Tstring, sunspec.Tpad:
		return f.Len
	}
	return 1
}

// WritePoint writes a single named control point on unit, encoding value with
// the point's LIVE scale factor read from the device — never a raw cast, so an
// out-of-range watt/percent can never wrap an int16 register (CODING_PRINCIPLES
// §3; audit GS-1/MTR-1). It reads the model first (to learn the scale factor and
// the surrounding registers), encodes value at the point's offset, and writes
// exactly that point's register window (FC 16) — leaving read-only scale-factor
// cells and neighbouring points untouched.
//
// Scaled numeric points (WMaxLimPct, WSet, …) encode through the layout's
// scale-factor-aware SetFloat; enum/bitfield points (WMaxLimPctEna, …) take the
// integer value verbatim. String/pad points are not writable here.
func (c *Conn) WritePoint(unit uint8, model uint16, point string, value float64) error {
	off, words, err := c.encodePoint(unit, model, point, value)
	if err != nil {
		return err
	}
	return c.WriteMultiple(unit, off, words)
}

// encodePoint reads model on unit, encodes value into point using the live scale
// factor, and returns the absolute register address of the point plus the
// register words to write. The read exercises the same reader cache Discover/
// Poll use.
func (c *Conn) encodePoint(unit uint8, model uint16, point string, value float64) (addr uint16, words []uint16, err error) {
	layout, err := layoutFor(model)
	if err != nil {
		return 0, nil, err
	}
	f, n, err := fieldFor(layout, point)
	if err != nil {
		return 0, nil, err
	}
	offset := layout.Offset(point)
	if offset < 0 {
		return 0, nil, fmt.Errorf("aggregator: point %q has no offset in model %d", point, model)
	}

	r, err := c.readerFor(unit)
	if err != nil {
		return 0, nil, fmt.Errorf("aggregator: write %s.%s on unit %d: scan device: %w", modelName(model), point, unit, err)
	}
	block, err := findBlock(r, model)
	if err != nil {
		return 0, nil, err
	}
	regs, err := r.ReadModel(model)
	if err != nil {
		return 0, nil, fmt.Errorf("aggregator: write %s.%s on unit %d: read model for scale factor: %w", modelName(model), point, unit, err)
	}
	if len(regs) < offset+n {
		return 0, nil, fmt.Errorf("aggregator: model %d read too short (%d regs) for point %q at %d+%d", model, len(regs), point, offset, n)
	}

	// Encode into a copy so the point's live scale factor (read above) governs
	// the raw value, then lift out exactly the point's registers.
	scratch := append([]uint16(nil), regs...)
	view := layout.View(scratch)
	if err := setPoint(view, f, point, value); err != nil {
		return 0, nil, err
	}
	words = append([]uint16(nil), scratch[offset:offset+n]...)
	return block.BaseAddr + uint16(offset), words, nil
}

// setPoint writes value into a layout view at a named point, dispatching on the
// field type so a scaled numeric uses the scale-factor-aware setter and an
// enum/bitfield takes the integer value directly.
func setPoint(v sunspec.View, f sunspec.Field, point string, value float64) error {
	switch f.Type {
	case sunspec.Tint16, sunspec.Tuint16, sunspec.Tint32, sunspec.Tuint32, sunspec.Tacc32:
		v.SetFloat(point, value)
	case sunspec.Tenum16, sunspec.Tbitfield16:
		v.SetEnum(point, uint16(value))
	case sunspec.Tenum32, sunspec.Tbitfield32:
		v.SetU32(point, uint32(value))
	default:
		return fmt.Errorf("aggregator: point %q (type %d) is not writable via WritePoint", point, f.Type)
	}
	return nil
}

// ReadPoint reads a single named point on unit as an engineering value (scale
// factor applied). It returns NaN — not an error — when the point is present but
// unimplemented/sentinel on the device (the codec's absence convention), so a
// readback loop can tell "not converged yet" from a transport failure.
func (c *Conn) ReadPoint(unit uint8, model uint16, point string) (float64, error) {
	layout, err := layoutFor(model)
	if err != nil {
		return math.NaN(), err
	}
	if !layout.Has(point) {
		return math.NaN(), fmt.Errorf("aggregator: point %q not in model %d layout", point, model)
	}
	r, err := c.readerFor(unit)
	if err != nil {
		return math.NaN(), fmt.Errorf("aggregator: read %s.%s on unit %d: scan device: %w", modelName(model), point, unit, err)
	}
	regs, err := r.ReadModel(model)
	if err != nil {
		return math.NaN(), fmt.Errorf("aggregator: read %s.%s on unit %d: %w", modelName(model), point, unit, err)
	}
	return layout.View(regs).Float(point), nil
}

// findBlock locates a model's block (for its base address) in a reader's scanned
// layout.
func findBlock(r *sunspec.Reader, model uint16) (sunspec.Block, error) {
	b, err := sunspec.FindModel(r.Blocks(), model)
	if err != nil {
		return sunspec.Block{}, fmt.Errorf("aggregator: %w", err)
	}
	return b, nil
}

// modelName is a terse label for error messages.
func modelName(model uint16) string { return fmt.Sprintf("M%d", model) }

// DenialResult records the outcome of a role-denial probe — the JSON-
// serializable evidence the denial-matrix oracle (T06.8) judges. The core does
// NOT decide PASS/FAIL; it reports exactly what happened so the oracle can
// assert "exception 0x01 and nothing else" (TCP-40/41): a write that was
// ACCEPTED (Wrote=true) is an authz gap, a denial with the wrong code is a
// different bug, and only ExceptionCode==1 is a correct denial.
type DenialResult struct {
	Unit          uint8  `json:"unit"`
	Model         uint16 `json:"model"`
	Point         string `json:"point"`
	Stage         string `json:"stage"`          // "write" normally; "read" if even the setpoint read was denied
	FC            uint8  `json:"fc"`             // function code that was denied (0x10 write / 0x03 read)
	Denied        bool   `json:"denied"`         // true iff the op returned exception 0x01 (illegal function / authz)
	ExceptionCode uint8  `json:"exception_code"` // exception code observed; 0 if the op succeeded
	Wrote         bool   `json:"wrote"`          // true iff the write was accepted (an authz gap)
}

// ProbeDenied attempts a control write on unit as the current role and reports
// how the gateway answered — the role-denial primitive the scenario campaigns
// compose into a full grant/deny matrix. It reads the model to encode value at
// the point's live scale factor (a read the read-only roles this targets are
// allowed to make); if even that read is denied, it reports the read-stage
// exception. The returned error is non-nil ONLY for a transport failure (a
// broken session) — a protocol exception is the expected, reported outcome, not
// an error.
//
// For a correctly-denied write the caller asserts res.Denied (ExceptionCode==1);
// res.Wrote==true means the write was wrongly accepted.
func (c *Conn) ProbeDenied(unit uint8, model uint16, point string, value float64) (DenialResult, error) {
	res := DenialResult{Unit: unit, Model: model, Point: point, Stage: "write", FC: mbap.FCWriteMultiple}

	addr, words, err := c.encodePoint(unit, model, point, value)
	if err != nil {
		// The setpoint read (needed for the scale factor) may itself be denied
		// for a fully-unauthorized role — surface that as a read-stage exception
		// rather than a plain setup failure. Any other error (bad point, short
		// model, transport break) is returned as-is.
		if ex, ok := AsException(err); ok {
			res.Stage = "read"
			res.FC = mbap.FCReadHolding
			res.ExceptionCode = uint8(ex.Code)
			res.Denied = ex.Code == mbap.ExIllegalFunction
			return res, nil
		}
		return res, err
	}

	werr := c.WriteMultiple(unit, addr, words)
	if werr == nil {
		res.Wrote = true
		return res, nil
	}
	if ex, ok := AsException(werr); ok {
		res.ExceptionCode = uint8(ex.Code)
		res.Denied = ex.Code == mbap.ExIllegalFunction
		return res, nil
	}
	return res, werr // transport failure
}
