package sunspec

import (
	"errors"
	"fmt"
)

// ErrGeometryUnknown is the sentinel every geometry failure unwraps to.
//
// A device whose declared model length, NCrv and NPt do not agree with the
// model's spec block length has a register map this package cannot compute
// offsets in. The only safe answer is to refuse: a guessed offset writes a
// grid-support curve into whatever registers happen to be there. Callers
// translate this into a capability of Unknown and an axis that answers
// CannotComply — never into a best-effort read.
var ErrGeometryUnknown = errors.New("sunspec: legacy curve geometry unknown")

// GeometryError says which model failed the geometry gate and why, and unwraps
// to ErrGeometryUnknown so callers can match on either.
type GeometryError struct {
	ModelID uint16
	Detail  string
}

func (e *GeometryError) Error() string {
	return fmt.Sprintf("sunspec: model %d geometry unknown: %s", e.ModelID, e.Detail)
}

func (e *GeometryError) Unwrap() error { return ErrGeometryUnknown }

// ErrScaleFactorUnavailable is the sentinel for "this point was commanded, but
// the scale factor it is encoded against cannot be read".
//
// The OFFSET-ADDRESSED View setters (SetScaledUintAt / SetScaledSignedAt /
// SetScaledU32At) return SILENTLY when View.SF fails — the scale-factor point
// is absent, carries the 0x8000 not-implemented sentinel, or is outside the
// sunssf domain [−10,+10] (LXR-004). Silence is the wrong answer for a
// COMMANDED value: the register keeps whatever it held, the encoder reports
// success, and the read-back comparison becomes the only thing standing
// between that and a control the operator believes is in force. Those three
// are reachable ONLY through der1547.go's setScaledUint/setScaledSigned/
// setScaledU32 wrappers, which pre-check the scale factor and raise this
// error, so the silent tier has no caller that can drop a commanded value.
//
// View.SetFloat — the NAME-addressed setter derbase's scalar writers use —
// raises it directly rather than through a wrapper (IW15-022): it can resolve
// the point's scale-factor binding, and the model label, from the layout
// itself, so there is nothing for a wrapper to supply.
//
// A value the caller did NOT command (NaN) never raises this: a device is
// entitled not to implement a scale factor for a point nobody is writing.
var ErrScaleFactorUnavailable = errors.New("sunspec: scale factor unreadable for a commanded point")

// ScaleFactorError names the point that could not be encoded and the
// scale-factor register that was unreadable. It unwraps to
// ErrScaleFactorUnavailable.
type ScaleFactorError struct {
	Model  string  // model label, e.g. "M705"; "" for an unlabelled layout
	Point  string  // the point being written, e.g. "VRef"
	SFName string  // the scale-factor point that could not be read
	Value  float64 // the engineering value that was commanded
}

func (e *ScaleFactorError) Error() string {
	return fmt.Sprintf("sunspec: %spoint %s: cannot encode %g — scale factor %s is absent, "+
		"not implemented, or outside the sunssf domain",
		modelPrefix(e.Model), e.Point, e.Value, e.SFName)
}

func (e *ScaleFactorError) Unwrap() error { return ErrScaleFactorUnavailable }

// ErrPointNotEncodable is the sentinel for a commanded value whose point has no
// scaled-float encoding at all.
//
// View.SetFloat encodes the 16- and 32-bit numeric types. A 64-bit point, a
// string or a pad has no arm in its type switch, so before IW15-022 a caller
// that named one had its value silently discarded — the same "commanded value
// dropped, success reported" shape as the scale-factor skip, reached by a
// different route. No caller inside this module can produce it (every SetFloat
// target in models 702/703/704 is 16- or 32-bit, and 64-bit points are written
// through their own helpers), which is exactly why it survived unnoticed.
var ErrPointNotEncodable = errors.New("sunspec: point type has no scaled-float encoding")

// PointTypeError names a declared point whose type SetFloat cannot encode. It
// unwraps to ErrPointNotEncodable.
type PointTypeError struct {
	Model string  // model label, e.g. "M802"; "" for an unlabelled layout
	Point string  // the point being written
	Value float64 // the engineering value that was commanded
}

func (e *PointTypeError) Error() string {
	return fmt.Sprintf("sunspec: %spoint %s: cannot encode %g — SetFloat covers the 16- and "+
		"32-bit numeric types only; 64-bit, string and pad points need their own writer",
		modelPrefix(e.Model), e.Point, e.Value)
}

func (e *PointTypeError) Unwrap() error { return ErrPointNotEncodable }

// modelPrefix renders a layout label for an error message, or nothing at all
// when the layout was never labelled — a consumer-built layout should read
// "sunspec: point Crv1.Pt1.V: ..." rather than "sunspec:  point ...".
func modelPrefix(model string) string {
	if model == "" {
		return ""
	}
	return model + " "
}

// ErrNotRepresentable is the sentinel for a value that cannot be encoded at the
// device's declared scale factor.
//
// The 7xx curve encoders use the silently-clamping setter tier and rely on the
// read-back hash to catch the clamp afterwards. The legacy curve encoders do
// NOT: a clamped or quantised curve point is a silently DIFFERENT grid-support
// curve, and legacy scale factors are coarse and vendor-chosen. Refusing up
// front produces a named reason the customer can be told, which is strictly
// better than discovering the difference in a read-back diff.
//
// Note that this is a STRONGER contract than EncodeOutcome.Representable()
// alone provides. That tier reports SATURATION — a value outside the register's
// range — and silently rounds everything inside it. Rounding is exactly the
// loss that matters here: V_SF = 0 on a 126 quantises volt points to whole
// percent, so a 102.5 %V breakpoint would be delivered as 103 %V with an
// EncodeExact outcome. The legacy encoders therefore add a quantisation check
// on top of the tier and refuse both failures through this one sentinel.
var ErrNotRepresentable = errors.New("sunspec: value not representable at the device's scale factor")

// NotRepresentableError names the point that could not be represented, with
// the value and scale factor that made it impossible.
type NotRepresentableError struct {
	ModelID uint16
	Point   string  // spec point name, e.g. "V3"
	Value   float64 // requested engineering value
	SF      int16   // the device's declared scale factor for that point
	Outcome EncodeOutcome
	// Quantised distinguishes the two failure kinds: true means the value fits
	// the register's range but cannot be expressed EXACTLY at this scale
	// factor (the delivered curve would differ from the commanded one), false
	// means the tier itself refused — saturation, a non-finite value, or a
	// scale factor outside the sunssf domain.
	Quantised bool
}

func (e *NotRepresentableError) Error() string {
	if e.Quantised {
		return fmt.Sprintf("sunspec: model %d point %s: %g cannot be expressed exactly at SF=%d "+
			"(the device would receive a different value)", e.ModelID, e.Point, e.Value, e.SF)
	}
	return fmt.Sprintf("sunspec: model %d point %s: %g not representable at SF=%d (%s)",
		e.ModelID, e.Point, e.Value, e.SF, encodeOutcomeName(e.Outcome))
}

func (e *NotRepresentableError) Unwrap() error { return ErrNotRepresentable }

func encodeOutcomeName(o EncodeOutcome) string {
	switch o {
	case EncodeExact:
		return "exact"
	case EncodeSaturatedHigh:
		return "saturated high"
	case EncodeSaturatedLow:
		return "saturated low"
	case EncodeNotImplemented:
		return "not implemented (non-finite)"
	case EncodeBadSF:
		return "scale factor outside the sunssf domain"
	}
	return "unknown"
}
