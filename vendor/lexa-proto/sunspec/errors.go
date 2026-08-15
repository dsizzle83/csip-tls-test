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
