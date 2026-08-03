package derbase

import (
	"errors"
	"fmt"
	"time"
)

// Typed control/device error vocabulary (LXR-002/-003/-005/-006).
//
// Every requested CSIP control axis must either execute against the device or
// fail with an error a caller can classify — silence is forbidden. The
// classes matter because the gateway maps them to different protocol truth:
//
//   - ErrUnsupportedControl → the DEVICE cannot perform the requested axis
//     (missing model, capability not declared). CSIP response: CannotComply.
//     Deterministic: retrying will not help.
//   - ErrInvalidControl → the REQUEST is malformed (out-of-domain value,
//     non-finite conversion, insane multiplier). CSIP response: rejected.
//     Deterministic.
//   - ErrMalformedDevice → the device's own SunSpec surface is corrupt or
//     hostile (short model, illegal scale factor). The device must be
//     quarantined; other DERs are unaffected. Deterministic until the device
//     is replaced/fixed.
//   - ErrAdoptTimeout / ErrVerifyFailed → the device did not positively
//     confirm an actuation. Absence of failure evidence is NOT success
//     (LXR-006); the caller must treat the function as not-adopted.
//   - ErrPartialActuation → a multi-register actuation stopped part-way and
//     the device was MEASURED in neither the state it started in nor the one
//     it was commanded into (LXR-012). Distinct from every class above
//     because the device is now in a state nobody asked for: the control
//     cannot be reported as started, retrying is not obviously safe, and the
//     site must reserve the DER's full nameplate until it is proven again.
var (
	ErrUnsupportedControl = errors.New("unsupported control")
	ErrInvalidControl     = errors.New("invalid control")
	ErrMalformedDevice    = errors.New("malformed device")
	ErrAdoptTimeout       = errors.New("curve adoption timed out without confirmation")
	ErrVerifyFailed       = errors.New("actuation read-back verification failed")
	ErrPartialActuation   = errors.New("partial actuation: device left in a mixed state")
)

// UnsupportedControlError reports a requested control axis the device cannot
// execute. Axis uses the CSIP DERControlBase field name (e.g. "opModFixedVar").
type UnsupportedControlError struct {
	Axis   string
	Reason string
}

func (e *UnsupportedControlError) Error() string {
	return fmt.Sprintf("unsupported control %s: %s", e.Axis, e.Reason)
}
func (e *UnsupportedControlError) Unwrap() error { return ErrUnsupportedControl }

// InvalidControlError reports a request whose value is malformed or outside
// the representable/physical domain regardless of device capability.
type InvalidControlError struct {
	Axis   string
	Reason string
}

func (e *InvalidControlError) Error() string {
	return fmt.Sprintf("invalid control %s: %s", e.Axis, e.Reason)
}
func (e *InvalidControlError) Unwrap() error { return ErrInvalidControl }

// MalformedDeviceError reports a device whose declared SunSpec surface is
// structurally wrong — most importantly a model declared SHORTER than its
// fixed spec layout, which the pre-LXR-003 code would slice past and panic
// on, taking the shared Modbus service (and every other DER behind it) down.
type MalformedDeviceError struct {
	Tag      string // device tag ("inverter", "battery", ...)
	Model    uint16 // SunSpec model ID
	Declared int    // device-declared data-block length (registers)
	Required int    // minimum length the spec layout requires
	Detail   string // optional extra context
}

func (e *MalformedDeviceError) Error() string {
	msg := fmt.Sprintf("%s: malformed device: model %d declares %d registers, spec layout requires %d",
		e.Tag, e.Model, e.Declared, e.Required)
	if e.Detail != "" {
		msg += " (" + e.Detail + ")"
	}
	return msg
}
func (e *MalformedDeviceError) Unwrap() error { return ErrMalformedDevice }

// CorruptReadError reports a block that came back with the shape of a failed
// or partial read (sentinel saturation, an illegal scale factor) and was
// therefore NOT written back — the read-modify-write refusals in write704,
// SetEnterService and the M123 limit plan (audit E2).
//
// It is a MalformedDeviceError sibling on purpose: ErrMalformedDevice is
// already documented as "the device's own SunSpec surface is corrupt or
// hostile", and a caller classifying device health wants both in that bucket.
// It has its own type because the refusal carries a fact the length-based
// MalformedDeviceError does not: NOTHING WAS WRITTEN. The gate fires on the
// read, ahead of every write, so the device is exactly where it was — which is
// what lets a plan of plans record the axis as NotAttempted instead of
// Unverified (see axisElementState).
type CorruptReadError struct {
	Tag    string
	Model  uint16
	Detail string
}

func (e *CorruptReadError) Error() string {
	return fmt.Sprintf("%s: refusing to write M%d — %s; not programming garbage back to the device",
		e.Tag, e.Model, e.Detail)
}
func (e *CorruptReadError) Unwrap() error { return ErrMalformedDevice }

// AdoptTimeoutError reports a curve-adoption handshake in which the device
// never drove AdptCrvRslt/AdptCtlRslt to COMPLETED within the poll window.
// This is a FAILURE: the pre-LXR-006 code treated it as best-effort success
// and enabled a function whose curve state was unknown.
type AdoptTimeoutError struct {
	Tag     string
	Model   uint16
	Timeout time.Duration
}

func (e *AdoptTimeoutError) Error() string {
	return fmt.Sprintf("%s: model %d adopt-curve not confirmed within %s — absence of a result is not adoption",
		e.Tag, e.Model, e.Timeout)
}
func (e *AdoptTimeoutError) Unwrap() error { return ErrAdoptTimeout }

// VerifyError reports a positive read-back that contradicted the write the
// device had just accepted.
type VerifyError struct {
	Tag    string
	Model  uint16
	Point  string
	Detail string
}

func (e *VerifyError) Error() string {
	return fmt.Sprintf("%s: model %d %s read-back verification failed: %s", e.Tag, e.Model, e.Point, e.Detail)
}
func (e *VerifyError) Unwrap() error { return ErrVerifyFailed }

// PartialActuationError reports an actuation plan that left the device in a
// MEASURED mixed state — neither the pre-state nor the commanded state (see
// plan.go). Outcome carries the per-element verdict, including which elements
// are Unverified rather than Failed, so the caller escalates on evidence
// rather than on a guess.
//
// Compensated says whether the plan managed to move the device to a
// compensating state that is no less restrictive than the one it found
// (§5(b)). It is NOT a success flag: the commanded control did not happen
// either way, and both values require the same escalation. It tells the
// caller whether the device is in a KNOWN state (Compensated: the pre-state,
// re-proven by read-back) or a frozen partial one (not compensated: declared,
// deliberately untouched, and unsafe to assume anything about).
type PartialActuationError struct {
	Tag         string
	Plan        string
	Outcome     PlanOutcome
	Compensated bool
}

func (e *PartialActuationError) Error() string {
	what := "frozen and declared"
	if e.Compensated {
		what = "compensated to the more restrictive of {pre-state, achieved}"
	}
	return fmt.Sprintf("%s: %s actuation left the device in a mixed state (%s): %s",
		e.Tag, e.Plan, what, e.Outcome)
}
func (e *PartialActuationError) Unwrap() error { return ErrPartialActuation }
