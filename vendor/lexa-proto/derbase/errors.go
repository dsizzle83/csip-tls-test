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
var (
	ErrUnsupportedControl = errors.New("unsupported control")
	ErrInvalidControl     = errors.New("invalid control")
	ErrMalformedDevice    = errors.New("malformed device")
	ErrAdoptTimeout       = errors.New("curve adoption timed out without confirmation")
	ErrVerifyFailed       = errors.New("actuation read-back verification failed")
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
