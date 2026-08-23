package gridsim

// softgrad.go — the DefaultDERControl-only ramp-rate defaults (setGradW /
// setSoftGradW), IEEE Std 2030.5-2018 p.252.
//
// ── What was missing ────────────────────────────────────────────────────────
//
// 2030.5 places setGradW and setSoftGradW on the DefaultDERControl and NOWHERE
// else: they are not DERControlBase children, so no event can carry them. The
// vendored csipmodel predates both, so this server had no way to author either
// — and a DER client's soft-start ramp (the SunSpec 703 ESRmpTms an
// EnterService write carries) is resolved from setSoftGradW alone. With no
// lever the ramp is always zero on this bench, the gateway's
// SetEnergizeWithRamp degenerates to its enable-only fall-through, and the
// energize-with-ramp write path cannot be exercised at all.
//
// ── Carried on a LOCAL wrapper, not a proto bump ────────────────────────────
//
// encoding/xml promotes an embedded struct's fields — including its XMLName —
// so defaultDERControlRamps marshals the SAME <DefaultDERControl> element with
// two extra children and needs no change to the pinned csipmodel. This mirrors
// exactly what the gateway under test already does on the READ side
// (lexa-gw internal/northbound/discovery/walker.go's
// extendedDefaultDERControlDoc), so the two halves of the bench agree on the
// shape without either one owning a fork of the model.
//
// The wrapper is used ONLY when a request actually asks for a ramp. A default
// carrying neither element is stored as the plain narrow type it always was, so
// the golden resource tree is byte-identical for every scenario that does not
// use this lever.

import model "lexa-proto/csipmodel"

// defaultDERControlRamps is a DefaultDERControl carrying 2030.5's two
// DefaultDERControl-level ramp-rate defaults. Both are PerCent — hundredths of
// a percent of setMaxW per second — and both are optional here, so a request
// naming one and not the other serves exactly the one it named.
type defaultDERControlRamps struct {
	model.DefaultDERControl
	SetGradW     *uint16 `xml:"setGradW,omitempty"`
	SetSoftGradW *uint16 `xml:"setSoftGradW,omitempty"`
}

// wantsRamps reports whether a POST /admin/default asked for either ramp-rate
// default, i.e. whether the wrapper shape is needed at all.
func (r adminDefaultReq) wantsRamps() bool {
	return !r.Clear && (r.SetGradW != nil || r.SetSoftGradW != nil)
}
