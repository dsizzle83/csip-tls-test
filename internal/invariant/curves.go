package invariant

// curves.go is this package's decode of the SunSpec curve/control models —
// 705 (Volt-Var), 706 (Volt-Watt), 711 (Frequency Droop) and 712 (Watt-Var) —
// the southbound half of every CURVE-linked IEEE 2030.5 control mode.
//
// It exists for the same reason units.go does, and under the same rule
// (doc.go): this package shares ONLY the SunSpec register-offset tables with
// the product and none of its CSIP/derbase interpretation. A referee that asked
// the gateway what it had written down would repeat the gateway's own mistake
// back at it; a referee that reads the DER's registers and re-derives the curve
// from the device's own NPt and scale factors can catch a curve that never
// landed, landed on the wrong model, landed with the wrong points, or was
// "adopted" by a device that only said so (the curve_adopt_lies shape the sims
// already model).
//
// WHAT IS ASSERTABLE HERE, AND WHAT IS NOT
//
// The device sims adopt curves realistically — a writable staging curve, an
// AdptCrvReq/AdptCrvRslt handshake, and a read-only live curve at index 0 that
// reflects the staged points on COMPLETED — but they simulate NO curve PHYSICS:
// a volt-var curve on the sim changes no measured var. So every assertion this
// file supports is about the REGISTERS and the ADOPT STATE, never about an
// effect on output. A caller that wants "the DER's output followed the curve"
// is asking a question this bench cannot answer, and must say so rather than
// answer a different one.
//
// The LIVE curve (index 0) is the only one read. Index 1+ are the writable
// staging curves; content sitting in staging is a curve the device was OFFERED,
// not one it adopted, and grading a staged curve as an adopted one would accept
// exactly the half-completed write the adopt handshake exists to distinguish.

import (
	"fmt"
	"math"
	"strings"

	"lexa-proto/sunspec"
)

// CurvePoint is one decoded breakpoint of a curve model's live curve, in the
// device's own engineering units (its scale factors already applied).
type CurvePoint struct {
	X float64
	Y float64
}

// String renders a point the way a finding quotes one.
func (p CurvePoint) String() string { return fmt.Sprintf("(%s, %s)", trimFloat(p.X), trimFloat(p.Y)) }

// CurveAxis is the static description of one curve/control model: which model
// it is, what a reader should call it, and what its two axes MEAN. The axis
// names are load-bearing in a finding — "the DER's 706 live curve holds
// (106 V, 100 W)" tells a reader something "(106, 100)" does not.
type CurveAxis struct {
	Model uint16
	// Name is the human label, e.g. "M705 Volt-Var".
	Name string
	// XName/YName name the physical quantity on each axis.
	XName, YName string
	// Pointless marks a model that carries no breakpoint table at all — 711,
	// whose frequency response is a PARAMETRIC droop (deadbands and gains), not
	// a curve of points. A caller correlating breakpoints must not pretend
	// otherwise; see CurveView.Pointless.
	Pointless bool
}

// curveAxes is the one table of curve models this package decodes. A model
// absent from it is a model this package will not pretend to understand.
var curveAxes = []CurveAxis{
	{Model: sunspec.ModelDERVoltVar, Name: "M705 Volt-Var", XName: "V", YName: "var"},
	{Model: sunspec.ModelDERVoltWatt, Name: "M706 Volt-Watt", XName: "V", YName: "W"},
	{Model: sunspec.ModelDERFreqDroop, Name: "M711 Frequency Droop", XName: "Hz", YName: "W",
		Pointless: true},
	{Model: sunspec.ModelDERWattVar, Name: "M712 Watt-Var", XName: "W", YName: "var"},
}

// CurveModels are the models a register-image source reads for curve evidence,
// in ascending order. Exported so a source (and a test) reads the same set this
// file can decode, rather than a second list that can drift from it.
func CurveModels() []uint16 {
	out := make([]uint16, 0, len(curveAxes))
	for _, a := range curveAxes {
		out = append(out, a.Model)
	}
	return out
}

// CurveAxisOf returns the static description of a curve model, and false for a
// model this package does not decode.
func CurveAxisOf(model uint16) (CurveAxis, bool) {
	for _, a := range curveAxes {
		if a.Model == model {
			return a, true
		}
	}
	return CurveAxis{}, false
}

// CurveView is one curve model's LIVE curve (index 0) plus the adopt-handshake
// state around it, as the device's own registers report them.
//
// Present is false when the device does not serve the model at all, which is a
// different fact from "serves it and adopted nothing" and must stay
// distinguishable: the first is a device that cannot carry the function, the
// second is a device that can and did not.
type CurveView struct {
	// Source names where this reading came from, for a finding that cites it.
	Source string
	Axis   CurveAxis

	// Present is true when the device served the model and it decoded.
	Present bool
	// Err records why a served model did not decode. Present is false then.
	Err string

	// Enabled is the model's own Ena register: the function switched ON.
	// A curve adopted into a disabled function commands nothing.
	Enabled bool
	// EnaRaw is Ena's raw register value, for a finding that must quote it.
	EnaRaw uint16

	// AdoptReq / AdoptResult are the handshake registers (AdptCrvReq /
	// AdptCrvRslt, or AdptCtlReq / AdptCtlRslt on 711).
	AdoptReq    uint16
	AdoptResult uint16
	// Adopted is AdoptResult == COMPLETED.
	Adopted bool

	// DeptRef is the live curve's DeptRef register — SunSpec's "curve dependent
	// reference", the base its y values are a percentage OF. HasDeptRef is false
	// for a model that carries no such register (711, which is parametric).
	//
	// It is decoded because a curve's y values are a PERCENTAGE, and a
	// percentage is not a quantity without the thing it is a percentage of. IEEE
	// 2030.5 names that base on every DERCurve (yRefType, minOccurs=1) and
	// SunSpec names it per curve bank (DeptRef); a referee that read the points
	// and not this register would grade "-30 % of setMaxVar" and "-30 % of
	// setMaxW" as the same curve, which on a 60 kW / 26.4 kvar DER is a 2.3x
	// error and on a 2 kvar machine a 30x one.
	DeptRef    uint16
	HasDeptRef bool

	// ReadOnly is the live curve's own ReadOnly flag. The live curve of a
	// conformant device is read-only; a writable "live" curve means the index-0
	// convention does not hold on this device and the reading below is not the
	// active curve.
	ReadOnly bool

	// NPt / NCrv are the device's own declared geometry.
	NPt, NCrv int

	// Points is the live curve's breakpoints, device engineering units. Always
	// empty for a Pointless axis.
	Points []CurvePoint

	// Params carries a Pointless model's parameters (711's deadbands, gains and
	// response time), rendered, since there is no point table to carry them.
	Params string
}

// Pointless reports whether this axis carries no breakpoint table, so a caller
// correlating a northbound DERCurve's points against it knows the correlation
// is not available (and must not report a verdict as though it were).
func (c CurveView) Pointless() bool { return c.Axis.Pointless }

// Describe renders what the device holds, for a finding that must say what it
// read rather than only what it wanted.
func (c CurveView) Describe() string {
	if !c.Present {
		if c.Err != "" {
			return fmt.Sprintf("%s did not decode: %s", c.Axis.Name, c.Err)
		}
		return fmt.Sprintf("%s is not served by this device", c.Axis.Name)
	}
	parts := []string{
		fmt.Sprintf("Ena=%d (%s)", c.EnaRaw, enabledWord(c.Enabled)),
		fmt.Sprintf("adopt req=%d rslt=%d (%s)", c.AdoptReq, c.AdoptResult, adoptWord(c.Adopted)),
		fmt.Sprintf("NPt=%d NCrv=%d", c.NPt, c.NCrv),
		fmt.Sprintf("live curve read-only=%t", c.ReadOnly),
	}
	if c.HasDeptRef {
		parts = append(parts, fmt.Sprintf("DeptRef=%d (%s)", c.DeptRef, DeptRefName(c.Axis.Model, c.DeptRef)))
	}
	switch {
	case c.Axis.Pointless:
		parts = append(parts, "no breakpoint table (parametric control): "+orNone(c.Params))
	case len(c.Points) == 0:
		parts = append(parts, "live curve holds NO points")
	default:
		pts := make([]string, 0, len(c.Points))
		for _, p := range c.Points {
			pts = append(pts, p.String())
		}
		parts = append(parts, fmt.Sprintf("live curve %s/%s points: %s", c.Axis.XName, c.Axis.YName,
			strings.Join(pts, " ")))
	}
	return c.Axis.Name + " — " + strings.Join(parts, ", ")
}

// DeptRefName spells a DeptRef code out for a finding, per model, so a reader
// sees which rating the device says its y values are a percentage of rather
// than a bare integer.
//
// PROVENANCE. Transcribed from the vendored SunSpec model JSON in lexa-proto
// (docs/schema/sunspec-models/): model_705.json and model_712.json declare
// {0 W_MAX_PCT, 1 VAR_MAX_PCT, 2 VAR_AVAL_PCT, 3 VA_MAX_PCT}; model_706.json
// declares {0 W_MAX_PCT, 1 W_AVAL_PCT}. Transcribed rather than bound
// mechanically because the sunspec package declares no DeptRef constants —
// stated plainly so the weakness is visible rather than implied. The DUT's own
// cmd/modbus/reconcile_adv.go carries the identical transcription with the
// identical provenance note; this referee restates it from the same source
// rather than importing it, which is this package's whole discipline.
func DeptRefName(model uint16, v uint16) string {
	switch model {
	case sunspec.ModelDERVoltVar, sunspec.ModelDERWattVar:
		switch v {
		case 0:
			return "W_MAX_PCT"
		case 1:
			return "VAR_MAX_PCT"
		case 2:
			return "VAR_AVAL_PCT"
		case 3:
			return "VA_MAX_PCT"
		}
	case sunspec.ModelDERVoltWatt:
		switch v {
		case 0:
			return "W_MAX_PCT"
		case 1:
			return "W_AVAL_PCT"
		}
	}
	return "unknown for this model"
}

func enabledWord(on bool) string {
	if on {
		return "ENABLED"
	}
	return "disabled"
}

func adoptWord(done bool) string {
	if done {
		return "COMPLETED"
	}
	return "not COMPLETED"
}

func orNone(s string) string {
	if s == "" {
		return "none read"
	}
	return s
}

// Curve decodes this unit's live curve for one curve model.
func (u UnitView) Curve(source string, model uint16) CurveView {
	return DecodeCurve(fmt.Sprintf("%s unit %d", source, u.Unit), model, u.Regs[model])
}

// DecodeCurve reads a curve model's header and its LIVE (index 0) curve out of
// that model's data registers.
//
// An empty regs slice is "the device does not serve this model" — the shape
// UnitView.Regs takes for a model the chain walk did not find — and is reported
// as absent, never as an empty curve, because "adopted nothing" and "cannot
// carry this function at all" are different answers to a conformance question.
func DecodeCurve(source string, model uint16, regs []uint16) CurveView {
	axis, known := CurveAxisOf(model)
	if !known {
		return CurveView{Source: source, Axis: CurveAxis{Model: model,
			Name: fmt.Sprintf("M%d", model), XName: "x", YName: "y"},
			Err: fmt.Sprintf("model %d is not a curve model this referee decodes", model)}
	}
	v := CurveView{Source: source, Axis: axis}
	if len(regs) == 0 {
		return v
	}

	hdr, reqField, rsltField, nField := curveHeaderOf(model)
	if len(regs) < hdr.Len() {
		v.Err = fmt.Sprintf("the %s block is %d registers, shorter than its own %d-register header",
			axis.Name, len(regs), hdr.Len())
		return v
	}
	h := hdr.View(regs)
	v.EnaRaw = h.U16At(hdr.Offset("Ena"))
	v.Enabled = v.EnaRaw == 1
	v.AdoptReq = h.U16At(hdr.Offset(reqField))
	v.AdoptResult = h.U16At(hdr.Offset(rsltField))
	v.Adopted = v.AdoptResult == sunspec.AdptCompleted
	if nField == "NCtl" {
		v.NCrv = int(h.U16At(hdr.Offset("NCtl")))
	} else {
		v.NPt = int(h.U16At(hdr.Offset("NPt")))
		v.NCrv = int(h.U16At(hdr.Offset("NCrv")))
	}

	switch model {
	case sunspec.ModelDERVoltVar:
		c, err := sunspec.Parse705Curve(regs, 0)
		if err != nil {
			v.Err = err.Error()
			return v
		}
		v.ReadOnly = c.ReadOnly
		v.DeptRef, v.HasDeptRef = c.DeptRef, true
		for _, p := range c.Points {
			v.Points = append(v.Points, CurvePoint{X: p.V, Y: p.Var})
		}
	case sunspec.ModelDERVoltWatt:
		c, err := sunspec.Parse706Curve(regs, 0)
		if err != nil {
			v.Err = err.Error()
			return v
		}
		v.ReadOnly = c.ReadOnly
		v.DeptRef, v.HasDeptRef = c.DeptRef, true
		for _, p := range c.Points {
			v.Points = append(v.Points, CurvePoint{X: p.V, Y: p.W})
		}
	case sunspec.ModelDERWattVar:
		c, err := sunspec.Parse712Curve(regs, 0)
		if err != nil {
			v.Err = err.Error()
			return v
		}
		v.ReadOnly = c.ReadOnly
		v.DeptRef, v.HasDeptRef = c.DeptRef, true
		for _, p := range c.Points {
			v.Points = append(v.Points, CurvePoint{X: p.W, Y: p.Var})
		}
	case sunspec.ModelDERFreqDroop:
		c, err := sunspec.Parse711Ctl(regs, 0)
		if err != nil {
			v.Err = err.Error()
			return v
		}
		v.ReadOnly = c.ReadOnly
		v.Params = fmt.Sprintf("DbOf=%s Hz DbUf=%s Hz KOf=%s KUf=%s RspTms=%s s PMin=%s",
			trimFloat(c.DbOf), trimFloat(c.DbUf), trimFloat(c.KOf), trimFloat(c.KUf),
			trimFloat(c.RspTms), trimFloat(c.PMin))
	}
	v.Present = true
	return v
}

// curveHeaderOf returns a curve model's header layout and the names of its
// handshake and geometry registers. 711 is the odd one: it carries CONTROLS,
// not curves, so its handshake is AdptCtlReq/AdptCtlRslt and its count is NCtl.
func curveHeaderOf(model uint16) (hdr *sunspec.Layout, reqField, rsltField, nField string) {
	switch model {
	case sunspec.ModelDERVoltVar:
		return sunspec.L705Hdr, "AdptCrvReq", "AdptCrvRslt", "NPt"
	case sunspec.ModelDERVoltWatt:
		return sunspec.L706Hdr, "AdptCrvReq", "AdptCrvRslt", "NPt"
	case sunspec.ModelDERWattVar:
		return sunspec.L712Hdr, "AdptCrvReq", "AdptCrvRslt", "NPt"
	default:
		return sunspec.L711Hdr, "AdptCtlReq", "AdptCtlRslt", "NCtl"
	}
}

// CurveMatch is the result of comparing a device's live curve against the
// breakpoints a control published northbound.
type CurveMatch struct {
	// Matched is true only when EVERY published point has a counterpart on the
	// device, in order, within tolerance, and the device holds no extra points.
	Matched bool
	// Reason explains a non-match in the language of the two point sets.
	Reason string
}

// MatchPoints compares a device's live curve against want, the breakpoints the
// northbound control published (already converted into the device's own
// engineering units by the caller, which owns that conversion because it owns
// the axis multipliers the wire carried).
//
// Order matters and extra points fail. A curve is a piecewise function: the
// same three breakpoints in a different order describe a different function,
// and a fourth breakpoint the head end never sent is a segment nobody asked
// for. Accepting either would let "the DER holds SOME curve" pass for "the DER
// holds THIS curve".
//
// tol is the slack allowed on ONE axis value, given that value — a function
// rather than a constant because a device's own scale factors decide the size
// of a rounding step, and a fixed absolute tolerance is either too tight on a
// coarse device or too loose on a fine one.
func MatchPoints(got, want []CurvePoint, tol func(want float64) float64) CurveMatch {
	if len(want) == 0 {
		return CurveMatch{Reason: "the control published no breakpoints, so there is nothing to correlate"}
	}
	if len(got) != len(want) {
		return CurveMatch{Reason: fmt.Sprintf("the device's live curve holds %d breakpoint(s) and the "+
			"control published %d: %s vs %s", len(got), len(want), renderPoints(got), renderPoints(want))}
	}
	for i := range want {
		if math.Abs(got[i].X-want[i].X) > tol(want[i].X) || math.Abs(got[i].Y-want[i].Y) > tol(want[i].Y) {
			return CurveMatch{Reason: fmt.Sprintf("breakpoint %d differs: the device holds %s, the control "+
				"published %s (device curve %s, published curve %s)", i+1, got[i], want[i],
				renderPoints(got), renderPoints(want))}
		}
	}
	return CurveMatch{Matched: true, Reason: fmt.Sprintf("the device's live curve holds exactly the "+
		"published breakpoints, in order: %s", renderPoints(got))}
}

func renderPoints(pts []CurvePoint) string {
	if len(pts) == 0 {
		return "(no points)"
	}
	out := make([]string, 0, len(pts))
	for _, p := range pts {
		out = append(out, p.String())
	}
	return strings.Join(out, " ")
}
