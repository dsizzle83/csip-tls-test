package gridsim

// fixedpf.go — the opModFixedPFAbsorbW / opModFixedPFInjectW lever.
//
// ── Why this file exists ────────────────────────────────────────────────────
//
// These two elements are STRUCTURED, and this bench used to author them as a
// bare number. IEEE Std 2030.5-2018 p.258 types both as
// PowerFactorWithExcitation with THREE MANDATORY children:
//
//	displacement (UInt16 [1])                   the PF magnitude, scaled
//	excitation   (boolean [1])                  true = over-excited
//	multiplier   (PowerOfTenMultiplierType [1]) apply 10^multiplier
//
// so a fixed power factor of 0.900 under-excited is
// {displacement 900, excitation false, multiplier -3} — which is exactly what
// CSIP CTP v1.3's Figure 8 (Fixed Power Factor Settings) prescribes for
// BASIC-008, child by child, and has prescribed all along.
//
// What this server served instead was `<opModFixedPFInjectW>95</...>`: a bare
// chardata Int16, because csipmodel typed the field *SignedPerCent. That typing
// was lexa-proto's own invention — no revision declares it, and the vendored
// draft's single opModFixedPF is itself a two-element structure — so the
// document this bench put on the wire was one no conformant server produces and
// no conformant client can read. lexa-proto fe483e7 corrected the model and
// deliberately gave the scalar shape NO decode tolerance, which means a bench
// still emitting it now serves a document the product correctly refuses.
//
// ── Whole or nothing, on the droop lever's rule ─────────────────────────────
//
// All three children are [1]. A request carrying two of them is REJECTED (400)
// rather than completed with zeros, and the difference is not pedantry:
// displacement 0 is not "no power factor commanded", it is a power factor of
// zero — a machine delivering pure reactive power — and excitation false is not
// "unspecified", it is the assertion that the DER is UNDER-excited, which is a
// direction. Silently zero-filling would put a control on the wire commanding
// something nobody asked for, inside documents used to certify conformance.
// Presence of the ELEMENT is carried by the pointer to this struct, exactly as
// it is for opModFreqDroop (freqdroop.go).
//
// ── The old scalar field is REFUSED, not translated ─────────────────────────
//
// `fixed_pf_inject_pct` / `fixed_pf_absorb_pct` are gone from this API and a
// request still carrying one is answered 400, on the same rule that retired
// x_ref_type. Translating it would require inventing the two children it cannot
// express: excitation has no representation in a magnitude at all, and the
// multiplier the old field implied (-4, since the value was read as hundredths
// of a percent) is not the one any Figure prescribes (-3). A bench that guessed
// would put a DIFFERENT power factor on the wire than the caller asked for and
// than the procedure prints — silently, and inside evidence.

import (
	"fmt"

	model "lexa-proto/csipmodel"
)

// fixedPFReq is the JSON body fragment carrying one PowerFactorWithExcitation,
// shared by POST /admin/control and POST /admin/default.
//
// Every field is a POINTER, for the reason freqDroopReq's are: the pointer
// distinguishes "absent" from "sent as 0", and 0 is a meaningful (if refusable)
// value for displacement and multiplier alike. Displacement and multiplier are
// signed int64 so an out-of-domain value is refused in the STANDARD's own
// vocabulary rather than by encoding/json, which would answer a negative
// displacement with "cannot unmarshal number -1 into Go value of type uint16"
// and name neither the element nor its type.
type fixedPFReq struct {
	Displacement *int64 `json:"displacement"` // UInt16, the PF magnitude scaled by multiplier
	Excitation   *bool  `json:"excitation"`   // true = over-excited
	Multiplier   *int64 `json:"multiplier"`   // PowerOfTenMultiplierType, int8
}

// toModel validates the request and renders it into the csipmodel element, or
// returns the reason it cannot be authored.
//
// nil in, nil out: a request carrying no fixed-PF element at all is not an
// error, it is a control that does not command the axis.
//
// element names the field the way the standard and the catalog's Figures do
// ("opModFixedPFInjectW"), so an error message and a Figure line can be read
// side by side.
func (r *fixedPFReq) toModel(element string) (*model.PowerFactorWithExcitation, error) {
	if r == nil {
		return nil, nil
	}
	// WHOLE OR NOTHING. See the file doc: all three children are [1], and a
	// partial element completed with zeros commands a different machine rather
	// than a partial command.
	var missing []string
	if r.Displacement == nil {
		missing = append(missing, "displacement")
	}
	if r.Excitation == nil {
		missing = append(missing, "excitation")
	}
	if r.Multiplier == nil {
		missing = append(missing, "multiplier")
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("%s is missing %v: all three children of PowerFactorWithExcitation are "+
			"[1] (IEEE Std 2030.5-2018 p.258), and this server will not complete the element with "+
			"zeros — displacement 0 is a power factor of ZERO, not an absent command, and excitation "+
			"false is the assertion that the DER is under-excited, not the absence of an assertion",
			element, missing)
	}
	if *r.Displacement < 0 || *r.Displacement > 65535 {
		return nil, fmt.Errorf("%s.displacement %d is outside UInt16's wire domain [0,65535] (IEEE Std "+
			"2030.5-2018 p.258)", element, *r.Displacement)
	}
	if *r.Multiplier < -128 || *r.Multiplier > 127 {
		return nil, fmt.Errorf("%s.multiplier %d is outside PowerOfTenMultiplierType's wire domain "+
			"[-128,127] (IEEE Std 2030.5-2018 p.258)", element, *r.Multiplier)
	}
	pf := &model.PowerFactorWithExcitation{
		Displacement: uint16(*r.Displacement),
		Excitation:   *r.Excitation,
		Multiplier:   int8(*r.Multiplier),
	}
	// THE PRODUCT OF THE THREE MUST BE A POWER FACTOR, and this bench checks it
	// rather than leaving the DUT to.
	//
	// A displacement power factor lives in (0, 1]. csipmodel's PF() is the same
	// arithmetic the product applies at receipt, so a request this accepts is a
	// request the product can execute — which is the property a conformance
	// bench most needs, because a control the DUT refuses for a defect in the
	// BENCH is a row that fails a correct device.
	//
	// It is a REFUSAL and not a clamp: clamping a power factor moves reactive
	// power to a quantity the head end did not request, which is the same rule
	// lexa-proto's derbase applies on the reading side.
	if v, ok := pf.PF(); !ok {
		return nil, fmt.Errorf("%s renders a displacement power factor of %g, which is not one: "+
			"displacement %d x 10^%d must land in (0,1] (IEEE Std 2030.5-2018 p.258 — the actual "+
			"displacement SHALL be within the limits established by setMinPFOverExcited and "+
			"setMinPFUnderExcited, and a magnitude outside (0,1] is not a power factor under any "+
			"limits). 0.900 under-excited, which is what CSIP CTP v1.3's Figure 8 prescribes, is "+
			"{displacement 900, excitation false, multiplier -3}",
			element, v, *r.Displacement, *r.Multiplier)
	}
	return pf, nil
}

// adminFixedPFInfo is one authored fixed-PF element as GET /admin/status
// renders it: the three children the wire carries, plus the power factor they
// compute to.
//
// PF is derived rather than stored, and it is here because the three children
// are not readable at a glance — a reader checking that this bench served
// Figure 8's condition wants to see 0.9, and a reader checking the DOCUMENT
// wants the children. Both are facts about the same element and neither can
// substitute for the other.
type adminFixedPFInfo struct {
	Displacement uint16  `json:"displacement"`
	Excitation   bool    `json:"excitation"`
	Multiplier   int8    `json:"multiplier"`
	PF           float64 `json:"pf"`
}

// fixedPFToInfo renders an authored fixed-PF element for the admin JSON, or nil
// when the control commands no such axis.
func fixedPFToInfo(pf *model.PowerFactorWithExcitation) *adminFixedPFInfo {
	if pf == nil {
		return nil
	}
	v, _ := pf.PF() // a stored element passed toModel's gate; ok is informational here
	return &adminFixedPFInfo{
		Displacement: pf.Displacement,
		Excitation:   pf.Excitation,
		Multiplier:   pf.Multiplier,
		PF:           v,
	}
}

// fixedPFScalarGone is the 400 a caller gets for still sending the retired
// scalar field. It names the replacement in full, because the whole hazard of
// this migration is a caller who "fixes" it by guessing at the two children the
// old number could not carry.
func fixedPFScalarGone(oldField, element string) error {
	return fmt.Errorf("%s is not a field of this API: %s is a PowerFactorWithExcitation (IEEE Std "+
		"2030.5-2018 p.258) with three mandatory children, and a bare magnitude cannot express two of "+
		"them — excitation has no representation in a number at all, and the multiplier the old field "+
		"implied (-4, hundredths of a percent) is not the one any Figure prescribes (-3). Send "+
		"%q: {\"displacement\": 900, \"excitation\": false, \"multiplier\": -3} for the 0.900 "+
		"under-excited that CSIP CTP v1.3's Figure 8 prints. This server will not guess: a guessed "+
		"excitation reverses the direction of reactive power inside evidence",
		oldField, element, jsonFieldFor(element))
}

// jsonFieldFor maps the standard's element name to this API's field name.
func jsonFieldFor(element string) string {
	if element == fixedPFInjectElement {
		return "fixed_pf_inject"
	}
	return "fixed_pf_absorb"
}

// The two elements, named the way the standard and the Figures do.
const (
	fixedPFInjectElement = "opModFixedPFInjectW"
	fixedPFAbsorbElement = "opModFixedPFAbsorbW"
)
