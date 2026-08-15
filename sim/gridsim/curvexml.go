package gridsim

// curvexml.go — the DERCurve this server puts ON THE WIRE, shaped by IEEE Std
// 2030.5-2018 rather than by the vendored Go struct's field order.
//
// ── Why a separate shape exists ─────────────────────────────────────────────
//
// Everything else in this simulator marshals csipmodel structs directly, and
// for every other resource that is right. DERCurve is the one place where the
// vendored struct's declaration order and the standard's sequence have to be
// held apart, and this bench's whole product is documents used to certify
// conformance. Two defects this shape was built to kill, both invisible from Go:
//
//  1. DROPPED MANDATORY ELEMENTS. csipmodel once tagged creationTime,
//     xMultiplier and yMultiplier `omitempty`, and all three are [1] (2018
//     p.253). A curve with xMultiplier 0 — which is what "no scaling" IS, and
//     what BASIC-012's Figure prescribes for its y axis — silently served no
//     yMultiplier element at all. A conformance bundle then contains a DERCurve
//     the standard rejects, and the row that published it reports a clean run.
//     (lexa-proto has since fixed the tags; this shape emits them
//     unconditionally regardless, which is what makes the guarantee local.)
//
//  2. ELEMENT ORDER. DERCurve is an xs:sequence — an ORDERED particle — and Go
//     emits struct fields in declaration order, so the two must agree or a
//     validating peer rejects a document every element of which is legal.
//
// ── The element set, RE-DERIVED against the published standard (IW15-027) ───
//
// This file used to say that csipmodel carried "an element the standard does
// not define", name vRef and xRefType, and decline to emit either. That was
// TRUE OF docs/schema/sep-2.0.4.xsd — the pre-publication ZigBee SEP 2.0 draft
// — and FALSE of IEEE Std 2030.5-2018, which declares vRef (p.253),
// autonomousVRefEnable (p.252) and autonomousVRefTimeConstant (p.253) on
// DERCurve. Declining to emit them meant this bench COULD NOT SERVE the
// standard's own Volt-Var curve, and BASIC-006's Figure 6 prescribes two of the
// three by name. All three are emitted now, in their sequence positions.
//
// xRefType stays gone and is the one that was right: no revision declares it —
// not 2018 (p.252-253), not 2023 (p.265-266), not the draft — and csipmodel has
// no field for it any more.
//
// THE SEQUENCE, 2018 p.252-253, which is case-insensitively alphabetical over
// the standard's own attribute names (see lexa-proto NORMATIVE_ANCHOR.md §1.4
// for how that order is derived and why it is flagged as the census's one
// inference):
//
//	autonomousVRefEnable, autonomousVRefTimeConstant, creationTime, CurveData,
//	curveType, openLoopTms, rampDecTms, rampIncTms, rampPT1Tms, vRef,
//	xMultiplier, yMultiplier, yRefType
//
// Nothing about the stored resources changes — s.resources still holds
// csipmodel types, every admin path still reads and writes them — only the
// bytes that leave serveXML.

import (
	"encoding/xml"

	model "lexa-proto/csipmodel"
)

// wireDERCurve is IEEE 2030.5-2018's DERCurve, in the standard's own element
// order, with every [1] element present unconditionally.
//
// The omitempty tags that remain are the standard's OPTIONAL [0..1] elements and
// the IdentifiedObject fields, which are optional there too. Nothing is dropped
// that the standard requires, and nothing is emitted that the standard does not
// declare.
type wireDERCurve struct {
	XMLName xml.Name `xml:"urn:ieee:std:2030.5:ns DERCurve"`
	Href    string   `xml:"href,attr,omitempty"`

	MRID        string `xml:"mRID,omitempty"`
	Description string `xml:"description,omitempty"`
	Version     uint16 `xml:"version,omitempty"`

	// [0..1], and FIRST in the sequence: "autonomousvref..." sorts ahead of
	// "creationtime". Both are opModVoltVar-only (2018 p.252-253, "If the
	// curveType is not opModVoltVar, then this field SHALL NOT be present"),
	// which the admin handler enforces before anything reaches this shape.
	AutonomousVRefEnable       *bool   `xml:"autonomousVRefEnable,omitempty"`
	AutonomousVRefTimeConstant *uint32 `xml:"autonomousVRefTimeConstant,omitempty"`

	// [1] — always emitted, 0 included.
	CreationTime int64                `xml:"creationTime"`
	CurveData    []model.DERCurveData `xml:"CurveData"`
	CurveType    uint16               `xml:"curveType"`

	// [0..1] — the timing family, emitted only when authored.
	OpenLoopTms *uint16 `xml:"openLoopTms,omitempty"`
	RampDecTms  *uint16 `xml:"rampDecTms,omitempty"`
	RampIncTms  *uint16 `xml:"rampIncTms,omitempty"`
	RampPT1Tms  *uint16 `xml:"rampPT1Tms,omitempty"`

	// vRef — [0..1], PerCent, and it sorts between rampPT1Tms and xMultiplier.
	// A POINTER because absence is meaningful: 2018 p.250 makes a PRESENT vRef
	// multiply every x value by vRef/10 000, so a zero served as an element is
	// a curve collapsed onto x=0, and a zero served as an absence is the
	// ordinary unscaled curve. omitempty on a value type would have made those
	// two indistinguishable in the struct and identical on the wire.
	VRef *model.PerCent `xml:"vRef,omitempty"`

	// [1] — always emitted, 0 included. A zero multiplier is "no scaling", a
	// real and common value, and dropping it changes the document from "these
	// raw values, unscaled" into one the standard rejects.
	XMultiplier int8  `xml:"xMultiplier"`
	YMultiplier int8  `xml:"yMultiplier"`
	YRefType    uint8 `xml:"yRefType"`
}

// wireDERCurveList is DERCurveList with its entries in the same wire shape.
type wireDERCurveList struct {
	XMLName xml.Name `xml:"urn:ieee:std:2030.5:ns DERCurveList"`
	Href    string   `xml:"href,attr,omitempty"`

	All      uint32 `xml:"all,attr"`
	Results  uint32 `xml:"results,attr"`
	PollRate uint32 `xml:"pollRate,attr,omitempty"`

	DERCurve []wireDERCurve `xml:"DERCurve"`
}

// toWireCurve renders one stored DERCurve into its wire shape.
//
// EVERY field of the stored curve is carried across. It used to drop two — VRef
// and XRefType — under the heading "elements sep 2.0.4 does not define", and
// half of that was an artifact of the wrong anchor: 2018 declares vRef (p.253).
// A conversion that silently omits a real element is the same class of defect as
// one that silently emits a phantom, and this is the only place that decides
// what a DERCurve looks like on the wire, so it must not do either.
//
// There is nothing left to drop: csipmodel has no XRefType field any more
// (lexa-proto 9856710, the one deletion of the four that survived IW15-027), so
// a compile error — not a silent omission — is what happens if it ever returns.
func toWireCurve(c model.DERCurve) wireDERCurve {
	return wireDERCurve{
		Href:                       c.Href,
		MRID:                       c.MRID,
		Description:                c.Description,
		Version:                    c.Version,
		AutonomousVRefEnable:       c.AutonomousVRefEnable,
		AutonomousVRefTimeConstant: c.AutonomousVRefTimeConstant,
		CreationTime:               c.CreationTime,
		CurveData:                  c.CurveData,
		CurveType:                  c.CurveType,
		OpenLoopTms:                c.OpenLoopTms,
		RampDecTms:                 c.RampDecTms,
		RampIncTms:                 c.RampIncTms,
		RampPT1Tms:                 c.RampPT1Tms,
		VRef:                       c.VRef,
		XMultiplier:                c.XMultiplier,
		YMultiplier:                c.YMultiplier,
		YRefType:                   c.YRefType,
	}
}

// curveForWire converts a stored curve resource into the shape serveXML should
// marshal, and reports whether it did. Anything else passes through untouched.
func curveForWire(resource any) (any, bool) {
	switch v := resource.(type) {
	case *model.DERCurve:
		w := toWireCurve(*v)
		return &w, true
	case *model.DERCurveList:
		out := wireDERCurveList{
			Href: v.Href, All: v.All, Results: v.Results, PollRate: v.PollRate,
			DERCurve: make([]wireDERCurve, 0, len(v.DERCurve)),
		}
		for _, c := range v.DERCurve {
			out.DERCurve = append(out.DERCurve, toWireCurve(c))
		}
		return &out, true
	}
	return resource, false
}
