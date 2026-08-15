package gridsim

// curvexml.go — the DERCurve this server puts ON THE WIRE, shaped by
// sep-2.0.4.xsd rather than by the vendored Go struct's field order.
//
// ── Why a separate shape exists ─────────────────────────────────────────────
//
// Everything else in this simulator marshals csipmodel structs directly, and
// for every other resource that is right. DERCurve is the one place where the
// vendored struct and the schema disagree in ways that make the DOCUMENT
// non-conformant, and this bench's whole product is documents used to certify
// conformance against that schema. Three separate defects, all invisible from
// Go:
//
//  1. DROPPED MANDATORY ELEMENTS. csipmodel tags creationTime, xMultiplier and
//     yMultiplier `omitempty`, and all three are minOccurs="1" in the XSD. A
//     curve with xMultiplier 0 — which is what "no scaling" IS, and what
//     BASIC-012's Figure prescribes for its y axis — silently served no
//     yMultiplier element at all. A conformance bundle then contains a DERCurve
//     the schema rejects, and the row that published it reports a clean run.
//
//  2. ELEMENT ORDER. The XSD sequence is creationTime, CurveData, curveType,
//     openLoopTms, rampDecTms, rampIncTms, rampPT1Tms, xMultiplier,
//     yMultiplier, yRefType. csipmodel declares curveType BEFORE CurveData, so
//     every curve this server ever served was out of sequence. xs:sequence is
//     ordered; a validating parser rejects it.
//
//  3. AN ELEMENT THE STANDARD DOES NOT DEFINE. csipmodel.DERCurve carries VRef
//     and XRefType, and sep 2.0.4 declares NEITHER on DERCurve — `grep -c vRef
//     docs/schema/sep-2.0.4.xsd` in lexa-proto is 0, and the only V-reference
//     elements in the standard are setVRef / setVRefOfs on DERSettings. This
//     server served <vRef>240</vRef> on its static fixture, restored by every
//     DELETE /admin/curve — the exact rule the suite's own noVrefElementInSchema
//     constant states, broken by the server the constant is written about.
//
// THE FIX IS HERE AND NOT IN csipmodel because lexa-proto is a pinned
// dependency of two repos and a struct-order change ripples through both; the
// defects are recorded for its registry. Nothing about the stored resources
// changes — s.resources still holds csipmodel types, every admin path still
// reads and writes them — only the bytes that leave serveXML.

import (
	"encoding/xml"

	model "lexa-proto/csipmodel"
)

// wireDERCurve is sep 2.0.4's DERCurve, in the schema's own element order, with
// every minOccurs="1" element present unconditionally.
//
// The omitempty tags that remain are the schema's OPTIONAL elements
// (minOccurs="0") and the IdentifiedObject fields, which are optional there
// too. Nothing is dropped that the standard requires, and nothing is emitted
// that the standard does not declare.
type wireDERCurve struct {
	XMLName xml.Name `xml:"urn:ieee:std:2030.5:ns DERCurve"`
	Href    string   `xml:"href,attr,omitempty"`

	MRID        string `xml:"mRID,omitempty"`
	Description string `xml:"description,omitempty"`
	Version     uint16 `xml:"version,omitempty"`

	// minOccurs=1 — always emitted, 0 included.
	CreationTime int64                `xml:"creationTime"`
	CurveData    []model.DERCurveData `xml:"CurveData"`
	CurveType    uint16               `xml:"curveType"`

	// minOccurs=0 — the timing family, emitted only when authored.
	OpenLoopTms *uint16 `xml:"openLoopTms,omitempty"`
	RampDecTms  *uint16 `xml:"rampDecTms,omitempty"`
	RampIncTms  *uint16 `xml:"rampIncTms,omitempty"`
	RampPT1Tms  *uint16 `xml:"rampPT1Tms,omitempty"`

	// minOccurs=1 — always emitted, 0 included. A zero multiplier is "no
	// scaling", a real and common value, and dropping it changes the document
	// from "these raw values, unscaled" into one the schema rejects.
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
// VRef and XRefType are DROPPED here rather than at the store, deliberately:
// the csipmodel fields exist and other code may still set them, and a
// conversion that silently omitted them while the struct kept them would be a
// second place for the same confusion to live. This is the only place that
// decides what a DERCurve looks like on the wire, and it declines to emit two
// elements sep 2.0.4 does not define.
func toWireCurve(c model.DERCurve) wireDERCurve {
	return wireDERCurve{
		Href:         c.Href,
		MRID:         c.MRID,
		Description:  c.Description,
		Version:      c.Version,
		CreationTime: c.CreationTime,
		CurveData:    c.CurveData,
		CurveType:    c.CurveType,
		OpenLoopTms:  c.OpenLoopTms,
		RampDecTms:   c.RampDecTms,
		RampIncTms:   c.RampIncTms,
		RampPT1Tms:   c.RampPT1Tms,
		XMultiplier:  c.XMultiplier,
		YMultiplier:  c.YMultiplier,
		YRefType:     c.YRefType,
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
