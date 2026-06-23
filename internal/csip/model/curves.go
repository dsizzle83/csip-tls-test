package model

import "encoding/xml"

// DER curve types (IEEE 2030.5 §). Mirror lexa-hub internal/northbound/model
// der.go so the gridsim can SERVE a DERCurveList that the hub's walker resolves
// (DERProgram.DERCurveListLink). XML element/field names must match.

// DERCurveData is one (x, y) breakpoint in a piecewise-linear DERCurve.
type DERCurveData struct {
	XValue int32 `xml:"xvalue"`
	YValue int32 `xml:"yvalue"`
}

// DERCurve is a piecewise-linear inverter characteristic curve (Volt-VAr,
// Volt-Watt, freq-watt, …) referenced from a DERControlBase.
type DERCurve struct {
	XMLName xml.Name `xml:"urn:ieee:std:2030.5:ns DERCurve"`
	Resource

	MRID         string `xml:"mRID,omitempty"`
	Description  string `xml:"description,omitempty"`
	Version      uint16 `xml:"version,omitempty"`
	CreationTime int64  `xml:"creationTime,omitempty"`

	CurveType uint16         `xml:"curveType"`
	CurveData []DERCurveData `xml:"CurveData,omitempty"`

	OpenLoopTms *uint16 `xml:"openLoopTms,omitempty"`
	RampDecTms  *uint16 `xml:"rampDecTms,omitempty"`
	RampIncTms  *uint16 `xml:"rampIncTms,omitempty"`

	XMultiplier int8   `xml:"xMultiplier,omitempty"`
	YMultiplier int8   `xml:"yMultiplier,omitempty"`
	VRef        *int16 `xml:"vRef,omitempty"`
	XRefType    uint8  `xml:"xRefType,omitempty"`
	YRefType    uint8  `xml:"yRefType,omitempty"`
}

// DERCurveList is a collection of DERCurve resources for one DERProgram.
type DERCurveList struct {
	XMLName xml.Name `xml:"urn:ieee:std:2030.5:ns DERCurveList"`
	Resource

	All      uint32     `xml:"all,attr"`
	Results  uint32     `xml:"results,attr"`
	PollRate uint32     `xml:"pollRate,attr,omitempty"`
	DERCurve []DERCurve `xml:"DERCurve"`
}
