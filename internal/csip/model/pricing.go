package model

import "encoding/xml"

// Pricing function set (IEEE 2030.5 §10.5). These types mirror the schema
// lexa-northbound parses (lexa-hub internal/northbound/model/pricing.go) so the
// gridsim can SERVE a pricing tree that the hub's walker discovers and publishes.
// The XML element/field names and namespace must match exactly.

// UnitValue is a quantity with a unit-of-measure code and power-of-ten
// multiplier (IEC 61968-9 UOM; e.g. 38=W, 72=Wh).
type UnitValue struct {
	Multiplier int8  `xml:"multiplier"`
	Unit       uint8 `xml:"unit,omitempty"`
	Value      int64 `xml:"value"`
}

// TariffProfile is the root resource of the Pricing function set.
type TariffProfile struct {
	XMLName xml.Name `xml:"urn:ieee:std:2030.5:ns TariffProfile"`
	Resource

	Subscribable              uint8  `xml:"subscribable,attr,omitempty"`
	MRID                      string `xml:"mRID,omitempty"`
	Description               string `xml:"description,omitempty"`
	Currency                  uint16 `xml:"currency,omitempty"` // ISO 4217 numeric
	PricePowerOfTenMultiplier int8   `xml:"pricePowerOfTenMultiplier,omitempty"`
	Primacy                   uint8  `xml:"primacy"`
	RateCode                  string `xml:"rateCode,omitempty"`
	ServiceCategoryKind       uint8  `xml:"serviceCategoryKind,omitempty"` // 0=electricity

	RateComponentListLink *ListLink `xml:"RateComponentListLink,omitempty"`
}

// TariffProfileList is a collection of TariffProfile resources.
type TariffProfileList struct {
	XMLName xml.Name `xml:"urn:ieee:std:2030.5:ns TariffProfileList"`
	Resource

	All           uint32          `xml:"all,attr"`
	Results       uint32          `xml:"results,attr"`
	PollRate      uint32          `xml:"pollRate,attr,omitempty"`
	TariffProfile []TariffProfile `xml:"TariffProfile"`
}

// RateComponent aggregates the TimeTariffIntervals for one rate direction.
type RateComponent struct {
	XMLName xml.Name `xml:"urn:ieee:std:2030.5:ns RateComponent"`
	Resource

	MRID        string `xml:"mRID,omitempty"`
	Description string `xml:"description,omitempty"`

	FlowRateEndLimit   *UnitValue `xml:"flowRateEndLimit,omitempty"`
	FlowRateStartLimit *UnitValue `xml:"flowRateStartLimit,omitempty"`

	ReadingTypeLink *Link  `xml:"ReadingTypeLink,omitempty"`
	RoleFlags       uint16 `xml:"roleFlags,omitempty"`

	TimeTariffIntervalListLink       *ListLink `xml:"TimeTariffIntervalListLink,omitempty"`
	ActiveTimeTariffIntervalListLink *ListLink `xml:"ActiveTimeTariffIntervalListLink,omitempty"`
}

// RateComponentList is a collection of RateComponent resources.
type RateComponentList struct {
	XMLName xml.Name `xml:"urn:ieee:std:2030.5:ns RateComponentList"`
	Resource

	All           uint32          `xml:"all,attr"`
	Results       uint32          `xml:"results,attr"`
	RateComponent []RateComponent `xml:"RateComponent"`
}

// TimeTariffInterval is a time-bound event specifying which TOU tier is active.
type TimeTariffInterval struct {
	XMLName xml.Name `xml:"urn:ieee:std:2030.5:ns TimeTariffInterval"`
	Resource

	Subscribable      uint8            `xml:"subscribable,attr,omitempty"`
	MRID              string           `xml:"mRID,omitempty"`
	Description       string           `xml:"description,omitempty"`
	CreationTime      int64            `xml:"creationTime,omitempty"`
	EventStatus       *EventStatus     `xml:"EventStatus,omitempty"`
	Interval          DateTimeInterval `xml:"interval"`
	RandomizeDuration *int32           `xml:"randomizeDuration,omitempty"`
	RandomizeStart    *int32           `xml:"randomizeStart,omitempty"`
	TouTier           uint8            `xml:"touTier"`

	ConsumptionTariffIntervalListLink *ListLink `xml:"ConsumptionTariffIntervalListLink,omitempty"`
}

// TimeTariffIntervalList is a collection of TimeTariffInterval resources.
type TimeTariffIntervalList struct {
	XMLName xml.Name `xml:"urn:ieee:std:2030.5:ns TimeTariffIntervalList"`
	Resource

	All                uint32               `xml:"all,attr"`
	Results            uint32               `xml:"results,attr"`
	Subscribable       uint8                `xml:"subscribable,attr,omitempty"`
	TimeTariffInterval []TimeTariffInterval `xml:"TimeTariffInterval"`
}

// ConsumptionTariffInterval specifies the price for a consumption block within
// a TimeTariffInterval.
type ConsumptionTariffInterval struct {
	XMLName xml.Name `xml:"urn:ieee:std:2030.5:ns ConsumptionTariffInterval"`
	Resource

	ConsumptionBlock uint8 `xml:"consumptionBlock"`
	Price            int32 `xml:"price"` // in units of TariffProfile.pricePowerOfTenMultiplier
	StartValue       int64 `xml:"startValue"`
}

// ConsumptionTariffIntervalList is a collection of ConsumptionTariffInterval
// resources.
type ConsumptionTariffIntervalList struct {
	XMLName xml.Name `xml:"urn:ieee:std:2030.5:ns ConsumptionTariffIntervalList"`
	Resource

	All                       uint32                      `xml:"all,attr"`
	Results                   uint32                      `xml:"results,attr"`
	ConsumptionTariffInterval []ConsumptionTariffInterval `xml:"ConsumptionTariffInterval"`
}
