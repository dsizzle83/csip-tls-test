package model

import "encoding/xml"

// Billing function set (IEEE 2030.5 §10.7). Mirror lexa-hub
// internal/northbound/model billing.go so the gridsim can SERVE a
// CustomerAccountList that the hub's walker discovers (FSA.CustomerAccountListLink).

// CustomerAccount holds account-level billing information.
type CustomerAccount struct {
	XMLName xml.Name `xml:"urn:ieee:std:2030.5:ns CustomerAccount"`
	Resource

	MRID                      string `xml:"mRID,omitempty"`
	Description               string `xml:"description,omitempty"`
	Currency                  uint16 `xml:"currency,omitempty"`
	CustomerAccountNumber     string `xml:"customerAccount,omitempty"`
	CustomerName              string `xml:"customerName,omitempty"`
	PricePowerOfTenMultiplier int8   `xml:"pricePowerOfTenMultiplier,omitempty"`

	CustomerAgreementListLink *ListLink `xml:"CustomerAgreementListLink,omitempty"`
}

// CustomerAccountList is a collection of CustomerAccount resources.
type CustomerAccountList struct {
	XMLName xml.Name `xml:"urn:ieee:std:2030.5:ns CustomerAccountList"`
	Resource

	All             uint32            `xml:"all,attr"`
	Results         uint32            `xml:"results,attr"`
	CustomerAccount []CustomerAccount `xml:"CustomerAccount"`
}

// CustomerAgreement represents a service agreement for one usage point/tariff.
type CustomerAgreement struct {
	XMLName xml.Name `xml:"urn:ieee:std:2030.5:ns CustomerAgreement"`
	Resource

	MRID            string `xml:"mRID,omitempty"`
	Description     string `xml:"description,omitempty"`
	ServiceLocation string `xml:"serviceLocation,omitempty"`

	TariffProfileLink *Link `xml:"TariffProfileLink,omitempty"`
}

// CustomerAgreementList is a collection of CustomerAgreement resources.
type CustomerAgreementList struct {
	XMLName xml.Name `xml:"urn:ieee:std:2030.5:ns CustomerAgreementList"`
	Resource

	All               uint32              `xml:"all,attr"`
	Results           uint32              `xml:"results,attr"`
	CustomerAgreement []CustomerAgreement `xml:"CustomerAgreement"`
}
