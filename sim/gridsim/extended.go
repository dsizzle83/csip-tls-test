package gridsim

// extended.go — serves the DER curve (§) and Billing (§10.7) function sets so
// the hub's walk discovers them (DERProgram.DERCurveListLink,
// FSA.CustomerAccountListLink). Like pricing, these are discovered by
// lexa-northbound; serving them completes the CSIP server and enables
// containment attacks (a malformed curve/billing resource must not break DER
// control — pricing/curve/billing discovery is non-fatal in the walker).

import model "lexa-proto/csipmodel"

func (s *Server) buildExtended(now int64) {
	// ── DER curve (Volt-VAr) for program 0 (/derp/0/dc) ──────────
	vref := int16(240)
	s.resources["/derp/0/dc"] = &model.DERCurveList{
		Resource: model.Resource{Href: "/derp/0/dc"},
		All:      1, Results: 1, PollRate: 300,
		DERCurve: []model.DERCurve{{
			Resource:    model.Resource{Href: "/derp/0/dc/0"},
			MRID:        "CURVE-VV-001",
			Description: "Volt-VAr curve",
			CurveType:   1, // Volt-VAr
			VRef:        &vref,
			XRefType:    1, // voltage
			YRefType:    4, // VAr as % of VArMax
			CurveData: []model.DERCurveData{
				{XValue: 92, YValue: 30}, {XValue: 98, YValue: 0},
				{XValue: 102, YValue: 0}, {XValue: 108, YValue: -30},
			},
		}},
	}

	// ── Billing (§10.7): one CustomerAccount / CustomerAgreement ──
	s.resources["/ca"] = &model.CustomerAccountList{
		Resource: model.Resource{Href: "/ca"},
		All:      1, Results: 1,
		CustomerAccount: []model.CustomerAccount{{
			Resource:                  model.Resource{Href: "/ca/0"},
			MRID:                      "ACCT-001",
			Description:               "Service Point Account",
			Currency:                  840,
			CustomerAccountNumber:     "SP-0001",
			CustomerName:              "QA Bench",
			PricePowerOfTenMultiplier: -3,
			CustomerAgreementListLink: &model.ListLink{Link: model.Link{Href: "/ca/0/ag"}, All: 1},
		}},
	}
	s.resources["/ca/0/ag"] = &model.CustomerAgreementList{
		Resource: model.Resource{Href: "/ca/0/ag"},
		All:      1, Results: 1,
		CustomerAgreement: []model.CustomerAgreement{{
			Resource:          model.Resource{Href: "/ca/0/ag/0"},
			MRID:              "AGR-001",
			Description:       "Residential TOU agreement",
			ServiceLocation:   "Service Point",
			TariffProfileLink: &model.Link{Href: "/tp/0"},
		}},
	}
}
