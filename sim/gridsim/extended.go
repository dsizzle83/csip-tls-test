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
	s.resources["/derp/0/dc"] = staticVoltVarCurve0()

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

// staticVoltVarCurve0 is the default program-0 Volt-VAr curve served at
// /derp/0/dc. It is the fixture the tree ships with (no active control
// references it until POST /admin/curve binds one) and the shape DELETE
// /admin/curve restores program 0 to. Factored out of buildExtended so the
// admin curve endpoint can reset it (curve.go).
func staticVoltVarCurve0() *model.DERCurveList {
	vref := int16(240)
	return &model.DERCurveList{
		Resource: model.Resource{Href: "/derp/0/dc"},
		All:      1, Results: 1, PollRate: 300,
		DERCurve: []model.DERCurve{{
			Resource:    model.Resource{Href: "/derp/0/dc/0"},
			MRID:        "CURVE-VV-001",
			Description: "Volt-VAr curve",
			CurveType:   model.CurveTypeVoltVar, // 0 (was mislabeled as 1 = FreqWatt)
			VRef:        &vref,
			// yRefType 3 = %statVarAvail. It was 4, under a comment that said
			// "VAr as % of VArMax" — and BOTH halves were wrong. sep 2.0.4's
			// DERUnitRefType makes 4 "%setEffectiveV", a VOLTAGE reference on
			// the VAr axis of a volt-var curve; %setMaxVar (the thing the
			// comment described) is 2, not 4. The schema is explicit about the
			// admissible set for this element: opModVoltVar's own documentation
			// says "the meaning of the y value is determined by yRefType and
			// must be one of %setMaxW, %setMaxVar, or %statVarAvail", so 4 is
			// not merely unusual here, it is not a legal value for this curve.
			//
			// It became load-bearing on 2026-08-14, when the DUT began
			// translating yRefType into the curve bank's DeptRef and REFUSING
			// what it cannot translate (lexa-gw cmd/modbus's curveDeptRef): this
			// fixture, served by default at /derp/0/dc, would have drawn a
			// cannot-comply from a correct gateway for a defect in the bench.
			//
			// xRefType is GONE, not corrected. sep 2.0.4 declares no such
			// element anywhere — `grep -c xRefType docs/schema/sep-2.0.4.xsd` in
			// lexa-proto is 0 — so serving one put a non-existent element on the
			// wire in a document this bench uses to certify conformance. (The
			// field exists on csipmodel.DERCurve, which decodes an element the
			// schema does not declare; that is an upstream defect recorded, not
			// fixed, here.) The x-axis reference is fixed by the MODE at both
			// ends and needs no carriage: a volt-var curve's x is an effective
			// percent voltage by definition of the mode.
			YRefType: model.RefTypeStatVarAvail,
			CurveData: []model.DERCurveData{
				{XValue: 92, YValue: 30}, {XValue: 98, YValue: 0},
				{XValue: 102, YValue: 0}, {XValue: 108, YValue: -30},
			},
		}},
	}
}
