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
	s.resources["/derp/0/dc"] = staticVoltVarCurve0(now)

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
// THE <vRef>240</vRef> THIS FIXTURE ONCE SERVED IS NOT COMING BACK, and the
// reason is not the one the previous note gave.
//
// It was deleted on 2026-08-15 on the grounds that "sep 2.0.4 declares no vRef
// element on DERCurve". That is true of docs/schema/sep-2.0.4.xsd, which is the
// pre-publication ZigBee draft, and FALSE of IEEE Std 2030.5-2018, which
// declares vRef on DERCurve at p.253 and makes it multiply every x value at
// p.250. The element is real, this server can serve one again (curve.go's
// `vref`, opModVoltVar-only per the standard's SHALL NOT), and curvexml.go emits
// it in its sequence position.
//
// THE VALUE was the actual defect, and it survives the correction: vRef is a
// PerCent — "hundredths of a percent, 0 to 10 000" (2018 p.167) — and 240 is a
// VOLTS reading in a percentage element. Served on this fixture it multiplied
// every breakpoint by 240/10 000, i.e. scaled the whole volt-var curve to 2.4 %
// of itself, on the default resource every DUT walking this tree fetches. So the
// fixture goes on carrying no vRef at all, which is legal ([0..1]) and is the
// ordinary unscaled curve — and it does so because the number was wrong, not
// because the element was imaginary.
//
// creationTime is SET, for the mirror-image reason: it is [1] (2018 p.253) and
// this fixture left it zero, which csipmodel's `omitempty` then dropped
// entirely. A DERCurve with no creationTime is as invalid as one with a
// mis-scaled vRef, and less visibly so.
func staticVoltVarCurve0(now int64) *model.DERCurveList {
	return &model.DERCurveList{
		Resource: model.Resource{Href: "/derp/0/dc"},
		All:      1, Results: 1, PollRate: 300,
		DERCurve: []model.DERCurve{{
			Resource:     model.Resource{Href: "/derp/0/dc/0"},
			MRID:         "CURVE-VV-001",
			Description:  "Volt-VAr curve",
			CreationTime: now,
			// curveType 11. IEEE Std 2030.5-2018 p.254 assigns opModVoltVar the
			// code 11, and p.250 states it a second time in the element's own
			// prose ("Specify DERCurveLink for curveType == 11") — which is
			// also, exactly, what CSIP CTP v1.3's Figure 6 prescribes. It read 0
			// until 2026-08-15 because the constant was derived from the draft
			// schema; the fixture never named a number, so correcting the
			// constant corrected the fixture (IW15-027).
			CurveType: model.CurveTypeVoltVar,
			// yRefType 3 = %statVarAvail. It was 4, under a comment that said
			// "VAr as % of VArMax" — and BOTH halves were wrong. IEEE Std
			// 2030.5-2018 p.256's DERUnitRefType makes 4 "%setEffectiveV", a
			// VOLTAGE reference on the VAr axis of a volt-var curve; %setMaxVar
			// (the thing the comment described) is 2, not 4. The standard is
			// explicit about the admissible set for this element: opModVoltVar's
			// own prose (p.250)
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
			// xRefType is GONE, not corrected, and it is the ONE of the four
			// 2026-08-15 deletions that the anchor correction did not overturn.
			// No revision declares it: IEEE 2030.5-2018's DERCurve is
			// autonomousVRefEnable..yRefType (p.252-253), 2030.5-2023 is the
			// same (p.265-266), and the draft schema has none either. csipmodel
			// no longer has the field, so serving one is a compile error rather
			// than a comment. The x-axis reference is fixed by the MODE at both
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
