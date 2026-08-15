package gridsim

// pricing.go — serves the IEEE 2030.5 §10.5 Pricing function set so a hub that
// walks it (lexa-northbound discovers FSA → TariffProfileListLink) receives a
// TOU tariff. The tree: TariffProfileList → TariffProfile → RateComponentList →
// RateComponent → {Active,}TimeTariffIntervalList → TimeTariffInterval →
// ConsumptionTariffIntervalList → ConsumptionTariffInterval (the price).

import model "lexa-proto/csipmodel"

func (s *Server) buildPricing(now int64) {
	// One electricity TariffProfile with a forward (consumption) RateComponent.
	s.resources["/tp"] = &model.TariffProfileList{
		Resource: model.Resource{Href: "/tp"},
		All:      1, Results: 1, PollRate: 300,
		TariffProfile: []model.TariffProfile{{
			Resource:                  model.Resource{Href: "/tp/0"},
			MRID:                      "TP-SP-001",
			Description:               "Service Point TOU Tariff",
			Currency:                  840, // USD
			PricePowerOfTenMultiplier: -3,
			Primacy:                   1,
			RateCode:                  "TOU-RES",
			ServiceCategoryKind:       0, // electricity
			RateComponentListLink:     &model.ListLink{Link: model.Link{Href: "/tp/0/rc"}, All: 1},
		}},
	}

	s.resources["/tp/0/rc"] = &model.RateComponentList{
		Resource: model.Resource{Href: "/tp/0/rc"},
		All:      1, Results: 1,
		RateComponent: []model.RateComponent{{
			Resource:    model.Resource{Href: "/tp/0/rc/0"},
			MRID:        "RC-FWD-001",
			Description: "Forward (consumption) rate",
			// ROLEFLAGS ADJUDICATION — the canonical one for RateComponent; see
			// pricing_dynamic.go for the second site.
			//
			// This was 0x0004 with the comment "isPrimary (forward)". sep 2.0.4
			// gives RateComponent.roleFlags the type RoleFlagsType (xsd:2291 ->
			// xsd:5826), the SAME type UsagePointBase uses, and RoleFlagsType
			// has no isPrimary and no isReverse. Its bit 2 is isPEV — xsd:5831,
			// "SHALL be set if the usage applies to an electric vehicle" — so
			// this bench was serving a residential time-of-use tariff that
			// declared itself an EV rate.
			//
			// The encoding sweep (lexa-proto 72d91be) is what made anyone look:
			// the VALUE survives it unaltered — 4 reads as 4 under either
			// convention and only the emitted text moves, "4" -> "0004" — so
			// unlike the MirrorUsagePoint fixtures this is not a semantics
			// rescue. It is a wrong value the sweep walked past and this commit
			// stops walking past.
			//
			// The forward/reverse distinction the old comment was reaching for
			// is not carried by roleFlags at all: it is ReadingType.flowDirection
			// (19 forward / 20 reverse), which the fixtures that carry a
			// ReadingType already set. The role that IS true of this rate is bit
			// 1, isPremisesAggregationPoint — "the UsagePoint is the point of
			// delivery for a premises" (xsd:5830) — which is also the role the
			// product's own site-meter MirrorUsagePoint declares (lexa-gw
			// cmd/telemetry/main.go, RoleFlags: 0x0002). Bench and DUT now
			// describe the same point of delivery the same way.
			//
			// Nothing in this tree reads RateComponent.RoleFlags. The only
			// artefact that moves is testdata/default-tree.golden.
			RoleFlags:                        0x0002, // isPremisesAggregationPoint
			TimeTariffIntervalListLink:       &model.ListLink{Link: model.Link{Href: "/tp/0/rc/0/tti"}, All: 2},
			ActiveTimeTariffIntervalListLink: &model.ListLink{Link: model.Link{Href: "/tp/0/rc/0/acttti"}, All: 1},
		}},
	}

	// Two TOU intervals: off-peak active now (12 h), peak following (6 h).
	offPeak := model.TimeTariffInterval{
		Resource:                          model.Resource{Href: "/tp/0/rc/0/tti/0"},
		MRID:                              "TTI-OFFPEAK",
		Description:                       "Off-peak",
		TouTier:                           1,
		Interval:                          model.DateTimeInterval{Start: now, Duration: 12 * 3600},
		ConsumptionTariffIntervalListLink: &model.ListLink{Link: model.Link{Href: "/tp/0/rc/0/tti/0/cti"}, All: 1},
	}
	peak := model.TimeTariffInterval{
		Resource:                          model.Resource{Href: "/tp/0/rc/0/tti/1"},
		MRID:                              "TTI-PEAK",
		Description:                       "Peak",
		TouTier:                           2,
		Interval:                          model.DateTimeInterval{Start: now + 12*3600, Duration: 6 * 3600},
		ConsumptionTariffIntervalListLink: &model.ListLink{Link: model.Link{Href: "/tp/0/rc/0/tti/1/cti"}, All: 1},
	}
	s.resources["/tp/0/rc/0/tti"] = &model.TimeTariffIntervalList{
		Resource: model.Resource{Href: "/tp/0/rc/0/tti"},
		All:      2, Results: 2,
		TimeTariffInterval: []model.TimeTariffInterval{offPeak, peak},
	}
	s.resources["/tp/0/rc/0/acttti"] = &model.TimeTariffIntervalList{
		Resource: model.Resource{Href: "/tp/0/rc/0/acttti"},
		All:      1, Results: 1,
		TimeTariffInterval: []model.TimeTariffInterval{offPeak}, // off-peak active now
	}

	// Prices (ConsumptionTariffInterval): off-peak cheap, peak expensive. With
	// PricePowerOfTenMultiplier=-3, 12000 → 12.0 ¢/kWh, 45000 → 45.0 ¢/kWh.
	s.resources["/tp/0/rc/0/tti/0/cti"] = &model.ConsumptionTariffIntervalList{
		Resource: model.Resource{Href: "/tp/0/rc/0/tti/0/cti"},
		All:      1, Results: 1,
		ConsumptionTariffInterval: []model.ConsumptionTariffInterval{{
			Resource:         model.Resource{Href: "/tp/0/rc/0/tti/0/cti/0"},
			ConsumptionBlock: 0, Price: 12000, StartValue: 0,
		}},
	}
	s.resources["/tp/0/rc/0/tti/1/cti"] = &model.ConsumptionTariffIntervalList{
		Resource: model.Resource{Href: "/tp/0/rc/0/tti/1/cti"},
		All:      1, Results: 1,
		ConsumptionTariffInterval: []model.ConsumptionTariffInterval{{
			Resource:         model.Resource{Href: "/tp/0/rc/0/tti/1/cti/0"},
			ConsumptionBlock: 0, Price: 45000, StartValue: 0,
		}},
	}
}
