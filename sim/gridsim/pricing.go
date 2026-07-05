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
			Resource:                         model.Resource{Href: "/tp/0/rc/0"},
			MRID:                             "RC-FWD-001",
			Description:                      "Forward (consumption) rate",
			RoleFlags:                        0x0004, // isPrimary (forward)
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
