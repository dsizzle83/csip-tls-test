package gridsim

import (
	"strings"
	"testing"

	"csip-tls-test/internal/csip/model"
)

func malformCtrlList(mrid string) *model.DERControlList {
	lim := model.ActivePower{Multiplier: 0, Value: 5000}
	return &model.DERControlList{
		Resource:   model.Resource{Href: "/derp/0/actderc"},
		All:        1,
		Results:    1,
		DERControl: []model.DERControl{{MRID: mrid, Interval: model.DateTimeInterval{Duration: 600, Start: 1000}, DERControlBase: model.DERControlBase{OpModExpLimW: &lim}}},
	}
}

func malformProgList() *model.DERProgramList {
	return &model.DERProgramList{
		Resource:   model.Resource{Href: "/edev/2/fsa/0/derp"},
		All:        1,
		Results:    1,
		DERProgram: []model.DERProgram{{Resource: model.Resource{Href: "/derp/0"}, Primacy: 1}},
	}
}

func TestMalform_TransformsTargetResources(t *testing.T) {
	s := &Server{}

	// empty_program_list: the served program list has no programs.
	if err := s.SetMalform(MalformEmptyProgramList); err != nil {
		t.Fatalf("arm: %v", err)
	}
	b, ok := s.malformedXML(malformProgList())
	if !ok {
		t.Fatal("empty_program_list: expected a malformed body")
	}
	if strings.Contains(string(b), "<DERProgram>") || !strings.Contains(string(b), `all="0"`) {
		t.Errorf("empty_program_list not empty:\n%s", b)
	}
	// A non-target resource is served normally.
	if _, ok := s.malformedXML(malformCtrlList("M-1")); ok {
		t.Error("empty_program_list must not transform a DERControlList")
	}

	// huge_activepower: an absurd export-limit value (overflow bait).
	s.SetMalform(MalformHugeActivePower)
	b, ok = s.malformedXML(malformCtrlList("M-1"))
	if !ok || !strings.Contains(string(b), "<value>32767</value>") {
		t.Errorf("huge_activepower missing absurd value:\n%s", b)
	}

	// bad_duration: a ~136-year interval.
	s.SetMalform(MalformBadDuration)
	b, _ = s.malformedXML(malformCtrlList("M-1"))
	if !strings.Contains(string(b), "<duration>4294967295</duration>") {
		t.Errorf("bad_duration missing absurd duration:\n%s", b)
	}

	// dup_mrid: the same control (mRID) appears twice.
	s.SetMalform(MalformDupMRID)
	b, _ = s.malformedXML(malformCtrlList("M-dup"))
	if n := strings.Count(string(b), "M-dup"); n < 2 {
		t.Errorf("dup_mrid: mRID appears %d times, want >= 2:\n%s", n, b)
	}
	if n := strings.Count(string(b), "<DERControl "); n < 2 {
		t.Errorf("dup_mrid: %d DERControl elements, want >= 2", n)
	}

	// missing_href: the program list's own href is stripped.
	s.SetMalform(MalformMissingHref)
	b, _ = s.malformedXML(malformProgList())
	if strings.Contains(string(b), `href="/edev/2/fsa/0/derp"`) {
		t.Errorf("missing_href: root href not stripped:\n%s", b)
	}

	// pagination: the program list's all= count lies (claims 999) while the body
	// still serves its actual program(s) and no real next page.
	s.SetMalform(MalformPagination)
	b, ok = s.malformedXML(malformProgList())
	if !ok || !strings.Contains(string(b), `all="999"`) {
		t.Errorf("pagination: all= count not inflated:\n%s", b)
	}
	if !strings.Contains(string(b), "<DERProgram>") && !strings.Contains(string(b), "<DERProgram ") {
		t.Errorf("pagination: served body should still contain the real program(s):\n%s", b)
	}

	// Cleared → pass-through.
	s.SetMalform("")
	if _, ok := s.malformedXML(malformProgList()); ok {
		t.Error("cleared malform must pass through")
	}
}

func TestMalform_UnknownKindRejected(t *testing.T) {
	s := &Server{}
	if err := s.SetMalform("bogus"); err == nil {
		t.Error("unknown malform kind should error")
	}
}

func malformTariffList() *model.TariffProfileList {
	return &model.TariffProfileList{
		Resource: model.Resource{Href: "/tp"}, All: 1, Results: 1,
		TariffProfile: []model.TariffProfile{{Resource: model.Resource{Href: "/tp/0"}, MRID: "TP-1", PricePowerOfTenMultiplier: -3, RateComponentListLink: &model.ListLink{Link: model.Link{Href: "/tp/0/rc"}}}},
	}
}

func malformConsumptionList() *model.ConsumptionTariffIntervalList {
	return &model.ConsumptionTariffIntervalList{
		Resource: model.Resource{Href: "/tp/0/rc/0/tti/0/cti"}, All: 1, Results: 1,
		ConsumptionTariffInterval: []model.ConsumptionTariffInterval{{Resource: model.Resource{Href: "/tp/0/rc/0/tti/0/cti/0"}, Price: 12000}},
	}
}

func TestMalform_PricingAttacks(t *testing.T) {
	s := &Server{}

	s.SetMalform(MalformBadPriceMultiplier)
	b, ok := s.malformedXML(malformTariffList())
	if !ok || !strings.Contains(string(b), "<pricePowerOfTenMultiplier>100<") {
		t.Errorf("bad_price_multiplier not applied:\n%s", b)
	}

	s.SetMalform(MalformNegativePrice)
	b, ok = s.malformedXML(malformConsumptionList())
	if !ok || !strings.Contains(string(b), "<price>-99999<") {
		t.Errorf("negative_price not applied:\n%s", b)
	}

	s.SetMalform(MalformHugePrice)
	b, _ = s.malformedXML(malformConsumptionList())
	if !strings.Contains(string(b), "<price>2147483647<") {
		t.Errorf("huge_price not applied:\n%s", b)
	}

	// A pricing malform must not transform a DER control list (wrong target).
	s.SetMalform(MalformNegativePrice)
	if _, ok := s.malformedXML(malformCtrlList("M-1")); ok {
		t.Error("negative_price must not transform a DERControlList")
	}

	// empty_curve_list strips the curves from a served DERCurveList.
	curves := &model.DERCurveList{
		Resource: model.Resource{Href: "/derp/0/dc"}, All: 1, Results: 1,
		DERCurve: []model.DERCurve{{Resource: model.Resource{Href: "/derp/0/dc/0"}, MRID: "C-1", CurveType: 1}},
	}
	s.SetMalform(MalformEmptyCurveList)
	b, ok = s.malformedXML(curves)
	if !ok || strings.Contains(string(b), "<DERCurve>") || !strings.Contains(string(b), `all="0"`) {
		t.Errorf("empty_curve_list not applied:\n%s", b)
	}
}
