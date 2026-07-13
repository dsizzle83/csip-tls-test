package tariff

import (
	"strings"
	"testing"
)

func ptrF(f float64) *float64 { return &f }

var allMonths = []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}
var allDays = []string{"mon", "tue", "wed", "thu", "fri", "sat", "sun"}

// validTariff returns a freshly-allocated, internally-valid tariff. Each call
// builds new slices, so a mutation applied by one test case cannot leak into
// another.
func validTariff() Tariff {
	return Tariff{
		ID: "v", Name: "Valid", ShortName: "v", Utility: "u", Territory: "t",
		Timezone: "America/Chicago", Currency: "USD",
		Effective:       Effective{From: "2025-01-01", To: "2025-12-31"},
		Provenance:      Provenance{Confidence: ConfidencePublished, Retrieved: "2026-07-12"},
		FixedMonthlyUSD: 9.95,
		RidersUSDPerKWh: 0.05,
		Energy: Energy{
			Seasons: []Season{{
				ID: "y", Months: append([]int(nil), allMonths...),
				DayTypes: []DayType{{
					Days: append([]string(nil), allDays...),
					Periods: []Period{
						{ID: "night", Label: "Night", Start: "21:00", End: "06:00", RateUSDPerKWh: 0.0},
						{ID: "day", Label: "Day", Start: "06:00", End: "21:00", RateUSDPerKWh: 0.20},
					},
				}},
			}},
			Tiers: []Tier{{UpToKWh: ptrF(500), AdderUSDPerKWh: 0}, {UpToKWh: nil, AdderUSDPerKWh: 0.03}},
		},
		Demand: []DemandCharge{{Label: "d", USDPerKW: 8.0, Months: []int{7}, Days: []string{"weekday"}, Start: "16:00", End: "21:00"}},
		Export: Export{Type: ExportBuyback, RateUSDPerKWh: 0.06},
	}
}

// TestValidateAcceptsValid is the positive control: the base tariff must pass.
func TestValidateAcceptsValid(t *testing.T) {
	tar := validTariff()
	if err := tar.Validate(); err != nil {
		t.Fatalf("valid tariff rejected: %v", err)
	}
}

// TestValidateRejects walks each hard rule with a one-field mutation that must
// be rejected, asserting the error names the failure.
func TestValidateRejects(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(*Tariff)
		wantSub string
	}{
		{
			name:    "period overlap",
			mutate:  func(t *Tariff) { t.Energy.Seasons[0].DayTypes[0].Periods[1].Start = "05:00" }, // day 05:00-21:00 overlaps night's 00:00-06:00
			wantSub: "overlap",
		},
		{
			name:    "period gap",
			mutate:  func(t *Tariff) { t.Energy.Seasons[0].DayTypes[0].Periods[1].End = "20:00" }, // 20:00..21:00 uncovered
			wantSub: "gap in coverage",
		},
		{
			name:    "missing weekday",
			mutate:  func(t *Tariff) { t.Energy.Seasons[0].DayTypes[0].Days = []string{"mon", "tue", "wed", "thu", "fri"} }, // weekend uncovered
			wantSub: "does not cover weekday",
		},
		{
			name: "duplicate weekday",
			mutate: func(t *Tariff) {
				t.Energy.Seasons[0].DayTypes[0].Days = []string{"mon", "tue", "wed", "thu", "fri", "sat", "sun", "mon"} // Monday twice
			},
			wantSub: "covers weekday",
		},
		{
			name:    "bad timezone",
			mutate:  func(t *Tariff) { t.Timezone = "Mars/Phobos" },
			wantSub: "timezone",
		},
		{
			name:    "rate above sanity ceiling",
			mutate:  func(t *Tariff) { t.Energy.Seasons[0].DayTypes[0].Periods[1].RateUSDPerKWh = 6.0 },
			wantSub: "sanity ceiling",
		},
		{
			name:    "negative rate",
			mutate:  func(t *Tariff) { t.RidersUSDPerKWh = -0.01 },
			wantSub: "< 0",
		},
		{
			name: "month claimed by two seasons",
			mutate: func(t *Tariff) {
				extra := t.Energy.Seasons[0] // shares month 7 (and all months)
				extra.ID = "x"
				t.Energy.Seasons = append(t.Energy.Seasons, extra)
			},
			wantSub: "claimed by both",
		},
		{
			name:    "month out of range",
			mutate:  func(t *Tariff) { t.Energy.Seasons[0].Months = []int{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11} },
			wantSub: "out of range",
		},
		{
			name:    "bad confidence enum",
			mutate:  func(t *Tariff) { t.Provenance.Confidence = "guessed" },
			wantSub: "confidence",
		},
		{
			name:    "effective reversed",
			mutate:  func(t *Tariff) { t.Effective.From, t.Effective.To = "2025-12-31", "2025-01-01" },
			wantSub: "before effective.from",
		},
		{
			name:    "effective unparseable",
			mutate:  func(t *Tariff) { t.Effective.From = "2025-13-01" },
			wantSub: "effective.from",
		},
		{
			name:    "bad export type",
			mutate:  func(t *Tariff) { t.Export.Type = "wheeling" },
			wantSub: "export.type",
		},
		{
			name:    "negative demand",
			mutate:  func(t *Tariff) { t.Demand[0].USDPerKW = -1 },
			wantSub: "< 0",
		},
		{
			name:    "tier breakpoints not increasing",
			mutate:  func(t *Tariff) { t.Energy.Tiers = []Tier{{UpToKWh: ptrF(500)}, {UpToKWh: ptrF(300)}} },
			wantSub: "not greater than previous",
		},
		{
			name:    "unbounded tier not last",
			mutate:  func(t *Tariff) { t.Energy.Tiers = []Tier{{UpToKWh: nil}, {UpToKWh: ptrF(500)}} },
			wantSub: "not the last tier",
		},
		{
			name:    "zero-length period",
			mutate:  func(t *Tariff) { t.Energy.Seasons[0].DayTypes[0].Periods[1].End = "06:00" }, // day 06:00-06:00
			wantSub: "zero-length",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			tar := validTariff()
			c.mutate(&tar)
			err := tar.Validate()
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", c.wantSub)
			}
			if !strings.Contains(err.Error(), c.wantSub) {
				t.Fatalf("error %q does not contain %q", err.Error(), c.wantSub)
			}
		})
	}
}

// TestParseRejectsMalformedJSON confirms Parse surfaces JSON decode errors.
func TestParseRejectsMalformedJSON(t *testing.T) {
	if _, err := Parse([]byte(`{"id": "x", not json}`)); err == nil {
		t.Fatal("expected parse error for malformed JSON, got nil")
	}
}
