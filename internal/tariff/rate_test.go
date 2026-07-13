package tariff

import (
	"testing"
	"time"
)

// weekdaySplitJSON is a single-season, all-year tariff whose day_types split
// the week into weekday ($0.25) and weekend ($0.15) flat rates. Export none.
const weekdaySplitJSON = `{
  "id":"rt-wk-split","name":"Weekday/Weekend split","short_name":"split",
  "utility":"x","territory":"t","timezone":"America/Chicago","currency":"USD",
  "effective":{"from":"2025-01-01","to":"2025-12-31"},
  "provenance":{"source_url":"","retrieved":"2026-07-12","confidence":"estimated","notes":""},
  "fixed_monthly_usd":0,
  "energy":{"seasons":[{"id":"y","months":[1,2,3,4,5,6,7,8,9,10,11,12],
    "day_types":[
      {"days":["weekday"],"periods":[{"id":"wd","label":"Weekday","start":"00:00","end":"24:00","rate_usd_per_kwh":0.25}]},
      {"days":["weekend"],"periods":[{"id":"we","label":"Weekend","start":"00:00","end":"24:00","rate_usd_per_kwh":0.15}]}
    ]}]},
  "riders_usd_per_kwh":0,
  "export":{"type":"none","rate_usd_per_kwh":0}
}`

// seasonalJSON is a two-season (summer/winter) all-day flat tariff. Export none.
const seasonalJSON = `{
  "id":"rt-season","name":"Seasonal","short_name":"season",
  "utility":"x","territory":"t","timezone":"America/Chicago","currency":"USD",
  "effective":{"from":"2025-01-01","to":"2025-12-31"},
  "provenance":{"source_url":"","retrieved":"2026-07-12","confidence":"estimated","notes":""},
  "fixed_monthly_usd":0,
  "energy":{"seasons":[
    {"id":"summer","months":[6,7,8,9],"day_types":[{"days":["mon","tue","wed","thu","fri","sat","sun"],
      "periods":[{"id":"s","label":"Summer","start":"00:00","end":"24:00","rate_usd_per_kwh":0.30}]}]},
    {"id":"winter","months":[1,2,3,4,5,10,11,12],"day_types":[{"days":["mon","tue","wed","thu","fri","sat","sun"],
      "periods":[{"id":"w","label":"Winter","start":"00:00","end":"24:00","rate_usd_per_kwh":0.10}]}]}
  ]},
  "riders_usd_per_kwh":0,
  "export":{"type":"none","rate_usd_per_kwh":0}
}`

// TestRateAtMidnightWrap walks the Day/Free-Nights boundaries of fixture A,
// where the night period wraps midnight (21:00–06:00). Import includes riders
// ($0.05); export is flat buyback ($0.06). July date → DST irrelevant (no
// transition occurs in July), which is the point: window math is wall-clock.
func TestRateAtMidnightWrap(t *testing.T) {
	tar := mustParseFile(t, "testdata/test-tou-freenight.json")
	loc := mustLoc(t, "America/Chicago")

	cases := []struct {
		hour, min  int
		wantPeriod string
		wantImport float64
	}{
		{0, 0, "night", 0.05},   // just after midnight — still night
		{5, 0, "night", 0.05},   // 05:00 night
		{5, 59, "night", 0.05},  // last minute of night
		{6, 0, "day", 0.25},     // 06:00 flips to day (0.20 + 0.05 riders)
		{12, 0, "day", 0.25},    // midday
		{20, 59, "day", 0.25},   // last minute of day
		{21, 0, "night", 0.05},  // 21:00 flips to night
		{23, 30, "night", 0.05}, // late night
	}
	for _, c := range cases {
		ri := tar.RateAt(time.Date(2025, 7, 15, c.hour, c.min, 0, 0, loc))
		if ri.PeriodID != c.wantPeriod {
			t.Errorf("%02d:%02d period = %q, want %q", c.hour, c.min, ri.PeriodID, c.wantPeriod)
		}
		if !approxEqual(ri.ImportUSDPerKWh, c.wantImport) {
			t.Errorf("%02d:%02d import = %v, want %v", c.hour, c.min, ri.ImportUSDPerKWh, c.wantImport)
		}
		if !approxEqual(ri.ExportUSDPerKWh, 0.06) {
			t.Errorf("%02d:%02d export = %v, want 0.06 (flat buyback)", c.hour, c.min, ri.ExportUSDPerKWh)
		}
	}
}

// TestRateAtWeekdayWeekend confirms the day_type split resolves by weekday.
func TestRateAtWeekdayWeekend(t *testing.T) {
	tar, err := Parse([]byte(weekdaySplitJSON))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	loc := mustLoc(t, "America/Chicago")

	wed := tar.RateAt(time.Date(2025, 7, 16, 10, 0, 0, 0, loc)) // Wednesday
	if wed.PeriodID != "wd" || !approxEqual(wed.ImportUSDPerKWh, 0.25) {
		t.Errorf("Wednesday = {%s, %v}, want {wd, 0.25}", wed.PeriodID, wed.ImportUSDPerKWh)
	}
	sat := tar.RateAt(time.Date(2025, 7, 19, 10, 0, 0, 0, loc)) // Saturday
	if sat.PeriodID != "we" || !approxEqual(sat.ImportUSDPerKWh, 0.15) {
		t.Errorf("Saturday = {%s, %v}, want {we, 0.15}", sat.PeriodID, sat.ImportUSDPerKWh)
	}
}

// TestRateAtSeasonBoundary confirms month → season resolution, including the
// exact Sep(9, summer) / Oct(10, winter) boundary.
func TestRateAtSeasonBoundary(t *testing.T) {
	tar, err := Parse([]byte(seasonalJSON))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	loc := mustLoc(t, "America/Chicago")

	cases := []struct {
		month      time.Month
		wantPeriod string
		wantImport float64
	}{
		{time.January, "w", 0.10},
		{time.July, "s", 0.30},
		{time.September, "s", 0.30}, // last summer month
		{time.October, "w", 0.10},   // first winter month after boundary
	}
	for _, c := range cases {
		ri := tar.RateAt(time.Date(2025, c.month, 15, 12, 0, 0, 0, loc))
		if ri.PeriodID != c.wantPeriod || !approxEqual(ri.ImportUSDPerKWh, c.wantImport) {
			t.Errorf("%s = {%s, %v}, want {%s, %v}", c.month, ri.PeriodID, ri.ImportUSDPerKWh, c.wantPeriod, c.wantImport)
		}
	}
}

// TestRateAtTimezoneConversion confirms a UTC instant is resolved through the
// tariff's timezone, not treated as local: 02:00Z on Jul 15 is 21:00 the prior
// evening in Chicago and must land in the night period.
func TestRateAtTimezoneConversion(t *testing.T) {
	tar := mustParseFile(t, "testdata/test-tou-freenight.json")

	night := tar.RateAt(time.Date(2025, 7, 15, 2, 0, 0, 0, time.UTC)) // → 2025-07-14 21:00 CDT
	if night.PeriodID != "night" {
		t.Errorf("02:00Z period = %q, want night (21:00 Chicago)", night.PeriodID)
	}
	day := tar.RateAt(time.Date(2025, 7, 15, 18, 0, 0, 0, time.UTC)) // → 13:00 CDT
	if day.PeriodID != "day" {
		t.Errorf("18:00Z period = %q, want day (13:00 Chicago)", day.PeriodID)
	}
}

// TestRateAtExportTypes confirms each export type's ExportUSDPerKWh: net
// metering credits the bare period energy rate (no riders/tier), and none pays
// nothing. (Buyback is covered by TestRateAtMidnightWrap.)
func TestRateAtExportTypes(t *testing.T) {
	// net_metering: fixture B period rate is $0.10, riders 0 → import 0.10,
	// export 0.10.
	nm := mustParseFile(t, "testdata/test-tiered-demand.json")
	ri := nm.RateAt(time.Date(2025, 7, 15, 12, 0, 0, 0, mustLoc(t, "America/Los_Angeles")))
	if !approxEqual(ri.ImportUSDPerKWh, 0.10) || !approxEqual(ri.ExportUSDPerKWh, 0.10) {
		t.Errorf("net metering = import %v / export %v, want 0.10 / 0.10", ri.ImportUSDPerKWh, ri.ExportUSDPerKWh)
	}

	// none: weekdaySplitJSON export type is none → export 0.
	none, err := Parse([]byte(weekdaySplitJSON))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	rn := none.RateAt(time.Date(2025, 7, 16, 10, 0, 0, 0, mustLoc(t, "America/Chicago")))
	if !approxEqual(rn.ExportUSDPerKWh, 0) {
		t.Errorf("export none = %v, want 0", rn.ExportUSDPerKWh)
	}
}
