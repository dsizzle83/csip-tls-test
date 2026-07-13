package tariff

import (
	"testing"
	"time"
)

// TestBillFixtureA is a hand-computed bill for the TOU free-nights fixture
// (testdata/test-tou-freenight.json): a time-of-use tariff with a free-night
// window, per-kWh riders, a fixed monthly charge, and flat buyback export.
//
// Tariff: America/Chicago. Periods: Day 06:00–21:00 @ $0.20/kWh, Free Nights
// 21:00–06:00 @ $0.00/kWh. Riders $0.05/kWh (all import). Fixed $9.95/mo.
// Export: buyback @ $0.06/kWh.
//
// Interval samples (times are Chicago-local, July 2025):
//
//	tick  local time         period        import kWh  export kWh
//	----  -----------------  ------------  ---------  ---------
//	 t1   2025-07-15 12:00   Day             2.0        0.5
//	 t2   2025-07-15 12:15   Day             2.0        0.5
//	 t3   2025-07-15 12:30   Day             2.0        0.5
//	 t4   2025-07-15 23:00   Free Nights     1.0        0.0
//	 t5   2025-07-15 23:15   Free Nights     1.0        0.0
//	 t6   2025-07-16 03:00   Free Nights     1.0        0.0
//
//	Day import    = 2.0 + 2.0 + 2.0            = 6.0 kWh
//	Night import  = 1.0 + 1.0 + 1.0            = 3.0 kWh
//	Total import  = 6.0 + 3.0                  = 9.0 kWh
//	Total export  = 0.5 + 0.5 + 0.5            = 1.5 kWh
//
//	Bill:
//	  fixed          1 mo  × $9.95            =  $9.95
//	  energy Day     6.0 kWh × $0.20          =  $1.20
//	  energy Nights  3.0 kWh × $0.00          =  $0.00
//	  riders         9.0 kWh × $0.05          =  $0.45
//	  export buyback 1.5 kWh × $0.06          = -$0.09
//	                                   TOTAL  = $11.51
func TestBillFixtureA(t *testing.T) {
	tar := mustParseFile(t, "testdata/test-tou-freenight.json")
	loc := mustLoc(t, "America/Chicago")
	at := func(day, hour, min int) time.Time { return time.Date(2025, 7, day, hour, min, 0, 0, loc) }

	b := NewBillCalc(tar, 2025, time.July)
	b.Add(at(15, 12, 0), 2.0, 0.5, 0) // Day
	b.Add(at(15, 12, 15), 2.0, 0.5, 0)
	b.Add(at(15, 12, 30), 2.0, 0.5, 0)
	b.Add(at(15, 23, 0), 1.0, 0.0, 0) // Free Nights
	b.Add(at(15, 23, 15), 1.0, 0.0, 0)
	b.Add(at(16, 3, 0), 1.0, 0.0, 0)
	bill := b.Close()

	if len(bill.LineItems) != 5 {
		t.Fatalf("line item count = %d, want 5:\n%+v", len(bill.LineItems), bill.LineItems)
	}
	wantLine(t, bill.LineItems[0], KindFixed, "Fixed monthly charge", 1, 9.95, 9.95)
	wantLine(t, bill.LineItems[1], KindEnergy, "Day", 6.0, 0.20, 1.20)
	wantLine(t, bill.LineItems[2], KindEnergy, "Free Nights", 3.0, 0.00, 0.00)
	wantLine(t, bill.LineItems[3], KindRiders, "Delivery & riders", 9.0, 0.05, 0.45)
	wantLine(t, bill.LineItems[4], KindExportCredit, "Export buyback", 1.5, 0.06, -0.09)
	if !approxEqual(bill.TotalUSD, 11.51) {
		t.Errorf("TotalUSD = %v, want 11.51", bill.TotalUSD)
	}
}

// TestBillFixtureB is a hand-computed bill for the tiered/demand fixture
// (testdata/test-tiered-demand.json): a flat energy rate with two monthly-kWh
// tiers (adder on the upper tier), a $/kW demand charge on a weekday on-peak
// window, and net-metering export. No fixed charge, no riders.
//
// Tariff: America/Los_Angeles. Single all-day period @ $0.10/kWh. Tiers:
// 0–20 kWh adder $0.00, 20+ kWh adder $0.06. Demand: $10.00/kW on the max
// 15-min import demand within July weekdays 16:00–21:00. Export: net metering.
//
// Interval samples (times are LA-local, July 2025):
//
//	tick  local time         wd   import  export  peakKW   in demand window?
//	----  -----------------  ---  ------  ------  ------   -----------------
//	 t1   2025-07-15 17:00   Tue   5.0     0.0     12.0    yes (weekday 16–21)
//	 t2   2025-07-15 17:15   Tue   5.0     0.0     18.0    yes  ← window max
//	 t3   2025-07-15 17:30   Tue   5.0     0.0     15.0    yes
//	 t4   2025-07-15 12:00   Tue   0.0     4.0      0.0    no (12:00 < 16:00)
//	 t5   2025-07-15 12:15   Tue   0.0     4.0      0.0    no
//	 t6   2025-07-19 18:00   Sat   5.0     0.0     25.0    no (weekend)
//	 t7   2025-07-16 08:00   Wed   5.0     0.0     30.0    no (08:00 < 16:00)
//
//	Total import  = 5+5+5+5+5 (t1,t2,t3,t6,t7)      = 25.0 kWh
//	Total export  = 4.0 + 4.0                       =  8.0 kWh (@ $0.10 period rate)
//	Demand peak   = max(12,18,15) in-window         = 18.0 kW   (t6/t7 excluded)
//	Tiers         : tier1 [0,20) → 20 kWh @ $0.00, tier2 [20,25) → 5 kWh @ $0.06
//
//	Bill:
//	  energy All-day   25.0 kWh × $0.10        =   $2.50
//	  tier 2 adder      5.0 kWh × $0.06        =   $0.30
//	  demand           18.0 kW  × $10.00       = $180.00
//	  export credit     8.0 kWh × $0.10        =  -$0.80
//	                                    TOTAL  = $182.00
func TestBillFixtureB(t *testing.T) {
	tar := mustParseFile(t, "testdata/test-tiered-demand.json")
	loc := mustLoc(t, "America/Los_Angeles")
	at := func(day, hour, min int) time.Time { return time.Date(2025, 7, day, hour, min, 0, 0, loc) }

	b := NewBillCalc(tar, 2025, time.July)
	b.Add(at(15, 17, 0), 5.0, 0.0, 12.0) // Tue on-peak
	b.Add(at(15, 17, 15), 5.0, 0.0, 18.0)
	b.Add(at(15, 17, 30), 5.0, 0.0, 15.0)
	b.Add(at(15, 12, 0), 0.0, 4.0, 0.0) // Tue midday export
	b.Add(at(15, 12, 15), 0.0, 4.0, 0.0)
	b.Add(at(19, 18, 0), 5.0, 0.0, 25.0) // Sat — excluded from demand
	b.Add(at(16, 8, 0), 5.0, 0.0, 30.0)  // Wed 08:00 — excluded from demand
	bill := b.Close()

	if len(bill.LineItems) != 4 {
		t.Fatalf("line item count = %d, want 4:\n%+v", len(bill.LineItems), bill.LineItems)
	}
	wantLine(t, bill.LineItems[0], KindEnergy, "All-day energy", 25.0, 0.10, 2.50)
	wantLine(t, bill.LineItems[1], KindTierAdder, "Tier 2 adder", 5.0, 0.06, 0.30)
	wantLine(t, bill.LineItems[2], KindDemand, "On-peak demand", 18.0, 10.0, 180.00)
	wantLine(t, bill.LineItems[3], KindExportCredit, "Export credit (net metering)", 8.0, 0.10, -0.80)
	if !approxEqual(bill.TotalUSD, 182.00) {
		t.Errorf("TotalUSD = %v, want 182.00", bill.TotalUSD)
	}
}

// TestBillIgnoresOutOfMonth confirms Add drops samples outside the
// accumulator's (year, month) in the tariff timezone — so a stray June or
// August tick does not pollute a July bill.
func TestBillIgnoresOutOfMonth(t *testing.T) {
	tar := mustParseFile(t, "testdata/test-tou-freenight.json")
	loc := mustLoc(t, "America/Chicago")

	b := NewBillCalc(tar, 2025, time.July)
	b.Add(time.Date(2025, 7, 10, 12, 0, 0, 0, loc), 4.0, 0, 0) // July — counted
	b.Add(time.Date(2025, 8, 10, 12, 0, 0, 0, loc), 9.0, 0, 0) // August — ignored
	b.Add(time.Date(2025, 6, 10, 12, 0, 0, 0, loc), 9.0, 0, 0) // June — ignored
	bill := b.Close()

	// Only the 4 kWh July tick counts: Day energy 4.0×0.20 = 0.80, riders
	// 4.0×0.05 = 0.20, fixed 9.95 → total 10.95.
	var day, riders float64
	for _, li := range bill.LineItems {
		switch {
		case li.Kind == KindEnergy && li.Label == "Day":
			day = li.Qty
		case li.Kind == KindRiders:
			riders = li.Qty
		}
	}
	if !approxEqual(day, 4.0) {
		t.Errorf("Day import qty = %v, want 4.0 (out-of-month ticks leaked)", day)
	}
	if !approxEqual(riders, 4.0) {
		t.Errorf("riders qty = %v, want 4.0", riders)
	}
	if !approxEqual(bill.TotalUSD, 10.95) {
		t.Errorf("TotalUSD = %v, want 10.95", bill.TotalUSD)
	}
}

// TestBillMonthFilterUsesTariffTZ confirms the (year, month) filter is applied
// in the tariff's timezone, not UTC: a UTC instant early on Aug 1 is still July
// in Chicago and must count toward the July bill.
func TestBillMonthFilterUsesTariffTZ(t *testing.T) {
	tar := mustParseFile(t, "testdata/test-tou-freenight.json")

	b := NewBillCalc(tar, 2025, time.July)
	// 2025-08-01T02:00:00Z == 2025-07-31 21:00 America/Chicago (still July).
	b.Add(time.Date(2025, 8, 1, 2, 0, 0, 0, time.UTC), 3.0, 0, 0)
	bill := b.Close()

	var night float64
	for _, li := range bill.LineItems {
		if li.Kind == KindEnergy {
			night = li.Qty // the sole energy period touched is Free Nights (21:00)
		}
	}
	if !approxEqual(night, 3.0) {
		t.Errorf("import qty = %v, want 3.0 (July-in-TZ tick was dropped)", night)
	}
}
