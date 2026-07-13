package tariff

import (
	"fmt"
	"math"
	"time"
)

// Line item kinds (Bill.LineItems[].Kind) — the closed set from CONTRACTS.md §1.
const (
	KindFixed        = "fixed"
	KindEnergy       = "energy" // one per period that saw import, keyed by period id
	KindTierAdder    = "tier_adder"
	KindRiders       = "riders"
	KindDemand       = "demand"
	KindExportCredit = "export_credit" // negative amount (a credit)
)

// LineItem is one row of an itemized bill.
type LineItem struct {
	Kind      string  `json:"kind"`
	Label     string  `json:"label"`
	Qty       float64 `json:"qty"`
	QtyUnit   string  `json:"qty_unit"`
	Rate      float64 `json:"rate"`
	AmountUSD float64 `json:"amount_usd"`
}

// Bill is the closed-out result for one billing month.
type Bill struct {
	LineItems []LineItem `json:"line_items"`
	TotalUSD  float64    `json:"total_usd"`
}

// BillCalc accumulates one billing month. Feed it 15-minute (or any cadence)
// interval samples with Add, then Close for the itemized Bill. Tier adders and
// demand charges are computed at Close from the accumulated monthly state.
type BillCalc struct {
	t     *Tariff
	loc   *time.Location
	year  int
	month time.Month

	// Import energy accumulated per period id, in first-seen order for stable
	// line-item ordering.
	periodOrder []string
	periodKWh   map[string]float64
	periodRate  map[string]float64 // period energy rate (excludes riders/tiers)
	periodLabel map[string]string

	totalImportKWh float64 // drives tiers and riders

	exportKWh       float64 // total exported energy this month
	exportCreditUSD float64 // accumulated credit (period-matched for net metering)

	demandPeakKW []float64 // running max in-window interval peak, parallel to t.Demand
}

// NewBillCalc starts an accumulator for (year, month) against tariff t.
func NewBillCalc(t *Tariff, year int, month time.Month) *BillCalc {
	return &BillCalc{
		t:            t,
		loc:          t.location(),
		year:         year,
		month:        month,
		periodKWh:    make(map[string]float64),
		periodRate:   make(map[string]float64),
		periodLabel:  make(map[string]string),
		demandPeakKW: make([]float64, len(t.Demand)),
	}
}

// Add folds one interval sample into the accumulator:
//   - importKWh: grid import energy in the interval (>= 0)
//   - exportKWh: exported energy in the interval (>= 0)
//   - intervalPeakImportKW: the interval's peak import demand (kW), used for
//     demand charges (the "max 15-min demand" is the max of these over the
//     month within each demand window)
//
// Samples whose timestamp — converted to the tariff's timezone — falls outside
// the accumulator's (year, month) are ignored (a BillCalc is scoped to one
// billing month).
func (b *BillCalc) Add(ts time.Time, importKWh, exportKWh, intervalPeakImportKW float64) {
	local := ts.In(b.loc)
	if local.Year() != b.year || local.Month() != b.month {
		return
	}
	p, ok := b.t.periodAt(local)
	if !ok {
		return
	}

	if importKWh != 0 {
		if _, seen := b.periodKWh[p.ID]; !seen {
			b.periodOrder = append(b.periodOrder, p.ID)
			b.periodRate[p.ID] = p.RateUSDPerKWh
			b.periodLabel[p.ID] = p.Label
		}
		b.periodKWh[p.ID] += importKWh
		b.totalImportKWh += importKWh
	}

	if exportKWh != 0 {
		switch b.t.Export.Type {
		case ExportNetMetering:
			// Period-matched energy rate at the moment of export (no riders,
			// no tier adder — see package doc).
			b.exportCreditUSD += p.RateUSDPerKWh * exportKWh
		case ExportBuyback:
			b.exportCreditUSD += b.t.Export.RateUSDPerKWh * exportKWh
		}
		b.exportKWh += exportKWh
	}

	for i := range b.t.Demand {
		if b.t.Demand[i].covers(local) && intervalPeakImportKW > b.demandPeakKW[i] {
			b.demandPeakKW[i] = intervalPeakImportKW
		}
	}
}

// Close produces the itemized bill. Line-item order is: fixed, energy (per
// period, first-seen order), tier adders, riders, demand, export credit. Each
// amount is rounded to the cent; TotalUSD is the sum of the rounded amounts.
func (b *BillCalc) Close() Bill {
	var items []LineItem

	// 1. Fixed monthly charge.
	if b.t.FixedMonthlyUSD > 0 {
		items = append(items, LineItem{
			Kind: KindFixed, Label: "Fixed monthly charge",
			Qty: 1, QtyUnit: "month", Rate: b.t.FixedMonthlyUSD,
			AmountUSD: round2(b.t.FixedMonthlyUSD),
		})
	}

	// 2. Energy, one line per period that saw import.
	for _, pid := range b.periodOrder {
		kwh := b.periodKWh[pid]
		rate := b.periodRate[pid]
		items = append(items, LineItem{
			Kind: KindEnergy, Label: b.periodLabel[pid],
			Qty: kwh, QtyUnit: "kWh", Rate: rate,
			AmountUSD: round2(kwh * rate),
		})
	}

	// 3. Tier adders over cumulative monthly import.
	items = append(items, b.tierLineItems()...)

	// 4. Riders on all import.
	if b.t.RidersUSDPerKWh > 0 && b.totalImportKWh > 0 {
		items = append(items, LineItem{
			Kind: KindRiders, Label: "Delivery & riders",
			Qty: b.totalImportKWh, QtyUnit: "kWh", Rate: b.t.RidersUSDPerKWh,
			AmountUSD: round2(b.totalImportKWh * b.t.RidersUSDPerKWh),
		})
	}

	// 5. Demand charges (one per declared charge, even at 0 kW observed).
	for i := range b.t.Demand {
		peak := b.demandPeakKW[i]
		items = append(items, LineItem{
			Kind: KindDemand, Label: b.t.Demand[i].Label,
			Qty: peak, QtyUnit: "kW", Rate: b.t.Demand[i].USDPerKW,
			AmountUSD: round2(peak * b.t.Demand[i].USDPerKW),
		})
	}

	// 6. Export credit (a negative amount).
	if b.exportKWh > 0 {
		switch b.t.Export.Type {
		case ExportNetMetering:
			rate := b.exportCreditUSD / b.exportKWh // blended (period-matched) credit rate
			items = append(items, LineItem{
				Kind: KindExportCredit, Label: "Export credit (net metering)",
				Qty: b.exportKWh, QtyUnit: "kWh", Rate: rate,
				AmountUSD: -round2(b.exportCreditUSD),
			})
		case ExportBuyback:
			items = append(items, LineItem{
				Kind: KindExportCredit, Label: "Export buyback",
				Qty: b.exportKWh, QtyUnit: "kWh", Rate: b.t.Export.RateUSDPerKWh,
				AmountUSD: -round2(b.exportKWh * b.t.Export.RateUSDPerKWh),
			})
		}
	}

	var total float64
	for _, li := range items {
		total += li.AmountUSD
	}
	return Bill{LineItems: items, TotalUSD: round2(total)}
}

// tierLineItems distributes cumulative monthly import across the tier
// breakpoints and emits a line for each tier with a nonzero adder and nonzero
// kWh falling in it.
func (b *BillCalc) tierLineItems() []LineItem {
	var out []LineItem
	lower := 0.0
	for i, tier := range b.t.Energy.Tiers {
		upper := math.Inf(1)
		if tier.UpToKWh != nil {
			upper = *tier.UpToKWh
		}
		hi := math.Min(b.totalImportKWh, upper)
		kwh := hi - lower
		if kwh > 0 && tier.AdderUSDPerKWh != 0 {
			out = append(out, LineItem{
				Kind: KindTierAdder, Label: fmt.Sprintf("Tier %d adder", i+1),
				Qty: kwh, QtyUnit: "kWh", Rate: tier.AdderUSDPerKWh,
				AmountUSD: round2(kwh * tier.AdderUSDPerKWh),
			})
		}
		lower = upper
		if math.IsInf(upper, 1) {
			break
		}
	}
	return out
}

// covers reports whether a demand charge's month/day/time window contains local
// (which must already be in the tariff's timezone). Empty months or days mean
// "any"; the time window may wrap midnight.
func (d DemandCharge) covers(local time.Time) bool {
	if len(d.Months) > 0 && !containsInt(d.Months, int(local.Month())) {
		return false
	}
	if len(d.Days) > 0 {
		wds, err := expandDays(d.Days)
		if err != nil || !containsWeekday(wds, local.Weekday()) {
			return false
		}
	}
	minute := local.Hour()*60 + local.Minute()
	return minuteInWindow(minute, mustHM(d.Start), mustHM(d.End))
}

// round2 rounds a dollar amount to the cent (half away from zero).
func round2(x float64) float64 {
	return math.Round(x*100) / 100
}
