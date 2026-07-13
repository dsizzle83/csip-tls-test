package tariff

import (
	"strings"
	"testing"
	"time"
)

// capFixture builds a minimal all-day flat tariff: 0.20 $/kWh energy,
// 0.05 $/kWh riders, $10 fixed, with the given export config.
func capFixture(t *testing.T, export string) *Tariff {
	t.Helper()
	tf, err := Parse([]byte(`{
		"id": "cap-fixture", "name": "Cap Fixture", "utility": "Test",
		"territory": "test", "timezone": "UTC", "currency": "USD",
		"effective": {"from": "2025-01-01", "to": "2025-12-31"},
		"provenance": {"source_url": "test", "retrieved": "2026-07-13", "confidence": "estimated"},
		"fixed_monthly_usd": 10.0,
		"riders_usd_per_kwh": 0.05,
		"energy": {"seasons": [{"id": "all", "months": [1,2,3,4,5,6,7,8,9,10,11,12],
			"day_types": [{"days": ["mon","tue","wed","thu","fri","sat","sun"],
				"periods": [{"id": "flat", "label": "Flat", "start": "00:00", "end": "24:00",
					"rate_usd_per_kwh": 0.20}]}]}]},
		"export": ` + export + `}`))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	return tf
}

// Import 100 kWh + export 200 kWh in July 2025:
// energy $20.00, riders $5.00, volumetric $25.00, fixed $10.00.
func capRun(t *testing.T, tf *Tariff) Bill {
	t.Helper()
	b := NewBillCalc(tf, 2025, time.July)
	ts := time.Date(2025, 7, 10, 12, 0, 0, 0, time.UTC)
	b.Add(ts, 100, 0, 0)
	b.Add(ts.Add(time.Hour), 0, 200, 0)
	return b.Close()
}

func TestNEMCreditCappedAtVolumetric(t *testing.T) {
	tf := capFixture(t, `{"type": "net_metering"}`) // default cap: energy_charges
	bill := capRun(t, tf)
	// Earned credit 200 kWh × 0.20 = $40 > volumetric $25 → applied $25,
	// carryover $15, total = fixed only.
	if bill.TotalUSD != 10.00 {
		t.Errorf("TotalUSD = %.2f, want 10.00 (floored at fixed charge)", bill.TotalUSD)
	}
	if bill.CreditCarryoverUSD != 15.00 {
		t.Errorf("CreditCarryoverUSD = %.2f, want 15.00", bill.CreditCarryoverUSD)
	}
	var credit float64
	for _, li := range bill.LineItems {
		if li.Kind == KindExportCredit {
			credit = li.AmountUSD
		}
	}
	if credit != -25.00 {
		t.Errorf("export_credit line = %.2f, want -25.00", credit)
	}
}

func TestNEMExplicitCapNoneGoesNegative(t *testing.T) {
	tf := capFixture(t, `{"type": "net_metering", "monthly_cap": "none"}`)
	bill := capRun(t, tf)
	// 10 + 25 − 40 = −5; no carryover under an explicit cash-out config.
	if bill.TotalUSD != -5.00 {
		t.Errorf("TotalUSD = %.2f, want -5.00", bill.TotalUSD)
	}
	if bill.CreditCarryoverUSD != 0 {
		t.Errorf("CreditCarryoverUSD = %.2f, want 0", bill.CreditCarryoverUSD)
	}
}

func TestBuybackDefaultUncapped(t *testing.T) {
	tf := capFixture(t, `{"type": "buyback", "rate_usd_per_kwh": 0.30}`)
	bill := capRun(t, tf)
	// 10 + 25 − 60 = −25 (cash-out plans may pay net-negative).
	if bill.TotalUSD != -25.00 {
		t.Errorf("TotalUSD = %.2f, want -25.00", bill.TotalUSD)
	}
	if bill.CreditCarryoverUSD != 0 {
		t.Errorf("CreditCarryoverUSD = %.2f, want 0", bill.CreditCarryoverUSD)
	}
}

func TestValidateRejectsBadMonthlyCap(t *testing.T) {
	tf := capFixture(t, `{"type": "net_metering"}`)
	tf.Export.MonthlyCap = "rollover"
	if err := tf.Validate(); err == nil || !strings.Contains(err.Error(), "monthly_cap") {
		t.Errorf("Validate() = %v, want monthly_cap error", err)
	}
}
