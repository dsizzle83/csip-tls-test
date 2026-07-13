package tariff

import (
	"math"
	"os"
	"testing"
	"time"
)

// loadTestdata reads and parses one testdata tariff file.
func loadTestdata(path string) (*Tariff, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return Parse(data)
}

// approxEqual is the float comparator for money/quantity assertions. The
// tolerance (1e-6) sits far below a cent yet safely above IEEE-754 noise from
// summing inexact decimal rates, so an assertion of a to-the-cent amount is
// exact in practice.
func approxEqual(a, b float64) bool { return math.Abs(a-b) < 1e-6 }

// wantAmount fails t unless line item li matches the expected kind/label/qty/
// rate/amount. Amount is the credibility field — asserted to the cent.
func wantLine(t *testing.T, li LineItem, kind, label string, qty, rate, amount float64) {
	t.Helper()
	if li.Kind != kind {
		t.Errorf("kind = %q, want %q", li.Kind, kind)
	}
	if li.Label != label {
		t.Errorf("label = %q, want %q", li.Label, label)
	}
	if !approxEqual(li.Qty, qty) {
		t.Errorf("%s qty = %v, want %v", label, li.Qty, qty)
	}
	if !approxEqual(li.Rate, rate) {
		t.Errorf("%s rate = %v, want %v", label, li.Rate, rate)
	}
	if !approxEqual(li.AmountUSD, amount) {
		t.Errorf("%s amount = %v, want %v (to the cent)", label, li.AmountUSD, amount)
	}
}

// mustLoc loads an IANA location or fails the test (tzdata is embedded).
func mustLoc(t *testing.T, name string) *time.Location {
	t.Helper()
	loc, err := time.LoadLocation(name)
	if err != nil {
		t.Fatalf("LoadLocation(%q): %v", name, err)
	}
	return loc
}

// mustParseFile loads and validates a testdata tariff or fails.
func mustParseFile(t *testing.T, path string) *Tariff {
	t.Helper()
	tar, err := loadTestdata(path)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	return tar
}
