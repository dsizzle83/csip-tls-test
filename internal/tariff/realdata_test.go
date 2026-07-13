package tariff

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestRealTariffDir validates every committed real-world tariff in
// data/tariffs/ against the engine — schema conformance plus a July-2025
// rate sanity probe. Skips when run outside the repo tree.
func TestRealTariffDir(t *testing.T) {
	dir := filepath.Join("..", "..", "data", "tariffs")
	if _, err := os.Stat(dir); err != nil {
		t.Skip("data/tariffs not present")
	}
	ts, err := Load(dir)
	if err != nil {
		t.Fatalf("Load(%s): %v", dir, err)
	}
	if len(ts) < 6 {
		t.Fatalf("expected >=6 real tariffs, got %d", len(ts))
	}
	// A July 2025 weekday afternoon must resolve to a sane import rate on
	// every tariff (peak US residential all-in stays well under $1/kWh).
	probe := time.Date(2025, 7, 15, 15, 30, 0, 0, time.UTC)
	for id, tf := range ts {
		ri := tf.RateAt(probe)
		if ri.ImportUSDPerKWh <= 0.05 || ri.ImportUSDPerKWh > 1.0 {
			t.Errorf("%s: implausible July weekday import rate %.4f $/kWh (period %s)",
				id, ri.ImportUSDPerKWh, ri.PeriodID)
		}
	}
}
