package tariff

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// maxRateUSDPerKWh is the sanity ceiling for any per-kWh rate (CONTRACTS.md §1:
// "All rates ≥ 0 and < 5 $/kWh"). Demand charges are $/kW, not $/kWh, so they
// are sanity-checked separately (>= 0) and are not subject to this ceiling.
const maxRateUSDPerKWh = 5.0

// maxDemandUSDPerKW is a loose sanity ceiling for demand ($/kW) charges — high
// enough for any real retail demand rate, low enough to catch a units typo.
const maxDemandUSDPerKW = 1000.0

// Validate applies every hard rule from CONTRACTS.md §1 and, as a side effect,
// caches the resolved timezone and effective range on the receiver. It is safe
// to call more than once. A nil return means the tariff is internally
// consistent and safe to bill against.
//
// NOT checked here (deliberately out of scope): whether the tariff's seasons
// cover the months a particular *scenario* touches. CONTRACTS.md §1 calls that
// a load-time error, but it is a cross-object check the whatif/scenario loader
// owns — a standalone summer-only file is legal on its own terms.
func (t *Tariff) Validate() error {
	if strings.TrimSpace(t.ID) == "" {
		return fmt.Errorf("id is required")
	}
	if strings.TrimSpace(t.Name) == "" {
		return fmt.Errorf("tariff %q: name is required", t.ID)
	}
	if strings.TrimSpace(t.Currency) == "" {
		return fmt.Errorf("tariff %q: currency is required", t.ID)
	}

	// Timezone must resolve (and is cached for the engine).
	loc, err := time.LoadLocation(t.Timezone)
	if err != nil {
		return fmt.Errorf("tariff %q: timezone %q: %w", t.ID, t.Timezone, err)
	}
	t.loc = loc

	// Provenance confidence enum.
	switch t.Provenance.Confidence {
	case ConfidenceFiled, ConfidencePublished, ConfidenceEstimated:
	default:
		return fmt.Errorf("tariff %q: confidence %q not in {filed,published,estimated}", t.ID, t.Provenance.Confidence)
	}

	// Effective range parses and is ordered.
	from, err := time.ParseInLocation(dateLayout, t.Effective.From, time.UTC)
	if err != nil {
		return fmt.Errorf("tariff %q: effective.from %q: %w", t.ID, t.Effective.From, err)
	}
	to, err := time.ParseInLocation(dateLayout, t.Effective.To, time.UTC)
	if err != nil {
		return fmt.Errorf("tariff %q: effective.to %q: %w", t.ID, t.Effective.To, err)
	}
	if to.Before(from) {
		return fmt.Errorf("tariff %q: effective.to %s is before effective.from %s", t.ID, t.Effective.To, t.Effective.From)
	}
	t.effFrom, t.effTo = from, to

	// Fixed charge and riders.
	if t.FixedMonthlyUSD < 0 {
		return fmt.Errorf("tariff %q: fixed_monthly_usd %g < 0", t.ID, t.FixedMonthlyUSD)
	}
	if err := checkRate(t.ID, "riders_usd_per_kwh", t.RidersUSDPerKWh); err != nil {
		return err
	}

	if err := t.validateEnergy(); err != nil {
		return err
	}
	if err := t.validateDemand(); err != nil {
		return err
	}
	if err := t.validateExport(); err != nil {
		return err
	}
	return nil
}

// checkRate enforces 0 <= r < 5 for a per-kWh rate.
func checkRate(id, field string, r float64) error {
	if r < 0 {
		return fmt.Errorf("tariff %q: %s %g < 0", id, field, r)
	}
	if r >= maxRateUSDPerKWh {
		return fmt.Errorf("tariff %q: %s %g >= %g $/kWh sanity ceiling", id, field, r, maxRateUSDPerKWh)
	}
	return nil
}

func (t *Tariff) validateEnergy() error {
	if len(t.Energy.Seasons) == 0 {
		return fmt.Errorf("tariff %q: energy.seasons is empty", t.ID)
	}

	// Months partition: no month may appear in two seasons; all in 1..12. Full
	// 1..12 coverage is NOT required (a summer-only file is legal — §1).
	monthOwner := make(map[int]string)
	for _, s := range t.Energy.Seasons {
		if len(s.Months) == 0 {
			return fmt.Errorf("tariff %q: season %q has no months", t.ID, s.ID)
		}
		for _, m := range s.Months {
			if m < 1 || m > 12 {
				return fmt.Errorf("tariff %q: season %q month %d out of range 1..12", t.ID, s.ID, m)
			}
			if prev, ok := monthOwner[m]; ok {
				return fmt.Errorf("tariff %q: month %d claimed by both season %q and %q", t.ID, m, prev, s.ID)
			}
			monthOwner[m] = s.ID
		}
		if err := t.validateSeasonWeek(s); err != nil {
			return err
		}
	}

	// Tiers: adders in range; breakpoints strictly increasing with exactly one
	// unbounded (nil) tier permitted, and only as the last tier.
	if err := t.validateTiers(); err != nil {
		return err
	}
	return nil
}

// validateSeasonWeek checks that a season's day_types partition the week (every
// weekday exactly once) and that each day_type's periods tile 24 h.
func (t *Tariff) validateSeasonWeek(s Season) error {
	if len(s.DayTypes) == 0 {
		return fmt.Errorf("tariff %q: season %q has no day_types", t.ID, s.ID)
	}
	seen := make(map[time.Weekday]int)
	for i, dt := range s.DayTypes {
		wds, err := expandDays(dt.Days)
		if err != nil {
			return fmt.Errorf("tariff %q: season %q day_types[%d]: %w", t.ID, s.ID, i, err)
		}
		if len(wds) == 0 {
			return fmt.Errorf("tariff %q: season %q day_types[%d] has no days", t.ID, s.ID, i)
		}
		for _, wd := range wds {
			seen[wd]++
		}
		if err := t.validatePeriods(s.ID, i, dt.Periods); err != nil {
			return err
		}
	}
	for wd := time.Sunday; wd <= time.Saturday; wd++ {
		switch n := seen[wd]; {
		case n == 0:
			return fmt.Errorf("tariff %q: season %q does not cover weekday %s", t.ID, s.ID, wd)
		case n > 1:
			return fmt.Errorf("tariff %q: season %q covers weekday %s %d times (must be exactly once)", t.ID, s.ID, wd, n)
		}
	}
	return nil
}

// validatePeriods checks that periods rate-sanity and tile [00:00,24:00) with
// no gap and no overlap, correctly accounting for midnight-wrapping windows.
func (t *Tariff) validatePeriods(seasonID string, dtIdx int, periods []Period) error {
	if len(periods) == 0 {
		return fmt.Errorf("tariff %q: season %q day_types[%d] has no periods", t.ID, seasonID, dtIdx)
	}
	// Each wrapping period contributes two segments; a normal one contributes
	// one. All segments together must exactly tile [0,1440).
	type seg struct {
		start, end int
		pid        string
	}
	var segs []seg
	for _, p := range periods {
		if err := checkRate(t.ID, fmt.Sprintf("season %q period %q rate", seasonID, p.ID), p.RateUSDPerKWh); err != nil {
			return err
		}
		s, err := parseHM(p.Start)
		if err != nil {
			return fmt.Errorf("tariff %q: season %q period %q start: %w", t.ID, seasonID, p.ID, err)
		}
		e, err := parseHM(p.End)
		if err != nil {
			return fmt.Errorf("tariff %q: season %q period %q end: %w", t.ID, seasonID, p.ID, err)
		}
		if s == e {
			return fmt.Errorf("tariff %q: season %q period %q is zero-length (start==end==%s)", t.ID, seasonID, p.ID, p.Start)
		}
		if s < e {
			segs = append(segs, seg{s, e, p.ID})
		} else {
			// Wrap: [start,24:00) plus [00:00,end). An end of exactly 00:00
			// (=0) means the period ends at midnight and contributes no
			// second segment.
			segs = append(segs, seg{s, 1440, p.ID})
			if e > 0 {
				segs = append(segs, seg{0, e, p.ID})
			}
		}
	}
	sort.Slice(segs, func(i, j int) bool { return segs[i].start < segs[j].start })
	cursor := 0
	for _, sg := range segs {
		switch {
		case sg.start < cursor:
			return fmt.Errorf("tariff %q: season %q day_types[%d]: period %q overlaps at minute %d", t.ID, seasonID, dtIdx, sg.pid, sg.start)
		case sg.start > cursor:
			return fmt.Errorf("tariff %q: season %q day_types[%d]: gap in coverage at minute %d (before period %q)", t.ID, seasonID, dtIdx, cursor, sg.pid)
		}
		cursor = sg.end
	}
	if cursor != 1440 {
		return fmt.Errorf("tariff %q: season %q day_types[%d]: periods end coverage at minute %d, not 24:00", t.ID, seasonID, dtIdx, cursor)
	}
	return nil
}

// validateTiers checks adder sanity and that breakpoints are strictly
// increasing with the unbounded (nil up_to_kwh) tier — if any — last.
func (t *Tariff) validateTiers() error {
	prev := 0.0
	for i, tier := range t.Energy.Tiers {
		if err := checkRate(t.ID, fmt.Sprintf("tiers[%d].adder_usd_per_kwh", i), tier.AdderUSDPerKWh); err != nil {
			return err
		}
		if tier.UpToKWh == nil {
			if i != len(t.Energy.Tiers)-1 {
				return fmt.Errorf("tariff %q: tiers[%d] is unbounded (up_to_kwh null) but is not the last tier", t.ID, i)
			}
			continue
		}
		if *tier.UpToKWh <= 0 {
			return fmt.Errorf("tariff %q: tiers[%d].up_to_kwh %g must be > 0", t.ID, i, *tier.UpToKWh)
		}
		if *tier.UpToKWh <= prev {
			return fmt.Errorf("tariff %q: tiers[%d].up_to_kwh %g not greater than previous breakpoint %g", t.ID, i, *tier.UpToKWh, prev)
		}
		prev = *tier.UpToKWh
	}
	return nil
}

func (t *Tariff) validateDemand() error {
	for i, d := range t.Demand {
		if d.USDPerKW < 0 {
			return fmt.Errorf("tariff %q: demand[%d].usd_per_kw %g < 0", t.ID, i, d.USDPerKW)
		}
		if d.USDPerKW > maxDemandUSDPerKW {
			return fmt.Errorf("tariff %q: demand[%d].usd_per_kw %g exceeds %g $/kW sanity ceiling", t.ID, i, d.USDPerKW, maxDemandUSDPerKW)
		}
		for _, m := range d.Months {
			if m < 1 || m > 12 {
				return fmt.Errorf("tariff %q: demand[%d] month %d out of range 1..12", t.ID, i, m)
			}
		}
		if _, err := expandDays(d.Days); err != nil {
			return fmt.Errorf("tariff %q: demand[%d].days: %w", t.ID, i, err)
		}
		s, err := parseHM(d.Start)
		if err != nil {
			return fmt.Errorf("tariff %q: demand[%d].start: %w", t.ID, i, err)
		}
		e, err := parseHM(d.End)
		if err != nil {
			return fmt.Errorf("tariff %q: demand[%d].end: %w", t.ID, i, err)
		}
		if s == e {
			return fmt.Errorf("tariff %q: demand[%d] window is zero-length (start==end)", t.ID, i)
		}
	}
	return nil
}

func (t *Tariff) validateExport() error {
	switch t.Export.MonthlyCap {
	case "", CapEnergyCharges, CapNone:
	default:
		return fmt.Errorf("tariff %q: export.monthly_cap %q not in {energy_charges,none}",
			t.ID, t.Export.MonthlyCap)
	}
	switch t.Export.Type {
	case ExportNetMetering, ExportNone:
		// rate is unused for these; sanity-check it only if present.
		if t.Export.RateUSDPerKWh != 0 {
			return checkRate(t.ID, "export.rate_usd_per_kwh", t.Export.RateUSDPerKWh)
		}
		return nil
	case ExportBuyback:
		return checkRate(t.ID, "export.rate_usd_per_kwh", t.Export.RateUSDPerKWh)
	default:
		return fmt.Errorf("tariff %q: export.type %q not in {net_metering,buyback,none}", t.ID, t.Export.Type)
	}
}
