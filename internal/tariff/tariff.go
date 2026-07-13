// Package tariff implements the LEXA dashboard V2 tariff engine: the on-disk
// JSON schema for a retail electricity plan, its validation, a stateless
// per-instant rate lookup (RateAt), and a one-billing-month accumulator that
// produces an itemized bill (BillCalc / Bill).
//
// It is the authoritative implementation of docs/dashboard-v2/CONTRACTS.md §1.
// The schema, the validation rules, and the engine surface are all specified
// there; this package owns validation and the UI/API trust its output.
//
// Design notes / resolved contract ambiguities (these were reviewed — see the
// package tests and the launch brief report):
//
//   - Net-metering export credit uses the period's ENERGY rate at the moment of
//     export only — no riders, and no monthly tier adder. CONTRACTS.md §1's
//     inline comment mentions "period rate + tier adder"; the build brief
//     resolved this in favor of excluding the tier adder, because a tier adder
//     is monthly-cumulative *state* and RateAt/Add are evaluated per instant
//     with no well-defined "which tier is this export in" answer. Both RateAt's
//     ExportUSDPerKWh and BillCalc's export_credit line therefore credit at the
//     bare period rate for net metering.
//
//   - ImportUSDPerKWh (RateAt) includes riders, excludes tier adders — tier
//     adders are monthly state applied only at BillCalc.Close(). This matches
//     CONTRACTS.md §1 exactly.
//
//   - BillCalc.Add ignores ticks whose timestamp (converted to the tariff's
//     timezone) falls outside the accumulator's (year, month). A BillCalc is
//     "one billing month accumulator" (CONTRACTS.md §1), so it self-scopes;
//     "cumulative monthly import" for tiers and "max demand over the month" are
//     then unambiguous.
//
//   - Line items round to the cent individually and TotalUSD is the sum of the
//     rounded line items (spreadsheet convention: totals tie out to the penny).
//
// Pure standard library. time/tzdata is embedded (see tzdata.go) so IANA zone
// resolution — and therefore every TOU window computation — is hermetic on any
// host regardless of system zoneinfo.
package tariff

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Export type enum (Tariff.Export.Type).
const (
	ExportNetMetering = "net_metering" // credited at the moment's period energy rate
	ExportBuyback     = "buyback"      // credited at a flat rate_usd_per_kwh
	ExportNone        = "none"         // export earns nothing
)

// Provenance confidence enum (Tariff.Provenance.Confidence).
const (
	ConfidenceFiled     = "filed"
	ConfidencePublished = "published"
	ConfidenceEstimated = "estimated"
)

// dateLayout is the effective-range date format ("2025-06-01").
const dateLayout = "2006-01-02"

// Tariff is one retail electricity plan (one data/tariffs/*.json file). Fields
// mirror CONTRACTS.md §1 exactly; JSON tags are the wire/UI shape.
type Tariff struct {
	ID              string         `json:"id"`
	Name            string         `json:"name"`
	ShortName       string         `json:"short_name"`
	Utility         string         `json:"utility"`
	Territory       string         `json:"territory"`
	Timezone        string         `json:"timezone"` // IANA; ALL window math happens in this TZ
	Currency        string         `json:"currency"`
	Effective       Effective      `json:"effective"`
	Provenance      Provenance     `json:"provenance"`
	FixedMonthlyUSD float64        `json:"fixed_monthly_usd"`
	Energy          Energy         `json:"energy"`
	RidersUSDPerKWh float64        `json:"riders_usd_per_kwh"` // per-kWh adder applied on ALL import
	Demand          []DemandCharge `json:"demand,omitempty"`
	Export          Export         `json:"export"`

	// loc caches the resolved timezone; populated by Validate and lazily by
	// location(). effFrom/effTo cache the parsed effective range.
	loc     *time.Location
	effFrom time.Time
	effTo   time.Time
}

// Effective is the date range the tariff was in force (inclusive).
type Effective struct {
	From string `json:"from"`
	To   string `json:"to"`
}

// Provenance records where the numbers came from and how much to trust them.
type Provenance struct {
	SourceURL  string `json:"source_url"`
	Retrieved  string `json:"retrieved"`
	Confidence string `json:"confidence"` // filed | published | estimated
	Notes      string `json:"notes"`
}

// Energy holds the TOU structure (seasons → day_types → periods) and optional
// monthly-kWh usage tiers whose adders stack onto the period rates.
type Energy struct {
	Seasons []Season `json:"seasons"`
	Tiers   []Tier   `json:"tiers,omitempty"`
}

// Season partitions the year by month; within it, day_types partition the week.
type Season struct {
	ID       string    `json:"id"`
	Months   []int     `json:"months"` // 1..12
	DayTypes []DayType `json:"day_types"`
}

// DayType maps a set of weekdays (individual "mon".."sun", or "weekday" /
// "weekend" groups) to the periods that cover its 24 hours.
type DayType struct {
	Days    []string `json:"days"`
	Periods []Period `json:"periods"`
}

// Period is a contiguous within-day rate window [start, end) in the tariff's
// TZ. It may wrap midnight (e.g. 21:00–06:00). end "24:00" means end-of-day.
type Period struct {
	ID            string  `json:"id"`
	Label         string  `json:"label"`
	Start         string  `json:"start"` // "HH:MM"
	End           string  `json:"end"`   // "HH:MM" ("24:00" = midnight)
	RateUSDPerKWh float64 `json:"rate_usd_per_kwh"`
}

// Tier is a monthly-kWh usage block whose adder stacks onto the period rate for
// every kWh that falls within it. UpToKWh nil = unbounded (the top tier).
type Tier struct {
	UpToKWh        *float64 `json:"up_to_kwh"`
	AdderUSDPerKWh float64  `json:"adder_usd_per_kwh"`
}

// DemandCharge is a $/kW charge on the max 15-min import demand observed within
// its month/day/time window over the billing month.
type DemandCharge struct {
	Label    string   `json:"label"`
	USDPerKW float64  `json:"usd_per_kw"`
	Months   []int    `json:"months"`
	Days     []string `json:"days"`
	Start    string   `json:"start"`
	End      string   `json:"end"`
}

// Export monthly-cap enum (Tariff.Export.MonthlyCap). Real net-metering
// programs (LADWP NEM, MA Class I) bank excess credits toward future months
// rather than paying cash at retail, so a month's credit cannot push the bill
// below its fixed charges.
const (
	// CapEnergyCharges caps the month's export credit at the month's
	// volumetric import charges (energy + tier adders + riders); the excess
	// is reported as Bill.CreditCarryoverUSD. Default for net_metering.
	CapEnergyCharges = "energy_charges"
	// CapNone applies the full credit even if the bill goes negative.
	// Default for buyback (cash-out plans).
	CapNone = "none"
)

// Export configures how exported (negative-grid) energy is credited.
type Export struct {
	Type          string  `json:"type"` // net_metering | buyback | none
	RateUSDPerKWh float64 `json:"rate_usd_per_kwh"`
	// MonthlyCap: "energy_charges" | "none". Empty selects the type's
	// default: net_metering → energy_charges, buyback → none.
	MonthlyCap string `json:"monthly_cap,omitempty"`
}

// monthlyCap resolves the effective cap mode, applying per-type defaults.
func (e Export) monthlyCap() string {
	if e.MonthlyCap != "" {
		return e.MonthlyCap
	}
	if e.Type == ExportNetMetering {
		return CapEnergyCharges
	}
	return CapNone
}

// RateInfo is the stateless answer to "what does a kWh cost/earn at this
// instant" — no monthly state, so it excludes tier adders (see package doc).
type RateInfo struct {
	PeriodID        string  `json:"period_id"`
	PeriodLabel     string  `json:"period_label"`
	ImportUSDPerKWh float64 `json:"import_usd_per_kwh"` // period rate + riders (no tier adder)
	ExportUSDPerKWh float64 `json:"export_usd_per_kwh"` // per export type (see package doc)
}

// Load reads every *.json in dir, parses and validates each, and returns them
// keyed by Tariff.ID. A malformed or invalid file, or a duplicate id, is an
// error (Load is all-or-nothing).
func Load(dir string) (map[string]*Tariff, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("tariff: read dir %q: %w", dir, err)
	}
	out := make(map[string]*Tariff)
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		path := filepath.Join(dir, e.Name())
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("tariff: read %q: %w", path, err)
		}
		t, err := Parse(data)
		if err != nil {
			return nil, fmt.Errorf("tariff %s: %w", e.Name(), err)
		}
		if _, dup := out[t.ID]; dup {
			return nil, fmt.Errorf("tariff: duplicate id %q (%s)", t.ID, e.Name())
		}
		out[t.ID] = t
	}
	return out, nil
}

// Parse decodes one tariff JSON document and validates it. A returned *Tariff
// is always valid (its timezone and effective range are resolved and cached).
func Parse(data []byte) (*Tariff, error) {
	var t Tariff
	if err := json.Unmarshal(data, &t); err != nil {
		return nil, fmt.Errorf("parse: %w", err)
	}
	if err := t.Validate(); err != nil {
		return nil, err
	}
	return &t, nil
}

// location returns the tariff's cached *time.Location, resolving it lazily.
// After Validate (which every Load/Parse runs) the cache is always populated;
// the lazy path only matters for a hand-constructed Tariff, and falls back to
// UTC if the zone name is unresolvable rather than panicking.
func (t *Tariff) location() *time.Location {
	if t.loc != nil {
		return t.loc
	}
	loc, err := time.LoadLocation(t.Timezone)
	if err != nil {
		return time.UTC
	}
	t.loc = loc
	return loc
}

// weekdayTokens maps the schema's weekday names to time.Weekday.
var weekdayTokens = map[string]time.Weekday{
	"sun": time.Sunday, "mon": time.Monday, "tue": time.Tuesday, "wed": time.Wednesday,
	"thu": time.Thursday, "fri": time.Friday, "sat": time.Saturday,
}

// expandDays turns a day_type/demand "days" list into the concrete weekdays it
// covers. "weekday" = Mon–Fri, "weekend" = Sat–Sun, otherwise a single named
// day. Duplicates are preserved so callers can detect over-coverage.
func expandDays(days []string) ([]time.Weekday, error) {
	var out []time.Weekday
	for _, d := range days {
		switch strings.ToLower(strings.TrimSpace(d)) {
		case "weekday":
			out = append(out, time.Monday, time.Tuesday, time.Wednesday, time.Thursday, time.Friday)
		case "weekend":
			out = append(out, time.Saturday, time.Sunday)
		default:
			wd, ok := weekdayTokens[strings.ToLower(strings.TrimSpace(d))]
			if !ok {
				return nil, fmt.Errorf("unknown day %q", d)
			}
			out = append(out, wd)
		}
	}
	return out, nil
}

// containsWeekday reports whether wd is in the list.
func containsWeekday(list []time.Weekday, wd time.Weekday) bool {
	for _, w := range list {
		if w == wd {
			return true
		}
	}
	return false
}

// containsInt reports whether n is in the list.
func containsInt(list []int, n int) bool {
	for _, v := range list {
		if v == n {
			return true
		}
	}
	return false
}

// parseHM parses "HH:MM" into minutes-of-day [0,1440]. "24:00" (=1440) is the
// end-of-day sentinel a period's End may use; any other hour is 0..23. It is
// strict: exactly two colon-separated integer fields, in range.
func parseHM(s string) (int, error) {
	parts := strings.Split(strings.TrimSpace(s), ":")
	if len(parts) != 2 {
		return 0, fmt.Errorf("bad time %q (want HH:MM)", s)
	}
	h, err := strconv.Atoi(parts[0])
	if err != nil {
		return 0, fmt.Errorf("bad time %q: %w", s, err)
	}
	m, err := strconv.Atoi(parts[1])
	if err != nil {
		return 0, fmt.Errorf("bad time %q: %w", s, err)
	}
	if h < 0 || h > 24 || m < 0 || m > 59 || (h == 24 && m != 0) {
		return 0, fmt.Errorf("time out of range %q", s)
	}
	return h*60 + m, nil
}

// mustHM is the hot-path variant used after validation, where the strings are
// known-good; on the impossible parse failure it returns 0.
func mustHM(s string) int {
	m, _ := parseHM(s)
	return m
}

// minuteInWindow reports whether minute (0..1439) falls in [start,end),
// handling a midnight-wrapping window (start >= end). A zero-length window
// (start == end) covers nothing.
func minuteInWindow(minute, start, end int) bool {
	if start == end {
		return false
	}
	if start < end {
		return minute >= start && minute < end
	}
	return minute >= start || minute < end
}
