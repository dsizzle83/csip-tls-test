package scenariodata

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"time"
)

const (
	// hourLayout matches weather.json's local-time hour strings, e.g.
	// "2025-07-01T00:00" — no seconds, no zone offset (the zone is given
	// separately by Weather.Timezone / Location.Timezone).
	hourLayout = "2006-01-02T15:04"
	// dateLayout matches scenario.json's period.start / period.end.
	dateLayout = "2006-01-02"
)

// rawWeatherFile is the on-disk shape of weather.json, decoded with pointer
// elements so an explicit JSON null is distinguishable from 0.0 — plain
// float64 targets silently keep their zero value on a JSON null, which
// would hide exactly the "API gap" case the contract says must be a load
// error ("Missing hours (API gaps) are a load error, not silently filled").
type rawWeatherFile struct {
	Timezone string     `json:"timezone"`
	Hours    []string   `json:"hours"`
	GHIWm2   []*float64 `json:"ghi_wm2"`
	TempC    []*float64 `json:"temp_c"`
}

// Load reads every data/scenarios/<id>/ pair under dir, validates each per
// docs/dashboard-v2/CONTRACTS.md §2, and returns them keyed by scenario id.
// Non-directory entries (and dirs starting with '.') are skipped. Any
// scenario failing to load or validate fails the whole call — a partially
// loaded dataset is worse than a loud error (same "no silent fill" spirit
// as the weather-gap rule above).
func Load(dir string) (map[string]*Scenario, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("scenariodata: read %s: %w", dir, err)
	}

	out := make(map[string]*Scenario)
	for _, e := range entries {
		name := e.Name()
		if !e.IsDir() || len(name) > 0 && name[0] == '.' {
			continue
		}
		sub := filepath.Join(dir, name)
		sc, err := loadOne(sub, name)
		if err != nil {
			return nil, fmt.Errorf("scenariodata: %s: %w", name, err)
		}
		out[sc.Meta.ID] = sc
	}
	return out, nil
}

func loadOne(dir, dirName string) (*Scenario, error) {
	meta, err := loadMeta(filepath.Join(dir, "scenario.json"))
	if err != nil {
		return nil, err
	}
	if meta.ID != dirName {
		return nil, fmt.Errorf("scenario.json id %q does not match directory name %q", meta.ID, dirName)
	}

	weather, err := loadWeather(filepath.Join(dir, "weather.json"))
	if err != nil {
		return nil, err
	}

	if err := validate(meta, weather); err != nil {
		return nil, err
	}

	return &Scenario{Meta: *meta, Weather: *weather}, nil
}

func loadMeta(path string) (*Meta, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read scenario.json: %w", err)
	}
	var m Meta
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, fmt.Errorf("parse scenario.json: %w", err)
	}
	if m.ID == "" {
		return nil, fmt.Errorf("scenario.json: id is empty")
	}
	return &m, nil
}

func loadWeather(path string) (*Weather, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read weather.json: %w", err)
	}
	var raw rawWeatherFile
	if err := json.Unmarshal(b, &raw); err != nil {
		return nil, fmt.Errorf("parse weather.json: %w", err)
	}

	ghi, err := derefNoNull("ghi_wm2", raw.GHIWm2)
	if err != nil {
		return nil, err
	}
	temp, err := derefNoNull("temp_c", raw.TempC)
	if err != nil {
		return nil, err
	}

	return &Weather{
		Timezone: raw.Timezone,
		Hours:    raw.Hours,
		GHIWm2:   ghi,
		TempC:    temp,
	}, nil
}

// derefNoNull dereferences a []*float64 decoded from JSON, failing loudly on
// any null element or non-finite (NaN/Inf) value.
func derefNoNull(field string, vals []*float64) ([]float64, error) {
	out := make([]float64, len(vals))
	for i, v := range vals {
		if v == nil {
			return nil, fmt.Errorf("weather.json: null value in %s at index %d", field, i)
		}
		if math.IsNaN(*v) || math.IsInf(*v, 0) {
			return nil, fmt.Errorf("weather.json: non-finite value in %s at index %d: %v", field, i, *v)
		}
		out[i] = *v
	}
	return out, nil
}

// validate checks the contract's loader rules: equal array lengths,
// contiguous hourly local timestamps covering the period exactly, and that
// declared timezones parse (and agree between scenario.json and
// weather.json). No NaN/null was already enforced while decoding
// weather.json (derefNoNull) so a null trailing hour fails here, not by
// silently truncating or zero-filling.
func validate(m *Meta, w *Weather) error {
	if len(w.Hours) != len(w.GHIWm2) || len(w.Hours) != len(w.TempC) {
		return fmt.Errorf("weather.json: array length mismatch hours=%d ghi_wm2=%d temp_c=%d",
			len(w.Hours), len(w.GHIWm2), len(w.TempC))
	}
	if len(w.Hours) == 0 {
		return fmt.Errorf("weather.json: no hours")
	}

	if _, err := time.LoadLocation(m.Location.Timezone); err != nil {
		return fmt.Errorf("scenario.json: location.timezone %q: %w", m.Location.Timezone, err)
	}
	if _, err := time.LoadLocation(w.Timezone); err != nil {
		return fmt.Errorf("weather.json: timezone %q: %w", w.Timezone, err)
	}
	if w.Timezone != m.Location.Timezone {
		return fmt.Errorf("weather.json timezone %q does not match scenario.json location.timezone %q",
			w.Timezone, m.Location.Timezone)
	}

	start, err := time.Parse(dateLayout, m.Period.Start)
	if err != nil {
		return fmt.Errorf("scenario.json: period.start %q: %w", m.Period.Start, err)
	}
	end, err := time.Parse(dateLayout, m.Period.End)
	if err != nil {
		return fmt.Errorf("scenario.json: period.end %q: %w", m.Period.End, err)
	}
	if end.Before(start) {
		return fmt.Errorf("scenario.json: period.end %q before period.start %q", m.Period.End, m.Period.Start)
	}

	wantFirst := start.Format(dateLayout) + "T00:00"
	wantLast := end.Format(dateLayout) + "T23:00"
	wantHours := (int(end.Sub(start).Hours())/24 + 1) * 24

	if len(w.Hours) != wantHours {
		return fmt.Errorf("weather.json: expected %d hours for period %s..%s, got %d",
			wantHours, m.Period.Start, m.Period.End, len(w.Hours))
	}
	if w.Hours[0] != wantFirst {
		return fmt.Errorf("weather.json: first hour %q != expected %q", w.Hours[0], wantFirst)
	}
	if w.Hours[len(w.Hours)-1] != wantLast {
		return fmt.Errorf("weather.json: last hour %q != expected %q", w.Hours[len(w.Hours)-1], wantLast)
	}

	var prev time.Time
	for i, h := range w.Hours {
		ts, err := time.Parse(hourLayout, h)
		if err != nil {
			return fmt.Errorf("weather.json: unparseable hour %q at index %d: %w", h, i, err)
		}
		if i > 0 && !ts.Equal(prev.Add(time.Hour)) {
			return fmt.Errorf("weather.json: non-contiguous hours at index %d: %q -> %q", i, w.Hours[i-1], h)
		}
		prev = ts
	}

	return nil
}
