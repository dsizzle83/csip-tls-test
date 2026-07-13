// Package scenariodata loads the dashboard V2 scenario datasets
// (data/scenarios/<id>/{scenario.json,weather.json}) per the schema in
// docs/dashboard-v2/CONTRACTS.md §2.
//
// Datasets are produced by scripts/fetch-scenario-data.py, which pulls real
// hourly weather from the Open-Meteo ERA5 archive. This package only reads
// and validates what's on disk — it does not fetch anything and does not
// know about tariffs; cross-validating a scenario's tariff_ids against
// data/tariffs is the what-if engine's job (internal/whatif), not this
// package's (see CONTRACTS.md §2).
package scenariodata

// Location is scenario.json's "location" object.
type Location struct {
	City      string  `json:"city"`
	State     string  `json:"state"`
	Lat       float64 `json:"lat"`
	Lon       float64 `json:"lon"`
	Timezone  string  `json:"timezone"` // IANA, e.g. "America/Chicago"
	Territory string  `json:"territory"`
	Blurb     string  `json:"blurb"`
}

// Period is scenario.json's "period" object: inclusive calendar-date range,
// "YYYY-MM-DD", in Location.Timezone.
type Period struct {
	Start string `json:"start"`
	End   string `json:"end"`
}

// WeatherProvenance is scenario.json's "weather" object (provenance only —
// the actual hourly series lives in weather.json / the Weather type).
type WeatherProvenance struct {
	Source    string `json:"source"`
	Retrieved string `json:"retrieved"`
	SourceURL string `json:"source_url"`
}

// HVACDefaults is the "hvac" sub-object of home_defaults.
type HVACDefaults struct {
	CoolSetpointF float64 `json:"cool_setpoint_f"`
	KWPerDegF     float64 `json:"kw_per_degf"`
	MaxKW         float64 `json:"max_kw"`
}

// HomeDefaults is scenario.json's "home_defaults" object.
type HomeDefaults struct {
	Profile string       `json:"profile"`
	BaseKW  float64      `json:"base_kw"`
	HVAC    HVACDefaults `json:"hvac"`
}

// BatteryDefaults is the "battery" sub-object of instrument_defaults.
type BatteryDefaults struct {
	KWh          float64 `json:"kwh"`
	KW           float64 `json:"kw"`
	ReservePct   float64 `json:"reserve_pct"`
	RoundTripEff float64 `json:"round_trip_eff"`
}

// EVDefaults is the "ev" sub-object of instrument_defaults.
type EVDefaults struct {
	Present    bool    `json:"present"`
	BatteryKWh float64 `json:"battery_kwh"`
	ChargerKW  float64 `json:"charger_kw"`
	WeekdayKWh float64 `json:"weekday_kwh"`
	DepartHour int     `json:"depart_hour"`
	ReturnHour int     `json:"return_hour"`
}

// InstrumentDefaults is scenario.json's "instrument_defaults" object.
type InstrumentDefaults struct {
	PVKW    float64         `json:"pv_kw"`
	Battery BatteryDefaults `json:"battery"`
	EV      EVDefaults      `json:"ev"`
}

// Meta mirrors scenario.json in full.
type Meta struct {
	ID                 string             `json:"id"`
	Label              string             `json:"label"`
	Location           Location           `json:"location"`
	Period             Period             `json:"period"`
	Weather            WeatherProvenance  `json:"weather"`
	TariffIDs          []string           `json:"tariff_ids"`
	DefaultTariffID    string             `json:"default_tariff_id"`
	HomeDefaults       HomeDefaults       `json:"home_defaults"`
	InstrumentDefaults InstrumentDefaults `json:"instrument_defaults"`
}

// Weather mirrors weather.json in full: hourly, local-time aligned, full
// period. Hours[i] is the local wall-clock ISO timestamp ("2006-01-02T15:04")
// for GHIWm2[i] / TempC[i].
type Weather struct {
	Timezone string    `json:"timezone"`
	Hours    []string  `json:"hours"`
	GHIWm2   []float64 `json:"ghi_wm2"`
	TempC    []float64 `json:"temp_c"`
}

// Scenario is one validated data/scenarios/<id>/ pair.
type Scenario struct {
	Meta    Meta
	Weather Weather
}
