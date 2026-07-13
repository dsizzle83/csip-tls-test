// Package whatif is the dashboard V2 "what-if" cost-simulation engine: the
// analytical core that turns a scenario dataset (internal/scenariodata) and a
// retail electricity plan (internal/tariff) into an itemized monthly bill,
// KPIs, daily/intraday series, savings, and an attribution decomposition, for
// three DER-adoption policies (baseline / der_dumb / der_lexa).
//
// It is the authoritative implementation of docs/dashboard-v2/CONTRACTS.md §3.
// It is pure standard library and CONSUMES internal/tariff and
// internal/scenariodata unmodified.
//
// # Simulation
//
// A 15-minute tick simulation runs over the scenario's inclusive calendar
// period in the scenario timezone (July = 31 days = 2,976 ticks). Hourly
// weather (GHI, temperature) is linearly interpolated to the tick. Sign
// convention EVERYWHERE: grid import > 0, export < 0 (bench meter convention).
//
// The model is fully deterministic and closed-form — there is NO pseudo-random
// component, so identical (scenario, instruments, tariff, policies) inputs
// yield byte-identical output by construction. (CONTRACTS.md §3 permits seeding
// a PRNG from the scenario id; v1's load model is a closed-form curve, so no
// PRNG is needed and none is used. Day-to-day load variation comes entirely
// from the observed hourly weather.)
//
// # Environment per tick (policy-independent)
//
// PV AC power (CONTRACTS.md §3):
//
//	cell_temp = temp_c + 0.03*ghi
//	ac_kw     = ghi/1000 * pv_kw * 0.85 * (1 - 0.004*max(0, cell_temp-25))   (clamped ≥ 0)
//
// Home load (documented here because the UI provenance panel quotes it):
//
//	load_kw = base_kw
//	        + occupancy(h)                         // fixed daily shape, NOT random
//	        + ac_kw
//	occupancy(h) = bump(h,6,9,0.5) + bump(h,17,22,1.0)      // kW
//	bump(h,a,b,amp) = amp*0.5*(1-cos(2π*(h-a)/(b-a)))  for a≤h<b, else 0   // raised cosine
//	ac_kw = clamp( max(0, temp_f - cool_setpoint_f) * kw_per_degf , 0, hvac.max_kw )
//	temp_f = temp_c*9/5 + 32
//
// The occupancy term is two smooth raised-cosine bumps — a modest morning
// (06:00–09:00, +0.5 kW peak) and a larger evening (17:00–22:00, +1.0 kW peak)
// ramp — identical every day (no per-tick randomness, no chatter). The AC term
// models the compressor's smooth time-averaged duty as a draw proportional to
// how far the outdoor temperature overshoots the cooling setpoint, clamped to
// the HVAC nameplate — again continuous, with no on/off chatter. All day-to-day
// load variation therefore traces to the observed ERA5 hourly temperature.
//
// EV (when present): departs depart_hour on weekdays, returns return_hour the
// same day having consumed weekday_kwh, which must be recharged before the next
// weekday departure. Weekends: home all day, no trip, no energy consumed (v1
// simplification). The recharge ENERGY (weekday_kwh per weekday trip) is
// identical across policies; only the recharge TIMING differs by policy.
//
// # Policies
//
//   - baseline: home load only — no PV, no battery. EV (if present) charges on
//     arrival at full charger_kw until the trip's weekday_kwh is replenished.
//   - der_dumb: PV + battery greedy self-consumption. Battery charges from PV
//     excess (≤ kw, ≤ 100% SOC) and discharges to cover net load (≥ reserve).
//     EV charges on arrival at full rate. No tariff awareness.
//   - der_lexa: tariff-aware, deterministic, explainable dispatch — see
//     dispatchLexa in engine.go for the full algorithm (day peak/valley
//     identification, PV self-consumption, valley→peak arbitrage that must
//     clear round-trip losses, deadline-safe cheapest-window EV charging, and
//     demand-charge peak shaving with a ratcheting import ceiling).
//
// Battery efficiency is symmetric: sqrt(round_trip_eff) is applied on charge
// and again on discharge, so a full round trip returns round_trip_eff.
//
// # Attribution
//
// Savings vs. baseline are decomposed by sequential ablation. Four dispatches
// are run internally per tariff: A=baseline, B=+PV only, C=+PV+battery(dumb),
// D=full lexa. Each bill is split into (nonDemandExport, demand, export)
// portions; the nonDemandExport portion is ablated into solar_self_use (A→B),
// battery_arbitrage (B→C) and ev_shift (C→policy), while demand_usd and
// export_usd are the demand- and export-line deltas vs. baseline. The five
// components sum EXACTLY to total savings (they are a decomposition of the same
// cent-rounded bill line items); the split of the nonDemandExport portion into
// the three levers is an APPROXIMATE decomposition (path-ordered ablation).
package whatif

import (
	"fmt"
	"sort"
	"time"

	"csip-tls-test/internal/scenariodata"
	"csip-tls-test/internal/tariff"
)

// Policy identifiers (the `policy` enum, CONTRACTS.md §3).
const (
	PolicyBaseline = "baseline"
	PolicyDerDumb  = "der_dumb"
	PolicyDerLexa  = "der_lexa"
)

// AllPolicies is the default policy set when a request omits `policies`.
var AllPolicies = []string{PolicyBaseline, PolicyDerDumb, PolicyDerLexa}

// dateLayout matches scenario period and daily-series dates ("2025-07-01").
const dateLayout = "2006-01-02"

// Instruments is the tunable instrument set (PV / battery / EV). It is the same
// shape as scenariodata.InstrumentDefaults (CONTRACTS.md §3 request
// `instruments`), so a partial override merged onto the scenario defaults
// decodes straight into it.
type Instruments = scenariodata.InstrumentDefaults

// Response is the POST /api/whatif/run 200 body (CONTRACTS.md §3).
type Response struct {
	Scenario   scenariodata.Meta `json:"scenario"`
	Runs       []RunResult       `json:"runs"`
	Savings    []Savings         `json:"savings"`
	Provenance Provenance        `json:"provenance"`
}

// RunResult is one (tariff, policy) simulation result (a `runs[]` element).
type RunResult struct {
	TariffID  string      `json:"tariff_id"`
	Policy    string      `json:"policy"`
	Bill      tariff.Bill `json:"bill"`
	KPIs      KPIs        `json:"kpis"`
	Daily     Daily       `json:"daily"`
	DayDetail DayDetail   `json:"day_detail"`
}

// KPIs are the headline numbers for a run.
type KPIs struct {
	ImportKWh          float64 `json:"import_kwh"`
	ExportKWh          float64 `json:"export_kwh"`
	PeakImportKW       float64 `json:"peak_import_kw"`
	SelfConsumptionPct float64 `json:"self_consumption_pct"`
	AvgSOCPct          float64 `json:"avg_soc_pct"`
}

// Daily is the per-day series (one entry per calendar day in the period).
// cost_usd is the day's ENERGY + export cost (import kWh × import rate − export
// credit); monthly constructs (fixed charge, tier adders, demand charges) are
// month-scoped and are NOT distributed into the daily series.
type Daily struct {
	Dates     []string  `json:"dates"`
	CostUSD   []float64 `json:"cost_usd"`
	ImportKWh []float64 `json:"import_kwh"`
	ExportKWh []float64 `json:"export_kwh"`
	PVKWh     []float64 `json:"pv_kwh"`
	LoadKWh   []float64 `json:"load_kwh"` // home load only (EV excluded; see day_detail.ev_kw)
}

// DayDetail is one day's 96-tick intraday trace (the engine picks the costliest
// baseline-policy day; all policies for a tariff report that same date).
type DayDetail struct {
	Date          string    `json:"date"`
	Ticks         int       `json:"ticks"`
	LoadKW        []float64 `json:"load_kw"`
	PVKW          []float64 `json:"pv_kw"`
	BattKW        []float64 `json:"batt_kw"` // + = discharge (to bus), − = charge
	EVKW          []float64 `json:"ev_kw"`
	GridKW        []float64 `json:"grid_kw"` // + = import, − = export
	SOCPct        []float64 `json:"soc_pct"`
	RateUSDPerKWh []float64 `json:"rate_usd_per_kwh"`
}

// Savings is a policy's saving vs. baseline for one tariff, with attribution.
type Savings struct {
	TariffID    string      `json:"tariff_id"`
	Vs          string      `json:"vs"`
	Policy      string      `json:"policy"`
	USD         float64     `json:"usd"`
	Pct         float64     `json:"pct"`
	Attribution Attribution `json:"attribution"`
}

// Attribution decomposes a policy's savings (all five sum to Savings.USD).
type Attribution struct {
	SolarSelfUseUSD     float64 `json:"solar_self_use_usd"`
	BatteryArbitrageUSD float64 `json:"battery_arbitrage_usd"`
	EVShiftUSD          float64 `json:"ev_shift_usd"`
	DemandUSD           float64 `json:"demand_usd"`
	ExportUSD           float64 `json:"export_usd"`
}

// Provenance surfaces the "where every number came from" blocks to the UI.
type Provenance struct {
	Weather   string             `json:"weather"`
	LoadModel string             `json:"load_model"`
	Tariffs   []TariffProvenance `json:"tariffs"`
	Engine    string             `json:"engine"`
}

// TariffProvenance is one tariff's provenance block, tagged with its identity.
type TariffProvenance struct {
	TariffID string `json:"tariff_id"`
	Name     string `json:"name"`
	tariff.Provenance
}

// CrossValError is a scenario/tariff mismatch that the API maps to HTTP 422
// (territory / timezone / effective-range / season-coverage mismatch).
type CrossValError struct {
	TariffID string
	Reason   string
}

func (e *CrossValError) Error() string {
	return fmt.Sprintf("cross-validation: tariff %q: %s", e.TariffID, e.Reason)
}

// InputError is a bad-instruments / bad-parameter error the API maps to HTTP 400.
type InputError struct{ Reason string }

func (e *InputError) Error() string { return "invalid input: " + e.Reason }

// Run executes the what-if engine for a scenario against one or more tariffs,
// under the given (already-resolved) instruments and policy set. It returns a
// *CrossValError for a scenario/tariff mismatch (→ 422), an *InputError for bad
// instruments/policies (→ 400), or the full Response.
//
// Every requested policy appears in Response.Runs; every requested DER policy
// (der_dumb / der_lexa) gets a Savings entry vs. baseline. All four ablation
// dispatches run internally regardless of the requested policy set (they are
// cheap and baseline is always needed for savings, attribution, and the
// day-detail day pick).
func Run(sc *scenariodata.Scenario, tariffs []*tariff.Tariff, inst Instruments, policies []string) (*Response, error) {
	if sc == nil {
		return nil, &InputError{Reason: "nil scenario"}
	}
	if len(tariffs) == 0 {
		return nil, &InputError{Reason: "no tariffs"}
	}
	if err := validateInstruments(inst); err != nil {
		return nil, err
	}
	wantPolicy, err := normalizePolicies(policies)
	if err != nil {
		return nil, err
	}
	for _, t := range tariffs {
		if err := crossValidate(sc, t); err != nil {
			return nil, err
		}
	}

	loc, err := time.LoadLocation(sc.Meta.Location.Timezone)
	if err != nil {
		return nil, &InputError{Reason: "scenario timezone: " + err.Error()}
	}
	env, err := buildEnv(sc, inst, loc)
	if err != nil {
		return nil, err
	}

	resp := &Response{
		Scenario:   sc.Meta,
		Provenance: buildProvenance(sc, tariffs),
	}

	for _, t := range tariffs {
		// Four ablation dispatches (A/B/C/D) per tariff.
		simA := simulate(env, t, cfgBaseline)
		simB := simulate(env, t, cfgPVOnly)
		simC := simulate(env, t, cfgDumb)
		simD := simulate(env, t, cfgLexa)

		billA := billFor(simA, env, t)
		billB := billFor(simB, env, t)
		billC := billFor(simC, env, t)
		billD := billFor(simD, env, t)

		// day_detail date: costliest baseline day (by daily energy cost).
		detailDay := costliestDay(simA, env)

		byPolicy := map[string]struct {
			sim  simResult
			bill tariff.Bill
		}{
			PolicyBaseline: {simA, billA},
			PolicyDerDumb:  {simC, billC},
			PolicyDerLexa:  {simD, billD},
		}
		for _, p := range AllPolicies { // deterministic order over the requested subset
			if !wantPolicy[p] {
				continue
			}
			pr := byPolicy[p]
			resp.Runs = append(resp.Runs, RunResult{
				TariffID:  t.ID,
				Policy:    p,
				Bill:      pr.bill,
				KPIs:      kpisFor(pr.sim, env),
				Daily:     dailyFor(pr.sim, env),
				DayDetail: dayDetailFor(pr.sim, env, detailDay),
			})
		}

		// Savings + attribution for each requested DER policy.
		sA := splitBill(billA)
		sB := splitBill(billB)
		sC := splitBill(billC)
		sD := splitBill(billD)
		if wantPolicy[PolicyDerDumb] {
			resp.Savings = append(resp.Savings, savingsEntry(t.ID, PolicyDerDumb, billA, billC, sA, sB, sC, sC))
		}
		if wantPolicy[PolicyDerLexa] {
			resp.Savings = append(resp.Savings, savingsEntry(t.ID, PolicyDerLexa, billA, billD, sA, sB, sC, sD))
		}
	}

	return resp, nil
}

// policySet is a set of requested policies.
type policySet = map[string]bool

// normalizePolicies validates the requested policy list (defaulting to all
// three) and returns it as a set.
func normalizePolicies(policies []string) (policySet, error) {
	if len(policies) == 0 {
		policies = AllPolicies
	}
	out := make(policySet, 3)
	for _, p := range policies {
		switch p {
		case PolicyBaseline, PolicyDerDumb, PolicyDerLexa:
			out[p] = true
		default:
			return nil, &InputError{Reason: fmt.Sprintf("unknown policy %q", p)}
		}
	}
	return out, nil
}

// validateInstruments rejects nonsensical instrument values (→ 400).
func validateInstruments(inst Instruments) error {
	if inst.PVKW < 0 {
		return &InputError{Reason: "pv_kw < 0"}
	}
	b := inst.Battery
	if b.KWh < 0 || b.KW < 0 {
		return &InputError{Reason: "battery kwh/kw < 0"}
	}
	if b.ReservePct < 0 || b.ReservePct > 100 {
		return &InputError{Reason: "battery reserve_pct out of [0,100]"}
	}
	if b.RoundTripEff < 0 || b.RoundTripEff > 1 {
		return &InputError{Reason: "battery round_trip_eff out of [0,1]"}
	}
	e := inst.EV
	if e.Present {
		if e.ChargerKW <= 0 {
			return &InputError{Reason: "ev charger_kw must be > 0 when ev present"}
		}
		if e.WeekdayKWh < 0 {
			return &InputError{Reason: "ev weekday_kwh < 0"}
		}
		if e.DepartHour < 0 || e.DepartHour > 23 || e.ReturnHour < 0 || e.ReturnHour > 23 {
			return &InputError{Reason: "ev depart_hour/return_hour out of [0,23]"}
		}
	}
	return nil
}

// crossValidate enforces the CONTRACTS.md §3 422 conditions between a scenario
// and a tariff: matching territory, matching timezone, the scenario period
// inside the tariff's effective range, and the tariff's seasons covering every
// month the scenario touches.
func crossValidate(sc *scenariodata.Scenario, t *tariff.Tariff) error {
	if t.Territory != sc.Meta.Location.Territory {
		return &CrossValError{TariffID: t.ID, Reason: fmt.Sprintf(
			"territory %q != scenario territory %q", t.Territory, sc.Meta.Location.Territory)}
	}
	if t.Timezone != sc.Meta.Location.Timezone {
		return &CrossValError{TariffID: t.ID, Reason: fmt.Sprintf(
			"timezone %q != scenario timezone %q", t.Timezone, sc.Meta.Location.Timezone)}
	}
	start, err := time.Parse(dateLayout, sc.Meta.Period.Start)
	if err != nil {
		return &InputError{Reason: "scenario period.start: " + err.Error()}
	}
	end, err := time.Parse(dateLayout, sc.Meta.Period.End)
	if err != nil {
		return &InputError{Reason: "scenario period.end: " + err.Error()}
	}
	effFrom, err := time.Parse(dateLayout, t.Effective.From)
	if err != nil {
		return &CrossValError{TariffID: t.ID, Reason: "effective.from: " + err.Error()}
	}
	effTo, err := time.Parse(dateLayout, t.Effective.To)
	if err != nil {
		return &CrossValError{TariffID: t.ID, Reason: "effective.to: " + err.Error()}
	}
	if start.Before(effFrom) || end.After(effTo) {
		return &CrossValError{TariffID: t.ID, Reason: fmt.Sprintf(
			"scenario period %s..%s outside tariff effective range %s..%s",
			sc.Meta.Period.Start, sc.Meta.Period.End, t.Effective.From, t.Effective.To)}
	}
	// Every month the scenario touches must be covered by a season.
	for m := start; !m.After(end); m = m.AddDate(0, 0, 1) {
		if !monthCovered(t, int(m.Month())) {
			return &CrossValError{TariffID: t.ID, Reason: fmt.Sprintf(
				"no season covers month %d that the scenario touches", int(m.Month()))}
		}
	}
	return nil
}

func monthCovered(t *tariff.Tariff, month int) bool {
	for _, s := range t.Energy.Seasons {
		for _, mm := range s.Months {
			if mm == month {
				return true
			}
		}
	}
	return false
}

// buildProvenance assembles the provenance block from the scenario and tariffs.
func buildProvenance(sc *scenariodata.Scenario, tariffs []*tariff.Tariff) Provenance {
	tp := make([]TariffProvenance, 0, len(tariffs))
	for _, t := range tariffs {
		tp = append(tp, TariffProvenance{
			TariffID:   t.ID,
			Name:       t.Name,
			Provenance: t.Provenance,
		})
	}
	return Provenance{
		Weather: fmt.Sprintf("%s hourly (GHI + 2 m temperature), retrieved %s — %s",
			sc.Meta.Weather.Source, sc.Meta.Weather.Retrieved, sc.Meta.Weather.SourceURL),
		LoadModel: "Modeled residential load: base_kw + fixed occupancy schedule " +
			"(raised-cosine morning 06–09 and evening 17–22 bumps) + AC response " +
			"max(0, temp_f − cool_setpoint_f) × kw_per_degf clamped to hvac.max_kw, " +
			"fitted to observed hourly temperatures. Deterministic per scenario.",
		Tariffs: tp,
		Engine:  "whatif v1 — 15-min deterministic simulation",
	}
}

// billSplit holds a bill decomposed into demand / export / everything-else.
type billSplit struct {
	nonDE  float64 // fixed + energy + tier + riders
	demand float64
	export float64 // export_credit line total (negative)
}

func splitBill(b tariff.Bill) billSplit {
	var demand, export float64
	for _, li := range b.LineItems {
		switch li.Kind {
		case tariff.KindDemand:
			demand += li.AmountUSD
		case tariff.KindExportCredit:
			export += li.AmountUSD
		}
	}
	return billSplit{nonDE: b.TotalUSD - demand - export, demand: demand, export: export}
}

// savingsEntry builds one Savings row. baseBill/polBill give the headline
// saving; the four splits (A,B,C,policy) give the ablation attribution. For
// der_dumb, splitPolicy == splitC so ev_shift is zero.
func savingsEntry(tariffID, policy string, baseBill, polBill tariff.Bill, sA, sB, sC, sPol billSplit) Savings {
	usd := round2(baseBill.TotalUSD - polBill.TotalUSD)
	var pct float64
	if baseBill.TotalUSD != 0 {
		pct = usd / baseBill.TotalUSD * 100
	}
	return Savings{
		TariffID: tariffID,
		Vs:       PolicyBaseline,
		Policy:   policy,
		USD:      usd,
		Pct:      round2(pct),
		Attribution: Attribution{
			SolarSelfUseUSD:     sA.nonDE - sB.nonDE,
			BatteryArbitrageUSD: sB.nonDE - sC.nonDE,
			EVShiftUSD:          sC.nonDE - sPol.nonDE,
			DemandUSD:           sA.demand - sPol.demand,
			ExportUSD:           sA.export - sPol.export,
		},
	}
}

// sortTariffsByID gives a stable output ordering independent of map iteration
// (callers pass an already-ordered slice; this is a convenience for the API).
func sortTariffsByID(ts []*tariff.Tariff) {
	sort.Slice(ts, func(i, j int) bool { return ts[i].ID < ts[j].ID })
}
