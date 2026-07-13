package whatif

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"testing"
	"time"

	"csip-tls-test/internal/scenariodata"
	"csip-tls-test/internal/tariff"
)

// ---- synthetic fixtures ---------------------------------------------------

// weatherProfile is a deterministic day/night curve: a midday GHI bell (0 at
// night, 900 W/m² peak at noon) and a warm sinusoidal temperature (28 °C nights,
// ~36 °C afternoons). It gives real AC load and real PV so battery/PV levers
// have something to bite on.
func weatherProfile(hod float64) (ghi, tempC float64) {
	if hod > 6 && hod < 18 {
		ghi = 900 * math.Sin(math.Pi*(hod-6)/12)
	}
	tempC = 28 + 8*math.Sin(math.Pi*(hod-6)/12) // ~28 at 06:00, peak ~36 at noon
	return ghi, tempC
}

// synthScenario builds an in-memory scenario (bypassing the on-disk loader) of
// `days` full days starting at startDate, in the given timezone/territory, with
// the standard instrument defaults.
func synthScenario(t *testing.T, id, tz, territory, startDate string, days int) *scenariodata.Scenario {
	t.Helper()
	loc, err := time.LoadLocation(tz)
	if err != nil {
		t.Fatalf("LoadLocation(%q): %v", tz, err)
	}
	sd, err := time.Parse(dateLayout, startDate)
	if err != nil {
		t.Fatalf("parse start %q: %v", startDate, err)
	}
	start := time.Date(sd.Year(), sd.Month(), sd.Day(), 0, 0, 0, 0, loc)
	endDate := start.AddDate(0, 0, days-1).Format(dateLayout)

	n := days * 24
	hours := make([]string, n)
	ghi := make([]float64, n)
	temp := make([]float64, n)
	for h := 0; h < n; h++ {
		ts := start.Add(time.Duration(h) * time.Hour)
		hours[h] = ts.Format("2006-01-02T15:04")
		g, c := weatherProfile(float64(ts.Hour()))
		ghi[h], temp[h] = g, c
	}

	return &scenariodata.Scenario{
		Meta: scenariodata.Meta{
			ID:    id,
			Label: id,
			Location: scenariodata.Location{
				City: "Test", State: "TX", Timezone: tz, Territory: territory,
			},
			Period:  scenariodata.Period{Start: startDate, End: endDate},
			Weather: scenariodata.WeatherProvenance{Source: "synthetic", Retrieved: "2026-07-13"},
			HomeDefaults: scenariodata.HomeDefaults{
				Profile: "single-family-3br", BaseKW: 0.45,
				HVAC: scenariodata.HVACDefaults{CoolSetpointF: 75, KWPerDegF: 0.16, MaxKW: 4.2},
			},
			InstrumentDefaults: scenariodata.InstrumentDefaults{
				PVKW: 8.0,
				Battery: scenariodata.BatteryDefaults{
					KWh: 13.5, KW: 5.0, ReservePct: 10, RoundTripEff: 0.90,
				},
				EV: scenariodata.EVDefaults{
					Present: true, BatteryKWh: 60, ChargerKW: 7.2,
					WeekdayKWh: 11, DepartHour: 8, ReturnHour: 17,
				},
			},
		},
		Weather: scenariodata.Weather{Timezone: tz, Hours: hours, GHIWm2: ghi, TempC: temp},
	}
}

// synthTOUTariff is a TOU plan where arbitrage clearly pays: free nights
// (20:00–06:00 @ $0), expensive days (06:00–20:00 @ $0.30), buyback export
// $0.04. valley 0 < peak 0.30 × 0.90 = 0.27 ⇒ battery pre-charge clears losses.
func synthTOUTariff(t *testing.T, territory, tz string) *tariff.Tariff {
	t.Helper()
	js := fmt.Sprintf(`{
      "id": "synth-tou", "name": "Synthetic TOU", "short_name": "TOU",
      "utility": "Test", "territory": %q, "timezone": %q, "currency": "USD",
      "effective": { "from": "2025-01-01", "to": "2025-12-31" },
      "provenance": { "source_url": "https://example.test", "retrieved": "2026-07-13",
                      "confidence": "estimated", "notes": "synthetic" },
      "fixed_monthly_usd": 10.0,
      "energy": { "seasons": [ { "id": "all", "months": [1,2,3,4,5,6,7,8,9,10,11,12],
        "day_types": [ { "days": ["mon","tue","wed","thu","fri","sat","sun"], "periods": [
          { "id": "night", "label": "Night", "start": "20:00", "end": "06:00", "rate_usd_per_kwh": 0.0 },
          { "id": "day",   "label": "Day",   "start": "06:00", "end": "20:00", "rate_usd_per_kwh": 0.30 }
        ] } ] } ] },
      "riders_usd_per_kwh": 0.0,
      "export": { "type": "buyback", "rate_usd_per_kwh": 0.04 }
    }`, territory, tz)
	tar, err := tariff.Parse([]byte(js))
	if err != nil {
		t.Fatalf("parse synth TOU tariff: %v", err)
	}
	return tar
}

// synthDemandTariff is a flat plan with an afternoon demand charge, to exercise
// the lexa demand-shaving path.
func synthDemandTariff(t *testing.T, territory, tz string) *tariff.Tariff {
	t.Helper()
	js := fmt.Sprintf(`{
      "id": "synth-demand", "name": "Synthetic Demand", "short_name": "Demand",
      "utility": "Test", "territory": %q, "timezone": %q, "currency": "USD",
      "effective": { "from": "2025-01-01", "to": "2025-12-31" },
      "provenance": { "source_url": "https://example.test", "retrieved": "2026-07-13",
                      "confidence": "estimated", "notes": "synthetic" },
      "fixed_monthly_usd": 0.0,
      "energy": { "seasons": [ { "id": "all", "months": [1,2,3,4,5,6,7,8,9,10,11,12],
        "day_types": [ { "days": ["mon","tue","wed","thu","fri","sat","sun"], "periods": [
          { "id": "flat", "label": "Flat", "start": "00:00", "end": "24:00", "rate_usd_per_kwh": 0.12 }
        ] } ] } ] },
      "riders_usd_per_kwh": 0.0,
      "demand": [ { "label": "Afternoon demand", "usd_per_kw": 15.0, "months": [7],
                   "days": ["weekday"], "start": "14:00", "end": "20:00" } ],
      "export": { "type": "none" }
    }`, territory, tz)
	tar, err := tariff.Parse([]byte(js))
	if err != nil {
		t.Fatalf("parse synth demand tariff: %v", err)
	}
	return tar
}

// ---- energy conservation --------------------------------------------------

func TestEnergyConservation(t *testing.T) {
	sc := synthScenario(t, "cons", "America/Chicago", "synth-tx", "2025-07-07", 4)
	tar := synthTOUTariff(t, "synth-tx", "America/Chicago")
	loc, _ := time.LoadLocation("America/Chicago")
	e, err := buildEnv(sc, sc.Meta.InstrumentDefaults, loc)
	if err != nil {
		t.Fatalf("buildEnv: %v", err)
	}
	for _, cfg := range []struct {
		name string
		c    polConfig
	}{
		{"baseline", cfgBaseline}, {"pvOnly", cfgPVOnly}, {"dumb", cfgDumb}, {"lexa", cfgLexa},
	} {
		sim := simulate(e, tar, cfg.c)
		for i, tr := range sim.ticks {
			lhs := tr.pvKWh + tr.importKWh + tr.battDischarge
			rhs := tr.loadKWh + tr.evKWh + tr.battCharge + tr.exportKWh
			if math.Abs(lhs-rhs) > 1e-9 {
				t.Fatalf("%s tick %d: conservation off by %g (lhs=%g rhs=%g)",
					cfg.name, i, lhs-rhs, lhs, rhs)
			}
			if tr.importKWh < 0 || tr.exportKWh < 0 {
				t.Fatalf("%s tick %d: negative grid import=%g export=%g", cfg.name, i, tr.importKWh, tr.exportKWh)
			}
			if tr.importKWh > 0 && tr.exportKWh > 0 {
				t.Fatalf("%s tick %d: simultaneous import and export", cfg.name, i)
			}
		}
	}
}

// ---- battery bounds & rate limits ----------------------------------------

func TestBatteryBounds(t *testing.T) {
	sc := synthScenario(t, "batt", "America/Chicago", "synth-tx", "2025-07-07", 4)
	tar := synthTOUTariff(t, "synth-tx", "America/Chicago")
	loc, _ := time.LoadLocation("America/Chicago")
	e, _ := buildEnv(sc, sc.Meta.InstrumentDefaults, loc)

	b := sc.Meta.InstrumentDefaults.Battery
	cap := b.KWh
	reserve := b.ReservePct / 100 * cap
	maxTick := b.KW * dtHours

	for _, cfg := range []polConfig{cfgDumb, cfgLexa} {
		sim := simulate(e, tar, cfg)
		for i, tr := range sim.ticks {
			if tr.storedKWh < reserve-1e-9 {
				t.Fatalf("tick %d: SOC %g below reserve %g", i, tr.storedKWh, reserve)
			}
			if tr.storedKWh > cap+1e-9 {
				t.Fatalf("tick %d: SOC %g above capacity %g", i, tr.storedKWh, cap)
			}
			if tr.battCharge > maxTick+1e-9 || tr.battDischarge > maxTick+1e-9 {
				t.Fatalf("tick %d: rate limit exceeded charge=%g discharge=%g max=%g",
					i, tr.battCharge, tr.battDischarge, maxTick)
			}
			if tr.battCharge > 1e-12 && tr.battDischarge > 1e-12 {
				t.Fatalf("tick %d: simultaneous charge and discharge", i)
			}
		}
	}
}

// ---- determinism ----------------------------------------------------------

func TestDeterminism(t *testing.T) {
	sc := synthScenario(t, "det", "America/Chicago", "synth-tx", "2025-07-07", 5)
	tar := synthTOUTariff(t, "synth-tx", "America/Chicago")

	r1, err := Run(sc, []*tariff.Tariff{tar}, sc.Meta.InstrumentDefaults, nil)
	if err != nil {
		t.Fatalf("Run 1: %v", err)
	}
	r2, err := Run(sc, []*tariff.Tariff{tar}, sc.Meta.InstrumentDefaults, nil)
	if err != nil {
		t.Fatalf("Run 2: %v", err)
	}
	b1, _ := json.Marshal(r1)
	b2, _ := json.Marshal(r2)
	if string(b1) != string(b2) {
		t.Fatal("two runs produced different JSON (non-deterministic)")
	}
}

// ---- policy cost ordering -------------------------------------------------

func TestPolicyCostOrdering(t *testing.T) {
	sc := synthScenario(t, "order", "America/Chicago", "synth-tx", "2025-07-07", 5)
	tar := synthTOUTariff(t, "synth-tx", "America/Chicago")

	resp, err := Run(sc, []*tariff.Tariff{tar}, sc.Meta.InstrumentDefaults, nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	cost := map[string]float64{}
	for _, r := range resp.Runs {
		cost[r.Policy] = r.Bill.TotalUSD
	}
	base, dumb, lexa := cost[PolicyBaseline], cost[PolicyDerDumb], cost[PolicyDerLexa]
	t.Logf("baseline=%.2f der_dumb=%.2f der_lexa=%.2f", base, dumb, lexa)
	if !(base >= dumb-1e-9) {
		t.Errorf("baseline (%.2f) should be ≥ der_dumb (%.2f)", base, dumb)
	}
	if !(dumb >= lexa-1e-9) {
		t.Errorf("der_dumb (%.2f) should be ≥ der_lexa (%.2f)", dumb, lexa)
	}
	// Both DER policies must be strictly cheaper than baseline on this tariff.
	if !(base > lexa) {
		t.Errorf("der_lexa (%.2f) should be strictly cheaper than baseline (%.2f)", lexa, base)
	}
}

// ---- EV always full by depart --------------------------------------------

func TestEVAlwaysFullByDepart(t *testing.T) {
	sc := synthScenario(t, "ev", "America/Chicago", "synth-tx", "2025-07-07", 5) // Mon..Fri
	loc, _ := time.LoadLocation("America/Chicago")
	e, _ := buildEnv(sc, sc.Meta.InstrumentDefaults, loc)
	ev := sc.Meta.InstrumentDefaults.EV

	// Count weekday trips in the horizon.
	trips := 0
	for i := range e.ticks {
		if e.ticks[i].weekday && e.ticks[i].t.Hour() == ev.ReturnHour && e.ticks[i].t.Minute() == 0 {
			trips++
		}
	}
	wantTotal := float64(trips) * ev.WeekdayKWh

	importRate := make([]float64, len(e.ticks))
	tar := synthTOUTariff(t, "synth-tx", "America/Chicago")
	for i := range e.ticks {
		importRate[i] = tar.RateAt(e.ticks[i].t).ImportUSDPerKWh
	}

	onArr := evScheduleOnArrival(e)
	smart := evScheduleSmart(e, importRate)

	sum := func(a []float64) float64 {
		s := 0.0
		for _, v := range a {
			s += v
		}
		return s
	}
	if math.Abs(sum(onArr)-wantTotal) > 1e-9 {
		t.Errorf("on-arrival total %g, want %g", sum(onArr), wantTotal)
	}
	if math.Abs(sum(smart)-wantTotal) > 1e-9 {
		t.Errorf("smart total %g, want %g", sum(smart), wantTotal)
	}

	// Per-window (return → next depart) the smart schedule must deliver exactly
	// weekday_kwh, and there must be no EV draw while the car is away
	// (depart→return) — i.e. it is full by departure.
	for i := range e.ticks {
		if !(e.ticks[i].weekday && e.ticks[i].t.Hour() == ev.ReturnHour && e.ticks[i].t.Minute() == 0) {
			continue
		}
		end := len(e.ticks)
		for j := i + 1; j < len(e.ticks); j++ {
			if e.ticks[j].weekday && e.ticks[j].t.Hour() == ev.DepartHour && e.ticks[j].t.Minute() == 0 {
				end = j
				break
			}
		}
		var w float64
		for j := i; j < end; j++ {
			w += smart[j]
		}
		if math.Abs(w-ev.WeekdayKWh) > 1e-9 {
			t.Errorf("smart window [%d,%d) delivered %g, want %g", i, end, w, ev.WeekdayKWh)
		}
	}
	// No charging while away (between depart and return, on weekdays).
	for i := range e.ticks {
		et := e.ticks[i]
		if et.weekday && et.t.Hour() >= ev.DepartHour && et.t.Hour() < ev.ReturnHour {
			if onArr[i] > 1e-12 || smart[i] > 1e-12 {
				t.Errorf("tick %d (%s): EV charging while away", i, et.t.Format(time.Kitchen))
			}
		}
	}
}

// ---- PV / load formula golden (hand-checked constants) --------------------

func TestPVFormulaGolden(t *testing.T) {
	// pvACPower(ghi=800, tempC=30, pv=8):
	//   cell   = 30 + 0.03*800            = 54
	//   derate = 1 - 0.004*(54-25)        = 1 - 0.116 = 0.884
	//   ac     = 0.8*8*0.85*0.884         = 4.80896
	if got := pvACPower(800, 30, 8); math.Abs(got-4.80896) > 1e-6 {
		t.Errorf("pvACPower(800,30,8) = %g, want 4.80896", got)
	}
	// pvACPower(ghi=1000, tempC=35, pv=10):
	//   cell=65, derate=1-0.004*40=0.84, ac=1*10*0.85*0.84 = 7.14
	if got := pvACPower(1000, 35, 10); math.Abs(got-7.14) > 1e-6 {
		t.Errorf("pvACPower(1000,35,10) = %g, want 7.14", got)
	}
	if got := pvACPower(0, 30, 8); got != 0 {
		t.Errorf("pvACPower(0,...) = %g, want 0", got)
	}

	// occupancy peaks: morning center 07:30 → 0.5 kW; evening center 19:30 → 1.0 kW.
	if got := occupancyKW(7.5); math.Abs(got-0.5) > 1e-9 {
		t.Errorf("occupancyKW(7.5) = %g, want 0.5", got)
	}
	if got := occupancyKW(19.5); math.Abs(got-1.0) > 1e-9 {
		t.Errorf("occupancyKW(19.5) = %g, want 1.0", got)
	}
	if got := occupancyKW(3.0); got != 0 {
		t.Errorf("occupancyKW(3.0) = %g, want 0", got)
	}

	hvac := scenariodata.HVACDefaults{CoolSetpointF: 75, KWPerDegF: 0.16, MaxKW: 4.2}
	// (95-75)*0.16 = 3.2 (below cap)
	if got := acKW(95, hvac); math.Abs(got-3.2) > 1e-9 {
		t.Errorf("acKW(95) = %g, want 3.2", got)
	}
	// (110-75)*0.16 = 5.6 → clamp to 4.2
	if got := acKW(110, hvac); math.Abs(got-4.2) > 1e-9 {
		t.Errorf("acKW(110) = %g, want 4.2 (clamped)", got)
	}
	// below setpoint → 0
	if got := acKW(70, hvac); got != 0 {
		t.Errorf("acKW(70) = %g, want 0", got)
	}
}

// ---- golden mini-run: 2 synthetic days, synthetic tariff ------------------

func TestGoldenMiniRun(t *testing.T) {
	// 2025-07-07 is a Monday; 2 days = Mon+Tue, both weekdays with EV trips.
	sc := synthScenario(t, "mini", "America/Chicago", "synth-tx", "2025-07-07", 2)
	tar := synthTOUTariff(t, "synth-tx", "America/Chicago")
	inst := sc.Meta.InstrumentDefaults

	loc, _ := time.LoadLocation("America/Chicago")
	e, _ := buildEnv(sc, inst, loc)
	if len(e.ticks) != 2*ticksPerDay {
		t.Fatalf("expected %d ticks, got %d", 2*ticksPerDay, len(e.ticks))
	}

	resp, err := Run(sc, []*tariff.Tariff{tar}, inst, nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	// Hand-check: BASELINE daily import energy == that day's (home load + EV)
	// energy, because baseline has no PV and no battery (grid supplies all).
	simBase := simulate(e, tar, cfgBaseline)
	evBase := evScheduleOnArrival(e)
	for d := 0; d < 2; d++ {
		var wantImport float64
		for i := d * ticksPerDay; i < (d+1)*ticksPerDay; i++ {
			wantImport += e.ticks[i].loadKWh + evBase[i]
		}
		var gotImport float64
		for i := d * ticksPerDay; i < (d+1)*ticksPerDay; i++ {
			gotImport += simBase.ticks[i].importKWh
		}
		if math.Abs(gotImport-wantImport) > 1e-9 {
			t.Errorf("day %d baseline import %g, want (load+ev) %g", d, gotImport, wantImport)
		}
	}

	// Ordering on the mini-run.
	cost := map[string]float64{}
	for _, r := range resp.Runs {
		cost[r.Policy] = r.Bill.TotalUSD
	}
	if !(cost[PolicyBaseline] >= cost[PolicyDerDumb]-1e-9 && cost[PolicyDerDumb] >= cost[PolicyDerLexa]-1e-9) {
		t.Errorf("mini-run ordering violated: base=%.2f dumb=%.2f lexa=%.2f",
			cost[PolicyBaseline], cost[PolicyDerDumb], cost[PolicyDerLexa])
	}

	// No negative bills, no absurd savings.
	for _, r := range resp.Runs {
		if r.Bill.TotalUSD < 0 {
			t.Errorf("policy %s: negative bill %.2f", r.Policy, r.Bill.TotalUSD)
		}
	}
}

// ---- attribution sums to total savings ------------------------------------

func TestAttributionSums(t *testing.T) {
	sc := synthScenario(t, "attr", "America/Chicago", "synth-tx", "2025-07-07", 5)
	tar := synthTOUTariff(t, "synth-tx", "America/Chicago")
	resp, err := Run(sc, []*tariff.Tariff{tar}, sc.Meta.InstrumentDefaults, nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(resp.Savings) != 2 {
		t.Fatalf("expected 2 savings entries (dumb, lexa), got %d", len(resp.Savings))
	}
	for _, s := range resp.Savings {
		a := s.Attribution
		sum := a.SolarSelfUseUSD + a.BatteryArbitrageUSD + a.EVShiftUSD + a.DemandUSD + a.ExportUSD
		if math.Abs(sum-s.USD) > 1e-6 {
			t.Errorf("policy %s: attribution sum %.6f != savings %.6f", s.Policy, sum, s.USD)
		}
	}
}

// ---- demand-charge shaving ------------------------------------------------

func TestDemandShaving(t *testing.T) {
	sc := synthScenario(t, "dem", "America/Chicago", "synth-tx", "2025-07-07", 5)
	tar := synthDemandTariff(t, "synth-tx", "America/Chicago")
	resp, err := Run(sc, []*tariff.Tariff{tar}, sc.Meta.InstrumentDefaults, nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	demandAmt := func(policy string) float64 {
		for _, r := range resp.Runs {
			if r.Policy != policy {
				continue
			}
			for _, li := range r.Bill.LineItems {
				if li.Kind == tariff.KindDemand {
					return li.AmountUSD
				}
			}
		}
		return math.NaN()
	}
	dumb, lexa := demandAmt(PolicyDerDumb), demandAmt(PolicyDerLexa)
	t.Logf("demand charge: der_dumb=$%.2f der_lexa=$%.2f", dumb, lexa)
	if lexa > dumb+1e-9 {
		t.Errorf("lexa demand charge (%.2f) should not exceed dumb (%.2f)", lexa, dumb)
	}
}

// ---- cross-validation (422 conditions) ------------------------------------

func TestCrossValidation(t *testing.T) {
	sc := synthScenario(t, "xv", "America/Chicago", "synth-tx", "2025-07-07", 2)
	inst := sc.Meta.InstrumentDefaults

	// Territory mismatch.
	bad := synthTOUTariff(t, "other-territory", "America/Chicago")
	if _, err := Run(sc, []*tariff.Tariff{bad}, inst, nil); !isCrossVal(err) {
		t.Errorf("territory mismatch: expected CrossValError, got %v", err)
	}
	// Timezone mismatch.
	badTZ := synthTOUTariff(t, "synth-tx", "America/New_York")
	if _, err := Run(sc, []*tariff.Tariff{badTZ}, inst, nil); !isCrossVal(err) {
		t.Errorf("timezone mismatch: expected CrossValError, got %v", err)
	}
	// Effective-range mismatch: scenario in July, tariff effective Jan only.
	js := `{ "id":"eff","name":"Eff","short_name":"E","utility":"T",
      "territory":"synth-tx","timezone":"America/Chicago","currency":"USD",
      "effective":{"from":"2025-01-01","to":"2025-01-31"},
      "provenance":{"source_url":"https://x.test","retrieved":"2026-07-13","confidence":"estimated","notes":"x"},
      "fixed_monthly_usd":0,
      "energy":{"seasons":[{"id":"all","months":[1,2,3,4,5,6,7,8,9,10,11,12],
        "day_types":[{"days":["mon","tue","wed","thu","fri","sat","sun"],
          "periods":[{"id":"f","label":"F","start":"00:00","end":"24:00","rate_usd_per_kwh":0.1}]}]}]},
      "riders_usd_per_kwh":0,"export":{"type":"none"} }`
	effTar, err := tariff.Parse([]byte(js))
	if err != nil {
		t.Fatalf("parse eff tariff: %v", err)
	}
	if _, err := Run(sc, []*tariff.Tariff{effTar}, inst, nil); !isCrossVal(err) {
		t.Errorf("effective-range mismatch: expected CrossValError, got %v", err)
	}

	// Sanity: the matching tariff passes.
	good := synthTOUTariff(t, "synth-tx", "America/Chicago")
	if _, err := Run(sc, []*tariff.Tariff{good}, inst, nil); err != nil {
		t.Errorf("matching tariff should pass, got %v", err)
	}
}

func isCrossVal(err error) bool {
	var cv *CrossValError
	return errors.As(err, &cv)
}

// ---- bad input (400) ------------------------------------------------------

func TestBadInput(t *testing.T) {
	sc := synthScenario(t, "bad", "America/Chicago", "synth-tx", "2025-07-07", 2)
	tar := synthTOUTariff(t, "synth-tx", "America/Chicago")

	bad := sc.Meta.InstrumentDefaults
	bad.PVKW = -1
	if _, err := Run(sc, []*tariff.Tariff{tar}, bad, nil); !isInput(err) {
		t.Errorf("negative pv_kw: expected InputError, got %v", err)
	}
	if _, err := Run(sc, []*tariff.Tariff{tar}, sc.Meta.InstrumentDefaults, []string{"nope"}); !isInput(err) {
		t.Errorf("unknown policy: expected InputError, got %v", err)
	}
}

func isInput(err error) bool {
	var ie *InputError
	return errors.As(err, &ie)
}

// ---- policy subset selection ----------------------------------------------

func TestPolicySubset(t *testing.T) {
	sc := synthScenario(t, "sub", "America/Chicago", "synth-tx", "2025-07-07", 2)
	tar := synthTOUTariff(t, "synth-tx", "America/Chicago")
	resp, err := Run(sc, []*tariff.Tariff{tar}, sc.Meta.InstrumentDefaults, []string{PolicyDerLexa})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(resp.Runs) != 1 || resp.Runs[0].Policy != PolicyDerLexa {
		t.Fatalf("expected only der_lexa run, got %d runs", len(resp.Runs))
	}
	if len(resp.Savings) != 1 || resp.Savings[0].Policy != PolicyDerLexa {
		t.Fatalf("expected only der_lexa savings, got %d", len(resp.Savings))
	}
}
