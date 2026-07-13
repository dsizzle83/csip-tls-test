package whatif

import (
	"math"
	"time"

	"csip-tls-test/internal/scenariodata"
	"csip-tls-test/internal/tariff"
)

const (
	ticksPerDay = 96   // 15-minute ticks
	dtHours     = 0.25 // tick length in hours
	tickStep    = 15 * time.Minute
)

// envTick is one tick's policy-independent environment.
type envTick struct {
	t         time.Time // local wall clock (scenario timezone)
	dayIdx    int       // 0-based day within the period
	weekday   bool
	hourOfDay float64 // [0,24)
	pvKWh     float64 // PV energy available this tick (AC), if a policy uses PV
	loadKWh   float64 // home load energy this tick (excludes EV)
	tempF     float64
}

// env is the whole-horizon environment plus period metadata.
type env struct {
	ticks []envTick
	loc   *time.Location
	dates []string // one "YYYY-MM-DD" per day, in order
	inst  Instruments
}

// buildEnv constructs the tick-by-tick environment (PV + home load) for the
// scenario period. It is independent of tariff and policy.
func buildEnv(sc *scenariodata.Scenario, inst Instruments, loc *time.Location) (*env, error) {
	start, err := time.Parse(dateLayout, sc.Meta.Period.Start)
	if err != nil {
		return nil, &InputError{Reason: "period.start: " + err.Error()}
	}
	end, err := time.Parse(dateLayout, sc.Meta.Period.End)
	if err != nil {
		return nil, &InputError{Reason: "period.end: " + err.Error()}
	}
	days := int(end.Sub(start).Hours()/24) + 1
	if days <= 0 {
		return nil, &InputError{Reason: "empty period"}
	}
	n := days * ticksPerDay

	w := &sc.Weather
	hd := sc.Meta.HomeDefaults

	e := &env{
		loc:   loc,
		inst:  inst,
		dates: make([]string, days),
		ticks: make([]envTick, n),
	}
	first := time.Date(start.Year(), start.Month(), start.Day(), 0, 0, 0, 0, loc)
	for d := 0; d < days; d++ {
		e.dates[d] = first.AddDate(0, 0, d).Format(dateLayout)
	}

	for i := 0; i < n; i++ {
		// Weather index: contiguous hourly series aligned to the same period
		// start; hourFloat maps a tick onto the hourly grid (no DST wrinkle in
		// the July scenarios, and the position is derived from tick index so it
		// is exact regardless).
		hourFloat := float64(i) * dtHours
		ghi := interp(w.GHIWm2, hourFloat)
		tempC := interp(w.TempC, hourFloat)

		tickTime := first.Add(time.Duration(i) * tickStep)
		hod := float64(tickTime.Hour()) + float64(tickTime.Minute())/60.0

		pvKW := pvACPower(ghi, tempC, inst.PVKW)
		tempF := tempC*9.0/5.0 + 32.0
		loadKW := hd.BaseKW + occupancyKW(hod) + acKW(tempF, hd.HVAC)

		e.ticks[i] = envTick{
			t:         tickTime,
			dayIdx:    i / ticksPerDay,
			weekday:   isWeekday(tickTime.Weekday()),
			hourOfDay: hod,
			pvKWh:     pvKW * dtHours,
			loadKWh:   loadKW * dtHours,
			tempF:     tempF,
		}
	}
	return e, nil
}

// pvACPower is the CONTRACTS.md §3 PV model (returns kW, clamped ≥ 0).
func pvACPower(ghi, tempC, pvKW float64) float64 {
	if ghi <= 0 || pvKW <= 0 {
		return 0
	}
	cellTemp := tempC + 0.03*ghi
	derate := 1 - 0.004*math.Max(0, cellTemp-25)
	ac := ghi / 1000.0 * pvKW * 0.85 * derate
	if ac < 0 {
		return 0
	}
	return ac
}

// occupancyKW is the fixed daily occupancy shape (two raised-cosine bumps).
func occupancyKW(h float64) float64 {
	return bump(h, 6, 9, 0.5) + bump(h, 17, 22, 1.0)
}

// bump is a raised-cosine (Hann) window over [a,b) peaking at amp.
func bump(h, a, b, amp float64) float64 {
	if h < a || h >= b {
		return 0
	}
	return amp * 0.5 * (1 - math.Cos(2*math.Pi*(h-a)/(b-a)))
}

// acKW is the smooth AC draw: proportional to setpoint overshoot, clamped to
// the HVAC nameplate. No on/off chatter (a continuous time-averaged duty).
func acKW(tempF float64, hvac scenariodata.HVACDefaults) float64 {
	raw := (tempF - hvac.CoolSetpointF) * hvac.KWPerDegF
	if raw < 0 {
		raw = 0
	}
	if hvac.MaxKW > 0 && raw > hvac.MaxKW {
		raw = hvac.MaxKW
	}
	return raw
}

// interp linearly interpolates arr at fractional index x, clamping at the ends.
func interp(arr []float64, x float64) float64 {
	if len(arr) == 0 {
		return 0
	}
	if x <= 0 {
		return arr[0]
	}
	i := int(math.Floor(x))
	if i >= len(arr)-1 {
		return arr[len(arr)-1]
	}
	frac := x - float64(i)
	return arr[i]*(1-frac) + arr[i+1]*frac
}

func isWeekday(wd time.Weekday) bool {
	return wd != time.Saturday && wd != time.Sunday
}

// ---- dispatch configuration ----------------------------------------------

type polConfig struct {
	usePV        bool
	useBattery   bool
	smartBattery bool // lexa arbitrage vs. dumb greedy
	smartEV      bool // lexa cheapest-window vs. on-arrival
}

var (
	cfgBaseline = polConfig{}                                                                 // A
	cfgPVOnly   = polConfig{usePV: true}                                                      // B
	cfgDumb     = polConfig{usePV: true, useBattery: true}                                    // C
	cfgLexa     = polConfig{usePV: true, useBattery: true, smartBattery: true, smartEV: true} // D
)

// ---- per-tick simulation result ------------------------------------------

type tickResult struct {
	importKWh     float64
	exportKWh     float64
	battCharge    float64 // terminal energy into battery (≥ 0)
	battDischarge float64 // terminal energy out of battery (≥ 0)
	evKWh         float64
	pvKWh         float64 // PV available (0 when policy has no PV)
	loadKWh       float64
	storedKWh     float64 // battery stored energy AFTER this tick
	importRate    float64 // $/kWh (incl. riders)
	exportRate    float64 // $/kWh credited for export
}

type simResult struct {
	ticks    []tickResult
	capacity float64 // battery capacity used (0 if battery disabled)
}

// simulate runs one policy dispatch over the whole horizon and returns the
// per-tick results. Grid is always the balancing residual, which makes per-tick
// energy conservation exact by construction.
func simulate(e *env, t *tariff.Tariff, cfg polConfig) simResult {
	n := len(e.ticks)
	res := simResult{ticks: make([]tickResult, n)}

	// Battery parameters (disabled if degenerate).
	b := e.inst.Battery
	batteryOn := cfg.useBattery && b.KWh > 0 && b.KW > 0 && b.RoundTripEff > 0
	var capacity, reserveFloor, sqrtEff, maxTickKWh, stored float64
	if batteryOn {
		capacity = b.KWh
		reserveFloor = b.ReservePct / 100.0 * capacity
		sqrtEff = math.Sqrt(b.RoundTripEff)
		maxTickKWh = b.KW * dtHours
		stored = reserveFloor // start at reserve (no free head-start energy)
		res.capacity = capacity
	}

	// Import rate per tick (for daily cost + peak/valley + smart EV).
	importRate := make([]float64, n)
	exportRate := make([]float64, n)
	for i := range e.ticks {
		ri := t.RateAt(e.ticks[i].t)
		importRate[i] = ri.ImportUSDPerKWh
		exportRate[i] = ri.ExportUSDPerKWh
	}

	// EV schedule (kWh per tick) — timing depends on policy.
	var evKWh []float64
	if e.inst.EV.Present {
		if cfg.smartEV {
			evKWh = evScheduleSmart(e, importRate)
		} else {
			evKWh = evScheduleOnArrival(e)
		}
	} else {
		evKWh = make([]float64, n)
	}

	// Precompute per-day peak/valley context for the lexa battery.
	var pk *peakContext
	if batteryOn && cfg.smartBattery {
		pk = buildPeakContext(e, importRate, evKWh, sqrtEff, reserveFloor, capacity)
	}

	// Demand-charge peak-shaving state (lexa only; no-op when tariff has none).
	var ceiling, observedPeak, warmStart float64
	demandActive := batteryOn && cfg.smartBattery && len(t.Demand) > 0
	inDemand := make([]bool, n)
	if demandActive {
		for i := range e.ticks {
			for di := range t.Demand {
				if t.Demand[di].Covers(e.ticks[i].t) {
					inDemand[i] = true
					break
				}
			}
		}
		warmStart = warmStartCeiling(e, evKWh, cfg.usePV, inDemand)
		ceiling = warmStart
	}

	for i := range e.ticks {
		et := &e.ticks[i]
		pv := 0.0
		if cfg.usePV {
			pv = et.pvKWh
		}
		load := et.loadKWh
		ev := evKWh[i]
		demand := load + ev

		var battCharge, battDischarge float64
		if batteryOn {
			if cfg.smartBattery {
				battCharge, battDischarge = dispatchLexa(dispatchIn{
					pv: pv, demand: demand, stored: stored,
					sqrtEff: sqrtEff, maxTick: maxTickKWh,
					reserveFloor: reserveFloor, capacity: capacity,
					isPeak: pk.isPeak[i], isValley: pk.isValley[i],
					arbitrage: pk.arbitrage[et.dayIdx], target: pk.target[et.dayIdx],
				})
			} else {
				battCharge, battDischarge = dispatchDumb(pv, demand, stored, sqrtEff, maxTickKWh, reserveFloor, capacity)
			}
		}

		// Demand-charge shaving (adds discharge to hold billed peak ≤ ceiling).
		if demandActive && inDemand[i] {
			projImportKWh := demand + battCharge - pv - battDischarge
			projImportKW := math.Max(0, projImportKWh) / dtHours
			ceiling = math.Max(warmStart, observedPeak)
			if projImportKW > ceiling {
				extraNeeded := (projImportKW - ceiling) * dtHours
				availDischarge := (stored-reserveFloor)*sqrtEff - battDischarge
				budget := maxTickKWh - battDischarge - battCharge
				extra := math.Min(extraNeeded, math.Min(math.Max(0, availDischarge), math.Max(0, budget)))
				battDischarge += extra
				projImportKW = math.Max(0, demand+battCharge-pv-battDischarge) / dtHours
			}
			if projImportKW > observedPeak {
				observedPeak = projImportKW
			}
		}

		// Apply battery state change.
		if batteryOn {
			stored += battCharge*sqrtEff - battDischarge/sqrtEff
			// Numerical guard against tiny drift past bounds.
			if stored < reserveFloor-1e-9 {
				stored = reserveFloor
			}
			if stored > capacity+1e-9 {
				stored = capacity
			}
		}

		// Grid = balancing residual (guarantees per-tick conservation).
		net := demand + battCharge - pv - battDischarge
		var imp, exp float64
		if net >= 0 {
			imp = net
		} else {
			exp = -net
		}

		res.ticks[i] = tickResult{
			importKWh: imp, exportKWh: exp,
			battCharge: battCharge, battDischarge: battDischarge,
			evKWh: ev, pvKWh: pv, loadKWh: load,
			storedKWh:  stored,
			importRate: importRate[i], exportRate: exportRate[i],
		}
	}
	return res
}

// dispatchIn bundles the lexa per-tick inputs.
type dispatchIn struct {
	pv, demand, stored          float64
	sqrtEff, maxTick            float64
	reserveFloor, capacity      float64
	isPeak, isValley, arbitrage bool
	target                      float64
}

// dispatchDumb: greedy self-consumption. Charge from PV excess; discharge to
// cover net load down to the reserve floor.
func dispatchDumb(pv, demand, stored, sqrtEff, maxTick, reserveFloor, capacity float64) (charge, discharge float64) {
	if pv > demand {
		excess := pv - demand
		room := (capacity - stored) / sqrtEff
		charge = math.Min(excess, math.Min(maxTick, math.Max(0, room)))
	} else if demand > pv {
		deficit := demand - pv
		avail := (stored - reserveFloor) * sqrtEff
		discharge = math.Min(deficit, math.Min(maxTick, math.Max(0, avail)))
	}
	return charge, discharge
}

// dispatchLexa: tariff-aware dispatch.
//  1. Always self-consume PV excess into the battery.
//  2. During the day's peak window, discharge to zero out grid import.
//  3. During the day's valley window, if arbitrage clears round-trip losses,
//     pre-charge from the grid toward the SOC needed to ride the peak.
//  4. Otherwise hold (let the grid cover the deficit) — save the battery for
//     the peak.
func dispatchLexa(in dispatchIn) (charge, discharge float64) {
	if in.pv > in.demand {
		// (1) PV excess → battery.
		excess := in.pv - in.demand
		room := (in.capacity - in.stored) / in.sqrtEff
		charge = math.Min(excess, math.Min(in.maxTick, math.Max(0, room)))
		return charge, 0
	}

	deficit := in.demand - in.pv
	if deficit > 0 && in.isPeak {
		// (2) Discharge through the peak to eliminate import.
		avail := (in.stored - in.reserveFloor) * in.sqrtEff
		discharge = math.Min(deficit, math.Min(in.maxTick, math.Max(0, avail)))
		return 0, discharge
	}

	if in.isValley && in.arbitrage && in.stored < in.target {
		// (3) Valley grid pre-charge toward the ride-the-peak target.
		need := (in.target - in.stored) / in.sqrtEff
		room := (in.capacity - in.stored) / in.sqrtEff
		charge = math.Min(need, math.Min(in.maxTick, math.Max(0, room)))
		return charge, 0
	}

	// (4) Hold.
	return 0, 0
}

// ---- peak / valley context (lexa battery) --------------------------------

type peakContext struct {
	isPeak    []bool    // per tick: in the day's peak (max-rate) contiguous run
	isValley  []bool    // per tick: at the day's valley (min) rate
	arbitrage []bool    // per day: valley_rate < peak_rate * round_trip_eff
	target    []float64 // per day: stored energy needed to ride the peak
}

// buildPeakContext computes, per calendar day, the peak/valley windows, whether
// valley→peak arbitrage clears the round-trip loss, and the stored-energy
// target needed to ride the day's peak deficit.
func buildPeakContext(e *env, importRate, evKWh []float64, sqrtEff, reserveFloor, capacity float64) *peakContext {
	n := len(e.ticks)
	pc := &peakContext{
		isPeak:   make([]bool, n),
		isValley: make([]bool, n),
	}
	days := len(e.dates)
	pc.arbitrage = make([]bool, days)
	pc.target = make([]float64, days)
	rte := sqrtEff * sqrtEff

	for d := 0; d < days; d++ {
		lo := d * ticksPerDay
		hi := lo + ticksPerDay
		if hi > n {
			hi = n
		}
		if lo >= hi {
			continue
		}
		peakRate, valleyRate := importRate[lo], importRate[lo]
		for i := lo; i < hi; i++ {
			if importRate[i] > peakRate {
				peakRate = importRate[i]
			}
			if importRate[i] < valleyRate {
				valleyRate = importRate[i]
			}
		}
		// Longest contiguous run at the peak rate → the peak window.
		bestStart, bestLen, curStart, curLen := -1, 0, -1, 0
		for i := lo; i < hi; i++ {
			if approxEq(importRate[i], peakRate) {
				if curLen == 0 {
					curStart = i
				}
				curLen++
				if curLen > bestLen {
					bestLen, bestStart = curLen, curStart
				}
			} else {
				curLen = 0
			}
			if approxEq(importRate[i], valleyRate) {
				pc.isValley[i] = true
			}
		}
		for i := bestStart; i < bestStart+bestLen && i >= 0; i++ {
			pc.isPeak[i] = true
		}

		pc.arbitrage[d] = valleyRate < peakRate*rte

		// Ride-the-peak target: enough stored energy to deliver the peak-window
		// deficit through the battery (deliver = stored*sqrtEff).
		var peakDeficit float64
		for i := bestStart; i < bestStart+bestLen && i >= 0; i++ {
			pv := e.ticks[i].pvKWh
			dem := e.ticks[i].loadKWh + evKWh[i]
			if dem > pv {
				peakDeficit += dem - pv
			}
		}
		target := reserveFloor + peakDeficit/sqrtEff
		if target > capacity {
			target = capacity
		}
		pc.target[d] = target
	}
	return pc
}

func approxEq(a, b float64) bool { return math.Abs(a-b) < 1e-12 }

// warmStartCeiling estimates a demand-charge import ceiling: the median raw
// in-window import (kW), a deterministic warm start the ceiling ratchets up
// from as unavoidable peaks appear.
func warmStartCeiling(e *env, evKWh []float64, usePV bool, inDemand []bool) float64 {
	var vals []float64
	for i := range e.ticks {
		if !inDemand[i] {
			continue
		}
		pv := 0.0
		if usePV {
			pv = e.ticks[i].pvKWh
		}
		raw := e.ticks[i].loadKWh + evKWh[i] - pv
		if raw < 0 {
			raw = 0
		}
		vals = append(vals, raw/dtHours)
	}
	if len(vals) == 0 {
		return 0
	}
	sortFloats(vals)
	return vals[len(vals)/2] // median
}

func sortFloats(a []float64) {
	// insertion-friendly small slices via sort.Slice would import sort; keep a
	// simple in-place sort to stay local to this file.
	for i := 1; i < len(a); i++ {
		for j := i; j > 0 && a[j-1] > a[j]; j-- {
			a[j-1], a[j] = a[j], a[j-1]
		}
	}
}

// ---- EV scheduling --------------------------------------------------------

// evScheduleOnArrival charges the trip's weekday_kwh starting at return_hour at
// the full charger rate (baseline / der_dumb).
func evScheduleOnArrival(e *env) []float64 {
	n := len(e.ticks)
	out := make([]float64, n)
	ev := e.inst.EV
	perTick := ev.ChargerKW * dtHours
	if perTick <= 0 {
		return out
	}
	for i := 0; i < n; i++ {
		et := e.ticks[i]
		if et.weekday && et.t.Hour() == ev.ReturnHour && et.t.Minute() == 0 {
			remaining := ev.WeekdayKWh
			for j := i; j < n && remaining > 1e-12; j++ {
				add := math.Min(perTick, remaining)
				out[j] += add
				remaining -= add
			}
		}
	}
	return out
}

// evScheduleSmart charges each weekday trip's weekday_kwh in the cheapest ticks
// of the window [return, next weekday depart), filling next-cheapest until the
// energy is met (deadline-safe — the window's capacity dwarfs weekday_kwh).
func evScheduleSmart(e *env, importRate []float64) []float64 {
	n := len(e.ticks)
	out := make([]float64, n)
	ev := e.inst.EV
	perTick := ev.ChargerKW * dtHours
	if perTick <= 0 {
		return out
	}
	for i := 0; i < n; i++ {
		et := e.ticks[i]
		if !(et.weekday && et.t.Hour() == ev.ReturnHour && et.t.Minute() == 0) {
			continue
		}
		// Window end = next weekday depart moment (or horizon end).
		end := n
		for j := i + 1; j < n; j++ {
			d := e.ticks[j]
			if d.weekday && d.t.Hour() == ev.DepartHour && d.t.Minute() == 0 {
				end = j
				break
			}
		}
		// Candidate ticks, cheapest first (stable tie-break by index).
		idx := make([]int, 0, end-i)
		for j := i; j < end; j++ {
			idx = append(idx, j)
		}
		sortByRate(idx, importRate)
		remaining := ev.WeekdayKWh
		for _, j := range idx {
			if remaining <= 1e-12 {
				break
			}
			add := math.Min(perTick, remaining)
			out[j] += add
			remaining -= add
		}
	}
	return out
}

// sortByRate sorts indices by (rate asc, index asc) — insertion sort keeps this
// file dependency-free and the slices are short (one EV window).
func sortByRate(idx []int, rate []float64) {
	for i := 1; i < len(idx); i++ {
		for j := i; j > 0; j-- {
			a, b := idx[j-1], idx[j]
			if rate[a] < rate[b] || (rate[a] == rate[b] && a < b) {
				break
			}
			idx[j-1], idx[j] = idx[j], idx[j-1]
		}
	}
}

// ---- bill + output reducers ----------------------------------------------

// billFor accumulates the itemized bill for a simulation. The period is a
// single calendar month in v1 (July); multi-month periods sum matching line
// items across months.
func billFor(sim simResult, e *env, t *tariff.Tariff) tariff.Bill {
	// Distinct (year, month) in the period.
	type ym struct {
		y int
		m time.Month
	}
	seen := map[ym]bool{}
	var order []ym
	for i := range e.ticks {
		key := ym{e.ticks[i].t.Year(), e.ticks[i].t.Month()}
		if !seen[key] {
			seen[key] = true
			order = append(order, key)
		}
	}
	calcs := make([]*tariff.BillCalc, len(order))
	idxOf := map[ym]int{}
	for k, key := range order {
		calcs[k] = tariff.NewBillCalc(t, key.y, key.m)
		idxOf[key] = k
	}
	for i := range e.ticks {
		tr := sim.ticks[i]
		key := ym{e.ticks[i].t.Year(), e.ticks[i].t.Month()}
		calcs[idxOf[key]].Add(e.ticks[i].t, tr.importKWh, tr.exportKWh, tr.importKWh/dtHours)
	}
	if len(calcs) == 1 {
		return calcs[0].Close()
	}
	bills := make([]tariff.Bill, len(calcs))
	for k := range calcs {
		bills[k] = calcs[k].Close()
	}
	return combineBills(bills)
}

// combineBills sums line items (by kind+label, preserving first-seen order)
// across multiple monthly bills.
func combineBills(bills []tariff.Bill) tariff.Bill {
	// Demand lines are NOT merged across months: their Qty is a peak kW, and
	// summing peaks is physically meaningless (and would break Qty×Rate ==
	// AmountUSD). Each month's demand line stays its own row, keyed by index.
	type key struct {
		kind, label string
		monthIdx    int // -1 for mergeable kinds; bill index for demand
	}
	agg := map[key]*tariff.LineItem{}
	var order []key
	var total, carryover float64
	for bi, b := range bills {
		for _, li := range b.LineItems {
			k := key{li.Kind, li.Label, -1}
			if li.Kind == tariff.KindDemand {
				k.monthIdx = bi
			}
			if agg[k] == nil {
				cp := li
				agg[k] = &cp
				order = append(order, k)
			} else {
				agg[k].Qty += li.Qty
				agg[k].AmountUSD += li.AmountUSD
			}
		}
		total += b.TotalUSD
		carryover += b.CreditCarryoverUSD
	}
	out := tariff.Bill{TotalUSD: round2(total), CreditCarryoverUSD: round2(carryover)}
	for _, k := range order {
		out.LineItems = append(out.LineItems, *agg[k])
	}
	return out
}

func kpisFor(sim simResult, e *env) KPIs {
	var imp, exp, pv, peakKW, socSum float64
	for i := range sim.ticks {
		tr := sim.ticks[i]
		imp += tr.importKWh
		exp += tr.exportKWh
		pv += tr.pvKWh
		if kw := tr.importKWh / dtHours; kw > peakKW {
			peakKW = kw
		}
		if sim.capacity > 0 {
			socSum += tr.storedKWh / sim.capacity * 100
		}
	}
	n := float64(len(sim.ticks))
	var selfCons, avgSOC float64
	if pv > 0 {
		selfCons = (pv - exp) / pv * 100
		if selfCons < 0 {
			selfCons = 0
		}
		if selfCons > 100 {
			selfCons = 100
		}
	}
	if sim.capacity > 0 && n > 0 {
		avgSOC = socSum / n
	}
	return KPIs{
		ImportKWh:          round3(imp),
		ExportKWh:          round3(exp),
		PeakImportKW:       round3(peakKW),
		SelfConsumptionPct: round2(selfCons),
		AvgSOCPct:          round2(avgSOC),
	}
}

func dailyFor(sim simResult, e *env) Daily {
	days := len(e.dates)
	d := Daily{
		Dates:     append([]string(nil), e.dates...),
		CostUSD:   make([]float64, days),
		ImportKWh: make([]float64, days),
		ExportKWh: make([]float64, days),
		PVKWh:     make([]float64, days),
		LoadKWh:   make([]float64, days),
	}
	for i := range sim.ticks {
		day := e.ticks[i].dayIdx
		tr := sim.ticks[i]
		d.CostUSD[day] += tr.importKWh*tr.importRate - tr.exportKWh*tr.exportRate
		d.ImportKWh[day] += tr.importKWh
		d.ExportKWh[day] += tr.exportKWh
		d.PVKWh[day] += tr.pvKWh
		d.LoadKWh[day] += tr.loadKWh
	}
	for i := 0; i < days; i++ {
		d.CostUSD[i] = round2(d.CostUSD[i])
		d.ImportKWh[i] = round3(d.ImportKWh[i])
		d.ExportKWh[i] = round3(d.ExportKWh[i])
		d.PVKWh[i] = round3(d.PVKWh[i])
		d.LoadKWh[i] = round3(d.LoadKWh[i])
	}
	return d
}

// costliestDay returns the day index with the highest daily energy cost under
// the given simulation (baseline).
func costliestDay(sim simResult, e *env) int {
	days := len(e.dates)
	cost := make([]float64, days)
	for i := range sim.ticks {
		tr := sim.ticks[i]
		cost[e.ticks[i].dayIdx] += tr.importKWh*tr.importRate - tr.exportKWh*tr.exportRate
	}
	best := 0
	for d := 1; d < days; d++ {
		if cost[d] > cost[best] {
			best = d
		}
	}
	return best
}

func dayDetailFor(sim simResult, e *env, day int) DayDetail {
	lo := day * ticksPerDay
	hi := lo + ticksPerDay
	if hi > len(sim.ticks) {
		hi = len(sim.ticks)
	}
	dd := DayDetail{
		Date:  e.dates[day],
		Ticks: hi - lo,
	}
	for i := lo; i < hi; i++ {
		tr := sim.ticks[i]
		dd.LoadKW = append(dd.LoadKW, round3(tr.loadKWh/dtHours))
		dd.PVKW = append(dd.PVKW, round3(tr.pvKWh/dtHours))
		dd.BattKW = append(dd.BattKW, round3((tr.battDischarge-tr.battCharge)/dtHours))
		dd.EVKW = append(dd.EVKW, round3(tr.evKWh/dtHours))
		dd.GridKW = append(dd.GridKW, round3((tr.importKWh-tr.exportKWh)/dtHours))
		soc := 0.0
		if sim.capacity > 0 {
			soc = tr.storedKWh / sim.capacity * 100
		}
		dd.SOCPct = append(dd.SOCPct, round2(soc))
		dd.RateUSDPerKWh = append(dd.RateUSDPerKWh, tr.importRate)
	}
	return dd
}

func round2(x float64) float64 { return math.Round(x*100) / 100 }
func round3(x float64) float64 { return math.Round(x*1000) / 1000 }
