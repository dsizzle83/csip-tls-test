// Bench replay driver: replays the cost-sim's synthetic summer environment
// against the REAL bench — injecting solar/load/EV state into the device sims,
// warping gridsim's CSIP clock so the hub's TOU windows and DER event
// schedules follow simulated time, and sampling the real meter + hub decisions
// to measure what the hub actually did.
//
// It runs server-side (not in the browser) so a multi-hour overnight replay
// survives the dashboard tab closing. One replay at a time.
//
//	POST /api/replay/start  {seed, tick_ms, start_day, days, env:{...}}
//	GET  /api/replay/status
//	POST /api/replay/abort
package main

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"log"
	"math"
	"net/http"
	"os"
	"strconv"
	"sync"
	"time"
)

const (
	replayTPD     = 96   // 15-min ticks per day
	replayDTHours = 0.25 // hours per tick

	// Tariff: must match lexa-hub's DefaultTOUCostModel and the dashboard's
	// synthetic engine so modeled and measured costs share one price basis.
	ratePeak     = 0.38 // $/kWh, 16:00–21:00
	ratePartial  = 0.18 // 07:00–16:00
	rateOff      = 0.10 // 21:00–07:00
	exportCredit = 0.07

	complianceTolW = 150 // W, same tolerance the Scenarios tab asserts with
)

func replayRate(hour float64) float64 {
	switch {
	case hour >= 16 && hour < 21:
		return ratePeak
	case hour >= 7 && hour < 16:
		return ratePartial
	default:
		return rateOff
	}
}

// ── Request / state types ─────────────────────────────────────────────────────

type replayEvent struct {
	Day   int     `json:"day"`
	Type  string  `json:"type"` // exportCap | importCap | genLimit
	Limit float64 `json:"limit"`
	Start float64 `json:"start"` // hour of day
	End   float64 `json:"end"`
}

type replayEnvData struct {
	Pv       []float64     `json:"pv"`       // kW per tick
	Load     []float64     `json:"load"`     // kW per tick
	EvHome   []int         `json:"evHome"`   // 1 = at home
	EvArrive []float64     `json:"evArrive"` // kWh trip energy, set on arrival tick
	Events   []replayEvent `json:"events"`
	Dates    []string      `json:"dates"` // "6/1" … per day
}

type replayStartReq struct {
	Seed     uint32        `json:"seed"`
	TickMs   int           `json:"tick_ms"`   // real ms per 15-min tick (default 8000)
	StartDay int           `json:"start_day"` // resume offset (default 0)
	Days     int           `json:"days"`      // 0 = all days in env
	Env      replayEnvData `json:"env"`
}

type replaySample struct {
	Tick       int      `json:"tick"`
	SimTime    string   `json:"sim_time"` // "6/14 17:30"
	GridW      float64  `json:"grid_W"`
	SolarW     float64  `json:"solar_W"`
	BatteryW   float64  `json:"battery_W"`
	EvW        float64  `json:"ev_W"`
	BatSOC     float64  `json:"bat_soc"`
	EvSOC      float64  `json:"ev_soc"`
	Constraint string   `json:"constraint,omitempty"` // active DER cap, human form
	Violation  bool     `json:"violation"`
	Excused    bool     `json:"excused"` // miss the hub reported as CannotComply (resource-limited)
	Decisions  []string `json:"decisions,omitempty"`
}

type replayMeasured struct {
	CostUSD    float64 `json:"cost_usd"`
	CreditUSD  float64 `json:"credit_usd"`
	NetUSD     float64 `json:"net_usd"`
	ImportKWh  float64 `json:"import_kwh"`
	ExportKWh  float64 `json:"export_kwh"`
	PeakImpKWh float64 `json:"peak_import_kwh"`
	ConsTicks  int     `json:"constrained_ticks"`
	Violations int     `json:"violations"`
	Excused    int     `json:"excused"` // resource-limited misses the hub reported (not counted as violations)
	Compliance float64 `json:"compliance_pct"`
	SampleErrs int     `json:"sample_errors"`
}

type replayStatus struct {
	Running     bool           `json:"running"`
	Finished    bool           `json:"finished"`
	Aborted     bool           `json:"aborted"`
	LastError   string         `json:"last_error,omitempty"`
	Seed        uint32         `json:"seed"`
	TickMs      int            `json:"tick_ms"`
	Tick        int            `json:"tick"`
	TotalTicks  int            `json:"total_ticks"`
	StartDay    int            `json:"start_day"`
	Day         int            `json:"day"`
	Date        string         `json:"date"`
	SimTime     string         `json:"sim_time"`
	TickLogPath string         `json:"tick_log_path,omitempty"` // per-tick per-DER CSV on the dashboard host
	Pct         float64        `json:"pct"`
	StartedAt   time.Time      `json:"started_at"`
	EtaS        int            `json:"eta_s"`
	Measured    replayMeasured `json:"measured"`
	DailyNet    []float64      `json:"daily_net"` // cumulative measured net $ per completed day
	Samples     []replaySample `json:"samples"`   // most recent ticks (bounded)
}

type replayDriver struct {
	mu             sync.Mutex
	backends       map[string]string // hub, gridsim, solar, battery, meter, ev → base URL
	client         *http.Client
	status         replayStatus
	cancel         context.CancelFunc
	checkpointPath string

	// Per-tick per-DER trace, written to a CSV on the dashboard host so a long
	// replay leaves a shareable record of what each DER did every 15-min tick.
	tickLogFile *os.File
	tickLogCSV  *csv.Writer
}

func newReplayDriver(backends map[string]string) *replayDriver {
	return &replayDriver{
		backends: backends,
		// WS-B: hub backend (:9100) is HTTPS self-signed; skip-verify transport
		// (hubtls.go). Same client reaches the http sims — TLS config is ignored
		// for http:// so they are unaffected. Bearer auth unchanged.
		client:         &http.Client{Timeout: 3 * time.Second, Transport: benchHubTransport()},
		checkpointPath: "replay-checkpoint.json",
	}
}

// ── HTTP endpoints ────────────────────────────────────────────────────────────

func (d *replayDriver) handleStart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var req replayStartReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	n := len(req.Env.Pv)
	if n == 0 || n%replayTPD != 0 ||
		len(req.Env.Load) != n || len(req.Env.EvHome) != n || len(req.Env.EvArrive) != n {
		http.Error(w, "env series missing or lengths inconsistent", http.StatusBadRequest)
		return
	}
	if req.TickMs < 500 {
		req.TickMs = 8000
	}
	totalDays := n / replayTPD
	if req.StartDay < 0 || req.StartDay >= totalDays {
		req.StartDay = 0
	}
	if req.Days <= 0 || req.StartDay+req.Days > totalDays {
		req.Days = totalDays - req.StartDay
	}

	d.mu.Lock()
	if d.status.Running {
		d.mu.Unlock()
		http.Error(w, "a replay is already running", http.StatusConflict)
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	d.cancel = cancel
	d.status = replayStatus{
		Running:    true,
		Seed:       req.Seed,
		TickMs:     req.TickMs,
		StartDay:   req.StartDay,
		TotalTicks: req.Days * replayTPD,
		StartedAt:  time.Now(),
	}
	d.mu.Unlock()

	go d.run(ctx, req)
	w.WriteHeader(http.StatusAccepted)
	_ = json.NewEncoder(w).Encode(map[string]any{"total_ticks": req.Days * replayTPD, "tick_ms": req.TickMs})
}

func (d *replayDriver) handleStatus(w http.ResponseWriter, r *http.Request) {
	d.mu.Lock()
	st := d.status
	// Copy slices so the encoder doesn't race the run loop.
	st.DailyNet = append([]float64(nil), d.status.DailyNet...)
	st.Samples = append([]replaySample(nil), d.status.Samples...)
	d.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(st)
}

func (d *replayDriver) handleAbort(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	d.mu.Lock()
	cancel := d.cancel
	running := d.status.Running
	d.mu.Unlock()
	if running && cancel != nil {
		cancel()
	}
	w.WriteHeader(http.StatusAccepted)
}

// ── Replay loop ───────────────────────────────────────────────────────────────

func (d *replayDriver) run(ctx context.Context, req replayStartReq) {
	log.Printf("replay: starting — %d days from day %d, %d ms/tick, seed %d",
		req.Days, req.StartDay, req.TickMs, req.Seed)

	defer d.restoreBench()

	// Simulated epoch: Jun 1 2026 00:00 in this host's local TZ (assumed to
	// match the hub's TZ — the hub evaluates TOU windows in its local time).
	simEpoch := time.Date(2026, 6, 1, 0, 0, 0, 0, time.Local).Unix()
	speed := 900.0 / (float64(req.TickMs) / 1000.0) // sim seconds per real second

	if err := d.setupBench(speed); err != nil {
		d.fail(fmt.Sprintf("bench setup failed: %v", err))
		return
	}

	d.openTickLog()

	evCapKWh := d.evCapacityKWh()
	evSOC := d.evSOCPct()

	// Tick-index the DER events for the replayed window.
	type tickEvent struct {
		startTick, endTick int
		ev                 replayEvent
		mrid               string // gridsim DERControl mRID, set when the control is posted
	}
	var events []tickEvent
	for _, e := range req.Env.Events {
		events = append(events, tickEvent{
			startTick: e.Day*replayTPD + int(e.Start/replayDTHours),
			endTick:   e.Day*replayTPD + int(e.End/replayDTHours),
			ev:        e,
		})
	}

	firstTick := req.StartDay * replayTPD
	lastTick := firstTick + req.Days*replayTPD // exclusive
	var activeEvent *tickEvent
	clockFails := 0
	prevHome := true
	if firstTick > 0 {
		prevHome = req.Env.EvHome[firstTick-1] == 1
	}

	for t := firstTick; t < lastTick; t++ {
		select {
		case <-ctx.Done():
			d.finish(true, "")
			return
		default:
		}

		day := t / replayTPD
		hour := float64(t%replayTPD) * replayDTHours
		simUnix := simEpoch + int64(t)*900
		simLabel := fmt.Sprintf("%s %02d:%02d", req.Env.Dates[day], int(hour), int(math.Mod(hour, 1)*60))

		// 1. Warp gridsim's CSIP clock to simulated time. This is load-bearing:
		//    if it fails persistently, the hub's TOU/event clock is wrong and
		//    the whole measurement is invalid — abort rather than mis-measure.
		if err := d.post("gridsim", "/admin/clock", map[string]any{"set_unix": simUnix}); err != nil {
			clockFails++
			if clockFails >= 10 {
				d.fail(fmt.Sprintf("gridsim clock unreachable (%v) — aborting", err))
				return
			}
		} else {
			clockFails = 0
		}

		// 2. Inject environment into the device sims (best-effort; sims hold
		//    their last value across a transient failure).
		_ = d.post("solar", "/inject", map[string]any{"W_W": req.Env.Pv[t] * 1000})
		_ = d.post("meter", "/inject", map[string]any{"LoadW_W": req.Env.Load[t] * 1000})

		// 3. EV departures/arrivals.
		home := req.Env.EvHome[t] == 1
		if prevHome && !home {
			evSOC = d.evSOCPct() // remember SOC as the car leaves
			_ = d.post("ev", "/inject", map[string]any{"action": "stop_session", "connector_id": 1})
		}
		if !prevHome && home {
			trip := req.Env.EvArrive[t]
			evSOC = math.Max(5, math.Min(95, evSOC-trip/evCapKWh*100))
			_ = d.post("ev", "/inject", map[string]any{"action": "set_soc", "soc_pct": evSOC})
			_ = d.post("ev", "/inject", map[string]any{"action": "start_session", "connector_id": 1})
		}
		prevHome = home

		// 4. DER event boundaries → real CSIP DERControls on program 0.
		// endTick is inclusive (matches the synthetic engine's cap window).
		if activeEvent != nil && t > activeEvent.endTick {
			_ = d.deleteControls(0)
			activeEvent = nil
		}
		for i := range events {
			if events[i].startTick == t {
				e := events[i]
				body := map[string]any{
					"program":     0,
					"duration_s":  (e.endTick - e.startTick + 1) * 900, // sim seconds
					"activate":    true,
					"description": fmt.Sprintf("replay %s: %s %.1f kW", req.Env.Dates[e.ev.Day], e.ev.Type, e.ev.Limit),
				}
				switch e.ev.Type {
				case "exportCap":
					body["exp_lim_W"] = int64(e.ev.Limit * 1000)
				case "importCap":
					body["imp_lim_W"] = int64(e.ev.Limit * 1000)
				case "genLimit":
					body["max_lim_W"] = int64(e.ev.Limit * 1000)
				}
				if mrid, err := d.postControl(body); err == nil {
					events[i].mrid = mrid
					activeEvent = &events[i]
				}
			}
		}

		// 5. Give the bench real time to propagate and the hub to respond.
		select {
		case <-ctx.Done():
			d.finish(true, "")
			return
		case <-time.After(time.Duration(req.TickMs) * time.Millisecond):
		}

		// 6. Sample reality and book the tick.
		var constraint *activeCap
		if activeEvent != nil {
			constraint = &activeCap{typ: activeEvent.ev.Type, limW: activeEvent.ev.Limit * 1000, mrid: activeEvent.mrid}
		}
		env := tickEnv{
			possibleSolarW: req.Env.Pv[t] * 1000, // panel potential before any curtailment
			siteLoadW:      req.Env.Load[t] * 1000,
			evConnected:    home, // car is plugged in whenever it's at home
		}
		d.sampleTick(t, hour, simLabel, constraint, env)

		// Day boundary: checkpoint.
		if (t+1)%replayTPD == 0 {
			d.mu.Lock()
			d.status.DailyNet = append(d.status.DailyNet, round2(d.status.Measured.CostUSD-d.status.Measured.CreditUSD))
			d.mu.Unlock()
			d.checkpoint()
		}
	}
	d.finish(false, "")
}

// activeCap describes the DER constraint in force during a tick.
type activeCap struct {
	typ  string  // exportCap | importCap | genLimit
	limW float64 // watts
	mrid string  // gridsim DERControl mRID (to match CannotComply alerts)
}

// tickEnv carries the injected environment for a tick — values the loop knows
// directly (not read back from a sim). possibleSolarW is the panel's potential
// output before any hub curtailment; comparing it to the measured solar output
// reveals how much generation the hub clipped.
type tickEnv struct {
	possibleSolarW float64
	siteLoadW      float64
	evConnected    bool
}

// sampleTick reads the real meter/hub/devices and accumulates measured cost
// and DER compliance for tick t.
func (d *replayDriver) sampleTick(t int, hour float64, simLabel string, constraint *activeCap, env tickEnv) {
	gridW, gridOK := d.meterW()
	hubInfo := d.hubSnapshot()

	// Solar actual + potential, read coherently from the sim itself. Falls back
	// to the hub's cached reading (and the injected potential) only if the sim
	// is unreachable this tick.
	solarW, possibleW, solarOK := d.solarSim()
	if !solarOK {
		solarW, possibleW = hubInfo.solarW, env.possibleSolarW
	}

	price := replayRate(hour)
	isPeak := hour >= 16 && hour < 21

	d.mu.Lock()
	defer d.mu.Unlock()
	m := &d.status.Measured

	sample := replaySample{
		Tick:      t,
		SimTime:   simLabel,
		SolarW:    solarW,
		BatteryW:  hubInfo.batteryW,
		EvW:       hubInfo.evW,
		BatSOC:    hubInfo.batSOC,
		EvSOC:     hubInfo.evSOC,
		Decisions: hubInfo.decisions,
	}

	if !gridOK {
		m.SampleErrs++
	} else {
		sample.GridW = gridW
		kwh := gridW / 1000 * replayDTHours
		if gridW > 0 {
			m.CostUSD += kwh * price
			m.ImportKWh += kwh
			if isPeak {
				m.PeakImpKWh += kwh
			}
		} else {
			m.CreditUSD += -kwh * exportCredit
			m.ExportKWh += -kwh
		}
	}
	m.NetUSD = round2(m.CostUSD - m.CreditUSD)

	// DER compliance: judged against the real meter/solar readings, exactly
	// like the Scenarios tab asserts (±150 W tolerance). A tick with no
	// reading counts as a sample error, not a violation.
	if constraint != nil {
		m.ConsTicks++
		sample.Constraint = fmt.Sprintf("%s ≤ %.0f W", constraint.typ, constraint.limW)
		if gridOK {
			switch constraint.typ {
			case "exportCap":
				sample.Violation = -gridW > constraint.limW+complianceTolW
			case "importCap":
				sample.Violation = gridW > constraint.limW+complianceTolW
			case "genLimit":
				sample.Violation = solarW > constraint.limW+complianceTolW
			}
		}
		// A miss the hub has reported it cannot meet (CannotComply alert for this
		// control) is a resource limit, not a control failure — excuse it from the
		// violation count. A silent miss still counts. Checked only on a miss, so
		// the extra gridsim call is rare.
		if sample.Violation && d.reportedCannotComply(constraint.mrid) {
			sample.Violation = false
			sample.Excused = true
			m.Excused++
		}
		if sample.Violation {
			m.Violations++
		}
		m.Compliance = round2(100 * (1 - float64(m.Violations)/float64(m.ConsTicks)))
	}

	d.status.Tick = t + 1 - d.status.StartDay*replayTPD
	d.status.Day = t / replayTPD
	d.status.Date = simLabel
	d.status.SimTime = simLabel
	d.status.Pct = float64(d.status.Tick) / float64(d.status.TotalTicks) * 100
	d.status.EtaS = (d.status.TotalTicks - d.status.Tick) * d.status.TickMs / 1000

	// Log the potential coherent with the actual above (same sim snapshot), so
	// solar_curtailed_kW = possible − actual is exact and never negative.
	env.possibleSolarW = possibleW
	d.writeTickRow(t, price, sample, env, gridOK)

	d.status.Samples = append(d.status.Samples, sample)
	if len(d.status.Samples) > 400 {
		d.status.Samples = d.status.Samples[len(d.status.Samples)-400:]
	}
}

// ── Per-tick DER trace (CSV) ───────────────────────────────────────────────────

// tickLogHeader documents the sign conventions in the column names themselves so
// the shared file is self-describing:
//
//	battery — positive discharging, negative charging
//	net_grid — positive importing from grid, negative exporting
//	solar/ev_draw/site_load — positive
var tickLogHeader = []string{
	"tick", "sim_time", "price_$/kWh",
	"solar_kW", "solar_possible_kW", "solar_curtailed_kW",
	"battery_kW(+dis/-chg)", "battery_soc_%",
	"ev_connected", "ev_soc_%", "ev_draw_kW",
	"site_load_kW", "net_grid_kW(+imp/-exp)",
	"constraint", "violation", "excused",
}

// openTickLog creates the per-tick CSV for this run and writes the header.
// A failure here is non-fatal: the replay still runs and the in-memory samples
// remain; only the shareable file is missing, which is logged.
func (d *replayDriver) openTickLog() {
	path := fmt.Sprintf("replay-ticklog-%s.csv", time.Now().Format("20060102-150405"))
	f, err := os.Create(path)
	if err != nil {
		log.Printf("replay: could not create tick log %s: %v", path, err)
		return
	}
	d.mu.Lock()
	d.tickLogFile = f
	d.tickLogCSV = csv.NewWriter(f)
	d.status.TickLogPath = path
	d.mu.Unlock()
	_ = d.tickLogCSV.Write(tickLogHeader)
	d.tickLogCSV.Flush()
	log.Printf("replay: per-tick DER trace → %s", path)
}

// writeTickRow appends one DER-detail row for tick t. Caller holds d.mu.
// kW fields are blanked when the underlying reading was unavailable, so a
// sample error is visibly distinct from a true zero.
func (d *replayDriver) writeTickRow(t int, price float64, s replaySample, env tickEnv, gridOK bool) {
	if d.tickLogCSV == nil {
		return
	}
	kW := func(w float64) string { return strconv.FormatFloat(w/1000, 'f', 3, 64) }
	pct := func(p float64) string { return strconv.FormatFloat(p, 'f', 1, 64) }
	curtailed := env.possibleSolarW - s.SolarW
	if curtailed < 0 {
		curtailed = 0
	}
	netGrid := kW(s.GridW)
	if !gridOK {
		netGrid = "" // meter unreachable this tick — distinguish from a real 0 kW
	}
	evConn := "0"
	if env.evConnected {
		evConn = "1"
	}
	violation := "0"
	if s.Violation {
		violation = "1"
	}
	excused := "0"
	if s.Excused {
		excused = "1"
	}
	row := []string{
		strconv.Itoa(t), s.SimTime, strconv.FormatFloat(price, 'f', 2, 64),
		kW(s.SolarW), kW(env.possibleSolarW), kW(curtailed),
		kW(s.BatteryW), pct(s.BatSOC),
		evConn, pct(s.EvSOC), kW(s.EvW),
		kW(env.siteLoadW), netGrid,
		s.Constraint, violation, excused,
	}
	_ = d.tickLogCSV.Write(row)
	d.tickLogCSV.Flush() // flush each tick so an aborted/crashed run keeps its trace
}

// closeTickLog flushes and closes the per-tick CSV. Safe to call when no log
// was opened.
func (d *replayDriver) closeTickLog() {
	d.mu.Lock()
	f, cw := d.tickLogFile, d.tickLogCSV
	d.tickLogFile, d.tickLogCSV = nil, nil
	d.mu.Unlock()
	if cw != nil {
		cw.Flush()
	}
	if f != nil {
		_ = f.Close()
	}
}

func round2(v float64) float64 { return math.Round(v*100) / 100 }

// ── Bench I/O helpers ─────────────────────────────────────────────────────────

func (d *replayDriver) url(name, path string) string { return d.backends[name] + path }

func (d *replayDriver) post(name, path string, body map[string]any) error {
	buf, _ := json.Marshal(body)
	req, err := http.NewRequest(http.MethodPost, d.url(name, path), bytes.NewReader(buf))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	setHubAuth(req, name) // TASK-014: token only for name=="hub"
	resp, err := d.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("%s%s: HTTP %d", name, path, resp.StatusCode)
	}
	return nil
}

// postControl POSTs a DERControl to gridsim's admin API and returns the mRID
// gridsim assigned, so the driver can later match the hub's CannotComply
// alerts (keyed by subject mRID) to the control that provoked them.
func (d *replayDriver) postControl(body map[string]any) (string, error) {
	buf, _ := json.Marshal(body)
	resp, err := d.client.Post(d.url("gridsim", "/admin/control"), "application/json", bytes.NewReader(buf))
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return "", fmt.Errorf("gridsim /admin/control: HTTP %d", resp.StatusCode)
	}
	var out struct {
		MRID string `json:"mrid"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return out.MRID, nil
}

// reportedCannotComply reports whether the hub has POSTed a CannotComply
// Response for the given control mRID — i.e. it told the grid server it is
// physically unable to meet that limit (battery at its SOC reserve). Such
// misses are excused from the violation count: a reported resource limit is an
// acceptable outcome, not a control failure. A silent miss (no alert) still
// counts. Empty mrid never matches.
func (d *replayDriver) reportedCannotComply(mrid string) bool {
	if mrid == "" {
		return false
	}
	var out struct {
		Alerts []struct {
			Subject string `json:"subject"`
		} `json:"alerts"`
	}
	if err := d.getJSON("gridsim", "/admin/alerts", &out); err != nil {
		return false
	}
	for _, a := range out.Alerts {
		if a.Subject == mrid {
			return true
		}
	}
	return false
}

func (d *replayDriver) getJSON(name, path string, out any) error {
	req, err := http.NewRequest(http.MethodGet, d.url(name, path), nil)
	if err != nil {
		return err
	}
	setHubAuth(req, name) // TASK-014: token only for name=="hub"
	resp, err := d.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("%s%s: HTTP %d", name, path, resp.StatusCode)
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

func (d *replayDriver) deleteControls(program int) error {
	buf, _ := json.Marshal(map[string]int{"program": program})
	req, _ := http.NewRequest(http.MethodDelete, d.url("gridsim", "/admin/control"), bytes.NewReader(buf))
	req.Header.Set("Content-Type", "application/json")
	resp, err := d.client.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}

// solarSim reads the solar sim's own /state at sample time, returning the
// inverter's committed output and its pre-curtailment potential from the SAME
// register snapshot. Sourcing both here — rather than the hub's cached /status
// for "actual" and the injected Pv[t] for "possible" — keeps them on one clock,
// so the ticklog can never show actual > possible and the genLimit check is
// judged on the inverter's real committed watts instead of a stale telemetry
// reading that lags on the solar curve's falling limb.
func (d *replayDriver) solarSim() (actualW, possibleW float64, ok bool) {
	var st struct {
		Measurements struct {
			W_W       float64 `json:"W_W"`
			PossibleW float64 `json:"possible_W"`
		} `json:"measurements"`
	}
	if err := d.getJSON("solar", "/state", &st); err != nil {
		return 0, 0, false
	}
	return st.Measurements.W_W, st.Measurements.PossibleW, true
}

func (d *replayDriver) meterW() (float64, bool) {
	var st struct {
		Measurements struct {
			W float64 `json:"W_W"`
		} `json:"measurements"`
	}
	if err := d.getJSON("meter", "/state", &st); err != nil {
		return 0, false
	}
	return st.Measurements.W, true
}

type hubSnap struct {
	solarW, batteryW, evW float64
	batSOC, evSOC         float64
	decisions             []string
}

func (d *replayDriver) hubSnapshot() hubSnap {
	var st struct {
		Power struct {
			SolarW   float64 `json:"solar_W"`
			BatteryW float64 `json:"battery_W"`
		} `json:"power"`
		Devices map[string]struct {
			Role   string  `json:"role"`
			SocPct float64 `json:"soc_pct"`
		} `json:"devices"`
		EvseStations []struct {
			PowerW float64 `json:"power_W"`
			SocPct float64 `json:"soc_pct"`
		} `json:"evse_stations"`
		LastPlan struct {
			Decisions []struct {
				Rule   string `json:"rule"`
				Reason string `json:"reason"`
				Impact string `json:"impact"`
			} `json:"decisions"`
		} `json:"last_plan"`
	}
	var snap hubSnap
	if err := d.getJSON("hub", "/status", &st); err != nil {
		return snap
	}
	snap.solarW = st.Power.SolarW
	snap.batteryW = st.Power.BatteryW
	for _, dev := range st.Devices {
		if dev.Role == "battery" {
			snap.batSOC = dev.SocPct
		}
	}
	for _, e := range st.EvseStations {
		snap.evW += e.PowerW
		if e.SocPct > 0 {
			snap.evSOC = e.SocPct
		}
	}
	for _, dec := range st.LastPlan.Decisions {
		snap.decisions = append(snap.decisions, fmt.Sprintf("[%s] %s → %s", dec.Rule, dec.Reason, dec.Impact))
	}
	return snap
}

func (d *replayDriver) evCapacityKWh() float64 {
	var st struct {
		Battery struct {
			CapacityWh float64 `json:"capacity_Wh"`
		} `json:"battery"`
	}
	if err := d.getJSON("ev", "/state", &st); err != nil || st.Battery.CapacityWh <= 0 {
		return 60 // sane default
	}
	return st.Battery.CapacityWh / 1000
}

func (d *replayDriver) evSOCPct() float64 {
	var st struct {
		Battery struct {
			SocPct float64 `json:"soc_pct"`
		} `json:"battery"`
	}
	if err := d.getJSON("ev", "/state", &st); err != nil {
		return 60
	}
	return st.Battery.SocPct
}

// setupBench freezes animations, links the meter, sets device sim speeds to
// the replay rate, and clears stale grid state.
func (d *replayDriver) setupBench(speed float64) error {
	// Gridsim must be reachable — it is the clock.
	if err := d.post("gridsim", "/admin/clock", map[string]any{"offset_s": 0}); err != nil {
		return fmt.Errorf("gridsim admin: %w", err)
	}
	for prog := 0; prog <= 2; prog++ {
		_ = d.deleteControls(prog)
	}
	if err := d.post("solar", "/control", map[string]any{"cmd": "pause"}); err != nil {
		return fmt.Errorf("solar sim: %w", err)
	}
	if err := d.post("meter", "/control", map[string]any{"cmd": "resume"}); err != nil {
		return fmt.Errorf("meter sim: %w", err)
	}
	// Battery: known SOC, connected, animation integrating at replay speed.
	_ = d.post("battery", "/inject", map[string]any{"SoC_pct": 50, "Conn": 1})
	if err := d.post("battery", "/control", map[string]any{"cmd": "resume", "speed": speed}); err != nil {
		return fmt.Errorf("battery sim: %w", err)
	}
	_ = d.post("ev", "/inject", map[string]any{"action": "set_sim_speed", "speed": speed})
	_ = d.post("ev", "/inject", map[string]any{"action": "stop_session", "connector_id": 1})
	return nil
}

// restoreBench returns every backend to normal demo state.
func (d *replayDriver) restoreBench() {
	_ = d.post("gridsim", "/admin/clock", map[string]any{"offset_s": 0})
	for prog := 0; prog <= 2; prog++ {
		_ = d.deleteControls(prog)
	}
	_ = d.post("solar", "/control", map[string]any{"cmd": "resume", "speed": 1})
	_ = d.post("battery", "/inject", map[string]any{"Conn": 1, "WMaxLimPct_pct": 0})
	_ = d.post("battery", "/control", map[string]any{"cmd": "resume", "speed": 1})
	_ = d.post("meter", "/control", map[string]any{"cmd": "resume"})
	_ = d.post("ev", "/inject", map[string]any{"action": "stop_session", "connector_id": 1})
	_ = d.post("ev", "/inject", map[string]any{"action": "set_sim_speed", "speed": 1})
	log.Printf("replay: bench restored (clock 0, programs cleared, sims at 1×)")
}

func (d *replayDriver) finish(aborted bool, errMsg string) {
	d.closeTickLog()
	d.mu.Lock()
	d.status.Running = false
	d.status.Finished = !aborted && errMsg == ""
	d.status.Aborted = aborted
	if errMsg != "" {
		d.status.LastError = errMsg
	}
	if c := d.status.Measured.ConsTicks; c > 0 {
		d.status.Measured.Compliance = round2(100 * (1 - float64(d.status.Measured.Violations)/float64(c)))
	} else {
		d.status.Measured.Compliance = 100
	}
	d.mu.Unlock()
	d.checkpoint()
	log.Printf("replay: done (aborted=%v err=%q) — measured net $%.2f, compliance %.1f%%",
		aborted, errMsg, d.status.Measured.NetUSD, d.status.Measured.Compliance)
}

func (d *replayDriver) fail(msg string) {
	log.Printf("replay: FAILED — %s", msg)
	d.finish(false, msg)
}

func (d *replayDriver) checkpoint() {
	d.mu.Lock()
	data, err := json.MarshalIndent(d.status, "", " ")
	d.mu.Unlock()
	if err == nil {
		_ = os.WriteFile(d.checkpointPath, data, 0o644)
	}
}
