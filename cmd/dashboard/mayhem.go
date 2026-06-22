// Mayhem driver: a hardware-in-the-loop fault-injection suite that drives the
// real bench (all the Pis) through the worst conditions a home DERMS hub could
// see — aggressive grid caps with no headroom, devices that ACK a command
// before acting on it, a sensor that freezes, a clock that lurches, a battery
// pinned full or empty, and finally all of it at once.
//
// Unlike the replay driver (which measures cost/compliance over a benign
// summer), mayhem is adversarial and DIAGNOSTIC: each scenario declares the
// behaviour a correct hub must show (an oracle), samples reality continuously,
// and then explains *exactly* where the hub's fault handling broke — did it
// even adopt the event, did it command a correction, did the device comply, did
// it admit it could not (CannotComply), or was it flying blind on stale data.
//
// Runs server-side so a multi-minute run survives the dashboard tab closing.
// One run at a time. It restores the bench on finish/abort.
//
//	POST /api/qa/start   {sample_ms?, only?:[ids]}
//	GET  /api/qa/status
//	POST /api/qa/abort
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"math"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

const (
	mayDefaultSampleMs = 1000 // sampling cadence during a scenario hold
	mayReactThreshW    = 250  // possible − actual solar above this ⇒ hub commanded curtailment
	mayStaleVarW       = 50   // meter range below this over a window ⇒ reading is frozen
	mayRestoreFracOK   = 0.95 // solar must return to ≥95% of potential to count as recovered

	// A breach is only a control failure if it PERSISTS. The hub's sticky guard
	// ramps a curtailment down over several orchestrator ticks, so the opening
	// seconds of a cap are legitimately over-limit even when the hub converges
	// perfectly. These two thresholds let the diagnosers tell a normal settling
	// ramp apart from a hub that never converges.
	mayConvergeDeadlineS = 30 // breach that clears within this many seconds ⇒ a normal settling ramp, not a failure
	mayConvergeHoldS     = 10 // the cap must stay within-limit for this many trailing seconds to count as converged
)

// ── Result types ──────────────────────────────────────────────────────────────

// maySample is one observation of the whole bench during a scenario.
type maySample struct {
	T         float64 `json:"t"` // seconds since scenario start
	RealGridW float64 `json:"real_grid_W"`
	GridOK    bool    `json:"grid_ok"`
	HubGridW  float64 `json:"hub_grid_W"`

	SolarW         float64 `json:"solar_W"`
	SolarPossibleW float64 `json:"solar_possible_W"`
	SolarOK        bool    `json:"solar_ok"`

	BatteryW float64 `json:"battery_W"`
	BatSOC   float64 `json:"bat_soc"`
	EvW      float64 `json:"ev_W"`
	EvSOC    float64 `json:"ev_soc"`

	HubReachable     bool    `json:"hub_reachable"`
	HubAdopted       bool    `json:"hub_adopted"`       // hub is applying a CSIP control this tick
	DisconnectActive bool    `json:"disconnect_active"` // a cease-to-energize (Connect=false) control is in force
	AdoptedTyp       string  `json:"adopted_typ"`       // exportCap|importCap|genLimit|fixed|connect
	AdoptedLimW      float64 `json:"adopted_lim_W"`
	AdoptedMRID      string  `json:"adopted_mrid"`
	ClockOffsetS     int64   `json:"clock_offset_s"`

	CannotComply bool     `json:"cannot_comply"` // hub posted a CannotComply for the active mRID
	Decisions    []string `json:"decisions,omitempty"`
}

// mayMetrics is the quantified outcome of a scenario.
type mayMetrics struct {
	Samples          int     `json:"samples"`
	SampleErrors     int     `json:"sample_errors"`
	BreachSeconds    float64 `json:"breach_seconds"`
	PeakBreachW      float64 `json:"peak_breach_W"`
	RecoverySeconds  float64 `json:"recovery_seconds"`  // -1 = n/a or never recovered
	ConvergedAtS     float64 `json:"converged_at_s"`    // earliest time after which every sample is within cap; -1 = never
	TailClean        bool    `json:"tail_clean"`        // the last mayConvergeHoldS seconds are all within cap
	BreachConverging bool    `json:"breach_converging"` // breach is shrinking toward the cap (a slew), not holding flat (an ignore)
	HubAdopted       bool    `json:"hub_adopted"`
	HubReacted       bool    `json:"hub_reacted"`
	ReportedCannot   bool    `json:"reported_cannot_comply"`
	HubBlind         bool    `json:"hub_blind"`
}

// mayFinding is the per-scenario verdict plus the root-cause story.
type mayFinding struct {
	ID         string     `json:"id"`
	Name       string     `json:"name"`
	Category   string     `json:"category"`
	Hypothesis string     `json:"hypothesis"` // the real-world fault this represents
	Expected   string     `json:"expected"`   // the oracle: what a correct hub does
	Verdict    string     `json:"verdict"`    // PASS|DEGRADED|FAIL|BLIND|INCONCLUSIVE
	Headline   string     `json:"headline"`
	Diagnosis  []string   `json:"diagnosis"` // bullet points: exactly what went wrong
	Fix        string     `json:"fix"`       // where in the product to look
	Metrics    mayMetrics `json:"metrics"`
}

type maySummary struct {
	Pass         int     `json:"pass"`
	Degraded     int     `json:"degraded"`
	Fail         int     `json:"fail"`
	Blind        int     `json:"blind"`
	Inconclusive int     `json:"inconclusive"`
	TotalBreachS float64 `json:"total_breach_seconds"`
	WorstPeakW   float64 `json:"worst_peak_breach_W"`
}

type mayhemStatus struct {
	Running    bool         `json:"running"`
	Finished   bool         `json:"finished"`
	Aborted    bool         `json:"aborted"`
	LastError  string       `json:"last_error,omitempty"`
	StartedAt  time.Time    `json:"started_at"`
	Current    string       `json:"current"`
	CurrentID  string       `json:"current_id"`
	Idx        int          `json:"idx"`
	Total      int          `json:"total"`
	Pct        float64      `json:"pct"`
	Phase      string       `json:"phase"` // setup|hold|recover|done
	ReportPath string       `json:"report_path,omitempty"`
	Summary    maySummary   `json:"summary"`
	Findings   []mayFinding `json:"findings"`
	Live       []maySample  `json:"live"` // recent samples of the running scenario
}

// ── Driver ────────────────────────────────────────────────────────────────────

type mayhemDriver struct {
	mu       sync.Mutex
	backends map[string]string
	client   *http.Client
	status   mayhemStatus
	cancel   context.CancelFunc

	// pvHighW is the "full sun" PV setpoint, capped just under the inverter
	// nameplate read at baseline. Injecting above nameplate would make the
	// inverter's reported potential unreachable, falsely tripping the
	// curtailment-detection and recovery oracles.
	pvHighW float64
}

func newMayhemDriver(backends map[string]string) *mayhemDriver {
	return &mayhemDriver{
		backends: backends,
		client:   &http.Client{Timeout: 3 * time.Second},
	}
}

// activeConstraint is the grid limit a scenario is judged against.
type activeConstraint struct {
	Typ  string // exportCap|importCap|genLimit|none
	LimW float64
	MRID string
}

// mayScenario is one adversarial test: arm the fault(s), hold while sampling,
// tear the fault down, then diagnose. perTick (optional) re-applies a fault that
// must persist or evolve across the hold (injected PV, a lurching clock).
type mayScenario struct {
	ID         string
	Name       string
	Category   string
	Hypothesis string
	Expected   string
	HoldS      int
	Fix        string

	setup    func(d *mayhemDriver) (*activeConstraint, error)
	perTick  func(d *mayhemDriver, i int)
	evaluate func(sc *mayScenario, cons *activeConstraint, s []maySample) mayFinding
	teardown func(d *mayhemDriver)
}

// ── HTTP endpoints ────────────────────────────────────────────────────────────

type mayhemStartReq struct {
	SampleMs int      `json:"sample_ms"`
	Only     []string `json:"only"` // run only these scenario IDs (empty = all)
}

func (d *mayhemDriver) handleStart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var req mayhemStartReq
	_ = json.NewDecoder(r.Body).Decode(&req) // empty body ⇒ defaults
	if req.SampleMs < 200 {
		req.SampleMs = mayDefaultSampleMs
	}

	scenarios := d.scenarios()
	if len(req.Only) > 0 {
		want := map[string]bool{}
		for _, id := range req.Only {
			want[id] = true
		}
		filtered := scenarios[:0:0]
		for _, sc := range scenarios {
			if want[sc.ID] {
				filtered = append(filtered, sc)
			}
		}
		scenarios = filtered
	}
	if len(scenarios) == 0 {
		http.Error(w, "no matching scenarios", http.StatusBadRequest)
		return
	}

	d.mu.Lock()
	if d.status.Running {
		d.mu.Unlock()
		http.Error(w, "a mayhem run is already in progress", http.StatusConflict)
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	d.cancel = cancel
	d.status = mayhemStatus{
		Running:   true,
		StartedAt: time.Now(),
		Total:     len(scenarios),
		Phase:     "setup",
	}
	d.mu.Unlock()

	go d.run(ctx, scenarios, time.Duration(req.SampleMs)*time.Millisecond)
	w.WriteHeader(http.StatusAccepted)
	_ = json.NewEncoder(w).Encode(map[string]any{"scenarios": len(scenarios), "sample_ms": req.SampleMs})
}

func (d *mayhemDriver) handleStatus(w http.ResponseWriter, r *http.Request) {
	d.mu.Lock()
	st := d.status
	st.Findings = append([]mayFinding(nil), d.status.Findings...)
	st.Live = append([]maySample(nil), d.status.Live...)
	d.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(st)
}

func (d *mayhemDriver) handleAbort(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	d.mu.Lock()
	cancel, running := d.cancel, d.status.Running
	d.mu.Unlock()
	if running && cancel != nil {
		cancel()
	}
	w.WriteHeader(http.StatusAccepted)
}

// ── Run loop ──────────────────────────────────────────────────────────────────

func (d *mayhemDriver) run(ctx context.Context, scenarios []*mayScenario, sample time.Duration) {
	log.Printf("mayhem: starting — %d scenarios, %v sampling", len(scenarios), sample)
	defer d.restoreBench()

	if err := d.baseline(); err != nil {
		d.fail(fmt.Sprintf("bench baseline failed: %v", err))
		return
	}

	for i, sc := range scenarios {
		select {
		case <-ctx.Done():
			d.finish(true, "")
			return
		default:
		}

		d.setPhase(i, sc, "setup")
		log.Printf("mayhem: [%d/%d] %s — %s", i+1, len(scenarios), sc.ID, sc.Name)

		cons := &activeConstraint{Typ: "none"}
		if sc.setup != nil {
			c, err := sc.setup(d)
			if err != nil {
				d.appendFinding(mayFinding{
					ID: sc.ID, Name: sc.Name, Category: sc.Category,
					Hypothesis: sc.Hypothesis, Expected: sc.Expected,
					Verdict:   "INCONCLUSIVE",
					Headline:  "could not arm the fault",
					Diagnosis: []string{fmt.Sprintf("Setup failed: %v. The bench may be down or a sim unreachable — fix connectivity and re-run.", err)},
					Fix:       sc.Fix,
				})
				if sc.teardown != nil {
					sc.teardown(d)
				}
				continue
			}
			if c != nil {
				cons = c
			}
		}

		// Hold the fault, sampling reality.
		d.setPhase(i, sc, "hold")
		samples := d.holdAndSample(ctx, sc, cons, sample)

		// Release the fault and clear any controls before judging recovery.
		d.setPhase(i, sc, "recover")
		if sc.teardown != nil {
			sc.teardown(d)
		}

		ev := sc.evaluate
		if ev == nil {
			ev = diagnoseConstraint
		}
		f := ev(sc, cons, samples)
		f.Fix = sc.Fix
		d.appendFinding(f)

		if ctx.Err() != nil {
			d.finish(true, "")
			return
		}
	}
	d.finish(false, "")
}

// holdAndSample runs the scenario hold, calling perTick before each sample so a
// persistent/evolving fault keeps biting, and returns the sample timeline.
func (d *mayhemDriver) holdAndSample(ctx context.Context, sc *mayScenario, cons *activeConstraint, interval time.Duration) []maySample {
	ticks := int(float64(sc.HoldS) * float64(time.Second) / float64(interval))
	if ticks < 1 {
		ticks = 1
	}
	start := time.Now()
	var samples []maySample
	d.clearLive()
	for i := 0; i < ticks; i++ {
		if sc.perTick != nil {
			sc.perTick(d, i)
		}
		select {
		case <-ctx.Done():
			return samples
		case <-time.After(interval):
		}
		s := d.sample(cons, time.Since(start).Seconds())
		samples = append(samples, s)
		d.pushLive(s)
	}
	return samples
}

// ── Sampling ──────────────────────────────────────────────────────────────────

func (d *mayhemDriver) sample(cons *activeConstraint, t float64) maySample {
	s := maySample{T: round2(t)}

	if gridW, ok := d.meterW(); ok {
		s.RealGridW, s.GridOK = gridW, true
	}
	if aw, pw, ok := d.solarSim(); ok {
		s.SolarW, s.SolarPossibleW, s.SolarOK = aw, pw, true
	}

	hub := d.hubState()
	s.HubReachable = hub.ok
	if hub.ok {
		s.HubGridW = hub.gridW
		s.BatteryW = hub.batteryW
		s.BatSOC = hub.batSOC
		s.EvW = hub.evW
		s.EvSOC = hub.evSOC
		s.ClockOffsetS = hub.clockOffsetS
		s.Decisions = hub.decisions
		if hub.ctrlActive {
			s.HubAdopted = true
			s.AdoptedTyp = hub.ctrlTyp
			s.AdoptedLimW = hub.ctrlLimW
			s.AdoptedMRID = hub.ctrlMRID
		}
		s.DisconnectActive = hub.disconnectActive
	}
	// A CannotComply alert is only meaningful while a real control is in force.
	if cons != nil && cons.MRID != "" {
		s.CannotComply = d.reportedCannotComply(cons.MRID)
	}
	return s
}

// ── Diagnosers (pure; unit-tested in mayhem_test.go) ──────────────────────────

func baseFinding(sc *mayScenario) mayFinding {
	return mayFinding{
		ID: sc.ID, Name: sc.Name, Category: sc.Category,
		Hypothesis: sc.Hypothesis, Expected: sc.Expected,
	}
}

// breachOver returns how far (W) a sample is past the constraint, or a negative
// number when within limit / not applicable.
func breachOver(cons *activeConstraint, s maySample) float64 {
	tol := float64(complianceTolW)
	switch cons.Typ {
	case "exportCap":
		if !s.GridOK {
			return -1
		}
		return (-s.RealGridW) - (cons.LimW + tol)
	case "importCap":
		if !s.GridOK {
			return -1
		}
		return s.RealGridW - (cons.LimW + tol)
	case "genLimit":
		if !s.SolarOK {
			return -1
		}
		return s.SolarW - (cons.LimW + tol)
	}
	return -1
}

// scanSamples computes the shared metrics every constraint diagnoser needs.
func scanSamples(cons *activeConstraint, s []maySample) mayMetrics {
	var m mayMetrics
	m.Samples = len(s)
	m.RecoverySeconds = -1
	var prevT float64
	adopted, reacted := 0, 0
	for i, smp := range s {
		if !smp.GridOK {
			m.SampleErrors++
		}
		if smp.HubAdopted && smp.AdoptedTyp == cons.Typ {
			adopted++
		}
		if smp.CannotComply {
			m.ReportedCannot = true
		}
		if smp.SolarOK && smp.SolarPossibleW-smp.SolarW > mayReactThreshW {
			reacted++
		}
		if over := breachOver(cons, smp); over > 0 {
			dt := smp.T - prevT
			if i == 0 {
				dt = 0
			}
			m.BreachSeconds += dt
			if over > m.PeakBreachW {
				m.PeakBreachW = over
			}
		}
		prevT = smp.T
	}
	m.BreachSeconds = round2(m.BreachSeconds)
	m.PeakBreachW = round2(m.PeakBreachW)
	m.HubAdopted = adopted > 0
	m.HubReacted = reacted > len(s)/4
	m.ConvergedAtS, m.TailClean = convergence(cons, s)
	m.BreachConverging = breachConverging(cons, s)
	// NOTE: HubBlind is intentionally NOT derived from hub-vs-meter grid
	// divergence here. The hub_grid value is lexa-api's MQTT-relayed display,
	// which lags the meter's direct register during fast changes — the optimizer
	// sees the same relayed value, so it is poll/relay latency that resolves, not
	// blindness. Genuine sensor-blindness (a frozen/dead source) is judged by
	// diagnoseStale instead. The divergence is still surfaced as an informational
	// note (hubVsRealLine) so a real persistent gap is visible.
	return m
}

// convergence distinguishes a transient settling ramp from a sustained breach.
// convergedAtS is the earliest sample time after which EVERY remaining sample is
// within the cap (−1 if it is still breaching at the end). tailClean is true when
// the last mayConvergeHoldS seconds are all within the cap — the evidence that the
// hub actually reached and HELD the limit rather than dipping under it once.
func convergence(cons *activeConstraint, s []maySample) (convergedAtS float64, tailClean bool) {
	if len(s) == 0 {
		return -1, false
	}
	lastBreach := -1
	for i, smp := range s {
		if breachOver(cons, smp) > 0 {
			lastBreach = i
		}
	}
	switch {
	case lastBreach < 0:
		convergedAtS = 0 // never breached
	case lastBreach < len(s)-1:
		convergedAtS = s[lastBreach+1].T
	default:
		convergedAtS = -1 // breaching at the very end
	}

	endT := s[len(s)-1].T
	sawTail := false
	tailClean = true
	for _, smp := range s {
		if smp.T < endT-mayConvergeHoldS {
			continue
		}
		sawTail = true
		if breachOver(cons, smp) > 0 {
			tailClean = false
			break
		}
	}
	if !sawTail {
		tailClean = false
	}
	return convergedAtS, tailClean
}

// breachConverging reports whether a constraint breach is trending toward
// compliance — the overage late in the window is well below its peak — rather
// than holding flat over the limit. It is the signature that separates a device
// SLEWING to the limit (ramp_limit: the overage shrinks toward zero) from one
// IGNORING it (reject_write/enable_gate: the overage stays near its peak). The
// diagnosers use it to call a still-settling slew DEGRADED rather than a FAIL,
// independent of exactly where the observation window happens to end.
func breachConverging(cons *activeConstraint, s []maySample) bool {
	if len(s) < 4 {
		return false
	}
	var peakOver float64
	for _, smp := range s {
		if o := breachOver(cons, smp); o > peakOver {
			peakOver = o
		}
	}
	if peakOver <= 0 {
		return false // no real breach to converge from
	}
	// Mean overage over the last few samples (≥0), smoothing single-sample noise.
	n := 3
	if n > len(s) {
		n = len(s)
	}
	var tail float64
	for _, smp := range s[len(s)-n:] {
		if o := breachOver(cons, smp); o > 0 {
			tail += o
		}
	}
	tail /= float64(n)
	return tail < 0.5*peakOver
}

// diagnoseConstraint is the core fault analyser for export/import/gen-cap
// scenarios. It walks the adoption → reaction → compliance → admission chain and
// names the first broken link.
func diagnoseConstraint(sc *mayScenario, cons *activeConstraint, s []maySample) mayFinding {
	f := baseFinding(sc)
	if len(s) == 0 {
		f.Verdict = "INCONCLUSIVE"
		f.Headline = "no samples collected (aborted before any reading)"
		return f
	}
	m := scanSamples(cons, s)
	f.Metrics = m
	capStr := fmt.Sprintf("%s ≤ %.0f W", cons.Typ, cons.LimW)

	if m.SampleErrors > len(s)/2 {
		f.Verdict = "INCONCLUSIVE"
		f.Headline = "meter unreachable for most of the run — cannot judge compliance"
		f.Diagnosis = []string{
			fmt.Sprintf("The grid meter failed to read on %d of %d samples. Bring the meter sim back and re-run; an unjudgeable scenario is itself a monitoring gap.", m.SampleErrors, len(s)),
		}
		return f
	}

	if m.BreachSeconds == 0 {
		f.Verdict = "PASS"
		f.Headline = fmt.Sprintf("held %s under worst-case conditions", capStr)
		f.Diagnosis = []string{
			fmt.Sprintf("No breach across %d samples (%.0fs). Hub adopted=%v, commanded a correction=%v.", len(s), s[len(s)-1].T, m.HubAdopted, m.HubReacted),
		}
		return f
	}

	// There WAS a breach. Walk the chain to name the broken link.
	f.Headline = fmt.Sprintf("%s exceeded by up to %.0f W for %.0fs", capStr, m.PeakBreachW, m.BreachSeconds)
	diag := []string{
		fmt.Sprintf("Constraint: %s (mRID %s). Peak overshoot %.0f W, total %.0fs out of limit.", capStr, shortMRID(cons.MRID), m.PeakBreachW, m.BreachSeconds),
	}

	switch {
	case m.ReportedCannot:
		// Admitting the limit via CannotComply is the acceptable outcome and
		// outranks which lever it used — a forced import with an empty battery
		// has no correction to make, only an admission. Checked before the
		// reaction branches so that case is not mislabeled a control failure.
		f.Verdict = "DEGRADED"
		diag = append(diag,
			"The hub posted a CannotComply for this control — it hit a physical limit (battery at its SOC bound, or PV already at zero) and admitted it to the grid server.",
			"This is acceptable behaviour: the breach is a reported resource limit, not a hidden control failure.")
		f.Fix = "No code fix required; confirm the CannotComply reason matches the real limiting device."
	case !m.HubAdopted:
		f.Verdict = "FAIL"
		diag = append(diag,
			"The hub never adopted the control: its /status csip_control did not reflect "+cons.Typ+" for any sample.",
			"Root cause is upstream of optimization — CSIP discovery, event activation, or DERControl adoption. The optimizer was never told to act.")
		f.Fix = "Trace northbound discovery/walker → scheduler adoption for this mRID; the event was posted to gridsim but never took effect in the hub."
	case m.TailClean && m.ConvergedAtS >= 0:
		// The breach was a transient: the hub drove the system within the cap and
		// HELD it for the tail of the window. Judge by how fast it settled, not by
		// the mere existence of an opening ramp — a sticky-guard curtailment that
		// resolves is correct closed-loop behaviour, not a failure.
		if m.ConvergedAtS <= mayConvergeDeadlineS {
			f.Verdict = "PASS"
			f.Headline = fmt.Sprintf("held %s after a %.0fs convergence ramp", capStr, m.ConvergedAtS)
			diag = append(diag,
				fmt.Sprintf("The hub adopted the control and drove the system within the cap %.0fs in, then held it for the rest of the window (peak transient %.0f W during the ramp).", m.ConvergedAtS, m.PeakBreachW),
				"A bounded settling ramp is expected closed-loop behaviour, not a control failure.")
			f.Fix = "No code fix required — the breach was a transient convergence ramp that resolved within the deadline."
		} else {
			f.Verdict = "DEGRADED"
			f.Headline = fmt.Sprintf("converged on %s but slowly (%.0fs, deadline %ds)", capStr, m.ConvergedAtS, mayConvergeDeadlineS)
			diag = append(diag,
				fmt.Sprintf("The hub did reach and hold the cap, but only after %.0fs — beyond the %ds settling deadline. Output was over the limit during that ramp (peak %.0f W).", m.ConvergedAtS, mayConvergeDeadlineS, m.PeakBreachW),
				"Correct end state, sluggish convergence — worth quantifying against your time-to-comply SLA.")
			f.Fix = "Tighten the optimizer's curtailment ramp / sticky-guard time constant if this exceeds the grid SLA for time-to-comply."
		}
	case m.HubAdopted && !m.HubReacted:
		f.Verdict = "FAIL"
		diag = append(diag,
			"The hub adopted the control (it shows in csip_control) but issued no effective correction: solar was not curtailed and the battery did not absorb, and it did NOT post a CannotComply.",
			"The gap is between adoption and actuation — the optimizer either produced no command or the command never reached the device.",
			decisionLine(s))
		f.Fix = "Check the orchestrator plan→command path: did it emit a curtail/charge command for this constraint, and did the Modbus/OCPP bridge deliver it?"
	default:
		f.Verdict = "FAIL"
		diag = append(diag,
			"The hub adopted the control and commanded a correction, but the device did not converge to the limit and the hub did NOT post a CannotComply.",
			"The hub is asserting control it does not actually have: either the command was rejected/ineffective at the device, or it ACKed without taking effect, and the hub never verified convergence.",
			fmt.Sprintf("Peak %.0f W over for %.0fs with no admission of failure.", m.PeakBreachW, m.BreachSeconds))
		f.Fix = "This is the closed-loop gap: add measured-effect verification and emit CannotComply when convergence is not observed within deadline (derbase ApplyControl / OCPP applyCommand)."
	}
	diag = append(diag, invSummaryLine("INV-EXPORT", invExport(cons, s)))
	f.Diagnosis = append(diag, hubVsRealLine(s))
	return f
}

// diagnoseConverge handles the accept-but-don't-converge faults — ack_before_effect
// (the device lags the write) and reject_write (the device ACKs then ignores it
// entirely). In both the device ACKs at the Modbus layer but its output never
// reaches the commanded limit; the question is whether the hub detects that via
// measurement and reports it rather than trusting the write ACK.
func diagnoseConverge(sc *mayScenario, cons *activeConstraint, s []maySample) mayFinding {
	f := diagnoseConstraint(sc, cons, s)
	// Re-frame: a breach here is expected while the device withholds the effect;
	// the verdict turns on whether the hub admitted it.
	if f.Verdict == "PASS" {
		f.Headline = "hub held the cap despite the device withholding the commanded effect"
		f.Diagnosis = append(f.Diagnosis, "Output converged within the cap and held — another lever covered the gap, or the effect arrived before the settling deadline.")
		return f
	}
	if f.Metrics.ReportedCannot {
		f.Verdict = "DEGRADED"
		f.Headline = "device did not honour the ACKed write; hub flagged it"
		f.Diagnosis = append([]string{"The device ACKed the curtailment at the Modbus layer but its output never reached the commanded limit (injected fault). The hub reported the shortfall rather than assuming success — correct."}, f.Diagnosis...)
		return f
	}
	if f.Verdict == "DEGRADED" {
		// The base diagnoser saw the output converge, but only after the device
		// finally honoured the write (past the settling deadline). The hub got
		// there without an explicit admission — acceptable, but slow.
		f.Headline = "device honoured the write late; hub converged once it did"
		f.Diagnosis = append([]string{"The device ACKed the curtailment at the Modbus layer but withheld the effect (injected fault). The hub drove it within the cap only after the effect landed, not on the ACK."}, f.Diagnosis...)
		return f
	}
	if f.Metrics.BreachConverging {
		// The output is slewing toward the cap (the overage shrank well below its
		// peak) but had not fully arrived when the window closed — a bounded slew,
		// not an ignored command. This is a settling-time concern, not blindness;
		// it is distinct from a flat, never-moving breach (which falls through to
		// FAIL below).
		f.Verdict = "DEGRADED"
		f.Headline = "device is slewing to the limit; still converging when the window ended"
		f.Diagnosis = append([]string{
			"The device ACKed the curtailment and its MEASURED output is ramping toward the limit — the overage shrank far below its peak — but it had not fully reached the cap when the window ended. A bounded slew, not an ignored command.",
			"Give the device its rated settling time (longer window) or tighten its slew rate; this is a time-to-comply concern, not a closed-loop blindness.",
		}, f.Diagnosis...)
		return f
	}
	f.Verdict = "FAIL"
	f.Headline = fmt.Sprintf("device ACKed but never honoured the curtailment; hub never reported the %.0fs breach", f.Metrics.BreachSeconds)
	f.Diagnosis = append([]string{
		"The device ACKed the curtailment at the Modbus layer but its output never reached the commanded limit (the injected fault — a lag, or an outright ignore). The hub treated the write as immediately effective.",
		"Because the hub never reads back or measures convergence, it kept reporting compliance while real output stayed over the cap for the whole window.",
	}, f.Diagnosis...)
	f.Fix = "Closed-loop ACK: after a curtailment write, verify the measured output reaches the target within a deadline; if not, escalate / post CannotComply. (derbase ApplyControl is write-only today.)"
	return f
}

// diagnoseStale handles the frozen-sensor scenario: the meter stops updating
// while the world changes underneath the hub.
func diagnoseStale(sc *mayScenario, cons *activeConstraint, s []maySample) mayFinding {
	f := baseFinding(sc)
	if len(s) == 0 {
		f.Verdict = "INCONCLUSIVE"
		f.Headline = "no samples"
		return f
	}
	f.Metrics = scanSamples(cons, s)
	lo, hi := math.Inf(1), math.Inf(-1)
	reads := 0
	for _, smp := range s {
		if smp.GridOK {
			reads++
			lo = math.Min(lo, smp.RealGridW)
			hi = math.Max(hi, smp.RealGridW)
		}
	}
	if reads < 2 {
		f.Verdict = "INCONCLUSIVE"
		f.Headline = "meter did not read — cannot tell frozen from absent"
		return f
	}
	rangeW := hi - lo
	frozen := rangeW < mayStaleVarW

	if !frozen {
		f.Verdict = "PASS"
		f.Headline = "meter kept updating; sensor-freeze fault did not take"
		f.Diagnosis = []string{fmt.Sprintf("Grid reading varied %.0f W over the window — the freeze did not engage, so this run does not test staleness. Confirm the meter sim honoured pause and re-run.", rangeW)}
		return f
	}
	// The meter is frozen. Did the hub keep trusting it?
	f.Metrics.HubBlind = true
	f.Verdict = "BLIND"
	f.Headline = fmt.Sprintf("meter frozen at ~%.0f W while conditions changed; hub kept trusting it", lo)
	f.Diagnosis = []string{
		fmt.Sprintf("The grid meter held within %.0f W for the entire %.0fs window despite the injected PV/load changes — the sensor was effectively dead.", rangeW, s[len(s)-1].T),
		"The hub continued to report and act on the frozen value: it made no stale-data decision and raised no alarm. A frozen sensor is indistinguishable from reality to this hub.",
		"This is the silent-blindness failure: the hub will happily violate any limit whose breach is only visible through the dead sensor.",
		decisionLine(s),
	}
	f.Fix = "Add a staleness/heartbeat check on each measurement source: if a reading stops changing or the device stops responding, mark it stale, fail safe (conservative limits), and surface it."
	return f
}

// diagnoseRecovery handles the device-dropout scenario: the inverter goes away
// mid-event and comes back; does the hub re-establish control and does solar
// return to full?
func diagnoseRecovery(sc *mayScenario, cons *activeConstraint, s []maySample) mayFinding {
	f := baseFinding(sc)
	if len(s) == 0 {
		f.Verdict = "INCONCLUSIVE"
		f.Headline = "no samples"
		return f
	}
	f.Metrics = scanSamples(cons, s)
	// Recovery time: from the last "low solar" sample to the first sample where
	// solar is back to ≥95% of potential and stays there.
	rec := -1.0
	for _, smp := range s {
		if smp.SolarOK && smp.SolarPossibleW > 100 {
			if smp.SolarW >= mayRestoreFracOK*smp.SolarPossibleW {
				if rec < 0 {
					rec = smp.T
				}
			} else {
				rec = -1 // dipped again; reset
			}
		}
	}
	f.Metrics.RecoverySeconds = rec
	last := s[len(s)-1]
	restored := last.SolarOK && last.SolarPossibleW > 100 && last.SolarW >= mayRestoreFracOK*last.SolarPossibleW

	switch {
	case restored && rec >= 0:
		f.Verdict = "PASS"
		f.Headline = fmt.Sprintf("solar recovered to full within %.0fs of the device returning", rec)
		f.Diagnosis = []string{"After the inverter dropped out and returned, output climbed back to its potential and the hub did not leave it stuck curtailed."}
	case !restored:
		f.Verdict = "FAIL"
		f.Headline = "solar left stuck below potential after the device returned"
		f.Diagnosis = []string{
			fmt.Sprintf("At the end of the window solar was %.0f W against a potential of %.0f W — the inverter came back but the hub did not restore it.", last.SolarW, last.SolarPossibleW),
			"This is the stuck-curtailment class: a control set before the dropout was never re-asserted or cleared on the device after it re-registered.",
			"Customers see lost generation indefinitely after a transient device blip.",
		}
		f.Fix = "On device re-registration, re-apply the active control (or clear a stale ceiling). Restore must SET the ceiling, never leave an empty no-op (cf. solarCommandToControl restore path)."
	default:
		f.Verdict = "DEGRADED"
		f.Headline = "solar eventually recovered but slowly / with a dip"
		f.Diagnosis = []string{"Output returned to potential but not monotonically — the hub re-established control with a delay worth quantifying against your SLA."}
	}
	return f
}

// diagnoseSOC handles battery-direction faults (wrong_sign / soc_refuse). A
// flipped battery is doubly dangerous: it can walk the pack out of its SoC
// envelope AND blow the very cap it was meant to help meet — a commanded charge
// that lands as a discharge adds to export instead of soaking it. So it judges
// BOTH axes: INV-SOC (pack discharging at/below the reserve floor or charging
// past the ceiling) and the active cap via INV-EXPORT/INV-CONVERGE (the breach
// the wrong-way discharge causes, and whether the hub admitted it). Judging only
// INV-SOC would let a scenario PASS while the export cap it posted was wide open.
func diagnoseSOC(sc *mayScenario, cons *activeConstraint, s []maySample) mayFinding {
	f := baseFinding(sc)
	if len(s) == 0 {
		f.Verdict = "INCONCLUSIVE"
		f.Headline = "no samples"
		return f
	}
	f.Metrics = scanSamples(cons, s)

	socViol := invSOC(s)
	expViol := invExport(cons, s)
	convViol := invConverge(cons, s) // sustained cap breach with no CannotComply

	// FAIL if the pack left its SoC envelope, or the active cap was breached and
	// never admitted.
	if len(socViol) > 0 || len(convViol) > 0 {
		f.Verdict = "FAIL"
		var diag []string
		if len(socViol) > 0 {
			f.Headline = fmt.Sprintf("battery breached its SoC envelope on %d samples", len(socViol))
			diag = append(diag,
				invSummaryLine("INV-SOC", socViol),
				"The battery moved the wrong way at its SoC bound (a commanded charge landed as a discharge, or vice versa) and the hub did not detect the divergence and halt it.",
				"A hub that trusts its own command without verifying the pack's measured direction will walk a low battery toward empty — the silent-actuation failure INV-SOC exists to catch.")
		} else {
			f.Headline = fmt.Sprintf("wrong-direction battery blew the %s cap by up to %.0f W with no CannotComply", cons.Typ, f.Metrics.PeakBreachW)
			diag = append(diag,
				"The flipped battery discharged into an active export cap instead of charging to relieve it, and the hub never admitted the resulting breach (no CannotComply).")
		}
		// Surface the other axis too so the full picture is visible.
		diag = append(diag, invSummaryLine("INV-CONVERGE", convViol))
		if len(socViol) == 0 {
			diag = append(diag, invSummaryLine("INV-SOC", socViol))
		}
		diag = append(diag, decisionLine(s))
		f.Fix = "Verify measured battery power direction/SoC trend against the commanded sign; halt and alarm when the pack moves opposite to the command (orchestrator battery adapter)."
		f.Diagnosis = append(diag, hubVsRealLine(s))
		return f
	}

	// The cap was breached during the fault but the hub admitted it (CannotComply):
	// honest, though the wrong-direction device still cost compliance headroom.
	if len(expViol) > 0 {
		f.Verdict = "DEGRADED"
		f.Headline = fmt.Sprintf("battery moved the wrong way and breached the %s cap, but the hub admitted it", cons.Typ)
		f.Diagnosis = []string{
			invSummaryLine("INV-EXPORT", expViol),
			"The pack discharged the wrong way under the cap, but the hub posted a CannotComply rather than hiding the breach.",
		}
		return f
	}

	f.Verdict = "PASS"
	f.Headline = "battery stayed within its SoC envelope and held the cap despite the direction fault"
	f.Diagnosis = []string{
		invSummaryLine("INV-SOC", socViol),
		invSummaryLine("INV-EXPORT", expViol),
		"The pack never left its SoC bounds and the active cap held — the hub kept it safe even though the device was commanded the wrong way.",
	}
	return f
}

// diagnoseDisconnect handles the cease-to-energize scenario: the grid commands an
// opModConnect=false control and every controllable DER must stop feeding the
// grid. It judges by INV-CONNECT — after a reaction grace, any solar production
// or battery discharge while the disconnect is in force is an unsafe back-feed.
func diagnoseDisconnect(sc *mayScenario, cons *activeConstraint, s []maySample) mayFinding {
	f := baseFinding(sc)
	if len(s) == 0 {
		f.Verdict = "INCONCLUSIVE"
		f.Headline = "no samples"
		return f
	}
	f.Metrics = scanSamples(cons, s)

	adopted := false
	for _, smp := range s {
		if smp.DisconnectActive {
			adopted = true
			break
		}
	}
	if !adopted {
		f.Verdict = "FAIL"
		f.Headline = "hub never adopted the disconnect"
		f.Diagnosis = []string{
			"No sample showed a cease-to-energize control in force: the hub's /status never reflected opModConnect=false for this mRID.",
			"Root cause is upstream of actuation — CSIP discovery / event activation for a Connect control. The DERs were never told to stop.",
			decisionLine(s),
		}
		f.Fix = "Trace northbound adoption of an opModConnect=false DERControl; the disconnect was posted to gridsim but never took effect in the hub."
		return f
	}

	// Excuse a bounded reaction window, then any energizing DER is a violation.
	var viol []invViolation
	for _, x := range invConnectSafe(s) {
		if x.T > mayConvergeDeadlineS {
			viol = append(viol, x)
		}
	}
	if len(viol) == 0 {
		f.Verdict = "PASS"
		f.Headline = "all DERs ceased to energize under the disconnect"
		f.Diagnosis = []string{
			invSummaryLine("INV-CONNECT", viol),
			"After the disconnect took effect, solar output and battery discharge fell to ~0 and held there — the hub stopped back-feeding a line the utility commanded dead.",
		}
		return f
	}
	f.Verdict = "FAIL"
	f.Headline = fmt.Sprintf("DER still energizing %.0fs into a disconnect", viol[0].T)
	f.Diagnosis = []string{
		invSummaryLine("INV-CONNECT", viol),
		"The hub adopted the cease-to-energize control but a DER kept feeding the grid past the reaction window — the most dangerous failure class: back-feeding a line the utility believes is de-energized.",
		decisionLine(s),
	}
	f.Fix = "On an opModConnect=false control, command every DER to cease energizing (solar WMaxLimPct→0 / disconnect, battery idle, EV stop) and verify measured output reaches ~0 (orchestrator connect handling)."
	return f
}

// diagnoseMalform handles the malformed-resource scenario: a buggy/hostile CSIP
// server serves a non-conformant resource while a safe control is active. The
// hub must CONTAIN the error — never panic/hang, and never drop the safe control
// for garbage or "none". It judges survivability first (did /status keep
// answering), then reuses the constraint oracle to confirm the safe cap held.
func diagnoseMalform(sc *mayScenario, cons *activeConstraint, s []maySample) mayFinding {
	if len(s) == 0 {
		f := baseFinding(sc)
		f.Verdict = "INCONCLUSIVE"
		f.Headline = "no samples"
		return f
	}
	reach := 0
	for _, smp := range s {
		if smp.HubReachable {
			reach++
		}
	}
	if reach < len(s)/2 {
		f := baseFinding(sc)
		f.Metrics = scanSamples(cons, s)
		f.Verdict = "FAIL"
		f.Headline = "hub stopped responding under the malformed resource"
		f.Diagnosis = []string{
			fmt.Sprintf("The hub's /status was unreachable on %d of %d samples after the malformed resource was served — a likely panic, hang, or walker deadlock.", len(s)-reach, len(s)),
			"A buggy or hostile CSIP server must never be able to take the hub down; discovery errors must be contained.",
			decisionLine(s),
		}
		f.Fix = "Harden the northbound walker/parser: bound the walk, validate resources, and fail closed to last-known-good controls on a malformed resource."
		return f
	}

	// Survived. The safety oracle: the safe cap must have HELD — the malform must
	// not have dropped it or replaced it with garbage. Judge by INV-EXPORT (a
	// SUSTAINED, post-deadline breach), which already excuses the hub's normal
	// curtailment settling ramp, and excuse it entirely if the hub admitted via
	// CannotComply. A transient ramp is not a malform failure.
	f := baseFinding(sc)
	f.Metrics = scanSamples(cons, s)
	breaches := invExport(cons, s)
	if len(breaches) == 0 || f.Metrics.ReportedCannot {
		f.Verdict = "PASS"
		f.Headline = "contained the malformed resource and held the safe control"
		f.Diagnosis = []string{
			"The hub stayed up (/status kept answering) and kept enforcing the active export cap despite the malformed resource — the discovery error was contained and the safe control was not replaced by garbage or 'none'.",
			invSummaryLine("INV-EXPORT", breaches),
			hubVsRealLine(s),
		}
		return f
	}
	f.Verdict = "FAIL"
	f.Headline = "malformed resource unseated the safe control"
	f.Diagnosis = []string{
		invSummaryLine("INV-EXPORT", breaches),
		"The malformed resource was served while a safe export cap was active, and the cap was then sustained-breached with no CannotComply — the bad resource dropped or corrupted the safe control instead of being contained.",
		decisionLine(s),
	}
	f.Fix = "Harden the northbound walker/parser; on a malformed resource fail closed to last-known-good controls rather than dropping or adopting garbage."
	return f
}

// ── Diagnosis helpers ──────────────────────────────────────────────────────────

func hubVsRealLine(s []maySample) string {
	for i := len(s) - 1; i >= 0; i-- {
		if s[i].GridOK && s[i].HubReachable {
			return fmt.Sprintf("At t=%.0fs the real meter read %.0f W net while the hub believed %.0f W.", s[i].T, s[i].RealGridW, s[i].HubGridW)
		}
	}
	return "No coherent meter+hub sample to compare."
}

func decisionLine(s []maySample) string {
	for i := len(s) - 1; i >= 0; i-- {
		if len(s[i].Decisions) > 0 {
			return "Last hub plan: " + strings.Join(s[i].Decisions, " | ")
		}
	}
	return "The hub's plan log was empty during the breach — the optimizer recorded no decision about this constraint."
}

func shortMRID(m string) string {
	if len(m) > 10 {
		return m[:10] + "…"
	}
	if m == "" {
		return "none"
	}
	return m
}

// ── Status plumbing ────────────────────────────────────────────────────────────

func (d *mayhemDriver) setPhase(idx int, sc *mayScenario, phase string) {
	d.mu.Lock()
	d.status.Idx = idx + 1
	d.status.Current = sc.Name
	d.status.CurrentID = sc.ID
	d.status.Phase = phase
	if d.status.Total > 0 {
		d.status.Pct = round2(float64(idx) / float64(d.status.Total) * 100)
	}
	d.mu.Unlock()
}

func (d *mayhemDriver) appendFinding(f mayFinding) {
	d.mu.Lock()
	d.status.Findings = append(d.status.Findings, f)
	switch f.Verdict {
	case "PASS":
		d.status.Summary.Pass++
	case "DEGRADED":
		d.status.Summary.Degraded++
	case "FAIL":
		d.status.Summary.Fail++
	case "BLIND":
		d.status.Summary.Blind++
	default:
		d.status.Summary.Inconclusive++
	}
	d.status.Summary.TotalBreachS = round2(d.status.Summary.TotalBreachS + f.Metrics.BreachSeconds)
	if f.Metrics.PeakBreachW > d.status.Summary.WorstPeakW {
		d.status.Summary.WorstPeakW = f.Metrics.PeakBreachW
	}
	d.mu.Unlock()
	log.Printf("mayhem: %s → %s — %s", f.ID, f.Verdict, f.Headline)
}

func (d *mayhemDriver) clearLive() {
	d.mu.Lock()
	d.status.Live = nil
	d.mu.Unlock()
}

func (d *mayhemDriver) pushLive(s maySample) {
	d.mu.Lock()
	d.status.Live = append(d.status.Live, s)
	if len(d.status.Live) > 120 {
		d.status.Live = d.status.Live[len(d.status.Live)-120:]
	}
	d.mu.Unlock()
}

func (d *mayhemDriver) finish(aborted bool, errMsg string) {
	path := d.writeReport()
	d.mu.Lock()
	d.status.Running = false
	d.status.Finished = !aborted && errMsg == ""
	d.status.Aborted = aborted
	d.status.Phase = "done"
	d.status.Pct = 100
	if errMsg != "" {
		d.status.LastError = errMsg
	}
	d.status.ReportPath = path
	sum := d.status.Summary
	d.mu.Unlock()
	log.Printf("mayhem: done (aborted=%v) — %d pass, %d degraded, %d fail, %d blind, %d inconclusive; worst breach %.0f W; report %s",
		aborted, sum.Pass, sum.Degraded, sum.Fail, sum.Blind, sum.Inconclusive, sum.WorstPeakW, path)
}

func (d *mayhemDriver) fail(msg string) {
	log.Printf("mayhem: FAILED — %s", msg)
	d.finish(false, msg)
}

// writeReport renders the findings to a shareable markdown file on the dashboard
// host and returns its path. Best-effort; a failure here does not affect status.
func (d *mayhemDriver) writeReport() string {
	d.mu.Lock()
	st := d.status
	findings := append([]mayFinding(nil), d.status.Findings...)
	d.mu.Unlock()
	if len(findings) == 0 {
		return ""
	}
	path := fmt.Sprintf("qa-mayhem-%s.md", time.Now().Format("20060102-150405"))
	var b strings.Builder
	fmt.Fprintf(&b, "# Mayhem QA report\n\n")
	fmt.Fprintf(&b, "Run started %s. %d pass · %d degraded · **%d fail** · **%d blind** · %d inconclusive.\n",
		st.StartedAt.Format(time.RFC3339), st.Summary.Pass, st.Summary.Degraded, st.Summary.Fail, st.Summary.Blind, st.Summary.Inconclusive)
	fmt.Fprintf(&b, "Worst breach: %.0f W. Total time out of limit: %.0fs.\n\n", st.Summary.WorstPeakW, st.Summary.TotalBreachS)
	for _, f := range findings {
		fmt.Fprintf(&b, "## [%s] %s — %s\n\n", f.Verdict, f.ID, f.Name)
		fmt.Fprintf(&b, "**%s**\n\n", f.Headline)
		fmt.Fprintf(&b, "- Represents: %s\n- Expected: %s\n", f.Hypothesis, f.Expected)
		fmt.Fprintf(&b, "- Breach: %.0f W peak, %.0fs total · adopted=%v reacted=%v cannot_comply=%v blind=%v · sample_errors=%d/%d\n\n",
			f.Metrics.PeakBreachW, f.Metrics.BreachSeconds, f.Metrics.HubAdopted, f.Metrics.HubReacted, f.Metrics.ReportedCannot, f.Metrics.HubBlind, f.Metrics.SampleErrors, f.Metrics.Samples)
		for _, line := range f.Diagnosis {
			fmt.Fprintf(&b, "- %s\n", line)
		}
		if f.Fix != "" {
			fmt.Fprintf(&b, "\n_Where to look: %s_\n", f.Fix)
		}
		b.WriteString("\n")
	}
	if err := os.WriteFile(path, []byte(b.String()), 0o644); err != nil {
		log.Printf("mayhem: could not write report %s: %v", path, err)
		return ""
	}
	log.Printf("mayhem: report → %s", path)
	return path
}

// ── Bench I/O ──────────────────────────────────────────────────────────────────

func (d *mayhemDriver) post(name, path string, body map[string]any) error {
	base, ok := d.backends[name]
	if !ok {
		return fmt.Errorf("unknown backend %q", name)
	}
	buf, _ := json.Marshal(body)
	resp, err := d.client.Post(base+path, "application/json", bytes.NewReader(buf))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("%s%s: HTTP %d", name, path, resp.StatusCode)
	}
	return nil
}

func (d *mayhemDriver) getJSON(name, path string, out any) error {
	base, ok := d.backends[name]
	if !ok {
		return fmt.Errorf("unknown backend %q", name)
	}
	resp, err := d.client.Get(base + path)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("%s%s: HTTP %d", name, path, resp.StatusCode)
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

// postControl posts a DERControl to gridsim and returns the assigned mRID.
func (d *mayhemDriver) postControl(body map[string]any) (string, error) {
	base := d.backends["gridsim"]
	buf, _ := json.Marshal(body)
	resp, err := d.client.Post(base+"/admin/control", "application/json", bytes.NewReader(buf))
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

func (d *mayhemDriver) deleteControls(program int) {
	base := d.backends["gridsim"]
	buf, _ := json.Marshal(map[string]int{"program": program})
	req, _ := http.NewRequest(http.MethodDelete, base+"/admin/control", bytes.NewReader(buf))
	req.Header.Set("Content-Type", "application/json")
	if resp, err := d.client.Do(req); err == nil {
		resp.Body.Close()
	}
}

func (d *mayhemDriver) reportedCannotComply(mrid string) bool {
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

func (d *mayhemDriver) meterW() (float64, bool) {
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

func (d *mayhemDriver) solarSim() (actualW, possibleW float64, ok bool) {
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

type mayHubState struct {
	ok                   bool
	gridW, batteryW, evW float64
	batSOC, evSOC        float64
	clockOffsetS         int64
	ctrlActive           bool
	ctrlTyp, ctrlMRID    string
	ctrlLimW             float64
	disconnectActive     bool
	decisions            []string
}

func (d *mayhemDriver) hubState() mayHubState {
	var st struct {
		ClockOffsetS int64 `json:"clock_offset_s"`
		CSIPControl  *struct {
			MRID string `json:"mrid"`
			Base struct {
				ExpLimW *int64 `json:"exp_lim_W"`
				MaxLimW *int64 `json:"max_lim_W"`
				ImpLimW *int64 `json:"imp_lim_W"`
				FixedW  *int64 `json:"fixed_W"`
				Connect *bool  `json:"connect"`
			} `json:"base"`
		} `json:"csip_control"`
		Devices map[string]struct {
			Role   string  `json:"role"`
			SocPct float64 `json:"soc_pct"`
		} `json:"devices"`
		Power struct {
			SolarW   float64 `json:"solar_W"`
			BatteryW float64 `json:"battery_W"`
			GridW    float64 `json:"grid_W"`
		} `json:"power"`
		EVSEs []struct {
			PowerW float64  `json:"power_W"`
			SOC    *float64 `json:"soc_pct"`
		} `json:"evse_stations"`
		LastPlan struct {
			Decisions []struct {
				Rule   string `json:"rule"`
				Reason string `json:"reason"`
				Impact string `json:"impact"`
			} `json:"decisions"`
		} `json:"last_plan"`
	}
	var h mayHubState
	if err := d.getJSON("hub", "/status", &st); err != nil {
		return h
	}
	h.ok = true
	h.gridW = st.Power.GridW
	h.batteryW = st.Power.BatteryW
	h.clockOffsetS = st.ClockOffsetS
	for _, dev := range st.Devices {
		if dev.Role == "battery" {
			h.batSOC = dev.SocPct
		}
	}
	for _, e := range st.EVSEs {
		h.evW += e.PowerW
		if e.SOC != nil && *e.SOC > 0 {
			h.evSOC = *e.SOC
		}
	}
	if c := st.CSIPControl; c != nil {
		h.ctrlActive = true
		h.ctrlMRID = c.MRID
		switch {
		case c.Base.ExpLimW != nil:
			h.ctrlTyp, h.ctrlLimW = "exportCap", float64(*c.Base.ExpLimW)
		case c.Base.MaxLimW != nil:
			h.ctrlTyp, h.ctrlLimW = "genLimit", float64(*c.Base.MaxLimW)
		case c.Base.ImpLimW != nil:
			h.ctrlTyp, h.ctrlLimW = "importCap", float64(*c.Base.ImpLimW)
		case c.Base.FixedW != nil:
			h.ctrlTyp, h.ctrlLimW = "fixed", float64(*c.Base.FixedW)
		case c.Base.Connect != nil:
			h.ctrlTyp = "connect"
			h.disconnectActive = !*c.Base.Connect
		}
	}
	for _, dec := range st.LastPlan.Decisions {
		h.decisions = append(h.decisions, fmt.Sprintf("[%s] %s→%s", dec.Rule, dec.Reason, dec.Impact))
	}
	return h
}

// ── Bench prep ─────────────────────────────────────────────────────────────────

// baseline puts the bench into a known controllable state: clock at zero, all
// controls cleared, solar paused (so injected PV is held and curtailment still
// applies), meter running and linked, battery at a mid SOC.
func (d *mayhemDriver) baseline() error {
	if err := d.post("gridsim", "/admin/clock", map[string]any{"offset_s": 0}); err != nil {
		return fmt.Errorf("gridsim clock: %w", err)
	}
	for prog := 0; prog <= 2; prog++ {
		d.deleteControls(prog)
	}
	if err := d.post("solar", "/control", map[string]any{"cmd": "pause"}); err != nil {
		return fmt.Errorf("solar sim: %w", err)
	}
	if err := d.post("meter", "/control", map[string]any{"cmd": "resume"}); err != nil {
		return fmt.Errorf("meter sim: %w", err)
	}
	_ = d.post("solar", "/fault", map[string]any{"kind": "ack_before_effect", "clear": true})
	_ = d.post("solar", "/fault", map[string]any{"kind": "reject_write", "clear": true})
	_ = d.post("solar", "/fault", map[string]any{"kind": "enable_gate", "clear": true})
	_ = d.post("solar", "/fault", map[string]any{"kind": "ramp_limit", "clear": true})
	_ = d.post("battery", "/fault", map[string]any{"kind": "wrong_sign", "clear": true})
	_ = d.post("battery", "/fault", map[string]any{"kind": "soc_refuse", "clear": true})
	for _, k := range []string{"profile_reject", "apply_next_tx", "min_current_floor", "stop_metervalues"} {
		_ = d.post("ev", "/fault", map[string]any{"kind": k, "clear": true})
	}
	_ = d.post("gridsim", "/admin/malform", map[string]any{"clear": true})
	_ = d.post("battery", "/inject", map[string]any{"SoC_pct": 50, "Conn": 1})
	_ = d.post("battery", "/control", map[string]any{"cmd": "resume", "speed": 1})
	_ = d.post("ev", "/inject", map[string]any{"action": "stop_session", "connector_id": 1})

	// Cap "full sun" injections just under the inverter nameplate so the sim's
	// reported potential is physically achievable (see pvHighW).
	d.pvHighW = 4800
	if np := d.solarNameplateW(); np > 0 {
		d.pvHighW = math.Min(6000, np*0.96)
	}
	return nil
}

// solarNameplateW reads the inverter's nameplate WMax from the solar sim.
func (d *mayhemDriver) solarNameplateW() float64 {
	var st struct {
		Nameplate struct {
			WMaxW float64 `json:"wmax_W"`
		} `json:"nameplate"`
	}
	if err := d.getJSON("solar", "/state", &st); err != nil {
		return 0
	}
	return st.Nameplate.WMaxW
}

func (d *mayhemDriver) injectEnv(pvW, loadW float64) {
	_ = d.post("solar", "/inject", map[string]any{"W_W": pvW})
	_ = d.post("meter", "/inject", map[string]any{"LoadW_W": loadW})
}

// restoreBench returns every backend to normal demo state. Mirrors replay's.
func (d *mayhemDriver) restoreBench() {
	_ = d.post("gridsim", "/admin/clock", map[string]any{"offset_s": 0})
	for prog := 0; prog <= 2; prog++ {
		d.deleteControls(prog)
	}
	_ = d.post("solar", "/fault", map[string]any{"kind": "ack_before_effect", "clear": true})
	_ = d.post("solar", "/fault", map[string]any{"kind": "reject_write", "clear": true})
	_ = d.post("solar", "/fault", map[string]any{"kind": "enable_gate", "clear": true})
	_ = d.post("solar", "/fault", map[string]any{"kind": "ramp_limit", "clear": true})
	_ = d.post("battery", "/fault", map[string]any{"kind": "wrong_sign", "clear": true})
	_ = d.post("battery", "/fault", map[string]any{"kind": "soc_refuse", "clear": true})
	for _, k := range []string{"profile_reject", "apply_next_tx", "min_current_floor", "stop_metervalues"} {
		_ = d.post("ev", "/fault", map[string]any{"kind": k, "clear": true})
	}
	_ = d.post("gridsim", "/admin/malform", map[string]any{"clear": true})
	_ = d.post("solar", "/control", map[string]any{"cmd": "resume", "speed": 1})
	_ = d.post("battery", "/inject", map[string]any{"Conn": 1, "WMaxLimPct_pct": 0})
	_ = d.post("battery", "/control", map[string]any{"cmd": "resume", "speed": 1})
	_ = d.post("meter", "/control", map[string]any{"cmd": "resume"})
	_ = d.post("ev", "/inject", map[string]any{"action": "stop_session", "connector_id": 1})
	_ = d.post("ev", "/inject", map[string]any{"action": "set_sim_speed", "speed": 1})
	log.Printf("mayhem: bench restored (clock 0, programs cleared, faults cleared, sims at 1×)")
}

// postCap is a small helper to post a duration-bounded cap control and return
// the constraint to judge against.
func (d *mayhemDriver) postCap(typ string, limW float64, holdS int, desc string) (*activeConstraint, error) {
	body := map[string]any{
		"program":     0,
		"duration_s":  holdS + 20,
		"activate":    true,
		"description": desc,
	}
	switch typ {
	case "exportCap":
		body["exp_lim_W"] = int64(limW)
	case "importCap":
		body["imp_lim_W"] = int64(limW)
	case "genLimit":
		body["max_lim_W"] = int64(limW)
	}
	mrid, err := d.postControl(body)
	if err != nil {
		return nil, err
	}
	return &activeConstraint{Typ: typ, LimW: limW, MRID: mrid}, nil
}

// postConnect posts a duration-bounded opModConnect control (connect=false is a
// cease-to-energize disconnect) and returns the constraint to judge against.
func (d *mayhemDriver) postConnect(connect bool, holdS int, desc string) (*activeConstraint, error) {
	mrid, err := d.postControl(map[string]any{
		"program":     0,
		"duration_s":  holdS + 20,
		"activate":    true,
		"description": desc,
		"connect":     connect,
	})
	if err != nil {
		return nil, err
	}
	return &activeConstraint{Typ: "connect", LimW: 0, MRID: mrid}, nil
}

// ── Scenario battery ───────────────────────────────────────────────────────────

// scenarios builds the worst-case suite, ending with the perfect storm. Each is
// self-contained: setup arms the fault, perTick keeps it biting, teardown clears.
func (d *mayhemDriver) scenarios() []*mayScenario {
	const loadLow = 250.0 // pvHigh comes from d.pvHighW (nameplate-aware, set in baseline)

	sc := []*mayScenario{
		{
			ID: "export-cap-full-battery", Name: "Zero-export cap, full sun, battery full",
			Category:   "Grid compliance (INV-EXPORT)",
			Hypothesis: "Utility commands zero export during a sunny low-load midday while the home battery is already full — the hub's only lever is to curtail PV to ~0.",
			Expected:   "Hold net export at ~0 W by curtailing solar. If it physically cannot, post CannotComply — never silently export over the cap.",
			HoldS:      100, // long enough for the sticky-guard curtailment ramp to settle and hold a clean tail
			Fix:        "Optimizer must curtail PV when the battery cannot absorb; verify the curtail command reaches the inverter.",
			setup: func(d *mayhemDriver) (*activeConstraint, error) {
				_ = d.post("battery", "/inject", map[string]any{"SoC_pct": 100, "Conn": 1})
				d.injectEnv(d.pvHighW, loadLow)
				return d.postCap("exportCap", 0, 100, "mayhem: zero export cap")
			},
			perTick:  func(d *mayhemDriver, i int) { d.injectEnv(d.pvHighW, loadLow) },
			evaluate: diagnoseConstraint,
		},
		{
			ID: "ack-before-effect", Name: "Inverter ACKs curtailment but lags 45 s",
			Category:   "Closed-loop actuation (INV-CONVERGE)",
			Hypothesis: "A real inverter accepts the SetPoint over Modbus (ACK) but its output ramps slowly — the hub believes the limit is in force before it is.",
			Expected:   "Detect that measured output has not reached the commanded limit and react (hold the battery, or post CannotComply) instead of trusting the write ACK.",
			HoldS:      50,
			Fix:        "Add measured-effect verification to derbase.ApplyControl; today it is write-only.",
			setup: func(d *mayhemDriver) (*activeConstraint, error) {
				_ = d.post("battery", "/inject", map[string]any{"SoC_pct": 100, "Conn": 1})
				d.injectEnv(d.pvHighW, loadLow)
				if err := d.post("solar", "/fault", map[string]any{"kind": "ack_before_effect", "delay_s": 45}); err != nil {
					return nil, fmt.Errorf("arm ack_before_effect: %w", err)
				}
				return d.postCap("genLimit", 1000, 50, "mayhem: gen limit 1 kW vs lagging inverter")
			},
			perTick:  func(d *mayhemDriver, i int) { d.injectEnv(d.pvHighW, loadLow) },
			evaluate: diagnoseConverge,
			teardown: func(d *mayhemDriver) {
				_ = d.post("solar", "/fault", map[string]any{"kind": "ack_before_effect", "clear": true})
			},
		},
		{
			ID: "reject-write-curtail", Name: "Inverter ACKs the curtailment but ignores it",
			Category:   "Closed-loop actuation (INV-CONVERGE)",
			Hypothesis: "A real inverter accepts the WMaxLimPct write over Modbus (ACK) but silently keeps producing at its old ceiling — accept-but-ignore. The hub believes the limit is in force the moment the write succeeds.",
			Expected:   "Detect via measurement that output never reached the commanded limit and react (post CannotComply, or use another lever) — never keep reporting compliance it does not have.",
			HoldS:      50,
			Fix:        "Add measured-effect verification to derbase.ApplyControl; today it is write-only. (Demonstrates robustness under SIMULATED abuse, not field-readiness.)",
			setup: func(d *mayhemDriver) (*activeConstraint, error) {
				_ = d.post("battery", "/inject", map[string]any{"SoC_pct": 100, "Conn": 1}) // battery full → PV curtailment is the only lever
				d.injectEnv(d.pvHighW, loadLow)
				if err := d.post("solar", "/fault", map[string]any{"kind": "reject_write"}); err != nil {
					return nil, fmt.Errorf("arm reject_write: %w", err)
				}
				return d.postCap("genLimit", 1000, 50, "mayhem: gen limit 1 kW vs an inverter that ignores it")
			},
			perTick:  func(d *mayhemDriver, i int) { d.injectEnv(d.pvHighW, loadLow) },
			evaluate: diagnoseConverge,
			teardown: func(d *mayhemDriver) {
				_ = d.post("solar", "/fault", map[string]any{"kind": "reject_write", "clear": true})
			},
		},
		{
			ID: "enable-gate-curtail", Name: "Inverter echoes the limit but never enables it",
			Category:   "Closed-loop actuation (INV-CONVERGE)",
			Hypothesis: "An inverter accepts the WMaxLimPct write and echoes the curtailment value on readback, but its enable flag stays off so the limit is never enforced — output holds at full potential. A hub that 'verifies' by reading the register back is fooled into reporting compliance.",
			Expected:   "Detect via MEASURED output (not register readback) that the limit never took effect and react (post CannotComply, or use another lever) — never trust the echoed value.",
			HoldS:      50,
			Fix:        "Bench shows the hub CATCHES this (it flags the cleared enable flag and posts CannotComply → DEGRADED) but is BLIND to reject-write-curtail under an identical breach (→ FAIL). Verification keys off the enable flag, not the limit value or measured output — complete it so both accept-but-ignore variants are caught. (Demonstrates robustness under SIMULATED abuse, not field-readiness.)",
			setup: func(d *mayhemDriver) (*activeConstraint, error) {
				_ = d.post("battery", "/inject", map[string]any{"SoC_pct": 100, "Conn": 1}) // battery full → PV curtailment is the only lever
				d.injectEnv(d.pvHighW, loadLow)
				if err := d.post("solar", "/fault", map[string]any{"kind": "enable_gate"}); err != nil {
					return nil, fmt.Errorf("arm enable_gate: %w", err)
				}
				return d.postCap("genLimit", 1000, 50, "mayhem: gen limit 1 kW vs an inverter that echoes but never enables it")
			},
			perTick:  func(d *mayhemDriver, i int) { d.injectEnv(d.pvHighW, loadLow) },
			evaluate: diagnoseConverge,
			teardown: func(d *mayhemDriver) {
				_ = d.post("solar", "/fault", map[string]any{"kind": "enable_gate", "clear": true})
			},
		},
		{
			ID: "ramp-limit-curtail", Name: "Inverter honours the limit but ramps to it slowly",
			Category:   "Closed-loop actuation (INV-CONVERGE)",
			Hypothesis: "An inverter accepts the curtailment instantly (register set) but slews its physical output toward the new ceiling at a bounded rate, sitting over the limit during the ramp before converging. Unlike an ignored write, it DOES reach the limit — just not immediately.",
			Expected:   "Tolerate a bounded convergence ramp: the limit is reached within the device's slew time. Flag DEGRADED only if convergence exceeds the compliance deadline; never a silent FAIL, and never a spurious CannotComply while it is still converging.",
			HoldS:      100, // hub sticky-guard latency + the device's 120 W/s slew need ~75s; leave a clean tail
			Fix:        "Distinguish 'converging toward the limit' from 'ignoring the limit' via the measured-output trend; allow a bounded settling window before escalating. (Demonstrates robustness under SIMULATED abuse, not field-readiness.)",
			setup: func(d *mayhemDriver) (*activeConstraint, error) {
				_ = d.post("battery", "/inject", map[string]any{"SoC_pct": 100, "Conn": 1}) // battery full → PV curtailment is the only lever
				d.injectEnv(d.pvHighW, loadLow)
				if err := d.post("solar", "/fault", map[string]any{"kind": "ramp_limit", "max_ramp_w_per_s": 120}); err != nil {
					return nil, fmt.Errorf("arm ramp_limit: %w", err)
				}
				return d.postCap("genLimit", 1000, 100, "mayhem: gen limit 1 kW vs an inverter that slews to it")
			},
			perTick:  func(d *mayhemDriver, i int) { d.injectEnv(d.pvHighW, loadLow) },
			evaluate: diagnoseConverge,
			teardown: func(d *mayhemDriver) {
				_ = d.post("solar", "/fault", map[string]any{"kind": "ramp_limit", "clear": true})
			},
		},
		{
			ID: "battery-wrong-sign", Name: "Battery executes a commanded charge as a discharge",
			Category:   "Resource limits (INV-SOC)",
			Hypothesis: "A battery wired or firmware-flipped in the wrong direction: when the hub commands a charge to soak up excess PV, the pack discharges instead, walking an already-low state of charge toward empty.",
			Expected:   "Detect the pack moving opposite to the command (SoC falling under a charge command) and halt/alarm before it discharges below the reserve floor.",
			HoldS:      90, // long enough for the wrong-way discharge to walk SoC across the 10% reserve floor
			Fix:        "Verify measured battery direction/SoC trend against the commanded sign in the orchestrator battery adapter. (Demonstrates robustness under SIMULATED abuse; the BatteryW sign convention must be confirmed against the live hub /status before trusting the verdict.)",
			setup: func(d *mayhemDriver) (*activeConstraint, error) {
				// Start just above the reserve floor so the flipped (discharge)
				// command drives SoC across it within the window, exercising INV-SOC —
				// and the same discharge blows the export cap, exercising INV-CONVERGE.
				_ = d.post("battery", "/inject", map[string]any{"SoC_pct": 10.5, "Conn": 1})
				d.injectEnv(d.pvHighW, loadLow) // excess PV → hub wants to charge the battery
				if err := d.post("battery", "/fault", map[string]any{"kind": "wrong_sign"}); err != nil {
					return nil, fmt.Errorf("arm wrong_sign: %w", err)
				}
				return d.postCap("exportCap", 0, 90, "mayhem: zero export cap drives a battery charge (flipped to discharge)")
			},
			perTick:  func(d *mayhemDriver, i int) { d.injectEnv(d.pvHighW, loadLow) },
			evaluate: diagnoseSOC,
			teardown: func(d *mayhemDriver) {
				_ = d.post("battery", "/fault", map[string]any{"kind": "wrong_sign", "clear": true})
			},
		},
		{
			ID: "battery-soc-refuse", Name: "Battery accepts the discharge command but does nothing",
			Category:   "Resource limits (INV-CONVERGE)",
			Hypothesis: "Under an import cap the hub commands the battery to discharge and cover the load, but the pack's BMS/contactor refuses — it ACKs the setpoint and produces zero power while it still has charge. A hub that assumes the discharge took effect keeps importing over the cap.",
			Expected:   "Detect that battery power never moved despite the command and react — fall back to another lever or post CannotComply. Never assume the commanded discharge happened.",
			HoldS:      70,
			Fix:        "Verify measured battery power against the commanded setpoint; on a non-responding pack, escalate / post CannotComply (orchestrator battery adapter). (Demonstrates robustness under SIMULATED abuse, not field-readiness.)",
			setup: func(d *mayhemDriver) (*activeConstraint, error) {
				_ = d.post("battery", "/inject", map[string]any{"SoC_pct": 50, "Conn": 1}) // half-full: it HAS charge to give
				d.injectEnv(300, 5000)                                                     // low PV, heavy load → forced import unless the battery discharges
				if err := d.post("battery", "/fault", map[string]any{"kind": "soc_refuse"}); err != nil {
					return nil, fmt.Errorf("arm soc_refuse: %w", err)
				}
				return d.postCap("importCap", 0, 70, "mayhem: zero import cap, battery refuses to discharge")
			},
			perTick:  func(d *mayhemDriver, i int) { d.injectEnv(300, 5000) },
			evaluate: diagnoseConstraint,
			teardown: func(d *mayhemDriver) {
				_ = d.post("battery", "/fault", map[string]any{"kind": "soc_refuse", "clear": true})
			},
		},
		{
			ID: "ev-profile-reject", Name: "Charger rejects the hub's current-limit profile",
			Category:   "OCPP smart charging (INV-CONVERGE)",
			Hypothesis: "Under an import cap with an empty battery (so the EV is the only lever) the hub sends a SetChargingProfile to dial the EV down, but the charger rejects smart charging and keeps drawing at full current. A hub that ignores the Rejected status keeps importing over the cap.",
			Expected:   "Treat the rejected profile as a failure and react — pause the session, use another lever, or post CannotComply. Never assume the EV load dropped.",
			HoldS:      70,
			Fix:        "The OCPP bridge returns an error on a rejected/timed-out SetChargingProfile (2026-06 fix); the optimizer must act on it, not just log. (Demonstrates robustness under SIMULATED abuse, not field-readiness.)",
			setup: func(d *mayhemDriver) (*activeConstraint, error) {
				_ = d.post("battery", "/inject", map[string]any{"SoC_pct": 5, "Conn": 1}) // empty → no battery lever, EV must be cut
				_ = d.post("ev", "/inject", map[string]any{"action": "set_soc", "soc_pct": 30})
				_ = d.post("ev", "/inject", map[string]any{"action": "start_session", "connector_id": 1})
				d.injectEnv(300, 500) // low PV + light base load; the EV is the heavy draw
				if err := d.post("ev", "/fault", map[string]any{"kind": "profile_reject"}); err != nil {
					return nil, fmt.Errorf("arm profile_reject: %w", err)
				}
				return d.postCap("importCap", 0, 70, "mayhem: zero import cap, charger rejects EV curtailment")
			},
			perTick:  func(d *mayhemDriver, i int) { d.injectEnv(300, 500) },
			evaluate: diagnoseConstraint,
			teardown: func(d *mayhemDriver) {
				_ = d.post("ev", "/fault", map[string]any{"kind": "profile_reject", "clear": true})
				_ = d.post("ev", "/inject", map[string]any{"action": "stop_session", "connector_id": 1})
			},
		},
		{
			ID: "grid-disconnect", Name: "Cease-to-energize: grid commands a disconnect",
			Category:   "Grid safety (INV-CONNECT)",
			Hypothesis: "The utility commands an immediate disconnect (opModConnect=false) while the inverter is exporting at full sun and the battery could discharge. Every controllable DER must stop feeding the grid within seconds — back-feeding a line the utility believes is dead is the most dangerous failure there is.",
			Expected:   "Drive solar output and battery discharge to ~0 within the reaction window and hold there for the whole disconnect. No DER may keep energizing the grid.",
			HoldS:      45,
			Fix:        "On an opModConnect=false control, command all DERs to cease energizing and verify measured output reaches ~0 (orchestrator connect handling).",
			setup: func(d *mayhemDriver) (*activeConstraint, error) {
				_ = d.post("battery", "/inject", map[string]any{"SoC_pct": 70, "Conn": 1})
				d.injectEnv(d.pvHighW, loadLow) // solar exporting at full sun
				return d.postConnect(false, 45, "mayhem: cease-to-energize disconnect")
			},
			perTick:  func(d *mayhemDriver, i int) { d.injectEnv(d.pvHighW, loadLow) },
			evaluate: diagnoseDisconnect,
			teardown: func(d *mayhemDriver) { d.deleteControls(0) }, // re-energize
		},
		{
			ID: "malformed-csip", Name: "Grid server serves a malformed resource",
			Category:   "CSIP robustness (INV-EXPORT survivability)",
			Hypothesis: "A buggy or hostile 2030.5 server serves a malformed DERControlList (the same control mRID twice) while a safe export cap is active. The hub must contain the parse error — never panic/hang, never drop the safe control for garbage or 'none'.",
			Expected:   "Stay up (/status keeps answering) and keep enforcing the active export cap. A malformed resource must not take the hub down or unseat a safe control.",
			HoldS:      45,
			Fix:        "Harden the northbound walker/parser; on a malformed resource fail closed to last-known-good controls.",
			setup: func(d *mayhemDriver) (*activeConstraint, error) {
				_ = d.post("battery", "/inject", map[string]any{"SoC_pct": 100, "Conn": 1}) // battery full → PV curtailment is the only lever
				d.injectEnv(d.pvHighW, loadLow)
				cons, err := d.postCap("exportCap", 0, 45, "mayhem: export cap then malformed resource")
				if err != nil {
					return nil, err
				}
				// Let the hub adopt the safe cap on a clean walk, THEN start serving
				// garbage — so there is a safe control for the malform to threaten.
				go func() {
					time.Sleep(8 * time.Second)
					_ = d.post("gridsim", "/admin/malform", map[string]any{"kind": "dup_mrid"})
				}()
				return cons, nil
			},
			perTick:  func(d *mayhemDriver, i int) { d.injectEnv(d.pvHighW, loadLow) },
			evaluate: diagnoseMalform,
			teardown: func(d *mayhemDriver) { _ = d.post("gridsim", "/admin/malform", map[string]any{"clear": true}) },
		},
		{
			ID: "stale-meter", Name: "Grid meter freezes while the world changes",
			Category:   "Sensor integrity (INV-STALE)",
			Hypothesis: "The revenue meter's reading stops updating (frozen TCP session / hung device) while PV climbs — the hub's grid signal goes stale.",
			Expected:   "Notice the reading stopped changing, mark it stale, fail safe, and raise an alarm — do not keep acting on a dead sensor.",
			HoldS:      35,
			Fix:        "Add a staleness/heartbeat check per measurement source feeding the optimizer.",
			setup: func(d *mayhemDriver) (*activeConstraint, error) {
				d.injectEnv(2000, loadLow)
				time.Sleep(500 * time.Millisecond)
				if err := d.post("meter", "/control", map[string]any{"cmd": "pause"}); err != nil {
					return nil, fmt.Errorf("freeze meter: %w", err)
				}
				return d.postCap("exportCap", 0, 35, "mayhem: export cap with frozen meter")
			},
			// Keep ramping injected PV; a healthy meter would show it, a frozen one won't.
			perTick:  func(d *mayhemDriver, i int) { d.injectEnv(2000+float64(i)*400, loadLow) },
			evaluate: diagnoseStale,
			teardown: func(d *mayhemDriver) { _ = d.post("meter", "/control", map[string]any{"cmd": "resume"}) },
		},
		{
			ID: "battery-empty-import-cap", Name: "Import cap at peak with an empty battery",
			Category:   "Resource limits (INV-SOC)",
			Hypothesis: "Utility caps import to 0 W during peak while load exceeds PV and the battery is empty — there is no physical way to avoid importing.",
			Expected:   "Discharge the battery to the extent possible, then post CannotComply for the unavoidable remainder. The failure must be admitted, not hidden.",
			HoldS:      90, // long enough to discharge what it can and settle before judging the admission
			Fix:        "Ensure the optimizer emits CannotComply when the reserve floor blocks compliance (battery at SOC min).",
			setup: func(d *mayhemDriver) (*activeConstraint, error) {
				_ = d.post("battery", "/inject", map[string]any{"SoC_pct": 5, "Conn": 1})
				d.injectEnv(300, 5000) // tiny PV, heavy load → forced import
				return d.postCap("importCap", 0, 90, "mayhem: zero import cap, empty battery")
			},
			perTick:  func(d *mayhemDriver, i int) { d.injectEnv(300, 5000) },
			evaluate: diagnoseConstraint,
		},
		{
			ID: "curtailment-release", Name: "Generation-limit event ends — solar must recover",
			Category:   "Recovery (INV-RESTORE)",
			Hypothesis: "A generation-limit event curtails the inverter, then expires. The hub must actively release the ceiling — the known stuck-curtailment failure leaves an inverter clamped at its last limit after the event clears.",
			Expected:   "When the cap lifts, solar climbs back to its full potential within seconds. It must never be left clamped below potential after the event ends.",
			HoldS:      60, // long tail so a slow ramp can be told apart from a true stuck restore
			Fix:        "Restore must SET the ceiling to full nameplate, not emit an empty no-op (solarCommandToControl restore path). NOTE: a true device dropout (Modbus link loss) needs the sim's service stopped via SSH — out of scope for this in-process injector.",
			setup: func(d *mayhemDriver) (*activeConstraint, error) {
				d.injectEnv(d.pvHighW, loadLow)
				return d.postCap("genLimit", 1500, 15, "mayhem: gen limit then release")
			},
			perTick: func(d *mayhemDriver, i int) {
				d.injectEnv(d.pvHighW, loadLow)
				if i == 15 { // event ends ~15s in, leaving ~45s to observe recovery
					d.deleteControls(0)
				}
			},
			evaluate: diagnoseRecovery,
			teardown: func(d *mayhemDriver) { d.deleteControls(0) },
		},
		{
			ID: "clock-jitter", Name: "CSIP clock corrections jitter while a cap is active",
			Category:   "Time integrity",
			Hypothesis: "NTP corrections step the grid server's clock by up to a minute while an export cap is active — event boundaries shift slightly under the hub.",
			Expected:   "Keep honouring the active cap across the correction: a modest, spec-legal clock step inside the event window must not flap the control or drop enforcement.",
			HoldS:      35,
			Fix: "Tolerate a non-monotonic clock-offset step (cmd/hub/state.go expiryConfirmTicks). " +
				"NOTE: a wildly oscillating server clock (±hours) is OUT OF SCOPE — IEEE 2030.5 requires the client to schedule events in SERVER time, so following a non-conformant server's clock is correct, not a bug.",
			setup: func(d *mayhemDriver) (*activeConstraint, error) {
				_ = d.post("battery", "/inject", map[string]any{"SoC_pct": 100, "Conn": 1})
				d.injectEnv(d.pvHighW, loadLow)
				// Long event window so the modest jitter stays inside it.
				return d.postCap("exportCap", 0, 600, "mayhem: export cap under clock jitter")
			},
			perTick: func(d *mayhemDriver, i int) {
				d.injectEnv(d.pvHighW, loadLow)
				// Realistic ±60s NTP-style jitter (within the 600s event window),
				// not a pathological hours-long lurch (a non-conformant server).
				off := int64((i%5 - 2) * 30)
				_ = d.post("gridsim", "/admin/clock", map[string]any{"offset_s": off})
			},
			evaluate: diagnoseConstraint,
			teardown: func(d *mayhemDriver) { _ = d.post("gridsim", "/admin/clock", map[string]any{"offset_s": 0}) },
		},
		{
			ID: "perfect-storm", Name: "Perfect storm — everything at once",
			Category:   "Combined worst case",
			Hypothesis: "Zero-export cap + full sun + full battery + an inverter that lags its ACK + a frozen meter + an EV demanding charge + a lurching clock — simultaneously. The worst hour this device could ever see.",
			Expected:   "Stay within export limit using every lever, or admit (CannotComply) that it cannot. Above all: never be silently blind. Recover cleanly when it ends.",
			HoldS:      60,
			Fix:        "Compound failures expose ordering bugs — fix the single-fault findings first, then re-run this.",
			setup: func(d *mayhemDriver) (*activeConstraint, error) {
				_ = d.post("battery", "/inject", map[string]any{"SoC_pct": 100, "Conn": 1})
				d.injectEnv(d.pvHighW, loadLow)
				_ = d.post("ev", "/inject", map[string]any{"action": "set_soc", "soc_pct": 30})
				_ = d.post("ev", "/inject", map[string]any{"action": "start_session", "connector_id": 1})
				if err := d.post("solar", "/fault", map[string]any{"kind": "ack_before_effect", "delay_s": 60}); err != nil {
					return nil, fmt.Errorf("arm ack_before_effect: %w", err)
				}
				// Long event window so the modest clock jitter stays inside it.
				cons, err := d.postCap("exportCap", 0, 600, "mayhem: perfect storm zero export")
				if err != nil {
					return nil, err
				}
				// Freeze the meter a few seconds in, after the breach is well underway.
				go func() {
					time.Sleep(8 * time.Second)
					_ = d.post("meter", "/control", map[string]any{"cmd": "pause"})
				}()
				return cons, nil
			},
			perTick: func(d *mayhemDriver, i int) {
				d.injectEnv(d.pvHighW, loadLow)
				// Realistic ±90s clock jitter within the event window (not an
				// unrealistic hours-long lurch — see the clock-jitter scenario).
				off := int64((i%7 - 3) * 30)
				_ = d.post("gridsim", "/admin/clock", map[string]any{"offset_s": off})
			},
			evaluate: diagnoseConstraint,
			teardown: func(d *mayhemDriver) {
				_ = d.post("meter", "/control", map[string]any{"cmd": "resume"})
				_ = d.post("solar", "/fault", map[string]any{"kind": "ack_before_effect", "clear": true})
				_ = d.post("ev", "/inject", map[string]any{"action": "stop_session", "connector_id": 1})
				_ = d.post("gridsim", "/admin/clock", map[string]any{"offset_s": 0})
			},
		},
	}
	return sc
}
