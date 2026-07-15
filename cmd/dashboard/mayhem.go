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
	"errors"
	"fmt"
	"io"
	"log"
	"math"
	"net/http"
	"os"
	"path/filepath"
	"runtime/debug"
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

	mayEVLiveDrawW = 500 // an EVSE drawing more than this is "actively charging" — the floor for judging hub-vs-truth EV divergence

	// mayJudgeAbsentBlindFrac is how much of a scenario's hold window an
	// oracle's JUDGING sensor — the one whose reading breachOver / the
	// relevant invariant actually checks (solar for genLimit, the grid meter
	// for export/import, the battery sim for INV-SOC) — may be absent before
	// a clean read is untrustworthy (WS-3). breachOver and invSOC both treat
	// an absent judging sensor as "no breach this tick", so a probe that is
	// dead for most of the window manufactures a PASS out of silence rather
	// than measured compliance. 20% tolerates a few dropped polls (bench
	// timing jitter, one slow HTTP round trip) without tripping; a HIL fault
	// that actually kills the probe for a meaningful slice of the hold
	// window does. See forceBlindOnProbeGap: it only ever tightens a
	// would-be PASS to BLIND, never a FAIL/DEGRADED reached from data the
	// sensor DID deliver.
	mayJudgeAbsentBlindFrac = 0.20
)

// ── Result types ──────────────────────────────────────────────────────────────

// maySample is one observation of the whole bench during a scenario.
type maySample struct {
	T         float64 `json:"t"` // seconds since scenario start
	RealGridW float64 `json:"real_grid_W"`
	GridOK    bool    `json:"grid_ok"`
	HubGridW  float64 `json:"hub_grid_W"`

	SolarW         float64 `json:"solar_W"` // from the solar sim /state (ground truth, not Modbus)
	SolarPossibleW float64 `json:"solar_possible_W"`
	SolarOK        bool    `json:"solar_ok"`
	HubSolarW      float64 `json:"hub_solar_W"` // the hub's Modbus-derived solar reading — for INV-TRANSPORT

	// SolarCeilingPct/SolarCeilingEna are the inverter's OWN WMaxLimPct
	// curtailment-ceiling register, read straight from the solar sim /state
	// (ground truth for what was actually WRITTEN to the device over Modbus,
	// as distinct from SolarW/SolarPossibleW's power-flow ground truth) — the
	// WS-2 (HANDOFF.md §8) fail-open detector: a restore write clamps this to
	// ~100%/disabled regardless of what the hub's own /status claims.
	SolarCeilingPct float64 `json:"solar_ceiling_pct"`
	SolarCeilingEna bool    `json:"solar_ceiling_ena"`
	SolarCeilingOK  bool    `json:"solar_ceiling_ok"`

	BatteryW     float64 `json:"battery_W"` // the hub's view (Modbus-derived) — display/observability
	BatSOC       float64 `json:"bat_soc"`
	BatterySimW  float64 `json:"battery_sim_W"`   // pack's TRUE net power from the batsim /state (ground truth) — for INV-SOC
	BatSimSOC    float64 `json:"battery_sim_soc"` // pack's TRUE SoC from the batsim /state (ground truth)
	BatterySimOK bool    `json:"battery_sim_ok"`  // the batsim reported a coherent state this tick
	EvW          float64 `json:"ev_W"`
	EvSOC        float64 `json:"ev_soc"`
	EvCurrentA   float64 `json:"ev_current_A"`     // EVSE draw (A) — for INV-EVMAX
	EvMaxA       float64 `json:"ev_max_current_A"` // EVSE configured max (A)
	EvSimW       float64 `json:"ev_sim_W"`         // charger's TRUE draw from the ev sim /state (ground truth) — for INV-EVBLIND
	EvSimA       float64 `json:"ev_sim_A"`         // charger's TRUE current (A), ground truth
	EvSimOK      bool    `json:"ev_sim_ok"`        // the ev sim reported a coherent charging state this tick

	HubReachable     bool    `json:"hub_reachable"`
	HubAdopted       bool    `json:"hub_adopted"`       // hub is applying a CSIP control this tick
	DisconnectActive bool    `json:"disconnect_active"` // a cease-to-energize (Connect=false) control is in force
	AdoptedTyp       string  `json:"adopted_typ"`       // exportCap|importCap|genLimit|fixed|connect
	AdoptedLimW      float64 `json:"adopted_lim_W"`
	AdoptedMRID      string  `json:"adopted_mrid"`
	ValidUntil       int64   `json:"valid_until"` // active control's validUntil (server unix) — for INV-EXPIRED
	WallUnix         int64   `json:"wall_unix"`   // sampler wall clock (unix) — server time = WallUnix + ClockOffsetS
	ClockOffsetS     int64   `json:"clock_offset_s"`

	CannotComply bool `json:"cannot_comply"` // hub posted a CannotComply for the active mRID
	// CannotComplyCount is how many CannotComply Responses gridsim has
	// recorded for the active mRID as of this sample (WS-4.5,
	// docs/refactor/HANDOFF.md §8, csip-tls-test repo) — distinct from
	// CannotComply's presence-only bool. gridsim's /admin/alerts accumulates
	// one entry per POST received and never removes one, so this is
	// monotonically non-decreasing across a scenario's samples; a diagnoser
	// proving "exactly one, no duplicate re-post" (e.g. across a
	// mid-episode northbound restart) reads the LAST sample's count rather
	// than the presence bool.
	CannotComplyCount int      `json:"cannot_comply_count"`
	Decisions         []string `json:"decisions,omitempty"`

	MeterStale bool `json:"meter_stale"` // hub flagged the grid meter frozen (detected INV-STALE)
	EvStale    bool `json:"ev_stale"`    // hub flagged an EVSE's telemetry silent (detected INV-EVBLIND)
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
	// Violations is the structured form of the "⚠ SAFETY AUDIT: …" diagnosis
	// bullet applySafetyAudit appends below — same invViolation slice, single
	// source of truth (CONTRACTS.md §4). Empty/omitted when the audit found
	// nothing, exactly when today's prose reads "SAFETY AUDIT held: no
	// violations across the window."
	Violations []invViolation `json:"violations,omitempty"`
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
	ChaosSeed  int64        `json:"chaos_seed,omitempty"`
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

	// scenarioDir is where scenarios() looks for *.json scenario specs
	// (TASK-076, -scenario-dir in main.go). Empty ⇒ specs disabled — the
	// zero value for every test driver built via newMayhemDriver(backends),
	// so existing tests are unaffected; main.go sets it explicitly.
	scenarioDir string

	// scenarioCtx is the CURRENT scenario's cancellation context (WS-3
	// run-integrity hardening), set by run() before calling setup and
	// canceled the instant the hold ends, before teardown runs. Delayed-fault
	// goroutines started via afterDelay read it so a fault that hasn't fired
	// yet when the scenario moves to teardown is dropped instead of landing
	// after teardown's own cleanup — teardown is always the last writer.
	// Guarded by mu like every other status field.
	scenarioCtx context.Context
}

func newMayhemDriver(backends map[string]string) *mayhemDriver {
	return &mayhemDriver{
		backends: backends,
		// WS-B: hub backend (:9100) is HTTPS self-signed; skip-verify transport
		// (hubtls.go). Same client reaches the http sims — TLS config is ignored
		// for http:// so they are unaffected. Bearer auth unchanged.
		client: &http.Client{Timeout: 3 * time.Second, Transport: benchHubTransport()},
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

	// Source tags where the scenario came from — "" (zero value, rendered as
	// "go") for every hand-written literal below, "spec" for one compiled
	// from a qa/scenarios/*.json file by scenariospec.go (TASK-076).
	// handleScenarios/mayhem.py --list surface it so a campaign report shows
	// which scenarios can be edited without a rebuild.
	Source string

	// ExpectedVerdicts documents the "expected-FAIL pins the gap" pattern
	// (06_TESTING_STRATEGY.md §4.5) for a spec-sourced scenario — informational
	// only, not enforced by the run loop. Always nil for a Go literal.
	ExpectedVerdicts []string

	// Extended marks a long-running scenario (HoldS in the minutes, not
	// seconds — RSK-12) that the default/full run excludes to protect
	// day-to-day FAST campaign wall-clock time (CLAUDE.md: "FAST for
	// development campaigns; STOCK via mayhem-campaign.sh for release
	// gates"). It still runs when explicitly named via --only, or when the
	// caller opts in via IncludeExtended (nightly / release-gate campaigns).
	// See filterExtended.
	Extended bool

	setup    func(d *mayhemDriver) (*activeConstraint, error)
	perTick  func(d *mayhemDriver, i int)
	evaluate func(sc *mayScenario, cons *activeConstraint, s []maySample) mayFinding
	teardown func(d *mayhemDriver)
}

// filterExtended drops Extended scenarios from a default/full run so a long
// (multi-minute) boundary-dither scenario cannot silently inflate every FAST
// campaign's wall-clock time (RSK-12). It is a no-op — and never called — when
// the caller named specific scenarios via --only (Only is always an intentional,
// explicit selection) or explicitly opted in via includeExtended (nightly /
// release-gate campaigns). Pure so the selection rule is unit-testable without
// spinning up a run.
func filterExtended(scenarios []*mayScenario, includeExtended bool) []*mayScenario {
	if includeExtended {
		return scenarios
	}
	out := scenarios[:0:0]
	for _, sc := range scenarios {
		if !sc.Extended {
			out = append(out, sc)
		}
	}
	return out
}

// ── HTTP endpoints ────────────────────────────────────────────────────────────

type mayhemStartReq struct {
	SampleMs        int      `json:"sample_ms"`
	Only            []string `json:"only"`             // run only these scenario IDs (empty = all)
	Matrix          bool     `json:"matrix"`           // run the fault-matrix run mode instead of the curated suite
	Chaos           bool     `json:"chaos"`            // run a seeded randomized chaos sequence
	Seed            int64    `json:"seed"`             // chaos seed (0 ⇒ time-derived, reported back for replay)
	Iterations      int      `json:"iterations"`       // chaos iteration count (0 ⇒ default)
	IncludeExtended bool     `json:"include_extended"` // opt in to Extended (long-running, GAP-08 dither) scenarios in a default/full run
}

func (d *mayhemDriver) handleStart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var req mayhemStartReq
	// An empty body (io.EOF) keeps the request-level defaults, same as before —
	// but a NON-empty malformed body (bad JSON, wrong types) must be rejected
	// rather than silently discarded, which used to launch the full hostile
	// suite on a typo'd request (WS-3 run-integrity hardening).
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil && !errors.Is(err, io.EOF) {
		http.Error(w, fmt.Sprintf("malformed request body: %v", err), http.StatusBadRequest)
		return
	}
	if req.SampleMs < 200 {
		req.SampleMs = mayDefaultSampleMs
	}

	scenarios := d.scenarios()
	var chaosSeed int64
	switch {
	case req.Chaos:
		chaosSeed = req.Seed
		if chaosSeed == 0 {
			chaosSeed = time.Now().UnixNano()
		}
		scenarios = d.chaosScenarios(chaosSeed, req.Iterations)
	case req.Matrix:
		scenarios = d.matrixScenarios()
	}
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
	} else {
		// A default/full run (curated, matrix, or chaos) excludes Extended
		// (long-running, GAP-08 dither) scenarios unless the caller opts in —
		// --only above is always an explicit, intentional selection and is
		// never filtered. See filterExtended.
		scenarios = filterExtended(scenarios, req.IncludeExtended)
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
		ChaosSeed: chaosSeed,
	}
	d.mu.Unlock()

	go d.runGuarded(ctx, scenarios, time.Duration(req.SampleMs)*time.Millisecond)
	w.WriteHeader(http.StatusAccepted)
	_ = json.NewEncoder(w).Encode(map[string]any{"scenarios": len(scenarios), "sample_ms": req.SampleMs, "chaos_seed": chaosSeed})
}

// runGuarded wraps run() with a recover() so a bug escaping a diagnoser (a
// nil-pointer, an index panic, whatever) aborts THIS run and keeps the
// dashboard process alive for the next one, instead of taking the whole
// server down mid-campaign (WS-3 run-integrity hardening). run()'s own
// `defer d.restoreBench()` still fires during the panic's stack unwind
// before this recovers it, so the bench is restored either way; this only
// has to fix up d.status, since run()'s normal d.finish path never reached.
func (d *mayhemDriver) runGuarded(ctx context.Context, scenarios []*mayScenario, sample time.Duration) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("mayhem: run panicked, aborting run: %v\n%s", r, debug.Stack())
			d.mu.Lock()
			d.status.Running = false
			d.status.Finished = false
			d.status.Aborted = true
			d.status.Phase = "done"
			d.status.LastError = fmt.Sprintf("internal panic: %v", r)
			d.mu.Unlock()
		}
	}()
	d.run(ctx, scenarios, sample)
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

// handleScenarios serves the curated scenario catalogue (id, name, category,
// hypothesis, expected) so external runners — scripts/mayhem.py --list / --only
// validation — query it instead of mirroring the Go list and drifting.
func (d *mayhemDriver) handleScenarios(w http.ResponseWriter, r *http.Request) {
	type scenarioInfo struct {
		ID         string `json:"id"`
		Name       string `json:"name"`
		Category   string `json:"category"`
		Hypothesis string `json:"hypothesis"`
		Expected   string `json:"expected"`
		Extended   bool   `json:"extended"` // long-running (GAP-08 dither); excluded from a default run unless --only or include_extended
		Source     string `json:"source"`   // "go" or "spec" (TASK-076) — spec scenarios can be added/edited with no dashboard rebuild
	}
	scs := d.scenarios()
	out := make([]scenarioInfo, 0, len(scs))
	for _, sc := range scs {
		src := sc.Source
		if src == "" {
			src = "go"
		}
		out = append(out, scenarioInfo{
			ID: sc.ID, Name: sc.Name, Category: sc.Category,
			Hypothesis: sc.Hypothesis, Expected: sc.Expected,
			Extended: sc.Extended, Source: src,
		})
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"scenarios": out})
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

		// Isolate each scenario from the previous one's device/fault state.
		d.resetForScenario()

		// scenCtx bounds THIS scenario's delayed-fault goroutines (d.afterDelay) —
		// canceled below the instant the hold ends, before teardown runs, so a
		// fault goroutine still waiting on its timer bails out instead of firing
		// after teardown already cleaned up (WS-3 run-integrity: teardown is
		// last-writer-wins). Parented on the run's own ctx so a full-run abort
		// cancels it too.
		scenCtx, scenCancel := context.WithCancel(ctx)
		d.mu.Lock()
		d.scenarioCtx = scenCtx
		d.mu.Unlock()

		cons := &activeConstraint{Typ: "none"}
		if sc.setup != nil {
			c, err := sc.setup(d)
			if err != nil {
				scenCancel() // setup failed — nothing from it should fire later
				headline := "could not arm the fault"
				if ctx.Err() != nil {
					headline += " (run aborted)"
				}
				d.appendFinding(mayFinding{
					ID: sc.ID, Name: sc.Name, Category: sc.Category,
					Hypothesis: sc.Hypothesis, Expected: sc.Expected,
					Verdict:   "INCONCLUSIVE",
					Headline:  headline,
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
		// Cancel the scenario context FIRST: any delayed-fault goroutine still
		// waiting on its timer must see this before teardown does its own
		// cleanup, so teardown is always the last writer.
		d.setPhase(i, sc, "recover")
		scenCancel()
		if sc.teardown != nil {
			sc.teardown(d)
		}

		ev := sc.evaluate
		if ev == nil {
			ev = diagnoseConstraint
		}
		f := ev(sc, cons, samples)
		f.Fix = sc.Fix
		if ctx.Err() != nil {
			// Run-integrity hardening (WS-3): an abort mid-scenario truncates the
			// sample window the diagnoser just judged, so whatever verdict it
			// computed from a partial hold is not a completed judgement. Force
			// INCONCLUSIVE with a distinct "aborted" marker rather than let a
			// partial-window PASS/FAIL stand as if the scenario had run to term.
			elapsed := 0.0
			if len(samples) > 0 {
				elapsed = samples[len(samples)-1].T
			}
			f.Verdict = "INCONCLUSIVE"
			f.Headline = fmt.Sprintf("aborted mid-scenario: %s", f.Headline)
			f.Diagnosis = append([]string{fmt.Sprintf(
				"The mayhem run was aborted %.0fs into this scenario's %ds hold window (only %d sample(s) collected). Re-run this scenario to completion before trusting any verdict.",
				elapsed, sc.HoldS, len(samples))}, f.Diagnosis...)
		}
		f = applySafetyAudit(f, cons, samples)
		d.appendFinding(f)

		if ctx.Err() != nil {
			d.finish(true, "")
			return
		}
	}
	d.finish(false, "")
}

// applySafetyAudit runs the cross-cutting safety-audit assertion engine
// against a scenario's finding — independent of that scenario's own oracle, a
// safety violation the targeted diagnoser would miss (back-feed during a
// disconnect, a pack past its reserve, an impossible EV draw, a stale control
// retained) is still surfaced, and escalates the verdict per escalateForAudit
// so a PASS can never hide one.
//
// WS-3: the audit's own INV-SOC leg (pastSettling(invSOC(s)) inside
// safetyAudit) is judged from the battery sim exactly like diagnoseSOC's, so
// it gets the identical probe-availability treatment — if the pack's
// ground-truth reading was mostly absent for this scenario's window, "the
// audit found no INV-SOC violation" is not trustworthy silence, and a PASS
// this cross-cutting check would otherwise wave through is downgraded to
// BLIND rather than certifying a battery-safety property the audit never
// actually got to observe. Extracted from the run loop so it is unit-testable
// without a live bench.
func applySafetyAudit(f mayFinding, cons *activeConstraint, samples []maySample) mayFinding {
	audit := safetyAudit(cons, samples)
	// f.Violations is the single source of truth the prose bullet below is
	// derived from (CONTRACTS.md §4) — same slice, no separate computation.
	f.Violations = audit
	if len(audit) > 0 {
		f.Diagnosis = append(f.Diagnosis, "⚠ "+invSummaryLine("SAFETY AUDIT", audit))
		if nv, hl := escalateForAudit(f.Verdict, audit); nv != f.Verdict {
			f.Verdict = nv
			f.Headline = hl
		}
	} else {
		f.Diagnosis = append(f.Diagnosis, invSummaryLine("SAFETY AUDIT", nil))
	}
	forceBlindOnBatteryProbeGap(&f, samples)
	return f
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

// afterDelay runs fn after delay UNLESS the current scenario has already
// moved past its hold (its scenarioCtx canceled) — the guard that makes
// teardown last-writer-wins over an in-flight delayed-fault goroutine (WS-3
// run-integrity hardening). Scenario setup/perTick funcs call this instead of
// a bare `go func(){ time.Sleep(d); ... }()` so a slow hold or an abort can
// never let the fault land after teardown already cleared it — e.g.
// malformScenario's "let the hub adopt a clean cap, THEN serve garbage after
// 8s" pattern must not re-arm the malform after the scenario has ended.
func (d *mayhemDriver) afterDelay(delay time.Duration, fn func()) {
	d.mu.Lock()
	ctx := d.scenarioCtx
	d.mu.Unlock()
	if ctx == nil {
		ctx = context.Background()
	}
	go func() {
		select {
		case <-time.After(delay):
			if ctx.Err() == nil {
				fn()
			}
		case <-ctx.Done():
		}
	}()
}

// armAfterAdoption fires fn once the hub reports an ACTIVE CSIP control
// (polled via hubState every pollEvery), or unconditionally at maxWait as a
// fallback so a never-adopting hub still gets its fault (and the oracle then
// reads the un-adopted state honestly). This closes the STOCK-cadence race a
// fixed afterDelay(8s) had: at STOCK the discovery interval is 20s, so the
// fault could be served BEFORE the hub's first walk ever adopted the safe cap
// — the 2026-07-10 STOCK gate false-FAILed malform-huge-activepower exactly
// this way ("unseated" a cap that was never seated). Same scenario-context
// guard as afterDelay: teardown stays last-writer-wins.
func (d *mayhemDriver) armAfterAdoption(pollEvery, maxWait time.Duration, fn func()) {
	d.mu.Lock()
	ctx := d.scenarioCtx
	d.mu.Unlock()
	if ctx == nil {
		ctx = context.Background()
	}
	go func() {
		deadline := time.After(maxWait)
		tick := time.NewTicker(pollEvery)
		defer tick.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-deadline:
				if ctx.Err() == nil {
					fn()
				}
				return
			case <-tick.C:
				if d.hubState().ctrlActive {
					if ctx.Err() == nil {
						fn()
					}
					return
				}
			}
		}
	}()
}

// armAfterCapAdopted is armAfterAdoption narrowed to a SPECIFIC control: it
// fires fn only once the hub is enforcing exactly (typ, limW) — not merely
// "some control is active". This matters whenever the bench default
// (program-0 DefaultDERControl, a 5 kW export cap) is present: hubState()
// reports ctrlActive=true for the default from the outset, so a plain
// armAfterAdoption fires before the scenario's own event cap is adopted. At
// STOCK (20 s discovery) that window is wide enough that a malform served
// then is held against the DEFAULT (→ ~4400 W) instead of the intended 0 W
// event, a false FAIL — the hub is provably correct once the event itself is
// last-known-good (manual STOCK hold-proof, 2026-07-10). Same maxWait
// fallback and scenario-context guard as armAfterAdoption.
func (d *mayhemDriver) armAfterCapAdopted(typ string, limW float64, pollEvery, maxWait time.Duration, fn func()) {
	d.mu.Lock()
	ctx := d.scenarioCtx
	d.mu.Unlock()
	if ctx == nil {
		ctx = context.Background()
	}
	go func() {
		deadline := time.After(maxWait)
		tick := time.NewTicker(pollEvery)
		defer tick.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-deadline:
				if ctx.Err() == nil {
					fn()
				}
				return
			case <-tick.C:
				h := d.hubState()
				if h.ctrlActive && h.ctrlTyp == typ && h.ctrlLimW == limW {
					if ctx.Err() == nil {
						fn()
					}
					return
				}
			}
		}
	}()
}

// ── Sampling ──────────────────────────────────────────────────────────────────

func (d *mayhemDriver) sample(cons *activeConstraint, t float64) maySample {
	s := maySample{T: round2(t), WallUnix: time.Now().Unix()}

	if gridW, ok := d.meterW(); ok {
		s.RealGridW, s.GridOK = gridW, true
	}
	if aw, pw, ok := d.solarSim(); ok {
		s.SolarW, s.SolarPossibleW, s.SolarOK = aw, pw, true
	}
	if pct, ena, ok := d.solarCeiling(); ok {
		s.SolarCeilingPct, s.SolarCeilingEna, s.SolarCeilingOK = pct, ena, true
	}
	if dw, da, ok := d.evSim(); ok {
		s.EvSimW, s.EvSimA, s.EvSimOK = dw, da, true
	}
	if bw, soc, ok := d.batterySim(); ok {
		s.BatterySimW, s.BatSimSOC, s.BatterySimOK = bw, soc, true
	}

	hub := d.hubState()
	s.HubReachable = hub.ok
	if hub.ok {
		s.HubGridW = hub.gridW
		s.HubSolarW = hub.solarW
		s.BatteryW = hub.batteryW
		s.BatSOC = hub.batSOC
		s.EvW = hub.evW
		s.EvSOC = hub.evSOC
		s.EvCurrentA = hub.evCurrentA
		s.EvMaxA = hub.evMaxA
		s.ClockOffsetS = hub.clockOffsetS
		s.Decisions = hub.decisions
		s.MeterStale = hub.meterStale
		s.EvStale = hub.evStale
		if hub.ctrlActive {
			s.HubAdopted = true
			s.AdoptedTyp = hub.ctrlTyp
			s.AdoptedLimW = hub.ctrlLimW
			s.AdoptedMRID = hub.ctrlMRID
			s.ValidUntil = hub.validUntil
		}
		s.DisconnectActive = hub.disconnectActive
	}
	// A CannotComply alert is only meaningful while a real control is in force.
	if cons != nil && cons.MRID != "" {
		if n := d.cannotComplyCount(cons.MRID); n >= 0 {
			s.CannotComply = n > 0
			s.CannotComplyCount = n
		}
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

// ── Probe availability (WS-3) ───────────────────────────────────────────────
//
// The vacuous-PASS gap: breachOver (above) and invSOC (invariants.go) both
// treat an absent judging sensor as "no breach this tick" — correct for a
// single dropped poll, but if the sensor is dead for most of the hold window
// the oracle is reading silence, not compliance. A dead solar probe on a
// genLimit scenario, or a dead battery sim on an INV-SOC scenario, must not
// be able to manufacture a PASS. These helpers make probe availability
// constraint-aware: each oracle is gated by the fraction of the window its
// OWN judging sensor actually answered, not by an unrelated one.

// probeAvailFrac is the fraction of s for which ok reports the judging sensor
// produced a coherent reading. An empty timeline reports 0 (unavailable) so a
// caller never mistakes "no samples" for a healthy probe.
func probeAvailFrac(s []maySample, ok func(maySample) bool) float64 {
	if len(s) == 0 {
		return 0
	}
	n := 0
	for _, smp := range s {
		if ok(smp) {
			n++
		}
	}
	return float64(n) / float64(len(s))
}

// judgingProbeOK returns the availability predicate for the sensor a
// constraint-cap oracle is actually judged from — mirroring breachOver's own
// per-Typ switch so the availability tally can never disagree with what the
// oracle reads. nil for a constraint type breachOver does not judge from a
// probe at all (connect/fixed/none) — those are not gated here.
func judgingProbeOK(typ string) func(maySample) bool {
	switch typ {
	case "exportCap", "importCap":
		return func(s maySample) bool { return s.GridOK }
	case "genLimit":
		return func(s maySample) bool { return s.SolarOK }
	default:
		return nil
	}
}

// judgingProbeLabel names the judging sensor for cons.Typ, for diagnosis text.
func judgingProbeLabel(typ string) string {
	switch typ {
	case "exportCap", "importCap":
		return "grid meter"
	case "genLimit":
		return "solar"
	default:
		return "probe"
	}
}

// forceBlindOnProbeGap closes the WS-3 vacuous-PASS gap: if f is currently
// PASS and the named judging sensor's availability over the window is below
// the mayJudgeAbsentBlindFrac floor, this overrides the verdict to BLIND with
// an explanation — the harness admits it was not watching for part of the
// window rather than certifying compliance it never measured.
//
// A verdict that is already FAIL/DEGRADED/BLIND/INCONCLUSIVE is left
// untouched: FAIL/DEGRADED were reached from data the sensor DID deliver
// (breachOver/invSOC only ever count a breach off a coherent reading), and
// downgrading a real finding to BLIND would hide it rather than fix the
// blind spot this exists to close.
func forceBlindOnProbeGap(f *mayFinding, label string, avail float64) {
	if f.Verdict != "PASS" || avail >= 1-mayJudgeAbsentBlindFrac {
		return
	}
	f.Verdict = "BLIND"
	f.Metrics.HubBlind = true
	f.Headline = fmt.Sprintf("%s probe absent for %.0f%% of the window — cannot trust the clean read", label, 100*(1-avail))
	f.Diagnosis = append(f.Diagnosis, fmt.Sprintf(
		"The %s judging sensor produced a coherent reading on only %.0f%% of samples (below the %.0f%% availability floor). An absent probe reads as \"no breach\" to the oracle, so this run's clean result is not evidence of compliance — the harness was not watching for part of the window. Fix the probe (or the fault injection wiring) and re-run before trusting this verdict.",
		label, 100*avail, 100*(1-mayJudgeAbsentBlindFrac)))
}

// forceBlindOnConstraintProbeGap applies forceBlindOnProbeGap using the
// judging sensor for cons.Typ — the shared choke point every constraint-cap
// diagnoser (diagnoseConstraint, diagnoseMalform) calls before returning a
// PASS built on breachOver(cons, ...).
func forceBlindOnConstraintProbeGap(f *mayFinding, cons *activeConstraint, s []maySample) {
	if cons == nil {
		return
	}
	ok := judgingProbeOK(cons.Typ)
	if ok == nil {
		return
	}
	forceBlindOnProbeGap(f, judgingProbeLabel(cons.Typ), probeAvailFrac(s, ok))
}

// forceBlindOnBatteryProbeGap applies forceBlindOnProbeGap using the battery
// sim as the judging sensor — INV-SOC's ground truth (invSOC, invariants.go)
// and the safety audit's INV-SOC leg (pastSettling(invSOC(s)) inside
// safetyAudit) both judge BatterySimW/BatSimSOC only when BatterySimOK.
func forceBlindOnBatteryProbeGap(f *mayFinding, s []maySample) {
	forceBlindOnProbeGap(f, "battery", probeAvailFrac(s, func(smp maySample) bool { return smp.BatterySimOK }))
}

// hubReactedSample reports whether the hub took a visible corrective action for
// the active constraint on this sample, using the lever appropriate to the
// constraint — not just solar curtailment. Without this, an import-cap or
// fixed-dispatch scenario where the hub discharged the battery reads as "no
// reaction" and gets mislabeled an adoption/command failure.
//
// Battery effect is judged from simulator ground truth where available (what the
// pack physically did), else the hub's view. EV current reduction is not counted:
// MeterValues carry no idle baseline to measure a reduction against, so an EV-only
// reaction is left to the per-scenario EV diagnosers rather than this generic
// metric (the limitation the reviewer flagged — scoped, not papered over).
func hubReactedSample(cons *activeConstraint, smp maySample) bool {
	// PV curtailment is a valid correction for any generation/export cap and for
	// a cease-to-energize (drive generation to zero).
	if smp.SolarOK && smp.SolarPossibleW-smp.SolarW > mayReactThreshW {
		return true
	}
	battW := smp.BatteryW
	if smp.BatterySimOK {
		battW = smp.BatterySimW
	}
	switch cons.Typ {
	case "exportCap", "genLimit":
		return battW < -mayReactThreshW // charging to absorb the surplus
	case "importCap", "fixed":
		return battW > mayReactThreshW // discharging to offset import / meet dispatch
	}
	return false
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
		if hubReactedSample(cons, smp) {
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
		forceBlindOnConstraintProbeGap(&f, cons, s)
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
	// Covers the m.TailClean/ConvergedAtS<=deadline branch above, the only other
	// path through this switch that can leave f.Verdict == "PASS" (a no-op for
	// every DEGRADED/FAIL branch).
	forceBlindOnConstraintProbeGap(&f, cons, s)
	return f
}

// diagnoseConverge handles the accept-but-don't-converge faults — ack_before_effect
// (the device lags the write) and reject_write (the device ACKs then ignores it
// entirely). In both the device ACKs at the Modbus layer but its output never
// reaches the commanded limit; the question is whether the hub detects that via
// measurement and reports it rather than trusting the write ACK.
func diagnoseConverge(sc *mayScenario, cons *activeConstraint, s []maySample) mayFinding {
	f := diagnoseConstraint(sc, cons, s)
	switch f.Verdict {
	case "PASS":
		// Re-frame: a breach here is expected while the device withholds the
		// effect; the verdict turns on whether the hub admitted it.
		f.Headline = "hub held the cap despite the device withholding the commanded effect"
		f.Diagnosis = append(f.Diagnosis, "Output converged within the cap and held — another lever covered the gap, or the effect arrived before the settling deadline.")
		return f
	case "INCONCLUSIVE", "BLIND":
		// The base constraint oracle already could not judge this window (meter
		// mostly down ⇒ INCONCLUSIVE, or WS-3's probe-availability gate forced
		// BLIND) — pass that verdict through unchanged. Falling into the
		// unconditional FAIL at the bottom of this function would mislabel
		// "couldn't see" as "device never honoured the write".
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
	// The meter is frozen. Did the hub DETECT it (surface it as stale) or stay blind?
	detected := 0
	for _, smp := range s {
		if smp.MeterStale {
			detected++
		}
	}
	if detected >= 3 { // sustained detection, not a one-sample blip
		f.Verdict = "DEGRADED"
		f.Headline = fmt.Sprintf("meter frozen at ~%.0f W; hub DETECTED it stale and surfaced it", lo)
		f.Diagnosis = []string{
			fmt.Sprintf("The grid meter held within %.0f W for the window, but the hub flagged it as stale (stale_sources) on %d samples — it is no longer flying blind on a dead sensor.", rangeW, detected),
			"Detection + surfacing is in place (it cross-checks the frozen reading against a moving inverter). Remaining hardening: have the OPTIMIZER fail safe on the flag (conservative limits) rather than only reporting it.",
			decisionLine(s),
		}
		f.Fix = "Detection done (lexa-api stale_sources). Next: gate the optimizer on the stale flag so a frozen grid meter drives conservative limits, not just an alarm."
		return f
	}

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
	// WS-3: this PASS rests on two clean reads — invSOC found nothing wrong
	// (judged from the battery sim) and the cap held (judged from cons.Typ's
	// meter/solar probe). Either sensor being mostly absent makes "found
	// nothing" indistinguishable from "wasn't looking".
	forceBlindOnBatteryProbeGap(&f, s)
	forceBlindOnConstraintProbeGap(&f, cons, s)
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
	viol := connectBackfeed(s)
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
// malformScenario builds a CSIP-robustness scenario for one gridsim malform kind:
// adopt a safe zero-export cap on a clean walk, then (8 s in) start serving the
// malformed resource and judge with diagnoseMalform — the hub must stay up and
// keep enforcing the safe cap. The battery is full so PV curtailment is the only
// lever, isolating "did the bad resource unseat the safe control" from battery
// behaviour. Shared by the malformed-resource variant suite.
func malformScenario(id, name, kind, hypothesis string) *mayScenario {
	const loadLow = 250.0
	return &mayScenario{
		ID: id, Name: name,
		Category:   "CSIP robustness (INV-EXPORT survivability)",
		Hypothesis: hypothesis,
		Expected:   "Stay up (/status keeps answering) and keep enforcing the active export cap. A malformed resource must not take the hub down or unseat a safe control.",
		HoldS:      75, // long enough that a real unseat stays breached to the tail and a transient blip recovers
		Fix:        "Harden the northbound walker/parser; bound the walk and fail closed to last-known-good controls on a malformed resource.",
		setup: func(d *mayhemDriver) (*activeConstraint, error) {
			_ = d.post("battery", "/inject", map[string]any{"SoC_pct": 100, "Conn": 1}) // battery full → PV curtailment is the only lever
			d.injectEnv(d.pvHighW, loadLow)
			// The BASELINE cap must stay valid through the whole 75 s observation
			// window: this scenario tests whether the malformed resource UNSEATS a
			// still-valid control, so the good cap must not legitimately expire
			// mid-window and score a false FAIL (audit: malform-empty-program was a
			// test artifact — the hub is correct to release a genuinely expired
			// control). Post it with a duration well past HoldS + setup + the 8 s
			// malform delay + settle. (postCap adds a further +20 s pad internally.)
			cons, err := d.postCap("exportCap", 0, 135, "mayhem: export cap then malformed "+kind)
			if err != nil {
				return nil, err
			}
			// Serve garbage only after the hub has adopted THIS 0 W event cap
			// (not merely the ever-present 5 kW bench default — see
			// armAfterCapAdopted). At STOCK that distinction is the difference
			// between the hub holding the intended 0 W event under the malform
			// (PASS) and holding the 5 kW default (false FAIL).
			d.armAfterCapAdopted(cons.Typ, cons.LimW, 2*time.Second, 60*time.Second, func() {
				_ = d.post("gridsim", "/admin/malform", map[string]any{"kind": kind})
			})
			return cons, nil
		},
		perTick:  func(d *mayhemDriver, i int) { d.injectEnv(d.pvHighW, loadLow) },
		evaluate: diagnoseMalform,
		teardown: func(d *mayhemDriver) { _ = d.post("gridsim", "/admin/malform", map[string]any{"clear": true}) },
	}
}

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
	// CannotComply excuses a breach only at a GENUINE physical limit. A malform
	// scenario holds an EXPORT cap, which the hub can always meet by curtailing PV
	// (and not discharging the battery) — so a sustained export breach here means
	// the malformed resource unseated or corrupted the safe cap, and a CannotComply
	// does not excuse exporting freely over a cap the hub could have held. (Import
	// caps, where an empty battery is a real limit, keep the admission excuse.)
	excusableCannot := f.Metrics.ReportedCannot && cons.Typ != "exportCap"
	if len(breaches) == 0 || excusableCannot {
		f.Verdict = "PASS"
		f.Headline = "contained the malformed resource and held the safe control"
		f.Diagnosis = []string{
			"The hub stayed up (/status kept answering) and kept enforcing the active export cap despite the malformed resource — the discovery error was contained and the safe control was not replaced by garbage or 'none'.",
			invSummaryLine("INV-EXPORT", breaches),
			hubVsRealLine(s),
		}
		forceBlindOnConstraintProbeGap(&f, cons, s)
		return f
	}
	// There WAS a post-deadline breach. Distinguish a sustained unseat (the cap
	// stays breached to the end of the window) from a brief transient the hub then
	// re-establishes (a clean tail). Only a sustained unseat is a containment
	// failure; a transient drop that recovers is a DEGRADED resilience note, not a
	// FAIL — this also keeps a single end-of-window sample from flapping the verdict.
	if f.Metrics.TailClean {
		f.Verdict = "DEGRADED"
		f.Headline = "transiently dropped the safe control under the malformed resource, then recovered"
		f.Diagnosis = []string{
			invSummaryLine("INV-EXPORT", breaches),
			"The malformed resource briefly unseated the active export cap (the inverter exported over it) but the hub re-established the cap before the end of the window — contained, but not seamlessly.",
			hubVsRealLine(s),
		}
		return f
	}
	f.Verdict = "FAIL"
	f.Headline = "malformed resource unseated the safe control"
	f.Diagnosis = []string{
		invSummaryLine("INV-EXPORT", breaches),
		"The malformed resource was served while a safe export cap was active, and the cap was then sustained-breached through the end of the window — the bad resource dropped or corrupted the safe control instead of being contained. For an export cap the hub can always curtail PV to comply, so a CannotComply does not excuse this.",
		decisionLine(s),
	}
	f.Fix = "Harden the northbound walker/parser; on a malformed resource fail closed to last-known-good controls rather than dropping or adopting garbage."
	return f
}

// diagnoseTransport handles the Modbus transport-fault scenarios (nan_sentinel,
// exception_code, latency). The hub MUST NOT act on a bad reading: it must
// recognise the SunSpec 0x8000 sentinel / a Modbus exception / a hung read as
// N-A or device-down and hold a safe value — never report a physically-
// impossible measurement, and never let the slow/failed device take down its
// control loop. The ground-truth solar value comes from the sim's /state (HTTP,
// unaffected by the Modbus fault); the hub's Modbus-derived reading is HubSolarW.
func diagnoseTransport(sc *mayScenario, cons *activeConstraint, s []maySample) mayFinding {
	f := baseFinding(sc)
	if len(s) == 0 {
		f.Verdict = "INCONCLUSIVE"
		f.Headline = "no samples"
		return f
	}
	f.Metrics = scanSamples(cons, s)

	reach := 0
	for _, smp := range s {
		if smp.HubReachable {
			reach++
		}
	}
	if reach < len(s)/2 {
		f.Verdict = "FAIL"
		f.Headline = "hub stopped responding under the transport fault"
		f.Diagnosis = []string{
			fmt.Sprintf("The hub's /status was unreachable on %d of %d samples — a slow/failed Modbus device blocked or crashed its control loop.", len(s)-reach, len(s)),
			"A device that hangs or errors on the wire must never take the hub down; reads must be bounded by a timeout and the device marked stale/down.",
		}
		f.Fix = "Bound every Modbus read with a timeout; on error/timeout mark the device stale and fail safe (lexa-modbus). Never block the optimizer on a device."
		return f
	}

	// A physically-impossible solar reading means the hub interpreted the 0x8000
	// sentinel / garbage as a real value instead of detecting device-down. Solar
	// output is always ≥0 and bounded well under 8 kW on this bench.
	garbage := 0
	var worst float64
	for _, smp := range s {
		if smp.HubReachable && (smp.HubSolarW < -100 || smp.HubSolarW > 8000) {
			garbage++
			if math.Abs(smp.HubSolarW) > math.Abs(worst) {
				worst = smp.HubSolarW
			}
		}
	}
	if garbage > len(s)/4 {
		f.Verdict = "FAIL"
		f.Headline = fmt.Sprintf("hub acted on a garbage Modbus reading (solar %.0f W)", worst)
		f.Diagnosis = []string{
			fmt.Sprintf("The hub reported a physically-impossible solar value (%.0f W) on %d of %d samples — it interpreted a transport-layer fault (the 0x8000 N/A sentinel, a Modbus exception, or a corrupted scale factor) as a real reading.", worst, garbage, len(s)),
			"A hub that acts on garbage transport data optimises against fabricated generation; the sentinel/bad scale must be recognised and the source marked suspect rather than trusted.",
			decisionLine(s),
		}
		f.Fix = "Treat 0x8000/0xFFFF as N/A and a Modbus exception as device-down; sanity-check decoded SunSpec power against the inverter nameplate so a corrupted scale factor cannot pass (lexa-modbus / sunspec)."
		return f
	}

	f.Verdict = "PASS"
	f.Headline = "hub did not act on the bad Modbus reading"
	f.Diagnosis = []string{
		"The hub stayed up and never reported a physically-impossible measurement under the transport fault — it recognised the sentinel/exception as N/A or device-down and held a safe value.",
		fmt.Sprintf("At t=%.0fs the sim's true solar was %.0f W; the hub reported %.0f W.", s[len(s)-1].T, s[len(s)-1].SolarW, s[len(s)-1].HubSolarW),
	}
	return f
}

// diagnoseEVFreeze judges the stop_metervalues fault: the charger keeps drawing
// (and still obeys SetChargingProfile) but stops emitting MeterValues/Updated, so
// the hub's per-EVSE telemetry freezes at its last value. Under an import cap the
// hub curtails the EV — its TRUE draw drops while its OCPP view stays frozen high,
// opening a divergence between what the hub believes and what the charger is doing.
// Two questions: (1) did the hub still hold the import cap — it can, via the real
// grid meter, even while blind to the EV channel; (2) did its EV telemetry go
// stale relative to ground truth. A cap held + frozen telemetry is BLIND: safe for
// now, but the hub cannot see the EVSE and would miss a later ramp.
func diagnoseEVFreeze(sc *mayScenario, cons *activeConstraint, s []maySample) mayFinding {
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
		return f
	}

	// Observability: does the hub's OCPP view of the EV diverge from ground truth?
	active, diverge := 0, 0
	var worstT, worstSim, worstHub float64
	for _, smp := range s {
		if !smp.EvSimOK {
			continue
		}
		ref := math.Max(smp.EvSimW, smp.EvW)
		if ref < mayEVLiveDrawW {
			continue // nothing meaningful on the EVSE this tick
		}
		active++
		if math.Abs(smp.EvW-smp.EvSimW) > 0.5*ref {
			diverge++
			if math.Abs(smp.EvW-smp.EvSimW) > math.Abs(worstHub-worstSim) {
				worstT, worstSim, worstHub = smp.T, smp.EvSimW, smp.EvW
			}
		}
	}
	hubBlind := active > 0 && diverge > active/2
	f.Metrics.HubBlind = hubBlind

	// Safety first: did the import cap hold? A bounded settling ramp is fine.
	settled := m.BreachSeconds == 0 ||
		(m.TailClean && m.ConvergedAtS >= 0 && m.ConvergedAtS <= mayConvergeDeadlineS)
	if !settled && !m.ReportedCannot {
		f.Verdict = "FAIL"
		f.Headline = fmt.Sprintf("%s breached %.0fs while blind to the EVSE", capStr, m.BreachSeconds)
		f.Diagnosis = []string{
			fmt.Sprintf("With the charger's MeterValues frozen the hub lost the import cap: peak %.0f W over for %.0fs and it never converged.", m.PeakBreachW, m.BreachSeconds),
			"A hub must not depend on per-device telemetry it can lose — the real grid meter still showed the breach; the optimizer should have curtailed off that and/or paused the session.",
			decisionLine(s),
		}
		f.Fix = "Stale-expire EVSE MeterValues and fall back to the grid meter for cap compliance; never assume a silent charger is idle (lexa-ocpp / orchestrator)."
		f.Diagnosis = append(f.Diagnosis, hubVsRealLine(s))
		return f
	}

	// Did the hub DETECT the silent charger (flag its telemetry stale)? If so it
	// held the cap off the grid meter AND is aware the per-EVSE view is stale — not
	// blind, so the divergence is acknowledged rather than silently trusted.
	evDetected := 0
	for _, smp := range s {
		if smp.EvStale {
			evDetected++
		}
	}
	if hubBlind && evDetected >= 3 {
		f.Verdict = "PASS"
		f.Headline = fmt.Sprintf("held %s and flagged the EVSE telemetry stale", capStr)
		f.Diagnosis = []string{
			fmt.Sprintf("The hub held the import cap off the real grid meter AND detected the charger's MeterValues went silent (flagged stale on %d samples) — it is not blindly trusting a frozen per-device reading.", evDetected),
			"Correct: cap compliance stays on the grid meter, and the stale EVSE telemetry is surfaced rather than trusted as live.",
		}
		return f
	}

	if hubBlind {
		f.Verdict = "BLIND"
		f.Headline = fmt.Sprintf("held %s but the hub's EVSE telemetry froze", capStr)
		f.Diagnosis = []string{
			fmt.Sprintf("The hub kept the cap (via the real grid meter), but its OCPP view of the EVSE diverged from ground truth on %d of %d active samples.", diverge, active),
			fmt.Sprintf("At t=%.0fs the charger truly drew %.0f W while the hub still reported %.0f W — its MeterValues had frozen.", worstT, worstSim, worstHub),
			"Safe for this static scenario, but the hub is blind to that EVSE: if the car ramped or a second load appeared it would not see it. Stale OCPP telemetry must be detected and flagged, not trusted.",
		}
		f.Fix = "Track MeterValues freshness per EVSE; mark a charger stale when Updated stops and surface it (lexa-ocpp / telemetry)."
		return f
	}

	f.Verdict = "PASS"
	f.Headline = fmt.Sprintf("held %s and tracked the EVSE through the telemetry gap", capStr)
	f.Diagnosis = []string{
		"The hub held the import cap and its EVSE view stayed consistent with ground truth despite the suppressed MeterValues — it did not act on stale telemetry.",
		fmt.Sprintf("Across %d active-EVSE samples the hub view tracked the charger's true draw (worst divergence %.0f W).", active, math.Abs(worstHub-worstSim)),
	}
	return f
}

// diagnoseReboot judges a device that drops off the Modbus bus and later returns
// (battery-reboot arms exception_code, then clears it mid-scenario). The oracle is
// three-part: the hub must (1) survive the outage — stay reachable, never hang on
// the dead device; (2) never report an impossible battery SoC/power while it is
// down; (3) recover a live reading after it returns. A pack that stays dropped for
// the whole post-reboot tail is BLIND (the hub never reconnected).
func diagnoseReboot(sc *mayScenario, cons *activeConstraint, s []maySample) mayFinding {
	f := baseFinding(sc)
	if len(s) == 0 {
		f.Verdict = "INCONCLUSIVE"
		f.Headline = "no samples collected (aborted before any reading)"
		return f
	}
	f.Metrics = scanSamples(cons, s)

	reach := 0
	for _, smp := range s {
		if smp.HubReachable {
			reach++
		}
	}
	if reach < len(s)/2 {
		f.Verdict = "FAIL"
		f.Headline = "hub stopped responding while the battery was off the bus"
		f.Diagnosis = []string{
			fmt.Sprintf("The hub's /status was unreachable on %d of %d samples — a dead battery blocked or crashed its control loop.", len(s)-reach, len(s)),
			"A device that stops answering must never take the hub down; reads must be bounded by a timeout and the pack marked down.",
		}
		f.Fix = "Bound battery reads with a timeout and mark the pack down on error; never block the optimizer on one device (lexa-modbus)."
		return f
	}

	// Impossible battery telemetry anywhere ⇒ the hub treated a missing/garbage
	// read as a real value. SoC is a percentage; battery power is well under 20 kW.
	garbage := 0
	var worstSOC float64 = 60
	for _, smp := range s {
		if !smp.HubReachable {
			continue
		}
		if smp.BatSOC > 101 || smp.BatSOC < -1 || math.Abs(smp.BatteryW) > 20000 {
			garbage++
			if math.Abs(smp.BatSOC-50) > math.Abs(worstSOC-50) {
				worstSOC = smp.BatSOC
			}
		}
	}
	if garbage > len(s)/4 {
		f.Verdict = "FAIL"
		f.Headline = fmt.Sprintf("hub reported an impossible battery reading (SoC %.0f%%)", worstSOC)
		f.Diagnosis = []string{
			fmt.Sprintf("On %d of %d samples the hub reported a physically-impossible battery SoC/power — it interpreted the exception/garbage from the off-bus pack as a real reading.", garbage, len(s)),
			"A dropped device must be marked down and its SoC stale-expired, not surfaced as live data.",
			decisionLine(s),
		}
		f.Fix = "On a Modbus exception mark the pack down and stale-expire its SoC; treat 0x8000/0xFFFF as N/A (lexa-modbus / sunspec)."
		return f
	}

	// Recovery: after the reboot the pack should read live again. If the entire
	// post-reboot tail still shows a dead (≈0) SoC, the hub never reconnected.
	endT := s[len(s)-1].T
	tailLive, tailSeen := false, false
	for _, smp := range s {
		if smp.T < endT-float64(mayConvergeHoldS) || !smp.HubReachable {
			continue
		}
		tailSeen = true
		if smp.BatSOC > 1 {
			tailLive = true
		}
	}
	if tailSeen && !tailLive {
		f.Verdict = "BLIND"
		f.Headline = "battery never came back after the reboot"
		f.Diagnosis = []string{
			"The hub rode out the outage without crashing or reporting garbage, but its battery reading stayed dead (≈0% SoC) through the whole post-reboot tail — it did not re-establish the pack after it returned to the bus.",
			"A rebooted device that answers again must be re-read; a permanently-dropped pack silently removes a control lever.",
		}
		f.Fix = "Re-probe / re-read a device after a Modbus error clears; do not latch it down permanently (lexa-modbus reconnect)."
		return f
	}

	f.Verdict = "PASS"
	f.Headline = "hub rode out the battery reboot and recovered a live reading"
	f.Diagnosis = []string{
		"The hub stayed up through the outage, never reported an impossible SoC/power, and read a live battery again after it returned to the bus.",
		fmt.Sprintf("Final battery reading: SoC %.0f%%, power %.0f W.", s[len(s)-1].BatSOC, s[len(s)-1].BatteryW),
	}
	return f
}

// diagnoseExpiry judges whether the hub releases a DERControl at its expiry. The
// scenario posts a short-lived export cap; once it is past validUntil + grace the
// hub must stop adopting it. A hub that keeps enforcing an expired control is
// caught by INV-EXPIRED. If the hub never adopted the control at all the expiry
// cannot be judged (INCONCLUSIVE) rather than a false PASS.
func diagnoseExpiry(sc *mayScenario, cons *activeConstraint, s []maySample) mayFinding {
	f := baseFinding(sc)
	if len(s) == 0 {
		f.Verdict = "INCONCLUSIVE"
		f.Headline = "no samples collected (aborted before any reading)"
		return f
	}
	f.Metrics = scanSamples(cons, s)

	adoptedEver := false
	for _, smp := range s {
		if smp.HubAdopted {
			adoptedEver = true
			break
		}
	}
	if !adoptedEver {
		f.Verdict = "INCONCLUSIVE"
		f.Headline = "hub never adopted the control — cannot judge expiry"
		f.Diagnosis = []string{
			"The hub never showed the export cap in csip_control during the window, so whether it expires the control correctly cannot be determined.",
			"Re-run; CSIP discovery may have missed the short-lived control before it expired.",
		}
		return f
	}

	if viol := invExpiredControl(s); len(viol) > 0 {
		f.Metrics.HubAdopted = true
		last := viol[len(viol)-1]
		f.Verdict = "FAIL"
		f.Headline = "hub enforced the control past its expiry"
		f.Diagnosis = []string{
			fmt.Sprintf("After the control's validUntil (+%ds grace) the hub was still adopting it: %s at t=%.0fs.", invExpiredGraceS, last.Detail, last.T),
			"An expired DERControl must be released — keeping it enforced curtails the inverter the utility no longer commands.",
			invSummaryLine("INV-EXPIRED", viol),
		}
		f.Fix = sc.Fix
		return f
	}

	f.Verdict = "PASS"
	f.Headline = "hub released the control at expiry"
	f.Diagnosis = []string{
		"The hub adopted the export cap while it was valid and dropped it within the grace window after validUntil — it never enforced an expired control.",
		expiryRecoveryLine(s),
	}
	return f
}

// expiryRecoveryLine reports the inverter's final output vs its potential, the
// evidence that the cap actually lifted once the control expired.
func expiryRecoveryLine(s []maySample) string {
	for i := len(s) - 1; i >= 0; i-- {
		if s[i].SolarOK {
			return fmt.Sprintf("At t=%.0fs the inverter produced %.0f W of %.0f W possible — free to recover once the cap expired.", s[i].T, s[i].SolarW, s[i].SolarPossibleW)
		}
	}
	return "No solar sample to confirm post-expiry recovery."
}

// diagnoseBatteryGarbage judges a held transport fault on the battery (the pack's
// registers read the 0x8000 N/A sentinel, so SoC/power decode to garbage). The hub
// must stay up and never surface an impossible SoC (a percentage) or power — it
// must recognise the sentinel as N/A rather than optimise against a fabricated SoC.
func diagnoseBatteryGarbage(sc *mayScenario, cons *activeConstraint, s []maySample) mayFinding {
	f := baseFinding(sc)
	if len(s) == 0 {
		f.Verdict = "INCONCLUSIVE"
		f.Headline = "no samples collected (aborted before any reading)"
		return f
	}
	f.Metrics = scanSamples(cons, s)

	reach := 0
	for _, smp := range s {
		if smp.HubReachable {
			reach++
		}
	}
	if reach < len(s)/2 {
		f.Verdict = "FAIL"
		f.Headline = "hub stopped responding under the battery transport fault"
		f.Diagnosis = []string{
			fmt.Sprintf("The hub's /status was unreachable on %d of %d samples — a garbage/failed battery read blocked or crashed its control loop.", len(s)-reach, len(s)),
			"A device returning garbage must never take the hub down; reads must be bounded and the pack marked down.",
		}
		f.Fix = sc.Fix
		return f
	}

	garbage := 0
	var worstSOC float64 = 50
	for _, smp := range s {
		if !smp.HubReachable {
			continue
		}
		if smp.BatSOC > 101 || smp.BatSOC < -1 || math.Abs(smp.BatteryW) > 20000 {
			garbage++
			if math.Abs(smp.BatSOC-50) > math.Abs(worstSOC-50) {
				worstSOC = smp.BatSOC
			}
		}
	}
	if garbage > len(s)/4 {
		f.Verdict = "FAIL"
		f.Headline = fmt.Sprintf("hub acted on a garbage battery reading (SoC %.0f%%)", worstSOC)
		f.Diagnosis = []string{
			fmt.Sprintf("The hub reported a physically-impossible battery SoC/power on %d of %d samples — it interpreted the SunSpec 0x8000 N/A sentinel as a real reading.", garbage, len(s)),
			"A hub that acts on the not-implemented sentinel optimises against a fabricated SoC; 0x8000 must be treated as N/A and the pack marked unavailable.",
			decisionLine(s),
		}
		f.Fix = sc.Fix
		return f
	}

	f.Verdict = "PASS"
	f.Headline = "hub did not act on the garbage battery reading"
	f.Diagnosis = []string{
		"The hub stayed up and never reported an impossible SoC/power under the transport fault — it recognised the sentinel as N/A and held a safe value.",
		fmt.Sprintf("Final battery reading: SoC %.0f%%, power %.0f W.", s[len(s)-1].BatSOC, s[len(s)-1].BatteryW),
	}
	return f
}

// diagnoseEVFlap judges a flapping EVSE connector (status oscillating
// Occupied/Faulted while a session is up). The hub must ride it out: stay up,
// never command EV current over the station max (a sign it mis-tracked the
// connector), and never surface an impossible EV power. Debouncing the flap is the
// expected behaviour; thrashing or over-current is the failure.
func diagnoseEVFlap(sc *mayScenario, cons *activeConstraint, s []maySample) mayFinding {
	f := baseFinding(sc)
	if len(s) == 0 {
		f.Verdict = "INCONCLUSIVE"
		f.Headline = "no samples collected (aborted before any reading)"
		return f
	}
	f.Metrics = scanSamples(cons, s)

	reach := 0
	for _, smp := range s {
		if smp.HubReachable {
			reach++
		}
	}
	if reach < len(s)/2 {
		f.Verdict = "FAIL"
		f.Headline = "hub stopped responding while the connector flapped"
		f.Diagnosis = []string{
			fmt.Sprintf("The hub's /status was unreachable on %d of %d samples — a flapping connector should never take it down.", len(s)-reach, len(s)),
			"Debounce StatusNotification; a flaky connector must not block the control loop.",
		}
		f.Fix = sc.Fix
		return f
	}

	if viol := invEVStationMax(s); len(viol) > 0 {
		f.Metrics.HubBlind = false
		f.Verdict = "FAIL"
		f.Headline = "hub commanded EV current over the station max during the flap"
		f.Diagnosis = []string{
			fmt.Sprintf("The EVSE drew over its configured station max on %d sample(s) — the hub mis-tracked the flapping connector and over-committed current.", len(viol)),
			invSummaryLine("INV-EVMAX", viol),
		}
		f.Fix = sc.Fix
		return f
	}

	garbage := 0
	for _, smp := range s {
		if smp.HubReachable && (smp.EvW < -100 || smp.EvW > 25000) {
			garbage++
		}
	}
	if garbage > len(s)/4 {
		f.Verdict = "FAIL"
		f.Headline = "hub reported an impossible EV power during the flap"
		f.Diagnosis = []string{
			fmt.Sprintf("The hub reported a physically-impossible EVSE power on %d of %d samples while the connector flapped.", garbage, len(s)),
			"A flapping connector must not corrupt the EVSE telemetry the optimizer reads.",
		}
		f.Fix = sc.Fix
		return f
	}

	f.Verdict = "PASS"
	f.Headline = "hub stayed stable through the connector flap"
	f.Diagnosis = []string{
		"The hub rode out the flapping connector: it stayed up, never commanded EV current over the station max, and reported no impossible EVSE power.",
		"A flaky connector did not thrash the control loop.",
	}
	return f
}

// diagnoseEVUnits judges the wrong_units fault: the charger reports its current
// ~1000× too high (milliamps under an "A" label). The hub must sanity-check the
// reading against the station max and reject a physically-impossible current — if
// it surfaces a current many times the station max (or a wild power), it ingested
// the mislabeled value and is optimising against fabricated draw.
func diagnoseEVUnits(sc *mayScenario, cons *activeConstraint, s []maySample) mayFinding {
	f := baseFinding(sc)
	if len(s) == 0 {
		f.Verdict = "INCONCLUSIVE"
		f.Headline = "no samples collected (aborted before any reading)"
		return f
	}
	f.Metrics = scanSamples(cons, s)

	reach := 0
	for _, smp := range s {
		if smp.HubReachable {
			reach++
		}
	}
	if reach < len(s)/2 {
		f.Verdict = "FAIL"
		f.Headline = "hub stopped responding under the wrong-units reading"
		f.Diagnosis = []string{
			fmt.Sprintf("The hub's /status was unreachable on %d of %d samples — a wrong-units MeterValue should never take it down.", len(s)-reach, len(s)),
		}
		f.Fix = sc.Fix
		return f
	}

	bad := 0
	var worstA, worstW float64
	for _, smp := range s {
		if !smp.HubReachable {
			continue
		}
		impl := false
		if smp.EvMaxA > 0 && smp.EvCurrentA > smp.EvMaxA*5 { // many times any plausible station max
			impl = true
			if smp.EvCurrentA > worstA {
				worstA = smp.EvCurrentA
			}
		}
		if smp.EvW > 25000 {
			impl = true
			if smp.EvW > worstW {
				worstW = smp.EvW
			}
		}
		if impl {
			bad++
		}
	}
	if bad > len(s)/4 {
		f.Verdict = "FAIL"
		f.Headline = fmt.Sprintf("hub ingested the wrong-units reading (%.0f A / %.0f W)", worstA, worstW)
		f.Diagnosis = []string{
			fmt.Sprintf("On %d of %d samples the hub surfaced a physically-impossible EVSE current/power — it trusted the mislabeled MeterValue (≈1000× the real draw) instead of sanity-checking it against the station max.", bad, len(s)),
			"A hub that optimises against a fabricated current will mis-plan the whole site; MeterValues must be validated against the EVSE rating before use.",
			decisionLine(s),
		}
		f.Fix = sc.Fix
		return f
	}

	f.Verdict = "PASS"
	f.Headline = "hub rejected the wrong-units reading"
	f.Diagnosis = []string{
		"The hub stayed up and never surfaced a physically-impossible EVSE current/power under the wrong-units fault — it validated the MeterValue against the station rating rather than trusting a 1000× draw.",
		fmt.Sprintf("Worst EVSE reading the hub reported: %.0f A.", maxEvCurrent(s)),
	}
	return f
}

// maxEvCurrent returns the largest EV current the hub reported across the window.
func maxEvCurrent(s []maySample) float64 {
	var m float64
	for _, smp := range s {
		if smp.EvCurrentA > m {
			m = smp.EvCurrentA
		}
	}
	return m
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

// mayReportDir is where writeReport saves its markdown run reports —
// under logs/, never the process CWD directly (CONTRACTS.md §4/§7). The
// report list/fetch routes (qa_reports.go) read from this same directory,
// and qaReportNameRe there is the filename scheme writeReport produces.
const mayReportDir = "logs/qa"

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
	if err := os.MkdirAll(mayReportDir, 0o755); err != nil {
		log.Printf("mayhem: could not create report dir %s: %v", mayReportDir, err)
		return ""
	}
	path := filepath.Join(mayReportDir, fmt.Sprintf("qa-mayhem-%s.md", time.Now().Format("20060102-150405")))
	var b strings.Builder
	fmt.Fprintf(&b, "# Mayhem QA report\n\n")
	fmt.Fprintf(&b, "Run started %s. %d pass · %d degraded · **%d fail** · **%d blind** · %d inconclusive.\n",
		st.StartedAt.Format(time.RFC3339), st.Summary.Pass, st.Summary.Degraded, st.Summary.Fail, st.Summary.Blind, st.Summary.Inconclusive)
	fmt.Fprintf(&b, "Worst breach: %.0f W. Total time out of limit: %.0fs.\n\n", st.Summary.WorstPeakW, st.Summary.TotalBreachS)
	if st.ChaosSeed != 0 {
		fmt.Fprintf(&b, "Chaos run — replay this exact sequence with `--chaos --seed %d`.\n\n", st.ChaosSeed)
	}
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
	req, err := http.NewRequest(http.MethodPost, base+path, bytes.NewReader(buf))
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

func (d *mayhemDriver) getJSON(name, path string, out any) error {
	base, ok := d.backends[name]
	if !ok {
		return fmt.Errorf("unknown backend %q", name)
	}
	req, err := http.NewRequest(http.MethodGet, base+path, nil)
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

// cannotComplyCount returns how many CannotComply Response POSTs gridsim has
// recorded for mrid (WS-4.5, docs/refactor/HANDOFF.md §8) — the ground-truth
// count backing maySample.CannotComplyCount. Returns -1, not 0, when gridsim
// is unreachable: a caller distinguishing "confirmed zero" from "unknown"
// (e.g. a scenario proving no duplicate POST landed) must not treat a probe
// failure as a clean reading.
func (d *mayhemDriver) cannotComplyCount(mrid string) int {
	var out struct {
		Alerts []struct {
			Subject string `json:"subject"`
		} `json:"alerts"`
	}
	if err := d.getJSON("gridsim", "/admin/alerts", &out); err != nil {
		return -1
	}
	n := 0
	for _, a := range out.Alerts {
		if a.Subject == mrid {
			n++
		}
	}
	return n
}

// reportedCannotComply is cannotComplyCount's presence-only view, used by
// every existing diagnoser that only cares WHETHER a CannotComply was
// posted, not how many times.
func (d *mayhemDriver) reportedCannotComply(mrid string) bool {
	return d.cannotComplyCount(mrid) > 0
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

// solarCeiling reads the inverter's OWN curtailment-ceiling register straight
// from the solar sim /state (sim/southbound/solar.go's SolarState.Controls) —
// ground truth for what lexa-modbus most recently WROTE to the device via
// Modbus, independent of what the hub's own /status claims it commanded. This
// is the register consumer-restart-after-quiescence (WS-2, HANDOFF.md §8)
// watches: a fail-open re-seed writes bus.RestoreCeilingW, which clamps to
// WMax on the wire — WMaxLimPct_pct reads ~100% (or the limit is reported
// disabled) — verifiably distinct from a live low-percent enforced cap.
// pctCeiling is the percent of nameplate currently honoured (0–100); limitEna
// is the device's own WMaxLimPct_Ena bit.
func (d *mayhemDriver) solarCeiling() (pctCeiling float64, limitEna bool, ok bool) {
	var st struct {
		Controls struct {
			WMaxLimPctPct float64 `json:"WMaxLimPct_pct"`
			WMaxLimPctEna int     `json:"WMaxLimPct_Ena"`
		} `json:"controls"`
	}
	if err := d.getJSON("solar", "/state", &st); err != nil {
		return 0, false, false
	}
	return st.Controls.WMaxLimPctPct, st.Controls.WMaxLimPctEna != 0, true
}

// evSim reads the charger's TRUE draw straight from the ev sim /state — the
// ground truth the hub only sees through OCPP MeterValues. Under a
// stop_metervalues fault the hub's view freezes while this keeps moving, which
// is exactly how diagnoseEVFreeze tells a blind hub from a sighted one. Returns
// 0 draw when no session is active.
func (d *mayhemDriver) evSim() (drawW, currentA float64, ok bool) {
	var st struct {
		Session struct {
			Active bool `json:"active"`
		} `json:"session"`
		Battery struct {
			PowerW   float64 `json:"power_W"`
			CurrentA float64 `json:"current_A"`
		} `json:"battery"`
	}
	if err := d.getJSON("ev", "/state", &st); err != nil {
		return 0, 0, false
	}
	if !st.Session.Active {
		return 0, 0, true
	}
	return st.Battery.PowerW, st.Battery.CurrentA, true
}

// batterySim reads the pack's TRUE net power and SoC straight from the batsim
// /state — the ground truth the hub only sees through Modbus. INV-SOC must judge
// the real pack, not the hub's view: under a wrong_sign / soc_refuse fault, or a
// blind/stale/sanitizing hub, the hub's battery reading can disagree with what
// the pack is physically doing, and the safety oracle has to catch the latter.
// Sign matches the hub convention: net W > 0 discharging, < 0 charging.
func (d *mayhemDriver) batterySim() (netW, socPct float64, ok bool) {
	var st struct {
		Battery struct {
			SoCPct float64 `json:"SoC_pct"`
		} `json:"battery"`
		Measurements struct {
			WW float64 `json:"W_W"`
		} `json:"measurements"`
	}
	if err := d.getJSON("battery", "/state", &st); err != nil {
		return 0, 0, false
	}
	return st.Measurements.WW, st.Battery.SoCPct, true
}

type mayHubState struct {
	ok                           bool
	gridW, batteryW, evW, solarW float64
	batSOC, evSOC                float64
	evCurrentA, evMaxA           float64
	clockOffsetS                 int64
	ctrlActive                   bool
	ctrlTyp, ctrlMRID            string
	ctrlLimW                     float64
	validUntil                   int64
	disconnectActive             bool
	decisions                    []string
	meterStale                   bool // hub flagged the grid meter frozen (stale_sources)
	evStale                      bool // hub flagged an EVSE's telemetry silent
}

func (d *mayhemDriver) hubState() mayHubState {
	var st struct {
		ClockOffsetS int64 `json:"clock_offset_s"`
		CSIPControl  *struct {
			MRID       string `json:"mrid"`
			ValidUntil int64  `json:"valid_until"`
			Base       struct {
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
			PowerW      float64  `json:"power_W"`
			SOC         *float64 `json:"soc_pct"`
			CurrentA    float64  `json:"current_A"`
			MaxCurrentA float64  `json:"max_current_A"`
			Stale       bool     `json:"stale"`
		} `json:"evse_stations"`
		StaleSources []string `json:"stale_sources"`
		LastPlan     struct {
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
	h.solarW = st.Power.SolarW
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
		if e.CurrentA > h.evCurrentA { // worst (highest-drawing) station
			h.evCurrentA, h.evMaxA = e.CurrentA, e.MaxCurrentA
		}
		if e.Stale {
			h.evStale = true
		}
	}
	for _, src := range st.StaleSources {
		if !strings.HasPrefix(src, "evse:") { // any non-EVSE stale source is a meter
			h.meterStale = true
		}
	}
	if c := st.CSIPControl; c != nil {
		h.ctrlActive = true
		h.ctrlMRID = c.MRID
		h.validUntil = c.ValidUntil
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
	d.clearAllFaults()
	_ = d.post("battery", "/inject", map[string]any{"SoC_pct": 50, "Conn": 1})
	// Capture the pack into hub-controlled idle: restoreBench (end of the
	// previous run) released it to the demo sinusoid, and the hub's deduped
	// idle command wouldn't re-capture it for up to 60 s (see resetForScenario).
	_ = d.post("battery", "/inject", map[string]any{"WMaxLimPct_pct": 0})
	_ = d.post("battery", "/inject", map[string]any{"Ena": 1})
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

// clearAllFaults disarms every fault injector across the bench (Modbus DER
// faults, OCPP faults, gridsim malform). Shared by baseline, restoreBench, and
// the per-scenario reset.
func (d *mayhemDriver) clearAllFaults() {
	_ = d.post("solar", "/fault", map[string]any{"kind": "ack_before_effect", "clear": true})
	_ = d.post("solar", "/fault", map[string]any{"kind": "reject_write", "clear": true})
	_ = d.post("solar", "/fault", map[string]any{"kind": "enable_gate", "clear": true})
	_ = d.post("solar", "/fault", map[string]any{"kind": "ramp_limit", "clear": true})
	_ = d.post("battery", "/fault", map[string]any{"kind": "wrong_sign", "clear": true})
	_ = d.post("battery", "/fault", map[string]any{"kind": "soc_refuse", "clear": true})
	_ = d.post("battery", "/fault", map[string]any{"kind": "charge_disabled", "clear": true})
	_ = d.post("battery", "/fault", map[string]any{"kind": "discharge_disabled", "clear": true})
	for _, k := range []string{"profile_reject", "apply_next_tx", "min_current_floor", "stop_metervalues", "apply_delayed", "wrong_units", "out_of_order_txevent"} {
		_ = d.post("ev", "/fault", map[string]any{"kind": k, "clear": true})
	}
	for _, dev := range []string{"solar", "battery"} {
		for _, k := range []string{"nan_sentinel", "latency", "exception_code"} {
			_ = d.post(dev, "/fault", map[string]any{"kind": k, "clear": true})
		}
	}
	_ = d.post("solar", "/fault", map[string]any{"kind": "bad_scale", "clear": true})
	for _, k := range []string{"invert_sign", "nan_sentinel", "latency", "exception_code"} {
		_ = d.post("meter", "/fault", map[string]any{"kind": k, "clear": true})
	}
	// Server-plumbing faults (Batch 3): unit_id_confusion / register_tearing are
	// sticky and must be disarmed on every Modbus sim. tcp_drop and boot_mid_tx
	// are one-shot actions with no sticky state (a clear is a no-op), so they are
	// not cleared here — posting them would needlessly re-fire the action.
	for _, dev := range []string{"solar", "battery", "meter"} {
		for _, k := range []string{"unit_id_confusion", "register_tearing"} {
			_ = d.post(dev, "/fault", map[string]any{"kind": k, "clear": true})
		}
	}
	_ = d.post("gridsim", "/admin/malform", map[string]any{"clear": true})
	_ = d.post("gridsim", "/admin/gone", map[string]any{"clear": true})
	_ = d.post("gridsim", "/admin/delay", map[string]any{"clear": true})
	d.gridsimOutageClear()
}

// resetForScenario isolates each scenario from the previous one's device state.
// Without it a device left curtailed (or a fault left armed) by scenario N can
// mask a fault in scenario N+1 — e.g. a reject_write that "rejects" a new
// curtailment simply holds the prior scenario's low ceiling, so the breach never
// shows. It clears every fault, all controls and clock skew, returns the inverter
// to an uncurtailed start and idles the battery, so each scenario starts clean.
func (d *mayhemDriver) resetForScenario() {
	for prog := 0; prog <= 2; prog++ {
		d.deleteControls(prog)
	}
	_ = d.post("gridsim", "/admin/clock", map[string]any{"offset_s": 0})
	d.clearAllFaults()
	_ = d.post("solar", "/inject", map[string]any{"WMaxLimPct_pct": 100}) // uncurtail
	// Idle the battery under HELD control: pct 0 alone RELEASES the pack to the
	// free-running demo sinusoid (that is restoreBench's demo semantics), and at
	// a cycle boundary the hub's idle command is dedupe-suppressed for up to
	// 60 s — scenario 1 then measured a ±4 kW ghost battery it never commanded
	// (QA v6: export-cap-full-battery INV-SOC FAIL, 50 s overshoots). The
	// second POST must be separate: within one body, map order is unspecified
	// and pct-0's implicit Ena-clear could land after the override.
	_ = d.post("battery", "/inject", map[string]any{"WMaxLimPct_pct": 0})
	_ = d.post("battery", "/inject", map[string]any{"Ena": 1}) // hold idle, don't release
	_ = d.post("ev", "/inject", map[string]any{"action": "stop_session", "connector_id": 1})
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
	d.clearAllFaults()
	_ = d.post("solar", "/inject", map[string]any{"WMaxLimPct_pct": 100}) // uncurtail the inverter
	_ = d.post("solar", "/control", map[string]any{"cmd": "resume", "speed": 1})
	_ = d.post("battery", "/inject", map[string]any{"Conn": 1, "WMaxLimPct_pct": 0})
	_ = d.post("battery", "/control", map[string]any{"cmd": "resume", "speed": 1})
	_ = d.post("meter", "/control", map[string]any{"cmd": "resume"})
	_ = d.post("ev", "/inject", map[string]any{"action": "stop_session", "connector_id": 1})
	_ = d.post("ev", "/inject", map[string]any{"action": "set_sim_speed", "speed": 1})
	log.Printf("mayhem: bench restored (clock 0, programs cleared, faults cleared, sims at 1×)")
}

// postCap posts a duration-bounded cap control to program 0 (primacy 1) and
// returns the constraint to judge against.
func (d *mayhemDriver) postCap(typ string, limW float64, holdS int, desc string) (*activeConstraint, error) {
	return d.postCapProg(0, typ, limW, holdS, desc)
}

// postCapProg posts a cap control to a specific DERProgram (0/1/2 ⇒ primacy
// 1/5/10; lower wins), for primacy/conflict scenarios.
func (d *mayhemDriver) postCapProg(program int, typ string, limW float64, holdS int, desc string) (*activeConstraint, error) {
	body := map[string]any{
		"program":     program,
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
			ID: "ev-meter-freeze", Name: "Charger keeps charging but stops reporting MeterValues",
			Category:   "OCPP observability (INV-EVBLIND)",
			Hypothesis: "The charger still obeys SetChargingProfile but stops emitting MeterValues/Updated. Under an import cap the hub curtails the EV — its true draw drops while the hub's OCPP view freezes at the old high value. The hub goes blind to that EVSE: it cannot attribute load, and would miss the car ramping back up.",
			Expected:   "Hold the cap off the real grid meter (which still works), AND detect that the EVSE telemetry went stale — flag the charger, do not keep trusting a frozen reading.",
			HoldS:      70,
			Fix:        "Track MeterValues freshness per EVSE and stale-expire a silent charger; keep cap compliance on the grid meter, not per-device OCPP telemetry (lexa-ocpp / telemetry).",
			setup: func(d *mayhemDriver) (*activeConstraint, error) {
				_ = d.post("battery", "/inject", map[string]any{"SoC_pct": 5, "Conn": 1})
				_ = d.post("ev", "/inject", map[string]any{"action": "set_soc", "soc_pct": 30})
				_ = d.post("ev", "/inject", map[string]any{"action": "start_session", "connector_id": 1})
				d.injectEnv(300, 500)
				if err := d.post("ev", "/fault", map[string]any{"kind": "stop_metervalues"}); err != nil {
					return nil, fmt.Errorf("arm stop_metervalues: %w", err)
				}
				// A cap the hub CAN meet by modulating the EV — so the true draw moves
				// (creating the hub-vs-truth divergence) while the cap still holds.
				return d.postCap("importCap", 1000, 70, "mayhem: import cap while the charger's MeterValues are frozen")
			},
			perTick:  func(d *mayhemDriver, i int) { d.injectEnv(300, 500) },
			evaluate: diagnoseEVFreeze,
			teardown: func(d *mayhemDriver) {
				_ = d.post("ev", "/fault", map[string]any{"kind": "stop_metervalues", "clear": true})
				_ = d.post("ev", "/inject", map[string]any{"action": "stop_session", "connector_id": 1})
			},
		},
		{
			ID: "malformed-csip", Name: "Grid server serves a malformed resource",
			Category:   "CSIP robustness (INV-EXPORT survivability)",
			Hypothesis: "A buggy or hostile 2030.5 server serves a malformed DERControlList (the same control mRID twice) while a safe export cap is active. The hub must contain the parse error — never panic/hang, never drop the safe control for garbage or 'none'.",
			Expected:   "Stay up (/status keeps answering) and keep enforcing the active export cap. A malformed resource must not take the hub down or unseat a safe control.",
			HoldS:      75,
			Fix:        "Harden the northbound walker/parser; on a malformed resource fail closed to last-known-good controls.",
			setup: func(d *mayhemDriver) (*activeConstraint, error) {
				_ = d.post("battery", "/inject", map[string]any{"SoC_pct": 100, "Conn": 1}) // battery full → PV curtailment is the only lever
				d.injectEnv(d.pvHighW, loadLow)
				cons, err := d.postCap("exportCap", 0, 75, "mayhem: export cap then malformed resource")
				if err != nil {
					return nil, err
				}
				// Serve garbage only after the hub adopts THIS 0 W event cap (not
				// the bench default — see armAfterCapAdopted).
				d.armAfterCapAdopted(cons.Typ, cons.LimW, 2*time.Second, 60*time.Second, func() {
					_ = d.post("gridsim", "/admin/malform", map[string]any{"kind": "dup_mrid"})
				})
				return cons, nil
			},
			perTick:  func(d *mayhemDriver, i int) { d.injectEnv(d.pvHighW, loadLow) },
			evaluate: diagnoseMalform,
			teardown: func(d *mayhemDriver) { _ = d.post("gridsim", "/admin/malform", map[string]any{"clear": true}) },
		},
		malformScenario("malform-missing-href", "Grid server strips the program list's href",
			"missing_href",
			"The 2030.5 server serves a DERProgramList with its own href stripped — an unresolvable resource. A hub that dereferences the missing link can NPE/hang or drop the whole program tree (and the safe control with it)."),
		malformScenario("malform-empty-program", "Grid server serves an empty program list",
			"empty_program_list",
			"The server suddenly serves a DERProgramList with zero programs (all=0) while a safe export cap is active. A hub that treats 'no programs' as 'cancel everything' silently drops the active cap instead of keeping last-known-good."),
		malformScenario("malform-huge-activepower", "Grid server serves an absurd ActivePower limit",
			"huge_activepower",
			"A DERControl arrives with an export limit of 32767×10^9 W — overflow bait. A hub that scales it into an int register wraps to garbage (audit GS-1/MTR-1) and may command a wild setpoint or drop the safe cap."),
		malformScenario("malform-bad-duration", "Grid server serves a ~136-year control interval",
			"bad_duration",
			"A DERControl interval is served with a 4294967295 s (~136-year) duration. A hub that trusts it never expires the control, or overflows its expiry math — either pinning a setpoint forever or mis-scheduling the safe cap."),
		malformScenario("malform-pagination", "Grid server lies about list pagination",
			"pagination",
			"The DERProgramList header claims all=999 programs across pages while serving one and advertising no real next page. A pager that trusts all= can loop fetching pages that never come or over-allocate — a discovery DoS that must be bounded."),
		{
			ID: "pricing-attack", Name: "Grid server serves malicious pricing",
			Category:   "CSIP robustness (pricing §10.5)",
			Hypothesis: "A hostile 2030.5 server serves a malformed tariff (an absurd price multiplier, 10^100) while a safe export cap is active. Pricing must affect optimization only WITHIN safety constraints — a bad tariff must never break DER discovery, unseat the safe control, or produce a NaN command.",
			Expected:   "Stay up and keep enforcing the active export cap; a bad tariff must not perturb the safety control. NOTE: the hub does not consume CSIP prices today (lexa-northbound discovers tariffs but never walks ConsumptionTariffInterval), so a price attack has no INTENDED behavioural effect — but QA observed the malformed tariff TRANSIENTLY drops the export cap mid-walk (DEGRADED) before the hub re-establishes it.",
			HoldS:      75,
			Fix:        "Isolate discovery of a malformed leaf resource so it cannot perturb an already-adopted safety control — QA showed a bad tariff briefly unseats the export cap before the hub recovers. Separately, wire lexa-northbound to walk ConsumptionTariffInterval so CSIP prices actually drive dispatch, bounded by the safety constraints.",
			setup: func(d *mayhemDriver) (*activeConstraint, error) {
				_ = d.post("battery", "/inject", map[string]any{"SoC_pct": 100, "Conn": 1}) // full → PV curtailment is the only lever
				d.injectEnv(d.pvHighW, loadLow)
				cons, err := d.postCap("exportCap", 0, 75, "mayhem: export cap under malicious pricing")
				if err != nil {
					return nil, err
				}
				// Let the hub adopt the safe cap, then start serving the bad tariff.
				d.afterDelay(8*time.Second, func() {
					_ = d.post("gridsim", "/admin/malform", map[string]any{"kind": "bad_price_multiplier"})
				})
				return cons, nil
			},
			perTick:  func(d *mayhemDriver, i int) { d.injectEnv(d.pvHighW, loadLow) },
			evaluate: diagnoseMalform,
			teardown: func(d *mayhemDriver) { _ = d.post("gridsim", "/admin/malform", map[string]any{"clear": true}) },
		},
		{
			ID: "curve-attack", Name: "Grid server serves an empty DER curve list",
			Category:   "CSIP robustness (DER curves §)",
			Hypothesis: "A program advertises a DERCurveListLink (Volt-VAr) but the server serves an empty curve list while a safe export cap is active. A missing/empty curve must be contained — discovery of optional curves is non-fatal and must never break DER control.",
			Expected:   "Stay up and keep enforcing the active export cap; an empty curve list must not perturb the safety control. (Like pricing, the hub discovers DER curves but does not yet consume them for control.) QA observed a brief transient cap drop before the hub recovers (DEGRADED).",
			HoldS:      75,
			Fix:        "Isolate optional-resource discovery (curves) so a malformed/empty leaf cannot transiently unseat an adopted control. Curves are discovered but not yet applied to inverter control modes — a wiring gap, not a safety one.",
			setup: func(d *mayhemDriver) (*activeConstraint, error) {
				_ = d.post("battery", "/inject", map[string]any{"SoC_pct": 100, "Conn": 1})
				d.injectEnv(d.pvHighW, loadLow)
				cons, err := d.postCap("exportCap", 0, 75, "mayhem: export cap under empty curve list")
				if err != nil {
					return nil, err
				}
				d.afterDelay(8*time.Second, func() {
					_ = d.post("gridsim", "/admin/malform", map[string]any{"kind": "empty_curve_list"})
				})
				return cons, nil
			},
			perTick:  func(d *mayhemDriver, i int) { d.injectEnv(d.pvHighW, loadLow) },
			evaluate: diagnoseMalform,
			teardown: func(d *mayhemDriver) { _ = d.post("gridsim", "/admin/malform", map[string]any{"clear": true}) },
		},
		{
			ID: "ev-connector-flap", Name: "EVSE connector flaps Occupied/Faulted mid-session",
			Category:   "OCPP observability (INV-EVMAX)",
			Hypothesis: "A flaky connector (bad pilot or contactor) rapidly flaps its status between Occupied and Faulted while a session is up. A hub that re-plans on every StatusNotification can thrash its commands or mis-track the session and command current to a connector it believes is free.",
			Expected:   "Debounce the flapping status, keep the session bounded, never command EV current over the station max, and stay up.",
			HoldS:      50,
			Fix:        "Debounce connector StatusNotification and bound EV current to the station max regardless of flap (lexa-ocpp).",
			setup: func(d *mayhemDriver) (*activeConstraint, error) {
				_ = d.post("ev", "/inject", map[string]any{"action": "set_soc", "soc_pct": 40})
				_ = d.post("ev", "/inject", map[string]any{"action": "start_session", "connector_id": 1})
				d.injectEnv(300, 1500)
				return &activeConstraint{Typ: "none"}, nil
			},
			perTick: func(d *mayhemDriver, i int) {
				d.injectEnv(300, 1500)
				st := []string{"Occupied", "Faulted"}[i%2] // flap the connector every tick
				_ = d.post("ev", "/inject", map[string]any{"connector_id": 1, "status": st})
			},
			evaluate: diagnoseEVFlap,
			teardown: func(d *mayhemDriver) {
				_ = d.post("ev", "/inject", map[string]any{"connector_id": 1, "status": "Available"})
				_ = d.post("ev", "/inject", map[string]any{"action": "stop_session", "connector_id": 1})
			},
		},
		{
			ID: "ev-wrong-units", Name: "Charger reports MeterValues current in the wrong units",
			Category:   "OCPP observability (INV-EVMAX)",
			Hypothesis: "The charger reports its current in milliamps under an 'A' label (≈1000× the real value), so a hub that trusts the value+unit reads thousands of amps. A hub that ingests it commands against a fabricated draw, alarms falsely, or computes a wild power — far over any station max.",
			Expected:   "Sanity-check MeterValues against the station/connector max and reject a physically-impossible current; never surface or optimise against a 1000× reading.",
			HoldS:      40,
			Fix:        "Validate MeterValues against the EVSE's rated max (and unit) before use; clamp/reject implausible readings (lexa-ocpp telemetry).",
			setup: func(d *mayhemDriver) (*activeConstraint, error) {
				_ = d.post("ev", "/inject", map[string]any{"action": "set_soc", "soc_pct": 40})
				_ = d.post("ev", "/inject", map[string]any{"action": "start_session", "connector_id": 1})
				d.injectEnv(300, 1500)
				if err := d.post("ev", "/fault", map[string]any{"kind": "wrong_units", "mult": 1000}); err != nil {
					return nil, fmt.Errorf("arm wrong_units: %w", err)
				}
				return &activeConstraint{Typ: "none"}, nil
			},
			perTick:  func(d *mayhemDriver, i int) { d.injectEnv(300, 1500) },
			evaluate: diagnoseEVUnits,
			teardown: func(d *mayhemDriver) {
				_ = d.post("ev", "/fault", map[string]any{"kind": "wrong_units", "clear": true})
				_ = d.post("ev", "/inject", map[string]any{"action": "stop_session", "connector_id": 1})
			},
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
			ID: "clock-jitter", Name: "CSIP clock corrections jitter while a cap is active",
			Category:   "Time integrity",
			Hypothesis: "NTP corrections step the grid server's clock by up to a minute while an export cap is active — event boundaries shift slightly under the hub.",
			Expected:   "Keep honouring the active cap across the correction: a modest, spec-legal clock step inside the event window must not flap the control or drop enforcement.",
			HoldS:      45, // jitter starts at i=10 (post-adoption); 45 s samples the full 7 s offset cycle several times
			Fix: "Tolerate a non-monotonic clock-offset step across the event window: scheduler holds a still-served, unexpired, ALREADY-ADOPTED event over both an empty resolution and the program's DefaultDERControl (clock-regression guard, both halves). " +
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
				//
				// The jitter begins only once the cap is adopted and settled
				// (i ≥ 10) — the same discipline as clock-jump-forward's "adopted
				// and settled; now time lurches". Jittering from i=0 straddles the
				// event's own START boundary: at a −30/−60 s sample the event
				// legitimately reads not-yet-started (the server clock is
				// authoritative), the hub correctly enforces the 5 kW default,
				// and the verdict measures an adoption race instead of the stated
				// hypothesis (corrections during an ACTIVE cap). QA v6 C3/C4 and
				// the 2026-07-03 spot-run failed exactly that race.
				//
				// The 7 s offset cycle is deliberately COPRIME with the ~5 s
				// discovery walk period: the old 5 s cycle aliased against it, so
				// every walk in a given run sampled the same single offset — a
				// run tested one offset, not jitter (and which offset was luck).
				if i >= 10 {
					off := int64((i%7 - 3) * 20) // −60…+60 in 20 s steps, 7 s cycle
					_ = d.post("gridsim", "/admin/clock", map[string]any{"offset_s": off})
				}
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
				d.afterDelay(8*time.Second, func() {
					_ = d.post("meter", "/control", map[string]any{"cmd": "pause"})
				})
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
	sc = append(sc, d.mqttScenarios()...)
	sc = append(sc, d.worldScenarios()...)
	sc = append(sc, d.intentScenarios()...)
	// Standards build-out supplemental QA (2026-07, docs/QA_STANDARDS_BUILDOUT.md):
	// reporting (B), advanced-DER+AUS (C), OCPP/V2G/OpenADR (D). Track A is the
	// modsim 7xx sim surface (no scenarios). All Go-literal, no oracleRegistry entries.
	sc = append(sc, d.reportingScenarios()...)
	sc = append(sc, d.advScenarios()...)
	sc = append(sc, d.ocppOpenADRScenarios()...)
	// CSIP server-edge fault seams (E): supersede/cancel/randomizeDuration on
	// the wire + 410/event-delay/slow-loris survival (docs/QA_COMPLETENESS_AUDIT.md
	// Batch 2). Go-literal oracles, see mayhem_csipedge.go's header.
	sc = append(sc, d.csipEdgeScenarios()...)
	// Transport / OCPP-lifecycle / rogue-value & boundary seams (F): Modbus
	// tcp_drop/unit-id/register-tearing, negative served limit, out-of-range
	// write saturation, boundary SoC, OCPP out-of-order/boot-mid-tx
	// (docs/QA_COMPLETENESS_AUDIT.md Batch 3 — the "may surface hub bugs" set).
	// Go-literal oracles, see mayhem_transport.go's header.
	sc = append(sc, d.transportScenarios()...)

	// TASK-076: scenarios-as-data. scenarios() runs fresh on every call —
	// handleStart calls it at REQUEST time, never once at process start — so
	// a spec file added or edited under d.scenarioDir takes effect on the
	// very next run with NO dashboard rebuild and NO csip-dashboard restart.
	// That is the fix for the 2026-07-03 stale-bin/dashboard incident (D8):
	// there is nothing left to forget to rebuild for a scenario-only change.
	//
	// An ID collision with a Go scenario above (or between two spec files) is
	// a load error, logged loudly here, and that ONE spec is skipped — it
	// must never silently shadow the Go twin, and it must never take the rest
	// of a run down (see loadSpecScenarios).
	existing := make(map[string]bool, len(sc))
	for _, s := range sc {
		existing[s.ID] = true
	}
	specs, errs := d.loadSpecScenarios(d.scenarioDir, existing)
	for _, e := range errs {
		log.Printf("mayhem: scenario spec load error: %v", e)
	}
	sc = append(sc, specs...)
	return sc
}
