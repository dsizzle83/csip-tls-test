package aggregator

// engine.go is the HEADLESS CAMPAIGN ENGINE (T06.6): the runner that loads a
// validated Campaign, connects as its role, executes its steps in order against a
// target, records every observation into a verdict-free RunState, and then hands
// the finished evidence to the campaign's named oracle for a single Verdict. It
// is the aggregator counterpart of the Mayhem run loop (cmd/dashboard/mayhem.go):
// each step verb maps 1:1 to a driver method here, exactly as each Mayhem action
// maps to a mayhemDriver method, so the vocabulary can only grow by mirroring a
// primitive — never by adding control flow.
//
// The engine's session/discovery/poll/write/readback/denial primitives are the
// T06.4/T06.5/T06.7 core (session.go, discover.go, poll.go, control.go,
// readback.go); this file only sequences them and threads a cancellable context
// so a campaign stops cleanly. Dependencies (how to connect, how to resolve a
// target to an address, how to arm a sim fault) are injected as function values
// (CODING_PRINCIPLES §1) so the engine drives both the live gateway and a
// loopback authz server without importing either.

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"lexa-proto/mbap"
)

// RunOptions injects the engine's environment as function values, never concrete
// packages. ConnectAs and Resolve are required; Fault is optional (a campaign
// that uses sim_fault without it gets a clear per-step error).
type RunOptions struct {
	// ConnectAs dials addr presenting role r's client certificate and returns a
	// live Conn. The production wiring (NewPKIEngine) binds this to the package
	// ConnectAs over a PKIRefs; a test binds it to a loopback dialer.
	ConnectAs func(addr string, r Role) (*Conn, error)
	// Resolve maps a campaign/step target name (TargetGateway/TargetDevice) to a
	// dial address.
	Resolve func(target string) (string, error)
	// Fault arms or clears a fault on a named sim (the sim_fault verb): simapi over
	// HTTP for a live run, an in-process hook for the loopback test. nil disables
	// sim_fault.
	Fault func(target string, spec json.RawMessage) error
}

// Engine runs campaigns. now/wait are injectable clocks (defaulted to real time
// in NewEngine) so a test can drive deterministic timing without a real wall
// clock; wait is context-cancellable, so no bare time.Sleep sits in the run path
// (CODING_PRINCIPLES §6).
type Engine struct {
	opts RunOptions
	now  func() time.Time
	wait func(ctx context.Context, d time.Duration) bool
}

// NewEngine builds an engine from injected options, defaulting the clock to real
// time.
func NewEngine(opts RunOptions) *Engine {
	return &Engine{opts: opts, now: time.Now, wait: realWait}
}

// NewPKIEngine wires the production path: ConnectAs over the given PKIRefs, and a
// Resolve backed by a target→address map (e.g. {"gateway":"69.0.0.2:802"}). Fault
// is left nil — the interactive CLI (T06.9) wires an simapi HTTP injector on top.
func NewPKIEngine(pki PKIRefs, addrs map[string]string) *Engine {
	return NewEngine(RunOptions{
		ConnectAs: func(addr string, r Role) (*Conn, error) { return ConnectAs(addr, r, pki) },
		Resolve: func(target string) (string, error) {
			if a, ok := addrs[target]; ok && a != "" {
				return a, nil
			}
			return "", fmt.Errorf("no address configured for target %q", target)
		},
	})
}

// realWait sleeps for d, returning true if the full duration elapsed and false if
// ctx was cancelled first — the engine's cancellable stand-in for time.Sleep.
func realWait(ctx context.Context, d time.Duration) bool {
	if d <= 0 {
		return ctx.Err() == nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

// campaignRun is the mutable per-run state: the live session, the verdict-free
// recorder, the accrued step results, the units discovered so far (for a poll
// "*"), and the background poll cancels/waitgroup.
type campaignRun struct {
	e          *Engine
	camp       *Campaign
	addr       string
	role       Role // the currently-connected role (camp.Role, or a connect_as override)
	conn       *Conn
	rs         *RunState
	steps      []StepResult
	discovered []uint8
	pollCancel []context.CancelFunc
	pollWG     sync.WaitGroup
}

// Run executes one campaign end to end and returns its CampaignReport. It returns
// an error only for an engine MISCONFIGURATION (missing ConnectAs/Resolve, or a
// target that will not resolve); every campaign-level outcome — including a
// failure to connect — is a verdict in the report, never a Go error, so a batch
// runner (T06.9) can keep going and a CI gate can compare the verdict.
func (e *Engine) Run(ctx context.Context, camp *Campaign) (*CampaignReport, error) {
	if e.opts.ConnectAs == nil || e.opts.Resolve == nil {
		return nil, fmt.Errorf("aggregator: engine misconfigured — ConnectAs and Resolve are required")
	}
	addr, err := e.opts.Resolve(camp.Target)
	if err != nil {
		return nil, fmt.Errorf("aggregator: resolve target %q: %w", camp.Target, err)
	}

	started := e.now()
	report := &CampaignReport{
		CampV: CampaignV, ID: camp.ID, Name: camp.Name, Role: camp.Role,
		Target: camp.Target, Addr: addr, Oracle: camp.Oracle.Name,
		Started: started, ExpectedVerdicts: camp.ExpectedVerdicts,
	}

	run := &campaignRun{e: e, camp: camp, addr: addr, role: camp.Role, rs: NewRunState(addr, camp.Role)}

	// Connect as the campaign's role. A connect failure is a campaign outcome
	// (INCONCLUSIVE) with the report still carrying a verdict — not an engine error.
	conn, cerr := e.opts.ConnectAs(addr, camp.Role)
	if cerr != nil {
		return e.finishNoConnect(report, started, fmt.Sprintf("could not connect as %s to %s: %v", camp.Role, addr, cerr)), nil
	}
	run.conn = conn
	run.rs.SetSession(conn.SessionInfo())

	for i, s := range camp.Steps {
		if ctx.Err() != nil {
			run.steps = append(run.steps, StepResult{Index: i, Do: s.Do, Err: "campaign cancelled"})
			break
		}
		run.steps = append(run.steps, run.dispatch(ctx, i, s))
	}

	// Stop background polls and close the session BEFORE reading the recorder, so
	// the report copy sees a quiesced RunState (the WaitGroup establishes the
	// happens-before that makes the field reads race-free).
	run.stopPolls()
	if run.conn != nil {
		_ = run.conn.Close()
	}

	e.finalize(run, report, started)
	return report, nil
}

// finishNoConnect finalizes a report for a campaign that never established a
// session: an INCONCLUSIVE verdict with the connect failure as the sole finding.
func (e *Engine) finishNoConnect(report *CampaignReport, started time.Time, msg string) *CampaignReport {
	report.Verdict = VerdictInconclusive
	report.Findings = []string{msg}
	report.Ended = e.now()
	report.DurationS = report.Ended.Sub(started).Seconds()
	report.VerdictExpected = verdictIn(VerdictInconclusive, report.ExpectedVerdicts)
	report.SummaryHuman = report.renderSummary()
	return report
}

// finalize copies the raw observations out of the recorder, runs the oracle, and
// renders the verdict/summary. Called after all polls have stopped.
func (e *Engine) finalize(run *campaignRun, report *CampaignReport, started time.Time) {
	report.Steps = run.steps
	report.Session = run.rs.Session
	report.Devices = run.rs.Devices
	report.Samples = run.rs.Samples
	report.Denials = run.rs.Denials

	oracle, err := buildOracle(run.camp.Oracle)
	if err != nil {
		report.Verdict = VerdictInconclusive
		report.Findings = []string{fmt.Sprintf("oracle %q could not be built: %v", run.camp.Oracle.Name, err)}
	} else {
		report.Verdict, report.Findings = oracle(report)
	}
	report.Ended = e.now()
	report.DurationS = report.Ended.Sub(started).Seconds()
	report.VerdictExpected = verdictIn(report.Verdict, report.ExpectedVerdicts)
	report.SummaryHuman = report.renderSummary()
}

// dispatch routes a step to its driver method. Every verb was accepted at load
// (validateStep), so the default arm is defensive only.
func (r *campaignRun) dispatch(ctx context.Context, i int, s Step) StepResult {
	switch s.Do {
	case StepConnectAs:
		return r.doConnectAs(i, s)
	case StepDiscover:
		return r.doDiscover(ctx, i, s)
	case StepPoll:
		return r.doPoll(ctx, i, s)
	case StepWritePoint:
		return r.doWritePoint(i, s)
	case StepWriteMulti:
		return r.doWriteMulti(i, s)
	case StepReadback:
		return r.doReadback(ctx, i, s)
	case StepExpectException:
		return r.doExpectException(i, s)
	case StepDisconnect:
		return r.doDisconnect(i, s)
	case StepResume:
		return r.doResume(ctx, i, s)
	case StepRenegotiate:
		return r.doRenegotiate(i, s)
	case StepSleep:
		return r.doSleep(ctx, i, s)
	case StepSimFault:
		return r.doSimFault(i, s)
	default:
		return StepResult{Index: i, Do: s.Do, Err: "unknown verb (should have been rejected at load)"}
	}
}

// wait is the campaignRun's view of the engine's cancellable sleep, so readback.go
// reads cleanly.
func (r *campaignRun) wait(ctx context.Context, d time.Duration) bool { return r.e.wait(ctx, d) }

// doConnectAs switches the session to a new role: stop polls, close the current
// session, and dial afresh. The discovered-unit list survives (the same gateway
// serves the same units to any role — discovery is reads, allowed for all roles);
// only the handshake facts change.
func (r *campaignRun) doConnectAs(i int, s Step) StepResult {
	res := StepResult{Index: i, Do: StepConnectAs}
	r.stopPolls()
	if r.conn != nil {
		_ = r.conn.Close()
		r.conn = nil
	}
	conn, err := r.e.opts.ConnectAs(r.addr, s.Role)
	if err != nil {
		res.Err = err.Error()
		return res
	}
	r.conn = conn
	r.role = s.Role
	si := conn.SessionInfo()
	r.rs.SetSession(si)
	res.Session = &si
	res.OK = true
	res.Note = fmt.Sprintf("connected as %s", s.Role)
	return res
}

// doDiscover walks the per-device unit map and records the inventory, extending
// the discovered-unit set a later poll "*" draws on.
func (r *campaignRun) doDiscover(ctx context.Context, i int, s Step) StepResult {
	res := StepResult{Index: i, Do: StepDiscover}
	if r.conn == nil {
		res.Err = "no session (connect first)"
		return res
	}
	var units []uint8
	if s.Units != nil && !s.Units.All {
		units = s.Units.Units
	}
	devs, err := r.conn.Discover(ctx, units...)
	if err != nil {
		res.Err = err.Error()
		return res
	}
	r.rs.AddDevices(devs)
	for _, d := range devs {
		if !containsUnit(r.discovered, d.Unit) {
			r.discovered = append(r.discovered, d.Unit)
		}
	}
	res.OK = true
	res.Note = fmt.Sprintf("discovered %d device(s): units %v", len(devs), unitList(devs))
	return res
}

// doPoll starts a background telemetry loop on the selected units, streaming
// snapshots into the RunState (a SnapshotSink). The loop runs until the campaign
// ends or a disconnect/connect_as stops it.
func (r *campaignRun) doPoll(ctx context.Context, i int, s Step) StepResult {
	res := StepResult{Index: i, Do: StepPoll}
	if r.conn == nil {
		res.Err = "no session (connect first)"
		return res
	}
	units := r.selectUnits(s.Units)
	if len(units) == 0 {
		res.Err = "poll: no units (run discover first, or list units explicitly)"
		return res
	}
	period := secondsDur(s.PeriodS)
	conn := r.conn
	pctx, cancel := context.WithCancel(ctx)
	r.pollCancel = append(r.pollCancel, cancel)
	r.pollWG.Add(1)
	go func() {
		defer r.pollWG.Done()
		// Poll returns nil on ctx-cancel (the normal stop) and only errors on
		// arguments already validated here/at load (period>0, units non-empty);
		// per-cycle I/O failures surface as CommLoss/Stale snapshots, not this
		// return value — so discarding it drops no observable failure.
		_ = conn.Poll(pctx, units, period, r.rs)
	}()
	res.OK = true
	res.Note = fmt.Sprintf("polling units %v every %s", units, period)
	return res
}

// selectUnits resolves a UnitSel: "*" (or absent) ⇒ everything discovered so far;
// an explicit list ⇒ exactly those units.
func (r *campaignRun) selectUnits(sel *UnitSel) []uint8 {
	if sel == nil || sel.All {
		return append([]uint8(nil), r.discovered...)
	}
	return append([]uint8(nil), sel.Units...)
}

// doWritePoint performs a typed, scale-correct control write and records its
// latency. When win_tms/rvrt_tms are set it also writes the reversion-timer
// companion register(s), so the gateway can revert on expiry.
func (r *campaignRun) doWritePoint(i int, s Step) StepResult {
	res := StepResult{Index: i, Do: StepWritePoint}
	if r.conn == nil {
		res.Err = "no session (connect first)"
		return res
	}
	start := r.e.now()
	err := r.conn.WritePoint(s.Unit, s.Model, s.Point, s.Value)
	lat := r.e.now().Sub(start).Milliseconds()
	res.LatencyMS = lat
	wr := WriteRecord{Unit: s.Unit, Model: s.Model, Point: s.Point, Value: s.Value, At: start, LatencyMS: lat, OK: err == nil}
	if err != nil {
		wr.Err = err.Error()
		res.Err = err.Error()
		if ex, ok := AsException(err); ok {
			res.Note = fmt.Sprintf("write rejected with exception %d", ex.Code)
		}
		r.rs.AddWrite(wr)
		res.Write = &wr
		return res
	}
	r.rs.AddWrite(wr)
	res.Write = &wr
	res.OK = true
	r.writeReversionCompanions(s, &res)
	return res
}

// writeReversionCompanions writes the <point>RvrtTms (and, where the layout has
// one, <point>WinTms) companion registers so a commanded limit reverts on expiry.
// 704 has no WinTms companion, so win_tms is recorded as metadata there.
func (r *campaignRun) writeReversionCompanions(s Step, res *StepResult) {
	if s.RvrtTms > 0 {
		r.writeCompanion(s, s.Point+"RvrtTms", float64(s.RvrtTms), res)
	}
	if s.WinTms > 0 {
		if r.layoutHasCompanion(s.Model, s.Point+"WinTms") {
			r.writeCompanion(s, s.Point+"WinTms", float64(s.WinTms), res)
		} else {
			res.Note = appendNote(res.Note, fmt.Sprintf("win_tms=%d recorded (model %d has no %sWinTms companion)", s.WinTms, s.Model, s.Point))
		}
	}
}

// layoutHasCompanion reports whether model's fixed layout defines a named point.
func (r *campaignRun) layoutHasCompanion(model uint16, name string) bool {
	l, err := layoutFor(model)
	if err != nil {
		return false
	}
	return l.Has(name)
}

// writeCompanion writes one companion register if it exists in the model layout,
// noting the outcome on the step (best-effort — a companion write failure is a
// note, not a step failure, since the primary write already landed).
func (r *campaignRun) writeCompanion(s Step, point string, value float64, res *StepResult) {
	if !r.layoutHasCompanion(s.Model, point) {
		res.Note = appendNote(res.Note, fmt.Sprintf("companion %s not in model %d — skipped", point, s.Model))
		return
	}
	if err := r.conn.WritePoint(s.Unit, s.Model, point, value); err != nil {
		res.Note = appendNote(res.Note, fmt.Sprintf("companion %s write failed: %v", point, err))
		return
	}
	r.rs.AddWrite(WriteRecord{Unit: s.Unit, Model: s.Model, Point: point, Value: value, At: r.e.now(), OK: true})
	res.Note = appendNote(res.Note, fmt.Sprintf("wrote reversion companion %s=%g", point, value))
}

// doWriteMulti is the raw FC16 escape hatch for a register the typed writer cannot
// address (e.g. a repeating-group point). It performs no scale-factor encoding —
// the campaign supplies raw register words.
func (r *campaignRun) doWriteMulti(i int, s Step) StepResult {
	res := StepResult{Index: i, Do: StepWriteMulti}
	if r.conn == nil {
		res.Err = "no session (connect first)"
		return res
	}
	start := r.e.now()
	err := r.conn.WriteMultiple(s.Unit, s.Addr, s.Values)
	res.LatencyMS = r.e.now().Sub(start).Milliseconds()
	if err != nil {
		res.Err = err.Error()
		if ex, ok := AsException(err); ok {
			res.Note = fmt.Sprintf("write rejected with exception %d", ex.Code)
		}
		return res
	}
	res.OK = true
	res.Note = fmt.Sprintf("wrote %d register(s) at unit %d addr %d", len(s.Values), s.Unit, s.Addr)
	return res
}

// doExpectException probes a control write and records how the gateway answered.
// It never returns a Go error for a protocol exception — that is the expected,
// reported outcome. A transport failure leaves Exception nil so the denyExpected
// oracle scores the probe INCONCLUSIVE (could not observe) rather than a wrong-
// code FAIL.
func (r *campaignRun) doExpectException(i int, s Step) StepResult {
	res := StepResult{Index: i, Do: StepExpectException}
	if r.conn == nil {
		res.Err = "no session (connect first)"
		return res
	}
	want := s.ExpectCode
	if want == 0 {
		want = uint8(mbap.ExIllegalFunction) // default: 01, the authz-denial code
	}
	dr, err := r.conn.ProbeDenied(s.Unit, s.Model, s.Point, s.Value)
	if err != nil {
		res.Err = err.Error()
		res.Note = "transport error probing denial"
		return res
	}
	r.rs.AddDenial(dr)
	match := !dr.Wrote && dr.ExceptionCode == want
	res.Exception = &ExceptionCheck{Result: dr, Expected: want, Match: match}
	res.OK = match
	if dr.Wrote {
		res.Note = "write was ACCEPTED (authz gap)"
	} else {
		res.Note = fmt.Sprintf("answered exception %d (expected %d)", dr.ExceptionCode, want)
	}
	return res
}

// doDisconnect stops polls and closes the session.
func (r *campaignRun) doDisconnect(i int, s Step) StepResult {
	res := StepResult{Index: i, Do: StepDisconnect}
	r.stopPolls()
	if r.conn != nil {
		_ = r.conn.Close()
		r.conn = nil
	}
	res.OK = true
	res.Note = "session closed"
	return res
}

// doResume re-establishes the session as the currently-selected role. If the
// session is merely broken it redials in place (backoff-bounded by ctx); if it was
// closed by a prior disconnect it dials afresh. Either path goes through
// mbtls.Dial, which now offers the cached TLS session (T06.8), so a re-establish
// to the same peer+identity RESUMES when the peer allows it (TCP-46) — the
// handshake facts, incl. Resumed, are attached to the step for the resumeAfterDrop
// oracle to judge.
func (r *campaignRun) doResume(ctx context.Context, i int, s Step) StepResult {
	res := StepResult{Index: i, Do: StepResume}
	if r.conn == nil {
		conn, err := r.e.opts.ConnectAs(r.addr, r.role)
		if err != nil {
			res.Err = err.Error()
			return res
		}
		r.conn = conn
	} else if err := r.conn.Reconnect(ctx); err != nil {
		res.Err = err.Error()
		return res
	}
	si := r.conn.SessionInfo()
	r.rs.SetSession(si)
	res.Session = &si
	res.OK = true
	res.Note = fmt.Sprintf("session re-established as %s (resumed=%t)", r.role, si.Resumed)
	return res
}

// doRenegotiate drives the renegotiation-refusal probe (T06.8): it attempts a
// client-initiated TLS renegotiation on the live session and records the
// OBSERVED policy — refused (the conformant gateway's expected behaviour: it
// advertises the RFC 5746 indication per TCP-62 but declines an actual
// renegotiation) or handled — plus whether the session stayed safe afterwards. A
// renegotiation is never an application error: a refusal is the expected outcome,
// so it is reported, not returned. When the step names a unit, a follow-up read
// confirms the session is still usable (or cleanly recovered via redial); the
// renegotiationRefusal oracle judges safety from this evidence.
func (r *campaignRun) doRenegotiate(i int, s Step) StepResult {
	res := StepResult{Index: i, Do: StepRenegotiate}
	if r.conn == nil {
		res.Err = "no session (connect first)"
		return res
	}
	rr := &RenegotiationResult{Attempted: true, RoleAsserted: string(r.role)}
	err := r.conn.Renegotiate()
	if err != nil {
		rr.Refused = true
		rr.Err = err.Error()
	}
	// Liveness: a benign read proves the session survived the renegotiation, or —
	// if the peer tore the stream down on the refused renegotiation — that the
	// emulator cleanly re-establishes it (both are safe; a wedged/corrupt session
	// is not). Two attempts: the first uses the existing session, and if that
	// broke, the second redials transparently. Skipped when the step names no unit.
	if s.Unit != 0 {
		var lerr error
		for attempt := 0; attempt < 2; attempt++ {
			if lerr = r.conn.Ping(s.Unit); lerr == nil {
				rr.SessionUsable = true
				break
			}
		}
		if lerr != nil {
			rr.Note = appendNote(rr.Note, fmt.Sprintf("post-reneg liveness failed after redial: %v", lerr))
		}
	} else {
		// No liveness unit: treat the client-side session object still being open
		// as "usable" — a refused renegotiation that left the object intact.
		rr.SessionUsable = r.conn.Session() != nil
	}
	res.Reneg = rr
	res.OK = rr.SessionUsable
	if rr.Refused {
		res.Note = "renegotiation refused by peer policy (TCP-62 indication only)"
	} else {
		res.Note = "renegotiation was handled by the peer"
	}
	return res
}

// doSleep waits for the step's duration, cancellable via the campaign context.
func (r *campaignRun) doSleep(ctx context.Context, i int, s Step) StepResult {
	res := StepResult{Index: i, Do: StepSleep}
	d := secondsDur(s.Seconds)
	if r.wait(ctx, d) {
		res.OK = true
		res.Note = fmt.Sprintf("slept %s", d)
	} else {
		res.Note = fmt.Sprintf("sleep interrupted by cancel (wanted %s)", d)
	}
	return res
}

// doSimFault arms/clears a fault on a named sim via the injected Fault func.
func (r *campaignRun) doSimFault(i int, s Step) StepResult {
	res := StepResult{Index: i, Do: StepSimFault}
	if r.e.opts.Fault == nil {
		res.Err = "sim_fault: no fault injector wired into the engine"
		return res
	}
	if err := r.e.opts.Fault(s.Target, s.Fault); err != nil {
		res.Err = err.Error()
		return res
	}
	res.OK = true
	res.Note = fmt.Sprintf("armed fault on %s: %s", s.Target, string(s.Fault))
	return res
}

// stopPolls cancels every background poll and waits for the goroutines to exit —
// the synchronization point that makes reading the RunState fields race-free
// afterward.
func (r *campaignRun) stopPolls() {
	for _, cancel := range r.pollCancel {
		cancel()
	}
	r.pollCancel = nil
	r.pollWG.Wait()
}

// secondsDur converts a fractional-seconds field to a Duration (0 for ≤0).
func secondsDur(sec float64) time.Duration {
	if sec <= 0 {
		return 0
	}
	return time.Duration(sec * float64(time.Second))
}

// containsUnit reports whether u is already in the discovered set.
func containsUnit(units []uint8, u uint8) bool {
	for _, x := range units {
		if x == u {
			return true
		}
	}
	return false
}

// unitList pulls the unit numbers from a device slice for a step note.
func unitList(devs []Device) []uint8 {
	out := make([]uint8, 0, len(devs))
	for _, d := range devs {
		out = append(out, d.Unit)
	}
	return out
}

// appendNote joins step-note fragments with "; ".
func appendNote(existing, add string) string {
	if existing == "" {
		return add
	}
	return existing + "; " + add
}
