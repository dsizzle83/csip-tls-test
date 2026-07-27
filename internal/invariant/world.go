package invariant

// world.go is the observable state an invariant is allowed to reason over, and
// the boundary that keeps it observable.
//
// # The boundary is the design
//
// The temptation, building this, is to hand a checker something convenient: the
// DUT's own view of its devices, a metrics endpoint, a JSON status dump. Every
// one of those makes the checker dependent on the component it is auditing. An
// invariant that asks the gateway whether it applied a setpoint correctly will
// pass on a gateway that mis-applied the setpoint and then mis-reported it,
// which is the exact defect shape this suite exists to find (GT-01: "connected
// = 1, 0 failures" while nothing had been posted for 3.6 days).
//
// So the sources here are arranged as three INDEPENDENT witnesses to the same
// events:
//
//	[NorthboundSource]  what the DUT says about itself and its devices, read
//	                    from its own SunSpec register map over mbaps :802.
//	[DERSource]         what each downstream device says about ITSELF, read
//	                    from the device — its own register image over plain
//	                    Modbus, or its simapi sidecar. This is the ground truth
//	                    the DUT's claims are checked against.
//	[HeadEndSource]     what the utility server received FROM the DUT — the
//	                    reports it PUT, the responses it POSTed, and when.
//
// An invariant becomes powerful exactly where two witnesses disagree. I7 is
// nothing but that: the DUT told the head-end a device was connected; the
// device says nobody has polled it in ten minutes; one of them is lying and
// only the DUT had a motive.
//
// [HostView] is the one channel that is not a peer's own account of itself. It
// is host-level resource accounting over a read-only SSH allowlist, and it
// exists only because I8 (no unbounded growth) has no honest external proxy for
// disk. Every invariant that touches it SKIPs with a reason when it is absent,
// so nothing here stops working against a fielded device nobody has a shell on.
//
// # One snapshot per tick
//
// All invariants in a tick see the SAME [Observation]. Two checkers that
// independently re-read the register map could disagree about what was true at
// the moment of a violation, and then the violation record — the thing the
// whole design is for — would be untrustworthy. [World.Observe] takes one
// snapshot, stores it, appends it to a bounded history, and every checker in
// that tick reads it.

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"

	"csip-tls-test/internal/certify"
)

// ── Source interfaces ────────────────────────────────────────────────────────

// NorthboundSource observes the DUT through its northbound SunSpec register
// map. It is READ ONLY by contract: there is no write method here, so a checker
// physically cannot command the device it is judging.
type NorthboundSource interface {
	// Name identifies the channel in evidence, e.g. "mbaps:69.0.0.2:802".
	Name() string
	// Observe reads the DUT's served units and their model register images.
	Observe(ctx context.Context) (DUTView, error)
}

// DERSource observes ONE downstream device through the device's own interface.
type DERSource interface {
	// Name is the device's bench name, e.g. "inv-plain".
	Name() string
	// Observe reads the device's own register image and sidecar state.
	Observe(ctx context.Context) (DERView, error)
}

// HeadEndSource observes what the utility server received from the DUT.
type HeadEndSource interface {
	Name() string
	Observe(ctx context.Context) (HeadEndView, error)
}

// HostSource observes host-level resource accounting on the DUT. Optional
// everywhere.
type HostSource interface {
	Name() string
	Observe(ctx context.Context) (HostView, error)
}

// Sources is the set of witnesses a World is built from. Any of them may be
// nil; the invariants that need a missing one SKIP with a reason.
type Sources struct {
	DUT     NorthboundSource
	DERs    map[string]DERSource
	HeadEnd HeadEndSource
	Host    HostSource
}

// ── Views ────────────────────────────────────────────────────────────────────

// UnitView is one Modbus unit's register image as read from a peer, plus enough
// addressing information for an assertion to name a specific register.
type UnitView struct {
	Unit uint8 `json:"unit"`
	// Models lists the SunSpec model ids the scan found, in chain order.
	Models []uint16 `json:"models"`
	// Regs holds each model's data registers, keyed by model id, exactly as
	// they came off the wire (no header).
	Regs map[uint16][]uint16 `json:"-"`
	// Base is each model's data block base address, so an assertion can cite
	// "holding register 40188" rather than "offset 9 of something".
	Base map[uint16]uint16 `json:"base,omitempty"`
	// Identity is the model 1 manufacturer/model/serial, when served.
	Identity string `json:"identity,omitempty"`
	// Err records a per-unit read failure without failing the whole view.
	Err string `json:"err,omitempty"`
}

// Has reports whether a model was read.
func (u UnitView) Has(model uint16) bool { return len(u.Regs[model]) > 0 }

// Nameplate decodes this unit's model 702.
func (u UnitView) Nameplate(source string) Nameplate {
	return DecodeNameplate(fmt.Sprintf("%s unit %d M702", source, u.Unit), u.Regs[702])
}

// Measurement decodes this unit's model 701.
func (u UnitView) Measurement(source string) Measurement {
	return DecodeMeasurement(fmt.Sprintf("%s unit %d M701", source, u.Unit), u.Regs[701])
}

// Commands decodes this unit's model 704 setpoints.
func (u UnitView) Commands(source string) []Command {
	return DecodeCommands(fmt.Sprintf("%s unit %d M704", source, u.Unit), u.Regs[704])
}

// DUTView is the device under test as seen through its own northbound server.
type DUTView struct {
	// Source is the channel name, carried in every fact derived from it.
	Source string `json:"source"`
	// Reachable is false when the northbound could not be read at all — which
	// during a chaos campaign is a normal, temporary state and not by itself a
	// violation of anything.
	Reachable bool `json:"reachable"`
	// Units are the served units, keyed by unit id.
	Units map[uint8]UnitView `json:"units,omitempty"`
	// Err explains an unreachable DUT.
	Err string `json:"err,omitempty"`
	// Latency is how long the read took, which is the only bounded-resource
	// signal available without a shell.
	Latency time.Duration `json:"latency_ns,omitempty"`
}

// UnitIDs returns the served unit ids in ascending order.
func (d DUTView) UnitIDs() []uint8 {
	out := make([]uint8, 0, len(d.Units))
	for u := range d.Units {
		out = append(out, u)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// DERView is one downstream device as seen through ITS OWN interface — never
// through the DUT's report of it.
type DERView struct {
	Name   string `json:"name"`
	Source string `json:"source"`
	// Reachable is false when the device could not be read.
	Reachable bool   `json:"reachable"`
	Err       string `json:"err,omitempty"`
	// Unit is the device's own register image (most sims serve a single unit).
	Unit UnitView `json:"unit"`
	// PollRequests is the number of Modbus requests the DUT has made to this
	// device, when the device counts them. An advancing counter is independent
	// proof that the DUT's southbound loop is alive; a frozen one is the
	// ground truth I7 checks the DUT's connectivity claims against.
	PollRequests int  `json:"poll_requests"`
	HasPollCount bool `json:"has_poll_count"`
	// Sessions is the number of live sessions the DUT holds against this
	// device — an externally visible leak detector for I8.
	Sessions    int  `json:"sessions"`
	HasSessions bool `json:"has_sessions"`
	// Animating reports whether the device's own simulation is running, so a
	// checker does not read a deliberately-frozen sim as a stalled device.
	Animating bool `json:"animating"`
	// ArmedFaults are the fault kinds the device reports armed on itself, from
	// its own sidecar — a cross-check on the campaign's manifest.
	ArmedFaults []string `json:"armed_faults,omitempty"`
}

// HeadEndView is the utility server's own record of its conversation with the
// DUT. Everything here is what the SERVER saw, not what the DUT says it sent.
type HeadEndView struct {
	Source    string `json:"source"`
	Reachable bool   `json:"reachable"`
	Err       string `json:"err,omitempty"`
	// ServerTime is the head-end's notion of now, which a clock-warp fault
	// moves and which an invariant must therefore not confuse with wall time.
	ServerTime time.Time `json:"server_time"`
	// Programs are the DER programs with their active and scheduled controls,
	// in CSIP units.
	Programs []Program `json:"programs,omitempty"`
	// Responses are every DERControlResponse the DUT POSTed.
	Responses []Response `json:"responses,omitempty"`
	// Alerts are the subset the server classified as cannot-comply.
	Alerts []Alert `json:"alerts,omitempty"`
	// Reports are the DERCapability / DERSettings / DERStatus documents the
	// DUT PUT, with the server's receive time. These are the DUT's CLAIMS,
	// and I7 exists to check them against the DERs' own accounts.
	Reports []Report `json:"reports,omitempty"`
}

// Program is one DERProgram and the controls the head-end is serving under it.
type Program struct {
	ID          int       `json:"id"`
	MRID        string    `json:"mrid"`
	Description string    `json:"description"`
	Primacy     int       `json:"primacy"`
	Default     *CtrlBase `json:"default,omitempty"`
	Active      []Ctrl    `json:"active,omitempty"`
	Scheduled   []Ctrl    `json:"scheduled,omitempty"`
}

// Ctrl is one DERControl the head-end is serving.
type Ctrl struct {
	MRID      string    `json:"mrid"`
	Start     time.Time `json:"start"`
	Duration  int       `json:"duration_s"`
	Status    int       `json:"status"`
	Base      CtrlBase  `json:"base"`
	CurveName string    `json:"curve,omitempty"`
}

// Covers reports whether the control's window contains t.
func (c Ctrl) Covers(t time.Time) bool {
	if c.Start.IsZero() {
		return false
	}
	return !t.Before(c.Start) && t.Before(c.Start.Add(time.Duration(c.Duration)*time.Second))
}

// CtrlBase is a DERControlBase in CSIP's own units — watts and percent, as the
// head-end published them. Converting these into a DER's units is I1's job and
// requires that DER's nameplate; nothing here does it implicitly.
type CtrlBase struct {
	ExpLimW     *float64 `json:"exp_lim_W,omitempty"`
	MaxLimW     *float64 `json:"max_lim_W,omitempty"`
	ImpLimW     *float64 `json:"imp_lim_W,omitempty"`
	GenLimW     *float64 `json:"gen_lim_W,omitempty"`
	LoadLimW    *float64 `json:"load_lim_W,omitempty"`
	FixedW      *float64 `json:"fixed_W,omitempty"`
	FixedVarPct *float64 `json:"fixed_var_pct,omitempty"`
	PFInjectPct *float64 `json:"fixed_pf_inject_pct,omitempty"`
	PFAbsorbPct *float64 `json:"fixed_pf_absorb_pct,omitempty"`
	Connect     *bool    `json:"connect,omitempty"`
	Energize    *bool    `json:"energize,omitempty"`
}

// Axes returns the base's set axes as (name, value, unit) triples, which is how
// I10 counts "how much of this control was applied".
func (b CtrlBase) Axes() []struct {
	Name  string
	Value float64
	Unit  Unit
} {
	type axis = struct {
		Name  string
		Value float64
		Unit  Unit
	}
	var out []axis
	add := func(name string, p *float64, u Unit) {
		if p != nil {
			out = append(out, axis{name, *p, u})
		}
	}
	add("opModExpLimW", b.ExpLimW, UnitWatt)
	add("opModMaxLimW", b.MaxLimW, UnitWatt)
	add("opModImpLimW", b.ImpLimW, UnitWatt)
	add("opModGenLimW", b.GenLimW, UnitWatt)
	add("opModLoadLimW", b.LoadLimW, UnitWatt)
	add("opModFixedW", b.FixedW, UnitPercent)
	add("opModFixedVar", b.FixedVarPct, UnitPercent)
	add("opModFixedPFInjectW", b.PFInjectPct, UnitPF)
	add("opModFixedPFAbsorbW", b.PFAbsorbPct, UnitPF)
	if b.Connect != nil {
		v := 0.0
		if *b.Connect {
			v = 1
		}
		out = append(out, axis{"opModConnect", v, UnitNone})
	}
	if b.Energize != nil {
		v := 0.0
		if *b.Energize {
			v = 1
		}
		out = append(out, axis{"opModEnergize", v, UnitNone})
	}
	return out
}

// Response is one DERControlResponse the DUT POSTed to the head-end.
type Response struct {
	Subject string `json:"subject"`
	Status  int    `json:"status"`
	LFDI    string `json:"lfdi,omitempty"`
}

// Alert is a Response the head-end classified as a cannot-comply signal.
type Alert struct {
	Subject    string    `json:"subject"`
	Status     int       `json:"status"`
	Vocab      string    `json:"vocab,omitempty"`
	LFDI       string    `json:"lfdi,omitempty"`
	ReceivedAt time.Time `json:"received_at"`
}

// Report is one DER* document the DUT PUT to the head-end — its self-report,
// and therefore its claim.
type Report struct {
	Path     string    `json:"path"`
	Resource string    `json:"resource"`
	Body     string    `json:"-"`
	Received time.Time `json:"received"`
}

// HostView is bounded host-level resource accounting, gathered over a read-only
// command allowlist. Available is false whenever no shell was configured, and
// every invariant that reads it must SKIP with that as its reason.
type HostView struct {
	Source    string `json:"source"`
	Available bool   `json:"available"`
	Err       string `json:"err,omitempty"`
	// FileBytes is the size of each operator-named persistent file.
	FileBytes map[string]int64 `json:"file_bytes,omitempty"`
	// FSFreeKB is free space per operator-named mount point.
	FSFreeKB map[string]int64 `json:"fs_free_kb,omitempty"`
	// TCPSockets is the count of TCP sockets on the host, the closest
	// externally-gatherable proxy for a descriptor leak.
	TCPSockets int  `json:"tcp_sockets"`
	HasSockets bool `json:"has_sockets"`
}

// ── Observation ──────────────────────────────────────────────────────────────

// Observation is everything observable at one instant, taken as one snapshot so
// every invariant in a tick reasons over the same world.
type Observation struct {
	// Seq is the tick number, starting at 1.
	Seq int `json:"seq"`
	// At is when the snapshot started.
	At time.Time `json:"at"`
	// Took is how long gathering it needed.
	Took time.Duration `json:"took_ns"`

	DUT     DUTView            `json:"dut"`
	DERs    map[string]DERView `json:"ders,omitempty"`
	HeadEnd HeadEndView        `json:"head_end"`
	Host    HostView           `json:"host"`

	// Faults is the manifest as it stood when this snapshot was taken.
	Faults ManifestSnapshot `json:"faults"`
	// Errs records which sources failed, keyed by source name.
	Errs map[string]string `json:"errs,omitempty"`
}

// DERNames returns the observed DER names in stable order.
func (o *Observation) DERNames() []string {
	out := make([]string, 0, len(o.DERs))
	for n := range o.DERs {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// ── World ────────────────────────────────────────────────────────────────────

// Params are the handful of values an invariant needs that no amount of
// observation will yield — a configured failsafe the DUT never publishes, a
// site export limit that lives in an operator's spreadsheet, the paths of the
// persistent files I8 should watch.
//
// They are separated from Sources deliberately. A checker that silently defaults
// a missing parameter is asserting the operator's intent; a checker that SKIPs
// with "needs -param failsafe_wmaxlimpct" is telling the truth. Every use of
// Params in this package takes the second option.
type Params struct {
	// Values are operator-supplied key=value pairs.
	Values map[string]string
	// Tol is the comparison slack for physical-quantity checks.
	Tol Tolerance
	// HistoryDepth bounds the retained observations. Zero means the default.
	HistoryDepth int
}

// DefaultParams returns the standard configuration.
func DefaultParams() Params {
	return Params{Values: map[string]string{}, Tol: DefaultTolerance(), HistoryDepth: 240}
}

// Get returns a parameter.
func (p Params) Get(key string) (string, bool) {
	v, ok := p.Values[key]
	return v, ok && v != ""
}

// Float returns a numeric parameter.
func (p Params) Float(key string) (float64, bool) {
	s, ok := p.Get(key)
	if !ok {
		return 0, false
	}
	var f float64
	if _, err := fmt.Sscanf(s, "%g", &f); err != nil {
		return 0, false
	}
	return f, true
}

// Duration returns a duration parameter, e.g. "-param recovery_budget=20m".
func (p Params) Duration(key string) (time.Duration, bool) {
	s, ok := p.Get(key)
	if !ok {
		return 0, false
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, false
	}
	return d, true
}

// List returns a comma-separated parameter split into fields.
func (p Params) List(key string) ([]string, bool) {
	s, ok := p.Get(key)
	if !ok {
		return nil, false
	}
	var out []string
	start := 0
	for i := 0; i <= len(s); i++ {
		if i == len(s) || s[i] == ',' {
			f := trimSpace(s[start:i])
			if f != "" {
				out = append(out, f)
			}
			start = i + 1
		}
	}
	return out, len(out) > 0
}

func trimSpace(s string) string {
	for len(s) > 0 && (s[0] == ' ' || s[0] == '\t') {
		s = s[1:]
	}
	for len(s) > 0 && (s[len(s)-1] == ' ' || s[len(s)-1] == '\t') {
		s = s[:len(s)-1]
	}
	return s
}

// World is the read-only view of the bench an invariant is handed.
//
// It carries no method that changes anything. The mutating half of a campaign —
// arming faults, recording write attempts — happens through [FaultManifest] and
// [Ledger], which the campaign holds directly and the World only reads.
type World struct {
	sources Sources
	faults  *FaultManifest
	ledger  *Ledger
	params  Params
	capture certify.CaptureRef

	mu   sync.RWMutex
	obs  *Observation
	hist []*Observation
	seq  int
}

// NewWorld builds a World over the given sources.
func NewWorld(src Sources, faults *FaultManifest, ledger *Ledger, p Params) *World {
	if p.Values == nil {
		p.Values = map[string]string{}
	}
	if p.HistoryDepth <= 0 {
		p.HistoryDepth = DefaultParams().HistoryDepth
	}
	if p.Tol == (Tolerance{}) {
		p.Tol = DefaultTolerance()
	}
	if faults == nil {
		faults = NewManifest("", 0)
	}
	if ledger == nil {
		ledger = NewLedger()
	}
	return &World{sources: src, faults: faults, ledger: ledger, params: p}
}

// SetCapture records the run's capture so assertions can cite frames.
func (w *World) SetCapture(c certify.CaptureRef) {
	w.mu.Lock()
	w.capture = c
	w.mu.Unlock()
}

// Capture returns the run's capture reference.
func (w *World) Capture() certify.CaptureRef {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return w.capture
}

// Params returns the run's parameters.
func (w *World) Params() Params { return w.params }

// Faults returns the live manifest, for the campaign to arm and clear through.
// Invariants must read [Observation.Faults] instead, which is the manifest as
// it stood at the observed instant.
func (w *World) Faults() *FaultManifest { return w.faults }

// Ledger returns the record of what the adversary attempted.
func (w *World) Ledger() *Ledger { return w.ledger }

// Sources returns the configured sources, so a checker can say which witness is
// missing when it SKIPs.
func (w *World) Sources() Sources { return w.sources }

// Observe takes one snapshot of every configured source and makes it current.
//
// A source failure is recorded in the Observation rather than returned: during a
// chaos campaign, half the bench being unreachable is the expected condition,
// and an Observe that refused to produce a snapshot then would blind the
// invariants exactly when they matter most. The returned error is reserved for
// "no sources are configured at all", which is a programming error.
func (w *World) Observe(ctx context.Context) (*Observation, error) {
	if w.sources.DUT == nil && len(w.sources.DERs) == 0 && w.sources.HeadEnd == nil && w.sources.Host == nil {
		return nil, fmt.Errorf("invariant: World has no sources configured")
	}
	start := time.Now()
	w.mu.Lock()
	w.seq++
	seq := w.seq
	w.mu.Unlock()

	obs := &Observation{
		Seq:    seq,
		At:     start,
		DERs:   map[string]DERView{},
		Errs:   map[string]string{},
		Faults: w.faults.Snapshot(),
	}

	var wg sync.WaitGroup
	var mu sync.Mutex
	note := func(name string, err error) {
		if err == nil {
			return
		}
		mu.Lock()
		obs.Errs[name] = err.Error()
		mu.Unlock()
	}

	if s := w.sources.DUT; s != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			t0 := time.Now()
			v, err := s.Observe(ctx)
			v.Source = s.Name()
			v.Latency = time.Since(t0)
			if err != nil {
				v.Reachable = false
				v.Err = err.Error()
			}
			mu.Lock()
			obs.DUT = v
			mu.Unlock()
			note(s.Name(), err)
		}()
	}
	for name, s := range w.sources.DERs {
		wg.Add(1)
		go func(name string, s DERSource) {
			defer wg.Done()
			v, err := s.Observe(ctx)
			v.Name = name
			v.Source = s.Name()
			if err != nil {
				v.Reachable = false
				v.Err = err.Error()
			}
			mu.Lock()
			obs.DERs[name] = v
			mu.Unlock()
			note(s.Name(), err)
		}(name, s)
	}
	if s := w.sources.HeadEnd; s != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			v, err := s.Observe(ctx)
			v.Source = s.Name()
			if err != nil {
				v.Reachable = false
				v.Err = err.Error()
			}
			mu.Lock()
			obs.HeadEnd = v
			mu.Unlock()
			note(s.Name(), err)
		}()
	}
	if s := w.sources.Host; s != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			v, err := s.Observe(ctx)
			v.Source = s.Name()
			if err != nil {
				v.Available = false
				v.Err = err.Error()
			}
			mu.Lock()
			obs.Host = v
			mu.Unlock()
			note(s.Name(), err)
		}()
	}
	wg.Wait()
	obs.Took = time.Since(start)

	w.mu.Lock()
	w.obs = obs
	w.hist = append(w.hist, obs)
	if len(w.hist) > w.params.HistoryDepth {
		w.hist = w.hist[len(w.hist)-w.params.HistoryDepth:]
	}
	w.mu.Unlock()
	return obs, nil
}

// Now returns the current observation, or nil before the first Observe. Every
// Check must handle nil by SKIPping — a checker invoked before the world has
// been observed has nothing to judge.
func (w *World) Now() *Observation {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return w.obs
}

// History returns the retained observations, oldest first, including the
// current one. The slice is a copy; the Observations in it are immutable once
// stored.
func (w *World) History() []*Observation {
	w.mu.RLock()
	defer w.mu.RUnlock()
	out := make([]*Observation, len(w.hist))
	copy(out, w.hist)
	return out
}

// Since returns the retained observations at or after t, oldest first.
func (w *World) Since(t time.Time) []*Observation {
	var out []*Observation
	for _, o := range w.History() {
		if !o.At.Before(t) {
			out = append(out, o)
		}
	}
	return out
}

// Inject makes obs the current observation without consulting any source. It
// exists for the teeth tests, which must be able to place the world in a state
// that MUST trip an invariant and prove that it does — an invariant suite that
// has never been seen to fire is decoration.
func (w *World) Inject(obs *Observation) {
	w.mu.Lock()
	w.seq++
	if obs.Seq == 0 {
		obs.Seq = w.seq
	}
	if obs.At.IsZero() {
		obs.At = time.Now()
	}
	if obs.Errs == nil {
		obs.Errs = map[string]string{}
	}
	if obs.DERs == nil {
		obs.DERs = map[string]DERView{}
	}
	if len(obs.Faults.Faults) == 0 && obs.Faults.Seed == 0 {
		obs.Faults = w.faults.Snapshot()
	}
	w.obs = obs
	w.hist = append(w.hist, obs)
	if len(w.hist) > w.params.HistoryDepth {
		w.hist = w.hist[len(w.hist)-w.params.HistoryDepth:]
	}
	w.mu.Unlock()
}
