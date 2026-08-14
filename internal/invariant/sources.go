package invariant

// sources.go wires the abstract witnesses in world.go to the actual bench.
//
// Everything here is a client of something that already exists — internal/
// aggregator for the DUT's mbaps northbound, lexa-proto/modbus for a plain
// southbound device, internal/certify's SimClient and AdminClient for the sims'
// control planes, and internal/certify's read-only Gateway for host accounting.
// Nothing here reimplements a protocol; the point of the file is the MAPPING
// from those clients onto the view types, which is where the honesty lives:
// a source that quietly returned an empty view on error would turn every
// invariant into a pass.
//
// Two conventions hold throughout:
//
//	an unreachable witness returns an error and a view with Reachable false,
//	never a zero view that reads as "everything is fine"; and
//
//	every view carries the channel name it came from, so a Fact can name its
//	source and a reader can tell the DER's own account from the DUT's.

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"csip-tls-test/internal/certify"
	"lexa-proto/modbus"
	"lexa-proto/sunspec"
)

// modelsOfInterest are the SunSpec models every register-image source reads.
// 701 is the measurement I7 and I10 corroborate against, 702 the nameplate I1
// bounds by, 703 the enter-service settings, 704 the commanded setpoints, and
// the curve models (705/706/711/712, CurveModels) the CURVE-linked control
// modes' own southbound landing sites — the registers a volt-var / volt-watt /
// watt-var curve or a frequency droop is adopted into (curves.go).
//
// A model absent from the device is skipped by readUnit, so adding the curve
// models costs a device that serves none of them nothing at all, and gives one
// that serves them the only independent account of what a curve control
// actually did.
var modelsOfInterest = append([]uint16{701, 702, 703, 704}, CurveModels()...)

// readUnit reads the models of interest for one unit through a Transport,
// returning a UnitView. A per-model read failure is recorded on the view rather
// than aborting: a device that serves 704 but not 702 is still worth observing,
// and the invariants that need 702 SKIP with that reason.
func readUnit(t modbus.Transport, unit uint8) (UnitView, error) {
	if err := t.SetUnitID(unit); err != nil {
		return UnitView{Unit: unit, Err: err.Error()}, err
	}
	r, err := sunspec.NewReader(t)
	if err != nil {
		return UnitView{Unit: unit, Err: err.Error()}, err
	}
	v := UnitView{
		Unit: unit,
		Regs: map[uint16][]uint16{},
		Base: map[uint16]uint16{},
	}
	for _, b := range r.Blocks() {
		v.Models = append(v.Models, b.ModelID)
	}
	for _, model := range modelsOfInterest {
		if !r.HasModel(model) {
			continue
		}
		regs, err := r.ReadModel(model)
		if err != nil {
			v.Err = appendErr(v.Err, fmt.Sprintf("model %d: %v", model, err))
			continue
		}
		v.Regs[model] = regs
		if b, err := sunspec.FindModel(r.Blocks(), model); err == nil {
			v.Base[model] = b.BaseAddr
		}
	}
	if c, err := sunspec.ReadCommon(r); err == nil {
		v.Identity = strings.TrimSpace(fmt.Sprintf("%s %s sn=%s", c.Manufacturer, c.Model, c.Serial))
	}
	return v, nil
}

func appendErr(existing, add string) string {
	if existing == "" {
		return add
	}
	return existing + "; " + add
}

// ── The DUT's northbound ─────────────────────────────────────────────────────

// NorthboundDialer opens a read-only session to the DUT's mbaps server and
// returns a Transport bound to it, plus a closer.
//
// It is an injected function rather than a concrete type so this package does
// not import the aggregator's session machinery (and therefore does not link a
// TLS stack) just to define an interface. The caller — a campaign runner that
// already holds a PKI and an aggregator engine — supplies two lines:
//
//	inv.NewMbapsNorthbound("mbaps:69.0.0.2:802", func(ctx context.Context) (modbus.Transport, func(), error) {
//	        c, err := aggregator.ConnectAs(target, aggregator.RoleReadOnly, refs)
//	        if err != nil { return nil, nil, err }
//	        return c.Transport(), func() { _ = c.Close() }, nil
//	}, units)
//
// Note the role: a monitor reads with the LEAST privileged credential that can
// read. It has no business holding a write-capable session open for hours
// against a device it is auditing.
type NorthboundDialer func(ctx context.Context) (modbus.Transport, func(), error)

// MbapsNorthbound observes the DUT through its mbaps northbound server.
type MbapsNorthbound struct {
	name  string
	dial  NorthboundDialer
	units []uint8
}

// NewMbapsNorthbound returns a northbound source. units may be empty, in which
// case units 1..8 are probed — the range lexa-gw serves on the bench, walked
// once per observation.
func NewMbapsNorthbound(name string, dial NorthboundDialer, units []uint8) *MbapsNorthbound {
	if len(units) == 0 {
		units = []uint8{1, 2, 3, 4, 5, 6, 7, 8}
	}
	return &MbapsNorthbound{name: name, dial: dial, units: units}
}

// Name identifies the channel.
func (s *MbapsNorthbound) Name() string { return s.name }

// Observe reads the DUT's served units.
func (s *MbapsNorthbound) Observe(ctx context.Context) (DUTView, error) {
	t, closer, err := s.dial(ctx)
	if err != nil {
		return DUTView{Source: s.name, Reachable: false, Err: err.Error()}, err
	}
	defer closer()

	v := DUTView{Source: s.name, Units: map[uint8]UnitView{}}
	for _, u := range s.units {
		if ctx.Err() != nil {
			break
		}
		uv, err := readUnit(t, u)
		if err != nil {
			continue // an unmapped unit is not an error; it is simply absent
		}
		if len(uv.Models) == 0 {
			continue
		}
		v.Units[u] = uv
	}
	if len(v.Units) == 0 {
		v.Err = "the DUT answered but served no SunSpec unit in the probed range"
		return v, nil
	}
	v.Reachable = true
	return v, nil
}

// ── A southbound DER, read over plain Modbus ─────────────────────────────────

// ModbusDER observes a device by reading ITS OWN register image over plain
// Modbus/TCP — the strongest witness available, because it is the device's own
// account of itself with the DUT nowhere in the path.
type ModbusDER struct {
	name string
	url  string
	unit uint8
	to   time.Duration

	mu sync.Mutex
	t  modbus.Transport
}

// NewModbusDER returns a source reading tcp://host:port. It dials lazily and
// re-dials after a failure, so a device that goes away and comes back is
// observed correctly across the outage rather than staying dead.
func NewModbusDER(name, url string, unit uint8, timeout time.Duration) *ModbusDER {
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	if unit == 0 {
		unit = 1
	}
	return &ModbusDER{name: name, url: url, unit: unit, to: timeout}
}

// Name identifies the device.
func (s *ModbusDER) Name() string { return s.name }

// Observe reads the device's own register image.
func (s *ModbusDER) Observe(ctx context.Context) (DERView, error) {
	_ = ctx
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.t == nil {
		t, err := modbus.NewTransport(s.url, s.to)
		if err != nil {
			return DERView{Name: s.name, Source: s.url, Err: err.Error()}, err
		}
		if err := t.Open(); err != nil {
			return DERView{Name: s.name, Source: s.url, Err: err.Error()}, err
		}
		s.t = t
	}
	uv, err := readUnit(s.t, s.unit)
	if err != nil {
		// Drop the transport so the next observation re-dials; a device that
		// rebooted must not be reported dead forever.
		_ = s.t.Close()
		s.t = nil
		return DERView{Name: s.name, Source: s.url, Err: err.Error()}, err
	}
	return DERView{Name: s.name, Source: s.url, Reachable: true, Unit: uv, Animating: true}, nil
}

// Close releases the transport.
func (s *ModbusDER) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.t != nil {
		_ = s.t.Close()
		s.t = nil
	}
}

// ── A southbound DER, read through its simapi sidecar ────────────────────────

// SimAPIDER observes a device through its simapi sidecar: GET /registers for
// the register image and GET /state for the sidecar-only facts (the request
// counter and the session table) that no Modbus read can produce.
//
// It is the right source for the SECURE device sim, whose Modbus port is behind
// mTLS and whose sidecar is the only cleartext view — and it is the source that
// makes I7 and I8's leak arm possible at all, because a device's own count of
// how often the DUT talked to it is exactly the independent witness those
// invariants need.
type SimAPIDER struct {
	name string
	sim  *certify.SimClient
	unit uint8
}

// NewSimAPIDER returns a source over a simapi sidecar.
func NewSimAPIDER(name string, sim *certify.SimClient, unit uint8) *SimAPIDER {
	if unit == 0 {
		unit = 1
	}
	return &SimAPIDER{name: name, sim: sim, unit: unit}
}

// Name identifies the device.
func (s *SimAPIDER) Name() string { return s.name }

// Observe reads the sidecar.
func (s *SimAPIDER) Observe(ctx context.Context) (DERView, error) {
	if s.sim == nil || !s.sim.Available() {
		err := fmt.Errorf("simapi sidecar for %s is not configured", s.name)
		return DERView{Name: s.name, Err: err.Error()}, err
	}
	v := DERView{Name: s.name, Source: s.sim.BaseURL}

	var raw map[string]any
	if err := s.sim.Registers(ctx, &raw); err != nil {
		return v, fmt.Errorf("read %s registers: %w", s.name, err)
	}
	regs, err := registerImage(raw)
	if err != nil {
		v.Err = err.Error()
		return v, err
	}
	uv, err := readUnit(newMemTransport(regs), s.unit)
	if err != nil {
		v.Err = err.Error()
		return v, err
	}
	v.Unit = uv
	v.Reachable = true

	// /state carries the counters no register read can produce. A failure here
	// is NOT fatal — the register image is already the primary witness — but it
	// is recorded, because the invariants that need the counters must SKIP
	// rather than conclude from their absence.
	var state simState
	if err := s.sim.State(ctx, &state); err != nil {
		v.Err = appendErr(v.Err, "state: "+err.Error())
		return v, nil
	}
	v.Animating = !state.Paused
	for _, sess := range state.Sessions {
		v.PollRequests += sess.Requests
	}
	if len(state.Sessions) > 0 {
		v.HasPollCount = true
		v.HasSessions = true
		v.Sessions = len(state.Sessions)
	}
	if state.Requests > 0 {
		v.HasPollCount = true
		if v.PollRequests == 0 {
			v.PollRequests = state.Requests
		}
	}
	v.ArmedFaults = state.armedFaultNames()
	return v, nil
}

// simState is the narrow slice of a sim's /state this package reads. The sims
// own their schemas, so only the fields with a defined meaning across every sim
// are modelled; anything else stays in the sim's own JSON.
type simState struct {
	Paused   bool `json:"paused"`
	Requests int  `json:"requests"`
	Sessions []struct {
		Peer     string `json:"peer"`
		Role     string `json:"role"`
		Requests int    `json:"requests"`
	} `json:"sessions"`
	Faults map[string]bool `json:"faults"`
}

func (s simState) armedFaultNames() []string {
	var out []string
	for k, v := range s.Faults {
		if v {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

// registerImage converts a simapi /registers response into an address→value
// map. The sims serve it as a JSON object of decimal address strings, which is
// awkward but is their schema, and re-modelling it here would create a second
// definition to drift.
func registerImage(raw map[string]any) (map[uint16]uint16, error) {
	out := make(map[uint16]uint16, len(raw))
	for k, v := range raw {
		addr, err := strconv.ParseUint(k, 10, 16)
		if err != nil {
			continue // a non-address key (a nested object) is not a register
		}
		switch n := v.(type) {
		case float64:
			out[uint16(addr)] = uint16(int64(n) & 0xFFFF)
		case json.Number:
			i, err := n.Int64()
			if err != nil {
				continue
			}
			out[uint16(addr)] = uint16(i & 0xFFFF)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("the /registers response contained no numeric register entries")
	}
	return out, nil
}

// memTransport serves a register image already in memory, so the same SunSpec
// reader decodes a sidecar dump and a live device. Unset registers read zero,
// which is what an unpopulated holding register reads on the wire.
type memTransport struct {
	regs map[uint16]uint16
	unit uint8
}

func newMemTransport(regs map[uint16]uint16) *memTransport {
	return &memTransport{regs: regs, unit: 1}
}

func (m *memTransport) Open() error              { return nil }
func (m *memTransport) Close() error             { return nil }
func (m *memTransport) SetUnitID(id uint8) error { m.unit = id; return nil }

func (m *memTransport) ReadHolding(addr, quantity uint16) ([]uint16, error) {
	if quantity == 0 || quantity > 125 {
		return nil, fmt.Errorf("memTransport: illegal quantity %d", quantity)
	}
	out := make([]uint16, quantity)
	for i := uint16(0); i < quantity; i++ {
		out[i] = m.regs[addr+i]
	}
	return out, nil
}

func (m *memTransport) ReadInput(addr, quantity uint16) ([]uint16, error) {
	return m.ReadHolding(addr, quantity)
}

// WriteHolding is refused. A source is a witness, not an actor, and the type
// system should say so even though the Transport interface does not.
func (m *memTransport) WriteHolding(uint16, []uint16) error {
	return fmt.Errorf("memTransport is read-only: an invariant source never writes")
}

// ── The head-end ─────────────────────────────────────────────────────────────

// GridsimHeadEnd observes the utility server's own record of its conversation
// with the DUT, through gridsim's admin API.
type GridsimHeadEnd struct {
	admin *certify.AdminClient
}

// NewGridsimHeadEnd returns a head-end source.
func NewGridsimHeadEnd(admin *certify.AdminClient) *GridsimHeadEnd {
	return &GridsimHeadEnd{admin: admin}
}

// Name identifies the channel.
func (s *GridsimHeadEnd) Name() string {
	if s.admin == nil {
		return "gridsim-admin(unconfigured)"
	}
	return "gridsim-admin:" + s.admin.BaseURL
}

// Observe reads the head-end's admin views. The status read is required; the
// responses / alerts / derputs reads are recorded as partial failures, because
// a head-end that answers /admin/status is reachable, and an invariant that
// needs a view it did not get should SKIP naming that view rather than treat
// the whole head-end as down.
func (s *GridsimHeadEnd) Observe(ctx context.Context) (HeadEndView, error) {
	v := HeadEndView{Source: s.Name()}
	if s.admin == nil || !s.admin.Available() {
		err := fmt.Errorf("no gridsim admin URL configured")
		v.Err = err.Error()
		return v, err
	}
	var st adminStatus
	if err := s.admin.Status(ctx, &st); err != nil {
		v.Err = err.Error()
		return v, err
	}
	v.Reachable = true
	v.ServerTime = time.Unix(st.ServerTime, 0)
	for _, p := range st.Programs {
		prog := Program{ID: p.ID, MRID: p.MRID, Description: p.Description, Primacy: p.Primacy}
		if p.Default != nil {
			b := p.Default.view()
			prog.Default = &b
		}
		for _, c := range p.Active {
			prog.Active = append(prog.Active, c.view())
		}
		for _, c := range p.Scheduled {
			prog.Scheduled = append(prog.Scheduled, c.view())
		}
		v.Programs = append(v.Programs, prog)
	}

	var rs adminResponses
	if err := s.admin.Responses(ctx, &rs); err != nil {
		v.Err = appendErr(v.Err, "responses: "+err.Error())
	} else {
		for _, r := range rs.Responses {
			v.Responses = append(v.Responses, Response{Subject: r.Subject, Status: int(r.Status), LFDI: r.LFDI})
		}
	}

	var al adminAlerts
	if err := s.admin.Get(ctx, "alerts", &al); err != nil {
		v.Err = appendErr(v.Err, "alerts: "+err.Error())
	} else {
		for _, a := range al.Alerts {
			v.Alerts = append(v.Alerts, Alert{
				Subject: a.Subject, Status: int(a.Status), Vocab: a.Vocab, LFDI: a.LFDI,
				ReceivedAt: time.Unix(a.ReceivedAt, 0),
			})
		}
	}

	var dp adminDERPuts
	if err := s.admin.DERPuts(ctx, &dp); err != nil {
		v.Err = appendErr(v.Err, "derputs: "+err.Error())
	} else {
		for _, r := range dp.DERPuts {
			v.Reports = append(v.Reports, Report{
				Path: r.Path, Resource: r.Resource, Body: r.Body, Received: time.Unix(r.ReceivedAt, 0),
			})
		}
	}
	return v, nil
}

// The gridsim admin JSON DTOs. They are transcribed rather than imported so
// this package does not depend on the simulator's internals — the same reason
// certify's clients hand back caller-supplied destinations.
type adminStatus struct {
	Programs []struct {
		ID          int         `json:"id"`
		MRID        string      `json:"mrid"`
		Description string      `json:"description"`
		Primacy     int         `json:"primacy"`
		Default     *adminBase  `json:"default"`
		Active      []adminCtrl `json:"active"`
		Scheduled   []adminCtrl `json:"scheduled"`
	} `json:"programs"`
	ServerTime int64 `json:"server_time"`
}

type adminBase struct {
	ExpLimW     *float64 `json:"exp_lim_W"`
	MaxLimW     *float64 `json:"max_lim_W"`
	ImpLimW     *float64 `json:"imp_lim_W"`
	GenLimW     *float64 `json:"gen_lim_W"`
	LoadLimW    *float64 `json:"load_lim_W"`
	FixedW      *float64 `json:"fixed_W"`
	FixedVarPct *float64 `json:"fixed_var_pct"`
	PFInject    *float64 `json:"fixed_pf_inject_pct"`
	PFAbsorb    *float64 `json:"fixed_pf_absorb_pct"`
	Connect     *bool    `json:"connect"`
	Energize    *bool    `json:"energize"`
}

func (b *adminBase) view() CtrlBase {
	if b == nil {
		return CtrlBase{}
	}
	return CtrlBase{
		ExpLimW: b.ExpLimW, MaxLimW: b.MaxLimW, ImpLimW: b.ImpLimW, GenLimW: b.GenLimW,
		LoadLimW: b.LoadLimW, FixedW: b.FixedW, FixedVarPct: b.FixedVarPct,
		PFInjectPct: b.PFInject, PFAbsorbPct: b.PFAbsorb, Connect: b.Connect, Energize: b.Energize,
	}
}

type adminCtrl struct {
	MRID      string    `json:"mrid"`
	Start     int64     `json:"start"`
	DurationS int       `json:"duration_s"`
	Status    int       `json:"status"`
	Base      adminBase `json:"base"`
	Curve     string    `json:"curve"`
}

func (c adminCtrl) view() Ctrl {
	return Ctrl{
		MRID: c.MRID, Start: time.Unix(c.Start, 0), Duration: c.DurationS,
		Status: c.Status, Base: c.Base.view(), CurveName: c.Curve,
	}
}

type adminResponses struct {
	Responses []struct {
		Subject string `json:"subject"`
		Status  uint8  `json:"status"`
		LFDI    string `json:"lfdi"`
	} `json:"responses"`
}

type adminAlerts struct {
	Alerts []struct {
		Subject    string `json:"subject"`
		Status     uint8  `json:"status"`
		Vocab      string `json:"vocab"`
		LFDI       string `json:"lfdi"`
		ReceivedAt int64  `json:"received_at"`
	} `json:"alerts"`
}

type adminDERPuts struct {
	DERPuts []struct {
		Path       string `json:"path"`
		Resource   string `json:"resource"`
		Body       string `json:"body"`
		ReceivedAt int64  `json:"received_at"`
	} `json:"der_puts"`
}

// ── The host ─────────────────────────────────────────────────────────────────

// SSHHost gathers bounded host-level resource accounting over certify.Gateway's
// read-only command allowlist.
//
// It is deliberately the thinnest thing that answers I8's question. It runs
// `stat -c %s` on named files, `df -k` on named mounts, and `ss -tan` for a
// socket count. It cannot restart anything, cannot edit anything, and refuses
// any command outside the allowlist — the bench is shared, and a monitor that
// mutated the DUT would invalidate every other agent's evidence along with its
// own.
type SSHHost struct {
	gw     *certify.Gateway
	files  []string
	mounts []string
}

// NewSSHHost returns a host source watching the named files and mounts. Both
// lists may be empty, in which case only the socket count is gathered.
func NewSSHHost(gw *certify.Gateway, files, mounts []string) *SSHHost {
	return &SSHHost{gw: gw, files: files, mounts: mounts}
}

// Name identifies the channel.
func (s *SSHHost) Name() string {
	if s.gw == nil || !s.gw.Available() {
		return "gateway-ssh(unconfigured)"
	}
	return "gateway-ssh:" + s.gw.SSH
}

// Observe gathers the host view.
func (s *SSHHost) Observe(ctx context.Context) (HostView, error) {
	v := HostView{Source: s.Name()}
	if s.gw == nil || !s.gw.Available() {
		err := fmt.Errorf("no gateway ssh destination configured, so host resource accounting is unavailable")
		v.Err = err.Error()
		return v, err
	}
	v.Available = true
	if len(s.files) > 0 {
		v.FileBytes = map[string]int64{}
		args := append([]string{"stat", "-c", "%n %s"}, s.files...)
		out, err := s.gw.Run(ctx, args...)
		if err != nil {
			v.Err = appendErr(v.Err, "stat: "+err.Error())
		}
		for _, line := range strings.Split(string(out), "\n") {
			fields := strings.Fields(line)
			if len(fields) != 2 {
				continue
			}
			if n, err := strconv.ParseInt(fields[1], 10, 64); err == nil {
				v.FileBytes[fields[0]] = n
			}
		}
	}
	if len(s.mounts) > 0 {
		v.FSFreeKB = map[string]int64{}
		args := append([]string{"df", "-k", "--output=target,avail"}, s.mounts...)
		out, err := s.gw.Run(ctx, args...)
		if err != nil {
			v.Err = appendErr(v.Err, "df: "+err.Error())
		}
		for _, line := range strings.Split(string(out), "\n")[1:] {
			fields := strings.Fields(line)
			if len(fields) != 2 {
				continue
			}
			if n, err := strconv.ParseInt(fields[1], 10, 64); err == nil {
				v.FSFreeKB[fields[0]] = n
			}
		}
	}
	if out, err := s.gw.Run(ctx, "ss", "-tanH"); err == nil {
		n := 0
		for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
			if strings.TrimSpace(line) != "" {
				n++
			}
		}
		v.TCPSockets, v.HasSockets = n, true
	} else {
		v.Err = appendErr(v.Err, "ss: "+err.Error())
	}
	return v, nil
}
