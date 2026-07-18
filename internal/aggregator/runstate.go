package aggregator

import (
	"encoding/json"
	"sync"
	"time"
)

// RunState is the JSON-serializable record of one emulator run — the structured
// state a later dashboard/report (T06.9) consumes. It is a passive, thread-safe
// RECORDER: it captures what the primitives observed (session facts, discovered
// devices, telemetry samples, control writes, denial probes) and carries NO
// verdict. Pass/fail judgment is the scenario engine's oracle (T06.6), which
// composes these observations; keeping RunState verdict-free preserves the
// "oracles are code, not data" boundary the bench guards (qa/scenarios/README).
//
// The report schema is versioned (RunV) so the dashboard can render an older run
// without a redeploy — additive changes bump nothing, breaking changes bump RunV.
type RunState struct {
	RunV    int            `json:"run_v"`
	Target  string         `json:"target"`
	Role    Role           `json:"role"`
	Started time.Time      `json:"started"`
	Session *SessionInfo   `json:"session,omitempty"`
	Devices []Device       `json:"devices,omitempty"`
	Samples []Snapshot     `json:"samples,omitempty"`
	Writes  []WriteRecord  `json:"writes,omitempty"`
	Denials []DenialResult `json:"denials,omitempty"`

	mu sync.Mutex
}

// RunStateV is the current run-state schema version.
const RunStateV = 1

// WriteRecord is one control write's outcome, with the measured round-trip
// latency a readback oracle later reasons over.
type WriteRecord struct {
	Unit      uint8     `json:"unit"`
	Model     uint16    `json:"model"`
	Point     string    `json:"point"`
	Value     float64   `json:"value"`
	At        time.Time `json:"at"`
	LatencyMS int64     `json:"latency_ms"`
	OK        bool      `json:"ok"`
	Err       string    `json:"err,omitempty"`
}

// NewRunState starts a run record for a target/role.
func NewRunState(target string, role Role) *RunState {
	return &RunState{RunV: RunStateV, Target: target, Role: role, Started: time.Now()}
}

// SetSession records the handshake facts (typically Conn.SessionInfo()).
func (rs *RunState) SetSession(si SessionInfo) {
	rs.mu.Lock()
	rs.Session = &si
	rs.mu.Unlock()
}

// AddDevices records a discovery result.
func (rs *RunState) AddDevices(devs []Device) {
	rs.mu.Lock()
	rs.Devices = append(rs.Devices, devs...)
	rs.mu.Unlock()
}

// AddSample records a telemetry snapshot. It is a valid SnapshotSink target, so
// a Poll loop can stream directly into the run record.
func (rs *RunState) AddSample(s Snapshot) {
	rs.mu.Lock()
	rs.Samples = append(rs.Samples, s)
	rs.mu.Unlock()
}

// Publish satisfies SnapshotSink, so `conn.Poll(ctx, units, period, runState)`
// records every sample.
func (rs *RunState) Publish(s Snapshot) { rs.AddSample(s) }

// AddWrite records a control write and its latency.
func (rs *RunState) AddWrite(w WriteRecord) {
	rs.mu.Lock()
	rs.Writes = append(rs.Writes, w)
	rs.mu.Unlock()
}

// AddDenial records a role-denial probe result.
func (rs *RunState) AddDenial(d DenialResult) {
	rs.mu.Lock()
	rs.Denials = append(rs.Denials, d)
	rs.mu.Unlock()
}

// MarshalJSON serializes the run state under lock, so a concurrent Poll writing
// samples cannot race the marshal. The alias sheds the mutex and the custom
// method to avoid infinite recursion.
func (rs *RunState) MarshalJSON() ([]byte, error) {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	type alias struct {
		RunV    int            `json:"run_v"`
		Target  string         `json:"target"`
		Role    Role           `json:"role"`
		Started time.Time      `json:"started"`
		Session *SessionInfo   `json:"session,omitempty"`
		Devices []Device       `json:"devices,omitempty"`
		Samples []Snapshot     `json:"samples,omitempty"`
		Writes  []WriteRecord  `json:"writes,omitempty"`
		Denials []DenialResult `json:"denials,omitempty"`
	}
	return json.Marshal(alias{
		RunV: rs.RunV, Target: rs.Target, Role: rs.Role, Started: rs.Started,
		Session: rs.Session, Devices: rs.Devices, Samples: rs.Samples,
		Writes: rs.Writes, Denials: rs.Denials,
	})
}
