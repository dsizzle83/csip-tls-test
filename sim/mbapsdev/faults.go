package main

// faults.go — mbaps-specific fault-injection hooks for mbapsdev, in the
// sim/modsim style (POST /fault {"kind":…}, cleared via {"kind":…,"clear":true}).
//
// These three kinds act on the TLS/session layer, which sim/southbound's
// faultController (register-level faults: reject_write, nan_sentinel, …) has
// no visibility into — they exist so T06's conformance and emulator tasks
// (T06.4 reconnect/backoff, T06.8 resumption-after-fatal /
// renegotiation-refusal probes) can drive negative cases at the mbaps
// transport, not just the register world:
//
//   - drop_session:     close the connection mid-exchange (after decoding a
//     request, before responding) — exercises the aggregator's reconnect path.
//   - refuse_resume:    close any session that arrives already resumed
//     (Session.Resumed) instead of serving it — models a device/gateway
//     policy that never allows resumption, forcing a full handshake.
//   - stall_handshake:  delay accepting (and therefore handshaking) each new
//     connection by a configurable delay — exercises a client's connect
//     timeout.
//
// register-level fault kinds (reject_write, nan_sentinel, latency,
// exception_code, ack_before_effect, …) are NOT reimplemented here: Device
// delegates any kind it does not recognize to the underlying
// sim.SolarServer/BatteryServer.ApplyFault, which already implements the
// full sim/modsim vocabulary against the SAME RegisterMap this package's
// dispatcher reads and writes (see main.go's newModel).
//
// tcp_drop (sim.FaultTCPDrop) is deliberately REJECTED rather than silently
// delegated: it bounces the underlying model's own internal plain-Modbus
// listener, which mbapsdev never exposes (see main.go) — armed over mbaps it
// would be an observable no-op. drop_session is the mbaps-native equivalent.

import (
	"encoding/json"
	"fmt"
	"sync"
	"time"
)

const (
	faultDropSession    = "drop_session"
	faultRefuseResume   = "refuse_resume"
	faultStallHandshake = "stall_handshake"
	faultTCPDrop        = "tcp_drop" // rejected — see package doc above
)

// defaultStallDelay is used when stall_handshake is armed without an
// explicit delay_s.
const defaultStallDelay = 5 * time.Second

// faultSpec is the POST /fault body shape, matching sim.FaultSpec's JSON
// contract (kind/delay_s/clear) so operators and QA scripts use one
// vocabulary across the plain sims and mbapsdev.
type faultSpec struct {
	Kind   string  `json:"kind"`
	DelayS float64 `json:"delay_s,omitempty"`
	Clear  bool    `json:"clear,omitempty"`
}

// mbapsFaults holds the armed/cleared state for the three transport-layer
// fault kinds. The zero value is fully unarmed (every check is a
// pass-through), so a Device is safe to use before any /fault call.
type mbapsFaults struct {
	mu             sync.Mutex
	dropSession    bool
	refuseResume   bool
	stallHandshake bool
	stallDelay     time.Duration
}

// apply arms or clears spec if it names one of the three mbaps-specific
// kinds, returning handled=false for anything else so the caller falls
// through to the underlying model's ApplyFault.
func (f *mbapsFaults) apply(spec faultSpec) (handled bool, err error) {
	switch spec.Kind {
	case faultDropSession:
		f.mu.Lock()
		f.dropSession = !spec.Clear
		f.mu.Unlock()
		return true, nil
	case faultRefuseResume:
		f.mu.Lock()
		f.refuseResume = !spec.Clear
		f.mu.Unlock()
		return true, nil
	case faultStallHandshake:
		f.mu.Lock()
		f.stallHandshake = !spec.Clear
		if spec.DelayS > 0 {
			f.stallDelay = time.Duration(spec.DelayS * float64(time.Second))
		} else if f.stallDelay == 0 {
			f.stallDelay = defaultStallDelay
		}
		f.mu.Unlock()
		return true, nil
	case faultTCPDrop:
		return true, fmt.Errorf("mbapsdev: %q has no meaning over mbaps — this device exposes no plain "+
			"Modbus TCP listener to drop; use %q to close the secure session mid-exchange instead",
			faultTCPDrop, faultDropSession)
	}
	return false, nil
}

// dropArmed reports whether drop_session is currently armed.
func (f *mbapsFaults) dropArmed() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.dropSession
}

// refuseResumeArmed reports whether refuse_resume is currently armed.
func (f *mbapsFaults) refuseResumeArmed() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.refuseResume
}

// stallInfo reports whether stall_handshake is armed and, if so, the delay
// to apply before the next Accept.
func (f *mbapsFaults) stallInfo() (armed bool, delay time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.stallHandshake, f.stallDelay
}

// snapshot returns a JSON-serializable view of the armed mbaps-fault state,
// folded into GET /state (see main.go's stateSnapshot) for QA visibility.
type mbapsFaultsSnapshot struct {
	DropSession    bool    `json:"drop_session"`
	RefuseResume   bool    `json:"refuse_resume"`
	StallHandshake bool    `json:"stall_handshake"`
	StallDelayS    float64 `json:"stall_delay_s,omitempty"`
}

func (f *mbapsFaults) snapshot() mbapsFaultsSnapshot {
	f.mu.Lock()
	defer f.mu.Unlock()
	return mbapsFaultsSnapshot{
		DropSession:    f.dropSession,
		RefuseResume:   f.refuseResume,
		StallHandshake: f.stallHandshake,
		StallDelayS:    f.stallDelay.Seconds(),
	}
}

// parseFaultSpec decodes a POST /fault body. A body that fails to decode is
// a 400 at the simapi layer (audit MOD-4: admin endpoints reject bad input
// rather than wrapping it), never a silently-ignored fault arm.
func parseFaultSpec(body []byte) (faultSpec, error) {
	var spec faultSpec
	if err := json.Unmarshal(body, &spec); err != nil {
		return faultSpec{}, fmt.Errorf("mbapsdev: fault: %w", err)
	}
	if spec.Kind == "" {
		return faultSpec{}, fmt.Errorf("mbapsdev: fault: missing \"kind\"")
	}
	return spec, nil
}
