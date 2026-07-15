package main

import (
	"context"
	"log"
	"sync"
	"time"
)

// ── Session simulation ────────────────────────────────────────────────────────
//
// Protocol-agnostic: talks only to h.proto (chargerProto) and h.batt
// (evBattery), so the exact same session state machine drives both OCPP
// versions.

// sessionHandle owns the cancellation of one charging session. The stop
// reason/trigger are recorded by whoever requests the stop (remote command,
// GUI inject, reset) before cancelling, so the session goroutine can report
// them in the Ended/StopTransaction message it sends on the way out.
type sessionHandle struct {
	cancel context.CancelFunc
	done   chan struct{}

	mu      sync.Mutex
	stopSet bool
	reason  stopReason
	trigger sessionTrigger
}

// setStop records why the session is being stopped. First caller wins.
func (sh *sessionHandle) setStop(reason stopReason, trigger sessionTrigger) {
	sh.mu.Lock()
	if !sh.stopSet {
		sh.stopSet = true
		sh.reason = reason
		sh.trigger = trigger
	}
	sh.mu.Unlock()
}

// stopCause returns the recorded stop reason/trigger, defaulting to a local stop.
func (sh *sessionHandle) stopCause() (stopReason, sessionTrigger) {
	sh.mu.Lock()
	defer sh.mu.Unlock()
	if !sh.stopSet {
		return stopLocal, trigChargingStateChanged
	}
	return sh.reason, sh.trigger
}

// startSession stops any running session (waiting for its Ended/
// StopTransaction to go out) and starts a new one. Blocks until the old
// session has fully wound down; callers on OCPP handler goroutines must wrap
// it in `go`.
func (h *csHandler) startSession(connectorID int, maxDuration time.Duration, trigger sessionTrigger, opts txStartOpts) {
	h.stopSession(stopLocal, trigChargingStateChanged)

	ctx, cancel := context.WithCancel(context.Background())
	sh := &sessionHandle{cancel: cancel, done: make(chan struct{})}
	h.mu.Lock()
	h.sess = sh
	h.mu.Unlock()

	go func() {
		defer close(sh.done)
		simulateSession(ctx, h, sh, connectorID, maxDuration, trigger, opts)
	}()
}

// stopSession stops the running session (if any) with the given stop cause
// and waits until the session goroutine has sent its Ended/StopTransaction
// message and exited. No-op when no session is active. Must not be called
// from the session goroutine itself.
func (h *csHandler) stopSession(reason stopReason, trigger sessionTrigger) {
	h.mu.Lock()
	sh := h.sess
	h.sess = nil
	h.mu.Unlock()
	if sh == nil {
		return
	}
	sh.setStop(reason, trigger)
	sh.cancel()
	<-sh.done
}

// sessionActive reports whether a charging session is currently running.
func (h *csHandler) sessionActive() bool {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.session.Active
}

// firstAvailableConnector returns the lowest-numbered connector currently in
// the Available state, or 0 when none is.
func (h *csHandler) firstAvailableConnector() int {
	h.mu.RLock()
	defer h.mu.RUnlock()
	best := 0
	for id, c := range h.connectors {
		if c.Status != connAvailable {
			continue
		}
		if best == 0 || id < best {
			best = id
		}
	}
	return best
}

func simulateSession(ctx context.Context, h *csHandler, sh *sessionHandle,
	connectorID int, maxDuration time.Duration, startTrigger sessionTrigger, opts txStartOpts) {
	log.Printf("evsim: connector %d — session starting (max %v, SOC=%.1f%%)",
		connectorID, maxDuration, func() float64 { soc, _, _ := h.batt.State(); return soc }())
	h.batt.ResetSession()
	// Reset the commanded current to the IEC 61851-1 minimum so the EV does
	// not draw at whatever leftover SetChargingProfile limit the prior session
	// happened to end at.  The CSMS will issue a fresh limit on its next
	// control tick (typically within a few seconds).
	h.batt.SetCommandedA(6.0)
	startedAt := time.Now()
	h.setSessionActive(connectorID, true)
	h.sendStatus(connectorID, connOccupied)
	txID := h.proto.TxStart(connectorID, startTrigger, opts, h.sample())
	h.setTxID(txID)

	outcome := runChargingLoop(ctx, h, connectorID, maxDuration)

	var reason stopReason
	var trigger sessionTrigger
	switch outcome {
	case sessionCancelled:
		reason, trigger = sh.stopCause()
	case sessionBatteryFull:
		reason, trigger = stopSOCLimitReached, trigChargingStateChanged
	case sessionDeadline:
		reason, trigger = stopTimeLimitReached, trigTimeLimitReached
	}

	// Charging has stopped: zero the current so final readings and later
	// snapshots don't report a stale mid-charge value.
	h.batt.StopCharging()

	h.proto.TxEnd(trigger, reason, startedAt, h.sample())
	h.sendStatus(connectorID, connAvailable)
	h.setSessionActive(connectorID, false)
	h.setTxID("")

	soc, _, _ := h.batt.State()
	log.Printf("evsim: connector %d — session ended (reason=%s), SOC=%.1f%%", connectorID, reason, soc)
}

// sessionOutcome says how a charging loop ended.
type sessionOutcome int

const (
	sessionCancelled   sessionOutcome = iota // ctx cancelled (remote/local stop, reset, supersede)
	sessionBatteryFull                       // EV battery reached 100% SOC
	sessionDeadline                          // maxDuration elapsed
)

// runChargingLoop drives the battery simulation and periodic meter reporting
// until maxDuration elapses, the battery reaches 100% SOC, or ctx is cancelled.
func runChargingLoop(ctx context.Context, h *csHandler, connectorID int, maxDuration time.Duration) sessionOutcome {
	simTicker := time.NewTicker(time.Second)
	defer simTicker.Stop()
	meterTicker := time.NewTicker(h.meterInterval)
	defer meterTicker.Stop()
	deadline := time.NewTimer(maxDuration)
	defer deadline.Stop()

	for {
		select {
		case <-ctx.Done():
			return sessionCancelled
		case <-simTicker.C:
			_, full := h.batt.Tick(time.Second)
			if full {
				log.Printf("evsim: connector %d — battery full (100%% SOC)", connectorID)
				return sessionBatteryFull
			}
		case <-meterTicker.C:
			if _, _, stopMeter := h.faults.get(); stopMeter {
				// stop_metervalues fault: keep charging but report nothing, so the
				// CSMS goes blind to the EV's actual draw. The hub must stop trusting
				// the stale reading and budget the EV conservatively.
				continue
			}
			h.proto.TxUpdate(trigMeterValuePeriodic, h.sample())
		case <-deadline.C:
			return sessionDeadline
		}
	}
}
