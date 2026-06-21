package sim

// faults.go — shared fault-injection controller for the Modbus sims.
//
// Each animated sim (solar, battery, …) embeds a faultController and points its
// RegisterMap.OnWriteAttempt hook at the controller's intercept method. The
// controller owns the armed-fault state and the write-time semantics; the sim
// only supplies the address of the control register the faults act on (the
// signed WMaxLimPct in Model 123) and the set of FaultKinds it advertises.
//
// This keeps one implementation of the OnWriteAttempt behaviour shared across
// sims (the pattern solar proved with ack_before_effect) instead of a copy per
// device. New write-time fault kinds are added here once; a sim opts in by
// listing the kind in its supported set (see solarFaultKinds / batteryFaultKinds).
//
// See docs/QA_FAULT_INJECTION.md for the fault matrix and the INV-* oracles the
// mayhem suite judges these faults against.

import (
	"encoding/json"
	"fmt"
	"log"
	"sync"
	"time"
)

// ackBeforeEffect holds the state for the FaultAckBeforeEffect injector: when
// armed, a control write is acknowledged at the Modbus layer but its effect on
// the output is deferred by delay.
type ackBeforeEffect struct {
	armed bool
	delay time.Duration
	timer *time.Timer // pending effect application; replaced on each new write
}

// faultController is the embeddable fault state shared by the Modbus sims.
// All fields are guarded by mu. The zero value is a valid, unarmed controller
// (every intercept is a pass-through), so a sim constructed without a fault
// wiring still behaves normally.
type faultController struct {
	mu        sync.Mutex
	label     string // sim name, for log lines ("solar" | "battery")
	ack       ackBeforeEffect
	reject    bool // FaultRejectWrite: ACK the command at Modbus but never apply it
	wrongSign bool // FaultWrongSign: apply the command with its sign flipped
}

// intercept implements the RegisterMap.OnWriteAttempt contract for a write that
// may cover cmdAddr (the sim's control register). It returns apply=true to let
// the RegisterMap store the values verbatim (the no-fault fast path), or
// apply=false when the controller has taken responsibility for the write — in
// which case the Modbus layer still reports success, modelling a device that
// ACKs at the protocol level regardless of what it does with the value.
//
// Faults act only on cmdAddr; every other register in the same write is always
// applied immediately so unrelated fields (Ena, Conn) are never collateral.
func (fc *faultController) intercept(regs *RegisterMap, cmdAddr, startAddr uint16, vals []uint16) bool {
	fc.mu.Lock()
	reject, wrongSign, ackArmed, ackDelay := fc.reject, fc.wrongSign, fc.ack.armed, fc.ack.delay
	fc.mu.Unlock()

	if !reject && !wrongSign && !ackArmed {
		return true // no write-time fault armed — apply verbatim
	}

	off := int(cmdAddr) - int(startAddr)
	if off < 0 || off >= len(vals) {
		return true // this write does not touch the control register — apply normally
	}

	// Apply every register except the control one; the fault decides that one.
	for i, v := range vals {
		if i != off {
			regs.Set(startAddr+uint16(i), v)
		}
	}

	switch {
	case reject:
		// Drop the control write: the register keeps its prior value while the
		// hub sees a Modbus ACK. Models an actuator that accepts the command and
		// silently ignores it — the case INV-CONVERGE exists to catch.
		log.Printf("[fault] reject_write: %s ignored control reg %d (Modbus ACK only)", fc.label, cmdAddr)

	case wrongSign:
		// Apply the command with its sign inverted: a charge becomes a discharge
		// (and vice versa). Models a device wired/firmware-flipped in the wrong
		// direction — the case INV-SOC exists to catch.
		flipped := uint16(-int16(vals[off]))
		regs.Set(cmdAddr, flipped)
		log.Printf("[fault] wrong_sign: %s applied control %d as %d", fc.label, int16(vals[off]), int16(flipped))

	case ackArmed:
		// Hold the control value for ackDelay, then apply it. During the window
		// the device keeps its previous ceiling while the hub already saw the
		// write succeed — the case INV-CONVERGE exists to catch.
		newVal := vals[off]
		fc.mu.Lock()
		if fc.ack.timer != nil {
			fc.ack.timer.Stop()
		}
		fc.ack.timer = time.AfterFunc(ackDelay, func() {
			regs.Set(cmdAddr, newVal)
			log.Printf("[fault] ack_before_effect: %s control reg %d=%d now in effect (after %s)", fc.label, cmdAddr, int16(newVal), ackDelay)
		})
		fc.mu.Unlock()
		log.Printf("[fault] ack_before_effect: %s control reg %d=%d ACKed, effect deferred %s", fc.label, cmdAddr, int16(newVal), ackDelay)
	}
	return false // the controller handled the control register
}

// apply arms or clears a fault from a POST /fault body. supported is the set of
// FaultKinds the calling sim advertises; an unsupported kind is an error (the
// simapi layer turns it into a 400). It is the shared backend of each sim's
// ApplyFault method.
func (fc *faultController) apply(body []byte, supported map[FaultKind]bool) error {
	var spec FaultSpec
	if err := json.Unmarshal(body, &spec); err != nil {
		return fmt.Errorf("fault: %w", err)
	}
	if !supported[spec.Kind] {
		return fmt.Errorf("fault: unsupported kind %q for %s", spec.Kind, fc.label)
	}

	fc.mu.Lock()
	defer fc.mu.Unlock()
	switch spec.Kind {
	case FaultAckBeforeEffect:
		if spec.Clear {
			fc.ack.armed = false
			if fc.ack.timer != nil {
				fc.ack.timer.Stop()
			}
			log.Printf("[fault] ack_before_effect: %s cleared", fc.label)
			return nil
		}
		if spec.DelayS <= 0 {
			return fmt.Errorf("fault %q: delay_s must be > 0", spec.Kind)
		}
		fc.ack.armed = true
		fc.ack.delay = time.Duration(spec.DelayS * float64(time.Second))
		log.Printf("[fault] ack_before_effect: %s armed, delay=%s", fc.label, fc.ack.delay)

	case FaultRejectWrite:
		fc.reject = !spec.Clear
		log.Printf("[fault] reject_write: %s armed=%v", fc.label, fc.reject)

	case FaultWrongSign:
		fc.wrongSign = !spec.Clear
		log.Printf("[fault] wrong_sign: %s armed=%v", fc.label, fc.wrongSign)
	}
	return nil
}
