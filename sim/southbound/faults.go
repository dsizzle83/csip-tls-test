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
	"math"
	"sync"
	"time"

	modbuslib "github.com/simonvetter/modbus"
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

	// enable_gate: the commanded limit lands in the control register, but the
	// enable flag at gateAddr is held off so the limit is never enforced. gateAddr
	// and hasGate are configured once at wiring time (solar only); a sim that does
	// not advertise FaultEnableGate leaves hasGate false and never arms it.
	gate     bool
	gateAddr uint16
	hasGate  bool

	// ramp_limit (effect-time): the device accepts the limit instantly but its
	// physical output ceiling slews toward the command at rampWPerS. effCeilW is
	// the current honoured ceiling; effValid is false until the first shaping call
	// seeds it (so arming never causes a jump). nowFn is an injectable clock for
	// deterministic tests (nil → time.Now). See effectiveCeilW.
	ramp      bool
	rampWPerS float64
	effCeilW  float64
	effValid  bool
	lastEffT  time.Time
	nowFn     func() time.Time

	// soc_refuse (effect-time, battery): the pack accepts the setpoint but
	// produces zero power. See shapeBatteryW.
	refuse bool

	// charge_disabled / discharge_disabled (effect-time, battery): the pack
	// refuses only one direction. Sign convention matches shapeBatteryW:
	// + is discharge, − is charge. See shapeBatteryW.
	chargeDisabled    bool
	dischargeDisabled bool

	// Transport-layer (Modbus read-path) faults. See transportRead.
	nanSentinel     bool // every read returns 0x8000 (SunSpec N/A)
	latencyMs       int  // per-read delay
	modbusException bool // every read returns a Modbus exception
}

// transportRead is the RegisterMap.OnRead hook. It applies the armed transport
// faults to a read about to be returned: latency sleeps, exception_code returns
// a Modbus error, nan_sentinel rewrites every value to the SunSpec 0x8000 N/A
// sentinel. With none armed it returns the values unchanged.
func (fc *faultController) transportRead(vals []uint16) ([]uint16, error) {
	fc.mu.Lock()
	lat, nan, exc := fc.latencyMs, fc.nanSentinel, fc.modbusException
	fc.mu.Unlock()

	if lat > 0 {
		time.Sleep(time.Duration(lat) * time.Millisecond)
	}
	if exc {
		return nil, modbuslib.ErrServerDeviceFailure
	}
	if nan {
		out := make([]uint16, len(vals))
		for i := range out {
			out[i] = 0x8000 // SunSpec int16 "not implemented / N/A" sentinel (−32768)
		}
		return out, nil
	}
	return vals, nil
}

// shapeBatteryW applies effect-time battery faults to the hub-commanded power
// (signed: + discharge / − charge). The soc_refuse fault forces it to zero — the
// pack accepts the setpoint but its contactor/BMS refuses to source or sink. A
// NaN command (no hub control) is passed through untouched. With no battery
// effect fault armed it returns commandedW unchanged.
func (fc *faultController) shapeBatteryW(commandedW float64) float64 {
	fc.mu.Lock()
	defer fc.mu.Unlock()
	if math.IsNaN(commandedW) {
		return commandedW
	}
	if fc.refuse {
		return 0
	}
	// Directional refusal: + is discharge, − is charge.
	if fc.dischargeDisabled && commandedW > 0 {
		return 0
	}
	if fc.chargeDisabled && commandedW < 0 {
		return 0
	}
	return commandedW
}

func (fc *faultController) now() time.Time {
	if fc.nowFn != nil {
		return fc.nowFn()
	}
	return time.Now()
}

// effectiveCeilW shapes the device's commanded output ceiling (W) into the
// ceiling it physically honours this update, applying the ramp_limit effect-time
// fault: when armed, the honoured ceiling slews toward the command at rampWPerS
// (W/s) using elapsed wall time, modelling an actuator with a bounded slew rate
// rather than an instant jump. With no effect fault armed it returns
// commandedCeilW unchanged and resets the slew so a later arming starts fresh.
//
// It is driven by elapsed time, not call count, so the 1 Hz Inject path and the
// 5 s animation step can both call it and the total slew tracks the wall clock.
func (fc *faultController) effectiveCeilW(commandedCeilW float64) float64 {
	fc.mu.Lock()
	defer fc.mu.Unlock()
	if !fc.ramp {
		fc.effValid = false
		return commandedCeilW
	}
	now := fc.now()
	if !fc.effValid {
		fc.effCeilW = commandedCeilW // seed at the current command — no jump on arm
		fc.effValid = true
		fc.lastEffT = now
		return fc.effCeilW
	}
	dt := now.Sub(fc.lastEffT).Seconds()
	fc.lastEffT = now
	if dt <= 0 {
		return fc.effCeilW
	}
	step := fc.rampWPerS * dt
	switch {
	case commandedCeilW > fc.effCeilW:
		fc.effCeilW = math.Min(commandedCeilW, fc.effCeilW+step)
	case commandedCeilW < fc.effCeilW:
		fc.effCeilW = math.Max(commandedCeilW, fc.effCeilW-step)
	}
	return fc.effCeilW
}

// configureGate wires the enable-flag register the FaultEnableGate fault holds
// off. Called once by a sim that advertises the kind (solar's WMaxLimPct_Ena).
func (fc *faultController) configureGate(gateAddr uint16) {
	fc.mu.Lock()
	fc.gateAddr, fc.hasGate = gateAddr, true
	fc.mu.Unlock()
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
	gate, gateAddr, hasGate := fc.gate, fc.gateAddr, fc.hasGate
	reject, wrongSign, ackArmed, ackDelay := fc.reject, fc.wrongSign, fc.ack.armed, fc.ack.delay
	fc.mu.Unlock()

	if gate && hasGate {
		// Apply the write verbatim — the commanded limit lands and is visible on
		// readback — then force the enable flag off so the limit is never enforced.
		// Done for ANY write (including an enable-only write) so the gate cannot be
		// re-opened by a separate Ena=1 write in the next control cycle.
		for i, v := range vals {
			regs.Set(startAddr+uint16(i), v)
		}
		regs.Set(gateAddr, 0)
		log.Printf("[fault] enable_gate: %s applied the limit but forced enable reg %d=0 (limit not enforced)", fc.label, gateAddr)
		return false
	}

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

	case FaultEnableGate:
		if !fc.hasGate {
			return fmt.Errorf("fault %q: %s has no enable register configured", spec.Kind, fc.label)
		}
		fc.gate = !spec.Clear
		log.Printf("[fault] enable_gate: %s armed=%v", fc.label, fc.gate)

	case FaultRampLimit:
		if spec.Clear {
			fc.ramp, fc.effValid = false, false
			log.Printf("[fault] ramp_limit: %s cleared", fc.label)
			return nil
		}
		if spec.MaxRampWPerS <= 0 {
			return fmt.Errorf("fault %q: max_ramp_w_per_s must be > 0", spec.Kind)
		}
		fc.ramp, fc.rampWPerS, fc.effValid = true, spec.MaxRampWPerS, false
		log.Printf("[fault] ramp_limit: %s armed, rate=%.0f W/s", fc.label, fc.rampWPerS)

	case FaultSocRefuse:
		fc.refuse = !spec.Clear
		log.Printf("[fault] soc_refuse: %s armed=%v", fc.label, fc.refuse)

	case FaultChargeDisabled:
		fc.chargeDisabled = !spec.Clear
		log.Printf("[fault] charge_disabled: %s armed=%v", fc.label, fc.chargeDisabled)

	case FaultDischargeDisabled:
		fc.dischargeDisabled = !spec.Clear
		log.Printf("[fault] discharge_disabled: %s armed=%v", fc.label, fc.dischargeDisabled)

	case FaultNanSentinel:
		fc.nanSentinel = !spec.Clear
		log.Printf("[fault] nan_sentinel: %s armed=%v", fc.label, fc.nanSentinel)

	case FaultModbusException:
		fc.modbusException = !spec.Clear
		log.Printf("[fault] exception_code: %s armed=%v", fc.label, fc.modbusException)

	case FaultLatency:
		if spec.Clear {
			fc.latencyMs = 0
		} else {
			ms := spec.LatencyMs
			if ms <= 0 {
				ms = 500
			}
			fc.latencyMs = ms
		}
		log.Printf("[fault] latency: %s latency_ms=%d", fc.label, fc.latencyMs)
	}
	return nil
}
