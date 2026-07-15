package main

import (
	"math"
	"sync"
	"time"
)

// ── EV battery CC/CV charging model ──────────────────────────────────────────
//
// CC phase (0 ≤ SOC < cvStartSOC): constant current at commanded limit.
// CV phase (cvStartSOC ≤ SOC < 100): current tapers linearly to zero.
//
// Energy update per tick:
//
//	ΔSOCpct = (actualA × voltageV × Δt_sim_h / capacityWh) × 100
//
// This model is shared verbatim by both the OCPP 2.0.1 and OCPP 1.6 protocol
// adapters (ocpp201.go / ocpp16.go) — evsim is a protocol adapter over ONE
// simulated device, not two separate simulators.

// evBattery models one EV battery over a charging session.
type evBattery struct {
	mu sync.Mutex

	CapacityWh  float64 // total usable capacity (Wh)
	SOC         float64 // current state of charge (0–100 %)
	VoltageV    float64 // AC supply voltage (V)
	MaxCurrentA float64 // EVSE hardware max current (A)
	CVStartSOC  float64 // SOC % where CC→CV transition begins (default 80)
	SimSpeed    float64 // time multiplier: each real tick covers SimSpeed × dt

	commandedA float64 // current limit from last SetChargingProfile (A)
	actualA    float64 // actual current per CC/CV model (A)
	sessionWh  float64 // cumulative energy this session (Wh)
	minFloorA  float64 // min_current_floor fault: charger won't modulate below this while charging (0 = off)
	reportMult float64 // wrong_units fault: multiply reported MeterValues current/power (0/1 = correct, 1000 = mA reported as A)
}

func newEVBattery(capacityWh, initialSOC, voltageV, maxCurrentA, simSpeed float64) *evBattery {
	return &evBattery{
		CapacityWh:  capacityWh,
		SOC:         math.Min(100, math.Max(0, initialSOC)),
		VoltageV:    voltageV,
		MaxCurrentA: maxCurrentA,
		CVStartSOC:  80.0,
		SimSpeed:    math.Max(0.001, simSpeed),
	}
}

// SetCommandedA updates the charging current limit from a SetChargingProfile.
func (b *evBattery) SetCommandedA(a float64) {
	b.mu.Lock()
	b.commandedA = a
	b.mu.Unlock()
}

// SetMinFloorA arms/clears the min_current_floor fault: while charging, the
// charger will not modulate the current below floorA even when commanded lower
// (a charger that cannot dim past its minimum). floorA <= 0 clears it.
func (b *evBattery) SetMinFloorA(floorA float64) {
	b.mu.Lock()
	b.minFloorA = floorA
	b.mu.Unlock()
}

// ReportCurrentMult returns the wrong_units multiplier applied to reported
// MeterValues current/power (1 when unarmed). SetReportCurrentMult arms it.
func (b *evBattery) ReportCurrentMult() float64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.reportMult <= 0 {
		return 1
	}
	return b.reportMult
}

func (b *evBattery) SetReportCurrentMult(m float64) {
	b.mu.Lock()
	b.reportMult = m
	b.mu.Unlock()
}

// ResetSession zeros the session energy counter. Call when a new session starts.
func (b *evBattery) ResetSession() {
	b.mu.Lock()
	b.sessionWh = 0
	b.mu.Unlock()
}

// StopCharging zeros the commanded and actual current. Call when a session
// ends so State() doesn't keep reporting the last mid-charge current.
func (b *evBattery) StopCharging() {
	b.mu.Lock()
	b.commandedA = 0
	b.actualA = 0
	b.mu.Unlock()
}

// Tick advances the battery simulation by dt × SimSpeed of simulated time.
// Returns (actualA, full): full is true when SOC reaches 100%.
func (b *evBattery) Tick(dt time.Duration) (actualA float64, full bool) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.SOC >= 100.0 || b.commandedA <= 0 {
		b.actualA = 0
		return 0, b.SOC >= 100.0
	}

	limit := math.Min(b.commandedA, b.MaxCurrentA)
	// min_current_floor fault: the charger cannot modulate below its minimum, so a
	// hub command to dim further is silently floored — the EV keeps drawing more
	// than commanded.
	if b.minFloorA > 0 && limit < b.minFloorA {
		limit = b.minFloorA
	}

	if b.SOC < b.CVStartSOC {
		// CC phase: full current.
		b.actualA = limit
	} else {
		// CV phase: linear taper from full current at cvStartSOC to 0 at 100%.
		taper := (100.0 - b.SOC) / (100.0 - b.CVStartSOC)
		b.actualA = limit * math.Max(0, taper)
	}

	// Advance simulated time.
	simSec := dt.Seconds() * b.SimSpeed
	dtH := simSec / 3600.0
	powerW := b.actualA * b.VoltageV
	energyWh := powerW * dtH

	b.SOC = math.Min(100.0, b.SOC+(energyWh/b.CapacityWh)*100.0)
	b.sessionWh += energyWh

	if b.SOC >= 100.0 {
		b.SOC = 100.0
		b.actualA = 0
		return 0, true
	}
	return b.actualA, false
}

// Phase returns "CC" or "CV" based on current SOC.
func (b *evBattery) Phase() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.SOC < b.CVStartSOC {
		return "CC"
	}
	return "CV"
}

// State returns a thread-safe snapshot of the battery.
func (b *evBattery) State() (soc, actualA, sessionWh float64) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.SOC, b.actualA, b.sessionWh
}
