package main

// matrix.go — the fault-matrix run mode (Phase 5). A curated, bounded cross of
// {grid constraint × device fault}, each run WITH and WITHOUT a clock-jitter
// modifier, so a single run sweeps the fault×timing interactions the hand-written
// scenarios cover only individually. It is pairwise-curated, not a blind
// Cartesian: only physically meaningful constraint/fault pairings are generated,
// and each reuses the same diagnosers as its single-fault sibling.
//
// Run via POST /api/qa/start {"matrix":true} or scripts/mayhem.py --matrix.

import "fmt"

// matrixCell describes one fault-matrix combination before the jitter cross.
type matrixCell struct {
	id         string
	constraint string // "genLimit" | "exportCap" | "importCap"
	limW       float64
	holdS      int
	pvW        float64 // injected PV; negative ⇒ use d.pvHighW (nameplate-aware full sun)
	loadW      float64
	batterySoC float64
	device     string // "solar" | "battery" | "" (no fault)
	fault      string // fault kind, or ""
	faultBody  map[string]any
	eval       func(*mayScenario, *activeConstraint, []maySample) mayFinding
}

// matrixScenarios builds the full fault matrix: each curated cell × {no jitter,
// ±60 s clock jitter}.
func (d *mayhemDriver) matrixScenarios() []*mayScenario {
	const usePVHigh = -1.0
	cells := []matrixCell{
		{id: "genlimit-clean", constraint: "genLimit", limW: 1000, holdS: 60, pvW: usePVHigh, loadW: 250, batterySoC: 100, eval: diagnoseConstraint},
		{id: "genlimit-reject", constraint: "genLimit", limW: 1000, holdS: 60, pvW: usePVHigh, loadW: 250, batterySoC: 100, device: "solar", fault: "reject_write", eval: diagnoseConverge},
		{id: "genlimit-enablegate", constraint: "genLimit", limW: 1000, holdS: 60, pvW: usePVHigh, loadW: 250, batterySoC: 100, device: "solar", fault: "enable_gate", eval: diagnoseConverge},
		{id: "genlimit-ramplimit", constraint: "genLimit", limW: 1000, holdS: 100, pvW: usePVHigh, loadW: 250, batterySoC: 100, device: "solar", fault: "ramp_limit", faultBody: map[string]any{"max_ramp_w_per_s": 120}, eval: diagnoseConverge},
		{id: "exportcap-wrongsign", constraint: "exportCap", limW: 0, holdS: 90, pvW: usePVHigh, loadW: 250, batterySoC: 10.5, device: "battery", fault: "wrong_sign", eval: diagnoseSOC},
		{id: "importcap-socrefuse", constraint: "importCap", limW: 0, holdS: 70, pvW: 300, loadW: 5000, batterySoC: 50, device: "battery", fault: "soc_refuse", eval: diagnoseConstraint},
	}
	out := make([]*mayScenario, 0, len(cells)*2)
	for _, c := range cells {
		for _, jitter := range []bool{false, true} {
			out = append(out, d.buildMatrixCell(c, jitter))
		}
	}
	return out
}

// buildMatrixCell turns a matrixCell into a runnable scenario, optionally adding
// a ±60 s clock-jitter modifier. Under jitter the grid event is posted for a much
// longer window so the modest skew always stays inside it (a non-conformant
// hours-long lurch is out of scope — the client must schedule in server time).
func (d *mayhemDriver) buildMatrixCell(c matrixCell, jitter bool) *mayScenario {
	id, name := "matrix/"+c.id, c.id
	if jitter {
		id += "+jitter"
		name += " + clock jitter"
	}
	pv := func() float64 {
		if c.pvW < 0 {
			return d.pvHighW
		}
		return c.pvW
	}
	capDur := c.holdS
	if jitter {
		capDur += 200 // long event window so ±60 s jitter stays well inside it
	}
	return &mayScenario{
		ID: id, Name: name,
		Category:   "Fault matrix",
		Hypothesis: fmt.Sprintf("Matrix cell: %s under %s%s.", c.constraint, faultDesc(c.device, c.fault), jitterDesc(jitter)),
		Expected:   "Hold the constraint or admit it (CannotComply); a device fault must not silently breach it, and a modest clock jitter must not change the outcome versus the no-jitter cell.",
		HoldS:      c.holdS,
		Fix:        "See the matching single-fault scenario for the device-specific fix.",
		setup: func(d *mayhemDriver) (*activeConstraint, error) {
			_ = d.post("battery", "/inject", map[string]any{"SoC_pct": c.batterySoC, "Conn": 1})
			d.injectEnv(pv(), c.loadW)
			if c.fault != "" {
				body := map[string]any{"kind": c.fault}
				for k, v := range c.faultBody {
					body[k] = v
				}
				if err := d.post(c.device, "/fault", body); err != nil {
					return nil, fmt.Errorf("arm %s on %s: %w", c.fault, c.device, err)
				}
			}
			return d.postCap(c.constraint, c.limW, capDur, "matrix: "+c.id)
		},
		perTick: func(d *mayhemDriver, i int) {
			d.injectEnv(pv(), c.loadW)
			if jitter {
				off := int64((i%5 - 2) * 30) // realistic ±60 s NTP-style jitter
				_ = d.post("gridsim", "/admin/clock", map[string]any{"offset_s": off})
			}
		},
		evaluate: c.eval,
		teardown: func(d *mayhemDriver) {
			if c.fault != "" {
				_ = d.post(c.device, "/fault", map[string]any{"kind": c.fault, "clear": true})
			}
			if jitter {
				_ = d.post("gridsim", "/admin/clock", map[string]any{"offset_s": 0})
			}
		},
	}
}

func faultDesc(device, fault string) string {
	if fault == "" {
		return "no device fault (clean baseline)"
	}
	return device + " " + fault
}

func jitterDesc(jitter bool) string {
	if jitter {
		return " with ±60 s clock jitter"
	}
	return ""
}
