package suitemodbusserver

// writes.go is the shared machinery of the five write-driven procedures
// (MB-1, MOD-3, EXC-1, and the three reversion tests).
//
// # Where the values come from
//
// Both source documents get the values to write from the device PICS: MOD-3
// says "based on the value range specified in the PICS", EXC-1 says "for enum
// points, write a value outside of the defined enumerations". There is no PICS
// workbook for this DUT. Inventing one would be the dishonest move; so would
// silently writing whatever fits in the register. What this file does instead
// is carry a small, explicit table of the adjustable points it is prepared to
// exercise, each with the SOURCE of its range written down — the point's
// declared units and the model definition's enumeration set — and each range
// converted through the scale factor the device itself reports. A point not in
// the table is not written, and MOD-3 says which points it did not exercise
// and why, rather than reporting coverage it does not have.
//
// # Why every write is preceded by a control write
//
// Three product policies on this DUT can refuse a northbound write before the
// procedure's criterion is reached (see the package doc). A refusal is
// indistinguishable, at the Modbus layer, from "the DUT correctly rejected the
// thing you were testing" unless you first establish that a VALID write to the
// same point is accepted. So writeProbe performs exactly that control write —
// the point's own current value, which changes nothing — and every caller
// grades the procedure only when it succeeded.
//
// # Restoration
//
// Every write this suite makes is undone before the check returns. A
// conformance run must leave the DUT in the state it found it: a curtailment
// setpoint left behind by a test is a control action nobody authorised.

import (
	"fmt"
	"math"
)

// adjustable describes one point this suite is prepared to write, and where the
// bounds it writes come from.
type adjustable struct {
	Model uint16
	Point string
	// Enum, when non-empty, is the complete set of legal values for an
	// enumerated point; MOD-3 step 3 writes every one of them.
	Enum []uint16
	// EngMin / EngMax bound a numeric point in engineering units.
	EngMin, EngMax float64
	// SF names the sunssf point the engineering bounds convert through. Empty
	// means the register carries engineering units directly.
	SF string
	// Source is recorded in the bundle: it is what a reviewer checks the range
	// against, in place of the PICS the procedure assumes.
	Source string
}

// key identifies the adjustable for messages.
func (a adjustable) key() string { return fmt.Sprintf("%d.%s", a.Model, a.Point) }

// adjustables is the table. It is deliberately short: these are the points the
// DUT's northbound projection can actually apply, and a suite that swept every
// RW register in the map would spend most of its run proving that the write
// decoder refuses things.
var adjustables = []adjustable{
	{
		Model: 704, Point: "WMaxLimPct",
		EngMin: 0, EngMax: 100, SF: "WMaxLimPct_SF",
		Source: "the point's declared units are Pct (percent of maximum active power); the limit-active-power " +
			"function is defined over 0..100 %, and the bound is converted through the WMaxLimPct_SF the " +
			"device itself reports",
	},
	{
		Model: 704, Point: "WMaxLimPctRvrtTms",
		EngMin: 0, EngMax: 3600,
		Source: "uint32 seconds with no scale factor; the sweep is bounded at one hour so a conformance run " +
			"stays finite, and 0 is the defined 'no automatic reversion' value",
	},
	{
		Model: 704, Point: "WMaxLimPctEna",
		Enum:   []uint16{0, 1},
		Source: "the DER model definition's enumeration for every *Ena point: DISABLED = 0, ENABLED = 1",
	},
}

// adjustableFor returns the table entry for a model/point pair.
func adjustableFor(model uint16, point string) (adjustable, bool) {
	for _, a := range adjustables {
		if a.Model == model && a.Point == point {
			return a, true
		}
	}
	return adjustable{}, false
}

// scaleFactor reads a model's sunssf point and returns its exponent. The second
// result is false when the point is absent from the transcription, unreadable,
// or reads the not-implemented sentinel — in which case a scaled bound cannot
// be computed and the caller must say so rather than assume 10^0.
func scaleFactor(c *client, m modelRef, block []uint16, name string) (int, bool) {
	def, ok := Models[m.ID]
	if !ok {
		return 0, false
	}
	p, ok := def.Point(name)
	if !ok || p.Type != TypeSunSSF {
		return 0, false
	}
	regs, ok := pointRegs(block, p)
	if !ok || len(regs) != 1 {
		return 0, false
	}
	if p.Type.NotImplemented(regs) {
		return 0, false
	}
	v := int(int16(regs[0]))
	if v < -10 || v > 10 {
		return 0, false
	}
	return v, true
}

// rawBounds converts an adjustable's engineering bounds into register values
// using the device-reported scale factor: raw = engineering / 10^sf.
func rawBounds(a adjustable, sf int) (min, max int64) {
	factor := math.Pow(10, float64(-sf))
	return int64(math.Round(a.EngMin * factor)), int64(math.Round(a.EngMax * factor))
}

// sweepValues returns the values MOD-3 step 1 requires: the minimum, the
// maximum, and three intermediates. When fewer than five distinct values exist
// in the range, all of them are returned, which is what the step's second
// sentence calls for.
func sweepValues(min, max int64) []int64 {
	if max < min {
		min, max = max, min
	}
	span := max - min
	if span < 4 {
		out := make([]int64, 0, span+1)
		for v := min; v <= max; v++ {
			out = append(out, v)
		}
		return out
	}
	return []int64{
		min,
		min + span/4,
		min + span/2,
		min + (3*span)/4,
		max,
	}
}

// encode renders a raw value as the point's registers.
func encode(p Point, v int64) ([]uint16, error) {
	switch p.Regs() {
	case 1:
		if v < math.MinInt16 || v > math.MaxUint16 {
			return nil, fmt.Errorf("suitemodbusserver: %d does not fit one register", v)
		}
		return []uint16{uint16(v)}, nil
	case 2:
		if v < math.MinInt32 || v > math.MaxUint32 {
			return nil, fmt.Errorf("suitemodbusserver: %d does not fit two registers", v)
		}
		return put32(uint32(v)), nil
	default:
		return nil, fmt.Errorf("suitemodbusserver: point %s is %d registers wide; this suite writes 16- and "+
			"32-bit points only", p.Name, p.Regs())
	}
}

// decodeRaw renders a point's registers as a raw integer for comparison.
func decodeRaw(p Point, regs []uint16) int64 {
	switch len(regs) {
	case 1:
		switch p.Type {
		case TypeInt16:
			return int64(int16(regs[0]))
		default:
			return int64(regs[0])
		}
	case 2:
		switch p.Type {
		case TypeInt32:
			return int64(int32(u32(regs)))
		default:
			return int64(u32(regs))
		}
	default:
		return 0
	}
}

// writePoint writes a whole point, choosing FC 6 for a single register and
// FC 16 for a wider one. Writing only part of a point is what the DUT's
// all-or-nothing decoder exists to refuse, and this suite never does it by
// accident — TCP-2 and EXC-1 do it on purpose and say so.
func writePoint(c *client, m modelRef, p Point, regs []uint16, note string) error {
	addr := m.Addr + uint16(p.Off)
	if len(regs) == 1 {
		return c.writeSingle(addr, regs[0], note)
	}
	return c.writeMultiple(addr, regs, note)
}

// readPointNow reads a point back with a single request, with no settling
// delay. v1.3 of the conformance procedures REMOVED the 1000 ms read-after-
// write allowance v1.2 had added, so a read that has to wait is a failure.
func readPointNow(c *client, m modelRef, p Point, note string) ([]uint16, error) {
	return readPoint(c, m, p, note)
}

// writeProbe is the control write: the point's own current value, written back
// unchanged. It establishes that writes to this point are reaching the write
// path at all, and it is the reason none of this suite's write procedures can
// mistake a policy refusal for a conformance result.
type writeProbe struct {
	// Point is the point probed.
	Point Point
	// Model is where it lives.
	Model modelRef
	// Original is the value found before anything was written.
	Original []uint16
	// Accepted reports whether the control write succeeded.
	Accepted bool
	// Err is the refusal, when there was one.
	Err error
	// Reason explains a refusal in the DUT's own policy terms.
	Reason string
	// TIDs are the transactions the probe used, for citation.
	TIDs []uint16
}

// probeWrite reads a point and writes its current value straight back.
func probeWrite(c *client, m modelRef, p Point, note string) (*writeProbe, error) {
	before := len(c.log)
	orig, err := readPoint(c, m, p, note+": read current value")
	if err != nil {
		return nil, fmt.Errorf("read %d.%s before writing: %w", m.ID, p.Name, err)
	}
	pr := &writeProbe{Point: p, Model: m, Original: append([]uint16(nil), orig...)}
	werr := writePoint(c, m, p, orig, note+": control write of the unchanged current value")
	if werr == nil {
		pr.Accepted = true
	} else {
		pr.Err = werr
		pr.Reason = denialReason(werr)
		if pr.Reason == "" {
			pr.Reason = errText(werr)
		}
	}
	for _, x := range c.log[before:] {
		pr.TIDs = append(pr.TIDs, x.TID)
	}
	return pr, nil
}

// restore writes a point's original value back, best-effort. A restoration
// failure is reported to the caller so it lands in the run log rather than
// disappearing: leaving a setpoint behind is exactly the kind of side effect a
// conformance run must not have silently.
func restore(c *client, pr *writeProbe, note string) error {
	if pr == nil || !pr.Accepted {
		return nil
	}
	return writePoint(c, pr.Model, pr.Point, pr.Original, note+": restore the pre-test value")
}
