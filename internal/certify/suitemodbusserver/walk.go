package suitemodbusserver

// walk.go is this suite's own SunSpec discovery walk, re-derived from the
// SunSpec Device Information Model Specification §6.1 and §6.2 rather than
// imported from lexa-proto/sunspec.
//
// The walk is the foundation every other check in this suite stands on: DEV-1
// asserts it directly, DEV-2/MOD-1/MOD-2/MOD-3 need the model addresses it
// produces, and MOD-4's "every required model is implemented" is a claim about
// the completeness of exactly this chain. Getting it from the same package the
// DUT builds its chain with would make the strongest claim in the suite
// circular.
//
// The algorithm, verbatim from §6.2:
//
//  1. Read the contents of addresses 0, 40000 and 50000 until the well-known
//     marker is found.
//  2. Repeat until a model ID of 0xFFFF is found: read the next two registers
//     for the ID and L of the next model, then add L to the address of the
//     register after the length register to find the next model.
//
// Two details the specification is explicit about and an implementation
// routinely gets wrong:
//
//   - The three base addresses are the full 16-bit, ZERO-BASED addresses that
//     appear in the Modbus protocol messages. 0x9C40 goes on the wire, not
//     0x9C41. The familiar 40001 is the 1-based rendering of the same base.
//   - The end model is TWO registers: ID 0xFFFF and length 0. Reading only the
//     ID register and stopping would let a device with a nonzero end-model
//     length pass.

import (
	"fmt"
	"sort"

	"lexa-proto/mbap"
)

// The SunSpec identifier, "SunS" (0x53756E53) as two big-endian registers, and
// the three standard base addresses. Transcribed from the Device Information
// Model Specification §6.1.1.
const (
	sunSMarker0 uint16 = 0x5375 // 'S','u'
	sunSMarker1 uint16 = 0x6E53 // 'n','S'
	endModelID  uint16 = 0xFFFF
)

// standardBases are the three addresses a SunSpec map may start at, in the
// order the specification lists them.
var standardBases = []uint16{0, 40000, 50000}

// baseProbe records what one candidate base address answered.
type baseProbe struct {
	Base uint16
	// Regs is the two-register read result; nil when the read did not succeed.
	Regs []uint16
	// Err is the failure, typically a Modbus exception for a base the device
	// does not implement.
	Err error
}

// Found reports whether this base carries the SunSpec identifier.
func (p baseProbe) Found() bool {
	return len(p.Regs) == 2 && p.Regs[0] == sunSMarker0 && p.Regs[1] == sunSMarker1
}

// String renders the probe for the report.
func (p baseProbe) String() string {
	switch {
	case p.Found():
		return fmt.Sprintf("%d: 0x%04x 0x%04x (SunS)", p.Base, p.Regs[0], p.Regs[1])
	case len(p.Regs) == 2:
		return fmt.Sprintf("%d: 0x%04x 0x%04x (not the SunSpec identifier)", p.Base, p.Regs[0], p.Regs[1])
	case p.Err != nil:
		if e, ok := asException(p.Err); ok {
			return fmt.Sprintf("%d: exception 0x%02x (%s)", p.Base, uint8(e.Code), e.Code)
		}
		return fmt.Sprintf("%d: %v", p.Base, p.Err)
	default:
		return fmt.Sprintf("%d: not probed", p.Base)
	}
}

// modelRef is one model located by the walk.
type modelRef struct {
	// ID is the model identifier from the header's first register.
	ID uint16
	// Addr is the absolute address of the ID register.
	Addr uint16
	// L is the declared instance length: the number of registers after the
	// length register that belong to this model.
	L uint16
	// DataAddr is Addr+2, the first data register.
	DataAddr uint16
	// Index is the model's position in the chain, 0-based.
	Index int
}

// span is the model's total register footprint including its two header
// registers.
func (m modelRef) span() int { return int(m.L) + 2 }

// chain is the result of a complete discovery walk.
type chain struct {
	// Base is the address the SunSpec identifier was found at.
	Base uint16
	// Probes records every base address tried, in specification order, so
	// DEV-1's "located at one of the standard start addresses" claim can cite
	// the negative probes as well as the positive one.
	Probes []baseProbe
	// Models are the models found, in chain order, excluding the end model.
	Models []modelRef
	// EndAddr is the address of the end model's ID register.
	EndAddr uint16
	// EndLen is the end model's declared length, which the specification
	// requires to be 0.
	EndLen uint16
	// EndSeen reports whether the walk terminated on the end marker rather than
	// on an error or the step ceiling.
	EndSeen bool
	// Steps is how many model headers were read.
	Steps int
}

// Model returns the first instance of a model id in the chain.
func (c *chain) Model(id uint16) (modelRef, bool) {
	for _, m := range c.Models {
		if m.ID == id {
			return m, true
		}
	}
	return modelRef{}, false
}

// IDs returns the model ids present, sorted ascending and de-duplicated.
func (c *chain) IDs() []uint16 {
	seen := map[uint16]bool{}
	var out []uint16
	for _, m := range c.Models {
		if !seen[m.ID] {
			seen[m.ID] = true
			out = append(out, m.ID)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// PresentSet returns the chain's model ids as a set.
func (c *chain) PresentSet() map[uint16]bool {
	out := map[uint16]bool{}
	for _, m := range c.Models {
		out[m.ID] = true
	}
	return out
}

// Summary renders the chain the way the discovery procedure describes it.
func (c *chain) Summary() string {
	s := fmt.Sprintf("base %d, ", c.Base)
	for _, m := range c.Models {
		s += fmt.Sprintf("[%d @%d L=%d] ", m.ID, m.Addr, m.L)
	}
	if c.EndSeen {
		s += fmt.Sprintf("[end 0x%04x @%d L=%d]", endModelID, c.EndAddr, c.EndLen)
	} else {
		s += "(no end model reached)"
	}
	return s
}

// maxChainSteps bounds the walk. A device whose length register is corrupt can
// otherwise send a walker round the address space forever; stopping and saying
// so is a finding, looping is a hang.
const maxChainSteps = 64

// findBase probes the three standard base addresses in specification order and
// returns the first that carries the identifier. Every probe is recorded,
// including the ones that failed, because "the content is located at one of the
// standard addresses" is a claim about all three.
func findBase(c *client) (chain, error) {
	var ch chain
	for _, base := range standardBases {
		regs, err := c.readHolding(base, 2, fmt.Sprintf("DEV-1 base probe at %d", base))
		p := baseProbe{Base: base, Regs: regs, Err: err}
		ch.Probes = append(ch.Probes, p)
		if p.Found() && ch.Base == 0 && len(ch.Models) == 0 {
			ch.Base = base
			// Keep probing the remaining bases: a device answering the
			// identifier at more than one base is a finding worth recording,
			// and the negative probes are cited evidence for DEV-1 step 2.
		}
	}
	found := false
	for _, p := range ch.Probes {
		if p.Found() {
			found = true
			break
		}
	}
	if !found {
		return ch, fmt.Errorf("suitemodbusserver: no SunSpec identifier at any standard base address (%v)", ch.Probes)
	}
	return ch, nil
}

// walkChain performs the model-chain walk from an already-located base.
func walkChain(c *client, ch *chain) error {
	addr := ch.Base + 2
	for ch.Steps = 0; ch.Steps < maxChainSteps; ch.Steps++ {
		hdr, err := c.readHolding(addr, 2, fmt.Sprintf("DEV-1 model header at %d", addr))
		if err != nil {
			return fmt.Errorf("suitemodbusserver: model header read at %d: %w", addr, err)
		}
		id, l := hdr[0], hdr[1]
		if id == endModelID {
			ch.EndAddr, ch.EndLen, ch.EndSeen = addr, l, true
			return nil
		}
		ch.Models = append(ch.Models, modelRef{
			ID: id, Addr: addr, L: l, DataAddr: addr + 2, Index: len(ch.Models),
		})
		next := int(addr) + 2 + int(l)
		if next > 0xFFFF {
			return fmt.Errorf("suitemodbusserver: model %d at %d declares L=%d, which walks past the end of the "+
				"16-bit address space", id, addr, l)
		}
		addr = uint16(next)
	}
	return fmt.Errorf("suitemodbusserver: the model chain did not terminate within %d models", maxChainSteps)
}

// discover locates the base and walks the chain.
func discover(c *client) (*chain, error) {
	ch, err := findBase(c)
	if err != nil {
		return &ch, err
	}
	if err := walkChain(c, &ch); err != nil {
		return &ch, err
	}
	return &ch, nil
}

// probeUnit finds a unit identifier the DUT answers the SunSpec identifier on.
//
// A plain SunSpec device has one unit and it is whatever the PICS says. The DUT
// here is a GATEWAY: it allocates a unit identifier per admitted southbound
// device from a persistent map, so the unit a run must address is a runtime
// fact, not a configuration constant. Probing for it is the only way to be
// certain the suite is talking to a real projection rather than reading
// exceptions and calling them a device.
//
// The exceptions the probe walks past are meaningful and are recorded: 0x0A
// says the unit is unknown, 0x0B says the unit is known but its device has
// never reported.
func probeUnit(c *client, maxUnit int) (uint8, []string, error) {
	var notes []string
	for u := 1; u <= maxUnit; u++ {
		c.unit = uint8(u)
		regs, err := c.readHolding(standardBases[1], 2, fmt.Sprintf("unit probe %d", u))
		switch {
		case err == nil && len(regs) == 2 && regs[0] == sunSMarker0 && regs[1] == sunSMarker1:
			notes = append(notes, fmt.Sprintf("unit %d: SunSpec identifier present", u))
			return uint8(u), notes, nil
		case err == nil:
			notes = append(notes, fmt.Sprintf("unit %d: 0x%04x 0x%04x (not the identifier)", u, regs[0], regs[1]))
		default:
			if e, ok := asException(err); ok {
				notes = append(notes, fmt.Sprintf("unit %d: exception 0x%02x (%s)", u, uint8(e.Code), e.Code))
				if e.Code == mbap.ExGatewayPath || e.Code == mbap.ExGatewayTarget ||
					e.Code == mbap.ExIllegalAddress || e.Code == mbap.ExIllegalFunction {
					continue
				}
				continue
			}
			// A transport failure is not something to iterate through: the
			// stream is no longer trustworthy.
			return 0, notes, fmt.Errorf("suitemodbusserver: unit probe %d: %w", u, err)
		}
	}
	return 0, notes, fmt.Errorf("suitemodbusserver: no unit in 1..%d answered the SunSpec identifier at %d",
		maxUnit, standardBases[1])
}
