package sim

// poke.go — MOVE ONE NAMED REGISTER, AND BE ABLE TO PUT IT BACK.
//
// # The gap this closes
//
// Every other /inject key on these sims is a FIELD override: "W_W", "Conn",
// "WMaxLimPct_pct". Each is decoded against the layout the sim's constructor
// computed, which is exactly right for a bench operator driving the device's
// physics and exactly wrong for the one thing the write rows of
// SS-MODBUS-CLIENT-CONF-v1.1 need.
//
// Those rows (§2.6 WR-1/WR-2) have to provoke the client into WRITING, and the
// only provocation available to a bench that must not command the device
// directly is DIVERGENCE: move the control register out from under the client
// and see whether its reconciler puts it back. That works only if the register
// moved is the one the client actually owns. Until now the suite's divergence
// lever was `{"WMaxLimPct_pct": 50}`, which writes the LEGACY model 123
// ceiling — and on an advanced sim the model 123 ceiling is a MIRROR the sim's
// own bridge re-derives from model 704 on its next animation tick, while the
// client reads and writes 704. The provocation was being restored under itself
// before the client ever saw it, and two rows whose whole method is divergence
// have SKIPped for want of a write in every campaign to date.
//
// A raw poke fixes that without the sim needing to know which point is which:
// the caller names an ADDRESS. The suite learns the address it wants from the
// client's own traffic — the ledger records the FC 0x10 write the client
// issues, address and all — so the register the row diverges is, by
// construction, the exact register the product owns. No model definition
// directory is consulted on either side, which is the property ERR-3's
// independence rests on.
//
// # Why it saves the prior value
//
// A conformance row must leave the bench as it found it, and "as it found it"
// for a control register is not a constant the row can hard-code — it is
// whatever the device held. Prior values are captured on first touch (not on
// every touch), so re-poking an address does not overwrite the true original
// with an already-poked value, and Clear restores the pristine contents
// however many times an address was moved. That is the same discipline
// sentinel.go's injector uses, for the same reason.

import (
	"encoding/json"
	"fmt"
	"log"
	"sync"
)

// RegisterPoke writes raw values to named holding registers and remembers what
// they held, so a later Clear puts the device back.
//
// It writes through RegisterMap.Set, which is the sim-internal path: write
// protection (protect.go) masks MODBUS writes to the scale-factor cells and
// deliberately does not apply here. A bench operator moving a register is the
// device changing its own mind, not a client writing to it.
type RegisterPoke struct {
	regs *RegisterMap
	mu   sync.Mutex
	// prior holds, per touched address, the value it held the FIRST time this
	// poke touched it.
	prior map[uint16]uint16
}

// NewRegisterPoke wraps regs. Construction alone never touches it.
func NewRegisterPoke(regs *RegisterMap) *RegisterPoke {
	return &RegisterPoke{regs: regs, prior: make(map[uint16]uint16)}
}

// Set writes value at addr, capturing the prior contents on first touch.
func (p *RegisterPoke) Set(addr, value uint16) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if _, saved := p.prior[addr]; !saved {
		p.prior[addr] = p.regs.Get(addr)
	}
	p.regs.Set(addr, value)
}

// Clear restores every address this poke has touched and forgets them.
func (p *RegisterPoke) Clear() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.prior) == 0 {
		return
	}
	for a, v := range p.prior {
		p.regs.Set(a, v)
	}
	log.Printf("[inject] registers: restored %d poked register(s)", len(p.prior))
	p.prior = make(map[uint16]uint16)
}

// Touched returns how many distinct addresses are currently held away from
// their original values.
func (p *RegisterPoke) Touched() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.prior)
}

// ── POST /inject {"registers":[{"addr":40234,"value":5000}]} ──────────────────

// pokeInjectSpec is the POST /inject body this file recognises. A body
// carrying neither key is left for the classic field-override path entirely
// unchanged.
type pokeInjectSpec struct {
	Registers []struct {
		Addr  uint16 `json:"addr"`
		Value *int   `json:"value"`
		Delta *int   `json:"delta,omitempty"`
	} `json:"registers,omitempty"`
	ClearRegisters bool `json:"clear_registers,omitempty"`
}

// ApplyInject claims a POST /inject body carrying "registers" or
// "clear_registers".
//
// `value` sets an absolute word; `delta` adds to whatever the register holds
// right now, which is what a caller wants when the point is a scaled quantity
// whose current value it does not want to have to decode — "move it by 500
// raw units" is a divergence whatever the scale factor turns out to be.
// Exactly one of the two must be given: a body with both would have two
// readings and no way to choose between them, and a body with neither is a
// no-op the caller probably did not mean.
func (p *RegisterPoke) ApplyInject(body []byte) (handled bool, err error) {
	var spec pokeInjectSpec
	if e := json.Unmarshal(body, &spec); e != nil {
		return false, nil
	}
	if len(spec.Registers) == 0 && !spec.ClearRegisters {
		return false, nil
	}
	if spec.ClearRegisters {
		p.Clear()
	}
	for _, r := range spec.Registers {
		switch {
		case r.Value != nil && r.Delta != nil:
			return true, fmt.Errorf("inject registers: address %d names both value and delta; give one", r.Addr)
		case r.Value != nil:
			if *r.Value < -32768 || *r.Value > 65535 {
				return true, fmt.Errorf("inject registers: value %d at address %d does not fit a 16-bit "+
					"holding register", *r.Value, r.Addr)
			}
			p.Set(r.Addr, uint16(*r.Value))
			log.Printf("[inject] registers: %d = %d (0x%04x)", r.Addr, *r.Value, uint16(*r.Value))
		case r.Delta != nil:
			cur := p.regs.Get(r.Addr)
			next := uint16(int32(int16(cur)) + int32(*r.Delta))
			p.Set(r.Addr, next)
			log.Printf("[inject] registers: %d %+d → %d (0x%04x)", r.Addr, *r.Delta, int16(next), next)
		default:
			return true, fmt.Errorf("inject registers: address %d names neither value nor delta", r.Addr)
		}
	}
	return true, nil
}
