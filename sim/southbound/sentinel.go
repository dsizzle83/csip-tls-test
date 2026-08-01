package sim

// sentinel.go — per-point SunSpec "not implemented" sentinel injection.
//
// nan_sentinel (faults.go) rewrites EVERY register on EVERY read to the
// int16 blanket sentinel 0x8000, which proves a client recognises "the
// whole device is unavailable" but never proves it recognises "this ONE
// point, of THIS type, is simply not populated" — the ordinary, permanent
// case a PICS model declares. §2.7.2 INFO-2 step 2 wants a point seeded
// with ITS OWN type's not-implemented value and read back; this fills that
// gap for the eight datatypes this capability was scoped to — see
// runs/final-fullsuite-20260731T234821/REPORT.md INFO-2#2.
//
// This is a direct register write, the same "poke a value now" model
// POST /inject already uses for every other field override (see simapi's
// doc comment) — not a sticky per-read hook like nan_sentinel. A single
// seed-and-read-back is what §2.7.2 step 2 asks for, and layering a second
// always-on OnRead rewrite on top of transportRead for every armed point
// would outlive its purpose and fight any OTHER read fault sharing the map.
// Like every other /inject override in this codebase, a seeded value can be
// overwritten by the next animation tick if the chosen point is one the
// animation actively updates; pick a static point (Model 1/120/121 fields,
// say) for a durable test.

import (
	"encoding/json"
	"fmt"
	"log"
	"sync"
)

// sentinelWords are the words of the SunSpec "not implemented" value for
// each datatype this fault knows, in the order written starting at the
// point's address. Widths and bit patterns are the Information Model's own
// table, not invented here. "string" is handled separately in Seed (it has
// no fixed width).
var sentinelWords = map[string][]uint16{
	"int16":      {0x8000},
	"uint16":     {0xFFFF},
	"enum16":     {0xFFFF},
	"int32":      {0x8000, 0x0000},
	"uint32":     {0xFFFF, 0xFFFF},
	"acc32":      {0x0000, 0x0000},
	"bitfield32": {0xFFFF, 0xFFFF},
}

// SentinelInjector pokes a chosen register's "not implemented" pattern
// directly into a *RegisterMap and remembers the prior contents so a later
// Clear can put them back.
type SentinelInjector struct {
	regs *RegisterMap
	mu   sync.Mutex
	// prior holds, per touched address, the value it held the FIRST time
	// Seed touched it — so a second Seed on the same address (re-arm with a
	// different type, say) does not overwrite the true original with an
	// already-injected sentinel, and Clear always restores the pristine
	// value regardless of how many times an address was re-seeded.
	prior map[uint16]uint16
}

// NewSentinelInjector wraps regs. Construction alone never touches it.
func NewSentinelInjector(regs *RegisterMap) *SentinelInjector {
	return &SentinelInjector{regs: regs, prior: make(map[uint16]uint16)}
}

// Seed writes typ's not-implemented sentinel at addr: fixed width for every
// type in sentinelWords, or strLen (default 1, a leading NUL = an empty
// string) registers of zero for "string".
func (si *SentinelInjector) Seed(addr uint16, typ string, strLen int) error {
	words, ok := sentinelWords[typ]
	if typ == "string" {
		n := strLen
		if n <= 0 {
			n = 1
		}
		words = make([]uint16, n) // all-zero: a leading NUL, the empty string
		ok = true
	}
	if !ok {
		return fmt.Errorf("sentinel: unknown type %q (want one of int16, uint16, enum16, int32, uint32, acc32, bitfield32, string)", typ)
	}
	si.mu.Lock()
	defer si.mu.Unlock()
	for i, w := range words {
		a := addr + uint16(i)
		if _, saved := si.prior[a]; !saved {
			si.prior[a] = si.regs.Get(a)
		}
		si.regs.Set(a, w)
	}
	log.Printf("[fault] unimplemented: seeded %s not-implemented sentinel at %d..%d", typ, addr, addr+uint16(len(words))-1)
	return nil
}

// Clear restores every address Seed has touched to its pre-injection value
// and forgets them, so a later Seed on the same address starts a fresh
// prior-value capture rather than restoring an already-restored one.
func (si *SentinelInjector) Clear() {
	si.mu.Lock()
	defer si.mu.Unlock()
	for a, v := range si.prior {
		si.regs.Set(a, v)
	}
	si.prior = make(map[uint16]uint16)
	log.Printf("[fault] unimplemented: cleared")
}

// ── POST /inject {"unimplemented":[{"addr":40190,"type":"int16"}]} ────────

// sentinelInjectSpec is the POST /inject body this file additionally
// recognises, independent of whatever fields the classic Inject path reads.
// A body with neither key is left for that path entirely unchanged.
type sentinelInjectSpec struct {
	Unimplemented []struct {
		Addr uint16 `json:"addr"`
		Type string `json:"type"`
		Len  int    `json:"len,omitempty"` // string only; registers to blank (default 1)
	} `json:"unimplemented,omitempty"`
	ClearUnimplemented bool `json:"clear_unimplemented,omitempty"`
}

// ApplyInject claims a POST /inject body that carries "unimplemented" or
// "clear_unimplemented"; every other body (the classic field-override form)
// is left unhandled so the caller falls through to srv.Inject unchanged.
func (si *SentinelInjector) ApplyInject(body []byte) (handled bool, err error) {
	var spec sentinelInjectSpec
	if e := json.Unmarshal(body, &spec); e != nil {
		return false, nil
	}
	if len(spec.Unimplemented) == 0 && !spec.ClearUnimplemented {
		return false, nil
	}
	if spec.ClearUnimplemented {
		si.Clear()
	}
	for _, u := range spec.Unimplemented {
		if e := si.Seed(u.Addr, u.Type, u.Len); e != nil {
			return true, e
		}
	}
	return true, nil
}
