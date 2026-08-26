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
	"sort"
	"sync"
)

// sentinelWords are the words of the SunSpec "not implemented" value for
// each datatype, in the order written starting at the point's address.
//
// The widths and bit patterns are the SunSpec Device Information Model
// Specification's own table, not invented here — SS-MODBUS-CLIENT-CONF-v1.1
// §2.7.2 INFO-2 requires a point of EVERY datatype present in the server's
// models to be set to its unimplemented value, and (per the catalog's own note
// on that row) the procedure declines to print the table it depends on.
//
// The variable-width types are handled in Seed rather than here, because they
// have no fixed word count:
//
//	string     n registers of zero — a leading NUL, i.e. the empty string
//	ipv6addr   8 registers of zero
//
// eui48 is 3 registers of all-ones. SunSpec lays eui48 out in 4 registers with
// the first as padding; the sentinel this table writes covers the six value
// bytes, which is the part a client decodes, and Seed's caller addresses the
// value rather than the pad.
//
// A note on the zero-valued sentinels (acc16/acc32/acc64, ipaddr, string): for
// those types the not-implemented value is genuinely 0, which is also a
// perfectly ordinary reading. That ambiguity is the SPECIFICATION'S, not this
// file's, and it is the reason INFO-2's criterion is about the client's
// RENDERING rather than about the wire alone.
var sentinelWords = map[string][]uint16{
	"int16":      {0x8000},
	"uint16":     {0xFFFF},
	"count":      {0xFFFF},
	"acc16":      {0x0000},
	"enum16":     {0xFFFF},
	"bitfield16": {0xFFFF},
	"sunssf":     {0x8000},
	"pad":        {0x8000},
	"int32":      {0x8000, 0x0000},
	"uint32":     {0xFFFF, 0xFFFF},
	"acc32":      {0x0000, 0x0000},
	"enum32":     {0xFFFF, 0xFFFF},
	"bitfield32": {0xFFFF, 0xFFFF},
	"ipaddr":     {0x0000, 0x0000},
	"float32":    {0x7FC0, 0x0000}, // canonical quiet NaN
	"eui48":      {0xFFFF, 0xFFFF, 0xFFFF},
	"int64":      {0x8000, 0x0000, 0x0000, 0x0000},
	"uint64":     {0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF},
	"acc64":      {0x0000, 0x0000, 0x0000, 0x0000},
	"float64":    {0x7FF8, 0x0000, 0x0000, 0x0000}, // canonical quiet NaN
}

// variableWidthSentinels are the datatypes whose not-implemented value is a
// run of zero registers whose LENGTH the point's declaration fixes rather than
// the type. The value is the default register count Seed uses when the caller
// gives no len.
var variableWidthSentinels = map[string]int{
	"string":   1, // a leading NUL is the whole of the empty string
	"ipv6addr": 8, // 128 bits
}

// SentinelTypes lists every datatype Seed knows, sorted — for the error a
// caller gets when it names one this table does not carry, and for a bench
// that wants to sweep the lot.
func SentinelTypes() []string {
	out := make([]string, 0, len(sentinelWords)+len(variableWidthSentinels))
	for t := range sentinelWords {
		out = append(out, t)
	}
	for t := range variableWidthSentinels {
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}

// SentinelWordsFor returns the register words that Seed writes for typ at the
// given declared length (len is used only by the variable-width types), and
// whether typ is known.
//
// It is exported so a caller that seeds a sentinel can state, in its own
// evidence, exactly which words it asked the device to serve — rather than
// asserting that the sim wrote the right thing and leaving a reader to take
// that on trust.
func SentinelWordsFor(typ string, strLen int) ([]uint16, bool) {
	if w, ok := sentinelWords[typ]; ok {
		return append([]uint16(nil), w...), true
	}
	if def, ok := variableWidthSentinels[typ]; ok {
		n := strLen
		if n <= 0 {
			n = def
		}
		return make([]uint16, n), true
	}
	return nil, false
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

// Seed writes typ's not-implemented sentinel at addr. strLen sets the register
// count for the variable-width types (string, ipv6addr) and is ignored for
// every other type, whose width its datatype fixes.
func (si *SentinelInjector) Seed(addr uint16, typ string, strLen int) error {
	words, ok := SentinelWordsFor(typ, strLen)
	if !ok {
		return fmt.Errorf("sentinel: unknown type %q (want one of %v)", typ, SentinelTypes())
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
