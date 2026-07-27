package suitemodbusclient

// sunspec.go is the SunSpec Device Information Model layer over the register
// image the DUT was observed to read.
//
// It knows four things and no more, because four things are all the procedures
// in SS-MODBUS-CLIENT-CONF-v1.1 rest on:
//
//   - the "SunS" identifier and the three standard base addresses a client is
//     expected to probe (CLI-4, ERR-1);
//   - the model chain: an ID/length header pair followed by a body, repeated
//     until the 0xFFFF end marker (CLI-1..4, ERR-3, READ-2);
//   - the per-datatype "not implemented" sentinel values (INFO-2);
//   - the Common Model's identity points, so a discovery assertion can quote
//     what the DUT actually learned about the device (CLI-1..4).
//
// Deliberately absent: a model definition directory. This suite must not decide
// that a model is "known" using the same table the DUT uses, or ERR-3 would
// test the table against itself. Model identity is taken from the wire, and
// whether the DUT recognised a model is inferred from its BEHAVIOUR — did it
// read the body, or did it step over the block using the length header?

import (
	"fmt"
	"sort"
)

// SunSpec identifier: the ASCII bytes "SunS" occupying two holding registers.
const (
	SunSHigh = 0x5375 // "Su"
	SunSLow  = 0x6E53 // "nS"
	// ModelChainEnd is the end-of-chain marker that terminates the model list.
	ModelChainEnd = 0xFFFF
	// CommonModelID is SunSpec model 1, the Common Model every server carries
	// and every one of these procedures requires the client to read.
	CommonModelID = 1
)

// StandardBases are the three base addresses a SunSpec client is expected to
// probe, in the order the DUT's own admission path uses them. CLI-4 requires a
// client to work at all three; ERR-1's noncompliant server sits one register
// off the middle one.
var StandardBases = []uint16{40000, 0, 50000}

// IsStandardBase reports whether an address is one of the three legal SunSpec
// base addresses.
func IsStandardBase(addr uint16) bool {
	for _, b := range StandardBases {
		if b == addr {
			return true
		}
	}
	return false
}

// Model is one entry of the SunSpec model chain as reconstructed from the wire.
type Model struct {
	// HeaderAddr is the address of the model's ID register; the length register
	// follows it and the body begins at HeaderAddr+2.
	HeaderAddr uint16
	ID         uint16
	Length     uint16
	// BodyRead is true when the DUT read at least one register of the model's
	// body — the observable difference between "the client consumed this model"
	// and "the client stepped over it using the length header", which is
	// exactly what ERR-3's criterion turns on.
	BodyRead bool
	// BodyCovered is true when every register of the body was read.
	BodyCovered bool
	// BodySingleRead is true when the whole body was retrieved by ONE request,
	// which is READ-2's criterion for a model of 125 registers or fewer.
	BodySingleRead bool
	// Reads are the read requests that touched this model's body.
	Reads []ReadSpan
}

// ReadSpan is one FC 0x03 / 0x04 request's address range.
type ReadSpan struct {
	Start, Quantity uint16
	// Exchange indexes the conversation's exchange list, so a check can cite
	// the request bytes.
	Exchange int
}

// End is the address one past the last register the span covers.
func (s ReadSpan) End() uint16 { return s.Start + s.Quantity }

// Covers reports whether the span contains addr.
func (s ReadSpan) Covers(addr uint16) bool {
	return addr >= s.Start && addr < s.Start+s.Quantity
}

// Chain walks the model chain from base using only registers the DUT was
// observed to read.
//
// A walk that runs out of observed registers stops and says so rather than
// guessing: an incomplete chain is an honest partial observation, and every
// caller here treats "the walk stopped early" as a reason to qualify its
// assertion, never as a reason to fail the DUT.
func (v *RegisterView) Chain(base uint16) (models []Model, complete bool, why string) {
	hi, okHi := v.Get(base)
	lo, okLo := v.Get(base + 1)
	if !okHi || !okLo {
		return nil, false, fmt.Sprintf("the SunSpec identifier registers at %d..%d were not among the "+
			"registers this test case observed the DUT read", base, base+1)
	}
	if hi != SunSHigh || lo != SunSLow {
		return nil, false, fmt.Sprintf("registers %d..%d hold 0x%04x 0x%04x, not the SunSpec identifier "+
			"0x%04x 0x%04x", base, base+1, hi, lo, SunSHigh, SunSLow)
	}
	addr := base + 2
	for {
		id, okID := v.Get(addr)
		if !okID {
			return models, false, fmt.Sprintf("the chain walk reached the model header at %d, which this "+
				"test case did not observe the DUT read", addr)
		}
		if id == ModelChainEnd {
			return models, true, ""
		}
		length, okLen := v.Get(addr + 1)
		if !okLen {
			return models, false, fmt.Sprintf("the length register of the model at %d (ID %d) was not "+
				"observed, so the chain cannot be walked past it", addr, id)
		}
		models = append(models, Model{HeaderAddr: addr, ID: id, Length: length})
		next := addr + 2 + length
		if next <= addr {
			return models, false, fmt.Sprintf("the model at %d declares length %d, which does not advance "+
				"the chain", addr, length)
		}
		addr = next
		if len(models) > 512 {
			return models, false, "the chain did not terminate within 512 models"
		}
	}
}

// annotate fills in each model's read-coverage facts from the conversation's
// read spans.
func annotateModels(models []Model, spans []ReadSpan) []Model {
	out := make([]Model, len(models))
	copy(out, models)
	for i := range out {
		m := &out[i]
		body := m.HeaderAddr + 2
		if m.Length == 0 {
			// A zero-length model has no body; treat it as trivially covered
			// so it cannot masquerade as a skipped model.
			m.BodyCovered, m.BodySingleRead = true, true
			continue
		}
		covered := make([]bool, m.Length)
		for _, s := range spans {
			touched := false
			for k := uint16(0); k < m.Length; k++ {
				if s.Covers(body + k) {
					covered[k] = true
					touched = true
				}
			}
			if touched {
				m.Reads = append(m.Reads, s)
				m.BodyRead = true
			}
			// One request covering the whole body: START at or before the body
			// and END at or after its last register.
			if s.Start <= body && s.End() >= body+m.Length {
				m.BodySingleRead = true
			}
		}
		all := true
		for _, c := range covered {
			if !c {
				all = false
				break
			}
		}
		m.BodyCovered = all
	}
	return out
}

// ── Not-implemented sentinels (SunSpec Device Information Model Specification) ──

// Sentinel is one datatype's "not implemented" value, as the register words it
// occupies. INFO-2's criterion is that the client identifies a point carrying
// its type's sentinel AS unimplemented rather than reporting the sentinel as a
// measurement, so the suite needs the table the procedure itself declines to
// print (see the catalog note on INFO-2).
type Sentinel struct {
	Type  string
	Words []uint16
}

// Sentinels is the per-datatype not-implemented table. eui48 and the string
// types are represented by their leading word: a string point is unimplemented
// when its first byte is 0x00, and eui48's sentinel is all-ones across its
// registers.
var Sentinels = []Sentinel{
	{"int16", []uint16{0x8000}},
	{"uint16", []uint16{0xFFFF}},
	{"count", []uint16{0xFFFF}},
	{"acc16", []uint16{0x0000}},
	{"enum16", []uint16{0xFFFF}},
	{"bitfield16", []uint16{0xFFFF}},
	{"sunssf", []uint16{0x8000}},
	{"int32", []uint16{0x8000, 0x0000}},
	{"uint32", []uint16{0xFFFF, 0xFFFF}},
	{"acc32", []uint16{0x0000, 0x0000}},
	{"enum32", []uint16{0xFFFF, 0xFFFF}},
	{"bitfield32", []uint16{0xFFFF, 0xFFFF}},
	{"ipaddr", []uint16{0x0000, 0x0000}},
	{"float32", []uint16{0x7FC0, 0x0000}}, // canonical quiet NaN
	{"int64", []uint16{0x8000, 0x0000, 0x0000, 0x0000}},
	{"uint64", []uint16{0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF}},
	{"acc64", []uint16{0x0000, 0x0000, 0x0000, 0x0000}},
	{"eui48", []uint16{0xFFFF, 0xFFFF, 0xFFFF}},
}

// SentinelTypesFor returns the datatypes whose not-implemented sentinel begins
// with word w. It is deliberately many-to-one: 0xFFFF is the sentinel for six
// different types, and an assertion that claimed to know which one a register
// belonged to — without a point map — would be inventing precision.
func SentinelTypesFor(w uint16) []string {
	var out []string
	for _, s := range Sentinels {
		if s.Words[0] == w {
			out = append(out, s.Type)
		}
	}
	sort.Strings(out)
	return out
}

// SentinelCount counts how many of the registers in a response carry a value
// that is the leading word of some datatype's not-implemented sentinel, and
// returns the distinct sentinel words seen.
func SentinelCount(regs []uint16) (n int, words []uint16) {
	seen := map[uint16]bool{}
	for _, r := range regs {
		if len(SentinelTypesFor(r)) == 0 {
			continue
		}
		n++
		seen[r] = true
	}
	for w := range seen {
		words = append(words, w)
	}
	sort.Slice(words, func(i, j int) bool { return words[i] < words[j] })
	return n, words
}

// CommonModel are the Common Model (ID 1) identity points, at their fixed
// offsets from the body's first register. Offsets and lengths are from the
// SunSpec Device Information Model Specification's model 1 definition.
var CommonModel = []struct {
	Name   string
	Offset uint16
	Regs   uint16
}{
	{"Mn (manufacturer)", 0, 16},
	{"Md (model)", 16, 16},
	{"Opt (options)", 32, 8},
	{"Vr (version)", 40, 8},
	{"SN (serial number)", 48, 16},
	{"DA (device address)", 64, 1},
}

// CommonModelString decodes one Common Model string point from the observed
// register image. It returns ok=false when the DUT was not observed reading the
// whole point, because a half-read string is not a value.
func (v *RegisterView) CommonModelString(bodyAddr, offset, regs uint16) (string, bool) {
	buf := make([]byte, 0, regs*2)
	for i := uint16(0); i < regs; i++ {
		w, ok := v.Get(bodyAddr + offset + i)
		if !ok {
			return "", false
		}
		buf = append(buf, byte(w>>8), byte(w))
	}
	// SunSpec strings are NUL-padded; trim at the first NUL.
	for i, b := range buf {
		if b == 0 {
			buf = buf[:i]
			break
		}
	}
	return string(buf), true
}
