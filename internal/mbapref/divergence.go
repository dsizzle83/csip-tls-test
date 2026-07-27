package mbapref

// divergence.go is the enumeration that keeps the acceptance oracle honest.
//
// Two independent decoders will not agree on every byte string, and they
// should not: strictness is a design choice, and a server that speaks four
// function codes is entitled to refuse things a general reader accepts. So a
// raw "they disagreed" oracle reports a wall of noise on the first real
// capture and gets muted, which is the failure mode of every differential
// tester that has ever been abandoned.
//
// The fix is not a tolerance. It is an ENUMERATION: each accepted difference
// is written down, with the direction it goes, the rule each side applied, and
// — the part that does the work — the OBSERVABLE CONSEQUENCE of the
// difference. Anything not on the list is a finding.
//
// Writing the consequence down is what stops this file from decaying into a
// list of excuses. "Both are reasonable" is how a real bug gets waved through;
// "the product closes the connection where the spec would have it answer an
// exception, so a peer that sends this loses its session and every queued
// write with it" is a claim someone can disagree with, and if they disagree
// the entry gets deleted and becomes a finding again.
//
// A divergence entry is also a standing invitation to check the OTHER
// direction. Every entry here is product-stricter-than-reference. There is no
// entry the other way, and there had better not be: a case where the product
// accepts something this reader refuses is a candidate authorization or
// actuation bug, and Compare reports it unenumerated by construction.

import "fmt"

// Divergence is one accepted, justified difference between the product's
// reader and this one.
type Divergence struct {
	// ID is stable and citable in a report.
	ID string
	// Title is the one-line shape of the difference.
	Title string
	// ProductRule is what lexa-proto/mbap does.
	ProductRule string
	// ReferenceRule is what this package does, and why the spec says so.
	ReferenceRule string
	// Consequence is what an operator or a peer actually observes because of
	// the difference. An entry whose consequence is "none" does not belong
	// here; it belongs in a finding, because a difference with no consequence
	// is a difference nobody needed to make.
	Consequence string
	// Stricter names the side that refuses more inputs.
	Stricter string
	// Defect marks an entry that is NOT a justified difference at all but a
	// confirmed bug, suppressed here only so that fuzzing can keep exploring
	// past it. Everything else in this table is meant to live here; a Defect
	// entry is meant to be DELETED, and the test suite carries a reproducer
	// that fails when the underlying fix lands so nobody has to remember.
	//
	// The distinction is kept in the type rather than in prose because the
	// two have opposite lifecycles, and a table that blurs them is how a bug
	// becomes "expected behaviour" over the course of a year.
	Defect bool
}

func (d Divergence) String() string {
	if d.Defect {
		return fmt.Sprintf("%s (CONFIRMED DEFECT, suppressed): %s", d.ID, d.Title)
	}
	return fmt.Sprintf("%s (%s stricter): %s", d.ID, d.Stricter, d.Title)
}

// Defects returns the suppressed-defect entries. A non-empty result is a
// standing debt, and the report prints it.
func Defects() []Divergence {
	var out []Divergence
	for _, d := range Divergences() {
		if d.Defect {
			out = append(out, d)
		}
	}
	return out
}

// Divergences returns the enumeration, in a stable order.
//
// It is short on purpose. A long list is evidence that the two
// implementations are not really testing each other.
func Divergences() []Divergence {
	return []Divergence{
		{
			ID:          "DIV-LEN2",
			Title:       "a Length field of 2 (a one-byte PDU) is a framing error to the product and a message error here",
			Stricter:    "product",
			ProductRule: "mbap.Decode requires 3 <= Length <= 254 and returns *FrameError below it, which its own contract says means close the connection",
			ReferenceRule: "MODBUS Messaging on TCP/IP V1.0b puts only 'number of following bytes' in the Length field and caps the PDU at 253, " +
				"so the framing constraint is 2 <= Length <= 254; a bare function code with no data is a well-framed message with an illegal body",
			Consequence: "a peer that sends a one-byte PDU has its TLS session torn down instead of receiving an exception response. " +
				"Benign for a conforming client, but it hands an unauthenticated-at-the-application-layer peer a one-frame session kill, " +
				"and it means the gateway's session-churn counters move for what the spec calls an ordinary bad request",
		},
		{
			ID:          "DIV-FC06SPAN",
			Title:       "the product does not span-check FC 06, this reader does not either, and both are right only by arithmetic",
			Stricter:    "neither",
			ProductRule: "ParseWriteReq's FC 06 arm never calls checkSpan; only the FC 16 arm does",
			ReferenceRule: "decodeWriteSingle does not span-check either, because a single-register write at the maximum address 0xFFFF " +
				"occupies exactly the last register and 0xFFFF+1 == 0x10000 is the boundary the check permits",
			Consequence: "none today — the two agree on every input. The entry exists because the agreement is accidental: " +
				"it survives only while FC 06 writes exactly one register, and a future 'write single with a count' extension " +
				"would silently lose the bound on the product side. This is a documented latent hazard, not a divergence",
		},
		{
			ID:     "DEFECT-READRESP-1BYTE",
			Defect: true,
			Title:  "lexa-proto/mbap.ParseReadResp panics on a one-byte response PDU",
			// Not a divergence: a panic is nobody's design choice. It is
			// suppressed here so FuzzMBAPExchange can keep exploring past it,
			// and TestFUZZMBAP01_ParseReadRespPanicsOnAOneBytePDU reproduces it
			// in three lines. Delete both when lexa-proto is fixed.
			Stricter: "n/a",
			ProductRule: "pdu.go:168 short-circuits `len(pdu) != 2+wantBytes || int(pdu[1]) != wantBytes`, so pdu[1] is never read " +
				"when the length check already failed — but the *PDUError message built on the next line reads pdu[1] unconditionally, " +
				"and it is reached for exactly the inputs the first arm rejected, including len(pdu) == 1",
			ReferenceRule: "decodeReadResp requires len(pdu) >= 2 before touching the byte-count byte at all",
			Consequence: "an index-out-of-range panic in the gateway's Modbus CLIENT — the path that reads a southbound inverter. " +
				"It is not reachable through mbap.Client today, and the reason is worth stating: Decode's Length >= 3 floor " +
				"(the same strictness DIV-LEN2 records as a spec deviation) guarantees a PDU of at least two bytes, " +
				"and client.go's `// Decode guaranteed len(resp.PDU) >= 2` is the only place that dependency is written down. " +
				"So an undocumented-as-load-bearing strictness choice at the framing layer is the sole thing standing between " +
				"a hostile southbound device and a crash; relaxing Decode to match the spec, which DIV-LEN2 argues has merit, " +
				"would make this remotely reachable by any device that answers a read with a bare function code. " +
				"ParseReadResp is exported and its doc comment invites standalone callers, who get no such protection",
		},
		{
			ID:       "DIV-RESPSHAPE",
			Title:    "the product validates a read response only against the request it remembers; this reader validates it standalone",
			Stricter: "reference",
			ProductRule: "ParseReadResp takes the ReadReq and requires len(pdu) == 2+2*req.Count and pdu[1] == 2*req.Count, " +
				"so a response is judged against what was asked, not against itself",
			ReferenceRule: "decodeReadResp has no request in hand (a capture is framed before it is paired) and so checks only " +
				"internal consistency: byte count even, and len(pdu) == 2+byteCount",
			Consequence: "the reference ACCEPTS a self-consistent response carrying the wrong number of registers, which the product " +
				"correctly refuses. The differential must therefore never treat reference-accepts/product-refuses on a read " +
				"response as a finding on its own — Compare only compares standalone decodes, and request/response pairing is " +
				"checked separately by PairStream where the request is available to both sides",
		},
	}
}

// divergenceIndex is the set of IDs, for the lookup Compare does per finding.
func divergenceIndex() map[string]Divergence {
	m := make(map[string]Divergence)
	for _, d := range Divergences() {
		m[d.ID] = d
	}
	return m
}
