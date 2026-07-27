package mbapref

// differential_test.go gives the four questions their teeth.
//
// Each subject below is lexa-proto/mbap with exactly one thing wrong, embedded
// so that everything not overridden is the real implementation. That
// construction is the point: it proves the question fires because of the
// specific defect and not because a hand-rolled stand-in was different in some
// other, uninteresting way.
//
// Every teeth case is paired with the same input run against [ProtoSubject],
// asserting silence. A check that fires on the healthy case as well is not a
// check, it is a fault light wired to the ignition.

import (
	"encoding/binary"
	"strings"
	"testing"

	"lexa-proto/mbap"
)

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// frame builds a well-formed ADU.
func frame(tid uint16, unit uint8, pdu ...byte) []byte {
	b := make([]byte, HeaderLen+len(pdu))
	binary.BigEndian.PutUint16(b[0:2], tid)
	binary.BigEndian.PutUint16(b[4:6], uint16(len(pdu)+1))
	b[6] = unit
	copy(b[HeaderLen:], pdu)
	return b
}

func readReqPDU(addr, count uint16) []byte {
	p := []byte{FCReadHolding, 0, 0, 0, 0}
	binary.BigEndian.PutUint16(p[1:3], addr)
	binary.BigEndian.PutUint16(p[3:5], count)
	return p
}

func writeSinglePDU(addr, val uint16) []byte {
	p := []byte{FCWriteSingle, 0, 0, 0, 0}
	binary.BigEndian.PutUint16(p[1:3], addr)
	binary.BigEndian.PutUint16(p[3:5], val)
	return p
}

func questions(fs []Finding) map[Question]int {
	m := map[Question]int{}
	for _, f := range fs {
		m[f.Question]++
	}
	return m
}

// fires asserts that q fired at least once and reports the details.
func fires(t *testing.T, fs []Finding, q Question) {
	t.Helper()
	if questions(fs)[q] == 0 {
		t.Fatalf("expected a %s finding, got %v", q, fs)
	}
	for _, f := range fs {
		if f.Question == q {
			t.Logf("  %s", f)
		}
	}
}

// silent asserts the healthy subject reports nothing on the same input. This
// is half of every teeth case and the half that is usually skipped.
func silent(t *testing.T, b []byte, dir Dir) {
	t.Helper()
	if fs := Compare(ProtoSubject(), b, dir); len(fs) != 0 {
		t.Fatalf("the real reader disagreed with the reference on healthy input: %v", fs)
	}
}

// ---------------------------------------------------------------------------
// the deliberately broken subjects
// ---------------------------------------------------------------------------

// offByOne reads the Length field as the PDU length instead of UnitID+PDU.
// This is the classic MBAP mistake and it is silent on a stream carrying one
// frame per segment — every frame parses, every field is right, and only the
// NEXT frame's boundary is wrong. It becomes visible only on coalesced
// traffic, which is exactly why the corpus is seeded from real captures.
type offByOne struct{ protoSubject }

func (offByOne) Name() string { return "off-by-one-length" }

func (offByOne) Frame(b []byte) Framing {
	out := Framing{Stop: StopClean, StopOff: len(b)}
	off := 0
	for off < len(b) {
		if len(b)-off < HeaderLen {
			out.Stop, out.StopOff, out.Reason = StopTruncated, off, "short header"
			return out
		}
		n := int(binary.BigEndian.Uint16(b[off+4 : off+6])) // the bug: no -1
		end := off + HeaderLen + n
		if end > len(b) {
			out.Stop, out.StopOff, out.Reason = StopTruncated, off, "short body"
			return out
		}
		out.Frames = append(out.Frames, Frame{
			TID: binary.BigEndian.Uint16(b[off : off+2]), PID: 0,
			Length: uint16(n), Unit: b[off+6], PDU: b[off+HeaderLen : end],
			Off: off, End: end,
		})
		off = end
	}
	return out
}

// resyncing hunts for the next plausible header after a framing violation
// instead of closing the connection. lexa-proto's contract forbids this in so
// many words; the differential is what keeps that contract from being a
// comment.
type resyncing struct{ protoSubject }

func (resyncing) Name() string { return "resynchronising" }

func (r resyncing) Frame(b []byte) Framing {
	out := Framing{Stop: StopClean, StopOff: len(b)}
	off := 0
	for off < len(b) {
		f := Reference(b[off:])
		for i := range f.Frames {
			f.Frames[i].Off += off
			f.Frames[i].End += off
		}
		out.Frames = append(out.Frames, f.Frames...)
		if f.Stop == StopClean {
			return out
		}
		if f.Stop == StopTruncated {
			out.Stop, out.StopOff, out.Reason = StopTruncated, off+f.StopOff, f.Reason
			return out
		}
		off += f.StopOff + 1 // the bug: skip a byte and keep looking
	}
	return out
}

// trimming drops the last byte of every PDU, standing in for any decoder that
// "repairs" what it thinks is padding. A repairing decoder hands the layer
// above it a message the peer never sent.
type trimming struct{ protoSubject }

func (trimming) Name() string { return "pdu-trimming" }

func (t trimming) Frame(b []byte) Framing {
	f := Reference(b)
	for i := range f.Frames {
		if n := len(f.Frames[i].PDU); n > 1 {
			f.Frames[i].PDU = f.Frames[i].PDU[:n-1]
		}
	}
	return f
}

// littleEndianTID reads the transaction identifier in the wrong byte order.
// Every frame still parses and every boundary is still right; only the value
// is wrong, which is the shape a semantics question exists for.
type littleEndianTID struct{ protoSubject }

func (littleEndianTID) Name() string { return "little-endian-tid" }

func (littleEndianTID) Frame(b []byte) Framing {
	f := Reference(b)
	for i := range f.Frames {
		f.Frames[i].TID = binary.LittleEndian.Uint16(b[f.Frames[i].Off : f.Frames[i].Off+2])
	}
	return f
}

// badEncoder decodes correctly but re-serialises with a nonzero protocol id.
// It isolates IDENTITY: nothing else can fire, because nothing else is wrong.
type badEncoder struct{ protoSubject }

func (badEncoder) Name() string { return "bad-encoder" }

func (badEncoder) Encode(f Frame) ([]byte, error) {
	b, err := mbap.Encode(mbap.ADU{
		Header: mbap.Header{TID: f.TID, Length: f.Length, UnitID: f.Unit}, PDU: f.PDU,
	})
	if err != nil {
		return nil, err
	}
	b[3] = 1 // the bug
	return b, nil
}

// zeroCountReader accepts a read request for zero registers. A zero-register
// read is not merely useless: on a server that answers it, the response is a
// two-byte PDU with byte count 0, and a client that then indexes the value
// slice reads whatever was there before.
type zeroCountReader struct{ protoSubject }

func (zeroCountReader) Name() string { return "zero-count-accepting" }

func (z zeroCountReader) ParseRequest(pdu []byte) (PDU, error) {
	if len(pdu) == 5 && (pdu[0] == FCReadHolding || pdu[0] == FCReadInput) {
		return PDU{Kind: KindReadReq, FC: pdu[0],
			Addr:  binary.BigEndian.Uint16(pdu[1:3]),
			Count: binary.BigEndian.Uint16(pdu[3:5])}, nil
	}
	return z.protoSubject.ParseRequest(pdu)
}

// offByOneRegister decodes a write to the register after the one on the wire.
// It is the smallest possible version of the defect class this whole layer
// exists for: 704.WMaxLimPct and its neighbours are one register apart.
type offByOneRegister struct{ protoSubject }

func (offByOneRegister) Name() string { return "off-by-one-register" }

func (o offByOneRegister) ParseRequest(pdu []byte) (PDU, error) {
	d, err := o.protoSubject.ParseRequest(pdu)
	if err == nil && d.Kind == KindWriteReq {
		d.Addr++
	}
	return d, err
}

// sloppyResponse accepts a read response carrying any number of registers,
// regardless of what was asked for.
type sloppyResponse struct{ protoSubject }

func (sloppyResponse) Name() string { return "sloppy-read-response" }

func (sloppyResponse) ParseReadResponse(req PDU, pdu []byte) ([]uint16, error) {
	d := DecodePDU(pdu, FromServer)
	if d.Kind != KindReadResp {
		return nil, &mbap.PDUError{Reason: "not a read response"}
	}
	return d.Values, nil // the bug: req.Count is never consulted
}

// ---------------------------------------------------------------------------
// teeth
// ---------------------------------------------------------------------------

func TestTeeth_FramingCatchesAnOffByOneLengthField(t *testing.T) {
	// Two frames back to back. One frame alone would NOT catch this: the
	// first frame's own fields are all correct and only its END is wrong, so
	// the error is invisible until something has to start after it.
	b := append(frame(1, 1, readReqPDU(40000, 2)...), frame(2, 1, readReqPDU(40002, 2)...)...)
	silent(t, b, FromClient)
	fires(t, Compare(offByOne{}, b, FromClient), QFraming)
}

func TestTeeth_FramingIsSilentOnASingleFrameEvenForTheOffByOneReader(t *testing.T) {
	// The honest converse, recorded so nobody strengthens the corpus by
	// accident and then wonders why it stopped finding this: with one frame
	// in the buffer the off-by-one reader is caught only by the TRUNCATION
	// class, not by a boundary mismatch, because there is no second frame to
	// misplace. This is the argument for seeding from coalesced real traffic
	// rather than hand-written single-frame vectors.
	b := frame(1, 1, readReqPDU(40000, 2)...)
	silent(t, b, FromClient)
	fs := Compare(offByOne{}, b, FromClient)
	if questions(fs)[QFraming] != 0 {
		t.Fatalf("did not expect a boundary finding from a single-frame buffer, got %v", fs)
	}
	if len(fs) == 0 {
		t.Fatal("expected the stop-class difference to be caught even so")
	}
	t.Logf("caught as: %v", fs)
}

func TestTeeth_AcceptanceCatchesAResynchronisingReader(t *testing.T) {
	// A good frame, then a byte of garbage, then a good frame. The reference
	// and the product both stop at the garbage; the resyncing reader steps
	// over it and reports a frame the product never saw — which, on the
	// gateway, would be a register write nobody authorised the session for.
	b := frame(1, 1, readReqPDU(40000, 2)...)
	b = append(b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff)
	b = append(b, frame(2, 1, writeSinglePDU(40010, 50)...)...)

	if fs := Unenumerated(Compare(ProtoSubject(), b, FromClient)); len(fs) != 0 {
		t.Fatalf("the real reader disagreed with the reference: %v", fs)
	}
	fires(t, Compare(resyncing{}, b, FromClient), QAcceptance)
}

func TestTeeth_IdentityCatchesAnEncoderThatChangesTheBytes(t *testing.T) {
	b := frame(7, 3, readReqPDU(40000, 4)...)
	silent(t, b, FromClient)
	fs := Compare(badEncoder{}, b, FromClient)
	fires(t, fs, QIdentity)
	// Isolation: nothing else may fire, because nothing else is wrong.
	for _, f := range fs {
		if f.Question != QIdentity {
			t.Fatalf("bad-encoder should fire IDENTITY alone, also got %v", f)
		}
	}
}

func TestTeeth_IdentityAndSemanticsBothCatchARepairingDecoder(t *testing.T) {
	// A decoder that trims the PDU is wrong in two ways at once and both
	// questions should say so: the message it passed on is not the message
	// that arrived (SEMANTICS) and it does not re-encode to what was received
	// (IDENTITY). Asserting the union rather than picking one keeps a future
	// simplification from quietly deleting whichever arm someone thought was
	// redundant.
	b := frame(9, 2, writeSinglePDU(40010, 1234)...)
	silent(t, b, FromClient)
	fs := Compare(trimming{}, b, FromClient)
	fires(t, fs, QIdentity)
	fires(t, fs, QSemantics)
}

func TestTeeth_SemanticsCatchesAByteOrderError(t *testing.T) {
	// TID 0x0102 little-endian reads as 0x0201. A TID error is not cosmetic:
	// it is how a response gets matched to the wrong request.
	b := frame(0x0102, 1, readReqPDU(40000, 2)...)
	silent(t, b, FromClient)
	fires(t, Compare(littleEndianTID{}, b, FromClient), QSemantics)
}

func TestTeeth_AcceptanceCatchesAZeroRegisterRead(t *testing.T) {
	b := frame(1, 1, readReqPDU(40000, 0)...)
	// The reference refuses the PDU; the real reader refuses it too, so the
	// healthy case is agreement-on-refusal and reports nothing.
	silent(t, b, FromClient)
	fires(t, Compare(zeroCountReader{}, b, FromClient), QAcceptance)
}

func TestTeeth_SemanticsNamesTheRegisterThatMoved(t *testing.T) {
	b := frame(1, 1, writeSinglePDU(40233, 80)...)
	silent(t, b, FromClient)
	fs := Compare(offByOneRegister{}, b, FromClient)
	fires(t, fs, QSemantics)
	// The finding must name the address, not merely report inequality. A
	// differential whose output is "they differ" costs the reader the whole
	// investigation.
	var named bool
	for _, f := range fs {
		if strings.Contains(f.Detail, "40233") && strings.Contains(f.Detail, "40234") {
			named = true
		}
	}
	if !named {
		t.Fatalf("the finding must name both addresses; got %v", fs)
	}
}

func TestTeeth_ExchangeCatchesAResponseAcceptedAgainstTheWrongRequest(t *testing.T) {
	// Ask for four registers, answer with one. Both are well formed; only the
	// pairing is wrong, and only a reader holding the request can see it.
	req := frame(1, 1, readReqPDU(40000, 4)...)
	resp := frame(1, 1, FCReadHolding, 2, 0x00, 0x7b)

	exs, fault := Pair(req, resp)
	if fault != nil {
		t.Fatalf("pairing: %v", fault)
	}
	if len(exs) != 1 {
		t.Fatalf("want 1 exchange, got %d", len(exs))
	}
	if fs := CompareExchange(ProtoSubject(), exs[0]); len(fs) != 0 {
		t.Fatalf("the real reader must refuse this response, as the reference does; got %v", fs)
	}
	fires(t, CompareExchange(sloppyResponse{}, exs[0]), QAcceptance)
}

func TestTeeth_ExchangeIsSilentOnAMatchingResponse(t *testing.T) {
	req := frame(1, 1, readReqPDU(40000, 2)...)
	resp := frame(1, 1, FCReadHolding, 4, 0x00, 0x7b, 0x01, 0x00)
	exs, fault := Pair(req, resp)
	if fault != nil {
		t.Fatalf("pairing: %v", fault)
	}
	for _, s := range []Subject{ProtoSubject(), sloppyResponse{}} {
		if fs := CompareExchange(s, exs[0]); len(fs) != 0 {
			t.Fatalf("%s reported a finding on a matching exchange: %v", s.Name(), fs)
		}
	}
}

func TestPair_RefusesToGuessWhenTransactionIdsDoNotAlternate(t *testing.T) {
	req := append(frame(1, 1, readReqPDU(0, 1)...), frame(2, 1, readReqPDU(1, 1)...)...)
	resp := append(frame(1, 1, FCReadHolding, 2, 0, 1), frame(99, 1, FCReadHolding, 2, 0, 2)...)

	exs, fault := Pair(req, resp)
	if fault == nil {
		t.Fatal("pairing must refuse when tids do not match, not guess")
	}
	if len(exs) != 1 {
		t.Fatalf("the exchanges before the fault are still usable; got %d", len(exs))
	}
	t.Logf("refused as: %v", fault)
}

func TestPair_AnUnansweredTrailingRequestIsNotAFault(t *testing.T) {
	req := append(frame(1, 1, readReqPDU(0, 1)...), frame(2, 1, readReqPDU(1, 1)...)...)
	resp := frame(1, 1, FCReadHolding, 2, 0, 1)
	exs, fault := Pair(req, resp)
	if fault != nil {
		t.Fatalf("a capture that ends between a request and its response is ordinary: %v", fault)
	}
	if len(exs) != 1 {
		t.Fatalf("want 1 exchange, got %d", len(exs))
	}
}

// ---------------------------------------------------------------------------
// the enumerated divergence, exercised rather than merely written down
// ---------------------------------------------------------------------------

func TestDIVLEN2_TheOneByteePDUIsAnEnumeratedDivergenceAndIsFilteredOut(t *testing.T) {
	// Length 2: UnitID plus a bare function code. The reference frames it and
	// judges it at the PDU layer; the product calls it a framing error and,
	// per its own contract, the caller closes the connection.
	b := []byte{0x00, 0x01, 0x00, 0x00, 0x00, 0x02, 0x01, FCReadHolding}

	refFraming := Reference(b)
	if len(refFraming.Frames) != 1 || refFraming.Stop != StopClean {
		t.Fatalf("the reference must frame a length-2 adu: %+v", refFraming)
	}
	got := ProtoSubject().Frame(b)
	if got.Stop != StopViolation {
		t.Fatalf("the product must refuse a length-2 adu at the framing layer: %+v", got)
	}

	fs := Compare(ProtoSubject(), b, FromClient)
	if len(fs) != 1 {
		t.Fatalf("want exactly one finding, got %v", fs)
	}
	if fs[0].Divergence != "DIV-LEN2" {
		t.Fatalf("the difference must be attributed to DIV-LEN2, got %q: %v", fs[0].Divergence, fs[0])
	}
	if u := Unenumerated(fs); len(u) != 0 {
		t.Fatalf("an enumerated divergence must not survive filtering: %v", u)
	}
	t.Logf("attributed as: %v", fs[0])
}

func TestDivergences_EveryEntryStatesAConsequence(t *testing.T) {
	// The enumeration is only a defence against noise while each entry
	// justifies itself. An entry with no stated consequence is an excuse, and
	// this test is what stops one being added.
	ds := Divergences()
	if len(ds) == 0 {
		t.Fatal("no divergences enumerated at all")
	}
	seen := map[string]bool{}
	for _, d := range ds {
		if seen[d.ID] {
			t.Fatalf("duplicate divergence id %q", d.ID)
		}
		seen[d.ID] = true
		for name, v := range map[string]string{
			"Title": d.Title, "ProductRule": d.ProductRule,
			"ReferenceRule": d.ReferenceRule, "Consequence": d.Consequence, "Stricter": d.Stricter,
		} {
			if strings.TrimSpace(v) == "" {
				t.Errorf("%s: %s is empty", d.ID, name)
			}
		}
	}
	// Every ID Compare can attribute must exist in the table, or a finding
	// would be filtered out by a label that means nothing.
	idx := divergenceIndex()
	for _, id := range []string{"DIV-LEN2"} {
		if _, ok := idx[id]; !ok {
			t.Errorf("Compare attributes %s but the table does not define it", id)
		}
	}
}

// ---------------------------------------------------------------------------
// the differential/traffic split
// ---------------------------------------------------------------------------

func TestClass_ADeviceLevelViolationIsTrafficAndNotADivergence(t *testing.T) {
	// A request for function 0x30 answered by an exception for function 0x03.
	// Both readers read those bytes identically and correctly; the thing at
	// fault is the imaginary device. Reported, but not as a divergence — a
	// fuzz oracle that treated it as one would fail within a second on input
	// it invented itself, which is exactly what FuzzMBAPExchange did before
	// the split existed. testdata/fuzz/FuzzMBAPExchange holds that input as a
	// regression seed.
	req := frame(1, 1, 0x30, 0x30, 0x30, 0x30, 0x30)
	resp := frame(1, 1, FCReadHolding|ExceptionBit, 0x30)

	fs, fault := CompareStreams(ProtoSubject(), req, resp)
	if fault != nil {
		t.Fatalf("pairing: %v", fault)
	}
	if len(Traffic(fs)) == 0 {
		t.Fatalf("the mismatched exception must still be reported: %v", fs)
	}
	if d := Differential(fs); len(d) != 0 {
		t.Fatalf("it must not be reported as a reader disagreement: %v", d)
	}
	t.Logf("reported as: %v", Traffic(fs)[0])
}

func TestClass_ADifferentialFindingSurvivesTheTrafficFilter(t *testing.T) {
	// The converse: the split must not be a way for real divergences to
	// escape. A reader disagreement is Differential even though the input is
	// equally synthetic.
	b := frame(1, 1, readReqPDU(40000, 0)...)
	fs := Compare(zeroCountReader{}, b, FromClient)
	if len(Differential(fs)) == 0 {
		t.Fatalf("a reader disagreement must survive Differential: %v", fs)
	}
	if len(Traffic(fs)) != 0 {
		t.Fatalf("and must not be reclassified as traffic: %v", Traffic(fs))
	}
}

// ---------------------------------------------------------------------------
// confirmed defects found by this layer
// ---------------------------------------------------------------------------

// TestFUZZMBAP01_ParseReadRespPanicsOnAOneBytePDU is the reproducer for a
// defect FuzzMBAPExchange found within three minutes of first being run
// (corpus entry testdata/fuzz/FuzzMBAPExchange/d76428f65499e2e7, minimised to
// the three lines below).
//
// lexa-proto/mbap/pdu.go:168 reads:
//
//	if len(pdu) != 2+wantBytes || int(pdu[1]) != wantBytes {
//	        return nil, &PDUError{
//	                Reason: fmt.Sprintf("read response shape (len %d, byte count %d) ...",
//	                        len(pdu), pdu[1], req.Count),
//
// The CONDITION is safe: `||` short-circuits, so `int(pdu[1])` is never
// evaluated when the length check has already failed. The MESSAGE is not. It
// reads pdu[1] unconditionally, and it is built exactly when the first arm
// rejected the input — which includes a one-byte PDU. The bounds check and the
// out-of-bounds read are four lines apart, which is why every reviewer of that
// function has read the guard and stopped.
//
// The package's own strictness table, TestParseReadRespStrict, covers "empty",
// "wrong fc", "exception pdu", "byte count lies", "short body" and "trailing
// bytes" — six hand-written cases, none of them length 1. That is the ordinary
// failure of a hand-written table: it enumerates the shapes its author had
// names for.
//
// # Reach
//
// Not reachable through mbap.Client today. Client.Do obtains the PDU from
// Decode, whose Length >= 3 floor guarantees at least two PDU bytes, and
// client.go says so in a comment: "// Decode guaranteed len(resp.PDU) >= 2".
// That comment is the only record anywhere that the floor is load-bearing —
// and DIV-LEN2 in this package argues, from the spec, that the floor is a
// deviation worth reconsidering. Relaxing it without noticing this would turn
// a crash-free gateway into one that a southbound inverter can kill by
// answering a register read with a bare function code.
//
// ParseReadResp is exported, and its doc comment explicitly contemplates
// callers outside the Client ("standalone callers see a *PDUError for any
// shape mismatch"). Those callers get no floor at all.
//
// Delete this test and DEFECT-READRESP-1BYTE together when pdu.go is fixed.
func TestFUZZMBAP01_ParseReadRespPanicsOnAOneBytePDU(t *testing.T) {
	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("mbap.ParseReadResp no longer panics on a one-byte pdu — the defect is fixed. " +
				"Delete this test and the DEFECT-READRESP-1BYTE entry in divergence.go.")
		}
		t.Logf("reproduced: %v", r)
	}()
	_, _ = mbap.ParseReadResp(mbap.ReadReq{FC: mbap.FCReadHolding, Addr: 40000, Count: 2}, []byte{0x03})
}

func TestFUZZMBAP01_TheDifferentialSurvivesTheSubjectPanicking(t *testing.T) {
	// The same input through the differential: it must report the panic rather
	// than propagate it, or one defect ends the exploration of every other.
	req := frame(1, 1, readReqPDU(0x3030, 48)...)
	resp := frame(1, 1, FCReadHolding)

	fs, fault := CompareStreams(ProtoSubject(), req, resp)
	if fault != nil {
		t.Fatalf("pairing: %v", fault)
	}
	var found bool
	for _, f := range fs {
		if f.Divergence == "DEFECT-READRESP-1BYTE" {
			found = true
			t.Logf("reported as: %v", f)
		}
	}
	if !found {
		t.Fatalf("the panic must be reported and attributed, got %v", fs)
	}
	if d := Differential(fs); len(d) != 0 {
		t.Fatalf("and suppressed from the fuzz oracle, got %v", d)
	}
}

func TestDefects_AreListedSeparatelyFromDivergences(t *testing.T) {
	// A suppressed defect is a debt. It must be enumerable on its own so a
	// report can print it, and it must not be mistakable for a design choice.
	ds := Defects()
	if len(ds) == 0 {
		t.Skip("no suppressed defects — nothing to owe")
	}
	for _, d := range ds {
		if !d.Defect {
			t.Fatalf("%s came back from Defects() without the flag", d.ID)
		}
		t.Logf("OUTSTANDING: %s\n    %s", d, d.Consequence)
	}
}
