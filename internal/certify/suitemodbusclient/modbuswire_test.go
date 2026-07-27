package suitemodbusclient

// modbuswire_test.go proves the dissector's teeth on inputs a conformant peer
// would never produce. The parser is the foundation every assertion in this
// suite stands on: if it silently repaired a wrong MBAP length, every framing
// PASS in the bundle would be worthless.

import (
	"encoding/binary"
	"testing"
)

func TestParseADUsDecodesAWellFormedExchange(t *testing.T) {
	data := append(readReq(7, 1, 40000, 4), writeSingleReq(8, 1, 40230, 100)...)
	res := ParseADUs(data, nil, false)
	if len(res.Problems) != 0 {
		t.Fatalf("problems on a clean stream: %v", res.Problems)
	}
	if len(res.ADUs) != 2 {
		t.Fatalf("ADUs = %d, want 2", len(res.ADUs))
	}
	if res.TrailingBytes != 0 {
		t.Errorf("trailing = %d, want 0", res.TrailingBytes)
	}
	a := res.ADUs[0]
	if a.TxID != 7 || a.UnitID != 1 || a.FC != FCReadHoldingRegisters {
		t.Errorf("first ADU = %+v", a)
	}
	if start, qty, ok := a.ReadRequest(); !ok || start != 40000 || qty != 4 {
		t.Errorf("ReadRequest = %d,%d,%v", start, qty, ok)
	}
	if a.Start != 0 || a.End != len(readReq(7, 1, 40000, 4)) {
		t.Errorf("byte range = [%d,%d)", a.Start, a.End)
	}
	if b := res.ADUs[1]; b.Start != a.End {
		t.Errorf("second ADU starts at %d, want %d — messages must abut", b.Start, a.End)
	}
}

func TestParseADUsRefusesAWrongLengthField(t *testing.T) {
	// A response whose MBAP length promises two more bytes than are present.
	// The parser must NOT deliver it as a complete message: doing so is exactly
	// how a client with a framing bug would look conformant.
	data := readRsp(1, 1, []uint16{0x1234, 0x5678})
	binary.BigEndian.PutUint16(data[4:6], binary.BigEndian.Uint16(data[4:6])+2)
	res := ParseADUs(data, nil, false)
	if len(res.ADUs) != 0 {
		t.Fatalf("a message shorter than its own length field parsed as complete: %+v", res.ADUs)
	}
	if res.TrailingBytes != len(data) {
		t.Errorf("trailing = %d, want the whole %d-byte fragment", res.TrailingBytes, len(data))
	}
}

func TestParseADUsReportsAnOverLongLengthField(t *testing.T) {
	// A length field claiming more than a PDU can hold. There is no way to find
	// the next boundary, so the parser must stop and say so rather than guess.
	data := readReq(1, 1, 0, 2)
	binary.BigEndian.PutUint16(data[4:6], 900)
	res := ParseADUs(data, nil, false)
	if len(res.ADUs) != 0 {
		t.Fatalf("ADUs = %d, want 0", len(res.ADUs))
	}
	if len(res.Problems) == 0 {
		t.Fatal("an out-of-range MBAP length field produced no problem report")
	}
}

func TestParseADUsFlagsANonZeroProtocolID(t *testing.T) {
	data := readReq(1, 1, 0, 2)
	binary.BigEndian.PutUint16(data[2:4], 1)
	res := ParseADUs(data, nil, false)
	if len(res.ADUs) != 1 {
		t.Fatalf("ADUs = %d, want 1 (the message is still framed)", len(res.ADUs))
	}
	if len(res.Problems) == 0 {
		t.Error("protocol id 1 was accepted silently; MODBUS on TCP fixes it at 0")
	}
}

func TestParseADUsResynchronisesAMidStreamCapture(t *testing.T) {
	full := append(readReq(1, 1, 40000, 4), readReq(2, 1, 40002, 2)...)
	full = append(full, readReq(3, 1, 40004, 2)...)
	full = append(full, readReq(4, 1, 40006, 2)...)
	// The capture began five bytes into the first message.
	res := ParseADUs(full[5:], nil, true)
	if res.Discarded != len(readReq(1, 1, 40000, 4))-5 {
		t.Fatalf("discarded = %d, want the remainder of the truncated first message", res.Discarded)
	}
	if len(res.ADUs) != 3 {
		t.Fatalf("ADUs = %d, want the 3 complete messages after the partial one", len(res.ADUs))
	}
	if res.ADUs[0].TxID != 2 {
		t.Errorf("first recovered txid = %d, want 2", res.ADUs[0].TxID)
	}
	if len(res.Problems) == 0 {
		t.Error("resynchronisation discarded bytes without recording that it had")
	}
}

func TestParseADUsRefusesToInventABoundary(t *testing.T) {
	res := ParseADUs([]byte("this is not modbus at all, not even slightly"), nil, true)
	if len(res.ADUs) != 0 {
		t.Fatalf("found %d ADU(s) in non-Modbus bytes", len(res.ADUs))
	}
	if len(res.Problems) == 0 {
		t.Error("a stream with no ADU boundary produced no problem report")
	}
}

func TestExceptionDecode(t *testing.T) {
	res := ParseADUs(excRsp(9, 1, FCReadHoldingRegisters, 0x04), nil, false)
	if len(res.ADUs) != 1 {
		t.Fatalf("ADUs = %d", len(res.ADUs))
	}
	a := res.ADUs[0]
	if !a.IsException() {
		t.Fatal("exception response not recognised")
	}
	if code, ok := a.ExceptionCode(); !ok || code != 0x04 {
		t.Errorf("code = 0x%02x,%v", code, ok)
	}
	if ExceptionName(0x04) != "SERVER DEVICE FAILURE" {
		t.Errorf("name = %q", ExceptionName(0x04))
	}
}

func TestReadResponseRefusesAWrongByteCount(t *testing.T) {
	data := readRsp(1, 1, []uint16{1, 2, 3})
	data[8] = 4 // byte count says 4, six bytes follow
	res := ParseADUs(data, nil, false)
	if len(res.ADUs) != 1 {
		t.Fatalf("ADUs = %d", len(res.ADUs))
	}
	if _, regs, ok := res.ADUs[0].ReadResponse(); ok {
		t.Errorf("a response whose byte count disagrees with its payload decoded to %v", regs)
	}
}

func TestPairExchangesMatchesByTransactionID(t *testing.T) {
	reqs := ParseADUs(append(readReq(10, 1, 0, 2), readReq(11, 1, 2, 2)...), nil, false).ADUs
	// Responses arrive in the opposite order — a client that matched
	// positionally would pair them wrongly.
	rsps := ParseADUs(append(readRsp(11, 1, []uint16{9, 9}), readRsp(10, 1, []uint16{1, 1})...), nil, false).ADUs
	ex := pairExchanges(reqs, rsps)
	if len(ex) != 2 {
		t.Fatalf("exchanges = %d", len(ex))
	}
	for _, e := range ex {
		if !e.Matched() {
			t.Fatalf("txid %d unmatched", e.Request.TxID)
		}
		if e.Response.TxID != e.Request.TxID {
			t.Errorf("txid %d paired with response %d", e.Request.TxID, e.Response.TxID)
		}
	}
	_, regs, _ := ex[0].Response.ReadResponse()
	if regs[0] != 1 {
		t.Errorf("txid 10 got the wrong response payload %v", regs)
	}
}

func TestPairExchangesRefusesAMismatchedFunctionCode(t *testing.T) {
	reqs := ParseADUs(readReq(5, 1, 0, 2), nil, false).ADUs
	rsps := ParseADUs(writeMultiRsp(5, 1, 0, 2), nil, false).ADUs
	ex := pairExchanges(reqs, rsps)
	if ex[0].Matched() {
		t.Error("a read request was paired with a write response sharing its transaction id")
	}
}

func TestAnalyseTxIDsCountsAReuseWhileOutstanding(t *testing.T) {
	reqs := ParseADUs(append(readReq(3, 1, 0, 2), readReq(3, 1, 2, 2)...), nil, false).ADUs
	ex := pairExchanges(reqs, nil)
	rep := analyseTxIDs(ex, nil)
	if rep.Unmatched != 2 {
		t.Errorf("unmatched = %d, want 2", rep.Unmatched)
	}
	if rep.Repeats != 1 {
		t.Errorf("repeats = %d, want 1 (the second use of txid 3 while the first was outstanding)", rep.Repeats)
	}
}

func TestAnalyseTxIDsSurvivesWraparound(t *testing.T) {
	reqs := ParseADUs(append(readReq(65535, 1, 0, 2), readReq(0, 1, 2, 2)...), nil, false).ADUs
	rsps := ParseADUs(append(readRsp(65535, 1, []uint16{1, 1}), readRsp(0, 1, []uint16{2, 2})...), nil, false).ADUs
	rep := analyseTxIDs(pairExchanges(reqs, rsps), rsps)
	if rep.Increasing != 1 {
		t.Errorf("increasing = %d, want 1: 65535→0 is the wrap, not a regression", rep.Increasing)
	}
	if rep.Mismatched != 0 {
		t.Errorf("mismatched = %d, want 0", rep.Mismatched)
	}
}

func TestAnalyseTxIDsFlagsAResponseNobodyAskedFor(t *testing.T) {
	reqs := ParseADUs(readReq(1, 1, 0, 2), nil, false).ADUs
	rsps := ParseADUs(readRsp(99, 1, []uint16{1, 1}), nil, false).ADUs
	rep := analyseTxIDs(pairExchanges(reqs, rsps), rsps)
	if rep.Mismatched != 1 {
		t.Errorf("mismatched = %d, want 1", rep.Mismatched)
	}
}

func TestADUHexRoundTripsTheWholeMessage(t *testing.T) {
	raw := readReq(0x1234, 1, 0x9d3f, 0x007d)
	a := ParseADUs(raw, nil, false).ADUs[0]
	want := "12 34 00 00 00 06 01 03 9d 3f 00 7d"
	if a.Hex() != want {
		t.Errorf("Hex() = %q, want %q", a.Hex(), want)
	}
	if !a.LengthConsistent() {
		t.Error("a well-formed request was reported as length-inconsistent")
	}
}

func TestSegmentedADUCarriesEveryFrameItArrivedIn(t *testing.T) {
	s := newSunSpecServer(40000)
	sc := &script{stepMs: 5, msgs: []msg{
		{fromClient: true, payload: readReq(1, 1, 40000, 4)},
		{payload: readRsp(1, 1, s.read(40000, 4)), splitAt: 5},
	}}
	c := scriptConversation(t, sc)
	if len(c.Responses) != 1 {
		t.Fatalf("responses = %d", len(c.Responses))
	}
	r := c.Responses[0]
	if !r.Segmented() {
		t.Fatalf("a response delivered in two segments reports frames %v", r.Frames)
	}
	if len(r.Frames) != 2 {
		t.Errorf("frames = %v, want two", r.Frames)
	}
}
