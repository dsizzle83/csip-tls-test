package suitemodbusserver

// unit_test.go proves the decision logic underneath the checks, on synthetic
// inputs, with no sockets involved: the transcription's self-consistency, the
// type rules, the PDU codec, the discovery walk, the profile lists, the value
// sweep, and the MBAP re-parse the citation phase depends on.
//
// These are the parts a bench run cannot exercise negatively. A live DUT will
// never hand the suite a protocol identifier of 7 or a model header that walks
// off the end of the address space, and those are precisely the inputs that
// decide whether an assertion is evidence or a guess.

import (
	"encoding/binary"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"csip-tls-test/internal/certify"
	"lexa-proto/mbap"
)

// --- the transcription -----------------------------------------------------

// TestTranscriptionLengthsMatchTheirPointTables is the guard on the whole
// transcription: a mistyped offset in models.go would otherwise be reported as
// a DUT defect. (The same arithmetic runs at package init and panics; this test
// states it as an assertion so a failure names the model.)
func TestTranscriptionLengthsMatchTheirPointTables(t *testing.T) {
	for id, m := range Models {
		if m.L == 0 {
			continue
		}
		if got := m.span() - 2; got != m.L {
			t.Errorf("model %d: the point table spans %d data registers, the model declares L=%d", id, got, m.L)
		}
	}
	// The lengths the specifications state, spelled out so a change to the
	// transcription has to be deliberate.
	for id, want := range map[uint16]int{1: 66, 701: 153, 702: 50, 703: 17, 704: 65, 713: 7} {
		if Models[id].L != want {
			t.Errorf("model %d declares L=%d, the specification says %d", id, Models[id].L, want)
		}
	}
}

func TestTranscribedPointsDoNotOverlap(t *testing.T) {
	for id, m := range Models {
		used := map[int]string{}
		for _, p := range m.Points {
			// A sync group's members are transcribed as members only, so no two
			// points may ever claim the same register.
			for off := p.Off; off < p.End(); off++ {
				if prev, taken := used[off]; taken {
					t.Errorf("model %d: register offset %d is claimed by both %s and %s", id, off, prev, p.Name)
				}
				used[off] = p.Name
			}
		}
	}
}

func TestNotImplementedSentinels(t *testing.T) {
	cases := []struct {
		typ  PointType
		regs []uint16
		want bool
	}{
		{TypeInt16, []uint16{0x8000}, true},
		{TypeInt16, []uint16{0x8001}, false},
		{TypeSunSSF, []uint16{0x8000}, true},
		{TypeSunSSF, []uint16{0xFFFF}, false}, // -1, a perfectly ordinary scale factor
		{TypeUint16, []uint16{0xFFFF}, true},
		{TypeUint16, []uint16{0xFFFE}, false},
		{TypeEnum16, []uint16{0xFFFF}, true},
		{TypeUint32, []uint16{0xFFFF, 0xFFFF}, true},
		{TypeUint32, []uint16{0xFFFF, 0xFFFE}, false},
		{TypeInt32, []uint16{0x8000, 0x0000}, true},
		{TypeUint64, []uint16{0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF}, true},
		{TypeUint64, []uint16{0xFFFF, 0xFFFF, 0xFFFF, 0}, false},
		{TypePad, []uint16{0x8000}, true},
		{TypeString, []uint16{0, 0, 0}, true},
		{TypeString, []uint16{0, 0x4142, 0}, false},
		// A truncated read must never be judged.
		{TypeUint32, []uint16{0xFFFF}, false},
	}
	for _, c := range cases {
		if got := c.typ.NotImplemented(c.regs); got != c.want {
			t.Errorf("%s.NotImplemented(%04x) = %v, want %v", c.typ, c.regs, got, c.want)
		}
	}
}

func TestSunSSFRangeIsTheOuterBoundOfTheScaleFactorTest(t *testing.T) {
	for _, v := range []int16{-10, -1, 0, 5, 10} {
		if !TypeSunSSF.InDatatypeRange([]uint16{uint16(v)}) {
			t.Errorf("scale factor %d rejected", v)
		}
	}
	for _, v := range []int16{-11, 11, 100} {
		if TypeSunSSF.InDatatypeRange([]uint16{uint16(v)}) {
			t.Errorf("scale factor %d accepted", v)
		}
	}
	// The not-implemented sentinel is legal even though it is outside -10..10.
	if !TypeSunSSF.InDatatypeRange([]uint16{0x8000}) {
		t.Error("the not-implemented scale factor was rejected as out of range")
	}
}

func TestBitfieldTopBitIsReserved(t *testing.T) {
	if TypeBitfield16.InDatatypeRange([]uint16{0x8001}) {
		t.Error("a bitfield16 with its top bit set was accepted")
	}
	if !TypeBitfield16.InDatatypeRange([]uint16{0x7FFF}) {
		t.Error("a full-but-legal bitfield16 was rejected")
	}
}

func TestExpectedLenComputesTheVariableGeometryOf714(t *testing.T) {
	if got, ok := expectedLen(714, map[string]uint16{"NPrt": 0}); !ok || got != 18 {
		t.Errorf("714 with no ports: got %d ok=%v, want 18", got, ok)
	}
	if got, ok := expectedLen(714, map[string]uint16{"NPrt": 2}); !ok || got != 18+66 {
		t.Errorf("714 with two ports: got %d ok=%v, want %d", got, ok, 18+66)
	}
	if _, ok := expectedLen(714, nil); ok {
		t.Error("714's length was predicted without its port count")
	}
	if _, ok := expectedLen(705, nil); ok {
		t.Error("a curve model's length was predicted")
	}
}

// --- the PDU codec ---------------------------------------------------------

func TestReadRequestAndResponseRoundTrip(t *testing.T) {
	req, err := buildReadReq(fcReadHolding, 40000, 3)
	if err != nil {
		t.Fatal(err)
	}
	want := []byte{0x03, 0x9C, 0x40, 0x00, 0x03}
	if !reflect.DeepEqual(req, want) {
		t.Fatalf("request = % x, want % x", req, want)
	}
	resp := []byte{0x03, 6, 0x00, 0x01, 0x00, 0x02, 0x00, 0x03}
	regs, err := parseReadResp(fcReadHolding, 3, resp)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(regs, []uint16{1, 2, 3}) {
		t.Fatalf("registers = %v", regs)
	}
}

func TestReadResponseByteCountIsChecked(t *testing.T) {
	// The byte-count field disagreeing with the requested quantity is the kind
	// of defect a checker built on the DUT's own codec could not see.
	if _, err := parseReadResp(fcReadHolding, 3, []byte{0x03, 4, 0, 1, 0, 2}); err == nil {
		t.Fatal("a byte count that does not match the request was accepted")
	}
	if _, err := parseReadResp(fcReadHolding, 1, []byte{0x83, 0x02}); err == nil {
		t.Fatal("an exception pdu was parsed as a read response")
	}
}

func TestReadRequestRefusesTheModbusQuantityCeiling(t *testing.T) {
	if _, err := buildReadReq(fcReadHolding, 0, 126); err == nil {
		t.Fatal("a 126-register read was built")
	}
	if _, err := buildReadReq(fcReadHolding, 0, 0); err == nil {
		t.Fatal("a zero-register read was built")
	}
}

func TestWriteEchoesAreValidated(t *testing.T) {
	if err := parseWriteSingleResp(10, 7, buildWriteSingleReq(10, 7)); err != nil {
		t.Fatalf("a correct FC 6 echo was rejected: %v", err)
	}
	if err := parseWriteSingleResp(10, 7, buildWriteSingleReq(10, 8)); err == nil {
		t.Fatal("an FC 6 echo with the wrong value was accepted")
	}
	req, err := buildWriteMultipleReq(20, []uint16{1, 2})
	if err != nil {
		t.Fatal(err)
	}
	if req[5] != 4 {
		t.Errorf("FC 16 byte count = %d, want 4", req[5])
	}
	if err := parseWriteMultipleResp(20, 2, []byte{0x10, 0x00, 0x14, 0x00, 0x03}); err == nil {
		t.Fatal("an FC 16 echo with the wrong quantity was accepted")
	}
}

// --- the discovery walk ----------------------------------------------------

// fakeRegs is an in-memory register file the walk can run against without a
// socket, via a client whose conn is a pipe to it. Rather than build that
// plumbing, the walk's arithmetic is tested through its own pure parts.
func TestChainHelpers(t *testing.T) {
	ch := &chain{Base: 40000, EndSeen: true, EndAddr: 40300}
	ch.Models = []modelRef{
		{ID: 1, Addr: 40002, L: 66, DataAddr: 40004},
		{ID: 701, Addr: 40070, L: 153, DataAddr: 40072},
		{ID: 1, Addr: 40225, L: 66, DataAddr: 40227},
	}
	if got := ch.IDs(); !reflect.DeepEqual(got, []uint16{1, 701}) {
		t.Errorf("IDs = %v, want [1 701] (sorted and de-duplicated)", got)
	}
	m, ok := ch.Model(701)
	if !ok || m.Addr != 40070 || m.span() != 155 {
		t.Errorf("Model(701) = %+v ok=%v", m, ok)
	}
	if !ch.PresentSet()[1] || ch.PresentSet()[999] {
		t.Error("PresentSet is wrong")
	}
}

func TestBaseProbeRecognisesTheSunSpecIdentifier(t *testing.T) {
	good := baseProbe{Base: 40000, Regs: []uint16{0x5375, 0x6E53}}
	if !good.Found() {
		t.Error("the SunS marker was not recognised")
	}
	// A device answering with the marker's bytes swapped is not a SunSpec
	// device, and the walk must not adopt it.
	bad := baseProbe{Base: 40000, Regs: []uint16{0x6E53, 0x5375}}
	if bad.Found() {
		t.Error("a byte-swapped marker was accepted")
	}
	if !contains(baseProbe{Base: 0, Err: &excError{FC: 3, Code: mbap.ExIllegalAddress}}.String(), "0x02") {
		t.Error("a probe's exception is not rendered")
	}
}

// --- the IEEE 1547 profile lists -------------------------------------------

func TestMissingModelsSeparatesRequiredFromConditional(t *testing.T) {
	present := map[uint16]bool{1: true, 701: true, 702: true, 704: true}
	hard, cond := missingModels(present, ProfileModels)
	want := []uint16{703, 705, 706, 707, 708, 709, 710, 711, 712}
	if !reflect.DeepEqual(hard, want) {
		t.Errorf("hard-missing = %v, want %v", hard, want)
	}
	if !reflect.DeepEqual(cond, []uint16{713}) {
		t.Errorf("conditionally-missing = %v, want [713] (storage capacity is optional without storage)", cond)
	}
}

func TestModel701VoltagePointsAreJudgedAgainstTheDevicesACType(t *testing.T) {
	// A single-phase device legitimately implements neither VL2 nor VL3.
	for _, name := range []string{"VL2", "VL3", "VL2L3", "VL3L1"} {
		need, excuse := pointRequired(701, name, 0, true, false)
		if need {
			t.Errorf("%s required of a single-phase device", name)
		}
		if excuse == "" {
			t.Errorf("%s was excused without a reason", name)
		}
	}
	// A three-phase device must implement all of them.
	for _, name := range []string{"VL1", "VL2", "VL3", "VL1L2", "VL2L3", "VL3L1"} {
		if need, _ := pointRequired(701, name, 2, true, false); !need {
			t.Errorf("%s not required of a three-phase device", name)
		}
	}
	// When the topology is unknown the strict reading applies.
	if need, _ := pointRequired(701, "VL3", 0, false, false); !need {
		t.Error("a voltage point was excused on an unknown topology")
	}
	// Points outside the profile's list are not required at all.
	if need, _ := pointRequired(701, "TmpCab", 2, true, false); need {
		t.Error("a point the profile does not list was required")
	}
}

// TestModel702ChargeRatingsAreJudgedAgainstDeclaredStorage pins the
// storageConditional interpretation in BOTH directions, because only the pair
// is worth anything: a qualifier that excuses a point unconditionally is
// indistinguishable from deleting the row.
//
// The reason this exists at all is a real, dated verdict flip. The bench's
// advanced solar sim used to leave WChaRteMaxRtg at the Go zero value, MOD-4
// read it as implemented, and 702 passed; harness 07178d1 replaced the zeros
// with the SunSpec not-implemented sentinel — the correct declaration for a PV
// inverter with no battery — and without this qualifier the same conformant
// bench would newly FAIL. See storageConditional's comment.
func TestModel702ChargeRatingsAreJudgedAgainstDeclaredStorage(t *testing.T) {
	charge := []string{"WChaRteMaxRtg", "VAChaRteMaxRtg"}

	// No model 713: the DUT declares no storage, so a charge-rate rating is a
	// rating of an axis it does not have.
	for _, name := range charge {
		need, excuse := pointRequired(702, name, 0, true, false)
		if need {
			t.Errorf("%s was required of a DUT that serves no model 713; a PV inverter honestly "+
				"declaring it does not implement a charge-rate rating would FAIL MOD-4", name)
		}
		if !strings.Contains(excuse, "INTERPRETATION") {
			t.Errorf("%s was excused by reason %q, which does not tell the reader that the qualifier "+
				"is this harness's reading rather than the profile's printed text", name, excuse)
		}
		if !strings.Contains(excuse, "713") {
			t.Errorf("%s's excuse %q does not name the condition that would revoke it", name, excuse)
		}
	}

	// Model 713 present: the DUT declares storage and is held to the ratings in
	// full. This is the half that keeps the qualifier from being a hole — the
	// bench's battery packs serve 713 and declare real charge ratings.
	for _, name := range charge {
		if need, excuse := pointRequired(702, name, 0, true, true); !need {
			t.Errorf("%s was excused for a DUT that DOES serve model 713 (%q); a device declaring "+
				"storage must declare what it can charge at", name, excuse)
		}
	}

	// Nothing else in 702 moves with storage. WMaxRtg in particular is a
	// discharge/generation rating every DER has.
	for _, name := range []string{"WMaxRtg", "VAMaxRtg", "CtrlModes", "VNomRtg"} {
		for _, storage := range []bool{false, true} {
			if need, _ := pointRequired(702, name, 0, true, storage); !need {
				t.Errorf("%s stopped being required at servesStorage=%v; the qualifier reached a "+
					"point that has nothing to do with a charge axis", name, storage)
			}
		}
	}
}

func TestProfileScaleFactorListsCoverTheCurveModels(t *testing.T) {
	for _, id := range []uint16{703, 704, 705, 706, 707, 708, 709, 710, 711, 712} {
		if len(requiredScaleFactors[id]) == 0 {
			t.Errorf("model %d has no required scale factors transcribed", id)
		}
	}
	// 711 uses Ctl/NCtl naming and has its own scale factors; a generic
	// "curve model" assumption would get this wrong.
	if !reflect.DeepEqual(requiredScaleFactors[711], []string{"Db_SF", "K_SF", "RspTms_SF"}) {
		t.Errorf("711's scale factors = %v", requiredScaleFactors[711])
	}
	// 712 deliberately has no RspTms_SF.
	for _, n := range requiredScaleFactors[712] {
		if n == "RspTms_SF" {
			t.Error("712 was given a RspTms_SF the profile does not require")
		}
	}
}

// --- the write machinery ---------------------------------------------------

func TestSweepValuesMeetsMOD3Step1(t *testing.T) {
	got := sweepValues(0, 100)
	if len(got) != 5 || got[0] != 0 || got[4] != 100 {
		t.Fatalf("sweep = %v, want the minimum, three intermediates and the maximum", got)
	}
	// "If an adjustable point has fewer possible values, all the possible
	// values must be tested."
	if got := sweepValues(0, 1); !reflect.DeepEqual(got, []int64{0, 1}) {
		t.Errorf("a two-value range swept as %v", got)
	}
	if got := sweepValues(5, 5); !reflect.DeepEqual(got, []int64{5}) {
		t.Errorf("a single-value range swept as %v", got)
	}
}

func TestRawBoundsApplyTheDeviceReportedScaleFactor(t *testing.T) {
	a, _ := adjustableFor(704, "WMaxLimPct")
	if min, max := rawBounds(a, 0); min != 0 || max != 100 {
		t.Errorf("sf=0 bounds = %d..%d, want 0..100", min, max)
	}
	// A scale factor of -1 means the register carries tenths of a percent, so
	// 100 % is 1000 raw. A suite that ignored the scale factor would write 100
	// and think it had reached the maximum.
	if min, max := rawBounds(a, -1); min != 0 || max != 1000 {
		t.Errorf("sf=-1 bounds = %d..%d, want 0..1000", min, max)
	}
	if min, max := rawBounds(a, 1); min != 0 || max != 10 {
		t.Errorf("sf=+1 bounds = %d..%d, want 0..10", min, max)
	}
}

func TestEncodeAndDecodeRawAgree(t *testing.T) {
	def := Models[704]
	pct, _ := def.Point("WMaxLimPct")
	tms, _ := def.Point("WMaxLimPctRvrtTms")
	wset, _ := def.Point("WSet")
	for _, c := range []struct {
		p Point
		v int64
	}{{pct, 0}, {pct, 65535}, {tms, 0}, {tms, 3600}, {wset, -5000}, {wset, 5000}} {
		regs, err := encode(c.p, c.v)
		if err != nil {
			t.Fatalf("encode %s %d: %v", c.p.Name, c.v, err)
		}
		if got := decodeRaw(c.p, regs); got != c.v {
			t.Errorf("%s: encoded %d, decoded %d", c.p.Name, c.v, got)
		}
	}
	// A string point is not something this suite knows how to write, and it
	// says so rather than writing the first two registers.
	if _, err := encode(Models[1].Points[2], 1); err == nil {
		t.Fatal("a 16-register string point was encoded as a write")
	}
}

func TestDenialReasonNamesTheProductPolicy(t *testing.T) {
	if r := denialReason(&excError{FC: 6, Code: mbap.ExIllegalFunction}); !contains(r, "authorization denial") {
		t.Errorf("0x01 not explained as an authorization denial: %q", r)
	}
	if r := denialReason(&excError{FC: 6, Code: mbap.ExIllegalAddress}); !contains(r, "SUN-002") {
		t.Errorf("0x02 not explained as the honesty gate: %q", r)
	}
	if r := denialReason(&excError{FC: 6, Code: mbap.ExGatewayTarget}); !contains(r, "southbound device") {
		t.Errorf("0x0b not explained: %q", r)
	}
	if r := denialReason(fmt.Errorf("connection reset")); r != "" {
		t.Errorf("a transport failure was explained as a policy denial: %q", r)
	}
}

// --- the MBAP re-parse the citation phase depends on -----------------------

func adu(tid uint16, unit uint8, pdu ...byte) []byte {
	b := make([]byte, 7+len(pdu))
	binary.BigEndian.PutUint16(b[0:2], tid)
	binary.BigEndian.PutUint16(b[4:6], uint16(len(pdu)+1))
	b[6] = unit
	copy(b[7:], pdu)
	return b
}

func TestParseADUsRecoversTheExchange(t *testing.T) {
	data := append(adu(1, 3, 0x03, 0x9C, 0x40, 0x00, 0x02), adu(2, 3, 0x06, 0x00, 0x0F, 0x00, 0x32)...)
	as := &appStream{Flow: "test", Data: data}
	got, rem, err := parseADUs(as)
	if err != nil || rem != 0 {
		t.Fatalf("parse: err=%v remainder=%d", err, rem)
	}
	if len(got) != 2 || got[0].TID != 1 || got[1].TID != 2 || got[1].FC() != 0x06 {
		t.Fatalf("recovered %+v", got)
	}
	if got[0].Start != 0 || got[0].End != 12 || got[1].Start != 12 {
		t.Errorf("byte ranges wrong: %+v", got)
	}
}

func TestParseADUsReportsATrailingPartialFrameRatherThanInventingOne(t *testing.T) {
	full := adu(1, 3, 0x03, 0x9C, 0x40, 0x00, 0x02)
	data := append(full, full[:8]...) // a complete header promising bytes that never came
	as := &appStream{Flow: "test", Data: data}
	got, rem, err := parseADUs(as)
	if err != nil {
		t.Fatalf("a truncated tail was treated as a parse failure: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("recovered %d ADUs, want 1", len(got))
	}
	if rem != 8 {
		t.Errorf("remainder = %d, want 8", rem)
	}
}

func TestParseADUsRefusesAStreamItCannotTrust(t *testing.T) {
	// A nonzero protocol identifier means the stream is not MBAP-aligned. The
	// parser must say so rather than hand back ADUs read from a guessed
	// boundary — a citation from a guessed boundary is not evidence.
	bad := adu(1, 3, 0x03, 0, 0, 0, 1)
	binary.BigEndian.PutUint16(bad[2:4], 7)
	if _, _, err := parseADUs(&appStream{Flow: "test", Data: bad}); err == nil {
		t.Fatal("a stream with a nonzero protocol identifier parsed cleanly")
	}
	oversize := adu(1, 3, 0x03, 0, 0, 0, 1)
	binary.BigEndian.PutUint16(oversize[4:6], 1000)
	if _, _, err := parseADUs(&appStream{Flow: "test", Data: oversize}); err == nil {
		t.Fatal("an out-of-range MBAP length parsed cleanly")
	}
}

func TestAppStreamFramesForMapsPlaintextOffsetsToFrames(t *testing.T) {
	as := &appStream{
		Flow: "test", Encrypted: true,
		Data: make([]byte, 30),
		segs: []segment{
			{start: 0, end: 10, frames: []int{4}},
			{start: 10, end: 20, frames: []int{7, 8}},
			{start: 20, end: 30, frames: []int{9}},
		},
	}
	if got := as.framesFor(5, 15); !reflect.DeepEqual(got, []int{4, 7, 8}) {
		t.Errorf("framesFor(5,15) = %v", got)
	}
	if got := as.framesFor(25, 30); !reflect.DeepEqual(got, []int{9}) {
		t.Errorf("framesFor(25,30) = %v", got)
	}
	if got := as.framesFor(5, 5); got != nil {
		t.Errorf("an empty range mapped to %v", got)
	}
	// TCP-3's criterion: a request that spanned more than one record.
	if n, _ := as.recordSpanFor(5, 15); n != 2 {
		t.Errorf("recordSpanFor(5,15) counted %d records, want 2", n)
	}
	if n, _ := as.recordSpanFor(0, 5); n != 1 {
		t.Errorf("recordSpanFor(0,5) counted %d records, want 1", n)
	}
}

func TestWireAgreesCatchesACaptureThatDoesNotShowTheExchange(t *testing.T) {
	log := []exchange{{TID: 1, Req: []byte{0x03, 0, 0, 0, 1}, Resp: []byte{0x03, 2, 0, 9}, Note: "read"}}
	conv := &conversation{
		Requests:  []observedADU{{TID: 1, PDU: []byte{0x03, 0, 0, 0, 1}}},
		Responses: []observedADU{{TID: 1, PDU: []byte{0x03, 2, 0, 9}}},
	}
	if n, mismatch := wireAgrees(log, conv); n != 1 || mismatch != "" {
		t.Fatalf("a matching capture was rejected: n=%d %q", n, mismatch)
	}
	conv.Responses[0].PDU = []byte{0x03, 2, 0, 8}
	if _, mismatch := wireAgrees(log, conv); mismatch == "" {
		t.Fatal("a response body that differs from what the harness read was accepted")
	}
	conv.Responses = nil
	if _, mismatch := wireAgrees(log, conv); mismatch == "" {
		t.Fatal("a missing response was accepted")
	}
	conv.Requests = nil
	if _, mismatch := wireAgrees(log, conv); mismatch == "" {
		t.Fatal("a missing request was accepted")
	}
}

// --- registration and coverage ---------------------------------------------

// TestRegistrationHasNoOrphans is the gate the runner itself enforces: a uid
// this suite registers that the catalog does not contain refuses the whole run.
func TestRegistrationHasNoOrphans(t *testing.T) {
	cat, err := certify.LoadDefault()
	if err != nil {
		t.Skipf("no committed catalog: %v", err)
	}
	reg := certify.NewRegistry()
	Register(reg)
	cov := reg.Coverage(cat, certify.Filter{})
	if len(cov.Orphans) != 0 {
		t.Fatalf("this suite registers uids the catalog does not have: %v", cov.Orphans)
	}
}

// TestEveryApplicableCaseOfBothDocumentsIsRegistered is the coverage claim: an
// applicable row with no implementation reads as an oversight, so the suite
// must bind all of them — including the ones it can only SKIP.
func TestEveryApplicableCaseOfBothDocumentsIsRegistered(t *testing.T) {
	cat, err := certify.LoadDefault()
	if err != nil {
		t.Skipf("no committed catalog: %v", err)
	}
	reg := certify.NewRegistry()
	Register(reg)
	cov := reg.Coverage(cat, certify.Filter{Docs: []string{"SS-MODBUS-CONF-v1.4", "SS-1547-TEST-v1.1"}})
	for _, d := range cov.Docs {
		if !d.Complete() {
			var names []string
			for _, e := range d.Unimplemented {
				names = append(names, e.UID)
			}
			t.Errorf("%s has unimplemented applicable cases: %v", d.Doc, names)
		}
	}
	total, applicable, implemented, missing := cov.Totals()
	if missing != 0 {
		t.Errorf("%d applicable case(s) unimplemented", missing)
	}
	if implemented != applicable {
		t.Errorf("implemented=%d applicable=%d total=%d", implemented, applicable, total)
	}
}

// TestInapplicableCasesAreDocumentedAndUnregistered pins the other half of the
// coverage story: the rows this suite deliberately does not implement are
// listed with a reason, and none of them is registered (which would file it
// under "implemented" and lose the reason).
func TestInapplicableCasesAreDocumentedAndUnregistered(t *testing.T) {
	cat, err := certify.LoadDefault()
	if err != nil {
		t.Skipf("no committed catalog: %v", err)
	}
	reg := certify.NewRegistry()
	Register(reg)
	for uid, reason := range Inapplicable {
		if _, registered := reg.Lookup(uid); registered {
			t.Errorf("%s is documented as inapplicable but is also registered", uid)
		}
		c, ok := cat.ByUID(uid)
		if !ok {
			t.Errorf("%s is not in the catalog", uid)
			continue
		}
		if c.Applicable {
			t.Errorf("%s is marked applicable by the catalog but this suite calls it inapplicable", uid)
		}
		if len(reason) < 40 {
			t.Errorf("%s's reason is too thin to be useful: %q", uid, reason)
		}
	}
	// Every inapplicable row of both documents must be accounted for.
	for _, c := range cat.Select(certify.Filter{Docs: []string{"SS-MODBUS-CONF-v1.4", "SS-1547-TEST-v1.1"}}) {
		if c.Applicable {
			continue
		}
		if _, ok := Inapplicable[c.UID]; !ok {
			t.Errorf("%s is inapplicable but this suite does not say why", c.UID)
		}
	}
}
