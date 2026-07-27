package report

import (
	"strings"
	"testing"
	"time"
)

var (
	scanClient = ap("69.0.0.20:51422")
	scanServer = ap("69.0.0.20:5020")
	scanBase   = time.Date(2026, 7, 26, 12, 0, 0, 0, time.UTC)
)

func mustBytes(t *testing.T, hexstr string) []byte {
	t.Helper()
	b, err := DecodeHexMsg(hexstr)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func scanFixture(t *testing.T, xs []exchange, closeIt bool) *ModbusScan {
	t.Helper()
	pkts := session(scanClient, scanServer, scanBase, xs, closeIt)
	frames := dissectAll(t, pkts)
	streams := assemble(frames)
	if len(streams) != 1 {
		t.Fatalf("%d streams, want 1", len(streams))
	}
	sc, err := ScanModbus(streams[0], frames, scanServer)
	if err != nil {
		t.Fatal(err)
	}
	return sc
}

// TestScanModbusRendersTheCapture is the core claim of this package: the log is
// a rendering of the pcap, not of the tool's intent. Every emitted `msg` must
// hex-encode exactly the captured bytes, and every entry must carry the
// timestamp of the frame that delivered them.
func TestScanModbusRendersTheCapture(t *testing.T) {
	sc := scanFixture(t, []exchange{
		{true, mustBytes(t, exampleReq)},
		{false, mustBytes(t, exampleResp)},
	}, true)

	if len(sc.Problems) != 0 {
		t.Fatalf("problems on a clean capture: %v", sc.Problems)
	}
	types := []string{}
	for _, e := range sc.Entries {
		types = append(types, e.Entry.Type)
	}
	want := []string{EntryConn, EntryReq, EntryResp, EntryDisc}
	if strings.Join(types, ",") != strings.Join(want, ",") {
		t.Fatalf("entry types = %v, want %v", types, want)
	}

	req := sc.Entries[1]
	if req.Entry.Msg != exampleReq {
		t.Errorf("msg = %s, want %s", req.Entry.Msg, exampleReq)
	}
	if req.End-req.Start != len(exampleReq)/2 {
		t.Errorf("byte range [%d,%d) does not span the message", req.Start, req.End)
	}
	if req.Dir == nil || len(req.Frames) == 0 {
		t.Fatal("the entry carries no provenance, so no check could cite it")
	}
	// The whole point: re-encoding the CITED bytes reproduces the emitted value.
	raw, err := req.Dir.Bytes.Range(req.Start, req.End)
	if err != nil {
		t.Fatal(err)
	}
	if HexMsg(raw) != req.Entry.Msg {
		t.Errorf("the log entry does not render the cited bytes: %s vs %s", HexMsg(raw), req.Entry.Msg)
	}

	conn := sc.Entries[0]
	if conn.Entry.IPAddr != scanServer.Addr().String() || conn.Entry.IPPort != int(scanServer.Port()) {
		t.Errorf("conn entry = %+v, want the server endpoint", conn.Entry)
	}
	if conn.Entry.Time >= req.Entry.Time {
		t.Error("the conn entry is not before the first request")
	}
	if req.Entry.Time == float64(int64(req.Entry.Time)) {
		t.Error("timestamps carry no sub-second decimals")
	}
	if f := ValidateModbusTestLogs(&ModbusTestLogs{Logs: []ModbusTestLog{sc.TestLog("MOD-1")}},
		TransportTCP); len(f) != 0 {
		t.Errorf("the derived log does not validate: %v", f)
	}
}

// TestScanModbusReassemblesASplitMessage: a message split across two segments
// must still render as ONE entry carrying the whole message. An emitter working
// from segments rather than from the reassembled stream would emit two.
func TestScanModbusReassemblesASplitMessage(t *testing.T) {
	raw := mustBytes(t, exampleReq)
	sc := scanFixture(t, []exchange{
		{true, raw[:5]},
		{true, raw[5:]},
		{false, mustBytes(t, exampleResp)},
	}, true)
	if len(sc.Problems) != 0 {
		t.Fatalf("problems: %v", sc.Problems)
	}
	if n := sc.Count(EntryReq); n != 1 {
		t.Fatalf("%d req entries for one split message, want 1", n)
	}
	e, _ := sc.First(EntryReq)
	if e.Entry.Msg != exampleReq {
		t.Errorf("msg = %s", e.Entry.Msg)
	}
	if len(e.Frames) != 2 {
		t.Errorf("frames = %v; the entry must cite both frames that carried it", e.Frames)
	}
}

// TestScanModbusRefusesAPartialTrailingMessage: half a message is not a short
// message, and emitting it would put bytes in the log that are not a Modbus
// message at all.
func TestScanModbusRefusesAPartialTrailingMessage(t *testing.T) {
	raw := mustBytes(t, exampleReq)
	sc := scanFixture(t, []exchange{
		{true, raw},
		{true, raw[:7]}, // truncated second request
		{false, mustBytes(t, exampleResp)},
	}, false)
	if sc.Count(EntryReq) != 1 {
		t.Errorf("%d req entries; the truncated message must not be emitted", sc.Count(EntryReq))
	}
	if !strings.Contains(strings.Join(sc.Problems, "\n"), "the log omits it rather than emitting a truncated") {
		t.Errorf("the omission was not reported: %v", sc.Problems)
	}

	// A tail shorter than the six-byte MBAP header takes the other refusal path.
	sc = scanFixture(t, []exchange{{true, raw}, {true, raw[:3]}}, false)
	if !strings.Contains(strings.Join(sc.Problems, "\n"), "shorter than an MBAP header") {
		t.Errorf("a sub-header tail was not reported: %v", sc.Problems)
	}
}

// TestScanModbusRefusesAMidStreamCapture: MBAP has no self-synchronising
// delimiter, so framing from an arbitrary first captured byte would emit
// plausible nonsense.
func TestScanModbusRefusesAMidStreamCapture(t *testing.T) {
	// No SYN: the capture began after the connection did.
	raw := mustBytes(t, exampleReq)
	pkts := synthPackets([]synthFrame{
		{src: scanClient, dst: scanServer, seq: 5000, payload: raw, at: scanBase},
		{src: scanServer, dst: scanClient, seq: 7000, payload: mustBytes(t, exampleResp),
			at: scanBase.Add(20 * time.Millisecond)},
	})
	frames := dissectAll(t, pkts)
	sc, err := ScanModbus(assemble(frames)[0], frames, scanServer)
	if err != nil {
		t.Fatal(err)
	}
	if len(sc.Entries) != 0 {
		t.Fatalf("%d entries were derived from a mid-stream capture", len(sc.Entries))
	}
	joined := strings.Join(sc.Problems, "\n")
	if !strings.Contains(joined, "mid-connection") {
		t.Errorf("the refusal reason is not stated: %v", sc.Problems)
	}
	if !strings.Contains(joined, "no SYN was captured") {
		t.Errorf("the missing connection information was not reported: %v", sc.Problems)
	}
}

func TestScanModbusRejectsAWrongServer(t *testing.T) {
	pkts := session(scanClient, scanServer, scanBase, []exchange{{true, mustBytes(t, exampleReq)}}, true)
	frames := dissectAll(t, pkts)
	if _, err := ScanModbus(assemble(frames)[0], frames, ap("10.9.9.9:502")); err == nil {
		t.Fatal("a stream that talks to nobody named was scanned anyway")
	}
}

// ---------------------------------------------------------------------------
// HTTP
// ---------------------------------------------------------------------------

const httpReq = "GET /sep2/dcap HTTP/1.1\r\nHost: 69.0.0.20:8080\r\nAccept: application/sep+xml\r\n" +
	"x-LOWER-case: kept\r\n\r\n"

const dcapBody = `<DeviceCapability xmlns="urn:ieee:std:2030.5:ns" href="/sep2/dcap"/>`

var httpResp = "HTTP/1.1 200 OK\r\nContent-Type: application/sep+xml; charset=utf-8\r\n" +
	"Content-Length: " + itoa(len(dcapBody)) + "\r\nConnection: keep-alive\r\n\r\n" + dcapBody

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

func TestScanHTTPRendersTheCapture(t *testing.T) {
	server := ap("69.0.0.20:8080")
	pkts := session(scanClient, server, scanBase, []exchange{
		{true, []byte(httpReq)},
		{false, []byte(httpResp)},
	}, true)
	frames := dissectAll(t, pkts)
	sc, err := ScanHTTP(assemble(frames)[0], frames, server)
	if err != nil {
		t.Fatal(err)
	}
	if len(sc.Problems) != 0 {
		t.Fatalf("problems: %v", sc.Problems)
	}
	if len(sc.Messages) != 2 {
		t.Fatalf("%d messages, want 2", len(sc.Messages))
	}
	req := sc.Messages[0].Message
	if req.Method != "GET" || req.URI != "/sep2/dcap" || req.Vers != "HTTP/1.1" {
		t.Errorf("request = %+v", req)
	}
	if req.Body != "" {
		t.Errorf("body = %q; §4.1.2 requires the empty string, and this request had none", req.Body)
	}
	// Header names must survive exactly as sent. net/http would canonicalise
	// this to X-Lower-Case, and the log would then not say what was on the wire.
	if _, ok := req.Headers["x-LOWER-case"]; !ok {
		t.Errorf("header names were canonicalised: %v", req.Headers)
	}

	resp := sc.Messages[1].Message
	if resp.Code != "200" {
		t.Errorf("code = %q, want the string \"200\"", resp.Code)
	}
	if resp.Reason != "OK\r\n" {
		t.Errorf("reason = %q, want the example's trailing CRLF", resp.Reason)
	}
	if resp.Body != dcapBody {
		t.Errorf("body = %q", resp.Body)
	}
	if f := ValidateCSIPTestLogs(&CSIPTestLogs{Logs: []CSIPTestLog{sc.TestLog("", "CORE-001")}}); len(f) != 0 {
		t.Errorf("the derived log does not validate: %v", f)
	}
	// Provenance: the cited range must be exactly the request as it lay in the
	// stream.
	m := sc.Messages[0]
	raw, err := m.Dir.Bytes.Range(m.Start, m.End)
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != httpReq {
		t.Errorf("the cited bytes are not the message: %q", raw)
	}
}

func TestScanHTTPDecodesChunkedBodies(t *testing.T) {
	server := ap("69.0.0.20:8080")
	chunked := "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n" +
		"5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n"
	pkts := session(scanClient, server, scanBase, []exchange{
		{true, []byte(httpReq)},
		{false, []byte(chunked)},
	}, true)
	frames := dissectAll(t, pkts)
	sc, err := ScanHTTP(assemble(frames)[0], frames, server)
	if err != nil {
		t.Fatal(err)
	}
	resp, ok := sc.First(MsgResp)
	if !ok {
		t.Fatalf("no response derived; problems %v", sc.Problems)
	}
	if resp.Message.Body != "hello world" {
		t.Errorf("body = %q, want the decoded entity", resp.Message.Body)
	}
}

func TestScanHTTPReportsATruncatedMessage(t *testing.T) {
	server := ap("69.0.0.20:8080")
	pkts := session(scanClient, server, scanBase, []exchange{
		{true, []byte("GET /sep2/dcap HTTP/1.1\r\nHost: x\r\n")}, // no blank line
	}, false)
	frames := dissectAll(t, pkts)
	sc, err := ScanHTTP(assemble(frames)[0], frames, server)
	if err != nil {
		t.Fatal(err)
	}
	if len(sc.Messages) != 0 {
		t.Fatalf("%d messages derived from an incomplete head", len(sc.Messages))
	}
	if !strings.Contains(strings.Join(sc.Problems, "\n"), "no complete HTTP head") {
		t.Errorf("the omission was not reported: %v", sc.Problems)
	}
}
