package writeset

// writeset_test.go — the ORACLE for the write-set extraction, against a capture
// whose every byte this file put there.
//
// A synthesised capture rather than a recorded one, and the reason is the
// negative row: to prove that a write OUTSIDE an mRID's window is not
// attributed to it, the test has to know exactly which writes exist and exactly
// when each happened. A recorded capture can show the tool agreeing with itself;
// only a constructed one can show it disagreeing with a write it should exclude.
//
// The packet builder is this package's own copy of the one in
// internal/certify/synth_test.go. Test helpers do not cross package boundaries
// in Go, and the alternative — exporting a packet forge from a production
// package so two tests can share it — would put capture-forging code in the
// shipped binary.

import (
	"encoding/binary"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"csip-tls-test/internal/evidence/netdis"
	"csip-tls-test/internal/evidence/pcapng"
)

const (
	tcpACK = 0x010
	tcpPSH = 0x008
)

// synthFrame describes one packet to synthesise.
type synthFrame struct {
	src, dst netip.AddrPort
	seq      uint32
	payload  []byte
	at       time.Time
}

// bytes renders the frame as Ethernet / IPv4 / TCP. Checksums are left zero:
// netdis does not verify them (a capture is not a NIC).
func (s synthFrame) bytes() []byte {
	tcp := make([]byte, 20+len(s.payload))
	binary.BigEndian.PutUint16(tcp[0:2], s.src.Port())
	binary.BigEndian.PutUint16(tcp[2:4], s.dst.Port())
	binary.BigEndian.PutUint32(tcp[4:8], s.seq)
	binary.BigEndian.PutUint16(tcp[12:14], 5<<12|tcpPSH|tcpACK)
	binary.BigEndian.PutUint16(tcp[14:16], 65535)
	copy(tcp[20:], s.payload)

	ip := make([]byte, 20+len(tcp))
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:4], uint16(len(ip)))
	ip[8] = 64
	ip[9] = 6
	copy(ip[12:16], s.src.Addr().AsSlice())
	copy(ip[16:20], s.dst.Addr().AsSlice())
	copy(ip[20:], tcp)

	eth := make([]byte, 14+len(ip))
	copy(eth[0:6], []byte{0x02, 0, 0, 0, 0, 0x02})
	copy(eth[6:12], []byte{0x02, 0, 0, 0, 0, 0x01})
	binary.BigEndian.PutUint16(eth[12:14], 0x0800)
	copy(eth[14:], ip)
	return eth
}

// writeCapture renders the frames as a classic pcap and returns its path.
func writeCapture(t *testing.T, specs []synthFrame) string {
	t.Helper()
	pkts := make([]pcapng.Packet, 0, len(specs))
	for i, s := range specs {
		data := s.bytes()
		pkts = append(pkts, pcapng.Packet{
			Index: i + 1, Time: s.at.UTC(), LinkType: netdis.LinkTypeEthernet,
			OrigLen: len(data), Data: data,
		})
	}
	buf := make([]byte, 24)
	binary.LittleEndian.PutUint32(buf[0:4], 0xA1B2C3D4)
	binary.LittleEndian.PutUint16(buf[4:6], 2)
	binary.LittleEndian.PutUint16(buf[6:8], 4)
	binary.LittleEndian.PutUint32(buf[16:20], 262144)
	binary.LittleEndian.PutUint32(buf[20:24], uint32(netdis.LinkTypeEthernet))
	for _, p := range pkts {
		hdr := make([]byte, 16)
		binary.LittleEndian.PutUint32(hdr[0:4], uint32(p.Time.Unix()))
		binary.LittleEndian.PutUint32(hdr[4:8], uint32(p.Time.Nanosecond()/1000))
		binary.LittleEndian.PutUint32(hdr[8:12], uint32(len(p.Data)))
		binary.LittleEndian.PutUint32(hdr[12:16], uint32(p.OrigLen))
		buf = append(buf, hdr...)
		buf = append(buf, p.Data...)
	}
	path := filepath.Join(t.TempDir(), "synth.pcap")
	if err := os.WriteFile(path, buf, 0o644); err != nil {
		t.Fatalf("write synthetic capture: %v", err)
	}
	return path
}

// ── MBAP builders ────────────────────────────────────────────────────────────

// mbap wraps a PDU in an MBAP header with the given transaction id.
func mbap(txid uint16, unit uint8, pdu []byte) []byte {
	out := make([]byte, 7+len(pdu))
	binary.BigEndian.PutUint16(out[0:2], txid)
	binary.BigEndian.PutUint16(out[2:4], 0) // protocol id
	binary.BigEndian.PutUint16(out[4:6], uint16(len(pdu)+1))
	out[6] = unit
	copy(out[7:], pdu)
	return out
}

// readReq is FC3: read `count` registers at `addr`.
func readReq(txid uint16, addr, count uint16) []byte {
	p := []byte{0x03, 0, 0, 0, 0}
	binary.BigEndian.PutUint16(p[1:3], addr)
	binary.BigEndian.PutUint16(p[3:5], count)
	return mbap(txid, 1, p)
}

// readResp is FC3's answer carrying `vals`.
func readResp(txid uint16, vals ...uint16) []byte {
	p := make([]byte, 2+2*len(vals))
	p[0] = 0x03
	p[1] = byte(2 * len(vals))
	for i, v := range vals {
		binary.BigEndian.PutUint16(p[2+2*i:], v)
	}
	return mbap(txid, 1, p)
}

// writeMulti is FC16: write `vals` starting at `addr`.
func writeMulti(txid uint16, addr uint16, vals ...uint16) []byte {
	p := make([]byte, 6+2*len(vals))
	p[0] = 0x10
	binary.BigEndian.PutUint16(p[1:3], addr)
	binary.BigEndian.PutUint16(p[3:5], uint16(len(vals)))
	p[5] = byte(2 * len(vals))
	for i, v := range vals {
		binary.BigEndian.PutUint16(p[6+2*i:], v)
	}
	return mbap(txid, 1, p)
}

// ── The fixture ──────────────────────────────────────────────────────────────

var (
	gw  = netip.MustParseAddrPort("10.0.0.1:40001") // the gateway (Modbus client)
	der = netip.MustParseAddrPort("10.0.0.2:5020")  // the DER sim (Modbus server)
	hub = netip.MustParseAddrPort("10.0.0.1:40002") // the northbound leg
	srv = netip.MustParseAddrPort("10.0.0.3:11113") // gridsim
)

const fixtureMRID = "DERC-SP-CURVE-1786940036"

// t0 is the fixture's epoch. Fixed, so two runs of these rows produce identical
// timestamps and a golden line can be quoted in a report.
var t0 = time.Date(2026, 8, 17, 12, 0, 0, 0, time.UTC)

// buildFixture lays out one supersession window and one write outside it.
//
//	frame 1-2   discovery: model 705 header at 40070 (data base 40072, L=30)
//	frame 3-4   discovery: model 712 header at 40104 (data base 40106, L=20)
//	frame 5     northbound: the control carrying fixtureMRID  <- window opens
//	frame 6     WRITE 40072 (in 705) — inside the window
//	frame 7     WRITE 40106 (in 712) — inside the window
//	frame 8     northbound: the Response for fixtureMRID      <- last mention
//	frame 9     WRITE 40072 — LONG after, outside the window
//
// Frame 9 is the whole point of the fixture. It is a real write, to an address
// the mRID's own window also wrote, and it must NOT be attributed: an extractor
// that keyed on address rather than on time would report it and be wrong.
func buildFixture() []synthFrame {
	var toDER, fromDER, north uint32 = 1, 1, 1
	sendDER := func(at time.Duration, b []byte) synthFrame {
		f := synthFrame{src: gw, dst: der, seq: toDER, payload: b, at: t0.Add(at)}
		toDER += uint32(len(b))
		return f
	}
	replyDER := func(at time.Duration, b []byte) synthFrame {
		f := synthFrame{src: der, dst: gw, seq: fromDER, payload: b, at: t0.Add(at)}
		fromDER += uint32(len(b))
		return f
	}
	sendNorth := func(at time.Duration, body string) synthFrame {
		b := []byte(body)
		f := synthFrame{src: srv, dst: hub, seq: north, payload: b, at: t0.Add(at)}
		north += uint32(len(b))
		return f
	}
	return []synthFrame{
		sendDER(0, readReq(1, 40070, 2)),
		replyDER(10*time.Millisecond, readResp(1, 705, 30)),
		sendDER(20*time.Millisecond, readReq(2, 40104, 2)),
		replyDER(30*time.Millisecond, readResp(2, 712, 20)),

		sendNorth(1*time.Second, "HTTP/1.1 200 OK\r\n\r\n<DERControl><mRID>"+fixtureMRID+"</mRID></DERControl>"),
		sendDER(2*time.Second, writeMulti(3, 40072, 1, 2, 3)),
		sendDER(3*time.Second, writeMulti(4, 40106, 9, 9)),
		sendNorth(4*time.Second, "POST /rsps/0/r\r\n\r\n<DERControlResponse><subject>"+fixtureMRID+"</subject><status>2</status></DERControlResponse>"),

		// Far outside the settle margin, same address as the first write.
		sendDER(10*time.Minute, writeMulti(5, 40072, 7, 7, 7)),
	}
}

func extractFixture(t *testing.T, mrid string) *Result {
	t.Helper()
	path := writeCapture(t, buildFixture())
	res, err := Extract(Options{Path: path, MRID: mrid})
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}
	return res
}

// ── Rows ─────────────────────────────────────────────────────────────────────

// TestExtract_FindsEveryWriteWithAddressAndTime is the base claim: the tool sees
// the writes, dates them, and reports the address — "a claim without addresses
// is not a claim in this campaign".
func TestExtract_FindsEveryWriteWithAddressAndTime(t *testing.T) {
	res := extractFixture(t, "")
	if len(res.Writes) != 3 {
		t.Fatalf("found %d writes, want 3: %+v", len(res.Writes), res.Writes)
	}
	want := []struct {
		addr  uint16
		count uint16
		at    time.Duration
		frame int
	}{
		{40072, 3, 2 * time.Second, 6},
		{40106, 2, 3 * time.Second, 7},
		{40072, 3, 10 * time.Minute, 9},
	}
	for i, w := range want {
		got := res.Writes[i]
		if got.Addr != w.addr || got.Count != w.count {
			t.Errorf("write %d = addr %d count %d, want addr %d count %d",
				i, got.Addr, got.Count, w.addr, w.count)
		}
		if !got.Time.Equal(t0.Add(w.at)) {
			t.Errorf("write %d at %s, want %s", i, got.Time, t0.Add(w.at))
		}
		if got.Frame != w.frame {
			t.Errorf("write %d came from frame %d, want %d", i, got.Frame, w.frame)
		}
	}
}

// TestExtract_DerivesTheChainFromTheCapturesOwnHeaderReads proves the model
// labelling is DERIVED, not configured. Nothing told this run that 705 lives at
// 40072; the gateway's own discovery reads did.
func TestExtract_DerivesTheChainFromTheCapturesOwnHeaderReads(t *testing.T) {
	res := extractFixture(t, "")
	if len(res.Chain) != 2 {
		t.Fatalf("discovered %d blocks, want 2: %+v", len(res.Chain), res.Chain)
	}
	for _, want := range []Block{
		{Model: 705, Base: 40072, Length: 30},
		{Model: 712, Base: 40106, Length: 20},
	} {
		var found bool
		for _, b := range res.Chain {
			if b.Model == want.Model && b.Base == want.Base && b.Length == want.Length {
				found = true
			}
		}
		if !found {
			t.Errorf("model %d@%d+%d was not discovered: %+v", want.Model, want.Base, want.Length, res.Chain)
		}
	}
	// And the writes carry the model the chain resolved for them.
	if got := res.Writes[0].Axis(); got != "M705" {
		t.Errorf("the write at 40072 is on axis %s, want M705", got)
	}
	if got := res.Writes[1].Axis(); got != "M712" {
		t.Errorf("the write at 40106 is on axis %s, want M712", got)
	}
	if off := res.Writes[0].Offset(); off != 0 {
		t.Errorf("the write at 40072 is at model offset %d, want 0", off)
	}
}

// TestExtract_AttributesOnlyTheWritesInsideTheMRIDWindow is the row this tool
// was asked for: PC-001's claim is about WHICH AXES a named control wrote.
func TestExtract_AttributesOnlyTheWritesInsideTheMRIDWindow(t *testing.T) {
	res := extractFixture(t, fixtureMRID)
	if res.Window == nil {
		t.Fatal("no window was derived for the mRID")
	}
	if len(res.Window.Mentions) < 2 {
		t.Errorf("the mRID was found %d time(s), want at least 2 (the control and its Response)",
			len(res.Window.Mentions))
	}
	got := res.Attributed()
	if len(got) != 2 {
		t.Fatalf("attributed %d writes, want 2: %+v", len(got), got)
	}
	if got[0].Addr != 40072 || got[1].Addr != 40106 {
		t.Errorf("attributed addresses %d,%d — want 40072,40106", got[0].Addr, got[1].Addr)
	}
	// THE NEGATIVE, and the reason the fixture has a ninth frame.
	for _, w := range got {
		if w.Frame == 9 {
			t.Error("the write ten minutes after the mRID's last mention was ATTRIBUTED to it. It is at " +
				"the same address as a write that IS in the window, so an extractor keying on address " +
				"rather than on time would report exactly this and be wrong")
		}
	}
	if res.Excluded != 1 {
		t.Errorf("excluded=%d, want 1 — the out-of-window write must be counted, not silently dropped",
			res.Excluded)
	}
}

// TestExtract_UnknownMRIDIsAnErrorNotAnEmptyReport. An empty write set for an
// mRID that is not in the capture reads as "this control wrote nothing", which
// is the strongest possible claim and would be made on no evidence at all.
func TestExtract_UnknownMRIDIsAnErrorNotAnEmptyReport(t *testing.T) {
	path := writeCapture(t, buildFixture())
	_, err := Extract(Options{Path: path, MRID: "DERC-NOT-IN-THIS-CAPTURE"})
	if err == nil {
		t.Fatal("an mRID absent from the capture produced a report instead of an error")
	}
	if !strings.Contains(err.Error(), "does not appear") {
		t.Errorf("the error does not say the mRID was not found: %v", err)
	}
}

// TestRender_IsStableAndGreppable pins the output shape a bundle manifest cites.
func TestRender_IsStableAndGreppable(t *testing.T) {
	res := extractFixture(t, fixtureMRID)
	var sb strings.Builder
	res.Render(&sb)
	out := sb.String()

	for _, want := range []string{
		"# writeset capture=",
		"# chain (derived from this capture's own header reads): M705@40072+30 M712@40106+20",
		"# mrid=" + fixtureMRID,
		"# confounded=no",
		"# attribution rule:",
		"#   mention frame=5",
		"# excluded=1",
		"axis M705 writes=1",
		"axis M712 writes=1",
		"addr=40072",
		"addr=40106",
		"frame=6",
		"ts=2026-08-17T12:00:02.000000Z",
		"values=1,2,3",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("the report does not contain %q:\n%s", want, out)
		}
	}
	// Rendering twice must produce identical bytes, or a manifest citing a line
	// cannot be re-checked.
	var sb2 strings.Builder
	res.Render(&sb2)
	if sb2.String() != out {
		t.Error("two renders of one result differ; the format is not stable")
	}
	// The excluded write must not appear anywhere in an mRID-scoped report.
	if strings.Contains(out, "frame=9") {
		t.Errorf("the out-of-window write is in the mRID-scoped report:\n%s", out)
	}
}

// TestExtract_WholeTimelineWhenNoMRIDIsGiven — the other mode the brief asks
// for: no filter, everything, grouped by axis.
func TestExtract_WholeTimelineWhenNoMRIDIsGiven(t *testing.T) {
	res := extractFixture(t, "")
	if res.Window != nil {
		t.Error("a report with no mRID carries a window")
	}
	if len(res.Attributed()) != 3 {
		t.Errorf("the unfiltered report holds %d writes, want all 3", len(res.Attributed()))
	}
	var sb strings.Builder
	res.Render(&sb)
	out := sb.String()
	if !strings.Contains(out, "axis M705 writes=2") {
		t.Errorf("the unfiltered report does not group both M705 writes together:\n%s", out)
	}
	if strings.Contains(out, "# mrid=") {
		t.Error("an unfiltered report claims an mRID scope")
	}
}
