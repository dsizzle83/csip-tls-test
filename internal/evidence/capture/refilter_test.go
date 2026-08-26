package capture

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"csip-tls-test/internal/evidence/netdis"
	"csip-tls-test/internal/evidence/pcapng"
)

// ---------------------------------------------------------------------------
// a pcapng writer, for tests only
//
// The evidence engine's pcapng package reads pcapng and writes classic
// libpcap, so there is nothing to build a two-interface fixture with. This is
// the smallest writer that produces a file that package parses — and, more to
// the point, one whose blocks the test knows the byte boundaries of, so it can
// assert that the re-filter copied the ones it kept through UNCHANGED rather
// than re-encoding them.
// ---------------------------------------------------------------------------

// byteOrder is what binary.LittleEndian and binary.BigEndian both satisfy:
// the reading half the file format needs and the appending half this writer
// does. The standard library splits them across two interfaces.
type byteOrder interface {
	binary.ByteOrder
	binary.AppendByteOrder
}

// ngFile accumulates blocks and remembers which of them carry frames.
type ngFile struct {
	bo       byteOrder
	blocks   [][]byte
	isPacket []bool
}

func newNGFile(bo byteOrder) *ngFile { return &ngFile{bo: bo} }

func (f *ngFile) add(raw []byte, isPacket bool) {
	f.blocks = append(f.blocks, raw)
	f.isPacket = append(f.isPacket, isPacket)
}

// bytes renders the whole file.
func (f *ngFile) bytes() []byte { return f.selected(nil) }

// selected renders the file with only the packet blocks keep marks, which is
// what the re-filter is expected to produce byte for byte. A nil keep means
// "everything".
func (f *ngFile) selected(keep []bool) []byte {
	var out []byte
	seen := 0
	for i, blk := range f.blocks {
		if f.isPacket[i] {
			seen++
			if keep != nil && !keep[seen-1] {
				continue
			}
		}
		out = append(out, blk...)
	}
	return out
}

// block wraps a body in the pcapng block framing.
func (f *ngFile) block(btype uint32, body []byte) []byte {
	if len(body)%4 != 0 {
		body = append(body, make([]byte, 4-len(body)%4)...)
	}
	total := uint32(12 + len(body))
	out := make([]byte, 0, total)
	out = f.bo.AppendUint32(out, btype)
	out = f.bo.AppendUint32(out, total)
	out = append(out, body...)
	return f.bo.AppendUint32(out, total)
}

func (f *ngFile) addSHB() {
	body := make([]byte, 0, 16)
	body = f.bo.AppendUint32(body, 0x1A2B3C4D) // byte-order magic
	body = f.bo.AppendUint16(body, 1)          // major
	body = f.bo.AppendUint16(body, 0)          // minor
	body = f.bo.AppendUint64(body, ^uint64(0)) // section length: unknown
	f.add(f.block(0x0A0D0D0A, body), false)
}

func (f *ngFile) addIDB(linkType uint16, name string) {
	body := make([]byte, 0, 16)
	body = f.bo.AppendUint16(body, linkType)
	body = f.bo.AppendUint16(body, 0)     // reserved
	body = f.bo.AppendUint32(body, 65535) // snaplen
	if name != "" {
		body = f.bo.AppendUint16(body, 2) // opt_if_name
		body = f.bo.AppendUint16(body, uint16(len(name)))
		body = append(body, name...)
		if pad := (4 - len(name)%4) % 4; pad != 0 {
			body = append(body, make([]byte, pad)...)
		}
		body = f.bo.AppendUint16(body, 0) // opt_endofopt
		body = f.bo.AppendUint16(body, 0)
	}
	f.add(f.block(0x00000001, body), false)
}

// addEPB appends an Enhanced Packet Block. tick is in microseconds, which is
// pcapng's default if_tsresol and therefore what the reader assumes.
func (f *ngFile) addEPB(ifaceID uint32, tick uint64, data []byte) {
	body := make([]byte, 0, 20+len(data)+3)
	body = f.bo.AppendUint32(body, ifaceID)
	body = f.bo.AppendUint32(body, uint32(tick>>32))
	body = f.bo.AppendUint32(body, uint32(tick))
	body = f.bo.AppendUint32(body, uint32(len(data)))
	body = f.bo.AppendUint32(body, uint32(len(data)))
	body = append(body, data...)
	f.add(f.block(0x00000006, body), true)
}

// addNRB and addDSB are the blocks that are neither headers nor frames, and
// the ones a re-filter that re-encoded instead of copying would silently lose:
// the Decryption Secrets Block is where an embedded key log lives.
func (f *ngFile) addNRB() {
	body := make([]byte, 0, 4)
	body = f.bo.AppendUint16(body, 0) // nrb_record_end
	body = f.bo.AppendUint16(body, 0)
	f.add(f.block(0x00000004, body), false)
}

func (f *ngFile) addDSB(secret string) {
	body := make([]byte, 0, 8+len(secret))
	body = f.bo.AppendUint32(body, 0x544C534B) // TLS Key Log
	body = f.bo.AppendUint32(body, uint32(len(secret)))
	body = append(body, secret...)
	f.add(f.block(0x0000000A, body), false)
}

// leakyCapture builds the shape the defect produces: two taps in one file,
// the FIRST one carrying the run's traffic plus everything else on the NIC,
// the second one filtered correctly.
//
// It returns the file, the frames in file order for reference, and the keep
// mask the re-filter is expected to arrive at for "tcp port 802".
func leakyCapture(bo byteOrder) (*ngFile, []bool) {
	f := newNGFile(bo)
	f.addSHB()
	f.addIDB(netdis.LinkTypeEthernet, "wlp2s0")
	f.addIDB(netdis.LinkTypeEthernet, "enp1s0")

	base := uint64(1755000000) * 1e6
	var keep []bool
	tick := base
	frame := func(iface uint32, data []byte, want bool) {
		tick += 1000
		f.addEPB(iface, tick, data)
		keep = append(keep, want)
	}

	frame(0, tcpFrame(addrBench, addrDUT, 51422, 802), true) // the run's own traffic
	frame(0, mdnsFrame(), false)                             // the leak
	f.addNRB()                                               // a name-resolution block mid-file
	frame(1, tcpFrame(addrOther, addrDUT, 11113, 44444), false)
	frame(0, tcpFrame(addrDUT, addrBench, 802, 51422), true)
	frame(0, arpFrame(), false)
	f.addDSB("CLIENT_RANDOM 00 11\n")
	frame(0, udpFrame(addrOther, addrDUT, 53, 44444), false)
	frame(1, tcpFrame(addrDUT, addrOther, 802, 33333), true)
	frame(0, icmpFrame(), false)
	frame(0, truncatedTCPFrame(), true) // undecidable: kept
	return f, keep
}

func writeTemp(t *testing.T, name string, data []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, data, 0o640); err != nil {
		t.Fatal(err)
	}
	return path
}

// ---------------------------------------------------------------------------

// TestClassifyCountsPerInterface is the accounting the bundle records: which
// tap delivered what, and which tap was running with no kernel filter at all.
func TestClassifyCountsPerInterface(t *testing.T) {
	file, wantKeep := leakyCapture(binary.LittleEndian)
	path := writeTemp(t, "leaky.pcapng", file.bytes())
	pkts, err := pcapng.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	f, err := ParseFilter("tcp port 802")
	if err != nil {
		t.Fatal(err)
	}

	res := classify(f, pkts, []string{"wlp2s0", "enp1s0"})

	if len(res.kept) != len(wantKeep) {
		t.Fatalf("keep mask has %d entries, want %d", len(res.kept), len(wantKeep))
	}
	for i := range wantKeep {
		if res.kept[i] != wantKeep[i] {
			t.Errorf("frame %d kept = %t, want %t", i+1, res.kept[i], wantKeep[i])
		}
	}

	want := []InterfaceFrames{
		{ID: 0, Name: "wlp2s0", Captured: 7, Kept: 3, Dropped: 4, Undecided: 1, FilterUnarmedSuspected: true},
		{ID: 1, Name: "enp1s0", Captured: 2, Kept: 1, Dropped: 1, FilterUnarmedSuspected: true},
	}
	if len(res.interfaces) != len(want) {
		t.Fatalf("interfaces = %+v, want %d entries", res.interfaces, len(want))
	}
	for i, w := range want {
		if res.interfaces[i] != w {
			t.Errorf("interface %d = %+v, want %+v", i, res.interfaces[i], w)
		}
	}
	if res.dropped != 5 || res.undecided != 1 {
		t.Errorf("dropped/undecided = %d/%d, want 5/1", res.dropped, res.undecided)
	}
}

// TestClassifyMarksOnlyTheLeakyInterface is the flag an operator reads. A
// capture whose second tap filtered correctly must not be reported as if both
// had failed.
func TestClassifyMarksOnlyTheLeakyInterface(t *testing.T) {
	f := newNGFile(binary.LittleEndian)
	f.addSHB()
	f.addIDB(netdis.LinkTypeEthernet, "wlp2s0")
	f.addIDB(netdis.LinkTypeEthernet, "enp1s0")
	tick := uint64(1755000000) * 1e6
	f.addEPB(0, tick+1, tcpFrame(addrBench, addrDUT, 51422, 802))
	f.addEPB(0, tick+2, mdnsFrame()) // only tap 0 leaks
	f.addEPB(1, tick+3, tcpFrame(addrDUT, addrOther, 802, 33333))
	f.addEPB(1, tick+4, tcpFrame(addrOther, addrDUT, 33333, 802))

	path := writeTemp(t, "onetap.pcapng", f.bytes())
	pkts, err := pcapng.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	flt, err := ParseFilter("tcp port 802")
	if err != nil {
		t.Fatal(err)
	}
	res := classify(flt, pkts, []string{"wlp2s0", "enp1s0"})

	if !res.interfaces[0].FilterUnarmedSuspected {
		t.Error("wlp2s0 delivered an unrelated frame but is not flagged")
	}
	if res.interfaces[1].FilterUnarmedSuspected {
		t.Error("enp1s0 filtered correctly but is flagged")
	}
	if res.interfaces[1].Dropped != 0 {
		t.Errorf("enp1s0 dropped = %d, want 0", res.interfaces[1].Dropped)
	}
}

// TestRewriteFilteredKeepsOnlyMatchingFrames is the artefact-level assertion:
// what is left in the file the bundle ships.
func TestRewriteFilteredKeepsOnlyMatchingFrames(t *testing.T) {
	for _, tc := range []struct {
		name string
		bo   byteOrder
	}{
		{"little endian", binary.LittleEndian},
		{"big endian", binary.BigEndian},
	} {
		t.Run(tc.name, func(t *testing.T) {
			file, keep := leakyCapture(tc.bo)
			path := writeTemp(t, "leaky.pcapng", file.bytes())

			if err := rewriteFiltered(path, keep); err != nil {
				t.Fatal(err)
			}

			// Byte for byte: every non-packet block survives — the Section
			// Header, BOTH Interface Description Blocks, the name-resolution
			// block and the decryption-secrets block — and every kept frame is
			// the tool's own bytes, not a re-encoding of them.
			got, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if want := file.selected(keep); !bytes.Equal(got, want) {
				t.Fatalf("filtered file is %d bytes, want the %d bytes of the kept blocks",
					len(got), len(want))
			}

			pkts, err := pcapng.ReadFile(path)
			if err != nil {
				t.Fatalf("filtered capture does not read back: %v", err)
			}
			wantKept := 0
			for _, k := range keep {
				if k {
					wantKept++
				}
			}
			if len(pkts) != wantKept {
				t.Fatalf("filtered capture holds %d frames, want %d", len(pkts), wantKept)
			}

			// Frame numbering — the citation key for the whole engine — must
			// be a single 1..N sequence over the file that ships.
			for i, p := range pkts {
				if p.Index != i+1 {
					t.Errorf("frame %d has Index %d", i+1, p.Index)
				}
			}

			// And nothing unrelated came through.
			flt, err := ParseFilter("tcp port 802")
			if err != nil {
				t.Fatal(err)
			}
			for _, p := range pkts {
				if m := flt.eval(p); m == matchNo {
					t.Errorf("frame %d survived the re-filter but does not match the filter", p.Index)
				}
			}
			// The interface split survives too: both taps still have frames.
			seen := map[int]int{}
			for _, p := range pkts {
				seen[p.Interface]++
			}
			if seen[0] == 0 || seen[1] == 0 {
				t.Errorf("filtered capture lost a tap: %v", seen)
			}
		})
	}
}

// TestRewriteFilteredLegacyPcap covers the tcpdump fallback container. It is
// rewritten by copying records for the same reason pcapng is copied by block:
// re-encoding through the legacy writer would normalise a nanosecond capture
// to microseconds and lose the part of a timestamp an evidence timeline needs.
func TestRewriteFilteredLegacyPcap(t *testing.T) {
	frames := [][]byte{
		tcpFrame(addrBench, addrDUT, 51422, 802),
		mdnsFrame(),
		tcpFrame(addrDUT, addrBench, 802, 51422),
		arpFrame(),
	}
	// A nanosecond-resolution big-endian file: the awkward end of the format.
	var raw []byte
	hdr := make([]byte, 24)
	binary.BigEndian.PutUint32(hdr[0:4], 0xA1B23C4D)
	binary.BigEndian.PutUint16(hdr[4:6], 2)
	binary.BigEndian.PutUint16(hdr[6:8], 4)
	binary.BigEndian.PutUint32(hdr[16:20], 65535)
	binary.BigEndian.PutUint32(hdr[20:24], uint32(netdis.LinkTypeEthernet))
	raw = append(raw, hdr...)
	for i, data := range frames {
		rec := make([]byte, 16)
		binary.BigEndian.PutUint32(rec[0:4], 1755000000)
		binary.BigEndian.PutUint32(rec[4:8], uint32(123456789+i))
		binary.BigEndian.PutUint32(rec[8:12], uint32(len(data)))
		binary.BigEndian.PutUint32(rec[12:16], uint32(len(data)))
		raw = append(raw, rec...)
		raw = append(raw, data...)
	}

	path := writeTemp(t, "leaky.pcap", raw)
	pkts, err := pcapng.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	flt, err := ParseFilter("tcp port 802")
	if err != nil {
		t.Fatal(err)
	}
	res := classify(flt, pkts, []string{"lo"})
	if res.dropped != 2 {
		t.Fatalf("dropped = %d, want 2", res.dropped)
	}
	if got := res.interfaces[0]; got.ID != 0 || got.Name != "lo" || got.Captured != 4 || got.Kept != 2 {
		t.Fatalf("interface 0 = %+v", got)
	}
	if err := rewriteFiltered(path, res.kept); err != nil {
		t.Fatal(err)
	}
	out, err := pcapng.ReadFile(path)
	if err != nil {
		t.Fatalf("filtered capture does not read back: %v", err)
	}
	if len(out) != 2 {
		t.Fatalf("filtered capture holds %d frames, want 2", len(out))
	}
	// The nanosecond fraction survives the rewrite: 123456789 ns, not 123456 µs.
	if ns := out[0].Time.Nanosecond(); ns != 123456789 {
		t.Errorf("first frame nanoseconds = %d, wanted the original 123456789", ns)
	}
	if out[1].Time.Nanosecond() != 123456791 {
		t.Errorf("second kept frame is the wrong record: %v", out[1].Time)
	}
}

// TestRewriteFilteredRefusesAMismatchedMask: the mask and the file have to
// describe the same frames, or the rewrite would delete the wrong ones. It is
// a programming error, and it must be loud rather than silently plausible.
func TestRewriteFilteredRefusesAMismatchedMask(t *testing.T) {
	file, keep := leakyCapture(binary.LittleEndian)
	original := file.bytes()
	path := writeTemp(t, "leaky.pcapng", original)

	if err := rewriteFiltered(path, keep[:len(keep)-1]); err == nil {
		t.Fatal("rewriteFiltered accepted a keep mask shorter than the file")
	}
	if err := rewriteFiltered(path, append(keep, true)); err == nil {
		t.Fatal("rewriteFiltered accepted a keep mask longer than the file")
	}
	// A refused rewrite must leave the capture exactly as it was.
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, original) {
		t.Error("a failed rewrite damaged the original capture")
	}
	// And it must not leave its scratch file behind for the manifest to find.
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.Contains(e.Name(), ".refilter-") {
			t.Errorf("a failed rewrite left %s behind", e.Name())
		}
	}
}

// ---------------------------------------------------------------------------
// the Stop path
// ---------------------------------------------------------------------------

// TestRefilterUpdatesTheSummary drives the hygiene pass exactly as Stop does,
// without needing a live capture tool, and checks that what the summary says
// is what the file holds — because Summary.Packets is what bundle.Verify
// re-checks against the pcap in the bundle.
func TestRefilterUpdatesTheSummary(t *testing.T) {
	file, keep := leakyCapture(binary.LittleEndian)
	path := writeTemp(t, "run.pcapng", file.bytes())

	c := &Capture{
		tool:    Tool{Name: "dumpcap"},
		ifaces:  []string{"wlp2s0", "enp1s0"},
		filter:  "tcp port 802",
		outPath: path,
	}
	var sum Summary
	pkts, err := c.describeFile(&sum)
	if err != nil {
		t.Fatal(err)
	}
	beforeBytes, beforePackets := sum.FileBytes, sum.Packets
	if beforePackets != len(keep) {
		t.Fatalf("describeFile read %d frames, want %d", beforePackets, len(keep))
	}

	if err := c.refilter(&sum, pkts); err != nil {
		t.Fatal(err)
	}

	wantKept := 0
	for _, k := range keep {
		if k {
			wantKept++
		}
	}
	if sum.Packets != wantKept {
		t.Errorf("Summary.Packets = %d, want the %d frames in the filtered file", sum.Packets, wantKept)
	}
	if sum.FileBytes >= beforeBytes {
		t.Errorf("Summary.FileBytes = %d, want less than the unfiltered %d", sum.FileBytes, beforeBytes)
	}
	if got, err := pcapng.ReadFile(path); err != nil {
		t.Fatalf("filtered capture does not read back: %v", err)
	} else if len(got) != sum.Packets {
		t.Errorf("file holds %d frames but the summary records %d", len(got), sum.Packets)
	}
	if sum.RefilterDropped() != 5 {
		t.Errorf("RefilterDropped() = %d, want 5", sum.RefilterDropped())
	}
	if sum.RefilterUndecided() != 1 {
		t.Errorf("RefilterUndecided() = %d, want 1", sum.RefilterUndecided())
	}
	if !sum.FilterUnarmed() {
		t.Error("FilterUnarmed() = false on a capture that carried unrelated traffic")
	}
	if got := sum.UnarmedInterfaces(); len(got) != 2 || got[0] != "wlp2s0" {
		t.Errorf("UnarmedInterfaces() = %v", got)
	}
	// First/last frame times must describe the filtered file, not the raw one.
	if !sum.FirstPacket.Equal(pkts[0].Time) {
		t.Errorf("FirstPacket = %v, want the first KEPT frame's time %v", sum.FirstPacket, pkts[0].Time)
	}
}

// TestRefilterLeavesACleanCaptureAlone: on a healthy bench nothing is dropped,
// and then the bundle must ship the exact bytes the capture tool wrote.
func TestRefilterLeavesACleanCaptureAlone(t *testing.T) {
	f := newNGFile(binary.LittleEndian)
	f.addSHB()
	f.addIDB(netdis.LinkTypeEthernet, "lo")
	tick := uint64(1755000000) * 1e6
	f.addEPB(0, tick+1, tcpFrame(addrBench, addrDUT, 51422, 802))
	f.addEPB(0, tick+2, tcpFrame(addrDUT, addrBench, 802, 51422))
	original := f.bytes()
	path := writeTemp(t, "clean.pcapng", original)

	c := &Capture{tool: Tool{Name: "dumpcap"}, ifaces: []string{"lo"}, filter: "tcp port 802", outPath: path}
	var sum Summary
	pkts, err := c.describeFile(&sum)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.refilter(&sum, pkts); err != nil {
		t.Fatal(err)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, original) {
		t.Error("a capture with nothing to drop was rewritten anyway")
	}
	if sum.RefilterDropped() != 0 || sum.FilterUnarmed() {
		t.Errorf("a clean capture reports drops: %+v", sum.Interfaces)
	}
	// The per-interface accounting is still recorded: "2 captured, 2 kept" is
	// a measurement, and its absence would be indistinguishable from silence.
	if len(sum.Interfaces) != 1 || sum.Interfaces[0].Captured != 2 || sum.Interfaces[0].Kept != 2 {
		t.Errorf("Interfaces = %+v", sum.Interfaces)
	}
}

// TestRefilterWithNoFilterKeepsEverything: an unfiltered capture is a
// deliberate choice (it is the tool's default) and the hygiene pass must not
// quietly become a filter of its own.
func TestRefilterWithNoFilterKeepsEverything(t *testing.T) {
	file, _ := leakyCapture(binary.LittleEndian)
	original := file.bytes()
	path := writeTemp(t, "unfiltered.pcapng", original)

	c := &Capture{tool: Tool{Name: "dumpcap"}, ifaces: []string{"wlp2s0", "enp1s0"}, outPath: path}
	var sum Summary
	pkts, err := c.describeFile(&sum)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.refilter(&sum, pkts); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, original) {
		t.Error("an unfiltered capture was rewritten")
	}
	if sum.RefilterDropped() != 0 {
		t.Errorf("RefilterDropped() = %d with no filter", sum.RefilterDropped())
	}
	total := 0
	for _, in := range sum.Interfaces {
		total += in.Captured
		if in.Captured != in.Kept {
			t.Errorf("interface %d kept %d of %d frames with no filter", in.ID, in.Kept, in.Captured)
		}
	}
	if total != len(pkts) {
		t.Errorf("per-interface counts total %d, want %d", total, len(pkts))
	}
}

// TestInterfaceNameFallsBackToTheID: a file with more interfaces than the
// command line had -i flags is reported by number rather than guessed at.
func TestInterfaceNameFallsBackToTheID(t *testing.T) {
	if got := interfaceName([]string{"lo"}, 0); got != "lo" {
		t.Errorf("interfaceName = %q, want lo", got)
	}
	if got := interfaceName([]string{"lo"}, 3); got != "" {
		t.Errorf("interfaceName for an unknown id = %q, want empty", got)
	}
	if got := interfaceName(nil, 0); got != "" {
		t.Errorf("interfaceName with no names = %q, want empty", got)
	}
}

// TestClassifyRecordsATapThatDeliveredNothing: on a split bench an interface
// that captured zero frames is a finding — a NIC that is down, mis-cabled, or
// carrying the traffic on the other one — and it is invisible if the row only
// appears once a frame arrives on it.
func TestClassifyRecordsATapThatDeliveredNothing(t *testing.T) {
	f := newNGFile(binary.LittleEndian)
	f.addSHB()
	f.addIDB(netdis.LinkTypeEthernet, "wlp2s0")
	f.addIDB(netdis.LinkTypeEthernet, "enp1s0")
	f.addEPB(0, uint64(1755000000)*1e6, tcpFrame(addrBench, addrDUT, 51422, 802))

	path := writeTemp(t, "onesided.pcapng", f.bytes())
	pkts, err := pcapng.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	flt, err := ParseFilter("tcp port 802")
	if err != nil {
		t.Fatal(err)
	}
	res := classify(flt, pkts, []string{"wlp2s0", "enp1s0"})

	if len(res.interfaces) != 2 {
		t.Fatalf("interfaces = %+v, want both taps listed", res.interfaces)
	}
	want := InterfaceFrames{ID: 1, Name: "enp1s0"}
	if res.interfaces[1] != want {
		t.Errorf("silent tap = %+v, want %+v", res.interfaces[1], want)
	}
}

// TestCopyKeptRefusesCorruption: the rewrite reads length fields out of the
// file it is about to replace. A length that cannot be honoured has to stop it,
// not be honoured approximately — writing a plausible-looking evidence file out
// of a corrupt one is the worst outcome available.
func TestCopyKeptRefusesCorruption(t *testing.T) {
	good := func() []byte {
		f := newNGFile(binary.LittleEndian)
		f.addSHB()
		f.addIDB(netdis.LinkTypeEthernet, "lo")
		f.addEPB(0, uint64(1755000000)*1e6, tcpFrame(addrBench, addrDUT, 51422, 802))
		return f.bytes()
	}

	for _, tc := range []struct {
		name    string
		corrupt func([]byte) []byte
	}{
		{"block length below the framing", func(b []byte) []byte {
			binary.LittleEndian.PutUint32(b[4:8], 12)
			return b
		}},
		{"block length not aligned", func(b []byte) []byte {
			binary.LittleEndian.PutUint32(b[4:8], 29)
			return b
		}},
		{"trailer disagrees with the header", func(b []byte) []byte {
			binary.LittleEndian.PutUint32(b[24:28], 999)
			return b
		}},
		{"file ends inside a block", func(b []byte) []byte { return b[:len(b)-6] }},
		{"not a capture at all", func(b []byte) []byte { return []byte("not a capture") }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := writeTemp(t, "corrupt.pcapng", tc.corrupt(good()))
			if err := rewriteFiltered(path, []bool{false}); err == nil {
				t.Fatal("rewriteFiltered accepted a corrupt capture")
			}
		})
	}
}
