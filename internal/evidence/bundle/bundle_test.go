package bundle

import (
	"encoding/binary"
	"encoding/json"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"csip-tls-test/internal/evidence/capture"
	"csip-tls-test/internal/evidence/netdis"
	"csip-tls-test/internal/evidence/pcapng"
)

// --- synthetic capture ----------------------------------------------------

const (
	desktopIP  = "69.0.0.20"
	gatewayIP  = "69.0.0.2"
	clientPort = 51422
	mbapsPort  = 802
)

// pcapngWriter emits the minimum pcapng a reader needs: one section, one
// Ethernet interface, and Enhanced Packet Blocks.
type pcapngWriter struct{ buf []byte }

func (w *pcapngWriter) u16(v uint16) []byte {
	b := make([]byte, 2)
	binary.LittleEndian.PutUint16(b, v)
	return b
}

func (w *pcapngWriter) u32(v uint32) []byte {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, v)
	return b
}

func (w *pcapngWriter) block(btype uint32, body []byte) {
	for len(body)%4 != 0 {
		body = append(body, 0)
	}
	total := uint32(12 + len(body))
	w.buf = append(w.buf, w.u32(btype)...)
	w.buf = append(w.buf, w.u32(total)...)
	w.buf = append(w.buf, body...)
	w.buf = append(w.buf, w.u32(total)...)
}

func newPcapngWriter() *pcapngWriter {
	w := &pcapngWriter{}
	shb := append([]byte(nil), w.u32(0x1A2B3C4D)...)
	shb = append(shb, w.u16(1)...)
	shb = append(shb, w.u16(0)...)
	shb = append(shb, []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}...)
	w.block(0x0A0D0D0A, shb)

	idb := append([]byte(nil), w.u16(1)...) // LINKTYPE_ETHERNET
	idb = append(idb, w.u16(0)...)
	idb = append(idb, w.u32(0)...) // no snaplen limit
	w.block(0x00000001, idb)
	return w
}

func (w *pcapngWriter) packet(ticksMicros uint64, data []byte) {
	body := append([]byte(nil), w.u32(0)...)
	body = append(body, w.u32(uint32(ticksMicros>>32))...)
	body = append(body, w.u32(uint32(ticksMicros))...)
	body = append(body, w.u32(uint32(len(data)))...)
	body = append(body, w.u32(uint32(len(data)))...)
	body = append(body, data...)
	w.block(0x00000006, body)
}

func ethIPv4TCP(srcIP, dstIP string, sport, dport uint16, seq uint32, flags byte, payload []byte) []byte {
	tcp := make([]byte, 20)
	binary.BigEndian.PutUint16(tcp[0:2], sport)
	binary.BigEndian.PutUint16(tcp[2:4], dport)
	binary.BigEndian.PutUint32(tcp[4:8], seq)
	tcp[12] = 5 << 4
	tcp[13] = flags
	binary.BigEndian.PutUint16(tcp[14:16], 0xFFFF)
	tcp = append(tcp, payload...)

	ip := make([]byte, 20)
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:4], uint16(20+len(tcp)))
	ip[8] = 64
	ip[9] = 6
	copy(ip[12:16], parseIP(srcIP))
	copy(ip[16:20], parseIP(dstIP))
	ip = append(ip, tcp...)

	eth := make([]byte, 14)
	binary.BigEndian.PutUint16(eth[12:14], 0x0800)
	return append(eth, ip...)
}

func parseIP(s string) []byte {
	var out []byte
	for _, part := range strings.Split(s, ".") {
		n := 0
		for _, c := range part {
			n = n*10 + int(c-'0')
		}
		out = append(out, byte(n))
	}
	return out
}

// mbapsRequest / mbapsResponse are realistic Modbus/TCP payloads: a write to a
// holding register, and the exception 01 an authorization failure returns.
var (
	mbapsRequest  = []byte{0x00, 0x01, 0x00, 0x00, 0x00, 0x09, 0x01, 0x10, 0x00, 0x64, 0x00, 0x01, 0x02, 0x01, 0xF4}
	mbapsResponse = []byte{0x00, 0x01, 0x00, 0x00, 0x00, 0x03, 0x01, 0x90, 0x01}
)

// writeSyntheticCapture lays down a five-frame conversation: SYN, SYN/ACK, the
// request, the exception response, FIN.
func writeSyntheticCapture(t *testing.T, path string) []pcapng.Packet {
	t.Helper()
	w := newPcapngWriter()
	const isn, risn = uint32(1000), uint32(5000)
	base := uint64(1_700_000_000_000_000)
	w.packet(base+0, ethIPv4TCP(desktopIP, gatewayIP, clientPort, mbapsPort, isn, 0x02, nil))
	w.packet(base+100, ethIPv4TCP(gatewayIP, desktopIP, mbapsPort, clientPort, risn, 0x12, nil))
	w.packet(base+200, ethIPv4TCP(desktopIP, gatewayIP, clientPort, mbapsPort, isn+1, 0x18, mbapsRequest))
	w.packet(base+300, ethIPv4TCP(gatewayIP, desktopIP, mbapsPort, clientPort, risn+1, 0x18, mbapsResponse))
	w.packet(base+400, ethIPv4TCP(desktopIP, gatewayIP, clientPort, mbapsPort, isn+1+uint32(len(mbapsRequest)), 0x11, nil))

	if err := os.WriteFile(path, w.buf, 0o644); err != nil {
		t.Fatal(err)
	}
	pkts, err := pcapng.ReadFile(path)
	if err != nil {
		t.Fatalf("synthetic capture does not read back: %v", err)
	}
	if len(pkts) != 5 {
		t.Fatalf("synthetic capture has %d packets, want 5", len(pkts))
	}
	return pkts
}

// buildBundle produces a complete, verifiable bundle in a temp directory.
func buildBundle(t *testing.T) (dir string, capturePath string, pkts []pcapng.Packet) {
	t.Helper()
	work := t.TempDir()
	capturePath = filepath.Join(work, "run.pcapng")
	pkts = writeSyntheticCapture(t, capturePath)

	keylogPath := filepath.Join(work, "evidence.keylog")
	if err := os.WriteFile(keylogPath, []byte("# no TLS in this fixture\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	asm := netdis.NewAssembler()
	for _, p := range pkts {
		if _, err := asm.AddPacket(p); err != nil {
			t.Fatalf("frame %d: %v", p.Index, err)
		}
	}
	streams := asm.FindPort(mbapsPort)
	if len(streams) != 1 {
		t.Fatalf("found %d streams", len(streams))
	}
	st := streams[0]
	toGateway := st.ByFlow(netdis.FlowKey{
		Src: netdis.Endpoint{Addr: mustAddr(desktopIP), Port: clientPort},
		Dst: netdis.Endpoint{Addr: mustAddr(gatewayIP), Port: mbapsPort},
	})
	fromGateway := st.ByFlow(netdis.FlowKey{
		Src: netdis.Endpoint{Addr: mustAddr(gatewayIP), Port: mbapsPort},
		Dst: netdis.Endpoint{Addr: mustAddr(desktopIP), Port: clientPort},
	})

	reqAssert, err := CiteBytes(
		"The aggregator issued a write to holding register 100 as role GridService.",
		"Modbus/TCP function 0x10 in the reassembled request stream",
		Pass, "write single register 100 = 500",
		StreamRef(toGateway), toGateway.Bytes, 0, len(mbapsRequest))
	if err != nil {
		t.Fatal(err)
	}
	respAssert, err := CiteBytes(
		"The gateway refused the write with Modbus exception 01 (illegal function / not authorized).",
		"Modbus/TCP response byte 7 has the exception bit set and byte 8 is 0x01",
		Pass, "function 0x90, exception 0x01",
		StreamRef(fromGateway), fromGateway.Bytes, 0, len(mbapsResponse))
	if err != nil {
		t.Fatal(err)
	}
	synAssert, err := CiteFrames(
		"The session was opened to port 802.",
		"TCP SYN to the mbaps port",
		Pass, "SYN from 69.0.0.20:51422 to 69.0.0.2:802", pkts, []int{1, 2})
	if err != nil {
		t.Fatal(err)
	}

	b := NewBuilder(RunMeta{
		Tool: "evidence-engine-test", ToolVersion: "0.0.1",
		Operator: "bench", Note: "synthetic fixture",
		Started:  time.Unix(1_700_000_000, 0).UTC(),
		Finished: time.Unix(1_700_000_060, 0).UTC(),
		DUT:      DUT{Name: "lexa-gw", Address: "69.0.0.2:802", Role: "device", Build: "test"},
	})
	b.SetCapture(capture.Summary{
		Tool: "dumpcap", ToolVersion: "4.2.2", Interface: "enp1s0",
		Filter: "tcp port 802", Packets: len(pkts), Format: "pcapng", FileBytes: 1234,
	}, capturePath)
	b.SetKeyLog(keylogPath)
	b.AddCase(TestCaseResult{
		ID: "RBAC-004", Doc: "Secure SunSpec Modbus v1.0 §5.3", Title: "Unauthorized write is refused",
		Assertions: []Assertion{reqAssert, respAssert},
	})
	b.AddCase(TestCaseResult{
		ID: "SunSpecTCP-1", Doc: "Secure SunSpec Modbus v1.0 §5.1", Title: "Port 802 is used",
		Assertions: []Assertion{synAssert},
	})
	b.AddCase(TestCaseResult{
		ID: "SunSpecTCP-3", Title: "Secure cert add/remove", Verdict: Skip,
		Assertions: []Assertion{{
			Claim:  "The device supports secure addition and removal of root certificates.",
			Method: "out-of-band administrative capability", Verdict: Skip,
			Observed: "not observable on the wire",
		}},
	})

	dir = filepath.Join(work, "bundle")
	if _, err := b.Write(dir); err != nil {
		t.Fatalf("Write: %v", err)
	}
	return dir, capturePath, pkts
}

func mustAddr(s string) netip.Addr { return netip.MustParseAddr(s) }

// --- tests ----------------------------------------------------------------

func TestWriteAndVerify(t *testing.T) {
	dir, _, _ := buildBundle(t)

	for _, name := range []string{BundleFile, ReportFile, ManifestFile} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Fatalf("%s missing: %v", name, err)
		}
	}
	b, err := Load(dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if b.Schema != SchemaVersion {
		t.Errorf("Schema = %q", b.Schema)
	}
	if len(b.Cases) != 3 {
		t.Fatalf("got %d cases", len(b.Cases))
	}
	// Verdicts must roll up from the assertions when not set explicitly.
	if b.Cases[0].Verdict != Pass || b.Cases[2].Verdict != Skip {
		t.Errorf("verdicts = %s / %s", b.Cases[0].Verdict, b.Cases[2].Verdict)
	}
	pass, fail, skip, warn, _ := b.Counts()
	if pass != 2 || fail != 0 || skip != 1 || warn != 0 {
		t.Errorf("counts = %d/%d/%d/%d", pass, fail, skip, warn)
	}
	if !b.OK() {
		t.Error("OK() = false for a bundle with no failures")
	}
	// The capture and key log must have been copied in, and the recorded path
	// must be the one inside the bundle.
	if b.Files.Capture != "capture/run.pcapng" || b.Files.KeyLog != "capture/evidence.keylog" {
		t.Fatalf("Files = %+v", b.Files)
	}
	if b.Capture.Path != b.Files.Capture {
		t.Errorf("capture summary path = %q, want the in-bundle path", b.Capture.Path)
	}

	rep, err := Verify(dir)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !rep.OK {
		t.Fatalf("Verify failed:\n%s", rep)
	}
	if rep.Packets != 5 {
		t.Errorf("Packets = %d", rep.Packets)
	}
	if rep.Checked != 3 {
		t.Errorf("Checked = %d, want the 3 assertions carrying digests", rep.Checked)
	}
	if rep.Unverifiable != 1 {
		t.Errorf("Unverifiable = %d, want the 1 narrative assertion", rep.Unverifiable)
	}
	if len(rep.Files) != 4 {
		t.Errorf("checked %d files, want bundle.json, REPORT.md and the two capture artefacts", len(rep.Files))
	}
	if !strings.Contains(rep.String(), "VERIFIED") {
		t.Errorf("report:\n%s", rep)
	}
}

// TestVerifyDetectsTamperedCapture is the headline property: edit the evidence
// and the bundle stops verifying.
func TestVerifyDetectsTamperedCapture(t *testing.T) {
	dir, _, _ := buildBundle(t)
	inBundle := filepath.Join(dir, "capture", "run.pcapng")
	data, err := os.ReadFile(inBundle)
	if err != nil {
		t.Fatal(err)
	}
	// Flip a bit inside the exception code of the Modbus response.
	idx := indexOf(data, mbapsResponse)
	if idx < 0 {
		t.Fatal("could not find the response payload in the capture")
	}
	data[idx+8] = 0x02 // exception 01 → 02
	if err := os.WriteFile(inBundle, data, 0o644); err != nil {
		t.Fatal(err)
	}

	rep, err := Verify(dir)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if rep.OK {
		t.Fatal("a tampered capture must not verify")
	}
	if len(rep.Problems) == 0 {
		t.Error("no problem reported")
	}
	sawManifest := false
	for _, f := range rep.Files {
		if strings.HasSuffix(f.Name, "run.pcapng") && !f.OK {
			sawManifest = true
		}
	}
	if !sawManifest {
		t.Error("the manifest check should have caught the edited capture")
	}

	// And with the manifest regenerated — the tamperer covering their tracks —
	// the byte-range digests must still catch it.
	if err := WriteManifest(dir); err != nil {
		t.Fatal(err)
	}
	rep, err = Verify(dir)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if rep.OK {
		t.Fatal("re-hashing the manifest must not launder a tampered capture: the assertion digests still cover it")
	}
	found := false
	for _, a := range rep.Assertions {
		if !a.OK && strings.Contains(a.Detail, "hash to") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected a byte-digest mismatch; got:\n%s", rep)
	}
}

func TestVerifyDetectsUnlistedFile(t *testing.T) {
	dir, _, _ := buildBundle(t)
	if err := os.WriteFile(filepath.Join(dir, "smuggled.txt"), []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}
	rep, err := Verify(dir)
	if err != nil {
		t.Fatal(err)
	}
	if rep.OK {
		t.Fatal("a file that is not in the manifest must fail verification")
	}
	if !strings.Contains(strings.Join(rep.Problems, " "), "smuggled.txt") {
		t.Errorf("problems = %v", rep.Problems)
	}
}

func TestVerifyDetectsMissingFile(t *testing.T) {
	dir, _, _ := buildBundle(t)
	if err := os.Remove(filepath.Join(dir, "capture", "evidence.keylog")); err != nil {
		t.Fatal(err)
	}
	rep, err := Verify(dir)
	if err != nil {
		t.Fatal(err)
	}
	if rep.OK {
		t.Fatal("a missing file must fail verification")
	}
}

// editBundle rewrites bundle.json through a callback and refreshes the manifest
// so the resulting failure is the assertion check, not the file hashes.
func editBundle(t *testing.T, dir string, fn func(*Bundle)) {
	t.Helper()
	b, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	fn(b)
	data, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, BundleFile), append(data, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := WriteManifest(dir); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyDetectsBadCitations(t *testing.T) {
	for _, tc := range []struct {
		name       string
		mutate     func(*Bundle)
		wantDetail string
	}{
		{
			name:       "frame that does not exist",
			mutate:     func(b *Bundle) { b.Cases[1].Assertions[0].Frames = []int{1, 999} },
			wantDetail: "does not contain",
		},
		{
			name:       "wrong byte digest",
			mutate:     func(b *Bundle) { b.Cases[0].Assertions[1].BytesSHA256 = strings.Repeat("00", 32) },
			wantDetail: "hash to",
		},
		{
			name:       "wrong frame digest",
			mutate:     func(b *Bundle) { b.Cases[1].Assertions[0].FramesSHA256 = strings.Repeat("11", 32) },
			wantDetail: "hash to",
		},
		{
			name:       "stream that is not in the capture",
			mutate:     func(b *Bundle) { b.Cases[0].Assertions[0].StreamRef = "1.2.3.4:1 > 5.6.7.8:2" },
			wantDetail: "does not contain",
		},
		{
			name:       "byte range past the end of the stream",
			mutate:     func(b *Bundle) { b.Cases[0].Assertions[0].ByteRange = [2]int{0, 9999} },
			wantDetail: "outside the",
		},
		{
			name: "right bytes, wrong frames",
			mutate: func(b *Bundle) {
				// The digest still matches, but the frames cited are not the
				// ones those bytes arrived in — a reviewer sent to the wrong
				// place is exactly as misled as one given wrong bytes.
				b.Cases[0].Assertions[0].Frames = []int{1}
			},
			wantDetail: "were carried in frames",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir, _, _ := buildBundle(t)
			editBundle(t, dir, tc.mutate)
			rep, err := Verify(dir)
			if err != nil {
				t.Fatal(err)
			}
			if rep.OK {
				t.Fatalf("verification passed a broken citation:\n%s", rep)
			}
			joined := ""
			for _, a := range rep.Assertions {
				joined += a.Detail + "\n"
			}
			if !strings.Contains(joined, tc.wantDetail) {
				t.Fatalf("details:\n%swant one containing %q", joined, tc.wantDetail)
			}
		})
	}
}

// TestVerifyRejectsConflictingOverlap: a capture in which two segments claim
// the same sequence range with different bytes is not something to certify
// from, whatever the assertions say.
func TestVerifyRejectsConflictingOverlap(t *testing.T) {
	dir, capturePath, _ := buildBundle(t)

	// Rebuild the capture with an extra segment that overwrites the response's
	// exception code at the same sequence number.
	w := newPcapngWriter()
	const isn, risn = uint32(1000), uint32(5000)
	base := uint64(1_700_000_000_000_000)
	w.packet(base+0, ethIPv4TCP(desktopIP, gatewayIP, clientPort, mbapsPort, isn, 0x02, nil))
	w.packet(base+100, ethIPv4TCP(gatewayIP, desktopIP, mbapsPort, clientPort, risn, 0x12, nil))
	w.packet(base+200, ethIPv4TCP(desktopIP, gatewayIP, clientPort, mbapsPort, isn+1, 0x18, mbapsRequest))
	w.packet(base+300, ethIPv4TCP(gatewayIP, desktopIP, mbapsPort, clientPort, risn+1, 0x18, mbapsResponse))
	forged := append([]byte(nil), mbapsResponse...)
	forged[8] = 0x00 // "no exception" — the tamperer's preferred reading
	w.packet(base+350, ethIPv4TCP(gatewayIP, desktopIP, mbapsPort, clientPort, risn+1, 0x18, forged))
	if err := os.WriteFile(capturePath, w.buf, 0o644); err != nil {
		t.Fatal(err)
	}
	// Copy it in and refresh the manifest, so only the overlap check can fail.
	if err := copyFile(capturePath, filepath.Join(dir, "capture", "run.pcapng")); err != nil {
		t.Fatal(err)
	}
	editBundle(t, dir, func(b *Bundle) { b.Capture.Packets = 6 })

	rep, err := Verify(dir)
	if err != nil {
		t.Fatal(err)
	}
	if rep.OK {
		t.Fatal("a capture with conflicting overlapping segments must not verify")
	}
	if !strings.Contains(strings.Join(rep.Problems, " "), "CONFLICTING") {
		t.Errorf("problems = %v", rep.Problems)
	}
}

func TestVerifyDetectsPacketCountMismatch(t *testing.T) {
	dir, _, _ := buildBundle(t)
	editBundle(t, dir, func(b *Bundle) { b.Capture.Packets = 99 })
	rep, err := Verify(dir)
	if err != nil {
		t.Fatal(err)
	}
	if rep.OK {
		t.Fatal("a packet-count mismatch must fail verification")
	}
}

func TestReportCitesFramesInline(t *testing.T) {
	dir, _, _ := buildBundle(t)
	data, err := os.ReadFile(filepath.Join(dir, ReportFile))
	if err != nil {
		t.Fatal(err)
	}
	report := string(data)
	for _, want := range []string{
		"RBAC-004", "Unauthorized write is refused",
		"Frames:", "Bytes sha256:", "69.0.0.2:802 > 69.0.0.20:51422",
		"sha256sum -c MANIFEST.sha256", "no digest",
		"lexa-gw", "69.0.0.2:802", "dumpcap",
	} {
		if !strings.Contains(report, want) {
			t.Errorf("REPORT.md does not mention %q", want)
		}
	}
	if strings.Contains(report, "%!") {
		t.Error("REPORT.md contains a formatting error")
	}
}

// TestManifestIsSha256sumCompatible: a reader with no Go toolchain must be able
// to check the manifest with the coreutils tool.
func TestManifestIsSha256sumCompatible(t *testing.T) {
	sha, err := exec.LookPath("sha256sum")
	if err != nil {
		t.Skip("sha256sum not available")
	}
	dir, _, _ := buildBundle(t)
	cmd := exec.Command(sha, "-c", ManifestFile)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("sha256sum -c failed: %v\n%s", err, out)
	}
	if strings.Contains(string(out), "FAILED") {
		t.Fatalf("sha256sum reported failures:\n%s", out)
	}
}

func TestLoadRejectsForeignSchema(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, BundleFile), []byte(`{"schema":"something-else"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(dir); err == nil || !strings.Contains(err.Error(), "schema") {
		t.Fatalf("err = %v, want a schema complaint", err)
	}
	if err := os.WriteFile(filepath.Join(dir, BundleFile), []byte(`{"schema":"`+SchemaVersion+`","surprise":1}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(dir); err == nil {
		t.Fatal("an unknown field must be rejected: a verifier that ignores what it does not understand is not a verifier")
	}
	if _, err := Verify(t.TempDir()); err == nil {
		t.Fatal("Verify of a directory with no bundle.json must fail")
	}
}

func TestCitationConstructors(t *testing.T) {
	work := t.TempDir()
	path := filepath.Join(work, "x.pcapng")
	pkts := writeSyntheticCapture(t, path)

	if _, err := CiteFrames("c", "m", Pass, "o", pkts, []int{1, 42}); err == nil {
		t.Error("citing a frame that does not exist must fail at authoring time")
	}
	a, err := CiteFrames("c", "m", Pass, "o", pkts, []int{3, 1})
	if err != nil {
		t.Fatal(err)
	}
	if a.Frames[0] != 1 || a.Frames[1] != 3 {
		t.Errorf("Frames = %v, want them sorted", a.Frames)
	}
	if !a.Citable() {
		t.Error("a frame citation with a digest must be Citable")
	}

	asm := netdis.NewAssembler()
	for _, p := range pkts {
		if _, err := asm.AddPacket(p); err != nil {
			t.Fatal(err)
		}
	}
	d := asm.FindPort(mbapsPort)[0].Dirs[0]
	if _, err := CiteBytes("c", "m", Pass, "o", StreamRef(d), d.Bytes, 0, 9999); err == nil {
		t.Error("citing a byte range past the end of a stream must fail at authoring time")
	}
	if (Assertion{}).Citable() {
		t.Error("an assertion with no digest must not be Citable")
	}
}

func TestRollUpAndSeverity(t *testing.T) {
	tc := TestCaseResult{Assertions: []Assertion{{Verdict: Pass}, {Verdict: Warn}, {Verdict: Pass}}}
	if got := tc.RollUp(); got != Warn {
		t.Errorf("RollUp = %s, want WARN", got)
	}
	tc.Assertions = append(tc.Assertions, Assertion{Verdict: Fail})
	if got := tc.RollUp(); got != Fail {
		t.Errorf("RollUp = %s, want FAIL", got)
	}
	if (TestCaseResult{}).RollUp() != Skip {
		t.Error("a case with no assertions rolls up to SKIP")
	}
	if Fail.Severity() <= Warn.Severity() || Warn.Severity() <= Pass.Severity() || Pass.Severity() <= Skip.Severity() {
		t.Error("verdict severity order is wrong")
	}
}

func TestBuilderRefusesEmptyDir(t *testing.T) {
	b := NewBuilder(RunMeta{Tool: "t"})
	if _, err := b.Write(""); err == nil {
		t.Fatal("Write with no directory must fail")
	}
}

func TestGitCommit(t *testing.T) {
	// The repository this test runs in is a git checkout, so this should
	// succeed; outside one it must degrade quietly rather than fail.
	commit, _ := GitCommit(".")
	if commit != "" && len(commit) != 40 {
		t.Errorf("GitCommit = %q, want a 40-character sha or empty", commit)
	}
	if c, d := GitCommit(t.TempDir()); c != "" || d {
		t.Errorf("GitCommit outside a checkout = %q,%t", c, d)
	}
}

func indexOf(haystack, needle []byte) int {
outer:
	for i := 0; i+len(needle) <= len(haystack); i++ {
		for j := range needle {
			if haystack[i+j] != needle[j] {
				continue outer
			}
		}
		return i
	}
	return -1
}

// TestWriteDoesNotDestroyACaptureAlreadyInsideTheBundle pins the fix for a bug
// that silently destroyed a whole run's evidence.
//
// The obvious way to invoke a conformance run is `-out runs/<ts>/`, and the
// runner writes its capture to `<out>/capture/run-<ts>.pcapng` — precisely the
// path Write copies the capture TO. os.Create truncates first, so with source
// and destination the same file the capture became zero bytes: the console had
// already reported the frames it counted, the bundle looked complete, and every
// citation in it was unverifiable. Nothing about that failure is loud, which is
// why it gets a test of its own.
func TestWriteDoesNotDestroyACaptureAlreadyInsideTheBundle(t *testing.T) {
	dir := t.TempDir()
	capturePath := filepath.Join(dir, CaptureDir, "run.pcapng")
	if err := os.MkdirAll(filepath.Dir(capturePath), 0o755); err != nil {
		t.Fatal(err)
	}
	pkts := writeSyntheticCapture(t, capturePath)
	before, err := os.ReadFile(capturePath)
	if err != nil {
		t.Fatal(err)
	}

	syn, err := CiteFrames("The session was opened.", "TCP SYN", Pass,
		"SYN observed", pkts, []int{1})
	if err != nil {
		t.Fatal(err)
	}

	b := NewBuilder(RunMeta{Tool: "same-file-test", ToolVersion: "1"})
	b.SetCapture(capture.Summary{
		Tool: "dumpcap", Interface: "lo", Packets: len(pkts), Format: "pcapng",
	}, capturePath)
	b.AddCase(TestCaseResult{ID: "X-1", Title: "the capture survives its own bundle",
		Verdict: Pass, Assertions: []Assertion{syn}})

	// dir is BOTH the bundle directory and the capture's home — the default
	// shape of a `-out runs/<ts>/` invocation.
	if _, err := b.Write(dir); err != nil {
		t.Fatalf("Write: %v", err)
	}

	after, err := os.ReadFile(capturePath)
	if err != nil {
		t.Fatalf("the capture is gone after Write: %v", err)
	}
	if len(after) == 0 {
		t.Fatal("Write truncated the capture to zero bytes — the run's evidence was destroyed by its own bundle")
	}
	if len(after) != len(before) {
		t.Errorf("the capture changed during Write: %d bytes before, %d after", len(before), len(after))
	}
	rep, err := Verify(dir)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !rep.OK {
		t.Errorf("a bundle whose capture already lived inside it does not verify:\n%s", rep.String())
	}
	if rep.Checked == 0 {
		t.Error("nothing was re-checked against the capture")
	}
}

// TestBundleRecordsItsOwnInvocation: the bundle already recorded dumpcap's
// whole argv and nothing at all about the command that chose the interface,
// the filter, the selection and the targets. Two bundles that disagree are most
// often two different command lines, and telling them apart used to mean
// finding the operator.
func TestBundleRecordsItsOwnInvocation(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "bundle")
	b := NewBuilder(RunMeta{
		Tool: "invocation-test",
		Command: RedactCommand([]string{
			"certify", "-doc", "SSM-CONF-v0.8", "-gateway-ssh", "cc93",
			"-bpf", "tcp port 802", "-param", "lab.token=hunter2",
		}),
	})
	b.AddCase(TestCaseResult{ID: "X-1", Title: "a case", Verdict: Skip,
		Assertions: []Assertion{{Claim: "narrative", Verdict: Skip, Observed: "off wire"}}})
	if _, err := b.Write(dir); err != nil {
		t.Fatal(err)
	}

	loaded, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded.Run.Command) == 0 {
		t.Fatal("bundle.json carries no invocation")
	}
	if got := strings.Join(loaded.Run.Command, " "); !strings.Contains(got, "-doc SSM-CONF-v0.8") ||
		!strings.Contains(got, "-gateway-ssh cc93") || strings.Contains(got, "hunter2") {
		t.Errorf("recorded invocation = %q", got)
	}

	data, err := os.ReadFile(filepath.Join(dir, ReportFile))
	if err != nil {
		t.Fatal(err)
	}
	report := string(data)
	for _, want := range []string{"How this run was invoked", "-doc SSM-CONF-v0.8", "'tcp port 802'", Redacted} {
		if !strings.Contains(report, want) {
			t.Errorf("REPORT.md does not show %q:\n%s", want, report)
		}
	}
	if strings.Contains(report, "hunter2") {
		t.Error("REPORT.md prints a secret the bundle redacted")
	}
	if strings.Contains(report, "%!") {
		t.Error("REPORT.md contains a formatting error")
	}
}

// TestBundleWithoutAnInvocationStillVerifies: bundles written before the field
// existed are on disk, and a verifier that rejected them would retroactively
// invalidate evidence for a metadata gap.
func TestBundleWithoutAnInvocationStillVerifies(t *testing.T) {
	dir, _, _ := buildBundle(t)
	loaded, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded.Run.Command) != 0 {
		t.Fatal("this fixture was supposed to carry no invocation")
	}
	rep, err := Verify(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !rep.OK {
		t.Fatalf("a bundle with no recorded invocation must still verify:\n%s", rep)
	}
	data, err := os.ReadFile(filepath.Join(dir, ReportFile))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "How this run was invoked") {
		t.Error("REPORT.md invents an invocation section for a bundle that has no invocation")
	}
}
