package bundle

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"csip-tls-test/internal/evidence/capture"
	"csip-tls-test/internal/evidence/netdis"
	"csip-tls-test/internal/evidence/pcapng"
)

// --- ephemeral-port reuse regression ---------------------------------------
//
// e166ec1 ("certify: stop ephemeral-port reuse from silently reassigning
// frames across cases") fixed this ambiguity on the AUTHORING side
// (window.go's consolidateStreams, evidence.go's mayCite/CiteBytes) but named
// Verify's independent reassemble() path as an explicit, out-of-scope
// residual: "internal/evidence/bundle's independent Verify path
// (reassemble()) still keys its own Direction lookup by the bare FlowKey
// string, not InstanceKey, so a CiteBytes-based (not CiteFrames-based)
// assertion on the EARLIER of two generations sharing a port could fail
// independent re-verification even though authoring now attributes it
// correctly."
//
// This file is that residual, reproduced directly: a capture holding two
// entirely unrelated connections that happen to share a local port, a
// BytesSHA256 citation against the EARLIER one, and confirmation Verify
// resolves it against the generation that actually authored it.
//
// This exact shape hit two real compliance bundles: certify -verify failed
// runs/compliance-csip-1-20260802T024142 and
// runs/compliance-csip-2-20260802T041607 with "netdis: byte range [X,Y) is
// outside the N-byte stream" (and, for citations that happened to land
// in-range against the wrong generation, a plain hash mismatch) despite "all
// 6 files match the manifest byte for byte" — the capture was intact; only
// Verify's own reassembly picked the wrong generation.

const (
	reuseDesktop = "69.0.0.20"
	reuseGateway = "69.0.0.2"
	reusePort    = 51422
	reuseSvcPort = 802
)

// earlyPayload is deliberately LONGER than latePayload: if Verify resolves a
// citation against the wrong (later) generation instead of the one that
// authored it, Range() reports the citation "outside" the shorter stream
// rather than merely returning different bytes. That makes the pre-fix bug
// reproduce as a clean, unambiguous test failure instead of a hash mismatch
// that could in principle coincide by chance.
var (
	earlyPayload = []byte("EARLY-GENERATION-REQUEST-PAYLOAD-0123456789")
	latePayload  = []byte("LATE-PAYLOAD")
)

// writeReusedPortCapture lays down two unrelated connections sharing
// reusePort: an early one (ISN 1000) carrying earlyPayload, and — after it
// has already closed — a later one (ISN 9000) carrying the much shorter
// latePayload. The different ISN is the only thing that tells the
// reassembler a fresh connection reused the port; see
// netdis.Assembler.AddFrame.
func writeReusedPortCapture(t *testing.T, path string) []pcapng.Packet {
	t.Helper()
	w := newPcapngWriter()
	base := uint64(1_700_000_000_000_000)

	const earlyISN, earlyRISN = uint32(1000), uint32(5000)
	w.packet(base+0, ethIPv4TCP(reuseDesktop, reuseGateway, reusePort, reuseSvcPort, earlyISN, 0x02, nil))
	w.packet(base+100, ethIPv4TCP(reuseGateway, reuseDesktop, reuseSvcPort, reusePort, earlyRISN, 0x12, nil))
	w.packet(base+200, ethIPv4TCP(reuseDesktop, reuseGateway, reusePort, reuseSvcPort, earlyISN+1, 0x18, earlyPayload))
	w.packet(base+300, ethIPv4TCP(reuseGateway, reuseDesktop, reuseSvcPort, reusePort, earlyRISN+1, 0x18, []byte("OK")))
	w.packet(base+400, ethIPv4TCP(reuseDesktop, reuseGateway, reusePort, reuseSvcPort, earlyISN+1+uint32(len(earlyPayload)), 0x11, nil))
	w.packet(base+500, ethIPv4TCP(reuseGateway, reuseDesktop, reuseSvcPort, reusePort, earlyRISN+1+2, 0x11, nil))

	// The kernel recycles reusePort for an entirely unrelated later
	// connection. Only the different ISN distinguishes it from a retransmit
	// of the early SYN.
	const lateISN, lateRISN = uint32(9000), uint32(6000)
	w.packet(base+10_000, ethIPv4TCP(reuseDesktop, reuseGateway, reusePort, reuseSvcPort, lateISN, 0x02, nil))
	w.packet(base+10_100, ethIPv4TCP(reuseGateway, reuseDesktop, reuseSvcPort, reusePort, lateRISN, 0x12, nil))
	w.packet(base+10_200, ethIPv4TCP(reuseDesktop, reuseGateway, reusePort, reuseSvcPort, lateISN+1, 0x18, latePayload))
	w.packet(base+10_300, ethIPv4TCP(reuseGateway, reuseDesktop, reuseSvcPort, reusePort, lateRISN+1, 0x18, []byte("OK")))
	w.packet(base+10_400, ethIPv4TCP(reuseDesktop, reuseGateway, reusePort, reuseSvcPort, lateISN+1+uint32(len(latePayload)), 0x11, nil))
	w.packet(base+10_500, ethIPv4TCP(reuseGateway, reuseDesktop, reuseSvcPort, reusePort, lateRISN+1+2, 0x11, nil))

	if err := os.WriteFile(path, w.buf, 0o644); err != nil {
		t.Fatal(err)
	}
	pkts, err := pcapng.ReadFile(path)
	if err != nil {
		t.Fatalf("synthetic reused-port capture does not read back: %v", err)
	}
	if len(pkts) != 12 {
		t.Fatalf("synthetic capture has %d packets, want 12", len(pkts))
	}
	return pkts
}

// buildReusedPortBundle builds a bundle citing the EARLY generation's request
// bytes — the case the pre-fix Verify resolved against the wrong (later,
// shorter) generation.
func buildReusedPortBundle(t *testing.T) (dir string, pkts []pcapng.Packet) {
	t.Helper()
	work := t.TempDir()
	capturePath := filepath.Join(work, "run.pcapng")
	pkts = writeReusedPortCapture(t, capturePath)

	asm := netdis.NewAssembler()
	for _, p := range pkts {
		if _, err := asm.AddPacket(p); err != nil {
			t.Fatalf("frame %d: %v", p.Index, err)
		}
	}
	streams := asm.FindPort(reuseSvcPort)
	if len(streams) != 2 {
		t.Fatalf("got %d connection generations over port %d, want 2", len(streams), reuseSvcPort)
	}
	early, late := streams[0], streams[1]
	if early.Gen != 0 {
		t.Fatalf("streams[0].Gen = %d, want the early (first-seen) generation", early.Gen)
	}
	if late.Gen == early.Gen {
		t.Fatal("streams[1] did not get a new generation — the ISN-based reuse detection did not fire")
	}

	fwdFlow := netdis.FlowKey{
		Src: netdis.Endpoint{Addr: mustAddr(reuseDesktop), Port: reusePort},
		Dst: netdis.Endpoint{Addr: mustAddr(reuseGateway), Port: reuseSvcPort},
	}
	toGateway := early.ByFlow(fwdFlow)
	if toGateway.Bytes.Len() != len(earlyPayload) {
		t.Fatalf("early generation's forward stream has %d bytes, want %d", toGateway.Bytes.Len(), len(earlyPayload))
	}
	lateToGateway := late.ByFlow(fwdFlow)
	if lateToGateway.Bytes.Len() >= len(earlyPayload) {
		t.Fatalf("late generation's forward stream has %d bytes, want fewer than the early generation's %d "+
			"bytes (the test needs the pre-fix bug to fail loudly with an out-of-range error, not merely a "+
			"hash mismatch)", lateToGateway.Bytes.Len(), len(earlyPayload))
	}

	reqAssert, err := CiteBytes(
		"The client's early-generation request reached the gateway.",
		"payload bytes of the FIRST connection instance over the reused local port",
		Pass, "early generation observed",
		StreamRef(toGateway), toGateway.Bytes, 0, len(earlyPayload))
	if err != nil {
		t.Fatal(err)
	}

	b := NewBuilder(RunMeta{
		Tool: "evidence-engine-test", ToolVersion: "0.0.1",
		Started: time.Unix(1_700_000_000, 0).UTC(), Finished: time.Unix(1_700_000_060, 0).UTC(),
		DUT: DUT{Name: "lexa-gw", Address: "69.0.0.2:802", Role: "device", Build: "test"},
	})
	b.SetCapture(capture.Summary{
		Tool: "dumpcap", ToolVersion: "4.2.2", Interface: "enp1s0",
		Filter: "tcp port 802", Packets: len(pkts), Format: "pcapng", FileBytes: 1234,
	}, capturePath)
	b.AddCase(TestCaseResult{
		ID: "PORT-REUSE-1", Title: "citation against the earlier of two reused-port generations",
		Assertions: []Assertion{reqAssert},
	})

	dir = filepath.Join(work, "bundle")
	if _, err := b.Write(dir); err != nil {
		t.Fatalf("Write: %v", err)
	}
	return dir, pkts
}

// TestVerifyResolvesCitationAgainstCorrectPortReuseGeneration is the
// regression test for the residual e166ec1 named: a byte-range citation
// against the EARLIER of two connection generations that share a local port
// must verify, because that generation is exactly the one CiteBytes computed
// the digest and frame list from at authoring time.
//
// Before this fix, reassemble()'s "src > dst" -> Direction map let the later
// generation silently overwrite the earlier one (last-write-wins over
// asm.Streams()'s first-seen order), so this failed with "netdis: byte range
// [0,44) is outside the 12-byte stream" (44 = len(earlyPayload), 12 =
// len(latePayload)) — the identical failure shape, down to the error
// wording, as runs/compliance-csip-1-20260802T024142 and
// runs/compliance-csip-2-20260802T041607 hit against real captures.
func TestVerifyResolvesCitationAgainstCorrectPortReuseGeneration(t *testing.T) {
	dir, pkts := buildReusedPortBundle(t)
	if len(pkts) != 12 {
		t.Fatalf("sanity: %d packets, want 12", len(pkts))
	}

	rep, err := Verify(dir)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !rep.OK {
		t.Fatalf("Verify failed on a citation against the earlier of two reused-port generations:\n%s", rep)
	}
	if rep.Checked != 1 {
		t.Fatalf("Checked = %d, want the 1 digest-bearing assertion", rep.Checked)
	}
	for _, a := range rep.Assertions {
		if !a.OK {
			t.Errorf("%s: %s: %s", a.Case, a.Claim, a.Detail)
		}
	}
}

// TestReusedPortDirectionLookupPicksTheCitingGeneration exercises
// resolveDirection directly: given the frames a citation names, it must
// return the Direction belonging to the SAME generation that carried them —
// generation 0, the early one — not merely any Direction whose bare
// "src > dst" happens to match.
func TestReusedPortDirectionLookupPicksTheCitingGeneration(t *testing.T) {
	dir, _ := buildReusedPortBundle(t)

	b, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	pkts, err := pcapng.ReadFile(filepath.Join(dir, filepath.FromSlash(b.Files.Capture)))
	if err != nil {
		t.Fatal(err)
	}
	rep := &VerifyReport{}
	asm := reassemble(pkts, rep)
	if len(rep.Problems) != 0 {
		t.Fatalf("reassemble reported problems on a clean capture: %v", rep.Problems)
	}

	a := b.Cases[0].Assertions[0]
	d, err := resolveDirection(asm, a)
	if err != nil {
		t.Fatalf("resolveDirection: %v", err)
	}
	if d.Gen != 0 {
		t.Fatalf("resolveDirection picked generation %d, want 0 (the generation that authored the citation)", d.Gen)
	}
	if d.Bytes.Len() != len(earlyPayload) {
		t.Fatalf("resolveDirection picked a %d-byte direction, want the early generation's %d bytes",
			d.Bytes.Len(), len(earlyPayload))
	}
}
