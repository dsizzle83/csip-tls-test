package report

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"csip-tls-test/internal/evidence/pcapng"
)

// tlsClientHello is a minimal but structurally valid TLS 1.2 ClientHello
// record: content type 22, version 0x0303, offering ECDHE-ECDSA-AES128-CCM-8
// (0xC0AE), the suite CSIP §5.2.1.1 pins. It exists so the trace test can prove
// SummariseTLS reads the FILE rather than trusting the caller.
func tlsClientHello() []byte {
	body := []byte{
		0x03, 0x03, // client_version
	}
	body = append(body, make([]byte, 32)...) // random
	body = append(body, 0x00)                // session id length
	body = append(body, 0x00, 0x02, 0xC0, 0xAE)
	body = append(body, 0x01, 0x00)           // compression methods
	body = append(body, 0x00, 0x00)           // extensions length
	hs := []byte{0x01, 0, 0, byte(len(body))} // handshake header
	hs = append(hs, body...)                  //
	rec := []byte{0x16, 0x03, 0x03, 0, 0}     // record header
	rec[3], rec[4] = byte(len(hs)>>8), byte(len(hs))
	return append(rec, hs...)
}

// tlsFatalAlert is a plaintext fatal alert record: level 2, description 42
// (bad_certificate) — the shape a correctly-refused certificate scenario has.
func tlsFatalAlert() []byte { return []byte{0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 42} }

func TestWritePcapRoundTrips(t *testing.T) {
	base := time.Date(2026, 7, 26, 9, 0, 0, 500_000_000, time.UTC)
	pkts := session(ap("69.0.0.20:44100"), ap("69.0.0.2:802"), base, []exchange{
		{true, tlsClientHello()},
		{false, tlsFatalAlert()},
	}, true)

	dir := t.TempDir()
	path := filepath.Join(dir, "scenario.pcap")
	info, err := ExportTrace(path, "COMM-004-expired", pkts, frameNumbers(pkts))
	if err != nil {
		t.Fatal(err)
	}
	back, err := pcapng.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(back) != len(pkts) {
		t.Fatalf("wrote %d frames, read back %d", len(pkts), len(back))
	}
	for i := range back {
		if string(back[i].Data) != string(pkts[i].Data) {
			t.Fatalf("frame %d changed on the round trip", i+1)
		}
		if !back[i].Time.Equal(pkts[i].Time.Truncate(time.Microsecond)) {
			t.Errorf("frame %d time %v, want %v", i+1, back[i].Time, pkts[i].Time)
		}
	}
	if info.SHA256 == "" || info.Bytes == 0 {
		t.Error("the trace carries no digest, so nothing ties it to the submission manifest")
	}

	// The substance of RPT-060: the exported FILE must show the outcome.
	if len(info.TLS.Handshake) == 0 || info.TLS.Handshake[0] != "client_hello" {
		t.Errorf("handshake = %v", info.TLS.Handshake)
	}
	if !info.TLS.FatalAlert {
		t.Error("the fatal alert in the trace was not recognised")
	}
	if !info.TLS.Terminated {
		t.Error("the FIN in the trace was not recognised")
	}
	if info.TLS.Complete {
		t.Error("a refused handshake was reported complete")
	}
}

// TestExportTraceRefusesAnEmptySelection: a trace file that contains no frames
// would claim a handshake that is not in it.
func TestExportTraceRefusesAnEmptySelection(t *testing.T) {
	pkts := session(ap("69.0.0.20:44100"), ap("69.0.0.2:802"),
		time.Now().UTC(), []exchange{{true, tlsClientHello()}}, true)
	if _, err := ExportTrace(filepath.Join(t.TempDir(), "x.pcap"), "none", pkts, []int{999}); err == nil {
		t.Fatal("an empty trace was written")
	}
}

// TestSummariseTLSReportsAMultiConnectionTrace: a COMM-004 trace carrying two
// connection attempts leaves a reviewer unable to tell which handshake is being
// judged, which defeats the artefact's purpose.
func TestSummariseTLSReportsAMultiConnectionTrace(t *testing.T) {
	base := time.Now().UTC()
	a := session(ap("69.0.0.20:44100"), ap("69.0.0.2:802"), base, []exchange{{true, tlsClientHello()}}, true)
	b := session(ap("69.0.0.20:44101"), ap("69.0.0.2:802"), base, []exchange{{true, tlsClientHello()}}, true)
	for i := range b {
		b[i].Index += len(a)
	}
	sum := SummariseTLS(append(a, b...))
	if !strings.Contains(sum.Problem, "2 TCP conversations") {
		t.Errorf("problem = %q", sum.Problem)
	}
}

func frameNumbers(pkts []pcapng.Packet) []int {
	out := make([]int, len(pkts))
	for i, p := range pkts {
		out[i] = p.Index
	}
	return out
}
