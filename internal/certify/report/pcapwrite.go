package report

// pcapwrite.go implements Chapter 5 of SS-CSIP-RESULTS-v1.1 — the COMM-004 raw
// TLS packet traces, the only change v1.1 made to the specification.
//
// The requirement is deceptively small: "a packet trace should be submitted for
// each connection scenario specified in COMM-004", in Libpcap or PcapNg,
// "including all the TLS packets associated with connection establishment", so
// SunSpec can "verify the correct test behavior for the certificate scenario
// presented". What makes it necessary is stated in the same chapter: a REJECTED
// connection produces no HTTP at all, so it is invisible in the Chapter 4 logs.
// The evidence that a DUT correctly refused an expired certificate exists only
// at the TLS record layer.
//
// So a trace is not a courtesy copy of the run capture. It is a per-scenario
// slice that must contain the whole handshake — the ClientHello through the
// Finished, or the ClientHello through the fatal alert and the FIN — and a
// slice that cut the alert off would evidence the opposite of what it claims.
// ExportTrace therefore re-reads what it wrote, re-dissects it, and reports what
// TLS messages the exported file actually contains, so the check asserting
// RPT-060 is asserting a property of the FILE rather than of the intent behind
// it.
//
// Classic libpcap is the output format. PcapNg would also be conformant, but
// libpcap is one 24-byte header and one 16-byte record per frame — a format
// whose correctness is inspectable at a glance — and this repository's reader
// already round-trips it, which is what the export test asserts.

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"time"

	"csip-tls-test/internal/evidence/netdis"
	"csip-tls-test/internal/evidence/pcapng"
	"csip-tls-test/internal/evidence/tlsdis"
)

// pcapMagicMicro is the classic little-endian microsecond magic — what
// `tcpdump -w` writes and what pcapng.ReadFile accepts.
const pcapMagicMicro = 0xA1B2C3D4

// pcapSnapLen is recorded in the file header. It is the maximum captured length
// present, not a truncation this writer applies: nothing here ever shortens a
// frame, because a trace whose handshake was clipped is worse than no trace.
func pcapSnapLen(pkts []pcapng.Packet) uint32 {
	max := uint32(0)
	for _, p := range pkts {
		if n := uint32(len(p.Data)); n > max {
			max = n
		}
	}
	if max == 0 {
		return 65535
	}
	return max
}

// WritePcap writes packets as a classic libpcap file.
//
// Every frame is written whole, with its original wire length preserved in the
// record header, so a reader can still tell that a frame was truncated by the
// CAPTURE — a fact that must survive into the trace, since a truncated
// handshake record cannot prove what a complete one would.
func WritePcap(w io.Writer, linkType uint16, pkts []pcapng.Packet) error {
	hdr := make([]byte, 24)
	binary.LittleEndian.PutUint32(hdr[0:4], pcapMagicMicro)
	binary.LittleEndian.PutUint16(hdr[4:6], 2)
	binary.LittleEndian.PutUint16(hdr[6:8], 4)
	binary.LittleEndian.PutUint32(hdr[16:20], pcapSnapLen(pkts))
	binary.LittleEndian.PutUint32(hdr[20:24], uint32(linkType))
	if _, err := w.Write(hdr); err != nil {
		return fmt.Errorf("report: write pcap header: %w", err)
	}
	rec := make([]byte, 16)
	for _, p := range pkts {
		if p.LinkType != linkType {
			return fmt.Errorf("report: frame %d has link type %d but the trace declares %d; "+
				"a single libpcap file cannot mix link types", p.Index, p.LinkType, linkType)
		}
		binary.LittleEndian.PutUint32(rec[0:4], uint32(p.Time.Unix()))
		binary.LittleEndian.PutUint32(rec[4:8], uint32(p.Time.Nanosecond()/1000))
		binary.LittleEndian.PutUint32(rec[8:12], uint32(len(p.Data)))
		binary.LittleEndian.PutUint32(rec[12:16], uint32(p.OrigLen))
		if _, err := w.Write(rec); err != nil {
			return fmt.Errorf("report: write pcap record header: %w", err)
		}
		if _, err := w.Write(p.Data); err != nil {
			return fmt.Errorf("report: write pcap frame %d: %w", p.Index, err)
		}
	}
	return nil
}

// TraceTLS is what a trace file actually contains at the TLS layer, recovered
// by re-reading the written file. It is the substance of the RPT-060 assertion:
// "a trace was written" is not the requirement; "the trace permits inspection
// of the TLS packets to verify the correct test behavior" is.
type TraceTLS struct {
	// Handshake lists the plaintext handshake message types seen, in order,
	// across both directions.
	Handshake []string
	// Records counts TLS records of any type.
	Records int
	// Alerts are the plaintext alerts, e.g. "fatal bad_certificate".
	Alerts []string
	// FatalAlert is true when a fatal alert is present — the signature of a
	// correctly-refused certificate scenario.
	FatalAlert bool
	// Terminated is true when a FIN or RST closed the conversation, which is
	// the other half of "the DUT refused and then closed".
	Terminated bool
	// Complete is true when the handshake reached a Finished message, i.e. the
	// scenario was ACCEPTED and the trace shows it through to completion.
	Complete bool
	// Problem records why the TLS layer could not be summarised, when it could
	// not: no TCP stream in the slice, or a record layer that does not parse.
	Problem string
}

// TraceInfo describes one exported trace file.
type TraceInfo struct {
	// Scenario is the COMM-004 connection scenario the trace evidences.
	Scenario string
	Path     string
	Frames   []int
	Bytes    int64
	// SHA256 is the digest of the written file, which is what ties the trace to
	// the bundle manifest.
	SHA256 string
	First  time.Time
	Last   time.Time
	TLS    TraceTLS
}

// ExportTrace writes the frames of one COMM-004 scenario to path and reports
// what the written file contains.
//
// The frames are supplied by the caller — normally from the run's own frame
// attribution for the test case that exercised the scenario — because this
// package must not guess which packets belong to which certificate scenario.
// Guessing is how a trace ends up proving the wrong refusal.
func ExportTrace(path, scenario string, all []pcapng.Packet, frames []int) (TraceInfo, error) {
	info := TraceInfo{Scenario: scenario, Path: path}
	want := map[int]bool{}
	for _, f := range frames {
		want[f] = true
	}
	var sel []pcapng.Packet
	for _, p := range all {
		if want[p.Index] {
			sel = append(sel, p)
		}
	}
	if len(sel) == 0 {
		return info, fmt.Errorf("report: scenario %q selected no frames from a %d-frame capture; "+
			"an empty trace would claim a handshake that is not in it", scenario, len(all))
	}
	sort.Slice(sel, func(i, j int) bool { return sel[i].Index < sel[j].Index })
	for _, p := range sel {
		info.Frames = append(info.Frames, p.Index)
	}
	info.First, info.Last = sel[0].Time, sel[len(sel)-1].Time

	var buf bytes.Buffer
	if err := WritePcap(&buf, sel[0].LinkType, sel); err != nil {
		return info, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return info, fmt.Errorf("report: create trace directory: %w", err)
	}
	if err := os.WriteFile(path, buf.Bytes(), 0o644); err != nil {
		return info, fmt.Errorf("report: write trace %s: %w", path, err)
	}
	info.Bytes = int64(buf.Len())
	sum := sha256.Sum256(buf.Bytes())
	info.SHA256 = hex.EncodeToString(sum[:])

	// Re-read what was written. Summarising the source packets instead would
	// leave the actual FILE unexamined, and the file is the deliverable.
	back, err := pcapng.ReadFile(path)
	if err != nil {
		return info, fmt.Errorf("report: the trace just written to %s does not read back: %w", path, err)
	}
	if len(back) != len(sel) {
		return info, fmt.Errorf("report: %s was written with %d frames and reads back with %d",
			path, len(sel), len(back))
	}
	info.TLS = SummariseTLS(back)
	return info, nil
}

// SummariseTLS dissects a set of packets and reports the TLS handshake they
// contain. It is used on the written trace, not on the source capture.
func SummariseTLS(pkts []pcapng.Packet) TraceTLS {
	asm := netdis.NewAssembler()
	for _, p := range pkts {
		f, err := netdis.DecodePacket(p)
		if err != nil {
			continue
		}
		asm.AddFrame(f)
	}
	streams := asm.Streams()
	if len(streams) == 0 {
		return TraceTLS{Problem: "the trace contains no TCP conversation, so it shows no TLS handshake"}
	}
	if len(streams) > 1 {
		return TraceTLS{Problem: fmt.Sprintf(
			"the trace contains %d TCP conversations; a COMM-004 scenario trace should carry one "+
				"connection attempt so a reviewer knows which handshake is being judged", len(streams))}
	}
	st := streams[0]
	out := TraceTLS{}
	for _, p := range pkts {
		f, err := netdis.DecodePacket(p)
		if err != nil || f.TCP == nil {
			continue
		}
		if f.TCP.Flags.Has(netdis.FIN) || f.TCP.Flags.Has(netdis.RST) {
			out.Terminated = true
		}
	}
	for _, d := range st.Dirs {
		if d == nil || d.Bytes == nil || d.Bytes.Len() == 0 {
			continue
		}
		td, err := tlsdis.ParseDirection(d.Bytes.Bytes(), d.Bytes)
		if err != nil && (td == nil || td.Stream == nil) {
			out.Problem = fmt.Sprintf("direction %s does not parse as TLS: %v", d.Flow, err)
			continue
		}
		if td.Stream != nil {
			out.Records += len(td.Stream.Records)
		}
		if td.Handshake != nil {
			for _, t := range td.Handshake.Types() {
				out.Handshake = append(out.Handshake, tlsdis.HandshakeTypeName(t))
				if t == tlsdis.HandshakeFinished {
					out.Complete = true
				}
			}
		}
		for _, a := range td.Alerts {
			out.Alerts = append(out.Alerts, a.String())
			if a.Fatal() {
				out.FatalAlert = true
			}
		}
	}
	if out.Records == 0 && out.Problem == "" {
		out.Problem = "the trace's TCP stream carries no TLS records"
	}
	return out
}
