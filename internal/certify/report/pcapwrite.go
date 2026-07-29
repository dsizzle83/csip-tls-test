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
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"csip-tls-test/internal/evidence/netdis"
	"csip-tls-test/internal/evidence/pcapng"
	"csip-tls-test/internal/evidence/tlsdis"
)

// WritePcap writes packets as a classic libpcap file.
//
// The format itself lives in internal/evidence/pcapng, beside the reader that
// round-trips it, because Chapter 5 is no longer the only specification asking
// for per-test slices of the run capture: the Secure SunSpec Modbus CTP names a
// pcap per row in its Reporting Requirements. Two writers of the same format
// would be two things to get wrong.
func WritePcap(w io.Writer, linkType uint16, pkts []pcapng.Packet) error {
	return pcapng.WriteLegacy(w, linkType, pkts)
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

// LoadTrace re-reads an ALREADY-EXPORTED trace file from disk and reports what
// it contains, the same way ExportTrace does immediately after writing one.
//
// It exists for GenerateTRR: a CSIP evidence bundle's archive/traces/*.pcap
// files were written by an earlier run of the results-report suite (RPT-060,
// via ExportTrace) against the run's LIVE capture, which no longer exists by
// the time a TRR package is assembled from the bundle's own directory.
// Packaging the traces into a submission therefore re-reads the files
// themselves — re-dissecting them exactly as ExportTrace's own post-write
// check does — rather than re-deriving anything from a capture that is gone.
//
// The scenario name is recovered from the file's base name, which is how
// ExportTrace names it (sanitise(name)+".pcap"): sanitise is idempotent on the
// characters it allows through, so round-tripping a scenario name built from
// them recovers it exactly.
func LoadTrace(path string) (TraceInfo, error) {
	scenario := strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))
	info := TraceInfo{Scenario: scenario, Path: path}
	data, err := os.ReadFile(path)
	if err != nil {
		return info, fmt.Errorf("report: read trace %s: %w", path, err)
	}
	info.Bytes = int64(len(data))
	sum := sha256.Sum256(data)
	info.SHA256 = hex.EncodeToString(sum[:])

	pkts, err := pcapng.ReadFile(path)
	if err != nil {
		return info, fmt.Errorf("report: trace %s does not read back as a pcap: %w", path, err)
	}
	for _, p := range pkts {
		info.Frames = append(info.Frames, p.Index)
	}
	if len(pkts) > 0 {
		info.First, info.Last = pkts[0].Time, pkts[len(pkts)-1].Time
	}
	info.TLS = SummariseTLS(pkts)
	return info, nil
}

// DiscoverTraces globs <dir>/archive/traces/*.pcap for every bundle directory
// given and loads each, so a TRR package cannot forget Chapter 5's traces by
// omitting a field: the caller supplies bundle directories it already has
// (Collated.Sources), and every trace those bundles ever exported comes along
// automatically. Results are sorted by bundle directory, then by scenario name,
// so two runs over the same bundles order them identically.
func DiscoverTraces(dirs []string) ([]TraceInfo, error) {
	sorted := append([]string(nil), dirs...)
	sort.Strings(sorted)
	var out []TraceInfo
	for _, dir := range sorted {
		matches, err := filepath.Glob(filepath.Join(dir, ArchiveDir, TraceDir, "*.pcap"))
		if err != nil {
			return nil, fmt.Errorf("report: list traces under %s: %w", dir, err)
		}
		sort.Strings(matches)
		for _, m := range matches {
			info, err := LoadTrace(m)
			if err != nil {
				return nil, err
			}
			out = append(out, info)
		}
	}
	return out, nil
}

// CopyTraces copies already-discovered traces into destDir's own
// archive/traces/ directory and returns their TraceInfo with Path updated to
// the copy, each one re-verified against the digest DiscoverTraces read.
//
// It exists because a CSIP TRR part's traces are discovered from a DIFFERENT
// bundle's directory (Collated.Sources), and generate.go's manifest digests
// only files that live under the submission's own Dir — a Chapter 5 trace left
// at its source path would resolve to a path outside Dir (filepath.Rel
// returning a "../" prefix) and silently drop out of both sub.Files and
// MANIFEST.sha256. Copying, rather than merely referencing, makes the package
// self-contained: a reviewer handed the TRR directory alone has the trace, not
// a path into an evidence bundle they may not have been given.
func CopyTraces(destDir string, traces []TraceInfo) ([]TraceInfo, error) {
	out := make([]TraceInfo, 0, len(traces))
	for _, t := range traces {
		data, err := os.ReadFile(t.Path)
		if err != nil {
			return nil, fmt.Errorf("report: re-read trace %s to copy it into the package: %w", t.Path, err)
		}
		sum := sha256.Sum256(data)
		if hex.EncodeToString(sum[:]) != t.SHA256 {
			return nil, fmt.Errorf("report: trace %s changed on disk between discovery and packaging "+
				"(digest mismatch)", t.Path)
		}
		rel := filepath.Join(ArchiveDir, TraceDir, filepath.Base(t.Path))
		if existing, err := os.ReadFile(filepath.Join(destDir, rel)); err == nil {
			if es := sha256.Sum256(existing); hex.EncodeToString(es[:]) != t.SHA256 {
				return nil, fmt.Errorf("report: two different traces both named %s would collide in the "+
					"package", filepath.Base(t.Path))
			}
		} else if err := writeFile(destDir, rel, data); err != nil {
			return nil, err
		}
		t.Path = filepath.Join(destDir, rel)
		out = append(out, t)
	}
	return out, nil
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
