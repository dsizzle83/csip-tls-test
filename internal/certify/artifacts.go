package certify

// artifacts.go writes the per-test packet captures a governing document names.
//
// # Why the run capture is not enough
//
// This tool takes ONE capture for a whole run, and that is the right design:
// every assertion in the bundle cites frame numbers in a single file, so a
// reviewer opens one pcapng and re-checks everything against it, and no test
// case can quietly cite another's traffic.
//
// It is not, however, what the Secure SunSpec Modbus Conformance Test
// Procedures ask a submitter to hand over. Every row's Reporting Requirements
// names a file: §2.4.1.3 "A packet capture (.pcap) of the entire session
// spanning all server and client iterations showing the TLS connection named
// tlsf_001.pcap"; §2.7.4.3 "…showing the renegotiation extension and
// renegotiation attempt named prot_004.pcap". A bundle carrying one
// run-20260728-140301.pcapng satisfies the substance of that requirement and
// fails its instruction, and a reviewer who cannot find tlsf_001.pcap has no
// obligation to go looking for it inside something else.
//
// So the names are DECLARED by the suite that owns the row
// (certify.WithCaptureArtifacts, from the document's own bullets) and the
// slices are cut HERE, from the same frame attribution every assertion uses.
// Nothing is re-observed and nothing is re-decided: an exported file is exactly
// the frames the case already owns, and each one is re-read after writing so
// the bundle reports what the FILE contains rather than what this code meant.
//
// # Splitting a case across several names
//
// Three of the document's rows name more than one file, because they exercise
// more than one connection and want them apart:
//
//	TLSF-003  tlsf_003_expired.pcap, tlsf_003_badsig.pcap, tlsf_003_untrusted.pcap
//	          — "One capture per bad certificate type"
//	TLSF-005  tlsf_005.pcap and tlsf_005_resume.pcap
//	          — the session, and "the resumption attempt"
//
// The split is by TCP connection in first-seen order, which is the order the
// checks make them in. When the connection count does not match the name count
// the export REFUSES rather than guessing: a file called
// tlsf_003_untrusted.pcap holding the expired-certificate handshake is worse
// evidence than no file, because it is evidence of the wrong thing under a name
// that says otherwise.

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"csip-tls-test/internal/evidence/netdis"
	"csip-tls-test/internal/evidence/pcapng"
)

// CaptureArtifact is one per-test capture file that was written, or the reason
// one was not.
type CaptureArtifact struct {
	// UID is the case the frames belong to; Name is the file name the
	// governing document prescribes.
	UID  string
	Name string
	// Path is where it was written. Empty when Problem is set.
	Path string
	// Frames are the run-capture frame indices it contains, so a reader can
	// find the same bytes in the run capture the assertions cite.
	Frames []int
	Bytes  int64
	// Problem says why no file was written, when none was.
	Problem string
}

// String renders one artefact for the bundle's run note.
func (a CaptureArtifact) String() string {
	if a.Problem != "" {
		return fmt.Sprintf("%s (%s): NOT WRITTEN — %s", a.Name, a.UID, a.Problem)
	}
	return fmt.Sprintf("%s (%s): %d frame(s), %d byte(s)", a.Name, a.UID, len(a.Frames), a.Bytes)
}

// exportCaseCaptures writes the declared per-test captures for one case.
//
// It returns one CaptureArtifact per declared name, always: a name the run
// could not honour is reported with its reason, never silently dropped, because
// a submitter comparing the bundle against the document's Reporting
// Requirements needs to see the gap here rather than discover it at the lab.
func exportCaseCaptures(fi *FrameIndex, set *FrameSet, uid string, names []string, dir string) []CaptureArtifact {
	out := make([]CaptureArtifact, 0, len(names))
	fail := func(reason string, a ...any) []CaptureArtifact {
		for _, n := range names {
			out = append(out, CaptureArtifact{UID: uid, Name: n, Problem: fmt.Sprintf(reason, a...)})
		}
		return out
	}

	if fi == nil {
		return fail("the run produced no frame index, so no slice of it could be written")
	}
	if set == nil || len(set.Frames) == 0 {
		return fail("no capture frame is attributed to %s, so the file would be empty and would "+
			"claim a session that is not in this run", uid)
	}

	groups, problem := splitByConnection(fi, set.Frames, len(names))
	if problem != "" {
		return fail("%s", problem)
	}

	for i, n := range names {
		art, err := writeArtifact(fi, groups[i], filepath.Join(dir, n))
		art.UID, art.Name = uid, n
		if err != nil {
			art.Problem = err.Error()
			art.Path = ""
		}
		out = append(out, art)
	}
	return out
}

// splitByConnection partitions frames into want groups.
//
// want == 1 is the common case and is the whole frame set unsplit — the
// document asks for "the entire session", and a case that opened several
// connections legitimately puts all of them in that one file.
//
// want > 1 groups by TCP connection in first-seen order. Frames that belong to
// no TCP conversation (an ARP, a stray ICMP) are dropped from a multi-way split
// rather than assigned arbitrarily; they remain in the run capture, which is
// where the assertions point.
func splitByConnection(fi *FrameIndex, frames []int, want int) ([][]int, string) {
	if want <= 1 {
		return [][]int{frames}, ""
	}
	owned := map[int]bool{}
	for _, n := range frames {
		owned[n] = true
	}
	var order []netdis.StreamKey
	byKey := map[netdis.StreamKey][]int{}
	for _, f := range fi.Frames() {
		if f == nil || f.TCP == nil || !owned[f.Index] {
			continue
		}
		fl, ok := f.Flow()
		if !ok {
			continue
		}
		k := fl.Stream()
		if _, seen := byKey[k]; !seen {
			order = append(order, k)
		}
		byKey[k] = append(byKey[k], f.Index)
	}
	if len(order) != want {
		return nil, fmt.Sprintf("the document names %d separate captures for this case but the frames "+
			"attributed to it hold %d TCP connection(s); splitting them would put one connection's "+
			"handshake under another's file name, so nothing was written", want, len(order))
	}
	groups := make([][]int, 0, want)
	for _, k := range order {
		groups = append(groups, byKey[k])
	}
	return groups, ""
}

// writeArtifact writes one slice and re-reads it.
func writeArtifact(fi *FrameIndex, frames []int, path string) (CaptureArtifact, error) {
	art := CaptureArtifact{Frames: append([]int(nil), frames...)}
	sort.Ints(art.Frames)

	var sel []pcapng.Packet
	for _, n := range art.Frames {
		if p, ok := fi.Packet(n); ok {
			sel = append(sel, p)
		}
	}
	if len(sel) == 0 {
		return art, fmt.Errorf("none of the %d attributed frame(s) is present in the capture index",
			len(art.Frames))
	}

	var buf bytes.Buffer
	if err := pcapng.WriteLegacy(&buf, sel[0].LinkType, sel); err != nil {
		return art, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return art, fmt.Errorf("create the capture-artefact directory: %w", err)
	}
	if err := os.WriteFile(path, buf.Bytes(), 0o644); err != nil {
		return art, fmt.Errorf("write %s: %w", path, err)
	}
	// Re-read what was written. Reporting the source packets instead would
	// leave the actual FILE — the deliverable — unexamined.
	back, err := pcapng.ReadFile(path)
	if err != nil {
		return art, fmt.Errorf("the file just written to %s does not read back: %w", path, err)
	}
	if len(back) != len(sel) {
		return art, fmt.Errorf("%s was written with %d frame(s) and reads back with %d",
			path, len(sel), len(back))
	}
	art.Path, art.Bytes = path, int64(buf.Len())
	return art, nil
}

// captureArtifactNote summarises the export for the bundle's run note, so the
// fact that these files exist — and which of them do not — is recorded in the
// bundle itself and not only in the console.
func captureArtifactNote(arts []CaptureArtifact) string {
	if len(arts) == 0 {
		return ""
	}
	written, missing := 0, []string{}
	for _, a := range arts {
		if a.Problem == "" {
			written++
			continue
		}
		missing = append(missing, a.String())
	}
	s := fmt.Sprintf("per-test captures required by the governing document's Reporting Requirements: "+
		"%d of %d written into %s/", written, len(arts), "capture")
	if len(missing) > 0 {
		s += ". NOT WRITTEN: " + strings.Join(missing, "; ")
	}
	return s
}
