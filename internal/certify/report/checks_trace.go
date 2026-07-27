package report

// checks_trace.go implements RPT-060: the Chapter 5 COMM-004 TLS packet traces.
//
// This row is the one place in the suite where the honest answer is an OffWire
// declaration over frames the check cannot cite, and it is worth stating why
// plainly rather than leaving the declaration to look like an evasion.
//
// The requirement is that the SUBMISSION carry a trace per COMM-004 certificate
// scenario, and that each trace contain that scenario's whole TLS handshake.
// The frames concerned belong to the COMM-004 test cases — a different suite's
// rows, in a different window — and certify's attribution rule forbids one
// check from citing another's frames. That rule is right: a reporting check
// that could cite a TLS suite's handshake could also cite the wrong one.
//
// So the evidence here is the exported FILES. Each is written from the run's
// own capture, re-read after writing, re-dissected, and reported by what it
// actually contains — records, handshake messages, alerts, termination. Their
// sha256 digests go into the submission manifest, and every frame in them also
// appears, byte-identical, in the run capture the COMM-004 rows cite. A
// reviewer who wants the link opens both.

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"

	"csip-tls-test/internal/certify"
)

// traceCheck implements RPT-060.
func (s *Suite) traceCheck() certify.Check {
	return func(ctx context.Context, rc *certify.RunCtx) (certify.Result, error) {
		raw, ok := param(rc, "comm004")
		if !ok || strings.TrimSpace(raw) == "" {
			return certify.Skipped("no COMM-004 connection scenario was named (-param %scomm004=<uid>[,<uid>…]), "+
				"so there is no certificate scenario whose handshake could be traced. Chapter 5 applies to "+
				"COMM-004 alone, and exporting the whole run capture under a scenario name would claim a "+
				"correspondence this run cannot establish", paramPrefix), nil
		}
		var uids []string
		for _, p := range strings.Split(raw, ",") {
			if p = strings.TrimSpace(p); p != "" {
				uids = append(uids, p)
			}
		}
		dir, err := s.OutDir(rc)
		if err != nil {
			return certify.Result{}, err
		}
		traceRoot := filepath.Join(dir, ArchiveDir, TraceDir)

		return certify.Result{
			Notes:   fmt.Sprintf("%d COMM-004 scenario(s) to trace into %s", len(uids), traceRoot),
			OffWire: true,
			OffWireReason: "the frames a COMM-004 trace must contain belong to the COMM-004 test cases, not " +
				"to this row, and certify forbids a check from citing another case's frames. The evidence " +
				"is therefore the exported trace files: each is re-read after writing, re-dissected, and " +
				"reported by the TLS records it actually contains, and its sha256 is in the submission " +
				"manifest. Every frame in a trace also appears byte-identically in the run capture that " +
				"the COMM-004 rows themselves cite",
			Cite: func(ctx context.Context, ev *certify.Evidence) ([]certify.Assertion, error) {
				return s.exportTraces(ev, traceRoot, uids)
			},
		}, nil
	}
}

func (s *Suite) exportTraces(ev *certify.Evidence, root string, uids []string) ([]certify.Assertion, error) {
	if ev.Attribution == nil {
		return []certify.Assertion{ev.SkipAssertion(
			"a raw TLS packet trace accompanies each COMM-004 certificate scenario",
			"per-scenario export from the run capture",
			"the run produced no frame attribution, so no scenario's frames could be identified")}, nil
	}
	var out []certify.Assertion
	var infos []TraceInfo
	all := ev.Index.Packets()

	for _, uid := range uids {
		set := ev.Attribution.Set(uid)
		name := uid
		if _, after, ok := strings.Cut(uid, "::"); ok {
			name = after
		}
		if set == nil || len(set.Frames) == 0 {
			out = append(out, certify.Assertion{
				Claim:   fmt.Sprintf("a raw TLS packet trace was exported for COMM-004 scenario %s", name),
				Method:  "per-scenario export from the run capture, using that case's own frame attribution",
				Verdict: certify.Fail,
				Observed: fmt.Sprintf("no capture frame is attributed to %s, so its handshake is not in this "+
					"run's capture and no trace can be written for it", uid),
			})
			continue
		}
		path := filepath.Join(root, sanitise(name)+".pcap")
		info, err := ExportTrace(path, name, all, set.Frames)
		if err != nil {
			out = append(out, certify.Assertion{
				Claim:    fmt.Sprintf("a raw TLS packet trace was exported for COMM-004 scenario %s", name),
				Method:   "per-scenario export from the run capture",
				Verdict:  certify.Fail,
				Observed: err.Error(),
			})
			continue
		}
		infos = append(infos, info)
		out = append(out, docAssertion(
			fmt.Sprintf("the trace for COMM-004 scenario %s is a libpcap file containing that scenario's "+
				"complete TLS connection establishment", name),
			"the exported file was re-read with this repository's pcap reader, re-dissected, and its TLS "+
				"record layer summarised — a property of the FILE, not of the intent behind it",
			traceVerdict(info),
			describeTrace(info),
			fmt.Sprintf("%s (sha256 %s), written from frames %d–%d of this run's capture",
				path, info.SHA256[:16], set.Frames[0], set.Frames[len(set.Frames)-1])))
	}

	status, detail := traceStatus(infos)
	out = append(out, docAssertion(
		"a packet trace accompanies every COMM-004 connection scenario the campaign exercised",
		"aggregate over the exported traces",
		verdictForStatus(status), detail,
		"the submission's archive/traces directory"))
	return out, nil
}

func traceVerdict(i TraceInfo) certify.Verdict {
	switch {
	case i.TLS.Problem != "":
		return certify.Fail
	case len(i.TLS.Handshake) == 0:
		return certify.Fail
	case !i.TLS.Complete && !i.TLS.FatalAlert && !i.TLS.Terminated:
		// A trace showing neither a completed handshake nor a refusal does not
		// evidence an outcome, which is the entire purpose of the artefact.
		return certify.Warn
	default:
		return certify.Pass
	}
}

func verdictForStatus(s ReqStatus) certify.Verdict {
	switch s {
	case ReqMet:
		return certify.Pass
	case ReqUnmet:
		return certify.Fail
	default:
		return certify.Skip
	}
}

func describeTrace(i TraceInfo) string {
	outcome := "handshake completed (Finished observed)"
	switch {
	case i.TLS.FatalAlert:
		outcome = "refused: " + strings.Join(i.TLS.Alerts, ", ")
	case !i.TLS.Complete && i.TLS.Terminated:
		outcome = "terminated by FIN/RST without completing the handshake"
	case !i.TLS.Complete:
		outcome = "no Finished and no termination — the trace does not show an outcome"
	}
	hs := "none"
	if len(i.TLS.Handshake) > 0 {
		hs = strings.Join(i.TLS.Handshake, " → ")
	}
	if i.TLS.Problem != "" {
		return fmt.Sprintf("%d frame(s), %d byte(s): %s", len(i.Frames), i.Bytes, i.TLS.Problem)
	}
	return fmt.Sprintf("%d frame(s), %d byte(s), %d TLS record(s); handshake %s; %s",
		len(i.Frames), i.Bytes, i.TLS.Records, hs, outcome)
}

// sanitise keeps a scenario name usable as a file name without inventing one.
func sanitise(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_', r == '.':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	return b.String()
}
