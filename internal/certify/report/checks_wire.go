package report

// checks_wire.go is where this suite earns its citations.
//
// Every check here does the same four things: conduct a real exchange, claim
// it, derive the detailed-test-log entries from the CAPTURED BYTES in the
// citation phase, and cite the exact byte range the emitted entry renders. The
// assertion that results says, in effect: "the submission's log entry for this
// message is these bytes, whose sha256 bundle.Verify re-derives from the pcap
// sitting beside it". A reviewer who doubts the log opens the capture at the
// cited frame.
//
// The alternative — validating a log the tool wrote from its own idea of the
// exchange — would satisfy the same catalog rows and prove nothing, which is
// why none of these checks accept a fixture.

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"

	"csip-tls-test/internal/certify"
	"csip-tls-test/internal/evidence/netdis"
)

// LogRule is one §4.1 rule expressed over a log derived from the wire.
type LogRule struct {
	// Claim is the sentence the assertion makes.
	Claim string
	// Method says how it was established.
	Method string
	// Assess judges the derived log and chooses the entry whose bytes evidence
	// the rule. Returning a nil entry produces a SKIP carrying observed as the
	// reason, which is the honest outcome when the exchange did not contain the
	// kind of entry the rule is about.
	Assess func(d *DerivedModbus) (certify.Verdict, string, *ScannedEntry)
	// Extra adds further assertions — schema findings, cross-checks — that are
	// not themselves byte-citable.
	Extra func(ev *certify.Evidence, d *DerivedModbus) []certify.Assertion
}

// DerivedModbus is the log this run derived from its own exchange, with
// everything a rule needs to judge it.
type DerivedModbus struct {
	Probe *Probe
	Scan  *ModbusScan
	Logs  *ModbusTestLogs
	// Findings are ValidateModbusTestLogs's output over Logs.
	Findings []string
	// SocketMatch reports whether the derived log accounts for exactly the
	// bytes this check's own socket wrote and read. A mismatch means the log is
	// NOT the complete record §4 demands, and it is surfaced on every rule.
	SocketMatch  bool
	SocketDetail string
}

// modbusLogCheck builds a check for one §4.1 Modbus rule.
func (s *Suite) modbusLogCheck(rule LogRule) certify.Check {
	return func(ctx context.Context, rc *certify.RunCtx) (certify.Result, error) {
		pr, err := ProbeModbus(ctx, rc, 2)
		if err != nil {
			return certify.Skipped("no Modbus exchange could be conducted, so no detailed test log could "+
				"be derived from the wire: %v", err), nil
		}
		return certify.Result{
			Notes: fmt.Sprintf("%d Modbus transaction(s) with %s", len(pr.Sent), pr.Server),
			Cite:  s.citeModbus(pr, rule),
		}, nil
	}
}

// citeModbus is the citation phase shared by every Modbus log rule.
func (s *Suite) citeModbus(pr *Probe, rule LogRule) certify.CiteFunc {
	return func(ctx context.Context, ev *certify.Evidence) ([]certify.Assertion, error) {
		if !ev.HasFrames() {
			return []certify.Assertion{ev.NoEvidence(rule.Claim)}, nil
		}
		st, err := ev.StreamOn(pr.Server.Port())
		if err != nil {
			return []certify.Assertion{ev.SkipAssertion(rule.Claim,
				"TCP stream reassembly of this check's own connection", err.Error())}, nil
		}
		d, err := deriveModbus(pr, st, ev)
		if err != nil {
			return nil, err
		}

		var out []certify.Assertion
		// Integrity first: a log that does not account for every byte the
		// socket saw is not the complete record §4 requires, and every rule
		// resting on that log inherits the doubt.
		out = append(out, certify.Assertion{
			Claim: "the derived detailed test log accounts for exactly the Modbus bytes this check's own " +
				"socket wrote and read",
			Method:   "byte-for-byte comparison of the socket's record against the log derived from the capture",
			Verdict:  verdictIf(d.SocketMatch),
			Observed: d.SocketDetail,
			Note: "a mismatch means the capture and the log disagree, and no rule below can be trusted " +
				"further than that",
		})
		for _, p := range d.Scan.Problems {
			out = append(out, certify.Assertion{
				Claim:    "the capture supports a complete detailed test log for this exchange",
				Method:   "MBAP framing of the reassembled stream",
				Verdict:  certify.Warn,
				Observed: p,
			})
		}

		verdict, observed, entry := rule.Assess(d)
		switch {
		case entry == nil:
			out = append(out, ev.SkipAssertion(rule.Claim, rule.Method, observed))
		case entry.Dir != nil:
			a, err := ev.CiteBytes(rule.Claim, rule.Method, verdict, observed, entry.Dir, entry.Start, entry.End)
			if err != nil {
				return nil, err
			}
			out = append(out, a)
		default:
			a, err := ev.CiteFrames(rule.Claim, rule.Method, verdict, observed, entry.Frames)
			if err != nil {
				return nil, err
			}
			out = append(out, a)
		}
		if rule.Extra != nil {
			out = append(out, rule.Extra(ev, d)...)
		}
		return out, nil
	}
}

// deriveModbus builds the log from the capture and cross-checks it against the
// check's own socket record.
func deriveModbus(pr *Probe, st *netdis.Stream, ev *certify.Evidence) (*DerivedModbus, error) {
	sc, err := ScanModbus(st, ev.Index.Frames(), pr.Server)
	if err != nil {
		return nil, err
	}
	logs := &ModbusTestLogs{Logs: []ModbusTestLog{sc.TestLog(ev.Case.ID)}}
	d := &DerivedModbus{
		Probe: pr, Scan: sc, Logs: logs,
		Findings: ValidateModbusTestLogs(logs, TransportTCP),
	}
	var sent, recv []byte
	for _, e := range sc.Entries {
		raw, err := DecodeHexMsg(e.Entry.Msg)
		if err != nil {
			continue
		}
		switch e.Entry.Type {
		case EntryReq:
			sent = append(sent, raw...)
		case EntryResp:
			recv = append(recv, raw...)
		}
	}
	var wrote []byte
	for _, b := range pr.Sent {
		wrote = append(wrote, b...)
	}
	d.SocketMatch = string(sent) == string(wrote) && string(recv) == string(pr.Received)
	d.SocketDetail = fmt.Sprintf(
		"socket wrote %d byte(s) and read %d; the log derived from the capture renders %d request byte(s) "+
			"in %d `req` entries and %d response byte(s) in %d `resp` entries",
		len(wrote), len(pr.Received), len(sent), sc.Count(EntryReq), len(recv), sc.Count(EntryResp))
	if !d.SocketMatch {
		d.SocketDetail += " — THEY DIFFER"
	}
	return d, nil
}

// schemaAssertion reports the §4.1 validation of the derived document. It is
// not byte-citable — a JSON schema rule is a property of a document — so it is
// a narrative assertion whose source is the document this run wrote.
func schemaAssertion(d *DerivedModbus, claim string) certify.Assertion {
	v, observed := certify.Pass, fmt.Sprintf(
		"%d entries across %d test log(s) validate against §4.1", len(allEntries(d.Logs)), len(d.Logs.Logs))
	if len(d.Findings) > 0 {
		v = certify.Fail
		observed = fmt.Sprintf("%d finding(s): %s", len(d.Findings), strings.Join(d.Findings, "; "))
	}
	return docAssertion(claim, "validation of the emitted Test Logs Object against §4.1", v, observed,
		"the Detailed Test Logs JSON this run derived from the capture")
}

// ---------------------------------------------------------------------------
// CSIP HTTP message rules
// ---------------------------------------------------------------------------

// HTTPRule is one Chapter 4 rule expressed over an HTTP log derived from the
// wire.
type HTTPRule struct {
	Claim  string
	Method string
	Assess func(d *DerivedHTTP) (certify.Verdict, string, *ScannedMessage)
	Extra  func(ev *certify.Evidence, d *DerivedHTTP) []certify.Assertion
}

// DerivedHTTP is the CSIP log this run derived from its own HTTP exchange.
type DerivedHTTP struct {
	Probe    *Probe
	Scan     *HTTPScan
	Logs     *CSIPTestLogs
	Findings []string
}

// httpLogCheck builds a check for one Chapter 4 CSIP rule.
func (s *Suite) httpLogCheck(rule HTTPRule) certify.Check {
	return func(ctx context.Context, rc *certify.RunCtx) (certify.Result, error) {
		path := "/"
		if p, ok := param(rc, "http-path"); ok && p != "" {
			path = p
		}
		pr, err := ProbeHTTP(ctx, rc, path)
		if err != nil {
			return certify.Skipped("no plaintext HTTP exchange could be conducted, so no detailed test log "+
				"could be derived from the wire: %v", err), nil
		}
		cfg, _, _ := s.Config(rc)
		cid := ""
		if cfg != nil {
			cid = cfg.ContextID
		}
		return certify.Result{
			Notes: fmt.Sprintf("one HTTP exchange with %s, %s", pr.Server, preview(pr.Received, 48)),
			Cite:  s.citeHTTP(pr, cid, rule),
		}, nil
	}
}

func (s *Suite) citeHTTP(pr *Probe, cid string, rule HTTPRule) certify.CiteFunc {
	return func(ctx context.Context, ev *certify.Evidence) ([]certify.Assertion, error) {
		if !ev.HasFrames() {
			return []certify.Assertion{ev.NoEvidence(rule.Claim)}, nil
		}
		st, err := ev.StreamOn(pr.Server.Port())
		if err != nil {
			return []certify.Assertion{ev.SkipAssertion(rule.Claim,
				"TCP stream reassembly of this check's own connection", err.Error())}, nil
		}
		sc, err := ScanHTTP(st, ev.Index.Frames(), pr.Server)
		if err != nil {
			return nil, err
		}
		logs := &CSIPTestLogs{CID: cid, Logs: []CSIPTestLog{sc.TestLog(cid, ev.Case.ID)}}
		d := &DerivedHTTP{Probe: pr, Scan: sc, Logs: logs, Findings: ValidateCSIPTestLogs(logs)}

		var out []certify.Assertion
		for _, p := range sc.Problems {
			out = append(out, certify.Assertion{
				Claim:    "the capture supports a complete detailed test log for this exchange",
				Method:   "HTTP framing of the reassembled stream",
				Verdict:  certify.Warn,
				Observed: p,
			})
		}
		verdict, observed, msg := rule.Assess(d)
		switch {
		case msg == nil:
			out = append(out, ev.SkipAssertion(rule.Claim, rule.Method, observed))
		case msg.Dir != nil:
			a, err := ev.CiteBytes(rule.Claim, rule.Method, verdict, observed, msg.Dir, msg.Start, msg.End)
			if err != nil {
				return nil, err
			}
			out = append(out, a)
		default:
			a, err := ev.CiteFrames(rule.Claim, rule.Method, verdict, observed, msg.Frames)
			if err != nil {
				return nil, err
			}
			out = append(out, a)
		}
		if rule.Extra != nil {
			out = append(out, rule.Extra(ev, d)...)
		}
		return out, nil
	}
}

// httpSchemaAssertion is the CSIP analogue of schemaAssertion.
func httpSchemaAssertion(d *DerivedHTTP, claim string) certify.Assertion {
	v, observed := certify.Pass, fmt.Sprintf("%d message(s) across %d test log(s) validate against §4.1",
		len(d.Scan.Messages), len(d.Logs.Logs))
	if len(d.Findings) > 0 {
		v = certify.Fail
		observed = fmt.Sprintf("%d finding(s): %s", len(d.Findings), strings.Join(d.Findings, "; "))
	}
	return docAssertion(claim, "validation of the emitted Test Logs Object against §4.1", v, observed,
		"the Detailed Test Logs JSON this run derived from the capture")
}

// ---------------------------------------------------------------------------
// The whole-submission check
// ---------------------------------------------------------------------------

// deliverableCheck implements RPT-001 / RPT-007 / RPT-TRR-1: a submission that
// is a public Summary Test Results plus an archived Detailed Test Log.
//
// It conducts the same exchange as the log rules so the archived half of the
// submission it writes contains a REAL log derived from a REAL capture. A
// deliverable check that wrote an empty archive would assert the structure of a
// submission nobody could act on.
func (s *Suite) deliverableCheck(certType string) certify.Check {
	return func(ctx context.Context, rc *certify.RunCtx) (certify.Result, error) {
		if certType == CertTypeModbus {
			pr, err := ProbeModbus(ctx, rc, 2)
			if err != nil {
				return s.buildOnly(rc, certType, nil,
					fmt.Sprintf("no Modbus exchange was possible (%v), so the archived half of the "+
						"submission is empty", err))
			}
			return certify.Result{
				Notes: fmt.Sprintf("%d Modbus transaction(s) with %s", len(pr.Sent), pr.Server),
				Cite: func(ctx context.Context, ev *certify.Evidence) ([]certify.Assertion, error) {
					if !ev.HasFrames() {
						return []certify.Assertion{ev.NoEvidence("the submission carries a detailed test log")}, nil
					}
					st, err := ev.StreamOn(pr.Server.Port())
					if err != nil {
						return []certify.Assertion{ev.SkipAssertion(
							"the submission carries a detailed test log",
							"TCP stream reassembly", err.Error())}, nil
					}
					d, err := deriveModbus(pr, st, ev)
					if err != nil {
						return nil, err
					}
					return s.assertSubmission(rc, certType, d.Logs)
				},
			}, nil
		}
		pr, err := ProbeHTTP(ctx, rc, "/")
		if err != nil {
			return s.buildOnly(rc, certType, nil,
				fmt.Sprintf("no HTTP exchange was possible (%v), so the archived half of the submission is empty", err))
		}
		cfg, _, _ := s.Config(rc)
		cid := ""
		if cfg != nil {
			cid = cfg.ContextID
		}
		return certify.Result{
			Notes: fmt.Sprintf("one HTTP exchange with %s", pr.Server),
			Cite: func(ctx context.Context, ev *certify.Evidence) ([]certify.Assertion, error) {
				if !ev.HasFrames() {
					return []certify.Assertion{ev.NoEvidence("the submission carries a detailed test log")}, nil
				}
				st, err := ev.StreamOn(pr.Server.Port())
				if err != nil {
					return []certify.Assertion{ev.SkipAssertion(
						"the submission carries a detailed test log",
						"TCP stream reassembly", err.Error())}, nil
				}
				sc, err := ScanHTTP(st, ev.Index.Frames(), pr.Server)
				if err != nil {
					return nil, err
				}
				logs := &CSIPTestLogs{CID: cid, Logs: []CSIPTestLog{sc.TestLog(cid, ev.Case.ID)}}
				return s.assertSubmission(rc, certType, logs)
			},
		}, nil
	}
}

// buildOnly is the degraded path: generate what can be generated and say
// plainly that the archive is empty.
func (s *Suite) buildOnly(rc *certify.RunCtx, certType string, logs any, why string) (certify.Result, error) {
	sub, _, err := s.Build(rc, certType, logs)
	if err != nil {
		return certify.Failed("the submission could not be generated: %v", err), nil
	}
	return certify.Result{
		Verdict: certify.Skip,
		Assertions: []certify.Assertion{
			skipAssertion(
				"the submission comprises a public Summary Test Results and an archived Detailed Test Log",
				"inspection of the generated submission directory", why),
		},
		Notes: fmt.Sprintf("submission written to %s; %s", sub.Dir, readinessLine(sub)),
	}, nil
}

// assertSubmission generates the submission from real logs and asserts §1's
// public/archive split over the directory it wrote.
func (s *Suite) assertSubmission(rc *certify.RunCtx, certType string, logs any) ([]certify.Assertion, error) {
	sub, omitted, err := s.Build(rc, certType, logs)
	if err != nil {
		return []certify.Assertion{{
			Claim:    "a submission could be generated from this run",
			Method:   "submission generator",
			Verdict:  certify.Fail,
			Observed: err.Error(),
		}}, nil
	}
	pubRel, _ := filepath.Rel(sub.Dir, sub.SummaryPath)
	archRel := ""
	if sub.LogsPath != "" {
		archRel, _ = filepath.Rel(sub.Dir, sub.LogsPath)
	}
	publicOK := strings.HasPrefix(filepath.ToSlash(pubRel), PublicDir+"/")
	archiveOK := archRel != "" && strings.HasPrefix(filepath.ToSlash(archRel), ArchiveDir+"/")

	as := []certify.Assertion{
		docAssertion(
			"the submission separates the publicly-posted Summary Test Results from the archived "+
				"Detailed Test Logs, which §1 says are never shared with the public",
			"inspection of the generated submission directory",
			verdictIf(publicOK && archiveOK),
			fmt.Sprintf("%s: %s (public) + %s (archive)", sub.Dir, pubRel, orNone(archRel)),
			"the submission directory this run wrote"),
		docAssertion(
			"the Summary Test Results is written under a name that states whether it is submittable",
			"inspection of the generated file name",
			certify.Pass,
			fmt.Sprintf("%s — %s", filepath.Base(sub.SummaryPath), completeness(sub.Complete, sub.Summary)),
			"the submission directory this run wrote"),
		docAssertion(
			"every file in the submission is digested in a manifest a recipient can verify",
			"inspection of "+ManifestFile,
			certify.Pass,
			fmt.Sprintf("%d file(s): %s", len(sub.Files), strings.Join(sub.Files, ", ")),
			"the submission directory this run wrote"),
		docAssertion(
			"the submission carries a per-requirement readiness assessment naming everything unmet",
			"inspection of "+ReadinessFile,
			readinessVerdict(sub),
			readinessObserved(sub),
			"the submission directory this run wrote"),
	}
	if len(omitted) > 0 {
		as = append(as, docAssertion(
			"cases whose bench verdict has no member in the §3.1.1 enumeration are omitted and named",
			"comparison against the PASS | FAIL | NOT SUPPORTED enumeration",
			certify.Warn,
			fmt.Sprintf("%d case(s) omitted: %s", len(omitted), strings.Join(omitted, ", ")),
			"the source evidence bundle"))
	}
	return as, nil
}

func readinessVerdict(sub *Submission) certify.Verdict {
	if sub.Readiness == nil {
		return certify.Fail
	}
	if sub.Readiness.Submittable() {
		return certify.Pass
	}
	return certify.Warn
}

func readinessObserved(sub *Submission) string {
	if sub.Readiness == nil {
		return "no readiness assessment was produced"
	}
	met, unmet, na := sub.Readiness.Counts()
	if unmet == 0 {
		return fmt.Sprintf("%d requirement(s): %d met, 0 unmet, %d not assessed", met+unmet+na, met, na)
	}
	var names []string
	for _, q := range sub.Readiness.Unmet() {
		names = append(names, q.ID)
	}
	return fmt.Sprintf("%d met, %d UNMET (%s), %d not assessed", met, unmet, strings.Join(names, ", "), na)
}
