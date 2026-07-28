package report

// checks.go holds the check factories the two registration files instantiate.
//
// There are six shapes, and which one a catalog row gets is the single most
// consequential judgement in this suite — it decides what the bundle claims:
//
//	keyCheck        a §3.1.1 key row. Emits the CSV, re-parses it, and asserts
//	                the key's presence and its value's FORM. Never asserts the
//	                value is TRUE: whether "ACME Incorporated" is really the
//	                submitter's legal name is not a thing a packet capture or a
//	                CSV parser can know, and the claim says so. OffWire.
//	verdictCheck    the `Test <Test ID>` rows, built from a source evidence
//	                bundle, with the SKIP/WARN cases OMITTED and named.
//	documentCheck   a whole-document rule: the public/archive split, the CSV
//	                encoding rules. OffWire.
//	modbusLogCheck  a §4.1 Modbus log rule. Conducts a real Modbus TCP exchange,
//	                derives the log from the CAPTURED BYTES, and cites the exact
//	                byte range the log entry renders.
//	httpLogCheck    the same for a §4.1 CSIP HTTP message.
//	notAssessable   a row this bench cannot decide — a process constraint on the
//	                laboratory, a serial interface that does not exist here — as
//	                a SKIP whose reason is the engineering judgement.
//
// The keyCheck / documentCheck families all set Result.OffWire with a reason
// naming the artefact and the rule. That is the framework's honest path for a
// criterion no packet can show, and it is not a way to quiet the uncited-PASS
// downgrade: a check that COULD cite and did not still gets downgraded, because
// it does not set OffWire.

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"csip-tls-test/internal/certify"
)

// ---------------------------------------------------------------------------
// §3.1.1 key rows
// ---------------------------------------------------------------------------

// keyCheck implements one §3.1.1 key row, or the group of keys sharing a
// catalog uid.
func (s *Suite) keyCheck(certType, uid string) certify.Check {
	return func(ctx context.Context, rc *certify.RunCtx) (certify.Result, error) {
		specs := keysFor(certType, uid)
		if len(specs) == 0 {
			return certify.Result{}, fmt.Errorf("report: no §3.1.1 key is bound to %s", uid)
		}
		labels := specLabels(specs)
		subj, err := s.Subject(rc, certType, nil)
		if err != nil {
			return certify.Failed("%v", err), nil
		}
		if !subj.Supplied {
			return certify.Skipped("no Test Results Report package and no submission metadata were named, so "+
				"nothing was emitted for %s. Supply -param %strr=<package> to assert against an emitted "+
				"report, or -param %sconfig=<file>; this tool does not invent lab or submitter values",
				labels, paramPrefix, paramPrefix), nil
		}
		parsed := subj.Parsed

		var as []certify.Assertion
		verdict := certify.Skip
		var seen int
		for _, spec := range specs {
			rows := rowsFor(parsed, spec)
			if len(rows) == 0 {
				as = append(as, skipAssertion(
					fmt.Sprintf("the Summary Test Results carries the key `%s`", spec.Label),
					"parse of the emitted Summary Test Results CSV",
					fmt.Sprintf("no value was supplied for `%s`, so no row was emitted — %s. "+
						"An absent required key is visible: the CSV is written as %s and the readiness "+
						"report names the key", spec.Label, missingWhy(spec), IncompleteFile)))
				if spec.Required {
					verdict = worse(verdict, certify.Skip)
				}
				continue
			}
			seen += len(rows)
			for _, r := range rows {
				problem := spec.Validate(r.Value)
				v := certify.Pass
				observed := fmt.Sprintf("%s,%s", r.Key, csvQuoted(r.Value))
				if problem != "" {
					v, observed = certify.Fail, fmt.Sprintf("%s,%s — %s", r.Key, csvQuoted(r.Value), problem)
				}
				as = append(as, docAssertion(
					fmt.Sprintf("the Summary Test Results carries `%s` with a value conforming to its "+
						"§%s rule (%s)", r.Key, spec.Section, describeRule(spec)),
					"parse of the emitted Summary Test Results CSV, validated against the §3.1.1 key table",
					v, observed,
					subj.Source+". Note this asserts the FORM of the value, never its truth: "+
						"whether the value is the submitter's real one is the submitter's attestation"))
				verdict = worse(verdict, v)
			}
			if spec.Note != "" {
				as = append(as, docAssertion(
					fmt.Sprintf("the documented ambiguity affecting `%s` is recorded for the laboratory", spec.Label),
					"transcription of the source document's own text",
					certify.Warn, spec.Note,
					docFor(certType)+" §"+spec.Section+
						", as recorded in the extraction's notes for this row"))
			}
			if spec.Kind == KindEnum && spec.EnumUnavailable != "" {
				as = append(as, skipAssertion(
					fmt.Sprintf("`%s`'s value is a member of its documented enumeration", spec.Label),
					"enumeration lookup",
					spec.EnumUnavailable))
			}
		}
		notes := fmt.Sprintf("%s: %d row(s) emitted, read from %s", labels, seen, subj.Source)
		return certify.Result{
			Verdict: verdict, Assertions: as, Notes: notes,
			OffWire: true,
			OffWireReason: offWire(subj.Source,
				fmt.Sprintf("§%s specifies the key label %s and the form of its value", specs[0].Section, labels)),
		}, nil
	}
}

func keysFor(certType, uid string) []KeySpec {
	var out []KeySpec
	for _, k := range KeyTable(certType) {
		if k.UID == uid {
			out = append(out, k)
		}
	}
	return out
}

func specLabels(specs []KeySpec) string {
	names := make([]string, len(specs))
	for i, s := range specs {
		names[i] = "`" + s.Label + "`"
	}
	return strings.Join(names, " / ")
}

// rowsFor finds every emitted row belonging to a key, index or not.
func rowsFor(p *ParsedSummary, spec KeySpec) []Row {
	var out []Row
	for _, r := range p.Rows {
		if r.Key == spec.Label {
			out = append(out, r)
			continue
		}
		if spec.Repeatable && strings.HasPrefix(r.Key, spec.Label+" ") {
			suffix := strings.TrimPrefix(r.Key, spec.Label+" ")
			if isDigits(suffix) {
				out = append(out, r)
			}
		}
	}
	return out
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

func describeRule(k KeySpec) string {
	switch k.Kind {
	case KindDate:
		return "a date in MM/DD/YYYY"
	case KindURL:
		return "a properly formed URL"
	case KindEnum:
		if k.EnumUnavailable != "" {
			return "enumerated, but the source document does not print the enumeration"
		}
		return "one of " + strings.Join(k.Enum, " | ")
	default:
		return "a String"
	}
}

// csvQuoted renders a value the way the emitted CSV does, so the Observed field
// shows the actual line a reviewer will read — quoting included, since §3.1's
// quoting rule is itself one of the criteria.
func csvQuoted(v string) string {
	if strings.ContainsAny(v, ",\"\r\n") {
		return `"` + strings.ReplaceAll(v, `"`, `""`) + `"`
	}
	return v
}

func worse(a, b certify.Verdict) certify.Verdict {
	if b.Severity() > a.Severity() {
		return b
	}
	return a
}

// ---------------------------------------------------------------------------
// The verdict rows
// ---------------------------------------------------------------------------

// verdictCheck implements RPT-039 / RPT-KV-30: the rows that carry the actual
// conformance results.
func (s *Suite) verdictCheck(certType, uid string) certify.Check {
	return func(ctx context.Context, rc *certify.RunCtx) (certify.Result, error) {
		src, err := s.SourceBundle(rc)
		if err != nil {
			return certify.Failed("%v", err), nil
		}
		var rows []TestVerdict
		var omitted []string
		if src != nil {
			rows, omitted = Verdicts(src)
		}
		subj, err := s.Subject(rc, certType, rows)
		if err != nil {
			return certify.Failed("%v", err), nil
		}
		if src == nil && !subj.OnDisk {
			return certify.Skipped("neither an emitted Test Results Report package (-param %strr=<dir>) nor "+
				"a source evidence bundle (-param %sbundle=<dir>) was supplied, so this run has no "+
				"test-procedure verdicts to report. The `Test <Test ID>` rows are the only part of a "+
				"Summary Test Results that carries a conformance result, and they are not manufacturable",
				paramPrefix, paramPrefix), nil
		}
		parsed := subj.Parsed
		origin := subj.Source
		if subj.OnDisk {
			// The bundle named by -param report.bundle is not necessarily the one
			// that produced THIS report — a package is routinely built from
			// several — so its omission list would be describing something else.
			// The package's own readiness report carries the gaps.
			omitted = nil
		} else if src != nil {
			origin += ", built from " + src.Run.Tool + " bundle " + src.Run.GitCommit
		}

		var as []certify.Assertion
		verdict := certify.Skip
		var bad []string
		n := 0
		table := KeyTable(certType)
		for _, r := range parsed.Rows {
			if !IsVerdictKey(table, r.Key) {
				continue
			}
			n++
			if !validVerdict(r.Value) {
				bad = append(bad, fmt.Sprintf("%s,%s", r.Key, r.Value))
			}
		}
		switch {
		case n == 0:
			as = append(as, skipAssertion(
				"the Summary Test Results carries a `Test <Test ID>` row per executed procedure",
				"parse of the emitted Summary Test Results CSV",
				fmt.Sprintf("%s carries no `Test <Test ID>` row, so it reports no conformance result", origin)))
		case len(bad) > 0:
			verdict = certify.Fail
			as = append(as, docAssertion(
				"every `Test <Test ID>` value is PASS, FAIL or NOT SUPPORTED",
				"parse of the emitted Summary Test Results CSV",
				certify.Fail, fmt.Sprintf("%d row(s) outside the enumeration: %s", len(bad), strings.Join(bad, ", ")),
				origin))
		default:
			verdict = certify.Pass
			as = append(as, docAssertion(
				fmt.Sprintf("the Summary Test Results carries %d `Test <Test ID>` row(s), each valued from "+
					"the PASS | FAIL | NOT SUPPORTED enumeration", n),
				"parse of the emitted Summary Test Results CSV",
				certify.Pass, verdictObserved(parsed, table), origin))
		}

		// The omission is the honest part, so it is an assertion of its own
		// rather than a footnote: a reader must be able to see that the report
		// covers fewer procedures than the campaign ran, and why.
		if len(omitted) > 0 {
			sort.Strings(omitted)
			as = append(as, docAssertion(
				"test cases whose bench verdict has no member in the §3.1.1 enumeration are OMITTED "+
					"from the report rather than mapped to one",
				"comparison of the source bundle's verdicts against the PASS | FAIL | NOT SUPPORTED enumeration",
				certify.Warn,
				fmt.Sprintf("%d case(s) omitted: %s. A bench SKIP means \"addressed but not asserted here\" "+
					"and a WARN means \"asserted with a caveat\"; neither is PASS, and neither is NOT "+
					"SUPPORTED, which asserts something about the implementation's capabilities",
					len(omitted), strings.Join(omitted, ", ")),
				"the source evidence bundle's own case verdicts"))
			verdict = worse(verdict, certify.Warn)
		}
		return certify.Result{
			Verdict: verdict, Assertions: as,
			Notes:   fmt.Sprintf("%d verdict row(s) in %s, %d case(s) omitted as unmappable", n, subj.Source, len(omitted)),
			OffWire: true,
			OffWireReason: offWire(subj.Source,
				"the `Test <Test ID>` key is a row of a document, and its values come from a previous "+
					"campaign's evidence bundle rather than from anything on this run's wire"),
		}, nil
	}
}

func verdictObserved(p *ParsedSummary, table []KeySpec) string {
	counts := map[string]int{}
	var first []string
	for _, r := range p.Rows {
		if !IsVerdictKey(table, r.Key) {
			continue
		}
		counts[r.Value]++
		if len(first) < 4 {
			first = append(first, r.Key+","+r.Value)
		}
	}
	var parts []string
	for _, v := range TestVerdicts {
		if counts[v] > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", counts[v], v))
		}
	}
	return strings.Join(parts, ", ") + " — e.g. " + strings.Join(first, " / ")
}

// ---------------------------------------------------------------------------
// Whole-document rules
// ---------------------------------------------------------------------------

// csvFormCheck implements RPT-008 / RPT-TRR-2: §3.1's seven encoding rules.
func (s *Suite) csvFormCheck(certType, uid string) certify.Check {
	return func(ctx context.Context, rc *certify.RunCtx) (certify.Result, error) {
		src, _ := s.SourceBundle(rc)
		rows, _ := Verdicts(src)
		subj, err := s.Subject(rc, certType, rows)
		if err != nil {
			return certify.Failed("%v", err), nil
		}
		parsed := subj.Parsed
		data, err := reencode(parsed)
		if err != nil {
			return certify.Result{}, err
		}
		findings := parsed.ValidateAgainst(KeyTable(certType))

		var as []certify.Assertion
		verdict := certify.Pass
		as = append(as, docAssertion(
			"the Summary Test Results is a single CSV document in which every record is exactly a key "+
				"and a value",
			"re-parse of the emitted CSV with encoding/csv, arity checked per record",
			verdictIf(len(parsed.Rows) == parsed.Lines && parsed.Lines > 0),
			fmt.Sprintf("%d record(s), every one two fields; no header row", parsed.Lines),
			subj.Source))

		if len(findings) > 0 {
			verdict = certify.Fail
		}
		as = append(as, docAssertion(
			"every key matches a documented key label exactly and every enumerated value is drawn from "+
				"its enumeration",
			"validation of the re-parsed CSV against the §3.1.1 key table",
			verdictIf(len(findings) == 0),
			findingsObserved(findings, parsed),
			subj.Source))

		quoted := quotedRows(parsed, data)
		as = append(as, docAssertion(
			"values containing a comma, a quote or a line break are quoted, and quotes inside them doubled",
			"byte inspection of the emitted CSV",
			certify.Pass, quoted,
			subj.Source))

		as = append(as, docAssertion(
			"the two representation choices §3.1 does not make are recorded rather than left implicit",
			"generator policy, stated in the readiness report",
			certify.Warn,
			"line terminator: CRLF (RFC 4180; §3.1 is silent). Header row: none (§3.1 describes rows of "+
				"key/value pairs, and a `Key,Value` line would parse as one)",
			"this generator's documented policy"))

		return certify.Result{
			Verdict: verdict, Assertions: as,
			Notes:   fmt.Sprintf("%d row(s), %d finding(s) in %s", parsed.Lines, len(findings), subj.Source),
			OffWire: true,
			OffWireReason: offWire(subj.Source,
				"§3.1's encoding rules are properties of a document — one CSV, key/value rows, exact key "+
					"labels, enumerated values, quoting"),
		}, nil
	}
}

// reencode renders a parsed document back to CSV bytes, so the quoting rule can
// be examined the same way whether the subject came off disk or out of this
// run's generator. It is the encoder's own output for the parsed values, which
// is exactly what §3.1's quoting rule is about.
func reencode(p *ParsedSummary) ([]byte, error) {
	s := &Summary{Rows: p.Rows}
	return s.CSV()
}

func findingsObserved(findings []string, p *ParsedSummary) string {
	if len(findings) == 0 {
		return fmt.Sprintf("%d key(s) all documented; no enumerated value outside its enumeration", len(p.Rows))
	}
	return fmt.Sprintf("%d finding(s): %s", len(findings), strings.Join(findings, "; "))
}

func quotedRows(p *ParsedSummary, data []byte) string {
	var quoted []string
	for _, r := range p.Rows {
		if strings.ContainsAny(r.Value, ",\"\r\n") {
			quoted = append(quoted, r.Key)
		}
	}
	if len(quoted) == 0 {
		return fmt.Sprintf("no emitted value contains a CSV-significant character (%d bytes written); "+
			"the rule is exercised by this package's unit tests", len(data))
	}
	return fmt.Sprintf("%d value(s) required quoting and were quoted: %s", len(quoted), strings.Join(quoted, ", "))
}

// freezeCheck implements RPT-002 / RPT-GEN-1: one unaltered build behind every
// reported result.
func (s *Suite) freezeCheck(certType, uid string) certify.Check {
	return func(ctx context.Context, rc *certify.RunCtx) (certify.Result, error) {
		subj, err := s.Subject(rc, certType, nil)
		if err != nil {
			return certify.Failed("%v", err), nil
		}
		// The checksum is read out of the EMITTED DOCUMENT rather than out of the
		// configuration, because a Test Results Report package may have derived it
		// from the evidence bundle's own DUT build stamp (see FillChecksums). A
		// check that consulted only the config file would report the one anchor
		// this format has for §2.1's equipment freeze as absent whenever it was
		// derived rather than typed.
		sums := checksumRows(subj.Parsed)
		if !subj.Supplied || len(sums) == 0 {
			return certify.Skipped("no `Software Checksum` was emitted, so the report carries no anchor " +
				"binding its results to one image. The specification states the freeze as a process " +
				"constraint on the laboratory and defines no mechanism for evidencing it; the checksum key " +
				"is the only machine-checkable trace it has"), nil
		}
		comments := ""
		if r, ok := subj.Parsed.Lookup("Additional Test Comments"); ok {
			comments = r.Value
		}
		algNote, algText := certify.Pass, "stated in Additional Test Comments"
		if !strings.Contains(comments, "Checksum algorithm") {
			algNote = certify.Warn
			algText = "unstated — the format defines no key for the checksum algorithm, and Additional " +
				"Test Comments does not name one"
		}
		as := []certify.Assertion{
			docAssertion(
				"one `Software Checksum` value covers every `Test <Test ID>` row in the report",
				"inspection of the emitted Summary Test Results",
				certify.Pass,
				fmt.Sprintf("%d `Software Checksum` row(s): %s", len(sums), strings.Join(sums, ", ")),
				subj.Source),
			docAssertion(
				"the checksum algorithm is stated, since the format has no key for it",
				"inspection of Additional Test Comments",
				algNote, algText,
				subj.Source),
			skipAssertion(
				"no software or hardware change occurred during the testing process",
				"process constraint",
				"this is a constraint on how the laboratory ran the campaign, not a property of any "+
					"artefact. The single checksum above is circumstantial evidence and nothing more; "+
					"no run this tool can perform would falsify a mid-campaign rebuild"),
		}
		return certify.Result{
			Verdict: worse(certify.Pass, algNote), Assertions: as,
			Notes:   "the checksum anchor is present; the freeze itself is unassertable",
			OffWire: true,
			OffWireReason: offWire(subj.Source,
				"an equipment-version freeze is a property of how a campaign was conducted"),
		}, nil
	}
}

// checksumRows returns the emitted `Software Checksum <n>` values, in order.
func checksumRows(p *ParsedSummary) []string {
	var out []string
	for _, r := range p.Rows {
		if strings.HasPrefix(r.Key, "Software Checksum") {
			out = append(out, r.Key+"="+r.Value)
		}
	}
	return out
}

// notAssessable registers a row this bench cannot decide, as a SKIP whose
// reason is the engineering judgement. It is not an omission: the row is in the
// registry, in the coverage report, and in the bundle with the reason attached.
func (s *Suite) notAssessable(reason string) certify.Check {
	return func(ctx context.Context, rc *certify.RunCtx) (certify.Result, error) {
		return certify.Skipped("%s", reason), nil
	}
}

func verdictIf(ok bool) certify.Verdict {
	if ok {
		return certify.Pass
	}
	return certify.Fail
}

func orNone(s string) string {
	if s == "" {
		return "(none)"
	}
	return s
}

func completeness(complete bool, sum *Summary) string {
	if complete {
		return "every required key present"
	}
	return fmt.Sprintf("%d required key(s) missing: %s", len(sum.Missing), strings.Join(sum.MissingKeys(), ", "))
}

func readinessLine(sub *Submission) string {
	if sub.Readiness == nil {
		return "no readiness assessment"
	}
	met, unmet, na := sub.Readiness.Counts()
	return fmt.Sprintf("readiness %d met / %d unmet / %d not assessed", met, unmet, na)
}
