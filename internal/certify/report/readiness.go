package report

// readiness.go is the tool assessing its own submission.
//
// "Did the run pass?" and "is the submission ready?" are different questions,
// and a tool that answers only the first is the tool a lab sends back. A
// submission can carry a hundred PASS verdicts and still be unsubmittable
// because nobody supplied the certificate number, or because the detailed logs
// were derived from a capture that began mid-connection, or because the
// COMM-004 traces were never exported. Readiness answers the second question,
// requirement by requirement, keyed by catalog uid.
//
// Three outcomes, and the distinction between the last two is the whole point:
//
//	Met          the artefacts satisfy the requirement, and here is what was checked
//	Unmet        the requirement is not satisfied, and here is exactly what is missing
//	NotAssessed  this requirement is not decidable from the artefacts — a process
//	             constraint on the laboratory, an enumeration the source document
//	             does not print, a role the DUT does not play — with the reason
//
// A NotAssessed row is not a soft pass. Submittable() requires zero Unmet AND
// it prints the NotAssessed count next to its verdict, so the reader always
// sees how much of the specification this tool declined to judge.

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// ReqStatus is one requirement's readiness outcome.
type ReqStatus string

// The three outcomes.
const (
	ReqMet         ReqStatus = "MET"
	ReqUnmet       ReqStatus = "UNMET"
	ReqNotAssessed ReqStatus = "NOT ASSESSED"
)

// Requirement is one RPT-* row's readiness.
type Requirement struct {
	UID string `json:"uid"`
	ID  string `json:"id"`
	// Statement is this tool's restatement of what the row requires, written
	// here rather than copied from the catalog so the readiness report is
	// readable standalone.
	Statement string    `json:"statement"`
	Status    ReqStatus `json:"status"`
	// Detail says what was checked, or exactly what is absent.
	Detail string `json:"detail"`
}

// Readiness is the whole self-assessment.
type Readiness struct {
	Doc          string    `json:"doc"`
	CertType     string    `json:"certificate_type"`
	Generated    time.Time `json:"generated"`
	Tool         string    `json:"tool,omitempty"`
	ToolVersion  string    `json:"tool_version,omitempty"`
	ConfigSource string    `json:"config_source,omitempty"`
	// ConfigSupplied is false only when NOTHING was supplied — the honest state
	// of an unconfigured bench run, and a different thing from metadata that
	// came from flags rather than a file.
	ConfigSupplied bool          `json:"config_supplied"`
	Requirements   []Requirement `json:"requirements"`
}

// AssessInput is everything Assess judges.
type AssessInput struct {
	Doc         string
	CertType    string
	Config      *SubmissionConfig
	Summary     *Summary
	ModbusLogs  *ModbusTestLogs
	CSIPLogs    *CSIPTestLogs
	Transport   Transport
	Traces      []TraceInfo
	Generated   time.Time
	Tool        string
	ToolVersion string
}

// Counts tallies the outcomes.
func (r *Readiness) Counts() (met, unmet, notAssessed int) {
	for _, q := range r.Requirements {
		switch q.Status {
		case ReqMet:
			met++
		case ReqUnmet:
			unmet++
		default:
			notAssessed++
		}
	}
	return
}

// Submittable reports whether nothing is Unmet.
func (r *Readiness) Submittable() bool {
	_, unmet, _ := r.Counts()
	return unmet == 0
}

// Unmet returns the failing requirements, for an error message.
func (r *Readiness) Unmet() []Requirement {
	var out []Requirement
	for _, q := range r.Requirements {
		if q.Status == ReqUnmet {
			out = append(out, q)
		}
	}
	return out
}

// Find returns one requirement's assessment by catalog uid, which is how a
// certify check asks "what did the generator conclude about the row I am
// implementing?".
func (r *Readiness) Find(uid string) (Requirement, bool) {
	for _, q := range r.Requirements {
		if q.UID == uid {
			return q, true
		}
	}
	return Requirement{}, false
}

// Assess produces the self-assessment.
func Assess(in AssessInput) *Readiness {
	if in.Generated.IsZero() {
		in.Generated = time.Now().UTC()
	}
	if in.Transport == "" {
		in.Transport = TransportTCP
	}
	r := &Readiness{
		Doc: in.Doc, CertType: in.CertType, Generated: in.Generated,
		Tool: in.Tool, ToolVersion: in.ToolVersion,
	}
	if in.Config != nil {
		r.ConfigSource = in.Config.Source
		r.ConfigSupplied = !in.Config.Empty()
	}
	r.Requirements = append(r.Requirements, assessKeys(in)...)
	if in.CertType == CertTypeModbus {
		r.Requirements = append(r.Requirements, assessModbusStructure(in)...)
	} else {
		r.Requirements = append(r.Requirements, assessCSIPStructure(in)...)
	}
	order := caseOrder(in.CertType)
	sort.SliceStable(r.Requirements, func(i, j int) bool {
		return order[r.Requirements[i].ID] < order[r.Requirements[j].ID]
	})
	return r
}

// assessKeys turns the §3.1.1 key table into one requirement per catalog uid.
// Several keys can share a uid (the §3.1.2 example rows do), so the outcomes
// are merged: any Unmet wins.
func assessKeys(in AssessInput) []Requirement {
	sum := in.Summary
	byUID := map[string]*Requirement{}
	var order []string
	problems := map[string][]string{}
	if sum != nil {
		for _, p := range sum.Problems {
			key, _, _ := strings.Cut(p, ":")
			problems[strings.TrimSpace(key)] = append(problems[strings.TrimSpace(key)], p)
		}
	}
	for _, k := range KeyTable(in.CertType) {
		q, ok := byUID[k.UID]
		if !ok {
			q = &Requirement{
				UID: k.UID, ID: idOf(k.UID),
				Statement: fmt.Sprintf("Summary Test Results carries the §%s key `%s` with a %s value",
					k.Section, k.Label, k.Kind),
				Status: ReqMet,
			}
			byUID[k.UID] = q
			order = append(order, k.UID)
		}
		emitted := 0
		var bad []string
		if sum != nil {
			for _, row := range sum.Rows {
				if row.Verdict || row.Spec.Label != k.Label {
					continue
				}
				emitted++
				bad = append(bad, problems[row.Key]...)
			}
		}
		switch {
		case len(bad) > 0:
			q.Status = ReqUnmet
			q.Detail = joinDetail(q.Detail, strings.Join(bad, "; "))
		case emitted > 0:
			q.Detail = joinDetail(q.Detail, fmt.Sprintf("`%s`: %d row(s) emitted and valid", k.Label, emitted))
			if k.Kind == KindEnum && k.EnumUnavailable != "" {
				q.Detail = joinDetail(q.Detail, "the enumeration itself could not be checked: "+k.EnumUnavailable)
			}
		case k.Required:
			q.Status = ReqUnmet
			q.Detail = joinDetail(q.Detail, fmt.Sprintf(
				"`%s` is required and has no value — %s", k.Label, missingWhy(k)))
		default:
			if q.Status == ReqMet && q.Detail == "" {
				q.Status = ReqNotAssessed
				q.Detail = fmt.Sprintf("`%s` is optional and was not supplied, so nothing was emitted for it", k.Label)
			}
		}
		if k.Note != "" {
			q.Detail = joinDetail(q.Detail, "documented ambiguity: "+k.Note)
		}
	}
	out := make([]Requirement, 0, len(order))
	for _, uid := range order {
		out = append(out, *byUID[uid])
	}
	return out
}

func joinDetail(a, b string) string {
	switch {
	case a == "":
		return b
	case b == "":
		return a
	default:
		return a + "; " + b
	}
}

func idOf(uid string) string {
	if _, id, ok := strings.Cut(uid, "::"); ok {
		return id
	}
	return uid
}

// req is the terse constructor the structural assessors use.
func req(uid, statement string, status ReqStatus, detail string) Requirement {
	return Requirement{UID: uid, ID: idOf(uid), Statement: statement, Status: status, Detail: detail}
}

func metIf(ok bool, metDetail, unmetDetail string) (ReqStatus, string) {
	if ok {
		return ReqMet, metDetail
	}
	return ReqUnmet, unmetDetail
}

// verdictSummary describes the emitted `Test <Test ID>` rows.
func verdictSummary(sum *Summary) (n int, detail string) {
	if sum == nil {
		return 0, "no Summary Test Results was built"
	}
	rows := sum.Verdicts()
	if len(rows) == 0 {
		return 0, "no `Test <Test ID>` row was emitted, so the report carries no conformance result"
	}
	counts := map[string]int{}
	for _, r := range rows {
		counts[r.Value]++
	}
	var parts []string
	for _, v := range TestVerdicts {
		if counts[v] > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", counts[v], v))
		}
	}
	return len(rows), fmt.Sprintf("%d verdict row(s): %s", len(rows), strings.Join(parts, ", "))
}

// assessCSIPStructure judges the SS-CSIP-RESULTS-v1.1 rows that are not key
// rows.
func assessCSIPStructure(in AssessInput) []Requirement {
	var out []Requirement
	sum := in.Summary
	logs := in.CSIPLogs
	logFindings := ValidateCSIPTestLogs(logs)
	haveLogs := logs != nil && len(logs.Logs) > 0
	csvOK, csvDetail := summaryFormOK(sum, in.CertType)

	add := func(r Requirement) { out = append(out, r) }

	st, d := metIf(sum != nil && haveLogs,
		"a public Summary Test Results CSV and a private Detailed Test Log JSON were both written, "+
			"into separate public/ and archive/ directories",
		"the two-part deliverable is incomplete: "+missingHalves(sum != nil, haveLogs))
	add(req(uidCSIP("RPT-001"), "the submission is split into the publicly-posted TRR data and the archived detailed logs", st, d))

	add(req(uidCSIP("RPT-002"), "every result came from one unaltered software/hardware build",
		ReqNotAssessed, softwareFreezeDetail(in)))
	add(req(uidCSIP("RPT-003"), "the complete equipment configuration is documented well enough to replicate the test",
		ReqNotAssessed, "the specification defines no format, key set or location for the configuration "+
			"document, so this tool cannot emit or check one; it is a submitter attachment"))
	add(req(uidCSIP("RPT-004"), "the client's configuration was frozen before and throughout the campaign",
		ReqNotAssessed, "a process constraint on the laboratory. The bench can evidence it only "+
			"circumstantially, by a single Software Checksum covering the whole campaign"))
	add(req(uidCSIP("RPT-005"), "an aggregator client's configuration changed only where a test directed it",
		ReqNotAssessed, "the DUT is a CSIP client, not an aggregator client; the catalog marks this row inapplicable"))
	add(req(uidCSIP("RPT-006"), "a server's configuration changed only where a test directed it",
		ReqNotAssessed, "the DUT is a CSIP client, not a server; the catalog marks this row inapplicable"))

	st, d = metIf(sum != nil && haveLogs,
		"both elements are present and the detailed log names the test procedures it evidences",
		"one of the two mandatory TRR elements is absent: "+missingHalves(sum != nil, haveLogs))
	add(req(uidCSIP("RPT-007"), "the TRR comprises Summary Test Results plus a Detailed Test Log for all tests", st, d))

	st, d = metIf(csvOK, csvDetail, csvDetail)
	add(req(uidCSIP("RPT-008"), "the Summary Test Results is one CSV of key/value rows obeying §3.1's encoding rules", st, d))

	n, vd := verdictSummary(sum)
	st, d = metIf(n > 0, vd, vd)
	add(req(uidCSIP("RPT-039"), "a `Test <Test ID>` row carries PASS, FAIL or NOT SUPPORTED for every procedure executed", st, d))

	add(req(uidCSIP("RPT-040"), "the worked example's extra keys (Certificate Type Version, Company State/Province)",
		ReqNotAssessed, "these keys appear in the §3.1.2 example and are defined nowhere in the document. "+
			"They are emitted only when the operator supplies them, and flagged for the laboratory rather "+
			"than guessed at"))
	add(req(uidCSIP("RPT-041"), "the verdict rows cover the test procedures a client submission is expected to carry",
		ReqNotAssessed, "the authoritative applicability matrix lives in the CSIP Conformance Test Procedures "+
			"document, not in the results-reporting specification; this tool reports the verdicts it was given "+
			"and does not invent a required-test list"))

	st, d = metIf(haveLogs && len(logFindings) == 0,
		fmt.Sprintf("%s, every message in plaintext HTTP form", describeCSIPLogs(logs)),
		csipLogDetail(haveLogs, logFindings))
	add(req(uidCSIP("RPT-050"), "the detailed logs carry every HTTP(S) message, unencrypted, JSON-encoded", st, d))

	st, d = metIf(haveLogs && len(logFindings) == 0,
		"every Test Log Object carries a non-empty `tests` array and a `messages` array",
		csipLogDetail(haveLogs, logFindings))
	add(req(uidCSIP("RPT-051"), "Test Log Object: tests[], optional cid, messages[]", st, d))
	add(req(uidCSIP("RPT-052"), "Message Object: time, type, method, uri, vers, headers, body", st, d))

	st, d = metIf(haveLogs && subSecond(logs),
		"message timestamps carry sub-second decimals, exceeding the MUST-level second accuracy",
		"sub-second timestamps could not be confirmed: "+csipLogDetail(haveLogs, logFindings))
	add(req(uidCSIP("RPT-053"), "message timestamps have at least second accuracy, ideally sub-second", st, d))

	st, d = metIf(haveLogs && len(logFindings) == 0,
		"response messages carry `code` as a string and `reason` with its trailing CRLF, as the §4.1.2 example does",
		csipLogDetail(haveLogs, logFindings))
	add(req(uidCSIP("RPT-054"), "a logged response carries its status code, reason and full header set", st, d))

	st, d = metIf(haveLogs,
		"the detailed logs are delivered as one Test Logs Object with a `logs` array",
		"no Test Logs Object was written")
	add(req(uidCSIP("RPT-055"), "Test Logs Object: logs[], optional cid", st, d))

	st, d = traceStatus(in.Traces)
	add(req(uidCSIP("RPT-060"), "a raw TLS packet trace accompanies each COMM-004 certificate scenario", st, d))
	return out
}

// assessModbusStructure judges the SS-MODBUS-RESULTS-v1.2 non-key rows.
func assessModbusStructure(in AssessInput) []Requirement {
	var out []Requirement
	sum := in.Summary
	logs := in.ModbusLogs
	findings := ValidateModbusTestLogs(logs, in.Transport)
	haveLogs := logs != nil && len(logs.Logs) > 0
	csvOK, csvDetail := summaryFormOK(sum, in.CertType)
	add := func(r Requirement) { out = append(out, r) }

	lst, ldet := labStatus(in.Config)
	add(req(uidModbus("RPT-APX-1"), "Test Laboratory is one of the thirteen authorized NRTLs", lst, ldet))
	dst, ddet := descriptionStatus(in.Config)
	add(req(uidModbus("RPT-APX-2"), "Test Description is one of the three SunSpec Modbus certification offerings",
		dst, ddet))

	add(req(uidModbus("RPT-GEN-1"), "the equipment version did not change during the campaign",
		ReqNotAssessed, softwareFreezeDetail(in)))
	add(req(uidModbus("RPT-GEN-2"), "the complete equipment configuration is documented for replication",
		ReqNotAssessed, "the specification defines no format, schema or delivery mechanism for the "+
			"configuration record; it is a submitter attachment this tool neither emits nor checks"))
	add(req(uidModbus("RPT-GEN-3"), "the device was configured before the run and not reconfigured during it",
		ReqNotAssessed, "a process constraint on the laboratory. The detailed logs make it inspectable — every "+
			"write function code is in them — but deciding which writes were test-directed needs the "+
			"procedure document"))

	st, d := metIf(sum != nil && haveLogs,
		"a public Summary Test Results CSV and a private Detailed Test Log JSON were both written, "+
			"into separate public/ and archive/ directories",
		"the two-part deliverable is incomplete: "+missingHalves(sum != nil, haveLogs))
	add(req(uidModbus("RPT-TRR-1"), "the TRR is Summary Test Results plus a Detailed Test Log for all tests", st, d))

	st, d = metIf(csvOK, csvDetail, csvDetail)
	add(req(uidModbus("RPT-TRR-2"), "the Summary Test Results obeys §3.1's CSV encoding rules", st, d))

	add(req(uidModbus("RPT-TRR-3"), "the worked example's test-ID namespace and its two undocumented keys",
		ReqNotAssessed, "the §3.1.2 example is non-normative and is the only place concrete SunSpec Modbus "+
			"test IDs appear; the procedures themselves live in a companion document this tool was not given"))

	n, vd := verdictSummary(sum)
	st, d = metIf(n > 0, vd, vd)
	add(req(uidModbus("RPT-KV-30"), "a `Test <Test ID>` row carries PASS, FAIL or NOT SUPPORTED per procedure", st, d))

	logOK := haveLogs && len(findings) == 0
	detail := modbusLogDetail(haveLogs, logs, findings)
	pairDetail := detail
	if logOK {
		paired, unmatched := PairTransactions(allEntries(logs))
		if len(unmatched) > 0 {
			logOK = false
			pairDetail = fmt.Sprintf("%s; but %d message(s) are unpaired, so the log is not the complete "+
				"exchange §4 requires: %s", detail, len(unmatched), strings.Join(unmatched, "; "))
		} else {
			pairDetail = fmt.Sprintf("%s; %d request/response pair(s) reconcile by MBAP transaction id",
				detail, paired)
		}
	}

	st, d = metIf(logOK, pairDetail, pairDetail)
	add(req(uidModbus("RPT-LOG-1"), "the logs carry every Modbus message plus TCP connection information", st, d))

	st, d = metIf(haveLogs && len(findings) == 0 && noCiphertext(logs), detail,
		joinDetail(detail, "a `msg` value did not decode to a Modbus PDU"))
	add(req(uidModbus("RPT-LOG-2"), "every logged Modbus message is in unencrypted form", st, d))

	for _, uid := range []string{"RPT-LOG-3", "RPT-LOG-4", "RPT-LOG-5", "RPT-LOG-7",
		"RPT-LOG-8", "RPT-LOG-10", "RPT-LOG-11", "RPT-LOG-12", "RPT-LOG-13", "RPT-LOG-14",
		"RPT-LOG-15", "RPT-LOG-16"} {
		st, d = metIf(haveLogs && len(findings) == 0, detail, detail)
		add(req(uidModbus(uid), modbusLogStatement(uid), st, d))
	}

	st, d = metIf(haveLogs && modbusSubSecond(logs),
		joinDetail(detail, "entry timestamps carry sub-second decimals, exceeding the MUST-level second accuracy"),
		joinDetail(detail, "sub-second entry timestamps could not be confirmed"))
	add(req(uidModbus("RPT-LOG-6"), "entry timestamps have at least second accuracy, ideally sub-second", st, d))

	add(req(uidModbus("RPT-LOG-9"), "an RTU `msg` is unit id, function code, data and CRC, with no MBAP header",
		ReqNotAssessed, "no Modbus RTU interface was exercised: this bench reaches the DUT over Modbus TCP "+
			"only. The RTU framing rule is implemented and unit-tested (DecodeRTU), but a rule with no "+
			"exchange behind it is not evidence"))
	return out
}

func modbusLogStatement(id string) string {
	switch id {
	case "RPT-LOG-3":
		return "the detailed logs are JSON, using the Test Log, Test Logs and Log Entry objects"
	case "RPT-LOG-4":
		return "Test Log Object: tests[] and entries[]"
	case "RPT-LOG-5":
		return "a Log Entry Object holds one Modbus message or one connection event"
	case "RPT-LOG-7":
		return "`type` is req, resp, conn or disc"
	case "RPT-LOG-8":
		return "`msg` is the complete Modbus message as an ascii hex string"
	case "RPT-LOG-10":
		return "a TCP `msg` includes the full MBAP header and a consistent Length field"
	case "RPT-LOG-11":
		return "`ipaddr` records the Modbus TCP connection's IP address"
	case "RPT-LOG-12":
		return "`ipport` records the Modbus TCP connection's port"
	case "RPT-LOG-13":
		return "every entry carries `time` and `type`"
	case "RPT-LOG-14":
		return "every req/resp entry carries `msg`"
	case "RPT-LOG-15":
		return "every conn entry carries `ipaddr` and `ipport`"
	case "RPT-LOG-16":
		return "Test Logs Object: logs[]"
	}
	return id
}

func missingHalves(haveSummary, haveLogs bool) string {
	switch {
	case !haveSummary && !haveLogs:
		return "neither the Summary Test Results nor the Detailed Test Logs were produced"
	case !haveSummary:
		return "the Summary Test Results was not produced"
	default:
		return "the Detailed Test Logs were not produced, so no result in the summary has evidence behind it"
	}
}

// summaryFormOK re-parses the emitted CSV and validates it against the key
// table — a check of the FILE, not of the model, and the same check a reviewer
// could run on the submitted document alone.
func summaryFormOK(sum *Summary, certType string) (bool, string) {
	if sum == nil {
		return false, "no Summary Test Results was built"
	}
	data, err := sum.CSV()
	if err != nil {
		return false, "the Summary Test Results could not be encoded as CSV: " + err.Error()
	}
	parsed, err := ParseSummary(data)
	if err != nil {
		return false, "the emitted CSV does not re-parse: " + err.Error()
	}
	findings := parsed.ValidateAgainst(KeyTable(certType))
	if len(findings) > 0 {
		return false, fmt.Sprintf("the emitted CSV has %d conformance finding(s): %s",
			len(findings), strings.Join(findings, "; "))
	}
	return true, fmt.Sprintf("%d row(s), each a key and a value, re-parsed from the written file and "+
		"validated against the §3.1.1 key table; RFC 4180 quoting, CRLF terminators, no header row", parsed.Lines)
}

func softwareFreezeDetail(in AssessInput) string {
	if in.Config == nil || len(in.Config.Software) == 0 || in.Config.Software[0].Checksum == "" {
		return "a process constraint on the laboratory, evidenced only circumstantially. No Software " +
			"Checksum was supplied, so even the circumstantial evidence is absent"
	}
	alg := in.Config.ChecksumAlgorithm
	if alg == "" {
		alg = "an unstated algorithm (the format defines no key for it)"
	}
	return fmt.Sprintf("a process constraint on the laboratory. One Software Checksum (%s, %s) covers "+
		"every verdict row in this report, which is the strongest evidence the format can carry",
		in.Config.Software[0].Checksum, alg)
}

func labStatus(cfg *SubmissionConfig) (ReqStatus, string) {
	if cfg == nil || cfg.TestLaboratory == "" {
		return ReqNotAssessed, "no Test Laboratory was supplied. This value cannot be derived from a bench " +
			"run: certification requires one of the thirteen Appendix A1 laboratories to run or witness the test"
	}
	for _, l := range AuthorizedLabs {
		if cfg.TestLaboratory == l {
			return ReqMet, fmt.Sprintf("%q is in the Appendix A1 enumeration", cfg.TestLaboratory)
		}
	}
	return ReqUnmet, fmt.Sprintf("%q is not one of the thirteen authorized laboratories (%s)",
		cfg.TestLaboratory, strings.Join(AuthorizedLabs, ", "))
}

func descriptionStatus(cfg *SubmissionConfig) (ReqStatus, string) {
	if cfg == nil || cfg.TestDescription == "" {
		return ReqNotAssessed, "no Test Description was supplied, so the certification offering — and " +
			"therefore the expected set of `Test <Test ID>` rows — is undeclared"
	}
	for _, d := range ModbusTestDescriptions {
		if cfg.TestDescription == d {
			return ReqMet, fmt.Sprintf("%q is one of the three Appendix A2 offerings", cfg.TestDescription)
		}
	}
	return ReqUnmet, fmt.Sprintf("%q is not one of %s", cfg.TestDescription,
		strings.Join(ModbusTestDescriptions, ", "))
}

func traceStatus(traces []TraceInfo) (ReqStatus, string) {
	if len(traces) == 0 {
		return ReqNotAssessed, "no COMM-004 connection scenario ran in this campaign, so there is no " +
			"handshake to trace. Chapter 5 applies to COMM-004 only"
	}
	var bad []string
	for _, t := range traces {
		switch {
		case t.TLS.Problem != "":
			bad = append(bad, fmt.Sprintf("%s: %s", t.Scenario, t.TLS.Problem))
		case len(t.TLS.Handshake) == 0:
			bad = append(bad, fmt.Sprintf("%s: the trace carries no plaintext handshake message", t.Scenario))
		case !t.TLS.Complete && !t.TLS.FatalAlert && !t.TLS.Terminated:
			bad = append(bad, fmt.Sprintf("%s: the trace neither completes the handshake nor shows a "+
				"refusal, so it does not evidence an outcome", t.Scenario))
		}
	}
	if len(bad) > 0 {
		return ReqUnmet, fmt.Sprintf("%d of %d trace(s) do not evidence a connection outcome: %s",
			len(bad), len(traces), strings.Join(bad, "; "))
	}
	var parts []string
	for _, t := range traces {
		outcome := "handshake completed"
		if t.TLS.FatalAlert {
			outcome = "refused with a fatal alert"
		} else if !t.TLS.Complete {
			outcome = "terminated without completing"
		}
		parts = append(parts, fmt.Sprintf("%s (%d frames, %d TLS records, %s)",
			t.Scenario, len(t.Frames), t.TLS.Records, outcome))
	}
	return ReqMet, fmt.Sprintf("%d libpcap trace(s), each re-read after writing and confirmed to contain "+
		"the connection's TLS records: %s", len(traces), strings.Join(parts, "; "))
}

// describeCSIPLogs summarises the CSIP detailed logs.
//
// The nil guard is load-bearing rather than defensive habit. Every call site is
// an argument to metIf, and Go evaluates BOTH of metIf's branches before the
// call — so the "met" description is built even when haveLogs is false and the
// pointer is nil. That is the ORDINARY case for a submission whose CSIP traffic
// rode TLS and was never rendered into plaintext, and without this guard the
// generator panicked while assembling the very row whose job is to report the
// artefact absent. Its Modbus twin, allEntries, has always had the same guard.
func describeCSIPLogs(l *CSIPTestLogs) string {
	if l == nil {
		return "0 test log(s) carrying 0 HTTP message(s)"
	}
	n := 0
	for _, log := range l.Logs {
		n += len(log.Messages)
	}
	return fmt.Sprintf("%d test log(s) carrying %d HTTP message(s)", len(l.Logs), n)
}

func csipLogDetail(have bool, findings []string) string {
	if !have {
		return "no CSIP detailed test log was produced in this run"
	}
	if len(findings) == 0 {
		return "the emitted Test Logs Object validates against §4.1"
	}
	return fmt.Sprintf("%d schema finding(s): %s", len(findings), strings.Join(findings, "; "))
}

func modbusLogDetail(have bool, l *ModbusTestLogs, findings []string) string {
	if !have {
		return "no Modbus detailed test log was produced in this run"
	}
	entries := len(allEntries(l))
	if len(findings) == 0 {
		return fmt.Sprintf("%d test log(s) carrying %d entries validate against §4.1", len(l.Logs), entries)
	}
	return fmt.Sprintf("%d schema finding(s) across %d entries: %s",
		len(findings), entries, strings.Join(findings, "; "))
}

func allEntries(l *ModbusTestLogs) []ModbusLogEntry {
	if l == nil {
		return nil
	}
	var out []ModbusLogEntry
	for _, log := range l.Logs {
		out = append(out, log.Entries...)
	}
	return out
}

func noCiphertext(l *ModbusTestLogs) bool {
	for _, e := range allEntries(l) {
		if e.Type != EntryReq && e.Type != EntryResp {
			continue
		}
		raw, err := DecodeHexMsg(e.Msg)
		if err != nil {
			return false
		}
		if _, err := DecodeMBAP(raw); err != nil {
			return false
		}
	}
	return true
}

func modbusSubSecond(l *ModbusTestLogs) bool {
	for _, e := range allEntries(l) {
		if e.Time != float64(int64(e.Time)) {
			return true
		}
	}
	return false
}

// subSecond reports whether any CSIP log timestamp carries sub-second
// precision. Nil-safe for the same reason as describeCSIPLogs: it is evaluated
// eagerly as a metIf argument even when there are no logs at all.
func subSecond(l *CSIPTestLogs) bool {
	if l == nil {
		return false
	}
	for _, log := range l.Logs {
		for _, m := range log.Messages {
			if m.Time != float64(int64(m.Time)) {
				return true
			}
		}
	}
	return false
}

// Markdown renders the readiness report that ships in the submission.
func (r *Readiness) Markdown() string {
	met, unmet, na := r.Counts()
	var b strings.Builder
	fmt.Fprintf(&b, "# Submission readiness — %s\n\n", r.Doc)
	fmt.Fprintf(&b, "**Certificate type:** %s  \n", r.CertType)
	if r.Tool != "" {
		fmt.Fprintf(&b, "**Generated by:** %s %s  \n", r.Tool, r.ToolVersion)
	}
	switch {
	case r.ConfigSource != "":
		fmt.Fprintf(&b, "**Submission metadata:** `%s`  \n", r.ConfigSource)
	case r.ConfigSupplied:
		fmt.Fprintf(&b, "**Submission metadata:** supplied on the command line, not from a file  \n")
	default:
		fmt.Fprintf(&b, "**Submission metadata:** none supplied — every lab and submitter field is absent  \n")
	}
	fmt.Fprintf(&b, "**Generated:** %s\n\n", r.Generated.UTC().Format(time.RFC3339))

	fmt.Fprintf(&b, "%d requirement(s): **%d met, %d unmet, %d not assessed**.\n\n", len(r.Requirements), met, unmet, na)
	if unmet == 0 {
		fmt.Fprintf(&b, "> ✓ Nothing required is missing. %d requirement(s) were NOT assessed — a process "+
			"constraint on the laboratory, an enumeration the source document does not print, or a role this "+
			"DUT does not play. Each says which, below. A not-assessed row is not a pass.\n\n", na)
	} else {
		fmt.Fprintf(&b, "> ✗ NOT SUBMITTABLE. %d requirement(s) are unmet and are named below with exactly "+
			"what is absent. Nothing has been filled in on the submitter's behalf.\n\n", unmet)
		for _, q := range r.Unmet() {
			fmt.Fprintf(&b, "> - **%s** — %s\n", q.ID, mdEscape(q.Detail))
		}
		fmt.Fprintf(&b, "\n")
	}

	fmt.Fprintf(&b, "| Requirement | Status | Statement | What was checked |\n")
	fmt.Fprintf(&b, "|-------------|--------|-----------|------------------|\n")
	for _, q := range r.Requirements {
		fmt.Fprintf(&b, "| `%s` | %s | %s | %s |\n", q.ID, q.Status, mdEscape(q.Statement), mdEscape(q.Detail))
	}
	fmt.Fprintf(&b, "\n")
	return b.String()
}

func mdEscape(s string) string {
	s = strings.ReplaceAll(s, "|", "\\|")
	return strings.ReplaceAll(s, "\n", " ")
}

// caseOrder ranks case IDs in document order, so the readiness report reads in
// the order the specification does rather than alphabetically (which would put
// RPT-KV-10 before RPT-KV-2).
func caseOrder(certType string) map[string]int {
	ids := CSIPCaseIDs
	if certType == CertTypeModbus {
		ids = ModbusCaseIDs
	}
	m := make(map[string]int, len(ids))
	for i, id := range ids {
		m[id] = i
	}
	return m
}
