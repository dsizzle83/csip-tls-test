package report

// checks_csip.go binds SS-CSIP-RESULTS-v1.1's 45 applicable catalog rows.
//
// The CSIP results specification is mostly the same §3.1.1 key table as the
// Modbus one — with a different Appendix A, which is to say with no Appendix A
// at all — plus a Chapter 4 whose log objects are HTTP messages rather than
// Modbus frames, plus the Chapter 5 packet traces that v1.1 added.
//
// One boundary is drawn deliberately and stated in the assertions rather than
// glossed. The Chapter 4 rows are requirements on the SHAPE of a logged HTTP
// message: method, URI, version, every header, the body, and on a response the
// status code as a string and the reason with its trailing CRLF. Those are
// evidenced here over a real plaintext HTTP exchange this suite conducts and
// cites. What is NOT evidenced here is §4.1.2's worked example CONTENT — a
// sep+xml DeviceCapability from a mutually-authenticated 2030.5 session. That
// needs the CSIP suite's own traffic and the run's key log, and the row that
// wants it says so instead of dressing up an admin-API response as one.

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"csip-tls-test/internal/certify"
)

// registerCSIP binds every applicable SS-CSIP-RESULTS-v1.1 row.
func (s *Suite) registerCSIP(reg *certify.Registry) {
	ct := CertTypeCSIP
	uid := uidCSIP

	// §1 and §2.
	reg.Register(uid("RPT-001"), SuiteName, s.deliverableCheck(ct),
		certify.WithRequires("capture"), certify.WithOrder(1))
	reg.Register(uid("RPT-002"), SuiteName, s.freezeCheck(ct, uid("RPT-002")), certify.WithOrder(2))
	reg.Register(uid("RPT-003"), SuiteName, s.notAssessable(
		"§2.2 requires the complete equipment configuration to be documented well enough to replicate the "+
			"test on an unconfigured production unit, and specifies no format, key set or location for that "+
			"document. There is nothing for a generator to emit or a checker to validate. For this product "+
			"the material would be the provisioning bundle — provision.json, the certificate set, the "+
			"server URI, the csip_enabled flag — but naming it does not make the row assertable"),
		certify.WithOrder(3))
	reg.Register(uid("RPT-004"), SuiteName, s.notAssessable(
		"§2.2.1 forbids ANY configuration change to a client DUT during the campaign — unlike §2.2.2 and "+
			"§2.2.3, it grants no test-directed exception, and this product is a client, so the strict rule "+
			"applies. It is a constraint on how the laboratory ran the campaign; no artefact this tool "+
			"produces could falsify a mid-campaign reconfiguration. The nearest evidence is the single "+
			"Software Checksum asserted under RPT-002"), certify.WithOrder(4))
	reg.Register(uid("RPT-007"), SuiteName, s.deliverableCheck(ct),
		certify.WithRequires("capture"), certify.WithOrder(7))
	reg.Register(uid("RPT-008"), SuiteName, s.csvFormCheck(ct, uid("RPT-008")), certify.WithOrder(8))

	// §3.1.1 key rows.
	for i, id := range csipKeyRows {
		reg.Register(uid(id), SuiteName, s.keyCheck(ct, uid(id)), certify.WithOrder(100+i))
	}
	reg.Register(uid("RPT-039"), SuiteName, s.verdictCheck(ct, uid("RPT-039")), certify.WithOrder(200))
	reg.Register(uid("RPT-040"), SuiteName, s.exampleKeysCheck(), certify.WithOrder(201))
	reg.Register(uid("RPT-041"), SuiteName, s.notAssessable(
		"§3.1.2's verdict block is an EXAMPLE — 52 rows a particular client submission happened to carry — "+
			"and the document never says which tests a client submission is REQUIRED to carry. The "+
			"authoritative applicability matrix is in the SunSpec IEEE 2030.5/CSIP Conformance Test "+
			"Procedures document, not here. Worse, the example simply OMITS the tests it does not apply "+
			"(COMM-001, CORE-001/002/018/019) rather than reporting them NOT SUPPORTED, which leaves the "+
			"correct treatment of an inapplicable procedure genuinely unresolved. This tool reports the "+
			"verdicts its source bundle contains and invents no required-test list"), certify.WithOrder(202))

	// Chapter 4.
	for i, r := range csipLogRules() {
		reg.Register(uid(r.id), SuiteName, s.httpLogCheck(r.rule),
			certify.WithRequires("capture"), certify.WithOrder(300+i))
	}

	// Chapter 5.
	reg.Register(uid("RPT-060"), SuiteName, s.traceCheck(),
		certify.WithRequires("capture"), certify.WithOrder(400))
}

// csipKeyRows are the §3.1.1 key rows in document order. RPT-039 (verdicts) and
// RPT-040 (the example's undocumented keys) are registered separately.
var csipKeyRows = []string{
	"RPT-010", "RPT-011", "RPT-012", "RPT-013", "RPT-014", "RPT-015", "RPT-016", "RPT-017",
	"RPT-018", "RPT-019", "RPT-020", "RPT-021", "RPT-022", "RPT-023", "RPT-024", "RPT-025",
	"RPT-026", "RPT-027", "RPT-028", "RPT-029", "RPT-030", "RPT-031", "RPT-032", "RPT-033",
	"RPT-034", "RPT-035", "RPT-036", "RPT-037", "RPT-038",
}

// exampleKeysCheck implements RPT-040: the two keys the §3.1.2 example emits and
// §3.1.1 does not define.
//
// The honest position is that neither key can be validated, because neither has
// a definition. What CAN be asserted is that the generator does not guess: it
// emits `Certificate Type Version` only when an operator supplies one, emits
// either the two §3.1.1 state/province keys or the example's combined key but
// never both, and records the mismatch for the laboratory.
func (s *Suite) exampleKeysCheck() certify.Check {
	return func(ctx context.Context, rc *certify.RunCtx) (certify.Result, error) {
		cfg, supplied, err := s.Config(rc)
		if err != nil {
			return certify.Failed("the submission configuration could not be used: %v", err), nil
		}
		if !supplied {
			return certify.Skipped("no submission metadata was configured, so neither of the §3.1.2 " +
				"example's undocumented keys was emitted. Neither has a definition anywhere in the " +
				"document, so neither can be validated even when supplied — this row asserts only that " +
				"the generator does not guess at them"), nil
		}
		sum := BuildSummary(cfg, CertTypeCSIP, nil)
		data, err := sum.CSV()
		if err != nil {
			return certify.Result{}, err
		}
		parsed, err := ParseSummary(data)
		if err != nil {
			return certify.Failed("the emitted Summary Test Results does not re-parse: %v", err), nil
		}
		_, hasVersion := parsed.Lookup("Certificate Type Version")
		_, hasState := parsed.Lookup("Company State")
		_, hasProvince := parsed.Lookup("Company Province")
		_, hasCombined := parsed.Lookup("Company State/Province")

		as := []certify.Assertion{
			docAssertion(
				"`Certificate Type Version` is emitted only when an operator supplies it, never guessed",
				"inspection of the emitted CSV against the configuration",
				certify.Pass,
				fmt.Sprintf("supplied: %t; emitted: %t. The key appears in the §3.1.2 example with the "+
					"value 2019 and has no definition, description or value type anywhere in the document, "+
					"so a generator that emitted a plausible year would be inventing a specification",
					cfg.CertificateTypeVersion != "", hasVersion),
				"the CSV this run generated"),
			docAssertion(
				"the state and province are emitted in exactly one of the two mutually exclusive forms: "+
					"§3.1.1's two keys, or the §3.1.2 example's combined key",
				"inspection of the emitted CSV",
				verdictIf(!(hasCombined && (hasState || hasProvince))),
				fmt.Sprintf("`Company State`: %t, `Company Province`: %t, `Company State/Province`: %t "+
					"(combine_state_province = %t). §3.1.1 is the normative table and is the default; "+
					"the combined key is emitted only on request",
					hasState, hasProvince, hasCombined, cfg.CombineStateProvince),
				"the CSV this run generated"),
			docAssertion(
				"the §3.1.1 / §3.1.2 mismatch is recorded for the laboratory rather than silently resolved",
				"transcription of the source document",
				certify.Warn,
				"§3.1.1 defines `Company State` and `Company Province` and does not define "+
					"`Certificate Type Version` or `Company State/Province`; §3.1.2's worked example emits "+
					"the latter two and neither of the former. The two sections of one document disagree, "+
					"and only SunSpec can settle which an ingest expects",
				"SS-CSIP-RESULTS-v1.1 §3.1.1 versus §3.1.2"),
			skipAssertion(
				"the emitted keys match what SunSpec's ingest accepts",
				"specification lookup",
				"an undocumented key cannot be validated against anything. This row is a question for the "+
					"laboratory before submission, not a criterion a tool can decide"),
		}
		return certify.Result{
			Verdict: certify.Warn, Assertions: as,
			Notes:   "the example's two undocumented keys are handled explicitly; neither is guessed",
			OffWire: true,
			OffWireReason: offWire("the Summary Test Results CSV this run generated",
				"§3.1.2's example emits keys §3.1.1 does not define, and how a generator treats them is a "+
					"property of the emitted document"),
		}, nil
	}
}

type idHTTPRule struct {
	id   string
	rule HTTPRule
}

// csipLogRules is the Chapter 4 rule set.
func csipLogRules() []idHTTPRule {
	return []idHTTPRule{
		{"RPT-050", HTTPRule{
			Claim: "the detailed test log records the HTTP message in UNENCRYPTED form: the cited stream " +
				"bytes are the message the log renders, readable at the HTTP layer with no TLS record framing",
			Method: "the cited byte range is the request as it lay in the reassembled stream; the emitted " +
				"Message Object renders exactly those bytes",
			Assess: func(d *DerivedHTTP) (certify.Verdict, string, *ScannedMessage) {
				m, ok := firstMessage(d, MsgReq)
				if !ok {
					return certify.Skip, "the exchange produced no HTTP request to cite", nil
				}
				plain := !tlsRecordPrefix(m.Message.Body) && m.Message.Method != ""
				return verdictIf(plain), fmt.Sprintf(
					"%s %s %s over %d cited byte(s), %d header(s), %d-byte body — no TLS record header is "+
						"present (a record would begin 0x16 0x03)",
					m.Message.Method, m.Message.URI, m.Message.Vers, m.End-m.Start,
					len(m.Message.Headers), len(m.Message.Body)), m
			},
			Extra: func(ev *certify.Evidence, d *DerivedHTTP) []certify.Assertion {
				return []certify.Assertion{
					httpSchemaAssertion(d, "the emitted Test Logs Object validates against §4.1"),
					skipAssertion(
						"the detailed log carries every HTTP message of a MUTUALLY-AUTHENTICATED CSIP session",
						"TLS decryption from the run's NSS key log",
						"this row's full criterion needs a 2030.5 session whose keys the run exported. The "+
							"exchange cited above is a plaintext HTTP conversation this check conducted "+
							"itself, which evidences the log FORMAT but not a CSIP session. Decryption of a "+
							"captured CSIP session requires -keylog and a key log covering the DUT's own "+
							"client, which this bench does not hold"),
				}
			},
		}},
		{"RPT-051", HTTPRule{
			Claim: "the Test Log Object carries a `tests` array naming the procedures it evidences and a " +
				"`messages` array of Message Objects",
			Method: "inspection of the emitted Test Log Object; the cited range is its first message",
			Assess: func(d *DerivedHTTP) (certify.Verdict, string, *ScannedMessage) {
				m, ok := firstMessage(d, MsgReq)
				log := d.Logs.Logs[0]
				valid := len(log.Tests) > 0 && len(log.Messages) > 0
				cid := log.CID
				if cid == "" {
					cid = "(omitted — §4.1.1 calls cid optional, and none was supplied)"
				}
				if !ok {
					return certify.Skip, "the exchange produced no HTTP message to cite", nil
				}
				return verdictIf(valid), fmt.Sprintf(`{"tests": %v, "cid": %s, "messages": [%d]}`,
					log.Tests, cid, len(log.Messages)), m
			},
			Extra: csipSchemaExtra("the Test Log Object has its two mandatory elements"),
		}},
		{"RPT-052", HTTPRule{
			Claim: "the Message Object records time, type, method, uri, vers, every header on the wire, and " +
				"a body that is the empty string rather than absent when there is none",
			Method: "the emitted Message Object was compared field by field against the cited stream bytes " +
				"it was decoded from",
			Assess: func(d *DerivedHTTP) (certify.Verdict, string, *ScannedMessage) {
				m, ok := firstMessage(d, MsgReq)
				if !ok {
					return certify.Skip, "the exchange produced no HTTP request to cite", nil
				}
				msg := m.Message
				complete := msg.Time > 0 && msg.Type == MsgReq && msg.Method != "" && msg.URI != "" &&
					msg.Vers != "" && msg.Headers != nil
				return verdictIf(complete), fmt.Sprintf(
					`{"time": %.6f, "type": %q, "method": %q, "uri": %q, "vers": %q, "headers": {%s}, `+
						`"body": %q} — header names are preserved exactly as sent, not canonicalised`,
					msg.Time, msg.Type, msg.Method, msg.URI, msg.Vers,
					headerNames(msg.Headers), msg.Body), m
			},
			Extra: csipSchemaExtra("every Message Object carries the documented elements"),
		}},
		{"RPT-053", HTTPRule{
			Claim: "a message's `time` is a number of seconds with at least second accuracy, and carries " +
				"sub-second decimals",
			Method: "the Message Object's time was taken from the capture timestamp of the frame that " +
				"delivered the cited bytes",
			Assess: func(d *DerivedHTTP) (certify.Verdict, string, *ScannedMessage) {
				m, ok := firstMessage(d, MsgReq)
				if !ok {
					return certify.Skip, "the exchange produced no HTTP message to cite", nil
				}
				sub := m.Message.Time != float64(int64(m.Message.Time))
				gap := ""
				if resp, ok := d.Scan.First(MsgResp); ok {
					gap = fmt.Sprintf("; the response is %.0f ms later, which is resolution the second-"+
						"accuracy MUST alone would not give", (resp.Message.Time-m.Message.Time)*1000)
				}
				return verdictIf(m.Message.Time > 0 && sub), fmt.Sprintf(
					"time %.7f, a JSON number of Unix epoch seconds, not a formatted date string%s",
					m.Message.Time, gap), m
			},
			Extra: csipSchemaExtra("timestamps are numeric and sub-second"),
		}},
		{"RPT-054", HTTPRule{
			Claim: "a logged RESPONSE carries `code` as a string, `reason` retaining its trailing CRLF, and " +
				"the full header set — the fields §4.1.2's contents table omits and its example requires",
			Method: "the emitted response Message Object was compared against the cited stream bytes",
			Assess: func(d *DerivedHTTP) (certify.Verdict, string, *ScannedMessage) {
				m, ok := firstMessage(d, MsgResp)
				if !ok {
					return certify.Skip, "the exchange produced no HTTP response to cite", nil
				}
				msg := m.Message
				_, codeErr := parseStatusCode(msg.Code)
				ok2 := codeErr == nil && strings.HasSuffix(msg.Reason, "\r\n") && msg.Headers != nil
				return verdictIf(ok2), fmt.Sprintf(
					`{"code": %q, "reason": %q, "vers": %q, "headers": {%s}, "body": %d bytes} — code is a `+
						"STRING and reason keeps its CRLF, matching the §4.1.2 example rather than the "+
						"contents table, which lists neither field",
					msg.Code, msg.Reason, msg.Vers, headerNames(msg.Headers), len(msg.Body)), m
			},
			Extra: func(ev *certify.Evidence, d *DerivedHTTP) []certify.Assertion {
				return []certify.Assertion{
					httpSchemaAssertion(d, "every response Message Object carries code and reason"),
					skipAssertion(
						"the logged response is a `DeviceCapability` document in namespace "+
							"urn:ieee:std:2030.5:ns with the link set §4.1.2's example shows",
						"2030.5 resource walk",
						"the worked example's CONTENT is a CSIP server's answer to GET /sep2/dcap. This "+
							"check evidences the response Message Object's SHAPE over an exchange it "+
							"conducted itself; asserting the sep+xml payload would need the CSIP suite's "+
							"own decrypted session, and claiming it from this exchange would be false"),
				}
			},
		}},
		{"RPT-055", HTTPRule{
			Claim: "the Test Logs Object bundles the test logs under a `logs` array with an optional shared " +
				"context id",
			Method: "inspection of the emitted container; the cited range is a message inside the first log",
			Assess: func(d *DerivedHTTP) (certify.Verdict, string, *ScannedMessage) {
				m, ok := firstMessage(d, MsgReq)
				if !ok {
					return certify.Skip, "the exchange produced no HTTP message to cite", nil
				}
				data, err := d.Logs.JSON()
				if err != nil {
					return certify.Fail, err.Error(), m
				}
				if _, err := ParseCSIPTestLogs(data); err != nil {
					return certify.Fail, "the emitted document does not round-trip: " + err.Error(), m
				}
				cid := d.Logs.CID
				note := "no cid was supplied, so none is emitted"
				if cid != "" {
					note = fmt.Sprintf("cid %q, which is what stitches separately-archived documents back "+
						"together", cid)
				}
				return certify.Pass, fmt.Sprintf(`{"logs": [%d]} in %d bytes, round-tripping through a `+
					"strict decoder; %s. Unlike the Modbus results document, v1.1 did NOT remove cid",
					len(d.Logs.Logs), len(data), note), m
			},
			Extra: csipSchemaExtra("the container has its mandatory logs array"),
		}},
	}
}

func csipSchemaExtra(claim string) func(*certify.Evidence, *DerivedHTTP) []certify.Assertion {
	return func(_ *certify.Evidence, d *DerivedHTTP) []certify.Assertion {
		return []certify.Assertion{httpSchemaAssertion(d, claim)}
	}
}

func firstMessage(d *DerivedHTTP, typ string) (*ScannedMessage, bool) {
	for i := range d.Scan.Messages {
		if d.Scan.Messages[i].Message.Type == typ {
			return &d.Scan.Messages[i], true
		}
	}
	return nil, false
}

// headerNames renders the header key set for an Observed field, sorted so the
// string is stable across runs.
func headerNames(h map[string]string) string {
	names := make([]string, 0, len(h))
	for k := range h {
		names = append(names, k)
	}
	sort.Strings(names)
	return strings.Join(names, ", ")
}
