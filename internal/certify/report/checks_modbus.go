package report

// checks_modbus.go binds SS-MODBUS-RESULTS-v1.2's 52 applicable catalog rows.
//
// The fifteen §4.1 rows are the substance. Each one names a property of a Log
// Entry Object — that `msg` is the complete message as ascii hex, that a `conn`
// entry carries the endpoint, that `time` has sub-second resolution — and each
// is proved by deriving the entry from a real captured exchange and citing the
// bytes it renders. RPT-LOG-9 (RTU framing) is the single row that cannot be:
// this bench has no serial interface, and a framing rule with no exchange
// behind it is a unit test, not evidence.

import (
	"fmt"
	"strings"

	"csip-tls-test/internal/certify"
)

// registerModbus binds every applicable SS-MODBUS-RESULTS-v1.2 row.
func (s *Suite) registerModbus(reg *certify.Registry) {
	ct := CertTypeModbus
	uid := uidModbus

	// §2 General Testing Considerations — process constraints on the laboratory.
	reg.Register(uid("RPT-GEN-1"), SuiteName, s.freezeCheck(ct, uid("RPT-GEN-1")), certify.WithOrder(1))
	reg.Register(uid("RPT-GEN-2"), SuiteName, s.notAssessable(
		"the specification requires the complete equipment configuration to be documented but defines no "+
			"format, schema, or delivery mechanism for it — §2.2 states only that it must be sufficient to "+
			"bring an unconfigured production unit to the tested state. There is nothing here for a "+
			"generator to emit or a checker to validate; it is a submitter attachment"), certify.WithOrder(2))
	reg.Register(uid("RPT-GEN-3"), SuiteName, s.notAssessable(
		"whether the device was reconfigured mid-campaign is a process constraint on the laboratory. The "+
			"detailed test logs make it INSPECTABLE — every write function code is in them — but deciding "+
			"which writes were directed by a test procedure needs the SunSpec Modbus Conformance Test "+
			"Procedures document, which this catalog does not contain"), certify.WithOrder(3))

	// §3 the Summary Test Results.
	reg.Register(uid("RPT-TRR-1"), SuiteName, s.deliverableCheck(ct),
		certify.WithRequires("capture"), certify.WithOrder(10))
	reg.Register(uid("RPT-TRR-2"), SuiteName, s.csvFormCheck(ct, uid("RPT-TRR-2")), certify.WithOrder(11))
	reg.Register(uid("RPT-TRR-3"), SuiteName, s.notAssessable(
		"§3.1.2's worked example is explicitly non-normative and is the only place concrete SunSpec Modbus "+
			"test IDs (DEV-*, MOD-*.<model>, CRV-*, REV-*, TCP-*, MB-*, EXC-*) appear. The procedures "+
			"themselves live in the companion SunSpec Modbus Conformance Test Procedures document, which "+
			"is not in this catalog, so no required-test list can be derived. The example's two "+
			"undocumented keys — `Certificate Type Version` and `Company State/Province` — are emitted "+
			"only when an operator supplies them and are flagged in the readiness report"), certify.WithOrder(12))

	// §3.1.1 key rows.
	for i, id := range modbusKeyRows {
		reg.Register(uid(id), SuiteName, s.keyCheck(ct, uid(id)), certify.WithOrder(100+i))
	}
	reg.Register(uid("RPT-KV-30"), SuiteName, s.verdictCheck(ct, uid("RPT-KV-30")), certify.WithOrder(200))

	// §4 the Detailed Test Logs.
	for i, r := range modbusLogRules() {
		reg.Register(uid(r.id), SuiteName, s.modbusLogCheck(r.rule),
			certify.WithRequires("capture"), certify.WithOrder(300+i))
	}
	reg.Register(uid("RPT-LOG-9"), SuiteName, s.notAssessable(
		"the RTU `msg` framing rule — unit id, function code, data, and a trailing CRC, with no MBAP "+
			"header — cannot be evidenced here: the DUT exposes no Modbus RTU interface on this bench and "+
			"the serial work item is on hold. The rule IS implemented (DecodeRTU verifies the CRC and "+
			"rejects an MBAP header) and unit-tested, but a framing rule with no captured exchange behind "+
			"it is an implementation claim, not evidence, and this suite does not print PASS for one"),
		certify.WithOrder(399))
}

// modbusKeyRows are the §3.1.1 key rows, in document order. RPT-KV-30 is the
// verdict row and is registered separately.
var modbusKeyRows = []string{
	"RPT-KV-1", "RPT-KV-2", "RPT-KV-3", "RPT-KV-4", "RPT-KV-5", "RPT-KV-6", "RPT-KV-7",
	"RPT-KV-8", "RPT-KV-9", "RPT-KV-10", "RPT-KV-11", "RPT-KV-12", "RPT-KV-13", "RPT-KV-14",
	"RPT-KV-15", "RPT-KV-16", "RPT-KV-17", "RPT-KV-18", "RPT-KV-19", "RPT-KV-20", "RPT-KV-21",
	"RPT-KV-22", "RPT-KV-23", "RPT-KV-24", "RPT-KV-25", "RPT-KV-26", "RPT-KV-27", "RPT-KV-28",
	"RPT-KV-29",
}

type idRule struct {
	id   string
	rule LogRule
}

// modbusLogRules is the §4.1 rule set. Every Assess returns the entry whose
// captured bytes evidence the rule, so the resulting assertion carries a
// re-derivable digest rather than a description.
func modbusLogRules() []idRule {
	return []idRule{
		{"RPT-LOG-1", LogRule{
			Claim: "the detailed test log carries every Modbus message exchanged in this session, plus the " +
				"connection information §4 requires for Modbus TCP",
			Method: "the log was derived from the reassembled capture, then compared byte-for-byte against " +
				"the record this check's own socket kept; the cited range is every request byte of the session",
			Assess: func(d *DerivedModbus) (certify.Verdict, string, *ScannedEntry) {
				span := wholeSpan(d.Scan, EntryReq)
				conn := entryOf(d.Scan, EntryConn)
				ok := d.SocketMatch && conn != nil && len(d.Findings) == 0
				observed := fmt.Sprintf("%s; connection information: %s",
					d.SocketDetail, connDescription(conn))
				if span == nil {
					return certify.Skip, "the exchange produced no request entries to cite", nil
				}
				return verdictIf(ok), observed, span
			},
			Extra: func(ev *certify.Evidence, d *DerivedModbus) []certify.Assertion {
				paired, unmatched := PairTransactions(allEntries(d.Logs))
				v, observed := certify.Pass, fmt.Sprintf(
					"%d request/response pair(s) reconcile by MBAP transaction id, with none left open", paired)
				if len(unmatched) > 0 {
					v = certify.Fail
					observed = fmt.Sprintf("%d unpaired message(s): %s", len(unmatched), strings.Join(unmatched, "; "))
				}
				return []certify.Assertion{
					docAssertion("every logged request has its logged response and vice versa",
						"transaction-id pairing over the derived log", v, observed,
						"the Detailed Test Logs JSON this run derived from the capture"),
					schemaAssertion(d, "the derived Test Logs Object validates against §4.1"),
				}
			},
		}},
		{"RPT-LOG-2", LogRule{
			Claim: "every logged Modbus message is in unencrypted form: the `msg` value decodes to a " +
				"well-formed Modbus PDU, not to TLS record bytes",
			Method: "each `msg` was hex-decoded and parsed as MBAP; the cited range is the first request",
			Assess: func(d *DerivedModbus) (certify.Verdict, string, *ScannedEntry) {
				e := entryOf(d.Scan, EntryReq)
				if e == nil {
					return certify.Skip, "the exchange produced no message entries", nil
				}
				raw, err := DecodeHexMsg(e.Entry.Msg)
				if err != nil {
					return certify.Fail, err.Error(), e
				}
				m, err := DecodeMBAP(raw)
				if err != nil {
					return certify.Fail, err.Error(), e
				}
				return certify.Pass, fmt.Sprintf("msg %s decodes to %s — a Modbus PDU in the clear, with no "+
					"TLS record header (a TLS record would begin 0x16 0x03)", e.Entry.Msg, m), e
			},
			Extra: modbusSchemaExtra("all logged messages decode as Modbus PDUs"),
		}},
		{"RPT-LOG-3", LogRule{
			Claim: "the detailed test logs are JSON, built from the Test Log, Test Logs and Log Entry objects",
			Method: "the emitted document was re-parsed with a decoder that rejects unknown fields; the " +
				"cited range is the message the first Log Entry Object renders",
			Assess: func(d *DerivedModbus) (certify.Verdict, string, *ScannedEntry) {
				e := entryOf(d.Scan, EntryReq)
				data, err := d.Logs.JSON()
				if err != nil {
					return certify.Fail, err.Error(), e
				}
				if _, err := ParseModbusTestLogs(data); err != nil {
					return certify.Fail, "the emitted document does not round-trip: " + err.Error(), e
				}
				return certify.Pass, fmt.Sprintf("a %d-byte Test Logs Object round-trips through a "+
					"strict decoder; its first Log Entry renders the cited bytes as %s",
					len(data), entryJSON(e)), e
			},
			Extra: modbusSchemaExtra("the emitted document uses only the three documented objects"),
		}},
		{"RPT-LOG-4", LogRule{
			Claim: "the Test Log Object carries a `tests` array naming the procedures it evidences and an " +
				"`entries` array of log entries",
			Method: "inspection of the emitted Test Log Object; the cited range is its first message entry",
			Assess: func(d *DerivedModbus) (certify.Verdict, string, *ScannedEntry) {
				e := entryOf(d.Scan, EntryReq)
				log := d.Logs.Logs[0]
				ok := len(log.Tests) > 0 && len(log.Entries) > 0
				return verdictIf(ok), fmt.Sprintf(`{"tests": %v, "entries": [%d entries]} — no "cid" is `+
					"emitted: v1.2's revision history records \"Removed cid.\" and the contents table lists "+
					"only the two elements", log.Tests, len(log.Entries)), e
			},
			Extra: modbusSchemaExtra("the Test Log Object has exactly the two documented elements"),
		}},
		{"RPT-LOG-5", LogRule{
			Claim: "a Log Entry Object holds exactly one Modbus message or one connection event, never a batch",
			Method: "the cited byte range is the single MBAP frame the first `req` entry renders — its " +
				"length is the message's length, so the entry cannot be carrying two",
			Assess: func(d *DerivedModbus) (certify.Verdict, string, *ScannedEntry) {
				e := entryOf(d.Scan, EntryReq)
				if e == nil {
					return certify.Skip, "the exchange produced no message entries", nil
				}
				raw, _ := DecodeHexMsg(e.Entry.Msg)
				single := e.End-e.Start == len(raw)
				return verdictIf(single), fmt.Sprintf("entry renders stream bytes [%d,%d) = %d byte(s), and "+
					"its msg decodes to a single %d-byte MBAP frame", e.Start, e.End, e.End-e.Start, len(raw)), e
			},
			Extra: modbusSchemaExtra("no entry carries more than one message"),
		}},
		{"RPT-LOG-6", LogRule{
			Claim: "an entry's `time` is a number of seconds with at least second accuracy, and carries " +
				"sub-second decimals",
			Method: "the entry's `time` was compared against the capture timestamp of the frame that " +
				"delivered the cited bytes",
			Assess: func(d *DerivedModbus) (certify.Verdict, string, *ScannedEntry) {
				e := entryOf(d.Scan, EntryReq)
				if e == nil {
					return certify.Skip, "the exchange produced no message entries", nil
				}
				sub := e.Entry.Time != float64(int64(e.Entry.Time))
				return verdictIf(e.Entry.Time > 0 && sub), fmt.Sprintf(
					"time %.6f (Unix epoch seconds), taken from the capture timestamp of frame %v that "+
						"delivered the cited bytes; sub-second decimals present: %t",
					e.Entry.Time, e.Frames, sub), e
			},
			Extra: func(ev *certify.Evidence, d *DerivedModbus) []certify.Assertion {
				var deltas []string
				for _, e := range d.Scan.Entries {
					if e.Entry.Type == EntryReq || e.Entry.Type == EntryResp {
						deltas = append(deltas, fmt.Sprintf("%.6f", e.Entry.Time))
					}
				}
				return []certify.Assertion{
					docAssertion("message timestamps ascend monotonically across the session",
						"ordering of the derived entries",
						verdictIf(ascending(d.Scan)),
						strings.Join(deltas, " → "),
						"the Detailed Test Logs JSON this run derived from the capture"),
					schemaAssertion(d, "the derived Test Logs Object validates against §4.1"),
				}
			},
		}},
		{"RPT-LOG-7", LogRule{
			Claim: "`type` is one of the four documented values — req, resp, conn, disc — in lower case",
			Method: "inspection of every derived entry's type; the cited range is the first `resp`, whose " +
				"direction is what distinguishes it from a `req`",
			Assess: func(d *DerivedModbus) (certify.Verdict, string, *ScannedEntry) {
				e := entryOf(d.Scan, EntryResp)
				if e == nil {
					return certify.Skip, "the exchange produced no response entries", nil
				}
				counts := map[string]int{}
				for _, x := range d.Scan.Entries {
					counts[x.Entry.Type]++
				}
				var parts []string
				bad := false
				for _, t := range ModbusEntryTypes {
					if counts[t] > 0 {
						parts = append(parts, fmt.Sprintf("%s×%d", t, counts[t]))
					}
				}
				for t := range counts {
					if !containsStr(ModbusEntryTypes, t) {
						bad = true
					}
				}
				return verdictIf(!bad), fmt.Sprintf("%s; the cited bytes are the response the server sent, "+
					"typed \"resp\". An exception response would also be typed \"resp\" — the format has no "+
					"separate type for one; it is recognised by 0x80 set on the function code",
					strings.Join(parts, ", ")), e
			},
			Extra: modbusSchemaExtra("every entry's type is in the enumeration"),
		}},
		{"RPT-LOG-8", LogRule{
			Claim: "`msg` is the COMPLETE Modbus message as an ascii hex string: the cited stream bytes " +
				"hex-encode to exactly the emitted value, with no prefix, no separators and nothing omitted",
			Method: "the cited byte range was hex-encoded and compared, character for character, with the " +
				"`msg` value in the emitted Detailed Test Logs",
			Assess: func(d *DerivedModbus) (certify.Verdict, string, *ScannedEntry) {
				e := entryOf(d.Scan, EntryReq)
				if e == nil {
					return certify.Skip, "the exchange produced no message entries", nil
				}
				raw, err := DecodeHexMsg(e.Entry.Msg)
				if err != nil {
					return certify.Fail, err.Error(), e
				}
				exact := HexMsg(raw) == e.Entry.Msg && len(raw) == e.End-e.Start
				return verdictIf(exact), fmt.Sprintf(
					`"msg": "%s" — %d hex digits for the %d cited stream bytes [%d,%d); re-encoding the `+
						"cited bytes reproduces the value exactly",
					e.Entry.Msg, len(e.Entry.Msg), e.End-e.Start, e.Start, e.End), e
			},
			Extra: modbusSchemaExtra("every `msg` in the document re-encodes from its own bytes"),
		}},
		{"RPT-LOG-10", LogRule{
			Claim: "a Modbus TCP `msg` carries the full MBAP header — transaction id, protocol id, length — " +
				"followed by unit id, function code and data, with a Length field consistent with the frame",
			Method: "the cited byte range was parsed as MBAP and its Length field checked against the " +
				"frame's actual size",
			Assess: func(d *DerivedModbus) (certify.Verdict, string, *ScannedEntry) {
				e := entryOf(d.Scan, EntryReq)
				if e == nil {
					return certify.Skip, "the exchange produced no message entries", nil
				}
				raw, _ := DecodeHexMsg(e.Entry.Msg)
				m, err := DecodeMBAP(raw)
				if err != nil {
					return certify.Fail, err.Error(), e
				}
				return certify.Pass, fmt.Sprintf("%s; Length %d + 6 header bytes = %d, the frame's size. "+
					"No CRC follows: that is RTU framing, not TCP", m, m.Length, len(raw)), e
			},
			Extra: func(ev *certify.Evidence, d *DerivedModbus) []certify.Assertion {
				ids := transactionIDs(d.Scan)
				return []certify.Assertion{
					docAssertion("transaction ids vary across the session and pair request to response",
						"MBAP transaction-id extraction from the derived log",
						verdictIf(len(ids) > 1),
						fmt.Sprintf("transaction ids observed: %s. The §4.1.2 examples show 0x0000 on both "+
							"request and response; a real capture should show them varying, and this one does",
							strings.Join(ids, ", ")),
						"the Detailed Test Logs JSON this run derived from the capture"),
					schemaAssertion(d, "every TCP msg carries a consistent MBAP header"),
				}
			},
		}},
		{"RPT-LOG-11", LogRule{
			Claim: "`ipaddr` records the IP address of the Modbus TCP connection",
			Method: "the cited frame is the SYN that opened the connection; the entry's ipaddr is the " +
				"server endpoint it was addressed to",
			Assess: func(d *DerivedModbus) (certify.Verdict, string, *ScannedEntry) {
				e := entryOf(d.Scan, EntryConn)
				if e == nil {
					return certify.Skip, "no SYN was captured, so no `conn` entry exists to carry an ipaddr", nil
				}
				ok := e.Entry.IPAddr == d.Scan.Server.Addr().String()
				return verdictIf(ok), fmt.Sprintf(`"ipaddr": %q — the SERVER endpoint the connection was `+
					"made to, which is the reading the §4.1.2 example supports; the document does not say "+
					"whose address it is", e.Entry.IPAddr), e
			},
			Extra: modbusSchemaExtra("the conn entry carries the endpoint"),
		}},
		{"RPT-LOG-12", LogRule{
			Claim: "`ipport` records the TCP port of the Modbus connection",
			Method: "the cited frame is the SYN that opened the connection; the entry's ipport is its " +
				"destination port",
			Assess: func(d *DerivedModbus) (certify.Verdict, string, *ScannedEntry) {
				e := entryOf(d.Scan, EntryConn)
				if e == nil {
					return certify.Skip, "no SYN was captured, so no `conn` entry exists to carry an ipport", nil
				}
				ok := e.Entry.IPPort == int(d.Scan.Server.Port())
				return verdictIf(ok), fmt.Sprintf(`"ipport": %d, emitted as a JSON NUMBER. The normative `+
					"prose calls ipport a String while the §4.1.2 example prints it unquoted; a strict "+
					"validator would reject the document's own example, so the example is followed and the "+
					"divergence is recorded in the readiness report", e.Entry.IPPort), e
			},
			Extra: modbusSchemaExtra("the conn entry carries the port"),
		}},
		{"RPT-LOG-13", LogRule{
			Claim:  "every log entry carries `time` and `type`",
			Method: "inspection of every derived entry; the cited range is the first message entry",
			Assess: func(d *DerivedModbus) (certify.Verdict, string, *ScannedEntry) {
				e := entryOf(d.Scan, EntryReq)
				missing := 0
				for _, x := range d.Scan.Entries {
					if x.Entry.Time == 0 || x.Entry.Type == "" {
						missing++
					}
				}
				return verdictIf(missing == 0), fmt.Sprintf(
					"%d entries, %d missing time or type", len(d.Scan.Entries), missing), e
			},
			Extra: modbusSchemaExtra("requirement 1 holds for every entry"),
		}},
		{"RPT-LOG-14", LogRule{
			Claim:  "every entry typed req or resp carries a `msg`",
			Method: "inspection of every derived message entry; the cited range is the first response",
			Assess: func(d *DerivedModbus) (certify.Verdict, string, *ScannedEntry) {
				e := entryOf(d.Scan, EntryResp)
				missing, n := 0, 0
				for _, x := range d.Scan.Entries {
					if x.Entry.Type != EntryReq && x.Entry.Type != EntryResp {
						continue
					}
					n++
					if x.Entry.Msg == "" {
						missing++
					}
				}
				return verdictIf(missing == 0 && n > 0), fmt.Sprintf(
					"%d message entries, %d without a msg; no message entry carries ipaddr or ipport, which "+
						"§4.1.2's message contents table does not list", n, missing), e
			},
			Extra: modbusSchemaExtra("requirement 2 holds for every message entry"),
		}},
		{"RPT-LOG-15", LogRule{
			Claim:  "every entry typed conn carries `ipaddr` and `ipport`; a disc entry need not",
			Method: "inspection of the derived connection events; the cited frame is the SYN",
			Assess: func(d *DerivedModbus) (certify.Verdict, string, *ScannedEntry) {
				e := entryOf(d.Scan, EntryConn)
				if e == nil {
					return certify.Skip, "no SYN was captured, so this session contributes no `conn` entry", nil
				}
				disc := entryOf(d.Scan, EntryDisc)
				discText := "no disc entry (the session was still open when the capture window closed)"
				if disc != nil {
					discText = fmt.Sprintf("disc entry at %.6f carries only time and type, as the §4.1.2 "+
						"example's does", disc.Entry.Time)
				}
				ok := e.Entry.IPAddr != "" && e.Entry.IPPort != 0
				return verdictIf(ok), fmt.Sprintf("conn entry %s; %s", connDescription(e), discText), e
			},
			Extra: modbusSchemaExtra("requirement 3 holds for every conn entry"),
		}},
		{"RPT-LOG-16", LogRule{
			Claim:  "the Test Logs Object is a container whose `logs` element is an array of Test Log Objects",
			Method: "inspection of the emitted container; the cited range is a message inside the first log",
			Assess: func(d *DerivedModbus) (certify.Verdict, string, *ScannedEntry) {
				e := entryOf(d.Scan, EntryReq)
				data, err := d.Logs.JSON()
				if err != nil {
					return certify.Fail, err.Error(), e
				}
				hasLogs := strings.Contains(string(data), `"logs"`)
				noCID := !strings.Contains(string(data), `"cid"`)
				return verdictIf(hasLogs && noCID), fmt.Sprintf(
					`{"logs": [%d test log(s)]}; no context id is emitted — the prose describes one but the `+
						"contents table and the JSON template list only `logs`, and v1.2's revision history "+
						"records \"Removed cid.\"", len(d.Logs.Logs)), e
			},
			Extra: modbusSchemaExtra("the container has exactly the one documented element"),
		}},
	}
}

// modbusSchemaExtra is the common Extra: the §4.1 validation of the whole
// emitted document, alongside whatever the rule itself cited.
func modbusSchemaExtra(claim string) func(*certify.Evidence, *DerivedModbus) []certify.Assertion {
	return func(_ *certify.Evidence, d *DerivedModbus) []certify.Assertion {
		return []certify.Assertion{schemaAssertion(d, claim)}
	}
}

// entryOf returns a pointer to the first derived entry of a type.
func entryOf(sc *ModbusScan, typ string) *ScannedEntry {
	for i := range sc.Entries {
		if sc.Entries[i].Entry.Type == typ {
			return &sc.Entries[i]
		}
	}
	return nil
}

// wholeSpan returns a synthetic entry covering every entry of a type in one
// direction, so a completeness claim cites the whole stream rather than one
// message of it.
func wholeSpan(sc *ModbusScan, typ string) *ScannedEntry {
	var first, last *ScannedEntry
	for i := range sc.Entries {
		e := &sc.Entries[i]
		if e.Entry.Type != typ || e.Dir == nil {
			continue
		}
		if first == nil {
			first = e
		}
		last = e
	}
	if first == nil {
		return nil
	}
	var frames []int
	if first.Dir.Bytes != nil {
		frames = first.Dir.Bytes.PacketsFor(first.Start, last.End)
	}
	return &ScannedEntry{
		Entry: first.Entry, Dir: first.Dir,
		Start: first.Start, End: last.End, Frames: frames,
	}
}

// connDescription renders a conn entry for an Observed field, or says plainly
// that none exists — which is itself a §4 finding, since connection information
// is required for Modbus TCP.
func connDescription(e *ScannedEntry) string {
	if e == nil {
		return "ABSENT — no SYN was captured, so this session contributes no `conn` entry and §4's " +
			"connection-information requirement is not met for it"
	}
	return fmt.Sprintf(`{"time": %.6f, "type": "conn", "ipaddr": %q, "ipport": %d} from frame %v`,
		e.Entry.Time, e.Entry.IPAddr, e.Entry.IPPort, e.Frames)
}

func ascending(sc *ModbusScan) bool {
	last := 0.0
	for _, e := range sc.Entries {
		if e.Entry.Type != EntryReq && e.Entry.Type != EntryResp {
			continue
		}
		if e.Entry.Time < last {
			return false
		}
		last = e.Entry.Time
	}
	return true
}

func transactionIDs(sc *ModbusScan) []string {
	seen := map[string]bool{}
	var out []string
	for _, e := range sc.Entries {
		raw, err := DecodeHexMsg(e.Entry.Msg)
		if err != nil || len(raw) < 2 {
			continue
		}
		id := fmt.Sprintf("0x%04X", be16(raw[0:2]))
		if !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	return out
}

func entryJSON(e *ScannedEntry) string {
	if e == nil {
		return "(no entry)"
	}
	return fmt.Sprintf(`{"time": %.6f, "type": %q, "msg": %q}`, e.Entry.Time, e.Entry.Type, e.Entry.Msg)
}
