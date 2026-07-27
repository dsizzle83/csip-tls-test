// Package report implements the two SunSpec RESULTS REPORTING specifications —
// SS-CSIP-RESULTS-v1.1 (47 catalog cases) and SS-MODBUS-RESULTS-v1.2 (54) — and
// the generator that satisfies them.
//
// # What makes this suite different from the others
//
// Every other suite in this bench asks a question about the DUT. This one asks
// a question about US: does the artefact we hand a certifying lab actually meet
// the published requirements on a Test Results Report? The RPT-* rows are
// requirements on the REPORT, not on the gateway. A suite that could prove the
// gateway conformant but could not emit a submittable report would have proved
// nothing anybody can act on, because SunSpec grants the Certified mark against
// a TRR, not against a pcap.
//
// So this package is a generator first and a checker second:
//
//	SubmissionConfig  the lab/submitter metadata a bench run cannot know
//	Summary           the public Summary Test Results CSV (§3.1)
//	ModbusTestLogs    the archived Modbus Detailed Test Logs (§4, JSON)
//	CSIPTestLogs      the archived CSIP HTTP Detailed Test Logs (§4, JSON)
//	Traces            the COMM-004 raw TLS packet traces (Chapter 5, v1.1)
//	Readiness         a per-requirement self-assessment of the above
//
// and a set of certify.Checks that assert the emitted artefacts against the
// catalog rows that specify them.
//
// # The three dishonesty modes, in this suite's dialect
//
// certify's package doc names the three ways a conformance tool lies. Each has
// a specific shape here, and a specific mechanism against it.
//
//  1. Inventing lab metadata. Roughly thirty of these hundred-and-one rows are
//     facts only a SunSpec Authorized Test Laboratory or the submitter can
//     supply: the certificate number SunSpec assigns, the company's legal name,
//     the supervising engineer, which of the thirteen authorized labs ran the
//     test. A generator that filled those with plausible defaults would produce
//     a document that LOOKS submittable and is a forgery. So: there are no
//     defaults. A field that was not supplied is not emitted, [Summary.Missing]
//     names it, [Generate] refuses to produce a report unless the caller
//     explicitly accepts an incomplete one, and when it does the CSV is written
//     under the name SUMMARY-INCOMPLETE.csv — a filename nobody forwards to a
//     lab by accident.
//
//  2. A log that disagrees with the capture. §4 requires the detailed logs to
//     contain ALL Modbus messages, in unencrypted form, as ascii-hex. The easy
//     implementation logs what the tool's own Modbus client thinks it sent.
//     That log can be perfectly well-formed and still not describe the wire —
//     a retransmit, a coalesced segment, a byte the library rewrote would all
//     be invisible. This package therefore derives every log entry FROM THE
//     CAPTURE ([ScanModbus], [ScanHTTP]): each entry carries the byte range of
//     the reassembled stream it was decoded from, and the checks cite exactly
//     that range. The log and the pcap cannot disagree, because the log is a
//     rendering of the pcap.
//
//  3. Claiming a requirement is met when it was merely addressed. The
//     [Readiness] report is per-requirement, keyed by catalog uid, with three
//     outcomes — met, unmet, and not-assessable-here-with-the-reason. Its
//     summary line refuses to say SUBMITTABLE while any required key or any
//     mandatory artefact is absent.
//
// # What a check in this suite may cite
//
// Two shapes recur.
//
// Wire-tied rows (RPT-LOG-8's ascii-hex framing, RPT-LOG-10's MBAP header,
// RPT-LOG-15's conn/ipaddr/ipport, RPT-050's plaintext HTTP) are proved by
// conducting a real exchange, claiming it, and citing in the second phase the
// exact stream bytes the emitted log entry renders. Those PASSes carry a
// sha256 bundle.Verify re-derives.
//
// Document-shape rows (the §3.1.1 key table, the §4.1.x JSON schemas) are
// requirements on a FILE. No packet can evidence "the CSV quotes a value
// containing a comma". Those checks set Result.OffWire with a reason naming the
// artefact and the rule, which is the framework's honest path for a criterion
// the wire cannot show — not a way to quiet a warning.
//
// Rows needing a lab (RPT-020 Test Laboratory, RPT-011 Certificate Number,
// RPT-APX-1's thirteen NRTLs) SKIP with the reason when unsupplied, and assert
// only the FORM of a supplied value. This tool never asserts that a
// submitter-supplied value is TRUE — only that the report carries it in the
// shape the specification requires. The claim wording says so.
//
// # Layout
//
//	config.go       submitter/lab metadata: JSON or flat-YAML, validated by key
//	keys.go         the §3.1.1 key tables, per certificate type, with their rules
//	summary.go      the Summary Test Results CSV: emit, re-parse, validate
//	modbuslog.go    §4.1 Modbus Test Log / Log Entry / Test Logs objects
//	csiplog.go      §4.1 CSIP Test Log / Message / Test Logs objects
//	mbapscan.go     capture -> Modbus log entries, with byte provenance
//	httpscan.go     capture -> CSIP HTTP message objects, with byte provenance
//	pcapwrite.go    Chapter 5 trace export: a classic libpcap writer
//	generate.go     the submission: public/ + archive/, or refuse
//	readiness.go    the per-requirement self-assessment
//	suite.go        the shared run state, the wire probe, the check factories
//	checks_modbus.go / checks_csip.go   the catalog bindings
//
// Nothing here imports the product, wolfSSL, or cgo: the whole package builds
// with CGO_ENABLED=0, because a report generator that cannot run on a laptop
// without a TLS sysroot is a report generator nobody runs.
package report
