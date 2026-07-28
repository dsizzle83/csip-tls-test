package suitessm

// capturenames.go transcribes the pcap file names the Secure SunSpec Modbus
// Conformance Test Procedures require of a submission.
//
// Every row of SSM-CONF-v0.8 that produces traffic ends in a "Reporting
// Requirements" subsection whose first bullet names a file, verbatim and in
// lower case:
//
//	§2.4.1.3  "A packet capture (.pcap) of the entire session spanning all
//	           server and client iterations showing the TLS connection named
//	           tlsf_001.pcap."
//	§2.4.3.3  "A packet capture (.pcap) of the entire session showing the TLS
//	           connection on port 802. One capture per bad certificate type
//	           named tlsf_003_expired.pcap, tlsf_003_badsig.pcap, and
//	           tlsf_003_untrusted.pcap."
//	§2.4.5.3  "…named tlsf_005.pcap." + "A packet capture (.pcap) of the
//	           resumption attempt named tlsf_005_resume.pcap."
//	§2.7.4.3  "A packet capture (.pcap) of the session showing the
//	           renegotiation extension and renegotiation attempt named
//	           prot_004.pcap."
//
// # Why this is a table and not a rule
//
// Thirty-four of the thirty-nine names are exactly the test id lower-cased with
// its hyphen turned into an underscore, and it is tempting to write that as a
// two-line function. The remaining five are not, and they are the ones that
// matter most: TLSF-003 is three files, one per bad-certificate type, and
// TLSF-005 is two, the session and the resumption attempt. A rule with
// exceptions bolted on hides the exceptions; a transcription shows a reviewer
// exactly what this bench believes the document says, next to the section it
// says it in. namingRuleHolds (capturenames_test.go) asserts the mechanical
// majority still follow the pattern, so a typo in the table is caught without
// the table being replaced by the pattern.
//
// # The rows with no bullet
//
// RBAC-004 and RBAC-005 are audits of the vendor's roles-to-rights map and
// AuthZ description; OPS-001 is a review of an export declaration. Their
// Reporting Requirements ask for documents, not captures, so they are absent
// here deliberately — an empty list means "the document names no capture for
// this row", which is a different statement from "nobody got round to it", and
// TestEveryTrafficRowNamesItsCapture holds the difference in place.

// captureNames maps a bare SSM-CONF-v0.8 test id to the pcap file name(s) its
// Reporting Requirements subsection prescribes, in document order.
var captureNames = map[string][]string{
	// §2.4 TLS Fundamentals.
	"TLSF-001": {"tlsf_001.pcap"},
	"TLSF-002": {"tlsf_002.pcap"},
	// One capture per bad certificate type, in the order §2.4.3.3 lists them.
	"TLSF-003": {"tlsf_003_expired.pcap", "tlsf_003_badsig.pcap", "tlsf_003_untrusted.pcap"},
	"TLSF-004": {"tlsf_004.pcap"},
	// The session, then the resumption attempt (§2.4.5.3, two bullets).
	"TLSF-005": {"tlsf_005.pcap", "tlsf_005_resume.pcap"},
	"TLSF-006": {"tlsf_006.pcap"},

	// §2.5 Cryptography. CRYP-003's server and client halves both name
	// cryp_003.pcap — §2.5.3.3 and §2.5.3.6 — so there is one file, not two.
	"CRYP-001": {"cryp_001.pcap"},
	"CRYP-002": {"cryp_002.pcap"},
	"CRYP-003": {"cryp_003.pcap"},
	"CRYP-004": {"cryp_004.pcap"},
	"CRYP-005": {"cryp_005.pcap"},
	"CRYP-006": {"cryp_006.pcap"},
	"CRYP-007": {"cryp_007.pcap"},

	// §2.6 Public Key Infrastructure.
	"PKI-001": {"pki_001.pcap"},
	"PKI-002": {"pki_002.pcap"},
	"PKI-003": {"pki_003.pcap"},
	"PKI-004": {"pki_004.pcap"},
	"PKI-005": {"pki_005.pcap"},
	"PKI-006": {"pki_006.pcap"},
	"PKI-007": {"pki_007.pcap"},
	"PKI-008": {"pki_008.pcap"},
	"PKI-009": {"pki_009.pcap"},

	// §2.7 Protocol.
	"PROT-001": {"prot_001.pcap"},
	"PROT-002": {"prot_002.pcap"},
	"PROT-003": {"prot_003.pcap"},
	"PROT-004": {"prot_004.pcap"},

	// §2.8 Role-Based Access Control. RBAC-004 and RBAC-005 are audits and
	// name no capture — see the file header.
	"RBAC-001": {"rbac_001.pcap"},
	"RBAC-002": {"rbac_002.pcap"},
	"RBAC-003": {"rbac_003.pcap"},
	"RBAC-006": {"rbac_006.pcap"},
	"RBAC-007": {"rbac_007.pcap"},
	"RBAC-008": {"rbac_008.pcap"},
	"RBAC-009": {"rbac_009.pcap"},
	"RBAC-010": {"rbac_010.pcap"},
	"RBAC-011": {"rbac_011.pcap"},
	"RBAC-012": {"rbac_012.pcap"},
}

// CaptureNames returns the pcap file names SSM-CONF-v0.8 requires for a test
// id, or nil when its Reporting Requirements name none.
//
// It is exported so a submission-assembly step can ask the same question the
// runner does, from the same transcription.
func CaptureNames(id string) []string {
	n, ok := captureNames[id]
	if !ok {
		return nil
	}
	return append([]string(nil), n...)
}
