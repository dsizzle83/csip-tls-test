package report

// summary.go builds the Summary Test Results element: the ONE CSV document that
// SunSpec posts publicly (§1, §3.1). Everything about it is governed by seven
// sentences in §3.1, and this file implements exactly those seven and nothing
// more:
//
//	one document · each row is a key and a value · row ordering is unimportant ·
//	enumerated values come only from the documented enumeration · all
//	non-enumerated values are strings · keys match the documented labels exactly ·
//	values containing CSV-significant characters are quoted.
//
// The emitter re-PARSES what it wrote and validates that, rather than
// validating the model it wrote from. A generator that checks its own
// intentions rather than its own output cannot catch the one class of bug that
// matters here — a quoting or encoding fault that makes the file say something
// different from what the model held.
//
// Two representation decisions the specification does not make, made here and
// recorded in the readiness report rather than left implicit:
//
//	Line terminator. §3.1 says "CSV" and nothing else. RFC 4180 says CRLF, so
//	CRLF it is; a reader on any platform accepts it.
//	Header row. The §3.1.2 example is RENDERED as a two-column table with "Key"
//	and "Value" headings, which leaves it ambiguous whether those are a CSV
//	line. They are not emitted: §3.1 describes rows of key/value pairs, and an
//	unexpected first row would parse as the key "Key" with the value "Value".

import (
	"bytes"
	"encoding/csv"
	"fmt"
	"io"
	"sort"
	"strings"
)

// Document identities, as the catalog spells them.
const (
	DocCSIP   = "SS-CSIP-RESULTS-v1.1"
	DocModbus = "SS-MODBUS-RESULTS-v1.2"
)

func uidCSIP(id string) string   { return "ss-csip-results-v1.1::" + id }
func uidModbus(id string) string { return "ss-modbus-results-v1.2::" + id }

// TestVerdict is one `Test <Test ID>` row: a test procedure's identifier and
// the enumerated verdict for it. This is the only part of the Summary that
// carries a conformance result; everything else is metadata.
type TestVerdict struct {
	// ID is the test procedure's name as the procedure document spells it
	// ("BASIC-001", "MOD-1.705"). It must be the same string the Detailed Test
	// Log's `tests` array uses — that join is how SunSpec ties a verdict to its
	// evidence.
	ID string
	// Verdict is PASS, FAIL or NOT SUPPORTED. Nothing else is expressible: the
	// enumeration has three members, so a bench SKIP or WARN has to be mapped
	// deliberately and the mapping stated, never silently rendered as PASS.
	Verdict string
	// Note is carried for the readiness report, not for the CSV: the format has
	// no per-test comment field.
	Note string
}

// Row is one emitted key/value pair.
type Row struct {
	Key   string
	Value string
	// Spec is the key table entry that produced the row; zero for verdict rows.
	Spec KeySpec
	// Verdict is set for `Test <Test ID>` rows.
	Verdict bool
}

// MissingKey is a required key the submitter did not supply.
type MissingKey struct {
	// Key is the documented label, so the operator can be told exactly what to
	// put in the configuration file.
	Key string
	// UID is the catalog case that requires it.
	UID string
	// Why explains what kind of value it is and who can supply it.
	Why string
}

// Summary is the Summary Test Results document.
type Summary struct {
	// CertType selects the governing key table.
	CertType string
	// Rows are what will be written, in emission order.
	Rows []Row
	// Missing names every required key with no value. A Summary with a
	// non-empty Missing is not a submittable document, and Generate will not
	// write it under a name that suggests otherwise.
	Missing []MissingKey
	// Problems are values that were supplied and are wrong for their key: a
	// malformed date, a laboratory outside the enumeration, a URL that is not
	// one. These are FAILURES, distinct from Missing, because a wrong value is
	// worse than an absent one.
	Problems []string
	// Notes are the documented ambiguities affecting keys that were actually
	// emitted, so the readiness report can raise them with the lab.
	Notes []string
}

// BuildSummary renders a configuration and a verdict set into the Summary Test
// Results document.
//
// It never invents a value. An unsupplied required key produces a MissingKey,
// not a placeholder; a supplied value that breaks its key's rule produces a
// Problem, not a silent correction.
func BuildSummary(cfg *SubmissionConfig, certType string, verdicts []TestVerdict) *Summary {
	if cfg == nil {
		cfg = &SubmissionConfig{}
	}
	s := &Summary{CertType: certType}
	for _, k := range KeyTable(certType) {
		values := k.value(cfg)
		if len(values) == 0 {
			if k.Required {
				s.Missing = append(s.Missing, MissingKey{
					Key: k.Label, UID: k.UID, Why: missingWhy(k),
				})
			}
			continue
		}
		for i, v := range values {
			if problem := k.Validate(v); problem != "" {
				s.Problems = append(s.Problems, fmt.Sprintf("%s: %s", k.Indexed(i+1), problem))
			}
			s.Rows = append(s.Rows, Row{Key: k.Indexed(i + 1), Value: v, Spec: k})
		}
		if k.Note != "" {
			s.Notes = append(s.Notes, fmt.Sprintf("%s — %s", k.Label, k.Note))
		}
		if k.Kind == KindEnum && k.EnumUnavailable != "" {
			s.Notes = append(s.Notes, fmt.Sprintf(
				"%s is enumerated but the enumeration could not be validated: %s", k.Label, k.EnumUnavailable))
		}
	}

	// Verdict rows last. §3.1 says ordering is unimportant, but both §3.1.2
	// examples put the metadata first and the verdicts last, and a human
	// opening the file wants the same shape.
	seen := map[string]bool{}
	for _, v := range verdicts {
		key := "Test " + v.ID
		if seen[key] {
			s.Problems = append(s.Problems, fmt.Sprintf("duplicate verdict row %q", key))
			continue
		}
		seen[key] = true
		if !validVerdict(v.Verdict) {
			s.Problems = append(s.Problems, fmt.Sprintf(
				"%s: verdict %q is not one of %s", key, v.Verdict, strings.Join(TestVerdicts, " | ")))
		}
		s.Rows = append(s.Rows, Row{Key: key, Value: v.Verdict, Verdict: true})
	}
	if len(verdicts) == 0 {
		s.Missing = append(s.Missing, MissingKey{
			Key: "Test <Test ID>", UID: verdictUID(certType),
			Why: "no test procedure verdicts were supplied; a Summary Test Results with no `Test <ID>` row " +
				"carries no conformance result at all",
		})
	}
	return s
}

func verdictUID(certType string) string {
	if certType == CertTypeModbus {
		return uidModbus("RPT-KV-30")
	}
	return uidCSIP("RPT-039")
}

func validVerdict(v string) bool {
	for _, e := range TestVerdicts {
		if v == e {
			return true
		}
	}
	return false
}

// missingWhy says who can supply an absent value, which is the difference
// between "the operator forgot" and "only a SunSpec Authorized Test Laboratory
// can put a value here".
func missingWhy(k KeySpec) string {
	switch k.Label {
	case "Certificate Number", "Certificate Signer Name", "Date Issued":
		return "assigned by SunSpec; it does not exist until the certificate does"
	case "Test Laboratory", "Supervising Test Engineer":
		return "supplied by the SunSpec Authorized Test Laboratory that ran the test"
	case "Company Name", "Company Address", "Company City", "Company Country", "Company Postal Code":
		return "supplied by the submitter (the company the certificate is issued to)"
	case "Protocol Implementation Conformance Statement":
		return "the published PICS URL for the certified software, supplied by the submitter"
	default:
		return "supplied by the submitter or the laboratory; this tool has no way to derive it"
	}
}

// Complete reports whether the Summary is submittable: every required key
// present and no supplied value wrong for its key.
func (s *Summary) Complete() bool { return len(s.Missing) == 0 && len(s.Problems) == 0 }

// MissingKeys returns the missing key labels, sorted, for a message.
func (s *Summary) MissingKeys() []string {
	out := make([]string, 0, len(s.Missing))
	for _, m := range s.Missing {
		out = append(out, m.Key)
	}
	sort.Strings(out)
	return out
}

// Verdicts returns the emitted `Test <Test ID>` rows.
func (s *Summary) Verdicts() []Row {
	var out []Row
	for _, r := range s.Rows {
		if r.Verdict {
			out = append(out, r)
		}
	}
	return out
}

// Lookup returns the emitted row with an exact key.
func (s *Summary) Lookup(key string) (Row, bool) {
	for _, r := range s.Rows {
		if r.Key == key {
			return r, true
		}
	}
	return Row{}, false
}

// WriteCSV writes the document per §3.1. It uses RFC 4180 CRLF terminators and
// encoding/csv's quoting, which quotes exactly the values §3.1 requires quoted:
// those containing a comma, a double quote or a line break.
func (s *Summary) WriteCSV(w io.Writer) error {
	cw := csv.NewWriter(w)
	cw.UseCRLF = true
	for _, r := range s.Rows {
		if err := cw.Write([]string{r.Key, r.Value}); err != nil {
			return fmt.Errorf("report: write summary row %q: %w", r.Key, err)
		}
	}
	cw.Flush()
	return cw.Error()
}

// CSV renders the document to bytes.
func (s *Summary) CSV() ([]byte, error) {
	var buf bytes.Buffer
	if err := s.WriteCSV(&buf); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// ParsedSummary is a Summary Test Results document read back from bytes. The
// checks assert against THIS, not against the model that produced it: what the
// file says is the only thing SunSpec will ever see.
type ParsedSummary struct {
	Rows []Row
	// Lines is the raw record count, so a stray header row is visible.
	Lines int
}

// ParseSummary reads a Summary Test Results CSV.
//
// It requires exactly two fields per record — §3.1's "each row consists of an
// information key and a value" — and reports a record with any other arity as
// an error rather than padding or truncating it.
func ParseSummary(data []byte) (*ParsedSummary, error) {
	cr := csv.NewReader(bytes.NewReader(data))
	cr.FieldsPerRecord = -1 // validated below, with a better message
	recs, err := cr.ReadAll()
	if err != nil {
		return nil, fmt.Errorf("report: parse summary CSV: %w", err)
	}
	out := &ParsedSummary{Lines: len(recs)}
	for i, rec := range recs {
		if len(rec) != 2 {
			return nil, fmt.Errorf("report: summary CSV line %d has %d field(s); §3.1 requires "+
				"exactly a key and a value", i+1, len(rec))
		}
		out.Rows = append(out.Rows, Row{Key: rec[0], Value: rec[1]})
	}
	return out, nil
}

// Lookup returns the parsed row with an exact key.
func (p *ParsedSummary) Lookup(key string) (Row, bool) {
	for _, r := range p.Rows {
		if r.Key == key {
			return r, true
		}
	}
	return Row{}, false
}

// Keys returns the emitted key labels in file order.
func (p *ParsedSummary) Keys() []string {
	out := make([]string, len(p.Rows))
	for i, r := range p.Rows {
		out[i] = r.Key
	}
	return out
}

// ValidateAgainst re-checks a parsed document against a key table: every key
// must be one the table documents (allowing the repeat index), every enumerated
// value must be in its enumeration, and the two `Hardware Model` spellings must
// not have collided. It returns one message per finding, empty when the
// document conforms.
//
// This is deliberately a check of the FILE against the SPECIFICATION, with no
// reference to the configuration that produced it — the same check a reviewer
// at SunSpec could run on the submitted CSV alone.
func (p *ParsedSummary) ValidateAgainst(table []KeySpec) []string {
	var findings []string
	seen := map[string]int{}
	for _, r := range p.Rows {
		seen[r.Key]++
		if IsVerdictKey(table, r.Key) {
			if !validVerdict(r.Value) {
				findings = append(findings, fmt.Sprintf(
					"%s: verdict %q is not one of %s", r.Key, r.Value, strings.Join(TestVerdicts, " | ")))
			}
			continue
		}
		spec, idx, ok := matchKey(table, r.Key)
		if !ok {
			findings = append(findings, fmt.Sprintf(
				"key %q is not a documented key label for this certificate type", r.Key))
			continue
		}
		if !spec.Repeatable && idx != 0 {
			findings = append(findings, fmt.Sprintf(
				"key %q carries a repeat index but %q is not a repeatable key", r.Key, spec.Label))
		}
		if problem := spec.Validate(r.Value); problem != "" {
			findings = append(findings, fmt.Sprintf("%s: %s", r.Key, problem))
		}
	}
	for k, n := range seen {
		if n > 1 {
			findings = append(findings, fmt.Sprintf("key %q appears %d times; keys are unique", k, n))
		}
	}
	sort.Strings(findings)
	return findings
}

// IsVerdictKey distinguishes a `Test <Test ID>` verdict row from the three
// documented keys that also begin with "Test " — `Test Laboratory`,
// `Test Completion Date` and `Test Description`. Prefix matching alone reports
// a laboratory's name as an invalid verdict, which is a finding a reviewer
// would have to disprove by hand.
func IsVerdictKey(table []KeySpec, key string) bool {
	if !strings.HasPrefix(key, "Test ") {
		return false
	}
	_, _, documented := matchKey(table, key)
	return !documented
}

// matchKey resolves a possibly-indexed emitted key back to its table entry. It
// returns the 1-based repeat index, or 0 when the key carried none.
func matchKey(table []KeySpec, key string) (KeySpec, int, bool) {
	if spec, ok := FindKey(table, key); ok {
		return spec, 0, true
	}
	i := strings.LastIndexByte(key, ' ')
	if i <= 0 {
		return KeySpec{}, 0, false
	}
	label, suffix := key[:i], key[i+1:]
	n := 0
	for _, c := range suffix {
		if c < '0' || c > '9' {
			return KeySpec{}, 0, false
		}
		n = n*10 + int(c-'0')
	}
	if n == 0 {
		return KeySpec{}, 0, false
	}
	spec, ok := FindKey(table, label)
	return spec, n, ok
}

// RequiredKeys lists the labels a submittable report must carry, for the
// operator-facing error message.
func RequiredKeys(certType string) []string {
	var out []string
	for _, k := range KeyTable(certType) {
		if k.Required {
			out = append(out, k.Label)
		}
	}
	return out
}
