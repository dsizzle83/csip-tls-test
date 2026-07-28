package report

// config.go carries the part of a Test Results Report a bench run can never
// discover: the certificate number SunSpec assigns, the legal name of the
// company the certificate is issued to, which of the thirteen authorized labs
// ran the test, who supervised it.
//
// The whole design of this file follows from one rule: NOTHING HERE HAS A
// DEFAULT. A generator that shipped `Company Name: ACME Incorporated` because
// the specification's example says so would emit a document that parses, looks
// complete, and is a forgery. Every value in a SubmissionConfig came from an
// operator, a config file, or a flag; a field nobody supplied stays empty, is
// not emitted, and is named in the readiness report.
//
// The file format is JSON, or a deliberately small YAML subset. The subset is
// small because a half-supported YAML is worse than none: a config that
// silently mis-parses an anchor or a folded scalar would put the wrong company
// name on a submission. parseFlatYAML therefore accepts exactly three shapes —
// scalars, lists of scalars, and lists of one-level maps — and returns a
// line-numbered error for anything else rather than guessing.

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// SoftwareRecord is one `Software Name <n>` / `Software Version <n>` /
// `Software Checksum <n>` group from §3.1.1. The three keys share an index and
// describe one binary, which is why they are one record here rather than three
// parallel lists a mis-edit could desynchronise.
type SoftwareRecord struct {
	// Name is the file name INCLUDING its type suffix (§3.1.1: "the file type
	// suffix is included in the value").
	Name string `json:"name"`
	// Version is a String. "11.01" must survive as "11.01", never as a float.
	Version string `json:"version"`
	// Checksum is the fingerprint binding the results to an exact image. The
	// specification never states the ALGORITHM — the example value 423EC0E4 is
	// eight hex digits, consistent with CRC-32 — so ChecksumAlgorithm below is
	// carried separately and stated in Additional Test Comments, which is the
	// only place the format has for it.
	Checksum string `json:"checksum"`
	// Element names which of the DUT's deployed binaries this record describes,
	// using the key an evidence bundle's DUT build stamp uses ("mbaps", "nb",
	// "modbus"). It has NO key in either §3.1.1 table and is never emitted; its
	// only job is to let [FillChecksums] derive Checksum from the digest the
	// campaign recorded, so the value in the report is the one the evidence was
	// produced against rather than one somebody re-typed.
	//
	// A record with no Element is never autofilled — an operator who computed
	// the digest another way is stating something this tool has no standing to
	// correct.
	Element string `json:"element,omitempty"`
}

// OSRecord is one `Operating System <n>` / `Operating System Version <n>` pair.
type OSRecord struct {
	Name string `json:"name"`
	// Version is documented as "X.X" — major plus the first digit of minor —
	// while the specification's own example is "18.04", which carries two. The
	// generator emits what it is given and the readiness report flags the
	// contradiction rather than silently truncating a version.
	Version string `json:"version"`
}

// SubmissionConfig is the lab- and submitter-supplied half of a TRR.
//
// Field names are the flat key space of both the JSON and the YAML forms, so a
// config file reads like the CSV it becomes.
type SubmissionConfig struct {
	// CertificateType selects which specification's key table governs the
	// report: "IEEE 2030.5/CSIP" or "SunSpec Modbus".
	CertificateType string `json:"certificate_type"`
	// CertificateTypeVersion is the key the §3.1.2 examples emit ("2019" for
	// CSIP, "2021" for Modbus) and that neither key table defines. It is
	// carried because the worked examples carry it; the readiness report notes
	// that it is undocumented.
	CertificateTypeVersion string `json:"certificate_type_version"`
	// CertificateNumber is assigned by SunSpec. A tool cannot synthesise one.
	CertificateNumber string `json:"certificate_number"`

	CompanyName       string `json:"company_name"`
	CompanyAddress    string `json:"company_address"`
	CompanyCity       string `json:"company_city"`
	CompanyState      string `json:"company_state"`
	CompanyProvince   string `json:"company_province"`
	CompanyCountry    string `json:"company_country"`
	CompanyPostalCode string `json:"company_postal_code"`

	// DateIssued is MM/DD/YYYY, assigned by SunSpec with the certificate.
	DateIssued string `json:"date_issued"`
	// TestLaboratory must be one of the enumerated SunSpec Authorized Test
	// Laboratories. An in-house bench run cannot legitimately populate it, and
	// the generator will not.
	TestLaboratory          string `json:"test_laboratory"`
	SupervisingTestEngineer string `json:"supervising_test_engineer"`
	// CertificateSignerName is filled in by SunSpec Alliance post-submission.
	CertificateSignerName string `json:"certificate_signer_name"`

	Software []SoftwareRecord `json:"software"`
	OS       []OSRecord       `json:"operating_systems"`
	// ChecksumAlgorithm names the algorithm behind Software Checksum. The
	// format has no key for it; the generator states it in Additional Test
	// Comments so the value is not an unverifiable eight-digit number.
	ChecksumAlgorithm string `json:"checksum_algorithm"`

	// SoftwareOperatingEnvironment is "Hardware Device" or "Cloud" per §3.1.1.
	// The §3.1.2 examples of BOTH documents instead print "Device"; the
	// generator emits the normative token and records the divergence.
	SoftwareOperatingEnvironment string `json:"software_operating_environment"`
	PICSURL                      string `json:"pics_url"`
	CloudProvider                string `json:"cloud_provider"`
	CloudProviderVersion         string `json:"cloud_provider_version"`

	ProductManufacturer  []string `json:"product_manufacturer"`
	ProductModel         []string `json:"product_model"`
	HardwareManufacturer []string `json:"hardware_manufacturer"`
	HardwareModel        []string `json:"hardware_model"`

	// TestCompletionDate is MM/DD/YYYY. It is the one date a bench genuinely
	// knows, and is still not defaulted: which day a laboratory considers the
	// campaign complete is the laboratory's statement, not a clock reading.
	TestCompletionDate string `json:"test_completion_date"`
	// TestDescription names the certification offering; enumerated in the
	// Modbus document's Appendix A, and in an Appendix A the CSIP document does
	// not contain.
	TestDescription        string `json:"test_description"`
	AdditionalTestComments string `json:"additional_test_comments"`

	// CombineStateProvince emits the single `Company State/Province` key the
	// §3.1.2 examples use instead of the two keys §3.1.1 defines. Off by
	// default: §3.1.1 is the normative table.
	CombineStateProvince bool `json:"combine_state_province"`
	// ContextID is the optional `cid` stitching separately-archived CSIP logs
	// back together. v1.2 of the Modbus document REMOVED cid, so it is emitted
	// for CSIP logs only.
	ContextID string `json:"context_id"`

	// PerCertificateType overrides the handful of values that legitimately
	// differ between the two reports of one Test Results Report package, keyed
	// by certificate type ("IEEE 2030.5/CSIP", "SunSpec Modbus").
	//
	// It exists because SunSpec issues ONE CERTIFICATE PER TYPE. A gateway that
	// is both a SunSpec Modbus device and an IEEE 2030.5 client gets two
	// certificate numbers, two PICS documents, and two Test Descriptions drawn
	// from two different (and in the CSIP document's case, absent) enumerations.
	// One flat configuration would put the Modbus certificate number on the CSIP
	// report, which is not a formatting mistake but a false statement.
	PerCertificateType map[string]CertTypeOverride `json:"per_certificate_type,omitempty"`

	// Comment is read and ignored. It exists because the decoder is strict —
	// an unknown key is an error, since a misspelled one would otherwise
	// silently omit a value from a certification submission — and the cost of
	// that strictness is that a configuration file cannot be annotated at all
	// unless one key is set aside for the purpose. This is that key. Nothing in
	// it reaches the report; a remark meant for the laboratory belongs in
	// additional_test_comments, which is emitted.
	Comment string `json:"_comment,omitempty"`

	// Source records where the configuration was read from, so the readiness
	// report can say whose numbers these are.
	Source string `json:"-"`
}

// CertTypeOverride is the per-certificate-type half of a submission
// configuration. Every field is optional; an empty one leaves the shared value
// in place.
type CertTypeOverride struct {
	CertificateNumber      string `json:"certificate_number,omitempty"`
	CertificateTypeVersion string `json:"certificate_type_version,omitempty"`
	DateIssued             string `json:"date_issued,omitempty"`
	CertificateSignerName  string `json:"certificate_signer_name,omitempty"`
	PICSURL                string `json:"pics_url,omitempty"`
	TestDescription        string `json:"test_description,omitempty"`
	TestCompletionDate     string `json:"test_completion_date,omitempty"`
	AdditionalTestComments string `json:"additional_test_comments,omitempty"`
	ContextID              string `json:"context_id,omitempty"`
}

// For returns the configuration governing one certificate type: the shared
// values with that type's overrides applied, and CertificateType pinned to the
// report being written.
//
// Pinning matters. `Certificate Type` is a §3.1.1 key and its value must name
// the specification the report is filed under; a package that emitted
// "SunSpec Modbus" on both halves because the operator wrote it once at the top
// of the file would file the CSIP results under the wrong certificate.
func (c *SubmissionConfig) For(certType string) *SubmissionConfig {
	local := &SubmissionConfig{}
	if c != nil {
		*local = *c
		local.Software = append([]SoftwareRecord(nil), c.Software...)
		local.OS = append([]OSRecord(nil), c.OS...)
	}
	local.CertificateType = certType
	ov, ok := local.PerCertificateType[certType]
	if !ok {
		return local
	}
	for _, f := range []struct {
		dst *string
		src string
	}{
		{&local.CertificateNumber, ov.CertificateNumber},
		{&local.CertificateTypeVersion, ov.CertificateTypeVersion},
		{&local.DateIssued, ov.DateIssued},
		{&local.CertificateSignerName, ov.CertificateSignerName},
		{&local.PICSURL, ov.PICSURL},
		{&local.TestDescription, ov.TestDescription},
		{&local.TestCompletionDate, ov.TestCompletionDate},
		{&local.AdditionalTestComments, ov.AdditionalTestComments},
		{&local.ContextID, ov.ContextID},
	} {
		if strings.TrimSpace(f.src) != "" {
			*f.dst = f.src
		}
	}
	return local
}

// Certificate type values, from the §3.1.1 enumeration.
const (
	CertTypeCSIP   = "IEEE 2030.5/CSIP"
	CertTypeModbus = "SunSpec Modbus"
	CertTypeDNP3   = "IEEE1815/AN2018"
	CertTypeRSD    = "SunSpec RSD"
)

// CertificateTypes is the closed enumeration both documents print.
var CertificateTypes = []string{CertTypeDNP3, CertTypeCSIP, CertTypeModbus, CertTypeRSD}

// LoadConfig reads a submission configuration from path. The extension selects
// the parser: .json is JSON, .yaml/.yml is the flat subset. Anything else is
// tried as JSON first and then as the YAML subset, so a file called `submission.conf`
// still works.
//
// Unknown fields are an error in both forms. A configuration file with a
// misspelled key would otherwise silently omit the value it meant to supply,
// and the omission would surface only as a missing row in a document already on
// its way to a laboratory.
func LoadConfig(path string) (*SubmissionConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("report: read submission config: %w", err)
	}
	var cfg *SubmissionConfig
	switch strings.ToLower(filepath.Ext(path)) {
	case ".json":
		cfg, err = parseJSONConfig(data)
	case ".yaml", ".yml":
		cfg, err = parseYAMLConfig(data)
	default:
		cfg, err = parseJSONConfig(data)
		if err != nil {
			var yerr error
			if cfg, yerr = parseYAMLConfig(data); yerr != nil {
				return nil, fmt.Errorf("report: %s parses as neither JSON (%v) nor the supported YAML subset (%v)",
					path, err, yerr)
			}
			err = nil
		}
	}
	if err != nil {
		return nil, fmt.Errorf("report: %s: %w", path, err)
	}
	cfg.Source = path
	return cfg, nil
}

func parseJSONConfig(data []byte) (*SubmissionConfig, error) {
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	cfg := &SubmissionConfig{}
	if err := dec.Decode(cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}

func parseYAMLConfig(data []byte) (*SubmissionConfig, error) {
	tree, err := parseFlatYAML(string(data))
	if err != nil {
		return nil, err
	}
	// Round-tripping through JSON reuses the strict decoder rather than
	// duplicating field-name knowledge in a second reflective mapper.
	buf, err := json.Marshal(tree)
	if err != nil {
		return nil, err
	}
	return parseJSONConfig(buf)
}

// parseFlatYAML accepts the three shapes a submission configuration needs and
// refuses everything else:
//
//	key: scalar
//	key:
//	  - scalar
//	  - scalar
//	key:
//	  - subkey: scalar
//	    subkey: scalar
//
// Indentation is two spaces per level. Tabs, anchors, flow collections, block
// scalars and nesting deeper than shown are rejected with the line number,
// because a configuration this file mis-reads becomes a wrong value on a
// certification submission.
func parseFlatYAML(src string) (map[string]any, error) {
	out := map[string]any{}
	lines := strings.Split(src, "\n")

	var pendingKey string
	var scalarList []string
	var mapList []map[string]any
	var current map[string]any

	flush := func() {
		switch {
		case pendingKey == "":
		case len(mapList) > 0:
			v := make([]any, len(mapList))
			for i := range mapList {
				v[i] = mapList[i]
			}
			out[pendingKey] = v
		case scalarList != nil:
			out[pendingKey] = scalarList
		}
		pendingKey, scalarList, mapList, current = "", nil, nil, nil
	}

	for i, raw := range lines {
		ln := i + 1
		if strings.ContainsRune(raw, '\t') {
			return nil, fmt.Errorf("line %d: tabs are not accepted; indent with two spaces", ln)
		}
		line := strings.TrimRight(raw, " ")
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if strings.HasPrefix(trimmed, "&") || strings.HasPrefix(trimmed, "*") ||
			strings.HasPrefix(trimmed, "---") || strings.HasSuffix(trimmed, "|") ||
			strings.HasSuffix(trimmed, ">") {
			return nil, fmt.Errorf("line %d: %q uses a YAML feature this parser does not support "+
				"(anchors, aliases, documents, block scalars)", ln, trimmed)
		}
		indent := len(line) - len(strings.TrimLeft(line, " "))
		if indent%2 != 0 {
			return nil, fmt.Errorf("line %d: indent is %d spaces; two spaces per level", ln, indent)
		}

		switch {
		case indent == 0:
			flush()
			key, val, ok := strings.Cut(trimmed, ":")
			if !ok {
				return nil, fmt.Errorf("line %d: %q is not `key: value`", ln, trimmed)
			}
			key = strings.TrimSpace(key)
			val = strings.TrimSpace(val)
			if val == "" {
				pendingKey = key
				continue
			}
			if err := rejectUnsupportedScalar(ln, val); err != nil {
				return nil, err
			}
			out[key] = unquoteYAML(val)

		case indent == 2 && strings.HasPrefix(trimmed, "- "):
			if pendingKey == "" {
				return nil, fmt.Errorf("line %d: list item with no key above it", ln)
			}
			item := strings.TrimSpace(strings.TrimPrefix(trimmed, "- "))
			if k, v, ok := strings.Cut(item, ":"); ok && !strings.HasPrefix(item, "http") {
				current = map[string]any{strings.TrimSpace(k): unquoteYAML(strings.TrimSpace(v))}
				mapList = append(mapList, current)
				continue
			}
			if mapList != nil {
				return nil, fmt.Errorf("line %d: list mixes scalars and mappings", ln)
			}
			scalarList = append(scalarList, unquoteYAML(item))

		case indent == 4 && current != nil:
			k, v, ok := strings.Cut(trimmed, ":")
			if !ok {
				return nil, fmt.Errorf("line %d: %q is not `key: value`", ln, trimmed)
			}
			current[strings.TrimSpace(k)] = unquoteYAML(strings.TrimSpace(v))

		default:
			return nil, fmt.Errorf("line %d: unsupported nesting at indent %d: %q", ln, indent, trimmed)
		}
	}
	flush()
	return out, nil
}

// rejectUnsupportedScalar refuses a value that uses a YAML feature this parser
// does not implement. An anchor reference silently read as the literal string
// "*anchor" would put that text on a certification submission.
func rejectUnsupportedScalar(line int, v string) error {
	switch {
	case strings.HasPrefix(v, "&"), strings.HasPrefix(v, "*"),
		strings.HasPrefix(v, "{"), strings.HasPrefix(v, "["),
		v == "|", v == ">", strings.HasPrefix(v, "!!"):
		return fmt.Errorf("line %d: value %q uses a YAML feature this parser does not support "+
			"(anchors, aliases, flow collections, block scalars, tags)", line, v)
	}
	return nil
}

// unquoteYAML strips one layer of matching quotes. Escapes inside are NOT
// interpreted: a submission value is a literal, and interpreting \n inside a
// company address would be an invention.
func unquoteYAML(s string) string {
	if len(s) >= 2 && (s[0] == '"' && s[len(s)-1] == '"' || s[0] == '\'' && s[len(s)-1] == '\'') {
		return s[1 : len(s)-1]
	}
	return s
}

// BindFlags exposes the configuration on a command line, for a suite binary
// that would rather pass three values than write a file. Flags are named
// <prefix><key> using the same flat key space as the file.
func (c *SubmissionConfig) BindFlags(fs *flag.FlagSet, prefix string) {
	str := func(name, usage string, p *string) { fs.StringVar(p, prefix+name, *p, usage) }
	str("certificate-type", "Summary key `Certificate Type` (enumerated)", &c.CertificateType)
	str("certificate-number", "Summary key `Certificate Number` (assigned by SunSpec)", &c.CertificateNumber)
	str("company-name", "Summary key `Company Name` (official legal name)", &c.CompanyName)
	str("company-address", "Summary key `Company Address`", &c.CompanyAddress)
	str("company-city", "Summary key `Company City`", &c.CompanyCity)
	str("company-state", "Summary key `Company State`", &c.CompanyState)
	str("company-province", "Summary key `Company Province`", &c.CompanyProvince)
	str("company-country", "Summary key `Company Country`", &c.CompanyCountry)
	str("company-postal-code", "Summary key `Company Postal Code`", &c.CompanyPostalCode)
	str("date-issued", "Summary key `Date Issued` (MM/DD/YYYY)", &c.DateIssued)
	str("test-laboratory", "Summary key `Test Laboratory` (a SunSpec Authorized Test Laboratory)", &c.TestLaboratory)
	str("supervising-engineer", "Summary key `Supervising Test Engineer`", &c.SupervisingTestEngineer)
	str("certificate-signer", "Summary key `Certificate Signer Name` (filled in by SunSpec)", &c.CertificateSignerName)
	str("operating-environment", "Summary key `Software Operating Environment` (Hardware Device|Cloud)", &c.SoftwareOperatingEnvironment)
	str("pics-url", "Summary key `Protocol Implementation Conformance Statement` (URL)", &c.PICSURL)
	str("test-completion-date", "Summary key `Test Completion Date` (MM/DD/YYYY)", &c.TestCompletionDate)
	str("test-description", "Summary key `Test Description` (enumerated)", &c.TestDescription)
	str("comments", "Summary key `Additional Test Comments`", &c.AdditionalTestComments)
	str("checksum-algorithm", "algorithm behind Software Checksum (the format has no key for it)", &c.ChecksumAlgorithm)
	str("context-id", "optional `cid` for CSIP detailed test logs", &c.ContextID)
	fs.BoolVar(&c.CombineStateProvince, prefix+"combine-state-province", c.CombineStateProvince,
		"emit the example's single `Company State/Province` key instead of the two §3.1.1 keys")
}

// paramPrefix is the -param namespace the runner passes configuration through
// when a suite binary is not available to bind flags.
const paramPrefix = "report."

// ApplyParams overlays -param report.<key>=<value> pairs onto the
// configuration. It reports an error for an unrecognised key rather than
// ignoring it: a typo in `-param report.compnay_name=…` must not become a
// silently missing row.
func (c *SubmissionConfig) ApplyParams(params map[string]string) error {
	var unknown []string
	for k, v := range params {
		name, ok := strings.CutPrefix(k, paramPrefix)
		if !ok {
			continue
		}
		if reservedParams[name] {
			continue
		}
		if !c.set(name, v) {
			unknown = append(unknown, k)
		}
	}
	if len(unknown) > 0 {
		sort.Strings(unknown)
		return fmt.Errorf("report: unrecognised parameter(s): %s", strings.Join(unknown, ", "))
	}
	return nil
}

// reservedParams are the -param report.* keys that steer the suite rather than
// populate the report.
var reservedParams = map[string]bool{
	"config": true, "out": true, "bundle": true, "modbus": true,
	"http": true, "http-path": true, "comm004": true, "allow-incomplete": true,
	// trr names an already-emitted Test Results Report package to assert
	// against, instead of one this run generates. See Suite.Subject.
	"trr": true,
}

// set assigns one flat key. It normalises `-` to `_` so both spellings work.
func (c *SubmissionConfig) set(name, v string) bool {
	switch strings.ReplaceAll(name, "-", "_") {
	case "certificate_type":
		c.CertificateType = v
	case "certificate_type_version":
		c.CertificateTypeVersion = v
	case "certificate_number":
		c.CertificateNumber = v
	case "company_name":
		c.CompanyName = v
	case "company_address":
		c.CompanyAddress = v
	case "company_city":
		c.CompanyCity = v
	case "company_state":
		c.CompanyState = v
	case "company_province":
		c.CompanyProvince = v
	case "company_country":
		c.CompanyCountry = v
	case "company_postal_code":
		c.CompanyPostalCode = v
	case "date_issued":
		c.DateIssued = v
	case "test_laboratory":
		c.TestLaboratory = v
	case "supervising_test_engineer":
		c.SupervisingTestEngineer = v
	case "certificate_signer_name":
		c.CertificateSignerName = v
	case "checksum_algorithm":
		c.ChecksumAlgorithm = v
	case "software_operating_environment":
		c.SoftwareOperatingEnvironment = v
	case "pics_url":
		c.PICSURL = v
	case "cloud_provider":
		c.CloudProvider = v
	case "cloud_provider_version":
		c.CloudProviderVersion = v
	case "product_manufacturer":
		c.ProductManufacturer = splitList(v)
	case "product_model":
		c.ProductModel = splitList(v)
	case "hardware_manufacturer":
		c.HardwareManufacturer = splitList(v)
	case "hardware_model":
		c.HardwareModel = splitList(v)
	case "test_completion_date":
		c.TestCompletionDate = v
	case "test_description":
		c.TestDescription = v
	case "additional_test_comments":
		c.AdditionalTestComments = v
	case "context_id":
		c.ContextID = v
	case "combine_state_province":
		b, err := strconv.ParseBool(v)
		if err != nil {
			return false
		}
		c.CombineStateProvince = b
	case "software_name", "software_version", "software_checksum":
		c.setSoftware(strings.ReplaceAll(name, "-", "_"), v)
	case "operating_system", "operating_system_version":
		c.setOS(strings.ReplaceAll(name, "-", "_"), v)
	default:
		return false
	}
	return true
}

// setSoftware fills index 0 of the software record list, which is the only
// index a single flag can address; multiple binaries need the config file.
func (c *SubmissionConfig) setSoftware(field, v string) {
	if len(c.Software) == 0 {
		c.Software = append(c.Software, SoftwareRecord{})
	}
	switch field {
	case "software_name":
		c.Software[0].Name = v
	case "software_version":
		c.Software[0].Version = v
	case "software_checksum":
		c.Software[0].Checksum = v
	}
}

func (c *SubmissionConfig) setOS(field, v string) {
	if len(c.OS) == 0 {
		c.OS = append(c.OS, OSRecord{})
	}
	switch field {
	case "operating_system":
		c.OS[0].Name = v
	case "operating_system_version":
		c.OS[0].Version = v
	}
}

func splitList(v string) []string {
	var out []string
	for _, p := range strings.Split(v, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// Empty reports whether nothing at all was supplied. It is what lets the
// readiness report distinguish "no submitter metadata exists" — the honest
// state of an unconfigured bench run — from "the metadata came from somewhere
// other than a file". Saying the first when the second is true would misreport
// a properly configured submission as an empty one.
func (c *SubmissionConfig) Empty() bool {
	if c == nil {
		return true
	}
	for _, v := range []string{
		c.CertificateType, c.CertificateTypeVersion, c.CertificateNumber,
		c.CompanyName, c.CompanyAddress, c.CompanyCity, c.CompanyState, c.CompanyProvince,
		c.CompanyCountry, c.CompanyPostalCode, c.DateIssued, c.TestLaboratory,
		c.SupervisingTestEngineer, c.CertificateSignerName, c.ChecksumAlgorithm,
		c.SoftwareOperatingEnvironment, c.PICSURL, c.CloudProvider, c.CloudProviderVersion,
		c.TestCompletionDate, c.TestDescription, c.AdditionalTestComments, c.ContextID,
	} {
		if strings.TrimSpace(v) != "" {
			return false
		}
	}
	return len(c.Software) == 0 && len(c.OS) == 0 && len(c.ProductManufacturer) == 0 &&
		len(c.ProductModel) == 0 && len(c.HardwareManufacturer) == 0 && len(c.HardwareModel) == 0
}

// CertificateTypeOrDefault resolves which key table governs. When the operator
// did not state a certificate type it is inferred from the document being
// reported on, because a Summary CSV must carry one and inferring it from the
// suite in hand is a fact, not an invention.
func (c *SubmissionConfig) CertificateTypeOrDefault(doc string) string {
	if c != nil && c.CertificateType != "" {
		return c.CertificateType
	}
	if strings.Contains(strings.ToUpper(doc), "MODBUS") {
		return CertTypeModbus
	}
	return CertTypeCSIP
}

// IsCloud reports whether the certified software is declared cloud-hosted,
// which decides which keys must read "Not Applicable".
func (c *SubmissionConfig) IsCloud() bool {
	return strings.EqualFold(strings.TrimSpace(c.SoftwareOperatingEnvironment), "cloud")
}

// NotApplicable is the exact literal both documents require: two words, title
// case. It is a constant rather than a string literal at each use so a
// submission cannot end up with "N/A" in one row and "Not Applicable" in
// another.
const NotApplicable = "Not Applicable"
