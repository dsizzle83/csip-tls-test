package report

// keys.go transcribes the §3.1.1 "Key/Value Pair Descriptions for Summary Test
// Results" tables of both specifications into data.
//
// It is data and not code because the two documents disagree with each other
// and, in three places, with themselves — and a generator that hard-coded one
// reading would quietly produce a non-conformant submission for the other
// certificate type. Every divergence the catalog's extraction recorded is
// carried here on the KeySpec that has it, so the readiness report can print
// the ambiguity next to the row it affects instead of burying it in a comment:
//
//   - `Software Operating Environment` is enumerated "Cloud" | "Hardware
//     Device" in §3.1.1 of both documents, and printed as "Device" in both
//     §3.1.2 examples. The normative table wins; the divergence is flagged.
//   - `Operating System Version` is specified as "X.X — major plus the FIRST
//     DIGIT of minor" and exemplified as "18.04". The generator emits the
//     operator's value verbatim and flags the contradiction.
//   - The Modbus §3.1.1 table prints the PRODUCT model key and the HARDWARE
//     model key with the same literal label, `Hardware Model <n>`. They collide
//     as CSV keys. The generator emits the hardware form only and records the
//     product model in Additional Test Comments, which is the sole free-text
//     key the format has.
//   - The CSIP document's Appendix A — the state, country, laboratory and test
//     description enumerations — is REFERENCED and ABSENT. Its enumerated keys
//     therefore carry EnumUnavailable, and validation asserts only that a value
//     is present and a String, saying why it cannot do more.
//
// The Modbus document's Appendix A IS present, so its laboratory and test
// description enumerations are closed sets and are enforced.

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

// ValueKind is how a key's value is validated.
type ValueKind string

// The value kinds the two §3.1.1 tables use.
const (
	// KindString — "all non-enumerated values are strings" (§3.1). Leading
	// zeros survive; 02123 is not 2123.
	KindString ValueKind = "String"
	// KindEnum — the value must be drawn from Enum, unless EnumUnavailable
	// says the source document does not print the enumeration.
	KindEnum ValueKind = "Enumerated"
	// KindDate — MM/DD/YYYY, zero padded, slash separated. Not ISO 8601.
	KindDate ValueKind = "Date"
	// KindURL — a String that must be a properly formed URL.
	KindURL ValueKind = "URL"
)

// KeySpec is one row of a §3.1.1 key table.
type KeySpec struct {
	// Label is the documented key label, exactly as the specification prints
	// it, without any repeat index. §3.1 requires keys to match it exactly.
	Label string
	Kind  ValueKind
	// Enum is the closed value set, when the source document prints one.
	Enum []string
	// EnumUnavailable says why an enumerated key cannot be checked against its
	// enumeration — always because the referenced Appendix A is not in the
	// document. A key carrying it is validated as a non-empty String and the
	// limitation is reported rather than hidden behind a PASS.
	EnumUnavailable string
	// Repeatable keys are emitted as `Label 1`, `Label 2`, … per §3.1.1's
	// "individual fields are distinguished by adding a number at the end of the
	// key label".
	Repeatable bool
	// Required marks a key a submittable report must carry. Not every key is:
	// Additional Test Comments may be empty, and the state/province pair is
	// satisfied by either half.
	Required bool
	// Section is the specification section that defines the key.
	Section string
	// UID is the catalog uid that specifies this key, so an assertion about the
	// key can name the test case it satisfies.
	UID string
	// Note carries the documented defect or ambiguity affecting this key.
	Note string
	// value extracts the key's value(s) from a configuration. Returning no
	// values means "the submitter did not supply this", which is a visible
	// omission, never a fabricated default.
	value func(*SubmissionConfig) []string
}

// Indexed returns the key label for the n-th (1-based) value of a repeatable
// key, and the plain label for a non-repeatable one.
func (k KeySpec) Indexed(n int) string {
	if !k.Repeatable {
		return k.Label
	}
	return fmt.Sprintf("%s %d", k.Label, n)
}

// Validate checks one value against the key's rule and returns the reason it
// fails, or "" when it holds.
func (k KeySpec) Validate(v string) string {
	if strings.TrimSpace(v) == "" {
		return "value is empty"
	}
	switch k.Kind {
	case KindDate:
		if !datePattern.MatchString(v) {
			return fmt.Sprintf("%q is not MM/DD/YYYY", v)
		}
	case KindURL:
		u, err := url.Parse(v)
		if err != nil || u.Scheme == "" || u.Host == "" {
			return fmt.Sprintf("%q is not a properly formed URL", v)
		}
	case KindEnum:
		if k.EnumUnavailable != "" || len(k.Enum) == 0 {
			return ""
		}
		if v == NotApplicable {
			return ""
		}
		for _, e := range k.Enum {
			if v == e {
				return ""
			}
		}
		return fmt.Sprintf("%q is not in the documented enumeration (%s)", v, strings.Join(k.Enum, " | "))
	}
	return ""
}

// datePattern is the MM/DD/YYYY the format requires: zero-padded two-digit
// month and day, four-digit year, slash separated. It deliberately does not
// accept 1/3/2019 — the specification prints 01/03/2019.
var datePattern = regexp.MustCompile(`^(0[1-9]|1[0-2])/(0[1-9]|[12][0-9]|3[01])/[0-9]{4}$`)

// Environment values from the §3.1.1 enumeration. The §3.1.2 examples of both
// documents print "Device" instead of EnvHardware; see the file comment.
const (
	EnvHardware = "Hardware Device"
	EnvCloud    = "Cloud"
)

// AuthorizedLabs is the Modbus document's Appendix A1 enumeration: the
// Nationally Recognized Test Labs authorized to run SunSpec Modbus conformance
// testing. It is a closed set, and an in-house bench is not in it — which is
// the whole point of carrying it: a self-run campaign can produce a well-formed
// TRR and still cannot legitimately populate this key.
var AuthorizedLabs = []string{
	"Bureau Veritas", "CERE", "CSA", "Intertek", "Intertek Canada", "Intertek China",
	"KOMERI", "SGS", "SGS China", "Taiwan Testing and Certification Center",
	"TÜV Rheinland", "TÜV SUD", "UL",
}

// ModbusTestDescriptions is the Appendix A2 enumeration of SunSpec Modbus
// certification offerings. Which one is named decides which Test <Test ID> rows
// the report must carry.
var ModbusTestDescriptions = []string{
	"SunSpec Modbus Conformance Certification",
	"SunSpec Modbus for IEEE 1547 Certification",
	"SunSpec Modbus for MESA Profile",
}

// TestVerdicts is the enumeration of the `Test <Test ID>` value: the only key
// in either table that carries an actual conformance result.
var TestVerdicts = []string{"PASS", "FAIL", "NOT SUPPORTED"}

// KeyTable returns the §3.1.1 table governing a certificate type.
func KeyTable(certType string) []KeySpec {
	if certType == CertTypeModbus {
		return modbusKeys()
	}
	return csipKeys()
}

// stateProvince derives the state/province pair. Both documents define two
// keys, each of which must read the literal "Not Applicable" when the other
// applies — so supplying one determines the other. That is a rule the
// specification states, not a value this tool invents.
func stateProvince(c *SubmissionConfig) (state, province string) {
	st, pv := strings.TrimSpace(c.CompanyState), strings.TrimSpace(c.CompanyProvince)
	switch {
	case st != "" && pv != "":
		return st, pv
	case st != "":
		return st, NotApplicable
	case pv != "":
		return NotApplicable, pv
	default:
		return "", ""
	}
}

// one wraps a single scalar as the zero-or-one value list the emitter wants:
// an empty string yields no row at all, which is how an unsupplied field stays
// visibly absent instead of appearing as an empty value.
func one(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	return []string{s}
}

// cloudOrNA implements §3.1.1's conditional: a hardware-hosted submission marks
// the Cloud keys "Not Applicable", and vice versa. Deriving it is not
// invention — the specification requires exactly this literal.
func cloudOrNA(c *SubmissionConfig, v string) []string {
	if !c.IsCloud() {
		return []string{NotApplicable}
	}
	return one(v)
}

func hardwareOrNA(c *SubmissionConfig, v []string) []string {
	if c.IsCloud() {
		return []string{NotApplicable}
	}
	return v
}

// csipKeys is the SS-CSIP-RESULTS-v1.1 §3.1.1 table.
func csipKeys() []KeySpec {
	const appendixAbsent = "the CSIP results document references an Appendix A for this enumeration " +
		"but does not contain one, so the token set cannot be validated from the source"
	return []KeySpec{
		{Label: "Certificate Type", Kind: KindEnum, Enum: CertificateTypes, Required: true,
			Section: "3.1.1", UID: uidCSIP("RPT-010"),
			value: func(c *SubmissionConfig) []string { return one(c.CertificateTypeOrDefault(DocCSIP)) }},
		{Label: "Certificate Type Version", Kind: KindString, Section: "3.1.2", UID: uidCSIP("RPT-040"),
			Note:  "used by the §3.1.2 example (value 2019) and defined nowhere in the document",
			value: func(c *SubmissionConfig) []string { return one(c.CertificateTypeVersion) }},
		{Label: "Certificate Number", Kind: KindString, Required: true, Section: "3.1.1", UID: uidCSIP("RPT-011"),
			Note:  "assigned by SunSpec; a testing tool cannot synthesise one",
			value: func(c *SubmissionConfig) []string { return one(c.CertificateNumber) }},
		{Label: "Company Name", Kind: KindString, Required: true, Section: "3.1.1", UID: uidCSIP("RPT-012"),
			value: func(c *SubmissionConfig) []string { return one(c.CompanyName) }},
		{Label: "Company Address", Kind: KindString, Required: true, Section: "3.1.1", UID: uidCSIP("RPT-013"),
			value: func(c *SubmissionConfig) []string { return one(c.CompanyAddress) }},
		{Label: "Company City", Kind: KindString, Required: true, Section: "3.1.1", UID: uidCSIP("RPT-014"),
			Note:  "the document's Description cell for this row erroneously repeats Company Name's text",
			value: func(c *SubmissionConfig) []string { return one(c.CompanyCity) }},
		{Label: "Company State", Kind: KindEnum, EnumUnavailable: appendixAbsent, Section: "3.1.1", UID: uidCSIP("RPT-015"),
			Note: "the §3.1.2 example instead emits a combined `Company State/Province` key",
			value: func(c *SubmissionConfig) []string {
				if c.CombineStateProvince {
					return nil
				}
				st, _ := stateProvince(c)
				return one(st)
			}},
		{Label: "Company Province", Kind: KindString, Section: "3.1.1", UID: uidCSIP("RPT-016"),
			value: func(c *SubmissionConfig) []string {
				if c.CombineStateProvince {
					return nil
				}
				_, pv := stateProvince(c)
				return one(pv)
			}},
		{Label: "Company State/Province", Kind: KindString, Section: "3.1.2", UID: uidCSIP("RPT-040"),
			Note: "the §3.1.2 example's combined key; not defined in §3.1.1",
			value: func(c *SubmissionConfig) []string {
				if !c.CombineStateProvince {
					return nil
				}
				st, pv := stateProvince(c)
				if st != "" && st != NotApplicable {
					return one(st)
				}
				return one(pv)
			}},
		{Label: "Company Country", Kind: KindEnum, EnumUnavailable: appendixAbsent, Required: true,
			Section: "3.1.1", UID: uidCSIP("RPT-017"),
			value: func(c *SubmissionConfig) []string { return one(c.CompanyCountry) }},
		{Label: "Company Postal Code", Kind: KindString, Required: true, Section: "3.1.1", UID: uidCSIP("RPT-018"),
			Note:  "a String: 02123 must not be normalised to 2123",
			value: func(c *SubmissionConfig) []string { return one(c.CompanyPostalCode) }},
		{Label: "Date Issued", Kind: KindDate, Required: true, Section: "3.1.1", UID: uidCSIP("RPT-019"),
			value: func(c *SubmissionConfig) []string { return one(c.DateIssued) }},
		{Label: "Test Laboratory", Kind: KindEnum, EnumUnavailable: appendixAbsent, Required: true,
			Section: "3.1.1", UID: uidCSIP("RPT-020"),
			Note:  "a SunSpec Authorized Test Laboratory; vendor self-testing is not expressible in this key",
			value: func(c *SubmissionConfig) []string { return one(c.TestLaboratory) }},
		{Label: "Supervising Test Engineer", Kind: KindString, Required: true, Section: "3.1.1", UID: uidCSIP("RPT-021"),
			value: func(c *SubmissionConfig) []string { return one(c.SupervisingTestEngineer) }},
		{Label: "Certificate Signer Name", Kind: KindString, Required: true, Section: "3.1.1", UID: uidCSIP("RPT-022"),
			Note:  "a SunSpec Alliance person; filled in post-submission, not by the testing tool",
			value: func(c *SubmissionConfig) []string { return one(c.CertificateSignerName) }},
		{Label: "Software Name", Kind: KindString, Repeatable: true, Required: true,
			Section: "3.1.1", UID: uidCSIP("RPT-023"),
			value: func(c *SubmissionConfig) []string { return softwareField(c, "name") }},
		{Label: "Software Version", Kind: KindString, Repeatable: true, Required: true,
			Section: "3.1.1", UID: uidCSIP("RPT-024"),
			value: func(c *SubmissionConfig) []string { return softwareField(c, "version") }},
		{Label: "Software Checksum", Kind: KindString, Repeatable: true, Required: true,
			Section: "3.1.1", UID: uidCSIP("RPT-025"),
			Note:  "the checksum ALGORITHM is unspecified by the format; it is stated in Additional Test Comments",
			value: func(c *SubmissionConfig) []string { return softwareField(c, "checksum") }},
		{Label: "Operating System", Kind: KindString, Repeatable: true, Required: true,
			Section: "3.1.1", UID: uidCSIP("RPT-026"),
			value: func(c *SubmissionConfig) []string { return osField(c, "name") }},
		{Label: "Operating System Version", Kind: KindString, Repeatable: true, Required: true,
			Section: "3.1.1", UID: uidCSIP("RPT-027"),
			Note:  `documented as "X.X" (major plus the first minor digit) but exemplified as 18.04`,
			value: func(c *SubmissionConfig) []string { return osField(c, "version") }},
		{Label: "Software Operating Environment", Kind: KindEnum, Enum: []string{EnvCloud, EnvHardware},
			Required: true, Section: "3.1.1", UID: uidCSIP("RPT-028"),
			Note:  `§3.1.1 enumerates "Cloud" | "Hardware Device"; the §3.1.2 example prints "Device"`,
			value: func(c *SubmissionConfig) []string { return one(c.SoftwareOperatingEnvironment) }},
		{Label: "Protocol Implementation Conformance Statement", Kind: KindURL, Required: true,
			Section: "3.1.1", UID: uidCSIP("RPT-029"),
			value: func(c *SubmissionConfig) []string { return one(c.PICSURL) }},
		{Label: "Cloud Provider", Kind: KindString, Required: true, Section: "3.1.1", UID: uidCSIP("RPT-030"),
			value: func(c *SubmissionConfig) []string { return cloudOrNA(c, c.CloudProvider) }},
		{Label: "Cloud Provider Version", Kind: KindString, Required: true, Section: "3.1.1", UID: uidCSIP("RPT-031"),
			value: func(c *SubmissionConfig) []string { return cloudOrNA(c, c.CloudProviderVersion) }},
		{Label: "Product Manufacturer", Kind: KindString, Repeatable: true, Section: "3.1.1", UID: uidCSIP("RPT-032"),
			Note:  "absent from the §3.1.2 example, which emits only the Hardware keys",
			value: func(c *SubmissionConfig) []string { return hardwareOrNA(c, c.ProductManufacturer) }},
		{Label: "Product Model", Kind: KindString, Repeatable: true, Section: "3.1.1", UID: uidCSIP("RPT-033"),
			Note: "the §3.1.1 table prints this key's label as `Hardware Model <n (Prod Model)>`, colliding " +
				"with the hardware-model key; emitted under the unambiguous label and flagged",
			value: func(c *SubmissionConfig) []string { return hardwareOrNA(c, c.ProductModel) }},
		{Label: "Hardware Manufacturer", Kind: KindString, Repeatable: true, Required: true,
			Section: "3.1.1", UID: uidCSIP("RPT-034"),
			value: func(c *SubmissionConfig) []string { return hardwareOrNA(c, c.HardwareManufacturer) }},
		{Label: "Hardware Model", Kind: KindString, Repeatable: true, Required: true,
			Section: "3.1.1", UID: uidCSIP("RPT-035"),
			value: func(c *SubmissionConfig) []string { return hardwareOrNA(c, c.HardwareModel) }},
		{Label: "Test Completion Date", Kind: KindDate, Required: true, Section: "3.1.1", UID: uidCSIP("RPT-036"),
			value: func(c *SubmissionConfig) []string { return one(c.TestCompletionDate) }},
		{Label: "Test Description", Kind: KindEnum, EnumUnavailable: appendixAbsent, Required: true,
			Section: "3.1.1", UID: uidCSIP("RPT-037"),
			value: func(c *SubmissionConfig) []string { return one(c.TestDescription) }},
		{Label: "Additional Test Comments", Kind: KindString, Section: "3.1.1", UID: uidCSIP("RPT-038"),
			value: func(c *SubmissionConfig) []string { return one(c.AdditionalTestComments) }},
	}
}

// modbusKeys is the SS-MODBUS-RESULTS-v1.2 §3.1.1 table. It differs from the
// CSIP table in three ways that matter: its Appendix A IS present (so the
// laboratory and test-description enumerations are enforced), it defines a
// Product Manufacturer but no separate Product Model label, and its Company
// State key is enumerated with an enumeration the document never prints.
func modbusKeys() []KeySpec {
	const stateEnumAbsent = "the state enumeration is not printed anywhere in the Modbus results document"
	const countryEnumAbsent = "the country enumeration is not printed anywhere in the Modbus results document; " +
		"the example uses USA, which is not ISO 3166"
	return []KeySpec{
		{Label: "Certificate Type", Kind: KindEnum, Enum: CertificateTypes, Required: true,
			Section: "3.1.1", UID: uidModbus("RPT-KV-1"),
			value: func(c *SubmissionConfig) []string { return one(c.CertificateTypeOrDefault(DocModbus)) }},
		{Label: "Certificate Type Version", Kind: KindString, Section: "3.1.2", UID: uidModbus("RPT-TRR-3"),
			Note:  "used by the §3.1.2 example (value 2021) and defined nowhere in the document",
			value: func(c *SubmissionConfig) []string { return one(c.CertificateTypeVersion) }},
		{Label: "Certificate Number", Kind: KindString, Required: true, Section: "3.1.1", UID: uidModbus("RPT-KV-2"),
			Note:  "assigned by SunSpec; may be blank at generation time and filled in later",
			value: func(c *SubmissionConfig) []string { return one(c.CertificateNumber) }},
		{Label: "Company Name", Kind: KindString, Required: true, Section: "3.1.1", UID: uidModbus("RPT-KV-3"),
			value: func(c *SubmissionConfig) []string { return one(c.CompanyName) }},
		{Label: "Company Address", Kind: KindString, Required: true, Section: "3.1.1", UID: uidModbus("RPT-KV-4"),
			value: func(c *SubmissionConfig) []string { return one(c.CompanyAddress) }},
		{Label: "Company City", Kind: KindString, Required: true, Section: "3.1.1", UID: uidModbus("RPT-KV-5"),
			value: func(c *SubmissionConfig) []string { return one(c.CompanyCity) }},
		{Label: "Company State", Kind: KindEnum, EnumUnavailable: stateEnumAbsent,
			Section: "3.1.1", UID: uidModbus("RPT-KV-6"),
			value: func(c *SubmissionConfig) []string {
				if c.CombineStateProvince {
					return nil
				}
				st, _ := stateProvince(c)
				return one(st)
			}},
		{Label: "Company Province", Kind: KindString, Section: "3.1.1", UID: uidModbus("RPT-KV-7"),
			Note: "the document does not say whether State and Province are mutually exclusive",
			value: func(c *SubmissionConfig) []string {
				if c.CombineStateProvince {
					return nil
				}
				_, pv := stateProvince(c)
				return one(pv)
			}},
		{Label: "Company State/Province", Kind: KindString, Section: "3.1.2", UID: uidModbus("RPT-TRR-3"),
			Note: "the §3.1.2 example's combined key; not defined in §3.1.1",
			value: func(c *SubmissionConfig) []string {
				if !c.CombineStateProvince {
					return nil
				}
				st, pv := stateProvince(c)
				if st != "" && st != NotApplicable {
					return one(st)
				}
				return one(pv)
			}},
		{Label: "Company Country", Kind: KindEnum, EnumUnavailable: countryEnumAbsent, Required: true,
			Section: "3.1.1", UID: uidModbus("RPT-KV-8"),
			value: func(c *SubmissionConfig) []string { return one(c.CompanyCountry) }},
		{Label: "Company Postal Code", Kind: KindString, Required: true, Section: "3.1.1", UID: uidModbus("RPT-KV-9"),
			Note:  "a String: leading zeros are significant and a spreadsheet round-trip would corrupt them",
			value: func(c *SubmissionConfig) []string { return one(c.CompanyPostalCode) }},
		{Label: "Date Issued", Kind: KindDate, Required: true, Section: "3.1.1", UID: uidModbus("RPT-KV-10"),
			value: func(c *SubmissionConfig) []string { return one(c.DateIssued) }},
		{Label: "Test Laboratory", Kind: KindEnum, Enum: AuthorizedLabs, Required: true,
			Section: "3.1.1", UID: uidModbus("RPT-KV-11"),
			Note:  "Appendix A1 is a closed set; an in-house bench run cannot legitimately populate this key",
			value: func(c *SubmissionConfig) []string { return one(c.TestLaboratory) }},
		{Label: "Supervising Test Engineer", Kind: KindString, Required: true,
			Section: "3.1.1", UID: uidModbus("RPT-KV-12"),
			value: func(c *SubmissionConfig) []string { return one(c.SupervisingTestEngineer) }},
		{Label: "Certificate Signer Name", Kind: KindString, Required: true,
			Section: "3.1.1", UID: uidModbus("RPT-KV-13"),
			value: func(c *SubmissionConfig) []string { return one(c.CertificateSignerName) }},
		{Label: "Software Name", Kind: KindString, Repeatable: true, Required: true,
			Section: "3.1.1", UID: uidModbus("RPT-KV-14"),
			value: func(c *SubmissionConfig) []string { return softwareField(c, "name") }},
		{Label: "Software Version", Kind: KindString, Repeatable: true, Required: true,
			Section: "3.1.1", UID: uidModbus("RPT-KV-15"),
			value: func(c *SubmissionConfig) []string { return softwareField(c, "version") }},
		{Label: "Software Checksum", Kind: KindString, Repeatable: true, Required: true,
			Section: "3.1.1", UID: uidModbus("RPT-KV-16"),
			Note:  "the checksum ALGORITHM is unspecified by the format; it is stated in Additional Test Comments",
			value: func(c *SubmissionConfig) []string { return softwareField(c, "checksum") }},
		{Label: "Operating System", Kind: KindString, Repeatable: true, Required: true,
			Section: "3.1.1", UID: uidModbus("RPT-KV-17"),
			value: func(c *SubmissionConfig) []string { return osField(c, "name") }},
		{Label: "Operating System Version", Kind: KindString, Repeatable: true, Required: true,
			Section: "3.1.1", UID: uidModbus("RPT-KV-18"),
			Note:  `documented as "X.X" (major plus the first minor digit) but exemplified as 18.04`,
			value: func(c *SubmissionConfig) []string { return osField(c, "version") }},
		{Label: "Software Operating Environment", Kind: KindEnum, Enum: []string{EnvCloud, EnvHardware},
			Required: true, Section: "3.1.1", UID: uidModbus("RPT-KV-19"),
			Note:  `§3.1.1 enumerates "Cloud" | "Hardware Device"; the §3.1.2 example prints "Device"`,
			value: func(c *SubmissionConfig) []string { return one(c.SoftwareOperatingEnvironment) }},
		{Label: "Protocol Implementation Conformance Statement", Kind: KindURL, Required: true,
			Section: "3.1.1", UID: uidModbus("RPT-KV-20"),
			Note:  "the PICS is what justifies any NOT SUPPORTED verdict row",
			value: func(c *SubmissionConfig) []string { return one(c.PICSURL) }},
		{Label: "Cloud Provider", Kind: KindString, Required: true, Section: "3.1.1", UID: uidModbus("RPT-KV-21"),
			value: func(c *SubmissionConfig) []string { return cloudOrNA(c, c.CloudProvider) }},
		{Label: "Cloud Provider Version", Kind: KindString, Required: true,
			Section: "3.1.1", UID: uidModbus("RPT-KV-22"),
			value: func(c *SubmissionConfig) []string { return cloudOrNA(c, c.CloudProviderVersion) }},
		{Label: "Product Manufacturer", Kind: KindString, Repeatable: true,
			Section: "3.1.1", UID: uidModbus("RPT-KV-23"),
			value: func(c *SubmissionConfig) []string { return hardwareOrNA(c, c.ProductManufacturer) }},
		{Label: "Product Model", Kind: KindString, Repeatable: true,
			Section: "3.1.1", UID: uidModbus("RPT-KV-24"),
			Note: "the §3.1.1 table prints the PRODUCT model key as `Hardware Model <n (Prod Model)>`, " +
				"identical to the hardware-model key once the parenthetical is stripped; emitted under " +
				"the unambiguous label so the two do not collide as CSV keys",
			value: func(c *SubmissionConfig) []string { return hardwareOrNA(c, c.ProductModel) }},
		{Label: "Hardware Manufacturer", Kind: KindString, Repeatable: true, Required: true,
			Section: "3.1.1", UID: uidModbus("RPT-KV-25"),
			value: func(c *SubmissionConfig) []string { return hardwareOrNA(c, c.HardwareManufacturer) }},
		{Label: "Hardware Model", Kind: KindString, Repeatable: true, Required: true,
			Section: "3.1.1", UID: uidModbus("RPT-KV-26"),
			value: func(c *SubmissionConfig) []string { return hardwareOrNA(c, c.HardwareModel) }},
		{Label: "Test Completion Date", Kind: KindDate, Required: true,
			Section: "3.1.1", UID: uidModbus("RPT-KV-27"),
			value: func(c *SubmissionConfig) []string { return one(c.TestCompletionDate) }},
		{Label: "Test Description", Kind: KindEnum, Enum: ModbusTestDescriptions, Required: true,
			Section: "3.1.1", UID: uidModbus("RPT-KV-28"),
			value: func(c *SubmissionConfig) []string { return one(c.TestDescription) }},
		{Label: "Additional Test Comments", Kind: KindString, Section: "3.1.1", UID: uidModbus("RPT-KV-29"),
			Note:  "may be empty (the §3.1.2 example shows an empty value)",
			value: func(c *SubmissionConfig) []string { return one(c.AdditionalTestComments) }},
	}
}

func softwareField(c *SubmissionConfig, field string) []string {
	var out []string
	for _, s := range c.Software {
		switch field {
		case "name":
			out = append(out, s.Name)
		case "version":
			out = append(out, s.Version)
		case "checksum":
			out = append(out, s.Checksum)
		}
	}
	return trimTrailingEmpty(out)
}

func osField(c *SubmissionConfig, field string) []string {
	var out []string
	for _, o := range c.OS {
		switch field {
		case "name":
			out = append(out, o.Name)
		case "version":
			out = append(out, o.Version)
		}
	}
	return trimTrailingEmpty(out)
}

// trimTrailingEmpty drops trailing blanks so a half-filled record does not
// produce `Software Checksum 2,` — a row that claims a value exists. Interior
// blanks are KEPT, because dropping one would renumber the rows and break the
// index correspondence §3.1.1 requires between Software Name n and Software
// Version n.
func trimTrailingEmpty(v []string) []string {
	for len(v) > 0 && strings.TrimSpace(v[len(v)-1]) == "" {
		v = v[:len(v)-1]
	}
	return v
}

// FindKey returns the spec for a label in a table.
func FindKey(table []KeySpec, label string) (KeySpec, bool) {
	for _, k := range table {
		if k.Label == label {
			return k, true
		}
	}
	return KeySpec{}, false
}
