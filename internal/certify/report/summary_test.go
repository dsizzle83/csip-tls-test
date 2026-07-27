package report

import (
	"strings"
	"testing"
)

func fullConfig() *SubmissionConfig {
	return &SubmissionConfig{
		CertificateType:              CertTypeModbus,
		CertificateNumber:            "ICS183884882",
		CompanyName:                  "Acme, Incorporated",
		CompanyAddress:               "569 Regents Park Avenue, Suite 4",
		CompanyCity:                  "Boston",
		CompanyState:                 "MA",
		CompanyCountry:               "USA",
		CompanyPostalCode:            "02123",
		DateIssued:                   "01/12/2019",
		TestLaboratory:               "UL",
		SupervisingTestEngineer:      "Peter A Smith",
		CertificateSignerName:        "Daniela T Jones",
		Software:                     []SoftwareRecord{{Name: "lexa-gw.bin", Version: "1.4.2", Checksum: "423EC0E4"}},
		OS:                           []OSRecord{{Name: "meta-lexa", Version: "5.0"}},
		ChecksumAlgorithm:            "SHA-256, truncated to 8 hex digits",
		SoftwareOperatingEnvironment: EnvHardware,
		PICSURL:                      "https://pics.sunspec.org/lexa-gw.xlsx",
		HardwareManufacturer:         []string{"Digi International"},
		HardwareModel:                []string{"ConnectCore 93"},
		TestCompletionDate:           "07/26/2026",
		TestDescription:              "SunSpec Modbus Conformance Certification",
	}
}

func TestSummaryCompleteConfigLeavesNothingMissing(t *testing.T) {
	sum := BuildSummary(fullConfig(), CertTypeModbus, []TestVerdict{{ID: "MB-1", Verdict: "PASS"}})
	if !sum.Complete() {
		t.Fatalf("missing %v; problems %v", sum.MissingKeys(), sum.Problems)
	}
}

// TestSummaryQuotesCSVSignificantValues is §3.1's last encoding rule, and the
// one an emitter is most likely to get wrong.
func TestSummaryQuotesCSVSignificantValues(t *testing.T) {
	sum := BuildSummary(fullConfig(), CertTypeModbus, nil)
	data, err := sum.CSV()
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	if !strings.Contains(text, `Company Name,"Acme, Incorporated"`) {
		t.Errorf("a value containing a comma was not quoted:\n%s", text)
	}
	if !strings.HasSuffix(strings.SplitN(text, "\n", 2)[0], "\r") {
		t.Error("records are not CRLF-terminated")
	}
	parsed, err := ParseSummary(data)
	if err != nil {
		t.Fatal(err)
	}
	if row, _ := parsed.Lookup("Company Name"); row.Value != "Acme, Incorporated" {
		t.Errorf("the quoted value did not round-trip: %q", row.Value)
	}
	if row, _ := parsed.Lookup("Company Postal Code"); row.Value != "02123" {
		t.Errorf("postal code round-tripped as %q; leading zeros are significant", row.Value)
	}
}

func TestSummaryRepeatableKeysAreIndexed(t *testing.T) {
	cfg := fullConfig()
	cfg.Software = []SoftwareRecord{
		{Name: "a.bin", Version: "1", Checksum: "AA"},
		{Name: "b.bin", Version: "2", Checksum: "BB"},
	}
	sum := BuildSummary(cfg, CertTypeModbus, nil)
	for _, want := range []string{"Software Name 1", "Software Name 2", "Software Checksum 2"} {
		if _, ok := sum.Lookup(want); !ok {
			t.Errorf("no row for %q", want)
		}
	}
	if _, ok := sum.Lookup("Software Name"); ok {
		t.Error("a repeatable key was emitted without its index")
	}
}

// TestSummaryValidatesSuppliedValues proves the checker has teeth: a wrong
// value is a Problem, which is a FAIL, distinct from an absent one.
func TestSummaryValidatesSuppliedValues(t *testing.T) {
	cfg := fullConfig()
	cfg.DateIssued = "2019-01-12"                      // ISO 8601, not MM/DD/YYYY
	cfg.TestLaboratory = "Dmitri's Garage"             // not in Appendix A1
	cfg.PICSURL = "pics.sunspec.org/x.xlsx"            // no scheme
	cfg.SoftwareOperatingEnvironment = "Device"        // the example's token, not §3.1.1's
	cfg.TestDescription = "SunSpec Modbus Conformance" // truncated offering name

	sum := BuildSummary(cfg, CertTypeModbus, nil)
	if sum.Complete() {
		t.Fatal("a summary carrying five wrong values reported itself complete")
	}
	joined := strings.Join(sum.Problems, "\n")
	for _, want := range []string{"Date Issued", "Test Laboratory", "Protocol Implementation",
		"Software Operating Environment", "Test Description"} {
		if !strings.Contains(joined, want) {
			t.Errorf("no problem reported for %s:\n%s", want, joined)
		}
	}
}

// TestCSIPEnumerationsAreNotFalselyValidated: the CSIP document references an
// Appendix A it does not contain, so its enumerated keys must NOT be validated
// against a set we invented. A tool that rejected a real laboratory's name
// because it was not on a list we made up would be worse than one that checked
// nothing.
func TestCSIPEnumerationsAreNotFalselyValidated(t *testing.T) {
	cfg := fullConfig()
	cfg.CertificateType = CertTypeCSIP
	cfg.TestLaboratory = "Some Lab SunSpec Authorised After This Document Was Written"
	cfg.TestDescription = "Test performed in compliance with California Rule 21 Phase 2 and Phase 3."
	sum := BuildSummary(cfg, CertTypeCSIP, nil)
	for _, p := range sum.Problems {
		if strings.Contains(p, "Test Laboratory") || strings.Contains(p, "Test Description") {
			t.Errorf("validated against an enumeration the source document does not print: %s", p)
		}
	}
	joined := strings.Join(sum.Notes, "\n")
	if !strings.Contains(joined, "could not be validated") {
		t.Errorf("the limitation was not recorded:\n%s", joined)
	}

	// The Modbus document DOES print its Appendix A, so the same value must be
	// rejected there. The difference between the two documents is the point.
	cfg.CertificateType = CertTypeModbus
	sum = BuildSummary(cfg, CertTypeModbus, nil)
	if !strings.Contains(strings.Join(sum.Problems, "\n"), "Test Laboratory") {
		t.Error("the Modbus Appendix A1 enumeration was not enforced")
	}
}

func TestParseSummaryRejectsMalformedRecords(t *testing.T) {
	if _, err := ParseSummary([]byte("Key,Value,Extra\r\n")); err == nil {
		t.Error("a three-field record parsed; §3.1 requires exactly a key and a value")
	}
}

func TestValidateAgainstCatchesUndocumentedKeys(t *testing.T) {
	data := []byte("Certificate Type,SunSpec Modbus\r\nInvented Key,x\r\nDate Issued,13/40/2019\r\n" +
		"Test MB-1,MAYBE\r\nCompany City,Boston\r\nCompany City,Springfield\r\n")
	parsed, err := ParseSummary(data)
	if err != nil {
		t.Fatal(err)
	}
	findings := parsed.ValidateAgainst(KeyTable(CertTypeModbus))
	joined := strings.Join(findings, "\n")
	for _, want := range []string{"Invented Key", "Date Issued", "Test MB-1", "appears 2 times"} {
		if !strings.Contains(joined, want) {
			t.Errorf("no finding for %q:\n%s", want, joined)
		}
	}
}

func TestVerdictRowsUseTheDocumentedPrefix(t *testing.T) {
	sum := BuildSummary(fullConfig(), CertTypeModbus, []TestVerdict{
		{ID: "MOD-1.705", Verdict: "PASS"},
		{ID: "EXC-3", Verdict: "FAIL"},
		{ID: "CRV-1.705", Verdict: "NOT SUPPORTED"},
	})
	for _, want := range []string{"Test MOD-1.705", "Test EXC-3", "Test CRV-1.705"} {
		if _, ok := sum.Lookup(want); !ok {
			t.Errorf("no row keyed %q — §3.1.1's key is `Test <Test ID>`, always prefixed", want)
		}
	}
	if len(sum.Problems) != 0 {
		t.Errorf("problems: %v", sum.Problems)
	}
}

func TestVerdictOutsideEnumerationIsAProblem(t *testing.T) {
	sum := BuildSummary(fullConfig(), CertTypeModbus, []TestVerdict{{ID: "MB-1", Verdict: "SKIP"}})
	if len(sum.Problems) == 0 {
		t.Fatal("SKIP was accepted as a verdict; the enumeration has three members and SKIP is not one")
	}
}
