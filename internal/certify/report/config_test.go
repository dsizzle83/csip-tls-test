package report

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestConfigHasNoDefaults is the test this package exists to keep passing. An
// empty configuration must produce an empty Summary — not the specification's
// example values, not a plausible company, not a placeholder certificate
// number. Every one of those would be a forgery a lab could not detect.
func TestConfigHasNoDefaults(t *testing.T) {
	sum := BuildSummary(&SubmissionConfig{}, CertTypeCSIP, nil)
	for _, r := range sum.Rows {
		if r.Key == "Certificate Type" {
			continue // derived from the document, which is a fact, not an invention
		}
		if r.Key == "Cloud Provider" || r.Key == "Cloud Provider Version" {
			// §3.1.1 REQUIRES the literal "Not Applicable" for a device-hosted
			// submission; emitting it is following the spec, not inventing.
			if r.Value != NotApplicable {
				t.Errorf("%s = %q, want the spec-mandated %q", r.Key, r.Value, NotApplicable)
			}
			continue
		}
		t.Errorf("an unconfigured submission emitted %s,%s — nothing but the specification's own "+
			"mandated literals may appear without an operator supplying it", r.Key, r.Value)
	}
	if len(sum.Missing) == 0 {
		t.Fatal("an unconfigured submission reported nothing missing")
	}
	if sum.Complete() {
		t.Fatal("an unconfigured submission reported itself complete")
	}
}

func TestLoadConfigJSONRejectsUnknownFields(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "submission.json")
	if err := os.WriteFile(path, []byte(`{"company_name":"X","compnay_city":"Y"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(path); err == nil {
		t.Fatal("a misspelled key loaded silently; the value it meant to supply would be missing " +
			"from the submission with no indication")
	}
}

func TestLoadConfigYAMLSubset(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "submission.yaml")
	src := `# a lab's submission metadata
certificate_type: SunSpec Modbus
company_name: "Acme, Incorporated"
company_postal_code: "02123"
test_laboratory: UL
software:
  - name: lexa-gw.bin
    version: "1.4.2"
    checksum: 423EC0E4
  - name: lexa-agent.bin
    version: "1.4.2"
    checksum: 9F21CC01
operating_systems:
  - name: meta-lexa
    version: "5.0"
hardware_model:
  - DERGate MB31-M-SC
`
	if err := os.WriteFile(path, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.CompanyName != "Acme, Incorporated" {
		t.Errorf("company_name = %q", cfg.CompanyName)
	}
	if cfg.CompanyPostalCode != "02123" {
		t.Errorf("postal code = %q; leading zeros must survive", cfg.CompanyPostalCode)
	}
	if len(cfg.Software) != 2 || cfg.Software[1].Checksum != "9F21CC01" {
		t.Fatalf("software = %+v", cfg.Software)
	}
	if len(cfg.OS) != 1 || cfg.OS[0].Version != "5.0" {
		t.Fatalf("operating systems = %+v", cfg.OS)
	}
	if len(cfg.HardwareModel) != 1 || cfg.HardwareModel[0] != "DERGate MB31-M-SC" {
		t.Fatalf("hardware model = %+v", cfg.HardwareModel)
	}
}

// TestYAMLSubsetRefusesRatherThanGuesses covers the reason the parser is small:
// a construct it does not fully understand must be an error, because a
// mis-parsed value becomes a wrong value on a certification submission.
func TestYAMLSubsetRefusesRatherThanGuesses(t *testing.T) {
	for name, src := range map[string]string{
		"tab indent":     "software:\n\t- name: x\n",
		"anchor":         "base: &anchor\ncompany_name: *anchor\n",
		"block scalar":   "company_address: |\n  line one\n  line two\n",
		"deep nesting":   "a:\n  - b:\n      c:\n        d: 1\n",
		"no colon":       "company_name\n",
		"mixed list":     "software:\n  - name: x\n  - plain\n",
		"orphan item":    "  - loose\n",
		"odd indent":     "software:\n   - name: x\n",
		"document start": "---\ncompany_name: x\n",
	} {
		if _, err := parseFlatYAML(src); err == nil {
			t.Errorf("%s: parsed without error; the parser must refuse what it cannot represent", name)
		}
	}
}

func TestApplyParamsRejectsUnknownKeys(t *testing.T) {
	cfg := &SubmissionConfig{}
	err := cfg.ApplyParams(map[string]string{
		"report.company_name": "Acme",
		"report.compnay_city": "Boston",
		"unrelated.param":     "ignored",
	})
	if err == nil {
		t.Fatal("a misspelled -param was accepted")
	}
	if !strings.Contains(err.Error(), "compnay_city") {
		t.Errorf("error does not name the offending key: %v", err)
	}
	if cfg.CompanyName != "Acme" {
		t.Errorf("the recognised parameter was not applied: %q", cfg.CompanyName)
	}
}

func TestApplyParamsAcceptsBothSpellings(t *testing.T) {
	cfg := &SubmissionConfig{}
	if err := cfg.ApplyParams(map[string]string{
		"report.company-name":   "Acme",
		"report.hardware-model": "A, B",
		"report.config":         "/ignored/path",
	}); err != nil {
		t.Fatal(err)
	}
	if cfg.CompanyName != "Acme" {
		t.Errorf("company name = %q", cfg.CompanyName)
	}
	if len(cfg.HardwareModel) != 2 {
		t.Errorf("hardware model = %+v", cfg.HardwareModel)
	}
}

func TestCloudAndHardwareKeysAreConditional(t *testing.T) {
	device := &SubmissionConfig{SoftwareOperatingEnvironment: EnvHardware,
		HardwareManufacturer: []string{"Digi"}, HardwareModel: []string{"CC93"}}
	sum := BuildSummary(device, CertTypeModbus, nil)
	for _, key := range []string{"Cloud Provider", "Cloud Provider Version"} {
		row, ok := sum.Lookup(key)
		if !ok || row.Value != NotApplicable {
			t.Errorf("%s = %q (present %t); a hardware-hosted submission must mark it %q",
				key, row.Value, ok, NotApplicable)
		}
	}

	cloud := &SubmissionConfig{SoftwareOperatingEnvironment: EnvCloud,
		CloudProvider: "AWS", CloudProviderVersion: "2026.1",
		HardwareManufacturer: []string{"ignored"}}
	sum = BuildSummary(cloud, CertTypeModbus, nil)
	if row, _ := sum.Lookup("Hardware Manufacturer 1"); row.Value != NotApplicable {
		t.Errorf("Hardware Manufacturer 1 = %q for a cloud submission", row.Value)
	}
	if row, _ := sum.Lookup("Cloud Provider"); row.Value != "AWS" {
		t.Errorf("Cloud Provider = %q", row.Value)
	}
}

// TestEmptyDistinguishesUnconfiguredFromFlagConfigured keeps the readiness
// report from telling a properly configured submitter that they supplied
// nothing.
func TestEmptyDistinguishesUnconfiguredFromFlagConfigured(t *testing.T) {
	if !(&SubmissionConfig{}).Empty() {
		t.Error("a zero configuration is not reported empty")
	}
	if (&SubmissionConfig{CompanyName: "Acme"}).Empty() {
		t.Error("a configuration with a company name is reported empty")
	}
	if (&SubmissionConfig{Software: []SoftwareRecord{{Name: "x"}}}).Empty() {
		t.Error("a configuration with a software record is reported empty")
	}
	if fullConfig().Empty() {
		t.Error("a complete configuration is reported empty")
	}
}
