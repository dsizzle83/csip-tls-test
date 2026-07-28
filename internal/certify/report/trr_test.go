package report

// trr_test.go proves the four things a Test Results Report assembler can get
// wrong in ways nobody notices until a laboratory reads the submission:
//
//	the CSV grows a key neither §3.1.1 table defines, or a verdict outside the
//	three-member enumeration;
//	a bench SKIP or WARN quietly becomes a PASS;
//	a Software Checksum appears that no evidence bundle supports;
//	a required key silently comes out blank.
//
// Each of those produces a document that parses. That is why they are tested
// here rather than left to the readiness report to notice.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"csip-tls-test/internal/evidence/bundle"
)

// fixedNow pins the one field a package legitimately varies between runs.
var fixedNow = time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC)

// operatorConfig is a configuration with every SUBMITTER-suppliable required
// key filled and every AUTHORITY key absent — the honest state of a self-test.
func operatorConfig() *SubmissionConfig {
	return &SubmissionConfig{
		CompanyName:       "Example Systems, Inc.",
		CompanyAddress:    "1 Example Way",
		CompanyCity:       "Boulder",
		CompanyState:      "CO",
		CompanyCountry:    "USA",
		CompanyPostalCode: "80301",
		Software: []SoftwareRecord{
			{Name: "mbapsd", Version: "0.9.0", Element: "mbaps"},
			{Name: "nbd", Version: "0.9.0", Element: "nb"},
		},
		OS:                           []OSRecord{{Name: "Linux", Version: "5.15"}},
		SoftwareOperatingEnvironment: EnvHardware,
		PICSURL:                      "https://example.invalid/pics.xlsx",
		HardwareManufacturer:         []string{"Digi International"},
		HardwareModel:                []string{"ConnectCore 6UL"},
		TestCompletionDate:           "07/28/2026",
		TestDescription:              "SunSpec Modbus Conformance Certification",
		PerCertificateType: map[string]CertTypeOverride{
			CertTypeCSIP: {TestDescription: "IEEE 2030.5 / CSIP conformance, direct DER client"},
		},
	}
}

// synthBundle is a bundle carrying one case per bench verdict, in both
// certificate types' documents.
func synthBundle() *bundle.Bundle {
	return &bundle.Bundle{
		Schema: bundle.SchemaVersion,
		Run: bundle.RunMeta{
			Tool: "csip-certify", ToolVersion: "deadbeef",
			DUT: bundle.DUT{Build: "mbaps:aaaa1111 nb:bbbb2222"},
		},
		Cases: []bundle.TestCaseResult{
			{ID: "ss-modbus-conf-v1.4::DEV-1", Verdict: bundle.Pass},
			{ID: "ss-modbus-conf-v1.4::DEV-2", Verdict: bundle.Fail},
			{ID: "ss-modbus-conf-v1.4::MOD-1", Verdict: bundle.Skip, Notes: "scoped out of this product"},
			{ID: "ss-modbus-conf-v1.4::MOD-2", Verdict: bundle.Skip, Notes: "no capture was taken"},
			{ID: "ss-modbus-conf-v1.4::MOD-3", Verdict: bundle.Warn, Notes: "asserted with a caveat"},
			{ID: "csip-conf-v1.3::COMM-002", Verdict: bundle.Pass},
			{ID: "csip-conf-v1.3::AGG-001", Verdict: bundle.Skip, Notes: "aggregator only"},
			// A row about the REPORT, which must never appear as a verdict.
			{ID: "ss-modbus-results-v1.2::RPT-KV-1", Verdict: bundle.Pass},
			// A document no Results Reporting specification governs.
			{ID: "some-other-doc-v9::XYZ-1", Verdict: bundle.Pass},
		},
	}
}

func synthSource() Source {
	return Source{
		Dir: "runs/synthetic", Bundle: synthBundle(),
		Applicability: CaseApplicability{
			"ss-modbus-conf-v1.4::MOD-1": "the DUT does not implement this optional model",
			"csip-conf-v1.3::AGG-001":    "the DUT is a direct DER client, not an aggregator client",
		},
	}
}

// ---------------------------------------------------------------------------
// The verdict mapping
// ---------------------------------------------------------------------------

// TestVerdictMappingCoversEveryBenchOutcome is the table the file comment of
// trr.go derives. It exists so that a future change to the mapping has to be a
// deliberate edit to a table a reviewer can read, not a one-line switch nobody
// notices.
func TestVerdictMappingCoversEveryBenchOutcome(t *testing.T) {
	na := CaseApplicability{"ss-modbus-conf-v1.4::INAPPLICABLE": "the DUT does not implement this role"}
	cases := []struct {
		name       string
		in         bundle.TestCaseResult
		wantRow    string // "" means no row
		wantKind   GapKind
		wantReason string
	}{
		{"pass", bundle.TestCaseResult{ID: "ss-modbus-conf-v1.4::A", Verdict: bundle.Pass}, "PASS", "", ""},
		{"fail", bundle.TestCaseResult{ID: "ss-modbus-conf-v1.4::B", Verdict: bundle.Fail}, "FAIL", "", ""},
		{
			"skip, catalog says inapplicable",
			bundle.TestCaseResult{ID: "ss-modbus-conf-v1.4::INAPPLICABLE", Verdict: bundle.Skip},
			"", "", "",
		},
		{
			"skip, evidence unavailable",
			bundle.TestCaseResult{ID: "ss-modbus-conf-v1.4::C", Verdict: bundle.Skip, Notes: "no capture"},
			"", GapEvidence, "no capture",
		},
		{
			"warn",
			bundle.TestCaseResult{ID: "ss-modbus-conf-v1.4::D", Verdict: bundle.Warn, Notes: "a caveat"},
			"", GapCaveat, "a caveat",
		},
		{
			"a document no Results Reporting specification governs",
			bundle.TestCaseResult{ID: "unknown-doc::E", Verdict: bundle.Pass},
			"", GapUnrouted, "",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			row, gap := MapVerdict(tc.in, na, "runs/x")
			switch {
			case tc.wantRow != "":
				if gap != nil {
					t.Fatalf("wanted a %s row, got a gap: %+v", tc.wantRow, gap)
				}
				if row.Verdict != tc.wantRow {
					t.Fatalf("verdict = %q, want %q", row.Verdict, tc.wantRow)
				}
			case tc.wantKind != "":
				if row != nil {
					t.Fatalf("wanted a gap, got row %+v", row)
				}
				if gap.Kind != tc.wantKind {
					t.Fatalf("gap kind = %q, want %q", gap.Kind, tc.wantKind)
				}
				if tc.wantReason != "" && !strings.Contains(gap.Reason, tc.wantReason) {
					t.Fatalf("gap reason %q does not carry %q", gap.Reason, tc.wantReason)
				}
			}
		})
	}

	// The one line that says something about the DEVICE: a catalog-inapplicable
	// SKIP is the only SKIP that earns a verdict, and it carries the reason.
	row, gap := MapVerdict(bundle.TestCaseResult{ID: "ss-modbus-conf-v1.4::INAPPLICABLE", Verdict: bundle.Skip}, na, "runs/x")
	if gap != nil || row == nil {
		t.Fatalf("a catalog-inapplicable SKIP produced a gap rather than a NOT SUPPORTED row: %+v", gap)
	}
	if row.Verdict != "NOT SUPPORTED" {
		t.Fatalf("verdict = %q, want NOT SUPPORTED", row.Verdict)
	}
	if !strings.Contains(row.Note, "does not implement this role") {
		t.Fatalf("the NOT SUPPORTED row does not carry the applicability reason: %q", row.Note)
	}
}

// TestNoBenchOutcomeCanBecomeAnUnsupportedPass is the inflation guard stated as
// a property rather than a table: whatever the input, a row that was not a
// bench PASS never comes out PASS.
func TestNoBenchOutcomeCanBecomeAnUnsupportedPass(t *testing.T) {
	for _, v := range []bundle.Verdict{bundle.Fail, bundle.Skip, bundle.Warn} {
		row, _ := MapVerdict(bundle.TestCaseResult{ID: "ss-modbus-conf-v1.4::X", Verdict: v}, nil, "")
		if row != nil && row.Verdict == "PASS" {
			t.Fatalf("bench %s became a reported PASS", v)
		}
	}
	// And without a catalog, nothing can claim the device lacks a feature.
	row, _ := MapVerdict(bundle.TestCaseResult{ID: "ss-modbus-conf-v1.4::X", Verdict: bundle.Skip}, nil, "")
	if row != nil {
		t.Fatalf("a SKIP with no catalog behind it produced a %q row", row.Verdict)
	}
}

// TestCollateRoutesEachDocumentAndRefusesADisagreement.
func TestCollateRoutesEachDocumentAndRefusesADisagreement(t *testing.T) {
	col, err := Collate([]Source{synthSource()})
	if err != nil {
		t.Fatalf("Collate: %v", err)
	}
	mod, csip := col[CertTypeModbus], col[CertTypeCSIP]
	if mod == nil || csip == nil {
		t.Fatalf("both certificate types should be present, got %v", col)
	}
	if got := len(mod.Verdicts); got != 3 { // DEV-1 PASS, DEV-2 FAIL, MOD-1 NOT SUPPORTED
		t.Errorf("SunSpec Modbus verdict rows = %d, want 3: %+v", got, mod.Verdicts)
	}
	for _, v := range mod.Verdicts {
		if v.ID == "RPT-KV-1" {
			t.Error("a row about the Test Results Report itself was reported as a device verdict")
		}
	}
	// The unrouted document contributes a gap, not a row and not silence.
	var unrouted bool
	for _, g := range append(mod.Gaps, csip.Gaps...) {
		if g.Kind == GapUnrouted {
			unrouted = true
		}
	}
	if !unrouted {
		t.Error("the case from an unrouted document vanished instead of being recorded as a gap")
	}

	// Two bundles disagreeing about one procedure is a refusal, not a tie-break.
	a := synthSource()
	b := synthSource()
	b.Dir = "runs/other"
	b.Bundle.Cases[0].Verdict = bundle.Fail
	if _, err := Collate([]Source{a, b}); err == nil {
		t.Fatal("two bundles disagreeing about DEV-1 produced a report anyway")
	} else if !strings.Contains(err.Error(), "DEV-1") {
		t.Fatalf("the refusal does not name the disagreeing procedure: %v", err)
	}
}

// ---------------------------------------------------------------------------
// The CSV key set
// ---------------------------------------------------------------------------

// TestEmittedCSVCarriesOnlyDocumentedKeys walks the emitted document exactly as
// a reviewer at SunSpec would: parse the file, look up every key in the §3.1.1
// table, and check every verdict against the three-member enumeration. Nothing
// consults the model that produced it.
func TestEmittedCSVCarriesOnlyDocumentedKeys(t *testing.T) {
	dir := t.TempDir()
	trr := mustTRR(t, dir)

	for _, part := range trr.Parts {
		path, data, err := ReadEmittedSummary(dir, part.CertType)
		if err != nil {
			t.Fatalf("%s: %v", part.CertType, err)
		}
		parsed, err := ParseSummary(data)
		if err != nil {
			t.Fatalf("%s does not re-parse: %v", path, err)
		}
		table := KeyTable(part.CertType)
		if findings := parsed.ValidateAgainst(table); len(findings) > 0 {
			t.Fatalf("%s: %d finding(s) against the §3.1.1 key table:\n  %s",
				path, len(findings), strings.Join(findings, "\n  "))
		}
		verdicts := 0
		for _, r := range parsed.Rows {
			if !IsVerdictKey(table, r.Key) {
				continue
			}
			verdicts++
			if !validVerdict(r.Value) {
				t.Errorf("%s: %s = %q, outside PASS | FAIL | NOT SUPPORTED", path, r.Key, r.Value)
			}
		}
		if verdicts == 0 {
			t.Errorf("%s carries no `Test <Test ID>` row at all", path)
		}
	}
}

// TestSelfTestDeclarationTravelsWithTheDocument. The absent laboratory keys are
// the most consequential thing about a self-test report, and the CSV is the
// half that gets posted publicly — so the declaration has to be IN it, not only
// in a README beside it.
func TestSelfTestDeclarationTravelsWithTheDocument(t *testing.T) {
	dir := t.TempDir()
	trr := mustTRR(t, dir)
	for _, part := range trr.Parts {
		_, data, err := ReadEmittedSummary(dir, part.CertType)
		if err != nil {
			t.Fatal(err)
		}
		parsed, _ := ParseSummary(data)
		row, ok := parsed.Lookup("Additional Test Comments")
		if !ok {
			t.Fatalf("%s carries no Additional Test Comments", part.CertType)
		}
		if !strings.Contains(row.Value, "SELF-TEST") {
			t.Errorf("%s: the comments do not carry the SELF-TEST declaration: %q", part.CertType, row.Value)
		}
		// And the laboratory keys are ABSENT, not blank: an empty value would be
		// a value outside the Appendix A1 enumeration.
		for _, key := range []string{"Test Laboratory", "Certificate Number", "Supervising Test Engineer"} {
			if r, present := parsed.Lookup(key); present {
				t.Errorf("%s: %s was emitted as %q; an unsupplied authority key must not be written at all",
					part.CertType, key, r.Value)
			}
		}
	}
}

// TestPerCertificateTypeValuesDoNotLeakAcross. SunSpec issues one certificate
// per type; putting the Modbus Test Description on the CSIP report would be a
// false statement, not a formatting slip.
func TestPerCertificateTypeValuesDoNotLeakAcross(t *testing.T) {
	dir := t.TempDir()
	mustTRR(t, dir)
	want := map[string]string{
		CertTypeModbus: "SunSpec Modbus Conformance Certification",
		CertTypeCSIP:   "IEEE 2030.5 / CSIP conformance, direct DER client",
	}
	for certType, description := range want {
		_, data, err := ReadEmittedSummary(dir, certType)
		if err != nil {
			t.Fatal(err)
		}
		parsed, _ := ParseSummary(data)
		if r, _ := parsed.Lookup("Test Description"); r.Value != description {
			t.Errorf("%s: Test Description = %q, want %q", certType, r.Value, description)
		}
		if r, _ := parsed.Lookup("Certificate Type"); r.Value != certType {
			t.Errorf("%s: Certificate Type = %q, want %q", certType, r.Value, certType)
		}
	}
}

// ---------------------------------------------------------------------------
// Refusals
// ---------------------------------------------------------------------------

// TestMissingOperatorKeysAreARefusalNamingAllOfThem.
func TestMissingOperatorKeysAreARefusalNamingAllOfThem(t *testing.T) {
	cfg := operatorConfig()
	cfg.CompanyName = ""
	cfg.PICSURL = ""
	_, err := GenerateTRR(TRROptions{
		Dir: t.TempDir(), Sources: []Source{synthSource()}, Config: cfg,
		Now: fixedNow, AllowAuthorityGaps: true,
	})
	if err == nil {
		t.Fatal("a package was written with no Company Name and no PICS URL")
	}
	for _, want := range []string{"Company Name", "Protocol Implementation Conformance Statement"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not name %q: %v", want, err)
		}
	}
}

// TestAuthorityKeysAreNotAnOperatorErrorButAreStillRefusedByDefault.
func TestAuthorityKeysAreNotAnOperatorErrorButAreStillRefusedByDefault(t *testing.T) {
	_, err := GenerateTRR(TRROptions{
		Dir: t.TempDir(), Sources: []Source{synthSource()}, Config: operatorConfig(), Now: fixedNow,
	})
	if err == nil {
		t.Fatal("a package was written despite the absent laboratory and certificate keys")
	}
	for _, want := range []string{"Test Laboratory", "Certificate Number", "AllowAuthorityGaps"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not mention %q: %v", want, err)
		}
	}
	// With the gaps accepted, the summary's NAME says so.
	dir := t.TempDir()
	trr := mustTRR(t, dir)
	for _, part := range trr.Parts {
		if base := filepath.Base(part.Submission.SummaryPath); base != IncompleteFile {
			t.Errorf("%s: summary written as %s, want %s", part.CertType, base, IncompleteFile)
		}
	}
}

// ---------------------------------------------------------------------------
// Software Checksum autofill
// ---------------------------------------------------------------------------

func TestChecksumAutofillFromTheBundlesBuildStamp(t *testing.T) {
	cfg := operatorConfig()
	cfg.Software = append(cfg.Software, SoftwareRecord{Name: "typed", Version: "1", Checksum: "0BADCAFE", Element: "mbaps"})
	cfg.Software = append(cfg.Software, SoftwareRecord{Name: "unknown", Version: "1", Element: "no-such-element"})

	fill, err := FillChecksums(cfg, []Source{synthSource()})
	if err != nil {
		t.Fatalf("FillChecksums: %v", err)
	}
	if cfg.Software[0].Checksum != "aaaa1111" || cfg.Software[1].Checksum != "bbbb2222" {
		t.Errorf("autofill did not use the bundle's build stamp: %+v", cfg.Software[:2])
	}
	if cfg.Software[2].Checksum != "0BADCAFE" {
		t.Error("autofill overwrote a checksum the operator supplied")
	}
	if len(fill.Unresolved) != 1 || !strings.Contains(fill.Unresolved[0], "no-such-element") {
		t.Errorf("an element no bundle records was not reported: %+v", fill.Unresolved)
	}
	if !strings.Contains(cfg.ChecksumAlgorithm, "SHA-256") {
		t.Errorf("the algorithm behind a derived checksum was not stated: %q", cfg.ChecksumAlgorithm)
	}
}

// TestChecksumRefusesTwoBuilds is §2.1 as code: one image behind every reported
// result, or no report.
func TestChecksumRefusesTwoBuilds(t *testing.T) {
	a := synthSource()
	b := synthSource()
	b.Dir = "runs/other"
	b.Bundle.Run.DUT.Build = "mbaps:99999999 nb:bbbb2222"
	_, err := FillChecksums(operatorConfig(), []Source{a, b})
	if err == nil {
		t.Fatal("two bundles built against different images produced one Software Checksum")
	}
	if !strings.Contains(err.Error(), "mbaps") || !strings.Contains(err.Error(), "2.1") {
		t.Errorf("the refusal does not name the element or the clause: %v", err)
	}
}

func TestParseBuildStampIgnoresWhatItCannotRead(t *testing.T) {
	got := ParseBuildStamp("mbaps:856bc322 garbage nb:ba8d13dd :empty trailing:")
	want := map[string]string{"mbaps": "856bc322", "nb": "ba8d13dd"}
	if len(got) != len(want) {
		t.Fatalf("ParseBuildStamp = %v, want %v", got, want)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %q, want %q", k, got[k], v)
		}
	}
}

// ---------------------------------------------------------------------------
// The §4 JSON shapes
// ---------------------------------------------------------------------------

// TestModbusLogEntryShapeMatchesTheDocumentedElementList checks the emitted
// JSON object key sets against §4.1.2's own tables, which list:
//
//	time, type, msg, ipaddr, ipport   (the Log Entry Object)
//	time, type, msg                   (a message entry)
//	time, type, ipaddr, ipport        (a conn entry)
//	time, type                        (the disc entry of the §4.1.2 example)
func TestModbusLogEntryShapeMatchesTheDocumentedElementList(t *testing.T) {
	logs := &ModbusTestLogs{Logs: []ModbusTestLog{{
		Tests: []string{"MB-1"},
		Entries: []ModbusLogEntry{
			{Time: 1539663163.977, Type: EntryConn, IPAddr: "192.168.0.10", IPPort: 502},
			{Time: 1539663164.152, Type: EntryReq, Msg: "00000000000601039F880001"},
			{Time: 1539663164.347, Type: EntryResp, Msg: "00000000000501030202C6"},
			{Time: 1539663169.214, Type: EntryDisc},
		},
	}}}
	data, err := logs.JSON()
	if err != nil {
		t.Fatal(err)
	}
	var raw struct {
		Logs []struct {
			Tests   []string                     `json:"tests"`
			Entries []map[string]json.RawMessage `json:"entries"`
			Extra   map[string]json.RawMessage   `json:"-"`
		} `json:"logs"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatal(err)
	}
	want := [][]string{
		{"time", "type", "ipaddr", "ipport"},
		{"time", "type", "msg"},
		{"time", "type", "msg"},
		{"time", "type"},
	}
	for i, e := range raw.Logs[0].Entries {
		assertKeySet(t, "entry "+string(rune('0'+i)), e, want[i])
	}
	// And the container has exactly the one element §4.1.3 lists — v1.2's
	// revision history records "Removed cid."
	assertTopLevel(t, data, []string{"logs"})
}

// TestCSIPMessageShapeMatchesTheDocumentedElementList checks §4.1.2's Message
// Object contents table (time, type, method, uri, vers, headers, body) plus the
// two fields the worked EXAMPLE requires on a response and the table omits
// (code, reason).
func TestCSIPMessageShapeMatchesTheDocumentedElementList(t *testing.T) {
	logs := &CSIPTestLogs{CID: "campaign-1", Logs: []CSIPTestLog{{
		Tests: []string{"CORE-003"},
		CID:   "campaign-1",
		Messages: []CSIPMessage{
			{
				Time: 1539663163.6476057, Type: MsgReq, Method: "GET", URI: "/sep2/dcap",
				Vers: "HTTP/1.1", Headers: map[string]string{"Accept": "application/sep+xml"}, Body: "",
			},
			{
				Time: 1539663163.9776247, Type: MsgResp, Vers: "HTTP/1.1", Code: "200", Reason: "OK\r\n",
				Headers: map[string]string{"Content-Length": "0"}, Body: "",
			},
		},
	}}}
	data, err := logs.JSON()
	if err != nil {
		t.Fatal(err)
	}
	var raw struct {
		Logs []struct {
			Messages []map[string]json.RawMessage `json:"messages"`
		} `json:"logs"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatal(err)
	}
	assertKeySet(t, "request", raw.Logs[0].Messages[0],
		[]string{"time", "type", "method", "uri", "vers", "headers", "body"})
	assertKeySet(t, "response", raw.Logs[0].Messages[1],
		[]string{"time", "type", "vers", "code", "reason", "headers", "body"})
	assertTopLevel(t, data, []string{"logs", "cid"})

	// §4.1.2: "the body is a string containing the body of the HTTP message …
	// empty string if no message body". Not null, not absent.
	if !strings.Contains(string(data), `"body": ""`) {
		t.Error("an empty body was not emitted as the empty string")
	}
	if !BodyHasNoJSONNull(data) {
		t.Error("a body was emitted as JSON null")
	}
}

func assertKeySet(t *testing.T, what string, got map[string]json.RawMessage, want []string) {
	t.Helper()
	set := map[string]bool{}
	for _, k := range want {
		set[k] = true
	}
	for k := range got {
		if !set[k] {
			t.Errorf("%s carries %q, which is not in the documented element list %v", what, k, want)
		}
	}
	for _, k := range want {
		if _, ok := got[k]; !ok {
			t.Errorf("%s is missing the documented element %q", what, k)
		}
	}
}

func assertTopLevel(t *testing.T, data []byte, want []string) {
	t.Helper()
	var top map[string]json.RawMessage
	if err := json.Unmarshal(data, &top); err != nil {
		t.Fatal(err)
	}
	assertKeySet(t, "the Test Logs Object", top, want)
}

// ---------------------------------------------------------------------------
// Determinism
// ---------------------------------------------------------------------------

// TestTRRIsDeterministic: the same evidence and the same configuration produce
// byte-identical documents, apart from the generation timestamp — which is an
// explicit input, not a clock reading, precisely so this can be asserted.
//
// It matters because a submission is signed, archived and compared. A package
// whose bytes moved between two runs over the same evidence would make any
// later "is this the report we sent?" question unanswerable.
func TestTRRIsDeterministic(t *testing.T) {
	first := t.TempDir()
	second := t.TempDir()
	mustTRR(t, first)
	mustTRR(t, second)

	walk := func(root string) map[string][]byte {
		out := map[string][]byte{}
		if err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() {
				return err
			}
			rel, _ := filepath.Rel(root, path)
			data, rerr := os.ReadFile(path)
			out[filepath.ToSlash(rel)] = data
			return rerr
		}); err != nil {
			t.Fatal(err)
		}
		return out
	}
	a, b := walk(first), walk(second)
	if len(a) != len(b) {
		t.Fatalf("two runs wrote different file sets: %d vs %d", len(a), len(b))
	}
	for name, want := range a {
		got, ok := b[name]
		if !ok {
			t.Errorf("%s is missing from the second package", name)
			continue
		}
		if string(want) != string(got) {
			t.Errorf("%s differs between two runs over the same evidence", name)
		}
	}

	// And the timestamp really is the only thing a different clock moves.
	third := t.TempDir()
	if _, err := GenerateTRR(trrOptions(third, fixedNow.Add(72*time.Hour))); err != nil {
		t.Fatal(err)
	}
	c := walk(third)
	same, different := 0, []string{}
	for name, want := range a {
		if string(want) == string(c[name]) {
			same++
			continue
		}
		different = append(different, name)
	}
	if same == 0 {
		t.Error("moving the clock changed every file; nothing is stable")
	}
	for _, name := range different {
		if strings.HasSuffix(name, ".csv") {
			t.Errorf("%s changed when only the generation timestamp moved", name)
		}
	}
}

func trrOptions(dir string, now time.Time) TRROptions {
	return TRROptions{
		Dir: dir, Sources: []Source{synthSource()}, Config: operatorConfig(),
		ModbusLogs: goodModbusLogs(), Now: now, Tool: Tool, ToolVersion: "test",
		AllowAuthorityGaps: true,
	}
}

func mustTRR(t *testing.T, dir string) *TRR {
	t.Helper()
	trr, err := GenerateTRR(trrOptions(dir, fixedNow))
	if err != nil {
		t.Fatalf("GenerateTRR: %v", err)
	}
	return trr
}

// TestGapsReachTheReadinessReport. An omission nobody can see is
// indistinguishable from a test that was never run, so the two places a
// reviewer looks — the package README and each part's readiness report — must
// both name it.
func TestGapsReachTheReadinessReport(t *testing.T) {
	dir := t.TempDir()
	mustTRR(t, dir)
	readiness, err := os.ReadFile(filepath.Join(dir, certTypeSlug(CertTypeModbus), ReadinessFile))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"MOD-2", "MOD-3", string(GapEvidence), string(GapCaveat)} {
		if !strings.Contains(string(readiness), want) {
			t.Errorf("the readiness report does not name %q", want)
		}
	}
	readme, err := os.ReadFile(filepath.Join(dir, TRRReadmeFile))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"NOT SUPPORTED", "MOD-2", "An omitted row is NOT a pass"} {
		if !strings.Contains(string(readme), want) {
			t.Errorf("the package README does not carry %q", want)
		}
	}
}
