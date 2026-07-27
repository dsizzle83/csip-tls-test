package certify

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// testCatalog is a miniature catalog covering the shapes the loader has to
// handle: two documents, an inapplicable case with a reason, all three
// automation levels, and the optional blocks (errata, profile conformance,
// requirement trace).
const testCatalog = `[
 {"uid":"doc-a::A-001","id":"A-001","doc":"DOC-A","doc_version":"v1","section":"5.1",
  "title":"Server sends CertificateRequest","purpose":"p","applies_to":"server",
  "dut_role":"mbaps-server","applicable":true,"applicability_reason":"",
  "automatable":"full","evidence":"the CertificateRequest handshake message",
  "preconditions":["a"],"steps":["1. dial"],"expected":["a CertificateRequest"],
  "observables":["TLS CertificateRequest from the server"],"requirement_refs":["§5.1"],
  "notes":"","source_shards":["s1"],"page_boundary_merged":false},

 {"uid":"doc-a::A-002","id":"A-002","doc":"DOC-A","doc_version":"v1","section":"5.2",
  "title":"Role extension present","purpose":"p","applies_to":"client",
  "dut_role":"mbaps-client","applicable":true,"applicability_reason":"",
  "automatable":"partial","evidence":"the client certificate's role extension",
  "preconditions":[],"steps":[],"expected":[],"observables":["client Certificate message"],
  "requirement_refs":[],"notes":"","source_shards":["s1"],"page_boundary_merged":false,
  "errata":[{"seq":1,"description":"d","corrective_action":["c"],"client_relevant":true,
             "observable_impact":"i"}]},

 {"uid":"doc-a::A-003","id":"A-003","doc":"DOC-A","doc_version":"v1","section":"9",
  "title":"Aggregator subscription","purpose":"p","applies_to":"both",
  "dut_role":"not-applicable","applicable":false,
  "applicability_reason":"Aggregator-client profile test. The gateway registers one EndDevice.",
  "automatable":"manual","evidence":"n/a","preconditions":[],"steps":[],"expected":[],
  "observables":[],"requirement_refs":[],"notes":"","source_shards":["s2"],
  "page_boundary_merged":true,
  "profile_conformance":{"der_client_required":false,"der_aggregator_client_required":true,
                         "server_required":true,"matrix_row_for":"A-003"},
  "csip_requirement_ids":["BASE.013"]},

 {"uid":"doc-b::B-001","id":"B-001","doc":"DOC-B","doc_version":"v2","section":"1",
  "title":"Discovery","purpose":"p","applies_to":"client","dut_role":"csip-client",
  "applicable":true,"applicability_reason":"","automatable":"full",
  "evidence":"the GET /dcap exchange","preconditions":[],"steps":[],"expected":[],
  "observables":["HTTP GET /dcap -> 200"],"requirement_refs":[],"notes":"",
  "source_shards":["s3"],"page_boundary_merged":false,
  "requirement_trace":[{"req_id":"DER.038","spec_section":"B.1.21","description":"d"}]}
]`

func loadTestCatalog(t *testing.T) *Catalog {
	t.Helper()
	cat, err := LoadBytes([]byte(testCatalog), "testdata/mini.json")
	if err != nil {
		t.Fatalf("LoadBytes: %v", err)
	}
	return cat
}

func TestLoadBytesIndexesAndDigests(t *testing.T) {
	cat := loadTestCatalog(t)
	if cat.Len() != 4 {
		t.Fatalf("Len = %d, want 4", cat.Len())
	}
	c, ok := cat.ByUID("doc-a::A-002")
	if !ok {
		t.Fatal("ByUID missed A-002")
	}
	if c.Automatable != AutoPartial || c.DUTRole != RoleMBAPSClient {
		t.Errorf("A-002 = %s/%s", c.Automatable, c.DUTRole)
	}
	if len(c.Errata) != 1 || !c.Errata[0].ClientRelevant {
		t.Errorf("A-002 errata = %+v", c.Errata)
	}
	if _, ok := cat.ByID("DOC-B", "B-001"); !ok {
		t.Error("ByID missed DOC-B/B-001")
	}
	// Same in-document id in a different document must not collide.
	if _, ok := cat.ByID("DOC-A", "B-001"); ok {
		t.Error("ByID matched B-001 in the wrong document")
	}

	ref := cat.Ref()
	if len(ref.SHA256) != 64 {
		t.Errorf("catalog sha256 = %q", ref.SHA256)
	}
	if ref.Cases != 4 || len(ref.Docs) != 2 {
		t.Errorf("ref = %+v", ref)
	}
	// The digest is over the bytes, so it must be stable across loads.
	again, err := LoadBytes([]byte(testCatalog), "elsewhere")
	if err != nil {
		t.Fatal(err)
	}
	if again.Ref().SHA256 != ref.SHA256 {
		t.Error("the same bytes hashed differently")
	}

	docs := cat.Docs()
	if docs[0].Doc != "DOC-A" || docs[0].Cases != 3 || docs[0].Applicable != 2 {
		t.Errorf("DOC-A info = %+v", docs[0])
	}
}

// An unmodelled field means the specification data carries meaning this code
// does not. Refusing to load is the honest response.
func TestLoadRejectsUnknownFields(t *testing.T) {
	bad := strings.Replace(testCatalog, `"title":"Discovery"`,
		`"title":"Discovery","tolerance_band":"±2%"`, 1)
	if _, err := LoadBytes([]byte(bad), "x"); err == nil {
		t.Fatal("a catalog with an unmodelled field loaded silently")
	} else if !strings.Contains(err.Error(), "tolerance_band") {
		t.Errorf("error does not name the field: %v", err)
	}
}

func TestLoadRejectsBadRecords(t *testing.T) {
	tests := []struct {
		name string
		json string
		want string
	}{
		{"duplicate uid", strings.Replace(testCatalog, `"doc-b::B-001"`, `"doc-a::A-001"`, 1), "appears at records"},
		{"unknown role", strings.Replace(testCatalog, `"dut-role-none"`, `"x"`, 1) + "", ""},
		{"unknown automatable", strings.Replace(testCatalog, `"automatable":"partial"`, `"automatable":"maybe"`, 1), "want full|partial|manual"},
		{"empty", "[]", "no test cases"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := LoadBytes([]byte(tc.json), "x")
			if tc.want == "" {
				return
			}
			if err == nil {
				t.Fatalf("loaded without error")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error = %v, want it to mention %q", err, tc.want)
			}
		})
	}
}

func TestLoadRejectsUnknownDUTRole(t *testing.T) {
	bad := strings.Replace(testCatalog, `"dut_role":"csip-client"`, `"dut_role":"gremlin"`, 1)
	_, err := LoadBytes([]byte(bad), "x")
	if err == nil || !strings.Contains(err.Error(), "gremlin") {
		t.Fatalf("err = %v, want a complaint about the unmodelled role", err)
	}
}

func TestFilter(t *testing.T) {
	cat := loadTestCatalog(t)
	tests := []struct {
		name string
		f    Filter
		want []string
	}{
		{"everything", Filter{}, []string{"doc-a::A-001", "doc-a::A-002", "doc-a::A-003", "doc-b::B-001"}},
		{"by doc", Filter{Docs: []string{"doc-b"}}, []string{"doc-b::B-001"}},
		{"by uid", Filter{UIDs: []string{"doc-a::A-001"}}, []string{"doc-a::A-001"}},
		{"by bare id", Filter{UIDs: []string{"B-001"}}, []string{"doc-b::B-001"}},
		{"by role", Filter{Roles: []DUTRole{RoleCSIPClient}}, []string{"doc-b::B-001"}},
		{"applicable only", Filter{ApplicableOnly: true},
			[]string{"doc-a::A-001", "doc-a::A-002", "doc-b::B-001"}},
		{"fully automatable", Filter{MinAutomatable: AutoFull},
			[]string{"doc-a::A-001", "doc-b::B-001"}},
		{"at least partial", Filter{MinAutomatable: AutoPartial},
			[]string{"doc-a::A-001", "doc-a::A-002", "doc-b::B-001"}},
		{"predicate", Filter{Match: func(c *Case) bool { return c.Section == "5.2" }},
			[]string{"doc-a::A-002"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var got []string
			for _, c := range cat.Select(tc.f) {
				got = append(got, c.UID)
			}
			if strings.Join(got, ",") != strings.Join(tc.want, ",") {
				t.Errorf("got %v, want %v", got, tc.want)
			}
		})
	}
}

// A typo in -doc must not run zero test cases and print a clean summary.
func TestValidateCatchesSelectorTypos(t *testing.T) {
	cat := loadTestCatalog(t)
	if err := cat.Validate(Filter{Docs: []string{"DOC-Z"}}); err == nil {
		t.Error("an unknown document was accepted")
	}
	if err := cat.Validate(Filter{UIDs: []string{"A-999"}}); err == nil {
		t.Error("an unknown uid was accepted")
	}
	if err := cat.Validate(Filter{Docs: []string{"doc-a"}, UIDs: []string{"A-001"}}); err != nil {
		t.Errorf("a valid selection was rejected: %v", err)
	}
}

func TestDefaultCatalogPathHonoursTheEnvironment(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "cat.json")
	if err := os.WriteFile(p, []byte(testCatalog), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv(CatalogEnv, p)
	got, err := DefaultCatalogPath()
	if err != nil || got != p {
		t.Fatalf("DefaultCatalogPath = %q, %v; want %q", got, err, p)
	}
	t.Setenv(CatalogEnv, filepath.Join(dir, "missing.json"))
	if _, err := DefaultCatalogPath(); err == nil {
		t.Error("a nonexistent CSIP_CATALOG was accepted")
	}
}

// The committed catalog is this tool's specification: it must load, strictly,
// and it must be the one the runner will find by default.
func TestCommittedCatalogLoads(t *testing.T) {
	path, err := DefaultCatalogPath()
	if err != nil {
		t.Skipf("no committed catalog reachable from %s: %v", mustGetwd(t), err)
	}
	cat, err := Load(path)
	if err != nil {
		t.Fatalf("the committed catalog does not load: %v", err)
	}
	if cat.Len() < 200 {
		t.Errorf("committed catalog has %d cases, expected the full extraction", cat.Len())
	}
	t.Logf("catalog %s: %d cases, sha256 %s", path, cat.Len(), cat.Ref().SHA256)
	for _, d := range cat.Docs() {
		t.Logf("  %-28s %-8s %3d cases (%d applicable)", d.Doc, d.Version, d.Cases, d.Applicable)
	}
	// Every case must carry the fields a suite depends on.
	for _, c := range cat.All() {
		if c.Title == "" {
			t.Errorf("%s has no title", c.UID)
		}
		if c.Applicable && !c.WireObservable() && c.Automatable == AutoFull {
			t.Errorf("%s is applicable and fully automatable but lists no observable — "+
				"a check for it could not cite anything", c.UID)
		}
	}
}

func mustGetwd(t *testing.T) string {
	t.Helper()
	d, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	return d
}
