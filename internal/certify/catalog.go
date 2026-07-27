package certify

// catalog.go is the typed view of the extracted test-case catalog.
//
// The catalog is DATA, not code: 282 records pulled out of the published
// SunSpec / CSIP conformance documents by a separate extraction pass, with the
// known extraction gaps written down beside it in CATALOG-CRITIQUE.md. It is
// this tool's specification. Two consequences shape everything below.
//
// First, the loader is STRICT. Unknown JSON fields are an error, not something
// to ignore, and so are an empty uid, a duplicate uid, and an unrecognised
// automatable/dut_role value. A catalog that grew a field we do not model is a
// catalog whose meaning we no longer fully represent, and the correct response
// is to stop and say so — not to run 282 test cases against a spec we half
// understand.
//
// Second, every load records the sha256 of the exact bytes read, and the runner
// copies the catalog file into the evidence bundle. A reader of a bundle can
// therefore answer "which version of the specification was this run measured
// against?" by hashing a file that is sitting in front of them, rather than by
// trusting a version string we typed.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// CatalogFile is the catalog's committed location, relative to the repository
// root. It is a derived artefact of published standards documents: safe to
// commit, no secrets.
const CatalogFile = "testdata/catalog/catalog.json"

// CatalogEnv names the environment variable that overrides catalog discovery,
// so a run can be pointed at a newer extraction without a rebuild.
const CatalogEnv = "CSIP_CATALOG"

// DUTRole is the role the device under test plays in a test case. It is the
// primary selector for "which suite owns this case": a csip-client case is
// driven by the 2030.5 suite, an mbaps-server case by the Secure Modbus suite,
// and so on.
type DUTRole string

// The roles present in the catalog.
const (
	RoleCSIPClient    DUTRole = "csip-client"
	RoleModbusServer  DUTRole = "modbus-server"
	RoleModbusClient  DUTRole = "modbus-client"
	RoleMBAPSServer   DUTRole = "mbaps-server"
	RoleMBAPSClient   DUTRole = "mbaps-client"
	RoleReporting     DUTRole = "reporting"
	RolePKI           DUTRole = "pki"
	RoleNotApplicable DUTRole = "not-applicable"
)

var knownRoles = map[DUTRole]bool{
	RoleCSIPClient: true, RoleModbusServer: true, RoleModbusClient: true,
	RoleMBAPSServer: true, RoleMBAPSClient: true, RoleReporting: true,
	RolePKI: true, RoleNotApplicable: true,
}

// Automatable is the extraction's judgement of how much of a procedure a bench
// can drive without a human.
type Automatable string

// The automation levels, weakest last.
const (
	// AutoFull — the whole procedure can be driven and asserted by this bench.
	AutoFull Automatable = "full"
	// AutoPartial — the bench can drive and assert part of it; the remainder
	// needs an operator, hardware, or a lab instrument.
	AutoPartial Automatable = "partial"
	// AutoManual — the procedure needs a human. A suite may still register a
	// check for it: recording the operator's observation with a timestamped
	// frame window is worth more than recording nothing.
	AutoManual Automatable = "manual"
)

var autoRank = map[Automatable]int{AutoManual: 0, AutoPartial: 1, AutoFull: 2}

// Rank orders automation levels: full > partial > manual.
func (a Automatable) Rank() int { return autoRank[a] }

// AtLeast reports whether a is at least as automatable as min. An empty min
// admits everything.
func (a Automatable) AtLeast(min Automatable) bool {
	if min == "" {
		return true
	}
	return a.Rank() >= min.Rank()
}

// ProfileConformance is the CSIP §4 applicability matrix row for a test case:
// which client/server profiles the case is required for.
type ProfileConformance struct {
	DERClientRequired           bool   `json:"der_client_required"`
	DERAggregatorClientRequired bool   `json:"der_aggregator_client_required"`
	ServerRequired              bool   `json:"server_required"`
	MatrixRowFor                string `json:"matrix_row_for"`
}

// Erratum is one published correction to a procedure. A check MUST honour the
// errata for the case it implements — running the uncorrected step and calling
// the result a conformance failure would be our bug, not the DUT's.
type Erratum struct {
	Seq              int      `json:"seq"`
	Description      string   `json:"description"`
	CorrectiveAction []string `json:"corrective_action"`
	ClientRelevant   bool     `json:"client_relevant"`
	ObservableImpact string   `json:"observable_impact"`
	// TestCase / AffectedTests scope the erratum when it does not apply to the
	// whole case it is filed under. An erratum with either set may belong to a
	// sibling test case, so a check should read them before applying it.
	TestCase      string   `json:"test_case,omitempty"`
	AffectedTests []string `json:"affected_tests,omitempty"`
}

// RequirementTrace links a test case to a numbered requirement in the source
// standard, which is what lets a bundle answer "which clause does this prove?".
type RequirementTrace struct {
	ReqID       string `json:"req_id"`
	SpecSection string `json:"spec_section"`
	Description string `json:"description"`
}

// Case is one extracted test case: the specification of one thing a suite must
// demonstrate.
//
// The field a check author should read first is Observables. It is the
// extraction's list of wire facts the procedure's pass criteria rest on, and it
// is the shopping list for the assertions the check has to mint. Expected is
// the procedure's own pass criteria in its own words; Observables is what those
// criteria look like on the wire.
type Case struct {
	// UID is globally unique across documents ("csip-conf-v1.3::AGG-001") and
	// is the key a suite registers against.
	UID string `json:"uid"`
	// ID is the identifier as printed in the source document ("AGG-001").
	// Unique within a document, NOT across documents.
	ID string `json:"id"`
	// Doc is the document key ("CSIP-CONF-v1.3"); DocVersion is the version as
	// the document itself states it.
	Doc        string `json:"doc"`
	DocVersion string `json:"doc_version"`
	Section    string `json:"section"`
	Title      string `json:"title"`
	Purpose    string `json:"purpose"`
	// AppliesTo is the procedure's own scoping: client, server, both, unknown.
	AppliesTo string `json:"applies_to"`
	// DUTRole is which of this bench's DUT surfaces the case exercises.
	DUTRole DUTRole `json:"dut_role"`
	// Applicable records whether the case applies to THIS product at all.
	// A false Applicable is not a licence to ignore the case: the runner still
	// emits a record for it, carrying ApplicabilityReason, so the bundle shows
	// the reader exactly what was excluded and why.
	Applicable          bool   `json:"applicable"`
	ApplicabilityReason string `json:"applicability_reason"`
	// Automatable is validated on load, so a check can switch on it without
	// worrying about a fourth spelling appearing.
	Automatable Automatable `json:"automatable"`

	// Evidence is the extraction's description of what evidence the case
	// requires. Treat it as the acceptance bar for the check's assertions.
	Evidence        string   `json:"evidence"`
	Preconditions   []string `json:"preconditions"`
	Steps           []string `json:"steps"`
	Expected        []string `json:"expected"`
	Observables     []string `json:"observables"`
	RequirementRefs []string `json:"requirement_refs"`
	Notes           string   `json:"notes"`

	ProfileConformance *ProfileConformance `json:"profile_conformance,omitempty"`
	CSIPRequirementIDs []string            `json:"csip_requirement_ids,omitempty"`
	Errata             []Erratum           `json:"errata,omitempty"`
	RequirementTrace   []RequirementTrace  `json:"requirement_trace,omitempty"`

	// SourceShards and PageBoundaryMerged are extraction provenance. A merged
	// page boundary is a hint that the text was reassembled across a PDF page
	// break and is worth re-reading against the source before trusting a
	// literal quotation of a step.
	SourceShards       []string `json:"source_shards"`
	PageBoundaryMerged bool     `json:"page_boundary_merged"`
}

// Ref is a short reference to the case, for logs and citations.
func (c *Case) Ref() string {
	if c.Doc == "" {
		return c.ID
	}
	return c.Doc + " " + c.ID
}

// WireObservable reports whether the extraction listed any wire observable for
// this case. A check for a case with no observables can honestly produce only
// SKIP or off-wire assertions, and the runner says so rather than letting an
// uncited PASS through.
func (c *Case) WireObservable() bool { return len(c.Observables) > 0 }

// DocInfo summarises one source document's presence in the catalog.
type DocInfo struct {
	Doc     string `json:"doc"`
	Version string `json:"version"`
	Cases   int    `json:"cases"`
	// Applicable is how many of them apply to this product.
	Applicable int `json:"applicable"`
}

// Catalog is a loaded, validated, indexed catalog.
type Catalog struct {
	cases   []Case
	byUID   map[string]int
	byDocID map[string]int
	docs    []DocInfo

	source string
	sha256 string
	size   int64
}

// CatalogRef is the catalog's identity, recorded in the evidence bundle so a
// reader can pin exactly which extraction a run was measured against.
type CatalogRef struct {
	Source string    `json:"source"`
	SHA256 string    `json:"sha256"`
	Bytes  int64     `json:"bytes"`
	Cases  int       `json:"cases"`
	Docs   []DocInfo `json:"docs"`
}

// String renders the reference for a one-line log or bundle note.
func (r CatalogRef) String() string {
	return fmt.Sprintf("%s (%d cases, %d bytes, sha256:%s)", r.Source, r.Cases, r.Bytes, r.SHA256)
}

// Load reads and validates a catalog from path.
func Load(path string) (*Catalog, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("certify: read catalog: %w", err)
	}
	c, err := LoadBytes(data, path)
	if err != nil {
		return nil, err
	}
	return c, nil
}

// LoadBytes validates an in-memory catalog. source is recorded verbatim as the
// bundle's provenance string, so pass a path when there is one.
func LoadBytes(data []byte, source string) (*Catalog, error) {
	dec := json.NewDecoder(strings.NewReader(string(data)))
	// Strict: an unmodelled field means the specification data grew a meaning
	// this code does not carry. See the file header.
	dec.DisallowUnknownFields()
	var raw []Case
	if err := dec.Decode(&raw); err != nil {
		return nil, fmt.Errorf("certify: parse catalog %s: %w", source, err)
	}
	if len(raw) == 0 {
		return nil, fmt.Errorf("certify: catalog %s contains no test cases", source)
	}

	sum := sha256.Sum256(data)
	cat := &Catalog{
		cases:   make([]Case, 0, len(raw)),
		byUID:   make(map[string]int, len(raw)),
		byDocID: make(map[string]int, len(raw)),
		source:  source,
		sha256:  hex.EncodeToString(sum[:]),
		size:    int64(len(data)),
	}
	docIndex := map[string]int{}
	for i, tc := range raw {
		if err := validateCase(&tc, i); err != nil {
			return nil, fmt.Errorf("certify: catalog %s: %w", source, err)
		}
		if prev, dup := cat.byUID[tc.UID]; dup {
			return nil, fmt.Errorf("certify: catalog %s: uid %q appears at records %d and %d",
				source, tc.UID, prev, i)
		}
		cat.byUID[tc.UID] = len(cat.cases)
		cat.byDocID[docIDKey(tc.Doc, tc.ID)] = len(cat.cases)
		cat.cases = append(cat.cases, tc)

		di, seen := docIndex[tc.Doc]
		if !seen {
			docIndex[tc.Doc] = len(cat.docs)
			cat.docs = append(cat.docs, DocInfo{Doc: tc.Doc, Version: tc.DocVersion})
			di = len(cat.docs) - 1
		}
		cat.docs[di].Cases++
		if tc.Applicable {
			cat.docs[di].Applicable++
		}
	}
	sort.Slice(cat.docs, func(i, j int) bool { return cat.docs[i].Doc < cat.docs[j].Doc })
	return cat, nil
}

func validateCase(tc *Case, i int) error {
	switch {
	case tc.UID == "":
		return fmt.Errorf("record %d has no uid", i)
	case tc.ID == "":
		return fmt.Errorf("record %d (%s) has no id", i, tc.UID)
	case tc.Doc == "":
		return fmt.Errorf("record %d (%s) has no doc", i, tc.UID)
	case !knownRoles[tc.DUTRole]:
		return fmt.Errorf("record %d (%s) has dut_role %q, which this loader does not model",
			i, tc.UID, tc.DUTRole)
	case autoRankKnown(tc.Automatable) == false:
		return fmt.Errorf("record %d (%s) has automatable %q, want full|partial|manual",
			i, tc.UID, tc.Automatable)
	}
	return nil
}

func autoRankKnown(a Automatable) bool {
	_, ok := autoRank[a]
	return ok
}

func docIDKey(doc, id string) string { return doc + "\x00" + id }

// DefaultCatalogPath finds the committed catalog: $CSIP_CATALOG if set,
// otherwise testdata/catalog/catalog.json in the nearest enclosing directory
// that has one. Walking up is what makes `go test ./internal/certify/` and a
// binary run from the repository root both find the same file.
func DefaultCatalogPath() (string, error) {
	if p := os.Getenv(CatalogEnv); p != "" {
		if _, err := os.Stat(p); err != nil {
			return "", fmt.Errorf("certify: %s=%s: %w", CatalogEnv, p, err)
		}
		return p, nil
	}
	dir, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("certify: locate catalog: %w", err)
	}
	for {
		cand := filepath.Join(dir, filepath.FromSlash(CatalogFile))
		if _, err := os.Stat(cand); err == nil {
			return cand, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("certify: no %s found in any parent of the working directory; "+
				"pass -catalog or set %s", CatalogFile, CatalogEnv)
		}
		dir = parent
	}
}

// LoadDefault loads the catalog from DefaultCatalogPath.
func LoadDefault() (*Catalog, error) {
	p, err := DefaultCatalogPath()
	if err != nil {
		return nil, err
	}
	return Load(p)
}

// Len is the number of test cases.
func (c *Catalog) Len() int { return len(c.cases) }

// All returns every case in catalog order (which is document order).
func (c *Catalog) All() []*Case {
	out := make([]*Case, len(c.cases))
	for i := range c.cases {
		out[i] = &c.cases[i]
	}
	return out
}

// ByUID looks a case up by its globally unique id.
func (c *Catalog) ByUID(uid string) (*Case, bool) {
	i, ok := c.byUID[uid]
	if !ok {
		return nil, false
	}
	return &c.cases[i], true
}

// ByID looks a case up by document and in-document id.
func (c *Catalog) ByID(doc, id string) (*Case, bool) {
	i, ok := c.byDocID[docIDKey(doc, id)]
	if !ok {
		return nil, false
	}
	return &c.cases[i], true
}

// Docs lists the source documents, sorted by key.
func (c *Catalog) Docs() []DocInfo { return append([]DocInfo(nil), c.docs...) }

// Doc reports whether the catalog contains a document with this key.
func (c *Catalog) Doc(doc string) (DocInfo, bool) {
	for _, d := range c.docs {
		if strings.EqualFold(d.Doc, doc) {
			return d, true
		}
	}
	return DocInfo{}, false
}

// Ref returns the catalog's bundle-recordable identity.
func (c *Catalog) Ref() CatalogRef {
	return CatalogRef{
		Source: c.source,
		SHA256: c.sha256,
		Bytes:  c.size,
		Cases:  len(c.cases),
		Docs:   c.Docs(),
	}
}

// Path returns the file the catalog was loaded from, if it was a file.
func (c *Catalog) Path() string { return c.source }

// Filter selects test cases. A zero Filter selects everything, which is the
// right default for a coverage report: the tool should always be able to say
// what it does NOT implement.
type Filter struct {
	// Docs restricts to these document keys (case-insensitive). Empty = all.
	Docs []string
	// UIDs restricts to these uids. A bare in-document id ("RBAC-004") is also
	// accepted and matches any document, because that is what an operator will
	// type; an ambiguous bare id matches every document that has it.
	UIDs []string
	// Roles restricts to these DUT roles. Empty = all.
	Roles []DUTRole
	// ApplicableOnly drops cases the extraction marked inapplicable to this
	// product. Off by default: the inapplicable ones and their reasons belong
	// in the coverage report.
	ApplicableOnly bool
	// MinAutomatable drops cases below this automation level. Empty = all.
	MinAutomatable Automatable
	// Match is an arbitrary extra predicate, ANDed with the rest.
	Match func(*Case) bool
}

// IsZero reports whether the filter selects everything.
func (f Filter) IsZero() bool {
	return len(f.Docs) == 0 && len(f.UIDs) == 0 && len(f.Roles) == 0 &&
		!f.ApplicableOnly && f.MinAutomatable == "" && f.Match == nil
}

// Matches applies the filter to one case.
func (f Filter) Matches(c *Case) bool {
	if len(f.Docs) > 0 && !containsFold(f.Docs, c.Doc) {
		return false
	}
	if len(f.UIDs) > 0 && !containsFold(f.UIDs, c.UID) && !containsFold(f.UIDs, c.ID) {
		return false
	}
	if len(f.Roles) > 0 {
		found := false
		for _, r := range f.Roles {
			if r == c.DUTRole {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	if f.ApplicableOnly && !c.Applicable {
		return false
	}
	if !c.Automatable.AtLeast(f.MinAutomatable) {
		return false
	}
	if f.Match != nil && !f.Match(c) {
		return false
	}
	return true
}

// Select returns the matching cases in catalog order.
func (c *Catalog) Select(f Filter) []*Case {
	var out []*Case
	for i := range c.cases {
		if f.Matches(&c.cases[i]) {
			out = append(out, &c.cases[i])
		}
	}
	return out
}

// Validate checks a filter against the catalog and reports selectors that match
// nothing. A typo in -doc or -uid must not silently run zero test cases and
// print a clean summary; that is the same failure mode as dropping a case.
func (c *Catalog) Validate(f Filter) error {
	var problems []string
	for _, d := range f.Docs {
		if _, ok := c.Doc(d); !ok {
			problems = append(problems, fmt.Sprintf("no document %q (have: %s)", d, strings.Join(c.docKeys(), ", ")))
		}
	}
	for _, u := range f.UIDs {
		if _, ok := c.ByUID(u); ok {
			continue
		}
		found := false
		for i := range c.cases {
			if strings.EqualFold(c.cases[i].ID, u) {
				found = true
				break
			}
		}
		if !found {
			problems = append(problems, fmt.Sprintf("no test case %q", u))
		}
	}
	if len(problems) > 0 {
		return errors.New("certify: catalog selection: " + strings.Join(problems, "; "))
	}
	return nil
}

func (c *Catalog) docKeys() []string {
	out := make([]string, len(c.docs))
	for i, d := range c.docs {
		out[i] = d.Doc
	}
	return out
}

func containsFold(ss []string, s string) bool {
	for _, v := range ss {
		if strings.EqualFold(v, s) {
			return true
		}
	}
	return false
}
