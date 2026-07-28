package suitecsip

// register_test.go proves the coverage claim this suite is judged on: every
// CSIP-CONF-v1.3 uid in the committed catalog has an implementation, and every
// uid this suite registers exists in the catalog.
//
// Both halves matter and they fail in opposite directions. A missing
// registration is a gap the coverage report names; an ORPHANED registration —
// a check bound to a uid the catalog does not have — makes the runner refuse to
// execute at all, and would take the other five suites down with it.

import (
	"context"
	"strings"
	"testing"

	"csip-tls-test/internal/certify"
)

const doc = "CSIP-CONF-v1.3"

func loadCatalog(t *testing.T) *certify.Catalog {
	t.Helper()
	path, err := certify.DefaultCatalogPath()
	if err != nil {
		t.Skipf("no committed catalog: %v", err)
	}
	cat, err := certify.Load(path)
	if err != nil {
		t.Fatalf("load catalog: %v", err)
	}
	return cat
}

func TestSuiteCoversTheWholeDocument(t *testing.T) {
	cat := loadCatalog(t)
	reg := certify.NewRegistry()
	Register(reg)

	cov := reg.Coverage(cat, certify.Filter{Docs: []string{doc}})
	if len(cov.Orphans) != 0 {
		t.Fatalf("this suite registers uids the catalog does not have: %v", cov.Orphans)
	}
	if len(cov.Docs) != 1 {
		t.Fatalf("coverage covers %d document(s), want 1", len(cov.Docs))
	}
	d := cov.Docs[0]
	if len(d.Unimplemented) != 0 {
		t.Errorf("%d applicable case(s) have no check: %v", len(d.Unimplemented), names(d.Unimplemented))
	}
	if len(d.Implemented) != d.Total {
		t.Errorf("implemented %d of %d case(s); the inapplicable rows must be registered too so the "+
			"coverage report explains them rather than omitting them", len(d.Implemented), d.Total)
	}
	if !d.Complete() {
		t.Error("the document is not reported complete")
	}
	t.Logf("%s: %d cases, %d applicable, %d implemented", d.Doc, d.Total, d.Applicable, len(d.Implemented))
}

func names(es []certify.CoverageEntry) []string {
	out := make([]string, 0, len(es))
	for _, e := range es {
		out = append(out, e.ID)
	}
	return out
}

// TestInapplicableRegistrationsMatchTheCatalog is the guard against the two
// ways the hand-written exclusion list can go wrong: claiming a row is
// inapplicable when the catalog says it applies (which would silently drop a
// required test) and listing a row the catalog does not have.
func TestInapplicableRegistrationsMatchTheCatalog(t *testing.T) {
	cat := loadCatalog(t)
	listed := map[string]bool{}
	for _, id := range inapplicableUIDs {
		listed[id] = true
		c, ok := cat.ByUID(uid(id))
		if !ok {
			t.Errorf("%s is on the inapplicable list but is not in the catalog", id)
			continue
		}
		if c.Applicable {
			t.Errorf("%s is registered as NOT APPLICABLE but the catalog marks it applicable to this DUT: %s",
				id, c.ApplicabilityReason)
		}
	}
	for _, c := range cat.Select(certify.Filter{Docs: []string{doc}}) {
		if !c.Applicable && !listed[c.ID] {
			t.Errorf("%s is inapplicable in the catalog but is not on this suite's inapplicable list, so it "+
				"is bound to a real check that will try to run it", c.ID)
		}
	}
}

// TestEveryApplicableRowHasARealCheck guards the opposite mistake: binding an
// applicable row to the not-applicable stub, which would report a required test
// as excluded.
func TestEveryApplicableRowHasARealCheck(t *testing.T) {
	cat := loadCatalog(t)
	reg := certify.NewRegistry()
	Register(reg)

	applicable := 0
	for _, c := range cat.Select(certify.Filter{Docs: []string{doc}}) {
		r, ok := reg.Lookup(c.UID)
		if !ok {
			t.Errorf("%s has no registration at all", c.ID)
			continue
		}
		if r.Suite != Suite {
			t.Errorf("%s is registered by suite %q", c.ID, r.Suite)
		}
		if !c.Applicable {
			continue
		}
		applicable++
		// Run the check against a context with no bench at all. An applicable
		// row's check must return a Result (a SKIP saying what was missing) and
		// never an error, because "the test could not be carried out" is what
		// the runner records as a FAIL — and a run with no bench configured
		// should report missing prerequisites, not twenty-three failures.
		rc := &certify.RunCtx{
			Case: c, Suite: Suite, Targets: certify.Targets{},
			GridSim: certify.NewAdminClient("", nil), Log: certify.DiscardLogger,
		}
		res, err := r.Check(context.Background(), rc)
		if err != nil {
			t.Errorf("%s: check errored with no bench configured: %v", c.ID, err)
			continue
		}
		if res.Verdict != certify.Skip {
			t.Errorf("%s: verdict with no bench configured = %s (%s), want SKIP",
				c.ID, res.Verdict, res.Notes)
		}
		if res.Notes == "" {
			t.Errorf("%s: SKIPped without saying why", c.ID)
		}
	}
	// 73 = the 51 rows the DER Client profile required, plus the 22 the DER
	// AGGREGATOR CLIENT profile adds (owner decision 2026-07-28: AGG-001..012,
	// CORE-018, CORE-019, ERR-002, MAINT-001/003/004/005, UTIL-002/003/004).
	// The six that remain N/A are CORE-001/002/004 and UTIL-001 (2030.5-server
	// rows), MAINT-002 (Annex A seq 32 makes it optional) and COMM-001
	// (optional for all device types) — all six blank in every §4 column.
	if applicable != 73 {
		t.Errorf("the catalog holds %d applicable %s rows; this suite was written against 73", applicable, doc)
	}
}

// TestProfileScopeIsTheAggregatorColumn is the guard on the re-scope itself:
// applicability must track §4's DER AGGREGATOR CLIENT column, not the DER
// Client column it used to track and not somebody's memory of either.
//
// It is stated over profile_conformance — the catalog's machine-readable record
// of the printed matrix — rather than over a hand-written list, so a
// re-extraction that changed a matrix row would fail here rather than silently
// re-scoping the certification.
func TestProfileScopeIsTheAggregatorColumn(t *testing.T) {
	cat := loadCatalog(t)
	// The rows §4 requires of a DER Aggregator Client but NOT of a DER Client:
	// these are exactly the rows the 2026-07-28 decision pulled in.
	var pulledIn []string
	for _, c := range cat.Select(certify.Filter{Docs: []string{doc}}) {
		pc := c.ProfileConformance
		if pc == nil || !pc.DERAggregatorClientRequired || pc.DERClientRequired {
			continue
		}
		pulledIn = append(pulledIn, c.ID)
		if !c.Applicable {
			t.Errorf("%s is required of a DER Aggregator Client by §4 but the catalog marks it "+
				"inapplicable; the 2026-07-28 re-scope requires it: %s", c.ID, c.ApplicabilityReason)
		}
		if c.DUTRole != certify.RoleCSIPClient {
			t.Errorf("%s is an applicable aggregator-client row with dut_role %q, want %q — the aggregator "+
				"IS a 2030.5 client toward the utility server", c.ID, c.DUTRole, certify.RoleCSIPClient)
		}
	}
	if len(pulledIn) != 22 {
		t.Errorf("§4 requires %d row(s) of a DER Aggregator Client that it does not require of a DER "+
			"Client (%v); the decision of 2026-07-28 was taken over 22", len(pulledIn), pulledIn)
	}

	// And the converse: nothing may be applicable that §4 requires of nobody
	// UNLESS its reason says so in as many words. Three rows are legitimately in
	// that position — BASIC-013, BASIC-014 and CORE-023 are optional evidence
	// this bench can produce — and they are the only ones.
	optional := map[string]bool{"BASIC-013": true, "BASIC-014": true, "CORE-023": true}
	for _, c := range cat.Select(certify.Filter{Docs: []string{doc}, ApplicableOnly: true}) {
		pc := c.ProfileConformance
		required := pc != nil && (pc.DERClientRequired || pc.DERAggregatorClientRequired || pc.ServerRequired)
		if required {
			continue
		}
		if !optional[c.ID] {
			t.Errorf("%s is applicable but §4 requires it of no profile, and it is not one of the three "+
				"rows recorded as optional evidence", c.ID)
			continue
		}
		if !strings.Contains(c.ApplicabilityReason, "OPTIONAL") {
			t.Errorf("%s is applicable-but-required-of-nobody; its applicability_reason must say OPTIONAL "+
				"in as many words so a reviewer cannot mistake it for a conformance gate: %s",
				c.ID, c.ApplicabilityReason)
		}
	}
}

// TestAggregatorRowsSkipRatherThanFailWithoutTheFleet is the guard against the
// worst failure mode this re-scope could produce: reporting a BENCH gap as a
// DUT finding.
//
// Every aggregator row is written against the Figure-15 four-EndDevice topology
// and most need the Subscription/Notification function set. sim/gridsim has
// neither. A check that answered that with FAIL would look like diligence and
// be a false positive on every run; a check that answered with PASS would be
// certifying a test that never ran. The contract is SKIP, with the gap named.
func TestAggregatorRowsSkipRatherThanFailWithoutTheFleet(t *testing.T) {
	cat := loadCatalog(t)
	reg := certify.NewRegistry()
	Register(reg)

	for _, id := range []string{
		"AGG-001", "AGG-002", "AGG-003", "AGG-007", "AGG-009", "AGG-010", "AGG-012",
		"CORE-018", "CORE-019", "ERR-002",
		"MAINT-001", "MAINT-003", "MAINT-004", "MAINT-005",
		"UTIL-002", "UTIL-003", "UTIL-004",
	} {
		c, ok := cat.ByID(doc, id)
		if !ok {
			t.Fatalf("the catalog has no %s %s", doc, id)
		}
		r, ok := reg.Lookup(c.UID)
		if !ok {
			t.Fatalf("%s has no registration", id)
		}
		if !c.Applicable {
			t.Fatalf("%s is not applicable; this test is about the rows the re-scope made real", id)
		}
		rc := &certify.RunCtx{
			Case: c, Suite: Suite, Targets: certify.Targets{},
			GridSim: certify.NewAdminClient("", nil), Log: certify.DiscardLogger,
		}
		res, err := r.Check(context.Background(), rc)
		if err != nil {
			t.Errorf("%s: check errored with no bench: %v", id, err)
			continue
		}
		if res.Verdict != certify.Skip {
			t.Errorf("%s: verdict with no bench = %s, want SKIP — a missing bench is never a DUT finding",
				id, res.Verdict)
		}
		// notApplicable is the OTHER thing that returns SKIP here, and binding an
		// applicable row to it would report a required test as excluded.
		if strings.Contains(res.Notes, "NOT APPLICABLE") {
			t.Errorf("%s is applicable but is bound to the not-applicable stub: %s", id, res.Notes)
		}
	}
}

// TestRegistrationOrderIsDeterministic proves the run sequence is stable, which
// is what lets a reviewer diff two bundles and see a behaviour change rather
// than a scheduling change.
func TestRegistrationOrderIsDeterministic(t *testing.T) {
	cat := loadCatalog(t)
	reg := certify.NewRegistry()
	Register(reg)
	run, err := certify.New(reg, cat, plannerOptions())
	if err != nil {
		t.Fatal(err)
	}
	first := planIDs(run.Plan())

	reg2 := certify.NewRegistry()
	Register(reg2)
	run2, err := certify.New(reg2, cat, plannerOptions())
	if err != nil {
		t.Fatal(err)
	}
	second := planIDs(run2.Plan())

	if len(first) != len(second) {
		t.Fatalf("two plans of the same selection differ in length: %d vs %d", len(first), len(second))
	}
	for i := range first {
		if first[i] != second[i] {
			t.Fatalf("plan position %d differs between runs: %s vs %s", i, first[i], second[i])
		}
	}
	if len(first) == 0 {
		t.Fatal("the plan is empty")
	}
	// The transport rows must come first: if the TLS profile is wrong, nothing
	// after it means anything.
	if first[0] != "COMM-002" {
		t.Errorf("the plan starts with %s; the transport rows should lead", first[0])
	}
	// The fault-injecting row must come last among the applicable rows.
	if got := lastApplicable(first); got != "ERR-001" {
		t.Errorf("the last applicable row is %s; ERR-001 is the only row that makes the shared server "+
			"misbehave and should run last", got)
	}
}

func plannerOptions() certify.Options {
	o := certify.DefaultOptions()
	o.Docs = []string{doc}
	o.DryRun = true
	o.NoCapture = true
	return o
}

func planIDs(ps []certify.Planned) []string {
	out := make([]string, 0, len(ps))
	for _, p := range ps {
		out = append(out, p.Case.ID)
	}
	return out
}

func lastApplicable(ids []string) string {
	skip := map[string]bool{}
	for _, id := range inapplicableUIDs {
		skip[id] = true
	}
	last := ""
	for _, id := range ids {
		if !skip[id] {
			last = id
		}
	}
	return last
}
