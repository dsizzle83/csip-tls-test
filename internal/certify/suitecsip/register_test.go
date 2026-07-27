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
	if applicable != 51 {
		t.Errorf("the catalog holds %d applicable %s rows; this suite was written against 51", applicable, doc)
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
