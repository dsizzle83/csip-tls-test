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
//
// It no longer requires the converse. Since the profile scope moved back to the
// DER Client column on 2026-07-28 there are TWO kinds of inapplicable row and
// they must not be conflated: the six bound to the notApplicable stub, which is
// what this list is, and the twenty-two aggregator-only rows, which stay bound
// to their real checks and run as informative evidence. Requiring every
// inapplicable row to be on this list would have forced those twenty-two back
// onto the stub — deleting working evaluators to satisfy a bookkeeping rule.
// TestAggregatorRowsAreInapplicableButStillImplemented is the other half.
func TestInapplicableRegistrationsMatchTheCatalog(t *testing.T) {
	cat := loadCatalog(t)
	for _, id := range inapplicableUIDs {
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
	// 51 = the §4 DER Client column. The owner decision of 2026-07-28 certifies
	// this DUT against that column in the GFEMS posture, superseding an earlier
	// decision the same day to claim the DER AGGREGATOR CLIENT column; the 22
	// rows the aggregator column adds (AGG-001..012, CORE-018, CORE-019,
	// ERR-002, MAINT-001/003/004/005, UTIL-002/003/004) are informative and are
	// counted below, not here. Six rows are N/A for reasons no profile choice
	// touches: CORE-001/002/004 and UTIL-001 (2030.5-server rows), MAINT-002
	// (Annex A seq 32 makes it optional) and COMM-001 (optional for all device
	// types) — all six blank in every §4 column.
	if applicable != 51 {
		t.Errorf("the catalog holds %d applicable %s rows; this suite was written against 51", applicable, doc)
	}
}

// TestProfileScopeIsTheDERClientColumn is the guard on the scope itself: the
// applicable set must be §4's DER CLIENT column EXACTLY — not the DER
// Aggregator Client column it briefly tracked on 2026-07-28, and not somebody's
// memory of either.
//
// It is stated over profile_conformance — the catalog's machine-readable record
// of the printed matrix — rather than over a hand-written list, so a
// re-extraction that changed a matrix row would fail here rather than silently
// re-scoping the certification.
//
// The equality is two-directional and both directions have teeth. A DER Client
// row that went inapplicable would drop a REQUIRED test; an aggregator-only row
// that went applicable would put twenty-two rows the claim does not cover back
// inside it. The only admitted exception is a row §4 requires of NOBODY, which
// may be applicable if — and only if — its reason says OPTIONAL in as many
// words.
func TestProfileScopeIsTheDERClientColumn(t *testing.T) {
	cat := loadCatalog(t)
	// Three rows are applicable although §4 requires them of no profile:
	// BASIC-013 and BASIC-014 (blank in all three columns) and CORE-023 (added
	// by Annex A seq 33 and absent from the printed matrix entirely). They are
	// optional evidence this bench can produce and conformance is not gated on
	// them. Their treatment did not change with the profile, which is why they
	// are named here rather than derived.
	optional := map[string]bool{"BASIC-013": true, "BASIC-014": true, "CORE-023": true}

	var aggregatorOnly []string
	for _, c := range cat.Select(certify.Filter{Docs: []string{doc}}) {
		pc := c.ProfileConformance
		switch {
		case pc != nil && pc.DERClientRequired:
			// The claimed column. Required of this DUT, so it must apply.
			if !c.Applicable {
				t.Errorf("%s carries an X in the §4 DER Client column but the catalog marks it "+
					"inapplicable; the claimed profile requires it: %s", c.ID, c.ApplicabilityReason)
			}
			if c.DUTRole != certify.RoleCSIPClient {
				t.Errorf("%s is a DER Client row with dut_role %q, want %q", c.ID, c.DUTRole,
					certify.RoleCSIPClient)
			}
		case pc != nil && pc.DERAggregatorClientRequired:
			// Required of an aggregator and of nobody else: outside the claim.
			aggregatorOnly = append(aggregatorOnly, c.ID)
			if c.Applicable {
				t.Errorf("%s is required only of a DER AGGREGATOR CLIENT and the DUT is certified as a "+
					"DER Client (GFEMS); marking it applicable puts it back inside the claim: %s",
					c.ID, c.ApplicabilityReason)
			}
			// dut_role stays csip-client: the row is outside the CLAIM, not
			// outside the client SURFACE, and its check still drives 2030.5 as a
			// client. Demoting it to not-applicable would say the opposite of
			// what the registration does.
			if c.DUTRole != certify.RoleCSIPClient {
				t.Errorf("%s is an informative aggregator row with dut_role %q, want %q — it is excluded "+
					"from the claim, not from the client surface, and its check still runs",
					c.ID, c.DUTRole, certify.RoleCSIPClient)
			}
		case c.Applicable:
			// Required of nobody, yet applicable. Admitted only with the word.
			if !optional[c.ID] {
				t.Errorf("%s is applicable but §4 requires it of no profile, and it is not one of the "+
					"three rows recorded as optional evidence", c.ID)
				continue
			}
			if !strings.Contains(c.ApplicabilityReason, "OPTIONAL") {
				t.Errorf("%s is applicable-but-required-of-nobody; its applicability_reason must say "+
					"OPTIONAL in as many words so a reviewer cannot mistake it for a conformance gate: %s",
					c.ID, c.ApplicabilityReason)
			}
		}
	}
	if len(aggregatorOnly) != 22 {
		t.Errorf("§4 requires %d row(s) of a DER Aggregator Client that it does not require of a DER "+
			"Client (%v); the decision of 2026-07-28 was taken over 22", len(aggregatorOnly), aggregatorOnly)
	}

	// The nesting the claim rests on: no row is required of a DER Client without
	// also being required of a DER Aggregator Client. If that ever stopped being
	// true, "the narrower column costs nothing" would stop being true with it.
	for _, c := range cat.Select(certify.Filter{Docs: []string{doc}}) {
		pc := c.ProfileConformance
		if pc != nil && pc.DERClientRequired && !pc.DERAggregatorClientRequired {
			t.Errorf("%s is required of a DER Client but NOT of a DER Aggregator Client; the two columns "+
				"no longer nest, so the claim's superset argument no longer holds", c.ID)
		}
	}
}

// TestAggregatorRowsAreInapplicableButStillImplemented pins the posture the
// 2026-07-28 DER Client decision chose for the twenty-two rows it dropped:
// OUTSIDE the claim, INSIDE the run.
//
// Deleting them, or rebinding them to the not-applicable stub, would have been
// the cheap answer and the wrong one. Their criteria are real evaluators
// (criteria_agg.go), the bench builds the fixtures they were written against
// (`sim/server -fleet`, `-subscription`), and a check that runs is worth more
// than a check that was deleted — a negative verdict here is evidence about a
// capability this product does not claim, which is a thing a reader of a bundle
// may need and cannot get from an omission.
func TestAggregatorRowsAreInapplicableButStillImplemented(t *testing.T) {
	cat := loadCatalog(t)
	reg := certify.NewRegistry()
	Register(reg)

	stub := map[string]bool{}
	for _, id := range inapplicableUIDs {
		stub[id] = true
	}
	n := 0
	for _, c := range cat.Select(certify.Filter{Docs: []string{doc}}) {
		pc := c.ProfileConformance
		if pc == nil || pc.DERClientRequired || !pc.DERAggregatorClientRequired {
			continue
		}
		n++
		if stub[c.ID] {
			t.Errorf("%s is on the not-applicable stub list; it has a real check in aggregator.go and "+
				"dropping it from the claim is not a reason to stop running it", c.ID)
		}
		r, ok := reg.Lookup(c.UID)
		if !ok {
			t.Errorf("%s has no registration at all — it left the claim and the run together", c.ID)
			continue
		}
		if r.Suite != Suite {
			t.Errorf("%s is registered by suite %q", c.ID, r.Suite)
		}
		// The reason has to say so, because the bundle prints it and a reader
		// who sees "applicable: false" and nothing else will assume the row was
		// skipped.
		if !strings.Contains(c.ApplicabilityReason, "INFORMATIVE") {
			t.Errorf("%s is inapplicable-but-implemented; its applicability_reason must say so, or a "+
				"reader of the bundle will read its verdict as a conformance finding: %s",
				c.ID, c.ApplicabilityReason)
		}
	}
	if n != 22 {
		t.Errorf("found %d aggregator-only row(s), want 22", n)
	}
}

// TestAggregatorRowsSkipRatherThanFailWithoutTheFleet is the guard against the
// worst failure mode these rows could produce: reporting a BENCH gap as a DUT
// finding.
//
// Every aggregator row is written against the Figure-15 four-EndDevice topology
// and most need the Subscription/Notification function set. The bench can serve
// both, but only when asked (`sim/server -fleet`, `-subscription`); with neither
// lever on there is no fixture. A check that answered that with FAIL would look
// like diligence and be a false positive on every run; a check that answered
// with PASS would be certifying a test that never ran. The contract is SKIP,
// with the gap named — and it survives the rows leaving the certification
// claim, because an informative verdict that is wrong is still wrong.
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
		if c.Applicable {
			t.Fatalf("%s is applicable; this test is about the rows that run OUTSIDE the claim", id)
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
	// The fault-injecting row must come last among the rows that EXECUTE, which
	// since 2026-07-28 includes the twenty-two informative aggregator rows: they
	// left the claim, not the plan, so ERR-001 has to stay behind them too.
	if got := lastExecuted(first); got != "ERR-001" {
		t.Errorf("the last executing row is %s; ERR-001 is the only row that makes the shared server "+
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

// lastExecuted is the last id in the plan bound to a real check — every row
// except the six on the not-applicable stub list.
func lastExecuted(ids []string) string {
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
