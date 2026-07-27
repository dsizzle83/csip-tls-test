package suitessm

// suite_test.go audits the registration against the committed catalog.
//
// The coverage claim in this suite's report — "every applicable SSM-CONF-v0.8
// case is addressed" — is exactly the kind of claim that rots silently: a
// catalog revision adds a procedure, nobody notices, and the run keeps printing
// a clean summary about a smaller document than the one it names. These tests
// make that impossible to miss.

import (
	"sort"
	"strings"
	"testing"

	"csip-tls-test/internal/certify"
)

const doc = "SSM-CONF-v0.8"

func loadCatalog(t *testing.T) *certify.Catalog {
	t.Helper()
	path, err := certify.DefaultCatalogPath()
	if err != nil {
		t.Skipf("no committed catalog to audit against: %v", err)
	}
	cat, err := certify.Load(path)
	if err != nil {
		t.Fatalf("load the committed catalog: %v", err)
	}
	return cat
}

func registry(t *testing.T) *certify.Registry {
	t.Helper()
	// A private registry: the tests must neither see nor be seen by the
	// process-wide one that init() populates.
	reg := certify.NewRegistry()
	Register(reg)
	return reg
}

func TestEveryApplicableCaseIsRegistered(t *testing.T) {
	cat := loadCatalog(t)
	cov := registry(t).Coverage(cat, certify.Filter{Docs: []string{doc}})

	if len(cov.Orphans) != 0 {
		t.Fatalf("the suite registers uids the catalog does not contain: %v", cov.Orphans)
	}
	if len(cov.Docs) != 1 {
		t.Fatalf("expected exactly one document's coverage, got %d", len(cov.Docs))
	}
	d := cov.Docs[0]
	if len(d.Unimplemented) != 0 {
		var names []string
		for _, e := range d.Unimplemented {
			names = append(names, e.ID)
		}
		sort.Strings(names)
		t.Errorf("%d applicable %s case(s) have no implementation: %s",
			len(names), doc, strings.Join(names, ", "))
	}
	if !d.Complete() {
		t.Error("the document's coverage is not complete")
	}
	t.Logf("%s: %d total, %d applicable, %d implemented, %d inapplicable",
		d.Doc, d.Total, d.Applicable, len(d.Implemented), len(d.Inapplicable))
}

func TestInapplicableCasesAreDeliberatelyUnregistered(t *testing.T) {
	cat := loadCatalog(t)
	reg := registry(t)

	// The two the catalog excludes must NOT be registered: registering them
	// would move them out of the coverage report's Inapplicable bucket and
	// discard the extraction's reason for excluding them.
	for uid, why := range InapplicableUIDs {
		c, ok := cat.ByUID(uid)
		if !ok {
			t.Errorf("%s is listed as deliberately unregistered but is not in the catalog at all", uid)
			continue
		}
		if c.Applicable {
			t.Errorf("%s is marked APPLICABLE in the catalog, so it must be implemented rather than "+
				"listed as inapplicable (this suite's stated reason: %s)", uid, why)
		}
		if _, registered := reg.Lookup(uid); registered {
			t.Errorf("%s is registered although the catalog marks it inapplicable; the coverage report "+
				"would then hide the extraction's reason", uid)
		}
	}

	// And nothing ELSE in the document may be inapplicable-and-unregistered
	// without appearing in InapplicableUIDs, so the two lists cannot drift.
	for _, c := range cat.Select(certify.Filter{Docs: []string{doc}}) {
		if c.Applicable {
			continue
		}
		if _, ok := InapplicableUIDs[c.UID]; !ok {
			t.Errorf("the catalog marks %s inapplicable but this suite's InapplicableUIDs does not "+
				"record a reason for skipping it", c.UID)
		}
	}
}

func TestEveryRegistrationHasSensibleCapabilityRequirements(t *testing.T) {
	known := map[string]bool{"bench": true, "capture": true, "keylog": true, "gridsim": true,
		"gateway": true, "pki": true}
	for _, r := range registry(t).Registrations() {
		if r.Suite != suiteName {
			t.Errorf("%s registered under suite %q, want %q", r.UID, r.Suite, suiteName)
		}
		for _, tag := range r.Requires {
			if !known[tag] {
				t.Errorf("%s requires unknown capability %q", r.UID, tag)
			}
		}
		// "keylog" must never be a hard requirement: a check with no key log
		// still has cleartext handshake criteria it can assert, and the runner
		// would skip the whole row rather than let those run.
		for _, tag := range r.Requires {
			if tag == "keylog" {
				t.Errorf("%s requires \"keylog\"; the runner would skip the entire case without one, "+
					"discarding the cleartext-handshake assertions it could still make. Handle a missing "+
					"key log inside the check with a SKIP assertion instead.", r.UID)
			}
		}
	}
}

func TestRegisteringTwiceIsACoordinationBugThatPanics(t *testing.T) {
	reg := certify.NewRegistry()
	Register(reg)
	defer func() {
		if recover() == nil {
			t.Error("registering the suite twice into one registry must panic: two checks claiming one " +
				"test case is a coordination bug whose only correct outcome is a loud failure")
		}
	}()
	Register(reg)
}

func TestPlanIsDeterministicAndInDocumentOrder(t *testing.T) {
	cat := loadCatalog(t)
	opts := certify.DefaultOptions()
	opts.Docs = []string{doc}
	opts.DryRun = true
	opts.NoCapture = true

	run, err := certify.New(registry(t), cat, opts)
	if err != nil {
		t.Fatal(err)
	}
	first := planUIDs(run.Plan())
	second := planUIDs(run.Plan())
	if strings.Join(first, ",") != strings.Join(second, ",") {
		t.Fatal("the plan is not deterministic between two calls")
	}
	if len(first) == 0 {
		t.Fatal("the plan is empty")
	}
	// The families should come out grouped, which is what WithOrder buys.
	// Only IMPLEMENTED rows are considered: an inapplicable case carries no
	// registration and therefore no Order, so the runner plans it first.
	first = planUIDs(implementedOnly(run.Plan()))
	family := func(uid string) string {
		id := uid[strings.Index(uid, "::")+2:]
		return id[:strings.Index(id, "-")]
	}
	seen := map[string]int{}
	last := ""
	for _, uid := range first {
		f := family(uid)
		if f != last {
			seen[f]++
			last = f
		}
	}
	for f, runs := range seen {
		if runs > 1 {
			t.Errorf("family %s is split into %d non-contiguous runs in the plan; WithOrder should keep "+
				"each family together so the console output reads like the procedures document", f, runs)
		}
	}
}

func implementedOnly(p []certify.Planned) []certify.Planned {
	var out []certify.Planned
	for _, x := range p {
		if x.Implemented {
			out = append(out, x)
		}
	}
	return out
}

func planUIDs(p []certify.Planned) []string {
	out := make([]string, len(p))
	for i, x := range p {
		out[i] = x.Case.UID
	}
	return out
}

func TestCatalogObservablesAreCoveredByTheCheckThatClaimsThem(t *testing.T) {
	// A weak but useful invariant: every registered case must name at least one
	// wire observable OR be one of the documentation rows this suite serves
	// off-wire. A case with wire observables and no wire-citing check is the
	// shape of a row that quietly stopped asserting anything.
	offWireRows := map[string]bool{
		"ssm-conf-v0.8::RBAC-004": true, // documentation audit, no wire traffic
		"ssm-conf-v0.8::RBAC-010": true, // rules-database configuration, management plane
		"ssm-conf-v0.8::PKI-009":  true, // optional capability behind a DUT config change
		"ssm-conf-v0.8::OPS-001":  true, // export declaration review
	}
	cat := loadCatalog(t)
	for _, r := range registry(t).Registrations() {
		c, ok := cat.ByUID(r.UID)
		if !ok {
			t.Errorf("%s is registered but absent from the catalog", r.UID)
			continue
		}
		if len(c.Observables) == 0 && !offWireRows[r.UID] {
			t.Errorf("%s has no catalog observables and is not declared an off-wire row", r.UID)
		}
	}
}
