package report

import (
	"testing"

	"csip-tls-test/internal/certify"
)

func loadCatalog(t *testing.T) *certify.Catalog {
	t.Helper()
	path, err := certify.DefaultCatalogPath()
	if err != nil {
		t.Skipf("no committed catalog: %v", err)
	}
	cat, err := certify.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	return cat
}

// TestCaseIDListsMatchTheCatalog keeps the readiness report and the
// registration honest about what the specification actually contains. A case
// the extraction adds or renames must break a test here rather than quietly
// drop out of coverage.
func TestCaseIDListsMatchTheCatalog(t *testing.T) {
	cat := loadCatalog(t)
	for doc, want := range map[string][]string{DocCSIP: CSIPCaseIDs, DocModbus: ModbusCaseIDs} {
		got := map[string]bool{}
		for _, c := range cat.Select(certify.Filter{Docs: []string{doc}}) {
			got[c.ID] = true
		}
		if len(got) != len(want) {
			t.Errorf("%s: catalog has %d cases, this package lists %d", doc, len(got), len(want))
		}
		for _, id := range want {
			if !got[id] {
				t.Errorf("%s: this package lists %s, which the catalog does not contain", doc, id)
			}
			delete(got, id)
		}
		for id := range got {
			t.Errorf("%s: the catalog contains %s, which this package does not list", doc, id)
		}
	}
}

// TestEveryApplicableCaseIsRegistered is the coverage bar. An unregistered uid
// reads as an oversight; a registered SKIP with a reason reads as a judgement,
// and the four rows deliberately left out are named in InapplicableCaseIDs.
func TestEveryApplicableCaseIsRegistered(t *testing.T) {
	cat := loadCatalog(t)
	reg := certify.NewRegistry()
	RegisterInto(reg)

	cov := reg.Coverage(cat, certify.Filter{Docs: []string{DocCSIP, DocModbus}})
	if len(cov.Orphans) != 0 {
		t.Fatalf("registered uids the catalog does not contain: %v", cov.Orphans)
	}
	for _, d := range cov.Docs {
		if len(d.Unimplemented) != 0 {
			for _, e := range d.Unimplemented {
				t.Errorf("%s %s has no implementation: %s", d.Doc, e.ID, e.Title)
			}
		}
		for _, e := range d.Inapplicable {
			if _, expected := InapplicableCaseIDs[e.ID]; !expected {
				t.Errorf("%s %s is unregistered and not listed as a deliberate omission", d.Doc, e.ID)
			}
		}
		if len(d.Inapplicable)+len(d.Implemented) != d.Total {
			t.Errorf("%s: %d implemented + %d inapplicable != %d total",
				d.Doc, len(d.Implemented), len(d.Inapplicable), d.Total)
		}
	}
	total, applicable, implemented, missing := cov.Totals()
	if total != 101 || applicable != 97 {
		t.Errorf("selected %d case(s), %d applicable; want 101 and 97", total, applicable)
	}
	if implemented != 97 || missing != 0 {
		t.Errorf("%d implemented, %d missing; want 97 and 0", implemented, missing)
	}
}

// TestInapplicableRowsAreNotRegistered guards the judgement recorded in
// cases.go: registering a check that could only SKIP would move these rows out
// of the coverage report's "not applicable" section, where the extraction's own
// reason is printed, and into "implemented".
func TestInapplicableRowsAreNotRegistered(t *testing.T) {
	reg := certify.NewRegistry()
	RegisterInto(reg)
	for id := range InapplicableCaseIDs {
		for _, uid := range []string{uidCSIP(id), uidModbus(id)} {
			if _, ok := reg.Lookup(uid); ok {
				t.Errorf("%s is registered despite being marked inapplicable", uid)
			}
		}
	}
}

// TestEveryKeyRowIsBoundToARealKey proves the key table and the registration
// agree: a keyCheck registered for a uid no KeySpec carries would return an
// error at run time, which is a failure the run could not recover from.
func TestEveryKeyRowIsBoundToARealKey(t *testing.T) {
	for _, id := range csipKeyRows {
		if len(keysFor(CertTypeCSIP, uidCSIP(id))) == 0 {
			t.Errorf("CSIP %s is registered as a key row but no KeySpec carries its uid", id)
		}
	}
	for _, id := range modbusKeyRows {
		if len(keysFor(CertTypeModbus, uidModbus(id))) == 0 {
			t.Errorf("Modbus %s is registered as a key row but no KeySpec carries its uid", id)
		}
	}
}

// TestLogRuleIDsAreDistinct catches a copy-paste that would make Register panic
// at init and take the whole binary down.
func TestLogRuleIDsAreDistinct(t *testing.T) {
	seen := map[string]bool{}
	for _, r := range modbusLogRules() {
		if seen[r.id] {
			t.Errorf("Modbus log rule %s is defined twice", r.id)
		}
		seen[r.id] = true
		if r.rule.Claim == "" || r.rule.Method == "" || r.rule.Assess == nil {
			t.Errorf("%s is incompletely specified", r.id)
		}
	}
	seen = map[string]bool{}
	for _, r := range csipLogRules() {
		if seen[r.id] {
			t.Errorf("CSIP log rule %s is defined twice", r.id)
		}
		seen[r.id] = true
		if r.rule.Claim == "" || r.rule.Method == "" || r.rule.Assess == nil {
			t.Errorf("%s is incompletely specified", r.id)
		}
	}
}

// TestDefaultRegistryCarriesTheSuite proves the init side effect works, which is
// how a suite binary picks these checks up.
func TestDefaultRegistryCarriesTheSuite(t *testing.T) {
	if _, ok := certify.Default().Lookup(uidModbus("RPT-LOG-8")); !ok {
		t.Fatal("importing this package did not register its checks in the default registry")
	}
}
