package certify

import "testing"

// testAliases is a miniature alias table exercising both alias kinds, for the
// loader tests that do not need the committed catalog.
const testAliases = `{
 "_purpose": "p", "_status": "s", "migrated": "2026-09-08", "finding": "REV0907-E9", "task": "WP7-T8",
 "doc_aliases": [ {"old_doc": "OLD-DOC-v1.1", "new_doc": "OLD-DOC-v1.0"} ],
 "uid_aliases": [ {"old_uid": "old-doc-v1.1::X-1", "new_uid": "old-doc-v1.0::X-1"} ]
}`

func TestLoadUIDAliasesBytesResolves(t *testing.T) {
	a, err := LoadUIDAliasesBytes([]byte(testAliases), "testdata/aliases.json")
	if err != nil {
		t.Fatalf("LoadUIDAliasesBytes: %v", err)
	}
	if got := a.ResolveDoc("old-doc-v1.1"); got != "OLD-DOC-v1.0" {
		t.Errorf("ResolveDoc(old, lower) = %q, want %q", got, "OLD-DOC-v1.0")
	}
	if got := a.ResolveDoc("OLD-DOC-V1.1"); got != "OLD-DOC-v1.0" {
		t.Errorf("ResolveDoc is not fold-insensitive on the key: got %q", got)
	}
	if got := a.ResolveDoc("NEVER-ALIASED"); got != "NEVER-ALIASED" {
		t.Errorf("ResolveDoc mutated an unaliased doc: got %q", got)
	}
	if got := a.ResolveUID("old-doc-v1.1::X-1"); got != "old-doc-v1.0::X-1" {
		t.Errorf("ResolveUID(old) = %q, want %q", got, "old-doc-v1.0::X-1")
	}
	if got := a.ResolveUID("never-aliased::Y-1"); got != "never-aliased::Y-1" {
		t.Errorf("ResolveUID mutated an unaliased uid: got %q", got)
	}
}

func TestLoadUIDAliasesBytesRejectsUnknownFields(t *testing.T) {
	if _, err := LoadUIDAliasesBytes([]byte(`{"doc_aliases":[],"uid_aliases":[],"surprise":true}`), "x"); err == nil {
		t.Fatal("an unmodelled field was accepted")
	}
}

func TestLoadUIDAliasesBytesRejectsIncompleteEntries(t *testing.T) {
	cases := []string{
		`{"doc_aliases":[{"old_doc":"A"}],"uid_aliases":[]}`,    // missing new_doc
		`{"doc_aliases":[],"uid_aliases":[{"old_uid":"a::1"}]}`, // missing new_uid
		`{"doc_aliases":[{"new_doc":"B"}],"uid_aliases":[]}`,    // missing old_doc
	}
	for _, c := range cases {
		if _, err := LoadUIDAliasesBytes([]byte(c), "x"); err == nil {
			t.Errorf("an incomplete alias entry was accepted: %s", c)
		}
	}
}

// TestNilUIDAliasesIsANoOp pins the "nil receiver is safe and a no-op"
// contract every consulting call site (Catalog.ByUID, Catalog.Doc,
// Catalog.resolveFilterAliases, report.certTypeFor) depends on.
func TestNilUIDAliasesIsANoOp(t *testing.T) {
	var a *UIDAliases
	if got := a.ResolveDoc("anything"); got != "anything" {
		t.Errorf("nil.ResolveDoc mutated input: got %q", got)
	}
	if got := a.ResolveUID("anything::1"); got != "anything::1" {
		t.Errorf("nil.ResolveUID mutated input: got %q", got)
	}
}

// TestCommittedCatalogResolvesOldSS1547UID is the WP7-T8 / REV0907-E9
// integration pin: Catalog.ByUID, Catalog.Doc and Catalog.Select must resolve
// the retired "ss-1547-test-v1.1" / "SS-1547-TEST-v1.1" keys against the
// COMMITTED catalog + testdata/catalog/uid_aliases.json, to the same cases
// the current "ss-1547-test-v1.0" / "SS-1547-TEST-v1.0" keys select — so a
// saved command line or an external reference minted before the re-key keeps
// working.
func TestCommittedCatalogResolvesOldSS1547UID(t *testing.T) {
	path, err := DefaultCatalogPath()
	if err != nil {
		t.Skipf("no committed catalog reachable from %s: %v", mustGetwd(t), err)
	}
	cat, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}

	newCase, ok := cat.ByUID("ss-1547-test-v1.0::MOD-4")
	if !ok {
		t.Fatal("sanity: the current-keyed uid is not in the committed catalog")
	}
	oldCase, ok := cat.ByUID("ss-1547-test-v1.1::MOD-4")
	if !ok {
		t.Fatal("ByUID did not resolve the retired uid ss-1547-test-v1.1::MOD-4 via " +
			"testdata/catalog/uid_aliases.json")
	}
	if oldCase != newCase {
		t.Errorf("ByUID(old) and ByUID(new) returned different cases: %p vs %p", oldCase, newCase)
	}

	if _, ok := cat.Doc("SS-1547-TEST-v1.1"); !ok {
		t.Error("Doc did not resolve the retired document key SS-1547-TEST-v1.1")
	}

	oldSel := cat.Select(Filter{UIDs: []string{"ss-1547-test-v1.1::MOD-4"}})
	if len(oldSel) != 1 || oldSel[0] != newCase {
		t.Errorf("Select(UIDs: [old uid]) = %v, want exactly [%p]", oldSel, newCase)
	}
	oldDocSel := cat.Select(Filter{Docs: []string{"SS-1547-TEST-v1.1"}})
	newDocSel := cat.Select(Filter{Docs: []string{"SS-1547-TEST-v1.0"}})
	if len(oldDocSel) != len(newDocSel) || len(oldDocSel) == 0 {
		t.Errorf("Select(Docs: [old doc]) returned %d cases, Select(Docs: [new doc]) returned %d; want equal and nonzero",
			len(oldDocSel), len(newDocSel))
	}

	if err := cat.Validate(Filter{UIDs: []string{"ss-1547-test-v1.1::MOD-4"}, Docs: []string{"SS-1547-TEST-v1.1"}}); err != nil {
		t.Errorf("Validate refused the retired selectors: %v", err)
	}
}
