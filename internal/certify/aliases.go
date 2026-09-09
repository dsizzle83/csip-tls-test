package certify

// aliases.go carries the catalog's uid/doc-key re-key history.
//
// A catalog uid is committed evidence: it gets baked verbatim into every
// TestCaseResult of every bundle a campaign ever writes, and into whatever
// command line an operator saved to reproduce a selection. When an extraction
// error is found and fixed — REV0907-E9 / WP7-T8 found the doc key and uid
// prefix "SS-1547-TEST-v1.1" was a misparse of a v1.0 document — the catalog
// row is re-keyed, but everything minted under the retired key is not: an old
// bundle under runs/ still carries "ss-1547-test-v1.1::MOD-4" as immutable
// evidence (see testdata/catalog/catalog.json's doc_version note on the two
// re-keyed rows), and a saved "-uid ss-1547-test-v1.1::MOD-4" must still mean
// something.
//
// testdata/catalog/uid_aliases.json is the append-only record of every such
// re-key, and UIDAliases is its loaded, indexed form. It is consulted only on
// a miss — see Catalog.ByUID, Catalog.Doc and Catalog.resolveFilterAliases —
// so a catalog with no re-key history, or a caller-supplied key that was
// never retired, pays nothing and behaves exactly as before this file existed.
import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// AliasesFile is the alias table's committed location, relative to the
// repository root — a sibling of CatalogFile.
const AliasesFile = "testdata/catalog/uid_aliases.json"

// docAlias is one retired document key and its replacement.
type docAlias struct {
	OldDoc string `json:"old_doc"`
	NewDoc string `json:"new_doc"`
}

// caseUIDAlias is one retired case uid and its replacement.
type caseUIDAlias struct {
	OldUID string `json:"old_uid"`
	NewUID string `json:"new_uid"`
}

// uidAliasFile is the on-disk shape of testdata/catalog/uid_aliases.json. The
// leading-underscore fields are human-facing provenance notes, not data this
// loader acts on, but they are modelled and validated like every other field
// here rather than left for DisallowUnknownFields to silently reject a future
// editor's addition.
type uidAliasFile struct {
	Purpose    string         `json:"_purpose"`
	Status     string         `json:"_status"`
	Migrated   string         `json:"migrated"`
	Finding    string         `json:"finding"`
	Task       string         `json:"task"`
	DocAliases []docAlias     `json:"doc_aliases"`
	UIDAliases []caseUIDAlias `json:"uid_aliases"`
}

// UIDAliases resolves a document key or case uid that a catalog re-key
// retired to its current replacement. Nil is a valid, no-op *UIDAliases:
// every method on it accepts a nil receiver and returns its input unchanged,
// which is the correct behaviour for a catalog with no committed alias table.
type UIDAliases struct {
	docs   map[string]string // lower-cased old doc key -> new doc key
	uids   map[string]string // lower-cased old uid -> new uid
	source string
}

// LoadUIDAliases reads and indexes the alias table at path.
func LoadUIDAliases(path string) (*UIDAliases, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("certify: read uid aliases %s: %w", path, err)
	}
	return LoadUIDAliasesBytes(data, path)
}

// LoadUIDAliasesBytes validates an in-memory alias table. source is recorded
// only for error messages.
func LoadUIDAliasesBytes(data []byte, source string) (*UIDAliases, error) {
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	var raw uidAliasFile
	if err := dec.Decode(&raw); err != nil {
		return nil, fmt.Errorf("certify: parse uid aliases %s: %w", source, err)
	}
	a := &UIDAliases{
		docs:   make(map[string]string, len(raw.DocAliases)),
		uids:   make(map[string]string, len(raw.UIDAliases)),
		source: source,
	}
	for i, d := range raw.DocAliases {
		if d.OldDoc == "" || d.NewDoc == "" {
			return nil, fmt.Errorf("certify: uid aliases %s: doc_aliases[%d] missing old_doc or new_doc", source, i)
		}
		a.docs[strings.ToLower(d.OldDoc)] = d.NewDoc
	}
	for i, u := range raw.UIDAliases {
		if u.OldUID == "" || u.NewUID == "" {
			return nil, fmt.Errorf("certify: uid aliases %s: uid_aliases[%d] missing old_uid or new_uid", source, i)
		}
		a.uids[strings.ToLower(u.OldUID)] = u.NewUID
	}
	return a, nil
}

// DefaultUIDAliasesPath finds the committed alias table by walking up from
// the working directory, exactly as DefaultCatalogPath does (findInAncestors,
// catalog.go). An empty path with a nil error means no alias table is
// reachable, which is not a failure: most catalogs carry no re-key history.
func DefaultUIDAliasesPath() (string, error) {
	p, err := findInAncestors(AliasesFile)
	if err != nil {
		return "", nil
	}
	return p, nil
}

// LoadDefaultUIDAliases loads the alias table at DefaultUIDAliasesPath, or
// returns a valid no-op *UIDAliases if none is committed reachable from here.
func LoadDefaultUIDAliases() (*UIDAliases, error) {
	p, err := DefaultUIDAliasesPath()
	if err != nil {
		return nil, err
	}
	if p == "" {
		return &UIDAliases{}, nil
	}
	return LoadUIDAliases(p)
}

// ResolveDoc returns the current document key for doc, translating a retired
// key through the alias table. A doc that was never re-keyed — including
// every doc when a is nil or empty — is returned unchanged: resolution is
// advisory, not validating, so it never turns an unknown doc into an error.
func (a *UIDAliases) ResolveDoc(doc string) string {
	if a == nil {
		return doc
	}
	if v, ok := a.docs[strings.ToLower(doc)]; ok {
		return v
	}
	return doc
}

// ResolveUID returns the current uid for uid, translating a retired uid
// through the alias table. See ResolveDoc.
func (a *UIDAliases) ResolveUID(uid string) string {
	if a == nil {
		return uid
	}
	if v, ok := a.uids[strings.ToLower(uid)]; ok {
		return v
	}
	return uid
}
