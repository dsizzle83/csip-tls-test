package certify

// scope_test.go pins the two ways a row leaves a run WITHOUT being a skip, and
// the one way a manifest must never be allowed to make rows disappear quietly.

import (
	"context"
	"strings"
	"testing"

	"csip-tls-test/internal/certify/manifest"
	"csip-tls-test/internal/evidence/bundle"
)

func loadManifest(t *testing.T, body string) *manifest.Manifest {
	t.Helper()
	m, err := manifest.Parse([]byte(body), "candidate.json")
	if err != nil {
		t.Fatalf("fixture manifest is invalid: %v", err)
	}
	return m
}

// serverOnly is the audit's minimum shape: a Secure SunSpec SERVER and nothing
// else.
func serverOnly(t *testing.T) *manifest.Manifest { return loadManifest(t, validManifestJSON) }

func bothDirections(t *testing.T) *manifest.Manifest {
	return loadManifest(t, strings.Replace(validManifestJSON,
		`"roles": ["server"]`, `"roles": ["server", "client"]`, 1))
}

func TestManifestScopeExcludesTheUnclaimedDirection(t *testing.T) {
	m := serverOnly(t)
	client := &Case{UID: "ssm-conf-v0.8::RBAC-011", DUTRole: RoleMBAPSClient, Applicable: true}
	d, ok := ManifestScope(m, client)
	if !ok {
		t.Fatal("a client-direction row survived a server-only manifest")
	}
	if d.Source != bundle.NASourceManifest {
		t.Errorf("Source = %q, want %q", d.Source, bundle.NASourceManifest)
	}
	if !strings.Contains(d.Reason, "CLIENT") || !strings.Contains(d.Reason, "secure_sunspec.roles") {
		t.Errorf("Reason does not say which direction or which key decided it: %q", d.Reason)
	}
	if !strings.Contains(d.Detail, "candidate.json") {
		t.Errorf("Detail does not name the declaration a reader would go and check: %q", d.Detail)
	}
}

func TestManifestScopeKeepsTheClaimedDirection(t *testing.T) {
	m := serverOnly(t)
	server := &Case{UID: "ssm-conf-v0.8::RBAC-002", DUTRole: RoleMBAPSServer, Applicable: true}
	if _, ok := ManifestScope(m, server); ok {
		t.Error("a server-direction row was excluded by a manifest that claims the server direction")
	}
	both := bothDirections(t)
	client := &Case{UID: "ssm-conf-v0.8::RBAC-011", DUTRole: RoleMBAPSClient, Applicable: true}
	if _, ok := ManifestScope(both, client); ok {
		t.Error("a client-direction row was excluded by a manifest that claims BOTH directions")
	}
}

// Silence is not a disclaimer. A run with no -manifest must behave exactly as
// it did before manifests existed.
func TestManifestScopeWithNoManifestExcludesNothing(t *testing.T) {
	for _, role := range []DUTRole{RoleMBAPSClient, RoleMBAPSServer, RoleCSIPClient, RoleModbusClient} {
		if _, ok := ManifestScope(nil, &Case{UID: "x", DUTRole: role}); ok {
			t.Errorf("a nil manifest excluded a %s row", role)
		}
	}
}

// A row the CATALOG says is applicable and the CANDIDATE says is out of scope is
// a disagreement between two documents. The manifest stands, but the conflict
// must be flagged — a scope decision nobody is told about is a row deleted.
func TestManifestScopeFlagsACatalogDisagreement(t *testing.T) {
	m := serverOnly(t)
	contested := &Case{UID: "ssm-conf-v0.8::RBAC-011", DUTRole: RoleMBAPSClient, Applicable: true}
	d, _ := ManifestScope(m, contested)
	if !d.Contested {
		t.Error("excluding a row the catalog marks APPLICABLE was not flagged as contested")
	}
	agreed := &Case{UID: "ssm-conf-v0.8::PKI-009", DUTRole: RoleMBAPSClient, Applicable: false}
	d2, _ := ManifestScope(m, agreed)
	if d2.Contested {
		t.Error("excluding a row the catalog ALSO marks inapplicable was flagged as contested")
	}
}

// Only the axes actually declared may act. A rule set that grows silently is a
// bulk exclusion nobody reviewed.
func TestScopeAxesAreDeclaredCoherently(t *testing.T) {
	seen := map[DUTRole]bool{}
	for _, ax := range scopeAxes {
		if seen[ax.Role] {
			t.Errorf("dut_role %q has two axes; which one decides?", ax.Role)
		}
		seen[ax.Role] = true
		if !knownRoles[ax.Role] {
			t.Errorf("axis names dut_role %q, which the catalog does not use", ax.Role)
		}
		if ax.Claim == "" || ax.Field == "" || ax.Direction == "" {
			t.Errorf("axis for %q is incompletely declared: %+v", ax.Role, ax)
		}
		// The claim must be a role the manifest schema actually accepts, or the
		// axis can never be satisfied and silently excludes everything.
		body := strings.Replace(validManifestJSON, `"roles": ["server"]`,
			`"roles": ["`+ax.Claim+`"]`, 1)
		if _, err := manifest.Parse([]byte(body), "axis-probe"); err != nil {
			t.Errorf("axis for %q claims role %q, which the manifest schema rejects: %v",
				ax.Role, ax.Claim, err)
		}
	}
}

// ── the catalog axis ──────────────────────────────────────────────────────

func TestCatalogScopeOnlyFiresForAnInapplicableRow(t *testing.T) {
	if _, ok := CatalogScope(&Case{UID: "x", Applicable: true}); ok {
		t.Error("an applicable row was declared out of scope by the catalog axis")
	}
	d, ok := CatalogScope(&Case{
		UID: "csip-conf-v1.3::AGG-001", Applicable: false,
		ApplicabilityReason: "the DUT is a DER Client, not an aggregator client. Long tail follows.",
	})
	if !ok {
		t.Fatal("an inapplicable row was not declared out of scope")
	}
	if d.Source != bundle.NASourceCatalog {
		t.Errorf("Source = %q, want %q", d.Source, bundle.NASourceCatalog)
	}
	if strings.Contains(d.Reason, "Long tail") {
		t.Errorf("Reason carries the whole applicability essay: %q", d.Reason)
	}
	if !strings.Contains(d.Detail, "applicable=false") {
		t.Errorf("Detail does not name the catalog field: %q", d.Detail)
	}
}

func TestCatalogScopeSuppliesAReasonEvenWhenTheCatalogDoesNot(t *testing.T) {
	d, ok := CatalogScope(&Case{UID: "x", Applicable: false})
	if !ok || strings.TrimSpace(d.Reason) == "" {
		t.Fatalf("CatalogScope() = (%+v, %v); an N/A with no reason is refused by bundle.Verify", d, ok)
	}
}

// The plan must NOT turn an implemented-but-inapplicable row into N/A: the
// framework deliberately runs those and reports them as informative, and
// deleting them would delete the informative tally.
func TestInformativeRowsKeepRunning(t *testing.T) {
	opts, _ := baseOptions(t, nil)
	opts.Suites = []string{"csip"}
	r, err := New(suitesForCampaigns(t), realCatalog(t), opts)
	if err != nil {
		t.Fatal(err)
	}
	var informative, na int
	for _, p := range r.Plan() {
		switch {
		case p.OutOfScope():
			na++
		case !p.Case.Applicable:
			informative++
		}
	}
	if informative == 0 {
		t.Fatal("no informative row survived the plan; the whole aggregator set has been turned into N/A")
	}
	if na != 0 {
		t.Errorf("%d row(s) were declared N/A with no manifest supplied", na)
	}
}

// An inapplicable row NOBODY implements is the shape that used to be a SKIP
// reading "not applicable to this product". It is N/A now.
func TestUnimplementedInapplicableRowsBecomeNotApplicable(t *testing.T) {
	opts, _ := baseOptions(t, nil)
	reg := NewRegistry()
	cat := realCatalog(t)
	// Register only ONE row, so every other inapplicable row is unimplemented.
	reg.Register("ssm-conf-v0.8::RBAC-002", "ssm", func(ctx context.Context, rc *RunCtx) (Result, error) {
		return Skipped("fixture"), nil
	})
	r, err := New(reg, cat, opts)
	if err != nil {
		t.Fatal(err)
	}
	var na, skipReadingNotApplicable int
	for _, p := range r.Plan() {
		if p.OutOfScope() {
			na++
			if p.Scope.Source != bundle.NASourceCatalog {
				t.Errorf("%s: Source = %q, want the catalog", p.Case.UID, p.Scope.Source)
			}
		}
		if strings.Contains(p.Skip, "not applicable") {
			skipReadingNotApplicable++
		}
	}
	if na == 0 {
		t.Fatal("no unimplemented inapplicable row became N/A")
	}
	if skipReadingNotApplicable > 0 {
		t.Errorf("%d row(s) still carry a SKIP whose text says 'not applicable' — the right words on "+
			"the wrong verdict, counted in the same number as a genuine evidence gap",
			skipReadingNotApplicable)
	}
}
