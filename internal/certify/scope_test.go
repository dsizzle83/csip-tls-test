package certify

// scope_test.go pins the two ways a row leaves a run WITHOUT being a skip, and
// the one way a manifest must never be allowed to make rows disappear quietly.

import (
	"context"
	"encoding/json"
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

// ── row-level requirements (RequirementScope) ───────────────────────────────

// withWriteFunctionCodes returns validManifestJSON with modbus_client.
// write_function_codes set to codes, e.g. "[16]" or "[6, 16]".
func withWriteFunctionCodes(codes string) string {
	return strings.Replace(validManifestJSON,
		`"modbus_client": {"transport": "tcp", "device_count": 1, "generation": "7xx"}`,
		`"modbus_client": {"transport": "tcp", "device_count": 1, "generation": "7xx", "write_function_codes": `+codes+`}`, 1)
}

func wr1Fixture() *Case {
	return &Case{
		UID: "ss-modbus-client-conf-v1.1::WR-1", DUTRole: RoleModbusClient, Applicable: true,
		Requires: map[string]json.RawMessage{"modbus_client.write_function_codes": json.RawMessage("[6]")},
	}
}

func TestRequirementScopeExcludesAnUnsatisfiedRequirement(t *testing.T) {
	m := loadManifest(t, withWriteFunctionCodes("[16]"))
	d, ok := RequirementScope(m, wr1Fixture())
	if !ok {
		t.Fatal("a row whose requirement the manifest contradicts survived RequirementScope")
	}
	if d.Source != bundle.NASourceManifest {
		t.Errorf("Source = %q, want %q", d.Source, bundle.NASourceManifest)
	}
	if !strings.Contains(d.Reason, "FC 6") || !strings.Contains(d.Reason, "write_function_codes") {
		t.Errorf("Reason does not name the missing code or the field that decided it: %q", d.Reason)
	}
	for _, want := range []string{"candidate.json", "FC 16", "PICS_SUNSPEC_MODBUS.md", "§4.2"} {
		if !strings.Contains(d.Detail, want) {
			t.Errorf("Detail does not carry %q, so a reader cannot go and check it: %q", want, d.Detail)
		}
	}
}

// A requirement the manifest DOES claim must not exclude the row — the check
// still has to run and cite the wire, for a candidate that says it does this.
func TestRequirementScopeKeepsASatisfiedRequirement(t *testing.T) {
	m := loadManifest(t, withWriteFunctionCodes("[6, 16]"))
	if _, ok := RequirementScope(m, wr1Fixture()); ok {
		t.Error("a row whose requirement the manifest DOES claim was excluded")
	}
}

// Silence is not a disclaimer: a manifest that never mentions the field has
// not withdrawn the claim, so the row must still run — ManifestScope's own
// rule, for the same reason (CAMPAIGNS.md §5, "No manifest means assert
// everything").
func TestRequirementScopeWithNoDeclarationExcludesNothing(t *testing.T) {
	if _, ok := RequirementScope(serverOnly(t), wr1Fixture()); ok {
		t.Error("an UNDECLARED field excluded a row; silence is not a disclaimer")
	}
	if _, ok := RequirementScope(nil, wr1Fixture()); ok {
		t.Error("a nil manifest excluded a row with a Requires clause")
	}
}

// A row with no Requires at all is untouched by this axis, whatever the
// manifest says.
func TestRequirementScopeWithNoRequiresExcludesNothing(t *testing.T) {
	m := loadManifest(t, withWriteFunctionCodes("[16]"))
	plain := &Case{UID: "ss-modbus-client-conf-v1.1::READ-1", DUTRole: RoleModbusClient, Applicable: true}
	if _, ok := RequirementScope(m, plain); ok {
		t.Error("a row with no Requires at all was excluded")
	}
	if _, ok := RequirementScope(m, nil); ok {
		t.Error("RequirementScope(m, nil) reported a case out of scope")
	}
}

// Coherence: every declared field must actually be usable, and the lookup
// helpers catalog.go's loader depends on must agree with the registry — the
// same property TestScopeAxesAreDeclaredCoherently holds the DUTRole axes to.
func TestRequirementFieldsAreDeclaredCoherently(t *testing.T) {
	if len(requirementFields) == 0 {
		t.Fatal("requirementFields is empty; WR-1's Requires would have nothing to evaluate it")
	}
	for field, rf := range requirementFields {
		if rf.Decode == nil || rf.Satisfied == nil {
			t.Errorf("requirement field %q is incompletely declared: %+v", field, rf)
		}
		if !RequirementFieldKnown(field) {
			t.Errorf("RequirementFieldKnown(%q) = false for a field requirementFields defines", field)
		}
	}
	if !containsFold(RequirementFieldNames(), "modbus_client.write_function_codes") {
		t.Errorf("RequirementFieldNames() = %v, missing the write-function-codes field", RequirementFieldNames())
	}
}

// The end-to-end path a manifest-driven exclusion has to survive: Plan() must
// mark WR-1 out of scope on THIS axis, read off the REAL catalog's own
// Requires declaration — not a synthetic fixture — so a change that drops the
// Plan() call site, or the catalog's requires entry, fails a test rather than
// silently widening the campaign.
func TestPlanExcludesTheRealWR1AgainstAContradictingManifest(t *testing.T) {
	const uid = "ss-modbus-client-conf-v1.1::WR-1"
	cat := realCatalog(t)
	tc, ok := cat.ByUID(uid)
	if !ok {
		t.Fatalf("the real catalog has no %s; the fixture has drifted", uid)
	}
	if len(tc.Requires) == 0 {
		t.Fatalf("%s carries no Requires in the real catalog; RequirementScope has nothing to read", uid)
	}

	reg := NewRegistry()
	reg.Register(uid, "modbus-client", func(ctx context.Context, rc *RunCtx) (Result, error) {
		return Skipped("fixture — should not run when the manifest contradicts the row's Requires"), nil
	})

	opts, _ := baseOptions(t, nil)
	opts.ManifestPath = writeManifest(t, withWriteFunctionCodes("[16]"))
	opts.UIDs = []string{uid}
	r, err := New(reg, cat, opts)
	if err != nil {
		t.Fatal(err)
	}
	plan := r.Plan()
	if len(plan) != 1 {
		t.Fatalf("Plan() selected %d row(s) for -uid %s, want 1", len(plan), uid)
	}
	p := plan[0]
	if !p.OutOfScope() {
		t.Fatal("WR-1 was not marked out of scope against a manifest declaring write_function_codes=[16]")
	}
	if p.Scope.Source != bundle.NASourceManifest {
		t.Errorf("Source = %q, want %q", p.Scope.Source, bundle.NASourceManifest)
	}

	// And the manifest that DOES claim FC 6 must still reach the check —
	// keeping WR-1 registered is only honest if a claiming candidate can still
	// exercise it.
	claiming, err := New(reg, cat, func() Options {
		o, _ := baseOptions(t, nil)
		o.ManifestPath = writeManifest(t, withWriteFunctionCodes("[6, 16]"))
		o.UIDs = []string{uid}
		return o
	}())
	if err != nil {
		t.Fatal(err)
	}
	cplan := claiming.Plan()
	if len(cplan) != 1 || cplan[0].OutOfScope() {
		t.Fatalf("a manifest claiming FC 6 still left WR-1 out of scope: %+v", cplan)
	}
	if !cplan[0].Implemented {
		t.Error("a manifest claiming FC 6 did not leave WR-1 implemented and reachable")
	}
}
