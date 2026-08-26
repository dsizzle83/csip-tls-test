package certify

// scope.go decides which catalog rows are OUT OF SCOPE for the candidate under
// test, from the candidate's own declaration.
//
// # Two different questions, two different sources
//
// The catalog already answers "is this row required of the claimed PROFILE?" —
// its `applicable` field, set from the published conformance matrix. That is a
// fact about the standard and is the same for every device certifying under that
// profile.
//
// This file answers the other one: "is this row about something THIS CANDIDATE
// is?" A row exercising the Secure SunSpec CLIENT direction is not a weaker or
// harder row for a candidate that declares itself server-only — it is a row
// about a direction the candidate does not have. Running it produces a verdict
// about nothing; skipping it silently produces a SKIP line indistinguishable
// from an evidence gap. Declaring it NOT APPLICABLE, with the manifest key that
// decided it, is the only honest third option, and it is what
// bundle.VerdictNotApplicable exists for.
//
// # Deliberately one axis
//
// Only the Secure SunSpec DIRECTION axis is implemented, and that restraint is
// the point rather than an omission. A scope rule is a silent bulk exclusion:
// get one wrong and dozens of rows leave a campaign without anyone reading a
// line of output. So the rules here must each be an EXPLICIT NEGATIVE — the
// manifest naming a set the row's own dut_role is not in — and each must be
// cheap to check by eye against the catalog. Axes that could be derived from
// looser signals (a csip.role that "implies" the aggregator rows, a
// modbus_client.device_count of zero) are deliberately absent: the catalog
// already excludes the aggregator rows by profile, and a manifest declaring no
// southbound devices fails validation long before it gets here.
//
// Adding an axis is one entry in scopeAxes plus its test. Adding one without a
// test is what TestScopeAxesAreDeclaredCoherently prevents.

import (
	"fmt"
	"strings"

	"csip-tls-test/internal/certify/manifest"
	"csip-tls-test/internal/evidence/bundle"
)

// ScopeDecision is a row placed out of scope, and the declaration that did it.
type ScopeDecision struct {
	// Reason is the sentence a reader of the bundle gets.
	Reason string
	// Source is whose declaration decided it.
	Source bundle.NASource
	// Detail is the exact declaration, so the reader can go and look.
	Detail string
	// Contested marks a decision that CONTRADICTS the catalog: the catalog
	// marks the row applicable to the claimed profile and the candidate's own
	// manifest says it is out of scope. The decision still stands — the
	// manifest is the candidate's own statement about itself — but it is
	// reported prominently rather than applied quietly, because one of the two
	// documents is wrong and the campaign owner has to be the one to say which.
	Contested bool
}

// Record renders the decision for the bundle.
func (d ScopeDecision) Record() *bundle.NotApplicable {
	return &bundle.NotApplicable{Reason: d.Reason, Source: d.Source, Detail: d.Detail}
}

// scopeAxis is one manifest declaration matched against one catalog dut_role.
type scopeAxis struct {
	// Role is the catalog dut_role this axis governs.
	Role DUTRole
	// Claim is the manifest role that must be declared for that dut_role to be
	// in scope.
	Claim string
	// Field names the manifest key, for the record's Detail.
	Field string
	// Direction is the human name of what is being excluded.
	Direction string
}

// scopeAxes are the manifest-derived scope rules. See the file doc for why there
// is one axis and not five.
var scopeAxes = []scopeAxis{
	{
		Role:      RoleMBAPSServer,
		Claim:     "server",
		Field:     "secure_sunspec.roles",
		Direction: "Secure SunSpec Modbus SERVER",
	},
	{
		Role:      RoleMBAPSClient,
		Claim:     "client",
		Field:     "secure_sunspec.roles",
		Direction: "Secure SunSpec Modbus CLIENT",
	},
}

// ManifestScope reports whether the candidate's declaration puts a row out of
// scope.
//
// A nil manifest excludes nothing at all. That is deliberate and it is what
// keeps a run with no -manifest byte-identical to one from before this file
// existed: an absent declaration is not a declaration of absence, and inferring
// scope from silence is exactly the guessing this whole mechanism replaces.
func ManifestScope(m *manifest.Manifest, c *Case) (ScopeDecision, bool) {
	if m == nil || c == nil {
		return ScopeDecision{}, false
	}
	for _, ax := range scopeAxes {
		if c.DUTRole != ax.Role {
			continue
		}
		if m.SecureSunSpec.HasRole(ax.Claim) {
			return ScopeDecision{}, false
		}
		return ScopeDecision{
			Reason: fmt.Sprintf("this row's subject is the %s direction (catalog dut_role %q), and the "+
				"candidate manifest does not claim it: %s declares [%s]. There is no such direction on "+
				"this candidate to measure",
				ax.Direction, c.DUTRole, ax.Field, strings.Join(m.SecureSunSpec.Roles, ", ")),
			Source:    bundle.NASourceManifest,
			Detail:    fmt.Sprintf("%s = [%s] (%s, sha256 %s)", ax.Field, strings.Join(m.SecureSunSpec.Roles, ", "), m.Path(), short(m.SHA256(), 16)),
			Contested: c.Applicable,
		}, true
	}
	return ScopeDecision{}, false
}

// CatalogScope reports the catalog's own applicability decision as a scope
// decision, for a row no suite implements.
//
// A row the catalog marks inapplicable AND that nothing implements used to be a
// SKIP reading "not applicable to this product: <reason>" — the right words
// carried on the wrong verdict, counted in the same number as a row whose check
// could not run. An implemented-but-inapplicable row is NOT touched here: the
// framework deliberately runs those and reports them as informative, and turning
// them into N/A would delete the informative tally entirely.
func CatalogScope(c *Case) (ScopeDecision, bool) {
	if c == nil || c.Applicable {
		return ScopeDecision{}, false
	}
	reason := strings.TrimSpace(c.ApplicabilityReason)
	if reason == "" {
		reason = "the catalog marks this row not applicable to the claimed profile and records no reason"
	}
	return ScopeDecision{
		Reason: firstSentence(reason),
		Source: bundle.NASourceCatalog,
		Detail: fmt.Sprintf("catalog %s: applicable=false", c.UID),
	}, true
}
