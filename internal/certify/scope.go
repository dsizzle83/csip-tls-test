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
// # Two shapes of axis, and both stay narrow on purpose
//
// scopeAxes (ManifestScope) excludes by DUT ROLE: every row of a given
// dut_role is in or out together, because the axis is a fact about a whole
// surface (the candidate is or is not a Secure SunSpec SERVER, full stop).
// That restraint is the point rather than an omission. A scope rule is a
// silent bulk exclusion: get one wrong and dozens of rows leave a campaign
// without anyone reading a line of output. So each entry here must be an
// EXPLICIT NEGATIVE — the manifest naming a set the row's own dut_role is not
// in — and cheap to check by eye against the catalog. Axes that could be
// derived from looser signals (a csip.role that "implies" the aggregator
// rows, a modbus_client.device_count of zero) are deliberately absent: the
// catalog already excludes the aggregator rows by profile, and a manifest
// declaring no southbound devices fails validation long before it gets here.
//
// requirementFields (RequirementScope, below) excludes by ROW: a single
// procedure whose in-scope-ness rests on a fact narrower than its whole
// dut_role — WR-1's subject is one function code, not the whole southbound
// client — carries that fact on the catalog row itself (Case.Requires)
// instead of growing scopeAxes for every such procedure. It is deliberately
// GENERIC in the same restrained spirit: catalog.go's loader refuses any
// Requires key this file does not list in requirementFields, at load, so a
// typo cannot sit silently inert forever, and the axis only ever EXCLUDES on
// a requirement the candidate specifically contradicted — an UNDECLARED field
// is inert, never treated as a negative.
//
// Adding a scopeAxes entry is one entry plus its test; adding one without a
// test is what TestScopeAxesAreDeclaredCoherently prevents. Adding a
// requirementFields entry is a catalog.go vocabulary entry plus one entry
// here plus its test.

import (
	"encoding/json"
	"fmt"
	"sort"
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

// ── Row-level manifest requirements ─────────────────────────────────────────

// requirementField is one manifest field a catalog row's Requires may name.
type requirementField struct {
	// Decode validates the catalog's raw requirement value and renders it for
	// prose. want is opaque outside this field's own Satisfied — the one thing
	// that lets Requires carry an int-list requirement for one field (write
	// function codes) and, one day, a string-list requirement for another (a
	// transport) without this shared plumbing caring which.
	//
	// It is called once at catalog load (catalog.go's validateCase), so a
	// malformed requirement is refused before any run starts, and again from
	// RequirementScope — where an error is then impossible, load already
	// proved it decodes.
	Decode func(raw json.RawMessage) (want any, rendered string, err error)
	// Satisfied reports whether the manifest DECLARED this field at all
	// (declared=false means the axis is INERT for this row: an undeclared
	// field excludes nothing, see CAMPAIGNS.md §5) and, when declared, whether
	// want is satisfied, plus a rendering of what the manifest itself
	// declares.
	Satisfied func(m *manifest.Manifest, want any) (declared, satisfied bool, haveRendered string)
	// Citation is further, field-level context worth printing beside the
	// mechanical fact — which PICS section a candidate's claim for this field
	// corresponds to, say. Optional.
	Citation string
}

// requirementFields is the whole vocabulary a catalog row's Requires may use.
// catalog.go's validateCase refuses any key not listed here, at load — see
// RequirementFieldKnown — so an unrecognised field can never sit silently
// inert forever, the same failure mode CatalogScope's own doc warns about.
var requirementFields = map[string]requirementField{
	"modbus_client.write_function_codes": {
		Decode:    decodeFunctionCodeList,
		Satisfied: satisfiesWriteFunctionCodes,
		Citation: "the candidate's PICS declares this axis in PICS_SUNSPEC_MODBUS.md §4.2 " +
			`("Read and write capability")`,
	},
}

// RequirementFieldKnown reports whether field is one requirementFields
// defines. catalog.go's loader calls it to refuse an unrecognised Requires key
// — naming it — before any run starts, rather than let the row's Requires sit
// permanently inert because nothing in this file was ever taught to read it.
func RequirementFieldKnown(field string) bool {
	_, ok := requirementFields[field]
	return ok
}

// RequirementFieldNames lists the known Requires keys, sorted, for an error
// message a reader can act on.
func RequirementFieldNames() []string {
	out := make([]string, 0, len(requirementFields))
	for k := range requirementFields {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// DecodeRequirement validates one Requires value against its field's known
// shape. catalog.go calls it at load time, once per (case, field) pair, so a
// malformed requirement is refused before any run starts. field must already
// be known (RequirementFieldKnown) — this does not check that itself, the
// same division every other validator in this package keeps: it validates the
// thing it owns and leaves "was this the right call to make" to the caller.
func DecodeRequirement(field string, raw json.RawMessage) error {
	_, _, err := requirementFields[field].Decode(raw)
	return err
}

// decodeFunctionCodeList is requirementFields' Decode for a Modbus function
// code list: a JSON array of at least one code, each in the protocol's
// one-byte range.
func decodeFunctionCodeList(raw json.RawMessage) (want any, rendered string, err error) {
	var codes []int
	if err := json.Unmarshal(raw, &codes); err != nil {
		return nil, "", fmt.Errorf("must be a JSON array of Modbus function codes: %w", err)
	}
	if len(codes) == 0 {
		return nil, "", fmt.Errorf("must name at least one function code")
	}
	for _, fc := range codes {
		if fc < 1 || fc > 127 {
			return nil, "", fmt.Errorf("%d is not a Modbus function code (1..127)", fc)
		}
	}
	return codes, renderFCList(codes), nil
}

// satisfiesWriteFunctionCodes is requirementFields' Satisfied for
// modbus_client.write_function_codes: the requirement holds when the
// candidate's OWN declared list shares at least one code with want.
func satisfiesWriteFunctionCodes(m *manifest.Manifest, want any) (declared, satisfied bool, haveRendered string) {
	if m == nil || !m.ModbusClient.WriteFunctionCodesDeclared() {
		return false, false, ""
	}
	have := renderFCList(m.ModbusClient.WriteFunctionCodes)
	for _, fc := range want.([]int) {
		if m.ModbusClient.ClaimsWriteFunctionCode(fc) {
			return true, true, have
		}
	}
	return true, false, have
}

// renderFCList renders Modbus function codes for prose: "FC 6" or "FC 6, FC 16".
func renderFCList(codes []int) string {
	parts := make([]string, len(codes))
	for i, fc := range codes {
		parts[i] = fmt.Sprintf("FC %d", fc)
	}
	return strings.Join(parts, ", ")
}

// RequirementScope reports whether a catalog row's own Requires excludes it,
// given what the candidate's manifest claims.
//
// Unlike ManifestScope's two hardcoded dut_role axes — every row of a role
// excluded together, because THAT axis is a fact about a whole surface — this
// reads the requirement off the ROW ITSELF (Case.Requires), so one procedure
// can be excluded on a fact specific to it without growing scopeAxes for
// every such procedure. WR-1 is the first: the catalog states it needs
// modbus_client.write_function_codes to include 6 (SS-MODBUS-CLIENT-CONF-v1.1
// §2.6.1's subject is a Modbus FC 06 write, and PICS_SUNSPEC_MODBUS.md §4.2
// rev g withdraws the claim: the client's WriteHolding path emits FC 16 even
// for a single register, so FC 06 never reaches the wire), and this axis
// reads that against whatever the candidate's OWN manifest says it emits.
//
// A field the manifest does not declare leaves this axis INERT for that row —
// see CAMPAIGNS.md §5, "No manifest means assert everything": a row is
// excluded only when the candidate said something specific enough to
// contradict the requirement, never by the manifest's silence on the matter.
// That is also why this stays a Plan()-time decision beside ManifestScope
// rather than something the row's own check decides: a manifest that DOES
// claim the function code must still reach the check and its wire citation
// (see suitemodbusclient's checkWR1), which a check that could exclude its
// own row could never be trusted to do honestly.
func RequirementScope(m *manifest.Manifest, c *Case) (ScopeDecision, bool) {
	if c == nil || len(c.Requires) == 0 {
		return ScopeDecision{}, false
	}
	fields := make([]string, 0, len(c.Requires))
	for f := range c.Requires {
		fields = append(fields, f)
	}
	sort.Strings(fields)
	for _, field := range fields {
		rf, ok := requirementFields[field]
		if !ok {
			// catalog.go's loader refuses an unrecognised field before any run
			// starts (RequirementFieldKnown). Reaching this means a Case was
			// built some other way — by hand, in a test — bypassing that
			// refusal. Fail loudly rather than silently treat the row as
			// unconstrained, the same posture AttachWindow's "replacing a
			// window" refusal takes toward a different bypassed invariant.
			panic(fmt.Sprintf("certify: %s requires[%q], which no scope axis evaluates "+
				"(catalog load should have refused this)", c.UID, field))
		}
		want, wantRendered, err := rf.Decode(c.Requires[field])
		if err != nil {
			panic(fmt.Sprintf("certify: %s requires[%q] no longer decodes: %v (catalog load should have "+
				"refused this)", c.UID, field, err))
		}
		declared, satisfied, haveRendered := rf.Satisfied(m, want)
		if !declared || satisfied {
			continue
		}
		detail := fmt.Sprintf("%s: candidate declares %s; %s requires %s (%s, sha256 %s)",
			field, haveRendered, c.UID, wantRendered, m.Path(), short(m.SHA256(), 16))
		if rf.Citation != "" {
			detail += "; " + rf.Citation
		}
		return ScopeDecision{
			Reason: fmt.Sprintf("this row requires the candidate to have claimed %s for %s, and the "+
				"candidate's manifest does not: it declares %s", wantRendered, field, haveRendered),
			Source: bundle.NASourceManifest,
			Detail: detail,
		}, true
	}
	return ScopeDecision{}, false
}
