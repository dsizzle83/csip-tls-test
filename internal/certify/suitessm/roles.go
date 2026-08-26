package suitessm

// roles.go decides, for every assertion this suite mints, WHICH SECURE SUNSPEC
// DIRECTION it is about — and takes the client-direction ones out of scope when
// the candidate does not claim that direction.
//
// # The problem this solves
//
// SSM-CONF-v0.8 is written for a device that may be an mbaps SERVER, an mbaps
// CLIENT, or both, and its Table 1 says which of the three each row is for. Most
// of the rows this suite implements are marked "Both", and their procedures are
// split accordingly: §2.5.1.1 is the Server Procedure, §2.5.1.2 the Client
// Procedure, and the criteria in §2.5.1.3 are a list with a line for each.
//
// The catalog's `dut_role` is ONE SCALAR PER CASE. That is the right grain for a
// row whose whole subject is one direction — PKI-009, PROT-003 and RBAC-011 are
// `mbaps-client`, and internal/certify/scope.go takes those out of scope, whole,
// against a server-only manifest. It is the wrong grain for a "Both" row, which
// is `mbaps-server` in the catalog because the server surface is what the bench
// drives, and which STILL contains one client-procedure assertion apiece.
//
// So a server-only candidate — which is what configs/candidate.json declares:
// `"secure_sunspec": {"roles": ["server"]}` — used to run eleven assertions
// about a direction it does not claim, wait 45 seconds each for a ClientHello
// that means nothing to its certification, and record a SKIP. Those SKIPs are
// indistinguishable, in a report, from an evidence gap somebody should go and
// fix. CRYP-001 is the worked example: six server assertions PASS, assertion 7
// waits out the gateway's southbound poll interval and SKIPs, and the row reads
// as unfinished work about a device that has no client direction to finish.
//
// # The grain, and why it is a table
//
// Every assertion gets a direction from the table below — never from a heuristic
// over the claim text, because the direction decides whether a criterion is
// ASSERTED or DECLARED OUT OF SCOPE, and a scope decision that can be changed by
// rewording a sentence is not a scope decision. The table is transcribed from
// the document (Table 1's Role column, and which of a case's procedure
// subsections each assertion implements) and TestEverySSMAssertionCarriesARole
// holds it against both the catalog and the suite's own source.
//
// A case declares a Default so that "everything else in this row is
// server-direction" is a written statement rather than an omission. That is the
// distinction the drift guard rests on: an unlisted assertion is not unlabelled,
// it carries the row's declared default — and any NEW assertion whose claim
// carries the document's "[C]" marker and is not in the table fails the guard.
//
// # What the decision does
//
// A client-direction assertion, on a run whose manifest does not claim the
// client direction, becomes bundle.VerdictNotApplicable with a reason naming the
// unclaimed role and the candidate profile, sourced to the manifest. It is NOT
// deleted: the claim, the method and the citation-less record stay in the
// bundle, so a reader sees which criterion was excluded and on whose authority.
//
// N/A sits at severity 0, so a case whose remaining server assertions all pass
// now rolls up to PASS instead of carrying a SKIP nobody can act on. Nothing
// else moves: an N/A cannot lower a FAIL, and a run with no manifest — where
// RunCtx.RoleClaimed answers true for every role — behaves exactly as it did
// before this file existed.

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"csip-tls-test/internal/certify"
	"csip-tls-test/internal/certify/manifest"
	"csip-tls-test/internal/evidence/bundle"
)

// Direction is the Secure SunSpec direction an assertion — or a whole row — is
// about.
type Direction string

// The directions, spelled as SSM-CONF-v0.8 Table 1's Role column spells them.
const (
	// DirServer — the criterion is about the DUT as an mbaps SERVER: evidence
	// from the bench's own connections to the DUT's listener.
	DirServer Direction = "server"
	// DirClient — the criterion is about the DUT as an mbaps CLIENT: evidence
	// from the DUT's southbound connections to the bench's device sim. These
	// are the assertions a server-only candidate takes out of scope.
	DirClient Direction = "client"
	// DirBoth — the criterion is about the DUT as a whole and not about either
	// socket: a configuration read, a certificate store, a vendor declaration.
	// It stays in scope whichever direction is claimed, because a DUT-wide
	// capability is not made irrelevant by an unclaimed direction.
	DirBoth Direction = "both"
)

// Valid reports whether d is one of the three.
func (d Direction) Valid() bool {
	switch d {
	case DirServer, DirClient, DirBoth:
		return true
	}
	return false
}

// claimRule maps a claim PREFIX to the direction of the procedure step that
// claim implements. A prefix rather than a whole claim because several claims
// are built with fmt.Sprintf and carry run-time values in their tails.
type claimRule struct {
	Prefix string
	Dir    Direction
}

// caseRoles is one case's assertion-direction declaration.
type caseRoles struct {
	// Case is SSM-CONF-v0.8 Table 1's Role column for this row, verbatim. It
	// is not used to decide anything at run time; it is the document fact the
	// drift guard holds the rest of the entry against.
	Case Direction
	// Default is the direction of every assertion this case mints that no rule
	// below matches. It is required: an absent default would make "unlabelled"
	// indistinguishable from "server", which is the confusion this file exists
	// to remove.
	Default Direction
	// Rules are the exceptions to Default, in order. First match wins.
	Rules []claimRule
}

// assertionRoles is the table. One entry per registered case, no exceptions —
// TestEverySSMAssertionCarriesARole fails on a registered case that is missing
// and on an entry naming a case nobody registers.
//
// The Case column is SSM-CONF-v0.8 §2.3 Table 1 ("Secure SunSpec Tests"),
// transcribed as printed — including RBAC-011's "Cient", read as Client.
var assertionRoles = map[string]caseRoles{
	// ── §2.4 TLS Fundamentals ───────────────────────────────────────────────
	"TLSF-001": {Case: DirBoth, Default: DirServer, Rules: []claimRule{
		{"SunSpecTCP-17/19 [C]:", DirClient},
	}},
	"TLSF-002": {Case: DirBoth, Default: DirServer, Rules: []claimRule{
		{"SunSpecTCP-18 [C]:", DirClient},
	}},
	// TLSF-003/004/005/006 are Table 1 "Server" rows: negative and
	// packet-inspection procedures with no Client Procedure subsection at all.
	"TLSF-003": {Case: DirServer, Default: DirServer},
	"TLSF-004": {Case: DirServer, Default: DirServer},
	"TLSF-005": {Case: DirServer, Default: DirServer},
	"TLSF-006": {Case: DirServer, Default: DirServer},

	// ── §2.5 Cryptography ───────────────────────────────────────────────────
	"CRYP-001": {Case: DirBoth, Default: DirServer, Rules: []claimRule{
		{"SunSpecTCP-17 [C]:", DirClient},
	}},
	"CRYP-002": {Case: DirBoth, Default: DirServer, Rules: []claimRule{
		{"SunSpecTCP-18 [C]:", DirClient},
	}},
	// CRYP-003's client half in the document is the management-plane audit, not
	// a wire observation, so this row has no [C] assertion. The disable
	// MECHANISM the suite evidences off-wire from the DUT's own configuration
	// governs both directions.
	"CRYP-003": {Case: DirBoth, Default: DirServer, Rules: []claimRule{
		{"SunSpecTCP-20: the EUT provides a mechanism to disable specific cipher suites", DirBoth},
	}},
	"CRYP-004": {Case: DirBoth, Default: DirServer, Rules: []claimRule{
		{"SunSpecTCP-43/44 [C]:", DirClient},
	}},
	"CRYP-005": {Case: DirBoth, Default: DirServer, Rules: []claimRule{
		{"SunSpecTCP-54/55 [C]:", DirClient},
	}},
	"CRYP-006": {Case: DirBoth, Default: DirServer, Rules: []claimRule{
		{"SunSpecTCP-15/16 [C]:", DirClient},
		// The vendor's PICS lists what the IMPLEMENTATION offers, in either
		// direction; it is not a fact about one socket.
		{"SunSpecTCP-15/16: every cipher suite in the vendor's PICS", DirBoth},
	}},
	"CRYP-007": {Case: DirBoth, Default: DirServer, Rules: []claimRule{
		{"SunSpecTCP-53 [C]:", DirClient},
	}},

	// ── §2.6 Public Key Infrastructure ──────────────────────────────────────
	"PKI-001": {Case: DirBoth, Default: DirServer},
	"PKI-002": {Case: DirBoth, Default: DirServer, Rules: []claimRule{
		// Certificate management is a device capability reached through the
		// management plane, not through either mbaps socket.
		{"SunSpecTCP-3: root certificates and the server certificate can be securely added", DirBoth},
	}},
	"PKI-003": {Case: DirBoth, Default: DirServer},
	"PKI-004": {Case: DirBoth, Default: DirServer, Rules: []claimRule{
		{"SunSpecTCP-51 [C]:", DirClient},
	}},
	"PKI-006": {Case: DirBoth, Default: DirServer},
	"PKI-007": {Case: DirBoth, Default: DirServer},
	"PKI-008": {Case: DirBoth, Default: DirServer},
	// PKI-009 is the one row whose Table 1 Role ("Both") and catalog dut_role
	// ("mbaps-client") differ — see clientOnlyByCatalog. Every observable this
	// suite reaches for it is the DUT's southbound trust posture, so the whole
	// row defaults to the client direction.
	"PKI-009": {Case: DirBoth, Default: DirClient},

	// ── §2.7 Protocol ───────────────────────────────────────────────────────
	"PROT-001": {Case: DirBoth, Default: DirServer},
	"PROT-002": {Case: DirBoth, Default: DirServer, Rules: []claimRule{
		{"SunSpecTCP-59 [C]:", DirClient},
	}},
	// PROT-003 is a Table 1 "Client" row: SunSpecTCP-61 is a requirement on the
	// EUT-C's ClientHello, so the row defaults to the client direction. The
	// suite additionally asserts the SERVER corollary — that the DUT's own
	// listener selects NULL compression — which the row does not require and
	// which is a server-direction observation.
	"PROT-003": {Case: DirClient, Default: DirClient, Rules: []claimRule{
		{"SunSpecTCP-61 (server corollary):", DirServer},
	}},
	"PROT-004": {Case: DirBoth, Default: DirServer, Rules: []claimRule{
		{"SunSpecTCP-62 [C]:", DirClient},
	}},

	// ── §2.8 Role-Based Access Control ──────────────────────────────────────
	// Every RBAC row the suite implements is a Table 1 "Server" or "Both" row
	// whose observable is the DUT's own authorization behaviour on its server
	// socket — except RBAC-011, which is the Client row.
	"RBAC-001": {Case: DirServer, Default: DirServer},
	"RBAC-002": {Case: DirServer, Default: DirServer},
	"RBAC-004": {Case: DirServer, Default: DirServer},
	"RBAC-005": {Case: DirServer, Default: DirServer},
	"RBAC-006": {Case: DirBoth, Default: DirServer},
	"RBAC-007": {Case: DirBoth, Default: DirServer},
	"RBAC-008": {Case: DirServer, Default: DirServer},
	"RBAC-009": {Case: DirServer, Default: DirServer},
	"RBAC-010": {Case: DirServer, Default: DirServer},
	"RBAC-011": {Case: DirClient, Default: DirClient},
	"RBAC-012": {Case: DirServer, Default: DirServer},

	// ── §2.9 Operational Security ───────────────────────────────────────────
	"OPS-001": {Case: DirBoth, Default: DirServer, Rules: []claimRule{
		// A vendor's export declaration is a document about the product, not
		// about a direction.
		{"SunSpecTCP-58: the vendor's Cryptographic Export Declaration", DirBoth},
	}},
}

// clientOnlyByCatalog records the rows whose catalog dut_role is mbaps-client
// while SSM-CONF-v0.8 Table 1 marks them otherwise, with the reason the two
// disagree.
//
// It exists so the disagreement is a written decision rather than a test
// nobody can make pass. The catalog scalar names the surface THIS BENCH DRIVES;
// Table 1 names the roles the DOCUMENT's procedure applies to. Where the whole
// of a row's observable evidence lives on the DUT's client side, the catalog
// puts it on mbaps-client even for a row the document marks "Both", and the
// effect — the row is out of scope for a server-only candidate — is the same
// one this file reaches for its per-assertion [C] halves.
var clientOnlyByCatalog = map[string]string{
	"PKI-009": "SunSpecTCP-49 is optional self-signed support for LOCAL communication, and every " +
		"observable this bench can reach for it is the DUT's SOUTHBOUND client trust posture — its " +
		"server side offers nothing to measure — so the catalog scalar is mbaps-client although Table 1 " +
		"marks the row Both",
}

// directionOf returns the direction of one assertion. It is TOTAL: a case with
// no table entry (which the drift guard makes impossible) falls back to
// DirServer, because the alternative — treating an unknown assertion as
// client-direction — would silently take a measured criterion out of scope.
func directionOf(caseID, claim string) Direction {
	e, ok := assertionRoles[caseID]
	if !ok {
		return DirServer
	}
	for _, r := range e.Rules {
		if strings.HasPrefix(claim, r.Prefix) {
			return r.Dir
		}
	}
	return e.Default
}

// CaseDirection returns SSM-CONF-v0.8 Table 1's Role column for a case id, so a
// report or an audit can print the document's own classification rather than
// re-deriving it.
func CaseDirection(caseID string) (Direction, bool) {
	e, ok := assertionRoles[caseID]
	return e.Case, ok
}

// AssertionRoleIDs lists the cases the table covers, sorted. It is exported for
// the suite's own audits.
func AssertionRoleIDs() []string {
	out := make([]string, 0, len(assertionRoles))
	for id := range assertionRoles {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

// caseID reduces a catalog uid to the bare in-document id the table is keyed by.
func caseID(uid string) string {
	if _, after, ok := strings.Cut(uid, "::"); ok {
		return after
	}
	return uid
}

// candidateScope is the part of the run context this file reads: what the
// candidate CLAIMS, and the declaration behind it.
//
// It is an interface rather than *certify.RunCtx for one reason, and it is the
// same reason certify.RunCtx exports AttachWindow: the decision this file makes
// is worth testing directly, and a RunCtx carrying a manifest can only be built
// by the runner. Two methods is the whole surface — a check cannot reach
// anything else through it, and *certify.RunCtx satisfies it as it stands, so
// the production path is not a variant of the tested one.
type candidateScope interface {
	// RoleClaimed reports whether the candidate claims a Secure SunSpec
	// direction. A nil manifest answers true for every role: silence is not a
	// disclaimer.
	RoleClaimed(role string) bool
	// Manifest is the declaration itself, for the reason and the citation.
	Manifest() *manifest.Manifest
}

// roleScoped wraps a check so every assertion it produces — in the live phase
// and in the citation phase — passes through the direction decision.
//
// It is applied by Register to EVERY registration, so a new check inherits the
// rule without having to know it exists. It can only ever move an assertion to
// N/A: it never touches a verdict otherwise, never reorders, and never changes
// the Result's own declared verdict — a check that could lower its own verdict
// from here could declare its way out of a failure, which is exactly what
// certify.NotApplicable's doc forbids at case level and this file honours at
// assertion level.
func roleScoped(uid string, check certify.Check) certify.Check {
	id := caseID(uid)
	return func(ctx context.Context, rc *certify.RunCtx) (certify.Result, error) {
		res, err := check(ctx, rc)
		if err != nil {
			return res, err
		}
		return scopeResult(rc, id, res), nil
	}
}

// scopeResult applies the direction decision to one check's whole result: the
// assertions it produced in the live phase, and — through a wrapped callback —
// the ones it will mint from the capture, which is where every [C] half in this
// suite actually lives.
//
// It is separate from roleScoped so the decision can be exercised with a
// candidate declaration and no bench; roleScoped is the adapter that hands it
// the run context.
func scopeResult(sc candidateScope, id string, res certify.Result) certify.Result {
	if sc.RoleClaimed("client") {
		return res
	}
	res.Assertions = scopeAssertionRoles(sc, id, res.Assertions)
	if cite := res.Cite; cite != nil {
		res.Cite = func(cctx context.Context, ev *certify.Evidence) ([]certify.Assertion, error) {
			as, cerr := cite(cctx, ev)
			if cerr != nil {
				return nil, cerr
			}
			return scopeAssertionRoles(sc, id, as), nil
		}
	}
	return res
}

// scopeAssertionRoles rewrites this case's client-direction assertions to NOT
// APPLICABLE.
func scopeAssertionRoles(sc candidateScope, id string, as []certify.Assertion) []certify.Assertion {
	for i := range as {
		if directionOf(id, as[i].Claim) != DirClient {
			continue
		}
		if as[i].Verdict == certify.NotApplicable {
			continue
		}
		as[i] = notApplicableClient(sc, as[i])
	}
	return as
}

// notApplicableClient turns one assertion into the out-of-scope record.
//
// The claim and the method survive: a reader must be able to see WHICH
// criterion was excluded, and by what method it would have been asserted, or
// the record is indistinguishable from a row quietly dropped. The citation does
// not survive — an out-of-scope criterion was not measured, and a digest beside
// it would say it was.
//
// # An observation that was nevertheless made is kept
//
// Most of the time the excluded assertion had reached no conclusion: nothing
// asked the DUT's southbound client to dial, so the criterion SKIPped. But the
// gateway does hold a southbound mbaps client, and a run whose window happens
// to catch its reconnect can reach a real PASS, WARN or FAIL on a direction the
// candidate does not claim. Discarding that would make this function a way to
// delete an inconvenient observation, which is precisely what
// bundle.VerdictNotApplicable's doc says the verdict must never be usable for.
//
// So a DECIDED original verdict is carried into the note, verbatim, beside the
// scope declaration. The row is still out of scope — the standard's [C] criteria
// are requirements on an EUT-C and this candidate is not one — and the reader
// still sees what the bench saw.
func notApplicableClient(sc candidateScope, a certify.Assertion) certify.Assertion {
	reason, detail := unclaimedClientReason(sc.Manifest())
	note := fmt.Sprintf("NOT APPLICABLE — declared by: %s; declaration: %s",
		bundle.NASourceManifest, detail)
	if a.Verdict != certify.Skip && a.Verdict != "" {
		note += fmt.Sprintf(". This run nevertheless observed the DUT's southbound client and reached %s "+
			"on this criterion, which is recorded here rather than discarded, and bears on no verdict: %s",
			a.Verdict, a.Observed)
	}
	return certify.Assertion{
		Claim:    a.Claim,
		Method:   a.Method,
		Verdict:  certify.NotApplicable,
		Observed: reason,
		Note:     note,
	}
}

// unclaimedClientReason renders the sentence and the declaration behind it.
//
// A nil manifest cannot reach here — RoleClaimed answers true for every role
// without one — but the nil case is still written out rather than left to
// panic, because "the code path is unreachable" is a claim that ages badly and
// a nil-safe sentence costs three lines.
func unclaimedClientReason(m *manifest.Manifest) (string, string) {
	if m == nil {
		return "the Secure SunSpec CLIENT direction is not claimed by this candidate",
			"secure_sunspec.roles (no manifest was supplied)"
	}
	roles := strings.Join(m.SecureSunSpec.Roles, ", ")
	if roles == "" {
		roles = "(none)"
	}
	reason := fmt.Sprintf(
		"this criterion is a [C] step of the procedure — it is about the candidate as a Secure SunSpec "+
			"Modbus CLIENT — and candidate profile %q does not claim that direction: secure_sunspec.roles "+
			"declares [%s]. There is no client direction on this candidate to measure, so no outcome about "+
			"it exists to report",
		m.Profile, roles)
	detail := fmt.Sprintf("secure_sunspec.roles = [%s] (%s, sha256 %s)",
		roles, m.Path(), shortDigest(m.SHA256()))
	return reason, detail
}

// shortDigest trims a hex digest for a one-line record; a reader who wants the
// whole thing hashes the manifest copy the bundle carries.
func shortDigest(s string) string {
	if len(s) <= 16 {
		return s
	}
	return s[:16] + "…"
}
