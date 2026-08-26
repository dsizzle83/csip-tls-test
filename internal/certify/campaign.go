package certify

// campaign.go is the answer to "what, exactly, is this run evidence FOR?"
//
// # The hole a campaign closes
//
// Until now the only way to say what a run covered was -suite, -doc and -uid:
// three free-form selectors with no notion of a whole, no notion of a
// precondition, and no notion of whether the result was allowed to decide
// anything. Three consequences followed, all of them found in shipped bundles.
//
// A run could select rows from protocols that cannot both be live at once — the
// CSIP control path and the Secure SunSpec northbound write path arbitrate for
// the same DER, so whichever one is not in authority reports its rows against a
// deliberate refusal — and nothing said so.
//
// A run could select ZERO rows and exit 0 (see explainEmptySelection): a clean
// summary over an empty bundle, indistinguishable at the exit code from a clean
// summary over a full one.
//
// And a whole-catalog run — every suite at once, which is the shape most of the
// archive is in — could be, and was, read as a certification result, when its
// unselectable preconditions guarantee that a large part of it measured the
// arbitration layer rather than the rows' own subjects.
//
// A campaign is the fix: a NAMED, CLOSED selection with a stated precondition
// that is PROVEN before case one, and a bundle that records both. Everything
// else stays available and is now explicitly EXPLORATORY — still run, still
// bundled, still verified, and marked non-gating so nobody has to reconstruct
// from a command line whether a bundle was allowed to decide a release.
//
// # Why three
//
// One per protocol lane the product owns, because the lane is precisely the unit
// that has a single coherent authority precondition:
//
//	csip           the DUT as a 2030.5 DER client, CSIP in authority
//	mbaps          the DUT as a Secure SunSpec Modbus server, mbaps in authority
//	modbus-client  the DUT as a southbound Modbus client, under whatever posture
//	               the candidate manifest declares
//
// The suites each expands to are the audit's (LAB29-001), not this file's
// invention, and campaignSuitesExist pins every one of them against the linked
// registry so a renamed suite cannot leave a campaign silently selecting less
// than it claims.

import (
	"fmt"
	"sort"
	"strings"
)

// Campaign names one closed, gating selection.
type Campaign string

// The campaigns. A value outside this set is refused by LookupCampaign.
const (
	// CampaignCSIP measures the DUT as an IEEE 2030.5 / CSIP DER client.
	CampaignCSIP Campaign = "csip"
	// CampaignMBAPS measures the DUT as a Secure SunSpec Modbus (mbaps)
	// northbound server, together with the SunSpec Modbus server behaviour and
	// the PKI rows that server's identity rests on.
	CampaignMBAPS Campaign = "mbaps"
	// CampaignModbusClient measures the DUT as a southbound SunSpec Modbus
	// client polling its DER.
	CampaignModbusClient Campaign = "modbus-client"
)

// CampaignSpec is one campaign's definition.
type CampaignSpec struct {
	// Name is the -campaign value.
	Name Campaign
	// Suites are the suites the campaign expands to. -suite is then not
	// accepted: a campaign is a closed selection or it is not a campaign.
	Suites []string
	// Authority is the DUT arbitration posture the campaign REQUIRES to be live
	// before case one. AuthorityAny means the campaign pins no single posture
	// and instead requires that whatever is live is one the candidate manifest
	// declares.
	Authority AuthorityProfile
	// Summary is the one-line description printed in -help and the console.
	Summary string
	// Precondition is the prose an operator needs when the check refuses: what
	// the bench must look like for this campaign to mean anything.
	Precondition string
}

// ApplicableOnly is true for every campaign: a campaign's subject is the rows
// the product CLAIMS, and a row the catalog marks inapplicable to the claimed
// profile is not part of any claim. Exploratory runs are where the informative
// rows are examined.
func (s CampaignSpec) ApplicableOnly() bool { return true }

// campaigns is the table. It is a slice rather than a map so -help and the docs
// print them in a stable, meaningful order rather than a random one.
var campaigns = []CampaignSpec{
	{
		Name:      CampaignCSIP,
		Suites:    []string{"csip"},
		Authority: AuthorityCSIP,
		Summary:   "the DUT as an IEEE 2030.5 / CSIP DER client",
		Precondition: "the DUT's live control authority must be \"csip\": the CSIP control path owns " +
			"lexa/desired/*, so a published DERControl actually reaches the DER. Under \"mbaps\" every " +
			"control row in this campaign measures the arbitration layer declining to hand over, not the " +
			"DUT's handling of the control.",
	},
	{
		Name:      CampaignMBAPS,
		Suites:    []string{"ssm", "modbus-server", "pki"},
		Authority: AuthorityMBAPS,
		Summary:   "the DUT as a Secure SunSpec Modbus northbound server (with its SunSpec server and PKI rows)",
		Precondition: "the DUT's live control authority must be \"mbaps\": the northbound Modbus write " +
			"path owns lexa/desired/*. Under \"csip\" the D1 lock-screen overlay " +
			"(configs/rbac/overlays.d/10-csip-mode.json) denies every model 704-712 control write for " +
			"EVERY role, SuperAdministratorSunSpec included, by design — so every RBAC and write row in " +
			"this campaign would measure that overlay instead of its own subject. That is exactly " +
			"RBAC-002-MODEL704-REG40298-WRITE-DENIED-ALL-ROLES (lexa-gw/docs/known_issues.json).",
	},
	{
		Name:      CampaignModbusClient,
		Suites:    []string{"modbus-client"},
		Authority: AuthorityAny,
		Summary:   "the DUT as a southbound SunSpec Modbus client polling its DER",
		Precondition: "this campaign pins no single authority: the DUT's southbound polling runs under " +
			"every posture, and its write rows are driven by whichever control path the candidate " +
			"declares. What IS required is that the live posture be one the candidate manifest's " +
			"authority_profiles list claims, and that the southbound fixture be the non-conflicting " +
			"shadow setup the profile declares — a second controller writing the same DER would make " +
			"every observed register a fact about two writers.",
	},
}

// Campaigns returns the campaign table.
func Campaigns() []CampaignSpec { return append([]CampaignSpec(nil), campaigns...) }

// CampaignNames lists the -campaign values, in table order.
func CampaignNames() []string {
	out := make([]string, len(campaigns))
	for i, c := range campaigns {
		out[i] = string(c.Name)
	}
	return out
}

// LookupCampaign resolves a -campaign value, fold-insensitively.
func LookupCampaign(name string) (CampaignSpec, bool) {
	for _, c := range campaigns {
		if strings.EqualFold(string(c.Name), name) {
			return c, true
		}
	}
	return CampaignSpec{}, false
}

// campaignSuitesExist reports the campaign suites the registry does not have.
//
// It is called from New for the campaign actually selected, and exercised across
// the WHOLE table by TestCampaignSuitesAllExist against the linked registry. A
// campaign naming a suite nobody registers would silently select fewer rows than
// it claims, which is the failure mode this whole file exists to remove.
func campaignSuitesExist(reg *Registry, s CampaignSpec) []string {
	return unknownSuites(reg, s.Suites)
}

// CampaignError explains a rejected -campaign invocation. It is a type so the
// several refusals below read the same way and a test can assert on the cause
// rather than on a paragraph.
type CampaignError struct {
	Campaign string
	Reason   string
}

func (e *CampaignError) Error() string {
	if e.Campaign == "" {
		return "certify: -campaign: " + e.Reason
	}
	return fmt.Sprintf("certify: -campaign %s: %s", e.Campaign, e.Reason)
}

// resolveCampaign applies -campaign to the options: it validates the value, the
// flag combinations it forbids, and expands the selection.
//
// It runs BEFORE the catalog filter is built, so the expansion is a real
// selection and not a post-hoc dispatch filter — the distinction Runner.filter's
// own doc explains at length.
func resolveCampaign(opts *Options) (CampaignSpec, error) {
	if opts.Campaign == "" {
		return CampaignSpec{}, nil
	}
	spec, ok := LookupCampaign(string(opts.Campaign))
	if !ok {
		return CampaignSpec{}, &CampaignError{
			Campaign: string(opts.Campaign),
			Reason:   "no such campaign (have: " + strings.Join(CampaignNames(), ", ") + ")",
		}
	}
	if len(opts.Suites) > 0 {
		return CampaignSpec{}, &CampaignError{
			Campaign: string(spec.Name),
			Reason: fmt.Sprintf("cannot be combined with -suite %s. A campaign IS a suite selection "+
				"(%s), closed on purpose: a bundle that claims to be the %s campaign and contains some "+
				"other set of rows is worse than one that claims nothing. Drop -campaign to run an "+
				"exploratory selection, or drop -suite to run the campaign",
				strings.Join(opts.Suites, ","), strings.Join(spec.Suites, " + "), spec.Name),
		}
	}
	if opts.ManifestPath == "" {
		return CampaignSpec{}, &CampaignError{
			Campaign: string(spec.Name),
			Reason: "requires -manifest <path>: a campaign's scope is decided against the CANDIDATE's own " +
				"declaration of what it is, and without one every scope decision in the bundle would be " +
				"this tool's guess recorded as the product's claim. The device installs it at " +
				"/etc/lexa/candidate.json",
		}
	}
	opts.Suites = append([]string(nil), spec.Suites...)
	opts.ApplicableOnly = spec.ApplicableOnly()
	return spec, nil
}

// explainEmptySelection returns an error for a selection that matches no case,
// naming the offending selectors and — where the catalog can say so — what they
// WOULD have matched.
//
// # Why this is an error and not an empty run
//
// `-suite modbus-server -uid ssm-conf-v0.8::RBAC-002` selects nothing: the uid
// exists, the suite exists, and no case is in both. Every downstream check then
// passes VACUOUSLY. Coverage.Complete ranges over an empty list and is true,
// RunReport.OK sees no failures and is true, the process exits 0, and a bundle
// is written whose only hint is one console line reading "Selected: 0 case(s)".
// A CI gate over that is green, and a green gate over nothing is the exact
// dishonesty this framework exists to prevent — the same failure Catalog.Validate
// already refuses for a -doc typo, one level up, at the intersection.
func explainEmptySelection(cat *Catalog, reg *Registry, opts *Options) error {
	var parts []string
	if opts.Campaign != "" {
		parts = append(parts, fmt.Sprintf("-campaign %s (suites %s)",
			opts.Campaign, strings.Join(opts.Suites, "+")))
	} else if len(opts.Suites) > 0 {
		parts = append(parts, "-suite "+strings.Join(opts.Suites, ","))
	}
	if len(opts.Docs) > 0 {
		parts = append(parts, "-doc "+strings.Join(opts.Docs, ","))
	}
	if len(opts.UIDs) > 0 {
		parts = append(parts, "-uid "+strings.Join(opts.UIDs, ","))
	}
	if len(opts.Roles) > 0 {
		roles := make([]string, len(opts.Roles))
		for i, r := range opts.Roles {
			roles[i] = string(r)
		}
		parts = append(parts, "-role "+strings.Join(roles, ","))
	}
	if opts.ApplicableOnly {
		parts = append(parts, "-applicable")
	}
	if opts.MinAutomatable != "" {
		parts = append(parts, "-automatable "+string(opts.MinAutomatable))
	}
	sel := strings.Join(parts, " ")
	if sel == "" {
		sel = "this selection"
	}

	// For each named uid, say which suite actually owns it and whether the
	// catalog calls it applicable — those two facts are the answer in almost
	// every real case, and making the operator run `certify -list` to find them
	// is making them do the tool's job.
	var detail []string
	for _, u := range opts.UIDs {
		for _, c := range cat.All() {
			if !strings.EqualFold(c.UID, u) && !strings.EqualFold(c.ID, u) {
				continue
			}
			suite := "(no suite implements it)"
			if reg != nil {
				if r, ok := reg.Lookup(c.UID); ok {
					suite = "suite " + r.Suite
				}
			}
			why := ""
			if opts.ApplicableOnly && !c.Applicable {
				why = "; the catalog marks it NOT applicable to this product, and -applicable drops it"
			}
			detail = append(detail, fmt.Sprintf("%s is in %s, %s%s", c.UID, c.Doc, suite, why))
		}
	}
	sort.Strings(detail)

	msg := fmt.Sprintf("certify: %s selects ZERO test cases. A run of nothing exits clean and writes an "+
		"empty bundle, which is indistinguishable from a run of everything at the exit code — so it is "+
		"refused here instead", sel)
	if len(detail) > 0 {
		msg += ".\n  " + strings.Join(detail, "\n  ")
	}
	return fmt.Errorf("%s", msg)
}
