package certify

// registry.go is where a suite says "I implement this catalog uid".
//
// The registry's real deliverable is not dispatch — a map would do that — it is
// COVERAGE. "Which of the 282 published test cases does this tool actually
// implement, and which does it not?" is a question a certification reviewer
// will ask, and a tool that cannot answer it precisely is a tool whose clean
// summary means nothing. Coverage therefore reports, per document, the
// implemented uids AND the unimplemented ones by name, and separates "we chose
// not to implement this because it does not apply to the product, here is the
// extraction's reason" from "nobody wrote this one".
//
// Two registration rules are enforced by panicking at init time rather than
// reported later, because both are coordination bugs between suites that must
// never reach a run:
//
//   - two suites registering the same uid (whose check runs? whose evidence is
//     in the bundle?), and
//   - registering a uid that is not in the catalog — checked at Coverage time
//     against the loaded catalog and surfaced as an Orphan, since the registry
//     itself has no catalog to consult at init.

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"csip-tls-test/internal/evidence/bundle"
)

// Verdict is re-exported so a suite needs exactly one import for the whole
// result vocabulary. It is bundle.Verdict: PASS / FAIL / SKIP / WARN, the same
// four values sim/ssm-conformance uses.
type Verdict = bundle.Verdict

// The four verdicts, re-exported for the same reason.
const (
	Pass = bundle.Pass
	Fail = bundle.Fail
	Skip = bundle.Skip
	Warn = bundle.Warn
)

// Assertion is re-exported: one checkable claim about the capture.
type Assertion = bundle.Assertion

// Check is one catalog test case's implementation.
//
// It runs while the run's single capture is LIVE, which is why it cannot cite
// frame numbers directly: the frames it is about to cause do not have indices
// yet. It does two things:
//
//  1. drives the DUT and observes it, and
//  2. tells its Window which connections it opened (rc.ClaimConn / rc.Dial),
//     which is what lets the runner attribute frames to it afterwards.
//
// Wire-cited assertions are minted in the second phase, from Result.Cite.
//
// A Check returning an error means the check itself could not be carried out —
// the sim was unreachable, a fixture was missing. That is recorded as a FAIL
// with the error as evidence, because "we could not test it" must never read
// like "it passed". A conformance FAILURE of the DUT is not an error: it is a
// Result with Verdict Fail and assertions saying what was seen instead.
type Check func(ctx context.Context, rc *RunCtx) (Result, error)

// CiteFunc mints the wire-cited assertions, after the capture has been stopped
// and read back. The Evidence it is handed is scoped to the frames attributed
// to this check: citing anything else is an error, not a silent success.
type CiteFunc func(ctx context.Context, ev *Evidence) ([]Assertion, error)

// Result is what a Check returns.
type Result struct {
	// Verdict may be left empty, in which case it is rolled up from the
	// assertions (worst wins) after the citation phase. Setting it explicitly
	// can only make the outcome STRICTER: the runner takes the worse of the
	// declared verdict and the assertion roll-up, so a check cannot stamp PASS
	// over a failing assertion.
	Verdict Verdict
	// Assertions are the claims that can be made without frame numbers —
	// admin-API observations, certificate facts, absence of a response.
	Assertions []Assertion
	// Notes is free prose recorded on the test case in the bundle.
	Notes string
	// Cite, when non-nil, is called after the capture is read back to mint the
	// frame-cited assertions. Its results are appended to Assertions.
	Cite CiteFunc
	// OffWire declares that this case's pass criteria are not observable on the
	// wire — a certificate-store policy, a document review, an operator's
	// observation. It suppresses the "PASS without a re-checkable citation"
	// downgrade, and the declaration is printed in the bundle so a reader knows
	// this row rests on something other than the pcap. Do not set it to quiet a
	// warning about a check that simply forgot to cite.
	OffWire bool
	// OffWireReason must be set when OffWire is: it is what the bundle prints.
	OffWireReason string
}

// Passed is the common shape: a verdict plus one narrative line, with the
// citations minted later.
func Passed(notes string, cite CiteFunc) Result {
	return Result{Verdict: Pass, Notes: notes, Cite: cite}
}

// Skipped records that the case was addressed but could not be asserted here.
// A SKIP with a reason is honest; a PASS with nothing behind it is not.
func Skipped(format string, a ...any) Result {
	return Result{Verdict: Skip, Notes: fmt.Sprintf(format, a...)}
}

// Failed records a conformance failure with a reason.
func Failed(format string, a ...any) Result {
	return Result{Verdict: Fail, Notes: fmt.Sprintf(format, a...)}
}

// Warned records an asserted-with-a-caveat outcome.
func Warned(format string, a ...any) Result {
	return Result{Verdict: Warn, Notes: fmt.Sprintf(format, a...)}
}

// rollUp returns the worst of the declared verdict and the assertions'.
func (r Result) rollUp() Verdict {
	worst := r.Verdict
	if worst == "" {
		worst = Skip
	}
	for _, a := range r.Assertions {
		if a.Verdict.Severity() > worst.Severity() {
			worst = a.Verdict
		}
	}
	return worst
}

// Registration binds one catalog uid to one suite's Check.
type Registration struct {
	// UID is the catalog uid this check implements.
	UID string
	// Suite is the owning suite's short name ("ssm-tls", "csip-client"), used
	// for -suite selection and printed in the report.
	Suite string
	// Check is the implementation.
	Check Check
	// Requires are capability tags the runner must have to execute this check
	// ("bench", "gridsim", "modsim", "keylog", "root"). A check whose
	// requirements are not met is reported SKIP with the missing tag named —
	// never quietly dropped.
	Requires []string
	// Order sequences checks within a suite when one must precede another
	// (a provisioning step before the case that depends on it). Lower runs
	// first; ties break on UID so the run order is fully deterministic.
	Order int
	// Timeout overrides Options.CheckTimeout for this one registration. Zero
	// (the default for every existing registration) means "use the run's
	// global -timeout" — this field changes nothing for a suite that never
	// sets it. It exists for a check whose OWN procedure has to wait out a
	// DUT's independent cadence (an autonomous poller's own ~10s cycle plus
	// reconnect backoff, say) for evidence no amount of hurrying produces
	// faster: a single global -timeout sized for that check would either
	// leave every faster check's budget alone (fine) or force every check
	// on the run to accept the slow check's worst case (not fine, on a run
	// with hundreds of cases). See suitemodbusclient's CLI-4/ERR-2/PROT-1/
	// READ-2 registrations for the motivating case
	// (runs/warnmeas-mc-ssm-20260802T134537's live-hardware findings).
	Timeout time.Duration
	// CaptureArtifacts are the file names a governing specification requires
	// this case's packet capture to be submitted under, in the order the
	// document lists them. Empty for a case whose document names none.
	//
	// The runner slices this case's attributed frames out of the run capture
	// and writes them under exactly these names. It exists because a
	// certification reviewer reads the Reporting Requirements, not this
	// repository: the Secure SunSpec Modbus CTP §2.4.1.3 says TLSF-001's
	// evidence is "a packet capture (.pcap) … named tlsf_001.pcap", and a
	// bundle carrying one run-wide pcapng satisfies the substance while failing
	// the instruction — which is a submission a lab sends back.
	//
	// More than one name means the document asks for the case's connections
	// separately (TLSF-003's three bad-certificate types, TLSF-005's session
	// and its resumption attempt). The runner splits on TCP connection in
	// first-seen order and refuses to guess when the counts disagree.
	CaptureArtifacts []string
}

// Option customises a registration.
type Option func(*Registration)

// WithRequires declares capability tags the check needs.
func WithRequires(tags ...string) Option {
	return func(r *Registration) { r.Requires = append(r.Requires, tags...) }
}

// WithOrder sets the within-suite ordering key.
func WithOrder(n int) Option { return func(r *Registration) { r.Order = n } }

// WithTimeout overrides Options.CheckTimeout for this one registration. See
// Registration.Timeout.
func WithTimeout(d time.Duration) Option {
	return func(r *Registration) { r.Timeout = d }
}

// WithCaptureArtifacts declares the file names this case's capture must be
// submitted under, in the order the governing document lists them. See
// Registration.CaptureArtifacts.
func WithCaptureArtifacts(names ...string) Option {
	return func(r *Registration) { r.CaptureArtifacts = append(r.CaptureArtifacts, names...) }
}

// Registry maps catalog uids to implementations.
type Registry struct {
	mu    sync.RWMutex
	byUID map[string]Registration
}

// NewRegistry returns an empty registry. Suites normally use the package-level
// Register against Default() from an init function; a private Registry is for
// tests, which must not be able to see or be seen by the global one.
func NewRegistry() *Registry { return &Registry{byUID: map[string]Registration{}} }

var defaultRegistry = NewRegistry()

// Default is the process-wide registry that suites register into.
func Default() *Registry { return defaultRegistry }

// Register binds a check in the default registry. It panics on a duplicate uid:
// two suites claiming the same test case is a coordination bug whose only
// correct outcome is a loud failure before any evidence is produced.
func Register(uid, suite string, check Check, opts ...Option) {
	defaultRegistry.Register(uid, suite, check, opts...)
}

// Register binds a check. See the package-level Register for the panic rule.
func (r *Registry) Register(uid, suite string, check Check, opts ...Option) {
	if uid == "" {
		panic("certify: Register with an empty uid")
	}
	if suite == "" {
		panic("certify: Register " + uid + " with an empty suite name")
	}
	if check == nil {
		panic("certify: Register " + uid + " with a nil Check")
	}
	reg := Registration{UID: uid, Suite: suite, Check: check}
	for _, o := range opts {
		o(&reg)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if prev, dup := r.byUID[uid]; dup {
		panic(fmt.Sprintf("certify: %s is registered twice: by suite %q and suite %q", uid, prev.Suite, suite))
	}
	r.byUID[uid] = reg
}

// Lookup returns the registration for a uid.
func (r *Registry) Lookup(uid string) (Registration, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	reg, ok := r.byUID[uid]
	return reg, ok
}

// Len is the number of registered checks.
func (r *Registry) Len() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.byUID)
}

// Registrations returns every registration, sorted by uid.
func (r *Registry) Registrations() []Registration {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]Registration, 0, len(r.byUID))
	for _, reg := range r.byUID {
		out = append(out, reg)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].UID < out[j].UID })
	return out
}

// Suites returns the distinct suite names, sorted.
func (r *Registry) Suites() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	seen := map[string]bool{}
	for _, reg := range r.byUID {
		seen[reg.Suite] = true
	}
	out := make([]string, 0, len(seen))
	for s := range seen {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

// CoverageEntry is one catalog case's coverage status.
type CoverageEntry struct {
	UID         string      `json:"uid"`
	ID          string      `json:"id"`
	Doc         string      `json:"doc"`
	Title       string      `json:"title"`
	Suite       string      `json:"suite,omitempty"`
	DUTRole     DUTRole     `json:"dut_role"`
	Applicable  bool        `json:"applicable"`
	Automatable Automatable `json:"automatable"`
	// Reason carries the extraction's applicability_reason for an inapplicable
	// case, so the coverage report explains an omission instead of just
	// recording it.
	Reason string `json:"reason,omitempty"`
}

// DocCoverage is one source document's coverage.
type DocCoverage struct {
	Doc     string `json:"doc"`
	Version string `json:"version"`
	// Total is the number of the document's cases the filter selected.
	Total int `json:"total"`
	// Applicable is how many of those apply to this product.
	Applicable int `json:"applicable"`
	// Implemented are the selected cases with a registered check, applicable or
	// not; Unimplemented are the APPLICABLE ones without; Inapplicable are the
	// ones excluded by the extraction, with their reasons.
	Implemented   []CoverageEntry `json:"implemented"`
	Unimplemented []CoverageEntry `json:"unimplemented"`
	Inapplicable  []CoverageEntry `json:"inapplicable"`
}

// Complete reports whether every applicable case in this document has an
// implementation.
func (d DocCoverage) Complete() bool { return len(d.Unimplemented) == 0 }

// Coverage is the whole "coverage of the standard" deliverable.
type Coverage struct {
	Catalog CatalogRef    `json:"catalog"`
	Docs    []DocCoverage `json:"docs"`
	// Orphans are registered uids with no catalog record: a suite implementing
	// a test case that does not exist, which means either a stale registration
	// or a catalog the suite was not written against. Either way the run must
	// not proceed as if nothing were wrong.
	Orphans []string `json:"orphans,omitempty"`
}

// Totals rolls the per-document counts up.
func (c Coverage) Totals() (total, applicable, implemented, missing int) {
	for _, d := range c.Docs {
		total += d.Total
		applicable += d.Applicable
		implemented += len(d.Implemented)
		missing += len(d.Unimplemented)
	}
	return
}

// Complete reports whether every applicable selected case has an implementation
// and there are no orphaned registrations. This is the acceptance bar behind
// the report's "ALL TEST CASES ADDRESSED" line.
func (c Coverage) Complete() bool {
	if len(c.Orphans) > 0 {
		return false
	}
	for _, d := range c.Docs {
		if !d.Complete() {
			return false
		}
	}
	return true
}

// Coverage computes coverage of the catalog cases the filter selects.
//
// Orphan detection deliberately looks at the WHOLE catalog, not the filtered
// selection: a registration for a uid outside the filter is fine, but a
// registration for a uid that exists nowhere is a bug regardless of the filter
// in force.
func (r *Registry) Coverage(cat *Catalog, f Filter) Coverage {
	r.mu.RLock()
	regs := make(map[string]Registration, len(r.byUID))
	for k, v := range r.byUID {
		regs[k] = v
	}
	r.mu.RUnlock()

	cov := Coverage{Catalog: cat.Ref()}
	byDoc := map[string]*DocCoverage{}
	var docOrder []string

	for _, c := range cat.Select(f) {
		dc, ok := byDoc[c.Doc]
		if !ok {
			dc = &DocCoverage{Doc: c.Doc, Version: c.DocVersion}
			byDoc[c.Doc] = dc
			docOrder = append(docOrder, c.Doc)
		}
		reg, implemented := regs[c.UID]
		e := CoverageEntry{
			UID: c.UID, ID: c.ID, Doc: c.Doc, Title: c.Title,
			Suite: reg.Suite, DUTRole: c.DUTRole,
			Applicable: c.Applicable, Automatable: c.Automatable,
		}
		dc.Total++
		if c.Applicable {
			dc.Applicable++
		}
		switch {
		case implemented:
			dc.Implemented = append(dc.Implemented, e)
		case !c.Applicable:
			e.Reason = c.ApplicabilityReason
			dc.Inapplicable = append(dc.Inapplicable, e)
		default:
			dc.Unimplemented = append(dc.Unimplemented, e)
		}
	}
	sort.Strings(docOrder)
	for _, d := range docOrder {
		cov.Docs = append(cov.Docs, *byDoc[d])
	}

	for uid := range regs {
		if _, ok := cat.ByUID(uid); !ok {
			cov.Orphans = append(cov.Orphans, uid)
		}
	}
	sort.Strings(cov.Orphans)
	return cov
}

// MissingCapabilities returns the registration's required tags that are absent
// from have, sorted.
func (reg Registration) MissingCapabilities(have map[string]bool) []string {
	var missing []string
	for _, t := range reg.Requires {
		if !have[t] {
			missing = append(missing, t)
		}
	}
	sort.Strings(missing)
	return missing
}

// String renders a registration for logs.
func (reg Registration) String() string {
	if len(reg.Requires) == 0 {
		return reg.Suite + ":" + reg.UID
	}
	return reg.Suite + ":" + reg.UID + " [" + strings.Join(reg.Requires, ",") + "]"
}
