package certify

// runner.go selects test cases, runs one capture for the whole run, executes
// the checks in a deterministic order, attributes frames, and writes the
// evidence bundle.
//
// # Deterministic order
//
// Cases run sorted by (document, within-suite Order, uid). Determinism is not
// tidiness: two runs of the same selection must produce the same sequence of
// frames on the wire, or a reviewer comparing two bundles cannot tell a
// behaviour change from a scheduling change.
//
// # A panicking check must not abort the run
//
// A conformance run costs a live bench and an operator's attention. Losing
// twenty completed test cases' evidence because the twenty-first dereferenced a
// nil pointer would be an own goal. Every check — and every citation callback —
// runs inside a recover, and a panic becomes a FAIL carrying the panic value
// and the stack, which is exactly what a reader needs to know: this test case's
// verdict is our bug, not the DUT's.
//
// # An uncited PASS is not a PASS
//
// After the citation phase the runner inspects each PASS. If nothing behind it
// carries a digest bundle.Verify can re-derive, the verdict is downgraded to
// WARN and the reason is printed and recorded — unless the check declared the
// criterion off-wire, with a reason, which is a different and honest thing. See
// Options.RequireCitation.

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime/debug"
	"sort"
	"strings"
	"time"

	"csip-tls-test/internal/certify/manifest"
	"csip-tls-test/internal/evidence/bundle"
	"csip-tls-test/internal/evidence/capture"
	"csip-tls-test/internal/evidence/keylog"
	"csip-tls-test/internal/evidence/metricscrape"
	"csip-tls-test/internal/evidence/pcapng"
)

// ToolName identifies this runner in the bundle.
const ToolName = "csip-certify"

// Capturer is the run's packet capture. *capture.Capture satisfies it; the
// interface exists so a test can drive the whole runner without root, a NIC, or
// dumpcap.
type Capturer interface {
	Start(ctx context.Context) error
	Stop() (capture.Summary, error)
	Path() string
}

// Options configure a run.
type Options struct {
	// CatalogPath overrides catalog discovery.
	CatalogPath string

	// Selection.
	Docs           []string
	UIDs           []string
	Suites         []string
	Roles          []DUTRole
	ApplicableOnly bool
	MinAutomatable Automatable

	// Campaign, when set, replaces the selection with a named CLOSED one and
	// arms that campaign's control-authority precondition. It is the only way
	// to produce a GATING bundle; everything else is exploratory. See
	// campaign.go.
	Campaign Campaign
	// ManifestPath is the candidate manifest (-manifest): the DUT's own
	// declaration of what it is, against which scope decisions are made.
	// REQUIRED with Campaign, optional otherwise, and a run without one makes
	// no manifest-derived scope decision at all.
	ManifestPath string
	// Preset names a bench topology whose target addresses fill in the flags
	// the operator did not set (preset.go). It is applied at the flag layer,
	// before the runner sees Options, so the runner has no notion of it beyond
	// this record of what was asked for.
	Preset string

	// DryRun lists what would run and writes no bundle.
	DryRun bool

	// Capture.
	//
	// Iface is the capture interface, or several separated by commas
	// ("wlp2s0,enp1s0") when the bench is split — northbound on one NIC,
	// southbound on another. One capture still covers the whole run and frame
	// numbering stays a single sequence, so citations are unaffected; what
	// changes is that a row resting on a southbound observable can be cited at
	// all. Capturing only one side of a split bench does not make those rows
	// FAIL, it makes them unmeasurable, which is harder to notice and worse.
	// The multi-interface form needs dumpcap (see the capture package).
	Iface string
	// BPF is the capture filter. Empty captures everything on the interface,
	// which is the safe default: a filter that excludes a frame the run needed
	// is not recoverable afterwards.
	BPF string
	// NoCapture runs without a capture at all — for loopback and in-process
	// development runs. Every wire citation then becomes impossible, and the
	// bundle says so on every affected case rather than quietly passing.
	NoCapture bool
	// Capturer overrides the capture implementation (tests).
	Capturer Capturer
	// KeyLogPath is where TLS secrets are exported (SSLKEYLOGFILE). Empty
	// means encrypted payloads are not decryptable from the bundle.
	KeyLogPath string
	// Guard overrides the per-window attribution guard.
	Guard time.Duration
	// CaptureSettle is how long the runner waits between the last check
	// finishing and stopping the capture. Zero means DefaultCaptureSettle;
	// negative means none.
	//
	// This is not politeness, it is correctness, and it was found the
	// expensive way. dumpcap reads from a kernel ring and writes the file in
	// batches: SIGINT the instant the last check returns and the frames still
	// in that ring are never written. Measured on loopback, a run whose whole
	// exchange took 200 ms and stopped the capture immediately produced a
	// 400-byte pcapng — the file header and NOTHING ELSE, ten frames lost.
	// Nothing about that failure is loud: the bundle is written, the citations
	// silently find no frames, and every PASS is downgraded to WARN for
	// "want of a citation" as though the checks had been sloppy rather than
	// the evidence discarded. On the live bench the tail of the LAST check is
	// always at risk for the same reason.
	CaptureSettle time.Duration

	// Bench.
	Targets Targets
	PKIDir  string
	// GatewaySSH and GatewayExec are the two READ-ONLY introspection
	// transports, and exactly one may be set: ssh to a remote DUT, or a local
	// command prefix for a DUT on this host. See Gateway.
	GatewaySSH  string
	GatewayExec string
	// DevAPI is the DUT's dev API base URL, reached THROUGH the introspection
	// transport (it is loopback-bound on the device). Empty means
	// DefaultDevAPI. The live control-authority reading comes from its GET
	// /mode; the topology preflight reads its /status and /southbound/inventory.
	DevAPI string
	HTTP   HTTPClient

	// SkipPreflight bypasses the bench cross-checks Runner.preflight makes —
	// principally that -gridsim and -gridsim-admin name one live process. It
	// exists for topologies preflight cannot reason about (a proxied or
	// port-forwarded admin API), and its use is recorded in the bundle,
	// because a run whose pairing was asserted rather than established is
	// evidence of a slightly different kind.
	SkipPreflight bool

	// Command is the argument vector that started this process. The runner
	// records it in the bundle with credential-shaped values replaced (see
	// bundle.RedactCommand); what is stored HERE is what the caller passed,
	// unaltered, since the caller may still need it.
	//
	// Empty means the entry point supplied none and the bundle carries no
	// invocation. That is a gap, not a fault: bundles written before the field
	// existed have none either, and Verify does not ask for it.
	Command []string

	// Output.
	OutDir   string
	Operator string
	Note     string
	DUT      bundle.DUT
	Out      io.Writer
	Log      Logger

	// CheckTimeout bounds one check. Zero means DefaultCheckTimeout.
	CheckTimeout time.Duration
	// Params are -param key=value pass-throughs.
	Params map[string]string
	// Capabilities the runner has, matched against Registration.Requires.
	// The runner adds the ones it can determine itself ("capture", "keylog",
	// "gridsim", "gateway", "pki").
	Capabilities map[string]bool

	// RequireCitation downgrades an uncited PASS to WARN. Default true; there
	// is no good reason to turn it off outside a framework test.
	RequireCitation bool
	// RequireCoverage makes an unimplemented applicable test case fail the run.
	RequireCoverage bool
}

// DefaultCheckTimeout bounds a single check.
const DefaultCheckTimeout = 3 * time.Minute

// DefaultCaptureSettle is the pause between the last check and stopping the
// capture. 750 ms is comfortably above the ~100 ms at which loopback frames
// started surviving in measurement, and it is paid once per run — a price no
// operator will notice next to losing a run's tail frames. See
// Options.CaptureSettle.
const DefaultCaptureSettle = 750 * time.Millisecond

// DefaultOptions returns the options a live bench run starts from.
func DefaultOptions() Options {
	return Options{
		Iface:           "enp1s0",
		Targets:         DefaultTargets(),
		PKIDir:          "certs/mbaps",
		OutDir:          "evidence",
		CheckTimeout:    DefaultCheckTimeout,
		RequireCitation: true,
		Params:          map[string]string{},
		Capabilities:    map[string]bool{},
	}
}

// stringList is a repeatable, comma-splitting flag value, so both
// `-doc A -doc B` and `-doc A,B` work.
type stringList struct{ v *[]string }

func (s stringList) String() string {
	if s.v == nil {
		return ""
	}
	return strings.Join(*s.v, ",")
}

func (s stringList) Set(v string) error {
	for _, part := range strings.Split(v, ",") {
		if part = strings.TrimSpace(part); part != "" {
			*s.v = append(*s.v, part)
		}
	}
	return nil
}

// keyValue collects -param key=value.
type keyValue struct{ m *map[string]string }

func (k keyValue) String() string { return "" }

func (k keyValue) Set(v string) error {
	key, val, ok := strings.Cut(v, "=")
	if !ok {
		return fmt.Errorf("want key=value, got %q", v)
	}
	if *k.m == nil {
		*k.m = map[string]string{}
	}
	(*k.m)[strings.TrimSpace(key)] = val
	return nil
}

// validateParamScopes refuses a per-case -param whose scope names no case in
// the catalog.
//
// A key is SCOPED when it contains a colon, and the scope is everything before
// the LAST one — which is what makes both spellings work, since a globally
// unique uid contains a "::" of its own ("csip-conf-v1.3::BASIC-029:csip.wait"
// scopes csip.wait to that case). No parameter name in the vocabulary contains
// a colon, so nothing unscoped is caught by that rule; a key that does contain
// one and resolves to no case is a typo, not a global, and is refused rather
// than silently treated as either.
func validateParamScopes(cat *Catalog, params map[string]string) error {
	var bad []string
	for key := range params {
		i := strings.LastIndex(key, ":")
		if i < 0 {
			continue // unscoped: an ordinary global parameter
		}
		scope, name := key[:i], key[i+1:]
		if scope == "" || name == "" {
			bad = append(bad, key)
			continue
		}
		if !catalogHasCase(cat, scope) {
			bad = append(bad, key)
		}
	}
	if len(bad) == 0 {
		return nil
	}
	sort.Strings(bad)
	return fmt.Errorf("certify: -param %s is scoped to a case this catalog does not have "+
		"(the scope is everything before the last colon, and must be a case uid or its bare "+
		"in-document id, e.g. -param BASIC-029:csip.wait=8m)", strings.Join(bad, ", "))
}

// catalogHasCase reports whether name identifies a case by uid or by bare
// in-document id, matched fold-insensitively — the same two spellings and the
// same case-insensitivity Filter.Matches accepts for -uid.
func catalogHasCase(cat *Catalog, name string) bool {
	for _, c := range cat.All() {
		if strings.EqualFold(c.UID, name) || strings.EqualFold(c.ID, name) {
			return true
		}
	}
	return false
}

// BindFlags registers the runner's command-line surface. A suite binary calls
// it, parses, and hands the Options to New.
func (o *Options) BindFlags(fs *flag.FlagSet) {
	fs.StringVar(&o.CatalogPath, "catalog", o.CatalogPath, "path to catalog.json (default: nearest "+CatalogFile+")")
	fs.Var(stringList{&o.Docs}, "doc", "only run cases from these catalog documents (repeatable, comma-separated)")
	fs.Var(stringList{&o.UIDs}, "uid", "only run these catalog uids or ids (repeatable, comma-separated)")
	fs.Var(stringList{&o.Suites}, "suite", "only run these suites (repeatable, comma-separated). "+
		"EXPLORATORY: a -suite selection produces a non-gating bundle — see -campaign")
	fs.Func("campaign", "run a named GATING campaign: "+strings.Join(CampaignNames(), "|")+
		". Expands to that campaign's suites, requires -manifest and the matching LIVE DUT control "+
		"authority (proven before case 1, not assumed), and records both in the bundle. Cannot be "+
		"combined with -suite", func(v string) error {
		o.Campaign = Campaign(strings.TrimSpace(v))
		return nil
	})
	fs.StringVar(&o.ManifestPath, "manifest", o.ManifestPath,
		"the candidate manifest (the DUT's own declaration of what it is; it installs one at "+
			manifest.DefaultDUTPath+"). Scope decisions are made against it and it is copied into the "+
			"bundle beside its digest. REQUIRED with -campaign")
	fs.StringVar(&o.DevAPI, "dev-api", o.DevAPI,
		"the DUT's dev API base URL, fetched ON the DUT through -gateway-ssh/-gateway-exec because it is "+
			"loopback-bound (default "+DefaultDevAPI+")")
	fs.Func("role", "only run cases for these DUT roles (repeatable, comma-separated)", func(v string) error {
		for _, part := range strings.Split(v, ",") {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			if !knownRoles[DUTRole(part)] {
				return fmt.Errorf("unknown dut_role %q", part)
			}
			o.Roles = append(o.Roles, DUTRole(part))
		}
		return nil
	})
	fs.BoolVar(&o.ApplicableOnly, "applicable", o.ApplicableOnly, "skip cases the catalog marks inapplicable to this product")
	fs.Func("automatable", "minimum automation level: full|partial|manual", func(v string) error {
		a := Automatable(v)
		if !autoRankKnown(a) {
			return fmt.Errorf("want full|partial|manual, got %q", v)
		}
		o.MinAutomatable = a
		return nil
	})
	fs.BoolVar(&o.DryRun, "dry-run", o.DryRun, "list the cases that would run, and the coverage gaps, then exit")
	fs.StringVar(&o.Iface, "iface", o.Iface,
		"capture interface, or a comma-separated list for a split bench (wlp2s0,enp1s0); "+
			"more than one needs dumpcap")
	fs.StringVar(&o.BPF, "bpf", o.BPF, "capture filter (empty captures everything)")
	fs.BoolVar(&o.NoCapture, "no-capture", o.NoCapture, "run without a packet capture (no wire citations are then possible)")
	fs.StringVar(&o.KeyLogPath, "keylog", o.KeyLogPath, "NSS key log the suites export TLS secrets to")
	fs.DurationVar(&o.Guard, "guard", o.Guard, "frame-attribution guard at each end of a check's window")
	fs.DurationVar(&o.CaptureSettle, "capture-settle", o.CaptureSettle,
		"pause before stopping the capture so it flushes the last check's frames (0 = default, <0 = none)")
	fs.StringVar(&o.OutDir, "out", o.OutDir, "evidence bundle output directory")
	fs.StringVar(&o.Operator, "operator", o.Operator, "operator name, recorded in the bundle")
	fs.StringVar(&o.Note, "note", o.Note, "free-text note recorded in the bundle")
	fs.StringVar(&o.PKIDir, "pki", o.PKIDir, "mbaps certificate fixture directory")
	fs.StringVar(&o.GatewaySSH, "gateway-ssh", o.GatewaySSH, "ssh destination for READ-ONLY gateway introspection")
	fs.StringVar(&o.GatewayExec, "gateway-exec", o.GatewayExec,
		"command PREFIX for READ-ONLY introspection of a gateway on THIS host, e.g. \"docker exec c\" or "+
			"\"scripts/lab/lab-exec\". The same read-only allowlist is enforced before the prefix runs. "+
			"Mutually exclusive with -gateway-ssh")
	fs.StringVar(&o.Targets.Gateway, "gateway", o.Targets.Gateway, "DUT mbaps address host:port")
	fs.StringVar(&o.Targets.GridSim, "gridsim", o.Targets.GridSim, "2030.5 server simulator host:port")
	fs.StringVar(&o.Targets.GridSimAdmin, "gridsim-admin", o.Targets.GridSimAdmin, "gridsim admin API base URL")
	fs.StringVar(&o.Targets.ModSim, "modsim", o.Targets.ModSim, "plain SunSpec Modbus sim host:port")
	fs.StringVar(&o.Targets.ModSimAPI, "modsim-api", o.Targets.ModSimAPI, "modsim simapi base URL")
	fs.Var(endpointFlag{&o.Targets, TargetMetrics}, "metrics-endpoint",
		"the DUT's own Prometheus endpoint URL, e.g. http://127.0.0.1:9102/metrics — loopback-only by "+
			"design, so also pass -gateway-ssh to fetch it on the DUT (the disclosure-counter evidence "+
			"channel reads it; empty disables that channel)")
	fs.StringVar(&o.Targets.MBAPSDev, "mbapsdev", o.Targets.MBAPSDev, "secure Modbus device sim host:port")
	fs.StringVar(&o.Targets.MBAPSDevAPI, "mbapsdev-api", o.Targets.MBAPSDevAPI, "mbapsdev simapi base URL")
	fs.DurationVar(&o.CheckTimeout, "timeout", o.CheckTimeout, "per-check timeout")
	fs.Var(keyValue{&o.Params}, "param", "procedure parameter key=value (repeatable)")
	fs.BoolVar(&o.RequireCitation, "require-citation", o.RequireCitation, "downgrade a PASS with no re-checkable citation to WARN")
	fs.BoolVar(&o.RequireCoverage, "require-coverage", o.RequireCoverage, "fail the run if an applicable test case has no implementation")
	fs.BoolVar(&o.SkipPreflight, "skip-preflight", o.SkipPreflight,
		"do not verify that -gridsim and -gridsim-admin are one live process (for topologies where they "+
			"legitimately differ; the bundle records that the check was skipped). It does NOT wave "+
			"through a WRONG control-authority reading: its only effect there is to let an EXPLORATORY "+
			"run with no gateway transport proceed, non-gating")
	fs.StringVar(&o.Preset, "preset", o.Preset,
		"fill in the bench addresses for a named topology — "+PresetSummary()+
			". Flags given explicitly always win")
}

// Filter builds the catalog filter from the selection options.
func (o *Options) Filter() Filter {
	return Filter{
		Docs:           o.Docs,
		UIDs:           o.UIDs,
		Roles:          o.Roles,
		ApplicableOnly: o.ApplicableOnly,
		MinAutomatable: o.MinAutomatable,
	}
}

// Planned is one selected test case and what will happen to it.
type Planned struct {
	Case         *Case
	Registration Registration
	// Implemented is false when no suite registered a check for this uid.
	Implemented bool
	// Skip, when non-empty, is why the case will not be executed: no
	// implementation, a missing capability, a suite filter. It means "this run
	// could not measure it" and nothing more.
	Skip string
	// Scope, when set, is why the case is NOT IN SCOPE for this candidate at
	// all — a different statement from Skip, carried on a different verdict.
	// See scope.go and bundle.VerdictNotApplicable.
	Scope *ScopeDecision
}

// OutOfScope reports whether this row is not applicable to the candidate.
func (p Planned) OutOfScope() bool { return p.Scope != nil }

// CaseResult is one test case's outcome.
type CaseResult struct {
	Case    *Case
	Suite   string
	Verdict Verdict
	Notes   string
	// Scope, when set, is why this row was declared NOT APPLICABLE. It is
	// present exactly when Verdict is NotApplicable — bundle.Verify refuses a
	// bundle where the two disagree.
	Scope *ScopeDecision
	// Assertions are the live-phase assertions plus whatever the citation
	// phase produced.
	Assertions []Assertion
	// Err is set when the check could not be carried out at all.
	Err error
	// Panic carries the recovered panic and its stack.
	Panic string
	// Frames are the capture frames attributed to this case.
	Frames []int
	// FrameSet is the full attribution record.
	FrameSet *FrameSet
	// LiveVerdict is the verdict the check DECLARED at the end of the live
	// phase, before the capture was parsed and the citation phase ran.
	//
	// It is kept because the two can differ, and when they do the difference is
	// itself worth reporting: the live phase reasons from bytes read off a
	// socket, the citation phase from bytes a stranger can re-read out of the
	// pcap, and those are different evidentiary standards. A console that
	// printed one and a bundle that recorded the other, with nothing saying so,
	// is what produced "11 FAIL on screen, 17 in the summary" in run
	// 20260726T225512 — and three REV cases the runner logged as SKIP and the
	// report published as FAIL.
	LiveVerdict Verdict
	// Reconciled is why the final verdict differs from LiveVerdict, when it
	// does.
	Reconciled string
	// Executed distinguishes "ran and skipped" from "never ran".
	Executed bool
	Duration time.Duration
	Started  time.Time
	// Downgraded records a verdict the runner lowered, and why.
	Downgraded string

	// cite / offWire carry the Result's citation callback and off-wire
	// declaration from the live phase into the citation phase. They are
	// unexported because they are runner bookkeeping, not part of the report a
	// caller consumes.
	cite          CiteFunc
	offWire       bool
	offWireReason string
	// metrics are the DUT's own counter readings this case took across its own
	// window, carried from the Result to writeBundle (IW15-030). They are on
	// the case rather than accumulated globally so a reading is attributable to
	// the row whose window produced it — a delta over anyone else's window is a
	// number about a different question.
	metrics []metricscrape.Record
	// captureArtifacts are the file names this case's registration declared
	// (Registration.CaptureArtifacts), carried from the plan so the citation
	// phase can slice the run capture without re-consulting the registry.
	captureArtifacts []string
}

// Citable reports whether any assertion carries a re-checkable digest.
func (r *CaseResult) Citable() bool {
	for _, a := range r.Assertions {
		if a.Citable() {
			return true
		}
	}
	return false
}

// RunReport is the whole run.
type RunReport struct {
	Catalog     CatalogRef
	Coverage    Coverage
	Plan        []Planned
	Cases       []CaseResult
	Attribution *Attribution
	Capture     capture.Summary
	// CaptureProblems are integrity findings about the capture itself.
	CaptureProblems []string
	// CaptureArtifacts are the per-test capture files the governing documents
	// name in their Reporting Requirements, sliced out of the run capture —
	// including the ones that could NOT be written, with the reason. See
	// artifacts.go.
	CaptureArtifacts []CaptureArtifact
	Bundle           *bundle.Bundle
	BundleDir        string
	Started          time.Time
	Finished         time.Time
	DryRun           bool
	// Campaign is the campaign this run declared, zero when exploratory.
	Campaign CampaignSpec
	// Authority is what the control-authority preflight established, or why it
	// could not.
	Authority authorityOutcome
	// Exploratory, when non-empty, is why this run is NOT GATING — a run that
	// may not decide anything. It is recorded in the bundle so a reader never
	// has to reconstruct it from a command line.
	Exploratory string
}

// Gating reports whether this run's result may decide anything: it declared a
// campaign, and nothing weakened it.
func (r *RunReport) Gating() bool { return r.Campaign.Name != "" && r.Exploratory == "" }

// Counts tallies the cases by verdict. N/A is returned separately from skip for
// the reason bundle.Bundle.Counts gives: folded together, the rows nobody can
// act on bury the ones somebody must.
func (r *RunReport) Counts() (pass, fail, skip, warn, na int) {
	for _, c := range r.Cases {
		switch c.Verdict {
		case Pass:
			pass++
		case Fail:
			fail++
		case Skip:
			skip++
		case Warn:
			warn++
		case NotApplicable:
			na++
		}
	}
	return
}

// VerdictCounts is a per-verdict tally. It mirrors bundle.VerdictCounts exactly,
// so the live run and the bundle written from it cannot report different shapes.
type VerdictCounts struct{ Pass, Fail, Skip, Warn, NotApplicable int }

func (v *VerdictCounts) add(k Verdict) {
	switch k {
	case Pass:
		v.Pass++
	case Fail:
		v.Fail++
	case Skip:
		v.Skip++
	case Warn:
		v.Warn++
	case NotApplicable:
		v.NotApplicable++
	}
}

// Total returns the number of cases in the tally.
func (v VerdictCounts) Total() int { return v.Pass + v.Fail + v.Skip + v.Warn + v.NotApplicable }

// InScope is the total less the rows declared not applicable — what a
// completion figure must be taken over.
func (v VerdictCounts) InScope() int { return v.Total() - v.NotApplicable }

// CountsByClaim splits the verdict tally in two: the cases that bear on the
// certification CLAIM (catalog `applicable`), and the INFORMATIVE cases the
// suite implements but does not claim. A FAIL among the informative set is a
// finding about a row nobody is certifying against; carrying it in the same
// number as a claim-relevant FAIL is what let one informative FAIL read as a
// certification failure in the headline. This changes no verdict — only how they
// are grouped for reporting.
func (r *RunReport) CountsByClaim() (applicable, informative VerdictCounts) {
	for _, c := range r.Cases {
		if c.Case.BearsOnClaim() {
			applicable.add(c.Verdict)
		} else {
			informative.add(c.Verdict)
		}
	}
	return
}

// Unaddressed returns the selected applicable cases with no implementation.
func (r *RunReport) Unaddressed() []CoverageEntry {
	var out []CoverageEntry
	for _, d := range r.Coverage.Docs {
		out = append(out, d.Unimplemented...)
	}
	return out
}

// OK reports a clean run: every applicable selected case addressed, no FAIL
// THAT BEARS ON THE CLAIM, no orphaned registration, no capture-integrity
// problem. It is the zero-FAIL exit criterion, and the process exit code.
//
// It counts the CLAIM-BEARING failures, not every failure, and that distinction
// is deliberate. A row the catalog marks non-certifiable measures behaviour no
// published procedure covers (see Case.Certifiable): its verdict is evidence
// about the product and cannot be a conformance result, so letting it turn a
// campaign red would make an exit criterion stated over a specification depend
// on a row that specification does not contain. Bundle.OK's doc names this a
// policy call for the owner of the claim; this is that call, made narrowly —
// only non-certifiable rows are excluded, and their FAILs stay fully visible in
// Counts(), in the informative half of CountsByClaim, in the console summary and
// in the bundle.
//
// An INAPPLICABLE-but-certifiable row (an aggregator procedure under a
// DER-Client claim) is excluded by the same reading, which is the behaviour the
// claim split was introduced for.
// A NOT-APPLICABLE row is neither a pass nor a failure: it contributes to no
// FAIL count, and it is excluded from the "did this run establish anything at
// all" floor, so a selection every row of which was out of scope cannot report
// itself clean.
func (r *RunReport) OK() bool {
	app, inf := r.CountsByClaim()
	if app.InScope()+inf.InScope() == 0 && len(r.Cases) > 0 {
		return false
	}
	return app.Fail == 0 && r.Coverage.Complete() && len(r.CaptureProblems) == 0
}

// Runner executes a run.
type Runner struct {
	reg  *Registry
	cat  *Catalog
	opts Options
	log  Logger
	out  io.Writer

	// campaign is the resolved -campaign, zero when the run is exploratory.
	campaign CampaignSpec
	// manifest is the loaded candidate manifest, nil when none was given.
	manifest *manifest.Manifest
	// gatewayExec is -gateway-exec split into an argv, once, at construction —
	// so a malformed prefix is a startup error rather than a failure on the
	// first introspection call, forty minutes in.
	gatewayExec []string
}

// gateway builds the READ-ONLY introspection client for this run. One
// constructor, so the two transports cannot diverge between the preflight and
// the checks.
func (r *Runner) gateway() *Gateway {
	return &Gateway{SSH: r.opts.GatewaySSH, Exec: r.gatewayExec}
}

// Manifest returns the candidate manifest this run was measured against, or nil.
func (r *Runner) Manifest() *manifest.Manifest { return r.manifest }

// New builds a runner. It validates the selection against the catalog up front,
// so a typo in -doc fails immediately instead of producing a clean report of
// zero test cases.
func New(reg *Registry, cat *Catalog, opts Options) (*Runner, error) {
	if reg == nil {
		return nil, fmt.Errorf("certify: no registry")
	}
	if cat == nil {
		return nil, fmt.Errorf("certify: no catalog")
	}
	// The campaign expands the selection BEFORE anything is validated against
	// the catalog, so everything below sees one selection whether the operator
	// named suites or a campaign — and the -suite/-campaign conflict, and the
	// missing -manifest, are refused here rather than surfacing later as a
	// puzzling row count.
	spec, err := resolveCampaign(&opts)
	if err != nil {
		return nil, err
	}
	// Two introspection transports naming two different devices is refused at
	// the flag layer rather than resolved at the call site: see Gateway.Run.
	if opts.GatewaySSH != "" && opts.GatewayExec != "" {
		return nil, fmt.Errorf("certify: -gateway-ssh %s and -gateway-exec %q are mutually exclusive — "+
			"they name different devices, and a run that read some facts from one and some from the "+
			"other would be evidence about neither", opts.GatewaySSH, opts.GatewayExec)
	}
	var gatewayExec []string
	if opts.GatewayExec != "" {
		gatewayExec, err = SplitCommandPrefix(opts.GatewayExec)
		if err != nil {
			return nil, err
		}
	}
	var cand *manifest.Manifest
	if opts.ManifestPath != "" {
		cand, err = manifest.Load(opts.ManifestPath)
		if err != nil {
			return nil, err
		}
	}
	if err := cat.Validate(opts.Filter()); err != nil {
		return nil, err
	}
	// A -suite name nobody registered selects nothing, and "nothing" would be
	// reported as a clean run of zero test cases — the same silent-typo failure
	// Catalog.Validate exists to prevent for -doc and -uid. Refuse instead, and
	// name what IS available.
	if unknown := unknownSuites(reg, opts.Suites); len(unknown) > 0 {
		if spec.Name != "" {
			// The campaign table names a suite this binary does not link. That
			// is a defect in the table or a renamed suite, never the operator's
			// mistake, and it must not be reported as one.
			return nil, &CampaignError{Campaign: string(spec.Name), Reason: fmt.Sprintf(
				"expands to suite(s) %s, which this binary does not have (have: %s). The campaign table "+
					"and the linked suites have diverged", strings.Join(unknown, ", "),
				strings.Join(reg.Suites(), ", "))}
		}
		return nil, fmt.Errorf("certify: no suite named %s (have: %s)",
			strings.Join(unknown, ", "), strings.Join(reg.Suites(), ", "))
	}
	// A -param scoped to a case the catalog does not have would silently leave
	// that case on the global value, and the bundle would then record a verdict
	// the operator believes was measured under a budget that was never applied.
	// Same silent-typo failure the two refusals above exist to prevent, refused
	// here for the same reason. See RunCtx.Param for what a scope is.
	if err := validateParamScopes(cat, opts.Params); err != nil {
		return nil, err
	}
	if opts.CheckTimeout <= 0 {
		opts.CheckTimeout = DefaultCheckTimeout
	}
	if opts.Params == nil {
		opts.Params = map[string]string{}
	}
	if opts.Capabilities == nil {
		opts.Capabilities = map[string]bool{}
	}
	// Derive Targets.GatewayHost from Targets.Gateway. See Targets.Normalise:
	// no command line sets the host field, so without this a run against any
	// address but the compiled-in bench default leaves suitessm comparing
	// frame directions against 69.0.0.2.
	opts.Targets.Normalise()
	r := &Runner{
		reg:         reg,
		cat:         cat,
		opts:        opts,
		log:         opts.Log,
		out:         opts.Out,
		campaign:    spec,
		manifest:    cand,
		gatewayExec: gatewayExec,
	}
	if r.log == nil {
		r.log = DiscardLogger
	}
	if r.out == nil {
		r.out = os.Stdout
	}
	// LAST, because it needs the resolved filter: a selection that matches
	// nothing is refused rather than run. Catalog.Validate above catches a
	// selector that names nothing AT ALL; this catches the INTERSECTION that
	// does — `-suite modbus-server -uid ssm-conf-v0.8::RBAC-002`, where every
	// selector is valid and no case is in all of them. See
	// explainEmptySelection for why an empty run is worse than a refused one.
	if len(cat.Select(r.filter())) == 0 {
		return nil, explainEmptySelection(cat, reg, &opts)
	}
	return r, nil
}

// filter is the run's EFFECTIVE catalog selection: the operator's filter plus
// -suite.
//
// -suite has to participate in SELECTION and not merely in dispatch, and the
// difference is one of honesty rather than tidiness. Applied afterwards, a
// `-suite ssm` run selected all 282 cases, executed 34, and skipped the rest
// with "suite csip not selected" — so the run's summary counted 248 skips the
// operator never asked about, and the COVERAGE.md sealed into the bundle
// described the whole catalog rather than the campaign that was actually run.
// A reader of that bundle would have to reconstruct the operator's intent from
// a wall of skip lines. Selecting on the suite instead makes the coverage
// report and the plan describe the same thing, exactly as -doc already does.
//
// A case with no registration cannot belong to a suite, so it drops out of a
// -suite selection. That is the right answer — it is not a gap in THIS campaign
// — and the unfiltered coverage remains one `certify -list` away.
func (r *Runner) filter() Filter {
	f := r.opts.Filter()
	if len(r.opts.Suites) == 0 {
		return f
	}
	base := f.Match
	f.Match = func(c *Case) bool {
		if base != nil && !base(c) {
			return false
		}
		reg, ok := r.reg.Lookup(c.UID)
		return ok && containsFold(r.opts.Suites, reg.Suite)
	}
	return f
}

// Coverage returns the coverage of the selected cases.
func (r *Runner) Coverage() Coverage { return r.reg.Coverage(r.cat, r.filter()) }

// Plan returns what would run, in execution order.
func (r *Runner) Plan() []Planned {
	caps := r.capabilities()
	cases := r.cat.Select(r.filter())
	plan := make([]Planned, 0, len(cases))
	for _, c := range cases {
		p := Planned{Case: c}
		// SCOPE FIRST, and before the registration lookup, because "this row is
		// not about anything this candidate is" is decided by declarations, not
		// by whether a suite happens to implement it. The candidate's own
		// manifest outranks the catalog here: it is the narrower and more
		// specific statement, and ManifestScope flags the disagreement when the
		// two contradict rather than resolving it silently.
		if d, ok := ManifestScope(r.manifest, c); ok {
			p.Scope = &d
			plan = append(plan, p)
			continue
		}
		reg, ok := r.reg.Lookup(c.UID)
		if !ok {
			// An inapplicable row nobody implements is OUT OF SCOPE, not
			// unmeasured. An APPLICABLE row nobody implements is a genuine gap
			// and stays a Skip, which is what the coverage report counts.
			if d, na := CatalogScope(c); na {
				p.Scope = &d
				plan = append(plan, p)
				continue
			}
			p.Skip = "no implementation registered"
			plan = append(plan, p)
			continue
		}
		p.Registration, p.Implemented = reg, true
		if missing := reg.MissingCapabilities(caps); len(missing) > 0 {
			p.Skip = "missing capability: " + strings.Join(missing, ", ")
		}
		plan = append(plan, p)
	}
	docRank := map[string]int{}
	for i, d := range r.cat.Docs() {
		docRank[d.Doc] = i
	}
	sort.SliceStable(plan, func(i, j int) bool {
		a, b := plan[i], plan[j]
		if da, db := docRank[a.Case.Doc], docRank[b.Case.Doc]; da != db {
			return da < db
		}
		if a.Registration.Order != b.Registration.Order {
			return a.Registration.Order < b.Registration.Order
		}
		return a.Case.UID < b.Case.UID
	})
	return plan
}

// capabilities merges the operator-declared capabilities with the ones the
// runner can determine for itself.
func (r *Runner) capabilities() map[string]bool {
	caps := map[string]bool{}
	for k, v := range r.opts.Capabilities {
		caps[k] = v
	}
	caps["capture"] = !r.opts.NoCapture
	caps["keylog"] = r.opts.KeyLogPath != ""
	caps["gridsim"] = r.opts.Targets.GridSimAdmin != ""
	// EITHER introspection transport satisfies the "gateway" capability. Tying
	// it to -gateway-ssh alone would make every check that reads a
	// config-derived fact skip on a local-exec run that can read them perfectly
	// well.
	caps["gateway"] = r.gateway().Available()
	caps["pki"] = r.opts.PKIDir != ""
	caps["bench"] = r.opts.Targets.Gateway != ""
	return caps
}

// Run executes the plan and writes the bundle.
func (r *Runner) Run(ctx context.Context) (*RunReport, error) {
	rep := &RunReport{
		Catalog:  r.cat.Ref(),
		Coverage: r.Coverage(),
		Plan:     r.Plan(),
		Started:  time.Now().UTC(),
		DryRun:   r.opts.DryRun,
		Campaign: r.campaign,
	}
	// A run that declared no campaign is exploratory by construction, and says
	// so from the first line rather than being discovered to be non-gating by
	// a reader of the bundle much later.
	if r.campaign.Name == "" {
		rep.Exploratory = "no -campaign was declared: this is an EXPLORATORY selection, and its result " +
			"is evidence about the implementation rather than a campaign anything may rest on"
	}
	reporter := NewReporter(r.out)
	reporter.Header(r, rep)
	if contested := contestedScope(rep.Plan); len(contested) > 0 {
		// The candidate's manifest and the conformance catalog disagree about
		// whether a row is in the claim. The manifest wins — it is the
		// candidate's own statement about itself — but the disagreement is
		// SHOUTED rather than applied quietly, because one of the two documents
		// is wrong and only the owner of the claim can say which.
		reporter.Line("SCOPE CONFLICT: %d row(s) are marked APPLICABLE by the catalog and OUT OF SCOPE by "+
			"the candidate manifest (%s). The manifest stands and those rows are recorded N/A with it "+
			"named as the source — but one of the two documents needs correcting: either the candidate "+
			"under-declares what it is, or the catalog over-claims for this profile",
			len(contested), firstUIDs(contested, 6))
	}

	if len(rep.Coverage.Orphans) > 0 {
		// A registration for a uid the catalog does not contain means the suite
		// and the specification have diverged. Refusing to run is the only
		// honest response: we cannot say what the extra check is testing.
		return rep, fmt.Errorf("certify: %d registered uid(s) are not in the catalog: %s",
			len(rep.Coverage.Orphans), strings.Join(rep.Coverage.Orphans, ", "))
	}
	if r.opts.DryRun {
		reporter.PlanListing(rep.Plan)
		reporter.CoverageListing(rep.Coverage)
		rep.Finished = time.Now().UTC()
		return rep, nil
	}

	// Before the capture, before the PKI, before anything that costs a bench:
	// establish that the topology the flags describe is the topology that
	// exists. A run that discovers this at the end discovers it as forty
	// minutes of findings about a device that was behaving perfectly. The dry
	// run above is exempt because it touches no bench at all.
	if err := r.preflight(ctx, reporter); err != nil {
		rep.Finished = time.Now().UTC()
		return rep, err
	}

	// Same discipline, one row over: a control row's own precondition is the
	// DUT's live control-authority posture, and nothing upstream of this loop
	// otherwise checked it before RBAC-002-MODEL704-REG40298-WRITE-DENIED-
	// ALL-ROLES (lexa-gw/docs/known_issues.json) shipped a battery that could
	// measure a lock-screen it never knew was engaged. This FAILS CLOSED: an
	// unprovable precondition ends the run here, before case 1, rather than
	// forty minutes later as a bundle full of findings about the arbitration
	// layer.
	auth, err := r.preflightAuthority(ctx, reporter, rep.Plan)
	rep.Authority = auth
	if auth.Unchecked != "" && rep.Exploratory == "" {
		rep.Exploratory = auth.Unchecked
	}
	if err != nil {
		rep.Finished = time.Now().UTC()
		return rep, err
	}

	// The candidate's declared topology, against the topology the DUT reports.
	// After the authority preflight because it uses the same channel, and
	// before the capture for the same reason everything else here is.
	if err := r.preflightManifest(ctx, reporter); err != nil {
		rep.Finished = time.Now().UTC()
		return rep, err
	}

	pki, pkiErr := (*PKI)(nil), error(nil)
	if r.opts.PKIDir != "" {
		pki, pkiErr = LoadPKI(r.opts.PKIDir)
		if pkiErr != nil {
			r.log.Printf("certify: PKI fixtures unavailable: %v", pkiErr)
		}
	}

	// One capture for the whole run. See the package doc for why.
	var capr Capturer
	captureRef := CaptureRef{KeyLogPath: r.opts.KeyLogPath}
	if !r.opts.NoCapture {
		var err error
		capr, err = r.newCapturer()
		if err != nil {
			return rep, err
		}
		if err := capr.Start(ctx); err != nil {
			return rep, fmt.Errorf("certify: start capture: %w", err)
		}
		captureRef = CaptureRef{
			Active: true, Path: capr.Path(), Interface: r.opts.Iface,
			Filter: r.opts.BPF, Started: time.Now().UTC(), KeyLogPath: r.opts.KeyLogPath,
		}
		reporter.Line("capture live: %s -> %s", ifaceLabel(r.opts.Iface), capr.Path())
	} else {
		reporter.Line("capture DISABLED (-no-capture): no wire citation is possible in this run")
	}

	sims := map[string]*SimClient{
		"modsim":   NewSimClient("modsim", r.opts.Targets.ModSimAPI, r.opts.HTTP),
		"mbapsdev": NewSimClient("mbapsdev", r.opts.Targets.MBAPSDevAPI, r.opts.HTTP),
	}
	for name, url := range r.opts.Targets.Extra {
		if strings.HasPrefix(url, "http") {
			sims[name] = NewSimClient(name, url, r.opts.HTTP)
		}
	}
	gridsim := NewAdminClient(r.opts.Targets.GridSimAdmin, r.opts.HTTP)
	gw := r.gateway()

	var windows []*Window
	runErr := error(nil)
	reporter.ExecutionBanner()
	for _, p := range rep.Plan {
		if err := ctx.Err(); err != nil {
			runErr = err
			reporter.Line("run cancelled: %v — %d case(s) not reached", err, len(rep.Plan)-len(rep.Cases))
			break
		}
		if p.OutOfScope() {
			// NOT a Skip. Nothing about this row was measurable because there
			// was nothing here to measure, and the record says who decided
			// that. One assertion carries the same statement so the case's
			// stored verdict follows from its own printed evidence and
			// bundle.Verify's roll-up agrees with it.
			res := CaseResult{
				Case: p.Case, Suite: p.Registration.Suite,
				Verdict: NotApplicable, Notes: p.Scope.Reason, Scope: p.Scope,
				Started: time.Now().UTC(),
				Assertions: []Assertion{{
					Claim:    "the test case is in scope for the candidate under test",
					Method:   "scope declaration (" + string(p.Scope.Source) + ")",
					Verdict:  NotApplicable,
					Observed: p.Scope.Reason,
					Note:     p.Scope.Detail,
				}},
			}
			rep.Cases = append(rep.Cases, res)
			reporter.Case(res)
			continue
		}
		if !p.Implemented || p.Skip != "" {
			res := CaseResult{
				Case: p.Case, Suite: p.Registration.Suite,
				Verdict: Skip, Notes: p.Skip, Started: time.Now().UTC(),
			}
			rep.Cases = append(rep.Cases, res)
			reporter.Case(res)
			continue
		}
		win := NewWindow(p.Case.UID, p.Registration.Suite)
		win.Guard = r.opts.Guard
		windows = append(windows, win)

		rc := &RunCtx{
			Case: p.Case, Suite: p.Registration.Suite, Registration: p.Registration,
			Targets: r.opts.Targets, PKI: pki, GridSim: gridsim, Sims: sims,
			Gateway: gw, Capture: captureRef, Params: r.opts.Params, Log: r.log,
			candidate: r.manifest,
		}
		// Cannot fail on a freshly built context; AttachWindow only refuses a
		// SECOND window, which is the invariant it exists to hold.
		if err := rc.AttachWindow(win); err != nil {
			panic(err)
		}
		res := r.execute(ctx, p, rc, win)
		rep.Cases = append(rep.Cases, res)
		reporter.Case(res)
	}

	if capr != nil {
		// Let the capture tool drain its ring before we interrupt it. See
		// Options.CaptureSettle: without this, the frames the last check caused
		// — or, on a fast run, every frame — are simply never written.
		if d := r.settle(); d > 0 {
			reporter.Line("settling %s so the capture flushes what the last check caused", d)
			time.Sleep(d)
		}
		sum, err := capr.Stop()
		rep.Capture = sum
		if err != nil {
			rep.CaptureProblems = append(rep.CaptureProblems, err.Error())
			reporter.Line("capture stopped with a problem: %v", err)
		} else {
			reporter.Line("capture stopped: %d frames, %d bytes", sum.Packets, sum.FileBytes)
		}
		// A capture that recorded nothing while checks were driving the wire is
		// an evidence failure, not a quiet curiosity. Left unsaid it surfaces
		// only as a pile of "PASS downgraded for want of a citation", which
		// reads like sloppy checks instead of a broken capture and sends the
		// reader looking in entirely the wrong place.
		if err == nil && sum.Packets == 0 && executedAny(rep) {
			rep.CaptureProblems = append(rep.CaptureProblems, fmt.Sprintf(
				"the capture on %s recorded ZERO frames although %d check(s) executed and drove the wire; "+
					"no citation in this bundle can be re-derived. Check the interface and the BPF filter (%s), "+
					"and that the capture tool has permission to see the traffic",
				ifaceLabel(r.opts.Iface), executedCount(rep), orNoFilter(r.opts.BPF)))
			reporter.Line("CAPTURE INTEGRITY: zero frames recorded while %d check(s) ran", executedCount(rep))
		}
	}

	// Citation phase.
	if capr != nil {
		if err := r.cite(ctx, rep, windows, capr.Path(), reporter); err != nil {
			rep.CaptureProblems = append(rep.CaptureProblems, err.Error())
		}
	} else {
		r.citeWithoutCapture(rep)
	}

	r.finalise(rep)
	rep.Finished = time.Now().UTC()
	reporter.Reconcile(rep)

	if !r.opts.DryRun && r.opts.OutDir != "" {
		b, dir, err := r.writeBundle(rep, capr)
		if err != nil {
			return rep, err
		}
		rep.Bundle, rep.BundleDir = b, dir
		reporter.Line("bundle written: %s", dir)
	}
	reporter.Summary(rep)
	if runErr == nil && r.opts.RequireCoverage {
		// A CI gate needs the exit code to carry the coverage verdict, not just
		// the console text: an unimplemented applicable test case is a defect in
		// the tool, and a green pipeline over an incomplete run is the exact
		// dishonesty this framework exists to prevent.
		if missing := rep.Unaddressed(); len(missing) > 0 {
			runErr = fmt.Errorf("certify: %d applicable test case(s) have no implementation: %s",
				len(missing), strings.Join(entryUIDs(missing), ", "))
		}
	}
	return rep, runErr
}

// contestedScope lists the rows whose manifest-derived scope decision
// contradicts the catalog. See ScopeDecision.Contested.
func contestedScope(plan []Planned) []string {
	var out []string
	for _, p := range plan {
		if p.Scope != nil && p.Scope.Contested && p.Case != nil {
			out = append(out, p.Case.UID)
		}
	}
	sort.Strings(out)
	return out
}

// unknownSuites returns the requested suite names no registration uses.
func unknownSuites(reg *Registry, want []string) []string {
	if len(want) == 0 {
		return nil
	}
	have := reg.Suites()
	var unknown []string
	for _, w := range want {
		if !containsFold(have, w) {
			unknown = append(unknown, w)
		}
	}
	return unknown
}

// settle resolves the capture settle interval.
//
// Zero takes the default, and a negative value disables it. An INJECTED
// capturer (Options.Capturer, which is how a test drives the runner without a
// NIC) defaults to none: it has no child process and no kernel ring, so there
// is nothing to flush and no reason to make every framework test wait
// three-quarters of a second to prove it. Setting the field explicitly still
// wins, for the test that injects a real capture.Capture.
func (r *Runner) settle() time.Duration {
	switch {
	case r.opts.CaptureSettle < 0:
		return 0
	case r.opts.CaptureSettle > 0:
		return r.opts.CaptureSettle
	case r.opts.Capturer != nil:
		return 0
	default:
		return DefaultCaptureSettle
	}
}

// executedAny reports whether any check actually ran.
func executedAny(rep *RunReport) bool { return executedCount(rep) > 0 }

func executedCount(rep *RunReport) int {
	n := 0
	for _, c := range rep.Cases {
		if c.Executed {
			n++
		}
	}
	return n
}

func orNoFilter(bpf string) string {
	if strings.TrimSpace(bpf) == "" {
		return "no filter"
	}
	return bpf
}

func entryUIDs(es []CoverageEntry) []string {
	out := make([]string, len(es))
	for i, e := range es {
		out[i] = e.UID
	}
	return out
}

// ifaceLabel renders the capture interface for a human.
//
// A single interface renders as itself — every report line and every bundle
// string a reviewer may be diffing against an earlier run is unchanged. Only
// the split-bench form gains words, because "wlp2s0,enp1s0" in a sentence about
// "the capture interface" reads like one oddly-named NIC.
func ifaceLabel(spec string) string {
	names := capture.SplitInterfaces(spec)
	if len(names) <= 1 {
		return spec
	}
	return fmt.Sprintf("%s (%d interfaces, one capture)", strings.Join(names, " + "), len(names))
}

// interfaceCoverage reports a leg of a split capture that recorded nothing.
//
// This is the split-bench evidence gap in its new disguise. A run that captures
// only one side does not FAIL: the rows resting on the other side's frames
// simply find none and are downgraded for want of a citation, which reads like
// sloppy checks and sends the reader to the wrong place entirely. So a silent
// leg is named here, once, as a capture problem.
//
// The id-to-name mapping is dumpcap's: it writes one Interface Description
// Block per -i, in the order given, so pcapng interface id N is the Nth name.
// Where the file disagrees with that (fewer described interfaces than names
// asked for) the message says so rather than guessing.
func interfaceCoverage(spec string, pkts []pcapng.Packet) string {
	names := capture.SplitInterfaces(spec)
	if len(names) < 2 || len(pkts) == 0 {
		// One interface has no coverage question to answer, and a capture with
		// no frames at all is already reported, loudly, by the caller.
		return ""
	}
	counts := make([]int, len(names))
	beyond := 0
	for _, p := range pkts {
		if p.Interface >= 0 && p.Interface < len(counts) {
			counts[p.Interface]++
			continue
		}
		beyond++
	}
	var silent []string
	for i, n := range counts {
		if n == 0 {
			silent = append(silent, names[i])
		}
	}
	if len(silent) == 0 {
		return ""
	}
	per := make([]string, len(names))
	for i, n := range counts {
		per[i] = fmt.Sprintf("%s=%d", names[i], n)
	}
	msg := fmt.Sprintf("the capture covered %s but recorded ZERO frames on %s (frames per interface: %s). "+
		"Every citation that rests on that leg's traffic is unavailable, and the cases resting on it will "+
		"read as uncited rather than failed. Check that the interface is up and carrying the leg's traffic, "+
		"and that the BPF filter can match on it",
		strings.Join(names, " + "), strings.Join(silent, " and "), strings.Join(per, ", "))
	if beyond > 0 {
		msg += fmt.Sprintf(". %d frame(s) name an interface id beyond the %d requested, so the "+
			"id-to-name mapping above may not be the capture's", beyond, len(names))
	}
	return msg
}

// newCapturer builds the real capture, or returns the injected one.
func (r *Runner) newCapturer() (Capturer, error) {
	if r.opts.Capturer != nil {
		return r.opts.Capturer, nil
	}
	dir := r.opts.OutDir
	if dir == "" {
		dir = "."
	}
	path := filepath.Join(dir, "capture", fmt.Sprintf("run-%s.pcapng", time.Now().UTC().Format("20060102-150405")))
	c, err := capture.New(r.opts.Iface, r.opts.BPF, path)
	if err != nil {
		return nil, fmt.Errorf("certify: prepare capture: %w", err)
	}
	return c, nil
}

// execute runs one check inside a recover and a timeout.
func (r *Runner) execute(ctx context.Context, p Planned, rc *RunCtx, win *Window) CaseResult {
	res := CaseResult{
		Case: p.Case, Suite: p.Registration.Suite,
		Started: time.Now().UTC(), Executed: true,
		captureArtifacts: p.Registration.CaptureArtifacts,
	}
	to := r.opts.CheckTimeout
	if p.Registration.Timeout > 0 {
		// A per-registration override (Registration.Timeout / WithTimeout) —
		// a check whose own procedure has to wait out a DUT's independent
		// cadence, not the run's global -timeout tuned for the common case.
		to = p.Registration.Timeout
	}
	cctx, cancel := context.WithTimeout(ctx, to)
	defer cancel()

	win.Open(time.Now().UTC())
	out, err := runCheck(cctx, p.Registration.Check, rc)
	win.Close(time.Now().UTC())
	res.Duration = time.Since(res.Started)

	if err != nil {
		// The check could not be carried out. That is a FAIL, not a SKIP:
		// "we could not test it" must never read like "it passed".
		res.Verdict = Fail
		res.Err = err
		res.Notes = "check could not be carried out: " + err.Error()
		if pe, ok := err.(*panicError); ok {
			res.Panic = pe.stack
			res.Notes = "check PANICKED: " + pe.value + " — this is a bug in the suite, not a DUT failure"
		}
		res.Assertions = append(res.Assertions, Assertion{
			Claim:    "the test case was carried out",
			Method:   "runner",
			Verdict:  Fail,
			Observed: err.Error(),
			Note:     "no conformance conclusion about the DUT can be drawn from this row",
		})
		return res
	}
	res.Verdict = out.rollUp()
	res.LiveVerdict = res.Verdict
	res.Notes = out.Notes
	res.Assertions = append(res.Assertions, out.Assertions...)
	res.cite = out.Cite
	res.offWire = out.OffWire
	res.offWireReason = out.OffWireReason
	res.metrics = out.Metrics
	return res
}

// panicError carries a recovered panic out of runCheck.
type panicError struct {
	value string
	stack string
}

func (e *panicError) Error() string { return "panic: " + e.value }

// runCheck is the recover boundary. It is a separate function so the deferred
// recover applies to exactly one call and nothing else.
func runCheck(ctx context.Context, check Check, rc *RunCtx) (res Result, err error) {
	defer func() {
		if v := recover(); v != nil {
			err = &panicError{value: fmt.Sprint(v), stack: string(debug.Stack())}
			res = Result{}
		}
	}()
	return check(ctx, rc)
}

// runCite is the recover boundary for the citation phase.
func runCite(ctx context.Context, fn CiteFunc, ev *Evidence) (as []Assertion, err error) {
	defer func() {
		if v := recover(); v != nil {
			err = &panicError{value: fmt.Sprint(v), stack: string(debug.Stack())}
			as = nil
		}
	}()
	return fn(ctx, ev)
}

// cite reads the capture back, attributes frames, and runs the citation phase.
func (r *Runner) cite(ctx context.Context, rep *RunReport, windows []*Window, path string, reporter *Reporter) error {
	fi, err := LoadFrameIndex(path)
	if err != nil {
		r.citeWithoutCapture(rep)
		return err
	}
	rep.CaptureProblems = append(rep.CaptureProblems, fi.Problems...)
	if msg := interfaceCoverage(r.opts.Iface, fi.Packets()); msg != "" {
		rep.CaptureProblems = append(rep.CaptureProblems, msg)
		reporter.Line("CAPTURE INTEGRITY: %s", msg)
	}
	att := fi.Attribute(windows)
	rep.Attribution = att
	// A genuine reuse ambiguity (see window.go's markAmbiguous) is folded into
	// CaptureProblems, not just left inside the Attribution struct: that is
	// what makes rep.OK() go false and the ambiguity impossible to miss in the
	// bundle, rather than something a reader would have to notice went missing
	// from a frame count.
	rep.CaptureProblems = append(rep.CaptureProblems, att.Ambiguous...)
	reporter.Line("attribution: %s", att.Summary())
	if len(att.Contested) > 0 {
		reporter.Line("WARNING: %d frame(s) were claimed by more than one test case and attributed to none",
			len(att.Contested))
	}
	for _, msg := range att.Ambiguous {
		reporter.Line("WARNING: %s", msg)
	}

	var kl *keylog.Log
	if r.opts.KeyLogPath != "" {
		if kl, err = keylog.Open(r.opts.KeyLogPath); err != nil {
			rep.CaptureProblems = append(rep.CaptureProblems,
				fmt.Sprintf("key log %s could not be read: %v — encrypted payload claims are not verifiable",
					r.opts.KeyLogPath, err))
			kl = nil
		}
	}

	// The per-test captures the governing documents name go out BEFORE the
	// citation phase, from the same attribution the assertions use, so that a
	// check whose citation callback fails still leaves the evidence files a
	// submission needs. They are slices of the run capture, not new
	// observations; see artifacts.go.
	artDir := filepath.Join(r.opts.OutDir, "capture")

	for i := range rep.Cases {
		c := &rep.Cases[i]
		if !c.Executed {
			continue
		}
		set := att.Set(c.Case.UID)
		c.FrameSet = set
		c.Frames = set.Frames
		if len(c.captureArtifacts) > 0 {
			rep.CaptureArtifacts = append(rep.CaptureArtifacts,
				exportCaseCaptures(fi, set, c.Case.UID, c.captureArtifacts, artDir)...)
		}
		if c.cite == nil {
			continue
		}
		ev := &Evidence{
			Case: c.Case, Set: set, Index: fi, KeyLog: kl,
			Capture: rep.Capture, Attribution: att,
		}
		as, err := runCite(ctx, c.cite, ev)
		if err != nil {
			// A citation callback that fails has not produced evidence, and a
			// verdict reached without evidence is not a verdict.
			c.Verdict = Fail
			note := "citation phase failed: " + err.Error()
			if pe, ok := err.(*panicError); ok {
				c.Panic = pe.stack
				note = "citation phase PANICKED: " + pe.value + " — a suite bug, not a DUT failure"
			}
			c.Notes = joinNote(c.Notes, note)
			c.Assertions = append(c.Assertions, Assertion{
				Claim: "the test case's wire evidence was collected", Method: "runner",
				Verdict: Fail, Observed: err.Error(),
			})
			continue
		}
		c.Assertions = append(c.Assertions, as...)
		if worst := worstOf(as); worst.Severity() > c.Verdict.Severity() {
			c.Verdict = worst
		}
		// A CiteFunc may only discover once the capture is in hand that this
		// row's criterion cannot be cut from it for a stated non-product reason
		// (TLS resumption is the canonical one — see DeclareOffWire). Carry that
		// into the same off-wire bookkeeping a Result.OffWire feeds, so finalise
		// suppresses the misleading "uncited PASS -> WARN" downgrade. A live-phase
		// off-wire declaration already set is never un-set.
		if ow, reason := ev.OffWire(); ow && !c.offWire {
			c.offWire = true
			c.offWireReason = reason
		}
	}
	return nil
}

// citeWithoutCapture records, on every case that expected to cite, that it
// could not — rather than letting the verdicts stand as if it had.
func (r *Runner) citeWithoutCapture(rep *RunReport) {
	for i := range rep.Cases {
		c := &rep.Cases[i]
		if !c.Executed || c.cite == nil {
			continue
		}
		c.Assertions = append(c.Assertions, Assertion{
			Claim:    "the test case's wire facts were cited from the capture",
			Method:   "runner",
			Verdict:  Skip,
			Observed: "no capture was taken in this run, so no frame citation exists",
		})
		if c.Verdict == Pass {
			c.Verdict = Warn
			c.Downgraded = "PASS downgraded: the run had no capture, so nothing is re-checkable"
		}
	}
}

// finalise applies the uncited-PASS rule, rolls the verdicts up, and records
// every case whose verdict moved away from what the live phase declared.
func (r *Runner) finalise(rep *RunReport) {
	for i := range rep.Cases {
		c := &rep.Cases[i]
		if worst := worstOf(c.Assertions); worst.Severity() > c.Verdict.Severity() {
			c.Verdict = worst
		}
		if c.Executed && c.LiveVerdict != "" && c.Verdict != c.LiveVerdict {
			c.Reconciled = fmt.Sprintf(
				"the live phase declared %s from what the socket saw; the citation phase re-derived the "+
					"criteria from the capture and the case is %s. The capture-derived verdict is the one "+
					"that stands: it is the only one a reader of this bundle can repeat.",
				c.LiveVerdict, c.Verdict)
			c.Notes = joinNote(c.Notes, "VERDICT RECONCILED — "+c.Reconciled)
		}
		if c.Verdict != Pass || !r.opts.RequireCitation {
			continue
		}
		if c.Citable() {
			continue
		}
		if c.offWire {
			reason := c.offWireReason
			if reason == "" {
				reason = "declared off-wire without a reason — the declaration itself is unevidenced"
			}
			c.Notes = joinNote(c.Notes, "off-wire criterion: "+reason)
			continue
		}
		c.Verdict = Warn
		c.Downgraded = "PASS downgraded to WARN: no assertion carries a digest the bundle's verifier can " +
			"re-derive from the capture"
		c.Notes = joinNote(c.Notes, c.Downgraded)
	}
}

// worstOf is the runner's roll-up: the worst verdict among a set of assertions,
// CAPPED below PASS when a LOAD-BEARING one skipped.
//
// The cap mirrors bundle.TestCaseResult.RollUp exactly, and it has to: this
// function decides the verdict the runner records and RollUp decides the one
// the bundle carries, so the two disagreeing would put a case in a bundle whose
// own assertions do not roll up to its stated verdict. See
// bundle.Assertion.LoadBearing for why the cap exists at all — Skip is severity
// 0 and a maximum-taking roll-up cannot be dented by it, so a case whose "did
// the device do it" assertion skipped otherwise passes on its supporting wire
// assertions alone.
//
// It changes no verdict on a suite whose load-bearing criteria already have no
// Skip path, which is every one of them today; it is the structural guard
// against the next criterion that grows one.
func worstOf(as []Assertion) Verdict {
	worst := Verdict("")
	unmeasured := false
	for _, a := range as {
		if a.Verdict.Severity() > worst.Severity() {
			worst = a.Verdict
		}
		if a.Unmeasured() {
			unmeasured = true
		}
	}
	if unmeasured && worst.Severity() < Warn.Severity() {
		return Warn
	}
	return worst
}

// writeBundle materialises the evidence bundle.
func (r *Runner) writeBundle(rep *RunReport, capr Capturer) (*bundle.Bundle, string, error) {
	dir := r.opts.OutDir
	commit, dirty := bundle.GitCommit(".")
	note := strings.TrimSpace(r.opts.Note)
	// bundle.json's schema is fixed and its loader rejects unknown fields, so
	// the catalog's identity travels in the run note — and the catalog FILE
	// itself is copied in below, where the manifest covers it. A reader can
	// therefore re-derive the digest rather than trust this line.
	note = joinNote(note, "catalog: "+rep.Catalog.String())
	if rep.Attribution != nil {
		note = joinNote(note, "frame attribution: "+rep.Attribution.Summary())
	}
	if len(rep.CaptureProblems) > 0 {
		note = joinNote(note, "capture integrity: "+strings.Join(rep.CaptureProblems, "; "))
	}
	note = joinNote(note, captureArtifactNote(rep.CaptureArtifacts))
	// A bypassed preflight travels with the evidence it weakens. RunMeta.Command
	// already carries the flag; this says what the flag COST, which is the part
	// a reader of the findings needs.
	if r.opts.SkipPreflight {
		note = joinNote(note, SkipPreflightNote)
	}
	if rep.Exploratory != "" {
		note = joinNote(note, "EXPLORATORY, NOT GATING: "+rep.Exploratory)
	}
	if contested := contestedScope(rep.Plan); len(contested) > 0 {
		note = joinNote(note, fmt.Sprintf("SCOPE CONFLICT: %d row(s) the catalog marks applicable were "+
			"recorded N/A on the candidate manifest's declaration (%s). The manifest is the candidate's "+
			"own statement and stands, but the two documents disagree and one of them needs correcting",
			len(contested), firstUIDs(contested, 8)))
	}

	b := bundle.NewBuilder(bundle.RunMeta{
		Tool: ToolName, ToolVersion: rep.Catalog.SHA256[:12],
		GitCommit: commit, GitDirty: dirty,
		// The redaction happens HERE, at the one door every entry point walks
		// through to reach a bundle, rather than at each caller — a rule
		// applied in several places is a rule that will one day be applied in
		// all but one.
		Command:  bundle.RedactCommand(r.opts.Command),
		Operator: r.opts.Operator, Note: note,
		Started: rep.Started, Finished: time.Now().UTC(),
		DUT: r.opts.DUT,
	})
	// The campaign record: what this bundle is evidence FOR, and whether it may
	// decide anything. Written on every run, exploratory ones included — "this
	// bundle is not gating" is a fact a CI gate must be able to read directly
	// rather than infer from a missing key.
	campaign := bundle.CampaignRecord{
		Name:        string(rep.Campaign.Name),
		Suites:      append([]string(nil), rep.Campaign.Suites...),
		Gating:      rep.Gating(),
		Exploratory: rep.Exploratory,
	}
	if rep.Authority.Required != AuthorityAny {
		campaign.Authority = string(rep.Authority.Required)
	}
	if rep.Authority.Reading != nil {
		campaign.AuthorityObserved = string(rep.Authority.Reading.Live)
	}
	b.SetCampaign(campaign)
	// The candidate manifest travels WITH its digest and WITH the file, so a
	// reader can hash the copy in front of them and confirm the scope decisions
	// in this bundle were made against it.
	if r.manifest != nil {
		b.SetCandidate(bundle.CandidateRef{
			Path:    r.manifest.Path(),
			SHA256:  r.manifest.SHA256(),
			Profile: r.manifest.Profile,
		})
		if _, err := os.Stat(r.manifest.Path()); err == nil {
			b.AddFile(r.manifest.Path())
		}
	}
	if capr != nil {
		b.SetCapture(rep.Capture, capr.Path())
	}
	if r.opts.KeyLogPath != "" {
		if _, err := os.Stat(r.opts.KeyLogPath); err == nil {
			b.SetKeyLog(r.opts.KeyLogPath)
		}
	}
	// The per-test captures a governing document names, under exactly those
	// names, beside the run capture they were cut from.
	for _, a := range rep.CaptureArtifacts {
		if a.Path != "" {
			b.AddCaptureFile(a.Path)
		}
	}
	// The specification the run was measured against ships inside the bundle,
	// so "which catalog?" is answerable by hashing a file the reader has.
	if p := r.cat.Path(); p != "" {
		if _, err := os.Stat(p); err == nil {
			b.AddFile(p)
		}
	}

	staging, err := os.MkdirTemp("", "certify-bundle-")
	if err != nil {
		return nil, "", fmt.Errorf("certify: staging directory: %w", err)
	}
	defer func() { _ = os.RemoveAll(staging) }()
	covPath := filepath.Join(staging, "COVERAGE.md")
	if err := os.WriteFile(covPath, []byte(CoverageMarkdown(rep.Coverage, rep.Plan)), 0o644); err != nil {
		return nil, "", fmt.Errorf("certify: write coverage: %w", err)
	}
	b.AddFile(covPath)

	for _, c := range rep.Cases {
		// The DUT's own counter readings, before the case that took them, so
		// the builder persists both raw exposition bodies and verify can
		// re-derive every delta from them rather than trusting the numbers a
		// check reported (IW15-030).
		for _, m := range c.metrics {
			b.AddMetrics(m)
		}
		b.AddCase(bundle.TestCaseResult{
			ID:         c.Case.UID,
			Doc:        fmt.Sprintf("%s %s §%s", c.Case.Doc, c.Case.DocVersion, c.Case.Section),
			Title:      c.Case.Title,
			Verdict:    c.Verdict,
			Applicable: c.Case.Applicable,
			// Written only when the case is NON-certifiable, so a bundle from a
			// campaign of published procedures is byte-identical to before.
			NonCertifiable: c.Case.Certifiable != nil && !*c.Case.Certifiable,
			// Present exactly when the verdict is N/A: bundle.Verify refuses a
			// bundle where the two disagree in either direction.
			NotApplicable: naRecord(c),
			Notes:         caseNotes(c),
			Assertions:    c.Assertions,
		})
	}
	out, err := b.Write(dir)
	if err != nil {
		return nil, "", fmt.Errorf("certify: write bundle: %w", err)
	}
	return out, dir, nil
}

// naRecord renders a case's scope decision for the bundle, or nil.
func naRecord(c CaseResult) *bundle.NotApplicable {
	if c.Verdict != NotApplicable || c.Scope == nil {
		return nil
	}
	return c.Scope.Record()
}

// caseNotes assembles the prose the bundle records for a case: the check's own
// notes, the attribution facts, and anything the runner had to say about the
// verdict.
func caseNotes(c CaseResult) string {
	parts := []string{}
	if c.Notes != "" {
		// LABELLED as the live phase's observation. Printing it bare, directly
		// under a case heading that carries the capture-derived verdict, is how
		// a report comes to say "✓ PASS the DUT tore the session down" three
		// lines above "FAIL — the DUT sent no fatal alert" and leave the reader
		// to work out which one is the finding. They are two different
		// instruments looking at the same event, and the report should say so.
		lead := "Live-phase observation (what the check's own socket saw; the numbered assertions below are " +
			"re-derived from the capture and are the verdict): "
		if c.Executed {
			parts = append(parts, lead+c.Notes)
		} else {
			parts = append(parts, c.Notes)
		}
	}
	if c.FrameSet != nil && c.Executed {
		parts = append(parts, fmt.Sprintf(
			"Frame attribution: %d frame(s) (%s), precision %s; %d frame(s) inside the window belonged to "+
				"other conversations and were excluded.",
			len(c.FrameSet.Frames), c.FrameSet.Span(), c.FrameSet.Precision, c.FrameSet.TimeOnlyRejected))
		if len(c.FrameSet.Contested) > 0 {
			parts = append(parts, fmt.Sprintf(
				"%d frame(s) were claimed by more than one test case and attributed to none: %v",
				len(c.FrameSet.Contested), firstN(c.FrameSet.Contested, 12)))
		}
		if len(c.FrameSet.Claims) > 0 {
			parts = append(parts, "Connections claimed: "+strings.Join(c.FrameSet.Claims, "; ")+".")
		}
	}
	if c.Panic != "" {
		parts = append(parts, "Panic stack:\n\n```\n"+c.Panic+"```")
	}
	return strings.Join(parts, "\n\n")
}

func firstSentence(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexAny(s, ".\n"); i > 0 {
		return s[:i+1]
	}
	if len(s) > 160 {
		return s[:160] + "…"
	}
	return s
}

// endpointFlag binds a flag straight into Targets.Extra, so a suite-specific
// endpoint needs a flag and a key rather than a new Targets field and edits in
// three files.
type endpointFlag struct {
	t   *Targets
	key string
}

func (e endpointFlag) String() string {
	if e.t == nil {
		return ""
	}
	return e.t.Endpoint(e.key)
}

func (e endpointFlag) Set(v string) error {
	e.t.WithEndpoint(e.key, v)
	return nil
}
