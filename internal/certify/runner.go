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

	"csip-tls-test/internal/evidence/bundle"
	"csip-tls-test/internal/evidence/capture"
	"csip-tls-test/internal/evidence/keylog"
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

	// DryRun lists what would run and writes no bundle.
	DryRun bool

	// Capture.
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
	Targets    Targets
	PKIDir     string
	GatewaySSH string
	HTTP       HTTPClient

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

// BindFlags registers the runner's command-line surface. A suite binary calls
// it, parses, and hands the Options to New.
func (o *Options) BindFlags(fs *flag.FlagSet) {
	fs.StringVar(&o.CatalogPath, "catalog", o.CatalogPath, "path to catalog.json (default: nearest "+CatalogFile+")")
	fs.Var(stringList{&o.Docs}, "doc", "only run cases from these catalog documents (repeatable, comma-separated)")
	fs.Var(stringList{&o.UIDs}, "uid", "only run these catalog uids or ids (repeatable, comma-separated)")
	fs.Var(stringList{&o.Suites}, "suite", "only run these suites (repeatable, comma-separated)")
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
	fs.StringVar(&o.Iface, "iface", o.Iface, "capture interface")
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
	fs.StringVar(&o.Targets.Gateway, "gateway", o.Targets.Gateway, "DUT mbaps address host:port")
	fs.StringVar(&o.Targets.GridSim, "gridsim", o.Targets.GridSim, "2030.5 server simulator host:port")
	fs.StringVar(&o.Targets.GridSimAdmin, "gridsim-admin", o.Targets.GridSimAdmin, "gridsim admin API base URL")
	fs.StringVar(&o.Targets.ModSim, "modsim", o.Targets.ModSim, "plain SunSpec Modbus sim host:port")
	fs.StringVar(&o.Targets.ModSimAPI, "modsim-api", o.Targets.ModSimAPI, "modsim simapi base URL")
	fs.StringVar(&o.Targets.MBAPSDev, "mbapsdev", o.Targets.MBAPSDev, "secure Modbus device sim host:port")
	fs.StringVar(&o.Targets.MBAPSDevAPI, "mbapsdev-api", o.Targets.MBAPSDevAPI, "mbapsdev simapi base URL")
	fs.DurationVar(&o.CheckTimeout, "timeout", o.CheckTimeout, "per-check timeout")
	fs.Var(keyValue{&o.Params}, "param", "procedure parameter key=value (repeatable)")
	fs.BoolVar(&o.RequireCitation, "require-citation", o.RequireCitation, "downgrade a PASS with no re-checkable citation to WARN")
	fs.BoolVar(&o.RequireCoverage, "require-coverage", o.RequireCoverage, "fail the run if an applicable test case has no implementation")
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
	// implementation, a missing capability, a suite filter.
	Skip string
}

// CaseResult is one test case's outcome.
type CaseResult struct {
	Case    *Case
	Suite   string
	Verdict Verdict
	Notes   string
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
	Bundle          *bundle.Bundle
	BundleDir       string
	Started         time.Time
	Finished        time.Time
	DryRun          bool
}

// Counts tallies the cases by verdict.
func (r *RunReport) Counts() (pass, fail, skip, warn int) {
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

// OK reports a clean run: every applicable selected case addressed, no FAIL,
// no orphaned registration, no capture-integrity problem.
func (r *RunReport) OK() bool {
	_, fail, _, _ := r.Counts()
	return fail == 0 && r.Coverage.Complete() && len(r.CaptureProblems) == 0
}

// Runner executes a run.
type Runner struct {
	reg  *Registry
	cat  *Catalog
	opts Options
	log  Logger
	out  io.Writer
}

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
	if err := cat.Validate(opts.Filter()); err != nil {
		return nil, err
	}
	// A -suite name nobody registered selects nothing, and "nothing" would be
	// reported as a clean run of zero test cases — the same silent-typo failure
	// Catalog.Validate exists to prevent for -doc and -uid. Refuse instead, and
	// name what IS available.
	if unknown := unknownSuites(reg, opts.Suites); len(unknown) > 0 {
		return nil, fmt.Errorf("certify: no suite named %s (have: %s)",
			strings.Join(unknown, ", "), strings.Join(reg.Suites(), ", "))
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
		reg:  reg,
		cat:  cat,
		opts: opts,
		log:  opts.Log,
		out:  opts.Out,
	}
	if r.log == nil {
		r.log = DiscardLogger
	}
	if r.out == nil {
		r.out = os.Stdout
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
		reg, ok := r.reg.Lookup(c.UID)
		if !ok {
			p.Skip = "no implementation registered"
			if !c.Applicable {
				p.Skip = "not applicable to this product: " + firstSentence(c.ApplicabilityReason)
			}
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
	caps["gateway"] = r.opts.GatewaySSH != ""
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
	}
	reporter := NewReporter(r.out)
	reporter.Header(r, rep)

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
		reporter.Line("capture live: %s -> %s", r.opts.Iface, capr.Path())
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
	gw := &Gateway{SSH: r.opts.GatewaySSH}

	var windows []*Window
	runErr := error(nil)
	reporter.ExecutionBanner()
	for _, p := range rep.Plan {
		if err := ctx.Err(); err != nil {
			runErr = err
			reporter.Line("run cancelled: %v — %d case(s) not reached", err, len(rep.Plan)-len(rep.Cases))
			break
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
			win: win,
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
				r.opts.Iface, executedCount(rep), orNoFilter(r.opts.BPF)))
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
	}
	cctx, cancel := context.WithTimeout(ctx, r.opts.CheckTimeout)
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
	att := fi.Attribute(windows)
	rep.Attribution = att
	reporter.Line("attribution: %s", att.Summary())
	if len(att.Contested) > 0 {
		reporter.Line("WARNING: %d frame(s) were claimed by more than one test case and attributed to none",
			len(att.Contested))
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

	for i := range rep.Cases {
		c := &rep.Cases[i]
		if !c.Executed {
			continue
		}
		set := att.Set(c.Case.UID)
		c.FrameSet = set
		c.Frames = set.Frames
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

func worstOf(as []Assertion) Verdict {
	worst := Verdict("")
	for _, a := range as {
		if a.Verdict.Severity() > worst.Severity() {
			worst = a.Verdict
		}
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

	b := bundle.NewBuilder(bundle.RunMeta{
		Tool: ToolName, ToolVersion: rep.Catalog.SHA256[:12],
		GitCommit: commit, GitDirty: dirty,
		Operator: r.opts.Operator, Note: note,
		Started: rep.Started, Finished: time.Now().UTC(),
		DUT: r.opts.DUT,
	})
	if capr != nil {
		b.SetCapture(rep.Capture, capr.Path())
	}
	if r.opts.KeyLogPath != "" {
		if _, err := os.Stat(r.opts.KeyLogPath); err == nil {
			b.SetKeyLog(r.opts.KeyLogPath)
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
	if err := os.WriteFile(covPath, []byte(CoverageMarkdown(rep.Coverage)), 0o644); err != nil {
		return nil, "", fmt.Errorf("certify: write coverage: %w", err)
	}
	b.AddFile(covPath)

	for _, c := range rep.Cases {
		b.AddCase(bundle.TestCaseResult{
			ID:         c.Case.UID,
			Doc:        fmt.Sprintf("%s %s §%s", c.Case.Doc, c.Case.DocVersion, c.Case.Section),
			Title:      c.Case.Title,
			Verdict:    c.Verdict,
			Notes:      caseNotes(c),
			Assertions: c.Assertions,
		})
	}
	out, err := b.Write(dir)
	if err != nil {
		return nil, "", fmt.Errorf("certify: write bundle: %w", err)
	}
	return out, dir, nil
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
