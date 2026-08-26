// Command certify drives the LEXA DER gateway through the published
// SunSpec / CSIP conformance test procedures and emits an EVIDENCE BUNDLE a
// third party can verify without trusting us: a packet capture plus a
// machine-checkable mapping from each test case to the exact frames and wire
// facts that demonstrate its pass criteria.
//
// # The six things it does
//
//	certify -list                                   what the catalog contains, and what is implemented
//	certify -doc SSM-CONF-v0.8 -dry-run             what a selection would run, and the gaps
//	certify -target 69.0.0.2:802 -iface enp1s0 -out runs/<ts>/    a real run
//	certify -verify runs/<ts>/                      re-verify a bundle, standalone
//	certify -report runs/<ts>/ -config lab.json     emit the SunSpec submission report
//	certify -trr runs/<ts>/ -trr-out pkg/ -config lab.json
//	                                                build the whole Test Results Report package:
//	                                                both Results Reporting specifications, from
//	                                                one or more bundles
//
// The six are mutually exclusive and the parser says so, because "-verify a
// bundle while also running a campaign" has no meaning and guessing which the
// operator wanted is exactly the sort of helpfulness that produces evidence
// nobody can explain.
//
// # Campaigns, and what a bundle is allowed to decide
//
// A run is one of two things, and the bundle now says which.
//
// A CAMPAIGN (-campaign csip|mbaps|modbus-client) is a named, CLOSED selection
// whose DUT precondition — which control-arbitration lane must own the DER — is
// PROVEN before case 1 and recorded. It requires -manifest, refuses -suite, and
// is the only shape whose result may gate anything.
//
// Everything else is EXPLORATORY: still captured, bundled and self-verified, and
// marked NOT GATING. A whole-catalog run cannot be anything else — it selects
// rows needing both control-authority postures at once, which no device can
// hold, and it says so rather than quietly measuring the arbitration layer.
//
// See docs/CAMPAIGNS.md for the campaign table, the fail-closed rules, the N/A
// verdict's semantics, the local-exec introspection runner and -preset local.
//
// # Why this binary links every suite
//
// It imports internal/certify/suites, which links all six. Two consequences are
// intentional. First, coverage is honest: the tool cannot report a document as
// unaddressed merely because the binary that printed the report was built
// without the package implementing it. Second, the registry panics at init on a
// duplicate catalog uid, so two suites claiming the same test case fails at
// process start, loudly, before any evidence exists — not silently, at run
// time, with an arbitrary winner.
//
// # What it refuses to do
//
//   - Report a PASS that carries no re-checkable citation. The runner
//     downgrades it to WARN and prints why, unless the check declared the
//     criterion off-wire with a reason (-require-citation, default on).
//   - Claim a key log it cannot produce. -keylog against a binary built without
//     -tags keylog is a hard error naming the sysroot and the tag, because a
//     run that believes its capture is decryptable and is not yields a bundle
//     that looks fine until someone tries to verify it.
//   - Hand back a bundle it has not verified. Every run that writes a bundle
//     re-verifies it from disk before printing the summary, and a bundle that
//     does not verify makes the run unclean whatever the test cases said.
//
// # Exit status
//
//	0  clean: every applicable selected case addressed, no FAIL, bundle verifies
//	1  a negative RESULT: a conformance failure, an unaddressed applicable case,
//	   a capture-integrity finding, a bundle that does not verify
//	2  the tool could not run: bad flags, no catalog, no capture interface
//
// The split matters for CI: exit 1 is a fact about the DUT or the evidence,
// exit 2 is a fact about the invocation, and a pipeline that cannot tell them
// apart will eventually treat a broken bench as a passing device.
//
// # Build configurations
//
// Ordinary (no TLS key export; encrypted payloads are not decryptable):
//
//	CGO_CFLAGS="-I$HOME/.local/wolfssl-amd64/include" \
//	CGO_LDFLAGS="-L$HOME/.local/wolfssl-amd64/lib -lwolfssl -lm" \
//	go build -o bin/certify ./cmd/certify              # make build-certify
//
// Evidence (exports NSS key-log lines so the capture decrypts):
//
//	CGO_CFLAGS="-I$HOME/.local/wolfssl-amd64-keylog/include" \
//	CGO_LDFLAGS="-L$HOME/.local/wolfssl-amd64-keylog/lib -lwolfssl -lm" \
//	go build -tags keylog -o bin/certify-keylog ./cmd/certify   # make certify-keylog
//
// A CGO_ENABLED=0 build also works and is not a lie: the mbaps (TLS) transport
// is absent, every check that needs it says so, and nothing degrades to
// plaintext against a DUT that has no plaintext port.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"csip-tls-test/internal/certify"
	"csip-tls-test/internal/certify/suites"
	"csip-tls-test/internal/evidence/bundle"
	"csip-tls-test/internal/writeset"
)

// Exit codes. See the package doc for why 1 and 2 are distinct.
const (
	exitOK    = 0
	exitFail  = 1
	exitUsage = 2
)

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

// invocation is the command line this process was started with, for the record
// the bundle keeps. The binary's own name is read rather than hardcoded because
// bin/certify and bin/certify-keylog are genuinely different programs — one can
// export TLS session secrets and one cannot — and a bundle whose invocation
// line said only "certify" would leave a reader guessing why its capture does
// or does not decrypt.
//
// The values are not redacted here. That happens once, in the runner, on the
// way into the bundle: see certify.Options.Command.
func invocation(args []string) []string {
	name := "certify"
	if len(os.Args) > 0 && os.Args[0] != "" {
		name = filepath.Base(os.Args[0])
	}
	return append([]string{name}, args...)
}

// cli is the flag surface: the runner's own options plus the mode selectors and
// the report-generation inputs the runner has no opinion about.
type cli struct {
	opts certify.Options

	// Mode selectors.
	list         bool
	verify       string
	report       string
	writes       string
	writesMRID   string
	writesUntil  string
	writesSettle time.Duration
	// trr names the evidence bundles a Test Results Report package is built
	// from, each optionally narrowed to some of its documents as `dir=<doc-key>`.
	trr      []string
	showCaps bool

	// target is an alias for -gateway, because "the target" is what an operator
	// calls the DUT and what every other tool in this bench spells -target. It
	// wins over -gateway when both are given, and the summary prints what was
	// used, so the precedence is never a guess.
	target string

	// Report generation.
	configPath      string
	reportOut       string
	trrOut          string
	certType        string
	allowIncomplete bool
	deriveLogs      bool

	// DUT identification, recorded in the bundle.
	dutName     string
	dutIdentity string
	dutRole     string
	dutBuild    string

	// caps are extra capability tags the operator asserts (things the runner
	// cannot detect: "root", "operator-present", "hardware-1547").
	caps []string

	// Output control.
	jsonOut bool
	verbose bool
	details bool
}

func run(args []string, stdout, stderr io.Writer) int {
	c := &cli{opts: certify.DefaultOptions()}
	// The runner's default output directory is a fixed name; this binary
	// timestamps a fresh one per run instead, so two campaigns cannot
	// silently write into each other's bundle. Cleared here so -help shows an
	// empty default rather than a lie about where evidence will land.
	c.opts.OutDir = ""

	// Record the invocation before parsing it, so a run whose flags the runner
	// later reinterprets still carries what was actually typed.
	c.opts.Command = invocation(args)

	fs := flag.NewFlagSet("certify", flag.ContinueOnError)
	fs.SetOutput(stderr)
	c.opts.BindFlags(fs)
	c.bindFlags(fs)
	fs.Usage = func() { usage(stderr, fs) }

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		return exitUsage
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(stderr, "certify: unexpected argument %q — every input is a flag\n", fs.Arg(0))
		usage(stderr, fs)
		return exitUsage
	}
	// The preset fills in the bench addresses the operator did NOT type, and it
	// has to happen here because "did not type" is knowable only from the
	// parser: fs.Visit reports the flags that actually appeared on the command
	// line, which is the one thing a comparison against defaults cannot
	// reconstruct. See certify.ApplyPreset.
	set := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { set[f.Name] = true })
	if err := certify.ApplyPreset(fs, c.opts.Preset, set); err != nil {
		fatal(stderr, err)
		return exitUsage
	}
	if err := c.resolve(); err != nil {
		fatal(stderr, err)
		return exitUsage
	}

	switch {
	case c.showCaps:
		return c.runCapabilities(stdout)
	case c.list:
		return c.runList(stdout, stderr)
	case c.verify != "":
		return c.runVerify(stdout, stderr)
	case c.report != "":
		return c.runReport(stdout, stderr)
	case c.writes != "":
		return c.runWrites(stdout, stderr)
	case len(c.trr) > 0:
		return c.runTRR(stdout, stderr)
	default:
		return c.runCampaign(stdout, stderr)
	}
}

func (c *cli) bindFlags(fs *flag.FlagSet) {
	fs.BoolVar(&c.list, "list", false, "list the catalog and what this tool implements, then exit")
	fs.StringVar(&c.verify, "verify", "", "re-verify an evidence bundle directory standalone, then exit")
	fs.StringVar(&c.report, "report", "", "generate the SunSpec submission report from an evidence bundle directory, then exit")
	fs.StringVar(&c.writes, "writes", "",
		"extract the southbound REGISTER WRITE SET from an evidence bundle directory (or a bare capture "+
			"file), then exit. Offline and read-only: it reads capture/*.pcapng and capture/*.keylog and "+
			"touches nothing else, so it can run against a bundle while a battery is still going")
	fs.StringVar(&c.writesMRID, "writes-mrid", "",
		"-writes: report only the writes attributed to this control mRID. The window is [first frame "+
			"mentioning the mRID .. last such frame + -writes-settle]; the rule is printed with the report")
	fs.StringVar(&c.writesUntil, "writes-until", "",
		"-writes: cut the window at the first mention of this SUPERSEDING mRID. Two controls delivered in "+
			"one DERControlList have identical mention sets, so no time rule can separate their writes — "+
			"this is the cut that can, and the caller is the one who knows the pair")
	fs.DurationVar(&c.writesSettle, "writes-settle", writeset.DefaultSettle,
		"-writes: how far past the mRID's last mention a write is still attributed to it (registers are "+
			"written after the control is fetched, so a window ending at the last mention would exclude "+
			"the writes the claim is about)")
	fs.Var(repeatFlag{&c.trr}, "trr",
		"build a Test Results Report package from an evidence bundle: `dir[=doc-key,…]` (repeat for more bundles)")
	fs.StringVar(&c.trrOut, "trr-out", "", "where -trr writes the Test Results Report package (required)")
	fs.BoolVar(&c.showCaps, "capabilities", false, "print the capability tags this invocation has, and which checks they gate")

	fs.StringVar(&c.target, "target", "", "DUT address host:port (alias for -gateway; wins when both are given)")

	fs.StringVar(&c.configPath, "config", "", "submission metadata (lab.json / lab.yaml) for -report")
	fs.StringVar(&c.reportOut, "report-out", "", "where -report writes the submission (default <bundle>/submission)")
	fs.StringVar(&c.certType, "cert-type", "", "certification type for -report: \"SunSpec Modbus\" or \"IEEE 2030.5 CSIP\" (default: from -config)")
	fs.BoolVar(&c.allowIncomplete, "allow-incomplete", false,
		"let -report write a submission with required keys missing (as SUMMARY-INCOMPLETE.csv)")
	fs.BoolVar(&c.deriveLogs, "derive-logs", true,
		"derive the §4 detailed test logs from the bundle's capture (cleartext conversations only)")

	fs.StringVar(&c.dutName, "dut-name", "", "device under test, recorded in the bundle")
	fs.StringVar(&c.dutIdentity, "dut-identity", "", "DUT credential recorded in the bundle: LFDI, cert fingerprint, serial")
	fs.StringVar(&c.dutRole, "dut-role", "", "DUT role recorded in the bundle")
	fs.StringVar(&c.dutBuild, "dut-build", "", "DUT firmware/build version recorded in the bundle")

	fs.Var(listFlag{&c.caps}, "cap",
		"assert a capability tag the runner cannot detect, e.g. root (repeatable, comma-separated)")

	fs.BoolVar(&c.jsonOut, "json", false, "machine-readable output where the mode has one (-list, -verify)")
	fs.BoolVar(&c.verbose, "v", false, "log every check's progress to stderr")
	fs.BoolVar(&c.details, "details", false, "-list: print every test case, not just the per-document totals")
}

// listFlag is a repeatable comma-splitting string flag, matching the runner's
// own -doc/-uid/-suite behaviour so the whole command line reads one way.
type listFlag struct{ v *[]string }

func (l listFlag) String() string {
	if l.v == nil {
		return ""
	}
	return strings.Join(*l.v, ",")
}

func (l listFlag) Set(v string) error {
	for _, part := range strings.Split(v, ",") {
		if part = strings.TrimSpace(part); part != "" {
			*l.v = append(*l.v, part)
		}
	}
	return nil
}

// repeatFlag is a repeatable string flag that does NOT split on commas.
//
// -trr needs it: its value is `dir=<doc-key>,<doc-key>` and a comma-splitting
// flag would tear the document list off the directory it narrows, leaving the
// second key parsed as a bundle path. One flag per bundle is also the honest
// spelling — each occurrence names one campaign.
type repeatFlag struct{ v *[]string }

func (r repeatFlag) String() string {
	if r.v == nil {
		return ""
	}
	return strings.Join(*r.v, " ")
}

func (r repeatFlag) Set(v string) error {
	if v = strings.TrimSpace(v); v != "" {
		*r.v = append(*r.v, v)
	}
	return nil
}

// resolve applies the cross-flag rules: mode exclusivity, the -target alias,
// the output directory, and the DUT record.
func (c *cli) resolve() error {
	modes := []string{}
	if c.list {
		modes = append(modes, "-list")
	}
	if c.verify != "" {
		modes = append(modes, "-verify")
	}
	if c.report != "" {
		modes = append(modes, "-report")
	}
	if c.writes != "" {
		modes = append(modes, "-writes")
	}
	if len(c.trr) > 0 {
		modes = append(modes, "-trr")
	}
	if c.showCaps {
		modes = append(modes, "-capabilities")
	}
	if len(modes) > 1 {
		return fmt.Errorf("%s select different modes; pick one", strings.Join(modes, " and "))
	}
	// A campaign RUNS a bench; it has no meaning attached to -verify, -report,
	// -writes, -trr or -list, all of which read a directory that already exists.
	// Accepting it silently there would let an operator believe a campaign had
	// been run when nothing was.
	if c.opts.Campaign != "" && len(modes) == 1 {
		return fmt.Errorf("-campaign %s runs a conformance campaign against the bench, and %s reads an "+
			"artefact that already exists; they cannot be combined", c.opts.Campaign, modes[0])
	}

	if c.target != "" {
		c.opts.Targets.Gateway = c.target
	}
	// Derive the DUT host from whichever of the two named it. The runner does
	// this too; doing it here as well means -list and the console header show
	// the same address the checks will dial.
	c.opts.Targets.Normalise()

	if c.opts.OutDir == "" && len(modes) == 0 {
		c.opts.OutDir = filepath.Join("runs", time.Now().UTC().Format("20060102-150405"))
	}
	c.opts.DUT = bundle.DUT{
		Name:     c.dutName,
		Address:  c.opts.Targets.Gateway,
		Identity: c.dutIdentity,
		Role:     c.dutRole,
		Build:    c.dutBuild,
	}
	if c.opts.Capabilities == nil {
		c.opts.Capabilities = map[string]bool{}
	}
	for _, tag := range c.caps {
		c.opts.Capabilities[tag] = true
	}
	return nil
}

// catalog loads the catalog the whole invocation is measured against.
func (c *cli) catalog() (*certify.Catalog, error) {
	if c.opts.CatalogPath != "" {
		return certify.Load(c.opts.CatalogPath)
	}
	return certify.LoadDefault()
}

// runCampaign is the default mode: plan, capture, execute, cite, bundle,
// verify.
func (c *cli) runCampaign(stdout, stderr io.Writer) int {
	cat, err := c.catalog()
	if err != nil {
		fatal(stderr, err)
		return exitUsage
	}

	// The key log must be opened BEFORE any TLS session, and a -keylog this
	// binary cannot honour is a hard error: see the package doc.
	if c.opts.KeyLogPath != "" {
		if err := keylogOutsideBundle(c.opts.KeyLogPath, c.opts.OutDir); err != nil {
			fatal(stderr, err)
			return exitUsage
		}
		if err := openKeylog(c.opts.KeyLogPath); err != nil {
			fatal(stderr, err)
			return exitUsage
		}
		defer closeKeylog()
	}
	// wolfSSL keeps process-global C state: initialise exactly once per
	// process (this repository's CLAUDE.md invariant), and only in the mode
	// that actually opens sessions.
	tlsInit()
	defer tlsCleanup()

	c.opts.Out = stdout
	if c.verbose {
		c.opts.Log = certify.NewLogger("certify ")
	} else {
		c.opts.Log = certify.DiscardLogger
	}

	runner, err := certify.New(suites.Registry(), cat, c.opts)
	if err != nil {
		fatal(stderr, err)
		return exitUsage
	}

	// Ctrl-C cancels the run rather than killing it: the runner stops the
	// capture, cites what it has, and still writes a bundle for the cases that
	// completed. Losing an hour of a live bench to an impatient keystroke is
	// not an acceptable failure mode.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	rep, runErr := runner.Run(ctx)
	if rep == nil {
		fatal(stderr, runErr)
		return exitUsage
	}
	if c.opts.DryRun {
		if runErr != nil {
			fatal(stderr, runErr)
			return exitFail
		}
		return exitOK
	}

	ok := rep.OK()
	if runErr != nil {
		fatal(stderr, runErr)
		ok = false
	}

	// Verify what we just wrote, from disk, with the same function a third
	// party runs. A tool that cannot verify its own bundle has not produced
	// evidence, whatever its test cases concluded.
	//
	// -no-capture is the one case where that check would lie in the other
	// direction. There is no capture, so bundle.Verify correctly reports it has
	// nothing to re-derive — and printing that as SELF-VERIFICATION FAILED
	// would read as a defect rather than as the declared consequence of the
	// flag. The honest output is to say plainly what this directory is and is
	// not, and never to call it evidence.
	switch {
	case rep.BundleDir != "" && c.opts.NoCapture:
		fmt.Fprintf(stdout, "\n  ⚠ THIS BUNDLE IS NOT EVIDENCE. -no-capture was in force, so no frame was\n"+
			"    recorded and not one assertion in %s carries a citation a third\n"+
			"    party could re-derive. It is a logic-only run: useful for developing checks,\n"+
			"    not for a certification submission. Re-run with a capture to produce evidence.\n",
			rep.BundleDir)
	case rep.BundleDir != "":
		vr, verr := bundle.Verify(rep.BundleDir)
		switch {
		case verr != nil:
			fmt.Fprintf(stdout, "  ✗ SELF-VERIFICATION FAILED: %v\n", verr)
			ok = false
		case !vr.OK:
			fmt.Fprintf(stdout, "\n%s\n", vr.String())
			fmt.Fprintf(stdout, "  ✗ SELF-VERIFICATION FAILED — the bundle just written does not verify\n")
			ok = false
		default:
			fmt.Fprintf(stdout, "  ✓ self-verification: %d assertion(s) re-derived from the capture, "+
				"%d carry no digest to check, %d packet(s)\n", vr.Checked, vr.Unverifiable, vr.Packets)
			fmt.Fprintf(stdout, "     a third party re-checks it with: certify -verify %s\n", rep.BundleDir)
		}
	}
	if !ok {
		return exitFail
	}
	return exitOK
}

// fatal prints an error with exactly one "certify: " prefix.
//
// Most of what reaches here comes from internal/certify, whose errors already
// carry the package's name. Prefixing again produced "certify: certify: no
// suite named ssmm" — small, but this tool's entire product is text a stranger
// is asked to trust, and sloppy presentation invites a reader to wonder what
// else is sloppy.
func fatal(w io.Writer, err error) {
	fmt.Fprintf(w, "certify: %s\n", strings.TrimPrefix(err.Error(), "certify: "))
}

func usage(w io.Writer, fs *flag.FlagSet) {
	fmt.Fprint(w, `certify — SunSpec / CSIP conformance evidence for the LEXA DER gateway

  certify -list [-doc D] [-details]              what the catalog contains and what is implemented
  certify -doc SSM-CONF-v0.8 -dry-run            what that selection would run, and its gaps
  certify -target 69.0.0.2:802 -iface enp1s0 -out runs/2026-07-26/
                                                 a real run: capture, checks, bundle
  certify -verify runs/2026-07-26/               re-verify a bundle from nothing but itself
  certify -report runs/2026-07-26/ -config lab.json
                                                 emit the SunSpec submission report
  certify -trr runs/csip/=csip-conf-v1.3 -trr runs/full/ -trr-out runs/trr -config lab.json
                                                 build the Test Results Report package: both
                                                 Results Reporting specifications, from several
                                                 bundles, with the verdict mapping stated in it

  certify -campaign mbaps -manifest configs/candidate.json -gateway-ssh cc93 -iface enp1s0 -out runs/mbaps/
                                                 a GATING campaign: closed selection, live DUT control
                                                 authority proven before case 1, recorded in the bundle
  certify -campaign csip -manifest c.json -preset local -gateway-exec "docker exec gw" -dry-run
                                                 the same, against a gateway on this host

  certify -no-capture -suite modbus-server -target 127.0.0.1:5020 -param modbus.transport=plain
                                                 EXPLORATORY (non-gating) logic-only run against a
                                                 loopback sim

Exit status: 0 clean · 1 a negative result (FAIL, gap, unverifiable bundle) · 2 bad invocation

Flags:
`)
	fs.PrintDefaults()
}
