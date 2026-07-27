// gw-campaign is the single entry point for the continuous adversary: it picks
// fault layers on a seed, applies them concurrently on a recorded schedule,
// checks every invariant (I1–I10) throughout, shrinks any violation to its
// minimal reproducer, and writes an evidence bundle.
//
//	# hermetic, no bench — the habitual run:
//	gw-campaign -loopback -pki certs/mbaps
//
//	# hermetic WITH TEETH: a deliberately non-conformant peer that lets a
//	# read-only credential write. A clean run here is a HARNESS failure.
//	gw-campaign -loopback -teeth -pki certs/mbaps
//
//	# live, against the bench gateway (read-only w.r.t. its config; faults go
//	# into the SIMS and the network, never into the gateway):
//	gw-campaign -target 69.0.0.2:802 -pki certs/mbaps \
//	    -inv-plain http://127.0.0.1:6020 -gridsim-admin http://127.0.0.1:11114
//
//	# reproduce a failure someone else saw:
//	gw-campaign -loopback -seed 8134297 -layers peer-lie,authz-probe
//
// This file is WIRING ONLY (CODING_PRINCIPLES §1): flags, wolfSSL init, world
// construction, exit-code mapping. The engine is internal/campaign, the judging
// is internal/invariant, and neither knows this binary exists.
//
// EXIT CODES. 0 the campaign passed; 1 an invariant was violated, or the run
// failed its own honesty floor (nothing armed, nothing asserted, or -teeth
// found nothing); 2 the harness could not run at all. The distinction between 1
// and 2 is the whole point: a device finding and a bench problem must not share
// an exit code, or an operator learns to ignore both.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"csip-tls-test/internal/campaign"
	"csip-tls-test/internal/evidence/bundle"
	"csip-tls-test/internal/invariant"
	"csip-tls-test/internal/wolfssl"
)

func main() {
	var (
		target   = flag.String("target", "69.0.0.2:802", "gateway mbaps server to attack (ignored with -loopback)")
		pkiDir   = flag.String("pki", "certs/mbaps", "bench mbaps PKI dir (manifest.json + role/negative certs)")
		serverCA = flag.String("server-ca", "", "override the CA that verifies the gateway's server cert")
		loopback = flag.Bool("loopback", false, "run hermetically against an in-process faithful loopback gateway")
		teeth    = flag.Bool("teeth", false, "hermetic only: stand up a DELIBERATELY NON-CONFORMANT loopback (a read-only credential may write). A run that finds NOTHING then FAILS — the harness cannot see the defect it was aimed at")

		gridsimAdmin = flag.String("gridsim-admin", "", "gridsim head-end admin API (enables the head-end and clock-warp layers)")
		invPlain     = flag.String("inv-plain", "", "plain DER sim simapi base URL (enables the peer-lie and comm-loss layers)")
		invSecure    = flag.String("inv-secure", "", "secure DER sim simapi base URL")
		gwSSH        = flag.String("gw-ssh", "", "read-only ssh destination for host resource accounting (I8's disk arm); empty makes I8 skip that arm with a reason")

		seed       = flag.Int64("seed", 0, "campaign seed; 0 draws one from the clock and PRINTS it")
		window     = flag.Duration("window", 90*time.Second, "run length, baseline tick to last recovery tick")
		cadence    = flag.Duration("cadence", 5*time.Second, "invariant monitor tick interval")
		actions    = flag.Int("actions", 8, "how many of the offered actions to schedule")
		overlap    = flag.Float64("overlap", 0.45, "fraction of the window over which faults are armed; smaller packs them closer and makes compound conditions more likely")
		layersFlag = flag.String("layers", "", "comma-separated fault layers (default: all). See -list-layers")
		invFlag    = flag.String("invariants", "", "comma-separated invariant ids to run (default: I1..I10)")
		paramFlag  = flag.String("param", "", "comma-separated key=value operator parameters the invariants cannot observe (e.g. failsafe_wmaxlimpct=0)")

		shrink       = flag.Bool("shrink", true, "on a violation, re-run with subsets to find the minimal reproducing action set")
		shrinkBudget = flag.Int("shrink-budget", 24, "maximum shrink re-runs per violation")

		outDir     = flag.String("out", "", "write the evidence bundle to this directory (default: runs/campaign-<label>-<seed>)")
		listLayers = flag.Bool("list-layers", false, "describe the fault layers and exit")
		verbose    = flag.Bool("v", false, "log every monitor tick and every arm/clear")
	)
	flag.Parse()

	if *listLayers {
		for _, l := range campaign.Standard() {
			fmt.Printf("%-16s %s\n\n", l.ID(), wrap(l.Describe(), 78, "                 "))
		}
		return
	}

	layers, unknownLayers := campaign.Select(splitCSV(*layersFlag))
	if len(unknownLayers) > 0 {
		fatal(2, "-layers names layers this build does not have: %v (see -list-layers)", unknownLayers)
	}
	if len(layers) == 0 {
		fatal(2, "-layers selected nothing to run")
	}
	if *teeth && !*loopback {
		fatal(2, "-teeth stands up a deliberately non-conformant peer and is hermetic only; it must not be "+
			"pointed at the live gateway, where a 'non-conformant peer' would be the gateway itself")
	}

	if *seed == 0 {
		*seed = time.Now().UnixNano() & 0x7FFFFFFF
	}

	logger := invariant.Logger(discard{})
	if *verbose {
		logger = log.New(os.Stderr, "campaign: ", log.Ltime)
	}

	label := "live"
	if *loopback {
		label = "hermetic"
		if *teeth {
			label = "hermetic-teeth"
		}
	}

	params := invariant.DefaultParams()
	for _, kv := range splitCSV(*paramFlag) {
		k, v, ok := strings.Cut(kv, "=")
		if !ok {
			fatal(2, "-param %q is not key=value", kv)
		}
		params.Values[strings.TrimSpace(k)] = strings.TrimSpace(v)
	}

	cfg := campaign.Config{
		Label: label, Seed: *seed, Window: *window, Cadence: *cadence,
		Actions: *actions, Overlap: *overlap, Invariants: splitCSV(*invFlag),
		Params: params, Log: logger, MustViolate: *teeth,
	}
	if *teeth {
		// The teeth run injects ONE known defect — a loopback that lets a
		// read-only credential write — and asserts the suite catches it. That
		// assertion is only meaningful if the probe that can see the defect is
		// actually scheduled, and a seeded draw over thirty-odd offered actions
		// usually leaves it out. Left to chance, a teeth run would report "the
		// harness is blind" on most seeds, and the operator would learn to
		// re-roll until it passed — which is worse than not running it.
		//
		// So the experiment is stated rather than hoped for: pin the read-only
		// write probe, keep everything else seeded, and let the shrinker
		// confirm afterwards that this one probe is the whole reproducer.
		cfg.Require = []string{"authz-probe/write-readonlysunspec"}
	}

	// wolfSSL keeps process-global C state — init exactly once, here in main.
	wolfssl.Init()
	defer wolfssl.Cleanup()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	wiring := worldWiring{
		Target: *target, PKIDir: *pkiDir, ServerCA: *serverCA,
		Loopback: *loopback, Teeth: *teeth,
		GridsimAdmin: *gridsimAdmin, InvPlain: *invPlain, InvSecure: *invSecure,
		GatewaySSH: *gwSSH, Log: logger,
	}
	envFn, err := wiring.envFunc()
	if err != nil {
		fatal(2, "build the world: %v", err)
	}

	fmt.Printf("gw-campaign %s: seed=%d window=%s cadence=%s layers=[%s]\n",
		label, *seed, *window, *cadence, strings.Join(layerIDs(layers), ","))

	res, err := campaign.Run(ctx, cfg, envFn, layers)
	if err != nil {
		fatal(2, "%v", err)
	}
	fmt.Print(campaign.Console(res))

	// Shrink every distinct violation to its minimal reproducer. Without this a
	// finding is an anecdote: nobody can act on "these eight faults, together,
	// somewhere, broke I1".
	var shrinks []campaign.ShrinkResult
	if *shrink && ctx.Err() == nil {
		for _, sig := range res.Signatures() {
			fmt.Printf("\nshrinking %s (budget %d re-runs)...\n", sig, *shrinkBudget)
			sr, serr := campaign.Shrink(ctx, sig, res, campaign.ShrinkConfig{
				Budget: *shrinkBudget, Config: cfg, Log: stdoutLogger{},
			}, envFn, layers)
			if serr != nil {
				fmt.Printf("shrink %s: %v\n", sig, serr)
				continue
			}
			shrinks = append(shrinks, sr)
			fmt.Print("\n" + sr.String())
		}
	}

	dir := *outDir
	if dir == "" {
		dir = filepath.Join("runs", fmt.Sprintf("campaign-%s-%d", label, *seed))
	}
	dut := bundle.DUT{Name: "lexa-gw", Address: wiring.dutAddr()}
	if *loopback {
		dut.Name = "gwloopback (in-process stand-in)"
		if *teeth {
			dut.Name = "gwloopback DELIBERATELY NON-CONFORMANT (read-only may write)"
		}
	}
	b, err := campaign.Emit(dir, res, shrinks, dut, invocation())
	if err != nil {
		fatal(2, "write the evidence bundle: %v", err)
	}
	pass, fail, skip, warn := b.Counts()
	fmt.Printf("\nevidence bundle: %s  (%d pass, %d fail, %d skip, %d warn)\n", dir, pass, fail, skip, warn)
	// The manifest check is what a campaign bundle can honestly offer, and the
	// hint says exactly that. `certify -verify` also tries to re-derive every
	// assertion from a packet capture, and a campaign takes none — so pointing
	// an operator at the full verifier would hand them a red "BUNDLE DOES NOT
	// VERIFY" for a bundle that is intact, and they would stop reading it. The
	// missing capture is a real limitation of this tool, recorded in the runbook
	// under "known limits", not something to paper over with a friendlier
	// command.
	fmt.Printf("check its integrity with: go run ./cmd/certify -verify %s\n", dir)
	fmt.Printf("  (expect \"all N file(s) match the manifest\" and a WARN that there is no capture:\n" +
		"   a campaign's assertions are control-plane observations, not wire citations)\n")

	if !res.OK {
		os.Exit(1)
	}
}

// layerIDs renders the selected layer ids for the run header.
func layerIDs(layers []campaign.Layer) []string {
	out := make([]string, 0, len(layers))
	for _, l := range layers {
		out = append(out, l.ID())
	}
	return out
}

// invocation reconstructs the command line, so the bundle records exactly what
// was run rather than an approximation someone typed into a commit message.
func invocation() string { return strings.Join(os.Args, " ") }

func fatal(code int, format string, args ...any) {
	fmt.Fprintf(os.Stderr, "gw-campaign: "+format+"\n", args...)
	os.Exit(code)
}

// discard is the silent logger for a non-verbose run.
type discard struct{}

func (discard) Printf(string, ...any) {}

// stdoutLogger streams shrink progress, which a human watching a multi-minute
// shrink genuinely needs.
type stdoutLogger struct{}

func (stdoutLogger) Printf(format string, args ...any) { fmt.Printf("  "+format+"\n", args...) }

func splitCSV(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// wrap re-flows a layer description for -list-layers.
func wrap(s string, width int, pad string) string {
	var b strings.Builder
	col := 0
	for _, w := range strings.Fields(s) {
		if col > 0 && col+len(w)+1 > width {
			b.WriteString("\n" + pad)
			col = 0
		} else if col > 0 {
			b.WriteString(" ")
			col++
		}
		b.WriteString(w)
		col += len(w)
	}
	return b.String()
}
