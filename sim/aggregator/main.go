// aggregator is the Secure SunSpec Modbus (mbaps) AGGREGATOR EMULATOR CLI
// (T06.9): a northbound mbaps CLIENT that plays the utility / VPP / aggregator,
// driving the lexa-gw gateway's :802 server (or a loopback mbapsdev) as a real
// DERMS head-end would. It has two modes over the SAME driver
// (internal/aggregator):
//
//   - interactive REPL — connect as a role, discover, poll, write, readback,
//     probe denials, and drive the TLS-fault verbs (disconnect/resume/
//     renegotiate) against one live session:
//
//     aggregator -target 69.0.0.2:802 -pki certs/mbaps -role GridServiceSunSpec -interactive
//
//   - headless batch — run one campaign or a whole campaign dir, roll up the
//     verdicts, write per-campaign reports, and EXIT NON-ZERO on any verdict
//     outside a campaign's expected_verdicts (the CI/gate path):
//
//     aggregator -target 69.0.0.2:802 -pki certs/mbaps -campaign qa/aggregator/curtail-solar-50.json -out logs/agg/<ts>/
//     aggregator -target 69.0.0.2:802 -pki certs/mbaps -campaign-dir qa/aggregator -out logs/agg/<ts>/ -json
//
// This file is WIRING ONLY (CODING_PRINCIPLES §1): flag parsing, PKI load,
// wolfSSL init, engine/REPL construction, signal handling. All logic lives in
// internal/aggregator (cli.go / engine.go / probes.go), driven through injected
// dependencies.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"csip-tls-test/internal/aggregator"
	"csip-tls-test/internal/wolfssl"
)

func main() {
	var (
		target      = flag.String("target", "127.0.0.1:8021", "mbaps server to drive (gateway :802, or a loopback mbapsdev)")
		pkiDir      = flag.String("pki", "certs/mbaps", "bench mbaps PKI dir (manifest.json + role client certs)")
		serverCA    = flag.String("server-ca", "", "override the CA that verifies the peer's SERVER cert (default: manifest device CA; set to the gateway owner CA for a live :802 run)")
		role        = flag.String("role", string(aggregator.RoleGridService), "role to connect as in interactive mode")
		interactive = flag.Bool("interactive", false, "run the interactive REPL (default when no -campaign/-campaign-dir is given)")
		campaign    = flag.String("campaign", "", "headless: run this single campaign JSON")
		campaignDir = flag.String("campaign-dir", "", "headless: run every campaign in this dir (the CI gate)")
		outDir      = flag.String("out", "", "headless: write per-campaign report.json + summary.md under this dir (default: logs/agg/<ts>)")
		jsonOut     = flag.Bool("json", false, "headless: also emit the batch roll-up as JSON to stdout")
		faultAPI    = flag.String("fault-api", "", "headless: a sim's simapi base URL for sim_fault steps (e.g. http://69.0.0.20:6031)")
	)
	flag.Parse()

	// wolfSSL keeps process-global C state — init exactly once, here in main
	// (CLAUDE.md wolfSSL_Init invariant).
	wolfssl.Init()
	defer wolfssl.Cleanup()

	refs, err := aggregator.LoadPKI(*pkiDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "aggregator: load PKI from %s: %v\n", *pkiDir, err)
		os.Exit(2)
	}
	if *serverCA != "" {
		refs.ServerCA = *serverCA
	}

	// Both campaign targets resolve to -target: the CLI drives one server at a
	// time (the gateway, or a loopback device), whichever the operator points at.
	addrs := map[string]string{
		aggregator.TargetGateway: *target,
		aggregator.TargetDevice:  *target,
	}
	eng := aggregator.NewEngine(aggregator.RunOptions{
		ConnectAs: func(addr string, r aggregator.Role) (*aggregator.Conn, error) {
			return aggregator.ConnectAs(addr, r, refs)
		},
		Resolve: func(tgt string) (string, error) {
			if a, ok := addrs[tgt]; ok && a != "" {
				return a, nil
			}
			return "", fmt.Errorf("no address configured for target %q", tgt)
		},
		Fault: aggregator.HTTPFaultInjector(*faultAPI),
	})

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Headless when a campaign or campaign dir is named; interactive otherwise.
	// -interactive with a campaign present is a mistake worth flagging rather than
	// silently ignoring.
	headless := *campaign != "" || *campaignDir != ""
	if headless && *interactive {
		fmt.Fprintln(os.Stderr, "aggregator: -interactive ignored — a campaign was given, running headless")
	}

	switch {
	case *campaign != "":
		os.Exit(runHeadless(ctx, func() (aggregator.BatchSummary, error) {
			return aggregator.RunCampaignFile(ctx, eng, *campaign, resolveOut(*outDir), *jsonOut, os.Stdout)
		}))
	case *campaignDir != "":
		os.Exit(runHeadless(ctx, func() (aggregator.BatchSummary, error) {
			return aggregator.RunCampaignDir(ctx, eng, *campaignDir, resolveOut(*outDir), *jsonOut, os.Stdout)
		}))
	default:
		repl := aggregator.NewREPL(
			func(addr string, r aggregator.Role) (*aggregator.Conn, error) {
				return aggregator.ConnectAs(addr, r, refs)
			},
			func(tgt string) (string, error) {
				if a, ok := addrs[tgt]; ok && a != "" {
					return a, nil
				}
				return "", fmt.Errorf("no address for target %q", tgt)
			},
			aggregator.TargetGateway, refs.Roles(), aggregator.Role(*role), os.Stdout,
		)
		if err := repl.Run(ctx, os.Stdin); err != nil {
			fmt.Fprintf(os.Stderr, "aggregator: repl: %v\n", err)
			os.Exit(1)
		}
	}
}

// runHeadless runs a batch and maps its gate outcome to a process exit code: 0
// when every campaign's verdict was within its expected set, 1 on any gate
// failure (an unexpected verdict or a load error), 2 on an engine
// misconfiguration. This is the CI-gate contract.
func runHeadless(_ context.Context, run func() (aggregator.BatchSummary, error)) int {
	sum, err := run()
	if err != nil {
		fmt.Fprintf(os.Stderr, "aggregator: %v\n", err)
		return 2
	}
	if sum.GateFailures > 0 {
		return 1
	}
	return 0
}

// resolveOut defaults an empty -out to a timestamped logs/agg dir so a headless
// run always leaves an evidence artifact.
func resolveOut(out string) string {
	if out != "" {
		return out
	}
	return filepath.Join("logs", "agg", time.Now().Format("20060102-150405"))
}
