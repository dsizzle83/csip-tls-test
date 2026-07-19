// gw-mayhem is the lexa-gw gateway hostile-QA runner: it drives the adversarial
// mbaps-northbound-authz family (and the qa/gw-scenarios/*.json specs) against the
// REAL gateway's :802 server or a faithful in-process loopback, folds the verdicts
// into a PASS/FAIL gate, and prints a per-scenario evidence table. It is the
// gateway counterpart of scripts/mayhem.py — a headless runner over the same
// verdict vocabulary — but drives mbaps directly (cgo wolfSSL), so it is a Go CLI,
// not a thin HTTP client.
//
//	# hermetic (no bench) — the default CI/dev run:
//	gw-mayhem -loopback -pki certs/mbaps
//	# live, against the gateway:
//	gw-mayhem -target 69.0.0.2:802 -pki certs/mbaps
//	# list / filter / JSON:
//	gw-mayhem -list
//	gw-mayhem -loopback -only authz-role-denial-matrix,authz-cert-negatives -json
//
// This file is WIRING ONLY (CODING_PRINCIPLES §1): flag parsing, wolfSSL init,
// loopback/world construction, exit-code mapping. All logic lives in
// sim/gw-mayhem.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	gwmayhem "csip-tls-test/sim/gw-mayhem"
	"csip-tls-test/sim/gw-mayhem/gwloopback"

	"csip-tls-test/internal/mbtls"
	"csip-tls-test/internal/wolfssl"
)

func main() {
	var (
		target   = flag.String("target", "69.0.0.2:802", "gateway mbaps server to drive (ignored with -loopback)")
		pkiDir   = flag.String("pki", "certs/mbaps", "bench mbaps PKI dir (manifest.json + role/negative certs)")
		serverCA = flag.String("server-ca", "", "override the CA that verifies the gateway's server cert (default: manifest device CA)")
		specDir  = flag.String("scenarios", "qa/gw-scenarios", "dir of qa/gw-scenarios/*.json data specs")
		loopback = flag.Bool("loopback", false, "run against an in-process faithful loopback gateway (hermetic, no bench)")
		list     = flag.Bool("list", false, "list the scenario suite and exit")
		only     = flag.String("only", "", "comma-separated scenario ids to run (default: all)")
		jsonOut  = flag.Bool("json", false, "emit the batch roll-up as JSON to stdout")
		outFile  = flag.String("out", "", "also write the batch summary JSON to this file")
	)
	flag.Parse()

	scenarios, loadErrs := gwmayhem.AllScenarios(*specDir)

	if *list {
		gwmayhem.ListScenarios(os.Stdout, scenarios, loadErrs)
		return
	}

	// wolfSSL keeps process-global C state — init exactly once, here in main.
	wolfssl.Init()
	defer wolfssl.Cleanup()

	addr := *target
	if *loopback {
		lb, err := startLoopback(*pkiDir)
		if err != nil {
			fmt.Fprintf(os.Stderr, "gw-mayhem: start loopback: %v\n", err)
			os.Exit(2)
		}
		defer lb.Close()
		addr = lb.Addr()
		fmt.Fprintf(os.Stderr, "gw-mayhem: loopback gateway at %s\n", addr)
	}

	world, err := gwmayhem.NewWorld(addr, *pkiDir, *serverCA)
	if err != nil {
		fmt.Fprintf(os.Stderr, "gw-mayhem: build world: %v\n", err)
		os.Exit(2)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	sum := gwmayhem.RunSuite(ctx, world, scenarios, loadErrs, splitCSV(*only), *jsonOut, os.Stdout)

	if *outFile != "" {
		if raw, merr := json.MarshalIndent(sum, "", "  "); merr == nil {
			if werr := os.WriteFile(*outFile, raw, 0o644); werr != nil {
				fmt.Fprintf(os.Stderr, "gw-mayhem: write %s: %v\n", *outFile, werr)
			}
		}
	}

	if sum.GateFailures > 0 {
		os.Exit(1)
	}
}

// startLoopback builds the faithful loopback gateway from the committed PKI: the
// device server leaf + the client CA that verifies role certs.
func startLoopback(pkiDir string) (*gwloopback.LoopbackServer, error) {
	profile := mbtls.DefaultServerProfile(
		filepath.Join(pkiDir, "ca-cert.pem"),
		filepath.Join(pkiDir, "dev-server-cert.pem"),
		filepath.Join(pkiDir, "dev-server-key.pem"),
	)
	return gwloopback.StartLoopback(profile, 0)
}

// splitCSV splits a comma list into trimmed, non-empty ids.
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
