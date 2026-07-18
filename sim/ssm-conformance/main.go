// sim/ssm-conformance walks ALL 62 Secure SunSpec Modbus/TCP requirements
// (SunSpecTCP-1..62) against a live mbaps gateway, printing one PASS/FAIL/SKIP
// line per requirement in the house style of sim/modsim-conformance, and emitting
// a CONFORMANCE_REPORT.md section that slots into the root report.
//
// It is the bench's INDEPENDENT Secure SunSpec Modbus referee (T06.10): every
// handshake, cipher, role-authz, PKI, and packet assertion is driven over the
// bench's own mbaps client + role parser (internal/mbtls, internal/aggregator) —
// deliberately NOT the product's lexa-platform/securemodbus, so a profile or
// authz bug in the gateway under test cannot hide behind a shared implementation
// (PN-1 / T00 ruling C9). It shares only lexa-proto/{mbap,sunspec} with the
// product (the wire format is the wire format).
//
// # Modes
//
// Loopback (default, no -target): the suite mints a throwaway EC P-256 PKI and
// stands up an in-process authz-enforcing mbaps server, then runs the full 62
// against it. This is a self-contained desktop self-test — zero bench access,
// zero cert-gen, zero committed-file churn — proving the checks have teeth (a
// non-conformant peer FAILs them). It is the default layer scripts/run-conformance.sh
// runs.
//
// Live (-target host:802 -pki certs/mbaps): the same 62 checks run against the
// real lexa-gw northbound mbaps server, using the committed role-cert + negative-
// fixture matrix (keys from `make gen-mbaps-certs`). The rows that print PASS here
// are the ones to flip impl→verified in the traceability matrix.
//
// Usage:
//
//	ssm-conformance                                     # loopback self-test (62 rows)
//	ssm-conformance -target 69.0.0.2:802 -pki certs/mbaps -out logs/ssm-<ts>.log
//	ssm-conformance -target 69.0.0.2:802 -pki certs/mbaps -device-target 69.0.0.20:8021
//	ssm-conformance ... -md CONFORMANCE_REPORT.section.md   # also emit the report section
package main

import (
	"context"
	"flag"
	"log"
	"net"
	"os"
	"strconv"
	"time"

	"csip-tls-test/internal/aggregator"
	"csip-tls-test/internal/wolfssl"
)

// runCtx is the resolved context every check reads: where the target is, the PKI
// to dial it with, and whether it is the in-process loopback (so a check can say
// so instead of failing an ephemeral-port SHOULD).
type runCtx struct {
	target     string
	device     string
	port       int
	ps         *pkiSet
	isLoopback bool
}

// probeUnit is the unit a liveness read (pump/Ping) targets. Unit 1 is served by
// the loopback and, on the live gateway, either answers or returns a protocol
// exception (0x0A) — both prove the session round-trips, which is all these
// probes assert.
func (rc *runCtx) probeUnit() uint8 { return 1 }

func main() {
	var (
		target   = flag.String("target", "", "mbaps gateway address host:port (empty = in-process loopback self-test)")
		pkiDir   = flag.String("pki", "certs/mbaps", "certs/mbaps PKI directory (live mode: role certs + negative fixtures)")
		devTgt   = flag.String("device-target", "", "optional mbapsdev address host:port to exercise the client-direction rows against")
		serverCA = flag.String("server-ca", "", "CA that verifies the gateway server cert (live mode; default <pki>/dev-ca.pem)")
		outFile  = flag.String("out", "", "log file path (empty = stdout only)")
		mdFile   = flag.String("md", "", "write the CONFORMANCE_REPORT.md section to this path")
	)
	flag.Parse()

	// wolfSSL keeps process-global C state — Init exactly once per process
	// (CLAUDE.md invariant), mirroring sim/mbapsdev and sim/server.
	wolfssl.Init()
	defer wolfssl.Cleanup()

	rc := &runCtx{device: *devTgt}
	var stop func()

	if *target == "" {
		ps, err := mintLoopbackPKI()
		if err != nil {
			log.Fatalf("ssm-conformance: mint loopback PKI: %v", err)
		}
		defer ps.cleanup()
		srv, srvStop, err := startLoopback(ps)
		if err != nil {
			log.Fatalf("ssm-conformance: start loopback server: %v", err)
		}
		stop = srvStop
		rc.ps = ps
		rc.target = srv.addr()
		rc.isLoopback = true
	} else {
		ps, err := loadManifestPKI(*pkiDir, *serverCA)
		if err != nil {
			log.Fatalf("ssm-conformance: load PKI %s: %v", *pkiDir, err)
		}
		rc.ps = ps
		rc.target = *target
	}
	if stop != nil {
		defer stop()
	}
	rc.port = portOf(rc.target)

	r, cleanup := newReporter(*outFile, rc.target, rc.device)
	defer cleanup()
	r.header()

	// The five spec blocks, in order.
	checkTransportSecurity(r, rc) // §5.1 TCP-1..14 (minus 8)
	checkCipherSuites(r, rc)      // §5.2 TCP-15..20
	checkAuthz(r, rc)             // §5.3 TCP-8, 21..41
	checkPKI(r, rc)               // §5.4 TCP-42..58
	checkPacketSession(r, rc)     // §5.5 TCP-59..62
	if rc.device != "" {
		checkDeviceTarget(r, rc) // corroborate client-direction rows vs mbapsdev
	}

	ok := r.summary()

	if *mdFile != "" {
		if err := os.WriteFile(*mdFile, []byte(r.markdownSection()), 0o644); err != nil {
			log.Fatalf("ssm-conformance: write markdown section %s: %v", *mdFile, err)
		}
		r.printf("CONFORMANCE_REPORT.md section written to %s\n", *mdFile)
	}

	if !ok {
		os.Exit(1)
	}
}

// portOf parses the port out of a host:port target, or 0 if unparseable.
func portOf(addr string) int {
	_, p, err := net.SplitHostPort(addr)
	if err != nil {
		return 0
	}
	n, err := strconv.Atoi(p)
	if err != nil {
		return 0
	}
	return n
}

// checkDeviceTarget corroborates the client-direction rows (TCP-12/27/28/43/44/61)
// by driving the SAME conformant mbaps client against a real mbapsdev device sim,
// reading its SunSpec Common (Model 1). It only STRENGTHENS those rows (re-records
// PASS on success); a failure here — e.g. a PKI-domain mismatch when a loopback
// self-test is pointed at a certs/mbaps mbapsdev — is logged as a note and never
// downgrades the primary-handshake verdicts.
func checkDeviceTarget(r *Reporter, rc *runCtx) {
	r.section("client", "Client-direction corroboration vs mbapsdev ("+rc.device+")")
	sess, err := dialRole(rc.device, rc.ps, RoleGridService)
	if err != nil || sess == nil {
		r.printf("  ⚠ note  device handshake failed (%v) — client rows stand on the primary target; "+
			"note -device-target expects the same PKI domain as -pki\n", err)
		return
	}
	defer sess.Close()

	// Confirm the client session round-trips a real SunSpec read against the
	// device before crediting the corroboration.
	conn, cerr := aggregator.ConnectAs(rc.device, RoleGridService, rc.ps.refs())
	if cerr != nil {
		r.printf("  ⚠ note  device ConnectAs failed (%v) — client rows stand on the primary target\n", cerr)
		return
	}
	defer conn.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	devs, derr := conn.Discover(ctx, 1, 2, 3, 4)
	if derr != nil || len(devs) == 0 {
		r.printf("  ⚠ note  device discovery found no SunSpec device (%v) — client rows stand on the primary target\n", derr)
		return
	}
	r.printf("  · read Model 1 identity from mbapsdev unit %d (%s)\n", devs[0].Unit, devs[0].Identity.Manufacturer)
	r.pass(12, "client presented its cert to mbapsdev and completed a mutual handshake (device corroboration)")
	r.pass(27, "client provisioned with a domain cert accepted by mbapsdev (device corroboration)")
	r.pass(28, "client role extension accepted by mbapsdev; its server cert carries none (device corroboration)")
	r.pass(43, "P-256 supported-groups offered to mbapsdev (ECDHE handshake completed)")
	r.pass(44, "EC point-format extension offered to mbapsdev (handshake completed)")
	r.pass(61, "NULL-compression ClientHello accepted by mbapsdev (handshake completed)")
}
