package main

import (
	"flag"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"csip-tls-test/internal/wolfssl"
	"csip-tls-test/sim/gridsim"
	"csip-tls-test/sim/tlsserver"
	"lexa-proto/ocppserver"
)

func main() {
	var (
		listenAddr  = flag.String("listen", "0.0.0.0:11111", "address:port to listen on")
		adminAddr   = flag.String("admin", "0.0.0.0:11112", "plain HTTP admin API address:port (DERControl management)")
		caCert      = flag.String("ca", "/home/dmitri/csip-tls-test/certs/ca-cert.pem", "CA cert PEM path")
		serverCert  = flag.String("cert", "/home/dmitri/csip-tls-test/certs/server-cert.pem", "server leaf cert PEM path")
		serverChain = flag.String("cert-chain", "", "server cert CHAIN PEM path (leaf + intermediates); overrides -cert when set (COMM-004 depth-3/4)")
		serverKey   = flag.String("key", "/home/dmitri/csip-tls-test/certs/server-key.pem", "server key PEM path")

		// See gridsim.Server.SetAdvertisedPollRate. A DUT honouring pollRate
		// paces its walk at the slowest advertised rate — /tm's 900s by
		// default — which makes the CSIP suite's walk-observation cases
		// unrunnable. Conformance runs pass 60.
		pollRateS = flag.Uint("poll-rate-s", 0, "advertise this pollRate (seconds) on /dcap and /tm; 0 keeps the built-in 300/900")

		// See tlsserver.Server.IdleTimeout. A client that reuses one TLS
		// session across every walk gives the capture no ClientHello to
		// observe, so the CSIP walk-observation cases SKIP forever. Set this
		// below the poll cadence and above one walk's duration.
		idleTimeoutS = flag.Uint("idle-timeout-s", 0, "close a connection idle this long, so each poll cycle opens one observable TLS session carrying the whole walk; 0 disables")

		// See tlsserver.Config.NoSessionTickets. A RESUMED session carries no
		// certificates, so a conformance window that catches one has no
		// certificate evidence to cite. Conformance runs that must cite the
		// certificate exchange per window pass this; the default keeps
		// resumption available, which is what a real 2030.5 client may use.
		noTickets = flag.Bool("no-tickets", false, "issue no TLS session tickets and keep no session cache, so every gateway dial is a FULL mTLS handshake with the certificates on the wire (conformance evidence runs; default allows resumption)")

		// Bench-only, and only in a -tags keylog build. Point this at the SAME
		// file certify writes: lexa_keylog_open appends, the NSS format is
		// line-oriented, and the analyzer does not care which process wrote
		// which line — so one file ends up holding both halves of every
		// captured session.
		keylogPath = flag.String("keylog", "", "append this server's TLS session secrets to an NSS key log (requires a -tags keylog build; bench evidence only)")

		// OCPP 2.0.1 CSMS flags (Security Profile 2: TLS + Basic Auth).
		// TLS is optional; omit -ocpp-cert/-ocpp-key for plain WebSocket (dev only).
		ocppPort     = flag.Int("ocpp-port", ocppserver.DefaultPort, "OCPP 2.0.1 CSMS WebSocket port")
		ocppCert     = flag.String("ocpp-cert", "", "OCPP server TLS cert PEM (enables TLS when set)")
		ocppKey      = flag.String("ocpp-key", "", "OCPP server TLS key PEM")
		ocppAuthUser = flag.String("ocpp-user", "", "OCPP basic-auth username (optional)")
		ocppAuthPass = flag.String("ocpp-pass", "", "OCPP basic-auth password (optional)")
	)
	flag.Parse()

	wolfssl.Init()
	defer wolfssl.Cleanup()

	// Fail loudly rather than serving a run whose capture nobody can decrypt.
	// A silent no-op here is discovered at analysis time, when the evidence is
	// already stale and the bench has moved on.
	if *keylogPath != "" {
		if err := wolfssl.OpenKeylog(*keylogPath); err != nil {
			log.Fatalf("-keylog %s: %v (a keylog build is required: make server-keylog)", *keylogPath, err)
		}
		defer wolfssl.CloseKeylog()
		log.Printf("[gridsim] TLS session secrets APPEND to %s — bench evidence build", *keylogPath)
	}

	// LFDI starts empty; SetClientCertDER fills it in from the peer cert
	// during each mTLS handshake (Step A: live derivation, not from a file).
	sim := gridsim.NewServer("")
	sim.SetAdvertisedPollRate(uint32(*pollRateS))

	// Tee logs into the admin API ring so GET /admin/logs streams them to
	// the dashboard's unified Logs tab.
	log.SetOutput(io.MultiWriter(os.Stderr, sim.LogWriter()))

	srv, err := tlsserver.New(tlsserver.Config{
		CACertPath:          *caCert,
		ServerCertPath:      *serverCert,
		ServerCertChainPath: *serverChain,
		ServerKeyPath:       *serverKey,
		NoSessionTickets:    *noTickets,
	})
	if err != nil {
		log.Fatalf("server init: %v", err)
	}
	if *noTickets {
		// Say it in the log the run archives, not only in the flag list: a
		// bundle reader asking why every window holds a full handshake should
		// find the answer in the server's own output.
		log.Printf("[gridsim] session tickets DISABLED and session cache OFF — every dial is a full mTLS handshake")
	}
	srv.Handler = sim.Handler()
	srv.IdleTimeout = time.Duration(*idleTimeoutS) * time.Second
	srv.OnHandshake = func(version, cipher string) {
		log.Printf("✓ mTLS handshake: version=%s cipher=%s", version, cipher)
	}
	srv.OnClientCert = sim.SetClientCertDER

	lis, err := net.Listen("tcp", *listenAddr)
	if err != nil {
		log.Fatalf("listen: %v", err)
	}
	log.Printf("Server listening on %s (mTLS, cipher=%s)",
		lis.Addr(), tlsserver.DefaultCipherList)

	// Publish the address the kernel actually handed us, so GET /admin/status
	// can say which data plane THIS process serves. A harness given -gridsim
	// and -gridsim-admin has no other way to establish that the two ports
	// belong to one process — see the admin-bind comment below for what
	// happened on the day they did not.
	sim.SetDataPlaneAddr(lis.Addr().String())

	// Start plain HTTP admin API (DERControl management — no mTLS).
	//
	// Bind BEFORE serving so a port clash is fatal here rather than a line in
	// the log. On 2026-07-28 a previous instance survived its own SIGTERM (see
	// the shutdown block below) and kept :11114; the replacement took :11113,
	// logged "address already in use" for the admin port, and carried on. The
	// DUT then talked to the new process while the conformance harness read
	// its server-side observations from the 8-hour-old orphan, which of course
	// recorded no DUT traffic — reported as "gridsim's request log records no
	// GET /dcap from the DUT in this window", i.e. a DUT fault. Two ports, two
	// processes, one silent misattribution.
	adminLis, err := net.Listen("tcp", *adminAddr)
	if err != nil {
		log.Fatalf("admin listen: %v (another gridsim still holds it?)", err)
	}
	adminSrv := &http.Server{Handler: sim.AdminHandler()}
	go func() {
		log.Printf("Admin API listening on %s (plain HTTP)", adminLis.Addr())
		if err := adminSrv.Serve(adminLis); err != nil && err != http.ErrServerClosed {
			log.Printf("admin serve ended: %v", err)
		}
	}()

	// Start OCPP 2.0.1 CSMS concurrently.
	ocppSrv := ocppserver.New(ocppserver.Config{
		Port:          *ocppPort,
		CertPath:      *ocppCert,
		KeyPath:       *ocppKey,
		BasicAuthUser: *ocppAuthUser,
		BasicAuthPass: *ocppAuthPass,
	})
	go ocppSrv.Start()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sig
		log.Printf("shutting down...")
		ocppSrv.Stop()
		_ = adminSrv.Close() // release :11114 — see the bind comment above
		_ = lis.Close()

		// srv.Close() waits on in-flight connection goroutines, and a 2030.5
		// client holds ONE persistent connection whose handler is parked in a
		// blocking read. Without IdleTimeout that wait never returns: the
		// process releases the TLS port, keeps the admin port, and lingers
		// forever looking like a healthy server. Backstop the wait so SIGTERM
		// always means gone.
		go func() {
			time.Sleep(5 * time.Second)
			log.Printf("shutdown timed out waiting for connections — exiting")
			os.Exit(0)
		}()
	}()

	if err := srv.Serve(lis); err != nil {
		log.Printf("serve ended: %v", err)
	}
	srv.Close()
	log.Printf("clean shutdown")
}
