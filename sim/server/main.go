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

	"csip-tls-test/internal/csipnotify"
	"csip-tls-test/internal/tlsclient"
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
		//
		// The help text names every class the setter touches, because the
		// slowest one is what the walk keeps: a reader who believed "on /dcap
		// and /tm" would set 30, watch the cadence stop at 60, and go looking
		// for the discrepancy in the DUT.
		pollRateS = flag.Uint("poll-rate-s", 0, "advertise this pollRate (seconds) on every resource class a "+
			"poll_rate_mode=honor client paces its walk from — DeviceCapability (/dcap), Time (/tm) and each "+
			"DERProgram's DERControlList, including the extended (curve-linked) form — and on every control "+
			"list created afterwards. A client paces at the SLOWEST advertisement, so one list left behind "+
			"pins the whole walk. 0 keeps the built-in rates (300 /dcap, 900 /tm, 60 control lists)")

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

		// The two DER AGGREGATOR CLIENT capabilities (owner decision 2026-07-28,
		// docs/PROFILE_SCOPE_2026-07-28_der-aggregator-client.md §5). Both
		// default OFF, and with both off this binary serves byte-identical XML
		// to the one it served before they existed — which is the point: the
		// direct-DER-client rows were certified against that tree and must not
		// silently start being measured against a different one.
		fleet = flag.Int("fleet", 0, "serve the CTP Figure-15 aggregator topology: an aggregator EndDevice "+
			"plus EDA1/EDA2 under SPA1/SPA2 and EDB1/EDB2 under SPB1/SPB2, each with a "+
			"FunctionSetAssignmentsListLink, a DERListLink and the node DERPrograms of its parent chain. "+
			"Only 4 is defined (the figure's size); 0 keeps the single-EndDevice tree")
		subscription = flag.Bool("subscription", false, "serve the IEEE 2030.5 Subscription/Notification "+
			"function set: advertise a SubscriptionListLink on every EndDevice, mark the "+
			"FunctionSetAssignmentsList subscribable=1, accept POST/GET/DELETE of Subscriptions, and POST a "+
			"Notification to a subscriber's notificationURI when the subscribed resource changes")

		// The notification transport. gridsim is pure Go and Go's crypto/tls has
		// no ECDHE-ECDSA-AES128-CCM-8, so it REFUSES an https:// notificationURI
		// and records the refusal; this binary has wolfSSL and can install a
		// Notifier that dials one properly. Without these the refusal stands,
		// loudly, which is the honest default: a Notification delivered over
		// some other TLS profile would be evidence about a connection IEEE
		// 2030.5 does not describe.
		notifyCert = flag.String("notify-cert", "", "CLIENT certificate PEM this server presents when it "+
			"dials a subscriber's https:// notificationURI. A Notification travels on a connection the "+
			"SERVER opens, so on that leg this process is the mTLS client and needs a client identity — not "+
			"the -cert it serves with. Set it with -notify-key to install the wolfSSL notifier; leave both "+
			"empty and an https:// notificationURI is refused with the reason recorded in "+
			"GET /admin/notifications")
		notifyKey = flag.String("notify-key", "", "private key PEM matching -notify-cert")
		notifyCA  = flag.String("notify-ca", "", "CA PEM used to verify the SUBSCRIBER's server certificate "+
			"on the notification leg; empty uses -ca")

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

	// Order matters and only in one direction: enabling subscriptions first
	// means the fleet's EndDevices and FunctionSetAssignmentsLists are built
	// already carrying the SubscriptionListLink and subscribable=1, rather than
	// being built without them and widened afterwards. Both orders end in the
	// same tree; this one does it in a single pass.
	if *subscription {
		sim.EnableSubscriptions()
		installNotifier(sim, *notifyCA, *caCert, *notifyCert, *notifyKey)
	}
	if *fleet != 0 {
		if err := sim.EnableFleet(*fleet); err != nil {
			log.Fatalf("-fleet %d: %v", *fleet, err)
		}
		if !*subscription {
			// Say it here rather than leaving a conformance operator to
			// discover it from a bundle full of SKIPs: the aggregator rows need
			// both halves, and a fleet without the function set closes only the
			// fan-out half of the gap.
			log.Printf("[gridsim] NOTE: -fleet is on but -subscription is not. The CTP's aggregator rows " +
				"that turn on Subscription/Notification (AGG-001, CORE-018/019, ERR-002, MAINT-001/003/004/005, " +
				"UTIL-003) will still report SKIP naming that gap")
		}
	}

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
	// Publish the two flags a conformance run's certificate evidence depends on,
	// so a harness can PROVE the posture before case 1 instead of discovering at
	// report time that every window held a resumed session. See
	// gridsim.Server.SetTLSPosture; a gridsim that never calls this reports no
	// tls object at all, which a fail-closed caller reads as unproven.
	sim.SetTLSPosture(*noTickets, srv.IdleTimeout)
	srv.OnHandshake = func(version, cipher string) {
		log.Printf("✓ mTLS handshake: version=%s cipher=%s", version, cipher)
	}
	srv.OnClientCert = sim.SetClientCertDER

	// Wire the runtime certificate-chain lever (GET/POST /admin/chain) to the
	// TLS server. This is what makes COMM-004 D/E/F/G runnable at all: those
	// rows need the bench to PRESENT a non-conformant chain, and before this
	// the only way to change the chain was to restart this process — which
	// invalidates the evidence of every test case already run against it.
	//
	// The adapter below exists so gridsim (pure Go, tested with no wolfSSL
	// sysroot) never imports tlsserver (cgo). It is the entire coupling
	// between the two.
	sim.SetChainSwapper(chainAdapter{srv})

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

// installNotifier gives the Subscription function set a transport that can dial
// the CSIP-mandatory cipher.
//
// It is the second seam of the same shape as chainAdapter below, and for the
// same reason: sim/gridsim must never import cgo, so the two halves of the
// simulator are bolted together here. The difference is that this one is
// OPTIONAL — a bench whose subscribers use an http:// listener needs nothing,
// and one whose subscriber is a real gateway needs a client identity that only
// the operator can supply.
//
// The absence is logged as loudly as the presence. An operator who started
// -subscription expecting Notifications and gets refusals in
// GET /admin/notifications should be able to find the reason in the server's
// own output rather than in a bundle full of SKIPs three hours later.
func installNotifier(sim *gridsim.Server, notifyCA, caCert, cert, key string) {
	if cert == "" || key == "" {
		log.Printf("[gridsim] NOTE: -subscription is on but no -notify-cert/-notify-key was given, so an " +
			"https:// notificationURI will be REFUSED and recorded as undeliverable. A Notification travels " +
			"on a connection this server dials, and IEEE 2030.5 requires it to be mutually authenticated; " +
			"supply a client identity to deliver one. An http:// bench listener works either way")
		return
	}
	ca := notifyCA
	if ca == "" {
		ca = caCert
	}
	sim.SetNotifier(csipnotify.New(csipnotify.Config{
		CACertPath:     ca,
		ClientCertPath: cert,
		ClientKeyPath:  key,
	}))
	log.Printf("[gridsim] Notification transport: wolfSSL mTLS (cipher %s), client identity %s, "+
		"subscriber CA %s. Session secrets are exported on this leg too in a -tags keylog build, so a "+
		"capture of the server-dialled Notification decrypts like every other bench flow",
		tlsclient.DefaultCipherList, cert, ca)
}

// chainAdapter presents the TLS server's chain lever as the narrow interface
// gridsim's admin plane consumes, translating one struct into the other.
//
// The translation is the price of keeping gridsim free of cgo, and it is worth
// paying: gridsim's unit tests run on any machine, and this file — which is
// already the place where the two halves of the simulator are bolted together —
// is where the seam belongs.
type chainAdapter struct{ srv *tlsserver.Server }

func (a chainAdapter) ActiveChain() gridsim.ChainState   { return toChainState(a.srv.ActiveChain()) }
func (a chainAdapter) OriginalChain() gridsim.ChainState { return toChainState(a.srv.OriginalChain()) }

func (a chainAdapter) SwapChain(label, certPath, keyPath string) (gridsim.ChainState, error) {
	info, err := a.srv.SwapChain(label, certPath, keyPath)
	return toChainState(info), err
}

func (a chainAdapter) RestoreChain() (gridsim.ChainState, error) {
	info, err := a.srv.RestoreChain()
	return toChainState(info), err
}

func toChainState(i tlsserver.ChainInfo) gridsim.ChainState {
	return gridsim.ChainState{
		Label:         i.Label,
		LeafSHA256:    i.LeafSHA256,
		ChainLen:      i.ChainLen,
		Subjects:      i.Subjects,
		Issuers:       i.Issuers,
		Original:      i.Original,
		InstalledUnix: i.InstalledUnix,
		Swaps:         i.Swaps,
		Warnings:      i.Warnings,
	}
}
