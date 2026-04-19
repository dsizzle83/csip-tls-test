package main

import (
	"flag"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"csip-tls-test/sim/gridsim"
	"csip-tls-test/internal/ocppserver"
	"csip-tls-test/sim/tlsserver"
	"csip-tls-test/internal/wolfssl"
)

func main() {
	var (
		listenAddr = flag.String("listen", "0.0.0.0:11111", "address:port to listen on")
		caCert     = flag.String("ca", "/home/dmitri/csip-tls-test/certs/ca-cert.pem", "CA cert PEM path")
		serverCert = flag.String("cert", "/home/dmitri/csip-tls-test/certs/server-cert.pem", "server cert PEM path")
		serverKey  = flag.String("key", "/home/dmitri/csip-tls-test/certs/server-key.pem", "server key PEM path")

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

	// LFDI starts empty; SetClientCertDER fills it in from the peer cert
	// during each mTLS handshake (Step A: live derivation, not from a file).
	sim := gridsim.NewServer("")

	srv, err := tlsserver.New(tlsserver.Config{
		CACertPath:     *caCert,
		ServerCertPath: *serverCert,
		ServerKeyPath:  *serverKey,
	})
	if err != nil {
		log.Fatalf("server init: %v", err)
	}
	srv.Handler = sim.Handler()
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
		_ = lis.Close()
	}()

	if err := srv.Serve(lis); err != nil {
		log.Printf("serve ended: %v", err)
	}
	srv.Close()
	log.Printf("clean shutdown")
}

