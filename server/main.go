package main

import (
	"flag"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"csip-tls-test/internal/gridsim"
	"csip-tls-test/internal/tlsserver"
	"csip-tls-test/internal/wolfssl"
)

func main() {
	var (
		listenAddr = flag.String("listen", "0.0.0.0:11111", "address:port to listen on")
		caCert     = flag.String("ca", "/home/dmitri/csip-tls-test/certs/ca-cert.pem", "CA cert PEM path")
		serverCert = flag.String("cert", "/home/dmitri/csip-tls-test/certs/server-cert.pem", "server cert PEM path")
		serverKey  = flag.String("key", "/home/dmitri/csip-tls-test/certs/server-key.pem", "server key PEM path")
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

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sig
		log.Printf("shutting down...")
		_ = lis.Close()
	}()

	if err := srv.Serve(lis); err != nil {
		log.Printf("serve ended: %v", err)
	}
	srv.Close()
	log.Printf("clean shutdown")
}

