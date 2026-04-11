package main

import (
	"crypto/x509"
	"encoding/pem"
	"flag"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"csip-tls-test/internal/csip/identity"
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
		// clientCert is used to pre-compute the LFDI the gridsim puts in the EndDevice
		// record. Step A (next session) will replace this with live peer-cert derivation
		// inside the TLS handshake so the server doesn't need to know the cert up front.
		clientCert = flag.String("client-cert", "/home/dmitri/csip-tls-test/certs/client-cert.pem", "client cert PEM to derive LFDI from")
	)
	flag.Parse()

	wolfssl.Init()
	defer wolfssl.Cleanup()

	lfdi, err := lfdiFromCertFile(*clientCert)
	if err != nil {
		log.Fatalf("derive LFDI from %s: %v", *clientCert, err)
	}
	log.Printf("Client LFDI: %s", lfdi)

	sim := gridsim.NewServer(lfdi)

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

// lfdiFromCertFile reads a PEM-encoded X.509 cert and returns its LFDI
// as a hex string per IEEE 2030.5-2018 §6.3.4.
func lfdiFromCertFile(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return "", os.ErrInvalid
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", err
	}
	lfdi, _ := identity.FromCertificate(cert)
	return lfdi.String(), nil
}
