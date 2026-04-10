package main

import (
	"flag"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"csip-tls-test/internal/tlsserver"
)

func main() {
	var (
		listenAddr = flag.String("listen", "0.0.0.0:11111", "address:port to listen on")
		caCert     = flag.String("ca", "/home/dmitri/csip-tls-test/certs/ca-cert.pem", "CA cert PEM path")
		serverCert = flag.String("cert", "/home/dmitri/csip-tls-test/certs/server-cert.pem", "server cert PEM path")
		serverKey  = flag.String("key", "/home/dmitri/csip-tls-test/certs/server-key.pem", "server key PEM path")
	)
	flag.Parse()

	tlsserver.Init()
	defer tlsserver.Cleanup()

	srv, err := tlsserver.New(tlsserver.Config{
		CACertPath:     *caCert,
		ServerCertPath: *serverCert,
		ServerKeyPath:  *serverKey,
	})
	if err != nil {
		log.Fatalf("server init: %v", err)
	}

	srv.OnHandshake = func(version, cipher string) {
		log.Printf("✓ mTLS handshake: version=%s cipher=%s", version, cipher)
	}

	lis, err := net.Listen("tcp", *listenAddr)
	if err != nil {
		log.Fatalf("listen: %v", err)
	}

	log.Printf("Server listening on %s (mTLS, cipher=%s)",
		lis.Addr(), tlsserver.DefaultCipherList)

	// Graceful shutdown on SIGINT/SIGTERM. Closing the listener
	// causes Serve to return cleanly; we then call srv.Close to drain
	// in-flight handlers and free the wolfSSL ctx.
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sig
		log.Printf("shutting down...")
		_ = lis.Close()
	}()

	if err := srv.Serve(lis); err != nil {
		log.Printf("serve ended with error: %v", err)
	}
	srv.Close()
	log.Printf("clean shutdown")
}
