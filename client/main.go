package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"csip-tls-test/internal/tlsclient"
	"csip-tls-test/internal/wolfssl"
)

func main() {
	var (
		serverAddr = flag.String("server", "127.0.0.1:11111", "server address:port")
		caCert     = flag.String("ca", "/home/dmitri/csip-tls-test/internal/tlsclient/testdata/certs/ca-cert.pem", "CA cert PEM path")
		clientCert = flag.String("cert", "/home/dmitri/csip-tls-test/internal/tlsclient/testdata/certs/client-cert.pem", "client cert PEM path")
		clientKey  = flag.String("key", "/home/dmitri/csip-tls-test/internal/tlsclient/testdata/certs/client-key.pem", "client key PEM path")
		verbose    = flag.Bool("v", false, "verbose: print full DCAP response")
	)
	flag.Parse()

	wolfssl.Init()
	defer wolfssl.Cleanup()

	client, err := tlsclient.New(tlsclient.Config{
		ServerAddr:     *serverAddr,
		CACertPath:     *caCert,
		ClientCertPath: *clientCert,
		ClientKeyPath:  *clientKey,
	})
	if err != nil {
		log.Fatalf("client init: %v", err)
	}
	defer client.Free()

	log.Printf("Connecting to %s...", *serverAddr)
	if err := client.Dial(); err != nil {
		log.Fatalf("dial: %v", err)
	}

	log.Printf("✓ mTLS handshake: version=%s cipher=%s",
		client.Version(), client.Cipher())

	dcap, err := client.FetchDCAP()
	if err != nil {
		log.Fatalf("FetchDCAP: %v", err)
	}

	fmt.Printf("✓ DeviceCapability fetched (href=%s)\n", dcap.Href)
	if dcap.EndDeviceListLink != nil {
		fmt.Printf("    EndDeviceList:    %s (all=%s)\n",
			dcap.EndDeviceListLink.Href, dcap.EndDeviceListLink.All)
	}
	if dcap.MirrorUsagePointLink != nil {
		fmt.Printf("    MirrorUsagePoint: %s (all=%s)\n",
			dcap.MirrorUsagePointLink.Href, dcap.MirrorUsagePointLink.All)
	}
	if dcap.SelfDeviceLink != nil {
		fmt.Printf("    SelfDevice:       %s\n", dcap.SelfDeviceLink.Href)
	}
	if dcap.TimeLink != nil {
		fmt.Printf("    Time:             %s\n", dcap.TimeLink.Href)
	}

	if *verbose {
		fmt.Fprintln(os.Stderr, "\n--- raw GET /dcap response ---")
		// Need to redial because FetchDCAP closed via Connection: close
		client.Close()
		if err := client.Dial(); err != nil {
			log.Fatalf("redial: %v", err)
		}
		raw, err := client.Get("/dcap")
		if err != nil {
			log.Fatalf("Get: %v", err)
		}
		fmt.Fprintln(os.Stderr, string(raw))
	}

	client.Close()
}
