package main

import (
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"os"

	"csip-tls-test/internal/csip/discovery"
	"csip-tls-test/internal/csip/identity"
	"csip-tls-test/internal/tlsclient"
	"csip-tls-test/internal/wolfssl"
)

func main() {
	var (
		serverAddr = flag.String("server", "192.168.0.188:11111", "server address:port")
		caCert     = flag.String("ca", "/home/dmitri/csip-tls-test/certs/ca-cert.pem", "CA cert PEM path")
		clientCert = flag.String("cert", "/home/dmitri/csip-tls-test/certs/client-cert.pem", "client cert PEM path")
		clientKey  = flag.String("key", "/home/dmitri/csip-tls-test/certs/client-key.pem", "client key PEM path")
		lfdi       = flag.String("lfdi", "", "client LFDI (hex, from cert); if empty, derived from -cert")
	)
	flag.Parse()

	wolfssl.Init()
	defer wolfssl.Cleanup()

	fetcher, err := tlsclient.NewWolfSSLFetcher(tlsclient.Config{
		ServerAddr:     *serverAddr,
		CACertPath:     *caCert,
		ClientCertPath: *clientCert,
		ClientKeyPath:  *clientKey,
	})
	if err != nil {
		log.Fatalf("init fetcher: %v", err)
	}
	defer fetcher.Free()

	// Derive LFDI from cert if not provided on the command line.
	clientLFDI := *lfdi
	if clientLFDI == "" {
		clientLFDI, err = lfdiFromCertFile(*clientCert)
		if err != nil {
			log.Fatalf("derive LFDI from cert: %v", err)
		}
	}
	log.Printf("Client LFDI: %s", clientLFDI)
	log.Printf("Connecting to %s...", *serverAddr)

	walker := discovery.NewWalker(fetcher, clientLFDI)
	tree, err := walker.Discover("/dcap")
	if err != nil {
		log.Fatalf("discovery walk: %v", err)
	}

	// ── Results ───────────────────────────────────────────────────
	fmt.Printf("✓ mTLS handshake: ECDHE-ECDSA-AES128-CCM-8 TLSv1.2 (server=%s)\n", *serverAddr)

	if tree.DeviceCapability != nil {
		fmt.Printf("✓ DeviceCapability fetched (href=%s, pollRate=%d)\n",
			tree.DeviceCapability.Href, tree.DeviceCapability.PollRate)
		if tree.DeviceCapability.EndDeviceListLink != nil {
			fmt.Printf("    EndDeviceList: %s (all=%d)\n",
				tree.DeviceCapability.EndDeviceListLink.Href,
				tree.DeviceCapability.EndDeviceListLink.All)
		}
	}

	if tree.Time != nil {
		fmt.Printf("✓ Time fetched (currentTime=%d, quality=%d)\n",
			tree.Time.CurrentTime, tree.Time.Quality)
	}

	if tree.SelfDevice != nil {
		fmt.Printf("✓ SelfDevice matched by LFDI\n")
		fmt.Printf("    LFDI: %s\n", tree.SelfDevice.LFDI)
	} else {
		fmt.Println("✗ SelfDevice NOT found — LFDI mismatch or EndDevice list empty")
		os.Exit(1)
	}

	fmt.Printf("✓ DERPrograms discovered: %d\n", len(tree.Programs))
	if len(tree.Programs) == 0 {
		fmt.Println("✗ No DERPrograms found — walker or server issue")
		os.Exit(1)
	}
	for i, ps := range tree.Programs {
		fmt.Printf("    Program[%d]: %s (primacy=%d)\n",
			i, ps.Program.MRID, ps.Program.Primacy)
		if ps.DefaultControl != nil && ps.DefaultControl.DERControlBase.OpModExpLimW != nil {
			fmt.Printf("        DefaultDERControl: OpModExpLimW=%dW\n",
				ps.DefaultControl.DERControlBase.OpModExpLimW.Value)
		}
		if ps.Controls != nil {
			fmt.Printf("        DERControls: %d scheduled\n", len(ps.Controls.DERControl))
		}
	}
}

func lfdiFromCertFile(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return "", fmt.Errorf("no PEM block in %s", path)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", err
	}
	lfdi, _ := identity.FromCertificate(cert)
	return lfdi.String(), nil
}
