package main

import (
	"csip-tls-test/internal/csipref/discovery"
	"csip-tls-test/internal/httpclient"
	"fmt"
	"log"
)

func main() {
	// 1. Point this to your WSL Machine's Windows IP address
	serverIP := "192.168.0.188"
	baseURL := fmt.Sprintf("http://%s:11111", serverIP)
	lfdi := "AB12CD34EF56789012345678901234567890ABCD"

	fetcher := httpclient.NewFetcher(baseURL, nil)
	walker := discovery.NewWalker(fetcher, lfdi)

	log.Printf("Starting discovery on %s...", baseURL)
	tree, err := walker.Discover("/dcap")
	if err != nil {
		log.Fatalf("Discovery failed: %v", err)
	}

	fmt.Printf("Success! Discovered EndDevice: %s\n", tree.SelfDevice.Href)
}
