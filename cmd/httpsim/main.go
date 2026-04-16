// httpsim runs the IEEE 2030.5 gridsim over plain HTTP (no mTLS).
// Useful for development and integration testing without a wolfSSL build.
//
// Usage:
//
//	httpsim [-addr :11111] [-lfdi <40-hex-chars>]
package main

import (
	"flag"
	"log"
	"net/http"

	"csip-tls-test/internal/gridsim"
)

func main() {
	addr  := flag.String("addr", ":11111", "listen address")
	lfdi  := flag.String("lfdi", "AB12CD34EF56789012345678901234567890ABCD",
		"client LFDI to expect (40 hex chars)")
	flag.Parse()

	sim := gridsim.NewServer(*lfdi)

	log.Printf("httpsim: IEEE 2030.5 simulator on %s (LFDI=%s)", *addr, *lfdi)
	if err := http.ListenAndServe(*addr, sim.Handler()); err != nil {
		log.Fatalf("httpsim: %v", err)
	}
}
