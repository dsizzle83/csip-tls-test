package main

import (
	"csip-tls-test/internal/gridsim"
	"log"
	"net/http"
)

const (
	port = ":11111"
	// Replace with your RPi's actual LFDI once you generate it from its cert
	clientLFDI = "AB12CD34EF56789012345678901234567890ABCD"
)

func main() {
	sim := gridsim.NewServer(clientLFDI)

	log.Printf("Starting IEEE 2030.5 Simulation Server on %s", port)
	log.Printf("Expecting client LFDI: %s", clientLFDI)

	// Bind to all interfaces (0.0.0.0) so the RPi can find it
	if err := http.ListenAndServe("0.0.0.0"+port, sim.Handler()); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}
