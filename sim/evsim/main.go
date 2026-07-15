// evsim is an OCPP charging station client simulator with a realistic EV
// battery model, speaking either OCPP 2.0.1 (default) or OCPP 1.6J
// (-proto 1.6) to the CSMS. The battery follows a CC/CV charging curve:
// constant current in the bulk phase (SOC < cvStartSOC) and a linear taper in
// the absorption phase (SOC ≥ cvStartSOC). MeterValues are sent to the CSMS
// periodically so the orchestrator receives actual current, not commanded.
//
// Both protocol modes drive the exact same simulated device (battery.go,
// state.go, session.go) — evsim is a protocol ADAPTER over one simulator, not
// two separate simulators. See proto.go for the chargerProto interface that
// draws that line, and ocpp201.go / ocpp16.go for the two implementations.
//
// Usage:
//
//	evsim -csms ws://69.0.0.1:8887/ocpp [-id evse-001] [-connectors 1]
//	       [-proto 2.0.1|1.6] [-battery-kwh 60] [-battery-soc 20]
//	       [-sim-speed 1.0] [-session-interval 180] [-session-duration 3600]
//	       [-meter-interval 10] [-voltage 230] [-max-current 32]
//	       [-api-port 6024]
//
// OCPP 1.6J mode:
//
//	evsim -csms ws://69.0.0.1:8887/ocpp -proto 1.6 -id evse-001
//
// Security Profile 2 (TLS + HTTP Basic Auth) — the SAME flags cover both
// protocol versions:
//
//	evsim -csms wss://hub:8887/ocpp -proto 1.6 -tls-ca certs/ca-cert.pem \
//	       -auth-user evse-001 -auth-pass <secret>
//
// The simulator models a single EV: at most one charging session (OCPP
// transaction) runs at a time, plugging into the first Available connector.
//
// API (default :6024):
//
//	GET  /state    — JSON snapshot: connection, connectors, session, battery
//	POST /inject   — inject connector status: {"connector_id":1,"status":"Faulted"}
//	               — trigger session:         {"action":"start_session","connector_id":1}
//	               — end session:             {"action":"stop_session","connector_id":1}
//	GET  /ws       — WebSocket; pushes /state every 2 s
package main

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	ocpp16 "github.com/lorenzodonini/ocpp-go/ocpp1.6"
	ocpp2 "github.com/lorenzodonini/ocpp-go/ocpp2.0.1"
	"github.com/lorenzodonini/ocpp-go/ws"

	"csip-tls-test/sim/simapi"
)

// Station identity sent in BootNotification (also replayed after a Reset).
// Shared by both protocol versions.
const (
	stationModel  = "CSIP-EV-Simulator"
	stationVendor = "GreenGrid-Labs"
)

func main() {
	csmsURL := flag.String("csms", "ws://69.0.0.1:8887/ocpp", "CSMS WebSocket base URL")
	protoFlag := flag.String("proto", "2.0.1", `OCPP protocol version: "2.0.1" (default) or "1.6" (1.6J)`)
	stationID := flag.String("id", "evse-001", "Charging station identifier")
	numConnectors := flag.Int("connectors", 1, "Number of connectors")
	sessionInterval := flag.Int("session-interval", 180, "Seconds between simulated sessions")
	sessionDuration := flag.Int("session-duration", 3600, "Max session duration (seconds); ends early if battery full")
	apiPort := flag.Int("api-port", 6024, "HTTP API port (0 to disable)")
	battKwh := flag.Float64("battery-kwh", 60.0, "EV battery capacity (kWh)")
	battSOC := flag.Float64("battery-soc", 20.0, "Initial battery state of charge (%)")
	simSpeed := flag.Float64("sim-speed", 1.0, "Simulation time multiplier (1=real-time, 60=60× faster)")
	meterIntervalS := flag.Int("meter-interval", 10, "MeterValues send interval (real seconds)")
	voltageV := flag.Float64("voltage", 230.0, "AC supply voltage (V)")
	maxCurrentA := flag.Float64("max-current", 32.0, "EVSE hardware max current (A)")

	// Security Profile 2 (TLS + HTTP Basic Auth). -tls-ca requires a wss:// URL.
	// These flags are shared by both -proto modes — no parallel/duplicate set.
	tlsCA := flag.String("tls-ca", "", "CA cert PEM that signed the CSMS server cert (enables TLS verification)")
	authUser := flag.String("auth-user", "", "HTTP Basic Auth username")
	authPass := flag.String("auth-pass", "", "HTTP Basic Auth password")
	flag.Parse()

	protoName, err := normalizeProto(*protoFlag)
	if err != nil {
		log.Fatalf("evsim: %v", err)
	}

	log.Printf("evsim: station=%s csms=%s proto=%s battery=%.0fkWh soc=%.0f%% speed=%.1fx",
		*stationID, *csmsURL, protoName, *battKwh, *battSOC, *simSpeed)

	wsClient, err := newWSClient(*csmsURL, *tlsCA, *authUser, *authPass)
	if err != nil {
		log.Fatalf("evsim: %v", err)
	}

	batt := newEVBattery(*battKwh*1000, *battSOC, *voltageV, *maxCurrentA, *simSpeed)
	h := &csHandler{
		stationID:       *stationID,
		csmsURL:         *csmsURL,
		batt:            batt,
		meterInterval:   time.Duration(*meterIntervalS) * time.Second,
		sessionDuration: time.Duration(*sessionDuration) * time.Second,
	}
	for i := 1; i <= *numConnectors; i++ {
		h.setConnector(i, connAvailable)
	}

	switch protoName {
	case "1.6":
		cp := ocpp16.NewChargePoint(*stationID, nil, wsClient)
		h16 := &ocpp16Handlers{h: h}
		cp.SetCoreHandler(h16)
		cp.SetSmartChargingHandler(h16)
		cp.SetRemoteTriggerHandler(h16)
		if err := cp.Start(*csmsURL); err != nil {
			log.Fatalf("evsim: connect to %s: %v", *csmsURL, err)
		}
		h.proto = newOCPP16Proto(cp)
	default: // "2.0.1"
		cs := ocpp2.NewChargingStation(*stationID, nil, wsClient)
		h201 := &ocpp201Handlers{h: h}
		cs.SetProvisioningHandler(h201)
		cs.SetAvailabilityHandler(h201)
		cs.SetRemoteControlHandler(h201)
		cs.SetSmartChargingHandler(h201)
		if err := cs.Start(*csmsURL); err != nil {
			log.Fatalf("evsim: connect to %s: %v", *csmsURL, err)
		}
		h.proto = newOCPP201Proto(cs)
	}
	log.Printf("evsim: connected")

	boot, err := h.proto.Boot()
	if err != nil {
		log.Fatalf("evsim: BootNotification: %v", err)
	}
	log.Printf("evsim: BootNotification status=%s interval=%s", boot.Status, boot.Interval)

	for i := 1; i <= *numConnectors; i++ {
		h.sendStatus(i, connAvailable)
	}

	if *apiPort != 0 {
		api := simapi.New(
			fmt.Sprintf(":%d", *apiPort),
			func() any { return h.Snapshot() },
			func(body []byte) error { return h.Inject(body) },
			nil,
			nil,
		)
		api.SetFaultFn(h.ApplyFault)
		// Tee logs into the API ring so the dashboard's Logs tab can stream them.
		log.SetOutput(io.MultiWriter(os.Stderr, api.LogWriter()))
	}

	hbInterval := boot.Interval
	if hbInterval <= 0 {
		hbInterval = 60 * time.Second
	}
	hbTicker := time.NewTicker(hbInterval)
	defer hbTicker.Stop()
	sessionTicker := time.NewTicker(time.Duration(*sessionInterval) * time.Second)
	defer sessionTicker.Stop()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	for {
		select {
		case <-quit:
			log.Printf("evsim: shutting down")
			h.proto.Stop()
			return
		case <-hbTicker.C:
			h.setLastHeartbeat(time.Now())
			if err := h.proto.Heartbeat(); err != nil {
				log.Printf("evsim: Heartbeat: %v", err)
			}
		case <-sessionTicker.C:
			// Start a new transaction only when none is running — a real EV
			// stays plugged in for the whole session rather than re-plugging
			// every interval. The sim models a single EV, so it plugs into
			// the first Available connector.
			if !h.sessionActive() {
				if cid := h.firstAvailableConnector(); cid != 0 {
					h.startSession(cid, h.sessionDuration, trigCablePluggedIn, txStartOpts{})
				}
			}
		}
	}
}

// normalizeProto validates and canonicalizes -proto into "2.0.1" or "1.6".
func normalizeProto(s string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "2.0.1", "2.0", "201":
		return "2.0.1", nil
	case "1.6", "1.6j", "16":
		return "1.6", nil
	default:
		return "", fmt.Errorf(`unsupported -proto %q (want "2.0.1" or "1.6")`, s)
	}
}

// newWSClient builds the WebSocket client for the CSMS connection. Shared by
// both -proto modes: ws.WsClient is protocol-independent (ocpp2.NewChargingStation
// and ocpp16.NewChargePoint both accept it), so TLS/Basic Auth setup lives in
// exactly one place regardless of OCPP version.
//
// Security Profile 2 (TLS + HTTP Basic Auth): pass -tls-ca with a wss:// URL
// and -auth-user/-auth-pass. A wss:// URL without -tls-ca uses the system
// root CA pool. Basic Auth over plain ws:// is allowed but warned about,
// since the credentials travel in cleartext.
func newWSClient(csmsURL, tlsCA, authUser, authPass string) (ws.WsClient, error) {
	secure := strings.HasPrefix(csmsURL, "wss://")

	var client *ws.Client
	switch {
	case tlsCA != "":
		if !secure {
			return nil, fmt.Errorf("-tls-ca requires a wss:// CSMS URL (got %s)", csmsURL)
		}
		caPEM, err := os.ReadFile(tlsCA)
		if err != nil {
			return nil, fmt.Errorf("read -tls-ca: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caPEM) {
			return nil, fmt.Errorf("-tls-ca %s contains no usable CA certificates", tlsCA)
		}
		client = ws.NewTLSClient(&tls.Config{
			RootCAs:    pool,
			MinVersion: tls.VersionTLS12,
		})
		log.Printf("evsim: TLS enabled (CA=%s)", tlsCA)
	case secure:
		client = ws.NewTLSClient(&tls.Config{MinVersion: tls.VersionTLS12})
		log.Printf("evsim: TLS enabled (system root CAs)")
	default:
		client = ws.NewClient()
	}

	if authUser != "" {
		if !secure {
			log.Printf("evsim: WARNING — Basic Auth over plain ws:// sends credentials in cleartext")
		}
		client.SetBasicAuth(authUser, authPass)
		log.Printf("evsim: HTTP Basic Auth enabled (user=%s)", authUser)
	}
	return client, nil
}
