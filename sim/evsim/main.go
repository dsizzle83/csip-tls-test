// evsim is an OCPP 2.0.1 charging station client simulator with a realistic
// EV battery model.  The battery follows a CC/CV charging curve: constant
// current in the bulk phase (SOC < cvStartSOC) and a linear taper in the
// absorption phase (SOC ≥ cvStartSOC).  MeterValues are sent to the CSMS
// periodically so the orchestrator receives actual current, not commanded.
//
// Usage:
//
//	evsim -csms ws://69.0.0.1:8887/ocpp [-id evse-001] [-connectors 1]
//	       [-battery-kwh 60] [-battery-soc 20] [-sim-speed 1.0]
//	       [-session-interval 180] [-session-duration 3600]
//	       [-meter-interval 10] [-voltage 230] [-max-current 32]
//	       [-api-port 6024]
//
// Security Profile 2 (TLS + HTTP Basic Auth):
//
//	evsim -csms wss://hub:8887/ocpp -tls-ca certs/ca-cert.pem \
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
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"math"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	ocpp2 "github.com/lorenzodonini/ocpp-go/ocpp2.0.1"
	"github.com/lorenzodonini/ocpp-go/ocpp2.0.1/availability"
	"github.com/lorenzodonini/ocpp-go/ocpp2.0.1/provisioning"
	"github.com/lorenzodonini/ocpp-go/ocpp2.0.1/remotecontrol"
	"github.com/lorenzodonini/ocpp-go/ocpp2.0.1/smartcharging"
	"github.com/lorenzodonini/ocpp-go/ocpp2.0.1/transactions"
	"github.com/lorenzodonini/ocpp-go/ocpp2.0.1/types"
	"github.com/lorenzodonini/ocpp-go/ws"

	"csip-tls-test/sim/simapi"
)

// Station identity sent in BootNotification (also replayed after a Reset).
const (
	stationModel  = "CSIP-EV-Simulator"
	stationVendor = "GreenGrid-Labs"
)

func main() {
	csmsURL := flag.String("csms", "ws://69.0.0.1:8887/ocpp", "CSMS WebSocket base URL")
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
	tlsCA := flag.String("tls-ca", "", "CA cert PEM that signed the CSMS server cert (enables TLS verification)")
	authUser := flag.String("auth-user", "", "HTTP Basic Auth username")
	authPass := flag.String("auth-pass", "", "HTTP Basic Auth password")
	flag.Parse()

	log.Printf("evsim: station=%s csms=%s battery=%.0fkWh soc=%.0f%% speed=%.1fx",
		*stationID, *csmsURL, *battKwh, *battSOC, *simSpeed)

	wsClient, err := newWSClient(*csmsURL, *tlsCA, *authUser, *authPass)
	if err != nil {
		log.Fatalf("evsim: %v", err)
	}
	cs := ocpp2.NewChargingStation(*stationID, nil, wsClient)

	batt := newEVBattery(*battKwh*1000, *battSOC, *voltageV, *maxCurrentA, *simSpeed)

	h := &csHandler{
		cs:              cs,
		stationID:       *stationID,
		csmsURL:         *csmsURL,
		batt:            batt,
		meterInterval:   time.Duration(*meterIntervalS) * time.Second,
		sessionDuration: time.Duration(*sessionDuration) * time.Second,
	}
	for i := 1; i <= *numConnectors; i++ {
		h.setConnector(i, availability.ConnectorStatusAvailable)
	}

	cs.SetProvisioningHandler(h)
	cs.SetAvailabilityHandler(h)
	cs.SetRemoteControlHandler(h)
	cs.SetSmartChargingHandler(h)

	if err := cs.Start(*csmsURL); err != nil {
		log.Fatalf("evsim: connect to %s: %v", *csmsURL, err)
	}
	log.Printf("evsim: connected")

	bootResp, err := cs.BootNotification(
		provisioning.BootReasonPowerUp, stationModel, stationVendor,
	)
	if err != nil {
		log.Fatalf("evsim: BootNotification: %v", err)
	}
	log.Printf("evsim: BootNotification status=%s interval=%ds", bootResp.Status, bootResp.Interval)

	for i := 1; i <= *numConnectors; i++ {
		sendStatus(cs, h, i, availability.ConnectorStatusAvailable)
	}

	if *apiPort != 0 {
		api := simapi.New(
			fmt.Sprintf(":%d", *apiPort),
			func() any { return h.Snapshot() },
			func(body []byte) error { return h.Inject(cs, body) },
			nil,
			nil,
		)
		// Tee logs into the API ring so the dashboard's Logs tab can stream them.
		log.SetOutput(io.MultiWriter(os.Stderr, api.LogWriter()))
	}

	hbInterval := time.Duration(bootResp.Interval) * time.Second
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
			cs.Stop()
			return
		case <-hbTicker.C:
			h.setLastHeartbeat(time.Now())
			if _, err := cs.Heartbeat(); err != nil {
				log.Printf("evsim: Heartbeat: %v", err)
			}
		case <-sessionTicker.C:
			// Start a new transaction only when none is running — a real EV
			// stays plugged in for the whole session rather than re-plugging
			// every interval. The sim models a single EV, so it plugs into
			// the first Available connector.
			if !h.sessionActive() {
				if cid := h.firstAvailableConnector(); cid != 0 {
					h.startSession(cs, cid, h.sessionDuration,
						transactions.TriggerReasonCablePluggedIn, nil)
				}
			}
		}
	}
}

// newWSClient builds the WebSocket client for the CSMS connection.
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

// ── EV battery CC/CV charging model ──────────────────────────────────────────
//
// CC phase (0 ≤ SOC < cvStartSOC): constant current at commanded limit.
// CV phase (cvStartSOC ≤ SOC < 100): current tapers linearly to zero.
//
// Energy update per tick:
//
//	ΔSOCpct = (actualA × voltageV × Δt_sim_h / capacityWh) × 100

// evBattery models one EV battery over a charging session.
type evBattery struct {
	mu sync.Mutex

	CapacityWh  float64 // total usable capacity (Wh)
	SOC         float64 // current state of charge (0–100 %)
	VoltageV    float64 // AC supply voltage (V)
	MaxCurrentA float64 // EVSE hardware max current (A)
	CVStartSOC  float64 // SOC % where CC→CV transition begins (default 80)
	SimSpeed    float64 // time multiplier: each real tick covers SimSpeed × dt

	commandedA float64 // current limit from last SetChargingProfile (A)
	actualA    float64 // actual current per CC/CV model (A)
	sessionWh  float64 // cumulative energy this session (Wh)
}

func newEVBattery(capacityWh, initialSOC, voltageV, maxCurrentA, simSpeed float64) *evBattery {
	return &evBattery{
		CapacityWh:  capacityWh,
		SOC:         math.Min(100, math.Max(0, initialSOC)),
		VoltageV:    voltageV,
		MaxCurrentA: maxCurrentA,
		CVStartSOC:  80.0,
		SimSpeed:    math.Max(0.001, simSpeed),
	}
}

// SetCommandedA updates the charging current limit from a SetChargingProfile.
func (b *evBattery) SetCommandedA(a float64) {
	b.mu.Lock()
	b.commandedA = a
	b.mu.Unlock()
}

// ResetSession zeros the session energy counter. Call when a new session starts.
func (b *evBattery) ResetSession() {
	b.mu.Lock()
	b.sessionWh = 0
	b.mu.Unlock()
}

// StopCharging zeros the commanded and actual current. Call when a session
// ends so State() doesn't keep reporting the last mid-charge current.
func (b *evBattery) StopCharging() {
	b.mu.Lock()
	b.commandedA = 0
	b.actualA = 0
	b.mu.Unlock()
}

// Tick advances the battery simulation by dt × SimSpeed of simulated time.
// Returns (actualA, full): full is true when SOC reaches 100%.
func (b *evBattery) Tick(dt time.Duration) (actualA float64, full bool) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.SOC >= 100.0 || b.commandedA <= 0 {
		b.actualA = 0
		return 0, b.SOC >= 100.0
	}

	limit := math.Min(b.commandedA, b.MaxCurrentA)

	if b.SOC < b.CVStartSOC {
		// CC phase: full current.
		b.actualA = limit
	} else {
		// CV phase: linear taper from full current at cvStartSOC to 0 at 100%.
		taper := (100.0 - b.SOC) / (100.0 - b.CVStartSOC)
		b.actualA = limit * math.Max(0, taper)
	}

	// Advance simulated time.
	simSec := dt.Seconds() * b.SimSpeed
	dtH := simSec / 3600.0
	powerW := b.actualA * b.VoltageV
	energyWh := powerW * dtH

	b.SOC = math.Min(100.0, b.SOC+(energyWh/b.CapacityWh)*100.0)
	b.sessionWh += energyWh

	if b.SOC >= 100.0 {
		b.SOC = 100.0
		b.actualA = 0
		return 0, true
	}
	return b.actualA, false
}

// Phase returns "CC" or "CV" based on current SOC.
func (b *evBattery) Phase() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.SOC < b.CVStartSOC {
		return "CC"
	}
	return "CV"
}

// State returns a thread-safe snapshot of the battery.
func (b *evBattery) State() (soc, actualA, sessionWh float64) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.SOC, b.actualA, b.sessionWh
}

// ── Session simulation ────────────────────────────────────────────────────────

// sessionHandle owns the cancellation of one charging session. The stop
// reason/trigger are recorded by whoever requests the stop (remote command,
// GUI inject, reset) before cancelling, so the session goroutine can report
// them in the TransactionEvent(Ended) it sends on the way out.
type sessionHandle struct {
	cancel context.CancelFunc
	done   chan struct{}

	mu      sync.Mutex
	reason  transactions.Reason
	trigger transactions.TriggerReason
}

// setStop records why the session is being stopped. First caller wins.
func (sh *sessionHandle) setStop(reason transactions.Reason, trigger transactions.TriggerReason) {
	sh.mu.Lock()
	if sh.reason == "" {
		sh.reason = reason
		sh.trigger = trigger
	}
	sh.mu.Unlock()
}

// stopCause returns the recorded stop reason/trigger, defaulting to a local stop.
func (sh *sessionHandle) stopCause() (transactions.Reason, transactions.TriggerReason) {
	sh.mu.Lock()
	defer sh.mu.Unlock()
	if sh.reason == "" {
		return transactions.ReasonLocal, transactions.TriggerReasonChargingStateChanged
	}
	return sh.reason, sh.trigger
}

// startSession stops any running session (waiting for its Ended event to go
// out) and starts a new one. Blocks until the old session has fully wound
// down; callers on OCPP handler goroutines must wrap it in `go`.
func (h *csHandler) startSession(cs ocpp2.ChargingStation, connectorID int, maxDuration time.Duration,
	trigger transactions.TriggerReason, remoteStartID *int) {
	h.stopSession(transactions.ReasonLocal, transactions.TriggerReasonChargingStateChanged)

	ctx, cancel := context.WithCancel(context.Background())
	sh := &sessionHandle{cancel: cancel, done: make(chan struct{})}
	h.mu.Lock()
	h.sess = sh
	h.mu.Unlock()

	go func() {
		defer close(sh.done)
		simulateSession(ctx, cs, h, sh, connectorID, maxDuration, trigger, remoteStartID)
	}()
}

// stopSession stops the running session (if any) with the given OCPP stop
// reason and waits until the session goroutine has sent its Ended event and
// exited. No-op when no session is active. Must not be called from the
// session goroutine itself.
func (h *csHandler) stopSession(reason transactions.Reason, trigger transactions.TriggerReason) {
	h.mu.Lock()
	sh := h.sess
	h.sess = nil
	h.mu.Unlock()
	if sh == nil {
		return
	}
	sh.setStop(reason, trigger)
	sh.cancel()
	<-sh.done
}

// sessionActive reports whether a charging session is currently running.
func (h *csHandler) sessionActive() bool {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.session.Active
}

// firstAvailableConnector returns the lowest-numbered connector currently in
// the Available state, or 0 when none is.
func (h *csHandler) firstAvailableConnector() int {
	h.mu.RLock()
	defer h.mu.RUnlock()
	best := 0
	for id, c := range h.connectors {
		if c.Status != availability.ConnectorStatusAvailable {
			continue
		}
		if best == 0 || id < best {
			best = id
		}
	}
	return best
}

func simulateSession(ctx context.Context, cs ocpp2.ChargingStation, h *csHandler, sh *sessionHandle,
	connectorID int, maxDuration time.Duration, startTrigger transactions.TriggerReason, remoteStartID *int) {
	log.Printf("evsim: connector %d — session starting (max %v, SOC=%.1f%%)",
		connectorID, maxDuration, func() float64 { soc, _, _ := h.batt.State(); return soc }())
	h.batt.ResetSession()
	// Reset the commanded current to the IEC 61851-1 minimum so the EV does
	// not draw at whatever leftover SetChargingProfile limit the prior session
	// happened to end at.  The CSMS will issue a fresh limit on its next
	// control tick (typically within a few seconds).
	h.batt.SetCommandedA(6.0)
	startedAt := time.Now()
	h.beginTx(connectorID)
	h.setSessionActive(connectorID, true)
	sendStatus(cs, h, connectorID, availability.ConnectorStatusOccupied)
	h.sendTxEvent(transactions.TransactionEventStarted, startTrigger, remoteStartID, "", startedAt)

	outcome := runChargingLoop(ctx, cs, h, connectorID, maxDuration)

	var reason transactions.Reason
	var trigger transactions.TriggerReason
	switch outcome {
	case sessionCancelled:
		reason, trigger = sh.stopCause()
	case sessionBatteryFull:
		reason, trigger = transactions.ReasonSOCLimitReached, transactions.TriggerReasonChargingStateChanged
	case sessionDeadline:
		reason, trigger = transactions.ReasonTimeLimitReached, transactions.TriggerReasonTimeLimitReached
	}

	// Charging has stopped: zero the current so final readings and later
	// snapshots don't report a stale mid-charge value.
	h.batt.StopCharging()

	// Final readings: legacy MeterValues for CSMS implementations that only
	// track those, then the authoritative TransactionEvent(Ended).
	soc, cur, energy := h.batt.State()
	sendMeterValues(cs, h.batt, connectorID, soc, cur, energy)
	h.sendTxEvent(transactions.TransactionEventEnded, trigger, nil, reason, startedAt)
	sendStatus(cs, h, connectorID, availability.ConnectorStatusAvailable)
	h.setSessionActive(connectorID, false)
	h.endTx()

	soc, _, _ = h.batt.State()
	log.Printf("evsim: connector %d — session ended (reason=%s), SOC=%.1f%%", connectorID, reason, soc)
}

// sessionOutcome says how a charging loop ended.
type sessionOutcome int

const (
	sessionCancelled   sessionOutcome = iota // ctx cancelled (remote/local stop, reset, supersede)
	sessionBatteryFull                       // EV battery reached 100% SOC
	sessionDeadline                          // maxDuration elapsed
)

// runChargingLoop drives the battery simulation and periodic meter reporting
// until maxDuration elapses, the battery reaches 100% SOC, or ctx is cancelled.
func runChargingLoop(ctx context.Context, cs ocpp2.ChargingStation, h *csHandler, connectorID int, maxDuration time.Duration) sessionOutcome {
	simTicker := time.NewTicker(time.Second)
	defer simTicker.Stop()
	meterTicker := time.NewTicker(h.meterInterval)
	defer meterTicker.Stop()
	deadline := time.NewTimer(maxDuration)
	defer deadline.Stop()

	for {
		select {
		case <-ctx.Done():
			return sessionCancelled
		case <-simTicker.C:
			_, full := h.batt.Tick(time.Second)
			if full {
				log.Printf("evsim: connector %d — battery full (100%% SOC)", connectorID)
				return sessionBatteryFull
			}
		case <-meterTicker.C:
			soc, cur, energy := h.batt.State()
			// Legacy MeterValues kept for CSMS implementations that predate
			// the TransactionEvent handler; the Updated event is the
			// spec-correct carrier for in-transaction meter data.
			sendMeterValues(cs, h.batt, connectorID, soc, cur, energy)
			h.sendTxEvent(transactions.TransactionEventUpdated,
				transactions.TriggerReasonMeterValuePeriodic, nil, "", time.Time{})
		case <-deadline.C:
			return sessionDeadline
		}
	}
}

// buildMeterValue assembles the five key measurands shared by MeterValues and
// TransactionEvent: Current.Import, Power.Active.Import,
// Energy.Active.Import.Register, SoC, Voltage.
func buildMeterValue(batt *evBattery, soc, currentA, energyWh float64) types.MeterValue {
	now := types.NewDateTime(time.Now())
	powerW := currentA * batt.VoltageV
	return types.MeterValue{
		Timestamp: *now,
		SampledValue: []types.SampledValue{
			{
				Measurand:     types.MeasurandCurrentImport,
				Value:         currentA,
				UnitOfMeasure: &types.UnitOfMeasure{Unit: "A"},
			},
			{
				Measurand:     types.MeasurandPowerActiveImport,
				Value:         powerW,
				UnitOfMeasure: &types.UnitOfMeasure{Unit: "W"},
			},
			{
				Measurand:     types.MeasurandEnergyActiveImportRegister,
				Value:         energyWh,
				UnitOfMeasure: &types.UnitOfMeasure{Unit: "Wh"},
			},
			{
				Measurand: types.MeasurandSoC,
				Value:     soc,
			},
			{
				Measurand:     types.MeasurandVoltage,
				Value:         batt.VoltageV,
				UnitOfMeasure: &types.UnitOfMeasure{Unit: "V"},
			},
		},
	}
}

// sendMeterValues sends a bare OCPP MeterValues message (legacy path — kept
// for CSMS implementations that don't consume TransactionEvent yet).
func sendMeterValues(cs ocpp2.ChargingStation, batt *evBattery, connectorID int, soc, currentA, energyWh float64) {
	mv := buildMeterValue(batt, soc, currentA, energyWh)
	if _, err := cs.MeterValues(connectorID, []types.MeterValue{mv}); err != nil {
		log.Printf("evsim: MeterValues connector=%d: %v", connectorID, err)
		return
	}
	log.Printf("evsim: MeterValues connector=%d soc=%.1f%% current=%.1fA power=%.0fW energy=%.0fWh phase=%s",
		connectorID, soc, currentA, currentA*batt.VoltageV, energyWh, batt.Phase())
}

// ── Transaction events ────────────────────────────────────────────────────────

// newTxID returns a random 32-hex-char transaction identifier (≤ 36 chars as
// required by the OCPP transactionId field).
func newTxID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		// Fallback: time-based ID. Collisions are irrelevant in a simulator.
		return fmt.Sprintf("tx-%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b[:])
}

// beginTx allocates a new transaction ID for a starting session and resets
// the per-transaction sequence counter.
func (h *csHandler) beginTx(connectorID int) {
	h.mu.Lock()
	h.txID = newTxID()
	h.txSeqNo = 0
	h.txConnectorID = connectorID
	h.mu.Unlock()
}

// endTx clears the transaction state after the Ended event has been sent.
func (h *csHandler) endTx() {
	h.mu.Lock()
	h.txID = ""
	h.txConnectorID = 0
	h.mu.Unlock()
}

// sendTxEvent sends a TransactionEvent (Started/Updated/Ended) for the current
// transaction, carrying the current meter sample. remoteStartID is set on
// Started events triggered by RequestStartTransaction; stopped is set on Ended
// events; startedAt (Ended only) is used for timeSpentCharging. No-op when no
// transaction is active.
func (h *csHandler) sendTxEvent(event transactions.TransactionEvent, trigger transactions.TriggerReason,
	remoteStartID *int, stopped transactions.Reason, startedAt time.Time) {
	h.mu.Lock()
	txID := h.txID
	seq := h.txSeqNo
	h.txSeqNo++
	connectorID := h.txConnectorID
	h.mu.Unlock()
	if txID == "" {
		return
	}

	soc, cur, energy := h.batt.State()
	info := transactions.Transaction{TransactionID: txID}
	switch event {
	case transactions.TransactionEventEnded:
		info.ChargingState = transactions.ChargingStateIdle
		info.StoppedReason = stopped
		if !startedAt.IsZero() {
			t := int(time.Since(startedAt).Seconds())
			info.TimeSpentCharging = &t
		}
	default:
		if cur > 0 {
			info.ChargingState = transactions.ChargingStateCharging
		} else {
			info.ChargingState = transactions.ChargingStateSuspendedEVSE
		}
	}
	if remoteStartID != nil {
		info.RemoteStartID = remoteStartID
	}

	connID := connectorID
	_, err := h.cs.TransactionEvent(event, types.NewDateTime(time.Now()), trigger, seq, info,
		func(req *transactions.TransactionEventRequest) {
			req.Evse = &types.EVSE{ID: 1, ConnectorID: &connID}
			req.MeterValue = []types.MeterValue{buildMeterValue(h.batt, soc, cur, energy)}
		})
	if err != nil {
		log.Printf("evsim: TransactionEvent %s tx=%s seq=%d: %v", event, txID, seq, err)
		return
	}
	log.Printf("evsim: TransactionEvent %s tx=%s seq=%d trigger=%s state=%s soc=%.1f%% current=%.1fA",
		event, txID, seq, trigger, info.ChargingState, soc, cur)
}

func sendStatus(cs ocpp2.ChargingStation, h *csHandler, connectorID int, status availability.ConnectorStatus) {
	now := types.NewDateTime(time.Now())
	h.setConnector(connectorID, status)
	_, err := cs.StatusNotification(now, status, 1, connectorID)
	if err != nil {
		log.Printf("evsim: StatusNotification connector=%d: %v", connectorID, err)
		return
	}
	log.Printf("evsim: StatusNotification connector=%d status=%s", connectorID, status)
}

// ── State tracking ────────────────────────────────────────────────────────────

type connectorInfo struct {
	ID         int                          `json:"id"`
	Status     availability.ConnectorStatus `json:"status"`
	LastUpdate time.Time                    `json:"last_update"`
}

type chargingProfileInfo struct {
	ReceivedAt string  `json:"received_at"`
	EvseID     int     `json:"evse_id"`
	ProfileID  int     `json:"profile_id"`
	Purpose    string  `json:"purpose"`
	LimitA     float64 `json:"limit_A"`
}

// batteryInfo is the JSON-serialisable battery snapshot in EVState.
type batteryInfo struct {
	CapacityWh float64 `json:"capacity_Wh"`
	SOC        float64 `json:"soc_pct"`
	CurrentA   float64 `json:"current_A"` // actual (CC/CV model), not commanded
	PowerW     float64 `json:"power_W"`
	SessionWh  float64 `json:"session_energy_Wh"`
	Phase      string  `json:"phase"` // "CC" or "CV"
}

// EVState is the JSON-serialisable snapshot for GET /state.
type EVState struct {
	Type      string    `json:"type"`
	Timestamp time.Time `json:"timestamp"`
	StationID string    `json:"station_id"`
	CSMS      struct {
		URL       string `json:"url"`
		Connected bool   `json:"connected"`
	} `json:"csms"`
	Connectors    []connectorInfo      `json:"connectors"`
	Session       sessionInfo          `json:"session"`
	Battery       batteryInfo          `json:"battery"`
	LastHeartbeat string               `json:"last_heartbeat,omitempty"`
	LastProfile   *chargingProfileInfo `json:"last_charging_profile,omitempty"`
}

type sessionInfo struct {
	Active        bool   `json:"active"`
	ConnectorID   int    `json:"connector_id,omitempty"`
	StartedAt     string `json:"started_at,omitempty"`
	TransactionID string `json:"transaction_id,omitempty"`
}

type csHandler struct {
	cs              ocpp2.ChargingStation
	stationID       string
	csmsURL         string
	batt            *evBattery
	meterInterval   time.Duration
	sessionDuration time.Duration

	mu            sync.RWMutex
	connectors    map[int]*connectorInfo
	session       sessionInfo
	lastHeartbeat time.Time
	lastProfile   *chargingProfileInfo

	// current session/transaction — guarded by mu
	sess          *sessionHandle
	txID          string
	txSeqNo       int
	txConnectorID int
}

func (h *csHandler) setLastHeartbeat(t time.Time) { h.mu.Lock(); h.lastHeartbeat = t; h.mu.Unlock() }

func (h *csHandler) setConnector(id int, status availability.ConnectorStatus) {
	h.mu.Lock()
	if h.connectors == nil {
		h.connectors = make(map[int]*connectorInfo)
	}
	h.connectors[id] = &connectorInfo{ID: id, Status: status, LastUpdate: time.Now()}
	h.mu.Unlock()
}

func (h *csHandler) setSessionActive(connectorID int, active bool) {
	h.mu.Lock()
	h.session.Active = active
	if active {
		h.session.ConnectorID = connectorID
		h.session.StartedAt = time.Now().UTC().Format(time.RFC3339)
	} else {
		h.session.ConnectorID = 0
		h.session.StartedAt = ""
	}
	h.mu.Unlock()
}

// Snapshot returns a thread-safe copy of the current state.
func (h *csHandler) Snapshot() EVState {
	h.mu.RLock()
	defer h.mu.RUnlock()

	st := EVState{
		Type:      "ev_charger",
		Timestamp: time.Now(),
		StationID: h.stationID,
	}
	st.CSMS.URL = h.csmsURL
	// Live connection state from the ocpp-go client (finding OCPP-4: a
	// write-once flag stayed "connected" forever after a CSMS drop).
	st.CSMS.Connected = h.cs.IsConnected()
	st.Session = h.session
	st.Session.TransactionID = h.txID
	if !h.lastHeartbeat.IsZero() {
		st.LastHeartbeat = h.lastHeartbeat.UTC().Format(time.RFC3339)
	}
	if h.lastProfile != nil {
		cp := *h.lastProfile
		st.LastProfile = &cp
	}
	for _, c := range h.connectors {
		cc := *c
		st.Connectors = append(st.Connectors, cc)
	}

	// Battery snapshot (separate lock to avoid holding both simultaneously).
	h.mu.RUnlock()
	soc, cur, sessionWh := h.batt.State()
	phase := h.batt.Phase()
	h.mu.RLock()

	st.Battery = batteryInfo{
		CapacityWh: h.batt.CapacityWh,
		SOC:        soc,
		CurrentA:   cur,
		PowerW:     cur * h.batt.VoltageV,
		SessionWh:  sessionWh,
		Phase:      phase,
	}
	return st
}

// Inject handles POST /inject requests from the GUI.
func (h *csHandler) Inject(cs ocpp2.ChargingStation, body []byte) error {
	var req map[string]any
	if err := json.Unmarshal(body, &req); err != nil {
		return fmt.Errorf("inject: %w", err)
	}

	if action, ok := req["action"].(string); ok {
		cid := 1
		if v, ok := req["connector_id"].(float64); ok {
			cid = int(v)
		}
		switch action {
		case "start_session":
			dur := 3600 * time.Second
			if v, ok := req["duration_s"].(float64); ok && v > 0 {
				dur = time.Duration(v) * time.Second
			}
			h.startSession(cs, cid, dur, transactions.TriggerReasonAuthorized, nil)
		case "stop_session":
			h.stopSession(transactions.ReasonLocal, transactions.TriggerReasonStopAuthorized)
		case "set_soc":
			if v, ok := req["soc_pct"].(float64); ok {
				h.batt.mu.Lock()
				h.batt.SOC = math.Min(100, math.Max(0, v))
				h.batt.mu.Unlock()
				log.Printf("evsim: injected SOC=%.1f%%", v)
			}
		case "set_sim_speed":
			if v, ok := req["speed"].(float64); ok && v > 0 {
				h.batt.mu.Lock()
				h.batt.SimSpeed = v
				h.batt.mu.Unlock()
				log.Printf("evsim: sim-speed set to %.1f×", v)
			}
		default:
			return fmt.Errorf("inject: unknown action %q", action)
		}
		return nil
	}

	if statusStr, ok := req["status"].(string); ok {
		cid := 1
		if v, ok := req["connector_id"].(float64); ok {
			cid = int(v)
		}
		sendStatus(cs, h, cid, availability.ConnectorStatus(statusStr))
		return nil
	}

	return fmt.Errorf("inject: request must contain 'status' or 'action' field")
}

// ── OCPP handler implementations ──────────────────────────────────────────────

func (h *csHandler) OnGetBaseReport(req *provisioning.GetBaseReportRequest) (*provisioning.GetBaseReportResponse, error) {
	return &provisioning.GetBaseReportResponse{Status: types.GenericDeviceModelStatusAccepted}, nil
}
func (h *csHandler) OnGetReport(req *provisioning.GetReportRequest) (*provisioning.GetReportResponse, error) {
	return &provisioning.GetReportResponse{Status: types.GenericDeviceModelStatusAccepted}, nil
}
func (h *csHandler) OnGetVariables(req *provisioning.GetVariablesRequest) (*provisioning.GetVariablesResponse, error) {
	// OCPP requires one result per requested variable (finding OCPP-6: an
	// empty response is schema-invalid). The simulator exposes no device
	// model, so every variable is honestly reported as unknown.
	resp := &provisioning.GetVariablesResponse{}
	for _, v := range req.GetVariableData {
		resp.GetVariableResult = append(resp.GetVariableResult, provisioning.GetVariableResult{
			AttributeStatus: provisioning.GetVariableStatusUnknownVariable,
			AttributeType:   v.AttributeType,
			Component:       v.Component,
			Variable:        v.Variable,
		})
	}
	return resp, nil
}
func (h *csHandler) OnReset(req *provisioning.ResetRequest) (*provisioning.ResetResponse, error) {
	log.Printf("evsim: Reset type=%s — accepted, simulating reboot", req.Type)
	// Simulated reboot: end any transaction with ImmediateReset, then replay
	// BootNotification as a freshly booted station would (finding OCPP-2:
	// previously accepted without acting).
	go func() {
		h.stopSession(transactions.ReasonImmediateReset, transactions.TriggerReasonResetCommand)
		time.Sleep(time.Second)
		if _, err := h.cs.BootNotification(provisioning.BootReasonRemoteReset, stationModel, stationVendor); err != nil {
			log.Printf("evsim: post-reset BootNotification: %v", err)
			return
		}
		log.Printf("evsim: post-reset BootNotification sent")
	}()
	return &provisioning.ResetResponse{Status: provisioning.ResetStatusAccepted}, nil
}
func (h *csHandler) OnSetNetworkProfile(req *provisioning.SetNetworkProfileRequest) (*provisioning.SetNetworkProfileResponse, error) {
	return &provisioning.SetNetworkProfileResponse{Status: provisioning.SetNetworkProfileStatusAccepted}, nil
}
func (h *csHandler) OnSetVariables(req *provisioning.SetVariablesRequest) (*provisioning.SetVariablesResponse, error) {
	// One result per variable, mirroring OnGetVariables (finding OCPP-6).
	resp := &provisioning.SetVariablesResponse{}
	for _, v := range req.SetVariableData {
		resp.SetVariableResult = append(resp.SetVariableResult, provisioning.SetVariableResult{
			AttributeStatus: provisioning.SetVariableStatusUnknownVariable,
			AttributeType:   v.AttributeType,
			Component:       v.Component,
			Variable:        v.Variable,
		})
	}
	return resp, nil
}
func (h *csHandler) OnChangeAvailability(req *availability.ChangeAvailabilityRequest) (*availability.ChangeAvailabilityResponse, error) {
	log.Printf("evsim: ChangeAvailability evse=%d op=%s", req.Evse.ID, req.OperationalStatus)
	return &availability.ChangeAvailabilityResponse{Status: availability.ChangeAvailabilityStatusAccepted}, nil
}
func (h *csHandler) OnRequestStartTransaction(req *remotecontrol.RequestStartTransactionRequest) (*remotecontrol.RequestStartTransactionResponse, error) {
	if h.sessionActive() {
		log.Printf("evsim: RequestStartTransaction id=%s — rejected (session already active)", req.IDToken.IdToken)
		return remotecontrol.NewRequestStartTransactionResponse(remotecontrol.RequestStartStopStatusRejected), nil
	}
	connectorID := 1
	if req.EvseID != nil && *req.EvseID > 0 {
		connectorID = *req.EvseID
	}
	remoteStartID := req.RemoteStartID
	log.Printf("evsim: RequestStartTransaction evse=%d id=%s remoteStartId=%d — accepted",
		connectorID, req.IDToken.IdToken, remoteStartID)
	// Accept now, start asynchronously: the Started event must not be sent
	// from inside this handler while the CSMS awaits our response.
	go h.startSession(h.cs, connectorID, h.sessionDuration,
		transactions.TriggerReasonRemoteStart, &remoteStartID)
	return remotecontrol.NewRequestStartTransactionResponse(remotecontrol.RequestStartStopStatusAccepted), nil
}
func (h *csHandler) OnRequestStopTransaction(req *remotecontrol.RequestStopTransactionRequest) (*remotecontrol.RequestStopTransactionResponse, error) {
	h.mu.RLock()
	txID := h.txID
	h.mu.RUnlock()
	if txID == "" || req.TransactionID != txID {
		log.Printf("evsim: RequestStopTransaction tx=%s — rejected (active tx=%q)", req.TransactionID, txID)
		return remotecontrol.NewRequestStopTransactionResponse(remotecontrol.RequestStartStopStatusRejected), nil
	}
	log.Printf("evsim: RequestStopTransaction tx=%s — accepted", req.TransactionID)
	go h.stopSession(transactions.ReasonRemote, transactions.TriggerReasonRemoteStop)
	return remotecontrol.NewRequestStopTransactionResponse(remotecontrol.RequestStartStopStatusAccepted), nil
}
func (h *csHandler) OnTriggerMessage(req *remotecontrol.TriggerMessageRequest) (*remotecontrol.TriggerMessageResponse, error) {
	log.Printf("evsim: TriggerMessage type=%s", req.RequestedMessage)
	resp := remotecontrol.NewTriggerMessageResponse(remotecontrol.TriggerMessageStatusAccepted)
	go func() {
		time.Sleep(200 * time.Millisecond)
		switch req.RequestedMessage {
		case remotecontrol.MessageTriggerStatusNotification:
			h.mu.RLock()
			connectors := make([]connectorInfo, 0, len(h.connectors))
			for _, c := range h.connectors {
				connectors = append(connectors, *c)
			}
			h.mu.RUnlock()
			for _, c := range connectors {
				sendStatus(h.cs, h, c.ID, c.Status)
			}
		case remotecontrol.MessageTriggerHeartbeat:
			if _, err := h.cs.Heartbeat(); err != nil {
				log.Printf("evsim: triggered Heartbeat: %v", err)
			}
		case remotecontrol.MessageTriggerMeterValues:
			soc, cur, energy := h.batt.State()
			// One EV model: during a session only its connector has a live
			// reading; otherwise report all connectors (current is zero
			// when idle, so the readings stay truthful).
			h.mu.RLock()
			var ids []int
			if h.session.Active {
				ids = []int{h.session.ConnectorID}
			} else {
				ids = make([]int, 0, len(h.connectors))
				for id := range h.connectors {
					ids = append(ids, id)
				}
			}
			h.mu.RUnlock()
			for _, id := range ids {
				sendMeterValues(h.cs, h.batt, id, soc, cur, energy)
			}
		}
	}()
	return resp, nil
}
func (h *csHandler) OnUnlockConnector(req *remotecontrol.UnlockConnectorRequest) (*remotecontrol.UnlockConnectorResponse, error) {
	log.Printf("evsim: UnlockConnector evse=%d connector=%d", req.EvseID, req.ConnectorID)
	return remotecontrol.NewUnlockConnectorResponse(remotecontrol.UnlockStatusUnlocked), nil
}
func (h *csHandler) OnSetChargingProfile(req *smartcharging.SetChargingProfileRequest) (*smartcharging.SetChargingProfileResponse, error) {
	p := req.ChargingProfile
	info := &chargingProfileInfo{
		ReceivedAt: time.Now().UTC().Format(time.RFC3339),
		EvseID:     req.EvseID,
		ProfileID:  p.ID,
		Purpose:    string(p.ChargingProfilePurpose),
	}
	if len(p.ChargingSchedule) > 0 && len(p.ChargingSchedule[0].ChargingSchedulePeriod) > 0 {
		info.LimitA = p.ChargingSchedule[0].ChargingSchedulePeriod[0].Limit
	}
	// Feed limit into the battery model so the CC/CV curve uses the new limit.
	h.batt.SetCommandedA(info.LimitA)

	h.mu.Lock()
	h.lastProfile = info
	txActive := h.txID != ""
	h.mu.Unlock()
	log.Printf("evsim: SetChargingProfile evse=%d profile=%d limit=%.1fA",
		req.EvseID, p.ID, info.LimitA)
	// Mid-transaction rate change → TransactionEvent(Updated) so the CSMS
	// sees the new operating point without waiting for the periodic sample.
	if txActive {
		go h.sendTxEvent(transactions.TransactionEventUpdated,
			transactions.TriggerReasonChargingRateChanged, nil, "", time.Time{})
	}
	return &smartcharging.SetChargingProfileResponse{Status: smartcharging.ChargingProfileStatusAccepted}, nil
}
func (h *csHandler) OnGetChargingProfiles(req *smartcharging.GetChargingProfilesRequest) (*smartcharging.GetChargingProfilesResponse, error) {
	return &smartcharging.GetChargingProfilesResponse{Status: smartcharging.GetChargingProfileStatusNoProfiles}, nil
}
func (h *csHandler) OnClearChargingProfile(req *smartcharging.ClearChargingProfileRequest) (*smartcharging.ClearChargingProfileResponse, error) {
	h.mu.Lock()
	h.lastProfile = nil
	h.mu.Unlock()
	h.batt.SetCommandedA(0)
	return &smartcharging.ClearChargingProfileResponse{Status: smartcharging.ClearChargingProfileStatusAccepted}, nil
}
func (h *csHandler) OnGetCompositeSchedule(req *smartcharging.GetCompositeScheduleRequest) (*smartcharging.GetCompositeScheduleResponse, error) {
	return smartcharging.NewGetCompositeScheduleResponse(smartcharging.GetCompositeScheduleStatusRejected, req.EvseID), nil
}
