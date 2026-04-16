// evsim is an OCPP 2.0.1 charging station client simulator with a realistic
// EV battery model.  The battery follows a CC/CV charging curve: constant
// current in the bulk phase (SOC < cvStartSOC) and a linear taper in the
// absorption phase (SOC ≥ cvStartSOC).  MeterValues are sent to the CSMS
// periodically so the orchestrator receives actual current, not commanded.
//
// Usage:
//
//	evsim -csms ws://192.168.10.1:8887/ocpp [-id evse-001] [-connectors 1]
//	       [-battery-kwh 60] [-battery-soc 20] [-sim-speed 1.0]
//	       [-session-interval 180] [-session-duration 3600]
//	       [-meter-interval 10] [-voltage 230] [-max-current 32]
//	       [-api-port 6024]
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
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"math"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	ocpp2 "github.com/lorenzodonini/ocpp-go/ocpp2.0.1"
	"github.com/lorenzodonini/ocpp-go/ocpp2.0.1/availability"
	"github.com/lorenzodonini/ocpp-go/ocpp2.0.1/provisioning"
	"github.com/lorenzodonini/ocpp-go/ocpp2.0.1/remotecontrol"
	"github.com/lorenzodonini/ocpp-go/ocpp2.0.1/smartcharging"
	"github.com/lorenzodonini/ocpp-go/ocpp2.0.1/types"

	"csip-tls-test/internal/simapi"
)

func main() {
	csmsURL         := flag.String("csms", "ws://192.168.10.1:8887/ocpp", "CSMS WebSocket base URL")
	stationID       := flag.String("id", "evse-001", "Charging station identifier")
	numConnectors   := flag.Int("connectors", 1, "Number of connectors")
	sessionInterval := flag.Int("session-interval", 180, "Seconds between simulated sessions")
	sessionDuration := flag.Int("session-duration", 3600, "Max session duration (seconds); ends early if battery full")
	apiPort         := flag.Int("api-port", 6024, "HTTP API port (0 to disable)")
	battKwh         := flag.Float64("battery-kwh", 60.0, "EV battery capacity (kWh)")
	battSOC         := flag.Float64("battery-soc", 20.0, "Initial battery state of charge (%)")
	simSpeed        := flag.Float64("sim-speed", 1.0, "Simulation time multiplier (1=real-time, 60=60× faster)")
	meterIntervalS  := flag.Int("meter-interval", 10, "MeterValues send interval (real seconds)")
	voltageV        := flag.Float64("voltage", 230.0, "AC supply voltage (V)")
	maxCurrentA     := flag.Float64("max-current", 32.0, "EVSE hardware max current (A)")
	flag.Parse()

	log.Printf("evsim: station=%s csms=%s battery=%.0fkWh soc=%.0f%% speed=%.1fx",
		*stationID, *csmsURL, *battKwh, *battSOC, *simSpeed)

	cs := ocpp2.NewChargingStation(*stationID, nil, nil)

	batt := newEVBattery(*battKwh*1000, *battSOC, *voltageV, *maxCurrentA, *simSpeed)

	h := &csHandler{
		cs:            cs,
		stationID:     *stationID,
		csmsURL:       *csmsURL,
		batt:          batt,
		meterInterval: time.Duration(*meterIntervalS) * time.Second,
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
	h.setConnected(true)
	log.Printf("evsim: connected")

	bootResp, err := cs.BootNotification(
		provisioning.BootReasonPowerUp, "CSIP-EV-Simulator", "GreenGrid-Labs",
	)
	if err != nil {
		log.Fatalf("evsim: BootNotification: %v", err)
	}
	log.Printf("evsim: BootNotification status=%s interval=%ds", bootResp.Status, bootResp.Interval)

	for i := 1; i <= *numConnectors; i++ {
		sendStatus(cs, h, i, availability.ConnectorStatusAvailable)
	}

	if *apiPort != 0 {
		simapi.New(
			fmt.Sprintf(":%d", *apiPort),
			func() any { return h.Snapshot() },
			func(body []byte) error { return h.Inject(cs, body) },
			nil,
			nil,
		)
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
			go simulateSession(cs, h, 1, time.Duration(*sessionDuration)*time.Second)
		}
	}
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

func simulateSession(cs ocpp2.ChargingStation, h *csHandler, connectorID int, maxDuration time.Duration) {
	log.Printf("evsim: connector %d — session starting (max %v, SOC=%.1f%%)",
		connectorID, maxDuration, func() float64 { soc, _, _ := h.batt.State(); return soc }())
	h.batt.ResetSession()
	h.setSessionActive(connectorID, true)
	sendStatus(cs, h, connectorID, availability.ConnectorStatusOccupied)

	runChargingLoop(cs, h, connectorID, maxDuration)

	// Final reading before closing.
	soc, cur, energy := h.batt.State()
	sendMeterValues(cs, h.batt, connectorID, soc, cur, energy)
	sendStatus(cs, h, connectorID, availability.ConnectorStatusAvailable)
	h.setSessionActive(connectorID, false)

	soc, _, _ = h.batt.State()
	log.Printf("evsim: connector %d — session complete, SOC=%.1f%%", connectorID, soc)
}

// runChargingLoop drives the battery simulation and periodic MeterValues until
// maxDuration elapses or the battery reaches 100% SOC.
func runChargingLoop(cs ocpp2.ChargingStation, h *csHandler, connectorID int, maxDuration time.Duration) {
	simTicker := time.NewTicker(time.Second)
	defer simTicker.Stop()
	meterTicker := time.NewTicker(h.meterInterval)
	defer meterTicker.Stop()
	deadline := time.NewTimer(maxDuration)
	defer deadline.Stop()

	for {
		select {
		case <-simTicker.C:
			_, full := h.batt.Tick(time.Second)
			if full {
				log.Printf("evsim: connector %d — battery full (100%% SOC)", connectorID)
				return
			}
		case <-meterTicker.C:
			soc, cur, energy := h.batt.State()
			sendMeterValues(cs, h.batt, connectorID, soc, cur, energy)
		case <-deadline.C:
			return
		}
	}
}

// sendMeterValues sends an OCPP MeterValues message with the five key measurands:
// Current.Import, Power.Active.Import, Energy.Active.Import.Register, SoC, Voltage.
func sendMeterValues(cs ocpp2.ChargingStation, batt *evBattery, connectorID int, soc, currentA, energyWh float64) {
	now := types.NewDateTime(time.Now())
	powerW := currentA * batt.VoltageV

	mv := types.MeterValue{
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

	if _, err := cs.MeterValues(connectorID, []types.MeterValue{mv}); err != nil {
		log.Printf("evsim: MeterValues connector=%d: %v", connectorID, err)
		return
	}
	log.Printf("evsim: MeterValues connector=%d soc=%.1f%% current=%.1fA power=%.0fW energy=%.0fWh phase=%s",
		connectorID, soc, currentA, powerW, energyWh, batt.Phase())
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
	CurrentA   float64 `json:"current_A"`   // actual (CC/CV model), not commanded
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
	Active      bool   `json:"active"`
	ConnectorID int    `json:"connector_id,omitempty"`
	StartedAt   string `json:"started_at,omitempty"`
}

type csHandler struct {
	cs        ocpp2.ChargingStation
	stationID string
	csmsURL   string
	batt      *evBattery
	meterInterval time.Duration

	mu            sync.RWMutex
	connected     bool
	connectors    map[int]*connectorInfo
	session       sessionInfo
	lastHeartbeat time.Time
	lastProfile   *chargingProfileInfo
}

func (h *csHandler) setConnected(v bool)            { h.mu.Lock(); h.connected = v; h.mu.Unlock() }
func (h *csHandler) setLastHeartbeat(t time.Time)   { h.mu.Lock(); h.lastHeartbeat = t; h.mu.Unlock() }

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
	st.CSMS.Connected = h.connected
	st.Session = h.session
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
			go simulateSession(cs, h, cid, dur)
		case "stop_session":
			sendStatus(cs, h, cid, availability.ConnectorStatusAvailable)
			h.setSessionActive(cid, false)
		case "set_soc":
			if v, ok := req["soc_pct"].(float64); ok {
				h.batt.mu.Lock()
				h.batt.SOC = math.Min(100, math.Max(0, v))
				h.batt.mu.Unlock()
				log.Printf("evsim: injected SOC=%.1f%%", v)
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
	return &provisioning.GetVariablesResponse{}, nil
}
func (h *csHandler) OnReset(req *provisioning.ResetRequest) (*provisioning.ResetResponse, error) {
	log.Printf("evsim: Reset type=%s — accepted", req.Type)
	return &provisioning.ResetResponse{Status: provisioning.ResetStatusAccepted}, nil
}
func (h *csHandler) OnSetNetworkProfile(req *provisioning.SetNetworkProfileRequest) (*provisioning.SetNetworkProfileResponse, error) {
	return &provisioning.SetNetworkProfileResponse{Status: provisioning.SetNetworkProfileStatusAccepted}, nil
}
func (h *csHandler) OnSetVariables(req *provisioning.SetVariablesRequest) (*provisioning.SetVariablesResponse, error) {
	return &provisioning.SetVariablesResponse{}, nil
}
func (h *csHandler) OnChangeAvailability(req *availability.ChangeAvailabilityRequest) (*availability.ChangeAvailabilityResponse, error) {
	log.Printf("evsim: ChangeAvailability evse=%d op=%s", req.Evse.ID, req.OperationalStatus)
	return &availability.ChangeAvailabilityResponse{Status: availability.ChangeAvailabilityStatusAccepted}, nil
}
func (h *csHandler) OnRequestStartTransaction(req *remotecontrol.RequestStartTransactionRequest) (*remotecontrol.RequestStartTransactionResponse, error) {
	log.Printf("evsim: RequestStartTransaction evse=%v id=%s", req.EvseID, req.IDToken.IdToken)
	return remotecontrol.NewRequestStartTransactionResponse(remotecontrol.RequestStartStopStatusAccepted), nil
}
func (h *csHandler) OnRequestStopTransaction(req *remotecontrol.RequestStopTransactionRequest) (*remotecontrol.RequestStopTransactionResponse, error) {
	log.Printf("evsim: RequestStopTransaction tx=%s", req.TransactionID)
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
			for id := range h.connectors {
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
	h.mu.Unlock()
	log.Printf("evsim: SetChargingProfile evse=%d profile=%d limit=%.1fA",
		req.EvseID, p.ID, info.LimitA)
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
