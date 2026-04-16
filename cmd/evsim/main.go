// evsim is an OCPP 2.0.1 charging station client simulator with a built-in
// HTTP API for GUI inspection and test injection.
//
// Usage:
//
//	evsim -csms ws://192.168.10.1:8887/ocpp [-id evse-001] [-connectors 1]
//	       [-session-interval 180] [-session-duration 120] [-api-port 6024]
//
// API (default :6024):
//
//	GET  /state    — JSON snapshot: connection, connectors, session, last profile
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
	sessionDuration := flag.Int("session-duration", 120, "Seconds per simulated session")
	apiPort         := flag.Int("api-port", 6024, "HTTP API port (0 to disable)")
	flag.Parse()

	log.Printf("evsim: station=%s csms=%s connectors=%d", *stationID, *csmsURL, *numConnectors)

	cs := ocpp2.NewChargingStation(*stationID, nil, nil)

	h := &csHandler{
		cs:        cs,
		stationID: *stationID,
		csmsURL:   *csmsURL,
	}
	// Initialise connector states.
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

	// BootNotification
	bootResp, err := cs.BootNotification(
		provisioning.BootReasonPowerUp, "CSIP-EV-Simulator", "GreenGrid-Labs",
	)
	if err != nil {
		log.Fatalf("evsim: BootNotification: %v", err)
	}
	log.Printf("evsim: BootNotification status=%s interval=%ds", bootResp.Status, bootResp.Interval)

	// Initial StatusNotification (Available) for each connector.
	for i := 1; i <= *numConnectors; i++ {
		sendStatus(cs, h, i, availability.ConnectorStatusAvailable)
	}

	// API server
	if *apiPort != 0 {
		simapi.New(
			fmt.Sprintf(":%d", *apiPort),
			func() any { return h.Snapshot() },
			func(body []byte) error { return h.Inject(cs, body) },
			nil, // no register dump for OCPP
			nil, // no animation control for OCPP
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

func simulateSession(cs ocpp2.ChargingStation, h *csHandler, connectorID int, duration time.Duration) {
	log.Printf("evsim: connector %d — session starting (%v)", connectorID, duration)
	h.setSessionActive(connectorID, true)
	sendStatus(cs, h, connectorID, availability.ConnectorStatusOccupied)
	time.Sleep(duration)
	sendStatus(cs, h, connectorID, availability.ConnectorStatusAvailable)
	h.setSessionActive(connectorID, false)
	log.Printf("evsim: connector %d — session complete", connectorID)
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

// connectorInfo tracks one connector's status.
type connectorInfo struct {
	ID         int                          `json:"id"`
	Status     availability.ConnectorStatus `json:"status"`
	LastUpdate time.Time                    `json:"last_update"`
}

// chargingProfileInfo records the last SetChargingProfile received from the CSMS.
type chargingProfileInfo struct {
	ReceivedAt string  `json:"received_at"`
	EvseID     int     `json:"evse_id"`
	ProfileID  int     `json:"profile_id"`
	Purpose    string  `json:"purpose"`
	LimitA     float64 `json:"limit_A"` // first period limit in amps (if rate unit = A)
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
	Connectors    []connectorInfo     `json:"connectors"`
	Session       sessionInfo         `json:"session"`
	LastHeartbeat string              `json:"last_heartbeat,omitempty"`
	LastProfile   *chargingProfileInfo `json:"last_charging_profile,omitempty"`
}

type sessionInfo struct {
	Active      bool   `json:"active"`
	ConnectorID int    `json:"connector_id,omitempty"`
	StartedAt   string `json:"started_at,omitempty"`
}

// csHandler implements all CSMS→station handler interfaces and tracks state.
type csHandler struct {
	cs        ocpp2.ChargingStation
	stationID string
	csmsURL   string

	mu            sync.RWMutex
	connected     bool
	connectors    map[int]*connectorInfo
	session       sessionInfo
	lastHeartbeat time.Time
	lastProfile   *chargingProfileInfo
}

func (h *csHandler) setConnected(v bool)       { h.mu.Lock(); h.connected = v; h.mu.Unlock() }
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

// Snapshot returns a thread-safe copy of current state.
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
	return st
}

// Inject handles POST /inject requests from the GUI.
// Supported actions:
//
//	{"connector_id":1, "status":"Faulted"}         — force a connector status
//	{"action":"start_session", "connector_id":1}   — begin a simulated session
//	{"action":"stop_session",  "connector_id":1}   — end a simulated session
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
			go simulateSession(cs, h, cid, 60*time.Second)
		case "stop_session":
			sendStatus(cs, h, cid, availability.ConnectorStatusAvailable)
			h.setSessionActive(cid, false)
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
	// Extract the first period's limit if the schedule is in amps.
	if len(p.ChargingSchedule) > 0 && len(p.ChargingSchedule[0].ChargingSchedulePeriod) > 0 {
		info.LimitA = p.ChargingSchedule[0].ChargingSchedulePeriod[0].Limit
	}
	h.mu.Lock()
	h.lastProfile = info
	h.mu.Unlock()
	log.Printf("evsim: SetChargingProfile evse=%d profile=%d purpose=%s limit=%.1fA",
		req.EvseID, p.ID, p.ChargingProfilePurpose, info.LimitA)
	return &smartcharging.SetChargingProfileResponse{Status: smartcharging.ChargingProfileStatusAccepted}, nil
}
func (h *csHandler) OnGetChargingProfiles(req *smartcharging.GetChargingProfilesRequest) (*smartcharging.GetChargingProfilesResponse, error) {
	return &smartcharging.GetChargingProfilesResponse{Status: smartcharging.GetChargingProfileStatusNoProfiles}, nil
}
func (h *csHandler) OnClearChargingProfile(req *smartcharging.ClearChargingProfileRequest) (*smartcharging.ClearChargingProfileResponse, error) {
	h.mu.Lock()
	h.lastProfile = nil
	h.mu.Unlock()
	return &smartcharging.ClearChargingProfileResponse{Status: smartcharging.ClearChargingProfileStatusAccepted}, nil
}
func (h *csHandler) OnGetCompositeSchedule(req *smartcharging.GetCompositeScheduleRequest) (*smartcharging.GetCompositeScheduleResponse, error) {
	return smartcharging.NewGetCompositeScheduleResponse(smartcharging.GetCompositeScheduleStatusRejected, req.EvseID), nil
}
