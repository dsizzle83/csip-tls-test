package main

import (
	"encoding/json"
	"fmt"
	"log"
	"math"
	"sync"
	"time"
)

// ── State tracking ────────────────────────────────────────────────────────────
//
// Everything in this file is protocol-agnostic: it is shared verbatim by both
// the OCPP 2.0.1 and OCPP 1.6 adapters (ocpp201.go / ocpp16.go), which call
// into it from their respective handler wrapper types.

type connectorInfo struct {
	ID         int        `json:"id"`
	Status     connStatus `json:"status"`
	LastUpdate time.Time  `json:"last_update"`
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

// csHandler is the protocol-agnostic simulation core: battery state, session
// lifecycle, fault injectors, and the HTTP control API all live here and are
// identical regardless of which OCPP version proto talks. Only proto (set
// once at startup, before any handler can fire) differs between the two
// protocol modes.
type csHandler struct {
	proto           chargerProto
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
	txID          string // current transaction's display ID (proto-assigned); "" when idle

	sess *sessionHandle // current session — guarded by mu

	faults evFaults // OCPP-layer fault injectors (POST /fault)
}

// sample returns a snapshot of the battery's current physics, ready to hand
// to either protocol adapter — the ONE place the wrong_units math and
// power/SoC read-out live, so neither adapter duplicates it.
func (h *csHandler) sample() meterSample {
	soc, cur, energy := h.batt.State()
	reportedA := cur * h.batt.ReportCurrentMult()
	return meterSample{
		SOC:      soc,
		CurrentA: reportedA,
		PowerW:   reportedA * h.batt.VoltageV,
		EnergyWh: energy,
		VoltageV: h.batt.VoltageV,
	}
}

// chargingLimit is the protocol-neutral form of a received SetChargingProfile
// — both smartcharging.SetChargingProfileRequest shapes (2.0.1 and 1.6) are
// translated into this by their respective handler wrappers before calling
// handleSetChargingProfile.
type chargingLimit struct {
	EvseID    int
	ProfileID int
	Purpose   string
	LimitA    float64
}

// handleSetChargingProfile applies fault-injection semantics (profile_reject
// / apply_next_tx / apply_delayed) then feeds the accepted limit into the
// battery model — the SAME logic for both OCPP versions; only the
// request/response encoding differs, in each protocol's own handler wrapper.
// Returns whether the profile should be reported Accepted (false = Rejected).
func (h *csHandler) handleSetChargingProfile(lim chargingLimit) bool {
	info := &chargingProfileInfo{
		ReceivedAt: time.Now().UTC().Format(time.RFC3339),
		EvseID:     lim.EvseID,
		ProfileID:  lim.ProfileID,
		Purpose:    lim.Purpose,
		LimitA:     lim.LimitA,
	}

	reject, applyNext, _ := h.faults.get()
	if reject {
		// profile_reject fault: decline smart charging. The limit is NOT applied;
		// the EV keeps drawing at its current rate. The hub must treat the Rejected
		// status as a failure and react — never assume the load dropped.
		h.mu.Lock()
		h.lastProfile = info
		h.mu.Unlock()
		log.Printf("evsim: SetChargingProfile evse=%d profile=%d REJECTED (fault profile_reject)", lim.EvseID, lim.ProfileID)
		return false
	}
	delayS := h.faults.applyDelay()
	switch {
	case applyNext:
		// apply_next_tx fault: ACCEPT the profile but do not apply it to the live
		// session — accept-but-ignore. The CSMS sees success while the EV keeps its
		// prior draw; only the meter reveals the rate never changed.
		log.Printf("evsim: SetChargingProfile evse=%d profile=%d ACCEPTED but not applied to live session (fault apply_next_tx)", lim.EvseID, lim.ProfileID)
	case delayS > 0:
		// apply_delayed fault: ACCEPT now but apply the new limit only after delayS —
		// delayed-obey. The CSMS sees success immediately while the EV keeps its prior
		// draw for the delay window; the hub must verify the rate against measurement.
		limitA := lim.LimitA
		go func() {
			time.Sleep(time.Duration(delayS) * time.Second)
			h.batt.SetCommandedA(limitA)
			log.Printf("evsim: apply_delayed: profile limit %.1fA now in effect (after %ds)", limitA, delayS)
		}()
		log.Printf("evsim: SetChargingProfile evse=%d profile=%d ACCEPTED, apply deferred %ds (fault apply_delayed)", lim.EvseID, lim.ProfileID, delayS)
	default:
		// Feed limit into the battery model so the CC/CV curve uses the new limit.
		h.batt.SetCommandedA(lim.LimitA)
	}

	h.mu.Lock()
	h.lastProfile = info
	h.mu.Unlock()
	log.Printf("evsim: SetChargingProfile evse=%d profile=%d limit=%.1fA", lim.EvseID, lim.ProfileID, lim.LimitA)
	// Mid-transaction rate change → an out-of-band meter report so the CSMS
	// sees the new operating point without waiting for the periodic sample.
	if h.sessionActive() {
		go h.proto.TxUpdate(trigChargingRateChanged, h.sample())
	}
	return true
}

// handleClearChargingProfile clears the limit back to whatever "unrestricted"
// means for this sim: SetCommandedA(0), matching the pre-existing 2.0.1
// behaviour exactly (a cleared TxDefaultProfile means no active limit, and
// this sim treats "no limit" as "not charging" — see evBattery.Tick).
func (h *csHandler) handleClearChargingProfile() {
	h.mu.Lock()
	h.lastProfile = nil
	h.mu.Unlock()
	h.batt.SetCommandedA(0)
}

// simulateReset stops any running session with an ImmediateReset stop cause,
// then replays BootNotification as a freshly booted station would — shared by
// both protocols' Reset handler (finding OCPP-2: previously accepted without
// acting).
func (h *csHandler) simulateReset() {
	go func() {
		h.stopSession(stopImmediateReset, trigResetCommand)
		time.Sleep(time.Second)
		if _, err := h.proto.Boot(); err != nil {
			log.Printf("evsim: post-reset BootNotification: %v", err)
			return
		}
		log.Printf("evsim: post-reset BootNotification sent")
	}()
}

// sendStatus updates local connector bookkeeping and notifies the CSMS —
// shared by both protocols' Status wire call.
func (h *csHandler) sendStatus(connectorID int, status connStatus) {
	h.setConnector(connectorID, status)
	if err := h.proto.Status(connectorID, status); err != nil {
		log.Printf("evsim: StatusNotification connector=%d: %v", connectorID, err)
		return
	}
	log.Printf("evsim: StatusNotification connector=%d status=%s", connectorID, status)
}

// triggerStatusNotifications resends StatusNotification for every known
// connector — shared by both protocols' OnTriggerMessage(StatusNotification).
func (h *csHandler) triggerStatusNotifications() {
	h.mu.RLock()
	connectors := make([]connectorInfo, 0, len(h.connectors))
	for _, c := range h.connectors {
		connectors = append(connectors, *c)
	}
	h.mu.RUnlock()
	for _, c := range connectors {
		h.sendStatus(c.ID, c.Status)
	}
}

// triggerMeterValues re-sends a meter reading outside any transaction
// bookkeeping — shared by both protocols' OnTriggerMessage(MeterValues).
func (h *csHandler) triggerMeterValues() {
	m := h.sample()
	h.mu.RLock()
	var ids []int
	if h.session.Active {
		// One EV model: during a session only its connector has a live reading.
		ids = []int{h.session.ConnectorID}
	} else {
		ids = make([]int, 0, len(h.connectors))
		for id := range h.connectors {
			ids = append(ids, id)
		}
	}
	h.mu.RUnlock()
	for _, id := range ids {
		h.proto.MeterValuesIdle(id, m)
	}
}

// triggerHeartbeat re-sends a Heartbeat — shared by both protocols'
// OnTriggerMessage(Heartbeat).
func (h *csHandler) triggerHeartbeat() {
	if err := h.proto.Heartbeat(); err != nil {
		log.Printf("evsim: triggered Heartbeat: %v", err)
	}
}

// triggerBoot re-sends BootNotification — used by 1.6's OnTriggerMessage
// (BootNotification is part of 1.6's TriggerMessage vocabulary; 2.0.1's
// RemoteTrigger profile does not currently wire this case).
func (h *csHandler) triggerBoot() {
	if _, err := h.proto.Boot(); err != nil {
		log.Printf("evsim: triggered BootNotification: %v", err)
	}
}

// ── Fault injection (OCPP-layer) ──────────────────────────────────────────────

// evFaults holds the OCPP-layer fault injectors for evsim — the CSMS/charger
// boundary equivalent of the Modbus sims' faultController. All fields guarded by
// mu. min_current_floor lives on the evBattery (it shapes the charge current);
// these three gate the OCPP message behaviour. The zero value is unarmed.
type evFaults struct {
	mu            sync.Mutex
	rejectProfile bool // profile_reject: SetChargingProfile returns Rejected, limit not applied
	applyNextTx   bool // apply_next_tx: ACCEPT the profile but don't apply it to the live session
	stopMeter     bool // stop_metervalues: keep charging, stop sending MeterValues / Updated
	applyDelayedS int  // apply_delayed: ACCEPT the profile but apply the new limit only after this many seconds
}

func (f *evFaults) get() (reject, applyNext, stopMeter bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.rejectProfile, f.applyNextTx, f.stopMeter
}

func (f *evFaults) applyDelay() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.applyDelayedS
}

type evFaultSpec struct {
	Kind   string  `json:"kind"`
	AmpsA  float64 `json:"amps_a,omitempty"`  // min_current_floor: the floor in amps (default 6)
	DelayS int     `json:"delay_s,omitempty"` // apply_delayed: seconds before the accepted limit takes effect (default 25)
	Mult   float64 `json:"mult,omitempty"`    // wrong_units: reported-current multiplier (default 1000)
	Clear  bool    `json:"clear,omitempty"`
}

// ApplyFault arms or clears an OCPP-layer fault injector, wired to simapi
// POST /fault. Supported kinds: profile_reject, apply_next_tx,
// min_current_floor (amps_a, default 6 A), stop_metervalues, apply_delayed
// (delay_s, default 25), wrong_units (mult, default 1000), out_of_order_txevent
// (2.0.1 lifecycle: non-monotonic seqNo), boot_mid_tx (one-shot: BootNotification
// during a live transaction). Each ACKs the OCPP message at the protocol level
// while the charger misbehaves — the hub must not assume success.
func (h *csHandler) ApplyFault(body []byte) error {
	var spec evFaultSpec
	if err := json.Unmarshal(body, &spec); err != nil {
		return fmt.Errorf("fault: %w", err)
	}
	switch spec.Kind {
	case "profile_reject":
		h.faults.mu.Lock()
		h.faults.rejectProfile = !spec.Clear
		h.faults.mu.Unlock()
		log.Printf("[fault] profile_reject: armed=%v", !spec.Clear)
	case "apply_next_tx":
		h.faults.mu.Lock()
		h.faults.applyNextTx = !spec.Clear
		h.faults.mu.Unlock()
		log.Printf("[fault] apply_next_tx: armed=%v", !spec.Clear)
	case "stop_metervalues":
		h.faults.mu.Lock()
		h.faults.stopMeter = !spec.Clear
		h.faults.mu.Unlock()
		log.Printf("[fault] stop_metervalues: armed=%v", !spec.Clear)
	case "apply_delayed":
		d := 0
		if !spec.Clear {
			d = spec.DelayS
			if d <= 0 {
				d = 25
			}
		}
		h.faults.mu.Lock()
		h.faults.applyDelayedS = d
		h.faults.mu.Unlock()
		log.Printf("[fault] apply_delayed: delay_s=%d", d)
	case "wrong_units":
		if spec.Clear {
			h.batt.SetReportCurrentMult(1)
		} else {
			m := spec.Mult
			if m <= 0 {
				m = 1000
			}
			h.batt.SetReportCurrentMult(m)
		}
		log.Printf("[fault] wrong_units: armed=%v", !spec.Clear)
	case "min_current_floor":
		floor := spec.AmpsA
		if spec.Clear {
			floor = 0
		} else if floor <= 0 {
			floor = 6 // OCPP minimum charge current default
		}
		h.batt.SetMinFloorA(floor)
		log.Printf("[fault] min_current_floor: floor=%.1fA", floor)
	case "out_of_order_txevent":
		// Emit TransactionEvents with a non-monotonic seqNo. Only 2.0.1 has
		// TransactionEvents; the reorder lives on ocpp201Proto and is reached via
		// an optional-interface assertion so 1.6 (no seqNo) is a no-op. The hub
		// must sequence events by seqNo, not arrival order (audit P2-5:
		// OnTransactionEvent reads SequenceNo but does not validate it today).
		if p, ok := h.proto.(interface{ SetTxReorder(bool) }); ok {
			p.SetTxReorder(!spec.Clear)
			log.Printf("[fault] out_of_order_txevent: armed=%v", !spec.Clear)
		} else {
			log.Printf("[fault] out_of_order_txevent: no-op (protocol has no TransactionEvent seqNo)")
		}
	case "boot_mid_tx":
		// One-shot: send a BootNotification while a transaction is open (a real
		// charger power-cycling or CSMS-reconnecting mid-session). A clear is a
		// no-op. The hub's OnBootNotification must handle a boot that arrives with
		// a live session — void/re-sync it or tolerate it — never wedge or go
		// blind to a still-charging car (audit P2-5: OnBootNotification does not
		// void an active tx today).
		if !spec.Clear {
			if h.sessionActive() {
				go func() {
					if _, err := h.proto.Boot(); err != nil {
						log.Printf("[fault] boot_mid_tx: BootNotification error: %v", err)
						return
					}
					log.Printf("[fault] boot_mid_tx: BootNotification sent during an active transaction")
				}()
			} else {
				log.Printf("[fault] boot_mid_tx: no active session — nothing to boot into")
			}
		}
	default:
		return fmt.Errorf("fault: unsupported kind %q for evsim", spec.Kind)
	}
	return nil
}

func (h *csHandler) setLastHeartbeat(t time.Time) { h.mu.Lock(); h.lastHeartbeat = t; h.mu.Unlock() }

func (h *csHandler) setConnector(id int, status connStatus) {
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

func (h *csHandler) setTxID(id string) {
	h.mu.Lock()
	h.txID = id
	h.mu.Unlock()
}

func (h *csHandler) currentTxID() string {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.txID
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
	st.CSMS.Connected = h.proto.IsConnected()
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
func (h *csHandler) Inject(body []byte) error {
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
			h.startSession(cid, dur, trigAuthorized, txStartOpts{})
		case "stop_session":
			h.stopSession(stopLocal, trigStopAuthorized)
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
		h.sendStatus(cid, connStatus(statusStr))
		return nil
	}

	return fmt.Errorf("inject: request must contain 'status' or 'action' field")
}
