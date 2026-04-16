package adapters

import (
	"fmt"
	"log"
	"math"
	"sync"
	"time"

	ocpp2 "github.com/lorenzodonini/ocpp-go/ocpp2.0.1"
	"github.com/lorenzodonini/ocpp-go/ocpp2.0.1/availability"
	"github.com/lorenzodonini/ocpp-go/ocpp2.0.1/meter"
	"github.com/lorenzodonini/ocpp-go/ocpp2.0.1/remotecontrol"
	"github.com/lorenzodonini/ocpp-go/ocpp2.0.1/smartcharging"
	"github.com/lorenzodonini/ocpp-go/ocpp2.0.1/types"

	"csip-tls-test/internal/orchestrator"
)

// ConnectorStatus mirrors the OCPP 2.0.1 ConnectorStatusEnumType values.
type ConnectorStatus string

const (
	StatusAvailable   ConnectorStatus = "Available"
	StatusOccupied    ConnectorStatus = "Occupied"
	StatusFaulted     ConnectorStatus = "Faulted"
	StatusUnavailable ConnectorStatus = "Unavailable"
)

// connectorState tracks one connector on a charging station.
type connectorState struct {
	connectorID int
	status      ConnectorStatus
	updatedAt   time.Time
}

// stationState tracks one OCPP charging station.
type stationState struct {
	id          string
	connected   bool
	connectedAt time.Time
	// connectors keyed by connector ID (1-based).
	connectors map[int]*connectorState
	// currentA is the measured charging current from MeterValues (A).
	// Updated from Current.Import; initially 0.
	currentA float64
	// maxCurrentA is the hardware limit.
	maxCurrentA float64
	// voltageV is the supply voltage; default 230 V.
	voltageV float64
	// soc is the EV battery state of charge (%) from MeterValues SoC measurand.
	// math.NaN() until first MeterValues received.
	soc float64
	// energyWh is the cumulative session energy (Wh) from MeterValues.
	energyWh float64
}

// OCPPStateTracker maintains a real-time view of connected OCPP stations
// and implements orchestrator.EVSEActuator to apply current limits.
//
// Usage:
//
//	tracker := adapters.NewOCPPStateTracker(ocppSrv.CSMS())
//	tracker.SetStationConfig("cs-001", 32.0, 230.0)
//	engine.RegisterEVSEActuator("cs-001", tracker)
type OCPPStateTracker struct {
	csms ocpp2.CSMS

	mu       sync.RWMutex
	stations map[string]*stationState
}

// NewOCPPStateTracker creates a tracker and wires connection/availability
// callbacks on csms.
func NewOCPPStateTracker(csms ocpp2.CSMS) *OCPPStateTracker {
	t := &OCPPStateTracker{
		csms:     csms,
		stations: make(map[string]*stationState),
	}

	csms.SetNewChargingStationHandler(func(cs ocpp2.ChargingStationConnection) {
		t.mu.Lock()
		if _, ok := t.stations[cs.ID()]; !ok {
			t.stations[cs.ID()] = &stationState{
				id:          cs.ID(),
				connectors:  make(map[int]*connectorState),
				maxCurrentA: 32.0,
				voltageV:    230.0,
				soc:         math.NaN(),
			}
		}
		st := t.stations[cs.ID()]
		st.connected = true
		st.connectedAt = time.Now()
		t.mu.Unlock()
		log.Printf("[ocpp-tracker] connected: %s", cs.ID())

		// Request current connector status. Some EVSEs only send
		// StatusNotification on state change, so a freshly-connected station
		// that is already occupied would never push its state without this.
		go t.requestStatusNotification(cs.ID())
	})

	csms.SetChargingStationDisconnectedHandler(func(cs ocpp2.ChargingStationConnection) {
		t.mu.Lock()
		if s, ok := t.stations[cs.ID()]; ok {
			s.connected = false
		}
		t.mu.Unlock()
		log.Printf("[ocpp-tracker] disconnected: %s", cs.ID())
	})

	csms.SetAvailabilityHandler(&availabilityForwarder{tracker: t})
	csms.SetMeterHandler(&meteringForwarder{tracker: t})
	return t
}

// SetStationConfig sets the hardware limits for a station before it connects.
func (t *OCPPStateTracker) SetStationConfig(stationID string, maxCurrentA, voltageV float64) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if _, ok := t.stations[stationID]; !ok {
		t.stations[stationID] = &stationState{
			id:         stationID,
			connectors: make(map[int]*connectorState),
		}
	}
	s := t.stations[stationID]
	s.maxCurrentA = maxCurrentA
	s.voltageV = voltageV
}

// EVSEStates returns the current state of all tracked connectors.
func (t *OCPPStateTracker) EVSEStates() []orchestrator.EVSEState {
	t.mu.RLock()
	defer t.mu.RUnlock()

	var out []orchestrator.EVSEState
	for _, s := range t.stations {
		if len(s.connectors) == 0 {
			out = append(out, orchestrator.EVSEState{
				StationID:   s.id,
				ConnectorID: 0,
				Connected:   s.connected,
				MaxCurrentA: s.maxCurrentA,
				VoltageV:    s.voltageV,
				Status:      string(StatusAvailable),
				SOC:         s.soc,
			})
			continue
		}
		for _, c := range s.connectors {
			sessionActive := c.status == StatusOccupied
			powerW := 0.0
			if sessionActive {
				powerW = s.currentA * s.voltageV
			}
			out = append(out, orchestrator.EVSEState{
				StationID:     s.id,
				ConnectorID:   c.connectorID,
				Connected:     s.connected,
				SessionActive: sessionActive,
				CurrentA:      s.currentA,
				MaxCurrentA:   s.maxCurrentA,
				VoltageV:      s.voltageV,
				PowerW:        powerW,
				Status:        string(c.status),
				SOC:           s.soc,
				EnergyWh:      s.energyWh,
			})
		}
	}
	return out
}

// ApplyEVSECommand implements orchestrator.EVSEActuator.
// It sends a SetChargingProfile request to the target station.
func (t *OCPPStateTracker) ApplyEVSECommand(cmd orchestrator.EVSECommand) error {
	t.mu.RLock()
	s, ok := t.stations[cmd.StationID]
	connected := ok && s.connected
	t.mu.RUnlock()

	if !connected {
		return fmt.Errorf("ocpp-tracker: station %q not connected", cmd.StationID)
	}

	evseID := cmd.ConnectorID
	if evseID == 0 {
		evseID = 1
	}

	limit := cmd.MaxCurrentA
	period := types.NewChargingSchedulePeriod(0, limit)
	schedule := types.NewChargingSchedule(1, types.ChargingRateUnitAmperes, period)
	profile := types.NewChargingProfile(
		1,
		0,
		types.ChargingProfilePurposeTxDefaultProfile,
		types.ChargingProfileKindAbsolute,
		[]types.ChargingSchedule{*schedule},
	)

	errCh := make(chan error, 1)
	callErr := t.csms.SetChargingProfile(
		cmd.StationID,
		func(resp *smartcharging.SetChargingProfileResponse, err error) {
			if err != nil {
				errCh <- err
				return
			}
			errCh <- nil
		},
		evseID,
		profile,
	)
	if callErr != nil {
		return fmt.Errorf("ocpp-tracker: send SetChargingProfile: %w", callErr)
	}

	select {
	case err := <-errCh:
		if err == nil {
			// Update tracked current so EVSEStates() reflects the commanded limit.
			t.mu.Lock()
			if s, ok := t.stations[cmd.StationID]; ok {
				s.currentA = cmd.MaxCurrentA
			}
			t.mu.Unlock()
		}
		return err
	case <-time.After(10 * time.Second):
		return fmt.Errorf("ocpp-tracker: SetChargingProfile timeout for %s", cmd.StationID)
	}
}

// ── Availability handler ──────────────────────────────────────────────────────

type availabilityForwarder struct {
	tracker *OCPPStateTracker
}

// requestStatusNotification asks the station to send a StatusNotification for
// each of its connectors. Called in a goroutine on connect so that stations
// which only send StatusNotification on state change still report their initial
// state to the CSMS (OCPP 2.0.1 §H.2 recommendation).
func (t *OCPPStateTracker) requestStatusNotification(stationID string) {
	// Brief settle delay — the OCPP BootNotification/registration exchange may
	// still be in flight immediately after the WS connect callback fires.
	time.Sleep(500 * time.Millisecond)

	err := t.csms.TriggerMessage(
		stationID,
		func(resp *remotecontrol.TriggerMessageResponse, err error) {
			if err != nil {
				log.Printf("[ocpp-tracker] TriggerMessage(StatusNotification) to %s: %v", stationID, err)
				return
			}
			log.Printf("[ocpp-tracker] TriggerMessage(StatusNotification) to %s: %s", stationID, resp.Status)
		},
		remotecontrol.MessageTriggerStatusNotification,
	)
	if err != nil {
		log.Printf("[ocpp-tracker] TriggerMessage send to %s: %v", stationID, err)
	}
}

func (h *availabilityForwarder) OnHeartbeat(
	csID string, _ *availability.HeartbeatRequest,
) (*availability.HeartbeatResponse, error) {
	now := types.NewDateTime(time.Now())
	return availability.NewHeartbeatResponse(*now), nil
}

func (h *availabilityForwarder) OnStatusNotification(
	csID string, req *availability.StatusNotificationRequest,
) (*availability.StatusNotificationResponse, error) {
	status := ConnectorStatus(req.ConnectorStatus)

	h.tracker.mu.Lock()
	if _, ok := h.tracker.stations[csID]; !ok {
		h.tracker.stations[csID] = &stationState{
			id:          csID,
			connectors:  make(map[int]*connectorState),
			maxCurrentA: 32.0,
			voltageV:    230.0,
			soc:         math.NaN(),
		}
	}
	s := h.tracker.stations[csID]
	s.connectors[req.ConnectorID] = &connectorState{
		connectorID: req.ConnectorID,
		status:      status,
		updatedAt:   time.Now(),
	}
	h.tracker.mu.Unlock()

	log.Printf("[ocpp-tracker] StatusNotification cs=%s connector=%d status=%s",
		csID, req.ConnectorID, status)
	return &availability.StatusNotificationResponse{}, nil
}

// ── Metering handler ──────────────────────────────────────────────────────────

type meteringForwarder struct {
	tracker *OCPPStateTracker
}

// OnMeterValues updates the tracker with measured values from the charging station.
// Handles: Current.Import → currentA (actual, not commanded),
//          SoC → soc, Energy.Active.Import.Register → energyWh.
func (h *meteringForwarder) OnMeterValues(
	csID string, req *meter.MeterValuesRequest,
) (*meter.MeterValuesResponse, error) {
	h.tracker.mu.Lock()
	defer h.tracker.mu.Unlock()

	s, ok := h.tracker.stations[csID]
	if !ok {
		// Station connected but not yet seen — create a stub entry.
		s = &stationState{
			id:          csID,
			connectors:  make(map[int]*connectorState),
			maxCurrentA: 32.0,
			voltageV:    230.0,
			soc:         math.NaN(),
		}
		h.tracker.stations[csID] = s
	}

	for _, mv := range req.MeterValue {
		for _, sv := range mv.SampledValue {
			v := sv.Value
			switch sv.Measurand {
			case types.MeasurandCurrentImport:
				s.currentA = v
			case types.MeasurandSoC:
				s.soc = v
			case types.MeasurandEnergyActiveImportRegister:
				// Value may carry a multiplier (e.g. kWh × 10^3 = Wh).
				multiplier := 0
				if sv.UnitOfMeasure != nil && sv.UnitOfMeasure.Multiplier != nil {
					multiplier = *sv.UnitOfMeasure.Multiplier
				}
				if multiplier != 0 {
					v *= math.Pow10(multiplier)
				}
				s.energyWh = v
			case types.MeasurandVoltage:
				if v > 0 {
					s.voltageV = v
				}
			}
		}
	}

	log.Printf("[ocpp-tracker] MeterValues cs=%s evse=%d current=%.1fA soc=%.1f%% energy=%.0fWh",
		csID, req.EvseID, s.currentA, s.soc, s.energyWh)
	return meter.NewMeterValuesResponse(), nil
}
