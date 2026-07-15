package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"sync"
	"sync/atomic"
	"time"

	ocpp2 "github.com/lorenzodonini/ocpp-go/ocpp2.0.1"
	"github.com/lorenzodonini/ocpp-go/ocpp2.0.1/availability"
	"github.com/lorenzodonini/ocpp-go/ocpp2.0.1/provisioning"
	"github.com/lorenzodonini/ocpp-go/ocpp2.0.1/remotecontrol"
	"github.com/lorenzodonini/ocpp-go/ocpp2.0.1/smartcharging"
	"github.com/lorenzodonini/ocpp-go/ocpp2.0.1/transactions"
	"github.com/lorenzodonini/ocpp-go/ocpp2.0.1/types"
)

// ── OCPP 2.0.1 protocol adapter ───────────────────────────────────────────────
//
// ocpp201Proto implements chargerProto against ocpp-go's ocpp2.0.1 charging
// station client. Sessions are bracketed with TransactionEvent
// (Started/Updated/Ended) — OCPP-1's invariant that charging sessions are
// TransactionEvent lifecycles, never bare MeterValues, applies to THIS
// protocol version only (1.6 has no TransactionEvent at all; see ocpp16.go).

type ocpp201Proto struct {
	cs ocpp2.ChargingStation

	mu            sync.Mutex
	txID          string
	txSeqNo       int
	txConnectorID int

	// reorderTx arms the out_of_order_txevent fault: while set, sendEvent emits
	// TransactionEvents with a non-monotonic seqNo (adjacent pairs swapped) so a
	// hub that assumes arrival order == event order mis-sequences the session.
	// Set via SetTxReorder (csHandler.ApplyFault, POST /fault).
	reorderTx atomic.Bool
}

// SetTxReorder arms/clears the out_of_order_txevent fault. Called by
// csHandler.ApplyFault via an optional-interface assertion on h.proto, so
// 1.6 (which has no TransactionEvent/seqNo) simply does not implement it.
func (p *ocpp201Proto) SetTxReorder(on bool) { p.reorderTx.Store(on) }

func newOCPP201Proto(cs ocpp2.ChargingStation) *ocpp201Proto {
	return &ocpp201Proto{cs: cs}
}

func (p *ocpp201Proto) IsConnected() bool { return p.cs.IsConnected() }
func (p *ocpp201Proto) Stop()             { p.cs.Stop() }

func (p *ocpp201Proto) Boot() (bootInfo, error) {
	resp, err := p.cs.BootNotification(provisioning.BootReasonPowerUp, stationModel, stationVendor)
	if err != nil {
		return bootInfo{}, err
	}
	return bootInfo{Status: string(resp.Status), Interval: time.Duration(resp.Interval) * time.Second}, nil
}

func (p *ocpp201Proto) Heartbeat() error {
	_, err := p.cs.Heartbeat()
	return err
}

func (p *ocpp201Proto) Status(connectorID int, status connStatus) error {
	now := types.NewDateTime(time.Now())
	_, err := p.cs.StatusNotification(now, availability.ConnectorStatus(status), 1, connectorID)
	return err
}

func (p *ocpp201Proto) currentTxID() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.txID
}

func (p *ocpp201Proto) TxStart(connectorID int, trigger sessionTrigger, opts txStartOpts, m meterSample) string {
	txID := newTxID()
	p.mu.Lock()
	p.txID = txID
	p.txSeqNo = 0
	p.txConnectorID = connectorID
	p.mu.Unlock()

	info := transactions.Transaction{TransactionID: txID, ChargingState: chargingStateFor(m)}
	if opts.RemoteStartID != nil {
		info.RemoteStartID = opts.RemoteStartID
	}
	p.sendEvent(transactions.TransactionEventStarted, trigger, info, m)
	return txID
}

func (p *ocpp201Proto) TxUpdate(trigger sessionTrigger, m meterSample) {
	// Legacy bare MeterValues, kept alongside TransactionEvent(Updated) for
	// CSMS implementations that don't consume TransactionEvent yet.
	p.sendLegacyMeterValues(m)
	info := transactions.Transaction{TransactionID: p.currentTxID(), ChargingState: chargingStateFor(m)}
	p.sendEvent(transactions.TransactionEventUpdated, trigger, info, m)
}

func (p *ocpp201Proto) TxEnd(trigger sessionTrigger, reason stopReason, startedAt time.Time, m meterSample) {
	// Final readings: legacy MeterValues for CSMS implementations that only
	// track those, then the authoritative TransactionEvent(Ended).
	p.sendLegacyMeterValues(m)
	info := transactions.Transaction{
		TransactionID: p.currentTxID(),
		ChargingState: transactions.ChargingStateIdle,
		StoppedReason: reasonToOCPP201(reason),
	}
	if !startedAt.IsZero() {
		t := int(time.Since(startedAt).Seconds())
		info.TimeSpentCharging = &t
	}
	p.sendEvent(transactions.TransactionEventEnded, trigger, info, m)
	p.mu.Lock()
	p.txID = ""
	p.mu.Unlock()
}

func (p *ocpp201Proto) MeterValuesIdle(connectorID int, m meterSample) {
	if _, err := p.cs.MeterValues(connectorID, []types.MeterValue{buildMeterValue201(m)}); err != nil {
		log.Printf("evsim: MeterValues connector=%d: %v", connectorID, err)
	}
}

func (p *ocpp201Proto) sendEvent(event transactions.TransactionEvent, trigger sessionTrigger, info transactions.Transaction, m meterSample) {
	p.mu.Lock()
	seq := p.txSeqNo
	p.txSeqNo++
	connID := p.txConnectorID
	p.mu.Unlock()

	// out_of_order_txevent: send a non-monotonic seqNo. XOR-ing the low bit swaps
	// each adjacent pair (real 0,1,2,3 → sent 1,0,3,2), so the FIRST event (Started,
	// real seq 0) carries a HIGHER seqNo than the one after it — a clear ordering
	// violation, while every sent value stays unique. The sim's own bookkeeping is
	// unaffected (it advances p.txSeqNo above); only the wire value is perturbed.
	sentSeq := seq
	if p.reorderTx.Load() {
		sentSeq = seq ^ 1
	}

	_, err := p.cs.TransactionEvent(event, types.NewDateTime(time.Now()), triggerToOCPP201(trigger), sentSeq, info,
		func(req *transactions.TransactionEventRequest) {
			req.Evse = &types.EVSE{ID: 1, ConnectorID: &connID}
			req.MeterValue = []types.MeterValue{buildMeterValue201(m)}
		})
	if err != nil {
		log.Printf("evsim: TransactionEvent %s tx=%s seq=%d: %v", event, info.TransactionID, sentSeq, err)
		return
	}
	log.Printf("evsim: TransactionEvent %s tx=%s seq=%d trigger=%s state=%s soc=%.1f%% current=%.1fA",
		event, info.TransactionID, sentSeq, triggerToOCPP201(trigger), info.ChargingState, m.SOC, m.CurrentA)
}

func (p *ocpp201Proto) sendLegacyMeterValues(m meterSample) {
	p.mu.Lock()
	connectorID := p.txConnectorID
	p.mu.Unlock()
	if _, err := p.cs.MeterValues(connectorID, []types.MeterValue{buildMeterValue201(m)}); err != nil {
		log.Printf("evsim: MeterValues connector=%d: %v", connectorID, err)
		return
	}
	log.Printf("evsim: MeterValues connector=%d soc=%.1f%% current=%.1fA power=%.0fW energy=%.0fWh",
		connectorID, m.SOC, m.CurrentA, m.PowerW, m.EnergyWh)
}

func chargingStateFor(m meterSample) transactions.ChargingState {
	if m.CurrentA > 0 {
		return transactions.ChargingStateCharging
	}
	return transactions.ChargingStateSuspendedEVSE
}

func triggerToOCPP201(t sessionTrigger) transactions.TriggerReason {
	switch t {
	case trigCablePluggedIn:
		return transactions.TriggerReasonCablePluggedIn
	case trigAuthorized:
		return transactions.TriggerReasonAuthorized
	case trigRemoteStart:
		return transactions.TriggerReasonRemoteStart
	case trigRemoteStop:
		return transactions.TriggerReasonRemoteStop
	case trigStopAuthorized:
		return transactions.TriggerReasonStopAuthorized
	case trigResetCommand:
		return transactions.TriggerReasonResetCommand
	case trigMeterValuePeriodic:
		return transactions.TriggerReasonMeterValuePeriodic
	case trigChargingRateChanged:
		return transactions.TriggerReasonChargingRateChanged
	case trigTimeLimitReached:
		return transactions.TriggerReasonTimeLimitReached
	default:
		return transactions.TriggerReasonChargingStateChanged
	}
}

func reasonToOCPP201(r stopReason) transactions.Reason {
	switch r {
	case stopRemote:
		return transactions.ReasonRemote
	case stopSOCLimitReached:
		return transactions.ReasonSOCLimitReached
	case stopTimeLimitReached:
		return transactions.ReasonTimeLimitReached
	case stopImmediateReset:
		return transactions.ReasonImmediateReset
	default:
		return transactions.ReasonLocal
	}
}

// buildMeterValue201 assembles the five key measurands shared by MeterValues
// and TransactionEvent: Current.Import, Power.Active.Import,
// Energy.Active.Import.Register, SoC, Voltage.
func buildMeterValue201(m meterSample) types.MeterValue {
	now := types.NewDateTime(time.Now())
	return types.MeterValue{
		Timestamp: *now,
		SampledValue: []types.SampledValue{
			{
				Measurand:     types.MeasurandCurrentImport,
				Value:         m.CurrentA,
				UnitOfMeasure: &types.UnitOfMeasure{Unit: "A"},
			},
			{
				Measurand:     types.MeasurandPowerActiveImport,
				Value:         m.PowerW,
				UnitOfMeasure: &types.UnitOfMeasure{Unit: "W"},
			},
			{
				Measurand:     types.MeasurandEnergyActiveImportRegister,
				Value:         m.EnergyWh,
				UnitOfMeasure: &types.UnitOfMeasure{Unit: "Wh"},
			},
			{
				Measurand: types.MeasurandSoC,
				Value:     m.SOC,
			},
			{
				Measurand:     types.MeasurandVoltage,
				Value:         m.VoltageV,
				UnitOfMeasure: &types.UnitOfMeasure{Unit: "V"},
			},
		},
	}
}

// newTxID returns a random 32-hex-char transaction identifier (≤ 36 chars as
// required by the OCPP transactionId field). Only 2.0.1 self-generates a
// transaction ID; 1.6's is CSMS-assigned (see ocpp16Proto.TxStart).
func newTxID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		// Fallback: time-based ID. Collisions are irrelevant in a simulator.
		return fmt.Sprintf("tx-%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b[:])
}

// ── OCPP 2.0.1 handler wrapper ────────────────────────────────────────────────
//
// ocpp201Handlers adapts csHandler's shared session/battery logic to the
// ocpp2.0.1 handler interfaces (provisioning/availability/remotecontrol/
// smartcharging). All actual state changes are delegated to h; this type
// only translates request/response wire shapes.
type ocpp201Handlers struct {
	h *csHandler
}

func (o *ocpp201Handlers) OnGetBaseReport(req *provisioning.GetBaseReportRequest) (*provisioning.GetBaseReportResponse, error) {
	return &provisioning.GetBaseReportResponse{Status: types.GenericDeviceModelStatusAccepted}, nil
}
func (o *ocpp201Handlers) OnGetReport(req *provisioning.GetReportRequest) (*provisioning.GetReportResponse, error) {
	return &provisioning.GetReportResponse{Status: types.GenericDeviceModelStatusAccepted}, nil
}
func (o *ocpp201Handlers) OnGetVariables(req *provisioning.GetVariablesRequest) (*provisioning.GetVariablesResponse, error) {
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
func (o *ocpp201Handlers) OnReset(req *provisioning.ResetRequest) (*provisioning.ResetResponse, error) {
	log.Printf("evsim: Reset type=%s — accepted, simulating reboot", req.Type)
	o.h.simulateReset()
	return &provisioning.ResetResponse{Status: provisioning.ResetStatusAccepted}, nil
}
func (o *ocpp201Handlers) OnSetNetworkProfile(req *provisioning.SetNetworkProfileRequest) (*provisioning.SetNetworkProfileResponse, error) {
	return &provisioning.SetNetworkProfileResponse{Status: provisioning.SetNetworkProfileStatusAccepted}, nil
}
func (o *ocpp201Handlers) OnSetVariables(req *provisioning.SetVariablesRequest) (*provisioning.SetVariablesResponse, error) {
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
func (o *ocpp201Handlers) OnChangeAvailability(req *availability.ChangeAvailabilityRequest) (*availability.ChangeAvailabilityResponse, error) {
	log.Printf("evsim: ChangeAvailability evse=%d op=%s", req.Evse.ID, req.OperationalStatus)
	return &availability.ChangeAvailabilityResponse{Status: availability.ChangeAvailabilityStatusAccepted}, nil
}
func (o *ocpp201Handlers) OnRequestStartTransaction(req *remotecontrol.RequestStartTransactionRequest) (*remotecontrol.RequestStartTransactionResponse, error) {
	h := o.h
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
	go h.startSession(connectorID, h.sessionDuration, trigRemoteStart, txStartOpts{RemoteStartID: &remoteStartID})
	return remotecontrol.NewRequestStartTransactionResponse(remotecontrol.RequestStartStopStatusAccepted), nil
}
func (o *ocpp201Handlers) OnRequestStopTransaction(req *remotecontrol.RequestStopTransactionRequest) (*remotecontrol.RequestStopTransactionResponse, error) {
	h := o.h
	txID := h.currentTxID()
	if txID == "" || req.TransactionID != txID {
		log.Printf("evsim: RequestStopTransaction tx=%s — rejected (active tx=%q)", req.TransactionID, txID)
		return remotecontrol.NewRequestStopTransactionResponse(remotecontrol.RequestStartStopStatusRejected), nil
	}
	log.Printf("evsim: RequestStopTransaction tx=%s — accepted", req.TransactionID)
	go h.stopSession(stopRemote, trigRemoteStop)
	return remotecontrol.NewRequestStopTransactionResponse(remotecontrol.RequestStartStopStatusAccepted), nil
}
func (o *ocpp201Handlers) OnTriggerMessage(req *remotecontrol.TriggerMessageRequest) (*remotecontrol.TriggerMessageResponse, error) {
	h := o.h
	log.Printf("evsim: TriggerMessage type=%s", req.RequestedMessage)
	resp := remotecontrol.NewTriggerMessageResponse(remotecontrol.TriggerMessageStatusAccepted)
	go func() {
		time.Sleep(200 * time.Millisecond)
		switch req.RequestedMessage {
		case remotecontrol.MessageTriggerStatusNotification:
			h.triggerStatusNotifications()
		case remotecontrol.MessageTriggerHeartbeat:
			h.triggerHeartbeat()
		case remotecontrol.MessageTriggerMeterValues:
			h.triggerMeterValues()
		}
	}()
	return resp, nil
}
func (o *ocpp201Handlers) OnUnlockConnector(req *remotecontrol.UnlockConnectorRequest) (*remotecontrol.UnlockConnectorResponse, error) {
	log.Printf("evsim: UnlockConnector evse=%d connector=%d", req.EvseID, req.ConnectorID)
	return remotecontrol.NewUnlockConnectorResponse(remotecontrol.UnlockStatusUnlocked), nil
}
func (o *ocpp201Handlers) OnSetChargingProfile(req *smartcharging.SetChargingProfileRequest) (*smartcharging.SetChargingProfileResponse, error) {
	p := req.ChargingProfile
	lim := chargingLimit{EvseID: req.EvseID, ProfileID: p.ID, Purpose: string(p.ChargingProfilePurpose)}
	if len(p.ChargingSchedule) > 0 && len(p.ChargingSchedule[0].ChargingSchedulePeriod) > 0 {
		lim.LimitA = p.ChargingSchedule[0].ChargingSchedulePeriod[0].Limit
	}
	if o.h.handleSetChargingProfile(lim) {
		return &smartcharging.SetChargingProfileResponse{Status: smartcharging.ChargingProfileStatusAccepted}, nil
	}
	return &smartcharging.SetChargingProfileResponse{Status: smartcharging.ChargingProfileStatusRejected}, nil
}
func (o *ocpp201Handlers) OnGetChargingProfiles(req *smartcharging.GetChargingProfilesRequest) (*smartcharging.GetChargingProfilesResponse, error) {
	return &smartcharging.GetChargingProfilesResponse{Status: smartcharging.GetChargingProfileStatusNoProfiles}, nil
}
func (o *ocpp201Handlers) OnClearChargingProfile(req *smartcharging.ClearChargingProfileRequest) (*smartcharging.ClearChargingProfileResponse, error) {
	o.h.handleClearChargingProfile()
	return &smartcharging.ClearChargingProfileResponse{Status: smartcharging.ClearChargingProfileStatusAccepted}, nil
}
func (o *ocpp201Handlers) OnGetCompositeSchedule(req *smartcharging.GetCompositeScheduleRequest) (*smartcharging.GetCompositeScheduleResponse, error) {
	return smartcharging.NewGetCompositeScheduleResponse(smartcharging.GetCompositeScheduleStatusRejected, req.EvseID), nil
}
