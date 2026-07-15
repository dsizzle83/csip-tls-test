package main

import (
	"log"
	"strconv"
	"sync"
	"time"

	core16 "github.com/lorenzodonini/ocpp-go/ocpp1.6/core"
	remotetrigger16 "github.com/lorenzodonini/ocpp-go/ocpp1.6/remotetrigger"
	smartcharging16 "github.com/lorenzodonini/ocpp-go/ocpp1.6/smartcharging"
	types16 "github.com/lorenzodonini/ocpp-go/ocpp1.6/types"
)

// ── OCPP 1.6J protocol adapter ────────────────────────────────────────────────
//
// ocpp16Proto implements chargerProto against ocpp-go's ocpp1.6 charge point
// client. 1.6 has no TransactionEvent: sessions are bracketed with
// StartTransaction / StopTransaction (1.6's transaction model), and
// mid-session updates are plain periodic MeterValues carrying the
// CSMS-assigned transactionId — there is no separate "Updated" message type.

// defaultIDTag is used for StartTransaction when no idTag was supplied by
// whatever triggered the session (GUI inject, auto session-interval tick,
// Reset replay) — only RemoteStartTransaction carries a real idTag.
const defaultIDTag = "EVSIM-LOCAL"

// ocpp16Client is the subset of ocpp16.ChargePoint's wire methods
// ocpp16Proto calls, narrowed from the full ~30-method ChargePoint interface
// (which also carries firmware/reservation/security/... profiles evsim never
// touches) so that tests can fake it without stubbing every profile.
// ocpp16.NewChargePoint's return value satisfies this interface structurally.
type ocpp16Client interface {
	BootNotification(chargePointModel, chargePointVendor string, props ...func(*core16.BootNotificationRequest)) (*core16.BootNotificationConfirmation, error)
	Heartbeat(props ...func(*core16.HeartbeatRequest)) (*core16.HeartbeatConfirmation, error)
	StatusNotification(connectorId int, errorCode core16.ChargePointErrorCode, status core16.ChargePointStatus, props ...func(*core16.StatusNotificationRequest)) (*core16.StatusNotificationConfirmation, error)
	StartTransaction(connectorId int, idTag string, meterStart int, timestamp *types16.DateTime, props ...func(*core16.StartTransactionRequest)) (*core16.StartTransactionConfirmation, error)
	StopTransaction(meterStop int, timestamp *types16.DateTime, transactionId int, props ...func(*core16.StopTransactionRequest)) (*core16.StopTransactionConfirmation, error)
	MeterValues(connectorId int, meterValues []types16.MeterValue, props ...func(*core16.MeterValuesRequest)) (*core16.MeterValuesConfirmation, error)
	IsConnected() bool
	Stop()
}

type ocpp16Proto struct {
	cp ocpp16Client

	mu            sync.Mutex
	active        bool
	connectorID   int
	transactionID int
}

func newOCPP16Proto(cp ocpp16Client) *ocpp16Proto {
	return &ocpp16Proto{cp: cp}
}

func (p *ocpp16Proto) IsConnected() bool { return p.cp.IsConnected() }
func (p *ocpp16Proto) Stop()             { p.cp.Stop() }

func (p *ocpp16Proto) Boot() (bootInfo, error) {
	resp, err := p.cp.BootNotification(stationModel, stationVendor)
	if err != nil {
		return bootInfo{}, err
	}
	return bootInfo{Status: string(resp.Status), Interval: time.Duration(resp.Interval) * time.Second}, nil
}

func (p *ocpp16Proto) Heartbeat() error {
	_, err := p.cp.Heartbeat()
	return err
}

func (p *ocpp16Proto) Status(connectorID int, status connStatus) error {
	_, err := p.cp.StatusNotification(connectorID, core16.NoError, statusToOCPP16(status))
	return err
}

func (p *ocpp16Proto) TxStart(connectorID int, trigger sessionTrigger, opts txStartOpts, m meterSample) string {
	idTag := opts.IDTag
	if idTag == "" {
		idTag = defaultIDTag
	}
	resp, err := p.cp.StartTransaction(connectorID, idTag, int(m.EnergyWh), types16.NewDateTime(time.Now()))
	if err != nil {
		log.Printf("evsim: StartTransaction connector=%d: %v", connectorID, err)
		return ""
	}
	p.mu.Lock()
	p.active = true
	p.connectorID = connectorID
	p.transactionID = resp.TransactionId
	p.mu.Unlock()

	idStatus := ""
	if resp.IdTagInfo != nil {
		idStatus = string(resp.IdTagInfo.Status)
	}
	log.Printf("evsim: StartTransaction connector=%d tx=%d idTagStatus=%s trigger=%s soc=%.1f%%",
		connectorID, resp.TransactionId, idStatus, trigger, m.SOC)
	return strconv.Itoa(resp.TransactionId)
}

func (p *ocpp16Proto) TxUpdate(trigger sessionTrigger, m meterSample) {
	connectorID, txID, active := p.txState()
	if !active {
		return
	}
	mv := buildMeterValue16(m)
	id := txID
	if _, err := p.cp.MeterValues(connectorID, []types16.MeterValue{mv}, func(req *core16.MeterValuesRequest) {
		req.TransactionId = &id
	}); err != nil {
		log.Printf("evsim: MeterValues connector=%d tx=%d: %v", connectorID, txID, err)
		return
	}
	log.Printf("evsim: MeterValues connector=%d tx=%d trigger=%s soc=%.1f%% current=%.1fA",
		connectorID, txID, trigger, m.SOC, m.CurrentA)
}

func (p *ocpp16Proto) TxEnd(trigger sessionTrigger, reason stopReason, startedAt time.Time, m meterSample) {
	connectorID, txID, active := p.txState()
	p.mu.Lock()
	p.active = false
	p.mu.Unlock()
	if !active {
		return
	}
	mv := buildMeterValue16(m)
	_, err := p.cp.StopTransaction(int(m.EnergyWh), types16.NewDateTime(time.Now()), txID, func(req *core16.StopTransactionRequest) {
		req.Reason = reasonToOCPP16(reason)
		req.TransactionData = []types16.MeterValue{mv}
	})
	if err != nil {
		log.Printf("evsim: StopTransaction connector=%d tx=%d: %v", connectorID, txID, err)
		return
	}
	log.Printf("evsim: StopTransaction connector=%d tx=%d reason=%s trigger=%s soc=%.1f%%",
		connectorID, txID, reasonToOCPP16(reason), trigger, m.SOC)
}

func (p *ocpp16Proto) MeterValuesIdle(connectorID int, m meterSample) {
	mv := buildMeterValue16(m)
	if _, err := p.cp.MeterValues(connectorID, []types16.MeterValue{mv}); err != nil {
		log.Printf("evsim: MeterValues connector=%d: %v", connectorID, err)
	}
}

func (p *ocpp16Proto) txState() (connectorID, transactionID int, active bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.connectorID, p.transactionID, p.active
}

// statusToOCPP16 maps the protocol-neutral connStatus onto 1.6's
// ChargePointStatus. 1.6 has no "Occupied" — the nearest single equivalent
// for "a session is active on this connector" is Charging; every other
// value's spelling is identical between the two protocols' enums.
func statusToOCPP16(s connStatus) core16.ChargePointStatus {
	if s == connOccupied {
		return core16.ChargePointStatusCharging
	}
	return core16.ChargePointStatus(s)
}

// reasonToOCPP16 maps the protocol-neutral stopReason onto 1.6's coarser
// Reason enum, which has no SOC-limit or time-limit specific values.
func reasonToOCPP16(r stopReason) core16.Reason {
	switch r {
	case stopRemote:
		return core16.ReasonRemote
	case stopImmediateReset:
		return core16.ReasonHardReset
	case stopSOCLimitReached, stopTimeLimitReached:
		return core16.ReasonOther
	default:
		return core16.ReasonLocal
	}
}

// buildMeterValue16 assembles the measurands the task requires for 1.6:
// Current.Import, Voltage, Energy.Active.Import.Register, SoC. Unlike 2.0.1,
// SampledValue.Value is a string in the 1.6 model.
func buildMeterValue16(m meterSample) types16.MeterValue {
	now := types16.NewDateTime(time.Now())
	f := func(v float64) string { return strconv.FormatFloat(v, 'f', -1, 64) }
	return types16.MeterValue{
		Timestamp: now,
		SampledValue: []types16.SampledValue{
			{Measurand: types16.MeasurandCurrentImport, Value: f(m.CurrentA), Unit: types16.UnitOfMeasureA},
			{Measurand: types16.MeasurandVoltage, Value: f(m.VoltageV), Unit: types16.UnitOfMeasureV},
			{Measurand: types16.MeasurandEnergyActiveImportRegister, Value: f(m.EnergyWh), Unit: types16.UnitOfMeasureWh},
			{Measurand: types16.MeasurandSoC, Value: f(m.SOC)},
		},
	}
}

// ── OCPP 1.6 handler wrapper ──────────────────────────────────────────────────
//
// ocpp16Handlers adapts csHandler's shared session/battery logic to the 1.6
// handler interfaces (core.ChargePointHandler, smartcharging.ChargePointHandler,
// remotetrigger.ChargePointHandler). All actual state changes are delegated to
// h; this type only translates request/response wire shapes.
type ocpp16Handlers struct {
	h *csHandler
}

// -------------------- core.ChargePointHandler --------------------

func (o *ocpp16Handlers) OnChangeAvailability(req *core16.ChangeAvailabilityRequest) (*core16.ChangeAvailabilityConfirmation, error) {
	log.Printf("evsim: ChangeAvailability connector=%d type=%s", req.ConnectorId, req.Type)
	return &core16.ChangeAvailabilityConfirmation{Status: core16.AvailabilityStatusAccepted}, nil
}
func (o *ocpp16Handlers) OnChangeConfiguration(req *core16.ChangeConfigurationRequest) (*core16.ChangeConfigurationConfirmation, error) {
	return &core16.ChangeConfigurationConfirmation{Status: core16.ConfigurationStatusNotSupported}, nil
}
func (o *ocpp16Handlers) OnClearCache(req *core16.ClearCacheRequest) (*core16.ClearCacheConfirmation, error) {
	return &core16.ClearCacheConfirmation{Status: core16.ClearCacheStatusAccepted}, nil
}
func (o *ocpp16Handlers) OnDataTransfer(req *core16.DataTransferRequest) (*core16.DataTransferConfirmation, error) {
	return &core16.DataTransferConfirmation{Status: core16.DataTransferStatusUnknownVendorId}, nil
}
func (o *ocpp16Handlers) OnGetConfiguration(req *core16.GetConfigurationRequest) (*core16.GetConfigurationConfirmation, error) {
	// No configurable keys exposed by the simulator; report every requested
	// key as unknown (mirrors 2.0.1's OnGetVariables honesty, finding
	// OCPP-6: an empty/omitted response is schema-invalid).
	return &core16.GetConfigurationConfirmation{UnknownKey: req.Key}, nil
}
func (o *ocpp16Handlers) OnRemoteStartTransaction(req *core16.RemoteStartTransactionRequest) (*core16.RemoteStartTransactionConfirmation, error) {
	h := o.h
	if h.sessionActive() {
		log.Printf("evsim: RemoteStartTransaction idTag=%s — rejected (session already active)", req.IdTag)
		return &core16.RemoteStartTransactionConfirmation{Status: types16.RemoteStartStopStatusRejected}, nil
	}
	connectorID := 1
	if req.ConnectorId != nil && *req.ConnectorId > 0 {
		connectorID = *req.ConnectorId
	}
	log.Printf("evsim: RemoteStartTransaction connector=%d idTag=%s — accepted", connectorID, req.IdTag)
	// Accept now, start asynchronously: StartTransaction must not be sent
	// from inside this handler while the CSMS awaits our response.
	go h.startSession(connectorID, h.sessionDuration, trigRemoteStart, txStartOpts{IDTag: req.IdTag})
	return &core16.RemoteStartTransactionConfirmation{Status: types16.RemoteStartStopStatusAccepted}, nil
}
func (o *ocpp16Handlers) OnRemoteStopTransaction(req *core16.RemoteStopTransactionRequest) (*core16.RemoteStopTransactionConfirmation, error) {
	h := o.h
	cur := h.currentTxID()
	want := strconv.Itoa(req.TransactionId)
	if cur == "" || cur != want {
		log.Printf("evsim: RemoteStopTransaction tx=%d — rejected (active tx=%q)", req.TransactionId, cur)
		return &core16.RemoteStopTransactionConfirmation{Status: types16.RemoteStartStopStatusRejected}, nil
	}
	log.Printf("evsim: RemoteStopTransaction tx=%d — accepted", req.TransactionId)
	go h.stopSession(stopRemote, trigRemoteStop)
	return &core16.RemoteStopTransactionConfirmation{Status: types16.RemoteStartStopStatusAccepted}, nil
}
func (o *ocpp16Handlers) OnReset(req *core16.ResetRequest) (*core16.ResetConfirmation, error) {
	log.Printf("evsim: Reset type=%s — accepted, simulating reboot", req.Type)
	o.h.simulateReset()
	return &core16.ResetConfirmation{Status: core16.ResetStatusAccepted}, nil
}
func (o *ocpp16Handlers) OnUnlockConnector(req *core16.UnlockConnectorRequest) (*core16.UnlockConnectorConfirmation, error) {
	log.Printf("evsim: UnlockConnector connector=%d", req.ConnectorId)
	return &core16.UnlockConnectorConfirmation{Status: core16.UnlockStatusUnlocked}, nil
}

// -------------------- smartcharging.ChargePointHandler --------------------

func (o *ocpp16Handlers) OnSetChargingProfile(req *smartcharging16.SetChargingProfileRequest) (*smartcharging16.SetChargingProfileConfirmation, error) {
	p := req.ChargingProfile
	lim := chargingLimit{EvseID: req.ConnectorId, ProfileID: p.ChargingProfileId, Purpose: string(p.ChargingProfilePurpose)}
	if p.ChargingSchedule != nil && len(p.ChargingSchedule.ChargingSchedulePeriod) > 0 {
		lim.LimitA = p.ChargingSchedule.ChargingSchedulePeriod[0].Limit
	}
	if o.h.handleSetChargingProfile(lim) {
		return &smartcharging16.SetChargingProfileConfirmation{Status: smartcharging16.ChargingProfileStatusAccepted}, nil
	}
	return &smartcharging16.SetChargingProfileConfirmation{Status: smartcharging16.ChargingProfileStatusRejected}, nil
}
func (o *ocpp16Handlers) OnClearChargingProfile(req *smartcharging16.ClearChargingProfileRequest) (*smartcharging16.ClearChargingProfileConfirmation, error) {
	o.h.handleClearChargingProfile()
	return &smartcharging16.ClearChargingProfileConfirmation{Status: smartcharging16.ClearChargingProfileStatusAccepted}, nil
}
func (o *ocpp16Handlers) OnGetCompositeSchedule(req *smartcharging16.GetCompositeScheduleRequest) (*smartcharging16.GetCompositeScheduleConfirmation, error) {
	return &smartcharging16.GetCompositeScheduleConfirmation{Status: smartcharging16.GetCompositeScheduleStatusRejected}, nil
}

// -------------------- remotetrigger.ChargePointHandler --------------------

func (o *ocpp16Handlers) OnTriggerMessage(req *remotetrigger16.TriggerMessageRequest) (*remotetrigger16.TriggerMessageConfirmation, error) {
	h := o.h
	log.Printf("evsim: TriggerMessage type=%s", req.RequestedMessage)
	switch req.RequestedMessage {
	case core16.BootNotificationFeatureName, core16.HeartbeatFeatureName,
		core16.MeterValuesFeatureName, core16.StatusNotificationFeatureName:
		resp := remotetrigger16.NewTriggerMessageConfirmation(remotetrigger16.TriggerMessageStatusAccepted)
		go func() {
			time.Sleep(200 * time.Millisecond)
			switch req.RequestedMessage {
			case core16.BootNotificationFeatureName:
				h.triggerBoot()
			case core16.HeartbeatFeatureName:
				h.triggerHeartbeat()
			case core16.MeterValuesFeatureName:
				h.triggerMeterValues()
			case core16.StatusNotificationFeatureName:
				h.triggerStatusNotifications()
			}
		}()
		return resp, nil
	default:
		return remotetrigger16.NewTriggerMessageConfirmation(remotetrigger16.TriggerMessageStatusNotImplemented), nil
	}
}
