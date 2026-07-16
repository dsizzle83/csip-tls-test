package main

import (
	"fmt"
	"net"
	"strconv"
	"sync"
	"testing"
	"time"

	ocpp16 "github.com/lorenzodonini/ocpp-go/ocpp1.6"
	core16 "github.com/lorenzodonini/ocpp-go/ocpp1.6/core"
	remotetrigger16 "github.com/lorenzodonini/ocpp-go/ocpp1.6/remotetrigger"
	smartcharging16 "github.com/lorenzodonini/ocpp-go/ocpp1.6/smartcharging"
	types16 "github.com/lorenzodonini/ocpp-go/ocpp1.6/types"
	"github.com/lorenzodonini/ocpp-go/ws"
)

// fakeChargePoint16 is a test double for ocpp16Client (the narrow subset of
// ocpp16.ChargePoint ocpp16Proto actually calls). It records every request it
// receives and returns canned confirmations, with no real network involved —
// this exercises ocpp201Proto/ocpp16Proto's translation logic in isolation,
// the same "call the handler/adapter directly, no live CSMS" style
// faults_test.go and TestRemoteStartStop already use.
type bootCall struct{ model, vendor string }

type statusCall struct {
	connectorID int
	errorCode   core16.ChargePointErrorCode
	status      core16.ChargePointStatus
}

type startCall struct {
	connectorID int
	idTag       string
	meterStart  int
}

type stopCall struct {
	meterStop     int
	transactionID int
	reason        core16.Reason
	data          []types16.MeterValue
}

type meterValuesCall struct {
	connectorID   int
	transactionID *int
	values        []types16.MeterValue
}

type fakeChargePoint16 struct {
	mu sync.Mutex

	connected bool
	stopped   bool

	boots       []bootCall
	statuses    []statusCall
	heartbeats  int
	starts      []startCall
	stops       []stopCall
	meterValues []meterValuesCall

	startTransactionID int // TransactionId the fake StartTransaction confirmation carries
}

// fakeChargePoint16Snapshot is a lock-free, race-safe copy of
// fakeChargePoint16's recorded calls for test assertions.
type fakeChargePoint16Snapshot struct {
	connected   bool
	stopped     bool
	boots       []bootCall
	statuses    []statusCall
	heartbeats  int
	starts      []startCall
	stops       []stopCall
	meterValues []meterValuesCall
}

func newFakeChargePoint16() *fakeChargePoint16 {
	return &fakeChargePoint16{connected: true, startTransactionID: 42}
}

func (f *fakeChargePoint16) BootNotification(model, vendor string, _ ...func(*core16.BootNotificationRequest)) (*core16.BootNotificationConfirmation, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.boots = append(f.boots, bootCall{model, vendor})
	return &core16.BootNotificationConfirmation{
		CurrentTime: types16.NewDateTime(time.Now()),
		Interval:    60,
		Status:      core16.RegistrationStatusAccepted,
	}, nil
}

func (f *fakeChargePoint16) Heartbeat(_ ...func(*core16.HeartbeatRequest)) (*core16.HeartbeatConfirmation, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.heartbeats++
	return &core16.HeartbeatConfirmation{CurrentTime: types16.NewDateTime(time.Now())}, nil
}

func (f *fakeChargePoint16) StatusNotification(connectorID int, errorCode core16.ChargePointErrorCode, status core16.ChargePointStatus, _ ...func(*core16.StatusNotificationRequest)) (*core16.StatusNotificationConfirmation, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.statuses = append(f.statuses, statusCall{connectorID, errorCode, status})
	return &core16.StatusNotificationConfirmation{}, nil
}

func (f *fakeChargePoint16) StartTransaction(connectorID int, idTag string, meterStart int, _ *types16.DateTime, _ ...func(*core16.StartTransactionRequest)) (*core16.StartTransactionConfirmation, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.starts = append(f.starts, startCall{connectorID, idTag, meterStart})
	return &core16.StartTransactionConfirmation{
		IdTagInfo:     types16.NewIdTagInfo(types16.AuthorizationStatusAccepted),
		TransactionId: f.startTransactionID,
	}, nil
}

func (f *fakeChargePoint16) StopTransaction(meterStop int, _ *types16.DateTime, transactionID int, props ...func(*core16.StopTransactionRequest)) (*core16.StopTransactionConfirmation, error) {
	req := &core16.StopTransactionRequest{}
	for _, p := range props {
		p(req)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.stops = append(f.stops, stopCall{meterStop, transactionID, req.Reason, req.TransactionData})
	return &core16.StopTransactionConfirmation{}, nil
}

func (f *fakeChargePoint16) MeterValues(connectorID int, values []types16.MeterValue, props ...func(*core16.MeterValuesRequest)) (*core16.MeterValuesConfirmation, error) {
	req := &core16.MeterValuesRequest{}
	for _, p := range props {
		p(req)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.meterValues = append(f.meterValues, meterValuesCall{connectorID, req.TransactionId, values})
	return &core16.MeterValuesConfirmation{}, nil
}

func (f *fakeChargePoint16) IsConnected() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.connected
}

func (f *fakeChargePoint16) Stop() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.stopped = true
	f.connected = false
}

func (f *fakeChargePoint16) snapshot() fakeChargePoint16Snapshot {
	f.mu.Lock()
	defer f.mu.Unlock()
	return fakeChargePoint16Snapshot{
		connected:   f.connected,
		stopped:     f.stopped,
		boots:       append([]bootCall(nil), f.boots...),
		statuses:    append([]statusCall(nil), f.statuses...),
		heartbeats:  f.heartbeats,
		starts:      append([]startCall(nil), f.starts...),
		stops:       append([]stopCall(nil), f.stops...),
		meterValues: append([]meterValuesCall(nil), f.meterValues...),
	}
}

func newTestHandler16(fake *fakeChargePoint16, batt *evBattery) (*csHandler, *ocpp16Handlers) {
	h := &csHandler{
		stationID:       "evsim-16-test",
		batt:            batt,
		meterInterval:   50 * time.Millisecond,
		sessionDuration: time.Minute,
	}
	h.proto = newOCPP16Proto(fake)
	return h, &ocpp16Handlers{h: h}
}

// TestOCPP16_BootAndStatus verifies BootNotification carries the station
// identity and StatusNotification maps connStatus onto 1.6's ChargePointStatus
// — including the Occupied -> Charging translation 1.6 needs since it has no
// direct "Occupied" equivalent.
func TestOCPP16_BootAndStatus(t *testing.T) {
	fake := newFakeChargePoint16()
	h, _ := newTestHandler16(fake, newEVBattery(60000, 20, 230, 32, 60))
	h.setConnector(1, connAvailable)

	boot, err := h.proto.Boot()
	if err != nil {
		t.Fatalf("Boot: %v", err)
	}
	if boot.Status != "Accepted" || boot.Interval != 60*time.Second {
		t.Errorf("boot = %+v, want status=Accepted interval=60s", boot)
	}
	snap := fake.snapshot()
	if len(snap.boots) != 1 || snap.boots[0].model != stationModel || snap.boots[0].vendor != stationVendor {
		t.Fatalf("boots = %+v, want one entry with model=%s vendor=%s", snap.boots, stationModel, stationVendor)
	}

	h.sendStatus(1, connAvailable)
	h.sendStatus(1, connOccupied)
	snap = fake.snapshot()
	if len(snap.statuses) != 2 {
		t.Fatalf("statuses = %+v, want 2 entries", snap.statuses)
	}
	if snap.statuses[0].status != core16.ChargePointStatusAvailable {
		t.Errorf("first status = %s, want Available", snap.statuses[0].status)
	}
	if snap.statuses[1].status != core16.ChargePointStatusCharging {
		t.Errorf("Occupied mapped to %s, want Charging (1.6 has no Occupied)", snap.statuses[1].status)
	}
}

// TestOCPP16_TransactionLifecycle drives a full charging session through the
// shared session state machine (session.go) in 1.6 mode and verifies
// StartTransaction / periodic MeterValues (carrying the CSMS-assigned
// transactionId) / StopTransaction fire in the right order with the right
// measurand content — 1.6's transaction model, not 2.0.1's TransactionEvent.
func TestOCPP16_TransactionLifecycle(t *testing.T) {
	fake := newFakeChargePoint16()
	batt := newEVBattery(60000, 50, 230, 32, 60)
	h, _ := newTestHandler16(fake, batt)
	h.setConnector(1, connAvailable)

	h.startSession(1, time.Minute, trigCablePluggedIn, txStartOpts{})

	waitFor(t, time.Second, func() bool {
		st := h.Snapshot()
		return st.Session.Active && st.Session.TransactionID != ""
	}, "session active with transaction ID")

	if got := h.Snapshot().Session.TransactionID; got != strconv.Itoa(fake.startTransactionID) {
		t.Errorf("Session.TransactionID = %q, want %q (CSMS-assigned)", got, strconv.Itoa(fake.startTransactionID))
	}

	snap := fake.snapshot()
	if len(snap.starts) != 1 {
		t.Fatalf("starts = %+v, want 1 StartTransaction call", snap.starts)
	}
	if snap.starts[0].connectorID != 1 {
		t.Errorf("StartTransaction connectorID = %d, want 1", snap.starts[0].connectorID)
	}
	if snap.starts[0].idTag == "" {
		t.Error("StartTransaction idTag is empty, want a default idTag")
	}

	// Let at least one periodic MeterValues go out mid-session.
	waitFor(t, time.Second, func() bool {
		return len(fake.snapshot().meterValues) >= 1
	}, "at least one periodic MeterValues")

	snap = fake.snapshot()
	mv := snap.meterValues[0]
	if mv.transactionID == nil || *mv.transactionID != fake.startTransactionID {
		t.Errorf("MeterValues transactionId = %v, want %d", mv.transactionID, fake.startTransactionID)
	}
	assertMeasurands16(t, mv.values)

	h.stopSession(stopLocal, trigStopAuthorized)

	st := h.Snapshot()
	if st.Session.Active {
		t.Error("session still active after stopSession")
	}
	if st.Session.TransactionID != "" {
		t.Errorf("transaction ID %q not cleared after stopSession", st.Session.TransactionID)
	}

	snap = fake.snapshot()
	if len(snap.stops) != 1 {
		t.Fatalf("stops = %+v, want 1 StopTransaction call", snap.stops)
	}
	if snap.stops[0].transactionID != fake.startTransactionID {
		t.Errorf("StopTransaction transactionId = %d, want %d", snap.stops[0].transactionID, fake.startTransactionID)
	}
	if snap.stops[0].reason != core16.ReasonLocal {
		t.Errorf("StopTransaction reason = %s, want Local", snap.stops[0].reason)
	}
	if len(snap.stops[0].data) == 0 {
		t.Error("StopTransaction TransactionData is empty, want a final meter value")
	}
}

// assertMeasurands16 checks that a 1.6 MeterValue carries exactly the four
// measurands the task requires: Current.Import, Voltage,
// Energy.Active.Import.Register, SoC.
func assertMeasurands16(t *testing.T, mvs []types16.MeterValue) {
	t.Helper()
	if len(mvs) != 1 {
		t.Fatalf("MeterValue count = %d, want 1", len(mvs))
	}
	want := map[types16.Measurand]bool{
		types16.MeasurandCurrentImport:              false,
		types16.MeasurandVoltage:                    false,
		types16.MeasurandEnergyActiveImportRegister: false,
		types16.MeasurandSoC:                        false,
	}
	for _, sv := range mvs[0].SampledValue {
		if _, ok := want[sv.Measurand]; !ok {
			t.Errorf("unexpected measurand %s", sv.Measurand)
			continue
		}
		want[sv.Measurand] = true
		if _, err := strconv.ParseFloat(sv.Value, 64); err != nil {
			t.Errorf("measurand %s value %q is not numeric: %v", sv.Measurand, sv.Value, err)
		}
	}
	for m, seen := range want {
		if !seen {
			t.Errorf("missing measurand %s", m)
		}
	}
}

// TestOCPP16_SetChargingProfileAmpLimit verifies a TxDefaultProfile amp limit
// received via the real 1.6 SetChargingProfile handler throttles the
// simulated current draw exactly the way the 2.0.1 mode's received charging
// limit already does (TestFaultProfileReject/TestFaultApplyNextTx exercise
// the same handleSetChargingProfile core; this test exercises the 1.6 wire
// entry point on top of it).
func TestOCPP16_SetChargingProfileAmpLimit(t *testing.T) {
	fake := newFakeChargePoint16()
	batt := newEVBattery(60000, 50, 230, 32, 60)
	batt.SetCommandedA(32)
	_, o := newTestHandler16(fake, batt)

	req := &smartcharging16.SetChargingProfileRequest{
		ConnectorId: 1,
		ChargingProfile: &types16.ChargingProfile{
			ChargingProfileId:      7,
			StackLevel:             0,
			ChargingProfilePurpose: types16.ChargingProfilePurposeTxDefaultProfile,
			ChargingProfileKind:    types16.ChargingProfileKindAbsolute,
			ChargingSchedule: types16.NewChargingSchedule(types16.ChargingRateUnitAmperes,
				types16.NewChargingSchedulePeriod(0, 10)),
		},
	}
	resp, err := o.OnSetChargingProfile(req)
	if err != nil {
		t.Fatalf("OnSetChargingProfile: %v", err)
	}
	if resp.Status != smartcharging16.ChargingProfileStatusAccepted {
		t.Fatalf("status = %v, want Accepted", resp.Status)
	}
	if batt.commandedA != 10 {
		t.Fatalf("commandedA = %v, want 10 (throttled by received limit)", batt.commandedA)
	}
}

// TestOCPP16_ClearChargingProfileRestoresUnrestricted verifies
// ClearChargingProfile restores whatever "unrestricted" means for this sim —
// matching the pre-existing 2.0.1 behaviour exactly (SetCommandedA(0)).
func TestOCPP16_ClearChargingProfileRestoresUnrestricted(t *testing.T) {
	fake := newFakeChargePoint16()
	batt := newEVBattery(60000, 50, 230, 32, 60)
	batt.SetCommandedA(16)
	_, o := newTestHandler16(fake, batt)

	resp, err := o.OnClearChargingProfile(&smartcharging16.ClearChargingProfileRequest{})
	if err != nil {
		t.Fatalf("OnClearChargingProfile: %v", err)
	}
	if resp.Status != smartcharging16.ClearChargingProfileStatusAccepted {
		t.Fatalf("status = %v, want Accepted", resp.Status)
	}
	// "Unrestricted" means the EV resumes at its native hardware max, NOT
	// commandedA=0 — which Tick (battery.go) reads as SUSPEND (the bug this test
	// used to encode: a cleared charger left pinned near 0 A instead of
	// recovering to full — mayhem clear-profile-release / ocpp16-smart-charge).
	if batt.commandedA != batt.MaxCurrentA {
		t.Fatalf("commandedA after clear = %v, want %v (MaxCurrentA — released to native rate, not 0/suspend)", batt.commandedA, batt.MaxCurrentA)
	}
}

// TestOCPP16_TriggerMessage verifies OnTriggerMessage responds Accepted and
// then (re)sends the requested message type, as OCPP 1.6 defines — and
// NotImplemented for a message type this simulator doesn't emit.
func TestOCPP16_TriggerMessage(t *testing.T) {
	fake := newFakeChargePoint16()
	h, o := newTestHandler16(fake, newEVBattery(60000, 50, 230, 32, 60))
	h.setConnector(1, connAvailable)

	cases := []struct {
		name    string
		trigger remotetrigger16.MessageTrigger
		check   func() bool
	}{
		{
			name:    "BootNotification",
			trigger: core16.BootNotificationFeatureName,
			check:   func() bool { return len(fake.snapshot().boots) >= 1 },
		},
		{
			name:    "Heartbeat",
			trigger: core16.HeartbeatFeatureName,
			check:   func() bool { return fake.snapshot().heartbeats >= 1 },
		},
		{
			name:    "StatusNotification",
			trigger: core16.StatusNotificationFeatureName,
			check:   func() bool { return len(fake.snapshot().statuses) >= 1 },
		},
		{
			name:    "MeterValues",
			trigger: core16.MeterValuesFeatureName,
			check:   func() bool { return len(fake.snapshot().meterValues) >= 1 },
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := o.OnTriggerMessage(&remotetrigger16.TriggerMessageRequest{RequestedMessage: tc.trigger})
			if err != nil {
				t.Fatalf("OnTriggerMessage(%s): %v", tc.name, err)
			}
			if resp.Status != remotetrigger16.TriggerMessageStatusAccepted {
				t.Fatalf("status = %v, want Accepted", resp.Status)
			}
			waitFor(t, time.Second, tc.check, fmt.Sprintf("triggered %s to be sent", tc.name))
		})
	}

	// A message type this simulator doesn't emit -> NotImplemented, no
	// background send.
	resp, err := o.OnTriggerMessage(&remotetrigger16.TriggerMessageRequest{
		RequestedMessage: remotetrigger16.MessageTrigger("DiagnosticsStatusNotification"),
	})
	if err != nil {
		t.Fatalf("OnTriggerMessage(unsupported): %v", err)
	}
	if resp.Status != remotetrigger16.TriggerMessageStatusNotImplemented {
		t.Errorf("status = %v, want NotImplemented", resp.Status)
	}
}

// ── Live in-process CSMS smoke test ──────────────────────────────────────────
//
// The tests above fake the wire client to test ocpp16Proto/ocpp16Handlers'
// translation logic in isolation and fast. This test instead dials a REAL
// ocpp1.6 Central System over a real WebSocket (subprotocol negotiation,
// JSON encoding included) — mirroring TestSession_TransactionLifecycle's
// style for 2.0.1 — for end-to-end confidence in the actual wiring. It does
// not touch the shared lexa-proto/ocppserver package (2.0.1-only today); the
// stub CSMS lives entirely in this test file.

type centralSystem16Stub struct {
	mu    sync.Mutex
	boots int
}

func (s *centralSystem16Stub) OnAuthorize(string, *core16.AuthorizeRequest) (*core16.AuthorizeConfirmation, error) {
	return &core16.AuthorizeConfirmation{IdTagInfo: types16.NewIdTagInfo(types16.AuthorizationStatusAccepted)}, nil
}
func (s *centralSystem16Stub) OnBootNotification(csID string, req *core16.BootNotificationRequest) (*core16.BootNotificationConfirmation, error) {
	s.mu.Lock()
	s.boots++
	s.mu.Unlock()
	return core16.NewBootNotificationConfirmation(types16.NewDateTime(time.Now()), 60, core16.RegistrationStatusAccepted), nil
}
func (s *centralSystem16Stub) OnDataTransfer(string, *core16.DataTransferRequest) (*core16.DataTransferConfirmation, error) {
	return core16.NewDataTransferConfirmation(core16.DataTransferStatusAccepted), nil
}
func (s *centralSystem16Stub) OnHeartbeat(string, *core16.HeartbeatRequest) (*core16.HeartbeatConfirmation, error) {
	return core16.NewHeartbeatConfirmation(types16.NewDateTime(time.Now())), nil
}
func (s *centralSystem16Stub) OnMeterValues(string, *core16.MeterValuesRequest) (*core16.MeterValuesConfirmation, error) {
	return core16.NewMeterValuesConfirmation(), nil
}
func (s *centralSystem16Stub) OnStatusNotification(string, *core16.StatusNotificationRequest) (*core16.StatusNotificationConfirmation, error) {
	return &core16.StatusNotificationConfirmation{}, nil
}
func (s *centralSystem16Stub) OnStartTransaction(string, *core16.StartTransactionRequest) (*core16.StartTransactionConfirmation, error) {
	return core16.NewStartTransactionConfirmation(types16.NewIdTagInfo(types16.AuthorizationStatusAccepted), 99), nil
}
func (s *centralSystem16Stub) OnStopTransaction(string, *core16.StopTransactionRequest) (*core16.StopTransactionConfirmation, error) {
	return core16.NewStopTransactionConfirmation(), nil
}

// TestOCPP16Session_LiveCSMS boots and runs one short charging session over a
// real WebSocket connection to confirm the ocpp16.NewChargePoint /
// ocpp16.NewCentralSystem wiring (subprotocol negotiation, JSON encoding)
// actually works end to end, not just the fake-client unit tests above.
func TestOCPP16Session_LiveCSMS(t *testing.T) {
	port := freePort(t)
	stub := &centralSystem16Stub{}
	central := ocpp16.NewCentralSystem(nil, ws.NewServer())
	central.SetCoreHandler(stub)
	go central.Start(port, "/ocpp/{id}")
	defer central.Stop()

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 50*time.Millisecond)
		if err == nil {
			conn.Close()
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	url := fmt.Sprintf("ws://127.0.0.1:%d/ocpp", port)
	wsClient, err := newWSClient(url, "", "", "")
	if err != nil {
		t.Fatalf("newWSClient: %v", err)
	}
	cp := ocpp16.NewChargePoint("evsim-16-live", nil, wsClient)

	batt := newEVBattery(60000, 50, 230, 32, 60)
	h := &csHandler{
		stationID:       "evsim-16-live",
		csmsURL:         url,
		batt:            batt,
		meterInterval:   200 * time.Millisecond,
		sessionDuration: time.Minute,
	}
	h16 := &ocpp16Handlers{h: h}
	cp.SetCoreHandler(h16)
	cp.SetSmartChargingHandler(h16)
	cp.SetRemoteTriggerHandler(h16)

	if err := cp.Start(url); err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer cp.Stop()
	h.proto = newOCPP16Proto(cp)
	h.setConnector(1, connAvailable)

	boot, err := h.proto.Boot()
	if err != nil {
		t.Fatalf("Boot: %v", err)
	}
	if boot.Status != "Accepted" {
		t.Fatalf("boot status = %s, want Accepted", boot.Status)
	}

	h.startSession(1, time.Minute, trigCablePluggedIn, txStartOpts{})
	waitFor(t, time.Second, func() bool {
		st := h.Snapshot()
		return st.Session.Active && st.Session.TransactionID == "99"
	}, "session active with CSMS-assigned transaction ID 99")

	h.stopSession(stopLocal, trigStopAuthorized)
	if h.Snapshot().Session.Active {
		t.Error("session still active after stopSession")
	}

	stub.mu.Lock()
	boots := stub.boots
	stub.mu.Unlock()
	if boots < 1 {
		t.Error("stub CSMS never saw a BootNotification")
	}
}
