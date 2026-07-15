package main

import "time"

// This file defines the wire boundary between the protocol-agnostic
// simulation core (battery.go, state.go, session.go) and one concrete OCPP
// version. ocpp201Proto (ocpp201.go) and ocpp16Proto (ocpp16.go) are the two
// implementations of chargerProto; main.go picks one based on -proto.
//
// evsim is a protocol ADAPTER over one simulated device: the battery physics,
// session state machine, fault injectors, and HTTP control API are shared
// verbatim by both protocol versions. Only the wire encoding differs, and
// that difference is confined to this interface + its two implementations.

// connStatus is a protocol-neutral connector/EVSE status, spelled using OCPP
// 2.0.1's five-value ConnectorStatus vocabulary (Available/Occupied/Reserved/
// Unavailable/Faulted) since that is the simpler of the two protocols'
// status enums. ocpp16Proto.Status maps the one value 1.6 lacks (Occupied)
// onto ChargePointStatusCharging; every other value's string spelling is
// shared verbatim by both protocols' wire enums.
type connStatus string

const (
	connAvailable   connStatus = "Available"
	connOccupied    connStatus = "Occupied"
	connReserved    connStatus = "Reserved"
	connUnavailable connStatus = "Unavailable"
	connFaulted     connStatus = "Faulted"
)

// sessionTrigger is the protocol-neutral reason a transaction-lifecycle
// message is being sent. OCPP 2.0.1 carries this on the wire directly
// (TransactionEventRequest.TriggerReason); OCPP 1.6's StartTransaction/
// StopTransaction/MeterValues have no such field, so ocpp16Proto only uses it
// for logging.
type sessionTrigger int

const (
	trigCablePluggedIn sessionTrigger = iota
	trigAuthorized
	trigRemoteStart
	trigRemoteStop
	trigStopAuthorized
	trigChargingStateChanged
	trigResetCommand
	trigMeterValuePeriodic
	trigChargingRateChanged
	trigTimeLimitReached
)

func (t sessionTrigger) String() string {
	switch t {
	case trigCablePluggedIn:
		return "CablePluggedIn"
	case trigAuthorized:
		return "Authorized"
	case trigRemoteStart:
		return "RemoteStart"
	case trigRemoteStop:
		return "RemoteStop"
	case trigStopAuthorized:
		return "StopAuthorized"
	case trigChargingStateChanged:
		return "ChargingStateChanged"
	case trigResetCommand:
		return "ResetCommand"
	case trigMeterValuePeriodic:
		return "MeterValuePeriodic"
	case trigChargingRateChanged:
		return "ChargingRateChanged"
	case trigTimeLimitReached:
		return "TimeLimitReached"
	default:
		return "Unknown"
	}
}

// stopReason is the protocol-neutral reason a transaction ended, translated
// to each protocol's native "reason" enum on the Ended/StopTransaction
// message. OCPP 1.6's Reason enum is coarser than 2.0.1's — see
// ocpp16.go's reasonToOCPP16 for the lossy cases.
type stopReason int

const (
	stopLocal stopReason = iota
	stopRemote
	stopSOCLimitReached
	stopTimeLimitReached
	stopImmediateReset
)

func (r stopReason) String() string {
	switch r {
	case stopLocal:
		return "Local"
	case stopRemote:
		return "Remote"
	case stopSOCLimitReached:
		return "SOCLimitReached"
	case stopTimeLimitReached:
		return "TimeLimitReached"
	case stopImmediateReset:
		return "ImmediateReset"
	default:
		return "Unknown"
	}
}

// meterSample is a snapshot of the evBattery's simulated physics at one
// instant, computed once (csHandler.sample, in state.go) and handed to
// whichever protocol adapter is active — so the SoC/current-draw/wrong-units
// math lives in exactly one place regardless of OCPP version.
type meterSample struct {
	SOC      float64 // %
	CurrentA float64 // A, post wrong_units multiplier (the "reported" value)
	PowerW   float64 // W, derived from the reported current
	EnergyWh float64 // Wh, cumulative this session
	VoltageV float64
}

// txStartOpts carries the protocol-specific bits needed to start a
// transaction that don't fit the shared enums above: 2.0.1's numeric
// RemoteStartID (RequestStartTransactionRequest) vs 1.6's idTag string
// (StartTransactionRequest.IdTag, required on every 1.6 transaction).
type txStartOpts struct {
	RemoteStartID *int   // 2.0.1 remote-start correlation ID; nil for locally/GUI-triggered sessions
	IDTag         string // 1.6 idTag; "" -> adapter default
}

// bootInfo is what BootNotification's confirmation carries that the shared
// main loop / reset handling cares about.
type bootInfo struct {
	Status   string
	Interval time.Duration
}

// chargerProto is the wire boundary the protocol-agnostic simulation core
// talks to.
type chargerProto interface {
	IsConnected() bool
	Stop()

	Boot() (bootInfo, error)
	Heartbeat() error
	Status(connectorID int, status connStatus) error

	// TxStart begins a transaction on connectorID and returns the ID to
	// display/log (self-generated for 2.0.1, CSMS-assigned for 1.6).
	TxStart(connectorID int, trigger sessionTrigger, opts txStartOpts, m meterSample) (txID string)
	// TxUpdate reports a meter sample against the transaction TxStart began.
	TxUpdate(trigger sessionTrigger, m meterSample)
	// TxEnd closes the transaction TxStart began.
	TxEnd(trigger sessionTrigger, reason stopReason, startedAt time.Time, m meterSample)

	// MeterValuesIdle reports a meter sample with no transaction context
	// (TriggerMessage while idle, or a connector with no live session).
	MeterValuesIdle(connectorID int, m meterSample)
}
