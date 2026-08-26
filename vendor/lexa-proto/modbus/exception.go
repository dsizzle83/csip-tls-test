package modbus

import (
	"errors"
	"fmt"
)

// exception.go — the TRANSPORT-LEVEL Modbus exception response, made
// observable (MODBUS-CLIENT-EXCEPTION-CODE-NOT-OBSERVABLE, registered
// 2026-08-26; SS-MODBUS-CLIENT-CONF-v1.1 §2.9.2 ERR-2 "accurately log all
// exception codes").
//
// THE DEFECT THIS CLOSES. A Modbus exception response is the server telling
// the client, in one byte, exactly WHY it declined a transaction. Until this
// file existed that byte was thrown away twice over on the plain-scheme path:
// the vendored client (github.com/simonvetter/modbus, modbus.go's
// mapExceptionCodeToError) turns the code into one of nine package-level
// STRING sentinels — `Error("illegal data address")` — and every layer above
// it (sunspec's %w wraps, lexa-gw's retryDevice, the reconciler shells)
// treated that string as an opaque transport failure. Nothing branched on the
// code, no journal event named it, and the operator-visible result of a
// device answering ILLEGAL DATA ADDRESS was a line saying the device was
// unavailable. "Which code did it send?" had no answer anywhere in the
// product.
//
// WHY THE ANSWER LIVES HERE and not in mbap. There are two southbound client
// implementations behind the one Transport interface this package defines —
// the vendored client below (tcp/rtu/rtuovertcp) and lexa-gw's
// mbapstransport over lexa-proto/mbap (mbaps://) — and a consumer that must
// decide "did the DEVICE refuse this, or did the LINK fail?" cannot be made
// to ask a different question of each. So the type every consumer matches on
// is defined at the seam they all share: this package. mbap keeps its own
// framing-layer *ExceptionError (the decode result of an exception PDU,
// carrying the code and nothing else) untouched; the mbaps transport
// translates that into this type at the point where the request's unit id,
// function code, address and count are actually known.
//
// WHAT IT CARRIES, and why each field is load-bearing rather than decorative:
//
//	UnitID   which unit on the bus answered. On a shared RS-485 line or
//	         through a Modbus gateway this is the difference between "the DER
//	         refused" and "the gateway cannot reach the DER".
//	FC       which function was refused. ILLEGAL FUNCTION against FC 16 on a
//	         device that answers FC 03 is a read-only register map, not a
//	         dead device.
//	Addr,    the exact register window. A refusal is a statement ABOUT AN
//	Count    ADDRESS RANGE; without it the log says a device said no and not
//	         what it said no to, which is the difference between a diagnosis
//	         and a shrug.
//	code     the byte itself, so the number and the spec's own name for it
//	         can both be reported.
//
// SESSION POLICY — the second half of the finding, and the reason Refused
// exists. See its doc comment.
//
// The two-word summary of the whole file: a Modbus exception is an ANSWER.

// ExceptionCode is a Modbus exception code as carried in the second byte of an
// exception-response PDU (MODBUS Application Protocol V1.1b3 §7).
//
// The named constants are the assigned codes 0x01..0x0B. 0x07 (NEGATIVE
// ACKNOWLEDGE) and 0x09 are not assigned in V1.1b3's table for the function
// codes this product speaks and have no constant; a device that sends one
// still round-trips through this type — Name renders it as UNKNOWN(0x..)
// rather than losing it.
type ExceptionCode uint8

// The assigned Modbus exception codes.
//
// These deliberately mirror lexa-proto/mbap's ExCode constants, which are the
// SERVER side of the same table (lexa-gw's northbound mbaps server chooses
// which code to answer with). The two sets are asserted equal, code for code,
// by TestExceptionCodesAgreeWithMBAP — one wire vocabulary, checked, rather
// than two that drift.
const (
	ExIllegalFunction ExceptionCode = 0x01 // the server does not implement this function code
	ExIllegalAddress  ExceptionCode = 0x02 // the register range is not one the server serves
	ExIllegalValue    ExceptionCode = 0x03 // the request's own parameters are refused
	ExDeviceFailure   ExceptionCode = 0x04 // unrecoverable error while performing the action
	ExAcknowledge     ExceptionCode = 0x05 // accepted, will take a long time (poll for completion)
	ExServerBusy      ExceptionCode = 0x06 // engaged with a long-duration program command
	ExMemoryParity    ExceptionCode = 0x08 // extended file-record parity failure
	ExGatewayPath     ExceptionCode = 0x0A // gateway misconfigured or overloaded
	ExGatewayTarget   ExceptionCode = 0x0B // gateway reached, target unit did not answer
)

// exceptionNames is the spec's own name for each assigned code.
//
// The strings are the SPECIFICATION's wording, deliberately, because they are
// what a conformance reader greps for: the SS-MODBUS-CLIENT ERR-2 procedure
// asks that the client "accurately log all exception codes", and the bench
// harness matches a log line against the spec name of the code it armed
// (csip-tls-test internal/certify/suitemodbusclient/modbuswire.go's
// exceptionNames, case-insensitively). Rewording one of these silently breaks
// a conformance row; TestExceptionNamesMatchTheSpecTable pins them.
var exceptionNames = map[ExceptionCode]string{
	ExIllegalFunction: "illegal function",
	ExIllegalAddress:  "illegal data address",
	ExIllegalValue:    "illegal data value",
	ExDeviceFailure:   "server device failure",
	ExAcknowledge:     "acknowledge",
	ExServerBusy:      "server device busy",
	ExMemoryParity:    "memory parity error",
	ExGatewayPath:     "gateway path unavailable",
	ExGatewayTarget:   "gateway target device failed to respond",
}

// Name returns the specification's name for the code, or UNKNOWN(0x..) for a
// code the spec does not assign. Never empty — a name is what makes the code
// legible in a log line, and an unassigned code is exactly the case where the
// reader most needs to be told a number rather than nothing.
func (c ExceptionCode) Name() string {
	if n, ok := exceptionNames[c]; ok {
		return n
	}
	return fmt.Sprintf("UNKNOWN(0x%02x)", uint8(c))
}

// String renders the code the way a log line wants it: number and name.
func (c ExceptionCode) String() string { return fmt.Sprintf("0x%02x %s", uint8(c), c.Name()) }

// Refused reports whether this code means THE SERVER ANSWERED AND DECLINED,
// as opposed to THE SERVER OR ITS PATH FAILED.
//
// This is the cut the session policy is made on, and it is a statement about
// the Modbus protocol rather than a local convention:
//
//	0x01 ILLEGAL FUNCTION      the server parsed the request, understood it,
//	0x02 ILLEGAL DATA ADDRESS  and declined it on its own terms. §7's own
//	0x03 ILLEGAL DATA VALUE    words for these three are that the function
//	                           code / address / value "is not an allowable"
//	                           one for the server — a verdict about the
//	                           REQUEST. The spec requires the server to take
//	                           NO ACTION when it answers one, so no register
//	                           moved, and the connection that carried the
//	                           answer is by construction still frame-aligned
//	                           and still healthy.
//
//	everything else            0x04 SERVER DEVICE FAILURE is an unrecoverable
//	                           error DURING the action (so a register may well
//	                           have moved); 0x0A/0x0B are a gateway saying the
//	                           path or the target is not there; 0x05/0x06 say
//	                           the server is busy; 0x08 is a memory fault. None
//	                           is a verdict about the request, and none is
//	                           evidence the device is in a state this client
//	                           can go on assuming.
//
// A consumer sorting "the session is bad, tear it down" from "the device
// answered fine and declined" must put the first three in the SECOND class.
// Sorting them into the first produces the pathology lexa-gw's
// cmd/modbus/session_class.go documents at length for derbase refusals — a
// healthy device, a healthy link, a deterministic refusal, and a Modbus
// session rebuilt on every poll for as long as the condition lasts — reached
// this time through the wire instead of through a local encode.
func (c ExceptionCode) Refused() bool {
	return c == ExIllegalFunction || c == ExIllegalAddress || c == ExIllegalValue
}

// ErrException is the sentinel every exception response unwraps to, so a
// caller can ask "was this an exception at all?" with errors.Is without
// naming the concrete type.
var ErrException = errors.New("modbus: server answered with an exception response")

// ExceptionError is a Modbus exception response, with the request that
// provoked it.
//
// It is returned by every Transport implementation in place of the vendored
// client's opaque string sentinels, and it is errors.As-able through the
// arbitrarily deep %w chains sunspec, derbase and lexa-gw's device wrappers
// build over a single register read.
//
// The code is unexported and reached through Code so the type can offer both
// the raw byte (what a metric and a wire-level report want) and the typed
// value (what a policy decision wants) without one shadowing the other.
// Construct with NewExceptionError.
type ExceptionError struct {
	// UnitID is the Modbus unit the request was addressed to.
	UnitID uint8
	// FC is the function code of the REQUEST (0x03/0x04/0x06/0x10) — not the
	// 0x80-flagged code the exception response carries.
	FC uint8
	// Addr is the first register the request named.
	Addr uint16
	// Count is how many registers it named. For a write this is the number of
	// values that were NOT written.
	Count uint16

	code ExceptionCode
}

// NewExceptionError builds an ExceptionError for a request that was answered
// with code.
func NewExceptionError(unitID, fc uint8, addr, count uint16, code ExceptionCode) *ExceptionError {
	return &ExceptionError{UnitID: unitID, FC: fc, Addr: addr, Count: count, code: code}
}

// Code returns the raw exception-code byte.
func (e *ExceptionError) Code() uint8 { return uint8(e.code) }

// Exception returns the typed exception code.
func (e *ExceptionError) Exception() ExceptionCode { return e.code }

// CodeName returns the specification's name for the code (see
// ExceptionCode.Name).
func (e *ExceptionError) CodeName() string { return e.code.Name() }

// Refused reports whether the server ANSWERED AND DECLINED, rather than
// failing (see ExceptionCode.Refused — the session policy is made on this).
func (e *ExceptionError) Refused() bool { return e.code.Refused() }

func (e *ExceptionError) Error() string {
	return fmt.Sprintf("modbus: unit %d fc 0x%02x at %d+%d: exception %s",
		e.UnitID, e.FC, e.Addr, e.Count, e.code)
}

// Unwrap makes errors.Is(err, ErrException) true for every exception
// response, at any wrapping depth.
func (e *ExceptionError) Unwrap() error { return ErrException }

// AsException reports whether err carries a Modbus exception response
// anywhere in its chain, returning it when it does.
//
// A convenience over errors.As for the many call sites that want the code
// itself rather than just the fact — and a single place to look for every
// consumer of the class.
func AsException(err error) (*ExceptionError, bool) {
	var e *ExceptionError
	if errors.As(err, &e) {
		return e, true
	}
	return nil, false
}

// RefusedException reports whether err is an exception response the SERVER
// ANSWERED with — 0x01/0x02/0x03 — as opposed to a device/gateway fault or
// any other error.
//
// This is the predicate a session-health classifier wants: true means the
// transaction was declined, no register moved, and the connection is still
// good. It answers false for nil, for a non-exception error, and for the
// fault-class codes.
func RefusedException(err error) bool {
	e, ok := AsException(err)
	return ok && e.Refused()
}
