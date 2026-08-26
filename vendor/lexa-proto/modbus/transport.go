// Package modbus provides a transport-layer abstraction for Modbus register
// access. Higher-level packages (sunspec, inverter) program against the
// Transport interface, not against a specific physical medium.
//
// The physical medium is selected by the URL passed to NewTransport:
//
//	"tcp://192.168.1.100:502"        — Modbus/TCP
//	"rtu:///dev/ttyUSB0"             — Modbus RTU over RS-485
//	"rtuovertcp://192.168.1.100:502" — RTU framing over TCP
//
// Adding a new physical layer means implementing Transport — no changes
// needed in the sunspec or inverter packages.
package modbus

import (
	"errors"
	"fmt"
	"sync/atomic"
	"time"

	modbuslib "github.com/simonvetter/modbus"
)

// The Modbus function codes this package's Transport operations issue. They
// are reported on an ExceptionError so a refusal names WHICH function the
// server declined, and they mirror lexa-proto/mbap's FC constants (the server
// side of the same table) code for code — asserted by
// TestFunctionCodesAgreeWithMBAP rather than left to drift.
const (
	FCReadHolding   uint8 = 0x03 // ReadHolding
	FCReadInput     uint8 = 0x04 // ReadInput
	FCWriteMultiple uint8 = 0x10 // WriteHolding
)

// Transport abstracts Modbus register access. Implementations are decoupled
// from any particular physical medium.
//
// # Error contract
//
// A server that ANSWERS a request with a Modbus exception response MUST be
// reported as an *ExceptionError carrying the code and the request that
// provoked it (see exception.go). Every other failure — a broken pipe, a
// deadline, a malformed frame — is returned as whatever the implementation's
// underlying layer produced.
//
// That distinction is a requirement of this interface rather than an
// implementation detail, because callers classify SESSION HEALTH from it: it
// is what lets a caller tell "the device declined this transaction, and the
// link is fine" from "the link is gone". lexa-gw's
// cmd/modbus/session_class.go is the classifier that depends on it.
type Transport interface {
	// Open establishes the connection. Must be called before any register op.
	Open() error
	// Close releases the connection.
	Close() error
	// SetUnitID selects the target slave/unit (default 1 for most devices).
	SetUnitID(id uint8) error
	// ReadHolding reads quantity holding registers starting at addr (0-based).
	ReadHolding(addr, quantity uint16) ([]uint16, error)
	// WriteHolding writes values to holding registers starting at addr.
	WriteHolding(addr uint16, values []uint16) error
	// ReadInput reads quantity input registers starting at addr (0-based).
	ReadInput(addr, quantity uint16) ([]uint16, error)
}

// client wraps a simonvetter ModbusClient to implement Transport.
//
// unitID mirrors the unit id handed to SetUnitID. The vendored client keeps
// its own copy and offers no getter, so this one exists purely so an
// ExceptionError can name the unit that answered — which on a shared RS-485
// line or behind a Modbus gateway is the difference between "the DER refused"
// and "the gateway cannot reach the DER".
//
// Atomic rather than a plain field: the vendored client is internally locked
// and has therefore always tolerated a caller that shares one Transport
// between goroutines, and a mirror field added underneath it must not be the
// thing that turns that into a data race. It is a uint32 because that is the
// narrowest atomic Go offers; the value is always a uint8.
type client struct {
	inner  *modbuslib.ModbusClient
	unitID atomic.Uint32
}

// newClient wraps mc with the unit id defaulted to the vendored client's own
// default (client.go's NewClient sets mc.unitId = 1), so the unit reported on
// an ExceptionError is correct for a caller that never calls SetUnitID.
func newClient(mc *modbuslib.ModbusClient) *client {
	c := &client{inner: mc}
	c.unitID.Store(1)
	return c
}

// NewTransport creates a Transport using the given Modbus URL and per-request
// timeout. The returned Transport is not connected — call Open() before use.
func NewTransport(url string, timeout time.Duration) (Transport, error) {
	mc, err := modbuslib.NewClient(&modbuslib.ClientConfiguration{
		URL:     url,
		Timeout: timeout,
	})
	if err != nil {
		return nil, fmt.Errorf("modbus: new client %q: %w", url, err)
	}
	return newClient(mc), nil
}

// NewSerialTransport creates a Modbus RTU (serial) Transport bound to an
// explicit line speed. It exists because the RTU baud rate is a property of
// the serial connection, not of the URL: the underlying client library reads
// the speed from its configuration, never from the URL string, so a Transport
// built with NewTransport always runs at the library default (19200 bps).
// Commissioning bus-sweeps that try several bauds need this constructor to
// reopen the port at each speed. url must be an "rtu://" (or "rtuovertcp://")
// URL; the returned Transport is not connected — call Open() before use.
func NewSerialTransport(url string, speedBps int, timeout time.Duration) (Transport, error) {
	if speedBps <= 0 {
		return nil, fmt.Errorf("modbus: serial transport %q: invalid speed %d bps", url, speedBps)
	}
	mc, err := modbuslib.NewClient(&modbuslib.ClientConfiguration{
		URL:     url,
		Speed:   uint(speedBps),
		Timeout: timeout,
	})
	if err != nil {
		return nil, fmt.Errorf("modbus: new serial client %q @ %d bps: %w", url, speedBps, err)
	}
	return newClient(mc), nil
}

func (c *client) Open() error {
	return c.inner.Open()
}

func (c *client) Close() error {
	return c.inner.Close()
}

func (c *client) SetUnitID(id uint8) error {
	if err := c.inner.SetUnitId(id); err != nil {
		return err
	}
	c.unitID.Store(uint32(id))
	return nil
}

func (c *client) ReadHolding(addr, quantity uint16) ([]uint16, error) {
	v, err := c.inner.ReadRegisters(addr, quantity, modbuslib.HOLDING_REGISTER)
	return v, c.exception(FCReadHolding, addr, quantity, err)
}

func (c *client) WriteHolding(addr uint16, values []uint16) error {
	err := c.inner.WriteRegisters(addr, values)
	return c.exception(FCWriteMultiple, addr, uint16(len(values)), err)
}

func (c *client) ReadInput(addr, quantity uint16) ([]uint16, error) {
	v, err := c.inner.ReadRegisters(addr, quantity, modbuslib.INPUT_REGISTER)
	return v, c.exception(FCReadInput, addr, quantity, err)
}

// exception restores the Modbus exception CODE the vendored client threw away.
//
// github.com/simonvetter/modbus decodes an exception response and then maps
// the code to one of nine package-level string sentinels (modbus.go's
// mapExceptionCodeToError), so by the time the error reaches this wrapper the
// byte is gone and every caller above sees an opaque transport failure. This
// function is the exact inverse of that table — the vendored source is
// PINNED (go.mod + vendor/), so the mapping is total and stable, and
// TestExceptionMapsEveryVendoredSentinel asserts every one of the nine is
// covered rather than trusting the switch to have stayed complete.
//
// err values that are not exception responses (dial failures, deadlines,
// framing errors, bad CRCs) pass through UNTOUCHED and unwrapped: this
// function's whole job is to name the one class it can name, and a wrapper
// around everything else would only make a transport fault harder to read.
func (c *client) exception(fc uint8, addr, count uint16, err error) error {
	if err == nil {
		return nil
	}
	code, ok := exceptionCodeOf(err)
	if !ok {
		return err
	}
	return NewExceptionError(uint8(c.unitID.Load()), fc, addr, count, code)
}

// exceptionCodeOf recovers the exception code from a vendored-client error.
//
// The nine assigned codes are recovered by sentinel identity — the vendored
// Error type is a string constant, so errors.Is compares by value and no text
// is examined.
func exceptionCodeOf(err error) (ExceptionCode, bool) {
	switch {
	case errors.Is(err, modbuslib.ErrIllegalFunction):
		return ExIllegalFunction, true
	case errors.Is(err, modbuslib.ErrIllegalDataAddress):
		return ExIllegalAddress, true
	case errors.Is(err, modbuslib.ErrIllegalDataValue):
		return ExIllegalValue, true
	case errors.Is(err, modbuslib.ErrServerDeviceFailure):
		return ExDeviceFailure, true
	case errors.Is(err, modbuslib.ErrAcknowledge):
		return ExAcknowledge, true
	case errors.Is(err, modbuslib.ErrServerDeviceBusy):
		return ExServerBusy, true
	case errors.Is(err, modbuslib.ErrMemoryParityError):
		return ExMemoryParity, true
	case errors.Is(err, modbuslib.ErrGWPathUnavailable):
		return ExGatewayPath, true
	case errors.Is(err, modbuslib.ErrGWTargetFailedToRespond):
		return ExGatewayTarget, true
	}
	return unassignedExceptionCode(err)
}

// libUnassignedExceptionFormat is the vendored client's message for an
// exception code its own table does not name — modbus.go's
// mapExceptionCodeToError default arm, verbatim:
//
//	err = fmt.Errorf("unknown exception code (%v)", exceptionCode)
//
// It is the ONE place this package reads a vendored error's TEXT, and it is
// deliberate rather than lazy: the code byte reached the vendored library and
// was formatted into a string instead of being carried, there is no other
// route to it (the decode is unexported and the value is not retained), and
// "the device sent 0x0C and we cannot say so" is precisely the failure
// SS-MODBUS-CLIENT §2.9.2's "accurately log ALL exception codes" is about. The
// vendored source is pinned in go.mod and vendored in the consuming repo, so
// the format cannot change under us without a module bump; the parse is
// asserted against this literal by TestUnassignedExceptionCodeParsesTheVendoredFormat.
const libUnassignedExceptionFormat = "unknown exception code (%d)"

// unassignedExceptionCode recovers the code from the vendored client's
// unknown-code message (see libUnassignedExceptionFormat). Anything else —
// including an error that merely resembles it — returns false and is left
// alone as an ordinary transport failure.
func unassignedExceptionCode(err error) (ExceptionCode, bool) {
	var code uint8
	n, serr := fmt.Sscanf(err.Error(), libUnassignedExceptionFormat, &code)
	if serr != nil || n != 1 {
		return 0, false
	}
	// Sscanf stops at the closing paren's mismatch only if trailing text
	// differs; re-render and compare so a message that merely STARTS the same
	// way is not mistaken for the vendored one.
	if fmt.Sprintf(libUnassignedExceptionFormat, code) != err.Error() {
		return 0, false
	}
	return ExceptionCode(code), true
}
