package aggregator

import (
	"errors"
	"fmt"
	"time"

	"lexa-proto/mbap"
)

// Raw Modbus ops over the mbaps session. Each surfaces a server exception as a
// *mbap.ExceptionError (the frame stays aligned, the connection stays usable —
// this is how a denied write reports exception 0x01 rather than a transport
// error, the discipline a false-PASS-free conformance driver depends on). Every
// other failure (a *FrameError, a TID mismatch, an I/O/deadline error) desyncs
// the stream: the op marks the connection broken so the next op redials, and
// returns the error wrapped (never resynchronizing by guessing — CODING_
// PRINCIPLES §3 MBAP strictness).

// ReadHolding reads count holding registers (FC 03) at addr from unit.
func (c *Conn) ReadHolding(unit uint8, addr, count uint16) ([]uint16, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return callT(c, func() ([]uint16, error) { return c.client.ReadHolding(unit, addr, count) })
}

// ReadInput reads count input registers (FC 04) at addr from unit. The gateway
// projects SunSpec into holding registers only, so this exists for completeness
// / conformance probes and typically answers exception 0x01.
func (c *Conn) ReadInput(unit uint8, addr, count uint16) ([]uint16, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return callT(c, func() ([]uint16, error) { return c.client.ReadInput(unit, addr, count) })
}

// WriteMultiple writes values to consecutive holding registers (FC 16) at addr
// on unit.
func (c *Conn) WriteMultiple(unit uint8, addr uint16, values []uint16) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	_, err := callT(c, func() ([]uint16, error) { return nil, c.client.WriteMultiple(unit, addr, values) })
	return err
}

// WriteSingle writes one holding register (FC 06) at addr on unit.
func (c *Conn) WriteSingle(unit uint8, addr, value uint16) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	_, err := callT(c, func() ([]uint16, error) { return nil, c.client.WriteSingle(unit, addr, value) })
	return err
}

// callT runs a single mbap op under c.mu with a per-op deadline, one immediate
// redial if the connection is already broken, and exception-vs-transport error
// classification. The caller holds c.mu.
func callT[T any](c *Conn, op func() (T, error)) (T, error) {
	var zero T
	if err := c.ensureConn(); err != nil {
		return zero, err
	}
	// Arm the per-op deadline (mbap.Client sets none). A failure to arm it would
	// leave the wolfSSL read/write unbounded, so fail closed and mark the session
	// broken (the fd is suspect) rather than proceed without a timeout
	// (CODING_PRINCIPLES §6 — every network wait is bounded).
	if err := c.sess.Conn.SetDeadline(time.Now().Add(c.opTimeout)); err != nil {
		c.broken = true
		return zero, fmt.Errorf("aggregator: arm op deadline on %s: %w", c.addr, err)
	}
	v, err := op()
	// Clearing is best-effort: the next op re-arms a fresh deadline regardless, so
	// a failed clear cannot leak an earlier window into a later op.
	_ = c.sess.Conn.SetDeadline(time.Time{})

	if err == nil {
		return v, nil
	}
	// A protocol exception is a valid answer: the connection is still frame-
	// aligned. Return it verbatim so callers can assert on the code.
	var ex *mbap.ExceptionError
	if errors.As(err, &ex) {
		return zero, err
	}
	// Anything else desyncs the stream — this session cannot be trusted.
	c.broken = true
	return zero, fmt.Errorf("aggregator: %s op on %s: %w", c.role, c.addr, err)
}

// ensureConn makes sure a usable client exists, performing one immediate
// (sleepless) redial if the session was previously marked broken. Callers that
// want to wait out an outage use Reconnect instead. Caller holds c.mu.
func (c *Conn) ensureConn() error {
	if c.client != nil && !c.broken {
		return nil
	}
	if err := c.redial(); err != nil {
		return fmt.Errorf("aggregator: reconnect %s as %s: %w", c.addr, c.role, err)
	}
	return nil
}

// AsException returns the *mbap.ExceptionError an op error carries, and ok=false
// for a nil or non-exception (transport) error. A convenience for callers
// building negative assertions (the denial primitive, T06.8 probes) without
// reimplementing the errors.As dance.
func AsException(err error) (*mbap.ExceptionError, bool) {
	if err == nil {
		return nil, false
	}
	var ex *mbap.ExceptionError
	if errors.As(err, &ex) {
		return ex, true
	}
	return nil, false
}
