package aggregator

import (
	"sync"

	"lexa-proto/modbus"
)

// transport adapts a Conn (mbap.Client over an mbtls.Session) to
// lexa-proto/modbus.Transport, so the whole SunSpec codec — sunspec.NewReader,
// Scan, ReadCommon, ReadModel/WriteModel, HasModel — drives the mbaps session
// unchanged, with no bespoke decode in the emulator (the reuse T06.4/T06.5 ask
// for). The unit id is bound per-transport via SetUnitID (the Transport contract
// carries no unit on each call); every register op delegates to the Conn's raw
// ops, which own deadlines, reconnect, and exception-vs-transport classification.
type transport struct {
	c *Conn

	mu   sync.Mutex
	unit uint8
}

// Transport returns a modbus.Transport bound to this connection, initially
// targeting unit 1. Each call returns an independent adapter, so a discovery
// walk can hold one transport per unit without cross-talk; the underlying Conn
// still serializes all I/O.
func (c *Conn) Transport() modbus.Transport {
	return &transport{c: c, unit: 1}
}

// transportForUnit returns a transport already bound to unit.
func (c *Conn) transportForUnit(unit uint8) modbus.Transport {
	return &transport{c: c, unit: unit}
}

// Open is a no-op: the Conn is dialed by ConnectAs and its lifecycle is owned by
// Conn.Close, not by the codec that borrows this transport.
func (t *transport) Open() error { return nil }

// Close is a no-op for the same reason — closing here would tear down a session
// the Conn may still be using for other units. Use Conn.Close.
func (t *transport) Close() error { return nil }

// SetUnitID selects the target unit (the gateway's southbound routing key).
func (t *transport) SetUnitID(id uint8) error {
	t.mu.Lock()
	t.unit = id
	t.mu.Unlock()
	return nil
}

func (t *transport) unitID() uint8 {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.unit
}

// ReadHolding reads quantity holding registers at addr from the bound unit.
func (t *transport) ReadHolding(addr, quantity uint16) ([]uint16, error) {
	return t.c.ReadHolding(t.unitID(), addr, quantity)
}

// WriteHolding writes values to holding registers at addr on the bound unit.
func (t *transport) WriteHolding(addr uint16, values []uint16) error {
	return t.c.WriteMultiple(t.unitID(), addr, values)
}

// ReadInput reads quantity input registers at addr from the bound unit.
func (t *transport) ReadInput(addr, quantity uint16) ([]uint16, error) {
	return t.c.ReadInput(t.unitID(), addr, quantity)
}
