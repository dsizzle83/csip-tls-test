// Package inverter implements device.Device for SunSpec-compliant grid-tied
// inverters covering both legacy SunSpec models (101/102/103, 121, 123) and
// the IEEE 1547-2018 SunSpec Modbus profile (701-712).
package inverter

import (
	"fmt"
	"time"

	"csip-tls-test/internal/southbound/derbase"
	"csip-tls-test/internal/southbound/device"
	model "lexa-proto/csipmodel"
	"lexa-proto/modbus"
	"lexa-proto/sunspec"
)

const tag = "inverter"

// Inverter implements device.Device for a SunSpec inverter over Modbus.
type Inverter struct {
	derbase.Base
	transport modbus.Transport
}

// New opens a Modbus connection, scans SunSpec models, and returns an Inverter.
func New(url string, timeout time.Duration, unitID uint8) (*Inverter, error) {
	t, err := modbus.NewTransport(url, timeout)
	if err != nil {
		return nil, err
	}
	if err := t.Open(); err != nil {
		return nil, fmt.Errorf("inverter: open %s: %w", url, err)
	}
	if err := t.SetUnitID(unitID); err != nil {
		t.Close()
		return nil, fmt.Errorf("inverter: set unit id %d: %w", unitID, err)
	}
	inv, err := newFromTransport(t)
	if err != nil {
		t.Close()
		return nil, err
	}
	return inv, nil
}

func newFromTransport(t modbus.Transport) (*Inverter, error) {
	r, err := sunspec.NewReader(t)
	if err != nil {
		return nil, fmt.Errorf("inverter: scan SunSpec blocks: %w", err)
	}
	base, err := derbase.Init(r, tag)
	if err != nil {
		return nil, err
	}
	return &Inverter{Base: base, transport: t}, nil
}

func (inv *Inverter) Close() error {
	return inv.transport.Close()
}

func (inv *Inverter) ReadMeasurements() (device.Measurements, error) {
	regs, err := inv.Reader.ReadModel(inv.MeasModel)
	if err != nil {
		return device.Measurements{}, fmt.Errorf("inverter: read model %d: %w", inv.MeasModel, err)
	}
	if inv.MeasModel == sunspec.ModelDERMeasureAC {
		return derbase.ReadMeasurementsM701(regs), nil
	}
	return derbase.ReadMeasurementsACModel(regs), nil
}

// Status reads the operating state from the inverter.
func (inv *Inverter) Status() (device.DeviceStatus, error) {
	regs, err := inv.Reader.ReadModel(inv.MeasModel)
	if err != nil {
		return device.DeviceStatus{}, fmt.Errorf("inverter: read status: %w", err)
	}
	if inv.MeasModel == sunspec.ModelDERMeasureAC {
		ac := sunspec.Parse701(regs)
		st := int(ac.St)
		return device.DeviceStatus{
			Connected: ac.ConnSt == 1,
			Energized: st == derbase.M701StOn || st == derbase.M701StThrottled || st == derbase.M701StStarting,
		}, nil
	}
	if len(regs) <= sunspec.M103_St {
		return device.DeviceStatus{}, fmt.Errorf("inverter: model %d too short for St", inv.MeasModel)
	}
	st := regs[sunspec.M103_St]
	return device.DeviceStatus{
		Connected: st == 4 || st == 5,
		Energized: st >= 3 && st <= 6,
	}, nil
}

func (inv *Inverter) ApplyControl(ctrl model.DERControlBase) error {
	return inv.Base.ApplyControl(ctrl, tag)
}

// Note: the old bench fork also delegated a wider IEEE 1547-2018 read/write
// surface (M702/705-712) here. Those derbase methods had zero callers beyond
// this pass-through and zero test coverage; removed along with their derbase
// counterparts rather than re-implemented against the shared codec's
// differently-shaped curve-write workflow (TASK-021; disposal is TASK-082).
