// Package battery implements device.Device for SunSpec-compliant battery
// storage systems covering both legacy SunSpec models (101/102/103, 121, 123,
// 802) and the IEEE 1547-2018 SunSpec Modbus profile (701-713).
package battery

import (
	"fmt"
	"time"

	"csip-tls-test/internal/southbound/derbase"
	"csip-tls-test/internal/southbound/device"
	model "lexa-proto/csipmodel"
	"lexa-proto/modbus"
	"lexa-proto/sunspec"
)

const tag = "battery"

// Battery implements device.Device for a SunSpec battery storage system.
type Battery struct {
	derbase.Base
	transport modbus.Transport
}

// New opens a Modbus connection, scans SunSpec models, and returns a Battery.
func New(url string, timeout time.Duration, unitID uint8) (*Battery, error) {
	t, err := modbus.NewTransport(url, timeout)
	if err != nil {
		return nil, err
	}
	if err := t.Open(); err != nil {
		return nil, fmt.Errorf("battery: open %s: %w", url, err)
	}
	if err := t.SetUnitID(unitID); err != nil {
		t.Close()
		return nil, fmt.Errorf("battery: set unit id %d: %w", unitID, err)
	}
	b, err := newFromTransport(t)
	if err != nil {
		t.Close()
		return nil, err
	}
	return b, nil
}

func newFromTransport(t modbus.Transport) (*Battery, error) {
	r, err := sunspec.NewReader(t)
	if err != nil {
		return nil, fmt.Errorf("battery: scan SunSpec blocks: %w", err)
	}
	base, err := derbase.Init(r, tag)
	if err != nil {
		return nil, err
	}
	return &Battery{
		Base:      base,
		transport: t,
	}, nil
}

func (b *Battery) Close() error {
	return b.transport.Close()
}

func (b *Battery) ReadMeasurements() (device.Measurements, error) {
	regs, err := b.Reader.ReadModel(b.MeasModel)
	if err != nil {
		return device.Measurements{}, fmt.Errorf("battery: read model %d: %w", b.MeasModel, err)
	}
	if b.MeasModel == sunspec.ModelDERMeasureAC {
		return derbase.ReadMeasurementsM701(regs), nil
	}
	return derbase.ReadMeasurementsACModel(regs), nil
}

// Status reads the battery connection state.
// Uses M701 → M802 → M103 fallback chain.
func (b *Battery) Status() (device.DeviceStatus, error) {
	if b.MeasModel == sunspec.ModelDERMeasureAC {
		regs, err := b.Reader.ReadModel(sunspec.ModelDERMeasureAC)
		if err != nil {
			return device.DeviceStatus{}, fmt.Errorf("battery: read M701 status: %w", err)
		}
		ac := sunspec.Parse701(regs)
		st := int(ac.St)
		return device.DeviceStatus{
			Connected: ac.ConnSt == 1,
			Energized: st == derbase.M701StOn || st == derbase.M701StThrottled || st == derbase.M701StStarting,
		}, nil
	}

	if b.Reader.HasModel(sunspec.ModelLithiumBattery) {
		regs, err := b.Reader.ReadModel(sunspec.ModelLithiumBattery)
		if err != nil {
			return device.DeviceStatus{}, fmt.Errorf("battery: read Model 802: %w", err)
		}
		if len(regs) > sunspec.M802_State {
			state := regs[sunspec.M802_State]
			chaSt := uint16(0)
			if len(regs) > sunspec.M802_ChaSt {
				chaSt = regs[sunspec.M802_ChaSt]
			}
			return device.DeviceStatus{
				Connected: state == 2 || state == 3,
				Energized: chaSt >= 3 && chaSt <= 6,
			}, nil
		}
	}

	regs, err := b.Reader.ReadModel(b.MeasModel)
	if err != nil {
		return device.DeviceStatus{}, fmt.Errorf("battery: read status: %w", err)
	}
	if len(regs) <= sunspec.M103_St {
		return device.DeviceStatus{}, fmt.Errorf("battery: model too short for St")
	}
	st := regs[sunspec.M103_St]
	return device.DeviceStatus{
		Connected: st == 4 || st == 5,
		Energized: st >= 3 && st <= 6,
	}, nil
}

func (b *Battery) ApplyControl(ctrl model.DERControlBase) error {
	return b.Base.ApplyControl(ctrl, tag)
}

// Note: the old bench fork also exposed ReadStorageCapacity (M713) plus a
// wider IEEE 1547-2018 read/write surface (M702/705-712) delegated to
// derbase. All had zero callers beyond their own pass-through/type
// declaration and zero test coverage; removed along with their derbase
// counterparts rather than re-implemented against the shared codec's
// differently-shaped M713 layout (spec Table 16 vs this fork's non-spec
// layout — disposition doc §2c S5) and curve-write workflow (TASK-021;
// disposal is TASK-082).
