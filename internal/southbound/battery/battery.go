// Package battery implements device.Device for SunSpec-compliant battery
// storage systems covering both legacy SunSpec models (101/102/103, 121, 123,
// 802) and the IEEE 1547-2018 SunSpec Modbus profile (701-713).
package battery

import (
	"fmt"
	"time"

	"csip-tls-test/internal/southbound/device"
	model "lexa-proto/csipmodel"
	"lexa-proto/derbase"
	"lexa-proto/modbus"
	"lexa-proto/sunspec"
)

const tag = "battery"

// M701 operating-state values used by Status() below (SunSpec Alliance Model
// 701 St field spec values: 0=Off 1=Sleeping 2=Starting 3=On 4=Throttled
// 5=ShuttingDown 6=Fault 7=Standby). lexa-proto/derbase deliberately keeps
// sunspec.ACMeasurement.St as a raw uint16 with no symbolic type (see its
// package doc), so each consumer that needs the enum keeps its own tiny
// read-only shim — this one replaces the bench-local derbase fork's
// M701St* constants that were deleted in TASK-082.
const (
	m701StStarting  = 2
	m701StOn        = 3
	m701StThrottled = 4
)

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
			Energized: st == m701StOn || st == m701StThrottled || st == m701StStarting,
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
// wider IEEE 1547-2018 read/write surface (M702/705-712) delegated to its own
// derbase. All had zero callers beyond their own pass-through/type
// declaration and zero test coverage; removed in TASK-021 rather than
// re-implemented against the shared codec's differently-shaped M713 layout
// (spec Table 16 vs this fork's non-spec layout — disposition doc §2c S5) and
// curve-write workflow. TASK-082 completed the disposal: the bench's own
// derbase.go (the trimmed M701-712/legacy mapping layer TASK-021 adapted onto
// the shared sunspec codec) is gone; Battery now embeds lexa-proto/derbase.Base
// directly — the same package lexa-hub consumes. The extra capability this
// pulls in (OpModFixedW, GenLimW/LoadLimW ceilings, reversion timers, the
// full VoltVar/VoltWatt/trip/droop/WattVar curve surface) was already
// adjudicated product-authoritative with zero bench-fix loss (TASK-020
// disposition §2c/§2d, D1-D3) — none of it is a "semantic change" requiring
// escalation, since the bench never had a fix the product lacked.
