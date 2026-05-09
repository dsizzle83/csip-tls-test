package main

import (
	"fmt"
	"log"
	"math"
	"sync"

	"csip-tls-test/internal/csip/model"
	"csip-tls-test/internal/southbound/device"
)

// pendingDevice wraps a DeviceConfig whose initial Modbus open failed.
// It retries opening the real device on every ReadMeasurements poll until
// the connection succeeds, then delegates all calls to the real device.
// This lets the hub register all configured devices at startup even when
// a simulator starts after the hub.
type pendingDevice struct {
	mu    sync.Mutex
	cfg   DeviceConfig
	inner device.Device
}

func newPendingDevice(cfg DeviceConfig) *pendingDevice {
	return &pendingDevice{cfg: cfg}
}

func (p *pendingDevice) tryConnect() device.Device {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.inner != nil {
		return p.inner
	}
	dev, err := openDevice(p.cfg)
	if err != nil {
		return nil
	}
	log.Printf("hub: device %s (%s): connected (deferred)", p.cfg.Name, p.cfg.URL)
	p.inner = dev
	return dev
}

func (p *pendingDevice) ReadMeasurements() (device.Measurements, error) {
	nan := device.Measurements{
		W: math.NaN(), V: math.NaN(), Hz: math.NaN(),
		VA: math.NaN(), Var: math.NaN(), PF: math.NaN(),
		DCV: math.NaN(), DCW: math.NaN(), TmpCab: math.NaN(),
	}
	dev := p.tryConnect()
	if dev == nil {
		return nan, fmt.Errorf("device %s: not yet connected", p.cfg.Name)
	}
	m, err := dev.ReadMeasurements()
	if err != nil {
		// Reset so the next poll retries the open.
		p.mu.Lock()
		p.inner = nil
		p.mu.Unlock()
		return nan, err
	}
	return m, nil
}

func (p *pendingDevice) ApplyControl(ctrl model.DERControlBase) error {
	p.mu.Lock()
	inner := p.inner
	p.mu.Unlock()
	if inner == nil {
		return fmt.Errorf("device %s: not connected", p.cfg.Name)
	}
	return inner.ApplyControl(ctrl)
}

func (p *pendingDevice) Status() (device.DeviceStatus, error) {
	p.mu.Lock()
	inner := p.inner
	p.mu.Unlock()
	if inner == nil {
		return device.DeviceStatus{Connected: false, Energized: false}, nil
	}
	return inner.Status()
}

func (p *pendingDevice) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.inner != nil {
		return p.inner.Close()
	}
	return nil
}
