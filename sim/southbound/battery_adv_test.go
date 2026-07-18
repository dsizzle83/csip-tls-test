package sim

// battery_adv_test.go — unit tests for the advanced-DER (7xx) battery
// surface added for sim/mbapsdev (T06.3): model 701/713 encoding and the 704
// control write/readback round trip, all driven against a bare register bank
// (no live Modbus listener — mirrors solar_adv_test.go's newAdvSolar pattern).

import (
	"testing"

	"lexa-proto/sunspec"
)

// newAdvBattery builds an advanced battery register bank + BatteryServer
// wired for unit tests WITHOUT a live Modbus listener.
func newAdvBattery(t *testing.T, wmaxKwh, wmaxW float64) *BatteryServer {
	t.Helper()
	r := &RegisterMap{regs: make(map[uint16]uint16)}
	bases, cursor := populateBatteryCore(r, wmaxKwh, wmaxW)
	adv, cursor := populateBattery7xx(r, cursor, wmaxKwh, wmaxW)
	r.Set(cursor, sunspec.EndMarker)
	r.Set(cursor+1, 0)
	bs := &BatteryServer{
		Server: &Server{Regs: r}, bases: bases, wmaxW: wmaxW, wmaxKwh: wmaxKwh,
		advanced: true, adv: adv,
	}
	bs.faults.label = "battery"
	return bs
}

// TestBatteryAdv701713RoundTrip verifies mirrorBattery701713Once encodes the
// 103/802 physical state into models 701/713 such that the real
// Parse701/Parse713 decode coherent, matching engineering values.
func TestBatteryAdv701713RoundTrip(t *testing.T) {
	bs := newAdvBattery(t, 10, 5000)
	r := bs.Regs
	b := bs.bases

	// Drive a known physical state: 1500 W discharge, 62% SoC, 97% SoH.
	r.Set(b.M103Base+sunspec.M103_W, uint16(int16(1500)))
	r.Set(b.M802Base+uint16(sunspec.M802_SoC), 6200) // SoC_SF=-2 -> 62.00%
	r.Set(b.M802Base+uint16(sunspec.M802_SoH), 9700) // SoH_SF=-2 -> 97.00%
	mirrorBattery701713Once(r, b, bs.adv, bs.wmaxKwh)

	m701 := sunspec.Parse701(readSlice(r, bs.adv.M701, bs.adv.M701Len))
	if m701.W != 1500 {
		t.Errorf("701 W = %v, want 1500", m701.W)
	}
	if m701.St != 1 || m701.ConnSt != 1 {
		t.Errorf("701 St=%d ConnSt=%d, want 1/1 (on, connected)", m701.St, m701.ConnSt)
	}

	m713 := sunspec.Parse713(readSlice(r, bs.adv.M713, sunspec.L713.Len()))
	if m713.SoC != 62 {
		t.Errorf("713 SoC = %v, want 62", m713.SoC)
	}
	if m713.SoH != 97 {
		t.Errorf("713 SoH = %v, want 97", m713.SoH)
	}
	wantAvail := 10 * 1000 * 0.62
	if m713.WHAvail != wantAvail {
		t.Errorf("713 WHAvail = %v, want %v", m713.WHAvail, wantAvail)
	}
	if m713.WHRtg != 10000 {
		t.Errorf("713 WHRtg = %v, want 10000", m713.WHRtg)
	}
}

// TestBatteryAdv701713Disconnected verifies the St/ConnSt mirror reflects a
// disconnected (Conn=0) unit.
func TestBatteryAdv701713Disconnected(t *testing.T) {
	bs := newAdvBattery(t, 10, 5000)
	r := bs.Regs
	b := bs.bases

	r.Set(b.M123Base+sunspec.M123_Conn, 0)
	mirrorBattery701713Once(r, b, bs.adv, bs.wmaxKwh)

	m701 := sunspec.Parse701(readSlice(r, bs.adv.M701, bs.adv.M701Len))
	if m701.St != 0 || m701.ConnSt != 0 {
		t.Errorf("701 St=%d ConnSt=%d, want 0/0 (off, disconnected)", m701.St, m701.ConnSt)
	}
}

// TestBatteryAdv704WriteReadback proves the 704 WMaxLimPct control write
// round-trips through the register store (the "write a 704 control and read
// back the echo" acceptance bar T06.3/mbapsdev drives against). WMaxLimPct_SF
// is -2, so a raw 5000 encodes 50.00%.
func TestBatteryAdv704WriteReadback(t *testing.T) {
	bs := newAdvBattery(t, 10, 5000)
	r := bs.Regs
	off := uint16(sunspec.L704.Offset("WMaxLimPct"))

	r.Set(bs.adv.M704+off, 5000)
	got := r.Get(bs.adv.M704 + off)
	if got != 5000 {
		t.Errorf("704 WMaxLimPct readback = %d, want 5000", got)
	}
	c704 := sunspec.Parse704(readSlice(r, bs.adv.M704, sunspec.L704.Len()))
	if c704.WMaxLimPct != 50 {
		t.Errorf("704 WMaxLimPct decoded = %v, want 50", c704.WMaxLimPct)
	}
}

// TestBatteryAdv713SFProtected verifies the model 713 scale-factor cells are
// write-protected exactly like every other advanced model's SFs (protect.go).
func TestBatteryAdv713SFProtected(t *testing.T) {
	bs := newAdvBattery(t, 10, 5000)
	r := bs.Regs
	sfOff := uint16(sunspec.L713.Offset("Pct_SF"))
	addr := bs.adv.M713 + sfOff
	before := r.Get(addr)
	masked := r.maskProtected(addr, []uint16{uint16(int16(before) + 1)})
	if masked[0] != before {
		t.Errorf("713 Pct_SF write not masked: got %d, want unchanged %d", masked[0], before)
	}
}
