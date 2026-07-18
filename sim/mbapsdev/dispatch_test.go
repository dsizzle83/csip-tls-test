package main

// dispatch_test.go — pure-logic unit tests for the PDU-level dispatch helpers
// (mapModbusErr, exceptionFor, handleADU's function-code routing) that need
// no TLS handshake, so they run in `make test-fast` (compiled with cgo like
// every mbtls-adjacent package, per the Makefile's test-fast comment, but
// exercising no wolfSSL call).

import (
	"testing"

	modbuslib "github.com/simonvetter/modbus"

	"lexa-proto/mbap"
)

// newTestDevice builds a real (but TLS-free) register world via newModel —
// RegisterMap has no exported zero-value-safe constructor (Set on a bare
// &sim.RegisterMap{} would panic on its nil internal map), and newModel is
// itself pure Go / plain TCP on loopback, so this needs no wolfSSL sysroot
// and stays in test-fast.
func newTestDevice(t *testing.T) *Device {
	t.Helper()
	mb, err := newModel("inverter", 5000, 10)
	if err != nil {
		t.Fatalf("newModel: %v", err)
	}
	t.Cleanup(mb.stop)
	return &Device{regs: mb.regs, modelFault: mb.fault, sessions: newSessionRegistry()}
}

func TestMapModbusErr(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want mbap.ExCode
	}{
		{"illegal function", modbuslib.ErrIllegalFunction, mbap.ExIllegalFunction},
		{"illegal address", modbuslib.ErrIllegalDataAddress, mbap.ExIllegalAddress},
		{"illegal value", modbuslib.ErrIllegalDataValue, mbap.ExIllegalValue},
		{"device failure", modbuslib.ErrServerDeviceFailure, mbap.ExDeviceFailure},
		{"device busy", modbuslib.ErrServerDeviceBusy, mbap.ExServerBusy},
		{"gw path unavailable", modbuslib.ErrGWPathUnavailable, mbap.ExGatewayPath},
		{"gw target failed", modbuslib.ErrGWTargetFailedToRespond, mbap.ExGatewayTarget},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := mapModbusErr(tc.err); got != tc.want {
				t.Errorf("mapModbusErr(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

func TestExceptionFor(t *testing.T) {
	req := mbap.ADU{Header: mbap.Header{TID: 7, UnitID: 1}, PDU: []byte{mbap.FCReadHolding, 0, 0, 0, 1}}

	pdErr := &mbap.PDUError{Reason: "bad count", Ex: mbap.ExIllegalValue}
	resp := exceptionFor(req, pdErr)
	if resp.PDU[0] != mbap.FCReadHolding|0x80 || mbap.ExCode(resp.PDU[1]) != mbap.ExIllegalValue {
		t.Errorf("exceptionFor(PDUError) = %+v, want exception 0x%02x", resp.PDU, mbap.ExIllegalValue)
	}
	if resp.TID != req.TID || resp.UnitID != req.UnitID {
		t.Errorf("exceptionFor did not preserve TID/UnitID: got TID=%d UnitID=%d", resp.TID, resp.UnitID)
	}

	// A non-PDUError (can't-happen once mbap.Decode already validated the
	// frame) answers device-failure rather than panicking or leaking detail.
	other := exceptionFor(req, errUnrelated)
	if mbap.ExCode(other.PDU[1]) != mbap.ExDeviceFailure {
		t.Errorf("exceptionFor(other error) = 0x%02x, want device-failure 0x%02x", other.PDU[1], mbap.ExDeviceFailure)
	}
}

var errUnrelated = &mbap.FrameError{Reason: "not a PDUError"}

func TestHandleADU_FC04ReadInputIsIllegalFunction(t *testing.T) {
	// FC04 short-circuits to an exception before touching the register map
	// (see handleADU), so a zero-value Device (nil regs) is sufficient here.
	d := &Device{}
	req := mbap.ADU{Header: mbap.Header{TID: 1, UnitID: 1}, PDU: []byte{mbap.FCReadInput, 0, 0, 0, 1}}
	resp, err := d.handleADU(req)
	if err != nil {
		t.Fatalf("handleADU(FC04): %v", err)
	}
	if resp.PDU[0] != mbap.FCReadInput|0x80 || mbap.ExCode(resp.PDU[1]) != mbap.ExIllegalFunction {
		t.Errorf("FC04 response = %+v, want exception 0x%02x (holding-register-only device)", resp.PDU, mbap.ExIllegalFunction)
	}
}

func TestHandleADU_UnknownFC(t *testing.T) {
	d := &Device{}                                                                   // unknown FC never reaches the register map either
	req := mbap.ADU{Header: mbap.Header{TID: 1, UnitID: 1}, PDU: []byte{0x2B, 0x0E}} // FC 43 (encapsulated interface) — unsupported
	resp, err := d.handleADU(req)
	if err != nil {
		t.Fatalf("handleADU(unknown FC): %v", err)
	}
	if mbap.ExCode(resp.PDU[1]) != mbap.ExIllegalFunction {
		t.Errorf("unknown FC response exception = 0x%02x, want 0x%02x", resp.PDU[1], mbap.ExIllegalFunction)
	}
}

func TestHandleADU_ReadWriteRoundTrip(t *testing.T) {
	d := newTestDevice(t)

	// FC16 write two registers at 100 — well below the SunSpec model chain
	// (which starts at 40000), so this exercises plain read/write dispatch
	// without touching any populated model data.
	writeReq := mbap.ADU{
		Header: mbap.Header{TID: 5, UnitID: 1},
		PDU:    mustBuildWriteReq(t, 100, []uint16{42, 43}),
	}
	resp, err := d.handleADU(writeReq)
	if err != nil {
		t.Fatalf("handleADU(write): %v", err)
	}
	if resp.PDU[0] != mbap.FCWriteMultiple {
		t.Fatalf("write response FC = %#02x, want %#02x (success, not exception)", resp.PDU[0], mbap.FCWriteMultiple)
	}

	// FC03 read the same two registers back — proves the write landed in the
	// SAME RegisterMap dispatch reads from (no double-modeling).
	readReq := mbap.ADU{
		Header: mbap.Header{TID: 6, UnitID: 1},
		PDU:    mustBuildReadReq(t, 100, 2),
	}
	resp, err = d.handleADU(readReq)
	if err != nil {
		t.Fatalf("handleADU(read): %v", err)
	}
	got, err := mbap.ParseReadResp(mbap.ReadReq{FC: mbap.FCReadHolding, Addr: 100, Count: 2}, resp.PDU)
	if err != nil {
		t.Fatalf("ParseReadResp: %v", err)
	}
	if got[0] != 42 || got[1] != 43 {
		t.Errorf("readback = %v, want [42 43]", got)
	}
}

func mustBuildWriteReq(t *testing.T, addr uint16, values []uint16) []byte {
	t.Helper()
	pdu, err := mbap.BuildWriteReq(mbap.WriteReq{FC: mbap.FCWriteMultiple, Addr: addr, Values: values})
	if err != nil {
		t.Fatalf("BuildWriteReq: %v", err)
	}
	return pdu
}

func mustBuildReadReq(t *testing.T, addr, count uint16) []byte {
	t.Helper()
	pdu, err := mbap.BuildReadReq(mbap.ReadReq{FC: mbap.FCReadHolding, Addr: addr, Count: count})
	if err != nil {
		t.Fatalf("BuildReadReq: %v", err)
	}
	return pdu
}
