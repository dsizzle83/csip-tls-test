package sim

import (
	"fmt"
	"net"
	"testing"
	"time"

	modbuslib "github.com/simonvetter/modbus"
	"lexa-proto/sunspec"
)

// TestUnitIDConfusion_ReadReturnsGatewayException: while unit_id_confusion is
// armed every read is answered with a gateway-target-failed exception (the
// wrong-slave signal), not data — so the hub can never act on a value.
func TestUnitIDConfusion_ReadReturnsGatewayException(t *testing.T) {
	r := &RegisterMap{regs: make(map[uint16]uint16)}
	for a := uint16(100); a < 110; a++ {
		r.Set(a, a)
	}
	// Unarmed: a normal read succeeds.
	if _, err := r.HandleHoldingRegisters(&modbuslib.HoldingRegistersRequest{Addr: 100, Quantity: 4}); err != nil {
		t.Fatalf("unarmed read: %v", err)
	}
	r.mu.Lock()
	r.unitIDConfusion = true
	r.mu.Unlock()
	_, err := r.HandleHoldingRegisters(&modbuslib.HoldingRegistersRequest{Addr: 100, Quantity: 4})
	if err != modbuslib.ErrGWTargetFailedToRespond {
		t.Fatalf("armed read err = %v, want ErrGWTargetFailedToRespond (0x0B)", err)
	}
}

// TestRegisterTearing_TornMultiRegisterRead: while register_tearing is armed a
// multi-register data read (≥ tearMinQuantity) comes back with a spliced middle
// value while a small probe read passes through clean.
func TestRegisterTearing_TornMultiRegisterRead(t *testing.T) {
	r := &RegisterMap{regs: make(map[uint16]uint16)}
	for a := uint16(0); a < 12; a++ {
		r.Set(a, 1000+a)
	}
	r.mu.Lock()
	r.tearing = true
	r.mu.Unlock()

	// A full data read (Quantity ≥ tearMinQuantity) is torn: exactly the middle
	// register differs from the coherent snapshot, the rest match.
	const q = 10
	got, err := r.HandleHoldingRegisters(&modbuslib.HoldingRegistersRequest{Addr: 0, Quantity: q})
	if err != nil {
		t.Fatalf("torn read: %v", err)
	}
	mid := q / 2
	for i := uint16(0); i < q; i++ {
		want := r.Get(i)
		if i == uint16(mid) {
			if got[i] == want {
				t.Errorf("register %d was not torn (got %d == snapshot %d)", i, got[i], want)
			}
		} else if got[i] != want {
			t.Errorf("register %d = %d, want %d (only the middle should tear)", i, got[i], want)
		}
	}

	// A small probe read (below the threshold) is left coherent so model
	// discovery still works.
	probe, err := r.HandleHoldingRegisters(&modbuslib.HoldingRegistersRequest{Addr: 0, Quantity: 2})
	if err != nil {
		t.Fatalf("probe read: %v", err)
	}
	if probe[0] != r.Get(0) || probe[1] != r.Get(1) {
		t.Errorf("small probe read was torn: got %v, want [%d %d]", probe, r.Get(0), r.Get(1))
	}
}

// TestApplyServerFault_Routing: the sticky server-layer kinds arm/clear their
// RegisterMap state; an unrecognised kind is left for the faultController
// (handled=false); a tcp_drop clear is a no-op that never touches the server.
func TestApplyServerFault_Routing(t *testing.T) {
	r := &RegisterMap{regs: make(map[uint16]uint16)}
	s := &Server{Regs: r} // no live modbus server needed for the state-only kinds

	for _, kind := range []string{"unit_id_confusion", "register_tearing"} {
		handled, err := s.applyServerFault([]byte(fmt.Sprintf(`{"kind":%q}`, kind)))
		if !handled || err != nil {
			t.Fatalf("arm %s: handled=%v err=%v", kind, handled, err)
		}
	}
	r.mu.Lock()
	armed := r.unitIDConfusion && r.tearing
	r.mu.Unlock()
	if !armed {
		t.Fatal("arming did not set the RegisterMap flags")
	}
	for _, kind := range []string{"unit_id_confusion", "register_tearing"} {
		if handled, err := s.applyServerFault([]byte(fmt.Sprintf(`{"kind":%q,"clear":true}`, kind))); !handled || err != nil {
			t.Fatalf("clear %s: handled=%v err=%v", kind, handled, err)
		}
	}
	r.mu.Lock()
	cleared := !r.unitIDConfusion && !r.tearing
	r.mu.Unlock()
	if !cleared {
		t.Fatal("clearing did not reset the RegisterMap flags")
	}

	// A register-level kind is not handled here (falls through to faultController).
	if handled, _ := s.applyServerFault([]byte(`{"kind":"reject_write"}`)); handled {
		t.Error("reject_write must not be handled by applyServerFault")
	}
	// A tcp_drop CLEAR is a no-op and must not touch (nil) srv.
	if handled, err := s.applyServerFault([]byte(`{"kind":"tcp_drop","clear":true}`)); !handled || err != nil {
		t.Fatalf("tcp_drop clear: handled=%v err=%v", handled, err)
	}
}

// TestTCPDrop_BouncesAndRebinds: arming tcp_drop on a live server severs
// connections and rebinds the same port, so a fresh client can read again.
func TestTCPDrop_BouncesAndRebinds(t *testing.T) {
	url := fmt.Sprintf("tcp://127.0.0.1:%d", freeTCPPort(t))
	ms, err := NewMeterServer(url, 1234)
	if err != nil {
		t.Fatalf("start meter server: %v", err)
	}
	defer ms.Stop()

	read := func() error {
		c, err := modbuslib.NewClient(&modbuslib.ClientConfiguration{URL: url, Timeout: 2 * time.Second})
		if err != nil {
			return err
		}
		if err := c.Open(); err != nil {
			return err
		}
		defer c.Close()
		_, err = c.ReadRegisters(uint16(sunspec.SunSpecBase), 2, modbuslib.HOLDING_REGISTER)
		return err
	}

	if err := read(); err != nil {
		t.Fatalf("pre-drop read: %v", err)
	}
	if handled, err := ms.Server.applyServerFault([]byte(`{"kind":"tcp_drop"}`)); !handled || err != nil {
		t.Fatalf("tcp_drop: handled=%v err=%v", handled, err)
	}
	// The server must serve again after the bounce (port rebound). Retry briefly
	// since the fresh listener needs a moment to come up.
	var rerr error
	for i := 0; i < 20; i++ {
		if rerr = read(); rerr == nil {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if rerr != nil {
		t.Fatalf("post-drop read (server did not rebind %s): %v", url, rerr)
	}
}

// freeTCPPort returns a currently-free localhost TCP port for a test server.
func freeTCPPort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("find free port: %v", err)
	}
	p := l.Addr().(*net.TCPAddr).Port
	_ = l.Close()
	return p
}
