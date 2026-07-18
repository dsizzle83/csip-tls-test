//go:build integration

package aggregator

// aggregator_integration_test.go proves the T06.4 (+T06.5 primitives) acceptance
// bar end to end against a loopback mbaps server: the emulator ConnectAs a role
// over the bench's own mbtls glue, discovers a device via SunSpec Model 1, polls
// telemetry, does a scale-correct write + readback on Model 704, and a role-
// denial probe that surfaces exception 0x01 (not a transport error). It also
// proves Stale flips under a not-implemented-sentinel read and that the session
// auto-reconnects after a mid-exchange drop.
//
// The loopback server is a minimal in-process mbaps server (mbtls.Listen +
// mbap dispatch over sim/southbound's animated SunSpec register world) that adds
// exactly what mbapsdev deliberately omits: a per-device UNIT MAP (unmapped
// units answer 0x0A — PN-6) and a role AUTHZ stub (read-only roles' writes
// answer 0x01 — the gateway's job, faithfully modelled here so the denial
// primitive can be proven without the live gateway). Requires the amd64 wolfSSL
// sysroot (desktop, `make test-integration`).

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"net"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"csip-tls-test/internal/mbtls"
	"csip-tls-test/internal/wolfssl"
	sim "csip-tls-test/sim/southbound"
	"lexa-proto/mbap"
	"lexa-proto/sunspec"

	modbuslib "github.com/simonvetter/modbus"
)

// TestMain initialises wolfSSL once for the whole integration binary (CLAUDE.md
// wolfSSL_Init invariant), mirroring internal/mbtls and sim/mbapsdev.
func TestMain(m *testing.M) {
	wolfssl.Init()
	code := m.Run()
	wolfssl.Cleanup()
	os.Exit(code)
}

// authzServer is a loopback mbaps server backed by a solar SunSpec register
// world, with a per-unit map and a role write-allow set — the two behaviours the
// emulator must exercise (unmapped→0x0A, denied-write→0x01) that mbapsdev, being
// an unconditional device sim, does not enforce.
type authzServer struct {
	regs       *sim.RegisterMap
	applyFault func([]byte) error
	served     map[uint8]bool
	writeRoles map[string]bool
	lis        *mbtls.Listener
	dropNext   atomic.Bool // when set, close the next session mid-exchange (drop_session)
}

func startAuthzServer(t *testing.T, pki testPKI, served []uint8, writeRoles []Role) *authzServer {
	t.Helper()
	srv, err := sim.NewSolarServerAdvanced("tcp://127.0.0.1:0", 5000, "")
	if err != nil {
		t.Fatalf("new solar model: %v", err)
	}
	srv.Pause() // freeze the animation so writes/readbacks are deterministic

	lis, err := mbtls.Listen("127.0.0.1:0", pki.serverProfile())
	if err != nil {
		srv.Stop()
		t.Fatalf("mbtls.Listen: %v", err)
	}
	s := &authzServer{
		regs:       srv.Regs,
		applyFault: srv.ApplyFault,
		served:     boolSet(served),
		writeRoles: roleSet(writeRoles),
		lis:        lis,
	}
	go s.acceptLoop()
	t.Cleanup(func() {
		_ = lis.Close()
		srv.Stop()
	})
	return s
}

func (s *authzServer) addr() string { return s.lis.Addr().String() }

func boolSet(units []uint8) map[uint8]bool {
	m := map[uint8]bool{}
	for _, u := range units {
		m[u] = true
	}
	return m
}

func roleSet(roles []Role) map[string]bool {
	m := map[string]bool{}
	for _, r := range roles {
		m[string(r)] = true
	}
	return m
}

func (s *authzServer) acceptLoop() {
	for {
		sess, err := s.lis.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			continue
		}
		go s.serve(sess)
	}
}

func (s *authzServer) serve(sess *mbtls.Session) {
	defer sess.Close()
	role, _ := sess.Role() // "" (empty) for a role-less cert; fine — authz below
	for {
		adu, err := mbap.Decode(sess.Conn)
		if err != nil {
			return // clean close or frame error → close (never resync)
		}
		if s.dropNext.Load() {
			return // drop mid-exchange: decoded the request, close before answering
		}
		resp := s.handle(adu, role)
		frame, err := mbap.Encode(resp)
		if err != nil {
			return
		}
		if _, err := sess.Conn.Write(frame); err != nil {
			return
		}
	}
}

func (s *authzServer) handle(req mbap.ADU, role string) mbap.ADU {
	if !s.served[req.UnitID] {
		return mbap.Exception(req, mbap.ExGatewayPath) // 0x0A unmapped unit (PN-6)
	}
	switch req.PDU[0] {
	case mbap.FCReadHolding:
		rreq, err := mbap.ParseReadReq(req.PDU)
		if err != nil {
			return mbap.Exception(req, mbap.ExIllegalValue)
		}
		vals, herr := s.regs.HandleHoldingRegisters(&modbuslib.HoldingRegistersRequest{
			UnitId: req.UnitID, Addr: rreq.Addr, Quantity: rreq.Count, IsWrite: false,
		})
		if herr != nil {
			return mbap.Exception(req, mapErr(herr))
		}
		pdu, err := mbap.BuildReadResp(rreq, vals)
		if err != nil {
			return mbap.Exception(req, mbap.ExDeviceFailure)
		}
		return mbap.ADU{Header: mbap.Header{TID: req.TID, UnitID: req.UnitID}, PDU: pdu}

	case mbap.FCWriteSingle, mbap.FCWriteMultiple:
		if !s.writeRoles[role] {
			// AuthZ denial: exception 0x01 and nothing else (TCP-40/41).
			return mbap.Exception(req, mbap.ExIllegalFunction)
		}
		wreq, err := mbap.ParseWriteReq(req.PDU)
		if err != nil {
			return mbap.Exception(req, mbap.ExIllegalValue)
		}
		if _, herr := s.regs.HandleHoldingRegisters(&modbuslib.HoldingRegistersRequest{
			UnitId: req.UnitID, Addr: wreq.Addr, Quantity: uint16(len(wreq.Values)), IsWrite: true, Args: wreq.Values,
		}); herr != nil {
			return mbap.Exception(req, mapErr(herr))
		}
		pdu, err := mbap.BuildWriteResp(wreq)
		if err != nil {
			return mbap.Exception(req, mbap.ExDeviceFailure)
		}
		return mbap.ADU{Header: mbap.Header{TID: req.TID, UnitID: req.UnitID}, PDU: pdu}

	default:
		return mbap.Exception(req, mbap.ExIllegalFunction)
	}
}

func mapErr(err error) mbap.ExCode {
	switch err {
	case modbuslib.ErrIllegalFunction:
		return mbap.ExIllegalFunction
	case modbuslib.ErrIllegalDataAddress:
		return mbap.ExIllegalAddress
	case modbuslib.ErrIllegalDataValue:
		return mbap.ExIllegalValue
	case modbuslib.ErrGWTargetFailedToRespond:
		return mbap.ExGatewayTarget
	default:
		return mbap.ExDeviceFailure
	}
}

// TestEmulatorCore_EndToEnd walks the whole core: ConnectAs → discover → poll →
// write+readback → denial probe → run-state JSON, against the loopback server
// serving units 2 & 3 with GridService/admins allowed to write.
func TestEmulatorCore_EndToEnd(t *testing.T) {
	pki := newTestPKI(t)
	srv := startAuthzServer(t, pki, []uint8{2, 3}, []Role{RoleGridService, RoleSuperAdmin, RoleNetworkAdmin})
	refs := pki.refs(t)
	ctx := context.Background()

	// 1. ConnectAs GridService — handshake facts populated, self-check passed.
	conn, err := ConnectAs(srv.addr(), RoleGridService, refs)
	if err != nil {
		t.Fatalf("ConnectAs: %v", err)
	}
	defer conn.Close()
	si := conn.SessionInfo()
	if !si.Connected || si.Cipher == "" || si.TLSVersion == "" {
		t.Fatalf("session missing handshake facts: %+v", si)
	}
	if si.Asserted != string(RoleGridService) {
		t.Errorf("asserted role = %q, want %q", si.Asserted, RoleGridService)
	}

	// 2. Discover units 1..4 → find exactly {2,3}; unmapped 1 & 4 skipped (0x0A).
	devs, err := conn.Discover(ctx, 1, 2, 3, 4)
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if len(devs) != 2 {
		t.Fatalf("Discover found %d devices, want 2 (units 2,3): %+v", len(devs), devs)
	}
	foundUnits := map[uint8]Device{}
	for _, d := range devs {
		foundUnits[d.Unit] = d
	}
	dev2, ok := foundUnits[2]
	if !ok {
		t.Fatalf("unit 2 not discovered: %+v", devs)
	}
	if dev2.Identity.Manufacturer == "" || dev2.Identity.Model == "" {
		t.Errorf("unit 2 Common identity incomplete: %+v", dev2.Identity)
	}
	if !containsModel(dev2.Models, sunspec.ModelCommon) || !containsModel(dev2.Models, sunspec.ModelDERMeasureAC) {
		t.Errorf("unit 2 models missing Model 1/701: %v", dev2.Models)
	}

	// 3. Telemetry: a healthy sample is neither stale nor comm-lost and carries
	//    finite measurement points.
	snap := conn.Sample(2)
	if snap.Stale || snap.CommLoss {
		t.Errorf("healthy sample flagged stale=%t commLoss=%t (err=%q)", snap.Stale, snap.CommLoss, snap.Err)
	}
	if len(snap.Points) == 0 {
		t.Errorf("sample carried no finite measurement points: %+v", snap)
	}

	// 4. Control: scale-correct write of WMaxLimPct=50, then readback ≈ 50.
	if err := conn.WritePoint(2, sunspec.ModelDERCtlAC, "WMaxLimPct", 50); err != nil {
		t.Fatalf("WritePoint WMaxLimPct: %v", err)
	}
	got, err := conn.ReadPoint(2, sunspec.ModelDERCtlAC, "WMaxLimPct")
	if err != nil {
		t.Fatalf("ReadPoint WMaxLimPct: %v", err)
	}
	if math.Abs(got-50) > 0.5 {
		t.Errorf("WMaxLimPct readback = %v, want ~50", got)
	}

	// 5. Assemble run state from the live results and prove it serializes.
	rs := NewRunState(srv.addr(), RoleGridService)
	rs.SetSession(si)
	rs.AddDevices(devs)
	rs.AddSample(snap)
	rs.AddWrite(WriteRecord{Unit: 2, Model: 704, Point: "WMaxLimPct", Value: got, OK: true})
	if _, err := json.Marshal(rs); err != nil {
		t.Fatalf("run state does not serialize: %v", err)
	}
}

// TestEmulatorCore_DenialProbe proves a read-only role's write is denied with
// exception 0x01 (surfaced as a DenialResult, not a transport error), while the
// same role's reads still work.
func TestEmulatorCore_DenialProbe(t *testing.T) {
	pki := newTestPKI(t)
	srv := startAuthzServer(t, pki, []uint8{2}, []Role{RoleGridService}) // ReadOnly NOT allowed to write
	refs := pki.refs(t)

	for _, role := range []Role{RoleReadOnly, RoleLexaVolt} {
		t.Run(string(role), func(t *testing.T) {
			conn, err := ConnectAs(srv.addr(), role, refs)
			if err != nil {
				t.Fatalf("ConnectAs %s: %v", role, err)
			}
			defer conn.Close()

			// Reads must still work for a read-only role.
			if _, err := conn.ReadHolding(2, sunspec.SunSpecBase, 2); err != nil {
				t.Fatalf("%s read denied unexpectedly: %v", role, err)
			}

			res, err := conn.ProbeDenied(2, sunspec.ModelDERCtlAC, "WMaxLimPct", 25)
			if err != nil {
				t.Fatalf("ProbeDenied returned a transport error: %v", err)
			}
			if res.Wrote {
				t.Fatalf("%s write was ACCEPTED — authz gap: %+v", role, res)
			}
			if !res.Denied || res.ExceptionCode != 1 {
				t.Errorf("%s denial = %+v, want Denied with exception 0x01 and nothing else", role, res)
			}
		})
	}
}

// TestEmulatorCore_PollStaleOnSentinel proves telemetry flips Stale when a
// nan_sentinel fault makes every register read as the SunSpec not-implemented
// sentinel — the freshness truth the gateway projects (design doc 02 §4.3).
func TestEmulatorCore_PollStaleOnSentinel(t *testing.T) {
	pki := newTestPKI(t)
	srv := startAuthzServer(t, pki, []uint8{2}, []Role{RoleGridService})
	refs := pki.refs(t)

	conn, err := ConnectAs(srv.addr(), RoleGridService, refs)
	if err != nil {
		t.Fatalf("ConnectAs: %v", err)
	}
	defer conn.Close()

	// Warm the reader cache with a clean scan before arming the fault, so the
	// sentinel read hits ReadModel (not the SunS scan, which would just fail to
	// find a header).
	if _, err := conn.Discover(context.Background(), 2); err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if snap := conn.Sample(2); snap.Stale {
		t.Fatalf("sample stale before any fault: %+v", snap)
	}

	if err := srv.applyFault([]byte(`{"kind":"nan_sentinel"}`)); err != nil {
		t.Fatalf("arm nan_sentinel: %v", err)
	}
	if snap := conn.Sample(2); !snap.Stale {
		t.Errorf("sample not stale under nan_sentinel: %+v", snap)
	}

	if err := srv.applyFault([]byte(`{"kind":"nan_sentinel","clear":true}`)); err != nil {
		t.Fatalf("clear nan_sentinel: %v", err)
	}
	if snap := conn.Sample(2); snap.Stale {
		t.Errorf("sample still stale after clearing nan_sentinel: %+v", snap)
	}
}

// TestEmulatorCore_PollLoop runs the telemetry loop in a goroutine, streaming
// samples into a RunState sink, and proves samples accrue and Latest/Snapshots
// expose the newest per unit. Run under -race, it exercises the concurrent
// poll/store/sink path against a foreground reader.
func TestEmulatorCore_PollLoop(t *testing.T) {
	pki := newTestPKI(t)
	srv := startAuthzServer(t, pki, []uint8{2, 3}, []Role{RoleGridService})
	refs := pki.refs(t)

	conn, err := ConnectAs(srv.addr(), RoleGridService, refs)
	if err != nil {
		t.Fatalf("ConnectAs: %v", err)
	}
	defer conn.Close()

	rs := NewRunState(srv.addr(), RoleGridService)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- conn.Poll(ctx, []uint8{2, 3}, 20*time.Millisecond, rs) }()

	// Wait until both units have a latest snapshot, then stop.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		_, ok2 := conn.Latest(2)
		_, ok3 := conn.Latest(3)
		if ok2 && ok3 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("Poll returned error: %v", err)
	}

	if _, ok := conn.Latest(2); !ok {
		t.Error("no latest snapshot for unit 2")
	}
	if len(conn.Snapshots()) != 2 {
		t.Errorf("Snapshots() = %d units, want 2", len(conn.Snapshots()))
	}
	if len(rs.Samples) == 0 {
		t.Error("RunState sink received no samples")
	}
}

// TestEmulatorCore_ReconnectAfterDrop proves the raw ops auto-redial after the
// session is dropped mid-exchange: a read fails while the drop is armed, then a
// read succeeds once the drop is cleared (the emulator re-established the session
// transparently).
func TestEmulatorCore_ReconnectAfterDrop(t *testing.T) {
	pki := newTestPKI(t)
	srv := startAuthzServer(t, pki, []uint8{2}, []Role{RoleGridService})
	refs := pki.refs(t)

	conn, err := ConnectAs(srv.addr(), RoleGridService, refs)
	if err != nil {
		t.Fatalf("ConnectAs: %v", err)
	}
	defer conn.Close()

	if _, err := conn.ReadHolding(2, sunspec.SunSpecBase, 2); err != nil {
		t.Fatalf("initial read: %v", err)
	}

	srv.dropNext.Store(true)
	if _, err := conn.ReadHolding(2, sunspec.SunSpecBase, 2); err == nil {
		t.Fatal("read succeeded while drop was armed, want a transport error")
	}

	srv.dropNext.Store(false)
	// The next op finds the session broken and redials once, transparently.
	deadline := time.Now().Add(5 * time.Second)
	var readErr error
	for time.Now().Before(deadline) {
		if _, readErr = conn.ReadHolding(2, sunspec.SunSpecBase, 2); readErr == nil {
			break
		}
	}
	if readErr != nil {
		t.Fatalf("read did not recover after clearing the drop: %v", readErr)
	}
}

func containsModel(models []uint16, id uint16) bool {
	for _, m := range models {
		if m == id {
			return true
		}
	}
	return false
}
