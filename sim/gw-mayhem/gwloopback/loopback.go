// Package gwloopback is the FAITHFUL hermetic stand-in gateway the gw-mayhem suite
// runs against with no bench access (make test-integration, and the runner's
// -loopback mode). It is kept in its own package so the gwmayhem library (families,
// oracles, runner) carries no mbtls.Listen SERVER path — its unit-test binary then
// links without pulling wolfSSL's server-side DH object, so make test-fast needs
// only the standard client link.
package gwloopback

// loopback.go is the faithful stand-in gateway. It is
// the same mbtls.Listen + mbap-dispatch-over-a-solar-register-world shape as the
// aggregator/ssm-conformance loopbacks, but tuned to model the REAL lexa-gw base
// mbaps-mode behaviour the mbaps-northbound-authz family judges — so a conformant
// stand-in makes every non-pinned scenario PASS hermetically, and the identical
// scenarios then run against the live :802 for the evidence runs:
//
//   - RBAC matrix: write is granted ONLY to GridService + SuperAdmin (ReadOnly,
//     LexaVolt, and — the non-obvious cell — NetworkAdmin are DENIED control writes
//     with 0x01); every recognized role may read.
//   - cert-authz: a role-less / malformed-role cert (chain valid) handshakes and is
//     denied every request with 0x01 (the acceptLoop keeps serving after a rejected
//     handshake, so an expired / wrong-CA cert simply fails to connect).
//   - malformed writes: an illegal FC and any denied op answer a bare 0x01; an
//     oversized frame is a framing violation the shared mbap.Decode rejects, closing
//     the session; a write to the read-only SunSpec marker answers 0x03; and — to
//     model the live gateway's GAP — an out-of-range control value is ACCEPTED (no
//     range check), keeping the pinned out-of-range scenario FAIL both here and live.
//   - transport: a small concurrent-session CAP refuses the flood's excess
//     post-handshake.

import (
	"errors"
	"net"
	"sync/atomic"

	"csip-tls-test/internal/aggregator"
	"csip-tls-test/internal/mbtls"
	sim "csip-tls-test/sim/southbound"
	"lexa-proto/mbap"
	"lexa-proto/sunspec"

	modbuslib "github.com/simonvetter/modbus"
)

// loopbackUnits are the units the loopback serves; every other unit answers 0x0A.
var loopbackUnits = []uint8{1, 2}

// loopbackWriteRoles is the faithful base-mode write-allow set: GridService (commanded
// controls) and SuperAdmin (rw *) only. ReadOnly / LexaVolt / NetworkAdmin are NOT here.
var loopbackWriteRoles = []aggregator.Role{aggregator.RoleGridService, aggregator.RoleSuperAdmin}

// defaultLoopbackCap is the concurrent-session cap the loopback enforces — the
// gateway-like MaxSessions=8, below the session-flood's floodN=12 (so the flood
// always observes refusals) but with headroom for the other families' sequential
// sessions.
const defaultLoopbackCap = 8

// LoopbackServer is the hermetic stand-in gateway.
type LoopbackServer struct {
	regs       *sim.RegisterMap
	served     map[uint8]bool
	writeRoles map[string]bool
	cap        int32
	active     int32
	lis        *mbtls.Listener
	srv        *sim.SolarServer
}

// StartLoopback binds the faithful loopback on 127.0.0.1:0 using serverProfile (the
// device server leaf + the client CA that verifies role certs) with the base-mode
// write-allow set. The caller closes it via the returned server's Close. cap ≤ 0
// uses defaultLoopbackCap.
func StartLoopback(serverProfile mbtls.Profile, sessionCap int) (*LoopbackServer, error) {
	return StartLoopbackWriteRoles(serverProfile, sessionCap, loopbackWriteRoles)
}

// StartLoopbackWriteRoles is StartLoopback with an explicit write-allow set — used
// by the "teeth" test to stand up a deliberately non-conformant peer (e.g. one that
// lets NetworkAdmin write) and prove the matrix oracle FAILs it.
func StartLoopbackWriteRoles(serverProfile mbtls.Profile, sessionCap int, writeRoles []aggregator.Role) (*LoopbackServer, error) {
	if sessionCap <= 0 {
		sessionCap = defaultLoopbackCap
	}
	srv, err := sim.NewSolarServerAdvanced("tcp://127.0.0.1:0", 5000, "")
	if err != nil {
		return nil, err
	}
	srv.Pause() // freeze the animation so reads/readbacks are deterministic
	lis, err := mbtls.Listen("127.0.0.1:0", serverProfile)
	if err != nil {
		srv.Stop()
		return nil, err
	}
	s := &LoopbackServer{
		regs:       srv.Regs,
		served:     boolSet(loopbackUnits),
		writeRoles: roleSet(writeRoles),
		cap:        int32(sessionCap),
		lis:        lis,
		srv:        srv,
	}
	go s.acceptLoop()
	return s, nil
}

// Addr is the loopback's listen address.
func (s *LoopbackServer) Addr() string { return s.lis.Addr().String() }

// Close tears the loopback down.
func (s *LoopbackServer) Close() {
	_ = s.lis.Close()
	s.srv.Stop()
}

func boolSet(units []uint8) map[uint8]bool {
	m := make(map[uint8]bool, len(units))
	for _, u := range units {
		m[u] = true
	}
	return m
}

func roleSet(roles []aggregator.Role) map[string]bool {
	m := make(map[string]bool, len(roles))
	for _, r := range roles {
		m[string(r)] = true
	}
	return m
}

// recognizedRoles is the set of the five known bench roles; a cert whose role is
// absent/malformed/unknown collapses to "no role" and is denied every request.
var recognizedRoles = func() map[string]bool {
	m := make(map[string]bool)
	for _, r := range aggregator.Roles() {
		m[string(r)] = true
	}
	return m
}()

func (s *LoopbackServer) acceptLoop() {
	for {
		sess, err := s.lis.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			continue // a rejected handshake (expired / wrong-CA) is expected; keep serving
		}
		// Session cap: an over-cap session is refused post-handshake — closed with no
		// Modbus traffic, exactly as the gateway's admit() does.
		if atomic.AddInt32(&s.active, 1) > s.cap {
			atomic.AddInt32(&s.active, -1)
			_ = sess.Close()
			continue
		}
		go func() {
			defer atomic.AddInt32(&s.active, -1)
			s.serve(sess)
		}()
	}
}

func (s *LoopbackServer) serve(sess *mbtls.Session) {
	defer sess.Close()
	role, _ := sess.Role() // "" for a role-less cert; authz below collapses it to no-write
	for {
		adu, err := mbap.Decode(sess.Conn)
		if err != nil {
			return // clean close or framing violation (oversized PDU) → close, never resync
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

// handle applies the unit map + role authz and dispatches reads/writes. Every
// denial collapses to a bare exception 0x01 (TCP-40/41), except the read-only-point
// refusal (0x03) and the unmapped-unit path (0x0A).
func (s *LoopbackServer) handle(req mbap.ADU, role string) mbap.ADU {
	if !s.served[req.UnitID] {
		return mbap.Exception(req, mbap.ExGatewayPath) // 0x0A unmapped unit
	}
	if !recognizedRoles[role] {
		return mbap.Exception(req, mbap.ExIllegalFunction) // 0x01 role-less / malformed
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
			return mbap.Exception(req, mbap.ExIllegalFunction) // 0x01 authz denial, nothing else
		}
		wreq, err := mbap.ParseWriteReq(req.PDU)
		if err != nil {
			return mbap.Exception(req, mbap.ExIllegalValue)
		}
		if readOnlyAddr(wreq.Addr) {
			// Defense in depth: a write to the read-only SunSpec marker is refused even
			// for an authz-allowed role (0x03), modelling the gateway's write decoder.
			return mbap.Exception(req, mbap.ExIllegalValue)
		}
		// NOTE: no numeric range check — an out-of-range control value (WMaxLimPct>100)
		// is ACCEPTED, modelling the live gateway's known gap (design 02 §4.4).
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
		return mbap.Exception(req, mbap.ExIllegalFunction) // any other FC → 0x01
	}
}

// readOnlyAddr reports whether addr is the read-only SunSpec identifier marker
// (40000: "SunS", 40001) — never a writable control register.
func readOnlyAddr(addr uint16) bool {
	return addr == sunspec.SunSpecBase || addr == sunspec.SunSpecBase+1
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
