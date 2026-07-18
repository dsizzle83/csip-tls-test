package main

// loopback.go is the in-process, authz-enforcing mbaps server the suite runs
// against by default (no -target). It is the same shape as the loopback server
// internal/aggregator's integration tests use: an mbtls.Listen server over
// sim/southbound's animated SunSpec register world, plus the two behaviours a
// real gateway has that a bare device sim does not —
//
//   - a per-device UNIT MAP: an unmapped unit answers exception 0x0A (PN-6, no
//     aggregate unit); and
//   - a role AUTHZ engine faithful enough that the §5.3 checks PASS against a
//     conformant peer: read-only roles' (and role-less / malformed-role certs')
//     writes answer exception 0x01 and nothing else (TCP-32/40/41), control
//     writes by GridService/Network/Super succeed, and every role may read.
//
// Running the suite against this loopback proves the checks have teeth (a
// non-conformant peer would FAIL them) with zero bench access; the identical
// checks then run against the live lexa-gw :802 for the evidence runs.

import (
	"errors"
	"net"
	"sync/atomic"

	"csip-tls-test/internal/aggregator"
	"csip-tls-test/internal/mbtls"
	sim "csip-tls-test/sim/southbound"
	"lexa-proto/mbap"

	modbuslib "github.com/simonvetter/modbus"
)

// loopbackServer is the suite's stand-in gateway.
type loopbackServer struct {
	regs       *sim.RegisterMap
	served     map[uint8]bool
	writeRoles map[string]bool
	lis        *mbtls.Listener
	srv        *sim.SolarServer
	dropNext   atomic.Bool // when set, close the next session mid-exchange (a drop fault)
}

// loopbackUnits are the units the loopback maps; every other unit answers 0x0A.
var loopbackUnits = []uint8{1, 2}

// startLoopback binds the loopback mbaps server on 127.0.0.1:0 using the minted
// device server leaf, trusting the minted client CA to verify role certs. Write
// is granted to GridService/Super/Network (the mbaps-mode control + admin roles);
// ReadOnly, LexaVolt, and role-less/malformed certs get read-only. The caller
// closes it via the returned stop func.
func startLoopback(ps *pkiSet) (*loopbackServer, func(), error) {
	return startLoopbackCustom(ps, loopbackUnits, []Role{aggregator.RoleGridService, aggregator.RoleSuperAdmin, aggregator.RoleNetworkAdmin})
}

// startLoopbackCustom is startLoopback with an explicit served-unit set and
// write-role set — used by the "teeth" test to stand up a deliberately
// non-conformant peer (e.g. one that lets a read-only role write) and prove the
// §5.3 checks FAIL it.
func startLoopbackCustom(ps *pkiSet, served []uint8, writeRoles []Role) (*loopbackServer, func(), error) {
	srv, err := sim.NewSolarServerAdvanced("tcp://127.0.0.1:0", 5000)
	if err != nil {
		return nil, nil, err
	}
	srv.Pause() // freeze the animation so reads/readbacks are deterministic

	profile := mbtls.DefaultServerProfile(ps.clientCA, ps.devServer.certFile, ps.devServer.keyFile)
	lis, err := mbtls.Listen("127.0.0.1:0", profile)
	if err != nil {
		srv.Stop()
		return nil, nil, err
	}
	s := &loopbackServer{
		regs:       srv.Regs,
		served:     boolSet(served),
		writeRoles: roleSet(writeRoles),
		lis:        lis,
		srv:        srv,
	}
	go s.acceptLoop()
	stop := func() {
		_ = lis.Close()
		srv.Stop()
	}
	return s, stop, nil
}

func (s *loopbackServer) addr() string { return s.lis.Addr().String() }

func boolSet(units []uint8) map[uint8]bool {
	m := make(map[uint8]bool, len(units))
	for _, u := range units {
		m[u] = true
	}
	return m
}

func roleSet(roles []Role) map[string]bool {
	m := make(map[string]bool, len(roles))
	for _, r := range roles {
		m[string(r)] = true
	}
	return m
}

func (s *loopbackServer) acceptLoop() {
	for {
		sess, err := s.lis.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			continue // a rejected handshake (no-cert/wrong-ca) is expected; keep serving
		}
		go s.serve(sess)
	}
}

func (s *loopbackServer) serve(sess *mbtls.Session) {
	defer sess.Close()
	role, _ := sess.Role() // "" for a role-less cert; authz below collapses that to no-write
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

// recognizedRoles is the set of the five known bench roles. A cert whose role
// is absent, malformed, empty, or otherwise unknown collapses to "no role" here
// (RoleFromDER returned "" or an error) and is denied EVERY request with 0x01
// (TCP-32, design 01 §3.1) — distinct from a valid read-only role, which may read.
var recognizedRoles = func() map[string]bool {
	m := make(map[string]bool)
	for _, r := range aggregator.Roles() {
		m[string(r)] = true
	}
	return m
}()

// handle applies the unit map + role authz and dispatches reads/writes to the
// register world. AuthZ denial and any unsupported function collapse to a bare
// exception 0x01 (TCP-40/41), exactly as the mbap contract mandates.
func (s *loopbackServer) handle(req mbap.ADU, role string) mbap.ADU {
	if !s.served[req.UnitID] {
		return mbap.Exception(req, mbap.ExGatewayPath) // 0x0A unmapped unit (PN-6)
	}
	if !recognizedRoles[role] {
		// No role / malformed role ⇒ every request denied with 0x01 (TCP-32).
		return mbap.Exception(req, mbap.ExIllegalFunction)
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
		return mbap.Exception(req, mbap.ExIllegalFunction) // other FCs → 0x01 (TCP FC map)
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
