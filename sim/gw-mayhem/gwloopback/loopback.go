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
//     the session; a write to the read-only SunSpec marker answers 0x03; and an
//     out-of-range 704 control value (WMaxLimPct outside [0,100], WSetPct/VarSetPct
//     outside [-100,100]) is REFUSED with 0x03 and never applied.
//   - transport: a small concurrent-session CAP refuses the flood's excess
//     post-handshake.
//
// A role the loopback CANNOT ESTABLISH is not a denial. If a session's peer
// identity is unavailable (mbtls.ErrPeerIdentityUnavailable — a resumed session
// whose peer certificate could not be recovered; see internal/mbtls/peerid.go) the
// loopback REFUSES to serve it: it closes the session and counts the refusal,
// rather than answering the bare 0x01 that means "authorization denied". Those are
// different claims, and answering the second for the first is exactly the bug that
// made this gate ORDER-DEPENDENT — an earlier scenario's cached TLS session cost a
// later one its role, and the suite recorded a fictional authz denial (4caad35).
// mbtls now recovers the identity, so this path should never fire; it stays as the
// backstop, because the failure it guards against is silent by construction. A
// transport failure, which the oracles score INCONCLUSIVE, is the honest outcome:
// the harness could not observe the gateway's answer, so it must not report one.
//
// The out-of-range behaviour used to be inverted here: this loopback deliberately
// modelled a live-gateway GAP (no range check) so the pinned out-of-range scenario
// FAILed in both places. That gap was CLOSED in the product (bounded signed
// setpoints; out-of-range WMaxLimPct -> exception 0x03) and the model was never
// updated, so the hermetic gate FAILed permanently on a case the real gateway
// passes — verified 2026-07-26 against the live :802, which correctly rejects all
// five out-of-range probes with 0x03. A gate that fails on known-good behaviour
// trains its operators to ignore it, which is worse than having no gate, so the
// model now tracks the shipped behaviour.

import (
	"errors"
	"log"
	"math"
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

// LoopbackWriteRoles is the faithful write-allow set, for a test that stands up a
// deliberately non-conformant peer with StartLoopbackWriteRoles and needs to pair
// it against the honest one. Returns a copy: the shipped set is not a knob.
func LoopbackWriteRoles() []aggregator.Role {
	out := make([]aggregator.Role, len(loopbackWriteRoles))
	copy(out, loopbackWriteRoles)
	return out
}

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
	// idRefusals counts sessions refused because their peer identity could not be
	// established (never a denial — see the package comment). It is exported through
	// IdentityRefusals so a harness can assert the backstop fired, and so a run that
	// hit it can say so instead of silently reporting authz verdicts it never reached.
	idRefusals int64
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

// IdentityRefusals is how many sessions this loopback refused because it could not
// establish the peer's identity. It must be 0 in a healthy run; a non-zero count
// means some scenario's verdict was reached without the loopback knowing who was
// asking, and the run's authz evidence is worth nothing until that is explained.
func (s *LoopbackServer) IdentityRefusals() int64 { return atomic.LoadInt64(&s.idRefusals) }

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
	// "" for a role-less cert — authz below collapses that to no-write, which is a
	// real verdict about a real certificate. An identity we could not establish is
	// NOT that: refuse the session rather than dress a harness fault up as a denial.
	role, roleErr := sess.Role()
	if errors.Is(roleErr, mbtls.ErrPeerIdentityUnavailable) {
		atomic.AddInt64(&s.idRefusals, 1)
		log.Printf("[gwloopback] refusing session from %s: %v (resumed=%t) — "+
			"a role that cannot be established is not an authorization denial",
			sess.Conn.RemoteAddr(), roleErr, sess.Resumed)
		return
	}
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
		// Numeric range check on the 704 control points, mirroring the gateway's write
		// decoder: an out-of-range setpoint is refused with 0x03 and NEVER applied.
		if !s.inRange704(wreq.Addr, wreq.Values) {
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
		return mbap.Exception(req, mbap.ExIllegalFunction) // any other FC → 0x01
	}
}

// readOnlyAddr reports whether addr is the read-only SunSpec identifier marker
// (40000: "SunS", 40001) — never a writable control register.
func readOnlyAddr(addr uint16) bool {
	return addr == sunspec.SunSpecBase || addr == sunspec.SunSpecBase+1
}

// ctlRange is one 704 control point's permitted range in ENGINEERING units
// (percent), as the SunSpec DER AC Controls model defines it.
type ctlRange struct {
	point  string
	sfName string
	signed bool
	lo, hi float64
}

// ctlRanges are the 704 setpoints the gateway's write decoder bounds. WMaxLimPct is
// an unsigned percent-of-max; WSetPct and VarSetPct are signed (a real negative
// commands import / absorb), which is why the -150 probes are distinct cases from
// the +150 ones rather than the same test twice.
var ctlRanges = []ctlRange{
	{"WMaxLimPct", "WMaxLimPct_SF", false, 0, 100},
	{"WSetPct", "WSetPct_SF", true, -100, 100},
	{"VarSetPct", "VarSetPct_SF", true, -100, 100},
}

// find704Base walks the SunSpec model chain to the DER AC Controls (704) data block,
// exactly as a conformant client would: past the "SunS" marker, then header by
// header until the model id matches or the 0xFFFF end marker is reached. Walking
// rather than hardcoding an offset keeps this correct if the served model set
// changes, and it fails closed (ok=false) rather than validating against a
// misidentified block.
func (s *LoopbackServer) find704Base() (uint16, bool) {
	addr := uint16(sunspec.SunSpecBase + 2) // skip the 2-register "SunS" identifier
	for i := 0; i < 64; i++ {               // bounded: a corrupt map must not spin
		id := s.regs.Get(addr)
		if id == 0xFFFF {
			return 0, false
		}
		length := s.regs.Get(addr + 1)
		if id == uint16(sunspec.ModelDERCtlAC) {
			return addr + 2, true // data starts after the (id, len) header
		}
		if length == 0 {
			return 0, false // malformed header; stop rather than loop forever
		}
		addr += 2 + length
	}
	return 0, false
}

// inRange704 reports whether a write to [addr, addr+len) leaves every 704 control
// point it touches within range. Values are compared in ENGINEERING units — the raw
// register is scaled by the model's own scale factor, read live from the map — because
// that is where the limit is defined and where the real gateway enforces it. A raw
// comparison would silently pass or fail depending on the SF the device happens to
// publish.
//
// Writes that touch no bounded point are unaffected, so this cannot make an unrelated
// write fail.
func (s *LoopbackServer) inRange704(addr uint16, values []uint16) bool {
	base, ok := s.find704Base()
	if !ok {
		return true // no 704 served: nothing to bound
	}
	for _, cr := range ctlRanges {
		pAddr := base + uint16(sunspec.L704.Offset(cr.point))
		idx := int(pAddr) - int(addr)
		if idx < 0 || idx >= len(values) {
			continue // this write does not cover the point
		}
		sf := int16(s.regs.Get(base + uint16(sunspec.L704.Offset(cr.sfName))))
		var eng float64
		if cr.signed {
			eng = float64(int16(values[idx]))
		} else {
			eng = float64(values[idx])
		}
		eng *= math.Pow(10, float64(sf))
		if eng < cr.lo || eng > cr.hi {
			return false
		}
	}
	return true
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
