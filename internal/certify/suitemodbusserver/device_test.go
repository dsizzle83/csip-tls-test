package suitemodbusserver

// device_test.go is the loopback DUT: an in-process SunSpec Modbus server with
// a knob for every way a device can be non-conformant.
//
// This follows the pattern sim/ssm-conformance established and this repository
// insists on: a conformance check whose only proof is that it passes against a
// good device proves nothing, because a check that always returns PASS passes
// against a good device too. Every check in this package is therefore tested
// twice — once against a device built to the specification, and once against a
// device broken in exactly the way that check exists to catch.
//
// The server also RECORDS the bytes of every connection, so the tests can
// synthesise a packet capture containing the real exchange and drive the whole
// two-phase pipeline — live check, capture stop, frame attribution, citation,
// bundle — without a NIC, root, or dumpcap.

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"csip-tls-test/internal/evidence/netdis"
	"csip-tls-test/internal/evidence/pcapng"
	"lexa-proto/mbap"
)

// deviceOpts are the non-conformance knobs. The zero value is a conformant
// device.
type deviceOpts struct {
	// Full1547 adds the models the IEEE 1547-2018 profile requires beyond the
	// gateway's v1 set, so MOD-4's model-presence criterion can pass.
	Full1547 bool
	// EndModelLen makes the end model declare a nonzero length (DEV-1).
	EndModelLen uint16
	// BlankManufacturer leaves model 1's Mn reading all zeros, its string
	// type's not-implemented value (DEV-2).
	BlankManufacturer bool
	// UnimplementedACType makes model 701's mandatory ACType read 0xFFFF
	// (MOD-1).
	UnimplementedACType bool
	// MaxReadQuantity, when nonzero, makes the device refuse an FC 3 request
	// for more registers than this — a device that cannot serve a whole model
	// in one read (MOD-2).
	MaxReadQuantity uint16
	// BadScaleFactor puts an out-of-range value in one sunssf point (1547 §2.4).
	BadScaleFactor bool
	// DenyWrites, when nonzero, answers every write with this exception,
	// standing in for the gateway's control-authority overlay (0x01) or its
	// unexecuted-point gate (0x02).
	DenyWrites mbap.ExCode
	// AcceptInvalidValues applies an out-of-enumeration or out-of-range write
	// instead of refusing it (EXC-1).
	AcceptInvalidValues bool
	// AcceptReadOnlyWrites applies a write to a read-only register (EXC-2).
	AcceptReadOnlyWrites bool
	// AnswerUnknownFunction answers an undefined function code with a normal
	// response (EXC-3).
	AnswerUnknownFunction bool
	// NoSingleWrite refuses FC 6 (MB-1).
	NoSingleWrite bool
	// ClampWMaxLimPct, when nonzero, ACCEPTS a write of 704.WMaxLimPct above
	// this value but silently stores the ceiling instead — the device that
	// acknowledges a write it did not honour, which is exactly what MOD-3's
	// read-after-write step exists to catch.
	ClampWMaxLimPct uint16
	// WMaxLimPctAtCeiling seeds 704.WMaxLimPct at its engineering-range
	// ceiling under scale factor -2 (raw 10000 = 100.00 %) instead of the
	// default mid-range seed, reproducing the shape
	// runs/final-fullsuite-20260731T234821 found: a prior case (EXC-1) can
	// leave the point sitting at its ceiling, and MB-1's perturbation must
	// still land on an in-range value rather than incrementing past it.
	WMaxLimPctAtCeiling bool
	// NoReassembly closes the connection when a read does not deliver a whole
	// ADU — the server that assumes one segment is one PDU (TCP-3, TCP-2).
	NoReassembly bool
	// FrameBudget, when nonzero, is how long this device waits for the REST of
	// a frame whose MBAP header has already promised a length. On expiry it
	// DISCARDS the partial accumulation and resynchronises on whatever arrives
	// next, answering it normally on the SAME connection.
	//
	// It is the knob that makes TCP-2's timing testable, and it is a real frame
	// budget rather than a switch: with it set, whether the check passes
	// depends on whether the check actually WAITED. A harness that pauses less
	// than this hands the device a follow-up while it is still assembling, and
	// gets the spliced answer under the stale transaction id — which is the
	// misreading TCP-2's pause exists to avoid, reproduced here on demand.
	//
	// The device with a budget and the device without are both conformant
	// shapes; a device with NO budget (the zero value here) is the one that
	// waits forever, and after a pause past any real budget its splice is a
	// genuine mis-parse.
	FrameBudget time.Duration
	// NoReversionReadback makes the remaining-time point read its
	// not-implemented value (REV-1).
	NoReversionReadback bool
	// ReversionNeverFires arms the timer but never applies the reversion
	// (REV-1).
	ReversionNeverFires bool
	// ReversionUnextendable ignores a rewrite of the timer once it is running
	// (REV-2).
	ReversionUnextendable bool
	// ReversionUncancellable ignores a write of 0 to a running timer (REV-3).
	ReversionUncancellable bool
	// Unit is the Modbus unit identifier the device answers on; 0 means 1.
	Unit uint8

	// LegacyModels chains the legacy 12x family the gateway's Stage-6
	// read-only projection serves — 126/127/128/129/130/131/132/134/160 — so
	// CRV-1's per-model read-only verification has subjects. Model 133 is
	// deliberately NOT in that list: the projection serves no 133 on any unit,
	// and CRV-1 has to report that as a named row rather than a silence, which
	// only a device that genuinely lacks it can prove.
	LegacyModels bool
	// LegacyOmit drops legacy models from the chain, standing in for a unit
	// whose own DER does not serve them (the chain is device-conditional).
	LegacyOmit []uint16
	// LegacyAcceptWrite makes this one legacy model APPLY a write instead of
	// refusing it — the device that acknowledges a write to a model it serves
	// read-only, which is the defect CRV-1's write probe exists to catch. The
	// acknowledgement is the failure whether or not the value moves, so this
	// knob stores the value too, giving the check no easier tell.
	LegacyAcceptWrite uint16
	// LegacyEchoWrong makes this one legacy model APPLY a write and then answer
	// it with a normal FC 6 response carrying a corrupted echo. It is the
	// nastier half of LegacyAcceptWrite: the write both succeeded and came back
	// as a protocol error, so a check that decided "refused or not" from the
	// client library's error alone would score it a refusal. The response's
	// function code is the only honest discriminator, and it says ACK.
	LegacyEchoWrong uint16
	// LegacyDenyCode overrides the exception every legacy model refuses with.
	// Zero means the real gateway's ladder: 0x02 (the SUN-002 executor gate)
	// for the eight models with a commanded group, 0x03 (the write decoder's
	// defence in depth) for 160, which has none.
	LegacyDenyCode mbap.ExCode
}

// legacyBlockLen is each legacy model's data-block length — the value its L
// register declares — under the projection's pinned geometry: a 10-register
// header plus NCrv=1 bank of the model's own fixed bank length (54 registers on
// 126/131/132, 50 on 129/130, 58 on 134); 127 and 128 carry no bank at all; 160
// is an 8-register header plus two 20-register DC-module blocks.
var legacyBlockLen = map[uint16]uint16{
	126: 10 + 54, 127: 10, 128: 14,
	129: 10 + 50, 130: 10 + 50, 131: 10 + 54,
	132: 10 + 54, 134: 10 + 58, 160: 8 + 2*20,
}

// legacyChainOrder is the order the gateway appends the legacy family in:
// after every 7xx model, so adding them moves no register of a unit that
// already existed (lexa-gw internal/regmap/chain.go:159-166).
var legacyChainOrder = []uint16{126, 127, 128, 129, 130, 131, 132, 134, 160}

// recSeg is one recorded TCP payload.
type recSeg struct {
	toServer bool
	peer     netip.AddrPort
	data     []byte
	at       time.Time
}

// device is the loopback SunSpec Modbus server.
type device struct {
	opts deviceOpts

	mu   sync.Mutex
	regs map[uint16]uint16
	rw   map[uint16]bool
	segs []recSeg

	// reversion state for model 704's WMaxLimPct group.
	revExpiry time.Time
	revArmed  bool

	base   uint16
	models []modelRef

	lis  net.Listener
	self netip.AddrPort
}

// enumBounds are the value grammars the device enforces, keyed by "model.point".
var deviceEnums = map[string][2]int64{
	"704.WMaxLimPctEna":     {0, 1},
	"704.WMaxLimPctEnaRvrt": {0, 1},
	"704.WMaxLimPctRvrt":    {0, 100},
	"704.PFWInjEna":         {0, 1},
	"704.VarSetEna":         {0, 1},
	"704.WSetEna":           {0, 1},
}

// newDevice lays out a chain and starts a listener.
func newDevice(t *testing.T, opts deviceOpts) *device {
	t.Helper()
	d := &device{
		opts: opts,
		regs: map[uint16]uint16{},
		rw:   map[uint16]bool{},
		base: 40000,
	}
	if d.opts.Unit == 0 {
		d.opts.Unit = 1
	}

	ids := []uint16{1, 701, 702, 704}
	if opts.Full1547 {
		ids = []uint16{1, 701, 702, 703, 704, 705, 706, 707, 708, 709, 710, 711, 712, 713}
	}
	if opts.LegacyModels {
		omit := map[uint16]bool{}
		for _, id := range opts.LegacyOmit {
			omit[id] = true
		}
		for _, id := range legacyChainOrder {
			if !omit[id] {
				ids = append(ids, id)
			}
		}
	}

	d.regs[d.base] = sunSMarker0
	d.regs[d.base+1] = sunSMarker1
	addr := d.base + 2
	for _, id := range ids {
		def, transcribed := Models[id]
		l := uint16(0)
		switch {
		case transcribed && def.L > 0:
			l = uint16(def.L)
		case id == 714:
			l = 18
		case legacyBlockLen[id] != 0:
			l = legacyBlockLen[id]
		default:
			// A curve model this suite does not transcribe: give it a plausible
			// body so the walk has something to skip.
			l = 24
		}
		d.models = append(d.models, modelRef{ID: id, Addr: addr, L: l, DataAddr: addr + 2})
		switch {
		case transcribed:
			d.seedModel(addr, def)
		default:
			for i := uint16(0); i < l; i++ {
				d.regs[addr+2+i] = 0
			}
			if legacyBlockLen[id] != 0 {
				d.seedLegacy(addr, id)
			}
		}
		// The header goes in AFTER the body seed, which zero-fills every point
		// including ID and L.
		d.regs[addr] = id
		d.regs[addr+1] = l
		addr += 2 + l
	}
	d.regs[addr] = endModelID
	d.regs[addr+1] = opts.EndModelLen

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	d.lis = lis
	ap, err := netip.ParseAddrPort(lis.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	d.self = ap
	go d.serve()
	t.Cleanup(func() { _ = lis.Close() })
	return d
}

// seedModel writes plausible, conformant values for one model's points.
func (d *device) seedModel(base uint16, def *Model) {
	put := func(off int, vals ...uint16) {
		for i, v := range vals {
			d.regs[base+uint16(off+i)] = v
		}
	}
	putStr := func(off, size int, s string) {
		b := make([]byte, size*2)
		copy(b, s)
		for i := 0; i < size; i++ {
			d.regs[base+uint16(off+i)] = binary.BigEndian.Uint16(b[i*2 : i*2+2])
		}
	}
	for _, p := range def.Points {
		switch p.Type {
		case TypePad:
			put(p.Off, 0x8000)
		case TypeSunSSF:
			var minusOne int16 = -1
			put(p.Off, uint16(minusOne))
		default:
			for i := 0; i < p.Regs(); i++ {
				put(p.Off+i, 0)
			}
		}
		if p.Access == AccessRW {
			for i := 0; i < p.Regs(); i++ {
				d.rw[base+uint16(p.Off+i)] = true
			}
		}
	}
	switch def.ID {
	case 1:
		if !d.opts.BlankManufacturer {
			putStr(2, 16, "LEXA Bench")
		}
		putStr(18, 16, "loopback-dut")
		putStr(34, 8, "opt")
		putStr(42, 8, "1.0.0")
		putStr(50, 16, "SN-0001")
		put(66, 1) // DA
	case 701:
		if d.opts.UnimplementedACType {
			put(2, 0xFFFF)
		} else {
			put(2, 2) // THREE_PHASE
		}
		put(3, 1) // St = ON
		put(5, 1) // ConnSt = CONNECTED
		put(15, 2400, 1385)
		put(46, 4160, 2400, 0) // VL1L2, VL1
		put(69, 4160, 2400)    // VL2L3, VL2
		put(92, 4160, 2400)    // VL3L1, VL3
		if d.opts.BadScaleFactor {
			var outOfRange int16 = 20 // V_SF outside the sunssf range -10..10
			put(114, uint16(outOfRange))
		}
	case 702:
		put(2, 8000) // WMaxRtg
	case 704:
		put(14, 0) // WMaxLimPctEna
		if d.opts.WMaxLimPctAtCeiling {
			var sf int16 = -2
			put(15, 10000)      // WMaxLimPct: raw ceiling under SF -2
			put(54, uint16(sf)) // WMaxLimPct_SF: -2
		} else {
			put(15, 50) // WMaxLimPct
			put(54, 0)  // WMaxLimPct_SF: percent carried directly in the register
		}
		put(16, 10) // WMaxLimPctRvrt
		put(20, 0, 0)
	}
}

// seedLegacy writes a plausible header for one legacy model. Only the points
// this suite transcribes (each model's probe register) and the geometry a
// reader would sanity-check are given real values; the rest of the bank stays
// zero, which is what an untranscribed block looks like to this suite anyway.
//
// The values are chosen so a probe register never reads 0: an Observed field
// saying "read 0x0000 before the write and 0x0000 after" would be true of a
// device that had no such register at all.
func (d *device) seedLegacy(base uint16, id uint16) {
	put := func(off int, v uint16) { d.regs[base+uint16(off)] = v }
	switch id {
	case 127:
		put(2, 40) // WGra, % PM/Hz
	case 128:
		put(2, 1) // ArGraMod = CENTER
	case 160:
		put(8, 2)  // N: two DC-input modules, matching the block length above
		put(9, 60) // TmsPer
	default:
		// The six curve-bank models share a header: ActCrv selects the live
		// bank (1-based), ModEna bit 0 switches the function on, NCrv/NPt
		// declare the geometry.
		put(2, 1)  // ActCrv
		put(3, 0)  // ModEna: the function is off
		put(7, 1)  // NCrv
		put(8, 10) // NPt
	}
}

// legacyModelAt reports which legacy model owns an absolute address.
func (d *device) legacyModelAt(addr uint16) (uint16, bool) {
	for _, m := range d.models {
		if legacyBlockLen[m.ID] == 0 {
			continue
		}
		if addr >= m.Addr && int(addr) < int(m.Addr)+m.span() {
			return m.ID, true
		}
	}
	return 0, false
}

// legacyDenyCode is the exception a legacy write is refused with, mirroring the
// gateway's own ladder (lexa-gw internal/listener/serve.go steps 7 and 7b): a
// point in the model's commanded group reaches writes.CheckExecutable and is
// refused 0x02 because no executor applies it, while model 160 — which declares
// no writable point at all, so it has no commanded group — is refused 0x03 by
// the write decoder before the executor question is asked.
func (d *device) legacyDenyCode(id uint16) mbap.ExCode {
	if d.opts.LegacyDenyCode != 0 {
		return d.opts.LegacyDenyCode
	}
	if id == 160 {
		return mbap.ExIllegalValue
	}
	return mbap.ExIllegalAddress
}

// Addr is the device's listen address.
func (d *device) Addr() string { return d.lis.Addr().String() }

func (d *device) serve() {
	for {
		conn, err := d.lis.Accept()
		if err != nil {
			return
		}
		go d.session(conn)
	}
}

func (d *device) session(conn net.Conn) {
	defer func() { _ = conn.Close() }()
	peer, err := netip.ParseAddrPort(conn.RemoteAddr().String())
	if err != nil {
		return
	}

	buf := make([]byte, 4096)
	var acc []byte
	for {
		// The frame budget only runs while a frame is PART-ASSEMBLED: an idle
		// connection with nothing accumulated is not mid-frame, and a device
		// that closed one would be testing a different property.
		if d.opts.FrameBudget > 0 && len(acc) > 0 {
			_ = conn.SetReadDeadline(time.Now().Add(d.opts.FrameBudget))
		} else {
			_ = conn.SetReadDeadline(time.Time{})
		}
		n, err := conn.Read(buf)
		if n > 0 {
			d.record(true, peer, buf[:n])
			acc = append(acc, buf[:n]...)
		}
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() && len(acc) > 0 {
				// Budget expired mid-frame: drop the partial frame and
				// resynchronise, rather than splicing the next bytes onto it.
				acc = acc[:0]
				continue
			}
			return
		}
		progressed := false
		for len(acc) >= 7 {
			length := int(binary.BigEndian.Uint16(acc[4:6]))
			if length < 3 || length > 254 {
				return
			}
			end := 6 + length
			if len(acc) < end {
				break
			}
			req := mbap.ADU{
				Header: mbap.Header{
					TID:    binary.BigEndian.Uint16(acc[0:2]),
					PID:    binary.BigEndian.Uint16(acc[2:4]),
					Length: uint16(length),
					UnitID: acc[6],
				},
				PDU: append([]byte(nil), acc[7:end]...),
			}
			acc = acc[end:]
			progressed = true
			resp := d.handle(req)
			frame, err := mbap.Encode(resp)
			if err != nil {
				return
			}
			d.record(false, peer, frame)
			if _, err := conn.Write(frame); err != nil {
				return
			}
		}
		if d.opts.NoReassembly && !progressed && len(acc) > 0 {
			// A device that assumes one read is one PDU: it never waits for the
			// rest of a split frame.
			return
		}
	}
}

func (d *device) record(toServer bool, peer netip.AddrPort, b []byte) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.segs = append(d.segs, recSeg{toServer: toServer, peer: peer, data: append([]byte(nil), b...), at: time.Now()})
}

// pointAt resolves an absolute address to the model and point that own it.
func (d *device) pointAt(addr uint16) (modelRef, Point, bool) {
	for _, m := range d.models {
		def, ok := Models[m.ID]
		if !ok {
			continue
		}
		if addr < m.Addr || int(addr) >= int(m.Addr)+m.span() {
			continue
		}
		off := int(addr - m.Addr)
		for _, p := range def.Points {
			if off >= p.Off && off < p.End() {
				return m, p, true
			}
		}
		return m, Point{}, false
	}
	return modelRef{}, Point{}, false
}

func (d *device) inMap(addr uint16) bool {
	_, ok := d.regs[addr]
	return ok
}

func (d *device) handle(req mbap.ADU) mbap.ADU {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.settleReversion()

	if req.UnitID != d.opts.Unit {
		return mbap.Exception(req, mbap.ExGatewayPath)
	}
	if len(req.PDU) < 1 {
		return mbap.Exception(req, mbap.ExIllegalValue)
	}
	switch req.PDU[0] {
	case fcReadHolding:
		if len(req.PDU) != 5 {
			return mbap.Exception(req, mbap.ExIllegalValue)
		}
		addr := binary.BigEndian.Uint16(req.PDU[1:3])
		count := binary.BigEndian.Uint16(req.PDU[3:5])
		if count == 0 || count > maxReadRegisters {
			return mbap.Exception(req, mbap.ExIllegalValue)
		}
		if d.opts.MaxReadQuantity != 0 && count > d.opts.MaxReadQuantity {
			return mbap.Exception(req, mbap.ExIllegalValue)
		}
		for i := 0; i < int(count); i++ {
			if !d.inMap(addr + uint16(i)) {
				return mbap.Exception(req, mbap.ExIllegalAddress)
			}
		}
		pdu := make([]byte, 2+int(count)*2)
		pdu[0] = fcReadHolding
		pdu[1] = byte(count * 2)
		for i := 0; i < int(count); i++ {
			binary.BigEndian.PutUint16(pdu[2+i*2:4+i*2], d.readReg(addr+uint16(i)))
		}
		return mbap.ADU{Header: mbap.Header{TID: req.TID, UnitID: req.UnitID}, PDU: pdu}

	case fcWriteSingle:
		if d.opts.NoSingleWrite {
			return mbap.Exception(req, mbap.ExIllegalFunction)
		}
		if len(req.PDU) != 5 {
			return mbap.Exception(req, mbap.ExIllegalValue)
		}
		addr := binary.BigEndian.Uint16(req.PDU[1:3])
		val := binary.BigEndian.Uint16(req.PDU[3:5])
		if ex := d.applyWrite(addr, []uint16{val}); ex != 0 {
			return mbap.Exception(req, ex)
		}
		pdu := req.PDU
		if id, ok := d.legacyModelAt(addr); ok && d.opts.LegacyEchoWrong == id {
			// A NORMAL response — function code 0x06, not 0x86 — that echoes
			// the wrong value back. Acknowledged and malformed at once.
			bad := append([]byte(nil), req.PDU...)
			binary.BigEndian.PutUint16(bad[3:5], val^0xFFFF)
			pdu = bad
		}
		return mbap.ADU{Header: mbap.Header{TID: req.TID, UnitID: req.UnitID}, PDU: pdu}

	case fcWriteMultiple:
		if len(req.PDU) < 6 {
			return mbap.Exception(req, mbap.ExIllegalValue)
		}
		addr := binary.BigEndian.Uint16(req.PDU[1:3])
		count := int(binary.BigEndian.Uint16(req.PDU[3:5]))
		if len(req.PDU) != 6+count*2 {
			return mbap.Exception(req, mbap.ExIllegalValue)
		}
		vals := make([]uint16, count)
		for i := range vals {
			vals[i] = binary.BigEndian.Uint16(req.PDU[6+i*2 : 8+i*2])
		}
		if ex := d.applyWrite(addr, vals); ex != 0 {
			return mbap.Exception(req, ex)
		}
		echo := make([]byte, 5)
		echo[0] = fcWriteMultiple
		binary.BigEndian.PutUint16(echo[1:3], addr)
		binary.BigEndian.PutUint16(echo[3:5], uint16(count))
		return mbap.ADU{Header: mbap.Header{TID: req.TID, UnitID: req.UnitID}, PDU: echo}

	default:
		if d.opts.AnswerUnknownFunction {
			return mbap.ADU{Header: mbap.Header{TID: req.TID, UnitID: req.UnitID},
				PDU: []byte{req.PDU[0], 0x00}}
		}
		return mbap.Exception(req, mbap.ExIllegalFunction)
	}
}

// readReg returns a register, computing the reversion readback live.
func (d *device) readReg(addr uint16) uint16 {
	m, p, ok := d.pointAt(addr)
	if ok && m.ID == 704 && p.Name == "WMaxLimPctRvrtRem" {
		if d.opts.NoReversionReadback {
			if addr == m.Addr+uint16(p.Off) {
				return 0xFFFF
			}
			return 0xFFFF
		}
		rem := uint32(0)
		if d.revArmed {
			if left := time.Until(d.revExpiry); left > 0 {
				rem = uint32(left.Round(time.Second) / time.Second)
			}
		}
		if addr == m.Addr+uint16(p.Off) {
			return uint16(rem >> 16)
		}
		return uint16(rem)
	}
	return d.regs[addr]
}

// applyWrite is the device's write ladder. It returns 0 on success.
func (d *device) applyWrite(addr uint16, vals []uint16) mbap.ExCode {
	if d.opts.DenyWrites != 0 {
		return d.opts.DenyWrites
	}
	for i := range vals {
		if !d.inMap(addr + uint16(i)) {
			return mbap.ExIllegalAddress
		}
	}
	// The legacy family's read-only posture, refused BEFORE any acknowledgement
	// — or, with LegacyAcceptWrite, the defect where it is not.
	if id, ok := d.legacyModelAt(addr); ok {
		if d.opts.LegacyAcceptWrite != id && d.opts.LegacyEchoWrong != id {
			return d.legacyDenyCode(id)
		}
		for i, v := range vals {
			d.regs[addr+uint16(i)] = v
		}
		return 0
	}
	// Read-only refusal.
	for i := range vals {
		if !d.rw[addr+uint16(i)] {
			if d.opts.AcceptReadOnlyWrites {
				continue
			}
			return mbap.ExIllegalValue
		}
	}
	// Value grammar.
	if !d.opts.AcceptInvalidValues {
		for i := range vals {
			m, p, ok := d.pointAt(addr + uint16(i))
			if !ok || p.Name == "" {
				continue
			}
			if m.ID == 704 && p.Name == "WMaxLimPct" {
				// SF-aware, mirroring both the real DUT's decode.go and this
				// suite's own writes.go rawBounds: the engineering range is
				// fixed (0..100 %) but the raw bound depends on the scale
				// factor the device itself reports, which
				// WMaxLimPctAtCeiling moves away from 0. A fixed {0,100} raw
				// bound here would silently stop matching the device once
				// the scale factor does.
				sfPt, _ := Models[704].Point("WMaxLimPct_SF")
				sf := int16(d.regs[m.Addr+uint16(sfPt.Off)])
				adj, _ := adjustableFor(704, "WMaxLimPct")
				lo, hi := rawBounds(adj, int(sf))
				v := int64(vals[i])
				if v < lo || v > hi {
					return mbap.ExIllegalValue
				}
				continue
			}
			bounds, has := deviceEnums[fmt.Sprintf("%d.%s", m.ID, p.Name)]
			if !has {
				continue
			}
			v := int64(vals[i])
			if v < bounds[0] || v > bounds[1] {
				return mbap.ExIllegalValue
			}
		}
	}
	for i, v := range vals {
		if d.opts.ClampWMaxLimPct != 0 {
			if m, p, ok := d.pointAt(addr + uint16(i)); ok && m.ID == 704 && p.Name == "WMaxLimPct" &&
				v > d.opts.ClampWMaxLimPct {
				v = d.opts.ClampWMaxLimPct
			}
		}
		d.regs[addr+uint16(i)] = v
	}
	d.noteReversionWrite(addr, vals)
	return 0
}

// noteReversionWrite arms, extends or cancels the reversion timer.
func (d *device) noteReversionWrite(addr uint16, vals []uint16) {
	m, p, ok := d.pointAt(addr)
	if !ok || m.ID != 704 || p.Name != "WMaxLimPctRvrtTms" || len(vals) < 2 {
		return
	}
	secs := uint32(vals[0])<<16 | uint32(vals[1])
	switch {
	case secs == 0:
		if d.opts.ReversionUncancellable && d.revArmed {
			return
		}
		d.revArmed = false
	default:
		if d.revArmed && d.opts.ReversionUnextendable {
			return
		}
		d.revArmed = true
		d.revExpiry = time.Now().Add(time.Duration(secs) * time.Second)
	}
}

// settleReversion applies the reversion when the timer has expired.
func (d *device) settleReversion() {
	if !d.revArmed || time.Now().Before(d.revExpiry) {
		return
	}
	d.revArmed = false
	if d.opts.ReversionNeverFires {
		return
	}
	for _, m := range d.models {
		if m.ID != 704 {
			continue
		}
		def := Models[704]
		ctl, _ := def.Point("WMaxLimPct")
		rvt, _ := def.Point("WMaxLimPctRvrt")
		d.regs[m.Addr+uint16(ctl.Off)] = d.regs[m.Addr+uint16(rvt.Off)]
	}
}

// ---------------------------------------------------------------------------
// Synthetic capture
// ---------------------------------------------------------------------------

// synthesise renders the recorded segments as a classic pcap the framework's
// reader accepts, one packet per recorded TCP payload plus a SYN handshake per
// connection.
func (d *device) synthesise() []pcapng.Packet {
	d.mu.Lock()
	defer d.mu.Unlock()

	type flowState struct{ cSeq, sSeq uint32 }
	states := map[netip.AddrPort]*flowState{}
	var out []pcapng.Packet
	idx := 0
	emit := func(src, dst netip.AddrPort, seq uint32, flags uint16, payload []byte, at time.Time) {
		idx++
		data := ethFrame(src, dst, seq, flags, payload)
		out = append(out, pcapng.Packet{
			Index: idx, Time: at.UTC(), LinkType: netdis.LinkTypeEthernet,
			OrigLen: len(data), Data: data,
		})
	}
	for _, s := range d.segs {
		st, ok := states[s.peer]
		if !ok {
			st = &flowState{cSeq: 1000, sSeq: 5000}
			states[s.peer] = st
			emit(s.peer, d.self, st.cSeq, tcpSYN, nil, s.at.Add(-2*time.Millisecond))
			emit(d.self, s.peer, st.sSeq, tcpSYN|tcpACK, nil, s.at.Add(-time.Millisecond))
			st.cSeq++
			st.sSeq++
		}
		if s.toServer {
			emit(s.peer, d.self, st.cSeq, tcpPSH|tcpACK, s.data, s.at)
			st.cSeq += uint32(len(s.data))
		} else {
			emit(d.self, s.peer, st.sSeq, tcpPSH|tcpACK, s.data, s.at)
			st.sSeq += uint32(len(s.data))
		}
	}
	return out
}

const (
	tcpSYN = 0x002
	tcpPSH = 0x008
	tcpACK = 0x010
)

// ethFrame renders Ethernet / IPv4 / TCP. Checksums are left zero: netdis does
// not verify them, and computing them would prove nothing about attribution.
func ethFrame(src, dst netip.AddrPort, seq uint32, flags uint16, payload []byte) []byte {
	tcp := make([]byte, 20+len(payload))
	binary.BigEndian.PutUint16(tcp[0:2], src.Port())
	binary.BigEndian.PutUint16(tcp[2:4], dst.Port())
	binary.BigEndian.PutUint32(tcp[4:8], seq)
	binary.BigEndian.PutUint16(tcp[12:14], 5<<12|flags)
	binary.BigEndian.PutUint16(tcp[14:16], 65535)
	copy(tcp[20:], payload)

	ip := make([]byte, 20+len(tcp))
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:4], uint16(len(ip)))
	ip[8] = 64
	ip[9] = 6
	copy(ip[12:16], src.Addr().Unmap().AsSlice())
	copy(ip[16:20], dst.Addr().Unmap().AsSlice())
	copy(ip[20:], tcp)

	eth := make([]byte, 14+len(ip))
	copy(eth[0:6], []byte{0x02, 0, 0, 0, 0, 0x02})
	copy(eth[6:12], []byte{0x02, 0, 0, 0, 0, 0x01})
	binary.BigEndian.PutUint16(eth[12:14], 0x0800)
	copy(eth[14:], ip)
	return eth
}

// pcapBytes renders packets as a classic little-endian microsecond pcap file.
func pcapBytes(pkts []pcapng.Packet) []byte {
	buf := make([]byte, 0, 24+len(pkts)*128)
	hdr := make([]byte, 24)
	binary.LittleEndian.PutUint32(hdr[0:4], 0xA1B2C3D4)
	binary.LittleEndian.PutUint16(hdr[4:6], 2)
	binary.LittleEndian.PutUint16(hdr[6:8], 4)
	binary.LittleEndian.PutUint32(hdr[16:20], 262144)
	binary.LittleEndian.PutUint32(hdr[20:24], uint32(netdis.LinkTypeEthernet))
	buf = append(buf, hdr...)
	for _, p := range pkts {
		rec := make([]byte, 16)
		binary.LittleEndian.PutUint32(rec[0:4], uint32(p.Time.Unix()))
		binary.LittleEndian.PutUint32(rec[4:8], uint32(p.Time.Nanosecond()/1000))
		binary.LittleEndian.PutUint32(rec[8:12], uint32(len(p.Data)))
		binary.LittleEndian.PutUint32(rec[12:16], uint32(p.OrigLen))
		buf = append(buf, rec...)
		buf = append(buf, p.Data...)
	}
	return buf
}
