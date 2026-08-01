package sim

// exception_target.go — targeted Modbus exceptions.
//
// The existing exception_code fault (faults.go's FaultModbusException) is a
// blanket: EVERY read fails the same fixed way. §2.9.2 ERR-2 wants specific,
// NAMED exception classes (ILLEGAL FUNCTION, ILLEGAL DATA ADDRESS, ILLEGAL
// DATA VALUE, …) provoked on a chosen function code and/or register range
// while the rest of the device stays healthy, so a client's recovery from
// EACH class can be told apart from "the whole device vanished" — see
// runs/final-fullsuite-20260731T234821/REPORT.md ERR-2#2/#3/#4.
//
// This is layered ON TOP of faultController.transportRead / a fresh
// RegisterMap.OnWriteError from OUTSIDE solar.go (see modsim/main.go),
// rather than added as a new case in faults.go's switch, so the blanket
// exception_code fault — still the majority of existing scenario usage — is
// untouched byte-for-byte: a plain {"kind":"exception_code"} body, with none
// of on_fc/on_addr/code set to a non-default value, is left for
// faultController exactly as it is today.

import (
	"encoding/json"
	"fmt"
	"log"
	"sync"

	modbuslib "github.com/simonvetter/modbus"
)

// exceptionByCode maps a raw Modbus exception code byte to the modbuslib
// sentinel error HandleHoldingRegisters must return for a client to see that
// code on the wire (mapErrorToExceptionCode in the vendored library is the
// other half of this table — see vendor/github.com/simonvetter/modbus/modbus.go).
var exceptionByCode = map[int]error{
	1:  modbuslib.ErrIllegalFunction,
	2:  modbuslib.ErrIllegalDataAddress,
	3:  modbuslib.ErrIllegalDataValue,
	4:  modbuslib.ErrServerDeviceFailure,
	5:  modbuslib.ErrAcknowledge,
	6:  modbuslib.ErrServerDeviceBusy,
	8:  modbuslib.ErrMemoryParityError,
	10: modbuslib.ErrGWPathUnavailable,
	11: modbuslib.ErrGWTargetFailedToRespond,
}

// TargetedException arms a single scoped Modbus exception: while armed, a
// request matching (function code, address range) fails with the armed
// error instead of being served; every other request — a different fc, a
// different address, or nothing armed at all — is unaffected. One slot, not
// a list, so re-arming (even with a different scope) is a plain overwrite:
// idempotent, no stacking, no orphaned scopes to hunt down on Clear.
type TargetedException struct {
	mu    sync.Mutex
	armed bool
	err   error
	fc    int // 0 = any function code
	// address range [start, end); anyAddr=true means "any address" and
	// makes start/end irrelevant.
	start, end uint16
	anyAddr    bool
}

// NewTargetedException returns an unarmed TargetedException — a construction
// alone never changes read/write behaviour.
func NewTargetedException() *TargetedException { return &TargetedException{} }

// Clear disarms the targeted exception. Safe to call when nothing is armed.
func (t *TargetedException) Clear() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.armed = false
}

// arm records a new scoped exception, replacing whatever was armed before.
func (t *TargetedException) arm(code, fc int, start, end uint16, anyAddr bool) error {
	err, ok := exceptionByCode[code]
	if !ok {
		return fmt.Errorf("fault %q: code %d is not a Modbus exception this bench maps (want one of 1,2,3,4,5,6,8,10,11)",
			FaultModbusException, code)
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.armed, t.err, t.fc, t.start, t.end, t.anyAddr = true, err, fc, start, end, anyAddr
	log.Printf("[fault] exception_code: targeted code=%d on_fc=%d on_addr=[%d,%d) any_addr=%v armed",
		code, fc, start, end, anyAddr)
	return nil
}

// check decides whether a request at function code fc covering
// [start,start+n) should fail with the armed exception. It returns
// (err, true) when it should fire, (nil, false) when this request is none of
// the targeted exception's concern (including "nothing armed").
func (t *TargetedException) check(fc int, start uint16, n int) (error, bool) {
	t.mu.Lock()
	armed, err, wantFC, aStart, aEnd, anyAddr := t.armed, t.err, t.fc, t.start, t.end, t.anyAddr
	t.mu.Unlock()
	if !armed {
		return nil, false
	}
	if wantFC != 0 && wantFC != fc {
		return nil, false
	}
	if !anyAddr {
		reqEnd := start + uint16(n)
		if reqEnd <= aStart || start >= aEnd {
			return nil, false
		}
	}
	return err, true
}

// WrapOnRead layers targeted-exception checking (function code 3 — the only
// one that ever reaches OnRead; see RegisterMap.HandleHoldingRegisters, FC04
// is never implemented and FC03 is the sole read path) in front of an
// existing OnRead hook, which every solar sim variant already sets to
// faultController.transportRead. With nothing armed, every call passes
// straight through to next unchanged.
func (t *TargetedException) WrapOnRead(next func(uint16, []uint16) ([]uint16, error)) func(uint16, []uint16) ([]uint16, error) {
	return func(start uint16, vals []uint16) ([]uint16, error) {
		if err, hit := t.check(3, start, len(vals)); hit {
			return nil, err
		}
		if next == nil {
			return vals, nil
		}
		return next(start, vals)
	}
}

// OnWriteError satisfies RegisterMap.OnWriteError directly (every solar sim
// variant leaves that hook nil, so this is a plain assignment in
// modsim/main.go, not a wrap). Function code is inferred from len(vals) —
// 6 for a single-register write, 16 for multiple — since
// HoldingRegistersRequest itself carries no raw function code (see
// HandleHoldingRegisters). With nothing armed for the inferred fc it returns
// nil, identical to the unset hook it replaces.
//
// NOTE: the write has already LANDED by the time OnWriteError runs (its
// documented contract in sim.go) — the device applies the value and THEN
// reports failure, the same apply-then-lie shape lying.go's
// exception_on_applied_write already uses. A true upfront refusal would need
// a new OnWriteAttempt-time exception path, which does not exist without
// editing sim.go.
func (t *TargetedException) OnWriteError(start uint16, vals []uint16) error {
	fc := 16
	if len(vals) == 1 {
		fc = 6
	}
	err, _ := t.check(fc, start, len(vals))
	return err
}

// ── POST /fault {"kind":"exception_code","code":N,"on_fc":F,"on_addr":[a,b]} ──

// targetedExcSpec is the POST /fault body this file additionally recognises
// for the EXISTING "exception_code" kind. Unmarshaled independently of
// FaultSpec (sim.go) so the extra fields are never silently dropped by a
// decode into the narrower struct.
type targetedExcSpec struct {
	Kind   FaultKind `json:"kind"`
	Clear  bool      `json:"clear,omitempty"`
	Code   int       `json:"code,omitempty"`
	OnFC   int       `json:"on_fc,omitempty"`
	OnAddr []int     `json:"on_addr,omitempty"`
}

// ApplyFault claims a POST /fault body ONLY when it targets exception_code
// WITH scoping (a non-default code, or on_fc, or on_addr). A plain
// {"kind":"exception_code"} — today's blanket usage — is reported unhandled
// so the caller falls through to the untouched faultController path; a
// targeted clear ALSO clears this layer defensively but still reports
// unhandled, so the blanket flag clears too in case both were ever armed at
// once.
func (t *TargetedException) ApplyFault(body []byte) (handled bool, err error) {
	var spec targetedExcSpec
	if e := json.Unmarshal(body, &spec); e != nil {
		return false, nil // let the classic path report the identical parse error
	}
	if spec.Kind != FaultModbusException {
		return false, nil
	}
	if spec.Clear {
		t.Clear()
		return false, nil
	}
	targeted := spec.OnFC != 0 || len(spec.OnAddr) > 0 || (spec.Code != 0 && spec.Code != 4)
	if !targeted {
		return false, nil // classic untargeted usage: unchanged behaviour
	}
	code := spec.Code
	if code == 0 {
		code = 4
	}
	var start, end uint16
	anyAddr := len(spec.OnAddr) == 0
	if !anyAddr {
		switch len(spec.OnAddr) {
		case 1:
			start = uint16(spec.OnAddr[0])
			end = start + 1
		case 2:
			start = uint16(spec.OnAddr[0])
			end = uint16(spec.OnAddr[1])
		default:
			return true, fmt.Errorf("fault %q: on_addr must have 1 (a single register) or 2 ([start,end)) elements", spec.Kind)
		}
	}
	if e := t.arm(code, spec.OnFC, start, end, anyAddr); e != nil {
		return true, e
	}
	return true, nil
}
