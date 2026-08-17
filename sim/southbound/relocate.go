package sim

// relocate.go — SunSpec map relocation: re-home an entire register image to
// a different starting base address.
//
// §2.4.4 CLI-4 requires a client's discovery to work no matter which of the
// three standard SunSpec bases — 0, 40000, 50000 — the server happens to
// use, and §2.9.1 ERR-1 requires a client to recognise (and recover from) a
// server whose map sits one register off a legal base (40001), which is
// noncompliant by definition. Every sim in this package has always served
// its map at the fixed 40000 with no way to move it, so neither row could
// be driven — see runs/final-fullsuite-20260731T234821/REPORT.md CLI-4#8
// and ERR-1#1/#2.
//
// This file closes that gap by moving the register CONTENT rather than by
// interposing a wire relay (contrast wire.go's Mangler / protorelay.go's
// ProtoRelay): every currently-stored register key is shifted by a delta
// under the map's own lock, so the same TCP listener, the same tcp_drop
// bounce, the same everything continues to behave exactly as it does today
// — only WHERE the model chain starts changes. That also keeps this file
// entirely outside solar.go/solar_adv.go's construction path: the sim that
// built the map never has to know it moved.
//
// Known limitation, by design: fields computed ONCE at construction time
// from the original 40000 layout — SolarBases (Snapshot/Inject's per-model
// offsets) and faultController's configured scale/gate/invert addresses —
// do NOT move with a relocation, because updating them would mean editing
// solar.go/faults.go. A relocated sim's GET /state and POST /inject decode
// against the ORIGINAL addresses and will read/write the wrong (or now-
// vacated) cells until the map is restored to the default base. This is
// acceptable for what relocation exists to test — SunSpec WIRE discovery —
// which never goes through /state or /inject.

import (
	"encoding/json"
	"fmt"
	"log"
	"sync"

	"lexa-proto/sunspec"
)

// shiftAll moves every register this map currently holds (and every write-
// protected address — see protect.go) from address k to k+delta, computed
// mod 65536 (Modbus's own 16-bit address space, so this is a bijection: two
// distinct source keys can never collide at the same destination, and a
// relocation is always fully reversible). It takes the map's own lock — the
// same one every Get/Set/HandleHoldingRegisters call already serializes
// through — so an in-flight request sees either the pre- or the
// post-relocation image in full, never a splice of both.
func (r *RegisterMap) shiftAll(delta int32) {
	if delta == 0 {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	shifted := make(map[uint16]uint16, len(r.regs))
	for k, v := range r.regs {
		shifted[uint16(int32(k)+delta)] = v
	}
	r.regs = shifted
	if len(r.protected) > 0 {
		shiftedProtected := make(map[uint16]bool, len(r.protected))
		for k, v := range r.protected {
			shiftedProtected[uint16(int32(k)+delta)] = v
		}
		r.protected = shiftedProtected
	}
}

// spliceRegion replaces everything this map holds in [start, clearTo] with the
// contents of src — registers AND write-protected addresses — in ONE
// transaction under the map's own lock, so an in-flight Modbus request sees the
// whole old region or the whole new one and never a half-laid chain. Same
// guarantee shiftAll gives, for the same reason.
//
// It exists because one lever genuinely re-lays a region of the served image at
// run time: SolarServer.SetLegacyShortBlock, which changes a curve model's bank
// stride and therefore moves every model after it and the chain's end marker.
// Building the new region into a DETACHED map first and splicing it here is
// what lets that lever reuse the ordinary populate* path — a second,
// "in-place" layout writer would be a second opinion about the geometry, and
// the geometry is the thing under test.
//
// The clear is inclusive of clearTo and must be given the further of the two
// ends: a region that SHRANK would otherwise leave stale registers past its new
// end marker, which is exactly the debris a chain walker that overruns would
// pick up.
//
// Write protection is REMOVED for the cleared range before src's is applied,
// because Protect is add-only (protect.go) and a re-lay that only added would
// leave the old geometry's scale-factor cells protected at addresses that now
// hold something else.
func (r *RegisterMap) spliceRegion(start, clearTo uint16, src *RegisterMap) {
	if src == nil || clearTo < start {
		return
	}
	src.mu.RLock()
	regs := make(map[uint16]uint16, len(src.regs))
	for k, v := range src.regs {
		regs[k] = v
	}
	protected := make(map[uint16]bool, len(src.protected))
	for k, v := range src.protected {
		protected[k] = v
	}
	src.mu.RUnlock()

	r.mu.Lock()
	defer r.mu.Unlock()
	for a := uint32(start); a <= uint32(clearTo); a++ {
		delete(r.regs, uint16(a))
		delete(r.protected, uint16(a))
	}
	for k, v := range regs {
		r.regs[k] = v
	}
	if len(protected) > 0 && r.protected == nil {
		r.protected = make(map[uint16]bool, len(protected))
	}
	for k, v := range protected {
		r.protected[k] = v
	}
}

// Relocator re-homes a *RegisterMap's SunSpec map to an arbitrary starting
// base address. It is a THIN piece of state layered OUTSIDE *RegisterMap
// (a wrapper, not a new field on the struct) precisely so relocation never
// has to touch the type's own construction path.
type Relocator struct {
	regs *RegisterMap
	mu   sync.Mutex
	base uint16 // the base this map is CURRENTLY relocated to
}

// NewRelocator wraps regs, which must already be populated at the standard
// sunspec.SunSpecBase (every constructor in this package populates there).
// Constructing a Relocator never itself moves anything — only Relocate does.
func NewRelocator(regs *RegisterMap) *Relocator {
	return &Relocator{regs: regs, base: sunspec.SunSpecBase}
}

// Base returns the base this map is currently relocated to.
func (rl *Relocator) Base() uint16 {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	return rl.base
}

// Relocate re-homes the map to newBase. The shift is computed relative to
// the CURRENT base, not accumulated blindly, so calling it twice in a row —
// including twice with the SAME newBase — is idempotent: the map ends up at
// exactly newBase either way, never double-shifted. Restoring normal
// service is Relocate(sunspec.SunSpecBase).
func (rl *Relocator) Relocate(newBase uint16) {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	if newBase == rl.base {
		log.Printf("[fault] relocate: already at base %d (idempotent no-op)", newBase)
		return
	}
	delta := int32(newBase) - int32(rl.base)
	rl.regs.shiftAll(delta)
	log.Printf("[fault] relocate: sim base %d -> %d (delta=%+d)", rl.base, newBase, delta)
	rl.base = newBase
}

// ── POST /fault {"kind":"relocate","base":N} ──────────────────────────────
//
// Routed through /fault rather than /control: the capability this enables —
// discovery against a server whose map sits at a non-standard, or
// deliberately noncompliant, address — IS a fault injection in the same
// sense every other FaultKind in this package is: a bench operator choosing
// to make the served device deviate from the well-formed default it serves
// absent any request. modsim/main.go also offers a -base N startup flag for
// the same capability before any client ever dials in.

// FaultRelocate is the FaultKind ApplyFault dispatches for a runtime
// relocation request.
const FaultRelocate FaultKind = "relocate"

// relocateSpec is the POST /fault body for FaultRelocate. Base is a pointer
// so an explicit {"base":0} (the legal all-zeros base) is distinguishable
// from an omitted field.
type relocateSpec struct {
	Kind  FaultKind `json:"kind"`
	Base  *int      `json:"base,omitempty"`
	Clear bool      `json:"clear,omitempty"`
}

// ApplyFault arms (or clears) a relocation from a POST /fault body. It
// reports handled=false for any other kind, so a sim binary's fault
// dispatcher can offer this ahead of the device-level ApplyFault, mirroring
// how wire.go's Mangler is offered ahead of it for wire kinds.
func (rl *Relocator) ApplyFault(body []byte) (handled bool, err error) {
	var spec relocateSpec
	if e := json.Unmarshal(body, &spec); e != nil {
		return false, fmt.Errorf("fault: %w", e)
	}
	if spec.Kind != FaultRelocate {
		return false, nil
	}
	if spec.Clear {
		rl.Relocate(sunspec.SunSpecBase)
		return true, nil
	}
	if spec.Base == nil {
		return true, fmt.Errorf("fault %q: base is required (0, 40000, 50000 are the standard SunSpec bases; "+
			"any other value, e.g. 40001, deliberately serves a noncompliant map)", spec.Kind)
	}
	if *spec.Base < 0 || *spec.Base > 0xFFFF {
		return true, fmt.Errorf("fault %q: base %d is not a valid Modbus register address", spec.Kind, *spec.Base)
	}
	rl.Relocate(uint16(*spec.Base))
	return true, nil
}
