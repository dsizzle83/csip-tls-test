package sim

// baseline.go — NAMED REGISTER IMAGES, AND THE RESET THAT PUTS ONE BACK.
//
// # What a baseline is for
//
// A conformance row's first obligation is to know what device it is measuring.
// The sims in this package are mutable by design — a dozen fault layers can
// poke a register, re-home the whole map, splice a model into the chain, seed a
// sentinel — and every one of those is cleared by its own verb, in its own
// shape, with its own idea of what "cleared" means. A row that arms three of
// them and then trusts three separate clears to have restored the device is
// trusting three things it did not check.
//
// A baseline replaces that with one operation and one answer:
//
//	POST /reset {"baseline":"as-built"}   →   {"epoch": 12, ...}
//
// After it returns, the device serves exactly the register image captured
// under that name, no fault layer is armed, poll accounting starts over, and
// the epoch it hands back is the fence every later query uses. A row that
// begins with a reset knows its starting device the way a unit test knows its
// fixture.
//
// # Why the image is captured, not reconstructed
//
// Restoring by RE-RUNNING the sim's populate path would be a second opinion
// about the register layout, and the layout is one of the things under test
// (ERR-3, CLI-4, the geometry gate). A captured image cannot disagree with the
// device that was actually served, because it IS that device. It is a copy of
// the map's contents — registers and write-protection alike — taken under the
// map's own lock, and it is written back the same way.
//
// # The order of a reset, and why it is that order
//
// Clearing comes BEFORE the image is written back, and it must:
//
//	a fault layer that owns registers (the sentinel injector, the model
//	splicer) restores what it took when it is cleared. If the image were
//	written back first, those restores would land on top of it and the device
//	would end up neither at the baseline nor where the fault left it.
//
// A relocation is a special case handled the same way: the relocator is asked
// to return the map to the base the baseline was captured at, so the map's
// content and the relocator's own idea of where it lives cannot disagree.

import (
	"fmt"
	"sort"
	"sync"
)

// BaselineName is the image every sim captures at startup, before any client
// can dial in — the device as constructed.
const BaselineName = "as-built"

// baselineImage is one captured register map.
type baselineImage struct {
	regs      map[uint16]uint16
	protected map[uint16]bool
}

// BaselineStore holds named register images and the hooks a restore must run.
//
// Safe for concurrent use.
type BaselineStore struct {
	regs *RegisterMap

	mu     sync.Mutex
	images map[string]*baselineImage
	// hooks run, in registration order, before the image is written back. Each
	// is one fault layer's own "clear" — registered by the sim binary that
	// wired that layer, so this file needs to know about none of them.
	hooks []resetHook
}

// resetHook is one named clear-up step of a reset. The name is reported in the
// reset's response, so an operator reading a bundle can see what was put back
// rather than having to trust that something was.
type resetHook struct {
	Name string
	Fn   func()
}

// NewBaselineStore wraps a register map. Constructing one captures nothing.
func NewBaselineStore(regs *RegisterMap) *BaselineStore {
	return &BaselineStore{regs: regs, images: make(map[string]*baselineImage)}
}

// OnReset registers a clear-up step. Steps run in registration order, before
// the register image is written back.
func (b *BaselineStore) OnReset(name string, fn func()) {
	if fn == nil {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.hooks = append(b.hooks, resetHook{Name: name, Fn: fn})
}

// Capture snapshots the register map under name, replacing any image already
// held there.
func (b *BaselineStore) Capture(name string) {
	img := &baselineImage{
		regs:      make(map[uint16]uint16),
		protected: make(map[uint16]bool),
	}
	b.regs.mu.RLock()
	for k, v := range b.regs.regs {
		img.regs[k] = v
	}
	for k, v := range b.regs.protected {
		img.protected[k] = v
	}
	b.regs.mu.RUnlock()

	b.mu.Lock()
	b.images[name] = img
	b.mu.Unlock()
}

// Names lists the captured baselines, sorted.
func (b *BaselineStore) Names() []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]string, 0, len(b.images))
	for n := range b.images {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// Restore clears every registered fault layer and writes the named image back
// over the whole register map. It returns the names of the clear-up steps it
// ran, so the caller can report them.
//
// An unknown name is an error naming the images that do exist — never a
// silent fall-back to some other image, which would leave a row measuring a
// device it did not ask for and reporting the result as a product finding.
func (b *BaselineStore) Restore(name string) ([]string, error) {
	b.mu.Lock()
	img, ok := b.images[name]
	hooks := append([]resetHook(nil), b.hooks...)
	known := make([]string, 0, len(b.images))
	for n := range b.images {
		known = append(known, n)
	}
	b.mu.Unlock()
	if !ok {
		sort.Strings(known)
		return nil, fmt.Errorf("reset: no baseline named %q (this sim holds: %v)", name, known)
	}

	ran := make([]string, 0, len(hooks))
	for _, h := range hooks {
		h.Fn()
		ran = append(ran, h.Name)
	}

	// One transaction under the map's own lock, so an in-flight Modbus request
	// sees the whole pre-reset image or the whole post-reset one and never a
	// splice of both — the same guarantee shiftAll and spliceRegion give.
	b.regs.mu.Lock()
	regs := make(map[uint16]uint16, len(img.regs))
	for k, v := range img.regs {
		regs[k] = v
	}
	protected := make(map[uint16]bool, len(img.protected))
	for k, v := range img.protected {
		protected[k] = v
	}
	b.regs.regs = regs
	b.regs.protected = protected
	b.regs.protectedRejects = 0
	b.regs.unitIDConfusion = false
	b.regs.tearing = false
	b.regs.mu.Unlock()

	return ran, nil
}

// ClearAll disarms every fault this controller can hold, leaving the wiring
// configured at construction untouched.
//
// It exists for POST /reset, which must be able to say "nothing is armed"
// without the caller enumerating a dozen kinds and hoping the list is
// complete. Each field is set to the value it has in a freshly constructed
// controller; the configuration fields (label, the gate/scale/invert
// addresses, nowFn) are deliberately NOT touched, because they describe the
// device, not a provocation.
func (fc *faultController) ClearAll() {
	fc.mu.Lock()
	defer fc.mu.Unlock()
	if fc.ack.timer != nil {
		fc.ack.timer.Stop()
	}
	fc.ack = ackBeforeEffect{}
	fc.reject = false
	fc.wrongSign = false
	fc.gate = false
	fc.ramp = false
	fc.rampWPerS = 0
	fc.effCeilW = 0
	fc.effValid = false
	fc.refuse = false
	fc.chargeDisabled = false
	fc.dischargeDisabled = false
	fc.nanSentinel = false
	fc.latencyMs = 0
	fc.modbusException = false
	fc.badScale = false
	fc.invertSign = false
	fc.raiseAlarmBits = 0
	fc.curveAdoptLies = false
	fc.pfAckIgnore = false
	fc.lyingConnSt = false
}

// ClearAll disarms every lie this controller can hold, leaving the wiring
// configured at construction (regs, cmdAddr, the measurement window, the named
// fields and windows, the reboot/bounce callbacks) untouched.
//
// The fired counters are deliberately KEPT. They are the controller's record
// of what it did, not a provocation, and a reset that erased them would erase
// evidence — the same reason the transaction ledger is not truncated by a
// reset either.
func (lc *lieController) ClearAll() {
	lc.mu.Lock()
	defer lc.mu.Unlock()
	if lc.revertTmr != nil {
		lc.revertTmr.Stop()
		lc.revertTmr = nil
	}
	lc.revert = false
	lc.revertD = 0
	lc.revertBase = 0
	lc.revertBaseSet = false
	lc.freeze = false
	lc.freezeWindows = nil
	lc.frozen = nil
	lc.sentinel = nil
	lc.excApplied = false
	lc.excCode = 0
	lc.excEvery = 0
	lc.excSeen = 0
	lc.shift = false
	lc.shiftAt = 0
	lc.shiftDelta = 0
	lc.shiftModel = 0
	lc.ackDrop = nil
	lc.ackEcho = false
	lc.ackPhantom = nil
	lc.holdMs = 0
	lc.inFlight = 0
}

// ClearAll disarms every legacy-curve fault this layer can hold.
func (f *legacyFaults) ClearAll() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.actCrvIgnored = false
	f.modEnaSticky = false
	f.readOnlyIgnored = false
	f.snptWStuck = false
}

// ClearFaults disarms every provocation this sim can be holding: the
// register-level fault controller, the lying-device controller, the
// legacy-curve fault flags, the server-plumbing flags, and every armed
// device-side reversion countdown.
//
// It is what POST /reset calls on the device, and it is deliberately a SINGLE
// method rather than a loop over FaultKinds issuing `{"clear":true}` bodies.
// A loop would have to know which kinds this image advertises — a legacy sim
// refuses a 7xx kind — and would report a reset as failed because one of the
// kinds it tried did not apply to the device it was resetting. Clearing state
// directly cannot have that failure mode: the state either exists on this sim
// or the field is already at its zero value.
//
// The register image itself is NOT touched here. Restoring it is the baseline
// store's job, and it must happen after this, so a fault layer that restores
// registers as it clears cannot land on top of the restored image.
func (ss *SolarServer) ClearFaults() {
	ss.faults.ClearAll()
	ss.lies.ClearAll()
	if ss.legacy != nil {
		ss.legacy.faults.ClearAll()
	}
	if ss.rvrt != nil {
		ss.rvrt.disarmAll(ss.Regs)
	}
	ss.Regs.mu.Lock()
	ss.Regs.unitIDConfusion = false
	ss.Regs.tearing = false
	ss.Regs.mu.Unlock()
}
