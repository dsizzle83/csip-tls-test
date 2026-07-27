package sim

// lying.go — THE LYING SOUTHBOUND DEVICE (adversarial-QA strategy §L4).
//
// Every fault in faults.go is a device that is BROKEN in a way it cannot hide:
// it returns an exception, or a sentinel, or nothing at all. A hub that checks
// its errors notices. The faults here are different in kind — they are the
// device LYING, answering with a well-formed, plausible, in-range value that is
// not true. That distinction is the whole point of this file, because a lie is
// the only southbound failure that produces SILENT WRONG CONTROL: the hub
// believes it is curtailing an inverter that is at full output, believes it is
// reading this device when it is reading another, believes a limit is in force
// that reverted forty seconds ago. Nothing errors. Nothing is out of range.
// The grid operator's instruction is simply not being carried out, and every
// status the system publishes says it is.
//
// The strategy calls this "the single highest-value simulator investment", and
// the triage of the live conformance run agreed for a duller reason: a large
// share of the Modbus-client conformance rows came back SKIP or WARN purely
// because modsim could not misbehave. A check that cannot fail proves nothing,
// and a check that cannot be MADE to fail cannot be shown to be a check at all.
//
// # The eight lies
//
//	ack_no_apply                 ACKs the write and stores nothing
//	revert_after                 applies the write, then silently undoes it
//	freeze_block                 serves a frozen measurement block from the past
//	sentinel_field               serves not-implemented where a real value lives
//	reboot_forget                drops commanded state and re-announces
//	layout_shift                 serves a different model chain after "firmware"
//	exception_on_applied_write   refuses a write it actually applied
//	slow_poll                    answers slower than the hub polls
//
// # Ground truth is preserved, deliberately
//
// Six of the eight act on the MODBUS READ PATH or on a timer. None of them
// touches the register bank's true contents, so the sim's own /registers and
// /state remain honest. That asymmetry is what makes the lie externally
// detectable at all: the QA oracle reads the device's own account through the
// sidecar, the DUT reads the device over Modbus, and the DIVERGENCE between the
// two is the observable. An injector that corrupted the ground truth as well
// would produce a device nobody — not the DUT, not the referee — could tell was
// lying, which is untestable rather than adversarial. The two exceptions are
// reboot_forget (a real device really does lose its commanded state across a
// reboot, so the bank really is reset) and revert_after (the revert is a real
// change of the device's real setpoint — the lie is that nothing announced it).
// ack_no_apply is the sharpest illustration of why the asymmetry has to hold:
// its echo variant is invisible to every Modbus observer, and the bank staying
// honest is the ONLY thing that keeps it a fault anyone can catch.
//
// # Composition with faults.go
//
// A lieController is installed IN FRONT of the sim's existing faultController
// hooks, so the two vocabularies compose: nan_sentinel + slow_poll is a device
// that is both blank and slow. The one documented exception is layout_shift,
// which owns the write path outright while armed (it is remapping addresses;
// letting a second injector also rewrite the control register would make the
// resulting behaviour unattributable). ack_no_apply owns only the ADDRESSES it
// targets, and still lets the sim's own interceptor see the write, so a
// write-protect or a reject composes with it normally. See lieWrite.
//
// # Pairing with internal/invariant
//
// Each kind names the invariant it exists to try to falsify. That mapping is
// not decoration: gw-mayhem's lying-DER family arms these and hands the verdict
// to internal/invariant, which is the pass/fail authority. This layer only
// creates the conditions.

import (
	"encoding/json"
	"fmt"
	"log"
	"sort"
	"strings"
	"sync"
	"time"

	modbuslib "github.com/simonvetter/modbus"
	"lexa-proto/sunspec"
)

// ── The kinds ────────────────────────────────────────────────────────────────

const (
	// FaultRevertAfter applies a control write for real — it ACKs, it lands in
	// the register, a readback confirms it, the physical output responds — and
	// then, DelayS later, silently restores the previous value. It models the
	// commonest field failure of a curtailment that "worked in the lab": a
	// watchdog, a local scheduler, or a UI-set default that reclaims the point
	// after the commissioning engineer has gone home. It is strictly nastier
	// than reject_write, because a hub that verifies its write by reading the
	// value back ONCE — the standard defence — is satisfied, and stays
	// satisfied, and is wrong from the moment the timer fires.
	//
	// Invariant: I2 (converges to the configured state and STAYS there — a
	// device that silently leaves the commanded state has left it whether or
	// not anyone was looking) and I7 (nothing may report success for a limit
	// that is no longer in force).
	FaultRevertAfter FaultKind = "revert_after"

	// FaultFreezeBlock snapshots a register window at arm time and serves that
	// snapshot to every Modbus read of the window for as long as it is armed,
	// while the device's real state — the register bank, the animation, the
	// sidecar's /state and /registers — carries on moving. It models a stuck
	// measurement DMA, a cached telemetry block, or a sensor task that died
	// while the Modbus task stayed up: the values are perfectly plausible, the
	// device answers promptly and never errors, and everything it says is
	// several minutes old.
	//
	// This is NOT the /control "pause" the bench already had. Pausing freezes
	// the sim's whole world, so ground truth freezes too and there is nothing
	// to diverge from. Freezing only the READ PATH is what makes staleness an
	// externally checkable claim rather than an assumption.
	//
	// Invariant: I7 (a status derived from a stale reading is a claim about the
	// present that did not happen) and I1 (a control computed from a frozen
	// measurement can exceed the device's real capability).
	FaultFreezeBlock FaultKind = "freeze_block"

	// FaultSentinelField serves the SunSpec not-implemented sentinel for a
	// NAMED set of registers only, leaving the rest of the block — and the
	// model-discovery chain — intact and correct. It is the surgical form of
	// nan_sentinel, and the difference matters: nan_sentinel blanks every
	// register in every read, which a hub notices immediately because model
	// discovery itself collapses. A single field going not-implemented mid-run
	// is the realistic case (a firmware that stops populating VAr, a phase
	// sensor that drops out) and is exactly the case a hub is likely to decode
	// as −32768 W and act on.
	//
	// Invariant: I1 (a sentinel decoded as a magnitude is an out-of-nameplate
	// command waiting to happen) and I7 (a device that reports a point it does
	// not have must not have that point reported as a measurement).
	FaultSentinelField FaultKind = "sentinel_field"

	// FaultRebootForget makes the device do what a power-cycled inverter does:
	// drop every commanded value back to its power-on default (limit disabled,
	// ceiling at nameplate), then sever its connections so it re-announces on
	// the hub's reconnect. Unlike tcp_drop — which resets only the transport
	// and keeps device state — the state is genuinely gone, so a hub that
	// treats "the device is back" as "the device is still curtailed" is now
	// running an uncurtailed inverter against a live grid instruction.
	//
	// It is a ONE-SHOT: arming it performs the reboot. There is no sticky state
	// to disarm, so a clear is a no-op (it must not cause a second reboot).
	//
	// Invariant: I2 (authority returns and the device must be driven back to
	// the commanded state, not assumed to be in it), I3 (nothing durable may
	// still assert the pre-reboot limit applied) and I7.
	FaultRebootForget FaultKind = "reboot_forget"

	// FaultLayoutShift serves a DIFFERENT SunSpec model chain: a filler model
	// is spliced in after Model 1, so every model after it moves by Delta
	// registers. The chain stays perfectly well-formed — a hub that re-walks it
	// finds every model exactly where the chain says, and is fine. A hub that
	// cached model base addresses at first discovery and did not re-walk on
	// reconnect now reads the wrong registers, and — the part that matters —
	// WRITES its power limit into the middle of a different model.
	//
	// This is a READ/WRITE-PATH remap, not a rewrite of the bank: internally
	// the device is unchanged, so the sidecar still tells the truth and the
	// divergence is observable. Arming bounces the listener, because "a
	// different chain on reconnect" is the realistic delivery — firmware
	// updates land on a device that then comes back different.
	//
	// Invariant: I1 (a limit written into a foreign model is not the limit
	// anyone commanded, in any unit) and I7.
	FaultLayoutShift FaultKind = "layout_shift"

	// FaultExceptionOnApplied answers a write with a Modbus exception AFTER
	// having applied it. The hub is told, in the protocol's own words, that the
	// command was refused; the device is now running it. Every conclusion the
	// hub draws from the refusal is wrong in the dangerous direction: it will
	// retry, or fall back to another lever, or report CannotComply, or — worst
	// — record the refusal durably and re-actuate the "failed" write later.
	//
	// This is the exact shape of I3's grounding defects (OBX-01, TRM-01), and
	// there was no way to produce it on the bench before: a refused write that
	// really did take effect cannot be simulated by a device that refuses
	// honestly.
	//
	// Invariant: I3 (a refused write leaves no durable state asserting it
	// applied, and is never re-actuated) and I7.
	FaultExceptionOnApplied FaultKind = "exception_on_applied_write"

	// FaultSlowPoll holds every Modbus read for HoldMs before answering. Set
	// above the hub's poll interval it stops being a latency fault and becomes
	// a CONCURRENCY fault: the hub's next poll starts before the previous one
	// finished, requests stack, and whatever the hub does about that — queue
	// unboundedly, open another connection per poll, time out and retry into
	// the same queue, or interleave two in-flight transactions on one socket
	// and mismatch the answers — is the actual finding. The controller counts
	// peak in-flight reads so a test can PROVE the stacking happened rather
	// than assume the sleep caused it (see LieStats).
	//
	// Distinct from `latency`, which is a fixed small per-read delay meant to
	// exercise timeouts. slow_poll is calibrated against the poll interval.
	//
	// Invariant: I8 (no unbounded growth — stacked requests are the cheapest
	// way to grow a connection table or a goroutine set without bound) and I9
	// (a device that is merely slow must recover without intervention once it
	// is not).
	FaultSlowPoll FaultKind = "slow_poll"

	// FaultAckNoApply is FI-04, the classic, and the gap the strategy names
	// outright ("no injection for this exists today", §L4). The
	// device answers a write with a normal, successful Modbus response — no
	// exception, no delay, nothing a client could log — and does not store the
	// value. The commanded limit is simply not in force, and the only thing
	// that ever said otherwise was the ACK.
	//
	// It has two settings, and the difference between them is the difference
	// between a hub that is merely trusting and a hub that cannot win:
	//
	//   Echo=false (default) — the register keeps its old value, so a readback
	//   shows the truth. This is the case a write-then-verify hub MUST catch,
	//   and the case that gives the check its teeth: a hub that reports success
	//   here has not read back at all, or has read back and not compared.
	//
	//   Echo=true — reads of the target register return the ACKed value that
	//   was never stored, while the register itself is untouched. Readback is
	//   defeated: a hub can write, verify, re-verify, and publish "applied"
	//   forever, and the machine will never have been curtailed. This is the
	//   write-only shadow register — a firmware that accepts a point into a
	//   staging buffer whose commit path is broken — and it is not detectable
	//   over Modbus at all. It is detectable only by comparing what the device
	//   SAYS against what the device DOES, which is exactly the divergence the
	//   invariant World is built to see: the sim's own /registers and the
	//   animated physical output stay honest on purpose.
	//
	// Distinct from revert_after, which really does apply the value (a readback
	// in the window is TRUE) and takes it away later. Here it never applied.
	// Distinct from reject_write, which refuses honestly and is therefore safe.
	//
	// Targets default to the sim's control register; Addrs/Fields name others.
	//
	// Invariant: I2 (the gateway must converge the device to the configured
	// state — a device that never left its old value has not converged, however
	// many ACKs were collected) and I7 (nothing may report a limit as applied
	// when no register holds it).
	FaultAckNoApply FaultKind = "ack_no_apply"
)

// lieKinds is the set this controller owns. ApplyFault consults it before the
// faultController so a lie kind never reaches that controller's supported-set
// check (which would reject it as unknown).
var lieKinds = map[FaultKind]bool{
	FaultRevertAfter:        true,
	FaultFreezeBlock:        true,
	FaultSentinelField:      true,
	FaultRebootForget:       true,
	FaultLayoutShift:        true,
	FaultExceptionOnApplied: true,
	FaultSlowPoll:           true,
	FaultAckNoApply:         true,
}

// lieSpec is the POST /fault body as this controller reads it. It is parsed
// separately from FaultSpec rather than growing that struct, so the lying layer
// carries its own vocabulary and the two never have to agree on a field name.
type lieSpec struct {
	Kind  FaultKind `json:"kind"`
	Clear bool      `json:"clear,omitempty"`

	DelayS float64 `json:"delay_s,omitempty"` // revert_after: seconds until the silent revert

	Addr  uint16 `json:"addr,omitempty"`  // freeze_block: window start (0 → the configured measurement block)
	Count uint16 `json:"count,omitempty"` // freeze_block: window length in registers

	// Addrs/Fields address a set of registers. sentinel_field blanks them;
	// ack_no_apply refuses to store them (empty → the control register).
	Addrs  []uint16 `json:"addrs,omitempty"`  // explicit register addresses
	Fields []string `json:"fields,omitempty"` // named fields (see configureFields)
	Value  *uint16  `json:"value,omitempty"`  // sentinel_field: sentinel to serve (default 0x8000, int16 N/A)

	Echo bool `json:"echo,omitempty"` // ack_no_apply: also serve the phantom value on readback

	Delta uint16 `json:"delta,omitempty"` // layout_shift: registers to splice in (default 8)
	Model uint16 `json:"model,omitempty"` // layout_shift: id of the spliced filler model (default 65533, a vendor id)

	ExCode uint8 `json:"ex_code,omitempty"` // exception_on_applied_write: exception to answer (default 0x04)
	Every  int   `json:"every,omitempty"`   // exception_on_applied_write: refuse 1 write in N (default 1 = every)

	HoldMs int `json:"hold_ms,omitempty"` // slow_poll: per-read hold (default 3000)
}

// ── Controller ───────────────────────────────────────────────────────────────

// defaultFillerModel is the SunSpec model id layout_shift splices in. 65533 is
// inside the vendor-defined range, so a conformant hub treats it as an unknown
// model to be skipped by length — which is precisely the correct behaviour the
// fault is checking the hub has.
const defaultFillerModel uint16 = 65533

// sunSpecNA is the SunSpec "not implemented / not available" sentinel for a
// signed 16-bit point (−32768).
const sunSpecNA uint16 = 0x8000

// lieController holds the armed lies for one sim. All fields are guarded by mu.
// The zero value is a valid, unarmed controller: every hook is a pass-through,
// so a sim that never installs one behaves exactly as it did before this file
// existed.
type lieController struct {
	mu    sync.Mutex
	label string

	// revert_after. revertBase is the value the device will fall back to — the
	// register's contents BEFORE the first command of this episode, captured
	// once and held. Re-capturing it on every write would make a hub that
	// re-asserts the same limit revert to that limit, i.e. to nothing, and the
	// fault would vanish precisely for the hub whose behaviour it is testing.
	revert        bool
	revertD       time.Duration
	revertTmr     *time.Timer
	revertBase    uint16
	revertBaseSet bool

	// freeze_block: frozen is the snapshot served for [freezeStart, +freezeCount).
	freeze      bool
	freezeStart uint16
	freezeCount uint16
	frozen      map[uint16]uint16

	// sentinel_field: addresses to blank, and the sentinel value to blank with.
	sentinel map[uint16]bool
	naValue  uint16

	// exception_on_applied_write
	excApplied bool
	excCode    uint8
	excEvery   int
	excSeen    int

	// layout_shift: a filler model of shiftDelta registers appears at shiftAt,
	// so reads/writes at or above shiftAt are remapped by shiftDelta.
	shift      bool
	shiftAt    uint16
	shiftDelta uint16
	shiftModel uint16

	// ack_no_apply: the addresses whose writes are ACKed and dropped, and — when
	// ackEcho is on — the phantom values to serve back for them. A phantom is
	// recorded only when a write is actually swallowed, so an armed-but-never-
	// written device reads exactly as it always did rather than as zeroes.
	ackDrop    map[uint16]bool
	ackEcho    bool
	ackPhantom map[uint16]uint16

	// slow_poll, with the in-flight accounting that makes stacking provable.
	holdMs     int
	inFlight   int
	peakFlight int
	stacked    int

	// Wiring, configured once at construction (see configure).
	regs      *RegisterMap
	cmdAddr   uint16 // the sim's control register — revert_after acts here
	measStart uint16 // default freeze_block window
	measCount uint16
	fields    map[string]uint16 // named registers sentinel_field can blank
	reboot    func()            // sim-supplied power-on reset of commanded state
	bounce    func() error      // sever live connections so the device re-announces

	// counters, for tests and for a human reading the log
	fired map[FaultKind]uint64
}

// LieStats is the controller's own account of what it did — the counters a test
// uses to prove a lie actually fired rather than inferring it from a sleep.
type LieStats struct {
	// Fired counts each kind's activations (a revert performed, a read served
	// frozen, a write refused-after-applying, a reboot, a layout splice).
	Fired map[string]uint64 `json:"fired,omitempty"`
	// PeakInFlight is the largest number of Modbus reads held simultaneously.
	// Greater than one is the PROOF that slow_poll stacked the hub's requests;
	// one means the hub serialised and the fault, however slow, did not stack.
	PeakInFlight int `json:"peak_in_flight"`
	// Stacked counts reads that began while another was still being held.
	Stacked int `json:"stacked"`
}

// configure wires the controller to its sim: the register map it lies about,
// the control register revert_after acts on, the default measurement window
// freeze_block snapshots, the named fields sentinel_field can blank, and the
// two sim-supplied callbacks reboot_forget needs. Called once, before the
// server starts serving.
func (lc *lieController) configure(label string, regs *RegisterMap, cmdAddr, measStart, measCount uint16,
	fields map[string]uint16, reboot func(), bounce func() error) {
	lc.mu.Lock()
	defer lc.mu.Unlock()
	lc.label = label
	lc.regs = regs
	lc.cmdAddr = cmdAddr
	lc.measStart, lc.measCount = measStart, measCount
	lc.fields = fields
	lc.reboot, lc.bounce = reboot, bounce
	lc.naValue = sunSpecNA
	lc.fired = make(map[FaultKind]uint64)
}

// wrap installs the controller's hooks in front of whatever the sim already had
// on regs. Read order is upstream-then-lies (a lie overrides a fault's rewrite,
// because the lie is the more specific claim); write order is lies-first, since
// layout_shift may need to remap the address before any other injector sees it.
//
// Called once, AFTER the sim has set its own OnRead/OnWriteAttempt.
func (lc *lieController) wrap(regs *RegisterMap) {
	prevRead, prevWrite := regs.OnRead, regs.OnWriteAttempt
	regs.OnRead = func(start uint16, vals []uint16) ([]uint16, error) {
		out := vals
		if prevRead != nil {
			var err error
			if out, err = prevRead(start, vals); err != nil {
				return nil, err
			}
		}
		return lc.lieRead(start, out)
	}
	regs.OnWriteAttempt = func(start uint16, vals []uint16) bool {
		return lc.lieWrite(start, vals, prevWrite)
	}
	regs.OnWriteError = lc.lieWriteError
}

// Stats returns a snapshot of what the controller has done.
func (lc *lieController) Stats() LieStats {
	lc.mu.Lock()
	defer lc.mu.Unlock()
	out := LieStats{Fired: make(map[string]uint64, len(lc.fired)), PeakInFlight: lc.peakFlight, Stacked: lc.stacked}
	for k, v := range lc.fired {
		out.Fired[string(k)] = v
	}
	return out
}

// note records that a lie fired. Caller holds lc.mu.
func (lc *lieController) note(k FaultKind) {
	if lc.fired == nil {
		lc.fired = make(map[FaultKind]uint64)
	}
	lc.fired[k]++
}

// ── Wiring the solar sim ─────────────────────────────────────────────────────

// installLies configures and wires the lying-device controller onto a PV
// inverter sim. Called once by each constructor, after the sim's own hooks are
// in place, so the lies sit in front of them.
//
// The three sim-specific facts the controller cannot discover for itself:
//
//   - the CONTROL register revert_after acts on. On an advanced sim that is
//     704's WMaxLimPct — the register the hub actually writes — not the legacy
//     123 mirror the bridge derives from it. Reverting the mirror would be
//     reverting a value nobody wrote, and the next animation tick would put it
//     straight back, so the lie would be invisible.
//   - the default MEASUREMENT block freeze_block snapshots: 701 on an advanced
//     sim (the model the hub prefers), 103 otherwise.
//   - what a power-on reset means for this device, which is a statement about
//     the DEVICE, not about Modbus: the limit disabled and the ceiling back at
//     nameplate.
func (ss *SolarServer) installLies() {
	b := ss.bases
	cmdAddr := b.M123Base + sunspec.M123_WMaxLimPct
	measStart, measCount := b.M103Base, uint16(50)
	fields := map[string]uint16{
		"W":   b.M103Base + sunspec.M103_W,
		"VAr": b.M103Base + sunspec.M103_VAr,
		"VA":  b.M103Base + sunspec.M103_VA,
		"PF":  b.M103Base + sunspec.M103_PF,
		"Hz":  b.M103Base + sunspec.M103_Hz,
		"A":   b.M103Base + sunspec.M103_A,
	}
	if ss.advanced {
		cmdAddr = ss.adv.M704 + uint16(sunspec.L704.Offset("WMaxLimPct"))
		measStart, measCount = ss.adv.M701, uint16(ss.adv.M701Len)
		for name, off := range map[string]string{
			"W_701": "W", "VAr_701": "Var", "VA_701": "VA", "PF_701": "PF", "Hz_701": "Hz",
		} {
			fields[name] = ss.adv.M701 + uint16(sunspec.L701.Offset(off))
		}
	}

	ss.lies.configure("solar", ss.Regs, cmdAddr, measStart, measCount, fields,
		func() { ss.powerOnReset() }, ss.Server.dropConnections)
	ss.lies.wrap(ss.Regs)
}

// powerOnReset returns the inverter's COMMANDED state to what it holds after a
// power cycle: no active limit, ceiling at nameplate, connected. Everything the
// hub told this device is gone — which is the whole content of reboot_forget,
// and the reason a hub must re-assert its controls after a device reappears
// rather than assume they survived.
func (ss *SolarServer) powerOnReset() {
	b := ss.bases
	ss.Regs.Set(b.M123Base+sunspec.M123_WMaxLimPct, 10000) // 100.00 %
	ss.Regs.Set(b.M123Base+sunspec.M123_WMaxLimPct_Ena, 0)
	ss.Regs.Set(b.M123Base+sunspec.M123_Conn, 1)
	if ss.advanced {
		// 704 WMaxLimPct_SF is seeded at −2 by populate704, so 100.00 % is
		// raw 10000 — the same encoding the legacy 123 point uses.
		ss.Regs.Set(ss.adv.M704+uint16(sunspec.L704.Offset("WMaxLimPct")), 10000)
		ss.Regs.Set(ss.adv.M704+uint16(sunspec.L704.Offset("WMaxLimPctEna")), 0)
	}
}

// ── The read path ────────────────────────────────────────────────────────────

// lieRead applies the armed read-path lies to a block about to be returned, in
// the order a real device would produce them: the hold happens first (it is the
// device being slow, before it has decided what to say), then the address remap
// (which model the hub is even looking at), then the frozen snapshot, then the
// per-field sentinel. Each stage is a no-op when unarmed, and the fast path
// (nothing armed) returns vals untouched without copying.
func (lc *lieController) lieRead(start uint16, vals []uint16) ([]uint16, error) {
	lc.mu.Lock()
	hold := lc.holdMs
	shift, shiftAt, shiftDelta, shiftModel := lc.shift, lc.shiftAt, lc.shiftDelta, lc.shiftModel
	freeze, fStart, fCount := lc.freeze, lc.freezeStart, lc.freezeCount
	na := lc.naValue
	hasSentinel := len(lc.sentinel) > 0
	hasPhantom := lc.ackEcho && len(lc.ackPhantom) > 0
	if hold > 0 {
		lc.inFlight++
		if lc.inFlight > lc.peakFlight {
			lc.peakFlight = lc.inFlight
		}
		if lc.inFlight > 1 {
			lc.stacked++
		}
		lc.note(FaultSlowPoll)
	}
	lc.mu.Unlock()

	if hold > 0 {
		time.Sleep(time.Duration(hold) * time.Millisecond)
		lc.mu.Lock()
		lc.inFlight--
		lc.mu.Unlock()
	}
	if !shift && !freeze && !hasSentinel && !hasPhantom {
		return vals, nil
	}

	out := append([]uint16(nil), vals...)
	if shift {
		lc.applyShiftedRead(start, out, shiftAt, shiftDelta, shiftModel)
	}
	for i := range out {
		addr := start + uint16(i)
		if freeze && addr >= fStart && addr < fStart+fCount {
			lc.mu.Lock()
			v, ok := lc.frozen[addr]
			if ok {
				lc.note(FaultFreezeBlock)
			}
			lc.mu.Unlock()
			if ok {
				out[i] = v
			}
		}
		if hasSentinel {
			lc.mu.Lock()
			blank := lc.sentinel[addr]
			if blank {
				lc.note(FaultSentinelField)
			}
			lc.mu.Unlock()
			if blank {
				out[i] = na
			}
		}
		// The phantom is applied LAST because it is the most specific claim the
		// device is making about this address: it is answering the question "did
		// my write land?", and the answer it has decided to give is yes.
		if hasPhantom {
			lc.mu.Lock()
			v, ok := lc.ackPhantom[addr]
			if ok {
				lc.note(FaultAckNoApply)
			}
			lc.mu.Unlock()
			if ok {
				out[i] = v
			}
		}
	}
	return out, nil
}

// applyShiftedRead rewrites out in place so the client sees the post-"firmware
// update" chain: everything below shiftAt is unchanged, [shiftAt, +delta) is a
// well-formed filler model header (id, length, zeroed body), and everything at
// or above shiftAt+delta is served from the register delta below it — i.e. the
// real models, moved up.
func (lc *lieController) applyShiftedRead(start uint16, out []uint16, shiftAt, delta, model uint16) {
	fired := false
	for i := range out {
		addr := start + uint16(i)
		switch {
		case addr < shiftAt:
			// below the splice — the SunS header and Model 1 are where they were.
		case addr < shiftAt+delta:
			switch addr - shiftAt {
			case 0:
				out[i] = model
			case 1:
				out[i] = delta - 2 // SunSpec length excludes the id/len pair
			default:
				out[i] = 0
			}
			fired = true
		default:
			out[i] = lc.regs.Get(addr - delta)
			fired = true
		}
	}
	if fired {
		lc.mu.Lock()
		lc.note(FaultLayoutShift)
		lc.mu.Unlock()
	}
}

// ── The write path ───────────────────────────────────────────────────────────

// lieWrite is the OnWriteAttempt hook. It returns the RegisterMap's apply
// contract: true lets the map store the values verbatim, false means this
// controller (or the injector it delegated to) has taken responsibility.
//
// layout_shift takes the write path outright while armed: it must translate the
// address the hub used into the bank address it really denotes, and letting a
// second injector then rewrite "the control register" — an address that no
// longer means what it meant — would produce behaviour no oracle could
// attribute. Every other lie delegates to the sim's existing interceptor first
// and acts on the result.
func (lc *lieController) lieWrite(start uint16, vals []uint16, prev func(uint16, []uint16) bool) bool {
	lc.mu.Lock()
	shift, shiftAt, delta := lc.shift, lc.shiftAt, lc.shiftDelta
	revert, revertD, cmdAddr := lc.revert, lc.revertD, lc.cmdAddr
	dropping := len(lc.ackDrop) > 0
	lc.mu.Unlock()

	if shift {
		lc.applyShiftedWrite(start, vals, shiftAt, delta)
		return false
	}
	if dropping && lc.ackNoApply(start, vals, prev) {
		return false
	}

	// revert_after must know the value the register held BEFORE this write, so
	// it can put it back later. Read it now — after the write lands it is gone.
	var prior uint16
	off := int(cmdAddr) - int(start)
	touchesCmd := revert && off >= 0 && off < len(vals)
	if touchesCmd {
		prior = lc.regs.Get(cmdAddr)
	}

	// Delegate to whatever the sim already had. The map still owns the store, so
	// an unarmed lieController changes nothing about how a write lands — no
	// per-register re-application, no loss of the block's write atomicity.
	apply := true
	if prev != nil {
		apply = prev(start, vals)
	}
	// The timer only needs the value the register held BEFORE the episode's
	// first write; it fires long after the store, so scheduling it here (rather
	// than after the map has applied) is safe and keeps the write path
	// untouched. Any write to the control register re-arms the timer, whether
	// or not it changed the value: a watchdog resets on the WRITE, so a hub
	// that re-asserts its limit inside the window keeps it — which is the whole
	// property the fault is asking about.
	if touchesCmd {
		lc.scheduleRevert(cmdAddr, prior, vals[off], revertD)
	}
	return apply
}

// applyShiftedWrite lands a write issued against the SHIFTED address space at
// the bank address it really denotes. A write that falls inside the spliced
// filler model is swallowed — the device has no such registers, and a real one
// would drop them — which is exactly what happens to a hub that cached its
// model bases before the update and is now writing its power limit into a
// vendor block.
func (lc *lieController) applyShiftedWrite(start uint16, vals []uint16, shiftAt, delta uint16) {
	swallowed := 0
	for i, v := range vals {
		addr := start + uint16(i)
		switch {
		case addr < shiftAt:
			lc.regs.Set(addr, v)
		case addr < shiftAt+delta:
			swallowed++ // into the filler model: dropped, as a real device would
		default:
			lc.regs.Set(addr-delta, v)
		}
	}
	lc.mu.Lock()
	lc.note(FaultLayoutShift)
	lc.mu.Unlock()
	if swallowed > 0 {
		log.Printf("[lie] layout_shift: %s swallowed %d register(s) written into the spliced model at %d — "+
			"the client is using PRE-update addresses", lc.label, swallowed, shiftAt)
	}
}

// ackNoApply implements the ACK-but-do-not-apply lie for the targeted addresses
// in one write block. It reports whether it took responsibility for the block;
// a block that touches none of the targets is left entirely alone, so arming the
// fault on a control register does not quietly change how telemetry or settings
// writes behave.
//
// The sequence is deliberate. The prior contents of the target registers are
// captured BEFORE anything else, because after the delegation they are gone.
// Whatever injector the sim already had still gets to see the write — it may be
// a write-protect, a scale-mangler or a reject — and its decision is honoured
// for every register the lie is NOT targeting. The targets are then restored to
// what they held, which is the fault itself: the device's answer will be a
// perfectly ordinary success, and its state will be exactly what it was.
//
// The caveat is block atomicity. For a mixed block (targets and non-targets in
// one write) the surviving registers are stored one at a time rather than as a
// unit, so a concurrent reader can in principle see a partially applied block.
// Real control writes land inside a single model, and the alternative — asking
// the register map to apply a subset atomically — would mean widening its
// contract for one fault. The trade is recorded here rather than hidden.
func (lc *lieController) ackNoApply(start uint16, vals []uint16, prev func(uint16, []uint16) bool) bool {
	lc.mu.Lock()
	drop := make([]bool, len(vals))
	hit := false
	for i := range vals {
		if lc.ackDrop[start+uint16(i)] {
			drop[i], hit = true, true
		}
	}
	echo := lc.ackEcho
	lc.mu.Unlock()
	if !hit {
		return false
	}

	prior := make(map[uint16]uint16, len(vals))
	for i := range vals {
		if drop[i] {
			addr := start + uint16(i)
			prior[addr] = lc.regs.Get(addr)
		}
	}

	apply := true
	if prev != nil {
		apply = prev(start, vals)
	}
	if apply {
		for i, v := range vals {
			if !drop[i] {
				lc.regs.Set(start+uint16(i), v)
			}
		}
	}
	for addr, p := range prior {
		lc.regs.Set(addr, p)
	}

	lc.mu.Lock()
	lc.note(FaultAckNoApply)
	if echo {
		if lc.ackPhantom == nil {
			lc.ackPhantom = make(map[uint16]uint16, len(prior))
		}
		for i, v := range vals {
			if drop[i] {
				lc.ackPhantom[start+uint16(i)] = v
			}
		}
	}
	lc.mu.Unlock()

	shown := "the readback will show the OLD value"
	if echo {
		shown = "and the readback will ECHO the value that was never stored"
	}
	log.Printf("[lie] ack_no_apply: %s ACKed a write of %d register(s) at %d and stored none of the %d targeted — %s",
		lc.label, len(vals), start, len(prior), shown)
	return true
}

// scheduleRevert arms (or re-arms) the silent undo of a control write. Each new
// write restarts the timer, so the device holds the newest command for the full
// delay — a watchdog that reclaims the point some time after the last thing
// anyone told it, which is how the real ones behave.
func (lc *lieController) scheduleRevert(addr, prior, applied uint16, d time.Duration) {
	lc.mu.Lock()
	if !lc.revertBaseSet {
		lc.revertBase, lc.revertBaseSet = prior, true
	}
	base := lc.revertBase
	if lc.revertTmr != nil {
		lc.revertTmr.Stop()
	}
	lc.revertTmr = time.AfterFunc(d, func() {
		lc.regs.Set(addr, base)
		lc.mu.Lock()
		lc.revertBaseSet = false // the episode is over; the next command sets a new baseline
		lc.note(FaultRevertAfter)
		lc.mu.Unlock()
		log.Printf("[lie] revert_after: %s silently restored control reg %d to %d after %s "+
			"(the hub's commanded %d is no longer in force, and nothing said so)",
			lc.label, addr, int16(base), d, int16(applied))
	})
	lc.mu.Unlock()
	log.Printf("[lie] revert_after: %s accepted control reg %d=%d; it will silently revert to %d in %s",
		lc.label, addr, int16(applied), int16(base), d)
}

// lieWriteError is the OnWriteError hook: it runs AFTER the write has landed and
// its non-nil return becomes the Modbus exception the client is told. That
// ordering is the entire fault — the device really did apply the value, and
// really does say it did not.
func (lc *lieController) lieWriteError(start uint16, vals []uint16) error {
	lc.mu.Lock()
	if !lc.excApplied {
		lc.mu.Unlock()
		return nil
	}
	lc.excSeen++
	every := lc.excEvery
	if every < 1 {
		every = 1
	}
	fire := lc.excSeen%every == 0
	code := lc.excCode
	if fire {
		lc.note(FaultExceptionOnApplied)
	}
	lc.mu.Unlock()
	if !fire {
		return nil
	}
	log.Printf("[lie] exception_on_applied_write: %s APPLIED the write at %d (%d register(s)) and is answering exception 0x%02x",
		lc.label, start, len(vals), code)
	return modbusException(code)
}

// ── Arming ───────────────────────────────────────────────────────────────────

// apply arms or clears a lie. It reports handled=false for a body whose kind is
// not one of this controller's, so the caller falls through to the server-fault
// and faultController layers unchanged.
func (lc *lieController) apply(body []byte) (handled bool, err error) {
	var spec lieSpec
	if e := json.Unmarshal(body, &spec); e != nil {
		return false, fmt.Errorf("fault: %w", e)
	}
	if !lieKinds[spec.Kind] {
		return false, nil
	}
	if lc.regs == nil {
		return true, fmt.Errorf("fault %q: this sim has no lying-device controller installed", spec.Kind)
	}
	switch spec.Kind {
	case FaultRevertAfter:
		return true, lc.armRevert(spec)
	case FaultFreezeBlock:
		return true, lc.armFreeze(spec)
	case FaultSentinelField:
		return true, lc.armSentinel(spec)
	case FaultRebootForget:
		return true, lc.armReboot(spec)
	case FaultLayoutShift:
		return true, lc.armShift(spec)
	case FaultExceptionOnApplied:
		return true, lc.armExcApplied(spec)
	case FaultSlowPoll:
		return true, lc.armSlowPoll(spec)
	case FaultAckNoApply:
		return true, lc.armAckNoApply(spec)
	}
	return false, nil
}

func (lc *lieController) armRevert(spec lieSpec) error {
	lc.mu.Lock()
	defer lc.mu.Unlock()
	if spec.Clear {
		lc.revert, lc.revertBaseSet = false, false
		if lc.revertTmr != nil {
			lc.revertTmr.Stop()
			lc.revertTmr = nil
		}
		log.Printf("[lie] revert_after: %s cleared", lc.label)
		return nil
	}
	if spec.DelayS <= 0 {
		return fmt.Errorf("fault %q: delay_s must be > 0 (the seconds the command survives before the silent revert)", spec.Kind)
	}
	lc.revert = true
	lc.revertD = time.Duration(spec.DelayS * float64(time.Second))
	log.Printf("[lie] revert_after: %s armed — a control write will hold for %s and then silently revert", lc.label, lc.revertD)
	return nil
}

func (lc *lieController) armFreeze(spec lieSpec) error {
	lc.mu.Lock()
	start, count := spec.Addr, spec.Count
	if start == 0 && count == 0 {
		start, count = lc.measStart, lc.measCount
	}
	if count == 0 {
		lc.mu.Unlock()
		return fmt.Errorf("fault %q: needs addr+count (this sim declared no default measurement block to freeze)", spec.Kind)
	}
	if spec.Clear {
		lc.freeze, lc.frozen = false, nil
		lc.mu.Unlock()
		log.Printf("[lie] freeze_block: %s cleared — reads track the live bank again", lc.label)
		return nil
	}
	lc.freeze, lc.freezeStart, lc.freezeCount = true, start, count
	lc.mu.Unlock()

	// Snapshot outside the lock: regs.Get takes the map's own lock, and the
	// two are unrelated. A read racing this arm sees either the live bank or
	// the frozen one — both are answers a real device could give.
	snap := make(map[uint16]uint16, count)
	for i := uint16(0); i < count; i++ {
		snap[start+i] = lc.regs.Get(start + i)
	}
	lc.mu.Lock()
	lc.frozen = snap
	lc.mu.Unlock()
	log.Printf("[lie] freeze_block: %s froze [%d..%d] on the READ path — the bank keeps moving, so /registers stays honest",
		lc.label, start, int(start)+int(count)-1)
	return nil
}

func (lc *lieController) armSentinel(spec lieSpec) error {
	lc.mu.Lock()
	defer lc.mu.Unlock()
	if spec.Clear {
		lc.sentinel = nil
		log.Printf("[lie] sentinel_field: %s cleared", lc.label)
		return nil
	}
	set := make(map[uint16]bool, len(spec.Addrs)+len(spec.Fields))
	for _, a := range spec.Addrs {
		set[a] = true
	}
	for _, f := range spec.Fields {
		addr, ok := lc.fields[f]
		if !ok {
			return fmt.Errorf("fault %q: unknown field %q for %s (known: %s)", spec.Kind, f, lc.label, knownFields(lc.fields))
		}
		set[addr] = true
	}
	if len(set) == 0 {
		return fmt.Errorf("fault %q: needs addrs or fields — blanking nothing is not a fault", spec.Kind)
	}
	lc.sentinel = set
	lc.naValue = sunSpecNA
	if spec.Value != nil {
		lc.naValue = *spec.Value
	}
	log.Printf("[lie] sentinel_field: %s serving 0x%04x for %d register(s); model discovery is left intact",
		lc.label, lc.naValue, len(set))
	return nil
}

// armAckNoApply targets the registers whose writes will be ACKed and discarded.
// With no addrs or fields it targets the sim's control register, which is both
// the useful default and the only one that can be chosen without guessing: it is
// the register a curtailment lands in, so "the write was accepted and the device
// is not curtailed" is the fault in its most consequential form.
//
// Clearing drops the phantom values with the targets. A device that stops lying
// stops claiming the value it never stored — leaving the echo behind would model
// nothing real and would make the recovery arm of every scenario unfalsifiable.
func (lc *lieController) armAckNoApply(spec lieSpec) error {
	lc.mu.Lock()
	defer lc.mu.Unlock()
	if spec.Clear {
		lc.ackDrop, lc.ackPhantom, lc.ackEcho = nil, nil, false
		log.Printf("[lie] ack_no_apply: %s cleared — writes land again and the phantom readback is gone", lc.label)
		return nil
	}
	set := make(map[uint16]bool, len(spec.Addrs)+len(spec.Fields)+1)
	for _, a := range spec.Addrs {
		set[a] = true
	}
	for _, f := range spec.Fields {
		addr, ok := lc.fields[f]
		if !ok {
			return fmt.Errorf("fault %q: unknown field %q for %s (known: %s)", spec.Kind, f, lc.label, knownFields(lc.fields))
		}
		set[addr] = true
	}
	if len(set) == 0 {
		if lc.cmdAddr == 0 {
			return fmt.Errorf("fault %q: needs addrs or fields (%s declared no control register to default to)", spec.Kind, lc.label)
		}
		set[lc.cmdAddr] = true
	}
	lc.ackDrop, lc.ackEcho, lc.ackPhantom = set, spec.Echo, nil
	if spec.Echo {
		log.Printf("[lie] ack_no_apply: %s will ACK and DISCARD writes to %d register(s), and echo them back on "+
			"read — readback verification cannot see this one", lc.label, len(set))
	} else {
		log.Printf("[lie] ack_no_apply: %s will ACK and DISCARD writes to %d register(s); a readback still tells "+
			"the truth, so a hub that verifies must catch it", lc.label, len(set))
	}
	return nil
}

func (lc *lieController) armReboot(spec lieSpec) error {
	if spec.Clear {
		return nil // one-shot: a clear must NOT reboot the device a second time
	}
	lc.mu.Lock()
	reboot, bounce := lc.reboot, lc.bounce
	lc.note(FaultRebootForget)
	label := lc.label
	lc.mu.Unlock()
	if reboot == nil {
		return fmt.Errorf("fault %q: this sim declared no power-on reset", FaultRebootForget)
	}
	reboot()
	log.Printf("[lie] reboot_forget: %s dropped its commanded state back to power-on defaults", label)
	if bounce != nil {
		if err := bounce(); err != nil {
			return fmt.Errorf("fault %q: re-announce: %w", FaultRebootForget, err)
		}
		log.Printf("[lie] reboot_forget: %s severed its connections and re-announced", label)
	}
	return nil
}

func (lc *lieController) armShift(spec lieSpec) error {
	if spec.Clear {
		lc.mu.Lock()
		lc.shift = false
		bounce := lc.bounce
		label := lc.label
		lc.mu.Unlock()
		if bounce != nil {
			_ = bounce()
		}
		log.Printf("[lie] layout_shift: %s cleared — the original chain is served again on reconnect", label)
		return nil
	}
	delta := spec.Delta
	if delta == 0 {
		delta = 8
	}
	if delta < 2 {
		return fmt.Errorf("fault %q: delta must be >= 2 (a model needs an id and a length register)", spec.Kind)
	}
	model := spec.Model
	if model == 0 {
		model = defaultFillerModel
	}
	at, err := lc.spliceAddr()
	if err != nil {
		return fmt.Errorf("fault %q: %w", spec.Kind, err)
	}
	lc.mu.Lock()
	lc.shift, lc.shiftAt, lc.shiftDelta, lc.shiftModel = true, at, delta, model
	bounce := lc.bounce
	label := lc.label
	lc.mu.Unlock()
	log.Printf("[lie] layout_shift: %s splices model %d (%d regs) at %d — every later model moves by %d on the wire",
		label, model, delta, at, delta)
	if bounce != nil {
		if err := bounce(); err != nil {
			return fmt.Errorf("fault %q: re-announce: %w", spec.Kind, err)
		}
	}
	return nil
}

// spliceAddr walks the device's real SunSpec chain and returns the address of
// the SECOND model's id register — where the filler is spliced in. Walking
// rather than hardcoding keeps the fault layout-agnostic: it works on the
// legacy solar chain, the advanced 7xx chain, the battery and the meter, and
// keeps working when any of them gains a model.
func (lc *lieController) spliceAddr() (uint16, error) {
	base := uint16(sunspec.SunSpecBase)
	if lc.regs.Get(base) != sunspec.SunSMagic0 || lc.regs.Get(base+1) != sunspec.SunSMagic1 {
		return 0, fmt.Errorf("no SunS header at %d — cannot locate the model chain", base)
	}
	cursor := base + 2
	id := lc.regs.Get(cursor)
	if id == sunspec.EndMarker {
		return 0, fmt.Errorf("the chain at %d is empty", cursor)
	}
	return cursor + 2 + lc.regs.Get(cursor+1), nil
}

func (lc *lieController) armExcApplied(spec lieSpec) error {
	lc.mu.Lock()
	defer lc.mu.Unlock()
	if spec.Clear {
		lc.excApplied, lc.excSeen = false, 0
		log.Printf("[lie] exception_on_applied_write: %s cleared", lc.label)
		return nil
	}
	code := spec.ExCode
	if code == 0 {
		code = 0x04 // server device failure: the most plausible "I could not do that"
	}
	if modbusException(code) == nil {
		return fmt.Errorf("fault %q: exception code 0x%02x has no Modbus encoding — refusing to answer a different code than asked for", spec.Kind, code)
	}
	every := spec.Every
	if every < 1 {
		every = 1
	}
	lc.excApplied, lc.excCode, lc.excEvery, lc.excSeen = true, code, every, 0
	log.Printf("[lie] exception_on_applied_write: %s will APPLY every write and refuse 1 in %d with exception 0x%02x",
		lc.label, every, code)
	return nil
}

func (lc *lieController) armSlowPoll(spec lieSpec) error {
	lc.mu.Lock()
	defer lc.mu.Unlock()
	if spec.Clear {
		lc.holdMs = 0
		log.Printf("[lie] slow_poll: %s cleared", lc.label)
		return nil
	}
	ms := spec.HoldMs
	if ms <= 0 {
		ms = 3000 // comfortably above any sane southbound poll interval
	}
	lc.holdMs = ms
	log.Printf("[lie] slow_poll: %s holding every read %d ms — above the hub's poll interval this stacks requests", lc.label, ms)
	return nil
}

// knownFields renders the configured field names for an error message.
func knownFields(m map[string]uint16) string {
	if len(m) == 0 {
		return "none"
	}
	names := make([]string, 0, len(m))
	for n := range m {
		names = append(names, n)
	}
	sort.Strings(names)
	return strings.Join(names, ", ")
}

// modbusException maps a raw exception code onto the error value the modbus
// server turns back into that code on the wire. It exists because the fault
// spec is written in the operator's vocabulary — "answer 0x04" — while the
// server speaks in sentinel errors, and a fault that silently answered a
// different code than the one asked for would make an oracle unfalsifiable.
// An unmapped code is an error at ARM time rather than a quiet substitution.
func modbusException(code uint8) error {
	switch code {
	case 0x01:
		return modbuslib.ErrIllegalFunction
	case 0x02:
		return modbuslib.ErrIllegalDataAddress
	case 0x03:
		return modbuslib.ErrIllegalDataValue
	case 0x04:
		return modbuslib.ErrServerDeviceFailure
	case 0x05:
		return modbuslib.ErrAcknowledge
	case 0x06:
		return modbuslib.ErrServerDeviceBusy
	case 0x08:
		return modbuslib.ErrMemoryParityError
	case 0x0a:
		return modbuslib.ErrGWPathUnavailable
	case 0x0b:
		return modbuslib.ErrGWTargetFailedToRespond
	}
	return nil
}
