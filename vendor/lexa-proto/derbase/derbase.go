// Package derbase provides shared SunSpec DER device logic consumed by
// lexa-hub's inverter and battery packages (TASK-023 — moved here from
// lexa-hub/internal/southbound/derbase; product side is merge authority
// per AD-003): IEEE 1547-2018 models (701-714), legacy models
// (103/121/123/802), measurement parsing, and — its main job — translation of
// IEEE 2030.5 / CSIP DERControlBase operating modes into SunSpec Modbus writes.
//
// Depends on this module's sunspec and csipmodel packages only — no
// dependency on either consumer repo, so lexa-hub's internal/southbound/device
// aliases this package's Measurements type rather than the reverse.
//
// CSIP → SunSpec mapping (model 704 unless noted):
//
//	opModEnergize        → 703 ES (enter service / cease-to-energize)
//	opModConnect         → 123 Conn (legacy immediate connect/disconnect)
//	opModFixedPFInjectW  → 704 PFWInj{PF,Ext}  (constant PF while injecting W)
//	opModFixedPFAbsorbW  → 704 PFWAbs{PF,Ext}  (constant PF while absorbing W)
//	opModFixedVar        → 704 VarSet{Mod,Pri,Pct}
//	opModFixedW          → 704 WSet (Set Active Power, watts) — setpoint
//	opModMaxLimW/ExpLimW/GenLimW → 704 WMaxLimPct (% of WMax) — ceiling
//	opModImpLimW/LoadLimW → 704 WSet negative (charge), or legacy 123
//
// Curve modes (opModVoltVar / opModVoltWatt / ride-through / freq-droop) are
// applied through the typed curve writers, which follow the §3.1.2 adopt
// workflow: write the staging curve, request adoption (AdptCrvReq>1), poll
// AdptCrvRslt, then enable the function (Ena=1) per §3.3.
package derbase

import (
	"fmt"
	"math"
	"time"

	model "lexa-proto/csipmodel"
	"lexa-proto/sunspec"
)

// Base holds shared SunSpec DER state and methods. Embed in concrete types.
type Base struct {
	Reader    *sunspec.Reader
	Wmax      float64 // nameplate WMax in watts; NaN if unavailable
	MeasModel uint16  // measurement model: 701, 103, 102, or 101

	// DefaultRvrtTms, when non-zero, is written as the reversion timeout (seconds)
	// on 704 control writes so the DER auto-reverts if communication is lost. The
	// orchestrator may set this from the active control's remaining duration.
	DefaultRvrtTms uint32

	// AdoptPollTimeout bounds how long curve writers wait for AdptCrvRslt to
	// report COMPLETED. Zero uses adoptPollDefault. Expiry without a result is
	// an AdoptTimeoutError, never success (LXR-006).
	AdoptPollTimeout time.Duration

	// LegacyRmpTms is the ramp time (seconds) written with every legacy M123
	// active-power ceiling. Zero uses defaultLegacyRmpTms. See that constant
	// for why the value is a policy knob and not a magic 5 (adopted D7).
	LegacyRmpTms uint16

	// noGroupedM123 memoizes that this device refused a grouped (single FC16)
	// M123 write, so later plans go straight to the element-by-element
	// sequence instead of paying the refusal every time (adopted D8). Sticky
	// for the life of the Base, which is per-device — a device that cannot do
	// a multi-register write to model 123 will not learn to.
	noGroupedM123 bool

	// Cap is the validated capability snapshot read from model 702 at Init
	// (LXR-005). HasCap reports whether the device implements 702 at all;
	// individual fields are NaN when the device leaves them unimplemented.
	Cap    sunspec.Capacity
	HasCap bool
	// CtrlModes is the raw 702 "supported control mode functions" bitfield.
	// Zero when unimplemented, sentinel, or genuinely declared empty — see
	// supportsCtrlMode for how (and how much) it is trusted.
	CtrlModes uint32

	Has701, Has702, Has703, Has704, Has705, Has706 bool
	Has707, Has708, Has709, Has710, Has711, Has712 bool
	Has713, Has714                                 bool
}

const adoptPollDefault = 3 * time.Second
const adoptPollInterval = 100 * time.Millisecond

// hasFullModel reports model presence AND that the device-declared length can
// hold the full fixed spec layout. A model declared SHORTER than its layout is
// not "a smaller variant" — the fixed DER models have no optional tail — it is
// a malformed or hostile device, and code that trusts the layout width against
// the declared width panics on slice bounds (LXR-003).
func hasFullModel(r *sunspec.Reader, modelID uint16, required int) (present bool, malformed *MalformedDeviceError) {
	declared, ok := r.ModelLen(modelID)
	if !ok {
		return false, nil
	}
	if int(declared) < required {
		return true, &MalformedDeviceError{Model: modelID, Declared: int(declared), Required: required}
	}
	return true, nil
}

// Init populates model-presence flags, validates declared model lengths,
// snapshots capability (702), selects the measurement model, and reads WMax.
// tag is used in error messages (e.g. "inverter", "battery").
//
// A control-relevant model declared shorter than its spec layout fails Init
// with a MalformedDeviceError: the device is quarantined at discovery instead
// of panicking the shared service on first control write (LXR-003). Callers
// hold one Base per device, so quarantine is naturally per-DER.
func Init(r *sunspec.Reader, tag string) (Base, error) {
	b := Base{
		Reader: r,
		Wmax:   math.NaN(),
		Has701: r.HasModel(sunspec.ModelDERMeasureAC),
		Has713: r.HasModel(sunspec.ModelDERStorageCap),
		Has714: r.HasModel(sunspec.ModelDERMeasureDC),
	}

	// Control-relevant fixed models: require the full spec layout length.
	fixed := []struct {
		id       uint16
		required int
		has      *bool
	}{
		{sunspec.ModelDERCapacity, sunspec.L702.Len(), &b.Has702},
		{sunspec.ModelDEREnterService, sunspec.L703.Len(), &b.Has703},
		{sunspec.ModelDERCtlAC, sunspec.L704.Len(), &b.Has704},
	}
	// Curve/repeating models: require at least the fixed header; the curve
	// parse/encode helpers bound-check the repeating blocks against NPt.
	curved := []struct {
		id       uint16
		required int
		has      *bool
	}{
		{sunspec.ModelDERVoltVar, sunspec.L705Hdr.Len(), &b.Has705},
		{sunspec.ModelDERVoltWatt, sunspec.L706Hdr.Len(), &b.Has706},
		{sunspec.ModelDERTripLV, sunspec.L707Hdr.Len(), &b.Has707},
		{sunspec.ModelDERTripHV, sunspec.L707Hdr.Len(), &b.Has708},
		{sunspec.ModelDERTripLF, sunspec.L709Hdr.Len(), &b.Has709},
		{sunspec.ModelDERTripHF, sunspec.L709Hdr.Len(), &b.Has710},
		{sunspec.ModelDERFreqDroop, sunspec.L711Hdr.Len(), &b.Has711},
		{sunspec.ModelDERWattVar, sunspec.L712Hdr.Len(), &b.Has712},
	}
	for _, m := range append(fixed, curved...) {
		present, malformed := hasFullModel(r, m.id, m.required)
		if malformed != nil {
			malformed.Tag = tag
			return Base{}, malformed
		}
		*m.has = present
	}

	if b.Has701 {
		b.MeasModel = sunspec.ModelDERMeasureAC
	} else {
		for _, c := range []uint16{sunspec.ModelInverterThreePh, sunspec.ModelInverterSplitPh, sunspec.ModelInverterSinglePh} {
			if r.HasModel(c) {
				b.MeasModel = c
				break
			}
		}
		if b.MeasModel == 0 {
			return Base{}, fmt.Errorf("%s: device has no AC measurement model (701, 103, 102, or 101)", tag)
		}
	}

	if b.Has702 {
		regs, err := r.ReadModel(sunspec.ModelDERCapacity)
		if err != nil {
			return Base{}, fmt.Errorf("%s: read M702 capability snapshot: %w", tag, err)
		}
		b.Cap = sunspec.Parse702(regs)
		b.HasCap = true
		b.CtrlModes = sunspec.L702.View(regs).Bitfield32("CtrlModes")
		if b.Cap.WMaxRtg > 0 && !math.IsInf(b.Cap.WMaxRtg, 0) {
			b.Wmax = b.Cap.WMaxRtg
		}
	} else if r.HasModel(sunspec.ModelBasicSettings) {
		if w, err := ReadWMax(r); err == nil {
			b.Wmax = w
		}
	}
	return b, nil
}

// supportsCtrlMode reports whether the device's declared 702 CtrlModes
// bitfield permits the given control-mode bit (sunspec.M702_CtrlMode_*).
//
// Trust model (LXR-005): a NONZERO declaration is enforced exactly — a device
// that says "I support fixed-PF and volt-var" does not get sent fixed-var.
// A zero or unimplemented CtrlModes carries no information (real firmware,
// including the bench DER, ships CtrlModes=0 while executing controls), so it
// falls back to model-presence gating rather than rejecting everything.
// Garbage is never treated as permission — only an explicit bit is.
func (b *Base) supportsCtrlMode(bit uint32) bool {
	if !b.HasCap || b.CtrlModes == 0 {
		return true
	}
	return b.CtrlModes&bit != 0
}

// ── Measurements ─────────────────────────────────────────────────────────────
//
// Measurements is defined here (not in lexa-hub's internal/southbound/device)
// because derbase is what constructs it from raw SunSpec registers — see
// TASK-023's derbase move. lexa-hub's device package keeps its own Device /
// DeviceStatus abstractions (owned by the southbound Device Reconciler,
// TASK-025) but re-exports this type as `type Measurements = derbase.Measurements`
// so every existing lexa-hub call site (device.Measurements{...} literals,
// method signatures) keeps compiling unchanged.

// Measurements holds a snapshot of electrical measurements from a DER device.
//
// Sign convention — power fields use the generator/load sign from the device's
// own perspective (IEC 62053 / SunSpec convention):
//
//	W > 0  device is exporting power (solar generating, battery discharging)
//	W < 0  device is importing power (battery charging, load consuming)
//
// The grid meter's W follows the same convention from the meter's perspective:
//
//	W > 0  power flowing from grid into site (import)
//	W < 0  power flowing from site into grid (export)
//
// Fields set to math.NaN() are not available from this device; pointer
// fields are nil when not available (the legacy 103 path, or a 701 device
// that leaves the point unimplemented).
type Measurements struct {
	// AC-side
	W   float64 // net AC real power (watts)
	VA  float64 // apparent power (volt-amps)
	Var float64 // reactive power (vars, positive = capacitive)
	V   float64 // phase-A-to-neutral voltage (volts)
	Hz  float64 // AC frequency (Hz)
	PF  float64 // power factor (−1 to +1)

	// Per-phase / line-to-line voltages (volts), 701 only. Each maps 1:1 to a
	// single 701 register — no fallback logic, unlike V above. NaN means the
	// device leaves the point unimplemented; the legacy 10x path (model
	// 101/102/103) never reports these and always leaves them NaN (see
	// ReadMeasurementsACModel). LLV/VL1L2/VL2L3/VL3L1 are line-to-line;
	// VL1/VL2/VL3 are line-to-neutral.
	LLV, VL1L2, VL1, VL2L3, VL2, VL3L1, VL3 float64

	// DC-side (inverters only; NaN if not applicable)
	DCV float64 // DC bus voltage (volts)
	DCW float64 // DC power (watts)

	// Thermal
	TmpCab float64 // cabinet temperature (°C); NaN if not reported

	// Storage (batteries only; NaN if not applicable)
	SOC float64 // state of charge (0–100 %)

	// DER operational state (model 701 only; nil on the legacy 10x path and
	// for 701 points the device leaves unimplemented — sentinel-checked, so a
	// nil here is "not reported", never a mistaken 0).
	OpSt   *uint16 // 701 St: operating state (0=off, 1=on)
	InvSt  *uint16 // 701 InvSt: inverter state (0..7)
	ConnSt *uint16 // 701 ConnSt: 0=disconnected, 1=connected
	Alrm   *uint32 // 701 Alrm: alarm bitfield (raw; mapping happens hub-side)

	// Lifetime energy accumulators (Wh); NaN when the device doesn't report
	// them. Import/export follow the DEVICE's own perspective (matching W's
	// sign convention above): import = energy absorbed (battery charging),
	// export = energy injected (generating/discharging).
	WhImpTotal float64 // total energy absorbed (701 TotWhAbs)
	WhExpTotal float64 // total energy injected (701 TotWhInj)
}

// ReadMeasurementsM701 parses model 701 into Measurements.
func ReadMeasurementsM701(regs []uint16) Measurements {
	m := sunspec.Parse701(regs)
	v := m.LNV
	if math.IsNaN(v) {
		v = m.VL1
	}
	out := Measurements{
		W: m.W, V: v, Hz: m.Hz, VA: m.VA, Var: m.Var, PF: m.PF, TmpCab: m.TmpCab, SOC: math.NaN(),
		// Direct 1:1 register mapping — no fallback (V's LNV/VL1 fallback above
		// does not apply here; each of these is its own 701 point).
		LLV: m.LLV, VL1L2: m.VL1L2, VL1: m.VL1, VL2L3: m.VL2L3, VL2: m.VL2, VL3L1: m.VL3L1, VL3: m.VL3,
		WhImpTotal: m.TotWhAbs, WhExpTotal: m.TotWhInj,
	}
	// St/InvSt/ConnSt/Alrm ride Parse701 as plain integers, which cannot
	// distinguish 0 from "not implemented" — re-check presence through the
	// layout view (ok=false on absent or sentinel) before adopting them.
	lv := sunspec.L701.View(regs)
	if st, ok := lv.Enum("St"); ok {
		out.OpSt = &st
	}
	if ist, ok := lv.Enum("InvSt"); ok {
		out.InvSt = &ist
	}
	if cst, ok := lv.Enum("ConnSt"); ok {
		out.ConnSt = &cst
	}
	if alrm, ok := lv.U32("Alrm"); ok {
		out.Alrm = &alrm
	}
	return out
}

// ReadMeasurementsACModel parses legacy Model 10x (101/102/103).
func ReadMeasurementsACModel(regs []uint16) Measurements {
	get := func(off int) uint16 {
		if off < len(regs) {
			return regs[off]
		}
		return 0
	}
	sf := func(off int) int16 { return int16(get(off)) }
	// Model 10x has no St/InvSt/ConnSt/Alrm or lifetime-Wh points that map
	// onto the 701 semantics — the state pointers stay nil and the energy
	// accumulators stay NaN (absent, per the struct doc).
	//
	// CRITICAL: model 10x also has no per-phase/line-to-line voltage points
	// (LLV/VL1L2/VL1/VL2L3/VL2/VL3L1/VL3 are 701-only). These MUST be
	// explicitly NaN'd here, in the initial literal — Go's float64 zero value
	// is 0.0, and a silent 0.0 reads as "measured zero volts", which every
	// downstream consumer (NI, alarms, display) treats as a real reading, not
	// as absence. Leaving any of these off this literal would fabricate a
	// phantom "0 V" measurement for every legacy-model device.
	m := Measurements{
		TmpCab: math.NaN(), SOC: math.NaN(), WhImpTotal: math.NaN(), WhExpTotal: math.NaN(),
		LLV: math.NaN(), VL1L2: math.NaN(), VL1: math.NaN(), VL2L3: math.NaN(), VL2: math.NaN(), VL3L1: math.NaN(), VL3: math.NaN(),
	}
	if len(regs) > sunspec.M103_W_SF {
		m.W = sunspec.ApplyScaleSigned(get(sunspec.M103_W), sf(sunspec.M103_W_SF))
	}
	if len(regs) > sunspec.M103_V_SF {
		m.V = sunspec.ApplyScaleUint(get(sunspec.M103_PhVphA), sf(sunspec.M103_V_SF))
	}
	if len(regs) > sunspec.M103_Hz_SF {
		m.Hz = sunspec.ApplyScaleUint(get(sunspec.M103_Hz), sf(sunspec.M103_Hz_SF))
	}
	if len(regs) > sunspec.M103_VA_SF {
		m.VA = sunspec.ApplyScaleSigned(get(sunspec.M103_VA), sf(sunspec.M103_VA_SF))
	}
	if len(regs) > sunspec.M103_VAr_SF {
		m.Var = sunspec.ApplyScaleSigned(get(sunspec.M103_VAr), sf(sunspec.M103_VAr_SF))
	}
	if len(regs) > sunspec.M103_PF_SF {
		m.PF = sunspec.ApplyScaleSigned(get(sunspec.M103_PF), sf(sunspec.M103_PF_SF)) / 100.0
	}
	if len(regs) > sunspec.M103_DCW_SF {
		m.DCV = sunspec.ApplyScaleUint(get(sunspec.M103_DCV), sf(sunspec.M103_DCV_SF))
		m.DCW = sunspec.ApplyScaleSigned(get(sunspec.M103_DCW), sf(sunspec.M103_DCW_SF))
	}
	if len(regs) > sunspec.M103_Tmp_SF {
		m.TmpCab = sunspec.ApplyScaleSigned(get(sunspec.M103_TmpCab), sf(sunspec.M103_Tmp_SF))
	}
	return m
}

// watts converts a CSIP ActivePower to watts. Retained for callers that have
// already validated the multiplier; new code should use wattsChecked.
func watts(ap *model.ActivePower) float64 {
	return float64(ap.Value) * math.Pow10(int(ap.Multiplier))
}

// wattsChecked converts a CSIP ActivePower to watts, rejecting a hostile or
// corrupt power-of-ten multiplier (LXR-004 northbound counterpart: an insane
// multiplier must not become ±Inf and flow into a register encode).
func wattsChecked(ap *model.ActivePower, axis string) (float64, error) {
	if ap.Multiplier < -10 || ap.Multiplier > 10 {
		return 0, &InvalidControlError{Axis: axis,
			Reason: fmt.Sprintf("power-of-ten multiplier %d outside [-10,10]", ap.Multiplier)}
	}
	w := float64(ap.Value) * math.Pow10(int(ap.Multiplier))
	if math.IsNaN(w) || math.IsInf(w, 0) {
		return 0, &InvalidControlError{Axis: axis, Reason: "non-finite watt conversion"}
	}
	return w, nil
}

// ── ApplyControl: CSIP DERControlBase → SunSpec ──────────────────────────────

// ApplyControl executes every axis present in ctrl against the device.
//
// Contract (LXR-002/-005): an axis that cannot be executed FAILS — with
// ErrUnsupportedControl when the device lacks the model/capability, or
// ErrInvalidControl when the request itself is out of domain. The pre-audit
// behavior of silently skipping an axis (`!= nil && b.Has704`) meant a head
// end could be told Started for a control the device never saw.
//
// ApplyControl is a plan of plans, and runs the same two phases every plan in
// this package runs (see plan.go) — for reasons the audit did not name:
//
//  1. PREFLIGHT EVERY PRESENT AXIS BEFORE WRITING ANY. The pre-LXR-012 code
//     validated each axis only as it reached it, so a request whose SECOND
//     axis the device cannot execute was rejected as a whole — after the
//     first axis had already been written. The head end is told CannotComply
//     while the device sits half-actuated in a state nobody commanded. A
//     request that cannot be executed in full is not executed in part.
//
//  2. RESTRICTIVE-FIRST ORDER, not source order. The pre-LXR-012 code
//     executed energize → connect → PF → var → W → ceiling, i.e. it put the
//     device INTO SERVICE at whatever output it liked and applied the curtail
//     last. A control that both energizes and limits — the ordinary CSIP
//     shape — therefore had a window, as long as the remaining Modbus writes
//     take, in which the DER exports at full nameplate under a control that
//     was supposed to cap it. The order is now: cease/disconnect → limits and
//     setpoints → connect-on/energize-on, so every intermediate state is at
//     least as restrictive as both the state before the request and the state
//     after it.
//
// This CHANGES THE ORDER OF WRITES for every existing consumer. That is the
// intended fix, not a side effect.
func (b *Base) ApplyControl(ctrl model.DERControlBase, tag string) error {
	steps, err := b.preflightControl(ctrl, tag)
	if err != nil {
		return err // whole-request rejection: nothing has been written
	}
	for _, rank := range []int{rankRestrict, rankLimit, rankRelease} {
		for _, s := range steps {
			if s.rank != rank {
				continue
			}
			if err := s.run(); err != nil {
				return err
			}
		}
	}
	return nil
}

// applyStep is one preflighted control axis: fully validated, not yet written.
type applyStep struct {
	axis string
	rank int
	run  func() error
}

// Execution ranks, applied in ascending order. A step's rank is decided by
// what it does to the DER's ability to export, not by which axis it is: the
// same opModEnergize is a rankRestrict step when it ceases and a rankRelease
// step when it energizes.
const (
	rankRestrict = iota // cease-to-energize, disconnect — always first
	rankLimit           // ceilings, setpoints, PF/var — the commanded envelope
	rankRelease         // connect-on, energize-on — only once the envelope is set
)

// preflightControl validates every present axis and returns the executable
// steps. It performs NO writes: any error means the whole request is refused
// with the device untouched.
//
// Reads are permitted (capability is already snapshotted; nothing here needs
// the bus). Device-level failures that only a write can discover — a corrupt
// read-modify-write block, a model that got shorter since discovery — still
// surface at execution time on the axis that hits them; restrictive-first
// ordering is what bounds the damage when they do.
func (b *Base) preflightControl(ctrl model.DERControlBase, tag string) ([]applyStep, error) {
	var steps []applyStep
	add := func(axis string, rank int, run func() error) {
		steps = append(steps, applyStep{axis: axis, rank: rank, run: run})
	}
	// releaseRank ranks a two-state axis: restricting the DER goes first,
	// releasing it goes last.
	releaseRank := func(releasing bool) int {
		if releasing {
			return rankRelease
		}
		return rankRestrict
	}

	if ctrl.OpModEnergize != nil {
		if !b.Has703 {
			return nil, &UnsupportedControlError{Axis: "opModEnergize", Reason: "device has no M703 (DEREnterService)"}
		}
		energize := *ctrl.OpModEnergize
		add("opModEnergize", releaseRank(energize), func() error {
			return b.SetEnterServiceEnabled(energize, tag)
		})
	}
	if ctrl.OpModConnect != nil {
		if !b.Reader.HasModel(sunspec.ModelImmediateCtrl) {
			return nil, &UnsupportedControlError{Axis: "opModConnect", Reason: "device has no M123 (immediate controls)"}
		}
		connect := *ctrl.OpModConnect
		add("opModConnect", releaseRank(connect), func() error {
			return b.SetConnect(connect, tag)
		})
	}
	if ctrl.OpModFixedPFInjectW != nil {
		if !b.Has704 {
			return nil, &UnsupportedControlError{Axis: "opModFixedPFInjectW", Reason: "device has no M704 (DERCtlAC)"}
		}
		if !b.supportsCtrlMode(sunspec.M702_CtrlMode_FixedPF) {
			return nil, &UnsupportedControlError{Axis: "opModFixedPFInjectW", Reason: "device CtrlModes does not declare FIXED_PF"}
		}
		pf := math.Abs(float64(ctrl.OpModFixedPFInjectW.Value)) / 10000.0
		if err := b.validatePF(pf, "opModFixedPFInjectW"); err != nil {
			return nil, err
		}
		over := ctrl.OpModFixedPFInjectW.Value >= 0
		add("opModFixedPFInjectW", rankLimit, func() error { return b.SetFixedPF(true, pf, over, tag) })
	}
	if ctrl.OpModFixedPFAbsorbW != nil {
		if !b.Has704 {
			return nil, &UnsupportedControlError{Axis: "opModFixedPFAbsorbW", Reason: "device has no M704 (DERCtlAC)"}
		}
		if !b.supportsCtrlMode(sunspec.M702_CtrlMode_FixedPF) {
			return nil, &UnsupportedControlError{Axis: "opModFixedPFAbsorbW", Reason: "device CtrlModes does not declare FIXED_PF"}
		}
		pf := math.Abs(float64(ctrl.OpModFixedPFAbsorbW.Value)) / 10000.0
		if err := b.validatePF(pf, "opModFixedPFAbsorbW"); err != nil {
			return nil, err
		}
		over := ctrl.OpModFixedPFAbsorbW.Value >= 0
		add("opModFixedPFAbsorbW", rankLimit, func() error { return b.SetFixedPF(false, pf, over, tag) })
	}
	if ctrl.OpModFixedVar != nil {
		if !b.Has704 {
			return nil, &UnsupportedControlError{Axis: "opModFixedVar", Reason: "device has no M704 (DERCtlAC)"}
		}
		if !b.supportsCtrlMode(sunspec.M702_CtrlMode_FixedVar) {
			return nil, &UnsupportedControlError{Axis: "opModFixedVar", Reason: "device CtrlModes does not declare FIXED_VAR"}
		}
		pct := float64(ctrl.OpModFixedVar.Value.Value) / 100.0
		if math.IsNaN(pct) || pct < -100 || pct > 100 {
			return nil, &InvalidControlError{Axis: "opModFixedVar",
				Reason: fmt.Sprintf("reactive setpoint %.2f%% outside [-100,100] of VarMax", pct)}
		}
		add("opModFixedVar", rankLimit, func() error { return b.SetConstantVar(pct, tag) })
	}
	if ctrl.OpModFixedW != nil {
		if !b.Has704 {
			return nil, &UnsupportedControlError{Axis: "opModFixedW", Reason: "device has no M704 (DERCtlAC)"}
		}
		if !b.supportsCtrlMode(sunspec.M702_CtrlMode_FixedW) {
			return nil, &UnsupportedControlError{Axis: "opModFixedW", Reason: "device CtrlModes does not declare FIXED_W"}
		}
		w, err := wattsChecked(ctrl.OpModFixedW, "opModFixedW")
		if err != nil {
			return nil, err
		}
		if err := b.validateSetpointW(w, "opModFixedW"); err != nil {
			return nil, err
		}
		add("opModFixedW", rankLimit, func() error { return b.SetActivePowerWatts(w, tag) })
	}

	// Ceilings → WMaxLimPct (% of WMax). First non-nil wins.
	if axis, lim := firstNonNilAxis(
		axisAP{"opModExpLimW", ctrl.OpModExpLimW},
		axisAP{"opModMaxLimW", ctrl.OpModMaxLimW},
		axisAP{"opModGenLimW", ctrl.OpModGenLimW}); lim != nil {
		w, err := wattsChecked(lim, axis)
		if err != nil {
			return nil, err
		}
		if w < 0 {
			return nil, &InvalidControlError{Axis: axis, Reason: fmt.Sprintf("negative ceiling %g W", w)}
		}
		// Both branches convert watts through the nameplate, so an unknown
		// WMax is a preflight rejection, not a failure discovered after the
		// other axes have been written.
		if err := b.requireWmax(tag); err != nil {
			return nil, err
		}
		if b.Has704 {
			if !b.supportsCtrlMode(sunspec.M702_CtrlMode_MaxW) {
				return nil, &UnsupportedControlError{Axis: axis, Reason: "device CtrlModes does not declare MAX_W"}
			}
			add(axis, rankLimit, func() error { return b.SetWMaxLimPctW(w, tag) })
		} else {
			if !b.Reader.HasModel(sunspec.ModelImmediateCtrl) {
				return nil, &UnsupportedControlError{Axis: axis, Reason: "device has neither M704 nor M123 for power limiting"}
			}
			add(axis, rankLimit, func() error { return b.SetExportLimit(lim, tag) })
		}
	}

	// Import / load (charge) → negative Set Active Power, or legacy 123.
	if axis, imp := firstNonNilAxis(
		axisAP{"opModImpLimW", ctrl.OpModImpLimW},
		axisAP{"opModLoadLimW", ctrl.OpModLoadLimW}); imp != nil {
		w, err := wattsChecked(imp, axis)
		if err != nil {
			return nil, err
		}
		if w < 0 {
			return nil, &InvalidControlError{Axis: axis, Reason: fmt.Sprintf("negative import limit %g W", w)}
		}
		if b.Has704 {
			if !b.supportsCtrlMode(sunspec.M702_CtrlMode_FixedW) {
				return nil, &UnsupportedControlError{Axis: axis, Reason: "device CtrlModes does not declare FIXED_W (required for charge setpoint)"}
			}
			if err := b.validateSetpointW(-w, axis); err != nil {
				return nil, err
			}
			add(axis, rankLimit, func() error { return b.SetActivePowerWatts(-w, tag) })
		} else {
			if !b.Reader.HasModel(sunspec.ModelImmediateCtrl) {
				return nil, &UnsupportedControlError{Axis: axis, Reason: "device has neither M704 nor M123 for import limiting"}
			}
			if err := b.requireWmax(tag); err != nil {
				return nil, err
			}
			add(axis, rankLimit, func() error { return b.SetImportLimit(imp, tag) })
		}
	}
	return steps, nil
}

// requireWmax rejects a percentage-of-nameplate control on a device whose
// nameplate is unknown. Same message the writers themselves produce, so the
// only thing that changes is WHEN a caller learns (before any axis is
// written, instead of after).
func (b *Base) requireWmax(tag string) error {
	if math.IsNaN(b.Wmax) || b.Wmax <= 0 {
		return fmt.Errorf("%s: cannot set power limit: WMax unknown", tag)
	}
	return nil
}

// validatePF rejects a power-factor request outside the physically meaningful
// [0,1] domain, or below the device's own declared minimum rated PF (702
// PFOvrExtRtg/PFUndExtRtg) when the device implements those ratings.
func (b *Base) validatePF(pf float64, axis string) error {
	if math.IsNaN(pf) || pf < 0 || pf > 1 {
		return &InvalidControlError{Axis: axis, Reason: fmt.Sprintf("power factor %g outside [0,1]", pf)}
	}
	if b.HasCap {
		// The rated PF is the MINIMUM the device supports (e.g. 0.85); a
		// request below it is outside declared capability (LXR-005).
		minRated := math.NaN()
		switch axis {
		case "opModFixedPFInjectW":
			minRated = b.Cap.PFOvrExtRtg
		case "opModFixedPFAbsorbW":
			minRated = b.Cap.PFUndExtRtg
		}
		if !math.IsNaN(minRated) && minRated > 0 && minRated <= 1 && pf < minRated {
			return &UnsupportedControlError{Axis: axis,
				Reason: fmt.Sprintf("requested PF %.4f below device rated minimum %.4f", pf, minRated)}
		}
	}
	return nil
}

// validateSetpointW rejects an active-power setpoint outside the device's
// declared charge/discharge rate ratings when those ratings are implemented
// (LXR-005: charge/discharge capability bounds were previously unenforced).
// Ratings the device leaves unimplemented (NaN) impose no bound here; the
// ±WMax clamp in SetActivePowerWatts still applies.
func (b *Base) validateSetpointW(w float64, axis string) error {
	if !b.HasCap {
		return nil
	}
	if w < 0 { // charge
		if r := b.Cap.WChaRteMaxRtg; !math.IsNaN(r) && r > 0 && -w > r {
			return &UnsupportedControlError{Axis: axis,
				Reason: fmt.Sprintf("charge setpoint %g W exceeds rated max charge rate %g W", -w, r)}
		}
	} else if w > 0 { // discharge/export
		if r := b.Cap.WDisChaRteMaxRtg; !math.IsNaN(r) && r > 0 && w > r {
			return &UnsupportedControlError{Axis: axis,
				Reason: fmt.Sprintf("discharge setpoint %g W exceeds rated max discharge rate %g W", w, r)}
		}
	}
	return nil
}

func firstNonNil(aps ...*model.ActivePower) *model.ActivePower {
	for _, ap := range aps {
		if ap != nil {
			return ap
		}
	}
	return nil
}

// axisAP pairs a CSIP axis name with its ActivePower pointer so ceiling /
// import fan-in keeps the axis name for error attribution.
type axisAP struct {
	axis string
	ap   *model.ActivePower
}

func firstNonNilAxis(pairs ...axisAP) (string, *model.ActivePower) {
	for _, p := range pairs {
		if p.ap != nil {
			return p.axis, p.ap
		}
	}
	return "", nil
}

// ── Model 703: Enter Service ─────────────────────────────────────────────────

func (b *Base) SetEnterService(s sunspec.EnterService, tag string) error {
	if !b.Has703 {
		return fmt.Errorf("%s: device has no M703 (DEREnterService)", tag)
	}
	regs, err := b.Reader.ReadModel(sunspec.ModelDEREnterService)
	if err != nil {
		return fmt.Errorf("%s: read M703: %w", tag, err)
	}
	if len(regs) < sunspec.L703.Len() {
		return &MalformedDeviceError{Tag: tag, Model: sunspec.ModelDEREnterService,
			Declared: len(regs), Required: sunspec.L703.Len(), Detail: "read returned short block"}
	}
	// Same corrupt-read guard as write704 (audit E2): never write a
	// sentinel-corrupt read of the enter-service block back to the device.
	if sunspec.L703.View(regs).ReadLooksCorrupt() {
		return fmt.Errorf("%s: refusing to write M703 — read block is sentinel-corrupt (partial/failed read)", tag)
	}
	if err := sunspec.Encode703(regs, s); err != nil {
		return err
	}
	return b.Reader.WriteModel(sunspec.ModelDEREnterService, 0, regs[:sunspec.L703.Len()])
}

// SetEnterServiceEnabled toggles only the ES permit-service / cease-to-energize bit.
func (b *Base) SetEnterServiceEnabled(energize bool, tag string) error {
	val := uint16(0)
	if energize {
		val = 1
	}
	return b.Reader.WriteModel(sunspec.ModelDEREnterService, uint16(sunspec.L703.Offset("ES")), []uint16{val})
}

func (b *Base) ReadEnterService(tag string) (sunspec.EnterService, error) {
	if !b.Has703 {
		return sunspec.EnterService{}, fmt.Errorf("%s: device has no M703", tag)
	}
	regs, err := b.Reader.ReadModel(sunspec.ModelDEREnterService)
	if err != nil {
		return sunspec.EnterService{}, fmt.Errorf("%s: read M703: %w", tag, err)
	}
	return sunspec.Parse703(regs), nil
}

// ── Model 704: AC Controls ───────────────────────────────────────────────────

// write704 read-modify-writes the whole 704 block after applying fn to its View.
// Writing the entire model keeps PF sync groups (PF+Ext) atomic per the spec.
func (b *Base) write704(tag string, fn func(v sunspec.View)) error {
	if !b.Has704 {
		return fmt.Errorf("%s: device has no M704 (DERCtlAC)", tag)
	}
	regs, err := b.Reader.ReadModel(sunspec.ModelDERCtlAC)
	if err != nil {
		return fmt.Errorf("%s: read M704: %w", tag, err)
	}
	// Defense in depth for LXR-003: Init refuses a device whose declared 704
	// is shorter than the layout, but never trust that invariant across a
	// rescan/replacement — an undersized read here would panic the shared
	// service on the regs[:Len] slice below.
	if len(regs) < sunspec.L704.Len() {
		return &MalformedDeviceError{Tag: tag, Model: sunspec.ModelDERCtlAC,
			Declared: len(regs), Required: sunspec.L704.Len(), Detail: "read returned short block"}
	}
	// Refuse to write back a corrupt read (audit E2): this whole-block
	// read-modify-write would otherwise persist a sentinel-saturated read (a
	// device rebooting mid-poll, or a fault-injected all-0x8000 read) into the
	// inverter's control registers — garbage setpoints and spurious sync-group
	// enables. A healthy 704 always carries valid scale factors (and never an
	// out-of-domain one — LXR-004).
	if sunspec.L704.View(regs).ReadLooksCorrupt() {
		return fmt.Errorf("%s: refusing to write M704 — read block is sentinel-corrupt (partial/failed read); not programming garbage back to the device", tag)
	}
	fn(sunspec.L704.View(regs))
	return b.Reader.WriteModel(sunspec.ModelDERCtlAC, 0, regs[:sunspec.L704.Len()])
}

// SetFixedPF enables constant power factor. inject selects the PFWInj (injecting
// active power) vs PFWAbs (absorbing) sync group; overExcited sets excitation.
func (b *Base) SetFixedPF(inject bool, pf float64, overExcited bool, tag string) error {
	return b.write704(tag, func(v sunspec.View) {
		ext := uint16(sunspec.M704_Ext_OverExcited)
		if !overExcited {
			ext = sunspec.M704_Ext_UnderExcited
		}
		if inject {
			v.SetBool("PFWInjEna", true)
			v.SetFloat("PFWInj_PF", pf) // engineering value = power factor
			v.SetEnum("PFWInj_Ext", ext)
		} else {
			v.SetBool("PFWAbsEna", true)
			v.SetFloat("PFWAbs_PF", pf)
			v.SetEnum("PFWAbs_Ext", ext)
		}
	})
}

// SetConstantVar enables constant reactive power as a percentage (signed: + inject).
func (b *Base) SetConstantVar(pct float64, tag string) error {
	return b.write704(tag, func(v sunspec.View) {
		v.SetBool("VarSetEna", true)
		v.SetEnum("VarSetMod", sunspec.M704_VarSetMod_VarMaxPct)
		v.SetEnum("VarSetPri", sunspec.M704_VarSetPri_Reactive)
		v.SetFloat("VarSetPct", pct)
	})
}

// SetActivePowerWatts sets the absolute active-power setpoint in watts (WSet,
// signed: + discharge/export, − charge/import). Clamped to ±WMax when known.
func (b *Base) SetActivePowerWatts(w float64, tag string) error {
	if !math.IsNaN(b.Wmax) && b.Wmax > 0 {
		if w > b.Wmax {
			w = b.Wmax
		}
		if w < -b.Wmax {
			w = -b.Wmax
		}
	}
	return b.write704(tag, func(v sunspec.View) {
		v.SetBool("WSetEna", true)
		v.SetEnum("WSetMod", sunspec.M704_WSetMod_Watts)
		v.SetFloat("WSet", w)
		v.SetU32("WSetRvrtTms", b.DefaultRvrtTms)
	})
}

// SetWMaxLimPctW sets the active-power ceiling as a percentage of WMax.
func (b *Base) SetWMaxLimPctW(w float64, tag string) error {
	if math.IsNaN(b.Wmax) || b.Wmax <= 0 {
		return fmt.Errorf("%s: cannot set power limit: WMax unknown", tag)
	}
	if w < 0 {
		w = 0
	}
	if w > b.Wmax {
		w = b.Wmax
	}
	pct := w / b.Wmax * 100.0
	return b.write704(tag, func(v sunspec.View) {
		v.SetBool("WMaxLimPctEna", true)
		v.SetFloat("WMaxLimPct", pct)
		v.SetU32("WMaxLimPctRvrtTms", b.DefaultRvrtTms)
	})
}

func (b *Base) ReadDERCtlAC(tag string) (sunspec.ACControls, error) {
	if !b.Has704 {
		return sunspec.ACControls{}, fmt.Errorf("%s: device has no M704", tag)
	}
	regs, err := b.Reader.ReadModel(sunspec.ModelDERCtlAC)
	if err != nil {
		return sunspec.ACControls{}, fmt.Errorf("%s: read M704: %w", tag, err)
	}
	return sunspec.Parse704(regs), nil
}

// ── Model 702: Capacity ──────────────────────────────────────────────────────

func (b *Base) ReadDERCapacity(tag string) (sunspec.Capacity, error) {
	if !b.Has702 {
		return sunspec.Capacity{}, fmt.Errorf("%s: device has no M702 (DERCapacity)", tag)
	}
	regs, err := b.Reader.ReadModel(sunspec.ModelDERCapacity)
	if err != nil {
		return sunspec.Capacity{}, fmt.Errorf("%s: read M702: %w", tag, err)
	}
	return sunspec.Parse702(regs), nil
}

// SetCapacityWMax overrides the nameplate active-power rating with an operator
// setting (702 WMax). Demonstrates the writable rating-override path (§4.2).
func (b *Base) SetCapacityWMax(w float64, tag string) error {
	if !b.Has702 {
		return fmt.Errorf("%s: device has no M702", tag)
	}
	regs, err := b.Reader.ReadModel(sunspec.ModelDERCapacity)
	if err != nil {
		return fmt.Errorf("%s: read M702: %w", tag, err)
	}
	if len(regs) < sunspec.L702.Len() {
		return &MalformedDeviceError{Tag: tag, Model: sunspec.ModelDERCapacity,
			Declared: len(regs), Required: sunspec.L702.Len(), Detail: "read returned short block"}
	}
	sunspec.L702.View(regs).SetFloat("WMax", w)
	return b.Reader.WriteModel(sunspec.ModelDERCapacity, 0, regs[:sunspec.L702.Len()])
}

// ── Curve adopt workflow (§3.1.2 / §3.3) ─────────────────────────────────────

// adoptCurve performs the full SunSpec curve-update handshake on a curve/control
// model: the staging curve has already been encoded into regs[start:end] at
// 0-based index 1. It writes that range, requests adoption with the 1-based
// staging index (=2, which the spec requires to be >1), polls the result point
// until COMPLETED/FAILED, enables the function (Ena=1), and verifies the
// enable by positive read-back.
//
// Failure semantics (LXR-006): a device that never reports COMPLETED within
// the poll window is a FAILURE (AdoptTimeoutError) — the pre-audit code
// proceeded to enable a function whose curve state was unknown, confusing
// absence of negative evidence with positive adoption. Likewise the final
// enable is only success once the device reads back Ena=1.
func (b *Base) adoptCurve(modelID uint16, regs []uint16, start, end int, adptReqField, adptRsltField, enaField string, hdr *sunspec.Layout, tag string) error {
	if err := b.Reader.WriteModel(modelID, uint16(start), regs[start:end]); err != nil {
		return fmt.Errorf("%s: write model %d curve: %w", tag, modelID, err)
	}
	const stagingIdx1Based = 2 // 0-based index 1 → 1-based 2 (>1 per §3.1.2)
	if err := b.Reader.WriteModel(modelID, uint16(hdr.Offset(adptReqField)), []uint16{stagingIdx1Based}); err != nil {
		return fmt.Errorf("%s: request adopt on model %d: %w", tag, modelID, err)
	}
	if err := b.pollAdoptResult(modelID, hdr.Offset(adptRsltField), tag); err != nil {
		return err
	}
	if err := b.Reader.WriteModel(modelID, uint16(hdr.Offset(enaField)), []uint16{1}); err != nil {
		return fmt.Errorf("%s: enable model %d: %w", tag, modelID, err)
	}
	// Positive read-back of the enable: an accepted write is not an applied
	// write. A device that silently refuses Ena=1 (or resets it) must not be
	// reported as running the function.
	verify, err := b.Reader.ReadModel(modelID)
	if err != nil {
		return fmt.Errorf("%s: verify enable on model %d: %w", tag, modelID, err)
	}
	enaOff := hdr.Offset(enaField)
	if enaOff < 0 || enaOff >= len(verify) {
		return &VerifyError{Tag: tag, Model: modelID, Point: enaField, Detail: "enable point not readable"}
	}
	if verify[enaOff] != 1 {
		return &VerifyError{Tag: tag, Model: modelID, Point: enaField,
			Detail: fmt.Sprintf("wrote 1, device reads back %d", verify[enaOff])}
	}
	return nil
}

func (b *Base) pollAdoptResult(modelID uint16, rsltOffset int, tag string) error {
	timeout := b.AdoptPollTimeout
	if timeout == 0 {
		timeout = adoptPollDefault
	}
	deadline := time.Now().Add(timeout)
	for {
		regs, err := b.Reader.ReadModel(modelID)
		if err != nil {
			return fmt.Errorf("%s: poll adopt result on model %d: %w", tag, modelID, err)
		}
		if rsltOffset >= 0 && rsltOffset < len(regs) {
			switch regs[rsltOffset] {
			case sunspec.AdptCompleted:
				return nil
			case sunspec.AdptFailed:
				return fmt.Errorf("%s: model %d adopt-curve FAILED", tag, modelID)
			}
		}
		if time.Now().After(deadline) {
			// Absence of a result is NOT adoption (LXR-006). The old
			// best-effort nil here let a silent device pass as adopted.
			return &AdoptTimeoutError{Tag: tag, Model: modelID, Timeout: timeout}
		}
		time.Sleep(adoptPollInterval)
	}
}

// ── Volt-Var (705) ───────────────────────────────────────────────────────────

func (b *Base) ReadVoltVar(tag string) (sunspec.VoltVarCurve, error) {
	if !b.Has705 {
		return sunspec.VoltVarCurve{}, fmt.Errorf("%s: device has no M705 (DERVoltVar)", tag)
	}
	regs, err := b.Reader.ReadModel(sunspec.ModelDERVoltVar)
	if err != nil {
		return sunspec.VoltVarCurve{}, fmt.Errorf("%s: read M705: %w", tag, err)
	}
	return sunspec.Parse705Curve(regs, 0)
}

func (b *Base) WriteVoltVar(c sunspec.VoltVarCurve, tag string) error {
	if !b.Has705 {
		return fmt.Errorf("%s: device has no M705 (DERVoltVar)", tag)
	}
	regs, err := b.Reader.ReadModel(sunspec.ModelDERVoltVar)
	if err != nil {
		return fmt.Errorf("%s: read M705: %w", tag, err)
	}
	start, end, err := sunspec.Encode705Curve(regs, 1, c)
	if err != nil {
		return err
	}
	return b.adoptCurve(sunspec.ModelDERVoltVar, regs, start, end, "AdptCrvReq", "AdptCrvRslt", "Ena", sunspec.L705Hdr, tag)
}

// ── Volt-Watt (706) ─────────────────────────────────────────────────────────

func (b *Base) ReadVoltWatt(tag string) (sunspec.VoltWattCurve, error) {
	if !b.Has706 {
		return sunspec.VoltWattCurve{}, fmt.Errorf("%s: device has no M706 (DERVoltWatt)", tag)
	}
	regs, err := b.Reader.ReadModel(sunspec.ModelDERVoltWatt)
	if err != nil {
		return sunspec.VoltWattCurve{}, fmt.Errorf("%s: read M706: %w", tag, err)
	}
	return sunspec.Parse706Curve(regs, 0)
}

func (b *Base) WriteVoltWatt(c sunspec.VoltWattCurve, tag string) error {
	if !b.Has706 {
		return fmt.Errorf("%s: device has no M706 (DERVoltWatt)", tag)
	}
	regs, err := b.Reader.ReadModel(sunspec.ModelDERVoltWatt)
	if err != nil {
		return fmt.Errorf("%s: read M706: %w", tag, err)
	}
	start, end, err := sunspec.Encode706Curve(regs, 1, c)
	if err != nil {
		return err
	}
	return b.adoptCurve(sunspec.ModelDERVoltWatt, regs, start, end, "AdptCrvReq", "AdptCrvRslt", "Ena", sunspec.L706Hdr, tag)
}

// ── Voltage trip (707/708) ──────────────────────────────────────────────────

func (b *Base) ReadVoltageTripLV(tag string) (sunspec.VoltageTripSet, error) {
	return b.readVoltageTrip(sunspec.ModelDERTripLV, b.Has707, "M707", tag)
}
func (b *Base) WriteVoltageTripLV(c sunspec.VoltageTripSet, tag string) error {
	return b.writeVoltageTrip(sunspec.ModelDERTripLV, b.Has707, "M707", c, tag)
}
func (b *Base) ReadVoltageTripHV(tag string) (sunspec.VoltageTripSet, error) {
	return b.readVoltageTrip(sunspec.ModelDERTripHV, b.Has708, "M708", tag)
}
func (b *Base) WriteVoltageTripHV(c sunspec.VoltageTripSet, tag string) error {
	return b.writeVoltageTrip(sunspec.ModelDERTripHV, b.Has708, "M708", c, tag)
}

func (b *Base) readVoltageTrip(modelID uint16, has bool, name, tag string) (sunspec.VoltageTripSet, error) {
	if !has {
		return sunspec.VoltageTripSet{}, fmt.Errorf("%s: device has no %s", tag, name)
	}
	regs, err := b.Reader.ReadModel(modelID)
	if err != nil {
		return sunspec.VoltageTripSet{}, fmt.Errorf("%s: read %s: %w", tag, name, err)
	}
	return sunspec.Parse707Set(regs, 0)
}

func (b *Base) writeVoltageTrip(modelID uint16, has bool, name string, c sunspec.VoltageTripSet, tag string) error {
	if !has {
		return fmt.Errorf("%s: device has no %s", tag, name)
	}
	regs, err := b.Reader.ReadModel(modelID)
	if err != nil {
		return fmt.Errorf("%s: read %s: %w", tag, name, err)
	}
	start, end, err := sunspec.Encode707Set(regs, 1, c)
	if err != nil {
		return err
	}
	return b.adoptCurve(modelID, regs, start, end, "AdptCrvReq", "AdptCrvRslt", "Ena", sunspec.L707Hdr, tag)
}

// ── Frequency trip (709/710) ─────────────────────────────────────────────────

func (b *Base) ReadFreqTripLF(tag string) (sunspec.FreqTripSet, error) {
	return b.readFreqTrip(sunspec.ModelDERTripLF, b.Has709, "M709", tag)
}
func (b *Base) WriteFreqTripLF(c sunspec.FreqTripSet, tag string) error {
	return b.writeFreqTrip(sunspec.ModelDERTripLF, b.Has709, "M709", c, tag)
}
func (b *Base) ReadFreqTripHF(tag string) (sunspec.FreqTripSet, error) {
	return b.readFreqTrip(sunspec.ModelDERTripHF, b.Has710, "M710", tag)
}
func (b *Base) WriteFreqTripHF(c sunspec.FreqTripSet, tag string) error {
	return b.writeFreqTrip(sunspec.ModelDERTripHF, b.Has710, "M710", c, tag)
}

func (b *Base) readFreqTrip(modelID uint16, has bool, name, tag string) (sunspec.FreqTripSet, error) {
	if !has {
		return sunspec.FreqTripSet{}, fmt.Errorf("%s: device has no %s", tag, name)
	}
	regs, err := b.Reader.ReadModel(modelID)
	if err != nil {
		return sunspec.FreqTripSet{}, fmt.Errorf("%s: read %s: %w", tag, name, err)
	}
	return sunspec.Parse709Set(regs, 0)
}

func (b *Base) writeFreqTrip(modelID uint16, has bool, name string, c sunspec.FreqTripSet, tag string) error {
	if !has {
		return fmt.Errorf("%s: device has no %s", tag, name)
	}
	regs, err := b.Reader.ReadModel(modelID)
	if err != nil {
		return fmt.Errorf("%s: read %s: %w", tag, name, err)
	}
	start, end, err := sunspec.Encode709Set(regs, 1, c)
	if err != nil {
		return err
	}
	return b.adoptCurve(modelID, regs, start, end, "AdptCrvReq", "AdptCrvRslt", "Ena", sunspec.L709Hdr, tag)
}

// ── Frequency droop (711) ────────────────────────────────────────────────────

func (b *Base) ReadFreqDroop(tag string) (sunspec.FreqDroopCtl, error) {
	if !b.Has711 {
		return sunspec.FreqDroopCtl{}, fmt.Errorf("%s: device has no M711 (DERFreqDroop)", tag)
	}
	regs, err := b.Reader.ReadModel(sunspec.ModelDERFreqDroop)
	if err != nil {
		return sunspec.FreqDroopCtl{}, fmt.Errorf("%s: read M711: %w", tag, err)
	}
	return sunspec.Parse711Ctl(regs, 0)
}

func (b *Base) WriteFreqDroop(c sunspec.FreqDroopCtl, tag string) error {
	if !b.Has711 {
		return fmt.Errorf("%s: device has no M711 (DERFreqDroop)", tag)
	}
	regs, err := b.Reader.ReadModel(sunspec.ModelDERFreqDroop)
	if err != nil {
		return fmt.Errorf("%s: read M711: %w", tag, err)
	}
	start, end, err := sunspec.Encode711Ctl(regs, 1, c)
	if err != nil {
		return err
	}
	return b.adoptCurve(sunspec.ModelDERFreqDroop, regs, start, end, "AdptCtlReq", "AdptCtlRslt", "Ena", sunspec.L711Hdr, tag)
}

// ── Watt-Var (712) ───────────────────────────────────────────────────────────

func (b *Base) ReadWattVar(tag string) (sunspec.WattVarCurve, error) {
	if !b.Has712 {
		return sunspec.WattVarCurve{}, fmt.Errorf("%s: device has no M712 (DERWattVar)", tag)
	}
	regs, err := b.Reader.ReadModel(sunspec.ModelDERWattVar)
	if err != nil {
		return sunspec.WattVarCurve{}, fmt.Errorf("%s: read M712: %w", tag, err)
	}
	return sunspec.Parse712Curve(regs, 0)
}

func (b *Base) WriteWattVar(c sunspec.WattVarCurve, tag string) error {
	if !b.Has712 {
		return fmt.Errorf("%s: device has no M712 (DERWattVar)", tag)
	}
	regs, err := b.Reader.ReadModel(sunspec.ModelDERWattVar)
	if err != nil {
		return fmt.Errorf("%s: read M712: %w", tag, err)
	}
	start, end, err := sunspec.Encode712Curve(regs, 1, c)
	if err != nil {
		return err
	}
	return b.adoptCurve(sunspec.ModelDERWattVar, regs, start, end, "AdptCrvReq", "AdptCrvRslt", "Ena", sunspec.L712Hdr, tag)
}

// ── Model 713/714 reads ──────────────────────────────────────────────────────

func (b *Base) ReadStorageCapacity(tag string) (sunspec.StorageCapacity, error) {
	if !b.Has713 {
		return sunspec.StorageCapacity{}, fmt.Errorf("%s: device has no M713 (DERStorageCapacity)", tag)
	}
	regs, err := b.Reader.ReadModel(sunspec.ModelDERStorageCap)
	if err != nil {
		return sunspec.StorageCapacity{}, fmt.Errorf("%s: read M713: %w", tag, err)
	}
	return sunspec.Parse713(regs), nil
}

func (b *Base) ReadDCMeasurement(tag string) (sunspec.DCMeasurement, error) {
	if !b.Has714 {
		return sunspec.DCMeasurement{}, fmt.Errorf("%s: device has no M714 (DERMeasureDC)", tag)
	}
	regs, err := b.Reader.ReadModel(sunspec.ModelDERMeasureDC)
	if err != nil {
		return sunspec.DCMeasurement{}, fmt.Errorf("%s: read M714: %w", tag, err)
	}
	return sunspec.Parse714(regs)
}

// ── Legacy M123 / M121 helpers ───────────────────────────────────────────────

// Plan and element names for the two M123 actuation plans. They travel in
// PlanOutcome, PartialActuationError, and (upstream) in journal entries and
// metric labels, so they are stable identifiers rather than log prose.
const (
	PlanM123Limit   = "m123-limit"
	PlanM123Connect = "m123-connect"

	ElemM123RmpTms     = "WMaxLimPct_RmpTms"
	ElemM123WMaxLimPct = "WMaxLimPct"
	ElemM123Ena        = "WMaxLimPct_Ena"
	ElemM123Conn       = "Conn"
)

// Element indexes within m123LimitPlan's PlanOutcome.Elements, in write order.
const (
	m123ElemRmp = iota
	m123ElemVal
	m123ElemEna
)

// defaultLegacyRmpTms is the ramp time (seconds) written with a legacy M123
// active-power ceiling when Base.LegacyRmpTms is left zero (adopted D7 — this
// was an unexplained literal 5 in the write path).
//
// It is a policy value, not a device constant: it is how long the inverter
// takes to walk from its present output to the commanded ceiling, and a
// ceiling that is not yet reached is a ceiling that is not protecting
// anything. 5 s is short enough to land well inside the CSIP
// actuation-confirm window and long enough not to slam a plant, which is why
// it is the default — but a site whose ceilings exist to prevent an
// export-limit breach wants it shorter, and a mechanically fussy plant wants
// it longer. Hence named, documented, and settable per device.
const defaultLegacyRmpTms = uint16(5)

func (b *Base) legacyRmpTms() uint16 {
	if b.LegacyRmpTms != 0 {
		return b.LegacyRmpTms
	}
	return defaultLegacyRmpTms
}

// readM123Point reads one M123 register. ok=false when the model cannot be
// read, the block is shorter than the point, or the point carries the uint16
// not-implemented sentinel — i.e. every case where the device did not tell us
// what that register holds.
func (b *Base) readM123Point(off int) (uint16, bool) {
	regs, err := b.Reader.ReadModel(sunspec.ModelImmediateCtrl)
	if err != nil || off < 0 || off >= len(regs) || regs[off] == 0xFFFF {
		return 0, false
	}
	return regs[off], true
}

// ── M123 Conn: the legacy connect plan ───────────────────────────────────────

// m123ConnPlan is connect/disconnect as a degenerate one-element plan:
// preflight, write, and prove by L1 register echo.
type m123ConnPlan struct {
	b      *Base
	tag    string
	want   uint16
	before float64 // measured pre-state (NaN = unknown)
}

// SetConnect connects (true) or disconnects (false) the DER through M123 Conn
// and PROVES the result by reading the register back.
//
// Before LXR-012-connect this function returned nil on any ACK. A device that
// accepts the write and does not act on it — the ordinary
// accepted-and-ignored firmware behaviour — was therefore reported as
// connected or disconnected on the strength of the ACK alone, which upstream
// became a Started for a connect that never happened, and (the direction that
// matters) a satisfied cease for a DER still exporting.
//
// The signature is unchanged for existing callers; SetConnectPlan is the same
// actuation with the measured outcome attached, the way RawFromScaleSigned
// wraps EncodeScaleSigned in the sunspec codec.
func (b *Base) SetConnect(connect bool, tag string) error {
	_, err := b.SetConnectPlan(connect, tag)
	return err
}

// SetConnectPlan is SetConnect returning the measured PlanOutcome. A nil
// error means the device MEASURABLY holds the commanded connect state.
func (b *Base) SetConnectPlan(connect bool, tag string) (PlanOutcome, error) {
	p, err := b.newM123ConnPlan(connect, tag)
	if err != nil {
		return PlanOutcome{Tag: tag, Plan: PlanM123Connect}, err
	}
	return p.execute()
}

func (b *Base) newM123ConnPlan(connect bool, tag string) (*m123ConnPlan, error) {
	if !b.Reader.HasModel(sunspec.ModelImmediateCtrl) {
		return nil, &UnsupportedControlError{Axis: "opModConnect", Reason: "device has no M123 (immediate controls)"}
	}
	regs, err := b.Reader.ReadModel(sunspec.ModelImmediateCtrl)
	if err != nil {
		return nil, fmt.Errorf("%s: read Model 123: %w", tag, err)
	}
	if len(regs) <= sunspec.M123_Conn {
		return nil, &MalformedDeviceError{Tag: tag, Model: sunspec.ModelImmediateCtrl,
			Declared: len(regs), Required: sunspec.M123_Conn + 1, Detail: "too short for Conn"}
	}
	// A device that leaves Conn unimplemented cannot be connected through
	// M123 and — more to the point — can never PROVE a connect state, so the
	// axis is unsupported rather than silently unverifiable (D6: unprovable
	// axes must reach the head end as CannotComply, not as success).
	if regs[sunspec.M123_Conn] == 0xFFFF {
		return nil, &UnsupportedControlError{Axis: "opModConnect",
			Reason: "device leaves M123 Conn unimplemented (0xFFFF): the connect state can never be proven"}
	}
	p := &m123ConnPlan{b: b, tag: tag, want: 0, before: float64(regs[sunspec.M123_Conn])}
	if connect {
		p.want = 1
	}
	return p, nil
}

func (p *m123ConnPlan) execute() (PlanOutcome, error) {
	out := PlanOutcome{Tag: p.tag, Plan: PlanM123Connect, Elements: []ElementOutcome{{
		Name: ElemM123Conn, Model: sunspec.ModelImmediateCtrl, Before: p.before, After: math.NaN(),
	}}}
	var writeErr error
	if err := p.b.Reader.WriteModel(sunspec.ModelImmediateCtrl, sunspec.M123_Conn, []uint16{p.want}); err != nil {
		writeErr = fmt.Errorf("%s: set connect=%v: %w", p.tag, p.want == 1, err)
		out.Elements[0].Err = writeErr
	}

	// L1 proof: the echo, never the ACK.
	got, ok := p.b.readM123Point(sunspec.M123_Conn)
	if !ok {
		// Post-state unreadable ⇒ Unverified, never Failed. A commanded
		// disconnect we cannot read back must be assumed not to have landed.
		out.Elements[0].State = ElementUnverified
		out.LessRestrictiveThanIntended = p.want == 0
		if writeErr != nil {
			return out, writeErr
		}
		return out, &VerifyError{Tag: p.tag, Model: sunspec.ModelImmediateCtrl, Point: ElemM123Conn,
			Detail: "device accepted the write but its post-state could not be read back"}
	}
	out.Elements[0].After = float64(got)
	if got == p.want {
		// Measured, not inferred: an errored write that nonetheless landed is
		// an applied element, and re-driving it would be a write the device
		// does not need.
		out.Elements[0].State = ElementApplied
		if writeErr != nil {
			out.Elements[0].Advisory = "write returned an error but the device measurably holds the commanded state"
		}
		return out, nil
	}
	out.Elements[0].State = ElementFailed
	out.LessRestrictiveThanIntended = p.want == 0
	if writeErr != nil {
		return out, writeErr
	}
	return out, &VerifyError{Tag: p.tag, Model: sunspec.ModelImmediateCtrl, Point: ElemM123Conn,
		Detail: fmt.Sprintf("wrote Conn=%d, device reads back %d", p.want, got)}
}

func (b *Base) SetImportLimit(ap *model.ActivePower, tag string) error {
	return b.setLegacyWMaxLimPct(-watts(ap), tag)
}

func (b *Base) SetExportLimit(ap *model.ActivePower, tag string) error {
	return b.setLegacyWMaxLimPct(watts(ap), tag)
}

// ReadLegacyWMaxLimPctW reads back the ACTIVE M123 active-power limit in
// watts — the exact register pair setLegacyWMaxLimPct writes, so a legacy
// (704-less) inverter can prove a commanded ceiling the same way a 700-series
// one does (LXR-012 positive read-back).
//
// It exists because the read-back was originally written against 704 only,
// which silently made every legacy inverter permanently UNVERIFIABLE: no
// sample could ever be a match, so the reconciler never converged and the
// CSIP actuation-confirm gate escalated CannotComply on every control. The
// asymmetry — writing M123 but reading 704 — is the whole bug.
//
// ok=false means no limit is proven in force: the enable bit is off, the
// scale factor is unusable, or the nameplate needed for % → W is unknown.
// Never "the limit is applied".
func (b *Base) ReadLegacyWMaxLimPctW(tag string) (float64, bool, error) {
	if !b.Reader.HasModel(sunspec.ModelImmediateCtrl) {
		return 0, false, nil
	}
	regs, err := b.Reader.ReadModel(sunspec.ModelImmediateCtrl)
	if err != nil {
		return 0, false, fmt.Errorf("%s: read Model 123: %w", tag, err)
	}
	if len(regs) <= sunspec.M123_WMaxLimPct_SF {
		return 0, false, &MalformedDeviceError{Tag: tag, Model: sunspec.ModelImmediateCtrl,
			Declared: len(regs), Required: sunspec.M123_WMaxLimPct_SF + 1, Detail: "too short for WMaxLimPct_SF"}
	}
	if regs[sunspec.M123_WMaxLimPct_Ena] != 1 {
		return 0, false, nil // no limit engaged on the device
	}
	sf := int16(regs[sunspec.M123_WMaxLimPct_SF])
	pct := sunspec.ApplyScaleUint(regs[sunspec.M123_WMaxLimPct], sf)
	if math.IsNaN(pct) || math.IsInf(pct, 0) {
		return 0, false, nil // unusable scale factor or sentinel
	}
	if math.IsNaN(b.Wmax) || b.Wmax <= 0 {
		return 0, false, nil // cannot convert % → W without a nameplate
	}
	return pct / 100.0 * b.Wmax, true, nil
}

// ReadLegacyConnect reads back the ACTIVE M123 connect state — the exact
// register SetConnect writes — so a legacy (704-less) inverter can prove a
// commanded connect/disconnect the same way a 701-bearing one proves it
// through ConnSt (LXR-012-connect positive read-back).
//
// It is the exact mirror of ReadLegacyWMaxLimPctW and exists for the same
// reason: without it every 704-less inverter is permanently UNPROVABLE on
// Connect. No sample can ever be a match, so the reconciler never converges,
// no terminal Applied is emitted, and the CSIP actuation-confirm gate
// escalates on every control — with the safety-relevant direction being a
// commanded cease that nothing can confirm.
//
// ok=false means no connect state is proven: the device has no M123, the
// block is short, the point is unimplemented, or it carries a value that is
// neither connected nor disconnected. Never "the device is connected".
func (b *Base) ReadLegacyConnect(tag string) (bool, bool, error) {
	if !b.Reader.HasModel(sunspec.ModelImmediateCtrl) {
		return false, false, nil
	}
	regs, err := b.Reader.ReadModel(sunspec.ModelImmediateCtrl)
	if err != nil {
		return false, false, fmt.Errorf("%s: read Model 123: %w", tag, err)
	}
	if len(regs) <= sunspec.M123_Conn {
		return false, false, &MalformedDeviceError{Tag: tag, Model: sunspec.ModelImmediateCtrl,
			Declared: len(regs), Required: sunspec.M123_Conn + 1, Detail: "too short for Conn"}
	}
	switch regs[sunspec.M123_Conn] {
	case 0:
		return false, true, nil
	case 1:
		return true, true, nil
	}
	// Unimplemented (0xFFFF) or an out-of-domain enum: unprovable, and an
	// unprovable connect state is never reported as connected.
	return false, false, nil
}

// ── M123 WMaxLimPct: the legacy active-power ceiling plan ────────────────────

// m123LimitPlan is the legacy (704-less) active-power ceiling as an actuation
// plan. Three registers — ramp time, value, enable — are ONE control, and the
// pre-LXR-012 writer sent all three with no proof that any of them landed: it
// returned the third write's error, so a device that ACK'd and dropped the
// enable reported a clean success while running uncurtailed.
//
// The plan's shape (see plan.go for the phases and the measured-not-inferred
// rule):
//
//   - preflight validates model, block length, corrupt-read, scale-factor
//     domain, encode representability and nameplate, and snapshots the
//     pre-state. The pre-state snapshot is not diagnostics: without it the
//     enable-refresh case (device already enabled, refresh write failed,
//     ceiling nonetheless in force) is indistinguishable from a genuine
//     mixed state, and over-classifying it would fail a control the device
//     is correctly executing.
//   - execute prefers ONE grouped FC16 over offsets 0-4, because the five
//     WMaxLimPct-group points are contiguous and a single transaction has no
//     partial-state window at all. A device that refuses it falls back to the
//     element sequence (D8), which doubles as the completion path for a
//     device that applied only a PREFIX of the grouped write.
//   - the sequence writes ramp → value → enable, enable LAST, so no
//     intermediate state is less restrictive than where it started.
type m123LimitPlan struct {
	b   *Base
	tag string

	// preflight products
	raw    uint16  // encoded WMaxLimPct target word
	pct    float64 // signed engineering target, % of WMax (negative = charge)
	charge bool
	sf     int16
	rmp    uint16

	grouped     bool
	win0, rvrt0 uint16 // a grouped write puts these two back AS READ

	// pre-state, measured before the first write
	val0, ena0, rmp0 uint16
	pct0             float64

	attempted [3]bool
}

// SetLegacyWMaxLimPctPlan runs the M123 ceiling plan and returns the measured
// outcome. A nil error means the commanded ceiling is measurably in force on
// the device (possibly applied-degraded — see PlanOutcome.Degraded); an
// ErrPartialActuation means the device was left in a state neither commanded
// nor pre-existing and must be escalated, not retried blindly.
func (b *Base) SetLegacyWMaxLimPctPlan(w float64, tag string) (PlanOutcome, error) {
	p, err := b.newM123LimitPlan(w, tag)
	if err != nil {
		return PlanOutcome{Tag: tag, Plan: PlanM123Limit}, err
	}
	return p.execute()
}

// setLegacyWMaxLimPct writes M123 WMaxLimPct. Negative w commands charge
// (battery sim convention); positive w limits export. It is a thin wrapper
// over the plan — the RawFromScaleSigned/EncodeScaleSigned convention: the
// outcome-bearing entry point is the real one, and this signature exists so
// existing callers keep compiling.
func (b *Base) setLegacyWMaxLimPct(w float64, tag string) error {
	_, err := b.SetLegacyWMaxLimPctPlan(w, tag)
	return err
}

// m123GroupSentinels counts how many of the five WMaxLimPct-group points read
// the uint16 not-implemented sentinel.
func m123GroupSentinels(regs []uint16) int {
	n := 0
	for _, off := range []int{sunspec.M123_WMaxLimPct, sunspec.M123_WMaxLimPct_WinTms,
		sunspec.M123_WMaxLimPct_RvrtTms, sunspec.M123_WMaxLimPct_RmpTms, sunspec.M123_WMaxLimPct_Ena} {
		if off < len(regs) && regs[off] == 0xFFFF {
			n++
		}
	}
	return n
}

// newM123LimitPlan is the plan's preflight: it validates the whole request and
// snapshots the pre-state, and writes nothing.
func (b *Base) newM123LimitPlan(w float64, tag string) (*m123LimitPlan, error) {
	if err := b.requireWmax(tag); err != nil {
		return nil, err
	}
	p := &m123LimitPlan{b: b, tag: tag, charge: w < 0, rmp: b.legacyRmpTms()}
	mag := math.Abs(w)
	if mag > b.Wmax {
		mag = b.Wmax
	}
	regs, err := b.Reader.ReadModel(sunspec.ModelImmediateCtrl)
	if err != nil {
		return nil, fmt.Errorf("%s: read Model 123: %w", tag, err)
	}
	if len(regs) <= sunspec.M123_WMaxLimPct_SF {
		return nil, &MalformedDeviceError{Tag: tag, Model: sunspec.ModelImmediateCtrl,
			Declared: len(regs), Required: sunspec.M123_WMaxLimPct_SF + 1, Detail: "too short for WMaxLimPct_SF"}
	}
	// M123 corrupt-read gate, the model-123 counterpart of write704's
	// ReadLooksCorrupt (audit E2). Model 123 has no declarative Layout, so the
	// two signals are checked by hand, in ReadLooksCorrupt's priority order:
	//
	//  1. the scale factor is out of the legal sunssf domain (below) — a
	//     read-only device constant, so an illegal one is authoritative
	//     evidence of a bad read;
	//  2. otherwise, sentinel saturation of the five points this plan writes.
	//
	// Saturation is deliberately ALL FIVE, not ReadLooksCorrupt's half-block:
	// WinTms and RvrtTms unimplemented is the ordinary shape of a real
	// inverter (it is exactly the D8 grouping-skip trigger below), and
	// rejecting it as corruption would refuse to curtail perfectly healthy
	// hardware. All five is the failed-read shape and nothing else.
	if m123GroupSentinels(regs) == 5 {
		return nil, fmt.Errorf("%s: refusing to write M123 — the WMaxLimPct group read back all-sentinel "+
			"(partial/failed read); not programming garbage back to the device", tag)
	}
	p.sf = int16(regs[sunspec.M123_WMaxLimPct_SF])
	if !sunspec.ValidSF(p.sf) {
		return nil, &MalformedDeviceError{Tag: tag, Model: sunspec.ModelImmediateCtrl,
			Declared: len(regs), Required: len(regs),
			Detail: fmt.Sprintf("WMaxLimPct_SF=%d outside legal sunssf domain", p.sf)}
	}
	pct := mag / b.Wmax * 100.0
	// Checked encode (LXR-004): a limit command that cannot be represented at
	// the device's scale factor must fail loudly, never be silently written as
	// a clamped different limit or a fabricated zero.
	var outcome sunspec.EncodeOutcome
	if p.charge {
		p.pct = -pct
		p.raw, outcome = sunspec.EncodeScaleSigned(-pct, p.sf)
	} else {
		p.pct = pct
		p.raw, outcome = sunspec.EncodeScaleUint(pct, p.sf)
	}
	if !outcome.Representable() {
		return nil, fmt.Errorf("%s: WMaxLimPct %.2f%% not representable at sf=%d (encode outcome %d): %w",
			tag, pct, p.sf, outcome, ErrInvalidControl)
	}

	// Pre-state snapshot (mandatory — see the type doc).
	p.val0 = regs[sunspec.M123_WMaxLimPct]
	p.ena0 = regs[sunspec.M123_WMaxLimPct_Ena]
	p.rmp0 = regs[sunspec.M123_WMaxLimPct_RmpTms]
	p.win0 = regs[sunspec.M123_WMaxLimPct_WinTms]
	p.rvrt0 = regs[sunspec.M123_WMaxLimPct_RvrtTms]
	p.pct0 = p.decode(p.val0)

	// Grouping decision (D8): a grouped write puts WinTms and RvrtTms back
	// AS READ, so it is only safe when the device implements them — writing a
	// sentinel into a timer point is exactly the garbage-back-to-the-device
	// class the corrupt-read gate above exists to prevent. The memo makes a
	// device that refused a grouped write pay for it once, not every time.
	p.grouped = !b.noGroupedM123 && m123GroupSentinels(regs) == 0
	return p, nil
}

// decode converts a raw WMaxLimPct word to engineering percent in the sign
// domain of the command being executed. NaN means "not interpretable", which
// ceilingRestriction scores as no limit in force.
func (p *m123LimitPlan) decode(raw uint16) float64 {
	if p.charge {
		return sunspec.ApplyScaleSigned(raw, p.sf)
	}
	if raw == 0xFFFF {
		return math.NaN() // uint16 not-implemented sentinel
	}
	return sunspec.ApplyScaleUint(raw, p.sf)
}

func (p *m123LimitPlan) write(off uint16, vals ...uint16) error {
	return p.b.Reader.WriteModel(sunspec.ModelImmediateCtrl, off, vals)
}

// readGroup re-reads the M123 block for classification. ok=false is the
// "post-state cannot be read" case the load-bearing rule turns into
// Unverified.
func (p *m123LimitPlan) readGroup() ([]uint16, bool) {
	regs, err := p.b.Reader.ReadModel(sunspec.ModelImmediateCtrl)
	if err != nil || len(regs) <= sunspec.M123_WMaxLimPct_SF {
		return nil, false
	}
	return regs, true
}

func (p *m123LimitPlan) execute() (PlanOutcome, error) {
	out := PlanOutcome{Tag: p.tag, Plan: PlanM123Limit, Elements: []ElementOutcome{
		{Name: ElemM123RmpTms, Model: sunspec.ModelImmediateCtrl, Before: float64(p.rmp0), After: math.NaN()},
		{Name: ElemM123WMaxLimPct, Model: sunspec.ModelImmediateCtrl, Before: p.pct0, After: math.NaN()},
		{Name: ElemM123Ena, Model: sunspec.ModelImmediateCtrl, Before: float64(p.ena0), After: math.NaN()},
	}}

	if p.grouped {
		// One FC16 over offsets 0-4: value, WinTms and RvrtTms back as read,
		// ramp, enable. No partial-state window exists inside a single
		// transaction — the device either takes it or it does not.
		p.attempted = [3]bool{true, true, true}
		err := p.write(sunspec.M123_WMaxLimPct, p.raw, p.win0, p.rvrt0, p.rmp, 1)
		if err == nil {
			return p.classify(out)
		}
		// D8 attempt-then-fall-back, with the memo so the next plan on this
		// device goes straight to the sequence. This same path COMPLETES a
		// grouped write the device applied only a prefix of: the sequence is
		// idempotent, and completion — every remaining element being neutral
		// or more restrictive — is itself the compensating action.
		p.b.noGroupedM123 = true
		out.Elements[m123ElemVal].Advisory = fmt.Sprintf(
			"device refused the grouped single-write (%v); completed element by element", err)
	}

	// 1. Ramp time. It governs how the device walks to the new ceiling, so it
	//    goes first — and its failure is advisory: a ceiling reached on the
	//    device's own ramp is still the commanded ceiling (row 4).
	p.attempted[m123ElemRmp] = true
	if err := p.write(sunspec.M123_WMaxLimPct_RmpTms, p.rmp); err != nil {
		out.Elements[m123ElemRmp].Err = fmt.Errorf("%s: set ramp time: %w", p.tag, err)
	}

	// 2. The ceiling value, still inert while the enable is off.
	p.attempted[m123ElemVal] = true
	if err := p.write(sunspec.M123_WMaxLimPct, p.raw); err != nil {
		out.Elements[m123ElemVal].Err = fmt.Errorf("%s: write WMaxLimPct: %w", p.tag, err)
	}

	// NEVER ENABLE A VALUE THAT IS NOT MEASURED AT TARGET. This read is the
	// measured-not-inferred rule applied where it is load-bearing rather than
	// diagnostic, in both directions: a value write that errored may have
	// landed (so the plan continues — row 7), and one that was ACK'd may have
	// been dropped (so the plan stops before latching whatever the device is
	// actually holding — row 8, the row where enabling would put an
	// unintended, possibly higher, ceiling into force).
	if got, ok := p.b.readM123Point(sunspec.M123_WMaxLimPct); !ok || got != p.raw {
		out.Elements[m123ElemEna].Advisory = "not written: the ceiling value was not proven at target, " +
			"and enabling an unproven value latches whatever the device is actually holding"
		return p.classify(out)
	}

	// 3. The enable — the completing element.
	p.attempted[m123ElemEna] = true
	if err := p.write(sunspec.M123_WMaxLimPct_Ena, 1); err != nil {
		out.Elements[m123ElemEna].Err = fmt.Errorf("%s: enable WMaxLimPct: %w", p.tag, err)
	}
	return p.classify(out)
}

// classify re-reads the device and decides what actually happened. Every
// verdict below comes from the READING; the recorded write errors only
// choose which error value is returned.
func (p *m123LimitPlan) classify(out PlanOutcome) (PlanOutcome, error) {
	regs, ok := p.readGroup()
	if !ok {
		for i := range out.Elements {
			if p.attempted[i] {
				out.Elements[i].State = ElementUnverified
			}
		}
		if firstElementErr(out) != nil {
			// A write errored AND the device will not say where it landed.
			// The unknown partial is treated as MIXED: with writes in flight
			// and no post-state, a clean verdict in either direction is the
			// guess this mechanism exists to refuse (rows 12/13).
			out.Mixed = true
			out.LessRestrictiveThanIntended = true
			return out, &PartialActuationError{Tag: p.tag, Plan: out.Plan, Outcome: out}
		}
		return out, &VerifyError{Tag: p.tag, Model: sunspec.ModelImmediateCtrl, Point: ElemM123WMaxLimPct,
			Detail: "device accepted every write but its post-state could not be read back"}
	}

	valAfter := regs[sunspec.M123_WMaxLimPct]
	enaAfter := regs[sunspec.M123_WMaxLimPct_Ena]
	rmpAfter := regs[sunspec.M123_WMaxLimPct_RmpTms]
	out.Elements[m123ElemRmp].After = float64(rmpAfter)
	out.Elements[m123ElemVal].After = p.decode(valAfter)
	out.Elements[m123ElemEna].After = float64(enaAfter)

	valOK, enaOK := valAfter == p.raw, enaAfter == 1
	out.Elements[m123ElemRmp].State = p.stateOf(m123ElemRmp, rmpAfter == p.rmp)
	out.Elements[m123ElemVal].State = p.stateOf(m123ElemVal, valOK)
	out.Elements[m123ElemEna].State = p.stateOf(m123ElemEna, enaOK)
	if rmpAfter != p.rmp {
		out.Elements[m123ElemRmp].Advisory = fmt.Sprintf(
			"device holds RmpTms=%ds, wrote %ds — this changes how fast the device walks to the ceiling, not the ceiling",
			rmpAfter, p.rmp)
	}

	if valOK && enaOK {
		// The commanded ceiling is MEASURED in force. A failed ramp time
		// leaves this applied-DEGRADED (D9), not failed — the device is
		// enforcing exactly what was asked for.
		return out, nil
	}

	achieved := ceilingRestriction(p.decode(valAfter), enaOK)
	intended := ceilingRestriction(p.pct, true)
	pre := ceilingRestriction(p.pct0, p.ena0 == 1)
	out.LessRestrictiveThanIntended = achieved > intended

	// Mixed = the device is in NEITHER the state the plan found it in NOR the
	// one it was commanded into. RmpTms is deliberately not part of this: it
	// is not a state of the ceiling, and folding it in would classify a
	// harmless ramp-time difference as a mixed-state escalation.
	out.Mixed = valAfter != p.val0 || enaAfter != p.ena0
	if !out.Mixed {
		// The device is exactly where the plan found it: a clean failure, not
		// a partial actuation. Nothing to compensate — there is nothing to
		// compensate FOR — and no reservation is warranted beyond whatever
		// the pre-state already implied.
		if err := firstElementErr(out); err != nil {
			return out, err
		}
		point, detail := ElemM123WMaxLimPct, fmt.Sprintf(
			"wrote raw %d (%.2f%% of WMax), device reads back %d", p.raw, p.pct, valAfter)
		if valOK {
			point, detail = ElemM123Ena, fmt.Sprintf(
				"wrote Ena=1, device reads back %d — the ceiling value is staged but not in force", enaAfter)
		}
		return out, &VerifyError{Tag: p.tag, Model: sunspec.ModelImmediateCtrl, Point: point, Detail: detail}
	}
	return p.compensate(out, valOK, achieved, pre, intended)
}

// stateOf turns a measured hit/miss into an ElementState. An element the plan
// never wrote is NotAttempted even when the device happens to hold the
// intended value — the plan reports what it did, and the measurement is in
// Before/After either way.
func (p *m123LimitPlan) stateOf(i int, hit bool) ElementState {
	switch {
	case hit && p.attempted[i]:
		return ElementApplied
	case !p.attempted[i]:
		return ElementNotAttempted
	default:
		return ElementFailed
	}
}

// compensate implements the §5 rule (adopted D1) for a MEASURED mixed state:
// one bounded re-attempt of the completing element, or a write of the more
// restrictive of {pre-state, achieved} — and otherwise freeze the device where
// it is and declare it. Nothing here ever moves a device toward less
// restrictive.
func (p *m123LimitPlan) compensate(out PlanOutcome, valOK bool, achieved, pre, intended float64) (PlanOutcome, error) {
	// (a) ONE bounded re-attempt of the completing element, and only when the
	// ceiling VALUE is measured at target. This is not a compensating move at
	// all — it completes the operator's own command — which is why it is
	// allowed to end in a state less restrictive than the pre-state if that
	// is what was commanded.
	if valOK {
		if err := p.write(sunspec.M123_WMaxLimPct_Ena, 1); err == nil {
			if regs, ok := p.readGroup(); ok &&
				regs[sunspec.M123_WMaxLimPct] == p.raw && regs[sunspec.M123_WMaxLimPct_Ena] == 1 {
				out.Elements[m123ElemEna].State = ElementApplied
				out.Elements[m123ElemEna].After = 1
				out.Elements[m123ElemEna].Advisory = "adopted on the plan's one bounded re-attempt"
				out.Mixed = false
				out.LessRestrictiveThanIntended = false
				return out, nil
			}
		}
	}

	// (b) Write the MORE RESTRICTIVE of {pre-state, achieved}. Strictly more
	// restrictive only: if the device is already held back at least as much
	// as it was before the plan, there is nothing to gain and a needless
	// write to a device in a partial state is its own hazard.
	//
	// Reverting the ENABLE is deliberately not among the options: with the
	// enable off the staged value is inert, so reverting throws away a
	// more-restrictive staged value and leaves a loose value to latch later.
	if strictlyMoreRestrictive(pre, achieved) {
		if val, ena, ok := p.restorePreState(); ok {
			switch {
			case val == p.raw && ena == 1:
				// The restored pre-state IS the commanded state: the plan was
				// asked for a ceiling the device already had, and a partial
				// write bounced it away and back. The verdict follows the
				// measurement here as everywhere else — the device holds the
				// command, so this is applied, not a partial actuation. A
				// caller told otherwise would escalate a DER that is doing
				// exactly what it was told.
				out.Elements[m123ElemVal].State = ElementApplied
				out.Elements[m123ElemVal].After = p.pct0
				out.Elements[m123ElemVal].Advisory = "re-proven at the commanded state after a partial write"
				out.Elements[m123ElemEna].State = ElementApplied
				out.Elements[m123ElemEna].After = float64(ena)
				out.Mixed = false
				out.LessRestrictiveThanIntended = false
				return out, nil
			case val == p.val0 && ena == p.ena0:
				out.Elements[m123ElemVal].State = ElementCompensated
				out.Elements[m123ElemVal].After = p.pct0
				out.Elements[m123ElemEna].State = ElementCompensated
				out.Elements[m123ElemEna].After = float64(ena)
				out.LessRestrictiveThanIntended = pre > intended
				return out, &PartialActuationError{Tag: p.tag, Plan: out.Plan, Outcome: out, Compensated: true}
			}
		}
	}

	// Freeze-and-declare: the device stays where it is, and the caller is
	// told exactly that, with the per-element evidence.
	return out, &PartialActuationError{Tag: p.tag, Plan: out.Plan, Outcome: out}
}

// restorePreState writes the pre-state ceiling back and returns the MEASURED
// (value, enable) that followed. ok=false when a restoring write errored or
// its result could not be read: an unproven restoration is not a
// compensation, it is one more unverified write, and the plan freezes and
// declares instead of claiming one.
func (p *m123LimitPlan) restorePreState() (uint16, uint16, bool) {
	if err := p.write(sunspec.M123_WMaxLimPct, p.val0); err != nil {
		return 0, 0, false
	}
	if err := p.write(sunspec.M123_WMaxLimPct_Ena, p.ena0); err != nil {
		return 0, 0, false
	}
	regs, ok := p.readGroup()
	if !ok {
		return 0, 0, false
	}
	return regs[sunspec.M123_WMaxLimPct], regs[sunspec.M123_WMaxLimPct_Ena], true
}

func ReadWMax(r *sunspec.Reader) (float64, error) {
	regs, err := r.ReadModel(sunspec.ModelBasicSettings)
	if err != nil {
		return 0, err
	}
	if len(regs) <= sunspec.M121_WMax_SF {
		return 0, fmt.Errorf("sunspec: Model 121 too short for WMax_SF")
	}
	sf := int16(regs[sunspec.M121_WMax_SF])
	wmax := sunspec.ApplyScaleUint(regs[sunspec.M121_WMax], sf)
	if wmax <= 0 || math.IsNaN(wmax) {
		return 0, fmt.Errorf("sunspec: Model 121 WMax is %g (invalid)", wmax)
	}
	return wmax, nil
}

func ReadWMaxFrom702(r *sunspec.Reader) (float64, error) {
	regs, err := r.ReadModel(sunspec.ModelDERCapacity)
	if err != nil {
		return 0, err
	}
	wmax := sunspec.L702.View(regs).Float("WMaxRtg")
	if wmax <= 0 || math.IsNaN(wmax) {
		return 0, fmt.Errorf("sunspec: Model 702 WMaxRtg is %g (invalid)", wmax)
	}
	return wmax, nil
}
