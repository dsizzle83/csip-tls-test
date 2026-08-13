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
//	opModFixedVar        → 704 VarSet{Mod,Pri,Pct}, VarSetMod chosen by the
//	                       control's own refType (varsetmod.go); refType=0 and
//	                       any base 704 cannot express are REFUSED
//	opModFixedW          → 704 WSet (Set Active Power, watts) — setpoint;
//	                       beyond the nameplate it REFUSES, never clamps
//	opModMaxLimW/ExpLimW/GenLimW → 704 WMaxLimPct (% of WMax) — ceiling, and
//	                       simultaneous ceilings min-combine in watts
//	opModImpLimW/LoadLimW → REFUSED: no 7xx register expresses an import bound
//	                       (see importBoundUnsupported for the survey)
//
// Curve modes (opModVoltVar / opModVoltWatt / ride-through / freq-droop) are
// applied through the typed curve writers, which follow the §3.1.2 adopt
// workflow: write the staging curve, request adoption (AdptCrvReq>1), poll
// AdptCrvRslt, then enable the function (Ena=1) per §3.3.
package derbase

import (
	"errors"
	"fmt"
	"math"
	"strings"
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

	// DefaultWRmpPct / DefaultVarRmpPct (CSIP_CONTROL_EXECUTION_2026-08-12.md
	// §3.2/§7.1), when non-nil, are written to 704's WRmp / VarRmp as a
	// standing device ramp-rate POLICY (percent of the reference named by
	// DefaultWRmpRefIsAMax, per second — unscaled, matching WRmp/VarRmp's own
	// register convention). Unlike DefaultRvrtTms, these are STICKY/GLOBAL
	// (§1.2): one write governs every subsequent WSet/WMaxLimPct/VarSet
	// transition until next changed, not a value scoped to one control. nil
	// (the zero value) leaves WRmp/VarRmp untouched — byte-identical to
	// today's behavior for every caller that does not opt in.
	DefaultWRmpPct       *float64
	DefaultVarRmpPct     *float64
	DefaultWRmpRefIsAMax bool

	// DefaultWSetRvrt / DefaultWSetEnaRvrt (IW13-004a — docs/design/
	// IW13_CONTROL_EXECUTION_COMPLETENESS_2026-08-12.md §2a) are the missing
	// reversion-alternate half of WSetRvrtTms: the countdown DefaultRvrtTms
	// already arms has never had a defined destination, so expiry today lands
	// the device on whatever WSetRvrt/WSetEnaRvrt already hold — the factory
	// default or a stale prior session, never a value this gateway chose.
	// DefaultWSetRvrt is WATTS, the same domain as SetActivePowerWatts' own w
	// parameter (WSet/WSetRvrt share one WSet_SF scale factor, no per-write
	// conversion) and is validated against the nameplate exactly like the
	// primary setpoint (checkSetpointWithinNameplate) — a reversion
	// destination the device cannot hold is refused, not silently written.
	// DefaultWSetEnaRvrt is the arming bit. The two are consumed together:
	// EnaRvrt=true with no value is refused (see rvrtAlternateWriter) rather
	// than silently armed against the register's current, unknown contents —
	// that is the exact hazard this finding exists to close. nil
	// DefaultWSetEnaRvrt (the zero value) leaves both registers untouched —
	// byte-identical to today for every caller that does not opt in; the gw
	// caller populates both from its own resolved default/DefaultFallback
	// (stage 2, not implemented here).
	DefaultWSetRvrt    *float64
	DefaultWSetEnaRvrt *bool

	// DefaultWMaxLimPctRvrt / DefaultWMaxLimPctEnaRvrt is DefaultWSetRvrt's
	// sibling for the WMaxLimPct ceiling axis (WMaxLimPctRvrtTms's own missing
	// destination). DefaultWMaxLimPctRvrt is WATTS — matching
	// SetWMaxLimPctW's own w parameter, NOT the WMaxLimPctRvrt register's raw
	// percent-of-WMax domain — and is converted to percent at write time
	// exactly as the primary WMaxLimPct value already is (negative refused,
	// above-nameplate clamped to 100%, the same rule SetWMaxLimPctW applies to
	// its own w). A ceiling reversion value is a bound like the primary
	// ceiling, so it clamps rather than refuses at the top of its range;
	// DefaultWSetRvrt above is a setpoint's alternate and refuses instead, for
	// the identical reason SetActivePowerWatts refuses rather than clamps.
	DefaultWMaxLimPctRvrt    *float64
	DefaultWMaxLimPctEnaRvrt *bool

	// CSIPRampTmsSeconds, when non-nil, is a CSIP-resolved per-axis ramp time
	// (seconds) for the legacy M123 active-power ceiling that legacyRmpTms()
	// prefers over LegacyRmpTms's fixed policy default (§3.3, closes Gap D) —
	// additive precedence, not a replacement: LegacyRmpTms/defaultLegacyRmpTms
	// still governs whenever this is nil (an mbaps-authority write, or a CSIP
	// control that named no ramp for this axis).
	CSIPRampTmsSeconds *uint16

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
	// CtrlModes is the RAW 702 "supported control mode functions" bitfield,
	// sentinel preserved: CtrlModesNotImplemented when the device leaves the
	// point unimplemented or truncates the block before it, and the declared
	// bitfield (possibly empty) otherwise. The sentinel is kept rather than
	// laundered to zero precisely so "not implemented" and "implemented and
	// empty" stay distinguishable — see capability.go for the three-state
	// deny-by-default rule and CtrlModeClaim for the query.
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
		// Bitfield32OK, not Bitfield32: the plain reader collapses "device says
		// NOT IMPLEMENTED" onto the empty bitfield, and the empty bitfield used
		// to mean "permit everything". Keep the sentinel so the capability gate
		// can tell the two apart (audit finding 4).
		if raw, ok := sunspec.L702.View(regs).Bitfield32OK("CtrlModes"); ok {
			b.CtrlModes = raw
		} else {
			b.CtrlModes = CtrlModesNotImplemented
		}
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
	WhExpTotal float64 // total energy injected (701 TotWhInj, or legacy 10x WH)

	// Live is this sample's measurement-liveness digest (liveness.go): a
	// class-partitioned fingerprint of the raw registers the sample was
	// decoded from, plus the energy accumulators in the clear.
	//
	// It is ADDITIVE and inert on its own. Every existing consumer that
	// copies, compares or serialises a Measurements keeps working unchanged —
	// nothing here is a wire value — and a consumer that wants freshness
	// compares two samples' digests across a window of its own choosing. The
	// zero value (all digests 0, all *Points 0) is what a Measurements built
	// by hand carries, and its zero VolatilePoints reads as "no evidence",
	// which is the correct answer for a synthesised sample.
	Live Liveness
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
	out.Live = LivenessOfM701(regs)
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
	// Model 10x has no St/InvSt/ConnSt/Alrm points that map onto the 701
	// semantics — the state pointers stay nil.
	//
	// It DOES have one lifetime energy accumulator (WH, acc32 at offsets
	// 22-23, scaled by WH_SF at 24), decoded below into WhExpTotal. Only the
	// EXPORT direction: the legacy model counts AC lifetime production and has
	// no absorbed-energy counterpart, so WhImpTotal stays NaN — absent, per
	// the struct doc, never a fabricated zero.
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
	// ── D-10: the legacy lifetime energy accumulator ─────────────────────────
	//
	// WH was the one 10x measurement this decoder threw away, and it is the one
	// the freshness cross-check most wants: an energy counter is MONOTONE, so
	// its stillness while the block claims kilowatts is a contradiction rather
	// than merely an absence of movement (S1). Decoding it here rather than
	// only inside the digest means the value also reaches the bus, where a
	// legacy inverter previously published no lifetime energy at all.
	//
	// readM103WH decides presence from WH_SF, not from the counter's own
	// value: an acc32 reserves NO not-implemented sentinel, so a raw 0 is a
	// legitimate "nothing accumulated yet" and must not be laundered into
	// absence. A device that does not implement WH leaves WH_SF at the int16
	// sentinel (or outside the legal sunssf domain), which is what fails here.
	if wh, ok := readM103WH(regs); ok {
		m.WhExpTotal = wh
	}
	m.Live = LivenessOfACModel(regs)
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

// pctChecked converts a CSIP SignedPerCent/PerCent hundredths value to a
// percent float, range-checked per the XSD's xs:short domain
// (docs/design/IW13_ACTIVE_POWER_UNITS_2026-08-12.md §2.4): signed axes
// (opModFixedW) to [-10000,10000] hundredths, unsigned axes (opModMaxLimW)
// to [0,10000]. IW13-001 — opModFixedW/opModMaxLimW are percent, not watts.
func pctChecked(hundredths int16, axis string, signed bool) (float64, error) {
	var lo int16
	if signed {
		lo = -10000
	}
	if hundredths < lo || hundredths > 10000 {
		return 0, &InvalidControlError{Axis: axis,
			Reason: fmt.Sprintf("percent %d hundredths outside [%d,10000]", hundredths, lo)}
	}
	return float64(hundredths) / 100.0, nil
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
// ApplyControl is a plan of plans, and runs the same three phases every plan
// in this package runs (see plan.go) — for reasons the audit did not name:
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
//  3. CLASSIFY THE DOCUMENT, not just the axis that broke. See
//     ApplyControlPlan.
//
// This CHANGES THE ORDER OF WRITES for every existing consumer. That is the
// intended fix, not a side effect.
//
// ApplyControl keeps the error-only signature for callers that have nothing to
// do with the per-axis detail; ApplyControlPlan is the same actuation with the
// document-level outcome attached, the same way SetConnect wraps
// SetConnectPlan.
func (b *Base) ApplyControl(ctrl model.DERControlBase, tag string) error {
	_, err := b.ApplyControlPlan(ctrl, tag)
	return err
}

// PlanApplyControl names the document-level plan in PlanOutcome,
// PartialActuationError and (upstream) journal entries and metric labels.
// Element names are the CSIP DERControlBase axis names.
const PlanApplyControl = "apply-control"

// ApplyControlPlan executes a CSIP control document and returns the
// DOCUMENT-LEVEL outcome (2026-08-03 audit finding 3, the proto half).
//
// ── What was wrong ───────────────────────────────────────────────────────────
//
// The pre-fix loop returned on the first runtime error. A two-axis document
// whose second axis failed came back as that axis's bare transport error, with
// the first axis silently applied and nothing in the return value saying so.
// The caller could not tell "nothing happened" from "half of it happened", and
// a fixed-PF write landing while the fixed-var write that was supposed to
// accompany it failed is a device operating under half a command — which
// upstream is either a false Started or an escalation with no evidence
// attached.
//
// ── The outcome ──────────────────────────────────────────────────────────────
//
// One ElementOutcome per axis, in EXECUTION order, each carrying the axis's
// measured disposition (Applied / Unverified / Failed / NotAttempted) and, for
// the axes that run a measuring plan of their own, that plan's whole
// PlanOutcome in Sub. Element Before/After stay NaN at this level: the
// document does not measure registers, its axes do, and inventing a
// document-level engineering value would be exactly the kind of fabrication
// plan.go's load-bearing rule forbids.
//
// Mixed is computed ACROSS the document: some axes measured applied and at
// least one not, i.e. the device is in neither the state the document found it
// in nor the state it was commanded into. That is the verdict a caller must
// escalate. A single-axis document that fails is not mixed — nothing else
// landed — and returns the axis's own error unchanged, so existing callers see
// no new error class where there was no new situation.
//
// LessRestrictiveThanIntended is set when any RESTRICTIVE-side axis (rank
// restrict or limit — cease, disconnect, ceilings, setpoints) did not reach
// Applied, plus whatever any sub-plan reported. Release-side axes are
// deliberately excluded: which brings us to the direction of a partial
// document.
//
// ── Why the tail is the safe half ────────────────────────────────────────────
//
// Because execution is restrictive-first, the axes remaining after a
// mid-document failure are always the LESS restrictive ones. A document that
// dies half-way therefore leaves the device with the restrictive axes applied
// and the releasing axes not: cease/disconnect and ceilings landed, connect-on
// and energize-on did not. The device ends up held back MORE than the control
// asked for, never less. That is the fail-safe direction, and it is why
// freezing — declining to execute the tail — is a legitimate compensating
// action at document level rather than an abdication.
//
// ── Compensation (§5, adopted D1, applied to the document) ───────────────────
//
//	(a) ONE bounded re-attempt of the failing axis, once per document. Like
//	    the per-plan rule this COMPLETES the operator's own command and is not
//	    a compensating move, so it is allowed even on a releasing axis. Once
//	    per document, not once per axis: a device that needed a retry on axis
//	    one and then failed on axis two is not a device to keep writing to.
//	(b) NEVER WRITE TOWARD LESS RESTRICTIVE. At document level the compensating
//	    action is therefore not a write at all — it is declining to execute the
//	    releasing tail, which leaves the device on the safe side of the
//	    command. The untouched axes are reported NotAttempted.
//	    Otherwise: freeze and declare, with a typed PartialActuationError
//	    carrying the whole PlanOutcome.
//
// Preflight is unchanged: any preflight failure returns before a single
// register moves, and the returned PlanOutcome carries no elements because
// there is nothing to report about a document that was never executed.
func (b *Base) ApplyControlPlan(ctrl model.DERControlBase, tag string) (PlanOutcome, error) {
	out := PlanOutcome{Tag: tag, Plan: PlanApplyControl}
	steps, err := b.preflightControl(ctrl, tag)
	if err != nil {
		return out, err // whole-request rejection: nothing has been written
	}
	return b.runControlSteps(tag, steps)
}

// ApplyActuationWatts is ApplyControlPlan's watts-native sibling (IW13-001 §5.2;
// docs/design/IW13_ACTIVE_POWER_UNITS_2026-08-12.md), for callers that already
// hold a resolved watts value for FixedW/MaxLimW and a plain connect opinion —
// cmd/modbus's southbound reconcile shells, specifically, which never decode a
// real CSIP document at all (bus.DesiredState.SetpointW/CeilingW arrive
// already resolved to watts, the OUTPUT of the gateway's own per-DER percent
// conversion). The pre-fix code re-wrapped that watts value into a synthetic
// ActivePower purely to reuse ApplyControlPlan's ordering/preflight/
// classification machinery; once OpModFixedW/OpModMaxLimW retype to percent
// (§1), doing that again would mean encoding an already-correct watts value
// as a FAKE percent just so this function could convert it back to watts one
// call later — exactly the type-says-one-thing-code-means-another bug this
// whole design exists to eliminate. No ActivePower/SignedPerCent/PerCent
// construction happens anywhere in this call.
//
// Same three-phase contract as ApplyControlPlan (preflight-all-then-execute,
// restrictive-first order, one bounded re-attempt, document-level Mixed/
// LessRestrictiveThanIntended classification) — see ApplyControlPlan's doc
// comment for the full reasoning, shared unchanged via runControlSteps.
//
// Restricted to the three axes the southbound reconcile shells actually
// drive (Connect, FixedW, MaxLimW). PF/var/curve/energize axes are the
// advanced-DER shell's own surface (cmd/modbus/reconcile_adv.go), reached
// through ApplyControlPlan directly with a real DERControlBase, never
// through this entry point.
func (b *Base) ApplyActuationWatts(fixedW, maxLimW *float64, connect *bool, tag string) (PlanOutcome, error) {
	out := PlanOutcome{Tag: tag, Plan: PlanApplyControl}
	steps, err := b.preflightActuationWatts(fixedW, maxLimW, connect, tag)
	if err != nil {
		return out, err
	}
	return b.runControlSteps(tag, steps)
}

// runControlSteps executes a preflighted step list and builds the document-
// level PlanOutcome — the shared engine both ApplyControlPlan and
// ApplyActuationWatts drive. Factored out of ApplyControlPlan verbatim
// (IW13-001 §5.2) so the two preflighters (CSIP-typed and watts-native) can
// share one execution/classification engine; this function's BEHAVIOR is
// unchanged from before the split.
func (b *Base) runControlSteps(tag string, steps []applyStep) (PlanOutcome, error) {
	out := PlanOutcome{Tag: tag, Plan: PlanApplyControl}
	// Materialize the execution order once so the outcome's element order IS
	// the write order — a reader of the outcome must not have to re-derive it.
	ordered := make([]applyStep, 0, len(steps))
	for _, rank := range []int{rankRestrict, rankLimit, rankRelease} {
		for _, s := range steps {
			if s.rank == rank {
				ordered = append(ordered, s)
			}
		}
	}
	out.Elements = make([]ElementOutcome, len(ordered))
	for i, s := range ordered {
		out.Elements[i] = ElementOutcome{Name: s.axis, Model: s.model,
			State: ElementNotAttempted, Before: math.NaN(), After: math.NaN(),
			// Seeded before execution: a min-combined ceiling's element must
			// name the axes it reduced even if the axis is never reached.
			Advisory: s.advisory}
	}

	var runErr error
	retried := false
	for i, s := range ordered {
		sub, err := s.run()
		// §5(a): one bounded re-attempt, per document, and ONLY for an axis
		// that does not run a measuring plan of its own. An axis that does
		// (sub != nil) has already spent its one bounded re-attempt inside
		// that plan, and re-running it would do worse than double the budget:
		// the plan re-snapshots the pre-state on entry, so a second run would
		// re-baseline onto the half-actuated state the first run left and
		// report the mixed state it just measured as a clean failure. The
		// evidence would be destroyed by the attempt to improve on it.
		if err != nil && sub == nil && !retried {
			retried = true
			sub2, err2 := s.run()
			sub, err = sub2, err2
			if err == nil {
				addAdvisory(&out.Elements[i], "adopted on the document's one bounded re-attempt")
			} else {
				addAdvisory(&out.Elements[i], "the document's one bounded re-attempt also failed")
			}
		}
		out.Elements[i].Sub = sub
		if err == nil {
			out.Elements[i].State = ElementApplied
			if sub != nil && sub.Degraded() {
				addAdvisory(&out.Elements[i], "axis plan applied-degraded: "+sub.String())
			}
			continue
		}
		out.Elements[i].State = axisElementState(sub, err)
		out.Elements[i].Err = err
		runErr = err
		break // freeze: every remaining axis stays NotAttempted, which is the
		// less-restrictive tail, which is the direction we want to skip.
	}

	applied, unapplied := 0, 0
	for i, s := range ordered {
		if out.Elements[i].State == ElementApplied {
			applied++
		} else {
			unapplied++
			// Restrictive-side axes are the ones whose absence LOOSENS the
			// device relative to the command. A releasing axis that did not
			// land leaves it tighter, which is never this flag.
			if s.rank <= rankLimit {
				out.LessRestrictiveThanIntended = true
			}
		}
		if sub := out.Elements[i].Sub; sub != nil {
			out.Mixed = out.Mixed || sub.Mixed
			out.LessRestrictiveThanIntended = out.LessRestrictiveThanIntended || sub.LessRestrictiveThanIntended
		}
	}
	if runErr == nil {
		// IW13-003 §1.3 item 3: a fully-successful document (every axis
		// Applied) can still carry a WRmp/VarRmp axis whose Sub shows the ramp
		// component was dropped by write704Rmp's isolating retry (§1.3 item
		// 2's addPlan registration is what puts that Sub here at all). Promote
		// it to the document's own returned error INSTEAD of nil — the one
		// place ApplyControlPlan/ApplyActuationWatts's shared engine can make
		// that promotion without either of those two functions needing a
		// change of their own (they already return (PlanOutcome, error)).
		if rerr := firstRampNotApplied(out); rerr != nil {
			return out, rerr
		}
		return out, nil
	}
	// The document is MIXED only when it actually left the device between two
	// states. A document whose FIRST axis failed carries the axis's own error
	// (which may already be a typed PartialActuationError from that axis's own
	// plan) rather than being re-wrapped into a document-level one.
	if applied > 0 && unapplied > 0 {
		out.Mixed = true
		return out, &PartialActuationError{Tag: tag, Plan: PlanApplyControl, Outcome: out}
	}
	return out, runErr
}

// axisElementState turns one axis's runtime failure into a MEASURED element
// state, on the same evidence rule as plan.go.
//
// An axis that ran a measuring plan carries that plan's own verdict — the
// document does not second-guess a measurement with an inference. An axis with
// no plan of its own is read from the error CLASS, and only from the classes
// that are load-bearing: the deterministic pre-write refusals (missing model,
// out-of-domain request, short/corrupt block — all of which fire on the READ,
// before any register moves) are NotAttempted, and everything else is
// Unverified, never Failed. That last part is the rule doing work: a transport
// error on a write may still have LANDED, and an axis with no read-back does
// not know which happened. Unverified is unproven in both directions, which is
// the truth here; Failed would be a definite verdict the document does not
// hold.
func axisElementState(sub *PlanOutcome, err error) ElementState {
	if err == nil {
		return ElementApplied
	}
	if sub != nil {
		return worstElementState(*sub)
	}
	switch {
	case errors.Is(err, ErrUnsupportedControl), errors.Is(err, ErrInvalidControl),
		errors.Is(err, ErrMalformedDevice):
		return ElementNotAttempted
	}
	return ElementUnverified
}

// applyStep is one preflighted control axis: fully validated, not yet written.
type applyStep struct {
	axis  string
	model uint16 // SunSpec model the axis writes, for the outcome's element
	rank  int
	// advisory is seeded onto the step's ElementOutcome before execution, for
	// facts about the STEP rather than about what the device did with it — at
	// present, which simultaneously-present axes a min-combined ceiling reduced
	// (see combineCeilingsW). A document that asked for three ceilings and gets
	// one element must be able to see the other two in the outcome.
	advisory string
	// run executes the axis, returning the axis's OWN measuring plan outcome
	// when it has one (the M123 plans) and nil when it does not. The document
	// never invents a measured verdict it does not hold.
	run func() (*PlanOutcome, error)
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
//
// Capability gating here is DENY BY DEFAULT: every 7xx axis needs a positive
// 702 CtrlModes bit, and the legacy M123 pathway is reached only through the
// measured legacy shape. capability.go states both rules in full.
func (b *Base) preflightControl(ctrl model.DERControlBase, tag string) ([]applyStep, error) {
	var steps []applyStep
	add := func(axis string, modelID uint16, rank int, run func() error) {
		steps = append(steps, applyStep{axis: axis, model: modelID, rank: rank,
			run: func() (*PlanOutcome, error) { return nil, run() }})
	}
	// addPlan registers an axis whose writer is a measuring plan, so the
	// document element can carry that plan's own verdict instead of a guess.
	addPlan := func(axis string, modelID uint16, rank int, run func() (PlanOutcome, error)) {
		steps = append(steps, applyStep{axis: axis, model: modelID, rank: rank,
			run: func() (*PlanOutcome, error) {
				o, err := run()
				return &o, err
			}})
	}
	// addCombined / addCombinedPlan register the single step a min-combined
	// ceiling reduces to, named after the BINDING axis and carrying the other
	// present axes as an advisory.
	addCombined := func(bind ceilingBind, modelID uint16, rank int, run func() error) {
		add(bind.axis, modelID, rank, run)
		steps[len(steps)-1].advisory = bind.advisory()
	}
	addCombinedPlan := func(bind ceilingBind, modelID uint16, rank int, run func() (PlanOutcome, error)) {
		addPlan(bind.axis, modelID, rank, run)
		steps[len(steps)-1].advisory = bind.advisory()
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
		// Model presence only: 702 CtrlModes has no enter-service bit, so
		// there is no positive claim a device could make (capability.go).
		if !b.Has703 {
			return nil, &UnsupportedControlError{Axis: "opModEnergize", Reason: "device has no M703 (DEREnterService)"}
		}
		energize := *ctrl.OpModEnergize
		add("opModEnergize", sunspec.ModelDEREnterService, releaseRank(energize), func() error {
			return b.SetEnterServiceEnabled(energize, tag)
		})
	}
	if ctrl.OpModConnect != nil {
		// Model presence only, for the same reason as opModEnergize: CtrlModes
		// has no connect bit. This is the legacy allowlist's connect half —
		// available to a legacy device with no 702 to claim anything with, and
		// equally available to a modern one, because there is no claim to make.
		if !b.Reader.HasModel(sunspec.ModelImmediateCtrl) {
			return nil, &UnsupportedControlError{Axis: "opModConnect", Reason: "device has no M123 (immediate controls)"}
		}
		connect := *ctrl.OpModConnect
		addPlan("opModConnect", sunspec.ModelImmediateCtrl, releaseRank(connect), func() (PlanOutcome, error) {
			return b.SetConnectPlan(connect, tag)
		})
	}
	if ctrl.OpModFixedPFInjectW != nil {
		if !b.Has704 {
			return nil, &UnsupportedControlError{Axis: "opModFixedPFInjectW", Reason: "device has no M704 (DERCtlAC)"}
		}
		if err := b.requireCtrlModes("opModFixedPFInjectW", modeFixedPF); err != nil {
			return nil, err
		}
		pf := math.Abs(float64(ctrl.OpModFixedPFInjectW.Value)) / 10000.0
		if err := b.validatePF(pf, "opModFixedPFInjectW"); err != nil {
			return nil, err
		}
		over := ctrl.OpModFixedPFInjectW.Value >= 0
		add("opModFixedPFInjectW", sunspec.ModelDERCtlAC, rankLimit, func() error { return b.SetFixedPF(true, pf, over, tag) })
	}
	if ctrl.OpModFixedPFAbsorbW != nil {
		if !b.Has704 {
			return nil, &UnsupportedControlError{Axis: "opModFixedPFAbsorbW", Reason: "device has no M704 (DERCtlAC)"}
		}
		if err := b.requireCtrlModes("opModFixedPFAbsorbW", modeFixedPF); err != nil {
			return nil, err
		}
		pf := math.Abs(float64(ctrl.OpModFixedPFAbsorbW.Value)) / 10000.0
		if err := b.validatePF(pf, "opModFixedPFAbsorbW"); err != nil {
			return nil, err
		}
		over := ctrl.OpModFixedPFAbsorbW.Value >= 0
		add("opModFixedPFAbsorbW", sunspec.ModelDERCtlAC, rankLimit, func() error { return b.SetFixedPF(false, pf, over, tag) })
	}
	if ctrl.OpModFixedVar != nil {
		if !b.Has704 {
			return nil, &UnsupportedControlError{Axis: "opModFixedVar", Reason: "device has no M704 (DERCtlAC)"}
		}
		if err := b.requireCtrlModes("opModFixedVar", modeFixedVar); err != nil {
			return nil, err
		}
		pct := float64(ctrl.OpModFixedVar.Value.Value) / 100.0
		if math.IsNaN(pct) || pct < -100 || pct > 100 {
			return nil, &InvalidControlError{Axis: "opModFixedVar",
				Reason: fmt.Sprintf("reactive setpoint %.2f%% outside [-100,100]", pct)}
		}
		// The percentage's BASE, named by the document's own refType. Resolving
		// it HERE, not in the writer, keeps a refType this device cannot express
		// a whole-request rejection with zero writes (varsetmod.go).
		mod, _, err := varSetModForRefType("opModFixedVar", ctrl.OpModFixedVar.RefType)
		if err != nil {
			return nil, err
		}
		if err := b.requireVarBase("opModFixedVar", mod, pct); err != nil {
			return nil, err
		}
		// The base RESOLVES the percentage; it does not make the result a
		// quantity the machine can produce. %setMaxW takes its percentage of
		// the ACTIVE nameplate and the result is REACTIVE power, so that second
		// question is asked separately — and asked HERE, so a var quantity
		// beyond the reactive rating is a whole-document rejection with zero
		// writes (LXR-002) rather than a mid-document failure.
		if err := b.checkVarWithinReactiveCapability("opModFixedVar", mod, pct); err != nil {
			return nil, err
		}
		// IW13-003 §1.3 item 2: addPlan (not add) whenever a VarRmp payload is
		// actually in play, so a dropped ramp becomes a measured Sub element
		// instead of the bare-error path's silence. Registration STAYS add()
		// when no ramp was requested — byte-identical to today for the common
		// case (TestSetActivePowerWatts_NoWRmpPayload_RejectingDeviceStillErrors's
		// VarSet analogue: nothing to isolate, nothing to report).
		if b.DefaultVarRmpPct != nil {
			addPlan("opModFixedVar", sunspec.ModelDERCtlAC, rankLimit, func() (PlanOutcome, error) {
				return b.SetConstantVarPlan(pct, mod, tag)
			})
		} else {
			add("opModFixedVar", sunspec.ModelDERCtlAC, rankLimit, func() error { return b.SetConstantVar(pct, mod, tag) })
		}
	}
	if ctrl.OpModFixedW != nil {
		if !b.Has704 {
			return nil, &UnsupportedControlError{Axis: "opModFixedW", Reason: "device has no M704 (DERCtlAC)"}
		}
		if err := b.requireCtrlModes("opModFixedW", modeFixedW); err != nil {
			return nil, err
		}
		// IW13-001: opModFixedW is SignedPerCent, not ActivePower. Decode the
		// percent, then resolve it against this device's own reference
		// (§2.1 — WDisChaRteMaxRtg/WChaRteMaxRtg when declared, else WMax
		// symmetrically) BEFORE the existing watts-domain checks, which are
		// unchanged from here on.
		pct, err := pctChecked(ctrl.OpModFixedW.Value, "opModFixedW", true)
		if err != nil {
			return nil, err
		}
		ref, ok, err := b.fixedWReference(ctrl.OpModFixedW.Value < 0)
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, &UnsupportedControlError{Axis: "opModFixedW", Reason: "cannot set percent-of-nameplate control: WMax unknown"}
		}
		w := pct / 100.0 * ref
		if err := b.validateSetpointW(w, "opModFixedW"); err != nil {
			return nil, err
		}
		// IW13-003 §1.3 item 2: see the opModFixedVar registration above for
		// the identical addPlan/add split and reasoning.
		if b.DefaultWRmpPct != nil {
			addPlan("opModFixedW", sunspec.ModelDERCtlAC, rankLimit, func() (PlanOutcome, error) {
				return b.SetActivePowerWattsPlan(w, tag)
			})
		} else {
			add("opModFixedW", sunspec.ModelDERCtlAC, rankLimit, func() error { return b.SetActivePowerWatts(w, tag) })
		}
	}

	// Ceilings → WMaxLimPct (% of WMax). Simultaneous ceilings MIN-COMBINE.
	if bind, ok, err := b.combineCeilingsW(ctrl, tag); err != nil {
		return nil, err
	} else if ok {
		w := bind.watts
		// Both branches convert watts through the nameplate, so an unknown
		// WMax is a preflight rejection, not a failure discovered after the
		// other axes have been written.
		if err := b.requireWmax(tag); err != nil {
			return nil, err
		}
		switch {
		case b.Has704:
			if err := b.requireCtrlModes(bind.axis, modeMaxW); err != nil {
				return nil, err
			}
			// IW13-003 §1.3 item 2: same addPlan/add split as opModFixedW/
			// opModFixedVar above, via the combined-ceiling registrar so the
			// min-combine advisory is still seeded on the step either way.
			if b.DefaultWRmpPct != nil {
				addCombinedPlan(bind, sunspec.ModelDERCtlAC, rankLimit, func() (PlanOutcome, error) {
					return b.SetWMaxLimPctWPlan(w, tag)
				})
			} else {
				addCombined(bind, sunspec.ModelDERCtlAC, rankLimit, func() error { return b.SetWMaxLimPctW(w, tag) })
			}
		case b.Reader.HasModel(sunspec.ModelImmediateCtrl):
			// LEGACY ALLOWLIST (capability.go): the M123 ceiling needs no 702
			// claim on a device measured to have no 7xx control surface. A
			// device that DOES publish 702 has reached here without a 704, so
			// it can make a MAX_W claim and must — the allowlist covers
			// devices that cannot claim, not devices that did not bother.
			if !b.LegacyM123Shape() {
				if err := b.requireCtrlModes(bind.axis, modeMaxW); err != nil {
					return nil, err
				}
			}
			addCombinedPlan(bind, sunspec.ModelImmediateCtrl, rankLimit, func() (PlanOutcome, error) {
				return b.SetLegacyWMaxLimPctPlan(w, tag)
			})
		default:
			return nil, &UnsupportedControlError{Axis: bind.axis, Reason: "device has neither M704 nor M123 for power limiting"}
		}
	}

	// Import / load (charge) ceilings: REFUSED on every device shape.
	// importBoundUnsupported states the register survey; nothing is written.
	if axis, imp := firstNonNilAxis(
		axisAP{"opModImpLimW", ctrl.OpModImpLimW},
		axisAP{"opModLoadLimW", ctrl.OpModLoadLimW}); imp != nil {
		// Validate the request anyway, so a document that is BOTH malformed and
		// unsupported is reported as malformed — the head end can fix that one.
		w, err := wattsChecked(imp, axis)
		if err != nil {
			return nil, err
		}
		if w < 0 {
			return nil, &InvalidControlError{Axis: axis, Reason: fmt.Sprintf("negative import limit %g W", w)}
		}
		return nil, importBoundUnsupported(ctrl)
	}
	return steps, nil
}

// preflightActuationWatts is ApplyActuationWatts's step-builder — the watts-
// native sibling of preflightControl, restricted to the three axes the
// southbound reconcile shells actually drive (Connect, FixedW, MaxLimW). It
// performs the SAME preflight checks preflightControl performs for these
// axes (capability gating, CtrlModes, nameplate/rating bounds via
// validateSetpointW/requireWmax), only with no percent/ActivePower decode
// anywhere: fixedW/maxLimW arrive already resolved to watts.
func (b *Base) preflightActuationWatts(fixedW, maxLimW *float64, connect *bool, tag string) ([]applyStep, error) {
	var steps []applyStep
	add := func(axis string, modelID uint16, rank int, run func() error) {
		steps = append(steps, applyStep{axis: axis, model: modelID, rank: rank,
			run: func() (*PlanOutcome, error) { return nil, run() }})
	}
	addPlan := func(axis string, modelID uint16, rank int, run func() (PlanOutcome, error)) {
		steps = append(steps, applyStep{axis: axis, model: modelID, rank: rank,
			run: func() (*PlanOutcome, error) {
				o, err := run()
				return &o, err
			}})
	}
	releaseRank := func(releasing bool) int {
		if releasing {
			return rankRelease
		}
		return rankRestrict
	}

	if connect != nil {
		if !b.Reader.HasModel(sunspec.ModelImmediateCtrl) {
			return nil, &UnsupportedControlError{Axis: "opModConnect", Reason: "device has no M123 (immediate controls)"}
		}
		c := *connect
		addPlan("opModConnect", sunspec.ModelImmediateCtrl, releaseRank(c), func() (PlanOutcome, error) {
			return b.SetConnectPlan(c, tag)
		})
	}
	if fixedW != nil {
		if !b.Has704 {
			return nil, &UnsupportedControlError{Axis: "opModFixedW", Reason: "device has no M704 (DERCtlAC)"}
		}
		if err := b.requireCtrlModes("opModFixedW", modeFixedW); err != nil {
			return nil, err
		}
		w := *fixedW
		if math.IsNaN(w) || math.IsInf(w, 0) {
			return nil, &InvalidControlError{Axis: "opModFixedW", Reason: "non-finite watt setpoint"}
		}
		if err := b.validateSetpointW(w, "opModFixedW"); err != nil {
			return nil, err
		}
		// IW13-003 §1.3 item 2: addPlan/add split, identical reasoning to
		// preflightControl's opModFixedW registration.
		if b.DefaultWRmpPct != nil {
			addPlan("opModFixedW", sunspec.ModelDERCtlAC, rankLimit, func() (PlanOutcome, error) {
				return b.SetActivePowerWattsPlan(w, tag)
			})
		} else {
			add("opModFixedW", sunspec.ModelDERCtlAC, rankLimit, func() error { return b.SetActivePowerWatts(w, tag) })
		}
	}
	if maxLimW != nil {
		w := *maxLimW
		if math.IsNaN(w) || math.IsInf(w, 0) {
			return nil, &InvalidControlError{Axis: "opModMaxLimW", Reason: "non-finite watt ceiling"}
		}
		if w < 0 {
			return nil, &InvalidControlError{Axis: "opModMaxLimW", Reason: fmt.Sprintf("negative ceiling %g W", w)}
		}
		// Both branches convert watts through the nameplate, so an unknown
		// WMax is a preflight rejection, not a failure discovered after the
		// other axes have been written — mirrors preflightControl's identical
		// combined-ceiling check.
		if err := b.requireWmax(tag); err != nil {
			return nil, err
		}
		switch {
		case b.Has704:
			if err := b.requireCtrlModes("opModMaxLimW", modeMaxW); err != nil {
				return nil, err
			}
			// IW13-003 §1.3 item 2: addPlan/add split, identical reasoning to
			// preflightControl's combined-ceiling registration.
			if b.DefaultWRmpPct != nil {
				addPlan("opModMaxLimW", sunspec.ModelDERCtlAC, rankLimit, func() (PlanOutcome, error) {
					return b.SetWMaxLimPctWPlan(w, tag)
				})
			} else {
				add("opModMaxLimW", sunspec.ModelDERCtlAC, rankLimit, func() error { return b.SetWMaxLimPctW(w, tag) })
			}
		case b.Reader.HasModel(sunspec.ModelImmediateCtrl):
			// LEGACY ALLOWLIST (capability.go) — same reasoning as
			// preflightControl's identical branch.
			if !b.LegacyM123Shape() {
				if err := b.requireCtrlModes("opModMaxLimW", modeMaxW); err != nil {
					return nil, err
				}
			}
			addPlan("opModMaxLimW", sunspec.ModelImmediateCtrl, rankLimit, func() (PlanOutcome, error) {
				return b.SetLegacyWMaxLimPctPlan(w, tag)
			})
		default:
			return nil, &UnsupportedControlError{Axis: "opModMaxLimW", Reason: "device has neither M704 nor M123 for power limiting"}
		}
	}
	return steps, nil
}

// importBoundUnsupported is the typed refusal for opModImpLimW / opModLoadLimW
// (DERBASE-IMPORT-AS-SETPOINT). It names every import axis the document
// carried, because a head end that sent two is owed the truth about both.
//
// ── The register survey behind this refusal ──────────────────────────
//
// The pre-fix code routed both axes to SetActivePowerWatts(-w), which writes
// 704 WSetEna=1, WSetMod=Watts, WSet=−w. WSet means PRODUCE THIS; the document
// said DO NOT IMPORT MORE THAN THIS. On an idle 60 kW machine,
// opModImpLimW{5 kW} therefore COMMANDED a 5 kW import from a DER under no
// obligation to move any active power (DIFF-CTL-020) — the only defect in the
// differential run that makes an idle DER move real power it was never told to
// move. And because opModFixedW lands in the same register at the same rank, a
// document carrying both had the import axis silently overwrite the discharge
// setpoint, with no error and no outcome element saying so (DIFF-CTL-030).
//
// Every register in the models this package speaks was surveyed for one that
// expresses an import BOUND, and there is none:
//
//	M704 WSet / WSetPct     signed SETPOINTS ("produce this"), not bounds. This
//	                        is the defect, not the fix.
//	M704 WMaxLimPct         a bound, but a uint16 percent of WMax on the OUTPUT
//	                        side. 704 defines no charge-side counterpart and no
//	                        sign for this point.
//	M702 WChaRteMax         RW, and it does mean "maximum rate of energy
//	                        transfer INTO the device" — but it is a SETTING in
//	                        the nameplate model, not a control: CtrlModes has no
//	                        bit for it (so deny-by-default has nothing to gate
//	                        on), it has no reversion timer (so a time-bound CSIP
//	                        event would derate the device permanently), and it
//	                        is the very point the device's advertised charge
//	                        capability is read from, so writing it would edit
//	                        the capability we report northbound.
//	M123 WMaxLimPct         a uint16 percent-of-WMax EXPORT ceiling. The
//	                        pre-fix legacy branch wrote a NEGATIVE percentage
//	                        into it, which is outside the point's declared type
//	                        — a bench-sim convention, not a device standard.
//	M802 WChaRteMax         same objection as M702's: a battery-detail setting,
//	                        outside the 1547 control surface entirely.
//
// So the axis is unsupported on every device shape this package can address,
// and the honest consequence is that it refuses EVERYWHERE. That is the
// correct outcome: the gateway's receipt screen renders a CannotComply, the
// head end learns the bound is not in force, and no DER is commanded to import
// power in the name of a limit. The day a device declares a real import-limit
// CONTROL — a capability bit plus a dedicated bounded register — this is where
// that branch goes, with read-back like every other bound.
func importBoundUnsupported(ctrl model.DERControlBase) error {
	axes := ""
	for _, p := range []axisAP{
		{"opModImpLimW", ctrl.OpModImpLimW},
		{"opModLoadLimW", ctrl.OpModLoadLimW},
	} {
		if p.ap == nil {
			continue
		}
		if axes != "" {
			axes += "+"
		}
		axes += p.axis
	}
	return &UnsupportedControlError{Axis: axes, Reason: "no register in models 702/704/123 " +
		"expresses an import/charge BOUND: WSet is a setpoint (commanding it would make an idle " +
		"DER import power it was never told to move), WMaxLimPct is an export-side ceiling, and " +
		"M702 WChaRteMax is an un-reverting nameplate setting with no CtrlModes bit — so the " +
		"bound cannot be expressed on this device and is refused rather than misexecuted"}
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

// fixedWReference resolves the watts base opModFixedW's SignedPerCent
// applies against (IW13-001; docs/design/IW13_ACTIVE_POWER_UNITS_2026-08-12.md
// §2.1): positive (discharge/export) prefers this device's own declared
// WDisChaRteMaxRtg; negative (charge) prefers WChaRteMaxRtg. Both directions
// fall back to WMax symmetrically when the device declares no distinct
// charge/discharge rating — the same Phase-1 judgment call the design
// documents for the gateway's own per-device fan-out (csipin.go), available
// here immediately rather than deferred, because b.Cap already reads these
// 702 points at Init (unlike the gateway's InventoryRecord today).
//
// An implemented-but-out-of-domain or implemented-zero rating (maxRatingBound
// error) is a positive claim about the device and is propagated rather than
// silently overridden by falling back to WMax — the same "claim is garbage,
// DENY" / "zero means incapacity" rule capability.go already states for
// every other rating bound in this file.
func (b *Base) fixedWReference(negative bool) (float64, bool, error) {
	point, v := "WDisChaRteMaxRtg", b.Cap.WDisChaRteMaxRtg
	if negative {
		point, v = "WChaRteMaxRtg", b.Cap.WChaRteMaxRtg
	}
	if r, ok, err := maxRatingBound("opModFixedW", point, v); err != nil {
		return 0, false, err
	} else if ok {
		return r, true, nil
	}
	if !math.IsNaN(b.Wmax) && b.Wmax > 0 {
		return b.Wmax, true, nil
	}
	return 0, false, nil
}

// validatePF rejects a power-factor request outside the physically meaningful
// [0,1] domain, or below the device's own declared minimum rated PF (702
// PFOvrExtRtg/PFUndExtRtg) when the device implements those ratings.
//
// The rated-PF guard used to read `minRated > 0 && minRated <= 1`, which
// silently DROPPED the bound for every implemented rating outside that
// window — a device declaring a rated PF of 1.5, or of 0, had its own claim
// discarded and got commanded to any PF at all. An implemented claim that
// cannot be true is not a bound to relax; see ratingBound in capability.go.
func (b *Base) validatePF(pf float64, axis string) error {
	if math.IsNaN(pf) || pf < 0 || pf > 1 {
		return &InvalidControlError{Axis: axis, Reason: fmt.Sprintf("power factor %g outside [0,1]", pf)}
	}
	if b.HasCap {
		// The rated PF is the MINIMUM the device supports (e.g. 0.85); a
		// request below it is outside declared capability (LXR-005).
		minRated, point := math.NaN(), ""
		switch axis {
		case "opModFixedPFInjectW":
			minRated, point = b.Cap.PFOvrExtRtg, "PFOvrExtRtg"
		case "opModFixedPFAbsorbW":
			minRated, point = b.Cap.PFUndExtRtg, "PFUndExtRtg"
		}
		if point != "" {
			bound, ok, err := minRatingBound(axis, point, minRated, 1)
			if err != nil {
				return err
			}
			if ok && pf < bound {
				return &UnsupportedControlError{Axis: axis,
					Reason: fmt.Sprintf("requested PF %.4f below device rated minimum %.4f", pf, bound)}
			}
		}
	}
	return nil
}

// validateSetpointW rejects an active-power setpoint the device cannot hold:
// outside the NAMEPLATE, or outside the device's declared charge/discharge rate
// ratings when those ratings are implemented (LXR-005: charge/discharge
// capability bounds were previously unenforced).
//
// Ratings the device leaves unimplemented (NaN) impose no bound here — that is
// honest unknown, and it is no longer load-bearing, because the axis needed a
// positive CtrlModes bit to reach this function at all. What DID change under
// LXR-005: the old `r > 0` guard silently dropped the bound for an implemented
// rating of 0 (or any other out-of-domain value), so a device declaring "my
// maximum charge rate is 0 W" was commanded to charge anyway. An implemented
// rating of zero is a positive declaration of incapacity, not an absence — see
// ratingBound.
//
// The NAMEPLATE bound is checked here as well as in SetActivePowerWatts, and
// that duplication is the point (DERBASE-SILENT-CLAMP): checking it only in the
// writer would make a 200 kW setpoint on a 60 kW machine a mid-document
// failure, after the document's earlier axes had already been written. Checked
// here it is a whole-request rejection with zero writes, which is the LXR-002
// precedent — a request that cannot be executed in full is not executed in
// part. The two checks share checkSetpointWithinNameplate so they cannot drift.
func (b *Base) validateSetpointW(w float64, axis string) error {
	if err := b.checkSetpointWithinNameplate(axis, w); err != nil {
		return err
	}
	if !b.HasCap {
		return nil
	}
	if w < 0 { // charge
		r, ok, err := maxRatingBound(axis, "WChaRteMaxRtg", b.Cap.WChaRteMaxRtg)
		if err != nil {
			return err
		}
		if ok && -w > r {
			return &UnsupportedControlError{Axis: axis,
				Reason: fmt.Sprintf("charge setpoint %g W exceeds rated max charge rate %g W", -w, r)}
		}
	} else if w > 0 { // discharge/export
		r, ok, err := maxRatingBound(axis, "WDisChaRteMaxRtg", b.Cap.WDisChaRteMaxRtg)
		if err != nil {
			return err
		}
		if ok && w > r {
			return &UnsupportedControlError{Axis: axis,
				Reason: fmt.Sprintf("discharge setpoint %g W exceeds rated max discharge rate %g W", w, r)}
		}
	}
	return nil
}

// ceilingBind is the single active-power ceiling a document's ceiling axes
// reduce to: the binding magnitude in watts, the axis that bound, and every
// axis that was combined to get there.
type ceilingBind struct {
	axis    string   // the axis whose bound is narrowest — what errors are attributed to
	watts   float64  // that bound, in watts
	present []string // every ceiling axis the document carried, in canonical order
}

// advisory renders the combine for the step's ElementOutcome, or "" when only
// one ceiling was present and there was nothing to combine.
func (c ceilingBind) advisory() string {
	if len(c.present) < 2 {
		return ""
	}
	return fmt.Sprintf("ceiling min-combined over %s; %s binds at %g W",
		strings.Join(c.present, ", "), c.axis, c.watts)
}

// combineCeilingsW reduces the simultaneously-present active-power ceiling axes
// to the NARROWEST bound (DERBASE-CEILING-PREFERENCE).
//
// ── What was wrong ───────────────────────────────────────────────────────────
//
// preflightControl reduced the three axes with firstNonNilAxis(Exp, Max, Gen) —
// a fixed PREFERENCE order, not a minimum. Limits are conjunctive: each one
// must hold, so the binding ceiling is the narrowest, and picking by name
// drops the others. {opModMaxLimW=5 kW, opModExpLimW=30 kW} on a 60 kW device
// programmed WMaxLimPct=50 % and left the utility's 5 kW ceiling NOWHERE on the
// device (DIFF-CTL-010), while the head end was told the control was applied —
// a curtailment instruction silently not in force. It survived three
// simultaneous ceilings: {Max=20 kW, Exp=40 kW, Gen=2 kW} held 40 kW against a
// 2 kW ask (DIFF-CTL-012).
//
// ── The rule ─────────────────────────────────────────────────────────────────
//
// Combine in WATTS, then express. The axes are CSIP ActivePower values, each
// carrying its OWN power-of-ten multiplier, so {value=5, multiplier=3} and
// {value=30000, multiplier=0} are not comparable until both are watts — and
// they are converted through the same checked conversion, so a hostile
// multiplier on ANY present axis rejects the document rather than being
// skipped because a different axis won the preference order. This mirrors the
// authority-side min-combine (lexa-gw 6ad0d59) one layer down: the gateway
// min-combines competing programs' ceilings, and the device layer must not
// then throw the narrowest away.
//
// Ties keep the canonical Exp→Max→Gen order, so equal bounds are attributed
// deterministically. ok=false means the document carried no ceiling axis.
//
// opModMaxLimW is PerCent, not ActivePower (IW13-001) — it is converted to
// watts against THIS device's own WMax before entering the same min-combine
// as opModExpLimW/opModGenLimW, which remain genuine ActivePower/watts axes
// and are unaffected (§1.2). This is now a method (was a free function) only
// because the MaxLimW conversion needs b.Wmax/b.requireWmax to do that
// conversion honestly — refusing the document, not guessing, when WMax is
// unknown — rather than being silently dropped from the combine.
func (b *Base) combineCeilingsW(ctrl model.DERControlBase, tag string) (ceilingBind, bool, error) {
	var out ceilingBind
	consider := func(axis string, w float64) error {
		if w < 0 {
			return &InvalidControlError{Axis: axis, Reason: fmt.Sprintf("negative ceiling %g W", w)}
		}
		out.present = append(out.present, axis)
		if out.axis == "" || w < out.watts {
			out.axis, out.watts = axis, w
		}
		return nil
	}
	// EVERY present axis is validated, not just the one that binds: an
	// unvalidated axis is a limit nobody checked, and it is the one that
	// would bind the day the numbers change.
	if ctrl.OpModExpLimW != nil {
		w, err := wattsChecked(ctrl.OpModExpLimW, "opModExpLimW")
		if err != nil {
			return ceilingBind{}, false, err
		}
		if err := consider("opModExpLimW", w); err != nil {
			return ceilingBind{}, false, err
		}
	}
	if ctrl.OpModMaxLimW != nil {
		pct, err := pctChecked(ctrl.OpModMaxLimW.Value, "opModMaxLimW", false)
		if err != nil {
			return ceilingBind{}, false, err
		}
		// Resolved eagerly, here, rather than deferred to the caller's later
		// requireWmax(tag) check: a deferred check would let an unconverted
		// MaxLimW silently fall out of the min-combine (out.axis staying ""
		// while out.present still names it) if it happened to be the only
		// ceiling axis present — exactly the silent-drop this design exists
		// to eliminate.
		if err := b.requireWmax(tag); err != nil {
			return ceilingBind{}, false, err
		}
		w := pct / 100.0 * b.Wmax
		if err := consider("opModMaxLimW", w); err != nil {
			return ceilingBind{}, false, err
		}
	}
	if ctrl.OpModGenLimW != nil {
		w, err := wattsChecked(ctrl.OpModGenLimW, "opModGenLimW")
		if err != nil {
			return ceilingBind{}, false, err
		}
		if err := consider("opModGenLimW", w); err != nil {
			return ceilingBind{}, false, err
		}
	}
	return out, out.axis != "", nil
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
		return &CorruptReadError{Tag: tag, Model: sunspec.ModelDEREnterService,
			Detail: "read block is sentinel-corrupt (partial/failed read)"}
	}
	if err := sunspec.Encode703(regs, s); err != nil {
		return err
	}
	return b.Reader.WriteModel(sunspec.ModelDEREnterService, 0, regs[:sunspec.L703.Len()])
}

// SetEnterServiceEnabled toggles only the ES permit-service / cease-to-energize bit.
//
// Gated on model presence, not on a CtrlModes bit: 702's bitfield defines no
// enter-service mode, so gating on a claim the spec gives a device no way to
// make would be denial by construction (capability.go). Model presence IS the
// positive measured signal here — and it is checked, which the pre-fix code
// did not do on this path even though preflightControl did.
func (b *Base) SetEnterServiceEnabled(energize bool, tag string) error {
	if !b.Has703 {
		return &UnsupportedControlError{Axis: "SetEnterServiceEnabled",
			Reason: "device has no M703 (DEREnterService)"}
	}
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
//
// It is deny-by-default on capability (audit finding 4), for the same reason it
// re-checks the block length: preflightControl already gates every 7xx axis on
// a positive 702 claim, but write704 is reachable directly through the exported
// setters (SetFixedPF, SetConstantVar, SetActivePowerWatts, SetWMaxLimPctW),
// and a 7xx control register must not be written on a device that never told us
// it does 7xx controls.
//
// modes is the UNION of CtrlModes bits for the control functions whose fields
// fn writes, and EVERY one of them must be positively claimed (round-2 audit
// F2). The pre-fix gate was claim-LEVEL — "does the device publish a CtrlModes
// declaration at all" — on the argument that this function does not know which
// axis it is serving. It does now, because its callers pass it: a device
// declaring MAX_W and nothing else used to accept a fixed-PF write through
// SetFixedPF, which is the deny-by-default rule holding in ApplyControl and
// nowhere else. The claim-level check is subsumed — CapAbsent and
// CapNotImplemented both fail the per-bit test with their own reason strings.
func (b *Base) write704(tag string, axis string, modes []ctrlMode, fn func(v sunspec.View)) error {
	_, err := b.write704Rmp(tag, axis, modes, fn, nil)
	return err
}

// write704Rmp is write704 plus an OPTIONAL second closure, rmpFn, that applies
// ONLY the §3.2 WRmp/VarRmp standing-rate write (writeWRmp/writeVarRmp) on top
// of whatever fn already set. Every 704 caller that has no ramp-rate write of
// its own (SetFixedPF — 704 has no PF ramp register at all) goes through
// write704's nil-rmpFn form and is byte-identical to before this split
// existed; SetActivePowerWatts/SetWMaxLimPctW/SetConstantVar pass a non-nil
// rmpFn (Defect 2, 2026-08 adversarial review).
//
// The split exists because 704 has no CtrlModes capability bit for WRmp/
// VarRmp at all (§1.2 Gap E: zero executor, hence zero capability signal,
// anywhere in this codebase before this design) — write704 cannot know
// BEFORE attempting the write whether a device honors the register, the way
// requireCtrlModes lets it refuse a PF/var/W axis it already knows is
// unclaimed. A validating DER firmware that rejects an unimplemented (or,
// pre-clamp, out-of-range — see resolveRampWPct's own fix) WRmp value NAKs
// the WHOLE FC16 block this write bundles it into, which would otherwise take
// the commanded SETPOINT down with it — an emergency-cut silently dropped
// because of a disagreement over a DIFFERENT register entirely. That is
// unacceptable: a real setpoint the caller commanded must never become
// collateral damage of a ramp-rate policy write's rejection.
//
// On a first-attempt failure, WHEN rmpFn was supplied, this retries EXACTLY
// ONCE against a FRESH read (never the stale, already-mutated regs — the
// first WriteModel's actual effect on the device is unknown, so re-reading
// is the same LXR-003/E2 caution this function already applies to its
// primary read) with a NARROWER write that STRUCTURALLY EXCLUDES the WRmp/
// WRmpRef/VarRmp register range (wrmpSpan below) rather than merely
// re-sending the same whole-block range with those three registers reset to
// their read-back values. That distinction matters: a real Modbus FC16
// request is accepted or refused as one indivisible unit by ADDRESS RANGE —
// a device that refuses to accept ANY write touching an unimplemented
// register rejects the whole request regardless of what value that register
// carries in it, so a retry that still ADDRESSES WRmp (even with an
// unchanged value) would fail identically. Only a write whose address range
// never mentions WRmp/WRmpRef/VarRmp at all can succeed on such a device.
// fn never writes into that range (SetActivePowerWatts/SetWMaxLimPctW/
// SetConstantVar's own closures only touch fields the layout places BEFORE
// it — verified by the layout's own field order in sunspec/derlayout.go's
// L704), so the exclusion loses no content fn cares about; it only forgoes
// re-sending the (unchanged-either-way) AntiIslEna/scale-factor/PF-sync-group
// tail this write cycle, which is a plain round-trip of already-current
// device state, not new commanded content — the very next 704 write (the
// following poll/reconcile cycle) sends the whole block again regardless.
//
// If the narrowed retry succeeds, the setpoint is confirmed landed and this
// reports success, PLUS isolated=true (IW13-003): the caller's own ramp
// payload never reached the device, and — unlike before this finding was
// closed — that is now a fact this function hands back rather than a silence
// the caller cannot distinguish from "no ramp was ever requested." WRmp/
// VarRmp simply keep whatever value the device already held (no different
// from an ordinary write cycle where the caller supplied no ramp — §3.2's own
// "re-derived fresh on every write" discipline means the very next write
// cycle tries the ramp-rate write again). If even the narrowed retry fails,
// the ORIGINAL error is returned — a device/comms problem unrelated to WRmp,
// which excluding WRmp correctly does nothing to fix.
//
// isolated is meaningful ONLY when err == nil; it is always false on any
// error return (including when rmpFn was nil to begin with — there was
// nothing to isolate). SetActivePowerWatts/SetWMaxLimPctW/SetConstantVar's
// own Plan-returning engines (SetActivePowerWattsPlan et al.) are what turn
// isolated==true into a measured PlanOutcome element instead of the bare
// `return nil` this function used to produce (IW13-003 §1.3) — this function
// itself still never fails a write that a WRmp/VarRmp rejection alone would
// not have failed, which remains the load-bearing fail-safe property (§1.4).
func (b *Base) write704Rmp(tag, axis string, modes []ctrlMode, fn func(v sunspec.View), rmpFn func(v sunspec.View)) (isolated bool, err error) {
	if !b.Has704 {
		return false, &UnsupportedControlError{Axis: axis, Reason: "device has no M704 (DERCtlAC)"}
	}
	if err := b.requireCtrlModes(axis, modes...); err != nil {
		return false, err
	}
	regs, err := b.read704Checked(tag)
	if err != nil {
		return false, err
	}
	v := sunspec.L704.View(regs)
	fn(v)
	if rmpFn != nil {
		rmpFn(v)
	}
	writeErr := b.Reader.WriteModel(sunspec.ModelDERCtlAC, 0, regs[:sunspec.L704.Len()])
	if writeErr == nil || rmpFn == nil {
		return false, writeErr
	}
	// Isolate: fresh read, fn only (no rmpFn), written NARROWLY so the WRmp/
	// WRmpRef/VarRmp address range is never part of this request at all.
	regs2, rerr := b.read704Checked(tag)
	if rerr != nil {
		return false, writeErr // cannot safely isolate — report the ORIGINAL failure
	}
	fn(sunspec.L704.View(regs2))
	wrmpOffset := sunspec.L704.Offset("WRmp")
	if wrmpOffset < 0 || wrmpOffset > sunspec.L704.Len() {
		return false, writeErr // layout invariant broken — no safe narrower range to isolate
	}
	if err2 := b.Reader.WriteModel(sunspec.ModelDERCtlAC, 0, regs2[:wrmpOffset]); err2 != nil {
		return false, writeErr // still fails without touching WRmp's address range at all: not a WRmp problem
	}
	return true, nil
}

// read704Checked reads the 704 block and applies write704Rmp's two read-side
// guards (LXR-003 short-block defense, audit E2 corrupt-read refusal) —
// factored out so write704Rmp's isolating retry runs the IDENTICAL checks
// against its fresh read that the primary attempt ran against its own.
func (b *Base) read704Checked(tag string) ([]uint16, error) {
	regs, err := b.Reader.ReadModel(sunspec.ModelDERCtlAC)
	if err != nil {
		return nil, fmt.Errorf("%s: read M704: %w", tag, err)
	}
	// Defense in depth for LXR-003: Init refuses a device whose declared 704
	// is shorter than the layout, but never trust that invariant across a
	// rescan/replacement — an undersized read here would panic the shared
	// service on the regs[:Len] slice below.
	if len(regs) < sunspec.L704.Len() {
		return nil, &MalformedDeviceError{Tag: tag, Model: sunspec.ModelDERCtlAC,
			Declared: len(regs), Required: sunspec.L704.Len(), Detail: "read returned short block"}
	}
	// Refuse to write back a corrupt read (audit E2): this whole-block
	// read-modify-write would otherwise persist a sentinel-saturated read (a
	// device rebooting mid-poll, or a fault-injected all-0x8000 read) into the
	// inverter's control registers — garbage setpoints and spurious sync-group
	// enables. A healthy 704 always carries valid scale factors (and never an
	// out-of-domain one — LXR-004).
	if sunspec.L704.View(regs).ReadLooksCorrupt() {
		return nil, &CorruptReadError{Tag: tag, Model: sunspec.ModelDERCtlAC,
			Detail: "read block is sentinel-corrupt (partial/failed read)"}
	}
	return regs, nil
}

// rvrtAlternateWriter validates a Default*Rvrt/Default*EnaRvrt pair
// (IW13-004a §2a.3) and returns a closure that writes them into the given
// View's value/enable fields, or an error refusing an unsafe combination.
//
// val/ena are consumed together, not independently:
//
//   - ena == nil: nothing was commanded. The returned closure is a no-op —
//     byte-identical to today, matching DefaultWSetRvrt/DefaultWMaxLimPctRvrt's
//     own "nil leaves the registers untouched" contract.
//   - *ena == true, val == nil: REFUSED. Arming reversion with no destination
//     value would revert the device to whatever the shadow register already
//     holds — the factory default or a stale prior session — which is the
//     exact hazard this finding exists to close (§2a.2's "reversion to a
//     stale, vendor-default or unconstrained condition"). A caller that wants
//     the device to keep reverting to its own unknown resting value should
//     leave ena nil (no opinion), not assert true with nothing behind it.
//   - *ena == true, val != nil: writes both — the ordinary arm-with-a-value case.
//   - *ena == false: writes the disable, and the value alongside it when
//     supplied (harmless: an inert, disabled alternate is never applied —
//     §2a.4's "sits armed and inert" concern only bites when enabled).
func rvrtAlternateWriter(axis, valueField, enaField string, val *float64, ena *bool) (func(v sunspec.View), error) {
	if ena == nil {
		return func(sunspec.View) {}, nil
	}
	if *ena && val == nil {
		return nil, &InvalidControlError{Axis: axis, Reason: fmt.Sprintf(
			"%s=true requires a %s alternate value; arming reversion with no destination would revert "+
				"the device to whatever the shadow register already holds (stale/unwritten) — refused "+
				"rather than silently armed (IW13-004a)", enaField, valueField)}
	}
	return func(v sunspec.View) {
		if val != nil {
			v.SetFloat(valueField, *val)
		}
		v.SetBool(enaField, *ena)
	}, nil
}

// rampNotApplied inspects one axis's Sub PlanOutcome for IW13-003's exact
// trigger shape — a WRmp/VarRmp element State==ElementFailed alongside its
// primary setpoint/ceiling element State==ElementApplied — and returns the
// typed RampNotAppliedError, or nil when that shape is not present (no ramp
// was requested, the ramp landed cleanly, or the primary element itself did
// not land — the last of which is a different, already-reported failure, not
// this one). axis is attached to the error for the caller's own reporting;
// it is NOT read from sub.
func rampNotApplied(axis string, sub PlanOutcome) error {
	rampName := ""
	for _, e := range sub.Elements {
		if e.Name != "WRmp" && e.Name != "VarRmp" {
			continue
		}
		if e.State != ElementFailed {
			return nil // ramp element present but not the dropped shape (or none at all)
		}
		rampName = e.Name
	}
	if rampName == "" {
		return nil
	}
	for _, e := range sub.Elements {
		if e.Name != rampName && e.State == ElementApplied {
			return &RampNotAppliedError{Axis: axis, Sub: sub}
		}
	}
	return nil // ramp dropped AND the primary element did not land — not this axis's story to tell
}

// firstRampNotApplied scans a DOCUMENT-level PlanOutcome's elements (the ones
// runControlSteps builds — Name is the CSIP axis name, e.g. "opModFixedW")
// for the first one whose Sub carries rampNotApplied's trigger shape. Used by
// runControlSteps itself so ApplyControlPlan/ApplyActuationWatts (which share
// that engine) both surface RampNotAppliedError through their existing
// (PlanOutcome, error) return with no changes of their own (§1.3 item 3).
func firstRampNotApplied(out PlanOutcome) error {
	for _, e := range out.Elements {
		if e.Sub == nil {
			continue
		}
		if rerr := rampNotApplied(e.Name, *e.Sub); rerr != nil {
			return rerr
		}
	}
	return nil
}

// SetFixedPF enables constant power factor. inject selects the PFWInj (injecting
// active power) vs PFWAbs (absorbing) sync group; overExcited sets excitation.
//
// Requires the device's positive FIXED_PF claim, on a direct call exactly as
// through ApplyControl (audit F2).
func (b *Base) SetFixedPF(inject bool, pf float64, overExcited bool, tag string) error {
	return b.write704(tag, "SetFixedPF", []ctrlMode{modeFixedPF}, func(v sunspec.View) {
		ext := uint16(sunspec.M704_Ext_OverExcited)
		if !overExcited {
			ext = sunspec.M704_Ext_UnderExcited
		}
		if inject {
			v.SetBool("PFWInjEna", true)
			v.SetFloat("PFWInj_PF", pf) // engineering value = power factor
			v.SetEnum("PFWInj_Ext", ext)
			// §2.4 closes Gap A: the PFWInj write previously ignored
			// DefaultRvrtTms entirely even though cmd/modbus's advanced shell
			// (withRvrtTms) already threaded a value in for this call to drop.
			v.SetU32("PFWInjRvrtTms", b.DefaultRvrtTms)
		} else {
			v.SetBool("PFWAbsEna", true)
			v.SetFloat("PFWAbs_PF", pf)
			v.SetEnum("PFWAbs_Ext", ext)
			v.SetU32("PFWAbsRvrtTms", b.DefaultRvrtTms)
		}
		// 704 has no PF ramp register of any kind (§1.2/§3.4's gap table) — no
		// writeWRmp/writeVarRmp call here, deliberately.
	})
}

// SetConstantVar enables constant reactive power as a percentage (signed:
// + inject) of the base named by mod — a sunspec.M704_VarSetMod_* code.
//
// mod is a PARAMETER, not a constant, because a percentage without its base is
// not a quantity: the pre-fix signature took only pct and wrote
// VarSetMod=VarMaxPct for every CSIP refType, so %setMaxW and %statVarAvail
// commanded the wrong physical quantity (varsetmod.go, DERBASE-VAR-REFTYPE).
// Callers translating a CSIP opModFixedVar get mod from varSetModForRefType;
// callers with a base of their own name it directly.
//
// Only the three codes a CSIP refType can name are accepted. VAMaxPct and Vars
// are refused here rather than passed through: nothing in this package can
// produce them, and accepting an arbitrary enum at an exported boundary is how
// an unvalidated integer becomes a control mode the device never declared.
// Requires the device's positive FIXED_VAR claim and a usable base for mod.
//
// A resolved var quantity beyond the device's declared REACTIVE capability is
// refused with a SetpointRangeError, not written and not clamped
// (checkVarWithinReactiveCapability) — the opModFixedW rule one axis over, and
// the bound is duplicated in preflightControl for the same reason
// validateSetpointW duplicates the watt one: checked only here it would be a
// mid-document failure, checked in both it is a whole-document rejection with
// zero writes. The two callers share one function so they cannot drift.
func (b *Base) SetConstantVar(pct float64, mod uint16, tag string) error {
	out, err := b.SetConstantVarPlan(pct, mod, tag)
	if err != nil {
		return err
	}
	return rampNotApplied("SetConstantVar", out)
}

// SetConstantVarPlan is SetConstantVar's PlanOutcome-returning engine
// (IW13-003 §1.3): the single implementation SetConstantVar (above) and
// preflightControl's addPlan registration (used only when DefaultVarRmpPct is
// actually in play) both call. See SetActivePowerWattsPlan's doc comment for
// the full reasoning shared by all three 704 axis engines — this function's
// own returned error is non-nil ONLY when VarSet itself did not land; a
// dropped VarRmp is reported through the returned PlanOutcome, never through
// this function's error, so an addPlan-driven document does not freeze or
// waste a re-attempt on an already-known deterministic device incapability.
func (b *Base) SetConstantVarPlan(pct float64, mod uint16, tag string) (PlanOutcome, error) {
	out := PlanOutcome{Tag: tag, Plan: "SetConstantVar"}
	switch mod {
	case sunspec.M704_VarSetMod_WMaxPct, sunspec.M704_VarSetMod_VarMaxPct,
		sunspec.M704_VarSetMod_VarAvailPct:
	default:
		return out, &InvalidControlError{Axis: "SetConstantVar", Reason: fmt.Sprintf(
			"VarSetMod=%d is not a percentage base this package commands (want WMaxPct=%d, "+
				"VarMaxPct=%d or VarAvailPct=%d)", mod, sunspec.M704_VarSetMod_WMaxPct,
			sunspec.M704_VarSetMod_VarMaxPct, sunspec.M704_VarSetMod_VarAvailPct)}
	}
	if err := b.requireVarBase("SetConstantVar", mod, pct); err != nil {
		return out, err
	}
	if err := b.checkVarWithinReactiveCapability("SetConstantVar", mod, pct); err != nil {
		return out, err
	}
	// Defect 2: rmpFn is passed ONLY when there is an actual VarRmp value to
	// isolate (b.DefaultVarRmpPct != nil) — NOT unconditionally as
	// b.writeVarRmp (whose OWN nil-check would make it a no-op VALUE-wise but
	// still a non-nil FUNCTION, and write704Rmp keys its isolating retry off
	// rmpFn being non-nil, not off what it would write). Passing it
	// unconditionally was tried and reverted during this fix's development:
	// it made write704Rmp silently retry-and-swallow ANY transient 704 write
	// failure, even ones with no VarRmp in play at all, which corrupted
	// ApplyControlPlan's OWN document-level bounded-re-attempt budget
	// accounting (TestApplyControlPlan_ReAttemptIsBoundedPerDocument
	// started failing — a real regression, not a test-only concern). Nil
	// here is exactly today's behavior: one write, one failure, surfaced
	// immediately — byte-identical for the overwhelming common no-ramp case.
	var rmpFn func(v sunspec.View)
	if b.DefaultVarRmpPct != nil {
		rmpFn = b.writeVarRmp
	}
	isolated, werr := b.write704Rmp(tag, "SetConstantVar", []ctrlMode{modeFixedVar}, func(v sunspec.View) {
		v.SetBool("VarSetEna", true)
		v.SetEnum("VarSetMod", mod)
		v.SetEnum("VarSetPri", sunspec.M704_VarSetPri_Reactive)
		v.SetFloat("VarSetPct", pct)
		// §2.4 closes Gap A (the other half — SetFixedPF above is the first):
		// VarSet previously ignored DefaultRvrtTms entirely.
		v.SetU32("VarSetRvrtTms", b.DefaultRvrtTms)
	}, rmpFn)
	if werr != nil {
		return out, werr
	}
	out.Elements = append(out.Elements, ElementOutcome{Name: "VarSet", Model: sunspec.ModelDERCtlAC, State: ElementApplied})
	if isolated {
		out.Elements = append(out.Elements, ElementOutcome{Name: "VarRmp", Model: sunspec.ModelDERCtlAC,
			State: ElementFailed, Advisory: "ramp rejected by device at the address-range level; " +
				"setpoint applied without the commanded ramp rate"})
	}
	return out, nil
}

// SetActivePowerWatts sets the absolute active-power setpoint in watts (WSet,
// signed: + discharge/export, − charge/import).
//
// A setpoint whose magnitude exceeds the nameplate is REFUSED with a typed
// SetpointRangeError carrying commanded vs achievable — it is NOT clamped
// (DERBASE-SILENT-CLAMP). The pre-fix code clamped to ±WMax and returned nil,
// so 200 kW on a 60 kW machine wrote 60 kW and reported success: the head end
// held a fleet model that was wrong and nothing on either side held the true
// state. See SetpointRangeError for why a ceiling may clamp and a setpoint may
// not, and validateSetpointW for the preflight copy of this bound — which is
// what makes the refusal a whole-document rejection with zero writes rather
// than a failure discovered half-way through a document.
//
// Requires the device's positive FIXED_W claim.
func (b *Base) SetActivePowerWatts(w float64, tag string) error {
	out, err := b.SetActivePowerWattsPlan(w, tag)
	if err != nil {
		return err
	}
	return rampNotApplied("SetActivePowerWatts", out)
}

// SetActivePowerWattsPlan is SetActivePowerWatts's PlanOutcome-returning
// engine (IW13-003 §1.3) — the single implementation SetActivePowerWatts
// (above) and preflightControl/preflightActuationWatts's addPlan
// registration (used only when DefaultWRmpPct is actually in play at
// registration time) both call. Its own returned error is non-nil ONLY when
// the setpoint itself did not land — a WRmp-only drop (write704Rmp's
// isolating retry succeeding) is reported through the returned PlanOutcome's
// elements, never through this function's error, so a document built with
// addPlan sees err==nil for this axis: it must not freeze the rest of the
// document or spend its one bounded re-attempt on an already-known,
// deterministic device incapability (§1.4). ApplyControlPlan/
// ApplyActuationWatts (via runControlSteps/firstRampNotApplied) are what
// promote a dropped ramp into a RampNotAppliedError at the DOCUMENT level.
func (b *Base) SetActivePowerWattsPlan(w float64, tag string) (PlanOutcome, error) {
	out := PlanOutcome{Tag: tag, Plan: "SetActivePowerWatts"}
	if err := b.checkSetpointWithinNameplate("SetActivePowerWatts", w); err != nil {
		return out, err
	}
	// Defect 2: rmpFn passed only when a WRmp value is actually in play — see
	// SetConstantVarPlan's identical comment for why unconditional b.writeWRmp
	// was reverted (it corrupted ApplyControlPlan's document-level re-attempt
	// budget accounting for every 704 write, not just WRmp-bearing ones).
	var rmpFn func(v sunspec.View)
	if b.DefaultWRmpPct != nil {
		rmpFn = b.writeWRmp
	}
	// IW13-004a: the reversion-alternate pair for THIS axis (WSetRvrt/
	// WSetEnaRvrt) — validated against the same nameplate bound as the
	// primary setpoint, since WSetRvrt is also a setpoint the device may be
	// told to hold. A caller that supplied no alternate (DefaultWSetEnaRvrt
	// nil) gets a pure no-op closure — byte-identical to today.
	if b.DefaultWSetRvrt != nil {
		if err := b.checkSetpointWithinNameplate("SetActivePowerWatts.WSetRvrt", *b.DefaultWSetRvrt); err != nil {
			return out, err
		}
	}
	rvrtFn, err := rvrtAlternateWriter("SetActivePowerWatts", "WSetRvrt", "WSetEnaRvrt", b.DefaultWSetRvrt, b.DefaultWSetEnaRvrt)
	if err != nil {
		return out, err
	}
	isolated, werr := b.write704Rmp(tag, "SetActivePowerWatts", []ctrlMode{modeFixedW}, func(v sunspec.View) {
		v.SetBool("WSetEna", true)
		v.SetEnum("WSetMod", sunspec.M704_WSetMod_Watts)
		v.SetFloat("WSet", w)
		v.SetU32("WSetRvrtTms", b.DefaultRvrtTms)
		rvrtFn(v)
	}, rmpFn)
	if werr != nil {
		return out, werr
	}
	out.Elements = append(out.Elements, ElementOutcome{Name: "WSet", Model: sunspec.ModelDERCtlAC, State: ElementApplied})
	if isolated {
		out.Elements = append(out.Elements, ElementOutcome{Name: "WRmp", Model: sunspec.ModelDERCtlAC,
			State: ElementFailed, Advisory: "ramp rejected by device at the address-range level; " +
				"setpoint applied without the commanded ramp rate"})
	}
	return out, nil
}

// checkSetpointWithinNameplate refuses an active-power SETPOINT the device
// cannot reach. An unknown nameplate imposes no bound — that is honest unknown,
// and the declared 702 rate ratings (validateSetpointW) are the other,
// independent bound.
func (b *Base) checkSetpointWithinNameplate(axis string, w float64) error {
	if math.IsNaN(b.Wmax) || b.Wmax <= 0 || math.Abs(w) <= b.Wmax {
		return nil
	}
	achievable := b.Wmax
	if w < 0 {
		achievable = -b.Wmax
	}
	return &SetpointRangeError{Axis: axis, Point: "M704 WSet", Commanded: w,
		Achievable: achievable, Bound: "WMax nameplate"}
}

// SetWMaxLimPctW sets the active-power ceiling as a percentage of WMax.
//
// A ceiling ABOVE the nameplate is clamped to 100 %, and that is not the
// silent substitution SetActivePowerWatts refuses: a device bounded at its own
// nameplate satisfies "do not exceed 200 kW" exactly, because it cannot exceed
// 60 kW either way. The commanded bound is in force; no quantity was replaced.
//
// A NEGATIVE ceiling is refused rather than clamped to zero. The pre-fix
// `if w < 0 { w = 0 }` turned a malformed request into a full curtailment —
// a real command, silently fabricated from a nonsensical one. preflightControl
// rejects negative ceilings too; this is the same rule at the exported
// boundary. Requires the device's positive MAX_W claim.
func (b *Base) SetWMaxLimPctW(w float64, tag string) error {
	out, err := b.SetWMaxLimPctWPlan(w, tag)
	if err != nil {
		return err
	}
	return rampNotApplied("SetWMaxLimPctW", out)
}

// SetWMaxLimPctWPlan is SetWMaxLimPctW's PlanOutcome-returning engine
// (IW13-003 §1.3) — see SetActivePowerWattsPlan's doc comment for the shared
// reasoning behind the split (SetWMaxLimPctW below and preflightControl/
// preflightActuationWatts's addPlan registration, used only when
// DefaultWRmpPct is in play, both call this).
func (b *Base) SetWMaxLimPctWPlan(w float64, tag string) (PlanOutcome, error) {
	out := PlanOutcome{Tag: tag, Plan: "SetWMaxLimPctW"}
	if math.IsNaN(b.Wmax) || b.Wmax <= 0 {
		return out, fmt.Errorf("%s: cannot set power limit: WMax unknown", tag)
	}
	if w < 0 || math.IsNaN(w) {
		return out, &InvalidControlError{Axis: "SetWMaxLimPctW", Reason: fmt.Sprintf(
			"negative or non-finite ceiling %g W; zeroing it would fabricate a full curtailment "+
				"nobody commanded", w)}
	}
	if w > b.Wmax {
		w = b.Wmax
	}
	pct := w / b.Wmax * 100.0
	// Defect 2: see SetActivePowerWattsPlan's identical comment — rmpFn only
	// when a WRmp value is actually in play.
	var rmpFn func(v sunspec.View)
	if b.DefaultWRmpPct != nil {
		rmpFn = b.writeWRmp
	}
	// IW13-004a: WMaxLimPctRvrt/WMaxLimPctEnaRvrt — DefaultWMaxLimPctRvrt is
	// WATTS (matching this function's own w), converted to percent here with
	// the SAME clamp-not-refuse rule the primary ceiling applies to w above:
	// a ceiling's alternate is still a ceiling, so it clamps at the top of its
	// range rather than refusing (unlike WSetRvrt, a setpoint's alternate,
	// which refuses — see SetActivePowerWattsPlan).
	var rvrtPct *float64
	if b.DefaultWMaxLimPctRvrt != nil {
		rv := *b.DefaultWMaxLimPctRvrt
		if math.IsNaN(rv) || rv < 0 {
			return out, &InvalidControlError{Axis: "SetWMaxLimPctW.WMaxLimPctRvrt", Reason: fmt.Sprintf(
				"negative or non-finite reversion-ceiling alternate %g W", rv)}
		}
		if rv > b.Wmax {
			rv = b.Wmax
		}
		p := rv / b.Wmax * 100.0
		rvrtPct = &p
	}
	rvrtFn, err := rvrtAlternateWriter("SetWMaxLimPctW", "WMaxLimPctRvrt", "WMaxLimPctEnaRvrt", rvrtPct, b.DefaultWMaxLimPctEnaRvrt)
	if err != nil {
		return out, err
	}
	isolated, werr := b.write704Rmp(tag, "SetWMaxLimPctW", []ctrlMode{modeMaxW}, func(v sunspec.View) {
		v.SetBool("WMaxLimPctEna", true)
		v.SetFloat("WMaxLimPct", pct)
		v.SetU32("WMaxLimPctRvrtTms", b.DefaultRvrtTms)
		rvrtFn(v)
	}, rmpFn)
	if werr != nil {
		return out, werr
	}
	out.Elements = append(out.Elements, ElementOutcome{Name: "WMaxLimPct", Model: sunspec.ModelDERCtlAC, State: ElementApplied})
	if isolated {
		out.Elements = append(out.Elements, ElementOutcome{Name: "WRmp", Model: sunspec.ModelDERCtlAC,
			State: ElementFailed, Advisory: "ramp rejected by device at the address-range level; " +
				"ceiling applied without the commanded ramp rate"})
	}
	return out, nil
}

// wRmpRefEnum resolves the shared WRmpRef selector (§1.2: 704 carries exactly
// ONE reference register for both WRmp and VarRmp) from DefaultWRmpRefIsAMax.
func (b *Base) wRmpRefEnum() uint16 {
	if b.DefaultWRmpRefIsAMax {
		return sunspec.M704_WRmpRef_AMax
	}
	return sunspec.M704_WRmpRef_WMax
}

// writeWRmp applies §3's standing WRmp ramp-rate policy write to a 704 View,
// when the caller has supplied DefaultWRmpPct. WRmp is a STICKY, GLOBAL
// register (§1.2): one setting governs every subsequent WSet/WMaxLimPct
// transition until next changed, not a value that auto-scopes to one
// control — so this is included in the SAME whole-block write as the axis
// value whenever the caller has a rate to assert (§3.2's "written every
// write cycle" discipline, cheap because write704 is already a whole-block
// RMW), and a complete no-op — byte-identical to today — when it does not.
func (b *Base) writeWRmp(v sunspec.View) {
	if b.DefaultWRmpPct == nil {
		return
	}
	v.SetEnum("WRmpRef", b.wRmpRefEnum())
	v.SetFloat("WRmp", *b.DefaultWRmpPct)
}

// writeVarRmp is writeWRmp's VarSet-axis sibling (DefaultVarRmpPct → VarRmp).
// Shares WRmpRef with writeWRmp since 704 carries only the one reference
// register for both rate points.
func (b *Base) writeVarRmp(v sunspec.View) {
	if b.DefaultVarRmpPct == nil {
		return
	}
	v.SetEnum("WRmpRef", b.wRmpRefEnum())
	v.SetFloat("VarRmp", *b.DefaultVarRmpPct)
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

// WriteVoltVar adopts and enables a Q(V) curve. Requires the device's positive
// VOLT_VAR claim: the pre-fix writer checked model presence only, so a device
// declaring MAX_W and nothing else had a volt-var curve adopted and ENABLED on
// it (audit F2).
func (b *Base) WriteVoltVar(c sunspec.VoltVarCurve, tag string) error {
	if !b.Has705 {
		return &UnsupportedControlError{Axis: "WriteVoltVar", Reason: "device has no M705 (DERVoltVar)"}
	}
	if err := b.requireCtrlModes("WriteVoltVar", modeVoltVar); err != nil {
		return err
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

// WriteVoltWatt adopts and enables a P(V) curve. Requires VOLT_WATT (audit F2).
func (b *Base) WriteVoltWatt(c sunspec.VoltWattCurve, tag string) error {
	if !b.Has706 {
		return &UnsupportedControlError{Axis: "WriteVoltWatt", Reason: "device has no M706 (DERVoltWatt)"}
	}
	if err := b.requireCtrlModes("WriteVoltWatt", modeVoltWatt); err != nil {
		return err
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
	return b.writeVoltageTrip(sunspec.ModelDERTripLV, b.Has707, "M707", modeLVTrip, c, tag)
}
func (b *Base) ReadVoltageTripHV(tag string) (sunspec.VoltageTripSet, error) {
	return b.readVoltageTrip(sunspec.ModelDERTripHV, b.Has708, "M708", tag)
}
func (b *Base) WriteVoltageTripHV(c sunspec.VoltageTripSet, tag string) error {
	return b.writeVoltageTrip(sunspec.ModelDERTripHV, b.Has708, "M708", modeHVTrip, c, tag)
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

// writeVoltageTrip requires the trip curve's own CtrlModes bit (audit F2): a
// ride-through curve is a 7xx control function like any other, and adopting one
// on a device that never declared it is the same defect as a fixed-PF write.
func (b *Base) writeVoltageTrip(modelID uint16, has bool, name string, mode ctrlMode, c sunspec.VoltageTripSet, tag string) error {
	if !has {
		return &UnsupportedControlError{Axis: "write" + name, Reason: "device has no " + name}
	}
	if err := b.requireCtrlModes("write"+name, mode); err != nil {
		return err
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
	return b.writeFreqTrip(sunspec.ModelDERTripLF, b.Has709, "M709", modeLFTrip, c, tag)
}
func (b *Base) ReadFreqTripHF(tag string) (sunspec.FreqTripSet, error) {
	return b.readFreqTrip(sunspec.ModelDERTripHF, b.Has710, "M710", tag)
}
func (b *Base) WriteFreqTripHF(c sunspec.FreqTripSet, tag string) error {
	return b.writeFreqTrip(sunspec.ModelDERTripHF, b.Has710, "M710", modeHFTrip, c, tag)
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

// writeFreqTrip requires the trip curve's own CtrlModes bit — see
// writeVoltageTrip.
func (b *Base) writeFreqTrip(modelID uint16, has bool, name string, mode ctrlMode, c sunspec.FreqTripSet, tag string) error {
	if !has {
		return &UnsupportedControlError{Axis: "write" + name, Reason: "device has no " + name}
	}
	if err := b.requireCtrlModes("write"+name, mode); err != nil {
		return err
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

// WriteFreqDroop adopts and enables a P(f) droop control. Requires FREQ_WATT —
// the CtrlModes symbol for frequency-droop active power (audit F2).
func (b *Base) WriteFreqDroop(c sunspec.FreqDroopCtl, tag string) error {
	if !b.Has711 {
		return &UnsupportedControlError{Axis: "WriteFreqDroop", Reason: "device has no M711 (DERFreqDroop)"}
	}
	if err := b.requireCtrlModes("WriteFreqDroop", modeFreqWatt); err != nil {
		return err
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

// WriteWattVar adopts and enables a Q(P) curve. Requires WATT_VAR (audit F2).
func (b *Base) WriteWattVar(c sunspec.WattVarCurve, tag string) error {
	if !b.Has712 {
		return &UnsupportedControlError{Axis: "WriteWattVar", Reason: "device has no M712 (DERWattVar)"}
	}
	if err := b.requireCtrlModes("WriteWattVar", modeWattVar); err != nil {
		return err
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
	// §3.3: a CSIP-resolved per-axis ramp takes precedence over the fixed
	// policy default — additive, not a removal: LegacyRmpTms/
	// defaultLegacyRmpTms still governs whenever no CSIP value is supplied.
	if b.CSIPRampTmsSeconds != nil {
		return *b.CSIPRampTmsSeconds
	}
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

// SetImportLimit is REFUSED on every device shape (DERBASE-IMPORT-AS-SETPOINT).
//
// It used to write −watts(ap) into M123 WMaxLimPct — a uint16 percent-of-WMax
// EXPORT ceiling — as a negative percentage, which is outside the point's
// declared type and expresses nothing a conformant device reads as an import
// bound. It is kept as a refusal rather than deleted so a caller learns WHY
// instead of losing the symbol: see importBoundUnsupported for the full
// register survey, and note that ApplyControl refuses opModImpLimW /
// opModLoadLimW for exactly the same reason.
func (b *Base) SetImportLimit(ap *model.ActivePower, tag string) error {
	return importBoundUnsupported(model.DERControlBase{OpModImpLimW: ap})
}

// SetExportLimit writes an active-power EXPORT ceiling through the M123 plan.
// Export is the direction model 123 can express, so this half is unaffected by
// the import-bound refusal above.
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
	raw uint16  // encoded WMaxLimPct target word
	pct float64 // engineering target, % of WMax
	sf  int16
	rmp uint16

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

// setLegacyWMaxLimPct writes the M123 WMaxLimPct EXPORT ceiling. It is a thin
// wrapper over the plan — the RawFromScaleSigned/EncodeScaleSigned convention:
// the outcome-bearing entry point is the real one, and this signature exists so
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
	// M123 WMaxLimPct is a uint16 percent of WMax on the OUTPUT side. The
	// pre-fix plan accepted a negative w and encoded a SIGNED percentage into
	// it as a "battery sim convention" — a value outside the point's declared
	// type that no conformant device reads as an import bound. The axis that
	// wanted it (opModImpLimW/opModLoadLimW) is now refused outright, so this
	// is the same refusal at the plan's own boundary rather than dead code
	// waiting for a caller (DERBASE-IMPORT-AS-SETPOINT; see
	// importBoundUnsupported for the register survey).
	if w < 0 || math.IsNaN(w) {
		return nil, &UnsupportedControlError{Axis: "M123 WMaxLimPct", Reason: fmt.Sprintf(
			"cannot express %g W: M123 WMaxLimPct is an unsigned percent-of-WMax export ceiling "+
				"and carries no import/charge direction", w)}
	}
	p := &m123LimitPlan{b: b, tag: tag, rmp: b.legacyRmpTms()}
	// A ceiling ABOVE the nameplate clamps to 100 %, and that is not a silent
	// substitution: a device bounded at its own nameplate satisfies the wider
	// bound exactly, because it cannot exceed it either way. Contrast
	// SetActivePowerWatts, where an out-of-range SETPOINT is refused.
	mag := w
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
		return nil, &CorruptReadError{Tag: tag, Model: sunspec.ModelImmediateCtrl,
			Detail: "the WMaxLimPct group read back all-sentinel (partial/failed read)"}
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
	p.pct = pct
	raw, outcome := sunspec.EncodeScaleUint(pct, p.sf)
	p.raw = raw
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

// decode converts a raw WMaxLimPct word to engineering percent. NaN means "not
// interpretable", which ceilingRestriction scores as no limit in force.
func (p *m123LimitPlan) decode(raw uint16) float64 {
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
