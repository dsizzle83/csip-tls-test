package derbase

// Legacy (12x) curve WRITERS — models 126, 129, 130, 131, 132, 134.
//
// The 7xx path has an adopt handshake to hide behind: write a staging curve,
// ask the device to adopt it, poll a result register. THE LEGACY FAMILY HAS
// NONE OF THAT. A curve write is a plain register write into a bank that the
// device may be executing right now, selected by ActCrv, enabled by a ModEna
// bit. There is no staging bank, no result register and no atomic adopt. So on
// this generation the SEQUENCE IS THE SAFETY ARGUMENT, and it is written out
// here rather than left to the caller:
//
//	Case A (preferred)  a writable bank that is NOT the live one exists. Write
//	                    it, verify it, then switch ActCrv to it. There is no
//	                    instant at which a partially-written curve is the
//	                    active curve.
//	Case B (fallback)   NCrv == 1, or every idle bank is ReadOnly. The live
//	                    bank is the only writable one, so it must be disabled,
//	                    rewritten, verified and re-enabled — a window in which
//	                    the function is off. Bounded by a 5 s budget.
//
// AND THE FAILURE ARM IS NOT ONE RULE. For 126/131/132/134 an unverified curve
// fails closed to ModEna = 0: their fallback is "no curve", the device reverts
// to its own configured behaviour inside its own settings envelope, and a
// half-written curve is strictly worse than no curve because the gateway does
// not know what it installed. For 129/130 — ride-through, a TRIP BOUNDARY —
// that same action is wrong: removing protection does not return the device to
// a known-safe envelope, it hands the boundary to an undocumented firmware
// fallback the gateway cannot read, cannot name and cannot report. Those models
// restore the ActCrv they found instead, and never write ModEna = 0 at all.
//
// That distinction is enforced STRUCTURALLY, not by convention: the fail-closed
// helper takes a nonProtectiveCurve witness that only the four non-protective
// models can produce, so the ride-through writer cannot call it even by
// mistake. See clearUnverifiedLegacyEnable and legacyRideThroughFailureArm.
//
// Reference: lexa-gw docs/design/LEGACY_CURVES_RC0_2026-08-14.md §2.4, §2.4.1,
// §2.6, §2.7, §2.8, §2.9.

import (
	"errors"
	"fmt"
	"math"
	"time"

	"lexa-proto/sunspec"
)

// legacyRewriteBudgetDefault bounds a Case-B rewrite — the window in which a
// live grid-support function is disabled while its only writable bank is
// rewritten. The caller holds the per-device transport mutex for the whole
// window, so this is also a poll-starvation bound.
const legacyRewriteBudgetDefault = 5 * time.Second

// ── Error vocabulary ─────────────────────────────────────────────────────────

// ErrUnresolvedReference reports that the GATEWAY's knowledge is missing, not
// the device's capability.
//
// The distinction is the whole point and it decides a protocol answer. A
// percentage control whose reference cannot be resolved (model 134's W<n> are
// "% WRef", and WRef must equal the device's own setMaxW) is not a control the
// device refused — it is a control nobody can compute yet. IW15-003's rule is
// that such an axis HOLDS at Received and resolves to CannotComply at the
// confirm deadline, rather than being declined immediately as if the device had
// said no. Declining it would report a device incapacity that does not exist.
var ErrUnresolvedReference = errors.New("control reference unresolved: the gateway cannot compute the value yet")

// UnresolvedReferenceError names the axis and the reference that could not be
// resolved.
type UnresolvedReferenceError struct {
	Axis   string
	Ref    string // the quantity that could not be resolved, e.g. "setMaxW"
	Reason string
}

func (e *UnresolvedReferenceError) Error() string {
	return fmt.Sprintf("unresolved reference for %s: %s cannot be resolved (%s) — the axis holds, "+
		"it is not declined: the device has not refused anything", e.Axis, e.Ref, e.Reason)
}
func (e *UnresolvedReferenceError) Unwrap() error { return ErrUnresolvedReference }

// ErrLegacyRewriteTimeout reports a Case-B rewrite that ran past its budget.
var ErrLegacyRewriteTimeout = errors.New("legacy curve rewrite exceeded its budget")

// LegacyRewriteTimeoutError names where the budget ran out. The rewrite window
// is the one in which the function is DISABLED, so exceeding it is not a
// latency complaint: it means a live grid-support function has been off longer
// than the design permits and the transaction must end, fail-closed.
type LegacyRewriteTimeoutError struct {
	Tag    string
	Model  uint16
	Phase  string
	Budget time.Duration
}

func (e *LegacyRewriteTimeoutError) Error() string {
	return fmt.Sprintf("%s: model %d single-bank rewrite exceeded its %s budget at %s — the function "+
		"was disabled for the whole window, so the transaction ends fail-closed",
		e.Tag, e.Model, e.Budget, e.Phase)
}
func (e *LegacyRewriteTimeoutError) Unwrap() error { return ErrLegacyRewriteTimeout }

// ErrLegacyTripRestoreFailed is the permanent escalation of §2.4.1's last row.
var ErrLegacyTripRestoreFailed = errors.New("legacy ride-through curve selection could not be restored")

// LegacyTripRestoreError reports the one genuinely bad state this design
// admits: a ride-through curve is live that the gateway could not verify, and
// the ActCrv restore that would have put the previous one back also failed.
//
// It does NOT disable the model, and that is deliberate. A wrong ride-through
// curve still defines a trip boundary the gateway can read back, report and
// alarm on; no ride-through curve leaves the boundary defined by firmware
// defaults the gateway has never read. A known-wrong protection setting is
// preferable to an unknown one, and both are preferable to none. The state is
// disclosed and alarmed, never silently held — and this model is LOCKED for
// further writes until the device is re-admitted.
type LegacyTripRestoreError struct {
	Tag         string
	Model       uint16
	PriorActCrv int
	Detail      string
}

func (e *LegacyTripRestoreError) Error() string {
	return fmt.Sprintf("%s: model %d legacy-trip-restore-failed: could not restore ActCrv=%d (%s). "+
		"An UNVERIFIED ride-through curve is live; protection is NOT disabled, the model is locked "+
		"against further writes, and this requires an operator alarm",
		e.Tag, e.Model, e.PriorActCrv, e.Detail)
}
func (e *LegacyTripRestoreError) Unwrap() error { return ErrLegacyTripRestoreFailed }

// ── Plan and outcome ─────────────────────────────────────────────────────────

// LegacyCurvePlan is one curve, already translated out of CSIP into the
// engineering units of the target model (§2.5). The caller owns the northbound
// translation — which axis maps to which model, how yRefType becomes DeptRef,
// which curve types have no legacy home at all — because that is protocol
// knowledge; this package owns the registers.
type LegacyCurvePlan struct {
	ModelID uint16
	// Axis is the CSIP axis name for error messages ("opModVoltVar"). Empty
	// falls back to a per-model default.
	Axis string
	// Points are in the model's own units: 126 (%VRef, signed % of DeptRef),
	// 131 (%WMax, PF), 132 (%VRef, % of DeptRef), 134 (absolute Hz, %WRef —
	// see §2.6), 129/130 (seconds, %VRef — TIME FIRST).
	Points []sunspec.LegacyCurvePoint
	// DeptRef is the LEGACY 1-based dependent-variable reference for 126
	// (1 %WMax, 2 %VArMax, 3 %VArAval) and 132 (1 %WMax, 2 %WAvail). Zero on
	// the models that have no such point. It is a TRANSLATION of yRefType,
	// never a copy of a 7xx DeptRef, which is 0-based.
	DeptRef uint16
	// CrvNam is optional; empty leaves the device's own name alone.
	CrvNam string
	// RvrtTmsS, when non-nil, arms the device-side curve-selection timeout in
	// seconds. Legacy's RvrtTms is uint16, so anything above 65535 is clamped
	// and DISCLOSED (§2.7) rather than silently shortened.
	RvrtTmsS *uint32
	// RmpTmsS, when non-nil, writes the header mode-transition ramp (seconds).
	RmpTmsS *uint16
	// RvrtAltBank must be nil. Legacy has no RvrtCrv register, so a reversion
	// ALTERNATE cannot be armed at all; a non-nil value is refused rather than
	// ignored, because ignoring it would report an armed alternate that does
	// not exist.
	RvrtAltBank *int
}

// LegacyRvrtShape reports what actually happened to the reversion timer, which
// is not always what was asked for and must never be reported as if it were.
type LegacyRvrtShape string

const (
	LegacyRvrtNotCommanded LegacyRvrtShape = "not-commanded"
	LegacyRvrtArmed        LegacyRvrtShape = "armed"
	// LegacyRvrtTruncated: armed, but at 65535 s (18.2 h) instead of the
	// longer window requested — legacy's register is uint16 seconds.
	LegacyRvrtTruncated LegacyRvrtShape = "truncated"
	// LegacyRvrtUnarmed: the device did not take the value. Devices commonly
	// implement RvrtTms as read-only zero. The curve itself still verified, so
	// the axis still adopts; refusing a verified grid-support curve because an
	// optional safety timer would not arm would be worse for the grid than
	// disclosing it.
	LegacyRvrtUnarmed LegacyRvrtShape = "unarmed"
)

// LegacyCurveOutcome is the evidence record of a legacy curve write.
type LegacyCurveOutcome struct {
	Model uint16
	Axis  string
	// Bank is the 1-based bank the curve was written into.
	Bank int
	// CaseB is true when the live bank had to be rewritten in place — the
	// window in which the function was disabled. PICS-disclosable (§7.2).
	CaseB bool
	// NoOp is true when the device already held exactly this curve, live and
	// enabled, so no curve register was written. On legacy that is a safety
	// property, not an optimisation: the alternative disables a live function
	// to rewrite it with what it already has, and on a single-bank device that
	// is a real interruption of grid support.
	//
	// A no-op pass may still refresh the device-side reversion timer, because a
	// lease is a different instruction from a curve. Rvrt/RvrtTmsS report what
	// happened to it.
	NoOp bool
	// PriorActCrv is the bank that was live before the command, recorded before
	// any register moved. It is what a ride-through restore puts back, and what
	// an operator needs to restore a curve selection by hand after a release.
	PriorActCrv int
	// Start/End are the register range written, body-relative.
	Start, End int
	// Rvrt/RvrtTmsS report the reversion timer honestly.
	Rvrt     LegacyRvrtShape
	RvrtTmsS uint32
	// WRefW/WRefPoint (model 134) name the active-power reference the curve's
	// percentages are answered against, and WHICH device point it came from —
	// so an evidence bundle can state it rather than assume it.
	WRefW     float64
	WRefPoint string
	// Disabled is true when the failure arm SWITCHED THE FUNCTION OFF: the
	// write failed after the new curve had already been selected, so the
	// device was left with ModEna = 0 rather than running a curve the gateway
	// cannot vouch for.
	//
	// It is a field rather than a detail inside the error because it is a fact
	// about the DEVICE, not about the call: something that was providing grid
	// support a moment ago is not providing it now, and a caller that only
	// classifies the error would report "the control failed" while missing
	// "and the previous one is gone too". A Case-B abort on 134 in particular
	// leaves frequency-watt off until the next reconcile pass, which is a
	// bounded but genuine loss of over-frequency curtailment and belongs on the
	// retained report rather than inside a generic diverged.
	Disabled bool
	// PartialBank is true when a narrowed retry stopped part way and the bank
	// therefore holds a mixture of the commanded curve and its previous
	// contents. It is never LIVE in that state — Case A has not selected it and
	// Case B has already disabled the function — but it is not what was
	// commanded either, and a caller that read only the error would think
	// nothing had moved.
	PartialBank bool
	// Warnings are disclosures that did not stop the write.
	Warnings []string
}

func (o *LegacyCurveOutcome) warn(format string, args ...any) {
	o.Warnings = append(o.Warnings, fmt.Sprintf(format, args...))
}

// ── The structural guard ─────────────────────────────────────────────────────

// nonProtectiveCurve is a WITNESS that a model's failure arm may write
// ModEna = 0.
//
// It exists because "126/131/132/134 fail closed, 129/130 never do" is a rule
// that a future edit could break silently: a shared helper with a conditional
// inside is one careless change away from disabling a trip boundary. Only
// nonProtective() can produce a usable witness, and it refuses the two
// protective models, so the ride-through writer cannot reach the fail-closed
// helper — not "does not", CANNOT.
type nonProtectiveCurve struct{ modelID uint16 }

// nonProtective returns a fail-closed witness for the four models whose
// fallback state is "no curve, device's own envelope".
func nonProtective(modelID uint16) (nonProtectiveCurve, bool) {
	switch modelID {
	case sunspec.ModelVoltVarLegacy, sunspec.ModelWattPFLegacy,
		sunspec.ModelVoltWattLegacy, sunspec.ModelFreqWattLegacy:
		return nonProtectiveCurve{modelID: modelID}, true
	}
	return nonProtectiveCurve{}, false
}

// isProtectiveLegacyModel reports the ride-through models, whose protection may
// never be removed as a failure action.
func isProtectiveLegacyModel(modelID uint16) bool {
	return modelID == sunspec.ModelLVRTLegacy || modelID == sunspec.ModelHVRTLegacy
}

// ── Public entry points ──────────────────────────────────────────────────────

// HasLegacyCurveModel reports whether the device publishes a legacy curve model.
func (b *Base) HasLegacyCurveModel(modelID uint16) bool {
	return b.Reader != nil && sunspec.IsLegacyCurveModel(modelID) && b.Reader.HasModel(modelID)
}

// ReadLegacyCurveGeometry reads and validates a legacy curve model's geometry.
// A device whose declared length, NCrv and NPt do not agree with the model's
// spec block length has a register map this package refuses to compute offsets
// in; the error is a MalformedDeviceError so a caller classifying device health
// buckets it with the other structural defects.
func (b *Base) ReadLegacyCurveGeometry(modelID uint16, tag string) (sunspec.LegacyCurveGeometry, error) {
	g, err := sunspec.ReadLegacyCurveGeometry(b.Reader, modelID)
	if err != nil {
		return g, legacyGeometryError(tag, modelID, g, err)
	}
	return g, nil
}

// WriteLegacyCurve installs a curve on one of the four NON-PROTECTIVE legacy
// models (126 volt-var, 131 watt-PF, 132 volt-watt, 134 freq-watt) and enables
// it, using Case A when a spare writable bank exists and Case B otherwise.
//
// It is NOT the entry point for 129/130: ride-through has a different failure
// arm and a different Case-B answer, and the two paths are deliberately
// separate functions rather than one function with a flag.
func (b *Base) WriteLegacyCurve(p LegacyCurvePlan, tag string) (LegacyCurveOutcome, error) {
	out := LegacyCurveOutcome{Model: p.ModelID, Axis: legacyAxisName(p), Rvrt: LegacyRvrtNotCommanded}
	witness, ok := nonProtective(p.ModelID)
	if !ok {
		return out, &UnsupportedControlError{Axis: out.Axis, Reason: fmt.Sprintf(
			"model %d is not a non-protective legacy curve model; ride-through models are written "+
				"through WriteLegacyRideThrough, which has a different failure arm", p.ModelID)}
	}
	st, err := b.legacyPreflight(p, tag, &out)
	if err != nil {
		return out, err
	}
	if st.noOp {
		// The curve is already installed and live. The lease is not: a
		// commanded reversion timeout is a standing instruction about how long
		// this curve may survive without the gateway, and refreshing it is the
		// only write a no-op pass has any business making.
		out.NoOp = true
		b.armLegacyTimers(st, &out, tag)
		return out, nil
	}

	var selected bool
	if !st.caseB {
		selected, err = b.legacyCaseA(st, &out, tag)
	} else {
		out.CaseB = true
		selected, err = b.legacyCaseB(st, &out, tag)
	}
	if err == nil {
		return out, nil
	}
	// §2.4.1's non-protective arm, SCOPED. Fail-closed answers exactly one
	// question — "the curve that is now selected may be one the gateway cannot
	// vouch for" — and that question only exists once the selection has moved
	// (Case A step 6) or the function has already been disabled to rewrite its
	// only bank (Case B step 4).
	//
	// BEFORE the switch there is nothing to fail closed ABOUT. The bank being
	// written is idle, the live bank is untouched, and the curve the device is
	// running is the one it was running before the command. Disabling it there
	// would switch off a working, verified, previously-commanded grid-support
	// function because a DIFFERENT bank refused a register — punishing the
	// device for a failure that never reached it. That is the same mistake
	// §2.4.1 refuses to make on the protective models, one model family over.
	if !selected {
		return out, err
	}
	out.Disabled = true
	out.warn("failed after the curve was selected: M%d was disabled (ModEna=0) rather than left "+
		"running a curve that did not verify", st.plan.ModelID)
	if ferr := b.clearUnverifiedLegacyEnable(witness, tag); ferr != nil {
		out.warn("fail-closed disable also failed: %v", ferr)
	}
	return out, err
}

// WriteLegacyRideThrough installs a must-disconnect curve on model 129 (LVRT)
// or 130 (HVRT).
//
// It is a SEPARATE function from WriteLegacyCurve, not a flag on it, for two
// reasons that are both about what happens when things go wrong:
//
//   - It REFUSES Case B. Rewriting the live bank means deleting the trip
//     boundary for the width of the transaction, and a protective setting is
//     not something to momentarily delete. Without a spare writable bank the
//     axis answers CannotComply with reason legacy-ride-through-single-bank.
//   - Its failure arm RESTORES rather than disables. Because Case A never
//     writes the live bank and Case B is refused, the previously-live bank is
//     untouched by construction, so a single ActCrv write returns the device
//     exactly to its pre-command configuration. Those two rules are the same
//     rule seen from two directions: the Case-B refusal is what MAKES the
//     failure arm recoverable.
func (b *Base) WriteLegacyRideThrough(p LegacyCurvePlan, tag string) (LegacyCurveOutcome, error) {
	out := LegacyCurveOutcome{Model: p.ModelID, Axis: legacyAxisName(p), Rvrt: LegacyRvrtNotCommanded}
	if !isProtectiveLegacyModel(p.ModelID) {
		return out, &UnsupportedControlError{Axis: out.Axis, Reason: fmt.Sprintf(
			"model %d is not a legacy ride-through model", p.ModelID)}
	}
	if lock, locked := b.legacyLockoutReason(p.ModelID); locked {
		return out, &LegacyTripRestoreError{Tag: tag, Model: p.ModelID,
			PriorActCrv: lock.priorActCrv, Detail: lock.reason}
	}
	st, err := b.legacyPreflight(p, tag, &out)
	if err != nil {
		return out, err
	}
	if st.noOp {
		out.NoOp = true
		b.armLegacyTimers(st, &out, tag)
		return out, nil
	}
	if st.caseB {
		// The design's single hardest refusal, and the one that makes the rest
		// of the protective path safe.
		return out, &UnsupportedControlError{Axis: out.Axis, Reason: fmt.Sprintf(
			"legacy-ride-through-single-bank: model %d declares NCrv=%d with no writable idle bank, "+
				"so installing this curve would delete the live trip boundary for the width of the "+
				"rewrite. A protective function is not momentarily removed to update it",
			p.ModelID, st.geom.NCrv)}
	}
	return out, b.legacyRideThroughCaseA(st, &out, tag)
}

// ReleaseLegacyCurve withdraws a commanded curve by clearing ModEna's bit 0.
//
// A withdrawal is a WRITE — the machine holds the last thing it was given until
// something tells it otherwise — but only on the three models where withdrawal
// is what a release MEANS:
//
//	126 / 131 / 132   ModEna = 0. The device reverts to its own configured
//	                  behaviour inside its own settings envelope.
//	134               NO WRITE. Not by the "nothing is less safe" argument —
//	                  using that to justify NOT disabling would be backwards —
//	                  but by CSIP semantics: releasing an opModFreqWatt control
//	                  means "this control no longer applies", which is not the
//	                  instruction "turn frequency response off". Frequency
//	                  response is a standing grid-support function the head end
//	                  did not author, and a released control does not repeal it.
//	129 / 130         NO WRITE. Ride-through is protective; those axes are
//	                  no-opinion, never released.
//
// ActCrv is NEVER written, on any model. Zeroing it would additionally destroy
// the device's own curve selection, which the gateway did not author and cannot
// restore. The prior ActCrv is reported at engage time so an operator can.
func (b *Base) ReleaseLegacyCurve(modelID uint16, tag string) (LegacyReleaseOutcome, error) {
	out := LegacyReleaseOutcome{Model: modelID, Axis: legacyDefaultAxis(modelID)}
	switch modelID {
	case sunspec.ModelVoltVarLegacy, sunspec.ModelWattPFLegacy, sunspec.ModelVoltWattLegacy:
	case sunspec.ModelFreqWattLegacy:
		out.NoOpinion = true
		out.Reason = "legacy-freq-watt-release-is-no-opinion: releasing an opModFreqWatt control " +
			"means the control no longer applies, not that frequency response is switched off; " +
			"frequency response is a standing function this control did not author"
		return out, nil
	case sunspec.ModelLVRTLegacy, sunspec.ModelHVRTLegacy:
		out.NoOpinion = true
		out.Reason = "legacy-ride-through-release-is-no-opinion: ride-through is a protective trip " +
			"boundary and is never stripped by a release"
		return out, nil
	default:
		return out, &UnsupportedControlError{Axis: out.Axis, Reason: fmt.Sprintf(
			"model %d is not a legacy curve model", modelID)}
	}
	if !b.HasLegacyCurveModel(modelID) {
		return out, &UnsupportedControlError{Axis: out.Axis, Reason: fmt.Sprintf(
			"device has no M%d", modelID)}
	}
	hdr, _, _, _ := sunspec.LegacyCurveLayouts(modelID)
	if err := b.setLegacyModEna(modelID, hdr, false, tag); err != nil {
		return out, err
	}
	out.Released = true
	return out, nil
}

// LegacyReleaseOutcome is what a commanded release DID.
//
// It is a struct with a nil error, rather than a typed refusal, because the
// answer for 134/129/130 is not "this device cannot do that" — it is "there is
// correctly nothing to do". Those two are different protocol answers: the first
// is CannotComply, and the second is a control that succeeds having written
// nothing. Returning ErrUnsupportedControl for the second would make a caller
// that classifies errors honestly report a refusal the standard does not call
// for, which is why the distinction lives in the RESULT rather than in the
// error class. A caller that ignores the struct still reports success, which is
// the right answer for a no-opinion axis; a caller that reads it can say WHY
// nothing was written on the retained report.
type LegacyReleaseOutcome struct {
	Model uint16
	Axis  string
	// Released: ModEna's bit 0 was cleared and the clear was verified.
	Released bool
	// NoOpinion: nothing was written, deliberately, and Reason names the rule.
	NoOpinion bool
	Reason    string
}

// ── Preflight ────────────────────────────────────────────────────────────────

// legacyWriteState is everything the sequencers need, resolved before any
// register moves.
type legacyWriteState struct {
	plan     LegacyCurvePlan
	geom     sunspec.LegacyCurveGeometry
	hdr      *sunspec.Layout
	bankL    *sunspec.Layout
	regs     []uint16 // the device's block as read
	want     []uint16 // regs with the encoded bank applied
	bank     int      // 1-based target bank
	base     int      // body offset of that bank
	caseB    bool
	start    int // written range, body-relative
	end      int
	noOp     bool
	deadline legacyDeadline
}

// legacyPreflight performs every check that can refuse BEFORE any register
// moves, and encodes the bank into a private copy of the block so that even a
// representability refusal happens with the device untouched.
func (b *Base) legacyPreflight(p LegacyCurvePlan, tag string, out *LegacyCurveOutcome) (legacyWriteState, error) {
	var st legacyWriteState
	st.plan = p
	axis := out.Axis

	if !sunspec.IsLegacyCurveModel(p.ModelID) {
		return st, &UnsupportedControlError{Axis: axis, Reason: fmt.Sprintf(
			"model %d is not a legacy curve model", p.ModelID)}
	}
	// Legacy curve writers gate on MODEL PRESENCE AND GEOMETRY, not on a 702
	// CtrlModes bit: a 12x device typically publishes no 702 at all, and the
	// 7xx capability gate would refuse every legacy device on the bench.
	if !b.HasLegacyCurveModel(p.ModelID) {
		return st, &UnsupportedControlError{Axis: axis, Reason: fmt.Sprintf(
			"device has no M%d — legacy curve axes are gated on model presence and geometry, "+
				"not on an M702 CtrlModes declaration", p.ModelID)}
	}
	if p.RvrtAltBank != nil {
		return st, &UnsupportedControlError{Axis: axis, Reason: "legacy-no-reversion-alternate: " +
			"the legacy curve models have no RvrtCrv register, so a reversion ALTERNATE cannot be " +
			"armed; it is refused rather than ignored, because ignoring it would report an armed " +
			"alternate that does not exist"}
	}
	if len(p.Points) == 0 {
		return st, &InvalidControlError{Axis: axis, Reason: "a curve with no points is not a curve; " +
			"CSIP CurveData is minOccurs=1"}
	}

	hdr, bankL, _, _ := sunspec.LegacyCurveLayouts(p.ModelID)
	st.hdr, st.bankL = hdr, bankL

	regs, err := b.Reader.ReadModel(p.ModelID)
	if err != nil {
		return st, fmt.Errorf("%s: read M%d: %w", tag, p.ModelID, err)
	}
	// The corruption gate the 7xx curve writers skip. The legacy headers carry
	// three or four sunssf points, so "any scale factor out of domain" is
	// authoritative and the half-block-sentinel heuristic never has to fire.
	if hdr.View(regs).ReadLooksCorrupt() {
		return st, &CorruptReadError{Tag: tag, Model: p.ModelID,
			Detail: "the header's scale factors are outside the sunssf domain, so this read is not " +
				"a real one and its contents must not be written back"}
	}
	g, err := sunspec.LegacyCurveGeometryOf(p.ModelID, len(regs), regs)
	if err != nil {
		return st, legacyGeometryError(tag, p.ModelID, g, err)
	}
	st.geom, st.regs = g, regs
	out.PriorActCrv = g.ActCrv

	if n, max := len(p.Points), g.UsablePoints(); n > max {
		return st, &UnsupportedControlError{Axis: axis, Reason: fmt.Sprintf(
			"curve has %d points, device supports %d (NPt=%d)", n, max, g.NPt)}
	}

	// Model 134's percentages are % WRef, and an UNRESOLVABLE reference is a
	// hold rather than a refusal — so it is answered here, before any bank is
	// chosen and long before any register moves. Whether WRef must actually be
	// WRITTEN is a per-bank question and is answered per bank below.
	if p.ModelID == sunspec.ModelFreqWattLegacy {
		if err := b.requireActivePowerReference(axis); err != nil {
			return st, err
		}
		out.WRefW, out.WRefPoint = b.Wmax, b.WmaxPoint
	}

	// ── The live-bank no-op probe ────────────────────────────────────────────
	//
	// THIS RUNS BEFORE BANK SELECTION, and that ordering is the whole point.
	// Selecting a spare bank first and asking "is this already what we want?"
	// afterwards can never answer yes on Case A, because the spare bank is by
	// construction not the live one — so an unchanged curve, re-commanded every
	// reconcile pass, would ping-pong between banks forever: writing bank 2,
	// then bank 1, then bank 2 again. Each of those passes overwrites the bank
	// the DEVICE configured (voiding the operator-restore promise the recorded
	// PriorActCrv makes) and churns ActCrv on a live function for no reason.
	//
	// So the question asked first is the only one that matters: does the curve
	// the device is RUNNING already equal the one commanded?
	//
	// The guard deliberately does NOT require the timer fields to be absent.
	// It used to, and that made it dead on the only path the product actually
	// produces: the gateway resolves a reversion timeout for every advanced
	// document — an absent validUntil becomes the default cap, never nil — so
	// every real plan carries one, every real pass skipped the guard, and the
	// bank ping-pong this guard exists to prevent came straight back. A
	// commanded timer is a reason to REFRESH THE LEASE, not a reason to rewrite
	// a curve the device is already running: the no-op path arms the timers and
	// touches nothing else.
	if live := g.ActCrv; live >= 1 && live <= g.NCrv {
		liveBase, _ := g.BankOffset(live)
		probe := append([]uint16(nil), regs...)
		lw := b.wrefForBank(p, regs, hdr, bankL, liveBase)
		if ls, le, perr := encodeLegacyBank(p, probe, live, lw); perr == nil &&
			legacyRangeEqual(probe, regs, ls, le) && legacyModEnaSet(regs, hdr) {
			st.bank, st.base, st.noOp = live, liveBase, true
			st.start, st.end, st.want = ls, le, probe
			st.deadline = newLegacyDeadline(b.legacyBudget())
			out.Bank = live
			return st, nil
		}
	}

	bank, caseB, err := legacyChooseBank(g, bankL, regs, axis)
	if err != nil {
		return st, err
	}
	st.bank, st.caseB = bank, caseB
	base, _ := g.BankOffset(bank)
	st.base = base
	out.Bank = bank

	wref := b.wrefForBank(p, regs, hdr, bankL, base)

	// Encode into a PRIVATE copy: a representability refusal must leave the
	// device untouched, and the encoders are atomic on the buffer they are
	// given.
	st.want = append([]uint16(nil), regs...)
	start, end, err := encodeLegacyBank(p, st.want, bank, wref)
	if err != nil {
		return st, err
	}
	st.start, st.end = start, end

	// The Case-B no-op: the target bank IS the live bank and already holds this
	// curve. On 7xx this is an optimisation; here it is a SAFETY requirement,
	// because the alternative is disabling a live function to rewrite it with
	// content it already has.
	if legacyRangeEqual(st.want, regs, start, end) &&
		g.ActCrv == bank && legacyModEnaSet(regs, hdr) {
		st.noOp = true
	}
	st.deadline = newLegacyDeadline(b.legacyBudget())
	return st, nil
}

// legacyChooseBank implements the Case A / Case B decision.
//
// Case A is preferred whenever ANY writable bank other than the live one
// exists — including every bank when ActCrv is 0 (no curve selected), where
// nothing is live and nothing can be disturbed.
func legacyChooseBank(g sunspec.LegacyCurveGeometry, bankL *sunspec.Layout, regs []uint16, axis string) (bank int, caseB bool, err error) {
	roOff := bankL.Offset("ReadOnly")
	// WRITABLE MEANS THE DEVICE SAID READWRITE, not merely that it did not say
	// READONLY. The spec enum is {0 READWRITE, 1 READONLY} and the point is
	// MANDATORY on all six models, so anything else — the 0xFFFF
	// not-implemented sentinel, a vendor's third value, a truncated read — is a
	// device that has not granted permission to overwrite this bank. Reading
	// "not exactly 1" as permission is the same laundering the capability gate
	// refuses one layer up: garbage is never permission.
	readOnly := func(i int) bool {
		base, ok := g.BankOffset(i)
		if !ok || base+roOff >= len(regs) {
			return true // unreadable is not writable
		}
		return regs[base+roOff] != 0
	}
	for i := 1; i <= g.NCrv; i++ {
		if i != g.ActCrv && !readOnly(i) {
			return i, false, nil
		}
	}
	if g.ActCrv >= 1 && g.ActCrv <= g.NCrv && !readOnly(g.ActCrv) {
		return g.ActCrv, true, nil
	}
	return 0, false, &UnsupportedControlError{Axis: axis, Reason: fmt.Sprintf(
		"all %d curve banks are flagged READONLY by the device; there is nowhere to write a curve",
		g.NCrv)}
}

// resolveLegacyWRef implements §2.6: model 134's W<n> are "% WRef" while CSIP's
// opModFreqWatt y is "%setMaxW". Those are equal only when WRef == setMaxW, and
// assuming it is the IW15-002a pathology one model over.
//
// Returns the value to WRITE into WRef (NaN when the device already carries an
// equal one, so the register is left alone).
func (b *Base) requireActivePowerReference(axis string) error {
	// Resolve through the SAME settings-first path the ceiling uses: the
	// setting (M121 WMax / 702 WMax) before the rating. A device an installer
	// derated answers percentages against its configuration, not its nameplate.
	if b.WmaxPoint == "" || math.IsNaN(b.Wmax) || b.Wmax <= 0 {
		return &UnresolvedReferenceError{Axis: axis, Ref: "setMaxW", Reason: "the device " +
			"publishes no usable active-power setting or rating, so the percentage the curve is " +
			"expressed in has no denominator"}
	}
	return nil
}

// wrefForBank answers the per-bank half of §2.6: what, if anything, must be
// written into THIS bank's WRef. NaN means "the device already carries an equal
// reference, leave the register alone" — rewriting a register to the value it
// already holds is a write that can fail for no benefit. Non-134 models have no
// WRef at all and always answer NaN.
func (b *Base) wrefForBank(p LegacyCurvePlan, regs []uint16, hdr, bankL *sunspec.Layout, base int) float64 {
	if p.ModelID != sunspec.ModelFreqWattLegacy {
		return math.NaN()
	}
	// The scale factor W<n>/WRef are bound to lives in the HEADER, so the view
	// must be the header's: a bank-bound view cannot see it.
	hdrView := hdr.View(regs)
	cur := hdrView.ScaleUintAt(base+bankL.Offset("WRef"), legacySF(bankL, "WRef"))
	if !math.IsNaN(cur) {
		if q := legacyQuantum(hdrView, bankL, "WRef"); math.Abs(cur-b.Wmax) <= q {
			return math.NaN()
		}
	}
	return b.Wmax
}

// ── Case A ───────────────────────────────────────────────────────────────────

// legacyCaseA writes an IDLE bank, verifies it, and only then switches ActCrv
// to it. There is no instant at which a partially-written curve is the active
// curve, which is the entire reason Case A is preferred.
// The bool reports whether the ActCrv SWITCH HAS HAPPENED — i.e. whether the
// newly-written bank may now be the live one. Only after that is the
// fail-closed disable the right answer to a failure; before it, the device is
// still running the curve it was running before the command and there is
// nothing to fail closed about.
func (b *Base) legacyCaseA(st legacyWriteState, out *LegacyCurveOutcome, tag string) (selected bool, err error) {
	if live, err := b.writeAndVerifyBank(st, out, tag); err != nil {
		// Ordinarily the idle bank simply did not take the curve: the live bank
		// is untouched and still selected, so there is nothing to undo. But if
		// the device selected the bank being written while the write was in
		// flight, an unverified curve is live and the fail-closed arm is the
		// only correct answer.
		return live, err
	}
	// Timers are armed BEFORE the switch so the timeout is already loaded when
	// the curve goes live.
	b.armLegacyTimers(st, out, tag)
	if err := b.setLegacyActCrv(st.plan.ModelID, st.hdr, st.bank, tag); err != nil {
		// The switch was refused and read back as the OLD selection, so the
		// old curve is still the live one. Nothing was taken away.
		return false, err
	}
	if err := b.setLegacyModEna(st.plan.ModelID, st.hdr, true, tag); err != nil {
		return true, err
	}
	return true, b.verifyLegacyLive(st, tag)
}

// legacyRideThroughCaseA is Case A with §2.4.1's PROTECTIVE failure arm. It is
// a separate function from legacyCaseA because its failure handling must be
// structurally incapable of reaching the fail-closed helper — a shared function
// with a conditional inside would leave that reachability one edit away.
func (b *Base) legacyRideThroughCaseA(st legacyWriteState, out *LegacyCurveOutcome, tag string) error {
	prior := st.geom.ActCrv

	// Step 2 failure is ordinarily benign: the bank being written is IDLE, so
	// the previously-live bank is untouched and still selected — full
	// pre-command protection, write nothing further.
	//
	// UNLESS the device selected that bank mid-write, which this very check can
	// discover and which makes the premise false: an unverified ride-through
	// curve would then be the live trip boundary. That is §2.4.1's step-6
	// situation arriving early, and it takes the same answer — restore the
	// selection recorded at engage, never disable, escalate if the restore
	// fails.
	if live, err := b.writeAndVerifyBank(st, out, tag); err != nil {
		if live {
			return b.legacyRideThroughFailureArm(st, prior, err, tag)
		}
		return err
	}
	b.armLegacyTimers(st, out, tag)

	if err := b.setLegacyActCrv(st.plan.ModelID, st.hdr, st.bank, tag); err != nil {
		return b.legacyRideThroughFailureArm(st, prior, err, tag)
	}
	// Enabling protection is an increase in protection, so it is allowed here;
	// DISABLING it never is, on any arm of this function.
	if err := b.setLegacyModEna(st.plan.ModelID, st.hdr, true, tag); err != nil {
		return b.legacyRideThroughFailureArm(st, prior, err, tag)
	}
	if err := b.verifyLegacyLive(st, tag); err != nil {
		return b.legacyRideThroughFailureArm(st, prior, err, tag)
	}
	return nil
}

// legacyRideThroughFailureArm restores the curve selection recorded at engage
// and NEVER writes ModEna. If the restore itself fails, the model is locked
// permanently and the error says so — but protection is still not disabled,
// because a known-wrong trip boundary is better than an unknown one.
func (b *Base) legacyRideThroughFailureArm(st legacyWriteState, prior int, cause error, tag string) error {
	model := st.plan.ModelID
	// ASK THE DEVICE WHERE ITS SELECTION IS before writing anything.
	//
	// The restore exists for one situation: the switch landed and the curve
	// that is now live is one this write could not verify. If the selection
	// never moved — a transport NAK on the switch, a refused write, a device
	// that rejected the new bank — then the previously-live curve is still
	// selected and still running, there is nothing to restore, and a restore
	// WRITE can only introduce a new failure. Attempting it anyway is how a NAK
	// on a write that was never needed becomes a permanent lockout and an
	// operator alarm over a state that does not exist.
	if regs, err := b.Reader.ReadModel(model); err == nil {
		if off := st.hdr.Offset("ActCrv"); off >= 0 && off < len(regs) && int(regs[off]) == prior {
			return cause
		}
	}
	// Either the selection moved, or we cannot prove it did not — and an
	// unproven selection is one to put back.
	if err := b.setLegacyActCrv(model, st.hdr, prior, tag); err != nil {
		b.lockLegacyModel(model, prior, fmt.Sprintf("ActCrv restore to %d failed: %v", prior, err))
		return &LegacyTripRestoreError{Tag: tag, Model: model, PriorActCrv: prior,
			Detail: err.Error()}
	}
	return cause
}

// ── Case B ───────────────────────────────────────────────────────────────────

// legacyCaseB rewrites the LIVE bank, which requires disabling the function for
// the width of the transaction. Only the four non-protective models ever reach
// it; ride-through refuses it outright.
// The bool reports whether the function has been DISABLED to make room for the
// rewrite. From that moment on every failure ends fail-closed, because the
// device is already not providing the function and re-enabling a bank whose
// content did not verify would be worse than leaving it off.
func (b *Base) legacyCaseB(st legacyWriteState, out *LegacyCurveOutcome, tag string) (selected bool, err error) {
	model := st.plan.ModelID
	if err := st.deadline.check(tag, model, "disable"); err != nil {
		return false, err
	}
	// Disable FIRST, and verify the disable. If the bit will not clear, the
	// device is still running its old curve and nothing else has been written:
	// abort with the device exactly where it was.
	if err := b.setLegacyModEna(model, st.hdr, false, tag); err != nil {
		// The bit would not clear: the device is still running its old curve
		// and nothing else has been written. Abort exactly where we started.
		return false, err
	}
	out.warn("case-B rewrite: M%d was disabled for the width of the transaction", model)

	if err := st.deadline.check(tag, model, "body"); err != nil {
		return true, err
	}
	if _, err := b.writeAndVerifyBank(st, out, tag); err != nil {
		// Case B has already disabled the function, so every failure from here
		// is fail-closed regardless of where the selection sits.
		return true, err
	}
	b.armLegacyTimers(st, out, tag)
	if err := st.deadline.check(tag, model, "select"); err != nil {
		return true, err
	}
	if err := b.setLegacyActCrv(model, st.hdr, st.bank, tag); err != nil {
		return true, err
	}
	if err := b.setLegacyModEna(model, st.hdr, true, tag); err != nil {
		return true, err
	}
	if err := st.deadline.check(tag, model, "verify"); err != nil {
		return true, err
	}
	return true, b.verifyLegacyLive(st, tag)
}

// legacyDeadline bounds the Case-B window.
type legacyDeadline struct {
	at     time.Time
	budget time.Duration
}

func newLegacyDeadline(budget time.Duration) legacyDeadline {
	return legacyDeadline{at: time.Now().Add(budget), budget: budget}
}

func (d legacyDeadline) check(tag string, model uint16, phase string) error {
	if time.Now().After(d.at) {
		return &LegacyRewriteTimeoutError{Tag: tag, Model: model, Phase: phase, Budget: d.budget}
	}
	return nil
}

func (b *Base) legacyBudget() time.Duration {
	if b.LegacyRewriteBudget > 0 {
		return b.LegacyRewriteBudget
	}
	return legacyRewriteBudgetDefault
}

// ── Register mechanics ───────────────────────────────────────────────────────

// writeAndVerifyBank writes the encoded bank and proves it landed, register for
// register.
//
// The comparison is over the whole written RANGE rather than over decoded
// values, and that is deliberate: a decoded comparison can agree while the
// registers differ (two raw words can round to the same engineering value), and
// the zero-filled unused slots have no decoded representation at all. What was
// commanded is a specific set of words; what must be verified is those words.
// The bool reports whether the bank just written HAS BECOME THE LIVE ONE
// despite the failure — see the ActCrv re-check below. The caller needs it to
// choose between "abort, nothing moved" and its model's failure arm.
func (b *Base) writeAndVerifyBank(st legacyWriteState, out *LegacyCurveOutcome, tag string) (liveOnWrittenBank bool, err error) {
	model := st.plan.ModelID
	if err := b.Reader.WriteModel(model, uint16(st.start), st.want[st.start:st.end]); err != nil {
		// A whole-block write covers every register in the bank, including
		// optional points the command never named — CrvNam, the ramp rates. A
		// vendor that implements one of those as read-only refuses the WHOLE
		// transaction, and the axis then fails entirely over a register nobody
		// asked to change. So a refusal is not final until the narrow write has
		// been tried: retry with only the registers whose values actually
		// differ, which is a subset of what the plan named and excludes every
		// register the command leaves alone.
		//
		// THE COST, STATED PLAINLY: the narrowed retry is a SEQUENCE of writes,
		// so unlike the single whole-block transaction it can stop half way and
		// leave the bank holding part of the new curve and part of the old one
		// — a curve nobody authored, of exactly the kind bankWriter's zero-fill
		// exists to prevent.
		//
		// It is kept anyway, because the invariant that matters is not "the
		// bank is never mixed" but NO PARTIALLY-AUTHORED CURVE MAY EVER BECOME
		// LIVE, and that one is held structurally on both paths:
		//
		//	Case A  the bank is IDLE. ActCrv is written only after the
		//	        whole-range comparison below passes, which a mixed bank
		//	        cannot pass, so the mixed bank is never selected. The one
		//	        way it could go live anyway — the device selecting it
		//	        mid-write — is the race the ActCrv re-check now catches and
		//	        routes to the model's failure arm.
		//	Case B  the bank is the live one, but ModEna was cleared and
		//	        verified clear before this write began, and every failure
		//	        from that point ends fail-closed. A mixed bank sits behind a
		//	        disabled function.
		//
		// What the alternative (revert to whole-block only) would buy is one
		// less state to reason about; what it would cost is every device whose
		// vendor made one optional point read-only losing the axis completely.
		// That is a worse trade against a hazard the arms already bound. The
		// obligation this leaves is HONESTY: the outcome must say registers
		// moved and the bank is mixed, rather than reporting a refusal that
		// sounds like nothing happened.
		runs := legacyChangedRuns(st.want, st.regs, st.start, st.end)
		if len(runs) == 0 {
			return false, fmt.Errorf("%s: write M%d bank %d: %w", tag, model, st.bank, err)
		}
		out.warn("whole-block write refused (%v); narrowing to %d changed register run(s) — the "+
			"device implements some optional bank point as read-only", err, len(runs))
		for i, r := range runs {
			if rerr := b.Reader.WriteModel(model, uint16(r[0]), st.want[r[0]:r[1]]); rerr != nil {
				if i > 0 {
					// Some runs landed and this one did not: the bank now holds
					// part of the commanded curve and part of whatever it held
					// before. Say so — the caller must not read this as "the
					// write was refused, nothing moved".
					out.PartialBank = true
					out.warn("the narrowed retry stopped after %d of %d run(s): bank %d now holds a "+
						"MIXTURE of the commanded curve and its previous contents. It is not "+
						"selected (Case A) or not enabled (Case B), so it is not live — but it is "+
						"not what was commanded either", i, len(runs), st.bank)
				}
				return false, fmt.Errorf("%s: write M%d bank %d: whole-block write refused (%v); "+
					"the narrowed retry landed %d of %d run(s) and was then refused at bank offset "+
					"+%d: %w", tag, model, st.bank, err, i, len(runs), r[0]-st.base, rerr)
			}
		}
	}
	back, err := b.Reader.ReadModel(model)
	if err != nil {
		return false, fmt.Errorf("%s: verify M%d bank %d: %w", tag, model, st.bank, err)
	}
	if len(back) < st.end {
		return false, &VerifyError{Tag: tag, Model: model, Point: "curve",
			Detail: fmt.Sprintf("device now declares %d registers, short of the bank's %d", len(back), st.end)}
	}
	// THE LIVE BANK IS RE-CHECKED HERE, not trusted from preflight — and the
	// two ways it can have moved mean OPPOSITE things about what to do next.
	//
	// Which bank is live was decided from one read, and the device can move
	// ActCrv on its own in between — most obviously when an armed RvrtTms
	// expires, which is a timer THIS PACKAGE ARMS.
	//
	//	moved ELSEWHERE     the bank just written is still idle. Nothing this
	//	                    write did is live, so the caller aborts with the
	//	                    device untouched.
	//	moved ONTO st.bank  the bank just written IS NOW LIVE, and its registers
	//	                    have not been compared yet — the device selected a
	//	                    bank while it was being written. That is precisely
	//	                    the "a partially-written curve is the active curve"
	//	                    state the whole Case-A sequence exists to prevent,
	//	                    and detecting it is worth nothing unless the caller
	//	                    ACTS: fail closed on a non-protective model, restore
	//	                    the prior selection on a protective one.
	//
	// The second case is reported as live=true even if the content would have
	// verified. The device ran an unknown fraction of this write as its active
	// curve for an unknown interval; that the end state happens to be right
	// does not make the selection ours, and a gateway that shrugs at "the
	// device picked a bank mid-write" has no basis for reporting what is
	// running.
	if actOff := st.hdr.Offset("ActCrv"); actOff >= 0 && actOff < len(back) {
		cur := int(back[actOff])
		switch {
		case !st.caseB && cur == st.bank:
			return true, &VerifyError{Tag: tag, Model: model, Point: "ActCrv", Detail: fmt.Sprintf(
				"the device selected bank %d — the bank being written — while the write was in "+
					"flight (an expiring reversion timer does exactly this), so an unverified "+
					"curve is now the active one", st.bank)}
		case cur != st.geom.ActCrv:
			return false, &VerifyError{Tag: tag, Model: model, Point: "ActCrv", Detail: fmt.Sprintf(
				"the device moved its curve selection from %d to %d while bank %d was being "+
					"written; bank %d is still idle, so nothing this write did is live",
				st.geom.ActCrv, cur, st.bank, st.bank)}
		}
	}
	for i := st.start; i < st.end; i++ {
		if back[i] == st.want[i] {
			continue
		}
		return false, &VerifyError{Tag: tag, Model: model,
			Point: legacyPointAt(st.bankL, i-st.base),
			Detail: fmt.Sprintf("bank %d offset +%d: wrote %#04x, device reads back %#04x",
				st.bank, i-st.base, st.want[i], back[i])}
	}
	return false, nil
}

// armLegacyTimers writes RvrtTms/RmpTms if the caller commanded them, and
// reports honestly what the device did with them. A timer that will not arm is
// a DISCLOSURE, not a refusal: the curve itself verified, and refusing a
// verified grid-support curve because an optional safety timer is read-only
// would be worse for the grid than saying so.
func (b *Base) armLegacyTimers(st legacyWriteState, out *LegacyCurveOutcome, tag string) {
	model := st.plan.ModelID
	if p := st.plan.RvrtTmsS; p != nil {
		want := *p
		shape := LegacyRvrtArmed
		if want > math.MaxUint16 {
			// uint16 seconds tops out at 18.2 h. A 24 h window cannot be
			// armed, and silently shortening it would be a safety timer the
			// operator believes is longer than it is.
			want = math.MaxUint16
			shape = LegacyRvrtTruncated
			out.warn("legacy-rvrt-tms-truncated: requested %ds exceeds the uint16 register; armed %ds instead",
				*p, want)
		}
		out.RvrtTmsS = want
		if err := b.writeHeaderPoint(model, st.hdr, "RvrtTms", uint16(want), tag); err != nil {
			shape = LegacyRvrtUnarmed
			out.warn("reversion timer did not arm (%v); the curve is adopted, the timer is not", err)
			out.RvrtTmsS = 0
		}
		out.Rvrt = shape
	}
	if p := st.plan.RmpTmsS; p != nil {
		if err := b.writeHeaderPoint(model, st.hdr, "RmpTms", *p, tag); err != nil {
			out.warn("mode-transition ramp did not arm (%v); the curve is adopted at the device's "+
				"own ramp rate", err)
		}
	}
	// WinTms is deliberately NOT written: there is no CSIP source for a
	// randomisation window, and zeroing it would remove a device-configured
	// randomisation the operator may rely on.
}

// writeHeaderPoint writes one header register and proves it took.
func (b *Base) writeHeaderPoint(model uint16, hdr *sunspec.Layout, point string, val uint16, tag string) error {
	off := hdr.Offset(point)
	if off < 0 {
		return &VerifyError{Tag: tag, Model: model, Point: point, Detail: "point absent from the model layout"}
	}
	if err := b.Reader.WriteModel(model, uint16(off), []uint16{val}); err != nil {
		return fmt.Errorf("%s: write M%d %s: %w", tag, model, point, err)
	}
	regs, err := b.Reader.ReadModel(model)
	if err != nil {
		return fmt.Errorf("%s: verify M%d %s: %w", tag, model, point, err)
	}
	if off >= len(regs) || regs[off] != val {
		got := "unreadable"
		if off < len(regs) {
			got = fmt.Sprintf("%d", regs[off])
		}
		return &VerifyError{Tag: tag, Model: model, Point: point,
			Detail: fmt.Sprintf("wrote %d, device reads back %s", val, got)}
	}
	return nil
}

// setLegacyActCrv selects a bank and proves the selection took.
func (b *Base) setLegacyActCrv(model uint16, hdr *sunspec.Layout, bank int, tag string) error {
	return b.writeHeaderPoint(model, hdr, "ActCrv", uint16(bank), tag)
}

// setLegacyModEna sets or clears ModEna's bit 0, PRESERVING the device's
// reserved bits, and proves the bit moved.
//
// ModEna is a bitfield16 whose enabled value is bit 0 — not an enum16 whose
// enabled value is 1. Writing the literal 1 would clear whatever else the
// vendor keeps in that word, and comparing the read-back against 1 would read a
// device that sets a reserved bit as disabled.
func (b *Base) setLegacyModEna(model uint16, hdr *sunspec.Layout, on bool, tag string) error {
	off := hdr.Offset("ModEna")
	regs, err := b.Reader.ReadModel(model)
	if err != nil {
		return fmt.Errorf("%s: read M%d before ModEna write: %w", tag, model, err)
	}
	if off < 0 || off >= len(regs) {
		return &VerifyError{Tag: tag, Model: model, Point: "ModEna", Detail: "point not readable"}
	}
	word := regs[off] &^ uint16(1)
	if on {
		word |= 1
	}
	if err := b.Reader.WriteModel(model, uint16(off), []uint16{word}); err != nil {
		return fmt.Errorf("%s: write M%d ModEna: %w", tag, model, err)
	}
	back, err := b.Reader.ReadModel(model)
	if err != nil {
		return fmt.Errorf("%s: verify M%d ModEna: %w", tag, model, err)
	}
	if off >= len(back) || (back[off]&1 == 1) != on {
		return &VerifyError{Tag: tag, Model: model, Point: "ModEna", Detail: fmt.Sprintf(
			"wrote bit0=%v, device reads back %#04x", on, legacyRegAt(back, off))}
	}
	return nil
}

// verifyLegacyLive is the final positive read-back: the right bank is selected
// AND the function is enabled. An accepted write is not an applied write.
func (b *Base) verifyLegacyLive(st legacyWriteState, tag string) error {
	model := st.plan.ModelID
	regs, err := b.Reader.ReadModel(model)
	if err != nil {
		return fmt.Errorf("%s: verify M%d live state: %w", tag, model, err)
	}
	actOff := st.hdr.Offset("ActCrv")
	if actOff >= len(regs) || int(regs[actOff]) != st.bank {
		return &VerifyError{Tag: tag, Model: model, Point: "ActCrv", Detail: fmt.Sprintf(
			"selected bank %d, device reads back %d", st.bank, legacyRegAt(regs, actOff))}
	}
	if !legacyModEnaSet(regs, st.hdr) {
		return &VerifyError{Tag: tag, Model: model, Point: "ModEna",
			Detail: "enabled the model, device reads back bit0 clear"}
	}
	return nil
}

// clearUnverifiedLegacyEnable is §2.4.1's NON-PROTECTIVE failure arm: an
// unverified curve is worse than no curve, so the model is disabled and the
// device falls back to its own configured behaviour.
//
// It takes a nonProtectiveCurve witness precisely so that it cannot be called
// for a ride-through model. Removing a trip boundary as a failure action is the
// mistake this signature exists to make impossible.
func (b *Base) clearUnverifiedLegacyEnable(m nonProtectiveCurve, tag string) error {
	if m.modelID == 0 || isProtectiveLegacyModel(m.modelID) {
		return fmt.Errorf("refusing to fail-closed on model %d: protection is never removed as a "+
			"failure action", m.modelID)
	}
	hdr, _, _, ok := sunspec.LegacyCurveLayouts(m.modelID)
	if !ok {
		return fmt.Errorf("model %d has no legacy curve layout", m.modelID)
	}
	return b.setLegacyModEna(m.modelID, hdr, false, tag)
}

// ── Per-model encode ─────────────────────────────────────────────────────────

// encodeLegacyBank builds the model's own curve struct from the generic plan
// and encodes it. Fields the plan does not command are NaN — "not commanded" —
// so the device's own value survives, rather than being overwritten with a Go
// zero that means something entirely different on the wire.
func encodeLegacyBank(p LegacyCurvePlan, regs []uint16, bank int, wref float64) (start, end int, err error) {
	switch p.ModelID {
	case sunspec.ModelVoltVarLegacy:
		return sunspec.EncodeLegacy126Curve(regs, bank, sunspec.LegacyVoltVarCurve{
			DeptRef: p.DeptRef, Pts: p.Points, CrvNam: p.CrvNam,
			RmpTmsS: math.NaN(), RmpDecPctMin: math.NaN(), RmpIncPctMin: math.NaN(),
		})
	case sunspec.ModelWattPFLegacy:
		return sunspec.EncodeLegacy131Curve(regs, bank, sunspec.LegacyWattPFCurve{
			Pts: p.Points, CrvNam: p.CrvNam,
			RmpPT1TmsS: math.NaN(), RmpDecPctMin: math.NaN(), RmpIncPctMin: math.NaN(),
		})
	case sunspec.ModelVoltWattLegacy:
		return sunspec.EncodeLegacy132Curve(regs, bank, sunspec.LegacyVoltWattCurve{
			DeptRef: p.DeptRef, Pts: p.Points, CrvNam: p.CrvNam,
			RmpPt1TmsS: math.NaN(), RmpDecPctMin: math.NaN(), RmpIncPctMin: math.NaN(),
		})
	case sunspec.ModelFreqWattLegacy:
		return sunspec.EncodeLegacy134Curve(regs, bank, sunspec.LegacyFreqWattCurve{
			Pts: p.Points, CrvNam: p.CrvNam,
			// SnptW MUST be false and MUST be verified: snapshot mode re-bases
			// the curve on the instantaneous output at the moment WRefStrHz was
			// crossed, which makes a curve defined against a fixed %setMaxW
			// base depend on irradiance at trigger time instead.
			SnptW:      false,
			WRefW:      wref,
			RmpPT1TmsS: math.NaN(), RmpDecPctMin: math.NaN(), RmpIncPctMin: math.NaN(),
			RmpRsUpPctMin: math.NaN(), WRefStrHz: math.NaN(), WRefStopHz: math.NaN(),
		})
	case sunspec.ModelLVRTLegacy:
		return sunspec.EncodeLegacy129Curve(regs, bank, sunspec.LegacyRideThroughCurve{
			Pts: p.Points, CrvNam: p.CrvNam,
		})
	case sunspec.ModelHVRTLegacy:
		return sunspec.EncodeLegacy130Curve(regs, bank, sunspec.LegacyRideThroughCurve{
			Pts: p.Points, CrvNam: p.CrvNam,
		})
	}
	return 0, 0, &UnsupportedControlError{Axis: legacyDefaultAxis(p.ModelID),
		Reason: fmt.Sprintf("model %d has no legacy curve encoder", p.ModelID)}
}

// ── Small helpers ────────────────────────────────────────────────────────────

// legacyLock is why a model is locked, and which selection the operator has to
// put back by hand. The prior selection travels WITH the lock: every report of
// the lockout names the same bank the original escalation did, instead of the
// zero value a re-raised error would otherwise carry.
type legacyLock struct {
	reason      string
	priorActCrv int
}

func (b *Base) legacyLockoutReason(model uint16) (legacyLock, bool) {
	if b.legacyLockout == nil {
		return legacyLock{}, false
	}
	l, ok := b.legacyLockout[model]
	return l, ok
}

func (b *Base) lockLegacyModel(model uint16, prior int, reason string) {
	if b.legacyLockout == nil {
		b.legacyLockout = map[uint16]legacyLock{}
	}
	b.legacyLockout[model] = legacyLock{reason: reason, priorActCrv: prior}
}

func legacyModEnaSet(regs []uint16, hdr *sunspec.Layout) bool {
	off := hdr.Offset("ModEna")
	return off >= 0 && off < len(regs) && regs[off]&1 == 1
}

func legacyRegAt(regs []uint16, off int) uint16 {
	if off < 0 || off >= len(regs) {
		return 0
	}
	return regs[off]
}

// legacyChangedRuns returns the contiguous [lo,hi) runs inside [start,end)
// whose values actually differ from what the device already holds. Registers
// the command leaves alone are excluded by construction, which is what makes
// the narrowed retry narrower than the plan itself.
func legacyChangedRuns(want, have []uint16, start, end int) [][2]int {
	var runs [][2]int
	i := start
	for i < end {
		if i >= len(want) || i >= len(have) || want[i] == have[i] {
			i++
			continue
		}
		lo := i
		for i < end && i < len(want) && i < len(have) && want[i] != have[i] {
			i++
		}
		runs = append(runs, [2]int{lo, i})
	}
	return runs
}

func legacyRangeEqual(a, b []uint16, start, end int) bool {
	if end > len(a) || end > len(b) {
		return false
	}
	for i := start; i < end; i++ {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// legacyPointAt names the spec point that owns a bank offset, so a verify
// failure says "V3" rather than "+7".
func legacyPointAt(l *sunspec.Layout, off int) string {
	name, best := "curve", -1
	for _, f := range l.Fields {
		o := l.Offset(f.Name)
		if o <= off && o > best {
			name, best = f.Name, o
		}
	}
	return name
}

// legacySF returns the scale-factor point a bank point is bound to, from the
// layout rather than from a literal.
func legacySF(l *sunspec.Layout, point string) string {
	f, ok := l.FieldOf(point)
	if !ok {
		return ""
	}
	return f.SF
}

// legacyQuantum is one least-significant step of a scaled point — the
// resolution below which "equal" is the only honest answer.
func legacyQuantum(v sunspec.View, l *sunspec.Layout, point string) float64 {
	sf, ok := v.SF(legacySF(l, point))
	if !ok {
		return 0
	}
	return math.Pow10(int(sf))
}

func legacyGeometryError(tag string, model uint16, g sunspec.LegacyCurveGeometry, cause error) error {
	// Only fill in the length pair when the LENGTH is what is wrong. Several of
	// the geometry gate's refusals — NCrv = 0, NPt out of range, ActCrv naming
	// a bank the device does not have — happen on a device whose declared
	// length is entirely coherent, and reporting "declares N, requires N" for
	// those would bury the real incoherence behind a tautology.
	required := 0
	if _, _, blk, ok := sunspec.LegacyCurveLayouts(model); ok && g.NCrv > 0 {
		if want := 10 + blk*g.NCrv; want != g.DeclLen {
			required = want
		}
	}
	declared := 0
	if required > 0 {
		declared = g.DeclLen
	}
	return &MalformedDeviceError{Tag: tag, Model: model, Declared: declared, Required: required,
		Detail: cause.Error()}
}

func legacyAxisName(p LegacyCurvePlan) string {
	if p.Axis != "" {
		return p.Axis
	}
	return legacyDefaultAxis(p.ModelID)
}

func legacyDefaultAxis(model uint16) string {
	switch model {
	case sunspec.ModelVoltVarLegacy:
		return "opModVoltVar"
	case sunspec.ModelWattPFLegacy:
		return "opModWattPF"
	case sunspec.ModelVoltWattLegacy:
		return "opModVoltWatt"
	case sunspec.ModelFreqWattLegacy:
		return "opModFreqWatt"
	case sunspec.ModelLVRTLegacy:
		return "opModLVRTMustTrip"
	case sunspec.ModelHVRTLegacy:
		return "opModHVRTMustTrip"
	}
	return fmt.Sprintf("M%d", model)
}
