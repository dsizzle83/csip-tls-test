// Promoted from lexa-hub@5218e6a (2026-07-17)

package bus

// DesiredState is the retained, versioned, per-device desired-state document
// (AD-013) — the single wire contract for AD-002's Device Reconciler. The
// optimizer publishes one retained document per device on
// lexa/desired/{class}/{device} (DesiredTopic); a reconciler co-located with
// the hardware driver reads it and owns write-on-diff / verify-by-readback /
// reassert-on-reconnect / non-convergence reporting. It replaces the four
// legacy convergence mechanisms tracked in
// docs/refactor/PRESERVATION_LEDGER.md (rows L1–L7).
//
// This type is introduced but not yet published or subscribed anywhere — the
// first publisher is TASK-027 and the first subscriber (the reconciler) is
// TASK-026, which also adds the topic → DesiredStateV case to SupportedV.
//
// Field-absence semantics (the silent-zero XML lesson applied to the bus):
// a nil *T field is "no opinion — leave that surface as the last standing
// intent set it", which is DISTINCT from an explicit zero, a command:
//   - SetpointW == &0 idles the battery (and is what enforces the SOC reserve,
//     ledger L1) — never confuse it with SetpointW == nil ("no setpoint").
//   - MaxCurrentA == &0 suspends the EVSE.
//   - Solar restore is an explicit large CeilingW (see RestoreCeilingW), NOT a
//     nil CeilingW: absence must never mean "restore to full output".
//
// Per class only that class's fields carry opinion; the rest stay nil (a
// battery document's CeilingW / MaxCurrentA are always nil, etc.).
type DesiredState struct {
	Envelope
	DeviceClass string `json:"device_class"` // "battery" | "solar" | "evse"
	DeviceID    string `json:"device_id"`    // device name, or EVSE stationID

	// CeilingW is the solar generation ceiling (W). Restore-to-full is an
	// explicit large value (RestoreCeilingW), which the device clamps to WMax;
	// nil means "no opinion", NOT "restore".
	CeilingW *float64 `json:"ceiling_w,omitempty"`
	// SetpointW is a signed power setpoint (W): +discharge, −charge. An
	// explicit 0 idles the pack (enforces the SOC reserve); nil means "no
	// setpoint". Battery docs have carried this since AD-013; D8/WP-14
	// extends it to EVSE docs (EVSECommand.SetpointW's doc) — same field,
	// same sign convention, same "only the active mode carries opinion"
	// rule: an EVSE doc in setpoint mode has SetpointW set and MaxCurrentA
	// nil; in ceiling mode (today's default, unchanged) it is the reverse.
	SetpointW *float64 `json:"setpoint_w,omitempty"`
	// Connect cease-energizes (false) or energizes (true) the battery; nil =
	// "no connect opinion".
	Connect *bool `json:"connect,omitempty"`
	// MaxCurrentA is the EVSE charging-current ceiling (A). An explicit 0
	// suspends the session; nil means "no current opinion".
	MaxCurrentA *float64 `json:"max_current_a,omitempty"`
	// ConnectorID is the EVSE connector this document targets (0 = the station
	// as a whole, per OCPP; the ocpp bridge maps 0 → 1). Meaningful only for
	// device_class == "evse"; carried inline so EVSE keeps one retained doc per
	// station (topic device == stationID).
	ConnectorID int `json:"connector_id,omitempty"`

	// ── CSIP_CONTROL_EXECUTION_2026-08-12.md §2/§3/§5: 704 register-write
	// hints for the scalar (WSet/WMaxLimPct) axes. All three are additive and
	// nil-safe: an author that never sets them (every mbaps-authored
	// DesiredState, unchanged) leaves the axis's register-write behavior
	// byte-identical to before this design landed — RvrtTms stays 0 (no
	// device-side reversion) and WRmp stays untouched. Only CSIPIn's
	// buildScalarLocked (csip authority) populates them.

	// RvrtTmsS is this axis's computed 704 reversion window (seconds, §2.1) —
	// the scalar-doc sibling of DesiredAdvanced.RvrtTmsS, same semantics,
	// applied to WSet/WMaxLimPct instead of the PF/var axes. nil = no
	// CSIP-computed window (an mbaps-authored doc, or a CSIP control whose
	// ValidUntil could not be resolved) — the reconciler shell must not write
	// a device-side reversion timer for this axis.
	RvrtTmsS *int64 `json:"rvrt_tms_s,omitempty"`
	// RampWPct is the standing 704 WRmp ramp-rate policy write (§3.2/§4.1):
	// percent of WMax per second, unscaled (matching WRmp's own register
	// convention — always expressed against WMax in this design's landing,
	// never AMax; see derbase.Base.DefaultWRmpRefIsAMax's doc for why AMax
	// support exists at the register layer but is unused here). nil = leave
	// WRmp untouched (today's behavior).
	RampWPct *float64 `json:"ramp_w_pct,omitempty"`
	// RampInexact marks a desired document derived from an EVENT that requested
	// a transition TIME (2030.5 DERControlBase.rampTms) the gateway cannot
	// execute exactly (IW13-006). rampTms names the time to go from the
	// device's CURRENT setting to the NEW one; the gateway has no trusted
	// current-value source, so RampWPct above is a nameplate-referenced
	// best-effort RATE that runs a sub-range transition steeper than requested
	// and finishes it early.
	//
	// The contract this field carries: the shell still LANDS the document
	// (containment — the setpoint/ceiling the utility commanded is what
	// matters most, and it is honored) and additionally stamps a PERMANENT
	// terminal ramp-inexact failure, so the response tracker reports the
	// control as CannotComply rather than letting a partially-executed control
	// read as a clean success.
	//
	// false on every setGradW/setSoftGradW-sourced ramp: a DefaultDERControl
	// commands a RATE, which WRmp is, and that path is executed exactly.
	// Additive at DesiredStateV=1 (AD-006): a publisher that never sets it
	// leaves behavior byte-identical.
	RampInexact bool `json:"ramp_inexact,omitempty"`
	// Declined marks a desired document that is a SAFE HOLD standing in for a
	// commanded axis the device cannot execute (IW14-002): the authority was
	// given a real command, found the device's own declared ratings say it
	// cannot perform that command's direction at all (a 702 charge/discharge
	// rate rating of ZERO, which is a positive claim of incapacity rather than
	// an absent rating), and authored its class-safe default in place of a
	// setpoint it has no honest way to compute.
	//
	// The contract this field carries is the mirror image of RampInexact's:
	// the shell still LANDS the document (the safe hold IS the containment —
	// the device ends up in the known-safe state, not in whatever state a
	// refused write would have left it) and additionally stamps a PERMANENT
	// terminal failure, so the response tracker reports the control
	// CannotComply. Without it the head end would be told a command executed
	// that never did: the document still carries the commanding source and
	// mRID, so the landed safe hold reads back as a clean Applied and the
	// control resolves Started.
	//
	// It is deliberately NOT a substitute for the axis-level refusals derbase
	// makes at the register layer — those refuse the WHOLE document, including
	// axes (opModConnect) the device CAN execute. This one keeps every other
	// axis of the document working and declines exactly the one axis the
	// device declared itself incapable of.
	//
	// Additive at DesiredStateV=1 (AD-006): a publisher that never sets it
	// leaves behavior byte-identical.
	Declined bool `json:"declined,omitempty"`
	// Unresolved marks a desired document whose commanded value could not be
	// TRANSLATED yet: the authority holds a real command, but the reference the
	// percent resolves against (nameplate/setMax*, and since IW15-002 the live
	// mutable settings) is not known to the gateway at this instant, so it
	// authored the class-safe hold in place of a value it cannot compute.
	//
	// It is Declined's TRANSIENT sibling and the distinction is the whole point
	// (IW15-003): Declined is a durable statement the DEVICE made about itself
	// (a declared zero rating) and is permanent-sticky; Unresolved is a statement
	// about the GATEWAY'S KNOWLEDGE, which is routinely transient at boot.
	//
	// Contract: the shell still LANDS the document (the hold IS the containment)
	// and stamps NO terminal — this flag must never reach hintsOf/ControlHints.
	// Its only consumer is northbound's actuation-confirm gate, which treats the
	// device as UNCONFIRMABLE-YET: the event holds at Received while containment
	// is enforced, and resolves either to Started (after the real value is
	// authored and readback-confirmed) or to CannotComply at the confirm-window
	// deadline. Never to Started off the hold.
	//
	// Additive at DesiredStateV=1 (AD-006): a publisher that never sets it
	// leaves behavior byte-identical.
	Unresolved bool `json:"unresolved,omitempty"`
	// RvrtSetpointW / RvrtCeilingW are the DESTINATION half of RvrtTmsS
	// (IW13-004a): the value the DEVICE ITSELF reverts to when the armed
	// reversion window above expires — 704 WSetRvrt for the battery setpoint
	// axis, WMaxLimPctRvrt for the solar ceiling axis. RvrtTmsS says WHEN the
	// DER reverts; these say TO WHAT. Without them an expiry lands the device
	// on whatever its own shadow register already holds (a factory default or
	// a stale prior session), which is the unverified destination IW13-004a
	// exists to close.
	//
	// BOTH ARE WATTS, including the ceiling one. That is not an oversight: the
	// consuming register writer (lexa-proto derbase.Base.DefaultWSetRvrt /
	// DefaultWMaxLimPctRvrt) takes watts on both axes and does the
	// percent-of-WMax conversion itself, against the DEVICE'S OWN nameplate,
	// exactly as it already does for the primary WMaxLimPct value — so the
	// alternate and the primary can never disagree about what 100% means.
	// Ceiling semantics carry through unchanged: a value above the device's
	// nameplate clamps to 100% (a bound above the nameplate is satisfied by
	// the nameplate), and RestoreCeilingW is the ordinary way to say "revert
	// to no curtailment". A SETPOINT alternate beyond the nameplate is refused
	// rather than clamped, the same asymmetry SetActivePowerWatts already
	// applies to the primary setpoint.
	//
	// WHAT THE AUTHORITY PUTS HERE (the posture, decided 2026-08-13): the
	// OPERATOR-CONFIGURED DEFAULTS — the same values the gateway itself
	// enforces when no control is active (its Defaults config: the battery's
	// hold setpoint, the inverter's default generation ceiling). RvrtTmsS is
	// sized from the control's own remaining life plus margin (or, for a
	// standing control, renewed on a cadence well inside the armed window), so
	// an expiry means either the control ended or the gateway is GONE — and
	// IEEE 2030.5's own semantics after an event ends are DefaultDERControl,
	// which the gateway's configured defaults ARE its realization of. For the
	// shipped battery default (0 W) that value coincides with the fail-safe
	// hold; the two postures diverge only for solar, where returning to the
	// configured ceiling mirrors default-control behavior rather than
	// curtailing a DER whose gateway simply stopped talking.
	//
	// nil = NO destination is asserted and the device's own register is left
	// UNTOUCHED — today's timeout-only behavior. That is the honest posture
	// whenever the authority cannot compute a destination it can defend (an
	// inverter whose nameplate is unknown, so "80% of an unknown rating" is
	// not a number), and it is deliberately NOT a value: writing a made-up
	// watts figure into a register the gateway will not be alive to correct is
	// the exact hazard this pair exists to close. Only the axis matching the
	// document's own class is ever populated (a battery doc's RvrtCeilingW is
	// always nil, and vice versa), mirroring SetpointW/CeilingW themselves.
	//
	// Both ride the SAME gate RvrtTmsS does: a document that arms no reversion
	// window carries no destination either. Arming a destination with no
	// window would be worse than useless. Per SunSpec SS-MODBUS-CONF v1.4
	// REV-3 a zero RvrtTms CANCELS reversion — "settings are never applied
	// after the timer has been cancelled" — so such a destination is a value
	// parked in a shadow register that no countdown will ever deliver: inert
	// on the day it is written, and a landmine afterwards, since the next
	// write that arms a countdown without re-authoring the destination hands
	// the DER this stale value as its post-death posture. The pair is written
	// together on the wire and it is gated together here.
	//
	// The CONVERSE of that gate is not silence: an armed WINDOW with no
	// destination is an explicit DISARM at the register layer — the consumer
	// emits 704 *EnaRvrt=0 with the value register left alone. Without it, a
	// device that was armed once could never be un-armed, and a later nil here
	// would leave the STALE DESTINATION standing on the device: the previous
	// control's alternate value, delivered by the next countdown as though this
	// document had authored it.
	//
	// WHAT THE DISARM ACTUALLY MEANS, corrected (gate #19/#20). It does NOT
	// make "the DER reverts to its own register default on expiry" true; that
	// claim was retracted after the generating text was read. SunSpec DER
	// Information Model Specification V1.2 §3.2 lists the "alternate,
	// function-dependent revision settings" as part of the reversion machinery,
	// and §3.3 gives the enable field its meaning: with the enable at 0 "any
	// changes made to the setting will not take effect" — the register holds
	// its value and the DER does not act on it. So *EnaRvrt=0 is the alternate
	// setting "this function is NOT ENABLED", and what expiry delivers is a
	// function that LAPSES: the axis stops being commanded, and the DER falls
	// back to whatever its own configuration says an uncommanded axis does.
	// That is not a value this document names, and it is not a backstop this
	// document can rely on — which is exactly why a defended destination is
	// preferred wherever the authority can compute one.
	//
	// The disarm is still load-bearing, for the reason above rather than the
	// retracted one: leaving the previous control's alternate value armed is
	// strictly worse than a lapse, because the countdown then hands the DER a
	// destination NO STANDING CONTROL AUTHORED.
	//
	// Additive at DesiredStateV=1 (AD-006): a publisher that never sets them
	// (every mbaps-authored document, and every pre-IW13-004a hub) leaves the
	// axis's register-write behavior byte-identical to before this landed.
	RvrtSetpointW *float64 `json:"rvrt_setpoint_w,omitempty"`
	RvrtCeilingW  *float64 `json:"rvrt_ceiling_w,omitempty"`
	// RvrtRenew says this axis's armed reversion LEASE must be renewed on a
	// wall-clock cadence, because it can otherwise expire while the control
	// that armed it is still in force. It is IW13-004b's missing
	// standing-vs-bounded signal, stated as the decision it actually governs,
	// and it has exactly one consumer: the reconciler shell's renewal
	// watchdog (reconcile.Reconciler.SetReassertEvery).
	//
	// Two control shapes need renewal, and only the authoring authority can
	// tell either of them from an ordinary control:
	//
	//   - STANDING (ValidUntil == 0 — a DefaultDERControl, or an event with no
	//     expiry): its armed window is a CONSTANT (the publisher's cap) and
	//     nothing ever re-authors its document, so without a renewal the DER's
	//     own onboard countdown reaches zero and it self-reverts about a day
	//     into otherwise healthy operation while the gateway still believes
	//     its control is in force. That is the HIGH-severity bug the renewal
	//     watchdog was built for.
	//   - LONG BOUNDED (remaining life longer than the publisher's cap): the
	//     window was CLAMPED below the control's own remaining life, so the
	//     device's countdown likewise expires under a live control.
	//
	// An ORDINARY bounded control needs no renewal and must not get one: its
	// armed window is remaining+margin, which by construction outlives the
	// control, and its own natural end re-authors the document (forcing a
	// fresh write) first — so arming the watchdog for it bought exactly one
	// needless mid-life re-write of the same registers, at roughly 55 % of the
	// control's remaining life.
	//
	// RvrtTmsS cannot substitute for this flag downstream: a bounded control
	// whose remaining life approaches the cap clamps to the IDENTICAL value a
	// standing control gets directly, and the cap itself is a publisher-side
	// constant no consuming process shares. Only the authority holds both
	// halves (ValidUntil and the resolved window), and this is where it says
	// what it concluded.
	//
	// false (the zero value) on every legacy/mbaps document means "no renewal"
	// — the same behavior those documents have today, since they carry no
	// armed window to renew in the first place.
	RvrtRenew bool `json:"rvrt_renew,omitempty"`
	// ConvergeTimeoutS is §5's per-axis ConvergeTimeout FLOOR (seconds): when
	// this axis's own commanded ramp could plausibly take longer than the
	// reconciler's ordinary default (60s) to converge, the axis's shell must
	// raise its Reconciler's ConvergeTimeout to at least this value so a
	// slow-but-progressing ramp is never mistaken for NonConvergedBegin. nil
	// or <=0 = no floor needed; the reconciler's ordinary default governs,
	// unchanged.
	ConvergeTimeoutS *int64 `json:"converge_timeout_s,omitempty"`

	// Source attributes the intent: "csip-event" | "csip-default" |
	// "economic" | "safety".
	Source string `json:"source"`
	// MRID is the origin identity of the intent, for later CannotComply
	// attribution (TASK-031) and terminal-report correlation: the active CSIP
	// control's mRID on the csip path, or the northbound TLS session identity
	// on the mbaps path (a raw Modbus/SunSpec write carries no mRID); empty
	// for economic/safety sources.
	MRID string `json:"mrid,omitempty"`
	// IssuedAt is the publisher's wall clock (Unix seconds) when the document
	// was produced — half of the (seq, issued_at) staleness key (AD-013).
	IssuedAt int64 `json:"issued_at"`
	// Seq is a per-device monotonic counter owned by the publisher. It resets
	// to 0 on a publisher restart, which the consumer distinguishes from a
	// replay via IssuedAt (AD-013 rule 2, the SeqReset case). It is per device,
	// never per class or global.
	Seq uint64 `json:"seq"`

	// Gen is the per-device generation/epoch for the P1.4 transactional-actuation
	// device-replacement fence (SUN-001 §2.3 — GO-004's deferred P3.2 tail). It
	// is a MONOTONIC counter (lead ruling D2) minted at device admit and bumped
	// on every rebind of a physically-replaced DER at the same name. Additive at
	// DesiredStateV=1 (AD-006): a legacy publisher (lexa-hub) never stamps it, so
	// it decodes to the zero value, and Gen==0 means UNFENCED — the reconciler
	// keeps the pre-P1.4 (Seq,IssuedAt)-only staleness semantics unchanged. A
	// non-zero Gen opts the device into the generation fence
	// (reconcile.Config.CurrentGen): a doc whose Gen is strictly OLDER than the
	// consumer's currently-bound generation is rejected, so a curtail ack'd for
	// inverter-0(gen 1) can never actuate on the physically-different
	// inverter-0(gen 2). Orthogonal to Seq: Seq fences replays/publisher-restart
	// within one device identity; Gen fences the identity itself.
	Gen uint64 `json:"gen,omitempty"`
}

// RestoreCeilingW is the "no curtailment" solar ceiling encoded in CeilingW to
// mean "restore to full output" — far above any nameplate so the device clamps
// it to WMax. It mirrors cmd/modbus's restoreCeilingW: restore is an explicit
// value on the wire, never an absent field (AD-013 field-absence semantics).
const RestoreCeilingW = 1e9

// RestoreCurrentA is the EVSE sibling of RestoreCeilingW (WP-13, B3): an
// explicit "no CSMS-imposed charging limit" MaxCurrentA — far above any
// hardware rating, so a release is a VALUE on the wire, never an absent
// field (AD-013 field-absence semantics). The lexa-ocpp reconciler shell maps
// a desired MaxCurrentA at/above the station's rated maximum (this sentinel
// included, by construction) to an OCPP ClearChargingProfile — removing the
// standing TxDefaultProfile — instead of re-setting a large numeric limit.
// Convergence for a release is trivial under the one-sided metered-current
// rule (an EV under its limit is always compliant), so Clear-Accepted is the
// write success and the next plausible sample converges it.
const RestoreCurrentA = 1e6

// Desired-state device classes, the {class} segment of DesiredTopic.
const (
	DesiredClassBattery = "battery"
	DesiredClassSolar   = "solar"
	DesiredClassEVSE    = "evse"
)

// Finite is DesiredState's counterpart to Measurement.Finite (GAP-09
// discipline: every *float64-bearing bus type joins this check) — added
// alongside D8/WP-14's EVSE reuse of SetpointW. DesiredState is decoded via
// mqttutil.Subscribe in both cmd/modbus (battery/solar) and cmd/ocpp (EVSE),
// which runs this via the interface{ Finite() error } type assertion
// immediately after unmarshal, so a non-finite CeilingW/SetpointW/MaxCurrentA
// is dropped (fail-closed: the reconciler's last-known-good desired state
// holds) rather than adopted as a live command.
func (d DesiredState) Finite() error {
	if err := finite("ceiling_w", d.CeilingW); err != nil {
		return err
	}
	if err := finite("setpoint_w", d.SetpointW); err != nil {
		return err
	}
	if err := finite("max_current_a", d.MaxCurrentA); err != nil {
		return err
	}
	if err := finite("ramp_w_pct", d.RampWPct); err != nil {
		return err
	}
	// The reversion DESTINATIONS join the check for a sharper reason than the
	// fields above: they are written into a DER's shadow register and then
	// left there, to take effect at a moment the gateway may not be alive for.
	// A NaN that slipped through would be armed as this fleet's post-death
	// posture and nobody would be watching when it fired.
	if err := finite("rvrt_setpoint_w", d.RvrtSetpointW); err != nil {
		return err
	}
	if err := finite("rvrt_ceiling_w", d.RvrtCeilingW); err != nil {
		return err
	}
	return nil
}
