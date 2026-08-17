// Promoted from lexa-hub@5218e6a (2026-07-17)

package bus

import "sort"

// DesiredAdvanced bus contract (WP-9, standards-buildout C1/C3/C4 —
// architecture D6, NORMATIVE): the hub's advanced-DER author (cmd/hub/adv.go,
// gated behind hub.json `advanced_der:"on"`) publishes ONE retained document
// per inverter/battery on DesiredAdvTopic(device) — `lexa/desired/adv/{device}`,
// QoS 1 (PubQoS's non-measurement default) — carrying the device's resolved
// advanced operating point: the arbitrated reactive-power mode, the volt-watt /
// freq-watt overlays, frequency droop, trip/ride-through curve sets, energize,
// the DefaultDERControl ramp gradients, and the computed reversion window.
// The consumer is WP-10's cmd/modbus adv reconciler shell; until it lands the
// docs sit retained and harmless (cmd/modbus's SubDesired dispatch switches on
// the topic class and ignores "adv"; lexa-ocpp likewise).
//
// D6 rules carried in this shape:
//
//   - Mutual exclusivity of reactive modes is STRUCTURAL: ReactiveMode is ONE
//     field, so a reconciler can never observe torn multi-reactive state. The
//     hub (single author) owns the D7 arbitration that picks it.
//   - The five mode axes (reactive_mode, volt_watt, freq_watt, freq_droop,
//     trips) are always present on the wire — an un-commanded axis is an
//     EXPLICIT null (a release command: "no <axis> in force"), never an absent
//     key. This is AD-013's explicit-values-never-absence rule applied to
//     provisioning state: absence must never be readable as "keep whatever
//     curve happens to be adopted".
//   - Adoption state does NOT ride this doc (a desired doc is publisher-owned
//     intent; readback state on it would create a second writer) — it rides
//     the retained per-device ReconcileReport extension (WP-10, §2.2).
//   - Content hashes (AdvCurve.Hash / AdvTripSet.Hash — CurveSetContentHash
//     over the axis's canonical entries) let both sides skip no-op
//     re-adoptions after reconnect/restart.
type DesiredAdvanced struct {
	Envelope
	DeviceClass string `json:"device_class"` // DesiredClassBattery | DesiredClassSolar
	DeviceID    string `json:"device_id"`

	// ReactiveMode is the single arbitrated reactive-power mode (D7), or an
	// explicit null (no reactive mode commanded — release). NEVER omitempty:
	// see the type doc's explicit-null rule.
	ReactiveMode *AdvReactiveMode `json:"reactive_mode"`

	// VoltWatt / FreqWatt are concurrent active-power overlays (1547 §4.7):
	// they pass through arbitration untouched and coexist with ReactiveMode.
	VoltWatt *AdvCurve `json:"volt_watt"`
	FreqWatt *AdvCurve `json:"freq_watt"`

	// FreqDroop carries frequency-droop parameters in SunSpec model 711 Ctl
	// vocabulary (see AdvFreqDroop for the 2030.5→711 mapping), or explicit
	// null.
	FreqDroop *AdvFreqDroop `json:"freq_droop"`

	// ReleaseFreqDroop is the PROVENANCE-SCOPED droop release (owner ruling R1,
	// 2026-08-15, closing lexa-gw known-issue IW15-023). It is only ever set on
	// a document whose FreqDroop is null.
	//
	// THE PROBLEM IT SOLVES. A null droop on a LIVE control is deliberately
	// NO-OPINION: a control that commands volt-var and simply does not mention
	// frequency droop must not switch off a droop somebody configured out of
	// band — the no-strip rule, pinned in lexa-gw by
	// TestAdvShell_LiveControlWithoutDroopDoesNotDisableIt. Only the all-null
	// RELEASE document (Source "none") released the axis. That left a real
	// residual: if the GATEWAY ITSELF wrote a droop under event E and event F
	// then superseded E commanding only volt-var, the droop stood on the DER —
	// commanded by a control that no longer exists — until the next all-null
	// release or a reversion expiry.
	//
	// WHY A FLAG AND NOT A RULE THE CONSUMER COULD INFER. The consumer (the
	// lexa-gw adv reconciler shell) sees one document at a time and cannot tell
	// "the gateway wrote this droop under the event that just ended" from "this
	// droop was configured on the DER by an installer and no document ever
	// mentioned it". Only the AUTHOR knows, because only the author remembers
	// what it authored. So the author carries the provenance (lexa-gw
	// internal/authority's advDroopAuthored, re-derived at boot from the
	// retained document this very field rides on) and states the conclusion
	// here. A consumer that sees a null droop with this flag CLEAR still treats
	// the axis as no-opinion, exactly as before — which is what keeps the
	// out-of-band droop safe.
	//
	// Additive at DesiredAdvancedV=3 (AD-006), and additive in the SAFE
	// direction under either skew: an old author never sets it, so a new
	// consumer reads no-opinion (today's behavior); an old consumer ignores the
	// key, so a new author's release is simply not executed (today's behavior).
	// Neither direction can invent a release that was not authored.
	ReleaseFreqDroop bool `json:"release_freq_droop,omitempty"`

	// ReleaseCurveAxes names the curve axes this document explicitly WITHDRAWS
	// (P4). Values come from the AdvAxis* vocabulary and are constrained to the
	// axes whose null CANNOT already carry a release — today that is freq_watt
	// alone; see ReleasableCurveAxes for the closed set and for why the other
	// three legacy curve axes are deliberately out of it. Absent or empty means
	// no explicit release.
	//
	// THE DEFECT BEHIND IT. A bench sweep of all four legacy DERCurveLink axes
	// with a clean explicit-null lever (xsi:nil, no activate, so no lapse
	// confound) found that none of them honours it: every one decodes xsi:nil as
	// a DERCurveLink with an EMPTY HREF, drops it on the ignored-content channel,
	// re-affirms the curve it was asked to release ("NO-OP — already held this
	// curve, live and enabled"), and answers Applied. The head end is told a
	// withdrawal landed that never did.
	//
	// THE FIX FOR THREE OF THE FOUR AXES IS ENTIRELY UPSTREAM OF THIS FIELD, and
	// saying so is the point of this paragraph. The primary defect is that the
	// AUTHORITY never learned of the release, because the decode dropped the nil;
	// repairing that (lexa-proto's marker, plus the authority nulling the axis)
	// is what closes it. Once the axis arrives null, THE NULL IS ALREADY A
	// RELEASE COMMAND on those three — this type's own doc says so twenty lines
	// above: "an un-commanded axis is an EXPLICIT null (a release command: 'no
	// <axis> in force'), never an absent key". The consumer implements exactly
	// that: volt_var and watt_pf DEFAULT to release() and are overridden only by
	// content, volt_watt is release() on null, and release() is executed —
	// executeReleaseLocked verifies-then-disables the axis function (Ena=0).
	//
	// SO A FLAG ON THOSE THREE WOULD BE A SECOND CHANNEL THAT CAN DISAGREE WITH
	// THE FIRST, in the ordinary direction rather than an exotic one: a null
	// volt_watt with no flag set still releases, while ReleasesCurveAxis would
	// answer false for it. A consumer that read the flag INSTEAD of the null
	// would silently regress three working axes. The narrowest contract that
	// closes the real gap is the correct one.
	//
	// WHY freq_watt IS DIFFERENT, and the only member today. Its null is
	// DELIBERATELY no-opinion, and that is ratified rather than incidental — the
	// consumer's own branch cites LEGACY_CURVES_RC0_2026-08-14.md §2.8's
	// three-state table, which puts model 134 in the "no write" column for a
	// commanded release and says "Only 126, 131 and 132 are releasable on
	// legacy", on the ground that "the release of an opModFreqWatt control means
	// 'this control no longer applies', which is not the same instruction as
	// 'turn frequency response off'. Frequency response is a standing
	// grid-support function the head end did not author and a released control
	// does not repeal." Because that axis's null is reserved for no-opinion, the
	// null channel is UNAVAILABLE to it, and a flag is the only way to say "the
	// server withdrew this" as distinct from "nothing commanded it".
	//
	// WHAT THE FLAG IS WORTH ON IT, stated plainly because it is not a register.
	// The ratified execution of a freq_watt release is to WRITE NOTHING. The
	// value is the honest RESPONSE: the gateway can answer the head end truthfully
	// about a control it has genuinely released, instead of the false Applied the
	// bench caught. An instruction whose correct execution is "no write" still
	// has to be distinguishable from one that was never given.
	//
	// AND IT STILL HAS TO BE A FLAG RATHER THAN AN INFERENCE, for the reason
	// ReleaseFreqDroop states under "WHY A FLAG AND NOT A RULE THE CONSUMER COULD
	// INFER": the consumer "sees one document at a time and cannot tell 'the
	// gateway wrote this droop under the event that just ended' from 'this droop
	// was configured on the DER by an installer and no document ever mentioned
	// it'. Only the AUTHOR knows, because only the author remembers what it
	// authored." On freq_watt that is exactly the ambiguity a null leaves, which
	// is why the author must state the conclusion here.
	//
	// A SLICE, NOT A BOOLEAN, even at cardinality one. The set is closed today
	// and not closed forever: an axis that acquires freq_watt-like semantics
	// joins it WITH ITS ARGUMENT (see ReleasableCurveAxes), and a list absorbs
	// that without a wire change or a second key to forget.
	//
	// UNKNOWN NAMES ARE IGNORED, NOT REFUSED, and the argument is this family's
	// own decode path rather than a general preference. mqttutil's Subscribe
	// calls Finite() and, on any error, DROPS THE WHOLE MESSAGE before a handler
	// sees it so last-known-good holds. So "refuse" here would not mean "refuse
	// this axis" — it would mean destroying every OTHER axis's command in the
	// document over one unrecognized string, on a family where the other axes
	// include live protection settings. Worse, it would invert the skew rule
	// below: a future author that releases a newly-qualifying axis would take an
	// older consumer's ENTIRE control down, when the documented safe direction is
	// that its release is "simply not executed". Ignoring leaves the axis exactly
	// where a silent document would have. ReleasesCurveAxis is therefore the only
	// question a consumer should ask; the raw slice is preserved verbatim so a
	// reader (and any log line) still sees what the author actually said —
	// narrowing what is EXECUTED is not licence to rewrite what was SAID.
	//
	// AN AXIS THIS DOCUMENT ALSO COMMANDS IS NOT RELEASED. A document naming an
	// axis whose curve it is simultaneously carrying is malformed, and
	// ReleasesCurveAxis resolves it in the non-destructive direction: content
	// wins. A curve present is an assertion, a release is a withdrawal, and
	// executing both is impossible — honouring the withdrawal would withdraw an
	// axis the same document is actively commanding. The author's invariant is
	// the one ReleaseFreqDroop states ("only ever set on a document whose
	// FreqDroop is null"); this makes a violation harmless instead of trusting
	// it. It guards one axis today and the principle is what generalises.
	//
	// Additive at DesiredAdvancedV=4 (AD-006) — no bump, no floor, exactly as
	// ReleaseFreqDroop and the reactive reversion pair landed. This family's three
	// bumps were all NON-additive: each rebound the MEANING of existing wire
	// content, which is the one thing an older document cannot survive. This adds
	// a key no previous document carries and changes the meaning of nothing.
	// Additive in the SAFE direction under either skew, and neither direction can
	// invent a release that was not authored: an old author never sets it, so a
	// new consumer reads no-opinion (today's behavior); an old consumer ignores
	// the key, so a new author's release is simply not executed (today's
	// behavior).
	ReleaseCurveAxes []string `json:"release_curve_axes,omitempty"`

	// Trips carries the trip/ride-through curve sets. Highest 1547 priority:
	// always passes through arbitration (D7 rule 3). Explicit null when the
	// active control links no ride-through curves.
	Trips *AdvTrips `json:"trips"`

	// Energize mirrors ActiveControl.Energize (opModEnergize — distinct from
	// connect). nil = no opinion (omitted), matching DesiredState's *T
	// convention for scalar opinions.
	Energize *bool `json:"energize,omitempty"`

	// SetGradW/SetSoftGradW are the DefaultDERControl-only ramp-rate defaults
	// (% of setMaxW per second, as decoded by the WP-8 publisher). nil on
	// event-sourced controls per the CSIP ramp-rate rule.
	SetGradW     *float64 `json:"set_grad_w,omitempty"`
	SetSoftGradW *float64 `json:"set_soft_grad_w,omitempty"`

	// RvrtTmsS is the computed device reversion window (C3): the authoring
	// hub's ValidUntil−serverNow clamped to [60 s, 24 h]; nil when the active
	// control carries no ValidUntil. Recomputed at every actual publish
	// (heartbeats refresh it); deliberately EXCLUDED from the author's
	// content-change comparison, like IssuedAt/Seq, so a ticking countdown
	// never forces a republish by itself.
	RvrtTmsS *int64 `json:"rvrt_tms_s,omitempty"`

	// RvrtVarSetPct/RvrtVarSetEna and RvrtPF/RvrtPFEna are RvrtTmsS's missing
	// DESTINATION on the two reactive axes this document can command (RC0 owner
	// ruling R-PF/Var, 2026-08-15) — the advanced family's counterpart to
	// DesiredState.RvrtSetpointW/RvrtCeilingW (IW13-004a).
	//
	// RvrtTmsS above arms a countdown on the DER. Until now nothing said where
	// that countdown LANDS the reactive axis, so expiry left the machine on
	// whatever PFWInjRvrt / VarSetPctRvrt already held — a factory default, or a
	// stale prior session, never a value this gateway chose. Model 704 carries
	// the registers for both (VarSetPctRvrt/VarSetEnaRvrt; the PFWInjRvrt and
	// PFWAbsRvrt sync groups with their own enables), so the ruling is to use
	// them.
	//
	// THE AUTHORITY RESOLVES THESE, the reconciler only writes them. The value
	// comes from the program's own DefaultDERControl (ActiveControl.
	// DefaultFallback's RvrtVarSetPct / RvrtPF — 2030.5's own answer to "what
	// does this DER do when no event applies"), and the arming bool is the
	// gateway's decision, taken only where a window is actually armed.
	//
	// nil/nil is NO OPINION — byte-identical to every document authored before
	// these fields existed, countdown-only. An explicit Ena=false with no value
	// is a DISARM: it switches the device's reversion function off for that
	// axis rather than leaving a destination standing that nobody currently
	// intends (IW13-004a-F7's shape, one family over).
	//
	// The PF pair is ONE field carrying magnitude AND excitation for the reason
	// stated at DefaultDERControlMsg: a magnitude without its excitation is not
	// a power factor, and making them one value is what stops the pair from
	// being separable in transit. Additive at DesiredAdvancedV=3 (AD-006).
	RvrtVarSetPct *float64 `json:"rvrt_var_set_pct,omitempty"`
	RvrtVarSetEna *bool    `json:"rvrt_var_set_ena,omitempty"`
	RvrtPF        *FixedPF `json:"rvrt_pf,omitempty"`
	RvrtPFEna     *bool    `json:"rvrt_pf_ena,omitempty"`

	// Source attributes the intent: "csip-event" | "csip-default" | "none"
	// (no active control — the all-null release document).
	Source string `json:"source"`
	// MRID is the active CSIP control this document derives from (CannotComply
	// attribution); empty when Source is "none".
	MRID string `json:"mrid,omitempty"`
	// IssuedAt/Seq are the AD-013 staleness/replay pair, same semantics as
	// DesiredState (Seq per device, resets on publisher restart, disambiguated
	// by IssuedAt).
	IssuedAt int64  `json:"issued_at"`
	Seq      uint64 `json:"seq"`

	// Unresolved is DesiredState.Unresolved's advanced-family sibling
	// (IW15-003): the authority holds a real advanced command but cannot yet
	// complete its TRANSLATION, because a reference the curve content resolves
	// against is not known to the gateway at this instant. It authored the
	// class-safe posture in place of content it cannot compute.
	//
	// nil-vs-value, stated at the field as the scalar sibling does: false (the
	// zero value, omitted from the wire) is a POSITIVE statement — "everything
	// this document commands is fully translated" — and it is also what a
	// legacy publisher's document decodes to, which is correct because a
	// publisher that predates the flag never authored an untranslated document.
	// true is a statement about the GATEWAY'S KNOWLEDGE, not about the device.
	//
	// WHY THE ADVANCED FAMILY NEEDS ONE AT ALL. It was argued, in
	// cmd/northbound's handleDesiredAdv, that it did not: "a curve document
	// carries raw breakpoints with no reference to resolve". That holds for
	// every curve model this product executes today (705 volt-var, 706
	// volt-watt, 712 watt-var) and for legacy 126/129-132. It STOPS being true
	// at SunSpec model 134, whose W<n> points are a percent of WRef — a device
	// register the gateway must resolve from settings, exactly the class of
	// reference IW15-003 exists for. Owner decision D2 puts 134 in RC0 scope.
	//
	// Contract, identical to the scalar flag's: the shell still LANDS the
	// document (the safe posture IS the containment) and stamps NO terminal;
	// this flag must never reach ControlHints. Its only consumer is
	// northbound's actuation-confirm gate, which treats the device as
	// UNCONFIRMABLE-YET — the event holds at Received and resolves either to
	// Started (once the real content is authored and readback-confirmed) or to
	// CannotComply at the confirm-window deadline. Never to Started off the
	// hold.
	//
	// It is deliberately DOC-SCOPED rather than per-axis. A per-axis
	// UnresolvedAxes list is the right long-term shape (the design's §3.3) and
	// lands with the executor that first needs it; the confirm gate's own
	// question today is per (class, device, axis) MEMBERSHIP with one
	// unresolved verdict per document, so a scalar is what it can actually
	// consume. Widening it later is additive.
	//
	// Additive at DesiredAdvancedV=1 (AD-006): a publisher that never sets it
	// leaves behavior byte-identical.
	Unresolved bool `json:"unresolved,omitempty"`

	// Gen is the per-device generation/epoch for the P1.4 transactional-actuation
	// device-replacement fence (SUN-001 §2.3 — GO-004's deferred P3.2 tail): the
	// advanced-overlay carrier of the SAME per-device generation the scalar
	// sibling DesiredState.Gen carries, so the scalar and adv paths fence one
	// physical device identity coherently. It is a MONOTONIC counter (lead ruling
	// D2) minted at device admit and bumped on every rebind of a physically-
	// replaced DER at the same name. Additive at DesiredAdvancedV=1 (AD-006): a
	// legacy adv author (pre-P1.4 cmd/hub/adv.go) never stamps it, so it decodes
	// to the zero value, and Gen==0 means UNFENCED — the WP-10 adv reconciler
	// keeps the pre-P1.4 (Seq,IssuedAt)-only staleness semantics unchanged. A
	// non-zero Gen opts the device into the generation fence, carried through
	// reconcile.DocMeta.Gen into reconcile.Config.CurrentGen exactly as the
	// scalar path does: an adv doc whose Gen is strictly OLDER than the
	// consumer's currently-bound generation is rejected, so a curve set ack'd for
	// inverter-0(gen 1) can never actuate on the physically-different
	// inverter-0(gen 2). Orthogonal to Seq: Seq fences replays/publisher-restart
	// within one device identity; Gen fences the identity itself. omitempty plus
	// the zero-decode keep it off the wire and unfenced for legacy documents.
	Gen uint64 `json:"gen,omitempty"`
}

// AdvReactiveMode reactive-power kinds (D6/D7 vocabulary).
//
// AdvReactiveWattVar means EXACTLY opModWattVar (sep 2.0.4 DERCurveType 10, y
// values a signed percentage under yRefType), executed against SunSpec model
// 712. It used to mean something else, and the correction is the point of
// decision D7 (lexa-gw docs/design/LEGACY_CURVES_RC0_2026-08-14.md §3.2): this
// comment previously recorded that "IEEE 2030.5's carriage for it is
// opModWattPF (Table 19 curveType 2 — y values are PF×100, not var)", i.e. a
// power-FACTOR curve was carried on the VAR axis and written into the var
// model. The two are different functions with different y units and different
// register homes, and the doc's carriage of CurveType did NOT save it: nothing
// downstream branched on CurveType, so 712 received PF numbers as vars.
//
// AdvReactiveWattPF is the fifth kind and carries opModWattPF under its own
// identity (paired 1:1 with bus.AdvAxisWattPF). Its only exact register home is
// legacy SunSpec model 131; a 7xx device answers CannotComply for it, and a
// 12x device answers CannotComply for watt_var. Neither generation has both.
//
// Adding a fifth kind does NOT add a second reactive carrier: ReactiveMode is
// still ONE field on DesiredAdvanced, so a reconciler still cannot observe torn
// multi-reactive state and mutual exclusivity remains structural.
const (
	AdvReactiveFixedPF  = "fixed_pf"
	AdvReactiveFixedVar = "fixed_var"
	AdvReactiveVoltVar  = "volt_var"
	AdvReactiveWattVar  = "watt_var"
	AdvReactiveWattPF   = "watt_pf"
)

// AdvReactiveMode is the single reactive-power axis of a DesiredAdvanced doc.
// Exactly one of the three payload fields is populated, selected by Kind:
// FixedPF for "fixed_pf", FixedVarPct for "fixed_var", Curve for
// "volt_var"/"watt_var"/"watt_pf".
type AdvReactiveMode struct {
	Kind string `json:"kind"` // AdvReactive* vocabulary above

	// FixedPF (kind "fixed_pf") reuses ActiveControl's FixedPF shape
	// ({pf, over_excited}). When a control carries BOTH opModFixedPFInjectW
	// and opModFixedPFAbsorbW the author keeps the inject half (the
	// generation-side setting) and alarms the absorb half as an ignored mode
	// — the doc has one fixed-PF slot by design (D6).
	FixedPF *FixedPF `json:"fixed_pf,omitempty"`

	// FixedVarPct (kind "fixed_var") is the signed % of setMaxVar, straight
	// from ActiveControl.FixedVarPct.
	FixedVarPct *float64 `json:"fixed_var_pct,omitempty"`

	// Curve (kind "volt_var" / "watt_var" / "watt_pf") is the resolved curve
	// content.
	Curve *AdvCurve `json:"curve,omitempty"`
}

// AdvCurve is one resolved curve on a DesiredAdvanced axis — the D6
// {curve_type, x_mult, y_mult, points≤10, hash} shape, carried verbatim from
// the matching CurveSetEntry (raw int32 breakpoints, multipliers never
// pre-applied — same reasoning as CurveSetEntry). YRefType is carried in
// addition to the D6-listed fields because it participates in the canonical
// content hash (CurveSetContentHash) — without it a reconciler could not
// recompute Hash from this doc + a device readback.
type AdvCurve struct {
	// CurveType is the DERCurveType code carried verbatim from CurveSetEntry —
	// IEEE Std 2030.5-2018 printed p.254, not the SEP 2.0.4 draft's "Table 19".
	// It is hashed into Hash below, which is why its 2026-08-15 rebind is a
	// DesiredAdvancedV = 3 bump and not a comment fix (bus/envelope.go).
	CurveType uint16       `json:"curve_type"`
	XMult     int8         `json:"x_mult,omitempty"`     // x-axis power-of-ten multiplier
	YMult     int8         `json:"y_mult,omitempty"`     // y-axis power-of-ten multiplier
	YRefType  uint8        `json:"y_ref_type,omitempty"` // DERUnitRefType, 2018 p.254 (0 = absent)
	Points    []CurvePoint `json:"points"`               // ordered (x, y) breakpoints, 1..10

	// OpenLoopTms is the curve's open-loop response time, carried verbatim from
	// the matching CurveSetEntry.OpenLoopTms — 2018 p.253, hundredths of a
	// second, nil when the server sent none, 0 meaning "no limit". Read that
	// field's doc for why absence and zero must stay distinguishable and why this
	// is therefore a pointer rather than a zero-sentinel uint16.
	//
	// IT IS ON THIS TYPE FOR TWO INDEPENDENT REASONS, either of which alone would
	// be sufficient:
	//
	//   - EXECUTION. THIS document is what the reconciler writes registers from,
	//     so a value that reaches CurveSet and stops there is discarded. That is
	//     exactly what happened, and is the bench-proven MEDIUM this field closes:
	//     lexa-gw's vvFromDoc starts from the template it read back from the
	//     DEVICE and overwrites only DeptRef and Points, so RspTms kept whatever
	//     the DER already held under every commanded curve.
	//
	//     ITS REGISTER HOME IS PER-AXIS, not one register — a distinction worth
	//     stating because "the 705 RspTms" is how the defect was reported and it
	//     is only true of the axis it was found on. Each curve model carries its
	//     own response time: model 705's RspTms for volt-var, 706's for
	//     volt-watt, in SECONDS, so the served hundredths are divided by 100. Two
	//     axes have no home for it at all and a writer must not invent one — the
	//     TRIP models (707-710) carry Tms, a trip-CLEARING time, which is a
	//     different quantity entirely; and freq-watt has no executing 7xx curve
	//     model in this product at all, existing in the vocabulary only so the
	//     axis can be NAMED and reported unsupported (see the AdvAxis* block in
	//     messages.go). Carrying the field on every AdvCurve is still correct:
	//     the hash needs it uniformly (below), and an axis with no register home
	//     simply does not write it.
	//   - HASH RECOMPUTATION. Hash below is CurveSetContentHash over the entry
	//     this curve was resolved from, and openLoopTms is now one of that line's
	//     inputs. A consumer rebuilding the entry from this document (lexa-gw's
	//     advEntry) cannot reproduce Hash without the field, so every curve axis
	//     would fail its own self-consistency check and be refused.
	//
	// This is the difference from VRef, which is deliberately NOT on this type:
	// vRef is folded into Points by the authority before this document is
	// authored, so the recomputation never needs it. A response time cannot be
	// folded into a breakpoint.
	OpenLoopTms *uint16 `json:"open_loop_tms,omitempty"`

	// Hash is CurveSetContentHash over the single canonical CurveSetEntry this
	// curve was resolved from (mode|curveType|mults|yRef|vRef|openLoopTms|points)
	// — the per-axis no-op re-adoption key (D6), echoed back on the WP-10
	// ReconcileReport as curve_hash.
	Hash string `json:"hash"`
}

// releasableCurveAxes is the CLOSED SET DesiredAdvanced.ReleaseCurveAxes may
// name. Membership is not "is this a curve axis" — it is a much narrower
// question: IS THIS AN AXIS WHOSE NULL CANNOT ALREADY CARRY A RELEASE? Today
// exactly one axis qualifies.
//
// freq_watt IS IN, because its null is deliberately reserved for no-opinion. The
// consumer's own branch cites LEGACY_CURVES_RC0_2026-08-14.md §2.8's three-state
// table, which puts model 134 in the "no write" column for a commanded release
// and says "Only 126, 131 and 132 are releasable on legacy": "the release of an
// opModFreqWatt control means 'this control no longer applies', which is not the
// same instruction as 'turn frequency response off'. Frequency response is a
// standing grid-support function the head end did not author and a released
// control does not repeal." With the null spoken for, a flag is the only channel
// left, and its ratified execution is to write nothing — the flag buys an honest
// Response, not a register write.
//
// volt_var, watt_pf AND volt_watt ARE DELIBERATELY OUT, and this paragraph
// exists so a future reader cannot re-add them without meeting the argument.
// THEIR NULL IS ALREADY THEIR RELEASE. DesiredAdvanced's type doc states the
// rule — "an un-commanded axis is an EXPLICIT null (a release command: 'no
// <axis> in force'), never an absent key" — and the consumer implements it:
// volt_var and watt_pf default to release() and are overridden only by content,
// volt_watt is release() on null, and release() is executed by
// executeReleaseLocked, which verifies-then-disables the axis function (Ena=0).
// Adding them here would create a SECOND channel able to disagree with the first
// in the ordinary direction: a null volt_watt with no flag set still releases,
// while ReleasesCurveAxis would answer false. A consumer that read the flag
// instead of the null would silently regress three working axes. P4's defect on
// those three was that the AUTHORITY never learned of the release (the decode
// dropped the nil); that is fixed upstream, not here.
//
// Nothing else is a candidate either: watt_var's home is 712, a 7xx model
// outside the legacy family; the trip axes are protection boundaries, where
// withdrawal is a different decision with a different owner; fixed_pf, fixed_var
// and energize are not curve axes; and freq_droop already has ReleaseFreqDroop.
//
// ADDING A NAME HERE IS NOT A FREE ACTION. It asserts two things: that the
// axis's null is genuinely unavailable as a release channel (or the flag is a
// duplicate), and that an older consumer ignoring the name — leaving that axis
// standing — is an acceptable outcome for it. That is why this is a closed
// literal pinned by a test rather than a filter over AdvAxis*.
var releasableCurveAxes = map[string]bool{
	AdvAxisFreqWatt: true,
}

// withdrawableCurveAxes is the closed set ActiveControl.ReleasedCurveAxes may
// name: the four curve axes whose DERCurveLink a nil marker can arrive on —
// volt_var (legacy model 126), watt_pf (131), volt_watt (132), freq_watt (134).
//
// IT IS DELIBERATELY WIDER THAN releasableCurveAxes, AND THE TWO MUST NOT BE
// MERGED. This set answers "what can the wire carry" — a decoder question, fixed
// by which links 2030.5 lets a server nil. releasableCurveAxes answers "what does
// the gateway act on with a FLAG rather than a null" — a policy question, whose
// answer is freq_watt alone because the other three are already released by their
// own null. Merging them breaks whichever side moves: narrow this one and the
// disclosure is lost at the only layer that can see it; widen that one and a flag
// becomes a second release channel able to disagree with the null. See
// ActiveControl.ReleasedCurveAxes for the carriage/policy division, and
// TestWithdrawableAndReleasableAreDeliberatelyDifferentSets for the guard.
//
// watt_var is absent for the same reason it is absent from the releasable set:
// its home is 712, a 7xx model outside the legacy curve family. The trip axes
// carry ride-through curves, not DERCurveLink control curves, and freq_droop is
// not a curve link at all.
var withdrawableCurveAxes = map[string]bool{
	AdvAxisVoltVar:  true,
	AdvAxisVoltWatt: true,
	AdvAxisWattPF:   true,
	AdvAxisFreqWatt: true,
}

// WithdrawableCurveAxes returns the closed set of axis names
// ActiveControl.ReleasedCurveAxes may carry, as a fresh slice the caller may
// keep or sort. Order is not significant and is not guaranteed.
func WithdrawableCurveAxes() []string {
	out := make([]string, 0, len(withdrawableCurveAxes))
	for axis := range withdrawableCurveAxes {
		out = append(out, axis)
	}
	sort.Strings(out)
	return out
}

// IsWithdrawableCurveAxis reports whether axis is one a curve-link nil marker
// can name on the wire. This is the CARRIAGE question; IsReleasableCurveAxis is
// the POLICY one, and they deliberately differ.
func IsWithdrawableCurveAxis(axis string) bool { return withdrawableCurveAxes[axis] }

// ReleasableCurveAxes returns the closed set of axis names
// DesiredAdvanced.ReleaseCurveAxes may name, as a fresh slice the caller may
// keep or sort. Order is not significant and is not guaranteed.
func ReleasableCurveAxes() []string {
	out := make([]string, 0, len(releasableCurveAxes))
	for axis := range releasableCurveAxes {
		out = append(out, axis)
	}
	sort.Strings(out)
	return out
}

// IsReleasableCurveAxis reports whether axis is one this flag may withdraw.
func IsReleasableCurveAxis(axis string) bool { return releasableCurveAxes[axis] }

// ReleasesCurveAxis reports whether this document EXPLICITLY WITHDRAWS the named
// curve axis. It is the only question a consumer should ask about
// ReleaseCurveAxes, and it is deliberately total — every rejection case answers
// false rather than erroring, because "not released" is the safe, no-opinion
// posture in all of them:
//
//   - the axis is not named: no opinion, the no-strip default;
//   - the axis is named but is not a releasable curve axis (an unrecognized
//     name, or a real axis outside the closed set): ignored, per the field doc's
//     refuse-vs-ignore argument;
//   - the axis is named AND this same document carries content for it: content
//     wins, because honouring a withdrawal of an axis the document is actively
//     commanding is the strip the no-strip rule forbids.
//
// A consumer must never infer a release from a null axis. That is the whole
// point of the flag; see the field doc and, above it, ReleaseFreqDroop's "WHY A
// FLAG AND NOT A RULE THE CONSUMER COULD INFER".
func (d DesiredAdvanced) ReleasesCurveAxis(axis string) bool {
	if !releasableCurveAxes[axis] {
		return false
	}
	named := false
	for _, a := range d.ReleaseCurveAxes {
		if a == axis {
			named = true
			break
		}
	}
	if !named {
		return false
	}
	return !d.commandsCurveAxis(axis)
}

// commandsCurveAxis reports whether this document carries curve CONTENT for the
// named axis — the contradiction guard behind ReleasesCurveAxis. The two
// reactive-carried axes are read through ReactiveMode, which is one field by
// design (mutual exclusivity is structural, see the type doc), so at most one of
// them can ever be commanded at a time.
func (d DesiredAdvanced) commandsCurveAxis(axis string) bool {
	switch axis {
	case AdvAxisVoltWatt:
		return d.VoltWatt != nil
	case AdvAxisFreqWatt:
		return d.FreqWatt != nil
	case AdvAxisVoltVar:
		return d.ReactiveMode != nil && d.ReactiveMode.Kind == AdvReactiveVoltVar && d.ReactiveMode.Curve != nil
	case AdvAxisWattPF:
		return d.ReactiveMode != nil && d.ReactiveMode.Kind == AdvReactiveWattPF && d.ReactiveMode.Curve != nil
	}
	return false
}

// AdvFreqDroop carries frequency-droop parameters in SunSpec model 711 Ctl
// vocabulary (DbOf/DbUf/KOf/KUf/OlrtS — the registers WP-10's
// derbase.WriteFreqDroop writes), converted by the authoring hub from the
// 2030.5 opModFreqDroop parameters (csipmodel.FreqDroop, carried on
// DERScheduleSlot.FreqDroop — see cmd/hub/adv.go's droopFromSchedule for the
// conversion and its 60 Hz nominal-frequency assumption).
type AdvFreqDroop struct {
	DbOfHz float64 `json:"dbof"`   // over-frequency dead band (Hz)
	DbUfHz float64 `json:"dbuf"`   // under-frequency dead band (Hz)
	KOf    float64 `json:"kof"`    // over-frequency per-unit droop slope
	KUf    float64 `json:"kuf"`    // under-frequency per-unit droop slope
	OlrtS  float64 `json:"olrt_s"` // open-loop response time (s)
}

// Adv trip-curve kinds (AdvTripCurve.Kind).
const (
	AdvTripMustTrip           = "must_trip"
	AdvTripMayTrip            = "may_trip"
	AdvTripMomentaryCessation = "momentary_cessation"
)

// AdvTrips groups the trip/ride-through curve sets by axis (D6:
// trips{lv,hv,lf,hf}). An axis with no commanded curves is omitted (the
// whole Trips field is an explicit null when NO axis has curves).
type AdvTrips struct {
	LV *AdvTripSet `json:"lv,omitempty"` // low-voltage ride-through (LVRT*)
	HV *AdvTripSet `json:"hv,omitempty"` // high-voltage ride-through (HVRT*)
	LF *AdvTripSet `json:"lf,omitempty"` // low-frequency ride-through (LFRT*)
	HF *AdvTripSet `json:"hf,omitempty"` // high-frequency ride-through (HFRT*)
}

// AdvTripSet is one trip axis's curves (≤3: must-trip, may-trip, momentary
// cessation — the LF/HF axes have no momentary-cessation mode in 2030.5) plus
// the axis-level content hash (CurveSetContentHash over the axis's canonical
// entries), the WP-10 re-adoption key for the whole set.
type AdvTripSet struct {
	Curves []AdvTripCurve `json:"curves"`
	Hash   string         `json:"hash"`
}

// AdvTripCurve is one ride-through curve bound to its trip kind.
type AdvTripCurve struct {
	Kind  string   `json:"kind"` // AdvTrip* vocabulary above
	Curve AdvCurve `json:"curve"`
}

// VersionAcceptable reports whether this DECODED document is one this build may
// ACT ON: at or above DesiredAdvancedMinV.
//
// It exists as a method rather than as three copies of `doc.V >= 2` because
// three separate processes subscribe to lexa/desired/adv — the reconciler that
// writes registers, the northbound gate that answers the head end, and the
// authority's boot re-seed — and a floor that only two of them apply is a floor
// that does not exist.
//
// mqttutil's decode path already enforces the CEILING (CheckVersion drops a
// document newer than this build understands). This is the other end, and it is
// the one the family needs: see DesiredAdvancedMinV for why accepting an older
// adv document is unsafe when it is safe everywhere else.
//
// NOT for the re-seed path. cmd/mode's PreseedAdv re-adopts only the LATCH —
// "a retained document exists for this device and it commands something" — and
// never the content. A stale document still proves the latch, and dropping it
// there would make a curve the head end has withdrawn unreleasable for the life
// of the process, which is the defect PreseedAdv exists to close. The refusal
// belongs where content is ACTED ON.
func (d DesiredAdvanced) VersionAcceptable() bool { return d.V >= DesiredAdvancedMinV }

// DesiredAdvTopic returns the retained advanced desired-state topic for a
// device (D6): lexa/desired/adv/{device}. "adv" occupies the {class} segment
// of the AD-013 desired-topic shape, so DeviceFromDesiredTopic extracts the
// device and the modbus/ocpp scalar reconcilers' class dispatch ignores these
// docs untouched (WP-10 is the first consumer).
func DesiredAdvTopic(device string) string {
	return "lexa/desired/adv/" + device
}

// SubDesiredAdv matches every retained advanced desired-state document
// (WP-10's cmd/modbus adv shell subscribes this; ACL rows in
// systemd/mosquitto-lexa.acl grant hub write / modbus read on it).
const SubDesiredAdv = "lexa/desired/adv/+"

// Finite is DesiredAdvanced's counterpart to Measurement.Finite (GAP-09):
// every *float64 (and the always-present droop parameters and FixedPF.PF) is
// checked. Curve breakpoints are raw int32 pairs — nothing to check there.
func (d DesiredAdvanced) Finite() error {
	if err := finite("set_grad_w", d.SetGradW); err != nil {
		return err
	}
	if err := finite("set_soft_grad_w", d.SetSoftGradW); err != nil {
		return err
	}
	if rm := d.ReactiveMode; rm != nil {
		if err := finite("reactive_mode.fixed_var_pct", rm.FixedVarPct); err != nil {
			return err
		}
		if rm.FixedPF != nil {
			if err := finiteVal("reactive_mode.fixed_pf.pf", rm.FixedPF.PF); err != nil {
				return err
			}
		}
	}
	// The reversion ALTERNATE's numbers get the same gate as the primaries', and
	// it matters more here rather than less: an armed destination is not read
	// back by anything until the countdown fires, so a NaN that reached a
	// register would surface as a machine doing something inexplicable, alone,
	// at the moment the gateway is gone.
	if err := finite("rvrt_var_set_pct", d.RvrtVarSetPct); err != nil {
		return err
	}
	if d.RvrtPF != nil {
		if err := finiteVal("rvrt_pf.pf", d.RvrtPF.PF); err != nil {
			return err
		}
	}
	if fd := d.FreqDroop; fd != nil {
		for _, f := range []struct {
			name string
			v    float64
		}{
			{"freq_droop.dbof", fd.DbOfHz},
			{"freq_droop.dbuf", fd.DbUfHz},
			{"freq_droop.kof", fd.KOf},
			{"freq_droop.kuf", fd.KUf},
			{"freq_droop.olrt_s", fd.OlrtS},
		} {
			if err := finiteVal(f.name, f.v); err != nil {
				return err
			}
		}
	}
	return nil
}
