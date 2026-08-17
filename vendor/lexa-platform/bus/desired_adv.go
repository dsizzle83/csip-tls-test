// Promoted from lexa-hub@5218e6a (2026-07-17)

package bus

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
