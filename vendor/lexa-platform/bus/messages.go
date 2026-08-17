// Promoted from lexa-hub@5218e6a (2026-07-17)

package bus

// Measurement is published by the modbus service for each device poll.
// Pointer fields are omitted when the device does not report that quantity.
//
// The voltage field is named VoltageV (wire key "voltage_v"), not V/"v": this
// type is one of the ~15 top-level published types that embeds Envelope
// (TASK-018), and Envelope's own field is also named V with wire key "v" (the
// schema version). Go's JSON encoder resolves same-key conflicts between an
// embedded field and the struct's own field by depth — the shallower (own)
// field silently wins and the embedded one is dropped from the wire
// entirely — so keeping this field as V/"v" would have made every
// Measurement publish appear to stamp a version while actually never
// emitting "v" at all (verified: internal/bus/envelope_test.go's collision
// case). VoltageV/"voltage_v" also matches the naming EVSEState already
// uses for the same physical quantity, so this aligns Measurement with the
// existing convention rather than inventing a new one. Every caller that
// read/wrote the old V field (cmd/modbus, cmd/hub, cmd/api, cmd/telemetry)
// is updated in the same change; there is no other reader of the old wire
// key "v" as voltage to migrate.
type Measurement struct {
	Envelope
	Device   string   `json:"device"`
	W        *float64 `json:"w,omitempty"`         // net power (W): + discharge/gen, - charge/load
	VoltageV *float64 `json:"voltage_v,omitempty"` // voltage (V)
	Hz       *float64 `json:"hz,omitempty"`        // frequency (Hz)

	// WP-2 (A1) enrichment — additive optional fields at V=1 (AD-006: an old
	// subscriber ignores the unknown keys; a new subscriber reading an old
	// publisher sees them nil-absent). Every *float64 here is covered by
	// Measurement.Finite (GAP-09). Sources: inverter/battery via
	// derbase.Measurements (701 or legacy 10x), meter via models 201/203;
	// a device that lacks a quantity leaves the field nil — never fabricated
	// (G27). The Wh totals are lifetime accumulators, monotonic non-decreasing
	// per device; cmd/modbus withholds a sample that moves backwards
	// (scale-factor/register-wrap suspicion — see whMonotonicGate there).
	VarW       *float64 `json:"var_w,omitempty"`        // reactive power (VAr), + = injecting/capacitive (device convention)
	VA         *float64 `json:"va,omitempty"`           // apparent power (VA)
	PF         *float64 `json:"pf,omitempty"`           // power factor [-1, 1]
	OpState    *uint16  `json:"op_state,omitempty"`     // 701 St (or 103 St mapped); operational state enum
	ConnState  *uint16  `json:"conn_state,omitempty"`   // 701 ConnSt bitfield
	AlarmBits  *uint32  `json:"alarm_bits,omitempty"`   // 701 Alrm bitfield (raw; mapping to CSIP Table 14 happens hub-side)
	WhImpTotal *float64 `json:"wh_imp_total,omitempty"` // lifetime import energy (Wh) — meter TotWhImp / 701 TotWhAbs
	WhExpTotal *float64 `json:"wh_exp_total,omitempty"` // lifetime export energy (Wh) — meter TotWhExp / 701 TotWhInj

	// Per-phase / line-to-line voltage carriage — additive optional fields at
	// MeasurementV=1 (AD-006: an old subscriber ignores the unknown keys; a
	// new subscriber reading an old publisher sees them nil-absent). This
	// follows VoltageV's pointer convention exactly — nil = absent-from-device,
	// never fabricated (G27) — NOT the DERSiteStatus.InverterStatus plain-value
	// pattern: that pattern is for enums with a legitimate zero floor, and a
	// voltage has none. A device that does not report a given quantity (e.g. a
	// single-phase meter has no L2/L3) leaves that field nil rather than a
	// fabricated zero. Units are volts throughout: VL1/VL2/VL3 are per-phase
	// line-to-neutral (L-N); VL1L2/VL2L3/VL3L1 are line-to-line (L-L); LLV is
	// the average line-to-line voltage. Source: downstream SunSpec 701 mirror.
	// Every *float64 here is covered by Measurement.Finite (GAP-09).
	LLV   *float64 `json:"llv,omitempty"`   // average line-to-line voltage (V)
	VL1L2 *float64 `json:"vl1l2,omitempty"` // line-to-line voltage, L1-L2 (V)
	VL1   *float64 `json:"vl1,omitempty"`   // per-phase line-to-neutral voltage, L1 (V)
	VL2L3 *float64 `json:"vl2l3,omitempty"` // line-to-line voltage, L2-L3 (V)
	VL2   *float64 `json:"vl2,omitempty"`   // per-phase line-to-neutral voltage, L2 (V)
	VL3L1 *float64 `json:"vl3l1,omitempty"` // line-to-line voltage, L3-L1 (V)
	VL3   *float64 `json:"vl3,omitempty"`   // per-phase line-to-neutral voltage, L3 (V)

	// CommLoss is the single comm-loss truth for a device (lexa-gw C7,
	// design 04 A.3): true when cmd/modbus has had no fresh read for >3 poll
	// periods. Additive optional field at V=1 (AD-006: an old subscriber
	// ignores it; a new subscriber reading an old publisher sees false).
	// Consumers derive staleness from THIS flag, not their own local timers:
	// the mbaps register projection (lexa-gw regmap) sets the SunSpec Alrm
	// comm-loss bit from it, and lexa-telemetry marks CSIP telemetry stale
	// from the same source — one flag, no divergent staleness windows.
	CommLoss bool `json:"comm_loss,omitempty"`

	// ── Measurement quality (RMD-024, closes IW4-003) ────────────────────────
	//
	// CommLoss above answers "did the poll reach the device". These two answer
	// the question it cannot: "do the values in this message describe the
	// device's PRESENT state". A device serving one frozen register block
	// forever answers every poll, so CommLoss is false for it, and before these
	// fields existed the producer republished the unchanged frozen values with a
	// brand-new Ts — indistinguishable, to every subscriber, from a new sample.
	// That is the whole of IW4-003: an operator or utility could not tell
	// whether status and measured output described the present.
	//
	// Additive at MeasurementV=1 (AD-006), NOT a version bump, and the choice is
	// deliberate: bumping the family version would make every subscriber that
	// has not yet learned these keys REJECT the message outright (CheckVersion),
	// which turns a partial upgrade into a total measurement blackout across the
	// fleet. Degrading is what a compatibility contract is for; rejecting is not.
	//
	// ── The compatibility rule, and why the vocabulary is a string ────────────
	//
	// The single rule this schema is built to make unbreakable: ABSENT QUALITY
	// IS UNKNOWN, NEVER FRESH. A `Stale bool` cannot express that — omitempty
	// makes absent and false the same bytes, so every legacy publisher would
	// arrive claiming "not stale", which is precisely the lie being fixed. A
	// string vocabulary with "" as its own member does express it, so that is
	// what this is.
	//
	// Both skew directions, stated rather than assumed:
	//
	//   - NEW consumer, OLD publisher: Quality decodes to QualityUnknown. The
	//     Stale() predicate is false (this consumer was told nothing, and
	//     inventing a suspicion it was not told about would withhold real data),
	//     and FreshnessProven() is ALSO false (nothing was established). So an
	//     unknown-quality sample behaves exactly as it did before this field
	//     existed — no regression — and no surface may render it as "fresh".
	//
	//     THE TWO JOBS SPLIT HERE, and RMD-027 is where the split was forced.
	//     SERVING and MARKING key on Stale(), for the reason above: an absent
	//     verdict must not be turned into a fabricated suspicion that withholds
	//     real data. RELEASING a safety condition keys on FreshnessProven(), and
	//     that is NOT a compatibility break, because every such condition is a
	//     LATCH THAT ONLY A POSITIVE SUSPICION CAN ARM. A publisher that never
	//     says `suspect` never arms one, so it never has one to clear, and its
	//     data flows exactly as before. The only publisher affected is one that
	//     said `suspect` and then stopped supplying verdicts at all — a
	//     mid-episode downgrade — and holding containment through that is the
	//     answer RMD-029 gives on purpose: evidence lost is not evidence of
	//     recovery. This comment previously argued the opposite ("keying a
	//     safety-condition CLEAR on positive freshness proof would leave a new
	//     consumer paired with an old publisher permanently unable to clear
	//     anything"); it was reasoning about a clear that could be reached
	//     without an arm, which no RMD-024 consumer has.
	//   - OLD consumer, NEW publisher: the unknown keys are ignored (the
	//     ordinary additive case) and that consumer keeps serving a suspect
	//     value as current. NOTHING IN THE WIRE FORMAT CAN FIX THAT, and saying
	//     so here is the honest statement of the residual: it is why RMD-024
	//     updates every in-repo consumer in the same wave rather than shipping
	//     the field and waiting.

	// Quality is the PRODUCER's verdict on this sample, from the vocabulary
	// below ("" = no verdict — see the compatibility rule above). It is the
	// bus projection of the gateway's per-device freshness tracker
	// (lexa-gw cmd/modbus/freshness.go): assessing / fresh / suspect /
	// unverifiable.
	Quality string `json:"quality,omitempty"`

	// LastMovedAt is the LAST-GOOD TIME: the Unix second at which the producer
	// last POSITIVELY ESTABLISHED that this device's own measurement block
	// moved — i.e. the last instant these values are known to have described
	// the machine. 0 = never established (a device frozen since the producer
	// started, a device that offers no assessable point, or a legacy
	// publisher).
	//
	// It is an ABSOLUTE INSTANT rather than an age in seconds on purpose: an
	// age is already wrong by the time a subscriber reads it, and a retained or
	// replayed message would carry an age that keeps looking current forever.
	// AgeS() below turns it into an age against the reader's own clock.
	//
	// THIS — not Ts — is the field a consumer publishing a "reading time"
	// northbound must use. Ts is the GATEWAY POLL INSTANT and always has been:
	// a true statement about when this gateway performed the read, and NOT a
	// device sample time (SunSpec measurement models carry no sample time at
	// all, which is the root of IW4-003). A consumer that reads Ts as "when
	// this value was measured" republishes frozen data as current; a consumer
	// that reads LastMovedAt cannot.
	LastMovedAt int64 `json:"last_moved_at,omitempty"`

	Ts int64 `json:"ts"` // Unix seconds — the GATEWAY POLL INSTANT (see LastMovedAt)
}

// Measurement.Quality vocabulary (RMD-024). The empty string is a deliberate
// member, not a missing case: it is what a legacy publisher — and a publisher
// that ran no assessment for this sample — produces, and it must never be
// read as fresh (see Measurement's compatibility rule).
const (
	// QualityUnknown is "no verdict was supplied". Not fresh, not suspect.
	QualityUnknown = ""
	// QualityAssessing is "a verdict was run and it is NOT YET EITHER ANSWER":
	// the producer has this device under assessment and has not (yet) observed
	// its measurement block move, but the block has also not been still long
	// enough — or is not the kind of block — to suspect it.
	//
	// It is the RMD-027 member, and it exists because "not yet suspect" was
	// being published as `fresh`. The producer's first sample of a device has
	// nothing to compare against, and a sample still inside the suspicion
	// window is, in that producer's own words, "not yet evidence of anything";
	// both were wire-`fresh` while LastMovedAt stayed 0, so the two fields
	// contradicted each other and a service restart over a frozen device
	// published a proof it did not have (IW5-002).
	//
	// WHAT A CONSUMER DOES WITH IT: exactly what it does with QualityUnknown.
	// Not stale (nothing has been positively suspected, so nothing may be
	// withheld or masked on its account) and not proven (nothing has been
	// positively established, so it may not RELEASE a safety condition). It is
	// distinct from QualityUnknown on the wire only so an operator surface can
	// say "this gateway is watching this device and has not concluded yet"
	// rather than "nobody checked" — which is a different sentence about a
	// different situation, and collapsing the two is the conflation RMD-024
	// removed in the other direction.
	QualityAssessing = "assessing"
	// QualityFresh is "the producer POSITIVELY ESTABLISHED that this device's
	// measurement block is moving" — it observed the block change between two
	// of its own samples. It is never a default, never an initial state, and
	// never the answer to "nothing looks wrong yet": those are QualityAssessing.
	//
	// A `fresh` sample therefore ALWAYS carries a non-zero LastMovedAt (the
	// instant of that establishment), and the pair is the whole contract: a
	// consumer that finds fresh with LastMovedAt=0 is talking to a producer
	// that predates RMD-027 and is asserting freshness it did not prove.
	QualityFresh = "fresh"
	// QualitySuspect is "every free-running measurement point has been
	// bit-identical across the producer's whole suspicion window; this sample
	// may not describe the device's present state".
	QualitySuspect = "suspect"
	// QualityUnverifiable is "this device offers no evidence of the kind the
	// freshness test consumes" — no implemented free-running point, or an idle
	// device with no thermal point to corroborate. It is NOT a soft suspect:
	// condemning a device class for what it does not implement is the mistake
	// this third verdict exists to avoid, so consumers treat it as unknown for
	// gating and disclose it verbatim for operators.
	QualityUnverifiable = "unverifiable"
)

// Stale reports that the producer POSITIVELY DETERMINED this sample may not
// describe the device's present state.
//
// THE MARKING GATE. Every RMD-024 consumer decision that ASSERTS something —
// marks a value, withholds a reading, masks a register, refuses to clear an
// alarm, ARMS a containment — keys on this predicate and on no other. An
// unknown, assessing or unverifiable quality is deliberately NOT stale: see
// Measurement's compatibility rule for why an absent or inconclusive verdict
// must degrade to the pre-fix behaviour rather than to a fabricated suspicion.
//
// It is NOT the release gate. Its negation is "nobody has positively suspected
// this", which is a much weaker statement than "this is current" and was being
// used for both (IW5-002). To RELEASE, see FreshnessProven.
func (m Measurement) Stale() bool { return m.Quality == QualitySuspect }

// FreshnessProven reports that the producer POSITIVELY ESTABLISHED that this
// sample is current — it watched this device's own measurement block move.
// Unknown, assessing and unverifiable are all NOT proven, which is the
// "never = fresh" half of the compatibility rule expressed as a predicate so
// no consumer has to re-derive it.
//
// THE RELEASE GATE (RMD-027). Any consumer action that RELEASES a safety
// condition — clearing a protective interlock, emitting an alarm
// return-to-normal, clearing an offline/masked projection, removing a device
// from a stale-source list — must require this and not merely !Stale().
// !Stale() is satisfied by a producer's very first sample of a device, which
// is exactly what a still-frozen device presents after a service restart, so
// gating a release on it lets a restart over frozen data clear protection that
// standing evidence armed.
//
// The direction is deliberately asymmetric, and cheaply so: ARMING on a
// suspicion that turns out to be wrong costs one avoidable containment;
// RELEASING on an absence of suspicion that turns out to be wrong costs the
// containment that was holding a real fault.
//
// It is also the DISCLOSURE predicate (an operator surface saying "this
// reading is proven current"), which is what it was originally added for.
func (m Measurement) FreshnessProven() bool { return m.Quality == QualityFresh }

// AgeS returns how many seconds old the last positively-established movement
// is at now (both Unix seconds), and whether that is known at all. ok=false
// means LastMovedAt was never stamped — a legacy publisher, or a device whose
// block has not been shown to move since the producer started; a caller must
// render that as UNKNOWN, never as age 0.
//
// A negative difference (a clock step between producer and consumer, or a
// consumer whose clock lags) is clamped to 0 rather than reported: an age is
// never negative, and a "-4 s old" reading on an operator surface reads as a
// bug in this gateway rather than as the clock skew it is.
func (m Measurement) AgeS(now int64) (int64, bool) {
	if m.LastMovedAt == 0 {
		return 0, false
	}
	age := now - m.LastMovedAt
	if age < 0 {
		age = 0
	}
	return age, true
}

// BattMetrics is published by the modbus service for battery-role devices after
// each successful SunSpec battery metrics read.
type BattMetrics struct {
	Envelope
	Device        string   `json:"device"`
	SOC           *float64 `json:"soc_pct,omitempty"`
	SOH           *float64 `json:"soh_pct,omitempty"`
	CapacityWh    *float64 `json:"capacity_wh,omitempty"`
	MaxChargeW    *float64 `json:"max_charge_w,omitempty"`
	MaxDischargeW *float64 `json:"max_discharge_w,omitempty"`
	Ts            int64    `json:"ts"`
}

// ActiveControl is published by the csip service after every discovery walk.
// Watt values already have the IEEE 2030.5 ActivePower multiplier applied.
// Source is "event", "default", or "none" (no programs / no active control).
//
// WP-8 (standards-buildout C1, architecture §2.2) added the advanced-control
// scalars below — additive optional fields at ActiveControlV=1 (AD-006: an
// old subscriber ignores the unknown keys; a new subscriber reading an old
// publisher sees them nil-absent). Curve CONTENT does not ride this message —
// it rides the separate retained CurveSet doc on TopicCSIPCurves (D6/§2.3),
// referenced here only by CurveSetID — so this doc stays small and the
// TASK-042 retained-control staleness/rewalk machinery is untouched.
type ActiveControl struct {
	Envelope
	Source  string   `json:"source"`
	MRID    string   `json:"mrid,omitempty"`
	Connect *bool    `json:"connect,omitempty"`
	ExpLimW *float64 `json:"exp_lim_w,omitempty"` // export limit (W)
	ImpLimW *float64 `json:"imp_lim_w,omitempty"` // import limit (W)
	// MaxLimWPct is opModMaxLimW, decoded to unsigned percent of setMaxW
	// (IW13-001; docs/design/IW13_ACTIVE_POWER_UNITS_2026-08-12.md §2.3) —
	// per-DER, resolved to watts per device by internal/authority/csipin.go,
	// never here. Range [0,100]. Was *float64 watts ("max_lim_w"); the old
	// field's meaning was never valid (the wire axis was always percent), so
	// it is renamed+retyped, not kept alongside a new one — csipin.go is
	// confirmed the only production consumer.
	MaxLimWPct *float64 `json:"max_lim_w_pct,omitempty"`
	// FixedWPct is opModFixedW, decoded to signed percent (not hundredths —
	// already divided by 100, matching FixedVarPct's own convention below):
	// +60.0 = 60% of setMaxW/setMaxDischargeRateW (discharge), -60.0 = 60% of
	// setMaxChargeRateW (charge). Per-DER — see
	// docs/design/IW13_ACTIVE_POWER_UNITS_2026-08-12.md §3. Range [-100,100].
	// Was *float64 watts ("fixed_w"); same rename+retype reasoning as
	// MaxLimWPct above.
	FixedWPct   *float64 `json:"fixed_w_pct,omitempty"`
	ClockOffset int64    `json:"clock_offset"`          // server_time − local_time (s)
	ValidUntil  int64    `json:"valid_until,omitempty"` // Unix seconds; 0 = no expiry

	// WP-8 additive advanced-control scalars (architecture §2.2, normative
	// names/types). All *float64 fields participate in Finite() (GAP-09).
	Energize      *bool    `json:"energize,omitempty"`        // opModEnergize (distinct from connect)
	GenLimW       *float64 `json:"gen_lim_w,omitempty"`       // opModGenLimW (gross generation cap — CSIP-AUS)
	LoadLimW      *float64 `json:"load_lim_w,omitempty"`      // opModLoadLimW (gross load cap — CSIP-AUS)
	TargetW       *float64 `json:"target_w,omitempty"`        // opModTargetW (parse-through; enforcement TBD)
	FixedPFInject *FixedPF `json:"fixed_pf_inject,omitempty"` // opModFixedPFInjectW
	FixedPFAbsorb *FixedPF `json:"fixed_pf_absorb,omitempty"` // opModFixedPFAbsorbW
	FixedVarPct   *float64 `json:"fixed_var_pct,omitempty"`   // opModFixedVar, signed % of setMaxVar

	// FreqDroop carries opModFreqDroop VERBATIM from DERControlBase, in IEEE
	// 2030.5 units (see FreqDroopIntent). nil = the control commands no
	// frequency droop; a non-nil value ALWAYS carries all five elements,
	// because sep 2.0.4's FreqDroopType declares every one of them
	// minOccurs="1" — there is no such thing as a partial droop command, and
	// the absence of a pointer per element is deliberate rather than an
	// omission (a droop with three of five parameters is not a weaker droop,
	// it is an undefined one).
	//
	// WHY IT IS HERE AT ALL (owner decision D5, 2026-08-14). opModFreqDroop
	// maps onto SunSpec model 711 EXACTLY — the sep 2.0.4 kOF/kUF descriptions
	// and the 711 Ctl descriptions are verbatim the same sentence, and every
	// conversion is a fixed decimal shift (see the field units below). But the
	// bus had no carrier for it: the only carriage was DERScheduleSlot.
	// FreqDroop on the 24 h plan, which is INFORMATIONAL (its one subscriber
	// is a status UI), so the advanced-document author — which consumes
	// ActiveControl and CurveSet, not the schedule — could never see it. An
	// exactly-executable control was unreachable for want of a struct field.
	//
	// Units stay 2030.5-NATIVE here on purpose. This document is the
	// northbound projection and speaks northbound vocabulary; the conversion
	// into model-711 engineering units (Hz, unitless, seconds — bus.
	// AdvFreqDroop) happens exactly ONCE, in the gateway authority, so there
	// is one place to read, test and be wrong in. Additive at
	// ActiveControlV=1 (AD-006).
	FreqDroop *FreqDroopIntent `json:"freq_droop,omitempty"`
	// SetGradW/SetSoftGradW are the DefaultDERControl-only ramp-rate defaults
	// (2030.5 setGradW/setSoftGradW, decoded to percent of setMaxW per
	// second). Per the CSIP ramp-rate rule they ride ONLY a default-sourced
	// control — nil on event-sourced controls, whose ramp is RampTms-driven.
	SetGradW     *float64 `json:"set_grad_w,omitempty"`
	SetSoftGradW *float64 `json:"set_soft_grad_w,omitempty"`
	// RvrtTmsS is the computed device reversion window (C3): ValidUntil−
	// serverNow clamped to [remainingDuration+margin, 24h] (CSIP_CONTROL_
	// EXECUTION_2026-08-12.md §2.1). Computed by the northbound publisher at
	// every actual publish (ToActiveControlAt) — no longer permanently nil as
	// of that design landing; the field itself (carriage) predates it.
	RvrtTmsS *int64 `json:"rvrt_tms_s,omitempty"`
	// RampTms is the winning event's commanded ramp time for the FixedW axis
	// ONLY (hundredths of a second, 2030.5 DERControlBase.RampTms's own
	// unit) — copied from scheduler.ActiveControl.RampByAxis[ModeFixedW] by
	// ToActiveControlAt (CSIP_CONTROL_EXECUTION_2026-08-12.md §3.1/§7.2). nil
	// on a default-sourced control (whose ramp rides SetGradW/SetSoftGradW
	// instead) or when the winning FixedW event named no ramp. Scoped to
	// FixedW only, not a general per-axis carriage: the design's own §8 item 6
	// judgment call — a wider RampByAxis-mirroring map is more correct for
	// multi-event compositions but is deferred, matching the scalar-primary-
	// only precedent RvrtTmsS already set.
	RampTms *uint16 `json:"ramp_tms,omitempty"`
	// RampTmsRequested is set when the winning event carried rampTms on ANY
	// scalar axis — not just the FixedW axis RampTms above is scoped to
	// (IW13-006). It is deliberately a WIDER predicate than RampTms's own
	// presence: an event that wins ONLY a ceiling axis (opModMaxLimW) with a
	// commanded ramp leaves RampTms nil, yet it still asked for a transition
	// TIME the gateway cannot execute.
	//
	// IEEE 2030.5-2018 defines rampTms as the requested time for the device to
	// transition from its CURRENT mode setting(s) to the NEW one(s). The
	// gateway has no trusted current-value source, so it converts that time
	// into a nameplate-referenced RATE (704 WRmp, %WMax/s) — a best-effort
	// approximation that finishes a sub-range transition EARLIER than the
	// requested time. It can therefore never execute the requested transition
	// time exactly, and executors must report a control carrying this flag as
	// only PARTIALLY complied (a permanent terminal ramp-inexact failure →
	// CannotComply northbound), never as a clean success.
	//
	// It says nothing about setGradW/setSoftGradW: a DefaultDERControl's ramp
	// is a RATE on the wire, lands on WRmp as a rate, and is fully supported.
	// Additive at ActiveControlV=1 (AD-006).
	RampTmsRequested bool `json:"ramp_tms_requested,omitempty"`
	// CurveSetID is the content hash (CurveSet.SetID) of the matching
	// retained lexa/csip/curves doc; "" = the active control links no
	// resolvable curves.
	CurveSetID string `json:"curve_set_id,omitempty"`

	// DefaultFallback carries the highest-priority program's DefaultDERControl
	// ALONGSIDE an active event, so the hub can degrade to it — IEEE 2030.5
	// event-end revert-to-default — instead of to UNCONSTRAINED when the event
	// expires during a discovery outage (ED-3/H5). nil when the active control IS
	// the default (Source=="default") or the program carries no DefaultDERControl.
	// Additive at ActiveControlV=1 (AD-006: old subscribers ignore the key); its
	// *float64 members participate in Finite() (GAP-09).
	DefaultFallback *DefaultDERControlMsg `json:"default_fallback,omitempty"`

	// ServerTs is the publisher's estimate of SERVER time at publish, derived
	// coherently from the /tm instant + monotonic elapsed (audit CS-1) rather
	// than the two independently-clocked fields Ts+ClockOffset. The hub anchors
	// its utility clock on this when present; a legacy publisher omits it (0) and
	// the hub falls back to Ts+ClockOffset. Additive at ActiveControlV=1 (AD-006).
	ServerTs int64 `json:"server_ts,omitempty"`

	// PollIntervalS is the publisher's own next-contact cadence, in seconds: the
	// interval lexa-northbound will wait before the whole-tree walk that
	// republishes this document, i.e. exactly what run.effectiveInterval returned
	// for the NEXT cycle. It is the machine-readable half of the utility-comm
	// heartbeat this doc already carries in Ts: a consumer that arms a watchdog on
	// Ts freshness needs to know how often freshness is promised, and in
	// poll_rate_mode "honor" that number is only knowable at runtime (lexa-gw
	// FAILSAFE-GRACE-POLL-COUPLING / IW9-004). Stamped for the NEXT interval, never
	// the elapsed one, so a consumer learns a cadence INCREASE on the message that
	// precedes the long gap. 0 = the publisher did not state a cadence.
	//
	// Additive at ActiveControlV=1 (AD-006), and deliberately NOT part of the
	// control's enforcement content: a consumer that dedups redeliveries by
	// comparing controls must exclude it exactly as it already excludes
	// Ts/ServerTs/ClockOffset, or a cadence change alone would re-author every
	// device.
	PollIntervalS int64 `json:"poll_interval_s,omitempty"`

	// ── P1.3 Track C step C3 (CSIP-003 per-mode provenance carriage) ──────
	// ModeProvenance attributes each control-mode axis PRESENT in this
	// published control (the scalar opMod* fields above plus any resolved
	// curve-linked axes named by the CurveMode* vocabulary) to the program /
	// event that supplied it — see the ModeProvenance type below. It is the
	// bus projection of the gateway scheduler's per-axis provenance map
	// (lexa-gw schedstate.ModeProvenance, landed C2 in 3b0641d): the northbound
	// publisher copies that map onto this field key-for-key in the next work
	// package. CARRIAGE ONLY — no subscriber arbitrates on it yet; today's
	// single-winner resolver stamps every present axis with the one winning
	// event, and the per-mode-MAP shape is what lets Track C's per-mode
	// resolver (C1, in lexa-gw) later attribute different axes to different
	// events without an ActiveControlV bump. Additive at ActiveControlV=1
	// (AD-006): an old publisher never stamps it and an old subscriber ignores
	// the key; a document without the field decodes to a nil map. nil when the
	// control sets no mode axis.
	ModeProvenance map[string]ModeProvenance `json:"mode_provenance,omitempty"`

	Ts int64 `json:"ts"`
}

// FreqDroopIntent is opModFreqDroop as IEEE 2030.5 states it — sep 2.0.4's
// FreqDroopType, element for element, unit for unit, nothing pre-converted.
//
// ALL FIVE ELEMENTS ARE MANDATORY in the XSD (minOccurs="1" on every one), so
// they are values rather than pointers and a non-nil ActiveControl.FreqDroop
// always carries a complete droop. That is not stylistic: a droop missing its
// under-frequency branch is not a gentler droop, it is an undefined machine,
// and a pointer per element would invite a caller to author one.
//
// THE MAPPING TO SunSpec MODEL 711 IS A PURE DECIMAL SHIFT, which is why
// decision D5 calls it exact. It is performed exactly once, in the gateway
// authority (lexa-gw internal/authority), producing bus.AdvFreqDroop:
//
//	DBOFmHz  /1000 -> AdvFreqDroop.DbOfHz  (711 DbOf, Hz)
//	DBUFmHz  /1000 -> AdvFreqDroop.DbUfHz  (711 DbUf, Hz)
//	KOFmilli /1000 -> AdvFreqDroop.KOf     (711 KOf,  unitless per-unit slope)
//	KUFmilli /1000 -> AdvFreqDroop.KUf     (711 KUf,  unitless)
//	OLRTcs   /100  -> AdvFreqDroop.OlrtS   (711 RspTms, seconds)
//
// No nominal-frequency assumption enters anywhere: kOF/kUF are already
// per-unit frequency change per per-unit power change, and sep 2.0.4's wording
// for them is verbatim identical to model 711's own. (Model 711's PMin has no
// 2030.5 source and is deliberately absent here — the executor reads the
// device's own PMin and writes it back unchanged rather than inventing one.)
//
// IT IS ALSO THE 24 h PLAN'S CARRIER (DERScheduleSlot.FreqDroop). There used
// to be a second type here — FreqDroopMsg, {dBuf, dF, dP, openLoopTms,
// tResponse} — described as "a DIFFERENT parameterization carried on an
// informational document". That description was wrong (IW15-019): opModFreqDroop
// has one parameterization, both carriers are filled from the same element, and
// four of FreqDroopMsg's five fields named elements sep 2.0.4 never declared, so
// the plan had always shown them as zero. FreqDroopMsg is gone; this type is
// what a droop looks like on this bus, control surface and informational
// surface alike.
type FreqDroopIntent struct {
	DBOFmHz  uint32 `json:"dbof_mhz"`  // over-frequency dead band, thousandths of Hz
	DBUFmHz  uint32 `json:"dbuf_mhz"`  // under-frequency dead band, thousandths of Hz
	KOFmilli uint16 `json:"kof_milli"` // over-frequency droop slope, thousandths, unitless
	KUFmilli uint16 `json:"kuf_milli"` // under-frequency droop slope, thousandths, unitless
	// OpenLoopTmsCs is the open-loop response time in HUNDREDTHS of a second.
	// 0 is meaningful vocabulary, not absence: sep 2.0.4 says "a value of 0 is
	// used to mean no limit".
	OpenLoopTmsCs uint16 `json:"olrt_cs"`
}

// ModeProvenance attributes ONE composed control-mode axis on ActiveControl to
// the program / event that supplied it (audit CSIP-003 root cause: an active
// control modeled a single source MRID rather than a per-mode provenance map).
// It is the bus mirror of lexa-gw's schedstate.ModeProvenance (P1.3 Track C
// step C2, commit 3b0641d) — field names and JSON keys match EXACTLY so the
// northbound publish step copies the scheduler map onto
// ActiveControl.ModeProvenance field-for-field.
//
// All fields are scalar, so ModeProvenance stays == comparable; the map that
// holds it (keyed by the opMod* / CurveMode* axis vocabulary) is what ends
// ActiveControl's own == comparability — harmless, as nothing compares an
// ActiveControl by value (matching d0928b4's additive precedent, which likewise
// adds no Equal method for its new fields).
type ModeProvenance struct {
	EventMRID      string `json:"event_mrid,omitempty"`      // supplying DERControl (or DefaultDERControl) MRID
	ProgramMRID    string `json:"program_mrid,omitempty"`    // supplying DERProgram MRID
	ProgramPrimacy uint32 `json:"program_primacy,omitempty"` // supplying DERProgram primacy (lower = higher priority)
	CreationTime   int64  `json:"creation_time,omitempty"`   // supplying event's creationTime (0 for a default)
	Source         string `json:"source,omitempty"`          // "event" or "default"

	// ExpiresAt is the CSIP-003 per-axis-tail addition (WP-1, design §1.4):
	// the per-axis effective end — the server-time (Unix seconds) at which THIS
	// axis's supplying event expires, so the composition must change — carried
	// per axis because different events win different axes and so end at
	// different times. It makes each axis's end explicit so the gateway's
	// fail-closed hold, its armed boundary timer, and this retained control all
	// read ONE per-axis truth instead of the single aggregate ValidUntil. 0 =
	// no expiry (a default-sourced axis has no interval — it stands until an
	// event supersedes it) OR unknown (a pre-tail document that never stamped
	// it). Additive at ActiveControlV=1 (AD-006): an old publisher never stamps
	// it, an old subscriber ignores the key, and a legacy ModeProvenance
	// decodes with ExpiresAt=0 — no version bump. int64 keeps ModeProvenance
	// all-scalar, so it stays == comparable. Mirrors lexa-gw
	// schedstate.ModeProvenance.ExpiresAt field-for-field (same JSON key).
	ExpiresAt int64 `json:"expires_at,omitempty"`
}

// DefaultDERControlMsg is the scalar-limit subset of a DefaultDERControl carried
// on ActiveControl.DefaultFallback (H5/ED-3). Curves ride lexa/csip/curves
// separately, so only the enforced scalar op-modes are needed here.
type DefaultDERControlMsg struct {
	MRID       string   `json:"mrid,omitempty"`
	Connect    *bool    `json:"connect,omitempty"`
	Energize   *bool    `json:"energize,omitempty"`
	ExpLimW    *float64 `json:"exp_lim_w,omitempty"`
	ImpLimW    *float64 `json:"imp_lim_w,omitempty"`
	MaxLimWPct *float64 `json:"max_lim_w_pct,omitempty"` // IW13-001 — see ActiveControl.MaxLimWPct
	GenLimW    *float64 `json:"gen_lim_w,omitempty"`     // CSIP-AUS — the case that makes this matter
	LoadLimW   *float64 `json:"load_lim_w,omitempty"`    // CSIP-AUS
	FixedWPct  *float64 `json:"fixed_w_pct,omitempty"`   // IW13-001 — see ActiveControl.FixedWPct

	// ── The REACTIVE axes' device-side reversion alternate (RC0 owner ruling
	//    R-PF/Var, 2026-08-15) ────────────────────────────────────────────────
	//
	// WHY THIS TYPE CARRIES THEM. A device-side reversion needs a DESTINATION,
	// and 2030.5 already names it: the DefaultDERControl is by definition what
	// the DER does when no event applies, so "where should this machine land
	// when the countdown for this event expires" and "what does the program's
	// default command" are the same question. Every other candidate answer —
	// a locally invented constant, the device's own shadow register, whatever
	// the previous session left behind — is a value nobody currently intends.
	//
	// EACH AXIS IS A VALUE PLUS AN ARMING BOOL, and both halves are required
	// for the pair to mean anything. A destination with no arm is a number
	// parked in a register no countdown will deliver (SS-MODBUS-CONF v1.4
	// REV-3: RvrtTms=0 CANCELS reversion); an arm with no destination reverts
	// the device to whatever its shadow register already holds, which
	// lexa-proto's writers REFUSE rather than perform. The arming bool is the
	// GATEWAY's decision (it arms only where a window is actually armed), not
	// a restatement of anything the head end sent.
	//
	// THE PF AXIS CARRIES ITS EXCITATION AS PART OF ITS VALUE, structurally.
	// RvrtPF is a *FixedPF — the {magnitude, over_excited} pair — rather than a
	// bare float beside an optional bool, because a displacement magnitude
	// without an excitation is not a power factor: 0.98 over-excited and 0.98
	// under-excited are opposite reactive commands. Making the pair one field
	// is what makes "plumb both or neither" a property of the type instead of
	// a rule somebody has to remember; lexa-proto's writer refuses a magnitude
	// with no excitation, and this shape means that refusal is unreachable from
	// here. The polarity is FixedPF's own (OverExcited = !excitation, 2018
	// p.258 — see that type), converted to model 704's opposite numbering once,
	// at the writer, and never re-derived in transit.
	//
	// Additive at ActiveControlV=1 (AD-006): an old publisher never stamps
	// them, an old subscriber ignores the keys, and absence means exactly what
	// it meant before these fields existed — no alternate is armed, the
	// countdown alone governs.
	RvrtVarSetPct *float64 `json:"rvrt_var_set_pct,omitempty"` // signed % of setMaxVar, the same domain as ActiveControl.FixedVarPct
	RvrtVarSetEna *bool    `json:"rvrt_var_set_ena,omitempty"`
	RvrtPF        *FixedPF `json:"rvrt_pf,omitempty"`
	RvrtPFEna     *bool    `json:"rvrt_pf_ena,omitempty"`
}

// FixedPF is a fixed power-factor command (opModFixedPFInjectW /
// opModFixedPFAbsorbW) on ActiveControl (WP-8, architecture §2.2).
//
// PF is the displacement power factor in (0, 1].
//
// OverExcited IS A DIRECTION, DECODED ONCE AT THE PUBLISHER, and this doc is
// where the 2026-08-15 excitation inversion (gate #17 finding 1) had its
// proximate source — so the correct polarity is stated here with its citation
// rather than described in terms of a convention that no longer exists.
//
// IEEE Std 2030.5-2018 printed p.258, excitation attribute (boolean), verbatim:
//
//	"True when DER is absorbing reactive power (under-excited), false when DER
//	 is injecting reactive power (over-excited)."
//
// So on the wire element, excitation TRUE means UNDER-excited, and this field is
// its INVERSE: OverExcited = !excitation. Downstream, SunSpec model 704 numbers
// the pair the other way again (M704_Ext_OverExcited = 0, M704_Ext_UnderExcited
// = 1), so the value travels across two opposing conventions and is converted at
// each boundary rather than copied.
//
// WHAT THIS PARAGRAPH USED TO SAY, recorded because it is why the defect
// propagated: it described csipmodel as folding PowerFactorWithExcitation into a
// signed per-cent whose SIGN carried excitation, "non-negative ⇒ over-excited".
// That fold was csipmodel's own invention — no revision of 2030.5 encodes
// excitation in a sign — and it was removed when the element was correctly typed
// (lexa-proto fe483e7). The doc outlived it and kept asserting "positive means
// over-excited", which is the polarity every consumer then carried onto the new
// boolean. A stale doc describing a deleted convention is not inert; it is an
// instruction.
//
// The publisher decodes this once so no subscriber re-derives the direction
// from raw wire values — which remains the right design and is exactly why the
// single decode site has to be right.
type FixedPF struct {
	PF          float64 `json:"pf"` // displacement power factor, (0, 1]
	OverExcited bool    `json:"over_excited"`
}

// RewalkRequest is published by lexa-hub on TopicCSIPRewalk (TASK-042, not
// retained, QoS 1) to ask lexa-northbound to refresh the retained
// lexa/csip/control message immediately, outside its normal discovery
// cadence. Reason is "stale" (a retained control was adopted with an age —
// measured against its own Ts — exceeding the hub's configured
// retained_adoption_max_age_s) or "decode" (the retained payload failed to
// unmarshal at all). See TopicCSIPRewalk's doc for the full mechanism.
type RewalkRequest struct {
	Envelope
	Reason string `json:"reason"` // "stale" | "decode"
	Ts     int64  `json:"ts"`
}

// ComplianceAlert is published by the hub (orchestrator) on
// TopicCSIPComplianceAlert when it cannot meet an active CSIP control limit.
// Active distinguishes the onset (true) from the clear (false) of a breach so
// the northbound service posts exactly one CannotComply Response per episode.
type ComplianceAlert struct {
	Envelope
	MRID       string  `json:"mrid"`        // active DERControl that cannot be met
	LimitType  string  `json:"limit_type"`  // "import" | "export" | "generation" | "generation-aus" | "load-aus" (WP-11)
	LimitW     float64 `json:"limit_w"`     // commanded limit (W)
	MeasuredW  float64 `json:"measured_w"`  // actual net/generation at the meter (W)
	ShortfallW float64 `json:"shortfall_w"` // how far over the limit (W)
	Reason     string  `json:"reason"`      // human-readable cause
	Active     bool    `json:"active"`      // true = breach onset, false = cleared
	Ts         int64   `json:"ts"`          // Unix seconds
	// EpisodeID names the breach episode this edge belongs to (TASK-031). The
	// breach-episode component (cmd/hub/breach.go) forms it once at onset
	// (mrid@issuedAt) and reuses it for the whole episode, across both evidence
	// sources (optimizer meter breaches + reconciler non-convergence). The
	// northbound responseTracker dedupes CannotComply POSTs by this ID when
	// present (falling back to MRID for pre-TASK-031 publishers and as a
	// hub-restart safety net), so both sources reporting the same real episode
	// yield exactly one CannotComply. Additive/omitempty: an alert without it is
	// a legacy publisher and dedupes by MRID as before.
	EpisodeID string `json:"episode_id,omitempty"`
}

// ReconcileReport is the device-level non-convergence evidence a reconciler
// shell (cmd/modbus battery/solar, cmd/ocpp EVSE) forwards to the hub's
// breach-episode component (TASK-031). It is the bus projection of an
// internal/reconcile.Report: "the hardware won't do what the active CSIP
// control asked", complementary to the optimizer's meter-level breach.
//
// Published RETAINED per device on ReconcileReportTopic(class, device) so the
// hub re-seeds current convergence state after its own restart (state, not an
// edge — the latest NonConvergedBegin/End wins). Only the two convergence-state
// kinds are published on this topic; transient/diagnostic report kinds
// (StaleDesired, Rejected*, SeqReset, InterlockHold) stay shell-log-only for
// now (TASK-031 scope).
type ReconcileReport struct {
	Envelope
	Kind        string `json:"kind"`                // reconcile.ReportKind.String() (NonConvergedBegin|NonConvergedEnd|AdoptState)
	DeviceClass string `json:"device_class"`        // battery | solar | evse | adv
	DeviceID    string `json:"device_id"`           // device / EVSE station ID
	MRID        string `json:"mrid,omitempty"`      // active CSIP control the held intent derives from
	Seq         uint64 `json:"seq,omitempty"`       // seq of the held desired document
	IssuedAt    int64  `json:"issued_at,omitempty"` // held document's publisher wall clock (Unix s)
	Episode     uint64 `json:"episode"`             // per-reconciler monotonic episode counter
	Ts          int64  `json:"ts"`                  // report wall-clock time (Unix s)

	// ── P1.4 transactional-actuation correlation (SUN-001 §2.4, additive — same
	// V). These let the lexa-gw mbaps durable write-outbox match a TERMINAL
	// report back to the OutboxRecord it opened — correlated by
	// RequestID+Gen+MRID+Seq — and commit that record pending→applied|failed
	// exactly once, closing the "aggregator writes WMaxLimPct then reads it back
	// to confirm the curtail" leg at the right boundary. All fields are
	// omitempty/zero-value-compatible: a legacy reconciler (lexa-hub) stamps none
	// of them, they decode to their zero values, and the outbox correlation is
	// simply inactive — the retained NonConvergedBegin/End convergence state this
	// type has always carried is untouched, so hub consumers are unaffected.

	// RequestID is the durable, unique id the mbaps outbox minted for the FC6/
	// FC16 request whose desired doc this report terminalizes ("" = no outbox
	// correlation: a legacy or non-northbound-write intent). The pure reconcile
	// core does not know it (no DesiredState field carries it yet), so the ACTIVE
	// shell fills it from the matched OutboxRecord (S6) — it rides the wire here
	// so the contract is in place.
	RequestID string `json:"request_id,omitempty"`
	// Gen is the per-device generation this report is attributed to, echoed from
	// the standing DesiredState.Gen (bus/desired.go). 0 = unfenced/legacy. Paired
	// with RequestID/MRID/Seq it fences an outbox commit to the device generation
	// the write was admitted at — a report at gen 1 can never commit a record for
	// the physically-replaced gen 2.
	Gen uint64 `json:"gen,omitempty"`
	// Reason is the human-readable cause on a terminal ReconcileKindFailed report
	// (e.g. "fenced-stale-generation", "offline", "cannot-comply"). The reconcile
	// core sets it (via reconcile.RejectReason) for the generation-fence case;
	// the ACTIVE shell sets it directly for offline / CannotComply
	// terminalizations (S6).
	//
	// IT ALSO CARRIES A SHELL-AUTHORED DISCLOSURE ON THE RETAINED AdoptState
	// REPORT, which is a widening of this field's original "empty on every other
	// kind" contract and is stated here rather than left as a producer's private
	// convention. What forced it is the LEGACY (12x) SunSpec curve family, whose
	// writes can leave the DEVICE in a state that the terminal verdict alone does
	// not describe:
	//
	//	"the function was switched OFF"   a write that failed after the new curve
	//	                                  was already selected disables the model
	//	                                  rather than leave it running a curve the
	//	                                  gateway cannot vouch for. Something that
	//	                                  was providing grid support a moment ago is
	//	                                  not providing it now, and a consumer that
	//	                                  read only the Kind would report "the
	//	                                  control failed" while missing "and the
	//	                                  previous one is gone too".
	//	"the bank is part-written"        a narrowed retry stopped mid-way, so the
	//	                                  bank holds a mixture of the commanded
	//	                                  curve and its previous contents. Never
	//	                                  live in that state, but not what was
	//	                                  commanded either.
	//	"nothing was written"             a no-op pass that nonetheless refreshed
	//	                                  the device-side reversion lease, which
	//	                                  must not be reported as a curve write.
	//
	// Those are facts about CURRENT DEVICE STATE, so they belong on the document
	// that describes current state and that a late subscriber re-seeds from —
	// not only in a log line that scrolls away, and not only on a terminal that
	// speaks about one call.
	//
	// NO CONSUMER BEHAVIOUR CHANGES, and that is what makes the widening additive
	// rather than a version bump: the actuation-confirm tracker
	// (ObserveReconcileAxis) ignores every report whose Kind is not Applied or
	// Failed, so a Reason on an AdoptState report reaches no latch and can
	// neither satisfy nor falsify one. A consumer that reads Reason without
	// checking Kind was already wrong for the ControlEcho kind.
	Reason string `json:"reason,omitempty"`

	// ── WP-10 advanced-DER extension (architecture §2.2, additive — same V).
	// Populated only by the cmd/modbus adv shell (class "adv",
	// lexa/reconcile/adv/{device}/report); empty on every legacy scalar
	// report. Adoption state rides THIS retained report — never the desired
	// doc (D6: readback state on publisher-owned intent would be a second
	// writer) — so the hub re-seeds provisioning state after restart exactly
	// like NonConverged state.

	// Axis names the advanced axis the report is about: "" (legacy scalar
	// report) | AdvAxis* below.
	Axis string `json:"axis,omitempty"`
	// AdoptState is the axis's provisioning state: "" (axis released / no adv
	// provisioning in force) | AdoptState* below.
	AdoptState string `json:"adopt_state,omitempty"`
	// CurveHash is the canonical content hash of the ADOPTED curve/set
	// (bus.AdvCurve.Hash / AdvTripSet.Hash vocabulary), readback-verified:
	// populated only when AdoptState is "adopted", i.e. the shell re-read the
	// live curve after the adopt handshake and recomputed the same hash.
	CurveHash string `json:"curve_hash,omitempty"`

	// ── Control-setpoint readback echo (design 02 §4.4, additive — same V).
	// Applied is the OPTIONAL map of SunSpec 704 control-point name → the
	// engineering value the reconciler ACTUALLY wrote to the DER this cycle
	// (e.g. "WMaxLimPct" → 50.0 for a 50%-of-nameplate active-power cap). It
	// exists so a gateway's northbound Secure-SunSpec projection (lexa-gw
	// internal/regmap.ApplyReconcileReport) can serve a REAL readback value for
	// the 704 control points instead of the not-implemented sentinel, closing
	// the "aggregator writes WMaxLimPct then reads it back to confirm the
	// curtail" leg of the bench smoke test.
	//
	// Honest-echo discipline (mirrors bus.Measurement's "nil = absent, never
	// fabricated"): a point appears here ONLY when the reconciler genuinely
	// applied it this cycle; an absent point — or a nil/empty map — means "no
	// applied value to echo", and the northbound register stays at its
	// not-implemented sentinel rather than a guessed value. Values are in each
	// point's own engineering units (percent for WMaxLimPct); the regmap
	// applies the point's scale factor on encode. Ride NON-retained on the
	// per-device report topic so they never overwrite the retained
	// NonConvergedBegin/End state the breach-episode component re-seeds from —
	// same non-retained delivery bus.Measurement uses (a control echo is live
	// projection state, not durable convergence state).
	Applied map[string]float64 `json:"applied,omitempty"`
}

// ReconcileKindControlEcho is the ReconcileReport.Kind a reconciler shell
// stamps on a shell-authored, NON-retained control-setpoint echo (the report
// that carries Applied). It is deliberately NOT one of the
// reconcile.ReportKind convergence kinds: the breach-episode consumer's
// default arm ignores it (the same way it ignores AdoptState), while the
// gateway regmap keys only on Applied and ignores Kind — so an echo informs
// the northbound readback without ever being mistaken for a convergence
// state transition.
const ReconcileKindControlEcho = "ControlEcho"

// ReconcileKindApplied and ReconcileKindFailed are the P1.4 transactional-
// actuation TERMINAL kinds a reconciler stamps on ReconcileReport.Kind to close
// the consumer-commit loop (SUN-001 §2.4). They are the string projection of
// reconcile.ReportApplied / reconcile.ReportFailed (reconcile.ReportKind.String()):
//
//   - Applied: the reconciler VERIFIED BY READBACK that the standing desired
//     converged on the device at the reported Gen (reconcile.Observe's
//     convergence transition). It is the signal the mbaps outbox commits a record
//     pending→applied on, and the CSIP-004(c) per-MRID actuation-confirm latch.
//   - Failed: the reconciler will not / can not apply the intent — carrying a
//     Reason. The reconcile core emits it for the generation fence (Reason
//     "fenced-stale-generation", reconcile.RejectStaleGeneration); the ACTIVE
//     shell also emits it for offline / CannotComply terminalizations (S6). The
//     outbox commits the open record pending→failed, never a false applied.
//
// Like ReconcileKindControlEcho these are deliberately NOT reconcile convergence
// kinds: a consumer that understands only NonConvergedBegin/End (lexa-hub's
// breach-episode default arm) ignores them, so adding them cannot perturb the
// retained convergence state that component re-seeds from.
const (
	ReconcileKindApplied = "Applied"
	ReconcileKindFailed  = "Failed"
)

// ReconcileReport.Axis vocabulary (WP-10, architecture §2.2). "freq_watt" is
// an additive extension beyond the §2.2 list: the D6 desired doc carries a
// freq-watt overlay axis, but no SunSpec 1547 model executes it (705/706/711/
// 712 cover volt-var/volt-watt/droop/watt-var only), so the execution shell
// must be able to NAME the axis to report it unsupported.
//
// AdvAxisWattPF is the THIRTEENTH axis (decision D7, lexa-gw
// docs/design/LEGACY_CURVES_RC0_2026-08-14.md §3.1). It is here for the same
// reason freq_watt is: an axis this product may have to NAME — to refuse it, to
// report it unsupported, to key a terminal report by it — must exist in the
// vocabulary even when no generation executes it yet. opModWattPF's only exact
// register home is legacy SunSpec model 131 (Watt-PF); the 7xx set has no
// watt-PF model at all. Before D7 the product had no watt_pf axis and therefore
// wrote opModWattPF's curve into model 712, the WATT-VAR model — the
// substitution §3.2 calls unshippable.
//
// It is deliberately NOT a fifth carrier on DesiredAdvanced: watt_pf rides the
// existing single AdvReactiveMode slot as the fifth Kind (AdvReactiveWattPF),
// so mutual exclusivity of the reactive axes stays STRUCTURAL. What the axis
// constant buys is addressability — advaxis.Engaged can map the kind to an
// axis, the executor registry can be asked about it per generation, and
// ReconcileReport.Axis can attribute a terminal to it.
const (
	AdvAxisVoltVar   = "volt_var"
	AdvAxisVoltWatt  = "volt_watt"
	AdvAxisWattVar   = "watt_var"
	AdvAxisWattPF    = "watt_pf"
	AdvAxisFreqWatt  = "freq_watt"
	AdvAxisFreqDroop = "freq_droop"
	AdvAxisTripLV    = "trip_lv"
	AdvAxisTripHV    = "trip_hv"
	AdvAxisTripLF    = "trip_lf"
	AdvAxisTripHF    = "trip_hf"
	AdvAxisFixedPF   = "fixed_pf"
	AdvAxisFixedVar  = "fixed_var"
	AdvAxisEnergize  = "energize"
)

// ReconcileReport.AdoptState vocabulary (WP-10, architecture §2.2). The empty
// string is deliberate vocabulary, not absence: "" = the axis is released /
// nothing in force.
const (
	AdoptStatePending     = "pending"     // commanded; execution not yet verified
	AdoptStateAdopted     = "adopted"     // readback-verified (curve hash match / measured convergence)
	AdoptStateDiverged    = "diverged"    // executed but readback/measurement disagrees with desired
	AdoptStateUnsupported = "unsupported" // device (der_gen/model set) cannot execute this axis
	AdoptStateFailed      = "failed"      // write or adopt handshake failed (incl. AdptCrvRslt FAILED)
)

// BattCommand is published by the hub (orchestrator) to the modbus service.
// Nil SetpointW means "leave unchanged".
type BattCommand struct {
	Envelope
	Device    string   `json:"device"`
	SetpointW *float64 `json:"setpoint_w,omitempty"` // + discharge, − charge (W)
	Connect   *bool    `json:"connect,omitempty"`
	Ts        int64    `json:"ts"`
}

// SolarCommand is published by the hub to the modbus service.
// Nil CurtailToW means "restore to full nameplate output".
type SolarCommand struct {
	Envelope
	Device     string   `json:"device"`
	CurtailToW *float64 `json:"curtail_to_w,omitempty"` // nil = uncurtailed
	Ts         int64    `json:"ts"`
}

// EVSEState is published by the ocpp service whenever connector state changes.
type EVSEState struct {
	Envelope
	StationID     string   `json:"station_id"`
	ConnectorID   int      `json:"connector_id"`
	Connected     bool     `json:"connected"`
	SessionActive bool     `json:"session_active"`
	CurrentA      *float64 `json:"current_a,omitempty"`
	MaxCurrentA   *float64 `json:"max_current_a,omitempty"`
	VoltageV      *float64 `json:"voltage_v,omitempty"`
	PowerW        *float64 `json:"power_w,omitempty"`
	SOC           *float64 `json:"soc_pct,omitempty"`
	EnergyWh      *float64 `json:"energy_wh,omitempty"`
	Status        string   `json:"status"`
	Ts            int64    `json:"ts"`
}

// EVSECommand is published by the hub to the ocpp service.
// MaxCurrentA == 0 means suspend the charging session.
type EVSECommand struct {
	Envelope
	StationID   string  `json:"station_id"`
	ConnectorID int     `json:"connector_id"`
	MaxCurrentA float64 `json:"max_current_a"`
	Ts          int64   `json:"ts"`
}

// ─── Pricing function set (IEEE 2030.5 §10.5) ───────────────────────────────

// PricingUpdate is published by the csip service after each discovery walk
// that finds a TariffProfile. It carries the full schedule of upcoming pricing
// intervals so the hub can make look-ahead battery dispatch decisions.
type PricingUpdate struct {
	Envelope
	TariffProfiles []TariffProfileMsg `json:"tariff_profiles"`
	Ts             int64              `json:"ts"`
}

// TariffProfileMsg is the per-profile slice of PricingUpdate.
type TariffProfileMsg struct {
	MRID                      string             `json:"mrid"`
	Description               string             `json:"description,omitempty"`
	Currency                  uint16             `json:"currency,omitempty"`      // ISO 4217
	PricePowerOfTenMultiplier int8               `json:"price_power_of_ten_mult"` // apply to Price values
	Primacy                   uint8              `json:"primacy"`
	RateCode                  string             `json:"rate_code,omitempty"`
	RateComponents            []RateComponentMsg `json:"rate_components,omitempty"`
}

// RateComponentMsg carries the upcoming price schedule for one rate direction.
type RateComponentMsg struct {
	MRID               string          `json:"mrid"`
	Description        string          `json:"description,omitempty"`
	NumberOfTouTiers   uint8           `json:"num_tou_tiers,omitempty"`
	ActiveIntervals    []TimeTariffMsg `json:"active_intervals,omitempty"`
	ScheduledIntervals []TimeTariffMsg `json:"scheduled_intervals,omitempty"`
}

// TimeTariffMsg is one pricing interval with its consumption tier prices.
// Price values are in units determined by TariffProfileMsg.PricePowerOfTenMultiplier.
type TimeTariffMsg struct {
	MRID          string          `json:"mrid"`
	Description   string          `json:"description,omitempty"`
	TouTier       uint8           `json:"tou_tier"`
	IntervalStart int64           `json:"interval_start"` // Unix seconds
	Duration      uint32          `json:"duration"`       // seconds
	Blocks        []PriceBlockMsg `json:"blocks,omitempty"`
}

// PriceBlockMsg is one consumption block within a TimeTariffMsg.
type PriceBlockMsg struct {
	ConsumptionBlock uint8 `json:"consumption_block"`
	Price            int32 `json:"price"`       // apply PricePowerOfTenMultiplier for real value
	StartValue       int64 `json:"start_value"` // cumulative commodity units at which this block starts
}

// ─── Billing function set (IEEE 2030.5 §10.7) ───────────────────────────────

// BillingUpdate is published by the csip service when billing data is available.
// It carries the current billing period summary for each customer agreement.
type BillingUpdate struct {
	Envelope
	CustomerAccounts []CustomerAccountMsg `json:"customer_accounts"`
	Ts               int64                `json:"ts"`
}

// CustomerAccountMsg is the per-account slice of BillingUpdate.
type CustomerAccountMsg struct {
	MRID         string                 `json:"mrid"`
	CustomerName string                 `json:"customer_name,omitempty"`
	Currency     uint16                 `json:"currency,omitempty"`
	Agreements   []CustomerAgreementMsg `json:"agreements,omitempty"`
}

// CustomerAgreementMsg summarises one service agreement's billing status.
type CustomerAgreementMsg struct {
	MRID            string             `json:"mrid"`
	Description     string             `json:"description,omitempty"`
	ServiceLocation string             `json:"service_location,omitempty"`
	BillingPeriods  []BillingPeriodMsg `json:"billing_periods,omitempty"`
}

// BillingPeriodMsg is a single billing period summary.
type BillingPeriodMsg struct {
	IntervalStart  int64  `json:"interval_start"`
	Duration       uint32 `json:"duration"`
	BillLastPeriod *int64 `json:"bill_last_period,omitempty"` // in currency micro-units
	BillToDate     *int64 `json:"bill_to_date,omitempty"`     // in currency micro-units
}

// ─── Flow Reservation function set (IEEE 2030.5 §10.9) ──────────────────────

// FlowReservationRequestMsg is published by the hub on
// lexa/csip/flowreservation/request when it wants to schedule a charging or
// discharging window. The csip service will POST the request to the utility
// server's EndDevice FlowReservationRequestList.
type FlowReservationRequestMsg struct {
	Envelope
	// MRID is the client-assigned identifier for this request (hex string).
	MRID        string `json:"mrid"`
	Description string `json:"description,omitempty"`

	// EnergyRequestedWh is the total energy transfer needed (Wh).
	EnergyRequestedWh *float64 `json:"energy_requested_wh,omitempty"`
	// PowerRequestedW is the desired charge/discharge rate (W).
	PowerRequestedW *float64 `json:"power_requested_w,omitempty"`
	// DurationRequested is the minimum charging duration needed (seconds).
	DurationRequested uint32 `json:"duration_requested"`

	// IntervalStart and IntervalDuration define the requested time window.
	IntervalStart    int64  `json:"interval_start"`
	IntervalDuration uint32 `json:"interval_duration"`

	Ts int64 `json:"ts"`
}

// FlowReservationStatusMsg is published by the csip service on
// lexa/csip/flowreservation/status after each discovery walk that finds
// FlowReservationResponses. The hub uses this to schedule EVSE charging windows.
type FlowReservationStatusMsg struct {
	Envelope
	Reservations []ReservationMsg `json:"reservations"`
	Ts           int64            `json:"ts"`
}

// ReservationMsg is one granted (or cancelled/superseded) flow reservation.
type ReservationMsg struct {
	MRID          string   `json:"mrid"`
	Subject       string   `json:"subject"`        // mRID of the FlowReservationRequest
	CurrentStatus uint8    `json:"current_status"` // 0=scheduled, 1=active, 2=cancelled, 3=superseded
	IntervalStart int64    `json:"interval_start"`
	Duration      uint32   `json:"duration"`
	EnergyAvailWh *float64 `json:"energy_avail_wh,omitempty"`
	PowerAvailW   *float64 `json:"power_avail_w,omitempty"`
}

// ─── DER 24-hour schedule (northbound → hub) ─────────────────────────────────

// DERScheduleMsg is published by lexa-northbound on lexa/northbound/schedule
// after each discovery walk. It carries the resolved 24-hour DER control plan,
// which lexa-hub uses for look-ahead battery dispatch and EVSE scheduling.
type DERScheduleMsg struct {
	Envelope
	WindowStart int64              `json:"window_start"` // Unix seconds
	WindowEnd   int64              `json:"window_end"`
	BuildTime   int64              `json:"build_time"`
	ClockOffset int64              `json:"clock_offset"` // server − local (s)
	Slots       []DERScheduleSlot  `json:"slots"`
	DERStatus   []DERStatusSummary `json:"der_status,omitempty"`
	Ts          int64              `json:"ts"`
}

// DERScheduleSlot is one time-contiguous segment of the 24-hour plan.
type DERScheduleSlot struct {
	Start       int64  `json:"start"` // Unix seconds
	End         int64  `json:"end"`
	Source      string `json:"source"` // "event", "default", or "none"
	MRID        string `json:"mrid,omitempty"`
	Description string `json:"description,omitempty"`
	ProgramMRID string `json:"program_mrid,omitempty"`
	Primacy     uint8  `json:"primacy,omitempty"`

	// Scalar operating modes — nil means not controlled in this slot.
	Connect       *bool    `json:"connect,omitempty"`
	Energize      *bool    `json:"energize,omitempty"`
	MaxLimWPct    *float64 `json:"max_lim_w_pct,omitempty"`   // % of setMaxW — IW13-001
	FixedWPct     *float64 `json:"fixed_w_pct,omitempty"`     // signed % (+ discharge, − charge) — IW13-001
	ExpLimW       *float64 `json:"exp_lim_w,omitempty"`       // W
	ImpLimW       *float64 `json:"imp_lim_w,omitempty"`       // W
	GenLimW       *float64 `json:"gen_lim_w,omitempty"`       // W
	LoadLimW      *float64 `json:"load_lim_w,omitempty"`      // W
	TargetW       *float64 `json:"target_w,omitempty"`        // W
	FixedVarPct   *float64 `json:"fixed_var_pct,omitempty"`   // % of rated VAr
	FixedPFAbsorb *float64 `json:"fixed_pf_absorb,omitempty"` // power factor × 100
	FixedPFInject *float64 `json:"fixed_pf_inject,omitempty"` // power factor × 100
	RampTms       *uint16  `json:"ramp_tms,omitempty"`        // hundredths of a second

	// Curve-linked modes — curves are summarized inline (not raw XML breakpoints).
	//
	// WattVar is opModWattVar (IW15-019 half 2). It was the one curve axis the
	// plan could not show while the product EXECUTED it: the gateway routes
	// opModWattVar end to end into SunSpec model 712, so a 24 h plan that omits
	// it under-reports a running function to the only surface an operator reads.
	// Added at the same time as the FreqDroop shape correction below, and for
	// the same reason — an informational carrier that silently drops content is
	// worse than one that has none, because it reads as a positive "nothing
	// commanded here".
	VoltVar  *DERCurveSummary `json:"volt_var,omitempty"`
	FreqWatt *DERCurveSummary `json:"freq_watt,omitempty"`
	WattPF   *DERCurveSummary `json:"watt_pf,omitempty"`
	WattVar  *DERCurveSummary `json:"watt_var,omitempty"`
	VoltWatt *DERCurveSummary `json:"volt_watt,omitempty"`

	// Ride-through curves — present when the server commands specific ride-through behavior.
	HFRTMayTrip            *DERCurveSummary `json:"hfrt_may_trip,omitempty"`
	HFRTMustTrip           *DERCurveSummary `json:"hfrt_must_trip,omitempty"`
	HVRTMayTrip            *DERCurveSummary `json:"hvrt_may_trip,omitempty"`
	HVRTMomentaryCessation *DERCurveSummary `json:"hvrt_momentary_cessation,omitempty"`
	HVRTMustTrip           *DERCurveSummary `json:"hvrt_must_trip,omitempty"`
	LFRTMayTrip            *DERCurveSummary `json:"lfrt_may_trip,omitempty"`
	LFRTMustTrip           *DERCurveSummary `json:"lfrt_must_trip,omitempty"`
	LVRTMayTrip            *DERCurveSummary `json:"lvrt_may_trip,omitempty"`
	LVRTMomentaryCessation *DERCurveSummary `json:"lvrt_momentary_cessation,omitempty"`
	LVRTMustTrip           *DERCurveSummary `json:"lvrt_must_trip,omitempty"`

	// FreqDroop carries opModFreqDroop's parameters — present when the slot's
	// control commands a frequency droop.
	//
	// IT IS THE SAME FreqDroopIntent THE CONTROL CARRIER USES, and the change
	// away from the old FreqDroopMsg is a CORRECTION, not a refactor (IW15-019
	// half 1). FreqDroopMsg declared {dBuf, dF, dP, openLoopTms, tResponse} —
	// four elements sep 2.0.4's FreqDroopType does not define. There is exactly
	// ONE opModFreqDroop parameterization ({dBOF, dBUF, kOF, kUF, openLoopTms}),
	// both carriers are filled from that same element, and the claim that this
	// was "a DIFFERENT parameterization carried on an informational document"
	// was simply false. The practical consequence was that the informational
	// plan had always emitted four zeros for a commanded droop — which does not
	// read as "unknown", it reads as a droop with no dead bands and no slopes,
	// a real and aggressive machine rather than an absent one.
	//
	// NOT ADDITIVE, deliberately: FreqDroopMsg is REMOVED rather than deprecated
	// in place. The JSON key stays "freq_droop" and its value shape changes, so
	// a subscriber pinned to the old shape decodes zeros for the fields it looks
	// for — which is exactly what it got before, from a publisher that could
	// never fill them. Keeping a wrong-shape type alive next to the right one
	// would preserve the one hazard worth removing: a future author picking the
	// nearest-named struct and re-introducing the four phantom elements.
	FreqDroop *FreqDroopIntent `json:"freq_droop,omitempty"`
}

// DERCurveSummary carries the key fields of a resolved DERCurve.
type DERCurveSummary struct {
	MRID        string       `json:"mrid,omitempty"`
	Description string       `json:"description,omitempty"`
	CurveType   uint16       `json:"curve_type"`
	XMultiplier int8         `json:"x_mult,omitempty"`
	YMultiplier int8         `json:"y_mult,omitempty"`
	Points      []CurvePoint `json:"points,omitempty"`
}

// CurvePoint is one (x, y) breakpoint in a DERCurveSummary.
type CurvePoint struct {
	X int32 `json:"x"`
	Y int32 `json:"y"`
}

// DERStatusSummary carries the last-known operational status of one DER device.
type DERStatusSummary struct {
	DERHref          string   `json:"der_href,omitempty"`
	GenConnectStatus *uint8   `json:"gen_connect_status,omitempty"`
	InverterStatus   *uint8   `json:"inverter_status,omitempty"`
	OperationalMode  *uint8   `json:"operational_mode,omitempty"`
	StorageMode      *uint8   `json:"storage_mode,omitempty"`
	StateOfChargePct *float64 `json:"soc_pct,omitempty"`
	EstimatedWAvail  *float64 `json:"estimated_w_avail,omitempty"`
	ModesSupported   uint32   `json:"modes_supported,omitempty"`
}

// PlanLog is the optimizer's plan trace for one engine pass (TopicHubPlan).
// Decisions may be empty — the message is still published so its timestamp
// serves as an engine heartbeat.
type PlanLog struct {
	Envelope
	Ts        int64          `json:"ts"` // Unix seconds of the plan's evaluation
	Decisions []PlanDecision `json:"decisions,omitempty"`
	// ShadowDivergences is the running count of constraint-shadow divergent
	// ticks (TASK-059), included so the dashboard/QA can watch the shadow diff
	// rate without a metrics scrape. Additive, omitempty ⇒ absent (and the wire
	// version unchanged, PlanLogV) whenever the shadow harness is off or has
	// seen zero divergences; a legacy decoder ignores the unknown key.
	ShadowDivergences uint64 `json:"shadow_divergences,omitempty"`

	// Mode is the live plan author at this pass — "optimizer" or "gateway"
	// (Unit 3.6/§3.7). Stamped by cmd/hub's planObserver from modeManager.Mode().
	// Additive; omitempty ⇒ absent on a legacy publisher (the wire version stays
	// PlanLogV). A live hub always sets it non-empty, so it is normally present.
	Mode string `json:"mode,omitempty"`

	// ForecastSource is the solar-forecast path the most recent plan used —
	// "external" (a fresh forecast was resampled onto the plan grid) or "diurnal"
	// (the clear-sky fallback ran: no forecast, or one rejected as too old).
	// Empty before the first plan. From engine.ForecastSource() (Unit 3.6/3.1).
	ForecastSource string `json:"forecast_source,omitempty"`

	// ForecastAgeS is the age (seconds) of the external solar forecast at the
	// most recent plan, or -1 when none was in effect. From
	// engine.ForecastAgeSeconds(). NOTE the omitempty semantics: -1 (no external
	// forecast) IS serialized; the omitted case is the zero value 0, which here
	// reads as "unset/absent", never a genuine 0-second-old forecast (that
	// momentary case is disambiguated by ForecastSource=="external").
	ForecastAgeS int64 `json:"forecast_age_s,omitempty"`
}

// PlanDecision mirrors orchestrator.Decision for the bus.
type PlanDecision struct {
	Rule   string `json:"rule"`
	Reason string `json:"reason"`
	Impact string `json:"impact"`
}

// ─── Certificate expiry status (northbound → api) ────────────────────────────

// CertStatus is published retained on TopicNorthboundCertStatus by
// lexa-northbound's cert-expiry monitor (TASK-072, §10.5): the result of
// inspecting the configured client and CA PEM files' leaf NotAfter, at
// startup and every 24h thereafter. lexa-telemetry points at the same cert
// files (its own config carries its own ca_cert/client_cert paths) but does
// not run a second monitor — one inspection of the shared file is enough;
// see cmd/northbound/certmon.go's package doc.
//
// *NotAfter fields are 0 (with the matching *Err populated) when that PEM
// file could not be read or parsed — fail-closed REPORTING, not a crash: an
// unreadable cert file is itself the alarm-worthy condition, not a reason to
// go silent. DaysLeft is the binding constraint: whichever of the two certs
// expires first, since either one expiring independently breaks the mTLS
// handshake (a well-formed chain has the CA outlive the leaf, never the
// reverse, but this does not assume that — it takes the minimum of whichever
// days-left values are known).
type CertStatus struct {
	Envelope
	ClientNotAfter int64  `json:"client_not_after,omitempty"` // Unix seconds; 0 if unknown (see ClientErr)
	CANotAfter     int64  `json:"ca_not_after,omitempty"`
	ClientDaysLeft int    `json:"client_days_left"`
	CADaysLeft     int    `json:"ca_days_left"`
	DaysLeft       int    `json:"days_left"` // min(ClientDaysLeft, CADaysLeft) among the certs successfully inspected
	ClientErr      string `json:"client_err,omitempty"`
	CAErr          string `json:"ca_err,omitempty"`

	// PinOK (WP-7, D4 — additive at CertStatusV=1 per AD-006) is the
	// registration-PIN verification verdict from lexa-northbound's per-walk
	// check of the server's Registration resource (CORE-003/BASIC-001).
	// nil = the check is disabled (registration_pin=0, the shipped default)
	// or has not yet produced a verdict (no successful walk since process
	// start — the INCONCLUSIVE-safe state); false = PIN mismatch or a
	// Registration fetch failure while the check is required — northbound is
	// holding its adopted control fail-closed and has suspended server
	// egress (internal/northbound/run/pin.go); true = verified this walk.
	PinOK *bool `json:"pin_ok,omitempty"`

	Ts int64 `json:"ts"` // Unix seconds this check ran
}
