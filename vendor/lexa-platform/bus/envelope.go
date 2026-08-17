// Promoted from lexa-hub@5218e6a (2026-07-17)

package bus

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
)

// Envelope is embedded by value in a bus message struct that participates in
// the versioned-schema convention (AD-006, TASK-017). Embedding it adds a
// "v" field to that struct's JSON shape without changing any existing field.
//
// json:"v,omitempty" is deliberate: it means a struct whose Envelope.V is
// left at its zero value serializes with no "v" key at all, which is how a
// legacy (pre-versioning) publisher's wire shape looks. A publisher that has
// been updated to stamp a real schema version always sets V >= 1, so "v"
// absent (v0, legacy) and "v" present (v1+, versioned) stay distinguishable
// on the wire. Nothing in this repo sets V to 0 explicitly — see the
// per-schema constants below, all born at 1.
//
// This type is introduced but not yet wired into any publisher or
// subscriber (that is TASK-018); embedding it here is inert until then.
type Envelope struct {
	V int `json:"v,omitempty"`
}

// Per-schema envelope versions (AD-006 design decision: one constant per
// message family, not a single global version — a global would force
// lockstep version bumps across schemas that change independently). Every
// family is born at 1. TASK-018 wires each constant into that family's
// publisher (stamped into the embedded Envelope.V) and subscriber (passed
// as CheckVersion's `supported` argument); bump a family's constant only
// when that family's shape changes in a way old subscribers can't tolerate.
const (
	MeasurementV            = 1 // lexa/measurements/{device}               (Measurement)
	BattMetricsV            = 1 // lexa/battery/{device}/metrics            (BattMetrics)
	ActiveControlV          = 1 // lexa/csip/control                        (ActiveControl)
	ComplianceAlertV        = 1 // lexa/csip/compliance/alert               (ComplianceAlert)
	BattCommandV            = 1 // lexa/control/battery/{device}            (BattCommand)
	SolarCommandV           = 1 // lexa/control/solar/{device}              (SolarCommand)
	EVSEStateV              = 1 // lexa/evse/{station}/state                (EVSEState)
	EVSECommandV            = 1 // lexa/evse/{station}/command              (EVSECommand)
	PricingUpdateV          = 1 // lexa/csip/pricing                        (PricingUpdate)
	BillingUpdateV          = 1 // lexa/csip/billing                        (BillingUpdate)
	FlowReservationRequestV = 1 // lexa/csip/flowreservation/request        (FlowReservationRequestMsg)
	FlowReservationStatusV  = 1 // lexa/csip/flowreservation/status         (FlowReservationStatusMsg)
	DERScheduleV            = 1 // lexa/northbound/schedule                 (DERScheduleMsg)
	PlanLogV                = 1 // lexa/hub/plan                            (PlanLog)
	DesiredStateV           = 1 // lexa/desired/{class}/{device}            (DesiredState, AD-013)
	ReconcileReportV        = 1 // lexa/reconcile/{class}/{device}/report   (ReconcileReport, TASK-031)
	RewalkRequestV          = 1 // lexa/csip/rewalk                        (RewalkRequest, TASK-042)
	CertStatusV             = 1 // lexa/northbound/certstatus               (CertStatus, TASK-072)

	// Intent/scan/mode/status schemas (TASK-082, docs/DEVICE_ROADMAP.md §1.3).
	// All born at 1, same convention as every family above.
	ModeIntentV          = 1 // lexa/intent/mode
	EVGoalIntentV        = 1 // lexa/intent/evgoal
	BackupReserveIntentV = 1 // lexa/intent/reserve
	TariffIntentV        = 1 // lexa/intent/tariff
	SolarForecastIntentV = 1 // lexa/intent/solarforecast
	LoadProfileIntentV   = 1 // lexa/intent/loadprofile
	ChargeNowIntentV     = 1 // lexa/intent/chargenow
	IntentResultV        = 1 // lexa/intent/result
	ModeStatusV          = 1 // lexa/hub/mode
	HubSettingsV         = 1 // lexa/hub/settings (GAP-8 reserve+tariff read-back)
	HubScheduleV         = 1 // lexa/hub/schedule (GAP-7 plan/forecast 24h series)
	CloudlinkStatusV     = 1 // lexa/cloudlink/status
	ScanRequestV         = 1 // lexa/scan/request
	ScanStatusV          = 1 // lexa/scan/status
	ScanResultV          = 1 // lexa/scan/result
	PendingStationsV     = 1 // lexa/ocpp/pending

	// LogEvent schema (WP-6, standards-buildout A4). Born at 1, same
	// convention as every family above.
	LogEventV = 1 // lexa/hub/logevent (LogEventMsg)

	// DERSiteReport schema (WP-4, standards-buildout A2). Born at 1, same
	// convention as every family above.
	DERSiteReportV = 1 // lexa/hub/dersite (DERSiteReport)
	// DERDeviceReport schema (product decision D3.1/D3.3 — the per-device
	// counterpart of DERSiteReport). Born at 1, same convention as every
	// family above; type in derdevice.go, topic DERDeviceReportTopic(device).
	DERDeviceReportV = 1 // lexa/der/{device}/report (DERDeviceReport)
	// CurveSet schema (WP-8, standards-buildout C1/D6). Born at 1; bumped to 2
	// on 2026-08-15 (registry IW15-027) and to 3 on 2026-08-16 — and, like
	// DesiredAdvanced beside it, every bump has come with a FLOOR rather than the
	// ordinary additive tolerance.
	//
	// ── v2 -> v3 (2026-08-16): openLoopTms enters the canonical hash line ────
	//
	// This bump is the OTHER kind of change from the one described below them,
	// and telling them apart is worth the paragraph because they fail
	// differently. v1 -> v2 rebound a hashed field's VALUE SPACE under an
	// unchanged canonical form. v2 -> v3 moves the CANONICAL FORM itself:
	// DERCurve.openLoopTms — 2018 p.253, the open-loop response time whose
	// register home is SunSpec model 705 RspTms — joins the per-entry line as a
	// seventh token (see CurveSetContentHash).
	//
	// A v2 document therefore carries a SetID computed over a canonical form that
	// no longer exists. It decodes perfectly — the key is simply absent — and a v3
	// consumer recomputing the digest gets a DIFFERENT answer for byte-identical
	// curve content, because the new line carries an absent-token the old one did
	// not. Downstream that is every curve axis failing its own self-consistency
	// check and being refused one at a time. On a RETAINED topic that is what the
	// first freshly-flashed process sees. Refusing the document at the version is
	// how a per-axis refusal storm becomes a single clean fail-closed hold.
	//
	// WHY THIS TOOK A BUMP WHEN vRef — the structurally identical change — DID
	// NOT. vRef joined the same line on 2026-08-15 and rode the v2 bump beside
	// it, on the stated ground that "v2 is unreleased: both changes land inside
	// one unpushed version generation". That was true, and it was TIME-BOXED. By
	// 2026-08-16 the condition had expired: the v2 generation is PUBLISHED on the
	// remediation branch, so digests computed under the v2 canonical form exist
	// outside the commit that defined it. Two builds both calling themselves v2
	// and disagreeing on the digest is the single state a version number exists
	// to make impossible — and the one a consumer has no other way to detect,
	// the version being the only signal that would have told it.
	//
	// The first draft of this paragraph justified the bump by saying lexa-gw
	// "already agrees on the v2 canonical form". THAT IS NOT AN ARGUMENT: lexa-gw
	// VENDORS this package, so it agrees with whatever this file says. The only
	// independent implementation is csip-tls-test's hand-written mirror, and it
	// agrees with neither v2 nor v3. See CurveSetContentHash for the full
	// correction; the bump rests on v2 having been published, not on agreement.
	//
	// ── v1 -> v2 (2026-08-15): the DERCurveType re-anchoring ────────────────
	//
	// WHAT CHANGED, and why it was not additive. Nothing in this file moved and
	// CurveSetContentHash's CANONICALIZATION was byte-for-byte what it had been:
	// the same sorted `mode|curveType|xMult|yMult|yRefType|points` lines into the
	// same SHA-256. What moved is the VALUE SPACE of one field.
	// CurveSetEntry.CurveType carries IEEE 2030.5's DERCurveType code, and until
	// 2026-08-15 lexa-proto's csipmodel transcribed that enumeration from a
	// pre-publication ZigBee SEP 2.0.4 draft schema instead of from IEEE Std
	// 2030.5-2018. Every code moved: opModVoltVar 0 -> 11, opModWattVar 10 ->
	// 14, opModVoltWatt 3 -> 12, opModWattPF 2 -> 13, and the four MayTrip codes
	// (1, 3, 6, 8) came into existence. See lexa-proto
	// docs/schema/NORMATIVE_ANCHOR.md §3.2 for the three-way census.
	//
	// So a v1 document decodes CLEANLY into the v2 struct and means something
	// else: `{"mode":"volt_var","curve_type":0}` said opModVoltVar under the
	// draft and says opModFreqWatt under the standard. And because CurveType is
	// hashed, EVERY retained SetID computed under the draft is a digest over a
	// value that has since been rebound — the identity is stale, not merely the
	// display.
	CurveSetV = 3 // lexa/csip/curves (CurveSet)
	// CurveSetMinV is the OLDEST CurveSet a consumer may ACT ON. Same exception
	// to AD-006's forward-compatible-only policy as DesiredAdvancedMinV, for the
	// same structural reason and against the same failure mode: lexa/csip/curves
	// is RETAINED, so the set a unit published before a flash is replayed to the
	// first process that subscribes after it.
	//
	// BOTH BUMPS RAISED IT, for different specific failures.
	//
	// v2 (the DERCurveType re-anchoring). The failure is NOT "the gateway writes
	// the wrong registers": curve POINTS did not move, so a replayed v1 set would
	// drive the DER to the same breakpoints. It is that the stale set is
	// laundered FORWARD. lexa-gw's CSIPIn.HandleCurves re-authors the advanced
	// desired document straight from the retained entries, copying CurveType
	// verbatim onto AdvCurve — so a v1 set replayed into a v2 build publishes a
	// brand-new, correctly-versioned DesiredAdvanced carrying the draft's
	// numbering, and the mis-anchoring survives the upgrade that fixed it.
	//
	// v3 (openLoopTms entering the canonical line). The failure is a DIGEST that
	// no longer reproduces. A v2 set's SetID was computed over a six-token line;
	// this build's recomputation produces a seven-token line and a different
	// answer for identical curve content. Every consumer that re-derives the hash
	// — the correlation against ActiveControl.CurveSetID, and the per-axis
	// self-consistency check on the advanced document authored from these entries
	// — reads that as content it cannot verify, one axis at a time. There is also
	// a quieter half: a v2 set carries no openLoopTms for ANY curve, so re-
	// authoring from it would publish an advanced document that silently commands
	// no response time on axes where the server had specified one, and the
	// gateway would go on leaving model 705 RspTms at whatever the DER held —
	// the very defect the field was added to close, surviving the upgrade that
	// closed it. That is the same laundered-forward shape as v2's, one field over.
	//
	// Refusing the document is what stops both, and refusing it is SAFE by
	// construction here: with no curve set to correlate, buildAdvLocked's
	// !inSync arm is a fail-closed HOLD — nothing authored, nothing released,
	// zero writes — until the northbound walk republishes a current-version set.
	CurveSetMinV = 3
	// DesiredAdvanced schema (WP-9, standards-buildout C1/C3/C4, D6). Born at
	// 1; bumped to 2 on 2026-08-15 — the FIRST non-additive change in this
	// family, and the reason DesiredAdvancedMinV exists beside it.
	//
	// ── v3 -> v4 (2026-08-16): openLoopTms is an input to every AdvCurve.Hash ─
	//
	// AdvCurve gained OpenLoopTms, carried verbatim from CurveSetEntry, and
	// CurveSetContentHash's canonical line gained a token for it (CurveSetV = 3
	// above carries the full reasoning, including why this one took its own bump
	// where vRef's structurally identical change rode an existing one).
	//
	// AdvCurve.Hash is that same digest, computed over the single canonical entry
	// each axis was resolved from, so every per-axis re-adoption key in a v3
	// document was computed under a canonical form this build no longer produces.
	// The hazard is the v2 -> v3 shape rather than the v1 -> v2 one, and it is the
	// easy-to-under-rate one for the same reason: the self-consistency check
	// CANNOT see it. advCurveSelfInconsistent re-hashes using the DOCUMENT'S OWN
	// fields at both ends, and a v3 document has no openLoopTms at either end, so
	// it reconciles perfectly with itself. What a mixed pair produces is a
	// SPURIOUS RE-ADOPT: the authority republishes the same curve at v4, the
	// absent-token moves the digest, the shell sees a changed target and re-runs
	// the stage/AdptCrvReq/enable transaction on a curve the DER is already
	// executing. On models 707-710 that is a re-adopt against a LIVE PROTECTION
	// BOUNDARY, performed for no reason at all — verbatim the outcome
	// DesiredAdvancedMinV exists to prevent.
	//
	// There is a second, quieter half specific to this bump: a v3 document
	// carries no response time on any axis, so acting on one leaves model 705
	// RspTms wherever the DER had it while the head end is told the curve landed
	// — the bench-proven MEDIUM this field closes, surviving the upgrade that
	// closed it.
	//
	// ── v1 -> v2, v2 -> v3 (2026-08-15) ──────────────────────────────────────
	//
	// Bumped to 3 the same day as 2, for the SECOND: AdvCurve.CurveType is the same rebound
	// DERCurveType value space CurveSetV=2 fences (see there), carried verbatim
	// from CurveSetEntry onto every curve and trip axis and hashed into every
	// AdvCurve.Hash and AdvTripSet.Hash. A v2 adv document is therefore a
	// document whose per-axis re-adoption keys were computed over the draft's
	// numbering.
	//
	// The v2 -> v3 hazard is narrower than v1 -> v2 and is still a hazard. The
	// self-consistency check CANNOT see it — advCurveSelfInconsistent re-hashes
	// using the DOCUMENT'S OWN CurveType at both ends, so a v2 document
	// reconciles perfectly with itself — which is exactly the "rebind that KEEPS
	// the string" blind spot the paragraph below names. What a mixed pair
	// produces is a spurious re-adopt: the same curve, republished with the
	// corrected code, hashes differently, so the shell sees a changed target and
	// re-runs the stage/AdptCrvReq/enable transaction on a curve the DER is
	// already executing. On 707-710 that is a re-adopt transaction against a
	// LIVE PROTECTION BOUNDARY, which this product refuses to do for no reason.
	//
	// WHAT CHANGED, and why it is not additive. At v1 a document whose
	// ReactiveMode.Kind was "watt_var" carried opModWattPF's curve: the
	// authority mapped CurveModeWattPF onto AdvReactiveWattVar, and the
	// reconciler mapped that axis back to mode "watt_pf" when it recomputed the
	// content hash. At v2, "watt_var" means opModWattVar and nothing else, and
	// opModWattPF has its own kind. No FIELD was added or removed — the VALUE
	// SPACE of an existing field was rebound, which is exactly the change
	// AD-006's additive rule cannot absorb: a v1 document decodes cleanly into
	// the v2 struct and means a different function.
	DesiredAdvancedV = 4 // lexa/desired/adv/{device} (DesiredAdvanced)
	// THE OBLIGATION THIS FAMILY CARRIES, stated here because the machinery
	// that protects it CANNOT DERIVE IT.
	//
	// Consumers of this family run a self-consistency check: a curve axis's
	// payload is re-hashed from the document's own points under the mode name
	// the consumer maps that axis to, and the axis is refused when the result
	// disagrees with the hash the document claims. That catches a rebind which
	// MOVES a mode string (the v1->v2 case: opModWattPF's curve was hashed
	// under "watt_pf" while riding the "watt_var" kind, so the recomputation
	// could never match).
	//
	// It CANNOT catch a rebind that KEEPS the string. Redefine what an existing
	// AdvReactive* Kind or CurveMode* name MEANS, leave the name alone, and
	// every hash still reconciles perfectly while both ends execute different
	// functions — silently, with no test failing anywhere.
	//
	// So: ANY CHANGE TO WHAT AN EXISTING Kind, Mode OR CurveType VALUE MEANS —
	// not merely adding a new one — MUST raise DesiredAdvancedMinV in the same
	// commit. Adding a genuinely new name is additive and does not. The two
	// STRING vocabularies are pinned as CLOSED SETS by tests in this package
	// (TestAdvReactiveKindVocabularyIsAClosedSet,
	// TestCurveModeVocabularyCarriesWattVar) so that touching either is a
	// deliberate edit a reviewer sees next to this paragraph.
	//
	// CurveType JOINED THAT SENTENCE ON 2026-08-15, AND ITS ABSENCE IS WHY THE
	// v3 BUMP WAS NEARLY MISSED. As written, the obligation named the two
	// vocabularies whose values are STRINGS — the ones a closed-set test can
	// pin — and said nothing about the third value space in the same hash line,
	// which is an integer owned by another repository. The IEEE 2030.5-2018
	// re-anchoring (registry IW15-027) rebound every DERCurveType code without
	// touching a single identifier here, so no closed-set test could have fired
	// and no field changed name. A hash input that is a number is exactly as
	// rebindable as one that is a word; the rule was always about MEANING and
	// now says so. There is no test that can pin this one from inside this
	// package — the authority is lexa-proto's csipmodel, whose own 2018-anchored
	// tests are the witness — so this paragraph is the control, deliberately.
	//
	// ── DesiredAdvancedMinV ──────────────────────────────────────────────────
	//
	// DesiredAdvancedMinV is the OLDEST DesiredAdvanced a consumer may ACT ON.
	//
	// IT MUST TRACK DesiredAdvancedV ON EVERY BUMP THIS FAMILY EVER TAKES, and
	// that is not a convention — it follows from the paragraphs above. The only
	// changes this schema is permitted to take non-additively are rebinds of an
	// existing value space, and a rebind is by construction the one thing an
	// older document cannot survive. So a bump that leaves this constant behind
	// is not a lesser slip than forgetting the bump: it is the bump's entire
	// purpose silently omitted, with the version number standing as evidence
	// that the work was done.
	//
	// THAT IS EXACTLY WHAT HAPPENED ON 2026-08-15. V went to 3 for the
	// DERCurveType rebind; this constant stayed at 2; and FOUR separate pieces
	// of prose — the paragraph you are reading, lexa-gw's curveSetActionable
	// doc, a test comment, and an applied registry entry — asserted a floor of 3
	// that did not exist. A v2 document would have passed VersionAcceptable
	// carrying draft-numbered CurveTypes hashed into every AdvCurve.Hash, the
	// authority would have republished the same curve at v3 with the corrected
	// code and a different digest, and the shell would have re-run the
	// stage/AdptCrvReq/enable transaction against a LIVE PROTECTION BOUNDARY —
	// the precise outcome the V bump was raised to prevent.
	// TestDesiredAdvancedMinVTracksV is the control that was missing.
	//
	// Ordinary AD-006 policy is forward-compatible only: CheckVersion rejects a
	// version NEWER than the subscriber supports and accepts anything older,
	// because an older publisher's document is a subset of a newer one's and
	// absent fields decode to their zero values. That reasoning holds for every
	// other family in this file and is precisely wrong here — a v1 adv document
	// is not a smaller v2 document, it is one whose reactive kind names a
	// different function.
	//
	// The failure it prevents is a FLASH, not a mixed fleet. lexa/desired/adv/
	// is RETAINED, so the documents a unit published before an upgrade are
	// replayed to the first process that subscribes after it. All three bumps
	// have that shape and they fail differently, which is why each is described:
	//
	//   - v1 (the watt-PF/watt-var split). A v1 watt-PF document replayed into a
	//     v2 reconciler is a curve of POWER FACTORS bound to the var axis,
	//     carrying a hash no readback can reproduce: the shell writes model 712,
	//     fails verification, fail-closed disables, and retries on every backoff
	//     — driving the machine between the curve's endpoints indefinitely.
	//   - v2 (the DERCurveType re-anchoring, IW15-027). This one does NOT
	//     mis-write and is not caught by the self-consistency check either, which
	//     is what makes it easy to under-rate: a v2 document re-hashes perfectly
	//     against itself, because the recomputation uses the document's own
	//     CurveType at both ends. What it produces is a SPURIOUS RE-ADOPT. The
	//     authority republishes the identical curve with the corrected code, the
	//     digest moves, the shell sees a changed target and re-runs the
	//     stage/AdptCrvReq/enable transaction on a curve the DER is already
	//     executing. On models 707-710 that is a re-adopt against a live
	//     protection boundary, performed for no reason at all.
	//   - v3 (openLoopTms entering the canonical hash line, 2026-08-16). Same
	//     spurious-re-adopt shape as v2 and for the same structural reason — a v3
	//     document re-hashes perfectly against itself, because it has no
	//     openLoopTms at either end of the recomputation — plus a second half v2
	//     did not have: a v3 document commands NO response time on any axis, so
	//     acting on one leaves model 705 RspTms wherever the DER happened to have
	//     it while the head end is told the curve landed. That is the bench-proven
	//     defect the field was added to close, laundered past the upgrade that
	//     closed it.
	//
	// Refusing the document is the only answer that leaves the DER where it was.
	//
	// Deliberately a SEPARATE constant rather than a change to CheckVersion's
	// rule, so the exception is visible at the one family that needs it and
	// every other family keeps the cheap additive path.
	DesiredAdvancedMinV = 4

	// OpenADR schemas (WP-15, standards-buildout E1). All born at 1, same
	// convention as every family above; types + topic constants in
	// internal/bus/openadr.go.
	OpenADRPricesV = 1 // lexa/openadr/prices (OpenADRPrices)
	OpenADRLimitsV = 1 // lexa/openadr/limits (OpenADRLimits)
	OpenADRStatusV = 1 // lexa/openadr/status (OpenADRStatus)

	// PairingDecision schema (WP-13, standards-buildout B2/D10). Born at 1,
	// same convention as every family above; type + topic constant in
	// internal/bus/pairing.go.
	PairingDecisionV = 1 // lexa/ocpp/pairing (PairingDecision)
)

// LegacyV0Accepted is the transition switch for AD-006's compatibility
// policy. While true (the default), a message with no "v" field — which is
// indistinguishable on the wire from an explicit "v":0, since omitempty
// never serializes zero — is treated as a legacy v0 publisher and accepted.
// Once every publisher in a topic's family is confirmed to stamp v>=1
// (tracked by TASK-018), this is flipped to false so stragglers are rejected
// instead of silently tolerated forever. It is a package-level var, not a
// per-topic setting, because the transition is expected to be a single
// repo-wide cutover; a later task can promote it to per-topic config if that
// assumption stops holding.
var LegacyV0Accepted = true

// VersionError is returned by CheckVersion when a message's envelope version
// falls outside the range a subscriber supports. It is exported (not just an
// error string) so callers can inspect Topic/Got/Supported — e.g. to decide,
// per AD-006, whether a rejected retained control-plane message should hold
// last-known-good (now) or trigger a re-request (TASK-042, later).
type VersionError struct {
	Topic     string
	Got       int
	Supported int
}

func (e *VersionError) Error() string {
	return fmt.Sprintf("bus: %s: version %d exceeds supported %d", e.Topic, e.Got, e.Supported)
}

// CheckVersion peeks at payload's envelope version and reports whether a
// subscriber supporting versions 1..supported should accept the message.
// It does not unmarshal into the real message type and never mutates
// anything; it is meant to run before the real json.Unmarshal in a decode
// path (TASK-018 wires this into mqttutil.Subscribe).
//
// Decode policy (AD-006):
//   - "v" absent (equivalently, an explicit "v":0 — the two are indistinguishable
//     given omitempty) is legacy v0: accepted while LegacyV0Accepted is true,
//     rejected once it is flipped false.
//   - 1 <= v <= supported: accepted.
//   - v > supported, or v < 0: rejected, returns *VersionError.
//   - Unknown fields alongside a supported v are not this function's concern:
//     Go's json.Unmarshal already ignores unrecognized keys by default, which
//     is what keeps additive (same-major) schema evolution cheap.
//
// Malformed-JSON responsibility (recorded here per the task's design
// requirement): CheckVersion's internal peek unmarshals only into a
// struct{ V int }. If that peek itself fails — payload is not a JSON object,
// or "v" is present but is not a JSON number (e.g. a string) — CheckVersion
// returns nil rather than an error. It deliberately does not attempt to
// detect or report malformed JSON: that is the real json.Unmarshal's job,
// a few lines later in the same decode path, and it is single-responsibility
// for CheckVersion to leave it there rather than duplicate (and risk
// disagreeing with) that error. A malformed payload that passes CheckVersion
// will fail the subsequent real unmarshal and be logged there, exactly as it
// is today with no version envelope at all.
func CheckVersion(topic string, payload []byte, supported int) error {
	var peek struct {
		V int `json:"v"`
	}
	if err := json.Unmarshal(payload, &peek); err != nil {
		// Malformed JSON or a non-integer "v" — not our job to flag; see the
		// doc comment above.
		return nil
	}
	if peek.V == 0 {
		if LegacyV0Accepted {
			return nil
		}
		return &VersionError{Topic: topic, Got: 0, Supported: supported}
	}
	if peek.V < 0 || peek.V > supported {
		return &VersionError{Topic: topic, Got: peek.V, Supported: supported}
	}
	return nil
}

// CheckVersionAtLeast is CheckVersion with a FLOOR as well as a ceiling: it
// accepts min <= v <= supported and rejects everything else, including the
// legacy v0/absent envelope regardless of LegacyV0Accepted.
//
// WHEN TO REACH FOR IT, stated narrowly because reaching for it by default
// would make every additive field a breaking change. Use it only where a
// version bump REBOUND THE MEANING of existing wire content rather than adding
// to it — where an older document decodes without error and says something the
// consumer would act on wrongly. DesiredAdvancedMinV is the first and only such
// case in this repo; its constant carries the specific reasoning.
//
// v0 is refused whenever min > 0 and it is not a special case: an envelope with
// no version cannot possibly be at or above a floor above zero, and
// LegacyV0Accepted's tolerance is about publishers that never learned to stamp
// a version, not about documents whose content has since changed meaning.
//
// The VersionError reports Supported (the ceiling) so existing handlers and
// metrics keep working unchanged; the floor is named in the log line at the
// call site, which is where an operator needs it.
func CheckVersionAtLeast(topic string, payload []byte, min, supported int) error {
	if err := CheckVersion(topic, payload, supported); err != nil {
		return err
	}
	if min <= 0 {
		return nil
	}
	var peek struct {
		V int `json:"v"`
	}
	if err := json.Unmarshal(payload, &peek); err != nil {
		// Same single-responsibility rule as CheckVersion: a malformed payload
		// is the real unmarshal's error to report, not ours.
		return nil
	}
	if peek.V < min {
		return &VersionError{Topic: topic, Got: peek.V, Supported: supported}
	}
	return nil
}

// rejectCounters holds one *uint64 per topic that has ever had a version
// rejected, incremented atomically by RejectAndAlarm. A sync.Map is used
// instead of a mutex+map because the write pattern (rare new keys, frequent
// increments to existing keys) is exactly what it's optimized for, and this
// is called from arbitrary subscriber goroutines.
var rejectCounters sync.Map // topic string -> *uint64

// logEveryN is the log rate-limit divisor for RejectAndAlarm: the first
// rejection recorded for a topic, and every logEveryNth one after, is
// logged; the rest only increment the counter. It is a var rather than a
// const solely so tests can shrink it and exercise the rate-limit path
// without firing hundreds of messages; production code has no reason to
// change it.
var logEveryN uint64 = 100

// RejectAndAlarm records one version rejection for err.Topic: it increments
// that topic's counter (exposed via VersionRejects for TASK-044's metrics
// endpoint to scrape once it exists) and emits a rate-limited structured log
// line. Logging is deliberately not one-line-per-message: a publisher stuck
// on the wrong schema version would otherwise spam the journal past its
// budget (TASK-009), so only the first rejection for a topic and every
// logEveryNth one after are logged.
func RejectAndAlarm(err *VersionError) {
	if err == nil {
		return
	}
	v, _ := rejectCounters.LoadOrStore(err.Topic, new(uint64))
	n := atomic.AddUint64(v.(*uint64), 1)
	if n == 1 || n%logEveryN == 0 {
		// TASK-045: migrated to slog (rate-limited decode-reject alarm).
		// "REJECT" kept intact in the message text.
		slog.Warn("[bus] REJECT unknown schema version",
			"topic", err.Topic, "v", err.Got, "supported", err.Supported, "count", n)
	}
}

// VersionRejects returns a snapshot of the per-topic reject counters
// maintained by RejectAndAlarm. Nothing scrapes this yet — TASK-044 is the
// consumer once a metrics endpoint exists.
func VersionRejects() map[string]uint64 {
	out := make(map[string]uint64)
	rejectCounters.Range(func(k, v any) bool {
		out[k.(string)] = atomic.LoadUint64(v.(*uint64))
		return true
	})
	return out
}

// decodeFailCounters holds one *uint64 per topic that has ever had a decode
// failure recorded by RecordDecodeFailure. Same sync.Map rationale as
// rejectCounters just above: rare new keys, frequent increments to existing
// ones, called from arbitrary subscriber goroutines. Kept as a distinct map
// (a sibling of rejectCounters, not a shared one) because a version reject
// and a decode/finite failure are different failure modes worth telling
// apart in a topic's history, even though both are meant to roll up into the
// same lexa_bus_decode_failures_total total.
var decodeFailCounters sync.Map // topic string -> *uint64

// RecordDecodeFailure records one decode failure for topic: either a raw
// json.Unmarshal error, or a message that unmarshalled successfully but
// failed its own Finite() check (GAP-09 — a non-finite numeric value that
// slipped past a lax decode path). It is mqttutil.Subscribe's sibling to
// RejectAndAlarm — same rate-limited counter+log shape — for the failure
// mode CheckVersion/RejectAndAlarm does not cover: today, a plain
// json.Unmarshal failure on a non-control topic is only ever log.Printf'd
// (mqttutil.go), invisible to anything scraping metrics. This turns that
// silent drop into a counted, alarmed one, matching the treatment a version
// rejection already gets.
func RecordDecodeFailure(topic string, err error) {
	if err == nil {
		return
	}
	v, _ := decodeFailCounters.LoadOrStore(topic, new(uint64))
	n := atomic.AddUint64(v.(*uint64), 1)
	if n == 1 || n%logEveryN == 0 {
		slog.Warn("[bus] REJECT decode failure",
			"topic", topic, "err", err, "count", n)
	}
}

// DecodeFailures returns a snapshot of the per-topic decode-failure counters
// maintained by RecordDecodeFailure. Sibling of VersionRejects; a caller
// wiring lexa_bus_decode_failures_total (TASK-044) should sum both this and
// VersionRejects — today only VersionRejects feeds that metric (see each
// service's main.go Collect callback), which is exactly the GAP-09 gap this
// task exists to close. Wiring the sum into those six main.go files is a
// follow-up outside this task's internal/bus + mqttutil lane.
func DecodeFailures() map[string]uint64 {
	out := make(map[string]uint64)
	decodeFailCounters.Range(func(k, v any) bool {
		out[k.(string)] = atomic.LoadUint64(v.(*uint64))
		return true
	})
	return out
}
