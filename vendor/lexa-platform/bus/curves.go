// Promoted from lexa-hub@5218e6a (2026-07-17)

package bus

// CurveSet bus contract (WP-8, standards-buildout C1 / architecture §2.3 +
// D6 preamble): lexa-northbound resolves the active DER control's
// curve-linked modes (DERControlBase opMod*Link hrefs → DERCurve resources,
// fetched during the discovery walk) and publishes the resolved content
// RETAINED on TopicCSIPCurves as one CurveSet. The hub (WP-9's adv-doc
// author) consumes it alongside ActiveControl, correlating the two docs by
// ActiveControl.CurveSetID == CurveSet.SetID.
//
// Content-addressed identity: SetID is CurveSetContentHash over the
// canonicalized entries (below) — pure curve CONTENT, not resource identity
// — so a server that reissues byte-identical curve shapes under new resource
// MRIDs/hrefs does not force downstream re-adoption, and a reconciler can
// recompute the same hash from a device READBACK (which has no MRID to
// offer) to verify adoption (D6's "content hashes let both sides skip no-op
// re-adoptions").

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strconv"
)

// Curve-linked mode names carried in CurveSetEntry.Mode — the same
// vocabulary DERScheduleSlot's curve JSON keys already use, so the two docs
// never disagree on what a mode is called.
//
// CurveModeWattVar closes a hole in this list. sep 2.0.4 defines FIVE shaping
// curve links on DERControlBase — opModVoltVar, opModFreqWatt, opModWattPF,
// opModVoltWatt and **opModWattVar** (DERCurveType 10) — and this vocabulary
// carried only the first four. With no name for watt-var, lexa-gw routed
// opModWattPF's curve content into SunSpec model 712, the WATT-VAR model,
// because 712 was the only watt-shaped reactive register home the vocabulary
// could reach. That substitution is the IW15-001 pathology on the curve family
// (lexa-gw docs/design/LEGACY_CURVES_RC0_2026-08-14.md §3.2 calls it
// unshippable: a power-FACTOR curve executed as a VAR curve, with the head end
// told it landed).
//
// After this the two modes are 1:1 with their register homes and NEITHER
// GENERATION HAS BOTH: opModWattVar → 712 (7xx only), opModWattPF → legacy
// model 131 (12x only). Naming watt-var here is what lets each be routed —
// or refused — under its own identity instead of one wearing the other's.
const (
	CurveModeVoltVar                = "volt_var"
	CurveModeFreqWatt               = "freq_watt"
	CurveModeWattPF                 = "watt_pf"
	CurveModeWattVar                = "watt_var"
	CurveModeVoltWatt               = "volt_watt"
	CurveModeHFRTMayTrip            = "hfrt_may_trip"
	CurveModeHFRTMustTrip           = "hfrt_must_trip"
	CurveModeHVRTMayTrip            = "hvrt_may_trip"
	CurveModeHVRTMomentaryCessation = "hvrt_momentary_cessation"
	CurveModeHVRTMustTrip           = "hvrt_must_trip"
	CurveModeLFRTMayTrip            = "lfrt_may_trip"
	CurveModeLFRTMustTrip           = "lfrt_must_trip"
	CurveModeLVRTMayTrip            = "lvrt_may_trip"
	CurveModeLVRTMomentaryCessation = "lvrt_momentary_cessation"
	CurveModeLVRTMustTrip           = "lvrt_must_trip"
)

// CurveSet is the retained curve-content document on TopicCSIPCurves
// (northbound → hub, QoS 1, WP-8). One entry per curve-linked mode the
// active control carries a RESOLVABLE curve for ("per-mode presence": a mode
// absent from Curves is not commanded, or its href did not resolve — the
// latter is alarmed at the walker, never silent). An empty set (SetID "",
// no entries) is the explicit "the active control links no curves" state,
// published so a superseded curve set does not linger retained.
type CurveSet struct {
	Envelope

	// SetID is CurveSetContentHash(Curves): "" for an empty set, else the
	// hex SHA-256 of the canonicalized entries. ActiveControl.CurveSetID on
	// the matching lexa/csip/control publish carries the same value.
	SetID string `json:"set_id,omitempty"`

	// MRID is the DERControl/DefaultDERControl the curves accompany (the
	// same value as the matching ActiveControl.MRID). Identity metadata —
	// deliberately NOT part of the content hash.
	MRID string `json:"mrid,omitempty"`

	// Program is the DERProgram href the curves were resolved from.
	// Identity metadata — deliberately NOT part of the content hash.
	Program string `json:"program,omitempty"`

	// Curves holds one entry per present curve-linked mode, sorted by Mode
	// (the publisher's canonical order — also what the hash sorts by).
	Curves []CurveSetEntry `json:"curves,omitempty"`

	Ts int64 `json:"ts"` // Unix seconds of the publish
}

// CurveSetEntry is one resolved DERCurve bound to the curve-linked mode that
// referenced it. Points are the raw 2030.5 int32 breakpoints with the axis
// power-of-ten multipliers carried alongside (never pre-applied: applying
// 10^mult can overflow float precision, and the reconciler writes the raw
// register values anyway). ≤ 10 points per the 2030.5 DERCurve bound — the
// scheduler's plausibility gate rejects the whole control otherwise, and the
// publisher additionally refuses to emit an entry that fails the same gate.
type CurveSetEntry struct {
	Mode string `json:"mode"`           // CurveMode* vocabulary above
	MRID string `json:"mrid,omitempty"` // the DERCurve resource's mRID (metadata, not hashed)
	// CurveType is csipmodel's DERCurveType code — IEEE Std 2030.5-2018 printed
	// p.254. NOT "Table 19", which is what this comment used to say and which
	// named a table in a pre-publication ZigBee SEP 2.0.4 draft. Every code in
	// that enumeration moved when lexa-proto re-anchored (opModVoltVar 0 -> 11,
	// opModWattVar 10 -> 14, …); because this field is hashed into SetID, that
	// rebind is what CurveSetV = 2 / CurveSetMinV fence. See bus/envelope.go.
	CurveType uint16 `json:"curve_type"`
	XMult     int8   `json:"x_mult,omitempty"` // x-axis power-of-ten multiplier
	YMult     int8   `json:"y_mult,omitempty"` // y-axis power-of-ten multiplier
	// YRefType is the y-axis units context — DERUnitRefType, IEEE Std
	// 2030.5-2018 p.256 — when the server sent one (0 = N/A/absent). It cited
	// "Table 19" until 2026-08-15, which is a table in the SEP 2.0.4 draft, two
	// lines below the CurveType comment expanded in the same wave specifically
	// to renounce that citation. Left uncorrected it would have been the next
	// reader's evidence that the draft is still this package's reference.
	YRefType uint8 `json:"y_ref_type,omitempty"`

	// VRef is the volt-var x-axis reference adjustment — 2018 p.253, PerCent
	// [0..1]: "The nominal ac voltage (rms) adjustment to the voltage curve
	// points for Volt-Var curves." 0 means the server sent none.
	//
	// IT IS CARRIED FOR DISCLOSURE AND FOR THE HASH, NOT FOR EXECUTION. The
	// x-axis multiplication 2018 p.250 prescribes ("If VRef is present in
	// DERCurve, then the x value of each pair is additionally multiplied by
	// VRef/10 000") is applied by the AUTHORITY when it builds the advanced
	// document, so Points here stay verbatim from the served resource and
	// AdvCurve.Points arrive at the reconciler already referenced. Keeping the
	// raw pair on this document is what lets a reader see what the server
	// actually said; applying it before the advanced document is what keeps
	// AdvCurve free of a field the readback-hash recomputation would have to
	// know about.
	//
	// HASHED, AND THAT IS THE DEFECT IT CLOSES. Two volt-var curves with
	// identical breakpoints and different vRef are DIFFERENT CURVES — they
	// regulate at different voltages — and before this field existed they
	// canonicalized identically, so a server moving only the reference produced
	// a SetID collision and the gateway dropped the change as a no-op
	// re-adoption. A content hash that cannot see a content difference is not a
	// content hash.
	VRef uint16 `json:"v_ref,omitempty"`

	// OpenLoopTms is the curve's open-loop response time — 2018 p.253, UInt16
	// [0..1]: "Open loop response time, the time to ramp up to 90% of the new
	// target in response to the change in voltage, in hundredths of a second.
	// Resolution is 1/100 sec. A value of 0 is used to mean no limit. When not
	// present, the device SHOULD follow its default behavior." Its register home
	// is SunSpec model 705 RspTms (seconds — the conversion is /100, the same
	// kind of fixed decimal shift lexa-gw's advFreqDroop already applies for the
	// model 711 Ctl axis).
	//
	// IT IS A POINTER, AND THAT IS DELIBERATE — the one field on this struct
	// where the sibling zero-sentinel idiom is unavailable. VRef above and
	// YRefType before it both spell absence as 0, because neither has a
	// meaningful zero: a vRef of 0 would scale every x value to nothing, and
	// yRefType 0 is literally the standard's "N/A". openLoopTms is the opposite —
	// the standard GIVES ZERO ITS OWN MEANING. `openLoopTms: 0` is an explicit
	// command ("ramp with NO response-time limit") and an absent element is a
	// deliberate abstention that leaves the device on its configured default.
	// Those are different instructions to the machine, and a uint16 in which 0
	// also means "absent" can only carry one of them. lexa-proto's
	// csipmodel.DERCurve.OpenLoopTms is *uint16 for exactly this reason; this
	// carriage matches the northbound document rather than its neighbours.
	//
	// CARRIED FOR EXECUTION *AND* FOR THE HASH — unlike VRef, which is carried
	// for disclosure only because the authority folds it into Points before the
	// advanced document exists. There is nothing to fold openLoopTms into: it is
	// a response time, not an axis scale, so it must survive all the way onto
	// AdvCurve and be written to a register. That is why AdvCurve gained this
	// field (bus/desired_adv.go) where VRef deliberately did not.
	//
	// HASHED, AND THAT IS THE DEFECT IT CLOSES (RC0 wave, bench-proven MEDIUM).
	// Before this field existed the served value was discarded here, so lexa-gw's
	// vvFromDoc — which starts from the template it read back from the DEVICE and
	// overwrites only DeptRef and Points — left model 705 RspTms holding whatever
	// the DER already had. Carriage alone would have been the more dangerous
	// half-fix: two curves differing only in openLoopTms would still canonicalize
	// identically, so the reconciler would recompute the SAME digest for the
	// response time it commanded and the response time the device actually holds,
	// and readback verification would PASS on the wrong RspTms. A content hash
	// that cannot see a content difference is not a content hash.
	OpenLoopTms *uint16      `json:"open_loop_tms,omitempty"`
	Points      []CurvePoint `json:"points"` // ordered (x, y) breakpoints, 1..10
}

// ContentHash returns CurveSetContentHash over the set's entries.
func (cs CurveSet) ContentHash() string {
	return CurveSetContentHash(cs.Curves)
}

// VersionAcceptable reports whether this DECODED curve set is one this build may
// ACT ON: at or above CurveSetMinV.
//
// The exact counterpart of DesiredAdvanced.VersionAcceptable, and a method for
// the same reason: the floor belongs next to the constant that explains it, not
// copied as `cs.V >= 2` into whichever process happens to subscribe. mqttutil's
// decode path already enforces the CEILING; this is the other end.
//
// UNLIKE the adv family there is no re-seed carve-out, because there is no
// latch: a CurveSet is pure content. Refusing one leaves the correlation
// unsatisfied, and lexa-gw's buildAdvLocked answers an unsatisfied correlation
// with a fail-closed HOLD — it authors nothing and releases nothing — which is
// exactly the disposition a document of unknown vintage deserves.
func (cs CurveSet) VersionAcceptable() bool { return cs.V >= CurveSetMinV }

// CurveSetContentHash is the canonical content hash for a curve set (WP-8,
// pinned by TestCurveSetContentHash_Pinned). Canonicalization:
//
//   - entries are sorted by Mode (each mode appears at most once, so the
//     sort is total) — field/slice order in the caller's hands never moves
//     the hash;
//   - each entry contributes the line
//     "mode|curveType|xMult|yMult|yRefType|vRef|openLoopTms|x1,y1;x2,y2;...;\n"
//     (decimal integers, the exact delimiters shown) to a single SHA-256,
//     except openLoopTms, which is the decimal value when the server sent one
//     and the single character "-" when it did not — see below;
//   - the hash is the lowercase hex digest;
//   - zero entries hash to "" — the same "no curves" sentinel
//     ActiveControl.CurveSetID uses (architecture §2.2).
//
// Deliberately EXCLUDED: entry MRID, set MRID/Program/Ts — those are
// resource identity/metadata, and the hash is content-addressed (see the
// package comment). Any change to this canonicalization is a CurveSetV
// version bump: both publisher and every consumer must agree on it.
//
// vRef JOINED THE LINE ON 2026-08-15 and that IS such a change — a real
// canonicalization move, unlike the CurveSetV = 2 bump beside it, which was a
// rebind of an existing field's value space under an unchanged canonical form.
// It needed no SECOND bump only because v2 was unreleased WHEN IT LANDED: both
// changes went in on the same day, inside one unpushed version generation, so v1
// remained the whole of what a consumer must refuse and v2 the whole of what it
// must accept. That reasoning was correct and it was time-boxed.
//
// openLoopTms JOINED THE LINE ON 2026-08-16 AND DID TAKE ITS OWN BUMP —
// CurveSetV = 3, CurveSetMinV = 3 — because the escape clause above had expired
// by then. The v2 generation had left this working tree: f2bdbf7 and 2720e44 are
// PUBLISHED on the remediation branch, so digests computed under the v2 form now
// exist outside the commit that defined it. Changing the canonical form under an
// unchanged version number would leave two builds both calling themselves v2 and
// disagreeing on the digest — the one state a version number exists to make
// impossible, and one no consumer could even detect, since the version is the
// only signal that would have told it. So this took the default path the
// paragraph above states, not the exception beside it.
//
// A CORRECTION TO THAT ARGUMENT'S FIRST DRAFT, recorded because the wrong
// version of it is a trap for the next reader. It originally read "a second
// repository already AGREES on the v2 canonical form", naming lexa-gw. LEXA-GW
// IS NOT A WITNESS TO ANYTHING HERE: it VENDORS this package, so it agrees with
// whatever this file says, trivially and always. The only INDEPENDENT
// implementation is csip-tls-test's hand-written mirror
// (cmd/dashboard/mayhem_adv.go's advCurveSetContentHash — six inputs: mode,
// curveType, xMult, yMult, yRefType, points) and it agrees with NEITHER v2 NOR
// v3, having never been taught vRef either. The bump decision does not rest on
// agreement and never needed to: it rests on v2 having been published at all.
// The independent mirror's drift is a defect in that repository, on its own
// worklist, and it is evidence FOR this bump rather than against it — a
// canonicalization that has an out-of-tree reimplementation is exactly the kind
// that must never move without a version to announce it.
//
// THE ABSENT TOKEN IS "-", NOT 0, and the reason is the whole of why this field
// is a pointer (see CurveSetEntry.OpenLoopTms): the standard gives 0 its own
// meaning ("no limit"), so a canonical form that spelled absence as 0 would hash
// "the server said ramp without limit" and "the server said nothing" to the same
// digest — a content collision between two different instructions, reintroduced
// at the exact layer this field was added to close. The form stays FIXED-ARITY:
// every entry contributes the same number of "|"-delimited tokens whether or not
// the element was served, so no entry can be confused with a differently-shaped
// one.
//
// TWO LIMITS OF THAT CLAIM, both PRE-EXISTING and neither closed here — stated
// because "cannot be read two ways" would otherwise read as stronger than the
// code:
//
//   - THE LINE HAS NO ESCAPING. Mode is a plain Go string interpolated into a
//     "|"-delimited record, so a mode name containing "|" or a newline could in
//     principle forge a different record. What actually prevents it is that Mode
//     is drawn from the CurveMode* vocabulary — a closed set of lowercase
//     identifiers, pinned by tests in this package — and never from server-
//     supplied text. That is a PUBLISHER INVARIANT this function does not
//     enforce and could not check cheaply; injectivity rests on it.
//   - MODE UNIQUENESS IS ASSUMED, NOT ENFORCED. The bullet above says "each mode
//     appears at most once, so the sort is total". That is the CurveSet
//     publisher's per-mode-presence contract, not something checked here. Feed
//     two entries with the same Mode and the sort is no longer total, so the
//     digest depends on their incoming order — the one case where "field/slice
//     order in the caller's hands never moves the hash" does not hold. The sort
//     below is SliceStable rather than Slice specifically so that this
//     degenerate input is at least DETERMINISTIC for a given input order, rather
//     than depending on the standard library's pivot choice; making it
//     order-INDEPENDENT would require rejecting duplicates, which needs an error
//     return this signature does not have.
func CurveSetContentHash(entries []CurveSetEntry) string {
	if len(entries) == 0 {
		return ""
	}
	sorted := make([]CurveSetEntry, len(entries))
	copy(sorted, entries)
	// Stable: with the publisher's per-mode-presence invariant held the sort is
	// total and stability is irrelevant, but if it is ever violated a stable sort
	// keeps the digest a deterministic function of the input instead of an
	// implementation detail of sort.Slice's pivot selection. See the doc above.
	sort.SliceStable(sorted, func(i, j int) bool { return sorted[i].Mode < sorted[j].Mode })

	h := sha256.New()
	for _, e := range sorted {
		fmt.Fprintf(h, "%s|%d|%d|%d|%d|%d|%s|", e.Mode, e.CurveType, e.XMult, e.YMult,
			e.YRefType, e.VRef, openLoopTmsToken(e.OpenLoopTms))
		for _, p := range e.Points {
			fmt.Fprintf(h, "%d,%d;", p.X, p.Y)
		}
		h.Write([]byte("\n"))
	}
	return hex.EncodeToString(h.Sum(nil))
}

// openLoopTmsToken renders the optional open-loop response time for the
// canonical hash line: its decimal value when served, "-" when absent. "-"
// cannot collide with any rendering of a UInt16, which is what keeps "no limit"
// (0) and "no opinion" (absent) distinct inputs to the digest.
func openLoopTmsToken(v *uint16) string {
	if v == nil {
		return "-"
	}
	return strconv.FormatUint(uint64(*v), 10)
}
