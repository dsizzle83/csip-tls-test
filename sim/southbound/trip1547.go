package sim

// trip1547.go — SunSpec models 707/708/709/710 (DERTripLV / DERTripHV /
// DERTripLF / DERTripHF): the IEEE 1547-2018 voltage and frequency trip curves.
//
// WHY these are a separate file rather than four more rows in solarCurveSpecs.
// The 7xx curve models this sim already serves (705/706/711/712) share one
// geometry: a header, then NCrv curves, each a fixed per-curve layout followed
// by NPt (x,y) pairs. populateCurveModel encodes exactly that. The trip models
// do not fit it in three separate ways:
//
//	1. There is no per-curve layout at all. lexa-proto ships L707Hdr/L709Hdr and
//	   nothing else, because a trip "curve-set" has no fixed preamble beyond a
//	   single ReadOnly register.
//	2. Each curve-SET holds THREE sub-curves — must-trip, may-trip and
//	   momentary-cessation — laid out end to end, each with its own ActPt.
//	3. A point is not two registers. A voltage point is V(uint16) + Tms(uint32)
//	   = 3 registers; a frequency point is Hz(uint32) + Tms(uint32) = 4.
//
// Bending curveModelSpec around that would have made the common path harder to
// read for the four models it already serves correctly, so the trip geometry
// gets its own populator and its own descriptor. The ADOPT handshake is NOT
// duplicated: both paths call SolarServer.adoptInto, so the §3.1.2 semantics —
// including the curve_adopt_lies fault — have one implementation.
//
// # The default curves, and where each number was READ from
//
// The trip points below are the DEFAULT settings IEEE Std 1547-2018 specifies.
// They were read from the local copy of the standard —
// ~/Documents/standards/1547-2018.pdf, the same corpus lexa-proto's
// docs/schema/NORMATIVE_ANCHOR.md anchors its 2030.5 page cites to — and not
// from memory:
//
//	Table 13 (DER response (shall trip) to abnormal voltages, for a DER of
//	abnormal operating performance Category III) —
//	    UV2  0.50 pu   2 s        OV1  1.10 pu   13 s
//	    UV1  0.88 pu  21 s        OV2  1.20 pu    0.16 s
//
//	Table 18 (DER response (shall trip) to abnormal frequencies) — ONE table
//	serves Category I, Category II and Category III alike, which is why no
//	category qualifies the frequency rows the way it qualifies the voltage ones —
//	    UF2  56.5 Hz   0.16 s     OF1  61.2 Hz  300 s
//	    UF1  58.5 Hz  300 s       OF2  62.0 Hz    0.16 s
//
// THE TABLE NUMBERS WERE WRONG HERE UNTIL AN ADVERSARIAL GATE CAUGHT THEM, and
// the correction is recorded rather than quietly applied. This file (6 sites),
// trip1547_test.go (4) and solar_adv.go (1) cited "Table 11 (voltage trip
// settings)", "Table 12" and "Table 19 (frequency trip settings)". None of the
// three is the table these numbers come from: Table 11 is the shall-trip
// voltage table for Category I (UV1 0.70 pu / 2.0 s — not the row below),
// Table 12 is the same table for Category II (UV1 0.70 pu / 10.0 s), and Table
// 19 is a frequency RIDE-THROUGH requirements table, not a trip one. The VALUES
// transcribed below were right the whole time; the pointers saying where they
// came from were not, which is exactly the failure IW15-027 is named for — a
// citation nobody re-read.
//
// One site of the same mistake survives OUTSIDE these files and is named rather
// than left for the next sweep to find: curve12x_test.go's legacy 129/130 case
// still says "Table 11 Category III" over the same 0.50 pu / 2 s and 0.88 pu /
// 21 s pair, which is Table 13's.
//
// Two further on-machine witnesses agree with the corrected numbers, and are
// named so a reviewer has something to check that is not this comment:
//
//   - The standard's OWN cross-references. §10.6.7's Table 35 (Voltage trip
//     parameters, mandatory) gives the HV/LV trip curve points' range as "See
//     Table 11 through Table 13"; §10.6.8's Table 37 (Frequency parameters)
//     gives the HF/LF trip curve points' range as "See Table 18".
//   - The SunSpec Modbus IEEE 1547-2018 Profile Specification and
//     Implementation Guide v1.1 (~/Documents/standards/SunSpec-Modbus-IEEE-
//     1547-2018-Profile-Specification-and-Implementation-Guide-v1.1-1.pdf),
//     which says in §2.10 "Table 13 in IEEE 1547-2018 specifies ranges and
//     default for high and low voltage trip" and in §2.12 the same sentence for
//     "Table 18" and frequency.
//
// Model 707 carries the two UNDER-voltage points, 708 the two OVER-voltage
// points, 709 the two under-frequency points and 710 the two over-frequency
// points, which is the split the model IDs themselves name (LV/HV/LF/HF).
//
// # The must-trip curves are TWO points where the profile maps FIVE
//
// Named because it is a real divergence and a reader will otherwise find it
// alone. The SunSpec profile's §2.10 worked example represents each 1547
// voltage trip setting pair as a FIVE-point curve — its Table 25 requires
// Crv.MustTrip.Pt[1-5].V/.Tms of a 707/708 — where points 2 and 4 carry the
// UV2/UV1 (OV2/OV1) settings and the other three exist only "to provide a
// uniform method of representing all curves". This sim serves the two points
// that carry the settings and declares ActPt = 2.
//
// That is a fixture choice, and it is safe HERE for a checkable reason rather
// than a hopeful one: every consumer on this bench reads these blocks through
// lexa-proto's Parse707Set/Parse709Set, which honour ActPt, and nothing in this
// repo asserts the five-point form — internal/certify/suitemodbusserver's
// profile1547.go deliberately transcribes no point list for models 705-712. A
// run that had to meet the profile's own representation convention would need
// the three filler points added here, and would be a change to this file.
//
// # MustTrip is populated; MayTrip and MomCess declare zero points
//
// Only the must-trip sub-curve carries points. The other two are present —
// they have to be, the geometry is fixed by NPt and NCrvSet — and each declares
// ActPt = 0. The two have DIFFERENT reasons, and only one of them is a
// statement about the standard:
//
//   - MAY-TRIP has nothing to transcribe, and that is checkable from both
//     directions. IEEE 1547-2018's settings tables for this function are Table
//     35 (voltage trip, mandatory) and Table 36 (momentary cessation, not
//     mandatory); neither carries a may-trip row and no table in the standard
//     prints may-trip curve points. The SunSpec profile agrees from the model
//     side: its 707/708 REQUIRED points are Crv.MustTrip.* (Table 25) and its
//     OPTIONAL points are Crv.MomCess.* (Table 26) — the string "MayTrip"
//     occurs nowhere in the document. Inventing points here would make a
//     fixture assert a device characteristic nothing specifies.
//
//   - MOMENTARY CESSATION IS A CATEGORY III BEHAVIOUR — this file used to
//     assert the reverse, and the reverse was wrong in both halves. IEEE
//     1547-2018 Table 16 (voltage ride-through requirements, Category III)
//     prescribes "Momentary Cessation" as the operating mode in TWO regions:
//     1.10 < V ≤ 1.20 pu (minimum ride-through 12 s, maximum response 0.083 s)
//     and V < 0.50 pu (1 s, 0.083 s). Categories I and II — Tables 14 and 15 —
//     have no momentary-cessation row at all; their only mention of it is the
//     footnote on "Cease to Energize" saying that required cessation of current
//     exchange "may include momentary cessation or trip", which is a permitted
//     way of ceasing and not a prescribed operating mode. So a real Category III
//     DER may very well hold momentary-cessation curve points, and the emptiness
//     below is NOT a consequence of the category. The old sentence had it
//     exactly backwards, and the justification is rewritten rather than
//     word-swapped.
//
// So why IS MomCess empty? Because the SETTING is optional and this fixture
// declines it — a bench decision, stated as one:
//
//   - 1547 §10.6.7 splits the two functions on exactly this line: voltage trip
//     parameters "shall be available" for information exchange (Table 35) while
//     the momentary cessation threshold "may be available", and Table 36's own
//     title is "Momentary cessation parameters (not mandatory)", each of its two
//     rows repeating "Support for this setting is not mandatory".
//   - The SunSpec profile puts the whole Crv.MomCess group in its OPTIONAL table
//     for 707/708 (Table 26) and says in §2.11 "Support for the adjustment of
//     momentary cessation is optional in 1547-2018".
//
// AND THE PROFILE DOES PRINT DEFAULTS FOR IT, which is the fact that would make
// a "nothing to transcribe" claim false here as it is true for may-trip: §2.11
// gives low-voltage (V1=50, Tms1=0), (V2=50, Tms2=2) and high-voltage (V1=110,
// Tms1=0), (V2=110, Tms2=13). This sim deliberately does not serve them. An
// EMPTY momentary-cessation sub-curve is what makes any content found there
// attributable to a control that was published: BASIC-004 in
// internal/certify/suitecsip/ridethrough.go publishes opModLVRT/HVRT
// MomentaryCessation curves and its whole evidence is a before/after read of
// these very registers, so a fixture that shipped a default MC curve would ask
// every reader of that bundle to know the default before they could tell
// commanded content from resting state. A scenario that needs a DER arriving
// WITH momentary cessation configured should seed those profile defaults into a
// new spec rather than into these, and TestTripModelsServeCategoryIIIDefaults's
// MomCess assertion moves with it.
//
// ActPt = 0 is a declaration of zero active points, which every conformant
// reader honours; the 0xFFFF "not implemented" sentinel would instead claim the
// sub-curve is absent, which would contradict the NCrvSet/NPt geometry the same
// block advertises.

import (
	"fmt"

	"lexa-proto/sunspec"
)

const (
	// advTripNPt is the device's declared NPt for the trip models: the number
	// of points each sub-curve can hold.
	//
	// EIGHT, RAISED FROM FOUR, and the reason is a certification procedure
	// rather than a preference. CSIP CTP v1.3's BASIC-004 Figure 4 prescribes an
	// opModLVRTMustTrip curve of SEVEN breakpoints —
	// (150,0)(150,5000)(1200,5000)(1200,7000)(2200,7000)(2200,8800)(10000,8800)
	// in the Figure's own raw units — and Encode707Set REFUSES a curve with more
	// points than the device's declared NPt ("trip curve has %d points, device
	// NPt=%d"). At four, this bench could not hold the certification
	// procedure's own curve: the row would have failed on the FIXTURE's
	// geometry and reported it as a device or product finding. Eight is seven
	// plus one slot of headroom, which is the same margin the old four gave the
	// two-point 1547 defaults (Table 13 on the voltage side, Table 18 on the
	// frequency one).
	//
	// THE STATED RATIONALE FOR FOUR NO LONGER HOLDS AND IS NOT QUIETLY DROPPED.
	// It was: "it keeps every trip block inside the 125-register Modbus
	// single-read cap (707/708 = 87 registers, 709/710 = 111), so a gateway
	// reads each model in one transaction." Recomputed at NPt=8, from
	// lexa-proto's own size functions (derlayout.go) and the 7-register
	// L707Hdr/L709Hdr:
	//
	//	707/708  tripVSetSize(8)  = 1 + 3×(1 + 8×3) = 76 regs/set
	//	         7 + 2×76         = 159 registers   (was 7 + 2×40 = 87)
	//	709/710  tripHzSetSize(8) = 1 + 3×(1 + 8×4) = 100 regs/set
	//	         7 + 2×100        = 207 registers   (was 7 + 2×52 = 111)
	//
	// So BOTH families now EXCEED the 125-register single-read cap, and this
	// comment says so rather than leaving a reader with a superseded promise.
	// That is a change of behaviour and it is safe for one reason, checked and
	// not assumed: sunspec.Reader.ReadModel reads through readChunked, which
	// splits any block wider than maxHoldingRead (125, PI-MBUS-300's 0x7D) into
	// consecutive transactions and concatenates them. 159 becomes 125+34 and
	// 207 becomes 125+82. Model 701 (153 registers) already takes exactly this
	// path on every discovery walk, so it is exercised on every advanced run
	// rather than only by these four models — see
	// TestTripBlocksSpanTheChunkedRead, which asserts the arithmetic above and
	// reads a trip model back through the real chunking reader.
	//
	// WRITES ARE STILL SINGLE-TRANSACTION and that is the half worth stating,
	// because Reader.WriteModel does NOT chunk — it hands the whole slice to one
	// WriteHolding. derbase's adoptCurve writes one STAGING SET at a time: 76
	// registers for 707/708 and 100 for 709/710, both inside FC16's
	// 123-register ceiling.
	//
	// THAT is the ceiling that binds this constant, not the read one. At
	// advNPt's ten the frequency staging set would be
	// tripHzSetSize(10) = 1 + 3×(1 + 10×4) = 124 registers — one past FC16 —
	// and every 709/710 adopt would be refused by the transport. Eight leaves
	// the write at 100 with room, and nine (112) would still fit; the choice of
	// eight is Figure 4's seven points plus one, not the write ceiling.
	advTripNPt = 8

	// advNCrvSet is the number of curve-sets each trip model serves: index 0 is
	// the live, read-only set; index 1 is the writable staging set the §3.1.2
	// adopt handshake promotes.
	advNCrvSet = 2
)

// tripModelSpec is the static description of one trip model.
//
// Exactly one of voltPts / freqPts is non-nil, and that choice also selects the
// register geometry (3-register voltage points vs 4-register frequency points).
type tripModelSpec struct {
	id      uint16
	hdr     *sunspec.Layout
	npt     int
	sfs     map[string]int16
	voltPts []sunspec.TripVPoint
	freqPts []sunspec.TripHzPoint
}

// isVolt reports whether this model uses the 707/708 voltage geometry.
func (s tripModelSpec) isVolt() bool { return s.voltPts != nil }

// setSize returns the register span of one curve-set.
//
// It is derived from lexa-proto's own offset helpers rather than recomputed
// here. tripVSetSize/tripHzSetSize are unexported, but the difference between
// two consecutive set offsets is the same number and cannot drift from the
// parser that reads the block — which is the property that matters, because a
// sim whose stride disagreed with the decoder would serve a block that
// round-trips through nothing.
func (s tripModelSpec) setSize() int {
	if s.isVolt() {
		return sunspec.TripVSetOffset(1, s.npt) - sunspec.TripVSetOffset(0, s.npt)
	}
	return sunspec.TripHzSetOffset(1, s.npt) - sunspec.TripHzSetOffset(0, s.npt)
}

// setOffset returns the offset of curve-set i within the model's data block.
func (s tripModelSpec) setOffset(i int) int {
	if s.isVolt() {
		return sunspec.TripVSetOffset(i, s.npt)
	}
	return sunspec.TripHzSetOffset(i, s.npt)
}

// solarTripSpecs is the trip-model table. See the file comment for the source
// of every number in it.
var solarTripSpecs = []tripModelSpec{
	{
		id: sunspec.ModelDERTripLV, hdr: sunspec.L707Hdr, npt: advTripNPt,
		sfs: map[string]int16{"V_SF": -1, "Tms_SF": -2},
		// IEEE 1547-2018 Table 13, Category III under-voltage defaults, in
		// ascending voltage so a reader walks the curve the way it is drawn.
		voltPts: []sunspec.TripVPoint{{V: 50, Tms: 2}, {V: 88, Tms: 21}},
	},
	{
		id: sunspec.ModelDERTripHV, hdr: sunspec.L707Hdr, npt: advTripNPt,
		sfs: map[string]int16{"V_SF": -1, "Tms_SF": -2},
		// IEEE 1547-2018 Table 13, Category III over-voltage defaults.
		voltPts: []sunspec.TripVPoint{{V: 110, Tms: 13}, {V: 120, Tms: 0.16}},
	},
	{
		id: sunspec.ModelDERTripLF, hdr: sunspec.L709Hdr, npt: advTripNPt,
		sfs: map[string]int16{"Hz_SF": -3, "Tms_SF": -2},
		// IEEE 1547-2018 Table 18, under-frequency defaults (one table, all
		// three abnormal-operating-performance categories).
		freqPts: []sunspec.TripHzPoint{{Hz: 56.5, Tms: 0.16}, {Hz: 58.5, Tms: 300}},
	},
	{
		id: sunspec.ModelDERTripHF, hdr: sunspec.L709Hdr, npt: advTripNPt,
		sfs: map[string]int16{"Hz_SF": -3, "Tms_SF": -2},
		// IEEE 1547-2018 Table 18, over-frequency defaults (same table, same
		// all-category scope as 709's).
		freqPts: []sunspec.TripHzPoint{{Hz: 61.2, Tms: 300}, {Hz: 62.0, Tms: 0.16}},
	},
}

// tripBlock describes one served trip model, for the adopt handshake and the
// snapshot.
type tripBlock struct {
	id      uint16
	base    uint16 // data-block base address
	hdr     *sunspec.Layout
	volt    bool // 707/708 geometry when true, 709/710 when false
	npt     int
	setSize int // registers per curve-set
	dataLen int
	hdrLen  int
	reqOff  int // hdr offset of AdptCrvReq
	rsltOff int // hdr offset of AdptCrvRslt
}

// populateTripModel writes one trip model: the header, a live read-only
// curve-set at index 0 carrying the 1547 defaults (Table 13's Category III
// numbers on 707/708, Table 18's all-category numbers on 709/710), and an empty
// writable staging set at index 1.
//
// The header — NPt, NCrvSet and the scale factors — is written BEFORE the
// points, because Encode707Set/Encode709Set read NPt to find the set they are
// asked to write and resolve V_SF/Hz_SF/Tms_SF by name to scale it. Seeding the
// points first would encode them against a zero NPt and an absent SF.
func populateTripModel(r *RegisterMap, cursor uint16, spec tripModelSpec) (tripBlock, uint16) {
	setSize := spec.setSize()
	dataLen := spec.hdr.Len() + advNCrvSet*setSize
	base, next := writeModelHeader(r, cursor, spec.id, dataLen)

	regs := make([]uint16, dataLen)
	h := spec.hdr.View(regs)
	h.SetEnum("NPt", uint16(spec.npt))
	h.SetEnum("NCrvSet", advNCrvSet)
	for name, sf := range spec.sfs {
		setSF(regs, spec.hdr, name, sf)
	}

	// Curve-set 0 is the live set. Encode*Set writes ReadOnly = 0 (a staging
	// set is writable by definition), so the live set's read-only flag is
	// stamped back afterwards — the same rule adoptInto re-applies after every
	// promotion.
	//
	// A failure here cannot come from anything the DUT or an operator does: it
	// means solarTripSpecs declares more default points than the NPt beside
	// them, which is a bug in this file. It panics rather than truncating,
	// because a silently short trip curve is a fixture that asserts a device
	// characteristic nobody wrote down.
	if spec.isVolt() {
		if _, _, err := sunspec.Encode707Set(regs, 0, sunspec.VoltageTripSet{MustTrip: spec.voltPts}); err != nil {
			panic(fmt.Sprintf("sim: model %d default trip curve does not fit its declared NPt=%d: %v",
				spec.id, spec.npt, err))
		}
	} else {
		if _, _, err := sunspec.Encode709Set(regs, 0, sunspec.FreqTripSet{MustTrip: spec.freqPts}); err != nil {
			panic(fmt.Sprintf("sim: model %d default trip curve does not fit its declared NPt=%d: %v",
				spec.id, spec.npt, err))
		}
	}
	h.SetU16At(spec.setOffset(0), 1) // live set: read-only

	writeSlice(r, base, regs)

	return tripBlock{
		id: spec.id, base: base, hdr: spec.hdr, volt: spec.isVolt(),
		npt: spec.npt, setSize: setSize, dataLen: dataLen, hdrLen: spec.hdr.Len(),
		reqOff:  spec.hdr.Offset("AdptCrvReq"),
		rsltOff: spec.hdr.Offset("AdptCrvRslt"),
	}, next
}

// ── Snapshot ─────────────────────────────────────────────────────────────────

// advTripState is one trip model's ground truth on GET /state, so a QA oracle
// can read the served curve without a Modbus client. Points are (x, seconds):
// per-cent of nominal voltage for 707/708, hertz for 709/710.
type advTripState struct {
	Model     uint16       `json:"model"`
	AdoptRslt int          `json:"adopt_rslt"`
	ReadOnly  bool         `json:"read_only"`
	MustTrip  [][2]float64 `json:"must_trip"`
	MayTrip   [][2]float64 `json:"may_trip"`
	MomCess   [][2]float64 `json:"mom_cess"`
}

// tripSnapshot reads the live curve-set of every served trip model.
//
// It decodes through lexa-proto's Parse707Set/Parse709Set rather than walking
// the registers here, so the snapshot and the wire agree by construction: if
// the populator ever encoded a block the shipped parser cannot read, /state
// shows it immediately instead of reporting a curve nobody else can see.
func (ss *SolarServer) tripSnapshot() []advTripState {
	if len(ss.adv.Trips) == 0 {
		return nil
	}
	out := make([]advTripState, 0, len(ss.adv.Trips))
	for _, tb := range ss.adv.Trips {
		regs := readSlice(ss.Regs, tb.base, tb.dataLen)
		st := advTripState{
			Model:     tb.id,
			AdoptRslt: int(ss.Regs.Get(tb.base + uint16(tb.rsltOff))),
		}
		if tb.volt {
			set, err := sunspec.Parse707Set(regs, 0)
			if err != nil {
				out = append(out, st)
				continue
			}
			st.ReadOnly = set.ReadOnly
			st.MustTrip = tripVPairs(set.MustTrip)
			st.MayTrip = tripVPairs(set.MayTrip)
			st.MomCess = tripVPairs(set.MomCess)
		} else {
			set, err := sunspec.Parse709Set(regs, 0)
			if err != nil {
				out = append(out, st)
				continue
			}
			st.ReadOnly = set.ReadOnly
			st.MustTrip = tripHzPairs(set.MustTrip)
			st.MayTrip = tripHzPairs(set.MayTrip)
			st.MomCess = tripHzPairs(set.MomCess)
		}
		out = append(out, st)
	}
	return out
}

func tripVPairs(pts []sunspec.TripVPoint) [][2]float64 {
	if len(pts) == 0 {
		return nil
	}
	out := make([][2]float64, len(pts))
	for i, p := range pts {
		out[i] = [2]float64{p.V, p.Tms}
	}
	return out
}

func tripHzPairs(pts []sunspec.TripHzPoint) [][2]float64 {
	if len(pts) == 0 {
		return nil
	}
	out := make([][2]float64, len(pts))
	for i, p := range pts {
		out[i] = [2]float64{p.Hz, p.Tms}
	}
	return out
}
