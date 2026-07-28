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
// # The default curves
//
// The trip points below are the DEFAULT settings IEEE Std 1547-2018 specifies
// for a DER of abnormal operating performance Category III:
//
//	Table 11 (voltage trip settings), Category III defaults —
//	    UV2  0.50 pu   2 s        OV1  1.10 pu   13 s
//	    UV1  0.88 pu  21 s        OV2  1.20 pu    0.16 s
//
//	Table 19 (frequency trip settings), defaults for all categories —
//	    UF2  56.5 Hz   0.16 s     OF1  61.2 Hz  300 s
//	    UF1  58.5 Hz  300 s       OF2  62.0 Hz    0.16 s
//
// Model 707 carries the two UNDER-voltage points, 708 the two OVER-voltage
// points, 709 the two under-frequency points and 710 the two over-frequency
// points, which is the split the model IDs themselves name (LV/HV/LF/HF).
//
// # MustTrip is populated; MayTrip and MomCess declare zero points
//
// Only the must-trip sub-curve carries points. The other two are present —
// they have to be, the geometry is fixed by NPt and NCrvSet — and each declares
// ActPt = 0. That is the honest encoding, not a gap:
//
//   - IEEE 1547-2018 leaves the may-trip region between the must-trip curve and
//     the mandatory-operation region to the manufacturer. There is no default to
//     transcribe, and inventing one would make a fixture assert a device
//     characteristic the standard does not specify.
//   - Category III performs no momentary cessation (it is a Category II
//     behaviour), so a Category III device's momentary-cessation curve is
//     genuinely empty.
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
	// Four, not advNPt's ten. The Category III defaults need two points per
	// sub-curve, so four is real headroom for a staged adopt — and it keeps
	// every trip block inside the 125-register Modbus single-read cap
	// (707/708 = 87 registers, 709/710 = 111), so a gateway reads each model
	// in one transaction. Model 701 already exercises the chunked-read path
	// deliberately; there is nothing to gain by making four more models do it.
	advTripNPt = 4

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
		// IEEE 1547-2018 Table 11, Category III under-voltage defaults, in
		// ascending voltage so a reader walks the curve the way it is drawn.
		voltPts: []sunspec.TripVPoint{{V: 50, Tms: 2}, {V: 88, Tms: 21}},
	},
	{
		id: sunspec.ModelDERTripHV, hdr: sunspec.L707Hdr, npt: advTripNPt,
		sfs: map[string]int16{"V_SF": -1, "Tms_SF": -2},
		// IEEE 1547-2018 Table 11, Category III over-voltage defaults.
		voltPts: []sunspec.TripVPoint{{V: 110, Tms: 13}, {V: 120, Tms: 0.16}},
	},
	{
		id: sunspec.ModelDERTripLF, hdr: sunspec.L709Hdr, npt: advTripNPt,
		sfs: map[string]int16{"Hz_SF": -3, "Tms_SF": -2},
		// IEEE 1547-2018 Table 19, under-frequency defaults.
		freqPts: []sunspec.TripHzPoint{{Hz: 56.5, Tms: 0.16}, {Hz: 58.5, Tms: 300}},
	},
	{
		id: sunspec.ModelDERTripHF, hdr: sunspec.L709Hdr, npt: advTripNPt,
		sfs: map[string]int16{"Hz_SF": -3, "Tms_SF": -2},
		// IEEE 1547-2018 Table 19, over-frequency defaults.
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
// curve-set at index 0 carrying the Category III defaults, and an empty
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
