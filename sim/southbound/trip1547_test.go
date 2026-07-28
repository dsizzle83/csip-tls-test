package sim

// trip1547_test.go — the two things that have to be true about models 707-710.
//
//  1. What the sim ENCODES is what a conformant reader DECODES. The round-trip
//     tests below write the block with the sim's own populator and read it back
//     with lexa-proto's Parse707Set / Parse709Set — the same functions the
//     gateway and the conformance harness use. A sim that agreed only with
//     itself would serve a device nobody else can read, and every downstream
//     verdict taken against it would be measuring the fixture.
//
//  2. Adding them changed NOTHING for anyone who did not ask. The regression
//     test pins the default advanced image register by register against the
//     trip-capable one, which is the property the -der-models opt-in exists to
//     guarantee.

import (
	"encoding/json"
	"math"
	"testing"

	"lexa-proto/sunspec"
)

// tripByModel returns the tripBlock for a model id.
func (ss *SolarServer) tripByModel(t *testing.T, id uint16) tripBlock {
	t.Helper()
	for _, tb := range ss.adv.Trips {
		if tb.id == id {
			return tb
		}
	}
	t.Fatalf("the sim serves no model %d", id)
	return tripBlock{}
}

// close reports whether two engineering values agree to within a tolerance the
// declared scale factor can actually represent.
func closeTo(got, want, tol float64) bool { return math.Abs(got-want) <= tol }

// TestTripModelsServeCategoryIIIDefaults is the round-trip: the sim encodes the
// IEEE 1547-2018 Category III defaults into 707/708/709/710, and lexa-proto's
// independent parser reads back exactly those numbers.
//
// The expected values are written out longhand rather than read from
// solarTripSpecs, deliberately. Asserting the block against the same table that
// wrote it would prove only that the copy succeeded; asserting it against the
// standard's printed numbers proves the encoder, the scale factors and the
// three-sub-curve geometry all agree with what the device claims to be.
func TestTripModelsServeCategoryIIIDefaults(t *testing.T) {
	ss := newAdvSolarModels(t, 6000, true)

	volt := []struct {
		id   uint16
		name string
		want []sunspec.TripVPoint
	}{
		// Table 11, Category III: UV2 0.50 pu / 2 s, UV1 0.88 pu / 21 s.
		{sunspec.ModelDERTripLV, "707 DERTripLV", []sunspec.TripVPoint{{V: 50, Tms: 2}, {V: 88, Tms: 21}}},
		// Table 11, Category III: OV1 1.10 pu / 13 s, OV2 1.20 pu / 0.16 s.
		{sunspec.ModelDERTripHV, "708 DERTripHV", []sunspec.TripVPoint{{V: 110, Tms: 13}, {V: 120, Tms: 0.16}}},
	}
	for _, tc := range volt {
		tb := ss.tripByModel(t, tc.id)
		regs := readSlice(ss.Regs, tb.base, tb.dataLen)

		if got := sunspec.L707Hdr.View(regs).U16At(sunspec.L707Hdr.Offset("NCrvSet")); got != advNCrvSet {
			t.Errorf("%s: NCrvSet = %d, want %d", tc.name, got, advNCrvSet)
		}
		set, err := sunspec.Parse707Set(regs, 0)
		if err != nil {
			t.Fatalf("%s: Parse707Set(live) : %v", tc.name, err)
		}
		if !set.ReadOnly {
			t.Errorf("%s: the live curve-set (index 0) is not marked ReadOnly", tc.name)
		}
		if len(set.MustTrip) != len(tc.want) {
			t.Fatalf("%s: MustTrip has %d point(s), want %d", tc.name, len(set.MustTrip), len(tc.want))
		}
		for i, w := range tc.want {
			// V_SF = -1 ⇒ 0.1 % resolution; Tms_SF = -2 ⇒ 10 ms.
			if !closeTo(set.MustTrip[i].V, w.V, 0.05) || !closeTo(set.MustTrip[i].Tms, w.Tms, 0.005) {
				t.Errorf("%s: MustTrip[%d] = (%.3f %%, %.3f s), want (%.3f %%, %.3f s)",
					tc.name, i, set.MustTrip[i].V, set.MustTrip[i].Tms, w.V, w.Tms)
			}
		}
		// MayTrip and MomCess are present in the block and declare zero active
		// points — see the honesty argument in trip1547.go's file comment.
		if len(set.MayTrip) != 0 {
			t.Errorf("%s: MayTrip has %d point(s); the standard specifies no default for it", tc.name, len(set.MayTrip))
		}
		if len(set.MomCess) != 0 {
			t.Errorf("%s: MomCess has %d point(s); Category III performs no momentary cessation",
				tc.name, len(set.MomCess))
		}
		// The staging set (index 1) exists and is writable and empty.
		staging, err := sunspec.Parse707Set(regs, 1)
		if err != nil {
			t.Fatalf("%s: Parse707Set(staging): %v", tc.name, err)
		}
		if staging.ReadOnly || len(staging.MustTrip) != 0 {
			t.Errorf("%s: staging set is ReadOnly=%v with %d MustTrip point(s); want writable and empty",
				tc.name, staging.ReadOnly, len(staging.MustTrip))
		}
	}

	freq := []struct {
		id   uint16
		name string
		want []sunspec.TripHzPoint
	}{
		// Table 19: UF2 56.5 Hz / 0.16 s, UF1 58.5 Hz / 300 s.
		{sunspec.ModelDERTripLF, "709 DERTripLF", []sunspec.TripHzPoint{{Hz: 56.5, Tms: 0.16}, {Hz: 58.5, Tms: 300}}},
		// Table 19: OF1 61.2 Hz / 300 s, OF2 62.0 Hz / 0.16 s.
		{sunspec.ModelDERTripHF, "710 DERTripHF", []sunspec.TripHzPoint{{Hz: 61.2, Tms: 300}, {Hz: 62.0, Tms: 0.16}}},
	}
	for _, tc := range freq {
		tb := ss.tripByModel(t, tc.id)
		regs := readSlice(ss.Regs, tb.base, tb.dataLen)

		if got := sunspec.L709Hdr.View(regs).U16At(sunspec.L709Hdr.Offset("NCrvSet")); got != advNCrvSet {
			t.Errorf("%s: NCrvSet = %d, want %d", tc.name, got, advNCrvSet)
		}
		set, err := sunspec.Parse709Set(regs, 0)
		if err != nil {
			t.Fatalf("%s: Parse709Set(live): %v", tc.name, err)
		}
		if !set.ReadOnly {
			t.Errorf("%s: the live curve-set (index 0) is not marked ReadOnly", tc.name)
		}
		if len(set.MustTrip) != len(tc.want) {
			t.Fatalf("%s: MustTrip has %d point(s), want %d", tc.name, len(set.MustTrip), len(tc.want))
		}
		for i, w := range tc.want {
			// Hz_SF = -3 ⇒ 1 mHz resolution; Tms_SF = -2 ⇒ 10 ms.
			if !closeTo(set.MustTrip[i].Hz, w.Hz, 0.0005) || !closeTo(set.MustTrip[i].Tms, w.Tms, 0.005) {
				t.Errorf("%s: MustTrip[%d] = (%.4f Hz, %.3f s), want (%.4f Hz, %.3f s)",
					tc.name, i, set.MustTrip[i].Hz, set.MustTrip[i].Tms, w.Hz, w.Tms)
			}
		}
		if len(set.MayTrip) != 0 || len(set.MomCess) != 0 {
			t.Errorf("%s: MayTrip/MomCess declare %d/%d points; both should be empty",
				tc.name, len(set.MayTrip), len(set.MomCess))
		}
	}
}

// TestTripModelsDeclareTheScaleFactorsTheProfileRequires pins the scale factors
// the IEEE 1547 profile names for these models (V_SF/Tms_SF on 707/708,
// Hz_SF/Tms_SF on 709/710) and proves each one is write-protected, so a
// whole-block read-modify-write from a gateway cannot silently redefine the
// units the curve is expressed in.
func TestTripModelsDeclareTheScaleFactorsTheProfileRequires(t *testing.T) {
	ss := newAdvSolarModels(t, 6000, true)
	for _, tc := range []struct {
		id   uint16
		hdr  *sunspec.Layout
		want map[string]int16
	}{
		{sunspec.ModelDERTripLV, sunspec.L707Hdr, map[string]int16{"V_SF": -1, "Tms_SF": -2}},
		{sunspec.ModelDERTripHV, sunspec.L707Hdr, map[string]int16{"V_SF": -1, "Tms_SF": -2}},
		{sunspec.ModelDERTripLF, sunspec.L709Hdr, map[string]int16{"Hz_SF": -3, "Tms_SF": -2}},
		{sunspec.ModelDERTripHF, sunspec.L709Hdr, map[string]int16{"Hz_SF": -3, "Tms_SF": -2}},
	} {
		tb := ss.tripByModel(t, tc.id)
		for name, want := range tc.want {
			addr := tb.base + uint16(tc.hdr.Offset(name))
			if got := int16(ss.Regs.Get(addr)); got != want {
				t.Errorf("model %d: %s = %d, want %d", tc.id, name, got, want)
			}
			if !ss.Regs.protected[addr] {
				t.Errorf("model %d: %s at %d is not write-protected", tc.id, name, addr)
			}
		}
	}
}

// TestTripModelAdoptPromotesTheStagedCurve drives the §3.1.2 handshake over the
// trip geometry: write a new must-trip curve into the staging set, request the
// adopt, and read the live set back through the shipped parser.
func TestTripModelAdoptPromotesTheStagedCurve(t *testing.T) {
	ss := newAdvSolarModels(t, 6000, true)
	tb := ss.tripByModel(t, sunspec.ModelDERTripLV)

	// Stage a curve in set 1 by encoding into a copy of the block and writing
	// the staging span back — which is what a gateway does with a block write.
	regs := readSlice(ss.Regs, tb.base, tb.dataLen)
	staged := sunspec.VoltageTripSet{MustTrip: []sunspec.TripVPoint{{V: 45, Tms: 1.5}, {V: 85, Tms: 15}}}
	start, end, err := sunspec.Encode707Set(regs, 1, staged)
	if err != nil {
		t.Fatalf("Encode707Set(staging): %v", err)
	}
	for i := start; i < end; i++ {
		ss.Regs.Set(tb.base+uint16(i), regs[i])
	}

	// Request adoption of the 1-based staging index 2 (= 0-based set 1).
	if !ss.interceptAdopt(tb.base+uint16(tb.reqOff), []uint16{2}) {
		t.Fatal("interceptAdopt did not claim the write to the 707 AdptCrvReq register")
	}
	if got := ss.Regs.Get(tb.base + uint16(tb.rsltOff)); got != sunspec.AdptCompleted {
		t.Fatalf("AdptCrvRslt = %d, want AdptCompleted (%d)", got, sunspec.AdptCompleted)
	}

	live, err := sunspec.Parse707Set(readSlice(ss.Regs, tb.base, tb.dataLen), 0)
	if err != nil {
		t.Fatalf("Parse707Set(live) after adopt: %v", err)
	}
	if !live.ReadOnly {
		t.Error("the promoted live set is not marked ReadOnly; §3.1.2 requires the live entry stay read-only")
	}
	if len(live.MustTrip) != 2 ||
		!closeTo(live.MustTrip[0].V, 45, 0.05) || !closeTo(live.MustTrip[0].Tms, 1.5, 0.005) ||
		!closeTo(live.MustTrip[1].V, 85, 0.05) || !closeTo(live.MustTrip[1].Tms, 15, 0.005) {
		t.Errorf("live MustTrip after adopt = %+v, want the staged (45 %%, 1.5 s) (85 %%, 15 s)", live.MustTrip)
	}
}

// TestTripModelsDoNotDisturbTheDefaultAdvancedImage is the regression guard the
// -der-models opt-in exists for.
//
// It builds both images and asserts, register by register, that every address
// the DEFAULT advanced image occupies holds the same value in the trip-capable
// image — including the model headers, which is what proves 711 and 712 did not
// move. The only permitted difference is the end marker, which by definition
// sits where the chain ends.
func TestTripModelsDoNotDisturbTheDefaultAdvancedImage(t *testing.T) {
	plain := &RegisterMap{regs: make(map[uint16]uint16)}
	_, plainAdv := populateSolarAdvanced(plain, 6000, 6000*0.44, "", false)
	full := &RegisterMap{regs: make(map[uint16]uint16)}
	_, fullAdv := populateSolarAdvanced(full, 6000, 6000*0.44, "", true)

	if len(plainAdv.Trips) != 0 {
		t.Fatalf("the default advanced image serves %d trip model(s); it must serve none", len(plainAdv.Trips))
	}
	if len(fullAdv.Trips) != len(solarTripSpecs) {
		t.Fatalf("the full image serves %d trip model(s), want %d", len(fullAdv.Trips), len(solarTripSpecs))
	}

	// Every advanced model keeps its base address.
	if plainAdv.M701 != fullAdv.M701 || plainAdv.M702 != fullAdv.M702 || plainAdv.M704 != fullAdv.M704 {
		t.Errorf("701/702/704 bases moved: %v/%v/%v -> %v/%v/%v",
			plainAdv.M701, plainAdv.M702, plainAdv.M704, fullAdv.M701, fullAdv.M702, fullAdv.M704)
	}
	if len(plainAdv.Curves) != len(fullAdv.Curves) {
		t.Fatalf("curve-model count changed: %d -> %d", len(plainAdv.Curves), len(fullAdv.Curves))
	}
	for i := range plainAdv.Curves {
		if plainAdv.Curves[i].id != fullAdv.Curves[i].id || plainAdv.Curves[i].base != fullAdv.Curves[i].base {
			t.Errorf("curve model %d moved: id %d @%d -> id %d @%d", i,
				plainAdv.Curves[i].id, plainAdv.Curves[i].base, fullAdv.Curves[i].id, fullAdv.Curves[i].base)
		}
	}

	// Every register the default image writes reads back identically, except
	// the end-marker pair, which is where the two images legitimately differ.
	endMarker := plainAdv.End - 1
	diffs := 0
	for addr, want := range plain.regs {
		if addr == endMarker || addr == endMarker+1 {
			continue
		}
		if got := full.Get(addr); got != want {
			if diffs < 8 {
				t.Errorf("register %d: default image has 0x%04X, trip image has 0x%04X", addr, want, got)
			}
			diffs++
		}
	}
	if diffs > 8 {
		t.Errorf("... and %d further diverging register(s)", diffs-8)
	}

	// The default image really does terminate where it always did, and the
	// trip image terminates later — i.e. the models were APPENDED.
	if full.Get(endMarker) == sunspec.EndMarker {
		t.Errorf("the trip image still ends at %d; the trip models were not appended", endMarker)
	}
	if fullAdv.End <= plainAdv.End {
		t.Errorf("trip image End=%d is not past the default End=%d", fullAdv.End, plainAdv.End)
	}
}

// TestTripSnapshotOmittedWithoutTripModels proves the /state payload of a sim
// that does not serve 707-710 is unchanged: the trips key is absent entirely,
// not present-and-empty, so no scenario comparing snapshots sees a new field.
func TestTripSnapshotOmittedWithoutTripModels(t *testing.T) {
	plain := newAdvSolar(t, 6000)
	b, err := json.Marshal(plain.advSnapshot())
	if err != nil {
		t.Fatalf("marshal default advanced snapshot: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if _, ok := m["trips"]; ok {
		t.Errorf("the default advanced snapshot carries a \"trips\" key: %s", b)
	}

	full := newAdvSolarModels(t, 6000, true)
	snap := full.advSnapshot()
	if len(snap.Trips) != len(solarTripSpecs) {
		t.Fatalf("trip snapshot has %d entries, want %d", len(snap.Trips), len(solarTripSpecs))
	}
	for _, st := range snap.Trips {
		if !st.ReadOnly {
			t.Errorf("model %d: snapshot reports the live set writable", st.Model)
		}
		if len(st.MustTrip) != 2 {
			t.Errorf("model %d: snapshot MustTrip has %d point(s), want 2", st.Model, len(st.MustTrip))
		}
		if len(st.MayTrip) != 0 || len(st.MomCess) != 0 {
			t.Errorf("model %d: snapshot MayTrip/MomCess are %d/%d, want 0/0",
				st.Model, len(st.MayTrip), len(st.MomCess))
		}
	}
}

// TestTripBlocksFitOneModbusRead records the sizing decision advTripNPt = 4 was
// made for: every trip block stays inside the 125-register single-read cap, so
// a gateway reads each of these models in one transaction rather than through
// the chunked path model 701 exists to exercise.
func TestTripBlocksFitOneModbusRead(t *testing.T) {
	ss := newAdvSolarModels(t, 6000, true)
	for _, tb := range ss.adv.Trips {
		if tb.dataLen > 125 {
			t.Errorf("model %d data block is %d registers, past the 125-register Modbus single-read cap",
				tb.id, tb.dataLen)
		}
	}
}
