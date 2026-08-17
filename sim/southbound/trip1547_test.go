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
	"fmt"
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
// IEEE 1547-2018 defaults into 707/708/709/710 — Table 13's Category III
// numbers on the voltage pair, Table 18's (which one table gives for all three
// categories) on the frequency pair — and lexa-proto's independent parser reads
// back exactly those numbers.
//
// The test keeps its CategoryIII name because the CATEGORY-SPECIFIC half is
// what it exists to pin: the frequency defaults would be the same whatever this
// device declared itself, the voltage ones would not, and the device declares
// Category III (model 702's AbnOpCatRtg — see
// TestNameplateDeclaresTheCategoryItsTripCurvesServe).
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
		// Table 13, Category III: UV2 0.50 pu / 2 s, UV1 0.88 pu / 21 s.
		{sunspec.ModelDERTripLV, "707 DERTripLV", []sunspec.TripVPoint{{V: 50, Tms: 2}, {V: 88, Tms: 21}}},
		// Table 13, Category III: OV1 1.10 pu / 13 s, OV2 1.20 pu / 0.16 s.
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
		// points — see the two DIFFERENT arguments in trip1547.go's file comment,
		// and note that these two failure messages are not interchangeable.
		if len(set.MayTrip) != 0 {
			t.Errorf("%s: MayTrip has %d point(s); no table in IEEE 1547-2018 prints may-trip curve "+
				"points (its settings tables are 35 and 36) and the SunSpec profile names no MayTrip point "+
				"for 707/708 at all, so there is nothing a fixture could be transcribing here",
				tc.name, len(set.MayTrip))
		}
		if len(set.MomCess) != 0 {
			// NOT "Category III performs no momentary cessation" — it does (1547
			// Table 16 prescribes it in two voltage regions), and this fixture's
			// emptiness is a bench choice about an OPTIONAL setting rather than a
			// property of the category. A device arriving with momentary cessation
			// configured is conformant; it is just not the baseline BASIC-004's
			// before/after oracle is written against.
			t.Errorf("%s: MomCess has %d point(s); this fixture declines the optional momentary-cessation "+
				"setting (1547 Table 36 \"not mandatory\", SunSpec profile Table 26 optional) so that any "+
				"content a conformance run finds in this sub-curve is attributable to a control it published",
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
		// Table 18: UF2 56.5 Hz / 0.16 s, UF1 58.5 Hz / 300 s.
		{sunspec.ModelDERTripLF, "709 DERTripLF", []sunspec.TripHzPoint{{Hz: 56.5, Tms: 0.16}, {Hz: 58.5, Tms: 300}}},
		// Table 18: OF1 61.2 Hz / 300 s, OF2 62.0 Hz / 0.16 s.
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

// TestNameplateDeclaresTheCategoryItsTripCurvesServe is the coherence check
// between the two halves of this device's 1547 story: model 702's AbnOpCatRtg
// is the DER's OWN declaration of its abnormal operating performance category,
// and models 707/708 carry the shall-trip curves of exactly one category.
//
// It is written as a coherence test rather than a value test on purpose. "The
// register holds a 2" would pass on a device serving Category I curves beside a
// Category III nameplate, which is the state this sim was actually in until
// populate702 grew the line: the point was never written, and an enum16's zero
// is the real value CAT_1 rather than an absence (absence is the 0xFFFF
// sentinel, which View.Enum reports as ok=false). So the DER positively claimed
// Category I while serving Category III's trip curves.
//
// The numbers pinned below are the ones that DIFFER between the three tables of
// IEEE Std 1547-2018 — Table 13 (Category III) gives UV1 0.88 pu / 21 s and OV1
// 1.10 pu / 13 s, where Table 11 (Category I) gives UV1 0.70 pu / 2.0 s and
// Table 12 (Category II) 0.70 pu / 10.0 s. The FREQUENCY models are deliberately
// not part of this check: Table 18 gives one set of frequency trip defaults for
// all three categories, so 709/710 can corroborate no category at all.
func TestNameplateDeclaresTheCategoryItsTripCurvesServe(t *testing.T) {
	ss := newAdvSolarModels(t, 6000, true)

	got, ok := sunspec.L702.View(readSlice(ss.Regs, ss.adv.M702, sunspec.L702.Len())).Enum("AbnOpCatRtg")
	if !ok {
		t.Fatalf("702.AbnOpCatRtg reads back as not-implemented, but this device serves 707/708 trip " +
			"curves and so HAS an abnormal operating performance category; the SunSpec 1547 profile " +
			"requires the point (its Table 18) and 1547 §6.4.2.1 requires the nameplate to carry the " +
			"category")
	}
	if got != abnOpCat702CategoryIII {
		t.Fatalf("702.AbnOpCatRtg = %d, want %d (CAT_3): the trip curves this same sim serves are Table "+
			"13's Category III defaults, and a nameplate naming any other category makes the device "+
			"internally inconsistent — anything downstream reasoning from the declared category would be "+
			"reasoning about a value nobody chose", got, abnOpCat702CategoryIII)
	}

	// The other half of the coherence claim: the curves that category names.
	for _, tc := range []struct {
		id   uint16
		name string
		want []sunspec.TripVPoint
	}{
		{sunspec.ModelDERTripLV, "707 DERTripLV", []sunspec.TripVPoint{{V: 50, Tms: 2}, {V: 88, Tms: 21}}},
		{sunspec.ModelDERTripHV, "708 DERTripHV", []sunspec.TripVPoint{{V: 110, Tms: 13}, {V: 120, Tms: 0.16}}},
	} {
		tb := ss.tripByModel(t, tc.id)
		set, err := sunspec.Parse707Set(readSlice(ss.Regs, tb.base, tb.dataLen), 0)
		if err != nil {
			t.Fatalf("%s: Parse707Set(live): %v", tc.name, err)
		}
		if len(set.MustTrip) != len(tc.want) {
			t.Fatalf("%s: MustTrip has %d point(s), want %d", tc.name, len(set.MustTrip), len(tc.want))
		}
		for i, w := range tc.want {
			if !closeTo(set.MustTrip[i].V, w.V, 0.05) || !closeTo(set.MustTrip[i].Tms, w.Tms, 0.005) {
				t.Errorf("%s: MustTrip[%d] = (%.3f %%, %.3f s), want Table 13's (%.3f %%, %.3f s) — the "+
					"nameplate declares Category III and this curve is not Category III's",
					tc.name, i, set.MustTrip[i].V, set.MustTrip[i].Tms, w.V, w.Tms)
			}
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
	_, plainAdv := populateSolarAdvanced(plain, 6000, 6000*0.44, "", AdvancedOptions{})
	full := &RegisterMap{regs: make(map[uint16]uint16)}
	_, fullAdv := populateSolarAdvanced(full, 6000, 6000*0.44, "", AdvancedOptions{Trip: true})

	if len(plainAdv.Trips) != 0 {
		t.Fatalf("the default advanced image serves %d trip model(s); it must serve none", len(plainAdv.Trips))
	}
	if len(fullAdv.Trips) != len(solarTripSpecs) {
		t.Fatalf("the full image serves %d trip model(s), want %d", len(fullAdv.Trips), len(solarTripSpecs))
	}

	// Every advanced model keeps its base address.
	if plainAdv.M701 != fullAdv.M701 || plainAdv.M702 != fullAdv.M702 || plainAdv.M703 != fullAdv.M703 ||
		plainAdv.M704 != fullAdv.M704 {
		t.Errorf("701/702/703/704 bases moved: %v/%v/%v/%v -> %v/%v/%v/%v",
			plainAdv.M701, plainAdv.M702, plainAdv.M703, plainAdv.M704,
			fullAdv.M701, fullAdv.M702, fullAdv.M703, fullAdv.M704)
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

// TestTripBlocksSpanTheChunkedRead replaces TestTripBlocksFitOneModbusRead,
// and the replacement IS the finding rather than an accommodation of it.
//
// The old test asserted that every trip block stayed inside the 125-register
// Modbus single-read cap, which was the stated rationale for advTripNPt = 4.
// That rationale is superseded: CSIP CTP v1.3's BASIC-004 Figure 4 prescribes a
// SEVEN-point opModLVRTMustTrip curve and Encode707Set refuses more points than
// the device's declared NPt, so at four this bench could not hold the
// certification procedure's own curve. NPt is 8 now and both families are past
// the cap.
//
// So the assertion INVERTS rather than disappearing. The sizes are pinned
// exactly — a silent change to either would move every register after these
// models — and the blocks are then read back through the real chunking reader,
// which is what makes "the chunked path handles it" a measurement instead of a
// claim in a comment. Writes are checked too, against FC16's own ceiling, since
// Reader.WriteModel does not chunk and an adopt writes a whole staging set.
func TestTripBlocksSpanTheChunkedRead(t *testing.T) {
	// The arithmetic from trip1547.go's advTripNPt comment, stated
	// independently of the size helpers so the two can disagree.
	//
	//	707/708  7 (L707Hdr) + 2 × (1 + 3×(1 + 8×3)) = 7 + 2×76  = 159
	//	709/710  7 (L709Hdr) + 2 × (1 + 3×(1 + 8×4)) = 7 + 2×100 = 207
	wantLen := map[uint16]int{
		sunspec.ModelDERTripLV: 159, sunspec.ModelDERTripHV: 159,
		sunspec.ModelDERTripLF: 207, sunspec.ModelDERTripHF: 207,
	}
	// The two Modbus ceilings, which are different numbers and are easy to
	// conflate: FC3 reads at most 125 registers (PI-MBUS-300 0x7D) and FC16
	// writes at most 123.
	const maxRead, maxWrite = 125, 123

	ss := newAdvSolarModels(t, 6000, true)
	if len(ss.adv.Trips) != len(wantLen) {
		t.Fatalf("the sim serves %d trip models, want %d", len(ss.adv.Trips), len(wantLen))
	}
	for _, tb := range ss.adv.Trips {
		want, ok := wantLen[tb.id]
		if !ok {
			t.Errorf("model %d is served but this test states no expected block length for it", tb.id)
			continue
		}
		if tb.dataLen != want {
			t.Errorf("model %d data block is %d registers, want %d — every register after this model "+
				"moves when this number does, so a change here is a change to the whole image",
				tb.id, tb.dataLen, want)
		}
		if tb.dataLen <= maxRead {
			t.Errorf("model %d is %d registers, inside the %d-register single-read cap: this test is "+
				"asserting the CHUNKED path and would no longer exercise it",
				tb.id, tb.dataLen, maxRead)
		}
		// One staging set is what derbase's adoptCurve writes in a single
		// unchunked WriteHolding, so it — not the whole block — is what has to
		// stay under the write ceiling.
		if tb.setSize > maxWrite {
			t.Errorf("model %d's curve-set is %d registers, past FC16's %d-register write ceiling: "+
				"Reader.WriteModel does not chunk, so every adopt of this model would be refused by "+
				"the transport", tb.id, tb.setSize, maxWrite)
		}
	}

	// And the blocks actually read back, through the same chunking reader a
	// gateway uses, over a transport that REFUSES an over-cap read the way a
	// real one does. A size assertion alone would pass on a sim serving 159
	// registers no client can read, and so would a read over the permissive
	// test transport the other cases here use — which answers any quantity and
	// would therefore prove nothing about chunking at all.
	reader, err := sunspec.NewReader(&cappedReadTransport{r: ss.Regs, cap: maxRead})
	if err != nil {
		t.Fatalf("open a SunSpec reader over a cap-enforcing transport: %v", err)
	}
	for _, tb := range ss.adv.Trips {
		regs, err := reader.ReadModel(tb.id)
		if err != nil {
			t.Fatalf("model %d did not read back through the chunking reader: %v", tb.id, err)
		}
		if len(regs) != tb.dataLen {
			t.Errorf("model %d read back %d registers, want its whole %d-register block — a short read "+
				"here is the chunked path dropping a chunk", tb.id, len(regs), tb.dataLen)
		}
		var perr error
		if tb.volt {
			_, perr = sunspec.Parse707Set(regs, 0)
		} else {
			_, perr = sunspec.Parse709Set(regs, 0)
		}
		if perr != nil {
			t.Errorf("model %d's chunk-read image does not parse: %v", tb.id, perr)
		}
	}
}

// cappedReadTransport is a register-map transport that REFUSES a read wider
// than the Modbus ceiling, exactly as a real one does.
//
// The permissive regMapTransport every other case here uses answers any
// quantity, so a "read the whole block" assertion taken over it proves nothing
// about chunking: it would pass identically on a reader that had never split
// the request. This one fails the read instead, which is what makes
// TestTripBlocksSpanTheChunkedRead a statement about Reader.readChunked rather
// than about the fixture.
type cappedReadTransport struct {
	r   *RegisterMap
	cap uint16
}

func (t *cappedReadTransport) Open() error           { return nil }
func (t *cappedReadTransport) Close() error          { return nil }
func (t *cappedReadTransport) SetUnitID(uint8) error { return nil }

func (t *cappedReadTransport) ReadHolding(addr, qty uint16) ([]uint16, error) {
	if qty > t.cap {
		return nil, fmt.Errorf("modbus: read of %d registers at %d exceeds the %d-register ceiling",
			qty, addr, t.cap)
	}
	out := make([]uint16, qty)
	for i := uint16(0); i < qty; i++ {
		out[i] = t.r.Get(addr + i)
	}
	return out, nil
}

func (t *cappedReadTransport) WriteHolding(uint16, []uint16) error { return nil }

func (t *cappedReadTransport) ReadInput(addr, qty uint16) ([]uint16, error) {
	return t.ReadHolding(addr, qty)
}
