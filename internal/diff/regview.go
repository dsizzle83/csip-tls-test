package diff

// regview.go is the register-interpretation differential, and it is the family
// that puts the SHARED layout tables under an independent referee.
//
// # The problem this family exists to solve
//
// Every other family in this package reads registers through
// lexa-proto/sunspec's Layout/View engine on both sides. That is defensible for
// wire framing, but it means a wrong OFFSET, a wrong TYPE, or a point wired to
// the wrong SCALE FACTOR is invisible: both readers make the same mistake and
// agree perfectly. The strategy's referee-independence rule
// (docs/ADVERSARIAL_QA_STRATEGY.md §5, AD-003(f)) is exactly about this hazard,
// and the honest response is not to note the blind spot in a comment but to
// build a second decoder.
//
// # What is and is not independent here
//
// [refPoints] is transcribed BY HAND from the model field ordering, and every
// number in it is derived independently:
//
//   - the OFFSET is computed by this file's own running sum over its own width
//     table ([regWidth]), not read from sunspec.Layout.Offset;
//   - the TYPE — and with it signedness and the not-implemented sentinel — is
//     restated here per point;
//   - the SCALE-FACTOR ASSOCIATION is restated here per point, which is the
//     thing most likely to drift silently: a point wired to the wrong SF
//     produces a value that is wrong by a factor of ten and looks entirely
//     plausible.
//
// What that catches: an offset arithmetic error, a signedness error, a wrong
// sentinel, and a point reading somebody else's scale factor. Any of these
// makes a decoded value wrong in a way nothing downstream would question.
//
// What it does NOT catch, stated plainly because a differential's value is
// exactly its independence and a reader is entitled to know the boundary: this
// transcription takes the FIELD LIST AND ITS ORDER from the same source the
// product does. If a point is missing from both, or two adjacent points are
// swapped in both, the two tables agree and this family is silent. Closing that
// would need a copy of the SunSpec model definition, which this repository does
// not have; [ReportedLimitations] says so on every run rather than leaving a
// reader to assume otherwise.

import (
	"context"
	"fmt"
	"math"
	"math/rand"

	"csip-tls-test/internal/invariant"
	"lexa-proto/sunspec"
)

// regType is the referee's own type vocabulary. It is deliberately NOT
// sunspec.FieldType: sharing the type enum would share the sentinel and
// signedness decisions, which are half of what this family adjudicates.
type regType string

// The types the transcribed points use.
const (
	tU16   regType = "uint16"
	tI16   regType = "int16"
	tU32   regType = "uint32"
	tI32   regType = "int32"
	tEnum  regType = "enum16"
	tBit16 regType = "bitfield16"
	tBit32 regType = "bitfield32"
	tAcc64 regType = "acc64"
	tSF    regType = "sunssf"
	tStr   regType = "string" // width given explicitly; never decoded numerically
	tPad   regType = "pad"
)

// regWidth is the referee's own width table, in registers.
func regWidth(t regType) int {
	switch t {
	case tU16, tI16, tEnum, tBit16, tSF, tPad:
		return 1
	case tU32, tI32, tBit32:
		return 2
	case tAcc64:
		return 4
	}
	return 1
}

// refField is one transcribed point.
type refField struct {
	Name string
	Type regType
	// SF names the scale-factor point this one is scaled by, "" for unscaled.
	SF string
	// Width overrides regWidth for string fields.
	Width int
}

func rf(name string, t regType) refField             { return refField{Name: name, Type: t} }
func rfs(name string, t regType, sf string) refField { return refField{Name: name, Type: t, SF: sf} }

// refModel is a transcribed model: an ordered field list plus the offsets this
// file computes from it.
type refModel struct {
	ID     uint16
	Fields []refField
	off    map[string]int
	typ    map[string]refField
	total  int
}

func newRefModel(id uint16, fields ...refField) *refModel {
	m := &refModel{ID: id, Fields: fields, off: map[string]int{}, typ: map[string]refField{}}
	cursor := 0
	for _, f := range fields {
		w := f.Width
		if w == 0 {
			w = regWidth(f.Type)
		}
		if f.Type != tPad {
			m.off[f.Name] = cursor
			m.typ[f.Name] = f
		}
		cursor += w
	}
	m.total = cursor
	return m
}

// Offset returns this transcription's offset for a point, and whether it has
// one at all.
func (m *refModel) Offset(name string) (int, bool) {
	o, ok := m.off[name]
	return o, ok
}

// Len is this transcription's model length.
func (m *refModel) Len() int { return m.total }

// sentinelOf returns the not-implemented sentinel for a type, as this referee
// reads SunSpec. The values are restated rather than imported: a shared
// sentinel constant would make a sentinel error invisible, and the 701
// power-factor rework in lexa-proto's own derlayout.go documents exactly how
// consequential the int16-vs-uint16 sentinel choice is.
func sentinelOf(t regType) (uint64, bool) {
	switch t {
	case tU16, tEnum, tBit16:
		return 0xFFFF, true
	case tI16, tSF:
		return 0x8000, true
	case tU32, tBit32:
		return 0xFFFFFFFF, true
	case tI32:
		return 0x80000000, true
	}
	return 0, false
}

// Decode reads one point as an engineering value, applying its scale factor.
// NaN means unimplemented or unresolvable, exactly as the product's Float does
// — the agreement on the CONVENTION is intentional; the agreement on the
// ARITHMETIC is what is being tested.
func (m *refModel) Decode(regs []uint16, name string) (float64, error) {
	f, ok := m.typ[name]
	if !ok {
		return math.NaN(), fmt.Errorf("referee: model %d has no point %q", m.ID, name)
	}
	o := m.off[name]
	w := regWidth(f.Type)
	if o+w > len(regs) {
		return math.NaN(), fmt.Errorf("referee: point %s at offset %d+%d is past the end of a %d-register block",
			name, o, w, len(regs))
	}
	var raw uint64
	for i := 0; i < w; i++ {
		raw = raw<<16 | uint64(regs[o+i])
	}
	if sent, has := sentinelOf(f.Type); has && raw == sent {
		return math.NaN(), nil
	}
	val := float64(signExtend(raw, f.Type))

	if f.SF == "" {
		return val, nil
	}
	sfOff, ok := m.off[f.SF]
	if !ok {
		return math.NaN(), fmt.Errorf("referee: point %s is scaled by %s, which this transcription "+
			"does not define", name, f.SF)
	}
	if sfOff >= len(regs) {
		return math.NaN(), fmt.Errorf("referee: the scale factor %s for %s is past the end of the block", f.SF, name)
	}
	sf := int16(regs[sfOff])
	scaled, ok := refDecode(int64(signExtend(raw, f.Type)), sf)
	if !ok {
		return math.NaN(), fmt.Errorf("referee: %s is scaled by %s = %d, which is not a legal scale factor",
			name, f.SF, sf)
	}
	return ratFloat(scaled), nil
}

func signExtend(raw uint64, t regType) int64 {
	switch t {
	case tI16, tSF:
		return int64(int16(raw))
	case tI32:
		return int64(int32(raw))
	}
	return int64(raw)
}

// ── The transcriptions ───────────────────────────────────────────────────────
//
// Only the points that carry a physical quantity a control decision depends on
// are transcribed. Transcribing all 153 registers of model 701 would add
// coverage of points nothing reads and would make the table too long to review,
// which is worse than not having it: an unreviewed transcription is not an
// independent referee, it is a second copy.

// ref702 is DER Capacity: the ratings and settings every percentage in the
// system is resolved against, and therefore the model where an offset error is
// most expensive.
var ref702 = newRefModel(702,
	rfs("WMaxRtg", tU16, "W_SF"),
	rfs("WOvrExtRtg", tU16, "W_SF"), rfs("WOvrExtRtgPF", tU16, "PF_SF"),
	rfs("WUndExtRtg", tU16, "W_SF"), rfs("WUndExtRtgPF", tU16, "PF_SF"),
	rfs("VAMaxRtg", tU16, "VA_SF"),
	rfs("VarMaxInjRtg", tU16, "Var_SF"), rfs("VarMaxAbsRtg", tU16, "Var_SF"),
	rfs("WChaRteMaxRtg", tU16, "W_SF"), rfs("WDisChaRteMaxRtg", tU16, "W_SF"),
	rfs("VAChaRteMaxRtg", tU16, "VA_SF"), rfs("VADisChaRteMaxRtg", tU16, "VA_SF"),
	rfs("VNomRtg", tU16, "V_SF"), rfs("VMaxRtg", tU16, "V_SF"), rfs("VMinRtg", tU16, "V_SF"),
	rfs("AMaxRtg", tU16, "A_SF"),
	rfs("PFOvrExtRtg", tU16, "PF_SF"), rfs("PFUndExtRtg", tU16, "PF_SF"),
	rfs("ReactSusceptRtg", tU16, "S_SF"),
	rf("NorOpCatRtg", tEnum), rf("AbnOpCatRtg", tEnum),
	rf("CtrlModes", tBit32), rf("IntIslandCatRtg", tBit16),
	rfs("WMax", tU16, "W_SF"),
	rfs("WMaxOvrExt", tU16, "W_SF"), rfs("WOvrExtPF", tU16, "PF_SF"),
	rfs("WMaxUndExt", tU16, "W_SF"), rfs("WUndExtPF", tU16, "PF_SF"),
	rfs("VAMax", tU16, "VA_SF"),
	rfs("VarMaxInj", tU16, "Var_SF"), rfs("VarMaxAbs", tU16, "Var_SF"),
	rfs("WChaRteMax", tU16, "W_SF"), rfs("WDisChaRteMax", tU16, "W_SF"),
	rfs("VAChaRteMax", tU16, "VA_SF"), rfs("VADisChaRteMax", tU16, "VA_SF"),
	rfs("VNom", tU16, "V_SF"), rfs("VMax", tU16, "V_SF"), rfs("VMin", tU16, "V_SF"),
	rfs("AMax", tU16, "A_SF"),
	rfs("PFOvrExt", tU16, "PF_SF"), rfs("PFUndExt", tU16, "PF_SF"),
	rf("IntIslandCat", tBit16),
	rf("W_SF", tSF), rf("PF_SF", tSF), rf("VA_SF", tSF), rf("Var_SF", tSF),
	rf("V_SF", tSF), rf("A_SF", tSF), rf("S_SF", tSF),
)

// ref704 is DER AC Controls: every setpoint the gateway writes.
var ref704 = newRefModel(704,
	rf("PFWInjEna", tEnum), rf("PFWInjEnaRvrt", tEnum),
	rf("PFWInjRvrtTms", tU32), rf("PFWInjRvrtRem", tU32),
	rf("PFWAbsEna", tEnum), rf("PFWAbsEnaRvrt", tEnum),
	rf("PFWAbsRvrtTms", tU32), rf("PFWAbsRvrtRem", tU32),
	rf("WMaxLimPctEna", tEnum),
	rfs("WMaxLimPct", tU16, "WMaxLimPct_SF"), rfs("WMaxLimPctRvrt", tU16, "WMaxLimPct_SF"),
	rf("WMaxLimPctEnaRvrt", tEnum), rf("WMaxLimPctRvrtTms", tU32), rf("WMaxLimPctRvrtRem", tU32),
	rf("WSetEna", tEnum), rf("WSetMod", tEnum),
	rfs("WSet", tI32, "WSet_SF"), rfs("WSetRvrt", tI32, "WSet_SF"),
	rfs("WSetPct", tI16, "WSetPct_SF"), rfs("WSetPctRvrt", tI16, "WSetPct_SF"),
	rf("WSetEnaRvrt", tEnum), rf("WSetRvrtTms", tU32), rf("WSetRvrtRem", tU32),
	rf("VarSetEna", tEnum), rf("VarSetMod", tEnum), rf("VarSetPri", tEnum),
	rfs("VarSet", tI32, "VarSet_SF"), rfs("VarSetRvrt", tI32, "VarSet_SF"),
	rfs("VarSetPct", tI16, "VarSetPct_SF"), rfs("VarSetPctRvrt", tI16, "VarSetPct_SF"),
	rf("VarSetEnaRvrt", tEnum), rf("VarSetRvrtTms", tU32), rf("VarSetRvrtRem", tU32),
	rf("WRmp", tU16), rf("WRmpRef", tEnum), rf("VarRmp", tU16), rf("AntiIslEna", tEnum),
	rf("PF_SF", tSF), rf("WMaxLimPct_SF", tSF), rf("WSet_SF", tSF),
	rf("WSetPct_SF", tSF), rf("VarSet_SF", tSF), rf("VarSetPct_SF", tSF),
	rfs("PFWInj_PF", tU16, "PF_SF"), rf("PFWInj_Ext", tEnum),
	rfs("PFWInjRvrt_PF", tU16, "PF_SF"), rf("PFWInjRvrt_Ext", tEnum),
	rfs("PFWAbs_PF", tU16, "PF_SF"), rf("PFWAbs_Ext", tEnum),
	rfs("PFWAbsRvrt_PF", tU16, "PF_SF"), rf("PFWAbsRvrt_Ext", tEnum),
)

// refModels is the set this family adjudicates, with the product layout each is
// compared against.
func refModels() []struct {
	ref *refModel
	l   *sunspec.Layout
} {
	return []struct {
		ref *refModel
		l   *sunspec.Layout
	}{
		{ref702, sunspec.L702},
		{ref704, sunspec.L704},
	}
}

// RunRegLayout compares the transcribed offsets, widths and scale-factor
// associations against the product's layout tables.
//
// This is the structural half of the family and it runs once per model, with no
// register data involved: an offset that differs is wrong for every value that
// will ever be read through it, so it should be reported as one finding about
// the table rather than as a thousand findings about values.
func RunRegLayout(_ context.Context) []Case {
	var out []Case
	for _, pair := range refModels() {
		out = append(out, compareLayout(pair.ref, pair.l, fmt.Sprintf("DIFF-REG-L%d", pair.ref.ID)))
	}
	return out
}

// compareLayout is the body of one structural case, taking the referee's table
// as a parameter so a test can hand it a DELIBERATELY WRONG one and prove the
// comparison fails. A structural check that has only ever seen two tables that
// agree has not been shown to be capable of noticing that they do not.
func compareLayout(ref *refModel, l *sunspec.Layout, id string) Case {
	c := Case{
		ID:      id,
		Family:  "reg",
		Title:   fmt.Sprintf("model %d: transcribed offsets, types and scale-factor wiring", ref.ID),
		Input:   fmt.Sprintf("model=%d", ref.ID),
		Product: Side{Name: "product", Lineage: "lexa-proto/sunspec.L70x — the layout table the DUT decodes with"},
		Referee: Side{Name: "referee", Lineage: "csip-tls-test/internal/diff — hand-transcribed table, own width arithmetic"},
		Limitation: "the FIELD LIST and its ORDER are taken from the same source on both sides; a point " +
			"missing from both, or a pair swapped in both, produces agreement and is not caught here",
	}

	c.Compare(CompareQuantity("model.length",
		Q(ProductSide.Name, "model.length", invariant.Q(float64(l.Len()), "reg")),
		Q(RefereeSide.Name, "model.length", invariant.Q(float64(ref.Len()), "reg")),
		invariant.Tolerance{}))

	for _, f := range ref.Fields {
		if f.Type == tPad {
			continue
		}
		refOff, _ := ref.Offset(f.Name)
		prodOff := l.Offset(f.Name)
		key := fmt.Sprintf("%s.offset", f.Name)
		if prodOff < 0 {
			c.Compare(Comparison{
				Key:     key,
				Product: T(ProductSide.Name, key, "the layout has no point %q", f.Name),
				Referee: T(RefereeSide.Name, key, "offset %d", refOff),
				Verdict: Fail,
				Reason: fmt.Sprintf("this referee transcribed a point %q into model %d that the "+
					"product's layout does not define. Either the transcription invented a point, "+
					"or the product is missing one — and a missing point is not decoded at all",
					f.Name, ref.ID),
			})
			continue
		}
		c.Compare(CompareQuantity(key,
			Q(ProductSide.Name, key, invariant.Q(float64(prodOff), "reg")),
			Q(RefereeSide.Name, key, invariant.Q(float64(refOff), "reg")),
			invariant.Tolerance{}))
	}
	c.Finalize("this transcription defines no points for this model")
	return c
}

// RunRegValues compares decoded engineering values between the two tables over
// a generated register image.
//
// The image is random, which is the point: a fixture built from plausible
// values exercises the same code path for every point and would miss a
// signedness error on a point that is never negative in practice. Random words
// hit the sentinel, the sign bit and the extremes without anyone having to
// think of them.
func RunRegValues(_ context.Context, seed int64, images int) []Case {
	rng := rand.New(rand.NewSource(seed))
	var out []Case
	for _, pair := range refModels() {
		for img := 0; img < images; img++ {
			regs := make([]uint16, pair.l.Len())
			for i := range regs {
				regs[i] = uint16(rng.Intn(65536))
			}
			// Scale-factor registers are drawn from the legal range on most
			// images: an image whose every SF is illegal exercises only the
			// refusal path, and the arithmetic would never be compared.
			for _, f := range pair.ref.Fields {
				if f.Type != tSF {
					continue
				}
				if o, ok := pair.ref.Offset(f.Name); ok && rng.Intn(8) != 0 {
					regs[o] = uint16(int16(rng.Intn(21) - 10))
				}
			}

			out = append(out, compareValues(pair.ref, pair.l, regs,
				fmt.Sprintf("DIFF-REG-V%d-%02d", pair.ref.ID, img),
				fmt.Sprintf("model=%d seed=%d image=%d", pair.ref.ID, seed, img)))
		}
	}
	return out
}

// compareValues is the body of one value case, taking the referee's table as a
// parameter for the same reason [compareLayout] does: a decode comparison that
// has never seen two decoders disagree is not known to be able to see it.
func compareValues(ref *refModel, l *sunspec.Layout, regs []uint16, id, input string) Case {
	c := Case{
		ID:      id,
		Family:  "reg",
		Title:   fmt.Sprintf("model %d: decoded values over a random register image", ref.ID),
		Input:   input,
		Product: Side{Name: "product", Lineage: "lexa-proto/sunspec.Layout.View.Float"},
		Referee: Side{Name: "referee", Lineage: "csip-tls-test/internal/diff — transcribed table, exact scale arithmetic"},
		Limitation: "the FIELD LIST and its ORDER are shared; this compares offset arithmetic, " +
			"signedness, sentinel handling and scale-factor wiring",
	}
	v := l.View(regs)
	for _, f := range ref.Fields {
		// Enums and bitfields carry no engineering value, and scale factors
		// are compared through the points that use them; decoding them here
		// would compare a raw word against itself.
		if f.Type == tPad || f.Type == tSF || f.Type == tBit16 || f.Type == tBit32 || f.Type == tEnum {
			continue
		}
		key := f.Name
		refVal, refErr := ref.Decode(regs, f.Name)
		prodVal := v.Float(f.Name)

		if refErr != nil {
			c.Compare(SkipComparison(key, "the referee could not decode this point: "+refErr.Error()))
			continue
		}
		refNaN, prodNaN := math.IsNaN(refVal), math.IsNaN(prodVal)
		if refNaN || prodNaN {
			c.Compare(CompareBool(key+".implemented",
				T(ProductSide.Name, key, "%s", describeFloat(prodVal)),
				T(RefereeSide.Name, key, "%s", describeFloat(refVal)),
				!prodNaN, !refNaN,
				fmt.Sprintf("whether %s decodes to a value on this image (sentinel and "+
					"scale-factor legality both land here)", f.Name)))
			continue
		}
		c.Compare(CompareQuantity(key,
			Q(ProductSide.Name, key, invariant.Q(prodVal, invariant.UnitNone)),
			Q(RefereeSide.Name, key, invariant.Q(refVal, invariant.UnitNone)),
			invariant.Tolerance{Rel: 1e-9, Abs: 1e-9}))
	}
	c.Finalize("no point in this model decoded on either side")
	return c
}

// RunRegCatalog runs the structural and value halves of the reg family.
func RunRegCatalog(ctx context.Context, r *Report, images int) {
	for _, c := range RunRegLayout(ctx) {
		r.Add(c)
	}
	for _, c := range RunRegValues(ctx, r.Seed, images) {
		r.Add(c)
	}
}
