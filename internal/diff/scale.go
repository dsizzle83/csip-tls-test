package diff

// scale.go is the scale-factor differential, and it is the family the brief
// calls the highest-value target: audit BR-01 was an absolute var count written
// into a percent-of-rated field, and audit BR-02 found the existing
// scale-factor cross-check TAUTOLOGICAL because it derived its tolerance from
// the value under test.
//
// # The oracle, and why it is not a round trip
//
// The obvious property to check is decode(encode(v)) == v. It is nearly
// worthless. A codec that is consistently wrong round-trips perfectly: shift by
// the wrong power of ten in both directions and every value comes back exactly.
// That is BR-02's tautology in a different costume.
//
// The property this file checks instead is MAGNITUDE PRESERVATION AGAINST AN
// INDEPENDENT ARITHMETIC. [refDecode] and [refEncode] compute raw x 10^sf with
// exact rational arithmetic (math/big.Rat), sharing no line of code and no
// floating-point rounding behaviour with the product's math.Pow10 path. The
// product's answer must equal the referee's exact answer to within half a
// least-significant unit — where the least-significant unit is 10^sf, a
// property of the ENCODING and not of the value, so the tolerance cannot grow
// with the error.
//
// # The three questions
//
//  1. IS THE SCALE FACTOR EVEN LEGAL? SunSpec's sunssf is a bounded type; a
//     register outside that range is not a scale factor, it is corruption or a
//     hostile device. The referee refuses it. What the product does with it is
//     the interesting half — see [SFLegalRange].
//
//  2. DOES DECODE PRESERVE MAGNITUDE? raw and sf in, engineering value out,
//     compared against exact rational arithmetic.
//
//  3. DOES ENCODE SATURATE HONESTLY? A value that does not fit the register at
//     the chosen scale factor cannot be encoded. There are two defensible
//     answers — refuse, or clamp and SAY SO — and one indefensible one, which is
//     to clamp silently and return a number the caller will treat as the value
//     it asked for. The referee's encode reports saturation as a second return
//     value; the comparison asks whether the product's caller could have known.
//     See [compareEncode] for which product entry point that question is put to,
//     and why the answer changed in lexa-proto 1bda02c.

import (
	"context"
	"fmt"
	"math"
	"math/big"
	"math/rand"

	"csip-tls-test/internal/invariant"
	"lexa-proto/sunspec"
)

// SFLegalRange is the referee's reading of the SunSpec sunssf type: a scale
// factor is a power of ten in [-10, +10].
//
// The bound is what makes the type meaningful. 10^-10 to 10^10 spans every
// physical quantity a DER register carries — picoamps to gigawatts — and a
// register outside it cannot be a scale factor any device intended. Treating
// such a register as arithmetic rather than as corruption is how a garbage read
// becomes a plausible-looking measurement, which is the quiet-failure class the
// whole strategy is about.
const (
	SFMin int16 = -10
	SFMax int16 = 10
)

// SFNotImplemented is the reserved sunssf sentinel: the point exists in the
// layout but the device does not implement it.
const SFNotImplemented int16 = -32768

// refDecode is the referee's decode: exact rational arithmetic, no float
// intermediate, no math.Pow10.
//
// ok is false when sf is not a legal scale factor. A caller that gets ok=false
// has been handed corruption and must not produce a number from it — which is
// precisely the behaviour the comparison against the product tests.
func refDecode(raw int64, sf int16) (val *big.Rat, ok bool) {
	if sf == SFNotImplemented {
		return nil, false
	}
	if sf < SFMin || sf > SFMax {
		return nil, false
	}
	r := new(big.Rat).SetInt64(raw)
	p := new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(abs16(sf))), nil)
	if sf >= 0 {
		return r.Mul(r, new(big.Rat).SetInt(p)), true
	}
	return r.Quo(r, new(big.Rat).SetInt(p)), true
}

// refEncode is the referee's encode: the exact rational value, rounded to
// nearest, then range-checked against the target register's representable
// interval.
//
// saturated is the answer to the question the product's encoder does not
// answer: "did this value fit?". lo and hi are the max-VALID edges, excluding
// the reserved not-implemented sentinel, because encoding a real value as
// "not implemented" corrupts it in a way no consumer can detect.
func refEncode(val *big.Rat, sf int16, lo, hi int64) (raw int64, saturated bool, ok bool) {
	if sf == SFNotImplemented || sf < SFMin || sf > SFMax {
		return 0, false, false
	}
	scaled := new(big.Rat).Set(val)
	p := new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(abs16(sf))), nil)
	if sf >= 0 {
		scaled.Quo(scaled, new(big.Rat).SetInt(p))
	} else {
		scaled.Mul(scaled, new(big.Rat).SetInt(p))
	}
	n := ratRoundHalfAwayFromZero(scaled)
	if n.Cmp(big.NewInt(hi)) > 0 {
		return hi, true, true
	}
	if n.Cmp(big.NewInt(lo)) < 0 {
		return lo, true, true
	}
	return n.Int64(), false, true
}

// ratRoundHalfAwayFromZero rounds a rational to the nearest integer, ties away
// from zero — the same rule math.Round applies, stated independently so the
// referee does not inherit the product's rounding by accident.
func ratRoundHalfAwayFromZero(r *big.Rat) *big.Int {
	num, den := r.Num(), r.Denom()
	q, rem := new(big.Int).QuoRem(num, den, new(big.Int))
	twice := new(big.Int).Abs(rem)
	twice.Lsh(twice, 1)
	if twice.Cmp(new(big.Int).Abs(den)) >= 0 {
		if r.Sign() < 0 {
			q.Sub(q, big.NewInt(1))
		} else {
			q.Add(q, big.NewInt(1))
		}
	}
	return q
}

func abs16(v int16) int16 {
	if v < 0 {
		return -v
	}
	return v
}

// ratFloat renders a rational as the float64 a comparison uses. Exactness is
// preserved right up to this point; the conversion happens once, at the very
// end, so no intermediate rounding can be mistaken for a disagreement.
func ratFloat(r *big.Rat) float64 {
	f, _ := r.Float64()
	return f
}

// SFCase is one scale-factor probe.
type SFCase struct {
	ID    string
	Title string
	// Raw is the register word under test, and SF the scale factor register.
	Raw uint16
	SF  int16
	// Signed selects the signed (int16) or unsigned (uint16) decode path.
	Signed bool
	// EncodeValue, when non-nil, additionally exercises the encode direction
	// with this engineering value.
	EncodeValue *big.Rat
	// Why records what this case exists to provoke, printed with the result.
	Why string
}

// RunSF adjudicates one scale-factor case.
func RunSF(_ context.Context, c SFCase) Case {
	out := Case{
		ID:     c.ID,
		Family: "sf",
		Title:  c.Title,
		Input:  fmt.Sprintf("raw=0x%04X sf=%d signed=%v", c.Raw, c.SF, c.Signed),
		Product: Side{Name: "product", Lineage: "lexa-proto/sunspec — ApplyScale*/EncodeScale*, plus the " +
			"outcome-discarding RawFromScale* wrapper, all on float64 math.Pow10"},
		Referee: Side{Name: "referee", Lineage: "csip-tls-test/internal/diff — exact math/big.Rat arithmetic"},
		Limitation: "this family adjudicates the ARITHMETIC of scale factors and the LEGALITY of the " +
			"scale-factor register; which scale factor a given point uses is a layout question, " +
			"adjudicated by family \"reg\"",
	}
	if c.Why != "" {
		out.Title += " — " + c.Why
	}

	rawSigned := int64(int16(c.Raw))
	if !c.Signed {
		rawSigned = int64(c.Raw)
	}

	// ── (1) legality ──────────────────────────────────────────────────────
	refVal, refOK := refDecode(rawSigned, c.SF)
	var prodVal float64
	if c.Signed {
		prodVal = sunspec.ApplyScaleSigned(c.Raw, c.SF)
	} else {
		prodVal = sunspec.ApplyScaleUint(c.Raw, c.SF)
	}
	prodRefused := math.IsNaN(prodVal)

	legalKey := "sf.legal"
	out.Compare(CompareBool(legalKey,
		T(ProductSide.Name, legalKey, "%s", describeFloat(prodVal)),
		T(RefereeSide.Name, legalKey, "%s", refusalText(refOK)),
		!prodRefused, refOK,
		fmt.Sprintf("scale factor %d is %s a legal SunSpec sunssf (referee's range is [%d,%d] plus the "+
			"0x8000 not-implemented sentinel); the question is whether each side produced a NUMBER from it",
			c.SF, legalWord(refOK), SFMin, SFMax)))

	if !refOK {
		if !prodRefused {
			out.Note(Finding{
				ID:       out.ID + "/illegal-sf-accepted",
				Title:    fmt.Sprintf("scale factor %d is outside the sunssf range and the product still produced a value", c.SF),
				Severity: "P1",
				Input:    out.Input,
				Product:  T(ProductSide.Name, legalKey, "%s", describeFloat(prodVal)),
				Referee:  T(RefereeSide.Name, legalKey, "refuses: %d is not a scale factor", c.SF),
				Impact: fmt.Sprintf("a device that publishes a corrupt or hostile scale-factor register makes "+
					"the gateway read %s from register 0x%04X. A reading of that shape is not obviously "+
					"wrong to anything downstream — it is a number, it has the right type, and it will be "+
					"reported, stored and used in control decisions like any other",
					describeFloat(prodVal), c.Raw),
				Limitation: "the referee's [-10,+10] bound is its reading of the sunssf type; the finding " +
					"that survives any bound is that the product applies NO bound at all",
			})
		}
		out.Finalize("the scale factor is not legal, so there is no engineering value for the two sides " +
			"to agree on; the legality comparison above is the whole of this case")
		return out
	}

	// ── (2) decode magnitude ──────────────────────────────────────────────
	if prodRefused {
		out.Compare(Comparison{
			Key:     "sf.decode",
			Product: T(ProductSide.Name, "sf.decode", "NaN"),
			Referee: Q(RefereeSide.Name, "sf.decode", invariant.Q(ratFloat(refVal), invariant.UnitNone)),
			Verdict: Fail,
			Reason: fmt.Sprintf("the scale factor %d is legal and the raw word decodes to %s exactly, and "+
				"the product returned NaN", c.SF, refVal.FloatString(12)),
		})
	} else {
		out.Compare(CompareQuantity("sf.decode",
			Q(ProductSide.Name, "sf.decode", invariant.Q(prodVal, invariant.UnitNone)),
			Q(RefereeSide.Name, "sf.decode", invariant.Q(ratFloat(refVal), invariant.UnitNone)).
				WithNote("exact: %s", refVal.FloatString(12)),
			halfLSB(c.SF)))
	}

	// ── (3) encode, and whether saturation is visible ─────────────────────
	if c.EncodeValue != nil {
		compareEncode(&out, c)
	}

	out.Finalize("nothing in this case was comparable")
	return out
}

// halfLSB is the tolerance a decode comparison allows: half of one
// least-significant unit at this scale factor, and nothing else.
//
// It is a property of the ENCODING, not of the value: at sf=1 the register
// counts in tens, so half a count is 5, whatever the number happens to be.
// Deriving it from the value under test is exactly the tautology BR-02 named,
// and this function exists so that mistake has to be made deliberately.
func halfLSB(sf int16) invariant.Tolerance {
	return invariant.Tolerance{Rel: 0, Abs: 0.5 * math.Pow10(int(sf))}
}

// compareEncode adjudicates the encode direction, including the question the
// product's signature used to have no room to answer.
//
// # Which product entry point this asks, and why that changed
//
// This function used to drive sunspec.RawFromScale* and raise a standing
// "silent-saturation" finding on every value that did not fit, on the grounds
// that "the encoder returns uint16 only". That sentence was true when it was
// written and is not true now. lexa-proto 1bda02c (LXR-004 — prompted by this
// very finding) split the codec in two:
//
//	EncodeScaleSigned/Uint   (uint16, EncodeOutcome) — the COMMAND-WRITER entry
//	                         point. The outcome separates EncodeExact from
//	                         EncodeSaturatedHigh/Low, so a caller CAN tell
//	                         "applied" from "applied as something else".
//	RawFromScaleSigned/Uint  uint16 — a round-trip wrapper that DISCARDS the
//	                         outcome, documented for sweeps and simulators
//	                         where the caller chose the scale factor itself.
//
// Continuing to put the "could the caller have known?" question to the wrapper
// measures this harness's own choice of entry point, not the product: discarding
// the answer is the wrapper's whole documented contract, and derbase's writers
// already call EncodeScale* and act on the outcome (derbase.go's m123LimitPlan
// compensation path is built on it). A finding that only reproduces because the
// referee dialled the deprecated number is a stale finding, and a stale finding
// costs a differential its credibility faster than a missed one.
//
// So both halves are now adjudicated against the referee — the reporting
// encoder's raw word AND its outcome, and separately the wrapper's raw word, so
// the two product entry points cannot drift apart unnoticed — and the
// silent-saturation finding is raised only where the product genuinely fails to
// signal. See TestSFCatalog_SaturationIsReportedToTheCaller for the inverted
// lock that keeps this honest.
func compareEncode(out *Case, c SFCase) {
	lo, hi := int64(-32767), int64(32767)
	if !c.Signed {
		lo, hi = 0, 65534
	}
	refRaw, refSat, refOK := refEncode(c.EncodeValue, c.SF, lo, hi)
	if !refOK {
		out.Compare(SkipComparison("sf.encode", "the referee will not encode against an illegal scale factor"))
		return
	}

	val := ratFloat(c.EncodeValue)
	var prodRaw, wrapperRaw uint16
	var outcome sunspec.EncodeOutcome
	if c.Signed {
		prodRaw, outcome = sunspec.EncodeScaleSigned(val, c.SF)
		wrapperRaw = sunspec.RawFromScaleSigned(val, c.SF)
	} else {
		prodRaw, outcome = sunspec.EncodeScaleUint(val, c.SF)
		wrapperRaw = sunspec.RawFromScaleUint(val, c.SF)
	}
	prodInt, wrapperInt := registerInt(prodRaw, c.Signed), registerInt(wrapperRaw, c.Signed)

	refClaim := func(key string) Claim {
		return Q(RefereeSide.Name, key, invariant.Q(float64(refRaw), invariant.UnitNone)).
			WithNote("exact encode of %s at sf=%d", c.EncodeValue.FloatString(6), c.SF)
	}
	out.Compare(CompareQuantity("sf.encode",
		Q(ProductSide.Name, "sf.encode", invariant.Q(float64(prodInt), invariant.UnitNone)),
		refClaim("sf.encode"),
		invariant.Tolerance{Abs: 0.5}))

	// The wrapper is still shipped and still callable, so it is still compared —
	// against the REFEREE, not against the reporting encoder, because a
	// product-versus-product check would agree by construction the day somebody
	// implements one in terms of the other (which is, today, exactly what
	// RawFromScale* is).
	out.Compare(CompareQuantity("sf.encode.wrapper",
		Q(ProductSide.Name, "sf.encode.wrapper", invariant.Q(float64(wrapperInt), invariant.UnitNone)).
			WithNote("sunspec.RawFromScale%s, the outcome-discarding round-trip wrapper", signedSuffix(c.Signed)),
		refClaim("sf.encode.wrapper"),
		invariant.Tolerance{Abs: 0.5}))

	held, _ := refDecode(prodInt, c.SF)
	told := !outcome.Representable()

	switch {
	case refSat && told:
		// The property the family exists to establish, now holding.
		out.Compare(Comparison{
			Key: "sf.saturation-visible",
			Product: T(ProductSide.Name, "sf.saturation-visible", "raw %d (%s), signalled: %s",
				prodInt, floatOrUnknown(held), outcomeText(outcome)),
			Referee: T(RefereeSide.Name, "sf.saturation-visible", "saturated at the %d edge; the caller must be told", refRaw),
			Verdict: Pass,
		})

	case refSat && !told:
		// The indefensible answer: the register does not carry the requested
		// value and nothing in the return says so.
		out.Compare(Comparison{
			Key: "sf.saturation-visible",
			Product: T(ProductSide.Name, "sf.saturation-visible", "raw %d, no signal (%s)",
				prodInt, outcomeText(outcome)),
			Referee: T(RefereeSide.Name, "sf.saturation-visible", "saturated at the %d edge", refRaw),
			Verdict: Fail,
			Reason: fmt.Sprintf("the value %s does not fit a %s register at sf=%d. The product clamped it to "+
				"raw %d — %s in engineering units — and returned no indication that it had done so, so a "+
				"caller cannot distinguish 'applied' from 'applied as something else'",
				c.EncodeValue.FloatString(3), signedWord(c.Signed), c.SF, prodInt, floatOrUnknown(held)),
			Facts: []invariant.Fact{
				invariant.F("sf.encode.requested", "", RefereeSide.Name, "%s", c.EncodeValue.FloatString(3)),
				invariant.F("sf.encode.raw", "", ProductSide.Name, "%d", prodInt),
				invariant.F("sf.encode.effective", "", RefereeSide.Name, "%s", floatOrUnknown(held)),
			},
		})
		out.Note(Finding{
			ID:       out.ID + "/silent-saturation",
			Title:    "an unrepresentable value is clamped and the caller is not told",
			Severity: "P2",
			Input:    out.Input + fmt.Sprintf(" encode=%s", c.EncodeValue.FloatString(3)),
			Product:  T(ProductSide.Name, "sf.encode", "raw %d (%s) — silently", prodInt, floatOrUnknown(held)),
			Referee:  T(RefereeSide.Name, "sf.encode", "%s does not fit; refuse or report", c.EncodeValue.FloatString(3)),
			Impact: "a control value the gateway believes it wrote is not the value on the device, and no " +
				"return path carries the difference. The register readback would show it, but the writer " +
				"never learns",
			Limitation: "the clamp itself is CORRECT and deliberate (audit SUN-004: clamping to the max-valid " +
				"edge rather than onto the reserved sentinel). The finding is the absent signal, not the clamp",
		})

	case !refSat && told:
		// BY DESIGN, and a divergence the two readings genuinely have. The
		// referee asks whether the ROUNDED value fits the register, so a
		// negative request whose magnitude is under half a least-significant
		// unit — −16595 W into an UNSIGNED register at sf=10, where one count is
		// 10 GW — rounds to 0 and "fits" on its terms. The product's
		// EncodeScaleUint answers the DOMAIN question first (`if val < 0 →
		// EncodeSaturatedLow`, sunspec/scale.go), because an unsigned register
		// cannot carry a sign at any resolution.
		//
		// Neither reading is wrong and the two agree on the raw word, so this is
		// not a finding: it is the product being STRICTER than the referee, in
		// the only direction that is safe to be stricter in. It is recorded as a
		// WARN rather than swallowed, because a differential that quietly
		// normalises away a real difference between two readings is no longer
		// reporting what it saw. The referee is deliberately NOT changed to match
		// — csipref.go's rule applies here too: a referee reconciled with the
		// product stops being able to find anything.
		out.Compare(Comparison{
			Key: "sf.representable",
			Product: T(ProductSide.Name, "sf.representable", "raw %d, signalled anyway: %s",
				prodInt, outcomeText(outcome)),
			Referee: T(RefereeSide.Name, "sf.representable", "raw %d carries %s to within half a count at sf=%d",
				refRaw, c.EncodeValue.FloatString(3), c.SF),
			Verdict: Warn,
			Reason: fmt.Sprintf("both sides encode raw %d, and they differ only on whether that counts as "+
				"saturation: the referee rounds first and finds %s representable at sf=%d, the product "+
				"treats a negative value in a %s register as out of DOMAIN before rounding. The product's "+
				"reading is the stricter one — it over-reports the loss of a sign, never under-reports it — "+
				"so no control value is at risk either way",
				refRaw, c.EncodeValue.FloatString(3), c.SF, signedWord(c.Signed)),
		})

	default:
		out.Compare(Comparison{
			Key:     "sf.representable",
			Product: T(ProductSide.Name, "sf.representable", "raw %d, %s", prodInt, outcomeText(outcome)),
			Referee: T(RefereeSide.Name, "sf.representable", "raw %d, no saturation", refRaw),
			Verdict: Pass,
		})
	}
}

// registerInt reinterprets an encoded register word as the signed or unsigned
// integer the point's type says it is.
func registerInt(raw uint16, signed bool) int64 {
	if signed {
		return int64(int16(raw))
	}
	return int64(raw)
}

// outcomeText names an EncodeOutcome for the report.
//
// It is written here rather than as a String() method on the product's type on
// purpose: a shared renderer would have the referee describing the product's
// answer in the product's own words, and the whole value of this side is that it
// says what it saw independently.
func outcomeText(o sunspec.EncodeOutcome) string {
	switch o {
	case sunspec.EncodeExact:
		return "EncodeExact — the caller is told the register carries the value it asked for"
	case sunspec.EncodeSaturatedHigh:
		return "EncodeSaturatedHigh — the caller is told it was clamped onto the high edge"
	case sunspec.EncodeSaturatedLow:
		return "EncodeSaturatedLow — the caller is told it was clamped onto the low edge"
	case sunspec.EncodeNotImplemented:
		return "EncodeNotImplemented — the caller is told the reserved sentinel was written"
	case sunspec.EncodeBadSF:
		return "EncodeBadSF — the caller is told the scale factor is not usable"
	}
	return fmt.Sprintf("outcome %d, which this referee's reading of EncodeOutcome does not define", o)
}

func signedSuffix(signed bool) string {
	if signed {
		return "Signed"
	}
	return "Uint"
}

func describeFloat(f float64) string {
	switch {
	case math.IsNaN(f):
		return "NaN (refused)"
	case math.IsInf(f, 1):
		return "+Inf"
	case math.IsInf(f, -1):
		return "-Inf"
	}
	return fmt.Sprintf("%g", f)
}

func floatOrUnknown(r *big.Rat) string {
	if r == nil {
		return "unknown"
	}
	return r.FloatString(6)
}

func refusalText(ok bool) string {
	if ok {
		return "accepts"
	}
	return "refuses"
}

func legalWord(ok bool) string {
	if ok {
		return "IS"
	}
	return "is NOT"
}

func signedWord(signed bool) string {
	if signed {
		return "int16"
	}
	return "uint16"
}

// SFCatalog is the standing set of scale-factor probes.
func SFCatalog() []SFCase {
	rat := func(s string) *big.Rat {
		r, _ := new(big.Rat).SetString(s)
		return r
	}
	return []SFCase{
		{ID: "DIFF-SF-001", Title: "ordinary decode at sf=0", Raw: 4200, SF: 0, Signed: true},
		{ID: "DIFF-SF-002", Title: "decode at sf=1 (tens of watts)", Raw: 4200, SF: 1, Signed: true},
		{ID: "DIFF-SF-003", Title: "decode at sf=-2 (hundredths)", Raw: 8000, SF: -2, Signed: true},
		{ID: "DIFF-SF-004", Title: "negative raw at sf=-2", Raw: 0xE0C0, SF: -2, Signed: true},
		{ID: "DIFF-SF-005", Title: "unsigned decode at the top of the range", Raw: 65534, SF: 1, Signed: false},
		{ID: "DIFF-SF-006", Title: "the not-implemented scale factor", Raw: 1234, SF: SFNotImplemented, Signed: true,
			Why: "both sides must refuse"},

		// The illegal scale factors. Each of these is a register a corrupt read
		// or a hostile device can produce, and none of them is a scale factor.
		{ID: "DIFF-SF-010", Title: "scale factor -32767", Raw: 1000, SF: -32767, Signed: true,
			Why: "one above the sentinel — not a sentinel, not a scale factor"},
		{ID: "DIFF-SF-011", Title: "scale factor +32767", Raw: 1000, SF: 32767, Signed: true,
			Why: "the int16 ceiling"},
		{ID: "DIFF-SF-012", Title: "scale factor -300", Raw: 1000, SF: -300, Signed: true,
			Why: "a plausible-looking byte-swap of a real register"},
		{ID: "DIFF-SF-013", Title: "scale factor +11", Raw: 1000, SF: 11, Signed: true,
			Why: "just outside the sunssf range"},
		{ID: "DIFF-SF-014", Title: "scale factor -11", Raw: 1000, SF: -11, Signed: true,
			Why: "just outside the sunssf range, low side"},

		// Encode, including values that cannot fit.
		{ID: "DIFF-SF-020", Title: "encode a value that fits", Raw: 0, SF: 0, Signed: true,
			EncodeValue: rat("1500")},
		{ID: "DIFF-SF-021", Title: "encode 100 kW at sf=0 — does not fit an int16", Raw: 0, SF: 0, Signed: true,
			EncodeValue: rat("100000"), Why: "the register tops out at 32767"},
		{ID: "DIFF-SF-022", Title: "encode 100 kW at sf=1 — fits", Raw: 0, SF: 1, Signed: true,
			EncodeValue: rat("100000")},
		{ID: "DIFF-SF-023", Title: "encode a large negative value at sf=-2", Raw: 0, SF: -2, Signed: true,
			EncodeValue: rat("-1000"), Why: "-100000 counts against a -32767 floor"},
		{ID: "DIFF-SF-024", Title: "encode a fractional value that rounds", Raw: 0, SF: 0, Signed: true,
			EncodeValue: rat("1500.5")},
		{ID: "DIFF-SF-025", Title: "encode a negative into an unsigned register", Raw: 0, SF: 0, Signed: false,
			EncodeValue: rat("-500"), Why: "the floor is 0, so the sign is lost"},
	}
}

// GenerateSF produces randomised scale-factor probes from a seed, so a run
// explores the space the catalogue fixes. The seed is recorded on the report,
// which is what makes a generated failure reproducible.
func GenerateSF(seed int64, n int) []SFCase {
	rng := rand.New(rand.NewSource(seed))
	out := make([]SFCase, 0, n)
	for i := 0; i < n; i++ {
		signed := rng.Intn(2) == 0
		// Draw mostly-legal scale factors with a deliberate minority outside
		// the range: a generator that only ever produces legal input cannot
		// find the legality defect, and one that only produces illegal input
		// never exercises the arithmetic.
		sf := int16(rng.Intn(21) - 10)
		if rng.Intn(6) == 0 {
			sf = int16(rng.Intn(65536) - 32768)
		}
		raw := uint16(rng.Intn(65536))
		val := new(big.Rat).SetFloat64(float64(rng.Intn(4_000_000)-2_000_000) / 100)
		out = append(out, SFCase{
			ID:          fmt.Sprintf("DIFF-SF-GEN-%04d", i),
			Title:       "generated scale-factor probe",
			Raw:         raw,
			SF:          sf,
			Signed:      signed,
			EncodeValue: val,
		})
	}
	return out
}

// RunSFCatalog runs the standing cases plus n generated ones into a report.
func RunSFCatalog(ctx context.Context, r *Report, generated int) {
	for _, c := range SFCatalog() {
		r.Add(RunSF(ctx, c))
	}
	for _, c := range GenerateSF(r.Seed, generated) {
		r.Add(RunSF(ctx, c))
	}
}
