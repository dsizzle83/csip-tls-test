package diff

// compare.go holds the adjudicators. There are only three of them and they are
// short, which is the point: the interesting judgement in a differential is
// "were these two things even comparable", not "is 4.0 close to 4.000001".
//
// Two rules are enforced here rather than left to each family.
//
// UNITS ARE PART OF THE COMPARISON. [CompareQuantity] refuses a cross-unit
// compare outright — it delegates to invariant.Tolerance.Exceeds, which returns
// an error rather than a verdict when the units differ. A differential that
// silently compared 80 (%) against 48000 (var) and reported agreement, or
// disagreement, would be reproducing audit BR-01 inside the tool built to catch
// it.
//
// THE TOLERANCE IS NOT DERIVED FROM THE VALUE UNDER TEST. Audit BR-02 found the
// existing scale-factor cross-check tautological because its tolerance came out
// of the number it was checking; such a check passes by construction. Every
// tolerance here is either an absolute floor in the quantity's own unit or a
// fraction of the REFEREE's value — never of the product's — and the tolerance
// that was used is recorded on the [Comparison] so a reader can see which.

import (
	"fmt"
	"math"

	"csip-tls-test/internal/invariant"
)

// CompareQuantity adjudicates two physical claims.
//
// The referee's value is the reference for the relative tolerance. That
// asymmetry is deliberate: taking the tolerance from the product's own answer is
// the tautology BR-02 named, and a check whose slack grows with the error it is
// looking for cannot fail.
func CompareQuantity(key string, product, referee Claim, tol invariant.Tolerance) Comparison {
	cmp := Comparison{Key: key, Product: product, Referee: referee, Tolerance: tol}

	switch {
	case !product.HasValue && !referee.HasValue:
		cmp.Verdict = Skip
		cmp.Reason = "neither side produced a value: " + bothNotes(product, referee)
		return cmp
	case !referee.HasValue:
		cmp.Verdict = Skip
		cmp.Reason = "the referee could not resolve this quantity, so the product's answer is " +
			"unadjudicated: " + noteOr(referee, "no reason given")
		return cmp
	case !product.HasValue:
		cmp.Verdict = Fail
		cmp.Reason = fmt.Sprintf("the referee resolved %s and the product produced nothing: %s",
			referee.Value, noteOr(product, "no reason given"))
		return cmp
	}

	if product.Value.Unit != referee.Value.Unit {
		cmp.Verdict = Fail
		cmp.Reason = fmt.Sprintf("the two sides answered in DIFFERENT UNITS — product %s, referee %s. "+
			"A number that changed unit between implementations is the BR-01 defect class itself, so "+
			"this is reported as a disagreement rather than converted", product.Value, referee.Value)
		return cmp
	}
	if !product.Value.Known() || !referee.Value.Known() {
		cmp.Verdict = Skip
		cmp.Reason = fmt.Sprintf("one side is not a number (product %s, referee %s); a NaN never "+
			"reaches a comparison here", product.Value, referee.Value)
		return cmp
	}

	slack := math.Max(math.Abs(referee.Value.Val)*tol.Rel, tol.Abs)
	delta := product.Value.Val - referee.Value.Val
	cmp.Facts = []invariant.Fact{
		invariant.F(key+".product", string(product.Value.Unit), product.Side, "%g", product.Value.Val),
		invariant.F(key+".referee", string(referee.Value.Unit), referee.Side, "%g", referee.Value.Val),
		invariant.F(key+".delta", string(referee.Value.Unit), "diff", "%g", delta),
		invariant.F(key+".slack", string(referee.Value.Unit), "diff", "%g", slack),
	}
	if math.Abs(delta) <= slack {
		cmp.Verdict = Pass
		return cmp
	}
	cmp.Verdict = Fail
	cmp.Reason = fmt.Sprintf("product %s, referee %s: %s apart, tolerance %g (rel %g of the REFEREE's "+
		"value, abs %g)%s", product.Value, referee.Value,
		invariant.Q(math.Abs(delta), referee.Value.Unit), slack, tol.Rel, tol.Abs, ratioSuffix(product, referee))
	return cmp
}

// ratioSuffix adds the multiple when the disagreement is large enough that a
// ratio is the honest way to describe it. A 24× overcommand described as "a
// difference of 46000 var" reads like a rounding argument; described as 24× it
// reads like what it is.
func ratioSuffix(product, referee Claim) string {
	r := math.Abs(referee.Value.Val)
	p := math.Abs(product.Value.Val)
	if r == 0 || p == 0 {
		return ""
	}
	ratio := p / r
	if ratio >= 1.5 {
		return fmt.Sprintf(" — the product's value is %.3gx the referee's", ratio)
	}
	if ratio <= 1/1.5 {
		return fmt.Sprintf(" — the product's value is %.3gx the referee's (an UNDER-delivery)", ratio)
	}
	return ""
}

// CompareText adjudicates two claims that are not numbers — a block list, a
// refusal, an error string. Equality is exact; there is no fuzzy matching,
// because a differential that normalises its way to agreement has adjudicated
// its own normalisation rather than the implementations.
func CompareText(key string, product, referee Claim) Comparison {
	cmp := Comparison{Key: key, Product: product, Referee: referee}
	switch {
	case product.Text == "" && referee.Text == "":
		cmp.Verdict = Skip
		cmp.Reason = "neither side produced a rendering to compare: " + bothNotes(product, referee)
	case product.Text == referee.Text:
		cmp.Verdict = Pass
	default:
		cmp.Verdict = Fail
		cmp.Reason = fmt.Sprintf("product %q, referee %q", product.Text, referee.Text)
		cmp.Facts = []invariant.Fact{
			invariant.F(key+".product", "", product.Side, "%s", product.Text),
			invariant.F(key+".referee", "", referee.Side, "%s", referee.Text),
		}
	}
	return cmp
}

// CompareBool adjudicates two yes/no claims — "did this side refuse the input".
// It exists separately from CompareText because "both refused" is a PASS worth
// distinguishing from "both accepted", and a report that cannot tell them apart
// hides the case where a hostile input was accepted by both.
func CompareBool(key string, product, referee Claim, productVal, refereeVal bool, what string) Comparison {
	cmp := Comparison{Key: key, Product: product, Referee: referee}
	if productVal == refereeVal {
		cmp.Verdict = Pass
		return cmp
	}
	cmp.Verdict = Fail
	cmp.Reason = fmt.Sprintf("%s: product says %v, referee says %v", what, productVal, refereeVal)
	cmp.Facts = []invariant.Fact{
		invariant.F(key+".product", "bool", product.Side, "%v", productVal),
		invariant.F(key+".referee", "bool", referee.Side, "%v", refereeVal),
	}
	return cmp
}

// SkipComparison records a comparison that could not be made, with the reason.
// A family that has nothing to compare must call this rather than simply
// appending nothing: an absent comparison and a skipped one look identical in a
// count but only one of them tells the reader why.
func SkipComparison(key, reason string) Comparison {
	return Comparison{
		Key:     key,
		Product: Claim{Side: ProductSide.Name, Key: key},
		Referee: Claim{Side: RefereeSide.Name, Key: key},
		Verdict: Skip,
		Reason:  reason,
	}
}

func noteOr(c Claim, fallback string) string {
	if c.Note != "" {
		return c.Note
	}
	if c.Text != "" {
		return c.Text
	}
	return fallback
}

func bothNotes(product, referee Claim) string {
	return fmt.Sprintf("product: %s; referee: %s", noteOr(product, "silent"), noteOr(referee, "silent"))
}
