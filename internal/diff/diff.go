package diff

// diff.go is the vocabulary every family in this package speaks.
//
// The shape is deliberately narrow: a [Case] is one probe, a [Comparison] is one
// pair of claims about one quantity, and a [Finding] is a comparison that
// disagreed, carried with enough context that somebody who was not here can
// reproduce it. The thing this file works hardest to make impossible is a
// disagreement reported as prose. "The product wrote the wrong value" is not a
// finding; "the product wrote 21120 var where the document asked for 48000 var,
// from THIS input, on THIS nameplate" is, and the difference is entirely in the
// struct fields.
//
// The second thing it works to make impossible is a family reporting PASS
// without having compared anything. [Case.Checked] counts comparisons actually
// evaluated, [Report.Summary] refuses a PASS on a zero count, and every
// constructor that could produce an empty case takes a reason string. This is
// the same floor internal/invariant enforces, for the same reason: a harness
// that can print a pass it did not earn is worse than no harness.

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"csip-tls-test/internal/evidence/bundle"
	"csip-tls-test/internal/invariant"
)

// Verdict is internal/invariant's verdict, re-exported so a differential result
// and an invariant result can share one report without translation. PENDING is
// legal in the type but unused here: a differential either compared two things
// or it did not, and there is nothing for the end of a run to resolve.
type Verdict = invariant.Verdict

// The verdicts this package uses.
const (
	Pass = invariant.Pass
	Fail = invariant.Fail
	Skip = invariant.Skip
	Warn = invariant.Warn
)

// Side names one implementation and, more importantly, its lineage. Lineage is
// not decoration: a differential between two views of the same code is worth
// nothing, and the only way a reader can judge whether a given comparison had
// any power is to be told where each half came from.
type Side struct {
	// Name is short and stable, e.g. "product/derbase".
	Name string
	// Lineage says where the code came from and who wrote it, e.g.
	// "lexa-proto/derbase — ships in the DUT".
	Lineage string
}

// The sides this package compares. ProductSide is whatever the gateway actually
// runs; RefereeSide is written here, from the standards, and is never synced
// with the product.
var (
	ProductSide = Side{
		Name:    "product",
		Lineage: "lexa-proto — the module vendored into and shipped by lexa-gw",
	}
	RefereeSide = Side{
		Name:    "referee",
		Lineage: "csip-tls-test — written here from IEEE 2030.5 / CSIP / SunSpec, never synced with the product",
	}
)

// Claim is one side's answer about one quantity.
//
// Value and Text are alternatives, not both: a claim about a setpoint is a
// [invariant.Quantity] so it can be compared with units intact, and a claim
// about something that is not a number — a block list, an error, a refusal —
// is Text. A comparator that is handed one of each says so rather than
// stringifying its way to a false agreement.
type Claim struct {
	Side  string             `json:"side"`
	Key   string             `json:"key"`
	Value invariant.Quantity `json:"value,omitzero"`
	// HasValue distinguishes "the value is zero" from "there is no value".
	HasValue bool `json:"has_value,omitempty"`
	// Text is the rendering for a non-numeric claim.
	Text string `json:"text,omitempty"`
	// Note carries the side's own caveat — "unresolved: the device serves no
	// M702", "saturated at the int16 edge" — and is printed next to the value
	// so a reader is never shown a number whose provenance the producer
	// doubted.
	Note string `json:"note,omitempty"`
}

// Q builds a numeric claim.
func Q(side, key string, q invariant.Quantity) Claim {
	return Claim{Side: side, Key: key, Value: q, HasValue: true}
}

// T builds a textual claim.
func T(side, key, format string, args ...any) Claim {
	return Claim{Side: side, Key: key, Text: fmt.Sprintf(format, args...)}
}

// WithNote returns a copy of c carrying a caveat.
func (c Claim) WithNote(format string, args ...any) Claim {
	c.Note = fmt.Sprintf(format, args...)
	return c
}

// String renders a claim for the report.
func (c Claim) String() string {
	body := c.Text
	if c.HasValue {
		body = c.Value.String()
	}
	if body == "" {
		body = "(nothing)"
	}
	if c.Note != "" {
		return body + " [" + c.Note + "]"
	}
	return body
}

// Comparison is two sides' claims about one key, plus the adjudication.
type Comparison struct {
	Key     string  `json:"key"`
	Product Claim   `json:"product"`
	Referee Claim   `json:"referee"`
	Verdict Verdict `json:"verdict"`
	// Reason is mandatory for anything other than Pass. A SKIP that does not
	// name what it could not compare is indistinguishable from a comparator
	// that forgot to run.
	Reason string `json:"reason,omitempty"`
	// Tolerance is the slack the comparison allowed, recorded so a reader can
	// see that the tolerance was not derived from the value under test — the
	// tautology audit BR-02 found.
	Tolerance invariant.Tolerance `json:"tolerance,omitzero"`
	Facts     []invariant.Fact    `json:"facts,omitempty"`

	// Advisory marks a row that is a CAVEAT rather than a comparison — the
	// standing warning that both sides share a constant, for instance. An
	// advisory row prints, and can raise the case's verdict to WARN, but it
	// does NOT count towards [Case.Checked]. Without this distinction a family
	// could satisfy the assertion floor by emitting its own disclaimers, which
	// is exactly the shape of dishonesty the floor exists to prevent.
	Advisory bool `json:"advisory,omitempty"`
}

// Validate enforces the contract a comparison must satisfy before it is allowed
// into a report.
func (c Comparison) Validate() error {
	if c.Key == "" {
		return fmt.Errorf("comparison has no key")
	}
	switch c.Verdict {
	case Pass:
		return nil
	case Fail, Skip, Warn:
		if strings.TrimSpace(c.Reason) == "" {
			return fmt.Errorf("comparison %q is %s with no reason", c.Key, c.Verdict)
		}
		return nil
	default:
		return fmt.Errorf("comparison %q has verdict %q, which this package does not use", c.Key, c.Verdict)
	}
}

// Finding is a disagreement, recorded so somebody who was not here can
// reproduce it. Every field below exists because a bug report missing it is a
// bug report nobody can act on.
type Finding struct {
	// ID is stable within a family, e.g. "DIFF-CTL-001".
	ID     string `json:"id"`
	Family string `json:"family"`
	Title  string `json:"title"`
	// Severity is P1 for anything that puts a wrong number on a DER, P2 for a
	// semantic divergence with no demonstrated physical consequence, P3 for a
	// reporting or shape difference.
	Severity string `json:"severity"`
	// Input is the reproducing input, rendered so it can be typed back in.
	Input string `json:"input"`
	// Product and Referee are BOTH sides' output. This package never assumes
	// the product is wrong OR that the referee is right, and a finding that
	// prints only one side is asserting exactly that.
	Product Claim `json:"product"`
	Referee Claim `json:"referee"`
	// Impact says what the disagreement does to a physical device.
	Impact string `json:"impact"`
	// Invariant names the invariant that judged this, when one did. Empty
	// means the differential adjudicated it alone, which is a weaker claim
	// and is printed as such.
	Invariant string `json:"invariant,omitempty"`
	// Limitation, when set, is what this finding does NOT establish.
	Limitation string           `json:"limitation,omitempty"`
	Facts      []invariant.Fact `json:"facts,omitempty"`
}

// Signature is a stable identity for a finding across runs, excluding values
// that move. Two runs that produce the same signature found the same thing.
func (f Finding) Signature() string {
	return f.Family + "/" + f.ID + "/" + f.Product.Key
}

// Case is one differential probe: one input shown to both sides.
type Case struct {
	ID     string `json:"id"`
	Family string `json:"family"`
	Title  string `json:"title"`
	// Input is what both sides were shown, rendered for replay.
	Input   string  `json:"input"`
	Verdict Verdict `json:"verdict"`
	Reason  string  `json:"reason,omitempty"`
	// Product and Referee record which implementations were compared, so a
	// reader can judge the case's power without reading the code.
	Product Side `json:"product_side"`
	Referee Side `json:"referee_side"`
	// Invariant names the invariant this case handed its state to, if any.
	Invariant string `json:"invariant,omitempty"`
	// Limitation names what this case cannot establish — normally the surface
	// the two sides share.
	Limitation  string       `json:"limitation,omitempty"`
	Comparisons []Comparison `json:"comparisons"`
	Findings    []Finding    `json:"findings,omitempty"`
}

// Compare appends a comparison and folds its verdict into the case's. It is the
// only way a comparison enters a case, so the count and the verdict cannot drift
// apart: a caller that appends to Comparisons directly is bypassing the floor.
func (c *Case) Compare(cmp Comparison) {
	if err := cmp.Validate(); err != nil {
		cmp.Verdict = Fail
		cmp.Reason = "malformed comparison: " + err.Error()
	}
	c.Comparisons = append(c.Comparisons, cmp)
	c.Verdict = invariant.Worse(c.Verdict, cmp.Verdict)
}

// Note records a finding on the case.
func (c *Case) Note(f Finding) {
	if f.Family == "" {
		f.Family = c.Family
	}
	c.Findings = append(c.Findings, f)
}

// Checked is the number of comparisons this case actually evaluated. A
// comparison that SKIPped does not count — it did not compare anything, which
// is the whole point of counting — and neither does an [Comparison.Advisory]
// row, which is the harness talking about itself.
func (c Case) Checked() int {
	n := 0
	for _, cmp := range c.Comparisons {
		if cmp.Verdict != Skip && !cmp.Advisory {
			n++
		}
	}
	return n
}

// Finalize applies the assertion floor to one case: a case that evaluated
// nothing is a SKIP naming that, never a PASS. reason is what the caller knows
// about why there was nothing to compare, and is required.
func (c *Case) Finalize(reason string) {
	if c.Checked() > 0 {
		if c.Verdict == "" {
			c.Verdict = Pass
		}
		return
	}
	c.Verdict = Skip
	if strings.TrimSpace(reason) == "" {
		reason = "no comparison was evaluated and the family did not say why " +
			"(this is a harness defect, not a device result)"
	}
	c.Reason = reason
}

// Report is a whole differential run.
type Report struct {
	Started time.Time `json:"started"`
	Elapsed string    `json:"elapsed,omitempty"`
	// Seed is recorded so a generated-input family replays exactly.
	Seed  int64  `json:"seed"`
	Cases []Case `json:"cases"`
	// Limitations are the run-level statements of what a differential in this
	// shape cannot catch. They are printed with the summary, not buried.
	Limitations []string `json:"limitations,omitempty"`

	start time.Time
}

// NewReport starts a report.
func NewReport(seed int64) *Report {
	now := time.Now().UTC()
	return &Report{Started: now, Seed: seed, start: now, Limitations: ReportedLimitations()}
}

// Add appends a finished case.
func (r *Report) Add(c Case) { r.Cases = append(r.Cases, c) }

// ReportedLimitations is what every run of this package prints about its own
// blind spots. It is a function rather than a comment because a limitation that
// is not in the artifact is a limitation the reader does not know about.
func ReportedLimitations() []string {
	return []string{
		"The SunSpec register layout TABLES (lexa-proto/sunspec.L70x) are shared wire definitions. " +
			"Family \"reg\" transcribes offsets, types and scale-factor associations independently, so " +
			"offset drift and signedness errors are caught; a shared error in the FIELD LIST or FIELD " +
			"ORDER is not.",
		"The SunSpec 704 mode enum VALUES (M704_VarSetMod_*, M704_WSetMod_*) are shared constants and " +
			"this repository holds no copy of the SunSpec model definition to check them against. Both " +
			"sides read the same numbers, so agreement on them is not evidence. Family \"ctl\" raises " +
			"this as a standing WARN.",
		"The CSIP wire TYPES (lexa-proto/csipmodel) are shared. The referee differs on SEMANTICS — " +
			"which register a mode belongs in, what its reference base is, and what happens when several " +
			"modes arrive together — not on how a field is spelled on the wire.",
		"lexa-proto/mbap framing is shared by design (docs/ADVERSARIAL_QA_STRATEGY.md §5). Nothing here " +
			"differentiates it, and nothing here should be read as having tested it.",
	}
}

// Summary is the roll-up, including the counts that make the floor auditable.
type Summary struct {
	Cases     int            `json:"cases"`
	Compared  int            `json:"compared"`
	Verdict   Verdict        `json:"verdict"`
	ByVerdict map[string]int `json:"by_verdict"`
	Findings  []Finding      `json:"findings,omitempty"`
	// Floor is set when the run as a whole compared nothing. A run that
	// compared nothing cannot pass, and this says so in the artifact rather
	// than only in the exit code.
	Floor string `json:"floor,omitempty"`
}

// Summary rolls the report up and applies the run-level assertion floor.
func (r *Report) Summary() Summary {
	s := Summary{ByVerdict: map[string]int{}, Verdict: Skip}
	for _, c := range r.Cases {
		s.Cases++
		s.Compared += c.Checked()
		s.ByVerdict[string(c.Verdict)]++
		s.Verdict = invariant.Worse(s.Verdict, c.Verdict)
		s.Findings = append(s.Findings, c.Findings...)
	}
	sort.SliceStable(s.Findings, func(i, j int) bool {
		return s.Findings[i].Severity < s.Findings[j].Severity
	})
	if s.Compared == 0 {
		s.Verdict = Skip
		s.Floor = "this run evaluated zero comparisons; a differential that compared nothing " +
			"has not tested anything, and PASS is not available to it"
	}
	if !r.start.IsZero() {
		r.Elapsed = time.Since(r.start).Round(time.Millisecond).String()
	}
	return s
}

// Markdown renders the report the way the rest of this bench renders reports:
// verdict first, then the disagreements with both sides' output, then the
// limitations. sim/ssm-conformance/report.go is the model.
func (r *Report) Markdown() string {
	sum := r.Summary()
	var b strings.Builder
	fmt.Fprintf(&b, "# Differential run — %s\n\n", sum.Verdict)
	fmt.Fprintf(&b, "- started: %s\n", r.Started.Format(time.RFC3339))
	if r.Elapsed != "" {
		fmt.Fprintf(&b, "- elapsed: %s\n", r.Elapsed)
	}
	fmt.Fprintf(&b, "- seed: %d\n", r.Seed)
	fmt.Fprintf(&b, "- cases: %d, comparisons evaluated: %d\n", sum.Cases, sum.Compared)
	for _, v := range []Verdict{Fail, Warn, Pass, Skip} {
		if n := sum.ByVerdict[string(v)]; n > 0 {
			fmt.Fprintf(&b, "- %s: %d\n", v, n)
		}
	}
	if sum.Floor != "" {
		fmt.Fprintf(&b, "\n**FLOOR** — %s\n", sum.Floor)
	}

	if len(sum.Findings) > 0 {
		fmt.Fprintf(&b, "\n## Findings\n")
		for _, f := range sum.Findings {
			fmt.Fprintf(&b, "\n### %s [%s] %s\n\n", f.ID, f.Severity, f.Title)
			fmt.Fprintf(&b, "- input: `%s`\n", f.Input)
			fmt.Fprintf(&b, "- product (%s): %s\n", f.Product.Side, f.Product)
			fmt.Fprintf(&b, "- referee (%s): %s\n", f.Referee.Side, f.Referee)
			fmt.Fprintf(&b, "- impact: %s\n", f.Impact)
			if f.Invariant != "" {
				fmt.Fprintf(&b, "- adjudicated by invariant %s\n", f.Invariant)
			}
			if f.Limitation != "" {
				fmt.Fprintf(&b, "- does NOT establish: %s\n", f.Limitation)
			}
		}
	}

	fmt.Fprintf(&b, "\n## Cases\n\n")
	for _, c := range r.Cases {
		fmt.Fprintf(&b, "### %s %s — %s\n\n", c.ID, c.Verdict, c.Title)
		if c.Input != "" {
			fmt.Fprintf(&b, "- input: `%s`\n", c.Input)
		}
		fmt.Fprintf(&b, "- %s vs %s\n", c.Product.Lineage, c.Referee.Lineage)
		if c.Reason != "" {
			fmt.Fprintf(&b, "- %s\n", c.Reason)
		}
		if c.Limitation != "" {
			fmt.Fprintf(&b, "- limitation: %s\n", c.Limitation)
		}
		for _, cmp := range c.Comparisons {
			fmt.Fprintf(&b, "  - `%s` %s — product %s | referee %s", cmp.Key, cmp.Verdict, cmp.Product, cmp.Referee)
			if cmp.Reason != "" {
				fmt.Fprintf(&b, " — %s", cmp.Reason)
			}
			b.WriteString("\n")
		}
		b.WriteString("\n")
	}

	fmt.Fprintf(&b, "## What this run cannot catch\n\n")
	for _, l := range r.Limitations {
		fmt.Fprintf(&b, "- %s\n", l)
	}
	return b.String()
}

// BundleCases converts the report into evidence-bundle test cases, so a
// differential run drops into the same artifact the conformance runner emits.
func (r *Report) BundleCases() []bundle.TestCaseResult {
	out := make([]bundle.TestCaseResult, 0, len(r.Cases))
	for _, c := range r.Cases {
		tc := bundle.TestCaseResult{
			ID:      c.ID,
			Doc:     "ADVERSARIAL_QA_STRATEGY.md §5 (differential testing)",
			Title:   c.Title,
			Verdict: c.Verdict.Bundle(),
			Notes:   c.Reason,
		}
		for _, cmp := range c.Comparisons {
			tc.Assertions = append(tc.Assertions, bundle.Assertion{
				Claim: fmt.Sprintf("%s agrees between %s and %s", cmp.Key, c.Product.Name, c.Referee.Name),
				Method: fmt.Sprintf("differential: %s vs %s, tolerance rel=%g abs=%g",
					c.Product.Lineage, c.Referee.Lineage, cmp.Tolerance.Rel, cmp.Tolerance.Abs),
				Verdict:  cmp.Verdict.Bundle(),
				Observed: fmt.Sprintf("product %s | referee %s%s", cmp.Product, cmp.Referee, reasonSuffix(cmp.Reason)),
			})
		}
		if len(tc.Assertions) == 0 {
			tc.Assertions = append(tc.Assertions, bundle.Assertion{
				Claim:    tc.Title,
				Method:   "differential",
				Verdict:  bundle.Skip,
				Observed: "no comparison was evaluated: " + c.Reason,
			})
		}
		out = append(out, tc)
	}
	return out
}

func reasonSuffix(reason string) string {
	if reason == "" {
		return ""
	}
	return " — " + reason
}
