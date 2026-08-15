package suitecsip

// ridethrough_catalog_test.go — the construction guarantee for BASIC-004/005:
// what the SHIPPING rows publish is what the certification procedure
// prescribes.
//
// WHY THIS FILE EXISTS. It is the IW15-004 pinning class, and the curve family
// learned it the expensive way: BASIC-006 published the shape of gridsim's own
// static fixture for months, because no test ever compared the row to the
// procedure. That changed no verdict while every curve row's southbound half
// was a decided FAIL on every bench, and it became a route to a FALSE PASS the
// moment a DER could execute the curve. The ride-through rows arrive with a
// southbound oracle that CAN go green on the first day, so they arrive with
// this test rather than acquiring it later.
//
// THE VALUES ARE READ FROM THE CATALOG, NOT RESTATED HERE, on the same rule
// curve_catalog_test.go states: a test carrying its own copy of Figure 4 would
// be two literals one edit apart from the row — the same shape as the defect it
// is meant to catch. The catalog's own precondition lines are parsed instead,
// so the only way for this test and the row to agree wrongly is for the catalog
// itself to say so, and the catalog is digest-pinned evidence.

import (
	"sort"
	"strconv"
	"strings"
	"testing"

	"csip-tls-test/internal/certify"
	"csip-tls-test/internal/invariant"
)

// tripRowByID returns the SHIPPING binding for one ride-through row, so every
// assertion below is about what a campaign runs.
func tripRowByID(t *testing.T, id string) *tripBinding {
	t.Helper()
	for _, r := range rideThroughRows() {
		if r.id == id {
			return r.row.binding
		}
	}
	t.Fatalf("no ride-through row is registered for %s", id)
	return nil
}

// tripCurveByElement returns one authored curve of a row.
func tripCurveByElement(t *testing.T, b *tripBinding, element string) tripCurve {
	t.Helper()
	for _, c := range b.Curves {
		if c.Element == element {
			return c
		}
	}
	t.Fatalf("this row authors no <%s>; it authors %s", element, strings.Join(b.elements(), ", "))
	return tripCurve{}
}

// tripFigureValues is testValues for the ride-through Figures, whose column
// punctuation the curve Figures' parser cannot read.
//
// Figure 4's lines are printed "Default = (16, 13000), ...; Test Values = (16,
// 12000), ...." — with an EQUALS SIGN after the column label and a full stop at
// the end — while Figure 6's are printed "Default 10; Test Values 5". The
// shared testValues helper strips a colon and stops, so on a Figure-4 line it
// hands back "= -2." and curve_catalog_test.go's catalogInt then fails to parse
// it as an integer. This strips the leading "=" and the trailing "." as well.
//
// It is a SEPARATE function rather than a widening of the shared one because
// the shared one is what pins BASIC-006/011/012, and loosening a parser that
// three shipping rows depend on — so that it would also accept a shape they
// never produce — is how a parser stops catching the malformed line it was
// written for.
func tripFigureValues(t *testing.T, line string) string {
	t.Helper()
	v := strings.TrimSpace(testValues(t, line))
	v = strings.TrimSpace(strings.TrimPrefix(v, "="))
	return strings.TrimSpace(strings.TrimSuffix(v, "."))
}

// tripFigurePoints parses the breakpoints out of one Figure line's Test Values.
func tripFigurePoints(t *testing.T, c *certify.Case, element string) []CurvePoint {
	t.Helper()
	vals := tripFigureValues(t, figureLine(t, c, element))
	m := figurePoint.FindAllStringSubmatch(vals, -1)
	if len(m) == 0 {
		t.Fatalf("%s: no (x,y) pairs in %s's test values: %q", c.ID, element, vals)
	}
	out := make([]CurvePoint, 0, len(m))
	for _, g := range m {
		x, err1 := strconv.ParseFloat(g[1], 64)
		y, err2 := strconv.ParseFloat(g[2], 64)
		if err1 != nil || err2 != nil {
			t.Fatalf("%s: unparseable breakpoint %q", c.ID, g[0])
		}
		out = append(out, CurvePoint{X: x, Y: y})
	}
	return out
}

// tripFigureInt parses a scalar Figure row's single-integer test value.
func tripFigureInt(t *testing.T, c *certify.Case, element string) int {
	t.Helper()
	vals := tripFigureValues(t, figureLine(t, c, element))
	n, err := strconv.Atoi(vals)
	if err != nil {
		t.Fatalf("%s: %s test value %q is not an integer", c.ID, element, vals)
	}
	return n
}

// tripFigureIntSet parses a Figure row whose test value is a SET of integers —
// Figure 4's "DERCurve.curveType: Default = 4, 5, 9, 10; Test Values = 4,5,9,10"
// and Figure 5's "{2, 7}" — returned sorted so a comparison is order-free.
//
// The Figures print the SET rather than a code per curve, which is the only
// honest reading of them: a curveType belongs to one DERCurve and one Figure
// covers several, so the column enumerates the codes the control's curves must
// carry between them. Comparing sets is therefore the assertion the document
// supports; comparing them pairwise would be inventing a correspondence the
// Figure does not state.
func tripFigureIntSet(t *testing.T, c *certify.Case, element string) []int {
	t.Helper()
	vals := tripFigureValues(t, figureLine(t, c, element))
	var out []int
	for _, f := range strings.Split(vals, ",") {
		f = strings.TrimSpace(f)
		if f == "" {
			continue
		}
		n, err := strconv.Atoi(f)
		if err != nil {
			t.Fatalf("%s: %s test values %q contain a non-integer %q", c.ID, element, vals, f)
		}
		out = append(out, n)
	}
	if len(out) == 0 {
		t.Fatalf("%s: %s test values %q parsed to no integers", c.ID, element, vals)
	}
	sort.Ints(out)
	return out
}

// TestRideThroughRows_PublishTheCatalogPrescribedValues is the construction
// test, per row and per authored curve.
//
// It asserts, against the catalog read at run time, that every curve the
// SHIPPING binding publishes carries the Figure's own Test Values, that the
// axis multipliers are the Figure's, and that the set of DERCurveType codes the
// row's elements resolve to is the set the Figure prints.
func TestRideThroughRows_PublishTheCatalogPrescribedValues(t *testing.T) {
	for _, tc := range []struct {
		id string
		// figureElement maps the row's 2030.5 element name to the name the
		// catalog's Figure prints for its CurveData row. They are NOT always
		// equal, and the divergences are the document's:
		//
		//   - Figure 4's settings table spells the two momentary-cessation rows
		//     "opModLVRTMustTripMomentaryCessation" /
		//     "opModHVRTMustTripMomentaryCessation" while its own Function table,
		//     IEEE Std 2030.5-2018 p.249-250 and the DERControlBase schema all
		//     use the shorter names. The catalog's `notes` field records the
		//     inconsistency. The bench follows the standard; this table is where
		//     that decision is written down so it cannot be quietly reversed.
		//   - Figure 4's opModLVRTMustTrip row omits the ".DERCurve" segment the
		//     other three carry, which the catalog's notes also record.
		figureElement map[string]string
		// yRefTypeInFigure is false for a Figure that prescribes no y reference.
		// Figure 5 prescribes none, and that is correct rather than an omission:
		// a frequency curve's y axis is absolute hertz.
		yRefTypeInFigure bool
	}{
		{
			id: "BASIC-004",
			figureElement: map[string]string{
				"opModLVRTMustTrip":           "opModLVRTMustTrip.CurveData",
				"opModLVRTMomentaryCessation": "opModLVRTMustTripMomentaryCessation.DERCurve.CurveData",
				"opModHVRTMustTrip":           "opModHVRTMustTrip.DERCurve.CurveData",
				"opModHVRTMomentaryCessation": "opModHVRTMustTripMomentaryCessation.DERCurve.CurveData",
			},
			yRefTypeInFigure: true,
		},
		{
			id: "BASIC-005",
			figureElement: map[string]string{
				"opModLFRTMustTrip": "opModLFRTMustTrip.DERCurve.CurveData",
				"opModHFRTMustTrip": "opModHFRTMustTrip.DERCurve.CurveData",
			},
			yRefTypeInFigure: false,
		},
	} {
		t.Run(tc.id, func(t *testing.T) {
			c := catalogCase(t, "csip-conf-v1.3::"+tc.id)
			b := tripRowByID(t, tc.id)

			if len(b.Curves) != len(tc.figureElement) {
				t.Fatalf("%s publishes %d curve(s) (%s) and its Figure prescribes %d — a row that sends "+
					"fewer curves than its Figure has not offered the DUT the combination the procedure "+
					"is about, and one that sends more is publishing a document nobody asked for",
					tc.id, len(b.Curves), strings.Join(b.elements(), ", "), len(tc.figureElement))
			}

			for _, cv := range b.Curves {
				figure, ok := tc.figureElement[cv.Element]
				if !ok {
					t.Errorf("%s publishes <%s>, which this test maps to no Figure row — an element the "+
						"row sends and nothing pins is an element that can drift", tc.id, cv.Element)
					continue
				}
				want := tripFigurePoints(t, c, figure)
				if len(cv.Points) != len(want) || renderPts(cv.Points) != renderPts(want) {
					t.Errorf("%s's <%s> publishes %s, want the catalog's Test Values %s — a row whose "+
						"procedure states its curve may not publish another one, and this row's oracle can "+
						"go GREEN on whatever it sends",
						tc.id, cv.Element, renderPts(cv.Points), renderPts(want))
				}
				if got, wantX := int(cv.XMult), tripFigureInt(t, c, "DERCurve.xMultiplier"); got != wantX {
					t.Errorf("%s's <%s> publishes xMultiplier %d, want the catalog's %d",
						tc.id, cv.Element, got, wantX)
				}
				if got, wantY := int(cv.YMult), tripFigureInt(t, c, "DERCurve.yMultiplier"); got != wantY {
					t.Errorf("%s's <%s> publishes yMultiplier %d, want the catalog's %d",
						tc.id, cv.Element, got, wantY)
				}
				if tc.yRefTypeInFigure {
					if got, wantR := int(cv.YRefType), tripFigureInt(t, c, "DERCurve.yRefType"); got != wantR {
						t.Errorf("%s's <%s> publishes yRefType %d, want the catalog's %d",
							tc.id, cv.Element, got, wantR)
					}
				} else if cv.YRefType != derUnitRefNA {
					t.Errorf("%s's <%s> publishes yRefType %d where its Figure prescribes NONE. A "+
						"frequency ride-through curve's y axis is ABSOLUTE hertz (model_709.json gives "+
						"Pt.Hz the units \"Hz\"), so there is no percentage reference to name and sending "+
						"one invents a base the standard does not give this axis",
						tc.id, cv.Element, cv.YRefType)
				}
			}

			// THE curveType SET, three ways: the CATALOG's printed Figure column,
			// lexa-proto/csipmodel's constants (which is what gridsim actually
			// emits), and this suite's own hand transcription of IEEE Std
			// 2030.5-2018 p.254 in curve_catalog_test.go. No two of the three are
			// derived from each other.
			var fromProduct, fromStandard []int
			for _, cv := range b.Curves {
				fromProduct = append(fromProduct, int(curveTypeConstantFor(t, cv.Element)))
				code, ok := standard2018CurveTypes[cv.Element]
				if !ok {
					t.Fatalf("IEEE 2030.5-2018 p.254 assigns no curveType to <%s>", cv.Element)
				}
				fromStandard = append(fromStandard, code)
			}
			sort.Ints(fromProduct)
			sort.Ints(fromStandard)
			fromCatalog := tripFigureIntSet(t, c, "DERCurve.curveType")

			if !sameInts(fromProduct, fromCatalog) {
				t.Errorf("%s's elements resolve to curveType set %v through lexa-proto/csipmodel — which "+
					"is what gridsim puts on the wire — and its Figure prescribes %v. These are two "+
					"independent documents and a real disagreement is a finding to be adjudicated, not "+
					"absorbed", tc.id, fromProduct, fromCatalog)
			}
			if !sameInts(fromStandard, fromCatalog) {
				t.Errorf("%s's Figure prescribes curveType set %v and IEEE 2030.5-2018 p.254 assigns %v "+
					"to the elements this row publishes", tc.id, fromCatalog, fromStandard)
			}

			if b.Prescribed == "" {
				t.Errorf("%s records no provenance for its published values, so a bundle cannot show "+
					"where they came from", tc.id)
			}
		})
	}
}

func sameInts(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// TestRideThroughRows_DeclareNoAuthoringGaps pins the other half of the
// reconciliation: everything both Figures prescribe, this bench sends.
//
// A gap here would be a claim about what this bench cannot serve, quoted into
// every bundle these rows appear in — the class of sentence IW15-027 found
// three of, all false about IEEE Std 2030.5-2018. Regaining one must be a
// decision with its own citation, not a drift.
func TestRideThroughRows_DeclareNoAuthoringGaps(t *testing.T) {
	for _, id := range []string{"BASIC-004", "BASIC-005"} {
		t.Run(id, func(t *testing.T) {
			b := tripRowByID(t, id)
			if n := len(b.Gaps); n != 0 {
				var all []string
				for _, g := range b.Gaps {
					all = append(all, g.Element+" — "+g.Why)
				}
				t.Errorf("%s declares %d authoring gap(s). Figure 4's settings are four CurveData rows, "+
					"curveType, the two multipliers and yRefType; Figure 5's are two CurveData rows, "+
					"curveType and the two multipliers — and this bench places every one of them on the "+
					"wire. Check a new gap against IEEE Std 2030.5-2018 and not against the vendored "+
					"draft schema before adding it:\n  %s", id, n, strings.Join(all, "\n  "))
			}
			// And the criterion the gaps drive says so positively.
			f := critTripPublishedTheProcedureValues("the subject", b).Construction()
			if f.Verdict != certify.Pass {
				t.Errorf("%s's prescribed-values criterion = %s, want PASS:\n%s", id, f.Verdict, f.Observed)
			}
			// The yRefType disclosure rides on it either way, or a reader takes
			// the PASS for a statement about an element nothing measured.
			if !strings.Contains(f.Observed, "DeptRef") {
				t.Errorf("%s's prescribed-values criterion does not disclose that the y-axis reference it "+
					"served has no register home on either generation:\n%s", id, f.Observed)
			}
		})
	}
}

// TestRideThroughRows_NameASubCurveOnEvery7xxArm is the construction guarantee
// that the referee is never asked to choose.
//
// A 7xx trip bank holds three sub-curves. An arm that named model 707 and no
// sub-curve would leave the oracle to pick one, and the pick that suggests
// itself — MustTrip — is the worst available: a momentary-cessation curve
// graded against the must-trip sub-curve reports a mismatch about a bank
// holding exactly what was commanded. resolve() refuses such an arm at run
// time; this refuses it at construction, where it can be fixed.
func TestRideThroughRows_NameASubCurveOnEvery7xxArm(t *testing.T) {
	for _, id := range []string{"BASIC-004", "BASIC-005"} {
		b := tripRowByID(t, id)
		for _, c := range b.Curves {
			if c.Model7xx == 0 {
				t.Errorf("%s's <%s> declares no 7xx model at all", id, c.Element)
				continue
			}
			if c.Sub7xx == invariant.SubCurveNone {
				t.Errorf("%s's <%s> names 7xx model %d and NO sub-curve, so the referee would have to "+
					"choose between MustTrip, MayTrip and MomCess", id, c.Element, c.Model7xx)
			}
			if c.Mapping7xx == "" {
				t.Errorf("%s's <%s> records no provenance for its 7xx register home, so a FAIL naming "+
					"that bank could not be checked by whoever reads the bundle", id, c.Element)
			}
		}
	}
}

// TestRideThroughRows_NameEveryLegacyAbsence is the same guarantee on the other
// generation, in the negative.
//
// The legacy 12x set has ONE ride-through model per voltage direction and none
// at all for frequency, so four of this row family's six curves have no legacy
// home. Every one of those absences must be NAMED — the rule BASIC-012's
// missing 7xx freq-watt table follows — because a row that silently dropped its
// southbound half on a whole generation would report the bench's coverage as
// the device's behaviour.
func TestRideThroughRows_NameEveryLegacyAbsence(t *testing.T) {
	for _, tc := range []struct {
		id       string
		element  string
		hasHome  bool
		wantWord string
	}{
		{"BASIC-004", "opModLVRTMustTrip", true, ""},
		{"BASIC-004", "opModHVRTMustTrip", true, ""},
		{"BASIC-004", "opModLVRTMomentaryCessation", false, "SINGLE region per bank"},
		{"BASIC-004", "opModHVRTMomentaryCessation", false, "SINGLE region per bank"},
		{"BASIC-005", "opModLFRTMustTrip", false, "NO legacy 12x model for frequency ride-through"},
		{"BASIC-005", "opModHFRTMustTrip", false, "NO legacy 12x model for frequency ride-through"},
	} {
		t.Run(tc.id+" "+tc.element, func(t *testing.T) {
			c := tripCurveByElement(t, tripRowByID(t, tc.id), tc.element)
			target := c.resolve(invariant.FamilyLegacy)
			if tc.hasHome {
				if target.NoRegisterHome != "" {
					t.Errorf("<%s> reports no legacy register home (%q), but models 129/130 carry exactly "+
						"this curve", tc.element, target.NoRegisterHome)
				}
				if target.Model == 0 {
					t.Errorf("<%s> resolves to legacy model 0", tc.element)
				}
				return
			}
			if target.NoRegisterHome == "" {
				t.Fatalf("<%s> claims a legacy register home (M%d). The legacy set has one "+
					"single-region bank per voltage direction and no frequency ride-through model at "+
					"all, so a claimed home here would grade a bank that does not exist",
					tc.element, target.Model)
			}
			if !strings.Contains(target.NoRegisterHome, tc.wantWord) {
				t.Errorf("<%s>'s legacy absence does not say why (%q does not mention %q)",
					tc.element, target.NoRegisterHome, tc.wantWord)
			}
		})
	}
}
