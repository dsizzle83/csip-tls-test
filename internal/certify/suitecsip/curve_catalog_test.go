package suitecsip

// curve_catalog_test.go — the construction guarantee the curve rows did not
// have: what a row PUBLISHES is what the certification procedure PRESCRIBES.
//
// WHY THIS FILE EXISTS. BASIC-013 has carried a construction test since IW15-004
// (inverter_control_lifecycle_test.go's TestOracledRow_PrescribedRowCarriesNoLadder)
// because a row that departs from its procedure's stated values produces a
// report claiming conformance for a command nobody asked for. No CURVE row had
// one, and all three prescribed-curve rows had drifted: BASIC-006 published the
// shape of gridsim's own static fixture, BASIC-011 published two points where
// Figure 11 prescribes three, BASIC-012 published two where Figure 12
// prescribes four. The drift changed no verdict while every curve row's
// southbound half was a decided FAIL on every bench; it became a route to a
// FALSE PASS the moment a legacy DER could execute the curve.
//
// THE VALUES ARE READ FROM THE CATALOG, NOT RESTATED HERE. A test that carried
// its own copy of Figure 6 would be two literals one edit apart from the row —
// the same shape as the defect it is meant to catch. The catalog's own
// precondition lines are parsed instead, so the only way for this test and the
// row to agree wrongly is for the catalog itself to say so, and the catalog is
// digest-pinned evidence.

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"csip-tls-test/internal/certify"
)

// figurePoint matches one "(x, y)" pair as the catalog prints it, with or
// without the space the Figures are inconsistent about.
var figurePoint = regexp.MustCompile(`\(\s*(-?\d+)\s*,\s*(-?\d+)\s*\)`)

// catalogCase loads a case out of the SHIPPING catalog.
func catalogCase(t *testing.T, uid string) *certify.Case {
	t.Helper()
	cat, err := certify.LoadDefault()
	if err != nil {
		t.Fatalf("load the shipping catalog: %v", err)
	}
	c, ok := cat.ByUID(uid)
	if !ok {
		t.Fatalf("the catalog carries no case %s", uid)
	}
	return c
}

// figureLine returns the single PER-ELEMENT precondition line naming want, and
// fails when there is not exactly one. Ambiguity here would let the test read a
// different Figure row than the one it is asserting about.
//
// The catalog carries some Figures twice — once row by row
// ("Figure 12 ... - opModFreqDroop.dBOF: Default 36; Test Values 60030") and
// once as a merged table line from the shard the extraction came from
// ("... (Setting | Default | Test Values): opModFreqDroop.dBOF | 36 | 60030; ...").
// They agree, and this reads the row-by-row form: it is the one whose element
// name is followed by a colon and whose columns are labelled "; Test Values",
// so the two shapes are distinguishable without matching on the Figure number.
func figureLine(t *testing.T, c *certify.Case, want string) string {
	t.Helper()
	var hits []string
	for _, p := range c.Preconditions {
		if strings.Contains(p, want+":") && strings.Contains(p, "; Test Values") {
			hits = append(hits, p)
		}
	}
	if len(hits) != 1 {
		t.Fatalf("%s: %d precondition line(s) mention %q, want exactly 1 — this test cannot tell which "+
			"Figure row it is reading:\n%s", c.ID, len(hits), want, strings.Join(hits, "\n"))
	}
	return hits[0]
}

// testValues returns the part of a Figure line after its "Test Values" label,
// which is the column a procedure's run actually uses.
func testValues(t *testing.T, line string) string {
	t.Helper()
	i := strings.Index(line, "Test Values")
	if i < 0 {
		t.Fatalf("the Figure line carries no Test Values column: %s", line)
	}
	return strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line[i+len("Test Values"):]), ":"))
}

// catalogCurveData parses the prescribed breakpoints out of a case's CurveData
// Figure line.
func catalogCurveData(t *testing.T, c *certify.Case) []CurvePoint {
	t.Helper()
	vals := testValues(t, figureLine(t, c, "DERCurve.CurveData"))
	m := figurePoint.FindAllStringSubmatch(vals, -1)
	if len(m) == 0 {
		t.Fatalf("%s: no (x,y) pairs in the CurveData test values: %q", c.ID, vals)
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

// catalogInt parses a scalar Figure row's test value ("DERCurve.xMultiplier").
func catalogInt(t *testing.T, c *certify.Case, element string) int {
	t.Helper()
	vals := testValues(t, figureLine(t, c, element))
	n, err := strconv.Atoi(strings.TrimSpace(strings.TrimSuffix(vals, ".")))
	if err != nil {
		t.Fatalf("%s: %s test value %q is not an integer", c.ID, element, vals)
	}
	return n
}

func renderPts(pts []CurvePoint) string {
	parts := make([]string, 0, len(pts))
	for _, p := range pts {
		parts = append(parts, fmt.Sprintf("(%g,%g)", p.X, p.Y))
	}
	return strings.Join(parts, " ")
}

// TestCurveRows_PublishTheCatalogPrescribedValues is the construction test the
// curve family did not have.
//
// It asserts, per row, that the breakpoints and axis multipliers the SHIPPING
// binding publishes are the ones the catalog's own Figure prescribes — read
// from the catalog at run time, never restated here.
func TestCurveRows_PublishTheCatalogPrescribedValues(t *testing.T) {
	for _, tc := range []struct {
		id string
		// yRefTypeInFigure is false for a Figure that prescribes no y
		// reference (BASIC-006's Figure 6 lists none), where the row's choice
		// is its own and is asserted separately below.
		yRefTypeInFigure bool
	}{
		{"BASIC-006", false},
		{"BASIC-011", true},
		{"BASIC-012", true},
	} {
		t.Run(tc.id, func(t *testing.T) {
			c := catalogCase(t, "csip-conf-v1.3::"+tc.id)
			b := rowByID(t, tc.id).mode.Curve
			if b == nil {
				t.Fatalf("%s carries no curve binding", tc.id)
			}

			want := catalogCurveData(t, c)
			if len(b.Points) != len(want) || renderPts(b.Points) != renderPts(want) {
				t.Errorf("%s publishes %s, want the catalog's Test Values %s — a row whose procedure "+
					"states its curve may not publish another one, and with a legacy execution arm this "+
					"row can now go GREEN on whatever it sends",
					tc.id, renderPts(b.Points), renderPts(want))
			}
			if got, wantX := int(b.XMult), catalogInt(t, c, "DERCurve.xMultiplier"); got != wantX {
				t.Errorf("%s publishes xMultiplier %d, want the catalog's %d", tc.id, got, wantX)
			}
			if got, wantY := int(b.YMult), catalogInt(t, c, "DERCurve.yMultiplier"); got != wantY {
				t.Errorf("%s publishes yMultiplier %d, want the catalog's %d", tc.id, got, wantY)
			}
			if tc.yRefTypeInFigure {
				if got, wantR := int(b.YRefType), catalogInt(t, c, "DERCurve.yRefType"); got != wantR {
					t.Errorf("%s publishes yRefType %d, want the catalog's %d", tc.id, got, wantR)
				}
			}
			if b.Prescribed == "" {
				t.Errorf("%s records no provenance for its published values, so a bundle cannot show "+
					"where they came from", tc.id)
			}
		})
	}
}

// TestBASIC006_YRefTypeIsThisSuitesOwnChoiceAndSaysSo pins the one prescribed
// row whose y reference the catalog does NOT state.
//
// Figure 6 lists CurveData, openLoopTms, the autonomous-Vref pair, curveType
// and the two multipliers — and no yRefType. The row's 3 (%statVarAvail) is
// this suite's own choice from opModVoltVar's admissible set, and it is
// load-bearing: it decides the DeptRef the referee requires, differently on each
// generation. A future edit that "corrected" it to match some other row would
// change what the DER is asserted to hold.
func TestBASIC006_YRefTypeIsThisSuitesOwnChoiceAndSaysSo(t *testing.T) {
	c := catalogCase(t, "csip-conf-v1.3::BASIC-006")
	for _, p := range c.Preconditions {
		if strings.Contains(p, "Figure 6") && strings.Contains(p, "yRefType") {
			t.Fatalf("Figure 6 DOES prescribe a yRefType (%q) — this row must publish the catalog's "+
				"value and the construction test must assert it", p)
		}
	}
	b := rowByID(t, "BASIC-006").mode.Curve
	if b.YRefType != derUnitRefStatVarAvail {
		t.Errorf("BASIC-006 publishes yRefType %d; it is not catalog-prescribed, so a change here is a "+
			"change to what the DER is asserted to hold (DeptRef 2 on 705, DeptRef 3 on 126) and must be "+
			"made deliberately", b.YRefType)
	}
}

// TestBASIC015_DoesNotClaimCatalogProvenanceForItsCurve is the converse
// guarantee. BASIC-015's procedure prescribes twenty-four fixed-power-factor
// DERControls and NO curve settings figure, so the Watt-PF curve the row
// publishes is this suite's own. Saying so is what keeps the bundle honest; a
// row that recorded a Figure it does not follow would be worse than one that
// recorded nothing.
func TestBASIC015_DoesNotClaimCatalogProvenanceForItsCurve(t *testing.T) {
	c := catalogCase(t, "csip-conf-v1.3::BASIC-015")
	for _, p := range c.Preconditions {
		if strings.Contains(p, "DERCurve.CurveData") {
			t.Fatalf("BASIC-015 DOES prescribe curve data (%q) — the row must publish it and the "+
				"construction test above must cover it", p)
		}
	}
	row := rowByID(t, "BASIC-015").mode
	for _, b := range []*curveBinding{row.Refusal.Curve, row.LegacyCurve} {
		if b == nil {
			t.Fatal("BASIC-015 is missing one of its two per-generation bindings")
		}
		if !strings.Contains(b.Prescribed, "prescribes NO curve settings figure") {
			t.Errorf("BASIC-015's binding records provenance %q, which does not say the values are this "+
				"suite's own", b.Prescribed)
		}
	}
}

// TestCurveRows_NameEveryPrescribedElementTheyCannotAuthor pins the second half
// of the reconciliation: an element the procedure prescribes and this bench
// cannot send is NAMED, and one whose test value differs from the procedure's
// own default HOLDS the row.
//
// Silently omitting them would let a bundle claim a row was run to a procedure
// it was only partly run to — which is the same overclaim as publishing the
// wrong curve, one field along.
func TestCurveRows_NameEveryPrescribedElementTheyCannotAuthor(t *testing.T) {
	for _, tc := range []struct {
		id           string
		wantMaterial []string
	}{
		// Figure 6 prescribes openLoopTms 5 against its own default of 10, so
		// the DUT is never offered the condition the row exists to create.
		{"BASIC-006", []string{"opModVoltVar.DERCurve.openLoopTms"}},
		// Figure 11 prescribes nothing this bench cannot author.
		{"BASIC-011", nil},
		// Figure 12 prescribes an immediate opModFreqDroop control alongside
		// the curve, and gridsim has no lever for it at all.
		{"BASIC-012", []string{
			"opModFreqDroop.dBOF", "opModFreqDroop.dBUF", "opModFreqDroop.kOF",
			"opModFreqDroop.kUF", "opModFreqDroop.openLoopTms",
		}},
	} {
		t.Run(tc.id, func(t *testing.T) {
			b := rowByID(t, tc.id).mode.Curve
			var got []string
			for _, g := range b.materialGaps() {
				got = append(got, g.Element)
			}
			if strings.Join(got, ",") != strings.Join(tc.wantMaterial, ",") {
				t.Errorf("%s's material authoring gaps = %v, want %v", tc.id, got, tc.wantMaterial)
			}
			for _, g := range b.Gaps {
				if g.Why == "" {
					t.Errorf("%s's gap %s names no missing lever, so it has no owner", tc.id, g.Element)
				}
				if g.Material && g.Prescribed == g.Default {
					t.Errorf("%s's gap %s is marked material with test value == default (%s); an element "+
						"whose omission changes nothing must not hold the row",
						tc.id, g.Element, g.Prescribed)
				}
				if !g.Material && g.Prescribed != g.Default && !strings.Contains(g.Why, "CurveSetV") {
					t.Errorf("%s's gap %s has test %s against default %s and is NOT marked material — an "+
						"element the procedure changes and this bench cannot send means the row was not "+
						"run to its procedure", tc.id, g.Element, g.Prescribed, g.Default)
				}
			}
			// And the criterion the gaps drive says the same thing.
			f := critCurvePublishedTheProcedureValues("the subject", b).Wire(nil, nil)
			wantVerdict := certify.Pass
			if len(tc.wantMaterial) > 0 {
				wantVerdict = certify.Fail
			}
			if f.Verdict != wantVerdict {
				t.Errorf("%s's prescribed-values criterion = %s, want %s:\n%s",
					tc.id, f.Verdict, wantVerdict, f.Observed)
			}
			for _, el := range tc.wantMaterial {
				if !strings.Contains(f.Observed, el) {
					t.Errorf("%s's criterion does not name the gap %s:\n%s", tc.id, el, f.Observed)
				}
			}
		})
	}
}

// TestCurveRows_MaterialGapsMatchTheCatalogsOwnColumns cross-checks each
// declared gap against the catalog, so a gap cannot claim a prescribed value the
// Figure does not print.
func TestCurveRows_MaterialGapsMatchTheCatalogsOwnColumns(t *testing.T) {
	for _, id := range []string{"BASIC-006", "BASIC-012"} {
		t.Run(id, func(t *testing.T) {
			c := catalogCase(t, "csip-conf-v1.3::"+id)
			for _, g := range rowByID(t, id).mode.Curve.Gaps {
				if strings.Contains(g.Why, "CurveSetV") {
					continue // the curveType divergence is deliberate, not a gap in the Figure
				}
				line := figureLine(t, c, lastSegment(g.Element))
				if !strings.Contains(testValues(t, line), g.Prescribed) {
					t.Errorf("%s's gap %s claims test value %q, which the catalog's own line does not "+
						"carry:\n%s", id, g.Element, g.Prescribed, line)
				}
			}
		})
	}
}

// lastSegment is the element name as the catalog prints it in its Figure rows
// ("opModFreqDroop.dBOF" -> "dBOF" is too weak; the full dotted name is what the
// Figure prints, so this only strips a leading namespace when the catalog uses
// the bare form).
func lastSegment(element string) string { return element }
