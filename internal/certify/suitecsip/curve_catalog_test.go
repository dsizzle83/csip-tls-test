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
	"csip-tls-test/internal/invariant"
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
	// The non-breakpoint Figure rows, per row. openLoopTms and the five
	// opModFreqDroop children joined this table when curve plan #32 built their
	// levers; before that they were the rows' MATERIAL GAPS, and the rows held
	// themselves at FAIL rather than claiming to have sent them.
	openLoopTms := figureScalar{"opModVoltVar.DERCurve.openLoopTms",
		func(b *curveBinding) (int, bool) {
			if b.OpenLoopTms == nil {
				return 0, false
			}
			return int(*b.OpenLoopTms), true
		}}
	droop := func(name string, read func(FreqDroopSettings) int) figureScalar {
		return figureScalar{"opModFreqDroop." + name, func(b *curveBinding) (int, bool) {
			if b.Droop == nil {
				return 0, false
			}
			return read(b.Droop.Settings), true
		}}
	}
	for _, tc := range []struct {
		id string
		// yRefTypeInFigure is false for a Figure that prescribes no y
		// reference (BASIC-006's Figure 6 lists none), where the row's choice
		// is its own and is asserted separately below.
		yRefTypeInFigure bool
		// authored are the Figure's non-breakpoint scalar rows this bench can
		// now place on the wire, checked against the catalog's own columns.
		authored []figureScalar
	}{
		{"BASIC-006", false, []figureScalar{openLoopTms}},
		{"BASIC-011", true, nil},
		{"BASIC-012", true, []figureScalar{
			droop("dBOF", func(s FreqDroopSettings) int { return int(s.DBOF) }),
			droop("dBUF", func(s FreqDroopSettings) int { return int(s.DBUF) }),
			droop("kOF", func(s FreqDroopSettings) int { return int(s.KOF) }),
			droop("kUF", func(s FreqDroopSettings) int { return int(s.KUF) }),
			droop("openLoopTms", func(s FreqDroopSettings) int { return int(s.OpenLoopTms) }),
		}},
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
			// The rest of the row's Figure — the scalars and the inline element
			// beside the breakpoints. Both were unsendable until curve plan #32
			// built their levers, and both rows held themselves at FAIL saying
			// so; with the levers built, an omission would no longer announce
			// itself and only this assertion would catch it.
			for _, el := range tc.authored {
				got, ok := el.read(b)
				if !ok {
					t.Errorf("%s authors no %s; the catalog prescribes it and the lever to send it exists, "+
						"so leaving it off means the DUT is never offered the condition the row is about",
						tc.id, el.element)
					continue
				}
				if want := catalogInt(t, c, el.element); got != want {
					t.Errorf("%s authors %s=%d, want the catalog's Test Value %d", tc.id, el.element, got, want)
				}
			}
		})
	}
}

// figureScalar is one non-breakpoint Figure row: the element name as the
// catalog prints it, and how to read what the binding authored for it.
type figureScalar struct {
	element string
	read    func(*curveBinding) (int, bool)
}

// TestCurveRows_RecordWhereEachAuthoredElementCanBeReadBack is the second half
// of the #32 construction guarantee, and it is about a distinction the suite
// did not previously have to make.
//
// An element the bench CAN now send is not thereby an element the DER can be
// read for. openLoopTms has no register in any SunSpec curve bank on either
// generation; opModFreqDroop has an exact home on 7xx (model 711) and none at
// all on legacy. "Authored northbound" and "measurable southbound" are separate
// facts about the same element, and a row that recorded only the first would
// let a southbound PASS be read as covering content nothing ever looked at.
func TestCurveRows_RecordWhereEachAuthoredElementCanBeReadBack(t *testing.T) {
	for _, tc := range []struct {
		id      string
		element string
		// home7xx/homeLegacy: whether the element has a register home there.
		home7xx, homeLegacy bool
	}{
		{"BASIC-006", "DERCurve.openLoopTms", false, false},
		{"BASIC-012", "opModFreqDroop", true, false},
	} {
		t.Run(tc.id+" "+tc.element, func(t *testing.T) {
			b := rowByID(t, tc.id).mode.Curve
			var found bool
			for _, a := range b.authored() {
				if a.Element != tc.element {
					continue
				}
				found = true
				if _, ok := a.homeOn(invariant.Family7xx); ok != tc.home7xx {
					t.Errorf("%s's %s reports a 7xx register home = %t (%q), want %t",
						tc.id, tc.element, ok, a.Home7xx, tc.home7xx)
				}
				if _, ok := a.homeOn(invariant.FamilyLegacy); ok != tc.homeLegacy {
					t.Errorf("%s's %s reports a legacy register home = %t (%q), want %t",
						tc.id, tc.element, ok, a.HomeLegacy, tc.homeLegacy)
				}
				if (!tc.home7xx || !tc.homeLegacy) && a.Why == "" {
					t.Errorf("%s's %s has no register home on one generation and records no reason, so "+
						"the absence has no owner", tc.id, tc.element)
				}
				if a.Value == "" {
					t.Errorf("%s's %s records no authored VALUE, so a bundle cannot show what was served",
						tc.id, tc.element)
				}
			}
			if !found {
				t.Fatalf("%s's authored-element record does not name %s at all, so nothing in the bundle "+
					"says it was served and not measured", tc.id, tc.element)
			}
			// And the sentence a verdict carries must actually name it on the
			// generation where it cannot be read.
			for fam, want := range map[invariant.CurveFamily]bool{
				invariant.Family7xx: !tc.home7xx, invariant.FamilyLegacy: !tc.homeLegacy,
			} {
				note := describeUnmappable(b.unmappableOn(fam))
				if got := strings.Contains(note, tc.element); got != want {
					t.Errorf("%s: the %s verdict note %s %s; want it %s", tc.id, fam,
						map[bool]string{true: "names", false: "does not name"}[got], tc.element,
						map[bool]string{true: "named", false: "unnamed"}[want])
				}
			}
		})
	}
}

// TestBASIC012_PublishesTheFigureUnitsVerbatimAndDoesNotCorrectThem pins a
// transcription decision that is easy to "fix" wrongly.
//
// Figure 12 prints dBOF/dBUF as Default 36 / Test 60030, and the catalog's own
// note records that the two columns cannot both be dead bands in one unit: 36
// reads as hundredths of Hz while 60030/59970 read as absolute frequencies in
// millihertz, and the document does not reconcile them. sep 2.0.4 fixes the
// element's unit at thousandths of Hz, so what this row puts on the wire is
// 60.030 Hz and 59.970 Hz.
//
// A future reader who "corrected" the row to 30/30 — a ±0.030 Hz dead band,
// which is what the Test Values probably MEAN — would be certifying a control
// the procedure never printed. The transcription question belongs to whoever
// owns the document; this keeps the bench sending what it says, and keeps the
// referee's own translation of it honest.
func TestBASIC012_PublishesTheFigureUnitsVerbatimAndDoesNotCorrectThem(t *testing.T) {
	c := catalogCase(t, "csip-conf-v1.3::BASIC-012")
	b := rowByID(t, "BASIC-012").mode.Curve
	if b.Droop == nil {
		t.Fatal("BASIC-012 authors no opModFreqDroop")
	}
	for _, tc := range []struct {
		element string
		got     uint32
	}{
		{"opModFreqDroop.dBOF", b.Droop.Settings.DBOF},
		{"opModFreqDroop.dBUF", b.Droop.Settings.DBUF},
	} {
		line := figureLine(t, c, tc.element)
		if !strings.Contains(testValues(t, line), strconv.Itoa(int(tc.got))) {
			t.Errorf("BASIC-012 sends %s=%d, which is not the value the Figure prints:\n%s",
				tc.element, tc.got, line)
		}
	}
	// The referee's own translation, which is what a verdict compares against:
	// thousandths of Hz -> Hz and hundredths of a second -> s, per the schema's
	// own sentences.
	if got := b.Droop.want711().DbOfHz; got != 60.03 {
		t.Errorf("the referee translates dBOF=%d to %v Hz on model 711, want 60.03",
			b.Droop.Settings.DBOF, got)
	}
	if got := b.Droop.want711().RspTmsS; got != 6 {
		t.Errorf("the referee translates openLoopTms=%d to %v s, want 6",
			b.Droop.Settings.OpenLoopTms, got)
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
		// NONE of the three rows has a material gap left, and that is curve
		// plan #32's whole deliverable.
		//
		// BASIC-006 held on openLoopTms (Figure 6: test 5 against default 10)
		// and BASIC-012 on all five opModFreqDroop children, because gridsim
		// could author neither. Both levers now exist, both rows author the
		// Figure's own values, and both rows hold only if the SERVE fails.
		//
		// What remains on each is immaterial and stays named: the
		// autonomous-Vref pair (which sep 2.0.4 declares nowhere, so no
		// conformant server can send it, and whose columns agree anyway) and
		// the curveType divergence (the catalog's own numbering, which the
		// schema does not define for the element).
		{"BASIC-006", nil},
		{"BASIC-011", nil},
		{"BASIC-012", nil},
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
			f := critCurvePublishedTheProcedureValues("the subject", b).Construction()
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

// TestCurvePrescribedValuesCriterion_HoldsWithoutACapture is N4: a HOLD that
// disappears when the pcap does is not a hold.
//
// criterion.assert reaches Wire only when a session was recovered and Server
// only when the bench's admin API answered. The material-gap criterion is
// neither: it asserts what the ROW IS BUILT TO SEND, which no capture could
// confirm or refute. Carried on Wire it landed on a severity-0 SkipAssertion on
// a captureless run — no false PASS, because nothing turned green, but the hold
// silently vanished in exactly the runs (a lab with no key log, a re-scored
// bundle) where a reader most needs to be told the row was not run to its
// procedure.
//
// So the criterion is asserted through the WHOLE minting path, twice: with a
// recovered session and with none. The verdict must be identical.
func TestCurvePrescribedValuesCriterion_HoldsWithoutACapture(t *testing.T) {
	for _, tc := range []struct {
		id   string
		want certify.Verdict
	}{
		// All three PASS now. BASIC-006 and BASIC-012 used to hold here — on
		// openLoopTms and on the five opModFreqDroop children respectively —
		// and curve plan #32 built both levers, so the rows author their
		// Figures whole and this construction claim is satisfied. The
		// criterion's teeth are unchanged and still tested: reintroduce a
		// material gap and it FAILs again, with or without a capture.
		{"BASIC-006", certify.Pass},
		{"BASIC-011", certify.Pass},
		{"BASIC-012", certify.Pass},
	} {
		t.Run(tc.id, func(t *testing.T) {
			crit := critCurvePublishedTheProcedureValues("the subject", rowByID(t, tc.id).mode.Curve)

			// A captureless, benchless observation: no transcript, no server.
			// This is what a run with no key log leaves behind.
			bare := &Observation{Case: &certify.Case{UID: "csip-conf-v1.3::" + tc.id, ID: tc.id}}
			got := assertVerdictOf(t, crit, bare)
			if got != tc.want {
				t.Fatalf("%s's prescribed-values criterion on a CAPTURELESS run = %s, want %s — a "+
					"construction claim must not be able to depend on an observation it never reads",
					tc.id, got, tc.want)
			}

			// And with a session recovered, the same answer.
			withSession := &Observation{
				Case:       &certify.Case{UID: "csip-conf-v1.3::" + tc.id, ID: tc.id},
				Transcript: &Transcript{Decrypted: true},
			}
			if got := assertVerdictOf(t, crit, withSession); got != tc.want {
				t.Errorf("%s's prescribed-values criterion WITH a session = %s, want %s — the two paths "+
					"must not disagree", tc.id, got, tc.want)
			}
		})
	}

	// THE TEETH, kept exercised now that no shipping row has a material gap.
	//
	// Curve plan #32 closed both of the rows that used to hold here, so the
	// FAIL branch above no longer runs against anything real — and a hold that
	// nothing exercises is a hold that can rot out. A synthetic binding stands
	// in for the next Figure element this bench cannot send: the criterion must
	// still FAIL on it, name it, and do both with and without a capture.
	t.Run("a material gap still holds the row", func(t *testing.T) {
		gapped := &curveBinding{
			Mode:       "volt_var",
			Points:     []CurvePoint{{X: 9100, Y: 4000}},
			Prescribed: "a synthetic binding, for this test only",
			Gaps: []curveGap{{Element: "opModVoltVar.DERCurve.rampPT1Tms", Prescribed: "300",
				Default: "0", Why: noPrescribedCurveRampLever, Material: true}},
		}
		crit := critCurvePublishedTheProcedureValues("the subject", gapped)
		for _, obs := range []*Observation{
			{Case: &certify.Case{UID: "csip-conf-v1.3::synthetic", ID: "synthetic"}},
			{Case: &certify.Case{UID: "csip-conf-v1.3::synthetic", ID: "synthetic"},
				Transcript: &Transcript{Decrypted: true}},
		} {
			if got := assertVerdictOf(t, crit, obs); got != certify.Fail {
				t.Errorf("a binding with a MATERIAL authoring gap scored %s, want FAIL — the hold that "+
					"BASIC-006 and BASIC-012 used to rest on must survive their closure", got)
			}
		}
		if f := crit.Construction(); !strings.Contains(f.Observed, "rampPT1Tms") {
			t.Errorf("the holding criterion does not name the element it holds on:\n%s", f.Observed)
		}
	})
}

// assertVerdictOf mints one criterion through the real assert path and returns
// the verdict it recorded, so a test exercises the tier selection rather than
// the evaluator alone.
func assertVerdictOf(t *testing.T, c criterion, obs *Observation) certify.Verdict {
	t.Helper()
	ev := &certify.Evidence{
		Case:  &certify.Case{UID: "csip-conf-v1.3::construction"},
		Index: certify.NewFrameIndex(nil),
		Set:   (&certify.Attribution{}).Set("construction"),
	}
	a, err := c.assert(ev, obs)
	if err != nil {
		t.Fatalf("mint the criterion: %v", err)
	}
	return a.Verdict
}
