package sunspecgolden_test

import (
	"fmt"
	"os"
	"strings"
	"testing"

	"csip-tls-test/internal/certify/sunspecgolden"

	"lexa-proto/sunspec"
)

// driftEnvVar gates the ONLY acceptable way to silence a known mismatch
// between lexa-proto's vendored sunspec package and this package's
// independently-sourced golden. The lead sets it for exactly one run, to
// prove the golden finds the drift it is supposed to find (M120, M122 and
// M802 are wrong at the pinned lexa-proto commit a3eeb10 — see
// docs/testdata/models/SOURCES.md and the finding cited in each subtest
// below); it is never set in CI or in a developer's normal test run, so the
// default `go test` sees every disagreement as a hard failure.
const driftEnvVar = "SUNSPEC_GOLDEN_EXPECT_DRIFT"

// typeToLexa maps this package's spec-token FieldType onto lexa-proto's own
// FieldType enum, so a Layout-backed model (701-712) can be compared without
// this package importing lexa-proto's internals or lexa-proto depending on
// this package.
var typeToLexa = map[sunspecgolden.FieldType]sunspec.FieldType{
	sunspecgolden.Uint16:     sunspec.Tuint16,
	sunspecgolden.Int16:      sunspec.Tint16,
	sunspecgolden.Enum16:     sunspec.Tenum16,
	sunspecgolden.Bitfield16: sunspec.Tbitfield16,
	sunspecgolden.Sunssf:     sunspec.Tsunssf,
	sunspecgolden.Uint32:     sunspec.Tuint32,
	sunspecgolden.Int32:      sunspec.Tint32,
	sunspecgolden.Enum32:     sunspec.Tenum32,
	sunspecgolden.Bitfield32: sunspec.Tbitfield32,
	sunspecgolden.Acc32:      sunspec.Tacc32,
	sunspecgolden.Uint64:     sunspec.Tuint64,
	sunspecgolden.Acc64:      sunspec.Tacc64,
	sunspecgolden.String:     sunspec.Tstring,
	sunspecgolden.Pad:        sunspec.Tpad,
}

// reportMismatches always fails the test on any mismatch — used for every
// model this golden expects lexa-proto to already match (everything except
// M120/M122/M802's known-drift subtests below).
func reportMismatches(t *testing.T, model string, mismatches []string) {
	t.Helper()
	if len(mismatches) == 0 {
		return
	}
	t.Fatalf("%s: %d point(s) disagree with the independently-sourced golden (testdata/models/SOURCES.md):\n%s",
		model, len(mismatches), strings.Join(mismatches, "\n"))
}

// reportDrift is reportMismatches EXCEPT that a mismatch is downgraded to a
// skip when SUNSPEC_GOLDEN_EXPECT_DRIFT=1 is set. Use ONLY for the three
// models known-wrong at the vendored pin.
func reportDrift(t *testing.T, model, knownUntil string, mismatches []string) {
	t.Helper()
	if len(mismatches) == 0 {
		return
	}
	msg := fmt.Sprintf("%s: %d point(s) disagree with the independently-sourced golden (testdata/models/SOURCES.md):\n%s",
		model, len(mismatches), strings.Join(mismatches, "\n"))
	if os.Getenv(driftEnvVar) == "1" {
		t.Skipf("known drift until proto pin >= %s: %s", knownUntil, msg)
		return
	}
	t.Fatal(msg)
}

// compareLayout checks a lexa-proto *sunspec.Layout against a golden point
// list, by name: offset, scale-factor binding, and data type must all agree.
// It never trusts the golden's Size against the layout directly (Layout
// exposes no exported register-width accessor) — a size defect in the
// layout still surfaces here because it shifts every subsequent point's
// offset, which the by-name Offset comparison below catches directly.
func compareLayout(layout *sunspec.Layout, golden []sunspecgolden.Point) []string {
	var mismatches []string
	for _, g := range golden {
		off := layout.Offset(g.Name)
		if off < 0 {
			mismatches = append(mismatches, fmt.Sprintf("%s: not present in lexa-proto layout %q (golden offset %d)", g.Name, layout.Name(), g.Offset))
			continue
		}
		if off != g.Offset {
			mismatches = append(mismatches, fmt.Sprintf("%s: lexa-proto offset %d != golden offset %d", g.Name, off, g.Offset))
		}
		f, ok := layout.FieldOf(g.Name)
		if !ok {
			mismatches = append(mismatches, fmt.Sprintf("%s: layout.Offset succeeded but FieldOf did not", g.Name))
			continue
		}
		wantType, known := typeToLexa[g.Type]
		if !known {
			mismatches = append(mismatches, fmt.Sprintf("%s: golden type %q has no lexa-proto FieldType mapping in this test", g.Name, g.Type))
			continue
		}
		if f.Type != wantType {
			mismatches = append(mismatches, fmt.Sprintf("%s: lexa-proto type %v != golden type %v", g.Name, f.Type, g.Type))
		}
		if f.SF != g.SF {
			mismatches = append(mismatches, fmt.Sprintf("%s: lexa-proto scale factor %q != golden scale factor %q", g.Name, f.SF, g.SF))
		}
	}
	return mismatches
}

// constCheck pins one vendored raw-offset constant (models.go's M<id>_*
// consts — used for models lexa-proto never promoted to a *Layout) against
// its golden counterpart by name. goldenName == "" records a vendored
// constant this golden has NO counterpart for at all — i.e. lexa-proto
// invented a register the SunSpec spec does not define.
type constCheck struct {
	vendoredName string
	vendoredOff  int
	goldenName   string
}

func compareConsts(model string, checks []constCheck, golden []sunspecgolden.Point) []string {
	byName := make(map[string]sunspecgolden.Point, len(golden))
	for _, p := range golden {
		byName[p.Name] = p
	}
	var mismatches []string
	for _, c := range checks {
		if c.goldenName == "" {
			mismatches = append(mismatches, fmt.Sprintf("%s = %d: no golden (spec) counterpart -- lexa-proto invented this point", c.vendoredName, c.vendoredOff))
			continue
		}
		gp, ok := byName[c.goldenName]
		if !ok {
			mismatches = append(mismatches, fmt.Sprintf("%s: golden %s has no point named %q", c.vendoredName, model, c.goldenName))
			continue
		}
		if c.vendoredOff != gp.Offset {
			mismatches = append(mismatches, fmt.Sprintf("%s = %d, golden %s.Offset = %d (mismatch)", c.vendoredName, c.vendoredOff, gp.Name, gp.Offset))
		}
	}
	return mismatches
}

// TestLexaProtoLayoutsMatchGolden is the WP4-T5/T6 (REV0907-E8) referee-
// independence proof: every model lexa-proto's vendored sunspec package
// exposes a comparable Go construct for (a *Layout, or a set of raw M<id>_*
// offset constants) is checked, point by point, against a golden built from
// an independently-fetched copy of the SunSpec Alliance model JSON — never
// from lexa-proto's own tables. See golden.go's package doc and
// testdata/models/SOURCES.md.
func TestLexaProtoLayoutsMatchGolden(t *testing.T) {
	t.Run("M1", testM1Common)

	t.Run("M103", func(t *testing.T) {
		golden, ok := sunspecgolden.Block("M103")
		if !ok {
			t.Fatal("golden has no M103 block")
		}
		reportMismatches(t, "M103", compareConsts("M103", m103Checks(), golden))
	})

	t.Run("M120", func(t *testing.T) {
		golden, ok := sunspecgolden.Block("M120")
		if !ok {
			t.Fatal("golden has no M120 block")
		}
		// REV0907-E8: model 120's table was wrong at 22 of its 25 named
		// points at lexa-proto a3eeb10 -- every value/SF pair after WRtg was
		// laid out as "all values, then all scale factors" instead of the
		// spec's per-quantity value+SF pairing. Fixed in lexa-proto eba7e97.
		reportDrift(t, "M120", "eba7e97", compareConsts("M120", m120Checks(), golden))
	})

	t.Run("M121", func(t *testing.T) {
		golden, ok := sunspecgolden.Block("M121")
		if !ok {
			t.Fatal("golden has no M121 block")
		}
		reportMismatches(t, "M121", compareConsts("M121", m121Checks(), golden))
	})

	t.Run("M122", func(t *testing.T) {
		golden, ok := sunspecgolden.Block("M122")
		if !ok {
			t.Fatal("golden has no M122 block")
		}
		// REV0907-E8: WAval/WAval_SF were placed at offsets 21/22 (immediately
		// after the four ActVArh accumulators, as if ActWh/ActVAh/ActVArhQ1-4
		// were each a single register) instead of the spec's 29/30 (each of
		// those six accumulators is acc64 -- 4 registers, not 1). Fixed in
		// lexa-proto eba7e97.
		reportDrift(t, "M122", "eba7e97", compareConsts("M122", m122Checks(), golden))
	})

	t.Run("M123", func(t *testing.T) {
		golden, ok := sunspecgolden.Block("M123")
		if !ok {
			t.Fatal("golden has no M123 block")
		}
		reportMismatches(t, "M123", compareConsts("M123", m123Checks(), golden))
	})

	t.Run("M701", func(t *testing.T) {
		golden, ok := sunspecgolden.Block("M701")
		if !ok {
			t.Fatal("golden has no M701 block")
		}
		reportMismatches(t, "M701", compareLayout(sunspec.L701, golden))
	})
	t.Run("M702", func(t *testing.T) {
		golden, ok := sunspecgolden.Block("M702")
		if !ok {
			t.Fatal("golden has no M702 block")
		}
		reportMismatches(t, "M702", compareLayout(sunspec.L702, golden))
	})
	t.Run("M703", func(t *testing.T) {
		golden, ok := sunspecgolden.Block("M703")
		if !ok {
			t.Fatal("golden has no M703 block")
		}
		reportMismatches(t, "M703", compareLayout(sunspec.L703, golden))
	})
	t.Run("M704", func(t *testing.T) {
		golden, ok := sunspecgolden.Block("M704")
		if !ok {
			t.Fatal("golden has no M704 block")
		}
		reportMismatches(t, "M704", compareLayout(sunspec.L704, golden))
	})
	t.Run("M705", func(t *testing.T) {
		hdr, ok := sunspecgolden.Block("M705Hdr")
		if !ok {
			t.Fatal("golden has no M705Hdr block")
		}
		crv, ok := sunspecgolden.Block("M705Crv")
		if !ok {
			t.Fatal("golden has no M705Crv block")
		}
		var mismatches []string
		mismatches = append(mismatches, compareLayout(sunspec.L705Hdr, hdr)...)
		mismatches = append(mismatches, compareLayout(sunspec.L705Crv, crv)...)
		reportMismatches(t, "M705", mismatches)
	})
	t.Run("M706", func(t *testing.T) {
		hdr, ok := sunspecgolden.Block("M706Hdr")
		if !ok {
			t.Fatal("golden has no M706Hdr block")
		}
		crv, ok := sunspecgolden.Block("M706Crv")
		if !ok {
			t.Fatal("golden has no M706Crv block")
		}
		var mismatches []string
		mismatches = append(mismatches, compareLayout(sunspec.L706Hdr, hdr)...)
		mismatches = append(mismatches, compareLayout(sunspec.L706Crv, crv)...)
		reportMismatches(t, "M706", mismatches)
	})
	t.Run("M707", func(t *testing.T) {
		// lexa-proto holds ONE header layout (L707Hdr) for both 707 and 708
		// -- they are the identical shape (Ena, AdptCrvReq, AdptCrvRslt, NPt,
		// NCrvSet, V_SF, Tms_SF); see derlayout.go. Both golden blocks are
		// checked against it.
		golden, ok := sunspecgolden.Block("M707Hdr")
		if !ok {
			t.Fatal("golden has no M707Hdr block")
		}
		reportMismatches(t, "M707Hdr", compareLayout(sunspec.L707Hdr, golden))
	})
	t.Run("M708_sharesM707Hdr", func(t *testing.T) {
		golden, ok := sunspecgolden.Block("M708Hdr")
		if !ok {
			t.Fatal("golden has no M708Hdr block")
		}
		reportMismatches(t, "M708Hdr (against shared L707Hdr)", compareLayout(sunspec.L707Hdr, golden))
	})
	t.Run("M709", func(t *testing.T) {
		golden, ok := sunspecgolden.Block("M709Hdr")
		if !ok {
			t.Fatal("golden has no M709Hdr block")
		}
		reportMismatches(t, "M709Hdr", compareLayout(sunspec.L709Hdr, golden))
	})
	t.Run("M710_sharesM709Hdr", func(t *testing.T) {
		// lexa-proto holds ONE header layout (L709Hdr) for both 709 and 710
		// -- the identical shape (Ena, AdptCrvReq, AdptCrvRslt, NPt, NCrvSet,
		// Hz_SF, Tms_SF).
		golden, ok := sunspecgolden.Block("M710Hdr")
		if !ok {
			t.Fatal("golden has no M710Hdr block")
		}
		reportMismatches(t, "M710Hdr (against shared L709Hdr)", compareLayout(sunspec.L709Hdr, golden))
	})
	t.Run("M711", func(t *testing.T) {
		hdr, ok := sunspecgolden.Block("M711Hdr")
		if !ok {
			t.Fatal("golden has no M711Hdr block")
		}
		ctl, ok := sunspecgolden.Block("M711Ctl")
		if !ok {
			t.Fatal("golden has no M711Ctl block")
		}
		var mismatches []string
		mismatches = append(mismatches, compareLayout(sunspec.L711Hdr, hdr)...)
		mismatches = append(mismatches, compareLayout(sunspec.L711Ctl, ctl)...)
		reportMismatches(t, "M711", mismatches)
	})
	t.Run("M712", func(t *testing.T) {
		hdr, ok := sunspecgolden.Block("M712Hdr")
		if !ok {
			t.Fatal("golden has no M712Hdr block")
		}
		crv, ok := sunspecgolden.Block("M712Crv")
		if !ok {
			t.Fatal("golden has no M712Crv block")
		}
		var mismatches []string
		mismatches = append(mismatches, compareLayout(sunspec.L712Hdr, hdr)...)
		mismatches = append(mismatches, compareLayout(sunspec.L712Crv, crv)...)
		reportMismatches(t, "M712", mismatches)
	})

	t.Run("M802", func(t *testing.T) {
		golden, ok := sunspecgolden.Block("M802")
		if !ok {
			t.Fatal("golden has no M802 block")
		}
		// REV0907-E8: the vendored M802_* table at a3eeb10 is a hand-invented
		// 26-register compression of the real 62-register spec model --
		// almost every offset disagrees, and M802_HeatCool names a register
		// the spec does not define at all. Fixed in lexa-proto b6eca4a
		// ("vendor model 802, fix every M802_* offset").
		reportDrift(t, "M802", "b6eca4a", compareConsts("M802", m802Checks(), golden))
	})
}

func m103Checks() []constCheck {
	return []constCheck{
		{"M103_A", sunspec.M103_A, "A"},
		{"M103_AphA", sunspec.M103_AphA, "AphA"},
		{"M103_AphB", sunspec.M103_AphB, "AphB"},
		{"M103_AphC", sunspec.M103_AphC, "AphC"},
		{"M103_A_SF", sunspec.M103_A_SF, "A_SF"},
		{"M103_PPVphAB", sunspec.M103_PPVphAB, "PPVphAB"},
		{"M103_PPVphBC", sunspec.M103_PPVphBC, "PPVphBC"},
		{"M103_PPVphCA", sunspec.M103_PPVphCA, "PPVphCA"},
		{"M103_PhVphA", sunspec.M103_PhVphA, "PhVphA"},
		{"M103_PhVphB", sunspec.M103_PhVphB, "PhVphB"},
		{"M103_PhVphC", sunspec.M103_PhVphC, "PhVphC"},
		{"M103_V_SF", sunspec.M103_V_SF, "V_SF"},
		{"M103_W", sunspec.M103_W, "W"},
		{"M103_W_SF", sunspec.M103_W_SF, "W_SF"},
		{"M103_Hz", sunspec.M103_Hz, "Hz"},
		{"M103_Hz_SF", sunspec.M103_Hz_SF, "Hz_SF"},
		{"M103_VA", sunspec.M103_VA, "VA"},
		{"M103_VA_SF", sunspec.M103_VA_SF, "VA_SF"},
		{"M103_VAr", sunspec.M103_VAr, "VAr"},
		{"M103_VAr_SF", sunspec.M103_VAr_SF, "VAr_SF"},
		{"M103_PF", sunspec.M103_PF, "PF"},
		{"M103_PF_SF", sunspec.M103_PF_SF, "PF_SF"},
		{"M103_WH", sunspec.M103_WH, "WH"},
		{"M103_WH_SF", sunspec.M103_WH_SF, "WH_SF"},
		{"M103_DCA", sunspec.M103_DCA, "DCA"},
		{"M103_DCA_SF", sunspec.M103_DCA_SF, "DCA_SF"},
		{"M103_DCV", sunspec.M103_DCV, "DCV"},
		{"M103_DCV_SF", sunspec.M103_DCV_SF, "DCV_SF"},
		{"M103_DCW", sunspec.M103_DCW, "DCW"},
		{"M103_DCW_SF", sunspec.M103_DCW_SF, "DCW_SF"},
		{"M103_TmpCab", sunspec.M103_TmpCab, "TmpCab"},
		{"M103_TmpSnk", sunspec.M103_TmpSnk, "TmpSnk"},
		{"M103_TmpTrns", sunspec.M103_TmpTrns, "TmpTrns"},
		{"M103_TmpOt", sunspec.M103_TmpOt, "TmpOt"},
		{"M103_Tmp_SF", sunspec.M103_Tmp_SF, "Tmp_SF"},
		{"M103_St", sunspec.M103_St, "St"},
		{"M103_StVnd", sunspec.M103_StVnd, "StVnd"},
	}
}

func m120Checks() []constCheck {
	return []constCheck{
		{"M120_DERTyp", sunspec.M120_DERTyp, "DERTyp"},
		{"M120_WRtg", sunspec.M120_WRtg, "WRtg"},
		{"M120_VARtg", sunspec.M120_VARtg, "VARtg"},
		{"M120_VArRtgQ1", sunspec.M120_VArRtgQ1, "VArRtgQ1"},
		{"M120_VArRtgQ2", sunspec.M120_VArRtgQ2, "VArRtgQ2"},
		{"M120_VArRtgQ3", sunspec.M120_VArRtgQ3, "VArRtgQ3"},
		{"M120_VArRtgQ4", sunspec.M120_VArRtgQ4, "VArRtgQ4"},
		{"M120_ARtg", sunspec.M120_ARtg, "ARtg"},
		{"M120_PFRtgQ1", sunspec.M120_PFRtgQ1, "PFRtgQ1"},
		{"M120_PFRtgQ2", sunspec.M120_PFRtgQ2, "PFRtgQ2"},
		{"M120_PFRtgQ3", sunspec.M120_PFRtgQ3, "PFRtgQ3"},
		{"M120_PFRtgQ4", sunspec.M120_PFRtgQ4, "PFRtgQ4"},
		{"M120_WHRtg", sunspec.M120_WHRtg, "WHRtg"},
		{"M120_AhrRtg", sunspec.M120_AhrRtg, "AhrRtg"},
		{"M120_MaxChaRte", sunspec.M120_MaxChaRte, "MaxChaRte"},
		{"M120_MaxDisChaRte", sunspec.M120_MaxDisChaRte, "MaxDisChaRte"},
		// The vendored constant is spelled M120_W_SF; the spec's own name for
		// WRtg's scale factor is "WRtg_SF" (models.go's comment on the very
		// next line calls it "power scale factor", i.e. WRtg's SF).
		{"M120_W_SF", sunspec.M120_W_SF, "WRtg_SF"},
		{"M120_VARtg_SF", sunspec.M120_VARtg_SF, "VARtg_SF"},
		{"M120_VArRtg_SF", sunspec.M120_VArRtg_SF, "VArRtg_SF"},
		{"M120_ARtg_SF", sunspec.M120_ARtg_SF, "ARtg_SF"},
		{"M120_PFRtg_SF", sunspec.M120_PFRtg_SF, "PFRtg_SF"},
		{"M120_WHRtg_SF", sunspec.M120_WHRtg_SF, "WHRtg_SF"},
		{"M120_AhrRtg_SF", sunspec.M120_AhrRtg_SF, "AhrRtg_SF"},
		{"M120_MaxChaRte_SF", sunspec.M120_MaxChaRte_SF, "MaxChaRte_SF"},
		{"M120_MaxDisChaRte_SF", sunspec.M120_MaxDisChaRte_SF, "MaxDisChaRte_SF"},
	}
}

func m121Checks() []constCheck {
	return []constCheck{
		{"M121_WMax", sunspec.M121_WMax, "WMax"},
		{"M121_WMax_SF", sunspec.M121_WMax_SF, "WMax_SF"},
	}
}

func m122Checks() []constCheck {
	return []constCheck{
		{"M122_PVConn", sunspec.M122_PVConn, "PVConn"},
		{"M122_StorConn", sunspec.M122_StorConn, "StorConn"},
		{"M122_ECPConn", sunspec.M122_ECPConn, "ECPConn"},
		{"M122_ActWh", sunspec.M122_ActWh, "ActWh"},
		{"M122_WAval", sunspec.M122_WAval, "WAval"},
		{"M122_WAval_SF", sunspec.M122_WAval_SF, "WAval_SF"},
	}
}

func m123Checks() []constCheck {
	return []constCheck{
		{"M123_Conn_WinTms", sunspec.M123_Conn_WinTms, "Conn_WinTms"},
		{"M123_Conn_RvrtTms", sunspec.M123_Conn_RvrtTms, "Conn_RvrtTms"},
		{"M123_Conn", sunspec.M123_Conn, "Conn"},
		{"M123_WMaxLimPct", sunspec.M123_WMaxLimPct, "WMaxLimPct"},
		{"M123_WMaxLimPct_WinTms", sunspec.M123_WMaxLimPct_WinTms, "WMaxLimPct_WinTms"},
		{"M123_WMaxLimPct_RvrtTms", sunspec.M123_WMaxLimPct_RvrtTms, "WMaxLimPct_RvrtTms"},
		{"M123_WMaxLimPct_RmpTms", sunspec.M123_WMaxLimPct_RmpTms, "WMaxLimPct_RmpTms"},
		// The vendored constant keeps the old "WMaxLimPct_Ena" spelling (see
		// models.go's own comment); the published point is WMaxLim_Ena, no "Pct".
		{"M123_WMaxLimPct_Ena", sunspec.M123_WMaxLimPct_Ena, "WMaxLim_Ena"},
		{"M123_OutPFSet", sunspec.M123_OutPFSet, "OutPFSet"},
		{"M123_OutPFSet_WinTms", sunspec.M123_OutPFSet_WinTms, "OutPFSet_WinTms"},
		{"M123_OutPFSet_RvrtTms", sunspec.M123_OutPFSet_RvrtTms, "OutPFSet_RvrtTms"},
		{"M123_OutPFSet_RmpTms", sunspec.M123_OutPFSet_RmpTms, "OutPFSet_RmpTms"},
		{"M123_OutPFSet_Ena", sunspec.M123_OutPFSet_Ena, "OutPFSet_Ena"},
		{"M123_VArWMaxPct", sunspec.M123_VArWMaxPct, "VArWMaxPct"},
		{"M123_VArMaxPct", sunspec.M123_VArMaxPct, "VArMaxPct"},
		{"M123_VArAvalPct", sunspec.M123_VArAvalPct, "VArAvalPct"},
		{"M123_VArPct_WinTms", sunspec.M123_VArPct_WinTms, "VArPct_WinTms"},
		{"M123_VArPct_RvrtTms", sunspec.M123_VArPct_RvrtTms, "VArPct_RvrtTms"},
		{"M123_VArPct_RmpTms", sunspec.M123_VArPct_RmpTms, "VArPct_RmpTms"},
		{"M123_VArPct_Mod", sunspec.M123_VArPct_Mod, "VArPct_Mod"},
		{"M123_VArPct_Ena", sunspec.M123_VArPct_Ena, "VArPct_Ena"},
		{"M123_WMaxLimPct_SF", sunspec.M123_WMaxLimPct_SF, "WMaxLimPct_SF"},
		{"M123_OutPFSet_SF", sunspec.M123_OutPFSet_SF, "OutPFSet_SF"},
		{"M123_VArPct_SF", sunspec.M123_VArPct_SF, "VArPct_SF"},
	}
}

func m802Checks() []constCheck {
	return []constCheck{
		{"M802_WHRtg", sunspec.M802_WHRtg, "WHRtg"},
		{"M802_WHRtg_SF", sunspec.M802_WHRtg_SF, "WHRtg_SF"},
		{"M802_AHRtg", sunspec.M802_AHRtg, "AHRtg"},
		{"M802_AHRtg_SF", sunspec.M802_AHRtg_SF, "AHRtg_SF"},
		{"M802_WChaRteMax", sunspec.M802_WChaRteMax, "WChaRteMax"},
		{"M802_WDisChaRteMax", sunspec.M802_WDisChaRteMax, "WDisChaRteMax"},
		// The vendored constant is spelled M802_W_SF; the spec names the
		// combined charge/discharge-rate scale factor WChaDisChaMax_SF.
		{"M802_W_SF", sunspec.M802_W_SF, "WChaDisChaMax_SF"},
		{"M802_DisChaRte", sunspec.M802_DisChaRte, "DisChaRte"},
		{"M802_DisChaRte_SF", sunspec.M802_DisChaRte_SF, "DisChaRte_SF"},
		{"M802_SoCMax", sunspec.M802_SoCMax, "SoCMax"},
		{"M802_SoCMin", sunspec.M802_SoCMin, "SoCMin"},
		// The spec JSON itself spells this "SocRsvMax" (lower-case c) -- kept
		// verbatim rather than "corrected" so the golden matches the
		// published model exactly.
		{"M802_SoCRsvMax", sunspec.M802_SoCRsvMax, "SocRsvMax"},
		{"M802_SoCRsvMin", sunspec.M802_SoCRsvMin, "SoCRsvMin"},
		{"M802_SoC_SF", sunspec.M802_SoC_SF, "SoC_SF"},
		{"M802_SoC", sunspec.M802_SoC, "SoC"},
		{"M802_DoD", sunspec.M802_DoD, "DoD"},
		{"M802_DoD_SF", sunspec.M802_DoD_SF, "DoD_SF"},
		{"M802_SoH", sunspec.M802_SoH, "SoH"},
		{"M802_SoH_SF", sunspec.M802_SoH_SF, "SoH_SF"},
		{"M802_ChaSt", sunspec.M802_ChaSt, "ChaSt"},
		{"M802_LocRemCtl", sunspec.M802_LocRemCtl, "LocRemCtl"},
		// HeatCool has no counterpart anywhere in the published model 802 --
		// the vendored table invented it.
		{"M802_HeatCool", sunspec.M802_HeatCool, ""},
		{"M802_Typ", sunspec.M802_Typ, "Typ"},
		{"M802_State", sunspec.M802_State, "State"},
	}
}
