package invariant

import (
	"strings"
	"testing"

	"lexa-proto/sunspec"
)

// m120Block builds a model-120 data block long enough to carry WRtg and its
// scale factor, at the published offsets.
func m120Block(wRtg uint16, sf int16) []uint16 {
	regs := make([]uint16, sunspec.M120_MaxDisChaRte_SF+1)
	regs[sunspec.M120_WRtg] = wRtg
	regs[sunspec.M120_W_SF] = uint16(sf)
	return regs
}

// m121Block builds a model-121 data block carrying WMax and its scale factor.
func m121Block(wMax uint16, sf int16) []uint16 {
	regs := make([]uint16, 30)
	regs[sunspec.M121_WMax] = wMax
	regs[sunspec.M121_WMax_SF] = uint16(sf)
	return regs
}

// TestDecodeLegacyNameplate_ResolvesSettingsFirst pins the rule that makes the
// legacy reference usable at all: a percentage is a percentage of what the
// device is CONFIGURED to do, so M121's WMax setting governs and M120's WRtg
// rating stands in only where no setting is published (IW15-002). Getting this
// backwards on a derated machine misreports a correct gateway.
func TestDecodeLegacyNameplate_ResolvesSettingsFirst(t *testing.T) {
	n := DecodeLegacyNameplate("src", m120Block(5000, 0), m121Block(4000, 0))
	if !n.Present {
		t.Fatal("a device serving both 120 and 121 published no active-power reference")
	}
	base, err := n.Base(RefWMax, 1, Measurement{})
	if err != nil {
		t.Fatalf("resolve the reference: %v", err)
	}
	if base.Q.Val != 4000 {
		t.Errorf("reference = %g W, want the 4000 W SETTING and not the 5000 W rating", base.Q.Val)
	}
	if base.Name != "WMax" {
		t.Errorf("reference name = %q, want WMax (the setting)", base.Name)
	}
}

// TestDecodeLegacyNameplate_FallsBackToTheRating: a device publishing only the
// M120 rating still has a resolvable reference, and the verdict must be able to
// say it used the rating.
func TestDecodeLegacyNameplate_FallsBackToTheRating(t *testing.T) {
	n := DecodeLegacyNameplate("src", m120Block(5000, 0), nil)
	base, err := n.Base(RefWMax, 1, Measurement{})
	if err != nil {
		t.Fatalf("resolve the reference from the rating alone: %v", err)
	}
	if base.Q.Val != 5000 || base.Name != "WMaxRtg" {
		t.Errorf("reference = %g W named %q, want 5000 W named WMaxRtg", base.Q.Val, base.Name)
	}
}

// TestDecodeLegacyNameplate_AppliesTheDeclaredScaleFactor: the legacy models
// carry their own scale factors and a reference read raw would be wrong by
// orders of magnitude on any device that uses one.
func TestDecodeLegacyNameplate_AppliesTheDeclaredScaleFactor(t *testing.T) {
	// WMax raw 500 at SF 1 is 5000 W.
	n := DecodeLegacyNameplate("src", nil, m121Block(500, 1))
	base, err := n.Base(RefWMax, 1, Measurement{})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if base.Q.Val != 5000 {
		t.Errorf("reference = %g W, want 5000 (raw 500 at SF 1)", base.Q.Val)
	}
}

// TestDecodeLegacyNameplate_AbsentOrIllegal is the fail-closed half. A device
// serving neither model, a block too short to hold the point, or a scale factor
// outside the sunssf domain must all yield "no reference" rather than a
// fabricated number — a wrong denominator turns every percent verdict into a
// confident falsehood.
func TestDecodeLegacyNameplate_AbsentOrIllegal(t *testing.T) {
	for _, tc := range []struct {
		name       string
		m120, m121 []uint16
	}{
		{"neither model served", nil, nil},
		{"120 too short", make([]uint16, sunspec.M120_W_SF), nil},
		{"121 too short", nil, make([]uint16, sunspec.M121_WMax_SF)},
		{"120 sf outside the domain", m120Block(5000, 11), nil},
		{"121 sf outside the domain", nil, m121Block(5000, -11)},
		{"121 sf is the not-implemented sentinel", nil, func() []uint16 {
			r := m121Block(5000, 0)
			r[sunspec.M121_WMax_SF] = 0x8000
			return r
		}()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			n := DecodeLegacyNameplate("src", tc.m120, tc.m121)
			if n.Present {
				t.Fatalf("Present is true; the device published no usable reference")
			}
			if _, err := n.Base(RefWMax, 1, Measurement{}); err == nil {
				t.Error("Base resolved a reference out of nothing")
			}
		})
	}
}

// TestDecodeLegacyNameplate_LeavesTheOtherReferencesUnanswered: this decoder
// answers ONE question — what an active-power percent is a percent of. A
// half-populated nameplate would let an unrelated oracle resolve a reactive or
// per-sign rate base off the legacy models without anyone deciding that it
// should.
func TestDecodeLegacyNameplate_LeavesTheOtherReferencesUnanswered(t *testing.T) {
	n := DecodeLegacyNameplate("src", m120Block(5000, 0), m121Block(5000, 0))
	for _, ref := range []RefBase{RefVarMaxInj, RefVarMaxAbs, RefVAMax, RefWRteMax} {
		if _, err := n.Base(ref, 1, Measurement{}); err == nil {
			t.Errorf("%v resolved off the legacy models; only the active-power reference is decoded there", ref)
		}
	}
}

// TestUnitView_LegacyNameplate_NamesItsSource: a verdict citing a denominator
// has to be able to say which registers it came from.
func TestUnitView_LegacyNameplate_NamesItsSource(t *testing.T) {
	uv := UnitView{Unit: 3, Regs: map[uint16][]uint16{
		sunspec.ModelNameplate:     m120Block(5000, 0),
		sunspec.ModelBasicSettings: m121Block(4000, 0),
	}}
	n := uv.LegacyNameplate("bench")
	if !n.Present {
		t.Fatal("LegacyNameplate found no reference on a unit serving both models")
	}
	for _, want := range []string{"bench", "unit 3", "M120", "M121"} {
		if !strings.Contains(n.Source, want) {
			t.Errorf("source %q does not mention %q", n.Source, want)
		}
	}
}

// TestModelsOfInterest_IncludesTheLegacyActivePowerReference: the decoder is
// useless if the read set never fetches the models. This is the wiring the
// 2026-08-17 legacy leg was missing.
func TestModelsOfInterest_IncludesTheLegacyActivePowerReference(t *testing.T) {
	for _, want := range []uint16{sunspec.ModelNameplate, sunspec.ModelBasicSettings} {
		found := false
		for _, m := range modelsOfInterest {
			if m == want {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("model %d is not read; a legacy DER's percent controls have no denominator", want)
		}
	}
}
