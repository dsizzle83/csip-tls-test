package invariant

// fixture_test.go builds register images by hand so the teeth tests can place a
// device in a state that MUST trip an invariant.
//
// These are deliberately NOT built by the same code the sims use to populate a
// device. A fixture that came from the simulator's own populate() would only
// ever produce states the simulator can produce, and the whole point of a teeth
// test is to produce a state nothing sane would.

import (
	"context"
	"testing"
	"time"

	"lexa-proto/sunspec"
)

// nameplateRegs builds a model 702 image with the given ratings, choosing scale
// factors large enough that the values fit their uint16 registers — which is
// exactly how a real device with a 100 kW rating publishes it, and which means
// the fixture exercises the scale-factor path rather than dodging it.
func nameplateRegs(t *testing.T, wMaxW, varInjW, varAbsW, vaMaxW float64) []uint16 {
	t.Helper()
	regs := make([]uint16, sunspec.L702.Len())
	v := sunspec.L702.View(regs)
	// Scale factors first: SetFloat reads them live.
	v.SetEnum("W_SF", sfReg(2))   // ×100
	v.SetEnum("Var_SF", sfReg(1)) // ×10
	v.SetEnum("VA_SF", sfReg(2))
	v.SetEnum("PF_SF", sfReg(-3))
	v.SetEnum("V_SF", 0)
	v.SetEnum("A_SF", 0)
	v.SetEnum("S_SF", 0)
	v.SetFloat("WMaxRtg", wMaxW)
	v.SetFloat("WMax", wMaxW)
	v.SetFloat("VarMaxInjRtg", varInjW)
	v.SetFloat("VarMaxInj", varInjW)
	v.SetFloat("VarMaxAbsRtg", varAbsW)
	v.SetFloat("VarMaxAbs", varAbsW)
	v.SetFloat("VAMaxRtg", vaMaxW)
	v.SetFloat("VAMax", vaMaxW)
	return regs
}

// controlRegs builds a model 704 image, applying mutate to set the setpoints
// under test. Scale factors are set first so SetFloat can encode.
func controlRegs(t *testing.T, mutate func(v sunspec.View)) []uint16 {
	t.Helper()
	regs := make([]uint16, sunspec.L704.Len())
	v := sunspec.L704.View(regs)
	v.SetEnum("PF_SF", sfReg(-3))
	v.SetEnum("WMaxLimPct_SF", 0)
	v.SetEnum("WSet_SF", sfReg(2))
	v.SetEnum("WSetPct_SF", 0)
	v.SetEnum("VarSet_SF", sfReg(1))
	v.SetEnum("VarSetPct_SF", 0)
	if mutate != nil {
		mutate(v)
	}
	return regs
}

// measurementRegs builds a minimal model 701 image.
func measurementRegs(t *testing.T, w float64, connSt uint16) []uint16 {
	t.Helper()
	regs := make([]uint16, sunspec.L701.Len())
	v := sunspec.L701.View(regs)
	v.SetEnum("W_SF", sfReg(2))
	v.SetEnum("VA_SF", sfReg(2))
	v.SetEnum("Var_SF", sfReg(1))
	v.SetEnum("PF_SF", sfReg(-3))
	v.SetEnum("A_SF", 0)
	v.SetEnum("V_SF", 0)
	v.SetEnum("Hz_SF", sfReg(-2))
	v.SetEnum("Tmp_SF", 0)
	v.SetEnum("TotWh_SF", 0)
	v.SetEnum("TotVarh_SF", 0)
	v.SetEnum("St", 2)
	v.SetEnum("ConnSt", connSt)
	v.SetFloat("W", w)
	v.SetFloat("Hz", 60)
	return regs
}

// unitFixture assembles a UnitView from model images.
func unitFixture(unit uint8, models map[uint16][]uint16) UnitView {
	uv := UnitView{Unit: unit, Regs: map[uint16][]uint16{}, Base: map[uint16]uint16{}}
	base := uint16(40002)
	for _, id := range []uint16{701, 702, 703, 704} {
		regs, ok := models[id]
		if !ok {
			continue
		}
		uv.Models = append(uv.Models, id)
		uv.Regs[id] = regs
		uv.Base[id] = base
		base += uint16(len(regs)) + 2
	}
	return uv
}

// derFixture wraps a UnitView as a reachable DER's own account of itself.
func derFixture(name string, uv UnitView) DERView {
	return DERView{
		Name:      name,
		Source:    "modbus:test/" + name,
		Reachable: true,
		Unit:      uv,
		Animating: true,
	}
}

// obsFixture builds an Observation from DER views.
func obsFixture(at time.Time, ders ...DERView) *Observation {
	o := &Observation{At: at, DERs: map[string]DERView{}, Errs: map[string]string{}}
	for _, d := range ders {
		o.DERs[d.Name] = d
	}
	return o
}

// scriptedDER is a DERSource that replays a fixed sequence of views, so a test
// can drive a Monitor through a scenario without a network.
type scriptedDER struct {
	name  string
	views []DERView
	i     int
}

func (s *scriptedDER) Name() string { return "scripted:" + s.name }

func (s *scriptedDER) Observe(context.Context) (DERView, error) {
	i := s.i
	if i >= len(s.views) {
		i = len(s.views) - 1
	}
	s.i++
	v := s.views[i]
	v.Name = s.name
	return v, nil
}

// scriptedHeadEnd replays a fixed head-end view.
type scriptedHeadEnd struct {
	view HeadEndView
	err  error
}

func (s *scriptedHeadEnd) Name() string { return "scripted:head-end" }

func (s *scriptedHeadEnd) Observe(context.Context) (HeadEndView, error) {
	return s.view, s.err
}

// scriptedHost replays a fixed host view.
type scriptedHost struct{ views []HostView }

func (s *scriptedHost) Name() string { return "scripted:host" }

func (s *scriptedHost) Observe(context.Context) (HostView, error) {
	if len(s.views) == 0 {
		return HostView{}, nil
	}
	v := s.views[0]
	if len(s.views) > 1 {
		s.views = s.views[1:]
	}
	return v, nil
}

// sfReg encodes a signed SunSpec scale factor into its register word. It exists
// because a scale factor is an int16 living in a uint16 register and writing
// the conversion inline four dozen times invites exactly one of them being
// wrong.
func sfReg(sf int16) uint16 { return uint16(sf) }
