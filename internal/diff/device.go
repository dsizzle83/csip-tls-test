package diff

// device.go is the DER this package runs its control differentials against: a
// SunSpec 701/702/704 register bank in memory, behind the same
// lexa-proto/modbus.Transport interface a real inverter sits behind.
//
// # Why an in-package device rather than sim/southbound
//
// sim/southbound's advanced solar server is the right peer for the LIVE arm and
// internal/invariant's peer_test.go already drives it over a real socket. This
// package needs something different: total control of the nameplate. The whole
// point of the control differential is to command a device whose reactive
// envelope is narrow relative to its active rating, whose scale factors are
// awkward, or whose WMax is simply absent — configurations a physically
// plausible simulator has no reason to offer and that a differential must be
// able to construct on demand. A map of registers gives that, deterministically,
// with no port and no goroutine.
//
// The register IMAGE is built with the shared sunspec layouts, and that is
// deliberate: this is fixture construction, not refereeing. If the layout table
// is wrong, the fixture is wrong in exactly the way a real device driven by that
// table would be wrong, and the ctl family's finding would be about the layout
// rather than about the control semantics. Family "reg" is where the layout
// itself is put under an independently transcribed referee.
//
// # What it can do that a plain map cannot
//
// A Device can lie and can refuse. RefuseWriteAt makes a register range answer
// a Modbus exception on write — which is how the ctl family reaches audit
// OBX-01's territory (a refused write must not leave durable state asserting it
// applied). RefuseReadAt does the same for reads, which is how a read-modify-
// write path gets to meet a device that went away between the read and the
// write. Both record what they refused, so a case can assert on the refusal
// rather than inferring it.

import (
	"fmt"
	"sync"

	"lexa-proto/sunspec"
)

// DeviceSpec is the nameplate and scale-factor shape of a simulated DER.
//
// Every field is separately settable because the defects this package hunts live
// in the RELATIONSHIPS between them: a percentage taken against the wrong one of
// two ratings is invisible on a device where the two ratings happen to be equal,
// and most plausible fixtures make them equal by accident.
type DeviceSpec struct {
	Name string

	// Ratings (702 read-only *Rtg points).
	WMaxRtgW     float64
	VAMaxRtgVA   float64
	VarMaxInjRtg float64
	VarMaxAbsRtg float64

	// Settings (702 RW points). Zero means "leave not-implemented", which is
	// a legal device shape and the one that makes a percentage unresolvable.
	WMaxW     float64
	VAMaxVA   float64
	VarMaxInj float64
	VarMaxAbs float64

	// Scale factors the device publishes. These are the device's own choice
	// in SunSpec and a client must honour them; picking awkward ones on
	// purpose is how a scale-handling bug is provoked.
	WSF, VASF, VarSF, PctSF, PFSF, VSF, ASF, SSF int16

	// Live 701 measurement. VarNow matters because %statVarAvail is
	// resolved against the present operating point, not against a rating.
	WNow, VANow, VarNow, PFNow, HzNow, VNow float64

	// OmitVarSetPctSF publishes the not-implemented sentinel for
	// VarSetPct_SF. A device may legally do this, and the interesting
	// question is what a client's write path does when the scale factor for
	// the point it is about to write is absent.
	OmitVarSetPctSF bool

	// Omit702 builds a device with no 702 at all — nameplate unknown. Legal,
	// and the shape in which a percent-of-rated command has no resolvable
	// base.
	Omit702 bool
}

// Bench702 is an ordinary, reactive-capable inverter: 60 kW active, 26.4 kvar
// each way, the proportions sim/southbound's advanced solar server serves. It is
// the control fixture, not the interesting one.
func Bench702() DeviceSpec {
	return DeviceSpec{
		Name:         "balanced-60kW",
		WMaxRtgW:     60_000,
		WMaxW:        60_000,
		VAMaxRtgVA:   63_000,
		VAMaxVA:      63_000,
		VarMaxInjRtg: 26_400,
		VarMaxInj:    26_400,
		VarMaxAbsRtg: 26_400,
		VarMaxAbs:    26_400,
		WSF:          1, VASF: 1, VarSF: 1, PctSF: -2, PFSF: -2, VSF: -1, ASF: -1, SSF: -4,
		WNow: 42_000, VANow: 42_100, VarNow: 2_000, PFNow: 0.997, HzNow: 60, VNow: 240,
	}
}

// ReactivePoor is the configuration in which a percentage taken against the
// wrong base stops being merely wrong and becomes an overcommand: a 60 kW PV
// inverter with a 2 kvar reactive envelope. Such products exist — a
// unity-power-factor-ish string inverter with a token var capability is an
// ordinary catalogue item — and on one of them, 80 % of the ACTIVE rating
// demanded as reactive power is 24x the device's whole reactive capability.
func ReactivePoor() DeviceSpec {
	s := Bench702()
	s.Name = "reactive-poor-60kW-2kvar"
	s.VarMaxInjRtg, s.VarMaxInj = 2_000, 2_000
	s.VarMaxAbsRtg, s.VarMaxAbs = 2_000, 2_000
	s.VarSF = 0
	return s
}

// NearlyLoaded is the same 60 kW inverter running at 62 kW of apparent power
// against a 63 kVA converter: almost all of its capacity is committed to active
// power, so its AVAILABLE reactive power at this instant is about 11 kvar,
// against a 26.4 kvar rating.
//
// It exists so the %statVarAvail reference base can be told apart from the
// %setMaxVar one. On an idle machine the two are nearly equal and any confusion
// between them is invisible; on a loaded one they differ by more than a factor
// of two, and a percentage taken against the rating instead of the headroom is
// an OVERCOMMAND of the operating point rather than of the nameplate — the sort
// I1 correctly does not fail, because the nameplate is not what was exceeded.
func NearlyLoaded() DeviceSpec {
	s := Bench702()
	s.Name = "loaded-60kW-at-62kVA"
	s.WNow, s.VANow, s.VarNow = 62_000, 62_000, 500
	return s
}

// NameplateAbsent is a device that serves no 702. A percent-of-rated setpoint
// has no resolvable base on it, and both sides should say so rather than pick
// one.
func NameplateAbsent() DeviceSpec {
	s := Bench702()
	s.Name = "no-702"
	s.Omit702 = true
	return s
}

// Device is a register bank behind a modbus.Transport.
type Device struct {
	Spec DeviceSpec

	mu   sync.Mutex
	regs map[uint16]uint16
	// Bases maps model id to the 0-based address of its first DATA register.
	Bases map[uint16]uint16
	// Lens maps model id to its data length in registers.
	Lens map[uint16]uint16

	unit uint8

	refuseWrite []span
	refuseRead  []span

	// Refused records every refusal, in order, so a case asserts on what the
	// device actually rejected rather than on what the harness intended.
	Refused []string
	// Writes records every accepted write as "addr:n", in order. A control
	// path that wrote nothing and a control path that wrote and had it
	// rejected are different failures.
	Writes []string
}

type span struct{ lo, hi uint16 } // inclusive

// NewDevice builds the register image for spec.
func NewDevice(spec DeviceSpec) *Device {
	d := &Device{
		Spec:  spec,
		regs:  map[uint16]uint16{},
		Bases: map[uint16]uint16{},
		Lens:  map[uint16]uint16{},
		unit:  1,
	}
	cursor := sunspec.SunSpecBase
	d.set(cursor, sunspec.SunSMagic0)
	d.set(cursor+1, sunspec.SunSMagic1)
	cursor += 2

	cursor = d.addModel(cursor, sunspec.ModelDERMeasureAC, sunspec.L701, d.fill701)
	if !spec.Omit702 {
		cursor = d.addModel(cursor, sunspec.ModelDERCapacity, sunspec.L702, d.fill702)
	}
	cursor = d.addModel(cursor, sunspec.ModelDERCtlAC, sunspec.L704, d.fill704)

	d.set(cursor, sunspec.EndMarker)
	d.set(cursor+1, 0)
	return d
}

// addModel writes a model header and its data block, returning the next cursor.
func (d *Device) addModel(cursor, id uint16, l *sunspec.Layout, fill func(regs []uint16)) uint16 {
	n := l.Len()
	d.set(cursor, id)
	d.set(cursor+1, uint16(n))
	base := cursor + 2
	regs := make([]uint16, n)
	fill(regs)
	for i, v := range regs {
		d.set(base+uint16(i), v)
	}
	d.Bases[id] = base
	d.Lens[id] = uint16(n)
	return base + uint16(n)
}

func (d *Device) fill701(regs []uint16) {
	v := sunspec.L701.View(regs)
	setSF(regs, sunspec.L701, "W_SF", d.Spec.WSF)
	setSF(regs, sunspec.L701, "VA_SF", d.Spec.VASF)
	setSF(regs, sunspec.L701, "Var_SF", d.Spec.VarSF)
	setSF(regs, sunspec.L701, "PF_SF", d.Spec.PFSF)
	setSF(regs, sunspec.L701, "V_SF", d.Spec.VSF)
	setSF(regs, sunspec.L701, "A_SF", d.Spec.ASF)
	setSF(regs, sunspec.L701, "Hz_SF", -2)
	setSF(regs, sunspec.L701, "Tmp_SF", -1)
	setSF(regs, sunspec.L701, "TotWh_SF", 0)
	setSF(regs, sunspec.L701, "TotVarh_SF", 0)
	v.SetEnum("ACType", 1)
	v.SetEnum("St", 1)
	v.SetEnum("InvSt", 3)
	v.SetEnum("ConnSt", 1)
	v.SetFloat("W", d.Spec.WNow)
	v.SetFloat("VA", d.Spec.VANow)
	v.SetFloat("Var", d.Spec.VarNow)
	v.SetFloat("PF", d.Spec.PFNow*100)
	v.SetFloat("Hz", d.Spec.HzNow)
	v.SetFloat("LNV", d.Spec.VNow)
}

func (d *Device) fill702(regs []uint16) {
	v := sunspec.L702.View(regs)
	setSF(regs, sunspec.L702, "W_SF", d.Spec.WSF)
	setSF(regs, sunspec.L702, "VA_SF", d.Spec.VASF)
	setSF(regs, sunspec.L702, "Var_SF", d.Spec.VarSF)
	setSF(regs, sunspec.L702, "PF_SF", d.Spec.PFSF)
	setSF(regs, sunspec.L702, "V_SF", d.Spec.VSF)
	setSF(regs, sunspec.L702, "A_SF", d.Spec.ASF)
	setSF(regs, sunspec.L702, "S_SF", d.Spec.SSF)
	v.SetFloat("WMaxRtg", d.Spec.WMaxRtgW)
	v.SetFloat("VAMaxRtg", d.Spec.VAMaxRtgVA)
	v.SetFloat("VarMaxInjRtg", d.Spec.VarMaxInjRtg)
	v.SetFloat("VarMaxAbsRtg", d.Spec.VarMaxAbsRtg)
	setOrLeave(v, "WMax", d.Spec.WMaxW)
	setOrLeave(v, "VAMax", d.Spec.VAMaxVA)
	setOrLeave(v, "VarMaxInj", d.Spec.VarMaxInj)
	setOrLeave(v, "VarMaxAbs", d.Spec.VarMaxAbs)
	v.SetFloat("VNom", 240)
}

func (d *Device) fill704(regs []uint16) {
	setSF(regs, sunspec.L704, "PF_SF", d.Spec.PFSF)
	setSF(regs, sunspec.L704, "WMaxLimPct_SF", d.Spec.PctSF)
	setSF(regs, sunspec.L704, "WSet_SF", 0)
	setSF(regs, sunspec.L704, "WSetPct_SF", d.Spec.PctSF)
	setSF(regs, sunspec.L704, "VarSet_SF", 0)
	if d.Spec.OmitVarSetPctSF {
		setSFRaw(regs, sunspec.L704, "VarSetPct_SF", 0x8000)
	} else {
		setSF(regs, sunspec.L704, "VarSetPct_SF", d.Spec.PctSF)
	}
}

// setOrLeave writes a 702 setting only when the spec gave one. A zero leaves
// the register at zero, which for a Tuint16 rating reads back as a rating of
// zero rather than as "absent" — the distinction matters to the referee, and
// the caller controls it by choosing whether to set the field at all.
func setOrLeave(v sunspec.View, name string, val float64) {
	if val == 0 {
		return
	}
	v.SetFloat(name, val)
}

func setSF(regs []uint16, l *sunspec.Layout, name string, sf int16) {
	setSFRaw(regs, l, name, uint16(sf))
}

func setSFRaw(regs []uint16, l *sunspec.Layout, name string, raw uint16) {
	o := l.Offset(name)
	if o >= 0 && o < len(regs) {
		regs[o] = raw
	}
}

// RefuseWriteAt makes every write overlapping [lo,hi] answer a Modbus
// exception. Addresses are absolute (the same numbers a client puts on the
// wire), so a caller expresses "refuse the whole 704 block" as
// RefuseWriteAt(d.Block(704)).
func (d *Device) RefuseWriteAt(lo, hi uint16) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.refuseWrite = append(d.refuseWrite, span{lo, hi})
}

// RefuseReadAt makes every read overlapping [lo,hi] answer a Modbus exception.
func (d *Device) RefuseReadAt(lo, hi uint16) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.refuseRead = append(d.refuseRead, span{lo, hi})
}

// Block returns the absolute inclusive address range of a model's data block.
func (d *Device) Block(model uint16) (lo, hi uint16) {
	base, ok := d.Bases[model]
	if !ok {
		return 0, 0
	}
	return base, base + d.Lens[model] - 1
}

// Model returns a copy of a model's data registers, which is what a referee
// decodes. It never returns the live slice: a decoder that aliased the bank
// would see a write land underneath it.
func (d *Device) Model(model uint16) ([]uint16, bool) {
	base, ok := d.Bases[model]
	if !ok {
		return nil, false
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	out := make([]uint16, d.Lens[model])
	for i := range out {
		out[i] = d.regs[base+uint16(i)]
	}
	return out, true
}

// Snapshot copies the whole bank, for a before/after comparison.
func (d *Device) Snapshot() map[uint16]uint16 {
	d.mu.Lock()
	defer d.mu.Unlock()
	out := make(map[uint16]uint16, len(d.regs))
	for k, v := range d.regs {
		out[k] = v
	}
	return out
}

func (d *Device) set(addr, val uint16) { d.regs[addr] = val }

// ── modbus.Transport ─────────────────────────────────────────────────────────

// Open is a no-op: an in-memory bank is always up.
func (d *Device) Open() error { return nil }

// Close is a no-op.
func (d *Device) Close() error { return nil }

// SetUnitID records the addressed unit.
func (d *Device) SetUnitID(id uint8) error { d.unit = id; return nil }

// ReadHolding serves the bank, enforcing the Modbus per-transaction ceiling so a
// client that forgets to chunk meets the same 0x03 illegal-data-value a real
// device answers with.
func (d *Device) ReadHolding(addr, quantity uint16) ([]uint16, error) {
	if quantity == 0 || quantity > 125 {
		return nil, fmt.Errorf("device %s: illegal quantity %d (Modbus ceiling is 125)", d.Spec.Name, quantity)
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if s, hit := overlaps(d.refuseRead, addr, quantity); hit {
		msg := fmt.Sprintf("read %d+%d refused (device refuses %d..%d)", addr, quantity, s.lo, s.hi)
		d.Refused = append(d.Refused, msg)
		return nil, fmt.Errorf("device %s: modbus exception 0x04 slave device failure: %s", d.Spec.Name, msg)
	}
	out := make([]uint16, quantity)
	for i := uint16(0); i < quantity; i++ {
		out[i] = d.regs[addr+i]
	}
	return out, nil
}

// ReadInput mirrors ReadHolding; SunSpec DER models live in holding registers
// and nothing here distinguishes the two spaces.
func (d *Device) ReadInput(addr, quantity uint16) ([]uint16, error) {
	return d.ReadHolding(addr, quantity)
}

// WriteHolding applies a write unless the device is configured to refuse it. A
// refusal is total: no register in the request lands, which is what a Modbus
// exception response means and what audit OBX-01's invariant is stated against.
func (d *Device) WriteHolding(addr uint16, values []uint16) error {
	if len(values) == 0 {
		return fmt.Errorf("device %s: empty write", d.Spec.Name)
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if s, hit := overlaps(d.refuseWrite, addr, uint16(len(values))); hit {
		msg := fmt.Sprintf("write %d+%d refused (device refuses %d..%d)", addr, len(values), s.lo, s.hi)
		d.Refused = append(d.Refused, msg)
		return fmt.Errorf("device %s: modbus exception 0x02 illegal data address: %s", d.Spec.Name, msg)
	}
	for i, v := range values {
		d.regs[addr+uint16(i)] = v
	}
	d.Writes = append(d.Writes, fmt.Sprintf("%d:%d", addr, len(values)))
	return nil
}

func overlaps(spans []span, addr, n uint16) (span, bool) {
	last := addr + n - 1
	for _, s := range spans {
		if addr <= s.hi && last >= s.lo {
			return s, true
		}
	}
	return span{}, false
}
