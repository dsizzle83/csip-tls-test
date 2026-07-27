package sim

// identity_test.go — the SunSpec Model 1 (Common) block every simulated device
// serves. These are fixture-accuracy tests: a simulator that misreports its own
// identity teaches a gateway the wrong lesson, and both defects pinned here were
// found by walking the bench with a real client, not in review.
//
// The field map is lexa-proto/sunspec/identity.go's own:
// Mn(0,16) / Md(16,16) / Opt(32,8) / Vr(40,8) / SN(48,16). Every field is a
// NUL-padded string, so a write to the wrong offset never fails — it lands in a
// neighbour and leaves the real field empty. That is exactly how the serial
// ended up in Options on two of these three devices, so each field is asserted
// by NAME rather than by poking a register the writer might also have got wrong.

import (
	"fmt"
	"strings"
	"testing"

	"lexa-proto/sunspec"
)

// model1 offsets, mirroring identity.go's unexported commonMnReg.. constants.
// Transcribed rather than imported because they are package-private to
// lexa-proto; TestModel1_OffsetsMatchTheDecoder below proves the transcription
// against the real decoder rather than trusting it.
const (
	m1Mn  = 0
	m1Md  = 16
	m1Opt = 32
	m1Vr  = 40
	m1SN  = 48
	m1End = 64
)

// model1Of builds a device's register bank and returns its Model 1 data block.
// Model 1's data starts at SunSpecBase+4 — magic (2 regs) then the [ID,L]
// header (2 regs) — and every device here declares L=66.
func model1Of(t *testing.T, populate func(r *RegisterMap)) []uint16 {
	t.Helper()
	r := &RegisterMap{regs: make(map[uint16]uint16)}
	populate(r)

	const m1Data = sunspec.SunSpecBase + 4
	if got := r.Get(sunspec.SunSpecBase + 2); got != sunspec.ModelCommon {
		t.Fatalf("first model id = %d, want %d (Common) — this helper's offset assumption is stale", got, sunspec.ModelCommon)
	}
	n := int(r.Get(sunspec.SunSpecBase + 3))
	if n < m1End {
		t.Fatalf("Model 1 declares L=%d, too short to hold SN (want >= %d)", n, m1End)
	}
	regs := make([]uint16, n)
	for i := range regs {
		regs[i] = r.Get(m1Data + uint16(i))
	}
	return regs
}

// m1String decodes a fixed-length SunSpec string field: two ASCII bytes per
// register, big-endian, NUL-padded. The same decode identity.go's regString
// performs; that one is unexported, so it is reproduced here and cross-checked
// against the real thing by TestModel1_OffsetsMatchTheDecoder.
func m1String(regs []uint16, lo, hi int) string {
	b := make([]byte, 0, (hi-lo)*2)
	for _, w := range regs[lo:hi] {
		b = append(b, byte(w>>8), byte(w))
	}
	return strings.TrimRight(string(b), "\x00 ")
}

// TestModel1_EveryDeviceReportsACompleteIdentity is the fixture-accuracy
// tripwire for all three simulated device types at once.
//
// Two defects it pins:
//
//   - Vr was never written by ANY of the three sims, so each served eight NUL
//     registers where its firmware version belongs. The IEEE 1547-2018 profile
//     §3.2 Table 16 marks Vr REQUIRED, and conformance case MOD-4 step 3 failed
//     on it. A gateway mirroring one of these devices cannot paper over that —
//     a version string is a fact about the DER's firmware, not about the
//     gateway — so the only honest fix is here, in the fixture.
//
//   - The battery and meter sims wrote their SERIAL into Opt (m1+32) instead of
//     SN (m1+48), so both reported Options="SN-..." and Serial="". An empty
//     serial is not cosmetic: a gateway keying device identity on
//     manufacturer|model|serial collapses every empty-serial device onto ONE
//     identity. That is precisely the bench finding populateSolarCore records
//     for the solar sim, which was fixed then while these two were missed.
func TestModel1_EveryDeviceReportsACompleteIdentity(t *testing.T) {
	for _, tc := range []struct {
		name       string
		populate   func(r *RegisterMap)
		wantModel  string
		wantSerial string
	}{
		{
			name:       "solar",
			populate:   func(r *RegisterMap) { populateSolarCore(r, 5000, "") },
			wantModel:  "CSIP-Solar-5000",
			wantSerial: solarSerialOrDefault(""),
		},
		{
			name:       "battery",
			populate:   func(r *RegisterMap) { populateBatteryCore(r, 10, 5000) },
			wantModel:  "CSIP-Battery-10kWh",
			wantSerial: "SN-BAT-001",
		},
		{
			name:       "meter",
			populate:   func(r *RegisterMap) { populateMeter(r, 0) },
			wantModel:  "CSIP-Meter-1Ph",
			wantSerial: "SN-MTR-001",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			regs := model1Of(t, tc.populate)

			if got := m1String(regs, m1Mn, m1Md); got != "SunSpec Sim" {
				t.Errorf("Mn = %q, want %q", got, "SunSpec Sim")
			}
			// Md is SIXTEEN registers (32 chars). Writing it through an
			// 8-register helper silently truncated "CSIP-Battery-10kWh".
			if got := m1String(regs, m1Md, m1Opt); got != tc.wantModel {
				t.Errorf("Md = %q, want %q — a truncated model string means Md was written with an 8-register helper", got, tc.wantModel)
			}
			// The field that collides gateway identity keys when empty.
			if got := m1String(regs, m1SN, m1End); got != tc.wantSerial {
				t.Errorf("SN = %q, want %q — an EMPTY serial collapses this device onto the same "+
					"manufacturer|model|serial identity as every other empty-serial sim", got, tc.wantSerial)
			}
			// Vr: required by the profile, and unforgeable downstream.
			if got := m1String(regs, m1Vr, m1SN); got == "" {
				t.Error("Vr is empty — IEEE 1547-2018 profile §3.2 Table 16 requires it, and no downstream " +
					"gateway may fabricate a DER's firmware version, so it can only be fixed in this fixture")
			}
			// A serial appearing in Opt is the signature of a write aimed at
			// m1+32 instead of m1+48 — the exact defect above.
			if got := m1String(regs, m1Opt, m1Vr); got != "" {
				t.Errorf("Opt = %q, want empty — these sims advertise no options string, and a serial here "+
					"is the signature of a write aimed at m1+32 (Opt) instead of m1+48 (SN)", got)
			}
		})
	}
}

// TestModel1_OffsetsMatchTheDecoder proves this file's transcribed offsets and
// its local string decoder against lexa-proto's REAL ReadCommon, so a layout
// change in lexa-proto cannot leave the assertions above quietly checking the
// wrong registers. It drives ReadCommon over the sim's own register map through
// an in-process transport — the same decode path a gateway runs.
func TestModel1_OffsetsMatchTheDecoder(t *testing.T) {
	r := &RegisterMap{regs: make(map[uint16]uint16)}
	// populateSolar, NOT populateSolarCore: the Core variant deliberately leaves
	// the end marker to its caller, and lexa-proto's model walker does not
	// terminate on an unterminated chain (see
	// TestSunSpecScan_WalksAnUnterminatedChainWithoutBound).
	populateSolar(r, 5000, "SN-XCHECK-9")

	reader, err := sunspec.NewReader(&regMapTransport{r: r})
	if err != nil {
		t.Fatalf("NewReader over the sim register map: %v", err)
	}
	c, err := sunspec.ReadCommon(reader)
	if err != nil {
		t.Fatalf("ReadCommon: %v", err)
	}

	regs := model1Of(t, func(rr *RegisterMap) { populateSolarCore(rr, 5000, "SN-XCHECK-9") })
	for _, f := range []struct {
		name    string
		local   string
		decoded string
	}{
		{"Mn", m1String(regs, m1Mn, m1Md), c.Manufacturer},
		{"Md", m1String(regs, m1Md, m1Opt), c.Model},
		{"Opt", m1String(regs, m1Opt, m1Vr), c.Options},
		{"Vr", m1String(regs, m1Vr, m1SN), c.Version},
		{"SN", m1String(regs, m1SN, m1End), c.Serial},
	} {
		if f.local != f.decoded {
			t.Errorf("%s: this file decodes %q, lexa-proto's ReadCommon decodes %q — the transcribed "+
				"offsets in identity_test.go are stale", f.name, f.local, f.decoded)
		}
	}
	if c.Version == "" {
		t.Error("ReadCommon sees an empty Vr — the value a gateway actually reads is still unset")
	}
}

// TestSunSpecScan_WalksAnUnterminatedChainWithoutBound PINS A DEFECT IN
// lexa-proto, found by accident and worth a permanent probe.
//
// lexa-proto/sunspec's scanModels walks the model chain with `for { ... cursor
// += 2 + length }` and leaves it only on the 0xFFFF end marker or a transport
// error. There is no iteration cap, no bound on cursor, and no check that the
// walk is making progress. A device that answers reads but never presents an
// end marker — because its chain was truncated, because a "firmware update"
// moved the marker out of the region the walker reaches, or because it simply
// returns zeros for unmapped registers, which is a perfectly ordinary Modbus
// implementation — is walked forever. cursor is a uint16, so it wraps at 65536
// and the walk begins again, issuing two-register reads at the device for as
// long as the process lives.
//
// This is I8's shape exactly: unbounded work driven entirely by what a peer
// says, on the FIRST thing that happens to any southbound device. It is
// reachable from every fault in lying.go that touches the chain, and it was
// found here because a fixture built without the end marker hung this package's
// tests for the full 110-second timeout rather than failing.
//
// The probe is bounded from the OUTSIDE: the transport itself refuses after
// scanCapReads, so the test terminates whatever the walker does. The assertion
// is that the walker went all the way to that cap — i.e. that nothing inside it
// stopped the walk. WHEN LEXA-PROTO GROWS A BOUND, THIS TEST WILL FAIL, and the
// correct response is to assert the new bound here rather than to delete it.
func TestSunSpecScan_WalksAnUnterminatedChainWithoutBound(t *testing.T) {
	r := &RegisterMap{regs: make(map[uint16]uint16)}
	populateSolarCore(r, 5000, "SN-UNTERMINATED") // no end marker, on purpose
	tr := &cappedTransport{regMapTransport: regMapTransport{r: r}, cap: scanCapReads}

	_, err := sunspec.Scan(tr)
	if err == nil {
		t.Fatal("the walk terminated on its own over an UNTERMINATED chain — either lexa-proto grew a " +
			"bound (good: assert it here) or this fixture now has an end marker (bad: the probe is dead)")
	}
	if tr.reads < scanCapReads {
		t.Fatalf("the walker stopped after %d reads, below the transport's cap of %d — it now has a bound "+
			"of its own; assert THAT bound here instead of this one", tr.reads, scanCapReads)
	}
	t.Logf("FINDING: lexa-proto/sunspec.scanModels issued %d reads against an unterminated chain and was "+
		"still walking; only the test's own cap stopped it (uint16 cursor wraps at 65536 → forever)", tr.reads)
}

// scanCapReads bounds the probe above. It is comfortably past any legitimate
// chain (a real device has tens of models, not thousands) and small enough that
// the test runs in milliseconds.
const scanCapReads = 20000

// cappedTransport is regMapTransport with a read budget, so a walker with no
// termination bound of its own is still stopped by something.
type cappedTransport struct {
	regMapTransport
	cap   int
	reads int
}

func (t *cappedTransport) ReadHolding(addr, qty uint16) ([]uint16, error) {
	t.reads++
	if t.reads >= t.cap {
		return nil, fmt.Errorf("probe cap: %d reads without reaching an end marker", t.reads)
	}
	return t.regMapTransport.ReadHolding(addr, qty)
}

// regMapTransport adapts a RegisterMap to modbus.Transport so lexa-proto's own
// Reader/ReadCommon can be driven in-process, with no listener and no socket.
type regMapTransport struct{ r *RegisterMap }

func (t *regMapTransport) Open() error           { return nil }
func (t *regMapTransport) Close() error          { return nil }
func (t *regMapTransport) SetUnitID(uint8) error { return nil }
func (t *regMapTransport) ReadHolding(addr, qty uint16) ([]uint16, error) {
	out := make([]uint16, qty)
	for i := uint16(0); i < qty; i++ {
		out[i] = t.r.Get(addr + i)
	}
	return out, nil
}
func (t *regMapTransport) WriteHolding(uint16, []uint16) error { return nil }

// ReadInput is never exercised: SunSpec device discovery reads HOLDING
// registers only, and this adapter exists purely to satisfy the interface.
func (t *regMapTransport) ReadInput(addr, qty uint16) ([]uint16, error) {
	return t.ReadHolding(addr, qty)
}
