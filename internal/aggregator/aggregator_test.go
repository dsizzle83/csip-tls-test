package aggregator

// Unit tests for the pure-Go surface of the emulator core: PKI/manifest
// resolution, ConnectAs guard rails (no handshake reached), scale-factor-correct
// point encoding, NaN-safe telemetry, and JSON-serializable run state. These run
// under `make test-fast` (they compile cgo transitively via mbtls but drive no
// wolfSSL handshake, so wolfssl.Init is not needed). The loopback handshake
// proof lives in the integration-tagged test.

import (
	"encoding/json"
	"math"
	"path/filepath"
	"strings"
	"testing"

	"lexa-proto/sunspec"
)

func TestRoles_FiveDistinct(t *testing.T) {
	rs := Roles()
	if len(rs) != 5 {
		t.Fatalf("Roles() = %d, want 5", len(rs))
	}
	seen := map[Role]bool{}
	for _, r := range rs {
		if seen[r] {
			t.Errorf("duplicate role %q", r)
		}
		seen[r] = true
	}
	for _, want := range []Role{RoleGridService, RoleSuperAdmin, RoleNetworkAdmin, RoleReadOnly, RoleLexaVolt} {
		if !seen[want] {
			t.Errorf("Roles() missing %q", want)
		}
	}
}

func TestLoadPKI_ResolvesRolesAndServerCA(t *testing.T) {
	pki := newTestPKI(t)
	refs, err := LoadPKI(pki.dir)
	if err != nil {
		t.Fatalf("LoadPKI: %v", err)
	}
	wantCA := filepath.Join(pki.dir, "ca-cert.pem")
	if refs.ServerCA != wantCA {
		t.Errorf("ServerCA = %q, want %q (manifest device.ca resolved)", refs.ServerCA, wantCA)
	}
	for _, r := range Roles() {
		cred, ok := refs.Cred(r)
		if !ok {
			t.Errorf("role %q missing from PKI refs", r)
			continue
		}
		if !filepath.IsAbs(cred.CertFile) || !filepath.IsAbs(cred.KeyFile) {
			t.Errorf("role %q paths not resolved absolute: %+v", r, cred)
		}
	}
}

func TestLoadPKI_MissingManifest(t *testing.T) {
	if _, err := LoadPKI(t.TempDir()); err == nil {
		t.Fatal("LoadPKI on a dir with no manifest.json should error")
	}
}

func TestConnectAs_UnknownRoleNoDial(t *testing.T) {
	refs := newTestPKI(t).refs(t)
	// A role with no credential must fail before any socket is opened; the addr
	// is a black hole so a bug that dials anyway would hang/refuse, not pass.
	if _, err := ConnectAs("203.0.113.1:1", Role("BogusRole"), refs); err == nil {
		t.Fatal("ConnectAs with an unregistered role should error before dialing")
	}
}

func TestConnectAs_NoServerCANoDial(t *testing.T) {
	refs := newTestPKI(t).refs(t)
	refs.ServerCA = ""
	if _, err := ConnectAs("203.0.113.1:1", RoleGridService, refs); err == nil {
		t.Fatal("ConnectAs with empty ServerCA should error before dialing")
	}
}

func TestConnectAs_RoleSelfCheckMismatch(t *testing.T) {
	pki := newTestPKI(t)
	refs := pki.refs(t)
	// Point the GridService slot at the ReadOnly certificate: the independent
	// role self-check (mbtls.RoleFromDER, PN-1) must catch the mismatch before
	// dialing, so a mis-wired manifest never presents the wrong identity.
	roCred, _ := refs.Cred(RoleReadOnly)
	refs.SetCred(RoleGridService, roCred)
	_, err := ConnectAs("203.0.113.1:1", RoleGridService, refs)
	if err == nil {
		t.Fatal("ConnectAs should reject a cert whose role does not match the requested role")
	}
	if !strings.Contains(err.Error(), "carries role") {
		t.Errorf("error = %v, want a role-mismatch (PKI wiring) error", err)
	}
}

func TestFieldRegs(t *testing.T) {
	cases := []struct {
		name string
		f    sunspec.Field
		want int
	}{
		{"uint16", sunspec.Field{Type: sunspec.Tuint16}, 1},
		{"int16", sunspec.Field{Type: sunspec.Tint16}, 1},
		{"enum16", sunspec.Field{Type: sunspec.Tenum16}, 1},
		{"sunssf", sunspec.Field{Type: sunspec.Tsunssf}, 1},
		{"uint32", sunspec.Field{Type: sunspec.Tuint32}, 2},
		{"int32", sunspec.Field{Type: sunspec.Tint32}, 2},
		{"bitfield32", sunspec.Field{Type: sunspec.Tbitfield32}, 2},
		{"uint64", sunspec.Field{Type: sunspec.Tuint64}, 4},
		{"string8", sunspec.Field{Type: sunspec.Tstring, Len: 8}, 8},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := fieldRegs(tc.f); got != tc.want {
				t.Errorf("fieldRegs(%s) = %d, want %d", tc.name, got, tc.want)
			}
		})
	}
}

func TestLayoutFor(t *testing.T) {
	for _, m := range []uint16{701, 702, 703, 704, 713} {
		if _, err := layoutFor(m); err != nil {
			t.Errorf("layoutFor(%d) errored: %v", m, err)
		}
	}
	// A curve model (repeating sub-groups) has no fixed-shape layout for the
	// point-addressed writer.
	if _, err := layoutFor(705); err == nil {
		t.Error("layoutFor(705) should error (curve model, not point-addressable)")
	}
}

// TestSetPoint_ScaleFactorNoRawCast proves the typed-write encoding path applies
// the point's scale factor and never raw-casts — the register-wrap invariant
// (CODING_PRINCIPLES §3, audit GS-1/MTR-1). A 50% WMaxLimPct at SF=-2 must
// encode to raw 5000, and the enable enum takes its integer value verbatim.
func TestSetPoint_ScaleFactorNoRawCast(t *testing.T) {
	regs := make([]uint16, sunspec.L704.Len())
	view := sunspec.L704.View(regs)
	// SF = -2 (register × 0.01), as populate704 configures the sim. A variable
	// conversion carries the two's-complement bits (0xFFFE) a constant cannot.
	sfM2 := int16(-2)
	view.SetEnum("WMaxLimPct_SF", uint16(sfM2))

	f, _, err := fieldFor(sunspec.L704, "WMaxLimPct")
	if err != nil {
		t.Fatalf("fieldFor: %v", err)
	}
	if err := setPoint(view, f, "WMaxLimPct", 50); err != nil {
		t.Fatalf("setPoint scaled: %v", err)
	}
	off := sunspec.L704.Offset("WMaxLimPct")
	if got := regs[off]; got != 5000 {
		t.Errorf("WMaxLimPct raw = %d, want 5000 (50%% at SF=-2, scale-encoded not raw-cast)", got)
	}
	if back := view.Float("WMaxLimPct"); math.Abs(back-50) > 1e-9 {
		t.Errorf("round-trip WMaxLimPct = %v, want 50", back)
	}

	ef, _, err := fieldFor(sunspec.L704, "WMaxLimPctEna")
	if err != nil {
		t.Fatalf("fieldFor ena: %v", err)
	}
	if err := setPoint(view, ef, "WMaxLimPctEna", 1); err != nil {
		t.Fatalf("setPoint enum: %v", err)
	}
	if got := regs[sunspec.L704.Offset("WMaxLimPctEna")]; got != 1 {
		t.Errorf("WMaxLimPctEna raw = %d, want 1", got)
	}
}

func TestSetPoint_UnsupportedType(t *testing.T) {
	// MnAlrmInfo is a string field — not writable via the numeric setter.
	f, _, err := fieldFor(sunspec.L701, "MnAlrmInfo")
	if err != nil {
		t.Fatalf("fieldFor: %v", err)
	}
	regs := make([]uint16, sunspec.L701.Len())
	if err := setPoint(sunspec.L701.View(regs), f, "MnAlrmInfo", 1); err == nil {
		t.Error("setPoint on a string field should error")
	}
}

func TestMeasPoints_DropsNaN(t *testing.T) {
	m := sunspec.ACMeasurement{
		W:  5000,
		VA: math.NaN(), // unimplemented → must be omitted, never emitted as NaN
		Hz: 60,
		PF: math.NaN(),
	}
	pts := measPoints(m)
	if _, ok := pts["W"]; !ok {
		t.Error("W should be present")
	}
	if _, ok := pts["Hz"]; !ok {
		t.Error("Hz should be present")
	}
	if _, ok := pts["VA"]; ok {
		t.Error("VA is NaN and must be omitted (NaN never crosses the wire)")
	}
	if _, ok := pts["PF"]; ok {
		t.Error("PF is NaN and must be omitted")
	}
}

// TestRunState_JSONRoundTrip proves the run state marshals cleanly (no NaN) and
// carries the versioned schema plus every observation family.
func TestRunState_JSONRoundTrip(t *testing.T) {
	rs := NewRunState("gw.example:802", RoleGridService)
	rs.SetSession(SessionInfo{Role: RoleGridService, Asserted: "GridServiceSunSpec", Cipher: "ECDHE-ECDSA-AES128-GCM-SHA256", TLSVersion: "TLSv1.3", Connected: true})
	rs.AddDevices([]Device{{Unit: 2, Identity: sunspec.Common{Manufacturer: "LEXA", Serial: "SN1"}, Models: []uint16{1, 701, 704}}})
	rs.AddSample(Snapshot{Unit: 2, Model: 701, Points: map[string]float64{"W": 5000, "Hz": 60}, ConnSt: 1})
	rs.AddWrite(WriteRecord{Unit: 2, Model: 704, Point: "WMaxLimPct", Value: 50, OK: true, LatencyMS: 12})
	rs.AddDenial(DenialResult{Unit: 2, Model: 704, Point: "WMaxLimPct", Denied: true, ExceptionCode: 1, FC: 0x10, Stage: "write"})

	raw, err := json.Marshal(rs)
	if err != nil {
		t.Fatalf("marshal run state: %v", err)
	}

	var back RunState
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatalf("unmarshal run state: %v", err)
	}
	if back.RunV != RunStateV {
		t.Errorf("RunV = %d, want %d", back.RunV, RunStateV)
	}
	if back.Role != RoleGridService || len(back.Devices) != 1 || len(back.Samples) != 1 ||
		len(back.Writes) != 1 || len(back.Denials) != 1 {
		t.Errorf("run state round-trip lost data: role=%q devices=%d samples=%d writes=%d denials=%d",
			back.Role, len(back.Devices), len(back.Samples), len(back.Writes), len(back.Denials))
	}
	if !back.Denials[0].Denied || back.Denials[0].ExceptionCode != 1 {
		t.Errorf("denial round-trip wrong: %+v", back.Denials[0])
	}
}

// TestRunState_PublishSink proves a RunState is a valid SnapshotSink.
func TestRunState_PublishSink(t *testing.T) {
	var sink SnapshotSink = NewRunState("t", RoleReadOnly)
	sink.Publish(Snapshot{Unit: 3, Model: 701})
	rs := sink.(*RunState)
	if len(rs.Samples) != 1 || rs.Samples[0].Unit != 3 {
		t.Errorf("Publish did not record the sample: %+v", rs.Samples)
	}
}
