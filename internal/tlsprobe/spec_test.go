package tlsprobe

// spec_test.go proves the parts of the probe that hold with no socket in sight:
// the transcribed suite tables, the offer the Spec resolves to, and the
// response validation every Modbus assertion downstream rests on.

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"csip-tls-test/internal/mbtls"
)

// TestMandatedSuitesMatchTheDocumentsTables holds the transcription against the
// document, codepoint by codepoint.
//
// The values are re-typed here rather than referenced from suites.go, which is
// the whole point: two independent transcriptions of SSM-CONF-v0.8 §2.4.1
// Table 1 and §2.4.2 Table 2 that disagree are a transcription error caught at
// test time rather than a probe that offers one suite and cites another.
func TestMandatedSuitesMatchTheDocumentsTables(t *testing.T) {
	want12 := []struct {
		code uint16
		iana string
	}{
		{0xC02B, "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"},
		{0xCCA9, "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256"},
		{0xC0AE, "TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8"},
	}
	want13 := []struct {
		code uint16
		iana string
	}{
		{0x1301, "TLS_AES_128_GCM_SHA256"},
		{0x1303, "TLS_CHACHA20_POLY1305_SHA256"},
		{0x1304, "TLS_AES_128_CCM_SHA256"},
	}
	check := func(label string, got []Suite, want []struct {
		code uint16
		iana string
	}, version Version) {
		t.Helper()
		if len(got) != len(want) {
			t.Fatalf("%s: %d suite(s), want %d", label, len(got), len(want))
		}
		for i := range want {
			if got[i].Code != want[i].code || got[i].IANA != want[i].iana {
				t.Errorf("%s[%d] = 0x%04X %s, want 0x%04X %s (the document's order is normative — "+
					"SunSpecTCP-19)", label, i, got[i].Code, got[i].IANA, want[i].code, want[i].iana)
			}
			if got[i].Version != version {
				t.Errorf("%s[%d] is declared %s, want %s", label, i, got[i].Version, version)
			}
			if got[i].Wolf == "" {
				t.Errorf("%s[%d] (0x%04X) has no wolfSSL name, so it cannot be offered",
					label, i, got[i].Code)
			}
		}
	}
	check("Mandatory12", Mandatory12, want12, TLS12)
	check("Mandatory13", Mandatory13, want13, TLS13)
}

// TestWolfNamesAgreeWithTheBenchsOwnProfile keeps this package's wolfSSL suite
// names from drifting away from internal/mbtls's, which the device sim and the
// aggregator emulator offer. The two are deliberately separate transcriptions
// (see the package doc); separate is only useful while they still name the same
// six suites.
func TestWolfNamesAgreeWithTheBenchsOwnProfile(t *testing.T) {
	got12 := make([]string, len(Mandatory12))
	for i, s := range Mandatory12 {
		got12[i] = s.Wolf
	}
	got13 := make([]string, len(Mandatory13))
	for i, s := range Mandatory13 {
		got13[i] = s.Wolf
	}
	if strings.Join(got12, ":") != strings.Join(mbtls.Mandated12, ":") {
		t.Errorf("TLS 1.2 wolfSSL names %v disagree with internal/mbtls.Mandated12 %v",
			got12, mbtls.Mandated12)
	}
	if strings.Join(got13, ":") != strings.Join(mbtls.Mandated13, ":") {
		t.Errorf("TLS 1.3 wolfSSL names %v disagree with internal/mbtls.Mandated13 %v",
			got13, mbtls.Mandated13)
	}
}

// TestCCMSuitesAreTheOnesGoCannotComplete names the reason this package exists,
// so a future reader can check the claim rather than take it.
func TestCCMSuitesAreTheOnesGoCannotComplete(t *testing.T) {
	want := map[uint16]bool{0xC0AE: true, 0x1304: true}
	if len(CCMSuites) != len(want) {
		t.Fatalf("CCMSuites has %d entries, want %d", len(CCMSuites), len(want))
	}
	for _, s := range CCMSuites {
		if !want[s.Code] {
			t.Errorf("CCMSuites contains 0x%04X %s, which is not one of the mandated AES-CCM suites",
				s.Code, s.IANA)
		}
		if !strings.Contains(s.IANA, "CCM") {
			t.Errorf("0x%04X %s is in CCMSuites but its IANA name does not name CCM", s.Code, s.IANA)
		}
	}
}

// TestAPinnedSuitePinsItsVersion is the property that makes "offering only
// TLS_AES_128_CCM_SHA256" a carried-out procedure step rather than an
// aspiration: a 1.3 suite offered inside a 1.2..1.3 range would let the DUT
// answer at 1.2 with something else entirely.
func TestAPinnedSuitePinsItsVersion(t *testing.T) {
	for _, s := range append(append([]Suite{}, Mandatory12...), Mandatory13...) {
		spec := Spec{Suite: s}
		minV, maxV, err := spec.versionRange()
		if err != nil {
			t.Fatalf("%s: %v", s, err)
		}
		if minV != s.Version || maxV != s.Version {
			t.Errorf("%s resolved to %s..%s, want %s..%s", s, minV, maxV, s.Version, s.Version)
		}
		list, offered := spec.offer()
		if list != s.Wolf || len(offered) != 1 || offered[0].Code != s.Code {
			t.Errorf("%s resolved to offer %q (%d suite(s)), want exactly %q", s, list, len(offered), s.Wolf)
		}
	}
}

// TestTheUnpinnedOfferPutsTLS13First is a wolfSSL 5.7.6 requirement, not a
// preference: on a mixed 1.2..1.3 cipher list it negotiates TLS 1.3 only when a
// 1.3 suite leads.
func TestTheUnpinnedOfferPutsTLS13First(t *testing.T) {
	list, offered := Spec{}.offer()
	if len(offered) != 6 {
		t.Fatalf("the unpinned offer carries %d suite(s), want all six mandated", len(offered))
	}
	for i, s := range offered[:3] {
		if s.Version != TLS13 {
			t.Fatalf("offer[%d] is %s, a %s suite; every TLS 1.3 suite must precede the TLS 1.2 suites "+
				"or wolfSSL will not negotiate TLS 1.3 at all", i, s, s.Version)
		}
	}
	if !strings.HasPrefix(list, TLS13GCM.Wolf) {
		t.Errorf("the cipher list %q does not lead with a TLS 1.3 suite", list)
	}
}

func TestVersionRangeRefusesWhatCannotBeNegotiated(t *testing.T) {
	cases := map[string]Spec{
		"a 1.3 suite in a 1.2-only range": {MinVersion: TLS12, MaxVersion: TLS12, Suite: TLS13CCM},
		"a 1.2 suite in a 1.3-only range": {MinVersion: TLS13, MaxVersion: TLS13, Suite: TLS12CCM8},
	}
	for name, spec := range cases {
		spec.Target = "127.0.0.1:1"
		spec.CAFiles = []string{"/dev/null"}
		spec.CertFile, spec.KeyFile = "/dev/null", "/dev/null"
		err := spec.validate()
		if err == nil {
			t.Errorf("%s: accepted, want refused before a socket is opened", name)
			continue
		}
		if !strings.Contains(err.Error(), "could never be negotiated") {
			t.Errorf("%s: %v — the error does not say why the offer is impossible", name, err)
		}
	}
}

func TestValidateNamesEveryProblemAtOnce(t *testing.T) {
	err := Spec{}.validate()
	if err == nil {
		t.Fatal("an empty Spec validated")
	}
	for _, want := range []string{"Target is empty", "CAFiles is empty", "CertFile and KeyFile"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the error does not mention %q:\n%v", want, err)
		}
	}
}

func TestValidateAcceptsARealFixtureSet(t *testing.T) {
	dir := t.TempDir()
	for _, n := range []string{"ca.pem", "cert.pem", "key.pem"} {
		if err := os.WriteFile(filepath.Join(dir, n), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	spec := Spec{
		Target:   "127.0.0.1:802",
		CAFiles:  []string{filepath.Join(dir, "ca.pem")},
		CertFile: filepath.Join(dir, "cert.pem"),
		KeyFile:  filepath.Join(dir, "key.pem"),
		Suite:    TLS12CCM8,
	}
	if err := spec.validate(); err != nil {
		t.Fatalf("a complete Spec was refused: %v", err)
	}
}

// ── the response validation every Modbus assertion rests on ─────────────────

// adu assembles an MBAP frame from its parts so a test can state a defect
// exactly rather than hand-editing a byte slice.
func adu(tid uint16, unit byte, pdu []byte) []byte {
	out := make([]byte, 7+len(pdu))
	binary.BigEndian.PutUint16(out[0:2], tid)
	binary.BigEndian.PutUint16(out[2:4], 0)
	binary.BigEndian.PutUint16(out[4:6], uint16(len(pdu)+1))
	out[6] = unit
	copy(out[7:], pdu)
	return out
}

func TestRegistersCatchesEveryHeaderDefectSeparately(t *testing.T) {
	good := adu(7, 1, []byte{0x03, 0x04, 0x53, 0x75, 0x6E, 0x53})
	cases := []struct {
		name string
		resp []byte
		want string
	}{
		{"a conformant answer", good, ""},
		{"wrong transaction id", adu(8, 1, []byte{0x03, 0x04, 0, 0, 0, 0}), "Transaction ID"},
		{"wrong unit id", adu(7, 2, []byte{0x03, 0x04, 0, 0, 0, 0}), "Unit ID"},
		{"a modbus exception", adu(7, 1, []byte{0x83, 0x02}), "exception 2"},
		{"the wrong function code", adu(7, 1, []byte{0x04, 0x04, 0, 0, 0, 0}), "function code"},
		{"a byte count that is not the register count", adu(7, 1, []byte{0x03, 0x02, 0, 0}), "byte count"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Registers(Exchange{Response: tc.resp}, 7, 1, 2)
			switch {
			case tc.want == "" && err != nil:
				t.Fatalf("a conformant answer was rejected: %v", err)
			case tc.want == "":
				return
			case err == nil:
				t.Fatalf("accepted a response with %s", tc.name)
			case !strings.Contains(err.Error(), tc.want):
				t.Errorf("%v — the error does not name the defect (%q)", err, tc.want)
			}
		})
	}
}

func TestRegistersRefusesAProtocolIDOtherThanZero(t *testing.T) {
	resp := adu(7, 1, []byte{0x03, 0x04, 0, 0, 0, 0})
	binary.BigEndian.PutUint16(resp[2:4], 1)
	if _, err := Registers(Exchange{Response: resp}, 7, 1, 2); err == nil ||
		!strings.Contains(err.Error(), "Protocol ID") {
		t.Errorf("Protocol ID 0x0001 accepted (%v)", err)
	}
}

func TestRegistersRefusesALengthFieldThatDoesNotMatchTheFrame(t *testing.T) {
	resp := adu(7, 1, []byte{0x03, 0x04, 0, 0, 0, 0})
	binary.BigEndian.PutUint16(resp[4:6], 99)
	if _, err := Registers(Exchange{Response: resp}, 7, 1, 2); err == nil ||
		!strings.Contains(err.Error(), "Length field") {
		t.Errorf("a Length field that contradicts the frame was accepted (%v)", err)
	}
}

func TestModelReadSummarySaysWhichDeviceAnswered(t *testing.T) {
	values := make([]uint16, 66)
	copy(values[0:], regsOf("SunSpec Sim"))
	copy(values[16:], regsOf("CSIP-Solar-5000"))
	copy(values[48:], regsOf("BENCH-MODSIM-01"))
	m := ModelRead{Attempted: true, Unit: 1, Base: 40000, Length: 66, Values: values,
		Read: Exchange{Response: make([]byte, 139)}}
	got := m.Summary()
	for _, want := range []string{"unit 1", "40004", "Mn SunSpec Sim", "Md CSIP-Solar-5000", "SN BENCH-MODSIM-01"} {
		if !strings.Contains(got, want) {
			t.Errorf("the summary does not carry %q:\n%s", want, got)
		}
	}
}

func regsOf(s string) []uint16 {
	b := []byte(s)
	out := make([]uint16, (len(b)+1)/2)
	for i := range out {
		hi := b[2*i]
		var lo byte
		if 2*i+1 < len(b) {
			lo = b[2*i+1]
		}
		out[i] = uint16(hi)<<8 | uint16(lo)
	}
	return out
}
