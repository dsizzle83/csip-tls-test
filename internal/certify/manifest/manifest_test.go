package manifest

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// valid is the shape LAB29-003 specifies, verbatim. Every test below starts
// from it, so a change to the product's manifest shows up here as one edit
// rather than as fifteen.
const valid = `{
  "profile": "one-to-one-7xx-tcp",
  "topology": {"configured_der": 1, "role": "inverter", "northbound_units": [1]},
  "csip": {"role": "der-client", "end_devices": 1, "der_resources": 1},
  "secure_sunspec": {"roles": ["server"], "transport": "tls-tcp", "port": 802},
  "modbus_client": {"transport": "tcp", "device_count": 1, "generation": "7xx"},
  "authority_profiles": ["csip", "mbaps"],
  "models": [1, 701, 702, 703, 704, 705, 706, 707, 708, 709, 710, 711, 712]
}`

func mustParse(t *testing.T, body string) *Manifest {
	t.Helper()
	m, err := Parse([]byte(body), "candidate.json")
	if err != nil {
		t.Fatalf("Parse() = %v, want a valid manifest", err)
	}
	return m
}

func TestParseTheSpecifiedShape(t *testing.T) {
	m := mustParse(t, valid)
	if m.Profile != "one-to-one-7xx-tcp" {
		t.Errorf("Profile = %q", m.Profile)
	}
	if m.ConfiguredDER != 1 || m.Role != "inverter" || len(m.NorthboundUnits) != 1 || m.NorthboundUnits[0] != 1 {
		t.Errorf("Topology = %+v", m.Topology)
	}
	if m.CSIP.Role != "der-client" || m.CSIP.EndDevices != 1 || m.CSIP.DERResources != 1 {
		t.Errorf("CSIP = %+v", m.CSIP)
	}
	if !m.SecureSunSpec.HasRole("server") || m.SecureSunSpec.HasRole("client") {
		t.Errorf("SecureSunSpec.Roles = %v, want server only", m.SecureSunSpec.Roles)
	}
	if m.SecureSunSpec.Port != 802 || m.SecureSunSpec.Transport != "tls-tcp" {
		t.Errorf("SecureSunSpec = %+v", m.SecureSunSpec)
	}
	if m.ModbusClient.Transport != "tcp" || m.ModbusClient.DeviceCount != 1 || m.ModbusClient.Generation != "7xx" {
		t.Errorf("ModbusClient = %+v", m.ModbusClient)
	}
	if !m.ClaimsAuthority("csip") || !m.ClaimsAuthority("mbaps") || m.ClaimsAuthority("local") {
		t.Errorf("AuthorityProfiles = %v", m.AuthorityProfiles)
	}
	if !m.HasModel(712) || m.HasModel(802) {
		t.Errorf("Models = %v", m.Models)
	}
	if len(m.SHA256()) != 64 {
		t.Errorf("SHA256() = %q, want a hex digest a bundle can record", m.SHA256())
	}
	if m.Size() != len(valid) {
		t.Errorf("Size() = %d, want %d", m.Size(), len(valid))
	}
}

// STRICT: an unknown key is an error, on the catalog loader's reasoning. A
// manifest carrying a field this harness does not model is one whose meaning it
// cannot fully represent.
func TestParseRejectsAnUnknownField(t *testing.T) {
	body := strings.Replace(valid, `"profile":`, `"profil3":`, 1)
	_, err := Parse([]byte(body), "candidate.json")
	if err == nil {
		t.Fatal("Parse() accepted an unknown field")
	}
	if !strings.Contains(err.Error(), "profil3") {
		t.Errorf("error does not name the offending key:\n%v", err)
	}
}

// TOLERANT: every problem at once, not one per edit-and-retry cycle.
func TestParseReportsEveryProblemTogether(t *testing.T) {
	_, err := Parse([]byte(`{"profile": "p"}`), "candidate.json")
	var inv *InvalidError
	if !errors.As(err, &inv) {
		t.Fatalf("Parse() = %v, want an *InvalidError", err)
	}
	for _, want := range []string{"topology", "csip", "secure_sunspec", "modbus_client",
		"authority_profiles", "models"} {
		found := false
		for _, p := range inv.Problems {
			if strings.HasPrefix(p, want) {
				found = true
			}
		}
		if !found {
			t.Errorf("the report does not name %q as missing; it has: %v", want, inv.Problems)
		}
	}
}

// An absent key must never decode to a declaration of its zero value: "no DERs"
// and "did not say" are different claims and only one of them is a claim.
func TestParseDistinguishesAbsentFromZero(t *testing.T) {
	missing := strings.Replace(valid,
		`"topology": {"configured_der": 1, "role": "inverter", "northbound_units": [1]}`,
		`"topology": {"role": "inverter", "northbound_units": [1]}`, 1)
	_, err := Parse([]byte(missing), "candidate.json")
	if err == nil {
		t.Fatal("Parse() accepted a manifest with no topology.configured_der")
	}
	if !strings.Contains(err.Error(), "configured_der is missing") {
		t.Errorf("error does not say the field is MISSING:\n%v", err)
	}
	// And an explicit zero is a different (also refused, but differently
	// worded) problem — reqInt's minimum, not reqInt's absence.
	zero := strings.Replace(valid, `"configured_der": 1`, `"configured_der": 0`, 1)
	if _, err := Parse([]byte(zero), "candidate.json"); err != nil {
		t.Errorf("Parse() = %v; configured_der:0 is a legal declaration for the reader (the coherence "+
			"checks below are what object to it in context)", err)
	}
}

func TestParseRejectsAnOutOfVocabularyValue(t *testing.T) {
	cases := map[string]string{
		"topology.role":            strings.Replace(valid, `"role": "inverter"`, `"role": "turbine"`, 1),
		"csip.role":                strings.Replace(valid, `"role": "der-client"`, `"role": "utility"`, 1),
		"secure_sunspec.roles":     strings.Replace(valid, `"roles": ["server"]`, `"roles": ["proxy"]`, 1),
		"secure_sunspec.transport": strings.Replace(valid, `"transport": "tls-tcp"`, `"transport": "dtls"`, 1),
		"modbus_client.transport":  strings.Replace(valid, `"transport": "tcp",`, `"transport": "carrier-pigeon",`, 1),
		"modbus_client.generation": strings.Replace(valid, `"generation": "7xx"`, `"generation": "9xx"`, 1),
		"authority_profiles":       strings.Replace(valid, `["csip", "mbaps"]`, `["csip", "telepathy"]`, 1),
	}
	for field, body := range cases {
		t.Run(field, func(t *testing.T) {
			if _, err := Parse([]byte(body), "candidate.json"); err == nil {
				t.Fatalf("Parse() accepted an out-of-vocabulary %s", field)
			}
		})
	}
}

// A document that contradicts ITSELF cannot be the authority for anything: a
// scope decision would have to pick one half over the other.
func TestParseRejectsSelfContradiction(t *testing.T) {
	cases := map[string]string{
		"DER count vs csip.der_resources": strings.Replace(valid, `"der_resources": 1`, `"der_resources": 3`, 1),
		"DER count vs device_count":       strings.Replace(valid, `"device_count": 1`, `"device_count": 4`, 1),
		"DER count vs northbound units":   strings.Replace(valid, `"northbound_units": [1]`, `"northbound_units": [1, 2]`, 1),
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := Parse([]byte(body), "candidate.json")
			if err == nil {
				t.Fatal("Parse() accepted a manifest that contradicts itself")
			}
		})
	}
}

func TestParseRejectsDuplicateAndImpossibleModels(t *testing.T) {
	dup := strings.Replace(valid, `[1, 701,`, `[1, 1, 701,`, 1)
	if _, err := Parse([]byte(dup), "candidate.json"); err == nil {
		t.Error("Parse() accepted a duplicated model id")
	}
	bad := strings.Replace(valid, `"models": [1,`, `"models": [0,`, 1)
	if _, err := Parse([]byte(bad), "candidate.json"); err == nil {
		t.Error("Parse() accepted model id 0")
	}
}

// An empty roles list would put every mbaps row out of scope. That is far too
// large a decision to arrive at by omission.
func TestParseRefusesEmptySecureSunSpecRoles(t *testing.T) {
	body := strings.Replace(valid, `"roles": ["server"]`, `"roles": []`, 1)
	_, err := Parse([]byte(body), "candidate.json")
	if err == nil {
		t.Fatal("Parse() accepted an empty secure_sunspec.roles")
	}
	if !strings.Contains(err.Error(), "secure_sunspec.roles") {
		t.Errorf("error does not name the field:\n%v", err)
	}
}

func TestLoadReadsAFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "candidate.json")
	if err := os.WriteFile(p, []byte(valid), 0o644); err != nil {
		t.Fatal(err)
	}
	m, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if m.Path() != p {
		t.Errorf("Path() = %q, want %q", m.Path(), p)
	}
	if _, err := Load(filepath.Join(t.TempDir(), "absent.json")); err == nil {
		t.Error("Load() = nil for a file that does not exist")
	}
}

func TestNilManifestAccessorsAreSafe(t *testing.T) {
	var m *Manifest
	if m.ClaimsAuthority("csip") || m.HasModel(1) {
		t.Error("a nil manifest claimed something")
	}
	if got := m.Summary(); !strings.Contains(got, "no candidate manifest") {
		t.Errorf("Summary() = %q", got)
	}
}

func TestSummaryNamesTheProfile(t *testing.T) {
	if got := mustParse(t, valid).Summary(); !strings.Contains(got, "one-to-one-7xx-tcp") {
		t.Errorf("Summary() = %q, want the profile in it", got)
	}
}
