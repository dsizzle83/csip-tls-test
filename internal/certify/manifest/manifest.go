// Package manifest reads the CANDIDATE MANIFEST: the machine-readable
// declaration of what the device under test claims to be.
//
// # Why the harness needs one at all
//
// Everything else this engine knows about scope comes from the CATALOG, which
// is a fact about the published standards and the profile column we certify
// against. That answers "is this row required of a DER Client?" and cannot
// answer "is this row required of THIS candidate?" — whether it serves one DER
// or forty, whether it is a Secure SunSpec server, a client, or both, which
// models it actually implements. Without that second half a campaign has to
// guess, and every guess it makes lands in an evidence bundle as though it were
// measured. The manifest is the product declaring it, in one file, so the
// harness can cite the declaration instead of inferring one.
//
// The product installs it at /etc/lexa/candidate.json; this package reads a copy
// named on the command line (-manifest), and the runner copies that copy into
// the evidence bundle beside its digest, so a reader can check that the scope
// decisions in a bundle were made against the manifest the bundle contains.
//
// # Tolerant but strict
//
// STRICT about shape: an unknown field is an error. A manifest that grew a key
// we do not model is a manifest whose meaning we no longer fully represent, and
// the correct response is to stop — the same rule, for the same reason, that the
// catalog loader applies to catalog.json.
//
// TOLERANT about the operator's time: every problem in the file is reported at
// once, not one per edit-and-retry cycle. A missing key is named as missing
// rather than silently decoding to a zero that then reads as a genuine
// declaration of "zero DERs" or "port 0".
//
// Exactly one key is OPTIONAL — secure_sunspec.frame_budget_ms — and the two
// rules do not soften for it. Absent, it is silence and NOTHING is recorded;
// present, it is validated against the same [1, 60000] ms range cmd/mbaps
// itself enforces. "Optional" here means the DOCUMENT may omit it, never that a
// reader may invent one: see SecureSunSpec.FrameBudget for why the default
// belongs to the check that has to decide what an undeclared budget means.
//
// That distinction is the reason this file has two types for one document.
// [raw] decodes with pointers, where absent and zero are different; [Manifest]
// is what everything else consumes, with plain values that are known to have
// been declared. Nothing outside this package should ever see a pointer to an
// int and have to wonder which it is holding.
//
// # One file, on purpose
//
// The product side of this manifest is being defined in parallel, and it will
// drift. Keeping the whole reader — schema, validation, vocabulary — in one
// small package makes reconciling that drift a single-file review rather than an
// archaeology exercise across the suites.
package manifest

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"
)

// DefaultDUTPath is where the product installs the manifest on the device. It is
// not read from here — this package reads a local copy — but it is the string an
// error message should point an operator at.
const DefaultDUTPath = "/etc/lexa/candidate.json"

// Topology is the DER-side shape of the candidate.
type Topology struct {
	// ConfiguredDER is how many DERs the candidate is configured to control.
	// The RC0 product profile carries exactly one; anything else is a topology
	// this campaign's rows were not written for.
	ConfiguredDER int
	// Role is what that DER is: "inverter", "battery", "meter".
	Role string
	// NorthboundUnits are the Modbus unit ids the northbound server exposes.
	NorthboundUnits []int
}

// CSIP is the 2030.5 client-side declaration.
type CSIP struct {
	// Role is the CSIP profile column claimed: "der-client" or
	// "der-aggregator-client".
	Role string
	// EndDevices and DERResources are how many of each the candidate presents.
	EndDevices   int
	DERResources int
}

// SecureSunSpec is the Secure SunSpec Modbus (mbaps) declaration.
type SecureSunSpec struct {
	// Roles are the DIRECTIONS claimed: "server", "client", or both. This is
	// the axis that decides whether a client-direction conformance row is in
	// scope for the candidate at all.
	Roles []string
	// Transport is the transport claimed, e.g. "tls-tcp".
	Transport string
	// Port is the northbound listener's port.
	Port int
	// FrameBudgetMS is the DUT's MBAP FRAME BUDGET in milliseconds: how long
	// its northbound listener will hold a connection open waiting for the rest
	// of a frame whose MBAP header has already promised a length, before it
	// gives up and closes (lexa-gw configs/mbaps.json limits.frame_budget_ms,
	// cmd/mbaps Config, internal/listener Server.FrameBudget).
	//
	// OPTIONAL, and the only optional key in this document. It is here because
	// SS-MODBUS-CONF v1.4 §2.7.7 (TCP-2, Partial Request) specifies NO timing
	// at all, and a harness that guesses one measures its own guess: pause too
	// briefly after the truncated frame and the follow-up ADU is byte-for-byte
	// indistinguishable from TCP-3's required segment reassembly — the same two
	// writes on the same connection, and a conformant server that reassembles
	// them is then recorded as having mis-parsed. The budget is the DUT's own
	// number and only the candidate can state it.
	//
	// ZERO MEANS NOT DECLARED. Read it through FrameBudget, which returns that
	// as a second value rather than as a duration of nought — the whole reason
	// this package decodes through pointers.
	FrameBudgetMS int
}

// MaxFrameBudgetMS is the largest budget this reader accepts, mirroring
// lexa-gw cmd/mbaps's own maxFrameBudgetMS. A manifest declaring more than a
// minute is far likelier to be seconds written as milliseconds than a listener
// that really waits that long, and a TCP-2 pause derived from it would stall
// the campaign rather than measure the DUT.
const MaxFrameBudgetMS = 60000

// FrameBudget returns the declared MBAP frame budget, and whether one was
// declared at all.
//
// The two-value form is the point: a caller must not be able to reach a budget
// of zero and treat it as a real number. There is no default here on purpose —
// what an undeclared budget means is a decision about EVIDENCE, and it belongs
// to the check that has to decide it (see suitemodbusserver's TCP-2), not to
// the reader of a declaration that does not contain one.
func (s SecureSunSpec) FrameBudget() (time.Duration, bool) {
	if s.FrameBudgetMS <= 0 {
		return 0, false
	}
	return time.Duration(s.FrameBudgetMS) * time.Millisecond, true
}

// ModbusClient is the southbound (DER-facing) Modbus client declaration.
type ModbusClient struct {
	// Transport is "tcp", "rtu", or "rtuovertcp".
	Transport string
	// DeviceCount is how many southbound devices the candidate polls.
	DeviceCount int
	// Generation is the SunSpec model generation the devices serve, e.g. "7xx".
	Generation string
}

// Manifest is the candidate's declaration, validated.
type Manifest struct {
	// Profile is the candidate profile key, e.g. "one-to-one-7xx-tcp". It names
	// the whole declaration in one token, for a bundle's summary line.
	Profile string
	Topology
	CSIP          CSIP
	SecureSunSpec SecureSunSpec
	ModbusClient  ModbusClient
	// AuthorityProfiles are the DUT arbitration postures the candidate claims,
	// from {"csip", "mbaps", "local"}. A campaign whose required authority is
	// not in this list is a campaign this candidate does not claim.
	AuthorityProfiles []string
	// Models are the SunSpec model ids the candidate's DER actually serves.
	Models []int

	path   string
	digest string
	size   int
}

// Path returns the file this manifest was read from.
func (m *Manifest) Path() string { return m.path }

// SHA256 returns the hex digest of the exact bytes read, so a bundle can record
// which declaration a run's scope decisions were made against and a reader can
// re-derive it from the copy shipped beside them.
func (m *Manifest) SHA256() string { return m.digest }

// Size returns the number of bytes read.
func (m *Manifest) Size() int { return m.size }

// HasRole reports whether the candidate claims this Secure SunSpec DIRECTION
// ("server" / "client"), matched fold-insensitively.
func (s SecureSunSpec) HasRole(role string) bool { return containsFold(s.Roles, role) }

// ClaimsAuthority reports whether the candidate claims this arbitration posture.
func (m *Manifest) ClaimsAuthority(a string) bool {
	if m == nil {
		return false
	}
	return containsFold(m.AuthorityProfiles, a)
}

// HasModel reports whether the candidate declares this SunSpec model id.
func (m *Manifest) HasModel(id int) bool {
	if m == nil {
		return false
	}
	for _, v := range m.Models {
		if v == id {
			return true
		}
	}
	return false
}

// Summary is a one-line description for a console header or a bundle note.
func (m *Manifest) Summary() string {
	if m == nil {
		return "(no candidate manifest)"
	}
	return fmt.Sprintf("%s — %d DER (%s), csip %s, secure-sunspec %s, modbus-client %s x%d %s",
		m.Profile, m.ConfiguredDER, orNone(m.Role), orNone(m.CSIP.Role),
		orNone(strings.Join(m.SecureSunSpec.Roles, "+")), orNone(m.ModbusClient.Transport),
		m.ModbusClient.DeviceCount, orNone(m.ModbusClient.Generation))
}

// The vocabularies this package validates against. They are deliberately narrow:
// a value outside them is far more likely to be a typo in a hand-edited manifest
// than a product feature nobody mentioned, and a typo that decodes silently
// becomes a scope decision nobody made.
var (
	knownDERRoles       = []string{"inverter", "battery", "meter"}
	knownCSIPRoles      = []string{"der-client", "der-aggregator-client"}
	knownSSMRoles       = []string{"server", "client"}
	knownAuthorities    = []string{"csip", "mbaps", "local"}
	knownMBTransports   = []string{"tcp", "rtu", "rtuovertcp"}
	knownSSMTransports  = []string{"tls-tcp"}
	knownDERGenerations = []string{"1xx", "7xx", "8xx"}
)

// raw is the on-disk document. Every scalar that could legitimately be zero is a
// POINTER, so "absent" and "declared zero" are different facts — see the package
// doc.
type raw struct {
	Profile  *string `json:"profile"`
	Topology *struct {
		ConfiguredDER   *int    `json:"configured_der"`
		Role            *string `json:"role"`
		NorthboundUnits []int   `json:"northbound_units"`
	} `json:"topology"`
	CSIP *struct {
		Role         *string `json:"role"`
		EndDevices   *int    `json:"end_devices"`
		DERResources *int    `json:"der_resources"`
	} `json:"csip"`
	SecureSunSpec *struct {
		Roles     []string `json:"roles"`
		Transport *string  `json:"transport"`
		Port      *int     `json:"port"`
		// OPTIONAL — see SecureSunSpec.FrameBudgetMS. Absent is a legal
		// manifest; present-and-out-of-range is not.
		FrameBudgetMS *int `json:"frame_budget_ms"`
	} `json:"secure_sunspec"`
	ModbusClient *struct {
		Transport   *string `json:"transport"`
		DeviceCount *int    `json:"device_count"`
		Generation  *string `json:"generation"`
	} `json:"modbus_client"`
	AuthorityProfiles []string `json:"authority_profiles"`
	Models            []int    `json:"models"`
}

// InvalidError is every problem found in one manifest, reported together.
//
// It is a type rather than a joined string because the caller that matters — the
// runner's preflight — wants to print them as a list under one heading, and
// because a test asserting "this manifest is rejected for THESE three reasons"
// should not have to substring-match a paragraph.
type InvalidError struct {
	Path     string
	Problems []string
}

func (e *InvalidError) Error() string {
	return fmt.Sprintf("manifest: %s is not a usable candidate manifest:\n  - %s",
		e.Path, strings.Join(e.Problems, "\n  - "))
}

// Load reads and validates a candidate manifest.
func Load(path string) (*Manifest, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("manifest: read %s: %w", path, err)
	}
	m, err := Parse(data, path)
	if err != nil {
		return nil, err
	}
	return m, nil
}

// Parse validates a manifest already in memory. Load is the ordinary entry
// point; this exists so a test — and any caller holding the bytes for another
// reason — need not go through the filesystem.
func Parse(data []byte, path string) (*Manifest, error) {
	if path == "" {
		path = "(in memory)"
	}
	var r raw
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&r); err != nil {
		return nil, fmt.Errorf("manifest: parse %s: %w (an unknown key is an error here on purpose: a "+
			"manifest carrying a field this harness does not model is one whose meaning it cannot fully "+
			"represent, and a scope decision made from a document we half understand is worse than no "+
			"scope decision at all)", path, err)
	}

	sum := sha256.Sum256(data)
	m := &Manifest{path: path, digest: hex.EncodeToString(sum[:]), size: len(data)}
	var p problems

	m.Profile = p.reqString(r.Profile, "profile", nil)

	if r.Topology == nil {
		p.missing("topology")
	} else {
		m.ConfiguredDER = p.reqInt(r.Topology.ConfiguredDER, "topology.configured_der", 0)
		m.Role = p.reqString(r.Topology.Role, "topology.role", knownDERRoles)
		m.NorthboundUnits = r.Topology.NorthboundUnits
		if len(m.NorthboundUnits) == 0 {
			p.missing("topology.northbound_units")
		}
		for _, u := range m.NorthboundUnits {
			if u < 1 || u > 247 {
				p.addf("topology.northbound_units contains %d, which is not a Modbus unit id (1..247)", u)
			}
		}
	}

	if r.CSIP == nil {
		p.missing("csip")
	} else {
		m.CSIP.Role = p.reqString(r.CSIP.Role, "csip.role", knownCSIPRoles)
		m.CSIP.EndDevices = p.reqInt(r.CSIP.EndDevices, "csip.end_devices", 0)
		m.CSIP.DERResources = p.reqInt(r.CSIP.DERResources, "csip.der_resources", 0)
	}

	if r.SecureSunSpec == nil {
		p.missing("secure_sunspec")
	} else {
		m.SecureSunSpec.Roles = r.SecureSunSpec.Roles
		if len(m.SecureSunSpec.Roles) == 0 {
			// Not defaulted. An empty roles list would make every mbaps row out
			// of scope, which is a decision far too large to arrive at by
			// omission.
			p.missing("secure_sunspec.roles")
		}
		for _, role := range m.SecureSunSpec.Roles {
			if !containsFold(knownSSMRoles, role) {
				p.addf("secure_sunspec.roles contains %q; want one of %s", role, strings.Join(knownSSMRoles, ", "))
			}
		}
		m.SecureSunSpec.Transport = p.reqString(r.SecureSunSpec.Transport, "secure_sunspec.transport", knownSSMTransports)
		m.SecureSunSpec.Port = p.reqInt(r.SecureSunSpec.Port, "secure_sunspec.port", 1)
		if m.SecureSunSpec.Port > 65535 {
			p.addf("secure_sunspec.port is %d, which is not a TCP port", m.SecureSunSpec.Port)
		}
		// OPTIONAL: absent is silence, not a declaration, and nothing is
		// recorded. Present, it must be a budget the product could actually
		// hold — the same [1, 60000] ms range cmd/mbaps validates, so a
		// manifest this reader accepts is one the DUT would also accept.
		if fb := r.SecureSunSpec.FrameBudgetMS; fb != nil {
			switch {
			case *fb < 1:
				p.addf("secure_sunspec.frame_budget_ms is %d; it is OPTIONAL, but a declared budget must "+
					"be at least 1 ms — omit the key to declare nothing", *fb)
			case *fb > MaxFrameBudgetMS:
				p.addf("secure_sunspec.frame_budget_ms is %d, above the %d ms cmd/mbaps itself accepts "+
					"(limits.frame_budget_ms); seconds written as milliseconds is the usual cause", *fb, MaxFrameBudgetMS)
			}
			m.SecureSunSpec.FrameBudgetMS = *fb
		}
	}

	if r.ModbusClient == nil {
		p.missing("modbus_client")
	} else {
		m.ModbusClient.Transport = p.reqString(r.ModbusClient.Transport, "modbus_client.transport", knownMBTransports)
		m.ModbusClient.DeviceCount = p.reqInt(r.ModbusClient.DeviceCount, "modbus_client.device_count", 0)
		m.ModbusClient.Generation = p.reqString(r.ModbusClient.Generation, "modbus_client.generation", knownDERGenerations)
	}

	m.AuthorityProfiles = r.AuthorityProfiles
	if len(m.AuthorityProfiles) == 0 {
		p.missing("authority_profiles")
	}
	for _, a := range m.AuthorityProfiles {
		if !containsFold(knownAuthorities, a) {
			p.addf("authority_profiles contains %q; want one of %s", a, strings.Join(knownAuthorities, ", "))
		}
	}

	m.Models = r.Models
	if len(m.Models) == 0 {
		p.missing("models")
	}
	seen := map[int]bool{}
	for _, id := range m.Models {
		if id < 1 || id > 65535 {
			p.addf("models contains %d, which is not a SunSpec model id", id)
		}
		if seen[id] {
			p.addf("models lists model %d more than once", id)
		}
		seen[id] = true
	}

	// Cross-field coherence. These are the statements the manifest makes ABOUT
	// ITSELF, and a document that contradicts itself cannot be the authority for
	// anything: which of the two halves would a scope decision follow?
	if r.Topology != nil && r.CSIP != nil {
		if m.ConfiguredDER > 0 && m.CSIP.DERResources > 0 && m.ConfiguredDER != m.CSIP.DERResources {
			p.addf("topology.configured_der is %d but csip.der_resources is %d — the same DERs counted "+
				"twice must come to the same number", m.ConfiguredDER, m.CSIP.DERResources)
		}
	}
	if r.Topology != nil && r.ModbusClient != nil {
		if m.ConfiguredDER > 0 && m.ModbusClient.DeviceCount > 0 && m.ConfiguredDER != m.ModbusClient.DeviceCount {
			p.addf("topology.configured_der is %d but modbus_client.device_count is %d — a DER the "+
				"candidate controls is a device it polls", m.ConfiguredDER, m.ModbusClient.DeviceCount)
		}
	}
	if r.Topology != nil && len(m.NorthboundUnits) > 0 && m.ConfiguredDER > 0 &&
		len(m.NorthboundUnits) != m.ConfiguredDER {
		p.addf("topology declares %d DER(s) but %d northbound unit(s) (%v) — the northbound server "+
			"exposes one unit per DER", m.ConfiguredDER, len(m.NorthboundUnits), m.NorthboundUnits)
	}

	if len(p) > 0 {
		sort.Strings(p)
		return nil, &InvalidError{Path: path, Problems: p}
	}
	return m, nil
}

// problems accumulates validation failures so all of them are reported at once.
type problems []string

func (p *problems) addf(format string, a ...any) { *p = append(*p, fmt.Sprintf(format, a...)) }

func (p *problems) missing(field string) {
	p.addf("%s is missing — it is required, and an absent key must never be read as a declaration of "+
		"its zero value", field)
}

// reqString records a missing or out-of-vocabulary string and returns whatever
// was there, so validation continues over the rest of the document.
func (p *problems) reqString(v *string, field string, vocabulary []string) string {
	if v == nil {
		p.missing(field)
		return ""
	}
	s := strings.TrimSpace(*v)
	if s == "" {
		p.addf("%s is empty", field)
		return ""
	}
	if len(vocabulary) > 0 && !containsFold(vocabulary, s) {
		p.addf("%s is %q; want one of %s", field, s, strings.Join(vocabulary, ", "))
	}
	return s
}

// reqInt records a missing or below-minimum integer and returns what was there.
func (p *problems) reqInt(v *int, field string, min int) int {
	if v == nil {
		p.missing(field)
		return 0
	}
	if *v < min {
		p.addf("%s is %d; want at least %d", field, *v, min)
	}
	return *v
}

func containsFold(ss []string, s string) bool {
	for _, v := range ss {
		if strings.EqualFold(strings.TrimSpace(v), strings.TrimSpace(s)) {
			return true
		}
	}
	return false
}

func orNone(s string) string {
	if s == "" {
		return "(none)"
	}
	return s
}
