package gridsim

// fleet.go — the CTP Figure-15 aggregator topology (default OFF).
//
// # What this builds and why
//
// CSIP Conformance Test Procedures V1.3 §8 opens with: "These tests assume the
// aggregator manages four EndDevice entities (EDA1, EDA2, EDB1, and EDB2) shown
// in the following topology" (Figure 15, p. 143). Every AGG / MAINT / UTIL row
// of the DER AGGREGATOR CLIENT profile is written against that fixture, and
// gridsim's default tree serves ONE EndDevice — so those rows could only ever
// report SKIP naming the gap (docs/PROFILE_SCOPE_2026-07-28_der-aggregator-client.md §5).
//
// EnableFleet(4) builds the fixture. It is off by default and the default tree
// is untouched by this file: a run that never calls EnableFleet serves
// byte-identical XML to the one it served before this file existed, which
// TestDefaultTreeIsByteIdentical pins against a golden generated from the tree
// as it stood at a51e13d.
//
// # The LFDI mapping, which is the whole design question
//
// An aggregator client holds ONE certificate, so exactly one LFDI arrives on
// the wire — and the CTP is explicit that the five EndDevice instances do not
// share it. UTIL-001 setup steps 5 and 6 (p. 144):
//
//	5. [S] Create an EndDevice instance for the aggregator with:
//	       • SFDI/LFDI - aggregator SFDI and LFDI
//	       • SubscriptionListLink
//	       • LogEventListLink
//	6. [S] Create an EndDevice instance for EDA1, EDA2, EDB1 and EDB2 with:
//	       • SFDI/LFDI - EndDevice SFDI and LFDI
//	       • FunctionSetAssignmentsListLink
//	       • DERListLink
//	       • LogEventListLink
//
// and UTIL-002 procedure step 3 (p. 146) has the client "Verif[y] there is an
// EndDevice instance with an SFDI/LFDI that matches its own (aggregator)
// SFDI/LFDI" — singular. So:
//
//	the DUT's certificate LFDI  →  the AGGREGATOR EndDevice (/edev/2), exactly
//	                               as in the single-device tree;
//	EDA1/EDA2/EDB1/EDB2         →  their OWN LFDI/SFDI, which are facts about
//	                               the managed inverters, not about the client
//	                               that manages them.
//
// What makes the four visible to the DUT is therefore NOT an LFDI match. It is
// that the server put them in this aggregator's EndDeviceList — UTIL-001 step 4,
// "Create an EndDeviceList for the aggregator Client". gridsim models that
// directly: every managed device carries a ManagedBy field holding the
// aggregator LFDI it belongs to, and serveFilteredEndDeviceList generalises the
// single-device rule from "LFDI equals the peer's" to "LFDI equals the peer's,
// OR ManagedBy equals the peer's". ManagedBy is (re)bound to the connecting
// certificate's LFDI on every SetClientCertDER, so the bench needs no
// out-of-band configuration to make the fleet the DUT's.
//
// The four synthetic LFDIs are derived — not invented — so a reader can
// recompute them: SHA-256 over the documented preimage
//
//	"gridsim-fleet/v1/" + <aggregator LFDI> + "/" + <device name>
//
// left-truncated to 160 bits, with the SFDI taken from it by IEEE 2030.5 §6.3.3
// (leftmost 36 bits, decimal, plus a mod-10 check digit) — the same derivation
// internal/csip/identity applies to a certificate, run over a seed instead.
// They are DERIVED IDENTITIES OF SIMULATED INVERTERS and are not certificate
// identities of anything; the doc comment on identity.FromSeed says so at the
// only place someone could mistake one for the other. Binding them to the
// aggregator's LFDI keeps two benches with different DUT certificates from
// colliding, and keeps one bench's fleet stable across restarts.
//
// # The DERProgram ladder
//
// UTIL-001 setup step 2: "Configure the server to create a DER Program
// associated with each node with the corresponding primacy value", and its
// last pass criterion: "Each EndDevice should be assigned a link to all the DER
// programs associated with its parent nodes."
//
// The node names come out of the procedures' own text — SPA1/SPA2/SPB1/SPB2
// (UTIL-001 step 3), FDA/FDB (UTIL-004 steps 9 and 15), TFA/TFB (AGG-002 setup,
// MAINT-003 setup step 5), SGA/SGB (MAINT-005 setup step 5) and SY (AGG-002
// setup step 2). The PRIMACY VALUES do not: Figure 15 and Figure 16 are
// graphics, and the only primacy numbers the printed text states are
// MAINT-005's setup step 5 — "DERProgram (primacy=1) for TFA and TFB nodes and
// DERProgram (primacy=2) for SGA and SGB nodes". Those two are honoured
// literally here. The rest of the ladder is gridsim's, chosen to preserve the
// figure's containment order, and it is recorded as gridsim's rather than
// presented as the document's:
//
//	SPA1 SPA2 SPB1 SPB2  primacy 0   service points (most local)
//	FDA  FDB             primacy 0   feeders
//	TFA  TFB             primacy 1   transformers   ← CTP MAINT-005 step 5
//	SGA  SGB             primacy 2   substation groups ← CTP MAINT-005 step 5
//	SY                   primacy 10  system (gridsim's existing program 2)
//
// Service points and feeders share primacy 0 because the two CTP-stated values
// leave no integer between 0 and 1, and because sharing one is not a defect:
// IEEE 2030.5 orders programs by "Primary key (primacy) and Secondary key
// (mRID)" (CTP §6, p. 51), and the CTP itself gives TFA and TFB "equal primacy"
// in MAINT-004's setup step 5. Each device's DERProgramList is served in that
// exact order — primacy ascending, mRID ascending within a primacy — so a
// client that trusts list order prioritises correctly.
//
// TFA and SY are not new programs: they ARE gridsim's existing program 0
// (primacy 1) and program 2 (primacy 10), hrefs and mRIDs unchanged. That is
// deliberate and load-bearing. The conformance suite's aggregator rows publish
// their TFA and SY DERControls through POST /admin/control with program 0 and
// program 2 (internal/certify/suitecsip/aggregator.go progTFA/progSY), so
// aliasing rather than duplicating is what makes those controls actually arrive
// at EDA1/EDA2 and at all four devices respectively.

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"log"
	"net/http"
	"sort"
	"strings"
	"time"

	"csip-tls-test/internal/csip/identity"
	model "lexa-proto/csipmodel"
)

// FleetSize is the number of MANAGED EndDevices the Figure-15 fixture defines
// (EDA1, EDA2, EDB1, EDB2). The served EndDeviceList holds one more than this:
// the aggregator's own EndDevice.
const FleetSize = 4

// aggregatorEdevIndex is the /edev slot the DUT's own EndDevice has always
// occupied. The managed devices are appended after it so that every href the
// single-device tree published keeps pointing at the same resource.
const aggregatorEdevIndex = 2

// fleetNode is one node of the Figure-15 topology and the DERProgram bound to
// it.
type fleetNode struct {
	// Name is the CTP's own name for the node (SPA1, FDA, TFA, SGA, SY).
	Name string
	// Primacy is the value gridsim serves for the node's DERProgram. See the
	// file comment for which of these the CTP states and which are gridsim's.
	Primacy uint8
	// Alias, when >= 0, names the EXISTING gridsim program index this node's
	// DERProgram is (rather than a new one built here). It is how the suite's
	// POST /admin/control lever reaches the fleet.
	Alias int
}

// href is where the node's DERProgram is served.
func (n fleetNode) href() string {
	if n.Alias >= 0 {
		return fmt.Sprintf("/derp/%d", n.Alias)
	}
	return "/derp/" + strings.ToLower(n.Name)
}

// fleetNodes is the Figure-15 topology, root last. Order within the slice is
// irrelevant; each device's list is sorted by (primacy, mRID) when it is built.
var fleetNodes = map[string]fleetNode{
	"SPA1": {"SPA1", 0, -1},
	"SPA2": {"SPA2", 0, -1},
	"SPB1": {"SPB1", 0, -1},
	"SPB2": {"SPB2", 0, -1},
	"FDA":  {"FDA", 0, -1},
	"FDB":  {"FDB", 0, -1},
	"TFA":  {"TFA", 1, progIdxTFA},
	"TFB":  {"TFB", 1, -1},
	"SGA":  {"SGA", 2, -1},
	"SGB":  {"SGB", 2, -1},
	"SY":   {"SY", 10, progIdxSY},
}

// The gridsim program indices the CTP's TFA and SY nodes alias. They are the
// same two the conformance suite publishes onto (suitecsip's progTFA/progSY),
// and the aliasing is what makes a control posted there arrive at the fleet.
const (
	progIdxTFA = 0
	progIdxSY  = 2
)

// fleetPlan is the device→node assignment of UTIL-001 setup step 3 ("Assign
// inverter EDA1 to node SPA1. Assign EDA2 to node SPA2. Assign EDB1 to node
// SPB1. Assign EDB2 to node SPB2.") together with each service point's parent
// chain, which is what "all the DER programs associated with its parent nodes"
// resolves to.
var fleetPlan = []struct {
	Name  string
	Nodes []string // leaf first, root last
}{
	{"EDA1", []string{"SPA1", "FDA", "TFA", "SGA", "SY"}},
	{"EDA2", []string{"SPA2", "FDA", "TFA", "SGA", "SY"}},
	{"EDB1", []string{"SPB1", "FDB", "TFB", "SGB", "SY"}},
	{"EDB2", []string{"SPB2", "FDB", "TFB", "SGB", "SY"}},
}

// FleetDevice is one managed EndDevice, as GET /admin/fleet reports it and
// POST /admin/fleet adjusts it.
type FleetDevice struct {
	// Name is the CTP's name for the device (EDA1…EDB2).
	Name string `json:"name"`
	// Node is the service point it is assigned to (UTIL-001 setup step 3).
	Node string `json:"node"`
	// Href is the EndDevice resource path.
	Href string `json:"href"`
	// LFDI/SFDI are the device's OWN identifiers — see the file comment. They
	// are never the aggregator's.
	LFDI string `json:"lfdi"`
	SFDI uint64 `json:"sfdi"`
	// PIN is the device's Registration pIN, carrying a valid IEEE 2030.5 §6.3.4
	// check digit.
	PIN uint32 `json:"pin"`
	// ManagedBy is the aggregator LFDI whose EndDeviceList this device appears
	// in. Empty means "no aggregator has connected yet", and such a device is
	// served to nobody.
	ManagedBy string `json:"managed_by"`
	// Programs names the node DERPrograms the device's FunctionSetAssignments
	// links, in the order they are served.
	Programs []string `json:"programs"`
}

// fleetState is the built fixture. nil on s.Server means fleet mode is off.
type fleetState struct {
	devices []*FleetDevice
}

// EnableFleet builds the CTP Figure-15 topology and serves it from now on.
//
// size must be FleetSize: the figure has four managed devices and a fixture
// with three would be a different test. Refusing rather than rounding is the
// same discipline scripts/bench-sims-up.sh applies to SIM_FLEET, and for the
// same reason — a half-built fixture reads as success.
func (s *Server) EnableFleet(size int) error {
	if size != FleetSize {
		return fmt.Errorf("gridsim: fleet size %d is not defined; CTP Figure 15 has %d managed EndDevices "+
			"(EDA1, EDA2, EDB1, EDB2) and a fixture of any other size is a different test", size, FleetSize)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.fleet == nil {
		s.fleet = &fleetState{}
	}
	s.buildFleetLocked()
	log.Printf("[gridsim] CTP Figure-15 fleet ENABLED: %d managed EndDevices (%s) plus the aggregator's own",
		FleetSize, strings.Join(fleetDeviceNames(), ", "))
	return nil
}

// FleetEnabled reports whether the Figure-15 topology is being served.
func (s *Server) FleetEnabled() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.fleet != nil
}

// Fleet returns a copy of the managed-device table.
func (s *Server) Fleet() []FleetDevice {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.fleetLocked()
}

func (s *Server) fleetLocked() []FleetDevice {
	if s.fleet == nil {
		return nil
	}
	out := make([]FleetDevice, 0, len(s.fleet.devices))
	for _, d := range s.fleet.devices {
		out = append(out, *d)
	}
	return out
}

func fleetDeviceNames() []string {
	names := make([]string, 0, len(fleetPlan))
	for _, p := range fleetPlan {
		names = append(names, p.Name)
	}
	return names
}

// ── identity ─────────────────────────────────────────────────────────────────

// fleetSeed is the documented preimage the managed devices' LFDIs are derived
// from. It is written out here rather than inlined so that the string a reader
// has to reproduce to recompute an LFDI is in exactly one place.
func fleetSeed(aggregatorLFDI, device string) []byte {
	return []byte("gridsim-fleet/v1/" + strings.ToUpper(aggregatorLFDI) + "/" + device)
}

// fleetPIN returns the Registration pIN for a managed device: a five-digit body
// derived from the device's position plus the IEEE 2030.5 §6.3.4 check digit
// that makes the digits sum to zero modulo ten. A pIN without a valid check
// digit is a conformance FAILURE the harness looks for (critRegistrationPIN),
// so the bench must not serve one by accident.
func fleetPIN(i int) uint32 {
	body := uint32(22222 + 11111*i) // EDA1 22222, EDA2 33333, EDB1 44444, EDB2 55555
	sum := 0
	for x := body; x > 0; x /= 10 {
		sum += int(x % 10)
	}
	return body*10 + uint32((10-sum%10)%10)
}

// ── resource construction ────────────────────────────────────────────────────

// buildFleetLocked (re)builds every fleet resource and the EndDeviceList that
// links them. Caller holds s.mu for writing.
//
// It is called from EnableFleet and again from rebuildEndDeviceList, so a new
// mTLS handshake re-binds the fleet to whatever certificate just arrived rather
// than leaving it owned by the previous peer.
func (s *Server) buildFleetLocked() {
	if s.fleet == nil {
		return
	}
	now := time.Now().Unix()
	aggLFDI := s.ClientLFDI

	s.fleet.devices = s.fleet.devices[:0]
	for i, p := range fleetPlan {
		idx := aggregatorEdevIndex + 1 + i
		href := fmt.Sprintf("/edev/%d", idx)
		lfdi, sfdi := identity.FromSeed(fleetSeed(aggLFDI, p.Name))
		dev := &FleetDevice{
			Name: p.Name, Node: p.Nodes[0], Href: href,
			LFDI: lfdi.String(), SFDI: uint64(sfdi), PIN: fleetPIN(i),
			ManagedBy: aggLFDI, Programs: append([]string(nil), p.Nodes...),
		}
		s.fleet.devices = append(s.fleet.devices, dev)
		s.buildFleetDeviceLocked(dev, idx, p.Nodes, now)
	}
	s.buildFleetProgramsLocked(now)
	s.rebuildFleetEndDeviceListLocked(now)
}

// buildFleetDeviceLocked installs the sub-tree of one managed EndDevice: the
// links UTIL-001 setup step 6 requires, plus the Registration the
// commissioning walk reads and the DER report targets UTIL-002 PUTs to.
func (s *Server) buildFleetDeviceLocked(dev *FleetDevice, idx int, nodes []string, now int64) {
	base := dev.Href
	subs := s.subs != nil

	s.resources[base+"/reg"] = &model.Registration{
		Resource:           model.Resource{Href: base + "/reg"},
		DateTimeRegistered: now - 86400,
		PIN:                dev.PIN,
	}

	s.resources[base+"/der"] = &model.DERList{
		Resource: model.Resource{Href: base + "/der"},
		All:      1, Results: 1,
		DER: []model.DER{{
			Resource:            model.Resource{Href: base + "/der/0"},
			DERCapabilityLink:   &model.Link{Href: base + "/der/0/dercap"},
			DERSettingsLink:     &model.Link{Href: base + "/der/0/derset"},
			DERStatusLink:       &model.Link{Href: base + "/der/0/derstat"},
			DERAvailabilityLink: &model.Link{Href: base + "/der/0/deravail"},
		}},
	}
	s.resources[base+"/der/0/dercap"] = &model.DERCapability{
		Resource: model.Resource{Href: base + "/der/0/dercap"},
		Type:     80, // PV, as the single-device tree's DER already is
		RtgMaxW:  model.ActivePower{Multiplier: 0, Value: 10000},
	}
	s.resources[base+"/der/0/derset"] = &model.DERSettings{
		Resource:    model.Resource{Href: base + "/der/0/derset"},
		SetMaxW:     &model.ActivePower{Multiplier: 0, Value: 10000},
		UpdatedTime: now,
	}
	genConnected, opMode := uint8(1), uint8(1)
	s.resources[base+"/der/0/derstat"] = &model.DERStatus{
		Resource:              model.Resource{Href: base + "/der/0/derstat"},
		GenConnectStatus:      &genConnected,
		OperationalModeStatus: &opMode,
		ReadingTime:           now,
	}
	availDur := uint32(3600)
	s.resources[base+"/der/0/deravail"] = &model.DERAvailability{
		Resource:             model.Resource{Href: base + "/der/0/deravail"},
		ReadingTime:          now,
		AvailabilityDuration: &availDur,
	}

	s.resources[base+"/lev"] = &model.LogEventList{
		Resource: model.Resource{Href: base + "/lev"},
		All:      0, Results: 0, PollRate: 300,
	}

	// FunctionSetAssignmentsList. The subscribable attribute is the precondition
	// CORE-018 and CORE-019 open with, and the conformance suite reads it off
	// this list (critSubscriptionAdvertised), so it is set exactly when the
	// Subscription function set is actually being served.
	fsa := &fleetFSAList{
		Href: base + "/fsa", All: 1, Results: 1, PollRate: 300,
		FunctionSetAssignments: []model.FunctionSetAssignments{{
			Resource:    model.Resource{Href: base + "/fsa/0"},
			MRID:        "FSA-" + dev.Name + "-001",
			Description: dev.Name + " function set assignments (" + dev.Node + ")",
			DERProgramListLink: &model.ListLink{
				Link: model.Link{Href: base + "/fsa/0/derp"},
				All:  uint32(len(nodes)),
			},
			TimeLink: &model.Link{Href: "/tm"},
		}},
	}
	if subs {
		fsa.Subscribable = 1
		fsa.FunctionSetAssignments[0].Subscribable = 1
	}
	s.resources[base+"/fsa"] = fsa

	progs := make([]model.DERProgram, 0, len(nodes))
	for _, n := range nodes {
		progs = append(progs, s.fleetProgramLocked(fleetNodes[n]))
	}
	sortDERPrograms(progs)
	s.resources[base+"/fsa/0/derp"] = &model.DERProgramList{
		Resource: model.Resource{Href: base + "/fsa/0/derp"},
		All:      uint32(len(progs)), Results: uint32(len(progs)), PollRate: 60,
		DERProgram: progs,
	}
}

// sortDERPrograms orders a DERProgramList the way IEEE 2030.5 says a client
// prioritises: primary key primacy ascending, secondary key mRID. A list served
// out of that order makes a client that trusts list order mis-prioritise, and
// the conformance suite reports it (critProgramList).
func sortDERPrograms(progs []model.DERProgram) {
	sort.SliceStable(progs, func(i, j int) bool {
		if progs[i].Primacy != progs[j].Primacy {
			return progs[i].Primacy < progs[j].Primacy
		}
		return progs[i].MRID < progs[j].MRID
	})
}

// fleetProgramLocked resolves one topology node to the DERProgram entry served
// in a device's DERProgramList.
//
// For an aliased node (TFA, SY) that is gridsim's existing program, copied
// verbatim from the tree so its mRID, description and control-list hrefs are
// the ones POST /admin/control writes to. For every other node it is a new
// program whose own control resources this function creates on first use.
func (s *Server) fleetProgramLocked(n fleetNode) model.DERProgram {
	subs := s.subs != nil
	if n.Alias >= 0 {
		if base, ok := s.resources["/edev/2/fsa/0/derp"].(*model.DERProgramList); ok &&
			n.Alias < len(base.DERProgram) {
			p := base.DERProgram[n.Alias]
			if subs {
				p.Subscribable = 1
			}
			// Serve the program at its own href too: the single-device tree only
			// ever published these inline in the list, so a client following the
			// href got a 404. Additive, and only in fleet mode.
			cp := p
			s.resources[p.Href] = &cp
			return p
		}
	}

	href := n.href()
	if _, ok := s.resources[href+"/dderc"]; !ok {
		s.resources[href+"/dderc"] = &model.DefaultDERControl{
			Resource:    model.Resource{Href: href + "/dderc"},
			MRID:        "DDERC-" + n.Name + "-001",
			Description: n.Name + " default DER control",
			DERControlBase: model.DERControlBase{
				OpModExpLimW: &model.ActivePower{Multiplier: 0, Value: 5000},
			},
		}
	}
	for _, suffix := range []string{"/derc", "/actderc"} {
		if _, ok := s.resources[href+suffix]; !ok {
			s.resources[href+suffix] = &model.DERControlList{
				Resource: model.Resource{Href: href + suffix},
				All:      0, Results: 0, PollRate: s.controlListPollRateLocked(),
			}
		}
	}
	p := model.DERProgram{
		Resource:              model.Resource{Href: href},
		MRID:                  "DERP-" + n.Name + "-001",
		Description:           n.Name + " DER Program (CTP Figure 15 node " + n.Name + ")",
		Primacy:               n.Primacy,
		DefaultDERControlLink: &model.Link{Href: href + "/dderc"},
		DERControlListLink:    &model.ListLink{Link: model.Link{Href: href + "/derc"}},
		ActiveDERControlListLink: &model.ListLink{
			Link: model.Link{Href: href + "/actderc"},
		},
	}
	if subs {
		p.Subscribable = 1
	}
	cp := p
	s.resources[href] = &cp
	return p
}

// buildFleetProgramsLocked makes sure every node program exists even if no
// device happened to reference it during this build.
func (s *Server) buildFleetProgramsLocked(_ int64) {
	for _, n := range fleetNodes {
		_ = s.fleetProgramLocked(n)
	}
}

// ── the EndDeviceList ────────────────────────────────────────────────────────

// fleetEndDevice widens model.EndDevice with the SubscriptionListLink the CTP's
// aggregator setup requires on every EndDevice instance.
//
// It is declared here rather than added to lexa-proto/csipmodel because that
// module is version-pinned in lockstep with the product repo (CLAUDE.md,
// TASK-024) and this is a bench FIXTURE concern: the DUT never sends an
// EndDevice, it only reads one. The element order matches model.EndDevice's
// with SubscriptionListLink appended, which is the same ordering liberty the
// shared type already takes with the sep.xsd sequence.
type fleetEndDevice struct {
	XMLName xml.Name `xml:"urn:ieee:std:2030.5:ns EndDevice"`

	Href         string `xml:"href,attr,omitempty"`
	Subscribable uint8  `xml:"subscribable,attr,omitempty"`

	LFDI        string `xml:"lFDI,omitempty"`
	SFDI        uint64 `xml:"sFDI,omitempty"`
	ChangedTime int64  `xml:"changedTime,omitempty"`
	Enabled     *bool  `xml:"enabled,omitempty"`

	DERListLink                    *model.ListLink `xml:"DERListLink,omitempty"`
	FunctionSetAssignmentsListLink *model.ListLink `xml:"FunctionSetAssignmentsListLink,omitempty"`
	RegistrationLink               *model.Link     `xml:"RegistrationLink,omitempty"`
	LogEventListLink               *model.ListLink `xml:"LogEventListLink,omitempty"`
	SubscriptionListLink           *model.ListLink `xml:"SubscriptionListLink,omitempty"`
}

// fleetEndDeviceList is the EndDeviceList that carries them.
type fleetEndDeviceList struct {
	XMLName xml.Name `xml:"urn:ieee:std:2030.5:ns EndDeviceList"`

	Href         string `xml:"href,attr,omitempty"`
	All          uint32 `xml:"all,attr"`
	Results      uint32 `xml:"results,attr"`
	PollRate     uint32 `xml:"pollRate,attr,omitempty"`
	Subscribable uint8  `xml:"subscribable,attr,omitempty"`

	EndDevice []fleetEndDevice `xml:"EndDevice"`
}

// fleetFSAList is model.FunctionSetAssignmentsList with the subscribable
// attribute the CORE-018/CORE-019 setup requires ("configure … with an
// attribute that can be subscribed to"). The shared type has no field for it.
type fleetFSAList struct {
	XMLName xml.Name `xml:"urn:ieee:std:2030.5:ns FunctionSetAssignmentsList"`

	Href         string `xml:"href,attr,omitempty"`
	All          uint32 `xml:"all,attr"`
	Results      uint32 `xml:"results,attr"`
	PollRate     uint32 `xml:"pollRate,attr,omitempty"`
	Subscribable uint8  `xml:"subscribable,attr,omitempty"`

	FunctionSetAssignments []model.FunctionSetAssignments `xml:"FunctionSetAssignments"`
}

// rebuildFleetEndDeviceListLocked installs /edev as the aggregator's EndDevice
// followed by the four managed ones.
//
// The two dummy devices /edev/0 and /edev/1 that the single-device tree carries
// are NOT in it. They exist to be 403'd (the LFDI-gating test), they are not
// part of Figure 15, and leaving them in would make the fleet count seven where
// the fixture is five.
func (s *Server) rebuildFleetEndDeviceListLocked(now int64) {
	subs := s.subs != nil
	boolTrue := true

	agg := fleetEndDevice{
		Href:             "/edev/2",
		LFDI:             s.ClientLFDI,
		SFDI:             s.clientSFDI,
		ChangedTime:      now,
		Enabled:          &boolTrue,
		RegistrationLink: &model.Link{Href: "/edev/2/reg"},
		DERListLink: &model.ListLink{
			Link: model.Link{Href: "/edev/2/der"}, All: 1,
		},
		FunctionSetAssignmentsListLink: &model.ListLink{
			Link: model.Link{Href: "/edev/2/fsa"}, All: 1,
		},
		LogEventListLink: &model.ListLink{
			Link: model.Link{Href: "/edev/2/lev"}, All: 0,
		},
	}
	if s.clientSFDI == 0 {
		// The single-device tree's built-in value, kept so a fleet enabled
		// before any handshake still serves a plausible sFDI rather than none.
		agg.SFDI = 123456789
	}
	if subs {
		agg.Subscribable = 1
		agg.SubscriptionListLink = &model.ListLink{Link: model.Link{Href: "/edev/2/sub"}}
	}

	eds := []fleetEndDevice{agg}
	for _, d := range s.fleet.devices {
		ed := fleetEndDevice{
			Href:             d.Href,
			LFDI:             d.LFDI,
			SFDI:             d.SFDI,
			ChangedTime:      now,
			Enabled:          &boolTrue,
			RegistrationLink: &model.Link{Href: d.Href + "/reg"},
			DERListLink: &model.ListLink{
				Link: model.Link{Href: d.Href + "/der"}, All: 1,
			},
			FunctionSetAssignmentsListLink: &model.ListLink{
				Link: model.Link{Href: d.Href + "/fsa"}, All: 1,
			},
			LogEventListLink: &model.ListLink{
				Link: model.Link{Href: d.Href + "/lev"}, All: 0,
			},
		}
		if subs {
			ed.Subscribable = 1
			ed.SubscriptionListLink = &model.ListLink{Link: model.Link{Href: d.Href + "/sub"}}
		}
		eds = append(eds, ed)
		// Each managed EndDevice is addressable in its own right — MAINT-001's
		// [TC] step GETs one by href and expects 404 only after a deletion.
		edCopy := ed
		s.resources[d.Href] = &edCopy
	}

	n := uint32(len(eds))
	list := &fleetEndDeviceList{
		Href: "/edev", All: n, Results: n, PollRate: 300, EndDevice: eds,
	}
	if subs {
		list.Subscribable = 1
	}
	s.resources["/edev"] = list
	if dcap, ok := s.resources["/dcap"].(*model.DeviceCapability); ok && dcap.EndDeviceListLink != nil {
		dcap.EndDeviceListLink.All = n
	}
}

// fleetOwns reports whether peerLFDI is the aggregator this fleet is bound to.
func (s *Server) fleetOwnsLocked(peerLFDI string) bool {
	if s.fleet == nil || peerLFDI == "" {
		return false
	}
	return strings.EqualFold(peerLFDI, s.ClientLFDI)
}

// serveFleetEndDeviceList answers GET /edev for the aggregator: its own
// EndDevice plus every managed device whose ManagedBy is its LFDI.
//
// This is the generalisation of the single-device rule and the place the LFDI
// mapping described at the top of this file is actually applied. A peer that is
// NOT the aggregator falls through to the exact-LFDI filter, so the fleet is
// never disclosed to a stranger.
func (s *Server) serveFleetEndDeviceList(w http.ResponseWriter, peerLFDI string) bool {
	s.mu.RLock()
	list, ok := s.resources["/edev"].(*fleetEndDeviceList)
	owns := s.fleetOwnsLocked(peerLFDI)
	managed := map[string]bool{}
	if s.fleet != nil {
		for _, d := range s.fleet.devices {
			if strings.EqualFold(d.ManagedBy, peerLFDI) {
				managed[strings.ToUpper(d.LFDI)] = true
			}
		}
	}
	s.mu.RUnlock()
	if !ok || !owns {
		return false
	}

	var filtered []fleetEndDevice
	for _, ed := range list.EndDevice {
		if strings.EqualFold(ed.LFDI, peerLFDI) || managed[strings.ToUpper(ed.LFDI)] {
			filtered = append(filtered, ed)
		}
	}
	n := uint32(len(filtered))
	s.serveXML(w, &fleetEndDeviceList{
		Href: "/edev", All: n, Results: n, PollRate: list.PollRate,
		Subscribable: list.Subscribable, EndDevice: filtered,
	})
	return true
}

// ── admin ────────────────────────────────────────────────────────────────────

// adminFleetReq is the body of POST /admin/fleet: an adjustment to one managed
// device, named by its CTP name.
type adminFleetReq struct {
	// Device is the CTP name (EDA1…EDB2). Required.
	Device string `json:"device"`
	// PIN, when non-zero, replaces the device's Registration pIN. It is
	// REJECTED if its digits do not sum to zero modulo ten: IEEE 2030.5 §6.3.4
	// requires the check digit, the conformance suite FAILs a pIN without one,
	// and a bench that let an operator configure an invalid pIN would report
	// its own misconfiguration as a DUT defect.
	PIN uint32 `json:"pin,omitempty"`
	// ManagedBy, when non-empty, rebinds the device to a different aggregator
	// LFDI. "-" detaches it, which is how MAINT-001's out-of-band removal is
	// driven without deleting the resource.
	ManagedBy string `json:"managed_by,omitempty"`
}

func (s *Server) handleAdminFleet(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.mu.RLock()
		devices, on := s.fleetLocked(), s.fleet != nil
		agg := s.ClientLFDI
		s.mu.RUnlock()
		if devices == nil {
			devices = []FleetDevice{}
		}
		// The node table is published because two of the eleven nodes are
		// ALIASES of gridsim's existing programs (TFA is program 0, SY is
		// program 2 — see the file comment), and an operator reading a
		// DERProgramList that says "Service Point DER Program" where the
		// procedure says TFA has no other way to discover that they are the
		// same program.
		nodes := map[string]any{}
		for name, n := range fleetNodes {
			e := map[string]any{"href": n.href(), "primacy": n.Primacy}
			if n.Alias >= 0 {
				e["aliases_program"] = n.Alias
			}
			nodes[name] = e
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"enabled":         on,
			"size":            len(devices),
			"aggregator_lfdi": agg,
			"aggregator_href": fmt.Sprintf("/edev/%d", aggregatorEdevIndex),
			"devices":         devices,
			"nodes":           nodes,
			"server_time":     s.Now(),
		})
	case http.MethodPost:
		var req adminFleetReq
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		changed, err := s.adjustFleetDevice(req)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		// Outside the lock, and after the resource tree already holds the new
		// list: a subscriber must never be told about a change it could then
		// fail to read back.
		s.notifyChanged(changed...)
		w.WriteHeader(http.StatusNoContent)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

// adjustFleetDevice applies one adminFleetReq and returns the resource hrefs
// whose subscribers must be notified.
func (s *Server) adjustFleetDevice(req adminFleetReq) ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.fleet == nil {
		return nil, fmt.Errorf("the CTP Figure-15 fleet is not enabled (start gridsim with -fleet %d)", FleetSize)
	}
	var dev *FleetDevice
	for _, d := range s.fleet.devices {
		if strings.EqualFold(d.Name, req.Device) {
			dev = d
			break
		}
	}
	if dev == nil {
		return nil, fmt.Errorf("no managed device named %q; the fleet is %s",
			req.Device, strings.Join(fleetDeviceNames(), ", "))
	}
	if req.PIN != 0 {
		if !validCheckDigit(uint64(req.PIN)) {
			return nil, fmt.Errorf("pIN %d has no valid IEEE 2030.5 §6.3.4 check digit (its digits do not sum "+
				"to zero modulo ten); serving it would make the bench's own misconfiguration look like a "+
				"DUT conformance failure", req.PIN)
		}
		dev.PIN = req.PIN
		if reg, ok := s.resources[dev.Href+"/reg"].(*model.Registration); ok {
			reg.PIN = req.PIN
		}
	}
	if req.ManagedBy != "" {
		if req.ManagedBy == "-" {
			dev.ManagedBy = ""
		} else {
			dev.ManagedBy = strings.ToUpper(req.ManagedBy)
		}
	}
	s.rebuildFleetEndDeviceListLocked(time.Now().Unix())
	return []string{"/edev", dev.Href}, nil
}

// validCheckDigit is the IEEE 2030.5 §6.3.2/§6.3.4 rule shared by the pIN and
// the SFDI: the value's digits, check digit included, sum to zero modulo ten.
//
// It takes a uint64 rather than the uint32 a pIN fits in because an SFDI does
// not fit in one — a twelve-digit SFDI silently truncated into uint32 produces a
// different number whose check digit is meaningless, and a check that "passes"
// on the truncation is worse than no check.
func validCheckDigit(v uint64) bool {
	sum := 0
	for x := v; x > 0; x /= 10 {
		sum += int(x % 10)
	}
	return sum%10 == 0
}
