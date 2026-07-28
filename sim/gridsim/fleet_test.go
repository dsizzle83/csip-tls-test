package gridsim

// fleet_test.go drives the CTP Figure-15 topology against the SERVED BYTES,
// not against the Go structs that produced them. Every assertion below reads
// the XML a client would receive, because the fixture's whole purpose is to be
// what a conformance harness sees on the wire — a struct that is right and a
// marshal that is wrong is a fixture that does not exist.

import (
	"encoding/xml"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"csip-tls-test/internal/csip/identity"
)

const testAggLFDI = "AABBCCDDEEFF00112233445566778899AABBCCDD"

// fleetServer starts a gridsim with the fixture on and returns it with a client
// that presents the aggregator's LFDI the way the mTLS front end would.
func fleetServer(t *testing.T, subscription bool) (*Server, func(method, path string) (*http.Response, []byte)) {
	t.Helper()
	s := NewServer(testAggLFDI)
	if subscription {
		s.EnableSubscriptions()
	}
	if err := s.EnableFleet(FleetSize); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(s.Handler())
	t.Cleanup(srv.Close)

	return s, func(method, path string) (*http.Response, []byte) {
		t.Helper()
		req, err := http.NewRequest(method, srv.URL+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("X-Peer-LFDI", testAggLFDI)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		var b strings.Builder
		buf := make([]byte, 4096)
		for {
			n, rerr := resp.Body.Read(buf)
			b.Write(buf[:n])
			if rerr != nil {
				break
			}
		}
		return resp, []byte(b.String())
	}
}

// parsed shapes — deliberately minimal and local, so a test asserts on the
// elements it names rather than inheriting a model's tolerance for absence.
type xEndDeviceList struct {
	XMLName   xml.Name     `xml:"EndDeviceList"`
	All       int          `xml:"all,attr"`
	Results   int          `xml:"results,attr"`
	EndDevice []xEndDevice `xml:"EndDevice"`
}

type xEndDevice struct {
	Href    string `xml:"href,attr"`
	LFDI    string `xml:"lFDI"`
	SFDI    uint64 `xml:"sFDI"`
	FSALink *xLink `xml:"FunctionSetAssignmentsListLink"`
	DERLink *xLink `xml:"DERListLink"`
	RegLink *xLink `xml:"RegistrationLink"`
	LogLink *xLink `xml:"LogEventListLink"`
	SubLink *xLink `xml:"SubscriptionListLink"`
}

type xLink struct {
	Href string `xml:"href,attr"`
}

type xFSAList struct {
	XMLName      xml.Name `xml:"FunctionSetAssignmentsList"`
	Subscribable string   `xml:"subscribable,attr"`
	FSA          []struct {
		MRID    string `xml:"mRID"`
		DERPLnk *xLink `xml:"DERProgramListLink"`
		TimeLnk *xLink `xml:"TimeLink"`
	} `xml:"FunctionSetAssignments"`
}

type xProgramList struct {
	XMLName xml.Name `xml:"DERProgramList"`
	Program []struct {
		Href    string `xml:"href,attr"`
		MRID    string `xml:"mRID"`
		Primacy int    `xml:"primacy"`
		Ctrl    *xLink `xml:"DERControlListLink"`
		Default *xLink `xml:"DefaultDERControlLink"`
	} `xml:"DERProgram"`
}

type xRegistration struct {
	XMLName xml.Name `xml:"Registration"`
	PIN     uint32   `xml:"pIN"`
}

// TestFleetServesTheFigure15EndDeviceList is the criterion critAggregatorFleet
// reads, asserted here on gridsim's own output: five EndDevice instances, each
// carrying both links the AGG-001 setup requires.
func TestFleetServesTheFigure15EndDeviceList(t *testing.T) {
	_, get := fleetServer(t, true)

	resp, body := get("GET", "/edev")
	if resp.StatusCode != 200 {
		t.Fatalf("GET /edev = %d", resp.StatusCode)
	}
	var list xEndDeviceList
	if err := xml.Unmarshal(body, &list); err != nil {
		t.Fatal(err)
	}
	if list.All != 5 || list.Results != 5 || len(list.EndDevice) != 5 {
		t.Fatalf("EndDeviceList carries all=%d results=%d and %d entries; CTP Figure 15 is the aggregator "+
			"plus EDA1/EDA2/EDB1/EDB2 = 5", list.All, list.Results, len(list.EndDevice))
	}
	for _, ed := range list.EndDevice {
		if ed.FSALink == nil || ed.DERLink == nil {
			t.Errorf("%s carries FSALink=%v DERListLink=%v; the AGG-001 setup requires both on every "+
				"EndDevice instance", ed.Href, ed.FSALink != nil, ed.DERLink != nil)
		}
		if ed.LogLink == nil {
			t.Errorf("%s carries no LogEventListLink; UTIL-001 setup steps 5 and 6 both require one", ed.Href)
		}
		if ed.SubLink == nil {
			t.Errorf("%s carries no SubscriptionListLink with the function set enabled", ed.Href)
		}
	}

	// The two dummy devices exist to be 403'd and are not part of Figure 15.
	for _, ed := range list.EndDevice {
		if ed.Href == "/edev/0" || ed.Href == "/edev/1" {
			t.Errorf("the fleet list carries the dummy device %s, which would make the fixture read as "+
				"seven devices where the figure has five", ed.Href)
		}
	}
}

// TestFleetLFDIMappingIsOneAggregatorAndFourOwnIdentities is the design
// question stated as a test.
//
// UTIL-002 procedure step 3 has the client verify "there is an EndDevice
// instance with an SFDI/LFDI that matches its own (aggregator) SFDI/LFDI" —
// exactly one. UTIL-001 setup step 6 gives EDA1..EDB2 "EndDevice SFDI and
// LFDI", their own. A fixture that gave all five the client's LFDI would pass a
// naive fleet count and then make critSelfIdentity ambiguous, so both halves
// are pinned.
func TestFleetLFDIMappingIsOneAggregatorAndFourOwnIdentities(t *testing.T) {
	s, get := fleetServer(t, true)

	_, body := get("GET", "/edev")
	var list xEndDeviceList
	if err := xml.Unmarshal(body, &list); err != nil {
		t.Fatal(err)
	}

	matches, seen := 0, map[string]bool{}
	for _, ed := range list.EndDevice {
		if seen[strings.ToUpper(ed.LFDI)] {
			t.Errorf("two EndDevices share the lFDI %s; a managed device's identity is its own", ed.LFDI)
		}
		seen[strings.ToUpper(ed.LFDI)] = true
		if strings.EqualFold(ed.LFDI, testAggLFDI) {
			matches++
			if ed.Href != "/edev/2" {
				t.Errorf("the aggregator's own LFDI is served on %s; it has always been /edev/2 and the "+
					"single-device tree's hrefs must not move under the fleet lever", ed.Href)
			}
		}
		if len(ed.LFDI) != 40 {
			t.Errorf("%s carries a %d-character lFDI; IEEE 2030.5 §6.3.2 is 160 bits as 40 hex digits",
				ed.Href, len(ed.LFDI))
		}
	}
	if matches != 1 {
		t.Fatalf("%d EndDevices carry the DUT's own LFDI; UTIL-002 step 3 verifies there is ONE", matches)
	}

	// The four are DERIVED, and the derivation is the documented one — a
	// reviewer recomputing an LFDI from the file's stated preimage must get the
	// same answer, or the documentation is decoration.
	for _, d := range s.Fleet() {
		wantLFDI, wantSFDI := identity.FromSeed(fleetSeed(testAggLFDI, d.Name))
		if d.LFDI != wantLFDI.String() {
			t.Errorf("%s LFDI %s does not match the documented derivation %s", d.Name, d.LFDI, wantLFDI)
		}
		if d.SFDI != uint64(wantSFDI) {
			t.Errorf("%s SFDI %d does not match §6.3.3 over its own LFDI (%d)", d.Name, d.SFDI, wantSFDI)
		}
		if !validCheckDigit(d.SFDI) {
			t.Errorf("%s SFDI %d has no valid §6.3.3 check digit", d.Name, d.SFDI)
		}
	}
}

// TestFleetIsServedToItsAggregatorAndNobodyElse pins the access rule that
// replaces the single-device LFDI filter: the managed devices are visible
// because the SERVER assigned them to this aggregator's EndDeviceList, and a
// peer that is not that aggregator sees what it always saw.
func TestFleetIsServedToItsAggregatorAndNobodyElse(t *testing.T) {
	s, _ := fleetServer(t, true)
	srv := httptest.NewServer(s.Handler())
	defer srv.Close()

	fetch := func(lfdi string) xEndDeviceList {
		t.Helper()
		req, _ := http.NewRequest("GET", srv.URL+"/edev", nil)
		if lfdi != "" {
			req.Header.Set("X-Peer-LFDI", lfdi)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		buf := make([]byte, 1<<16)
		n, _ := resp.Body.Read(buf)
		var l xEndDeviceList
		if err := xml.Unmarshal(buf[:n], &l); err != nil {
			t.Fatalf("unmarshal for peer %q: %v", lfdi, err)
		}
		return l
	}

	if got := len(fetch(testAggLFDI).EndDevice); got != 5 {
		t.Errorf("the aggregator sees %d EndDevices, want 5", got)
	}
	if got := len(fetch("00000000000000000000000000000000DEADBEEF").EndDevice); got != 0 {
		t.Errorf("a stranger sees %d EndDevices; the fleet belongs to the aggregator the server assigned "+
			"it to, and disclosing it to any peer would make the LFDI gate decorative", got)
	}

	// Detaching a device out of band removes it from the list, which is the
	// lever MAINT-001's "no longer being managed by the aggregator" needs.
	if _, err := s.adjustFleetDevice(adminFleetReq{Device: "EDA1", ManagedBy: "-"}); err != nil {
		t.Fatal(err)
	}
	if got := len(fetch(testAggLFDI).EndDevice); got != 4 {
		t.Errorf("after detaching EDA1 the aggregator sees %d EndDevices, want 4", got)
	}
}

// TestFleetProgramsFollowTheParentChain covers UTIL-001's last pass criterion —
// "Each EndDevice should be assigned a link to all the DER programs associated
// with its parent nodes" — and the ordering critProgramList reports on.
func TestFleetProgramsFollowTheParentChain(t *testing.T) {
	_, get := fleetServer(t, true)

	want := map[string][]string{
		"/edev/3": {"DERP-FDA-001", "DERP-SPA1-001", "DERP-SP-001", "DERP-SGA-001", "DERP-SYS-001"}, // EDA1
		"/edev/4": {"DERP-FDA-001", "DERP-SPA2-001", "DERP-SP-001", "DERP-SGA-001", "DERP-SYS-001"}, // EDA2
		"/edev/5": {"DERP-FDB-001", "DERP-SPB1-001", "DERP-TFB-001", "DERP-SGB-001", "DERP-SYS-001"},
		"/edev/6": {"DERP-FDB-001", "DERP-SPB2-001", "DERP-TFB-001", "DERP-SGB-001", "DERP-SYS-001"},
	}

	for edev, wantMRIDs := range want {
		resp, body := get("GET", edev+"/fsa")
		if resp.StatusCode != 200 {
			t.Fatalf("GET %s/fsa = %d", edev, resp.StatusCode)
		}
		var fsa xFSAList
		if err := xml.Unmarshal(body, &fsa); err != nil {
			t.Fatal(err)
		}
		if fsa.Subscribable != "1" {
			t.Errorf("%s/fsa subscribable=%q; critSubscriptionAdvertised requires 1 (unconditional "+
				"subscription) and reports SKIP for anything else", edev, fsa.Subscribable)
		}
		if len(fsa.FSA) != 1 || fsa.FSA[0].DERPLnk == nil || fsa.FSA[0].TimeLnk == nil {
			t.Fatalf("%s/fsa: %d FSA, DERProgramListLink/TimeLink present=%v/%v — IEEE 2030.5 §9.2.3 "+
				"requires an event-carrying FSA to carry a TimeLink", edev, len(fsa.FSA),
				len(fsa.FSA) > 0 && fsa.FSA[0].DERPLnk != nil, len(fsa.FSA) > 0 && fsa.FSA[0].TimeLnk != nil)
		}

		resp, body = get("GET", fsa.FSA[0].DERPLnk.Href)
		if resp.StatusCode != 200 {
			t.Fatalf("GET %s = %d", fsa.FSA[0].DERPLnk.Href, resp.StatusCode)
		}
		var pl xProgramList
		if err := xml.Unmarshal(body, &pl); err != nil {
			t.Fatal(err)
		}
		var got []string
		last := -1
		for _, p := range pl.Program {
			got = append(got, p.MRID)
			if p.Primacy < last {
				t.Errorf("%s DERProgramList is not in ascending primacy order (%d after %d); a client that "+
					"trusts list order would mis-prioritise", edev, p.Primacy, last)
			}
			last = p.Primacy
			if p.Ctrl == nil || p.Default == nil {
				t.Errorf("%s program %s carries DERControlListLink=%v DefaultDERControlLink=%v; a node "+
					"program with no control list cannot receive the controls the node is for",
					edev, p.MRID, p.Ctrl != nil, p.Default != nil)
			}
		}
		if strings.Join(got, ",") != strings.Join(wantMRIDs, ",") {
			t.Errorf("%s programs = %v, want %v", edev, got, wantMRIDs)
		}
	}
}

// TestTFAAndSYAliasTheProgramsTheSuitePublishesOnto is the load-bearing detail
// of the ladder: suitecsip's aggregator rows publish their TFA and SY controls
// through POST /admin/control with program 0 and program 2 (progTFA/progSY). If
// the fleet's TFA were a NEW program, every one of those controls would land
// somewhere EDA1 and EDA2 never look, and AGG-003..AGG-012 would report a DUT
// that ignored an event it was never sent.
func TestTFAAndSYAliasTheProgramsTheSuitePublishesOnto(t *testing.T) {
	_, get := fleetServer(t, true)

	_, body := get("GET", "/edev/3/fsa/0/derp") // EDA1
	var pl xProgramList
	if err := xml.Unmarshal(body, &pl); err != nil {
		t.Fatal(err)
	}
	seen := map[string]string{}
	for _, p := range pl.Program {
		seen[p.MRID] = p.Ctrl.Href
	}
	if got := seen["DERP-SP-001"]; got != "/derp/0/derc" {
		t.Errorf("EDA1's TFA program points its DERControlList at %q, not /derp/0/derc — POST "+
			"/admin/control {program:0} would never reach it", got)
	}
	if got := seen["DERP-SYS-001"]; got != "/derp/2/derc" {
		t.Errorf("EDA1's SY program points its DERControlList at %q, not /derp/2/derc", got)
	}

	// EDB1 must NOT see TFA: AGG-003's untagged negative pass criterion is
	// "Client fails if EDB1 and/or EDB2 POSTs any responses to the TFA event".
	_, body = get("GET", "/edev/5/fsa/0/derp")
	var plB xProgramList
	if err := xml.Unmarshal(body, &plB); err != nil {
		t.Fatal(err)
	}
	for _, p := range plB.Program {
		if p.MRID == "DERP-SP-001" {
			t.Error("EDB1's DERProgramList carries the TFA program; the CTP's aggregator rows turn on EDB1 " +
				"and EDB2 being OUTSIDE the TFA scope")
		}
	}
}

// TestFleetRegistrationPINsCarryACheckDigit guards the bench against reporting
// its own misconfiguration as a DUT failure: critRegistrationPIN FAILs a pIN
// whose digits do not sum to zero modulo ten (IEEE 2030.5 §6.3.4).
func TestFleetRegistrationPINsCarryACheckDigit(t *testing.T) {
	s, get := fleetServer(t, true)

	for _, d := range s.Fleet() {
		resp, body := get("GET", d.Href+"/reg")
		if resp.StatusCode != 200 {
			t.Fatalf("GET %s/reg = %d", d.Href, resp.StatusCode)
		}
		var reg xRegistration
		if err := xml.Unmarshal(body, &reg); err != nil {
			t.Fatal(err)
		}
		if reg.PIN != d.PIN {
			t.Errorf("%s serves pIN %d where /admin/fleet reports %d", d.Name, reg.PIN, d.PIN)
		}
		if !validCheckDigit(uint64(reg.PIN)) {
			t.Errorf("%s pIN %d has no valid §6.3.4 check digit", d.Name, reg.PIN)
		}
	}

	// A distinct pIN per device, or three of the four rows would be checking the
	// same fact.
	seen := map[uint32]string{}
	for _, d := range s.Fleet() {
		if prev, dup := seen[d.PIN]; dup {
			t.Errorf("%s and %s share pIN %d", prev, d.Name, d.PIN)
		}
		seen[d.PIN] = d.Name
	}

	// And the admin lever refuses an invalid one rather than serving it.
	if _, err := s.adjustFleetDevice(adminFleetReq{Device: "EDA1", PIN: 111111}); err == nil {
		t.Error("POST /admin/fleet accepted pIN 111111, whose digits sum to 6; serving it would make the " +
			"bench's own misconfiguration read as a DUT conformance failure")
	}
	if _, err := s.adjustFleetDevice(adminFleetReq{Device: "EDA1", PIN: 111115}); err != nil {
		t.Errorf("POST /admin/fleet rejected the valid pIN 111115: %v", err)
	}
}

// TestFleetRefusesASizeTheFigureDoesNotHave keeps a half-built fixture from
// reading as success — the same discipline scripts/bench-sims-up.sh applies to
// SIM_FLEET.
func TestFleetRefusesASizeTheFigureDoesNotHave(t *testing.T) {
	for _, n := range []int{0, 1, 3, 5} {
		if err := NewServer(testAggLFDI).EnableFleet(n); err == nil {
			t.Errorf("EnableFleet(%d) was accepted; only %d is defined", n, FleetSize)
		}
	}
}

// TestFleetWithoutSubscriptionsAdvertisesNoneOfIt pins that the two levers are
// independent, so that a bench which enables only the fleet does not quietly
// claim a function set it is not serving.
func TestFleetWithoutSubscriptionsAdvertisesNoneOfIt(t *testing.T) {
	_, get := fleetServer(t, false)

	_, body := get("GET", "/edev")
	if strings.Contains(string(body), "SubscriptionListLink") {
		t.Error("the fleet advertises a SubscriptionListLink with the Subscription function set off")
	}
	var list xEndDeviceList
	if err := xml.Unmarshal(body, &list); err != nil {
		t.Fatal(err)
	}
	if len(list.EndDevice) != 5 {
		t.Errorf("the fleet is %d EndDevices without the subscription lever, want 5", len(list.EndDevice))
	}
	resp, _ := get("POST", "/edev/2/sub")
	if resp.StatusCode == http.StatusCreated {
		t.Error("a Subscription POST was accepted with the function set off")
	}
}
