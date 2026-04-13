package integration_test

import (
	"crypto/tls"
	"encoding/xml"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"csip-tls-test/internal/csip/discovery"
	"csip-tls-test/internal/csip/model"
	"csip-tls-test/internal/gridsim"
	"csip-tls-test/internal/httpclient"
)

// testLFDI must match what the grid sim uses for the client's EndDevice.
const testLFDI = "AB12CD34EF56789012345678901234567890ABCD"

func newTestFetcher(ts *httptest.Server) *httpclient.Fetcher {
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
	return httpclient.NewFetcher(ts.URL, client)
}

// TestFullDiscoveryOverHTTP spins up the grid sim as an HTTP server,
// then runs the discovery walker against it using a real HTTP client.
// This is the Milestone 3 equivalent of the Milestone 2 "/dcap GET"
// test, but now we walk the entire resource tree.
//
// Maps to CSIP conformance tests:
//   - COMM-002 (Basic Discovery OOB)
//   - CORE-003 (Polling Interaction — discovery portion)
//   - CORE-005 (Basic Time)
//   - CORE-010 (Function Set Assignments)
//   - CORE-012 (Basic DER Program/Control — discovery portion)
//   - BASIC-001 (DER Identification — LFDI matching)
func TestFullDiscoveryOverHTTP(t *testing.T) {
	sim := gridsim.NewServer(testLFDI)
	ts := httptest.NewServer(sim.Handler())
	defer ts.Close()

	fetcher := newTestFetcher(ts)
	walker := discovery.NewWalker(fetcher, testLFDI)
	tree, err := walker.Discover("/dcap")
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}

	// ── Validate DeviceCapability (COMM-002) ──────────────────
	if tree.DeviceCapability == nil {
		t.Fatal("DeviceCapability is nil")
	}
	if tree.DeviceCapability.Href != "/dcap" {
		t.Errorf("dcap href = %q", tree.DeviceCapability.Href)
	}
	if tree.DeviceCapability.PollRate != 300 {
		t.Errorf("dcap pollRate = %d, want 300", tree.DeviceCapability.PollRate)
	}
	if tree.DeviceCapability.EndDeviceListLink == nil {
		t.Fatal("dcap missing EndDeviceListLink")
	}
	if tree.DeviceCapability.TimeLink == nil {
		t.Fatal("dcap missing TimeLink")
	}
	if tree.DeviceCapability.MirrorUsagePointListLink == nil {
		t.Fatal("dcap missing MirrorUsagePointListLink")
	}

	// ── Validate Time (CORE-005) ──────────────────────────────
	if tree.Time == nil {
		t.Fatal("Time is nil")
	}
	if tree.Time.Quality != 7 {
		t.Errorf("Time.Quality = %d, want 7 (intentionally uncoordinated)", tree.Time.Quality)
	}
	if tree.Time.CurrentTime <= 0 {
		t.Error("Time.CurrentTime should be positive")
	}

	// ── Validate EndDevice match by LFDI (BASIC-001) ──────────
	if tree.SelfDevice == nil {
		t.Fatal("SelfDevice is nil — LFDI match failed")
	}
	if tree.SelfDevice.LFDI != testLFDI {
		t.Errorf("SelfDevice.LFDI = %q, want %q", tree.SelfDevice.LFDI, testLFDI)
	}
	if tree.SelfDevice.RegistrationLink == nil {
		t.Error("SelfDevice missing RegistrationLink")
	}

	// ── Validate DERList (CORE-009) ───────────────────────────
	if tree.DERList == nil {
		t.Fatal("DERList is nil")
	}
	if len(tree.DERList.DER) != 1 {
		t.Errorf("DERList has %d DERs, want 1", len(tree.DERList.DER))
	}

	// ── Validate FSAList (CORE-010) ───────────────────────────
	if tree.FSAList == nil {
		t.Fatal("FSAList is nil")
	}
	if len(tree.FSAList.FunctionSetAssignments) != 1 {
		t.Fatalf("FSAList has %d FSAs, want 1", len(tree.FSAList.FunctionSetAssignments))
	}
	fsa := tree.FSAList.FunctionSetAssignments[0]
	if fsa.DERProgramListLink == nil {
		t.Fatal("FSA missing DERProgramListLink")
	}
	if fsa.TimeLink == nil {
		t.Error("FSA missing TimeLink (required by BASE.007)")
	}

	// ── Validate 3 DERPrograms (CORE-012) ────────────────────
	if len(tree.Programs) != 3 {
		t.Fatalf("got %d programs, want 3 (primacy 1/5/10)", len(tree.Programs))
	}

	// Programs are in list order: primacy=1, primacy=5, primacy=10.
	// HighestPriorityProgram confirms sorting logic.
	hp := discovery.HighestPriorityProgram(tree.Programs)
	if hp == nil || hp.Program.Primacy != 1 {
		t.Fatal("HighestPriorityProgram should have primacy=1")
	}

	// Use Programs[0] (service point, primacy=1) for detailed assertions.
	ps := tree.Programs[0]
	if ps.Program.Primacy != 1 {
		t.Errorf("Programs[0].Primacy = %d, want 1", ps.Program.Primacy)
	}

	// ── Validate DefaultDERControl ────────────────────────────
	if ps.DefaultControl == nil {
		t.Fatal("DefaultDERControl is nil")
	}
	if ps.DefaultControl.DERControlBase.OpModExpLimW == nil {
		t.Fatal("DefaultDERControl missing OpModExpLimW")
	}
	if ps.DefaultControl.DERControlBase.OpModExpLimW.Value != 5000 {
		t.Errorf("Default OpModExpLimW = %d, want 5000", ps.DefaultControl.DERControlBase.OpModExpLimW.Value)
	}
	if ps.DefaultControl.DERControlBase.OpModConnect == nil || !*ps.DefaultControl.DERControlBase.OpModConnect {
		t.Error("DefaultDERControl.OpModConnect should be true")
	}
	if ps.DefaultControl.DERControlBase.OpModEnergize == nil || !*ps.DefaultControl.DERControlBase.OpModEnergize {
		t.Error("DefaultDERControl.OpModEnergize should be true")
	}

	// ── Validate DERControlList (4 controls in SP program) ────
	if ps.Controls == nil {
		t.Fatal("DERControlList is nil")
	}
	if len(ps.Controls.DERControl) != 4 {
		t.Fatalf("SP program: got %d controls, want 4", len(ps.Controls.DERControl))
	}

	// SP-001: scheduled, potentiallySuperseded=true
	sp001 := ps.Controls.DERControl[0]
	if sp001.DERControlBase.OpModExpLimW == nil || sp001.DERControlBase.OpModExpLimW.Value != 3000 {
		t.Errorf("SP-001 OpModExpLimW = %v, want 3000", sp001.DERControlBase.OpModExpLimW)
	}
	if sp001.Interval.Duration != 120 {
		t.Errorf("SP-001 duration = %d, want 120", sp001.Interval.Duration)
	}
	if sp001.EventStatus == nil || sp001.EventStatus.CurrentStatus != 0 {
		t.Error("SP-001 should be Scheduled (status=0)")
	}
	if sp001.EventStatus != nil && !sp001.EventStatus.PotentiallySuperseded {
		t.Error("SP-001 should have potentiallySuperseded=true")
	}

	// SP-002: scheduled, supersedes SP-001
	sp002 := ps.Controls.DERControl[1]
	if sp002.DERControlBase.OpModExpLimW == nil || sp002.DERControlBase.OpModExpLimW.Value != 2500 {
		t.Errorf("SP-002 OpModExpLimW = %v, want 2500", sp002.DERControlBase.OpModExpLimW)
	}
	if sp002.Interval.Start != sp001.Interval.Start {
		t.Error("SP-002 should start at the same time as SP-001 (overlapping interval)")
	}
	if sp002.CreationTime <= sp001.CreationTime {
		t.Error("SP-002 creationTime should be later than SP-001 (newer wins)")
	}

	// SP-003: cancelled — client must drop it
	sp003 := ps.Controls.DERControl[2]
	if sp003.EventStatus == nil || sp003.EventStatus.CurrentStatus != 6 {
		t.Errorf("SP-003 CurrentStatus = %v, want 6 (Cancelled)", sp003.EventStatus)
	}

	// SP-004: future control with randomizeStart
	sp004 := ps.Controls.DERControl[3]
	if sp004.RandomizeStart == nil {
		t.Error("SP-004 should have RandomizeStart set")
	}
	if sp004.RandomizeStart != nil && *sp004.RandomizeStart != 30 {
		t.Errorf("SP-004 RandomizeStart = %d, want 30", *sp004.RandomizeStart)
	}

	// ── Validate site program (primacy=5) ─────────────────────
	site := tree.Programs[1]
	if site.Program.Primacy != 5 {
		t.Errorf("Programs[1].Primacy = %d, want 5", site.Program.Primacy)
	}
	if site.DefaultControl == nil || site.DefaultControl.DERControlBase.OpModExpLimW == nil {
		t.Fatal("Site program DefaultDERControl missing OpModExpLimW")
	}
	if site.DefaultControl.DERControlBase.OpModExpLimW.Value != 7000 {
		t.Errorf("Site Default OpModExpLimW = %d, want 7000", site.DefaultControl.DERControlBase.OpModExpLimW.Value)
	}
	if len(site.Controls.DERControl) != 2 {
		t.Errorf("Site program: got %d controls, want 2", len(site.Controls.DERControl))
	}

	// ── Validate system program (primacy=10) ──────────────────
	sys := tree.Programs[2]
	if sys.Program.Primacy != 10 {
		t.Errorf("Programs[2].Primacy = %d, want 10", sys.Program.Primacy)
	}
	if sys.DefaultControl == nil || sys.DefaultControl.DERControlBase.OpModExpLimW == nil {
		t.Fatal("System program DefaultDERControl missing OpModExpLimW")
	}
	if sys.DefaultControl.DERControlBase.OpModExpLimW.Value != 9000 {
		t.Errorf("System Default OpModExpLimW = %d, want 9000", sys.DefaultControl.DERControlBase.OpModExpLimW.Value)
	}

	// ── Validate MirrorUsagePointList discovered ──────────────
	if tree.MirrorUsagePoints == nil {
		t.Fatal("MirrorUsagePointList is nil")
	}

	// ── Registration PIN verification (BASIC-001, CORE-009) ───
	// gridsim serves PIN=111115 (CSIP conformance test value, spec §3.2.3).
	// The client must verify this before trusting any control events.
	reg, err := walker.VerifyRegistration(tree.SelfDevice, 111115)
	if err != nil {
		t.Fatalf("VerifyRegistration: %v", err)
	}
	if reg.PIN != 111115 {
		t.Errorf("PIN = %d, want 111115", reg.PIN)
	}

	// ── ClockOffset populated from /tm ────────────────────────
	// gridsim's Time uses time.Now(), so offset should be near zero.
	if tree.ClockOffset < -5 || tree.ClockOffset > 5 {
		t.Errorf("ClockOffset = %d, want near 0 (gridsim uses local time)", tree.ClockOffset)
	}

	t.Log("✓ Full CSIP discovery walk completed successfully")
	t.Logf("  DeviceCapability: %s (pollRate=%d)", tree.DeviceCapability.Href, tree.DeviceCapability.PollRate)
	t.Logf("  Time: quality=%d, tz=%d", tree.Time.Quality, tree.Time.TzOffset)
	t.Logf("  SelfDevice: %s (LFDI=%s)", tree.SelfDevice.Href, tree.SelfDevice.LFDI)
	t.Logf("  FSAs: %d, Programs: %d (primacy 1/5/10)", len(tree.FSAList.FunctionSetAssignments), len(tree.Programs))
	t.Logf("  HP Default OpModExpLimW: %dW", ps.DefaultControl.DERControlBase.OpModExpLimW.Value)
}

// TestDefaultDERControlFallback verifies that discovery.ActiveDefaultControl
// returns the DefaultDERControl from the highest-priority program (primacy=1).
// Per BASIC-016 and CORE-012: when no DERControl event is active, the client
// applies this fallback value.
func TestDefaultDERControlFallback(t *testing.T) {
	sim := gridsim.NewServer(testLFDI)
	ts := httptest.NewServer(sim.Handler())
	defer ts.Close()

	fetcher := newTestFetcher(ts)
	walker := discovery.NewWalker(fetcher, testLFDI)
	tree, err := walker.Discover("/dcap")
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}

	active := discovery.ActiveDefaultControl(tree.Programs)
	if active == nil {
		t.Fatal("ActiveDefaultControl returned nil")
	}
	// Highest-priority (primacy=1) DefaultDERControl has 5kW limit.
	if active.DERControlBase.OpModExpLimW == nil {
		t.Fatal("active DefaultDERControl missing OpModExpLimW")
	}
	if active.DERControlBase.OpModExpLimW.Value != 5000 {
		t.Errorf("fallback OpModExpLimW = %d, want 5000 (from primacy=1 program)", active.DERControlBase.OpModExpLimW.Value)
	}
	t.Logf("✓ DefaultDERControl fallback: OpModExpLimW=%dW (from highest-priority program, primacy=%d)",
		active.DERControlBase.OpModExpLimW.Value,
		discovery.HighestPriorityProgram(tree.Programs).Program.Primacy)
}

// TestMUPPostCreate verifies the MirrorUsagePoint POST flow:
//
//	POST /mup → 201 Created + Location header
//	GET  /mup/{n} → 200 OK, returns the registered MUP
//	POST /mup/{n} → 204 No Content (readings accepted)
func TestMUPPostCreate(t *testing.T) {
	sim := gridsim.NewServer(testLFDI)
	ts := httptest.NewServer(sim.Handler())
	defer ts.Close()

	fetcher := newTestFetcher(ts)

	// POST a MirrorUsagePoint to register a new measurement point.
	mup := model.MirrorUsagePoint{
		MRID:                "MUP-001",
		RoleFlags:           49,
		ServiceCategoryKind: 0,
		Status:              0,
		PostRate:            900,
	}
	body, err := xml.Marshal(mup)
	if err != nil {
		t.Fatalf("marshal MUP: %v", err)
	}

	_, location, err := fetcher.Post("/mup", body, gridsim.ContentType)
	if err != nil {
		t.Fatalf("POST /mup: %v", err)
	}
	if !strings.HasPrefix(location, "/mup/") {
		t.Errorf("Location = %q, want /mup/N", location)
	}

	// GET the created MUP — should return 200 with our MRID.
	gotBody, err := fetcher.Get(location)
	if err != nil {
		t.Fatalf("GET %s: %v", location, err)
	}
	var got model.MirrorUsagePoint
	if err := xml.Unmarshal(gotBody, &got); err != nil {
		t.Fatalf("unmarshal MUP: %v", err)
	}
	if got.MRID != "MUP-001" {
		t.Errorf("MUP.MRID = %q, want MUP-001", got.MRID)
	}
	if got.Href != location {
		t.Errorf("MUP.Href = %q, want %q", got.Href, location)
	}
	if got.PostRate != 900 {
		t.Errorf("MUP.PostRate = %d, want 900", got.PostRate)
	}

	// POST readings to the registered MUP endpoint — should return 204.
	mmr := model.MirrorMeterReading{
		MRID:        "MMR-001",
		Description: "Real power export",
	}
	readingBody, _ := xml.Marshal(mmr)
	_, _, err = fetcher.Post(location, readingBody, gridsim.ContentType)
	if err != nil {
		t.Fatalf("POST %s (readings): %v", location, err)
	}

	t.Logf("✓ MUP POST flow: registered at %s, readings accepted", location)
}

// TestMUPPostNotFound verifies that POST to an unknown /mup/{n} returns 404.
func TestMUPPostNotFound(t *testing.T) {
	sim := gridsim.NewServer(testLFDI)
	ts := httptest.NewServer(sim.Handler())
	defer ts.Close()

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/mup/999", strings.NewReader("<MirrorMeterReading/>"))
	req.Header.Set("Content-Type", gridsim.ContentType)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("POST /mup/999: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("POST /mup/999 status = %d, want 404", resp.StatusCode)
	}
}

// TestDiscoveryContentType verifies the grid sim returns the correct
// Content-Type header (GEN.003: application/sep+xml).
func TestDiscoveryContentType(t *testing.T) {
	sim := gridsim.NewServer(testLFDI)
	ts := httptest.NewServer(sim.Handler())
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/dcap")
	if err != nil {
		t.Fatalf("GET /dcap: %v", err)
	}
	defer resp.Body.Close()

	ct := resp.Header.Get("Content-Type")
	if ct != "application/sep+xml" {
		t.Errorf("Content-Type = %q, want application/sep+xml (GEN.003)", ct)
	}
}

// TestDiscovery404OnMissingResource verifies the grid sim returns 404
// for unknown paths (GEN.037).
func TestDiscovery404OnMissingResource(t *testing.T) {
	sim := gridsim.NewServer(testLFDI)
	ts := httptest.NewServer(sim.Handler())
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/nonexistent")
	if err != nil {
		t.Fatalf("GET /nonexistent: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want 404", resp.StatusCode)
	}
}

// TestDiscoveryMethodNotAllowed verifies the grid sim returns 405
// for non-GET methods on resource paths (CORE-001).
func TestDiscoveryMethodNotAllowed(t *testing.T) {
	sim := gridsim.NewServer(testLFDI)
	ts := httptest.NewServer(sim.Handler())
	defer ts.Close()

	req, _ := http.NewRequest(http.MethodDelete, ts.URL+"/dcap", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("DELETE /dcap: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want 405", resp.StatusCode)
	}
}

// TestLFDIGatedEndDeviceList verifies that when X-Peer-LFDI is present,
// GET /edev returns only the connecting device's EndDevice (not the full list).
// This tests the LFDI-gated view via the gridsim HTTP handler directly.
func TestLFDIGatedEndDeviceList(t *testing.T) {
	sim := gridsim.NewServer(testLFDI)
	ts := httptest.NewServer(sim.Handler())
	defer ts.Close()

	client := &http.Client{}

	// Without X-Peer-LFDI → full list (3 devices).
	resp, err := http.Get(ts.URL + "/edev")
	if err != nil {
		t.Fatalf("GET /edev: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	var full model.EndDeviceList
	if err := xml.NewDecoder(resp.Body).Decode(&full); err != nil {
		t.Fatalf("decode full list: %v", err)
	}
	if full.All != 3 {
		t.Errorf("full list All = %d, want 3", full.All)
	}

	// With X-Peer-LFDI → filtered list (1 device).
	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/edev", nil)
	req.Header.Set("X-Peer-LFDI", testLFDI)
	resp2, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET /edev with peer LFDI: %v", err)
	}
	defer resp2.Body.Close()
	var filtered model.EndDeviceList
	if err := xml.NewDecoder(resp2.Body).Decode(&filtered); err != nil {
		t.Fatalf("decode filtered list: %v", err)
	}
	if filtered.All != 1 {
		t.Errorf("filtered list All = %d, want 1", filtered.All)
	}
	if len(filtered.EndDevice) != 1 {
		t.Fatalf("filtered list has %d devices, want 1", len(filtered.EndDevice))
	}
	if filtered.EndDevice[0].LFDI != testLFDI {
		t.Errorf("filtered device LFDI = %q, want %q", filtered.EndDevice[0].LFDI, testLFDI)
	}

	t.Logf("✓ LFDI-gated /edev: full=%d devices, filtered=%d devices", full.All, filtered.All)
}

// TestLFDIGatedForbidden verifies that /edev/0 and /edev/1 return 403
// when X-Peer-LFDI is set (the connecting device is not those devices).
func TestLFDIGatedForbidden(t *testing.T) {
	sim := gridsim.NewServer(testLFDI)
	ts := httptest.NewServer(sim.Handler())
	defer ts.Close()

	client := &http.Client{}
	for _, path := range []string{"/edev/0", "/edev/1", "/edev/0/fsa"} {
		req, _ := http.NewRequest(http.MethodGet, ts.URL+path, nil)
		req.Header.Set("X-Peer-LFDI", testLFDI)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("GET %s (with peer LFDI): status = %d, want 403", path, resp.StatusCode)
		}
	}

	// Without X-Peer-LFDI: /edev/0 is accessible (dummy devices exist in map).
	// Note: /edev/0 has no FSA links so it's not useful, but it's not forbidden.
	resp, err := http.Get(ts.URL + "/edev/0")
	if err != nil {
		t.Fatalf("GET /edev/0 no peer: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode == http.StatusForbidden {
		t.Error("GET /edev/0 without peer LFDI should not return 403")
	}

	t.Log("✓ LFDI-gated 403 for non-client EndDevice paths")
}
