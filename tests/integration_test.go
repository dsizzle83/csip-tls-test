package integration_test

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"testing"

	"csip-tls-test/internal/csip/discovery"
	"csip-tls-test/internal/gridsim"
	"csip-tls-test/internal/httpclient"
)

// testLFDI must match what the grid sim uses for the client's EndDevice.
const testLFDI = "AB12CD34EF56789012345678901234567890ABCD"

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
	// Start the grid sim
	sim := gridsim.NewServer(testLFDI)
	ts := httptest.NewServer(sim.Handler())
	defer ts.Close()

	// Create an HTTP-based fetcher pointing at the test server
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
	fetcher := httpclient.NewFetcher(ts.URL, client)

	// Run the full discovery walk
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

	// ── Validate DERPrograms (CORE-012) ───────────────────────
	if len(tree.Programs) != 1 {
		t.Fatalf("got %d programs, want 1", len(tree.Programs))
	}
	ps := tree.Programs[0]
	if ps.Program.Primacy != 1 {
		t.Errorf("Program.Primacy = %d, want 1", ps.Program.Primacy)
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

	// ── Validate DERControlList ───────────────────────────────
	if ps.Controls == nil {
		t.Fatal("DERControlList is nil")
	}
	if len(ps.Controls.DERControl) != 1 {
		t.Fatalf("got %d controls, want 1", len(ps.Controls.DERControl))
	}
	ctrl := ps.Controls.DERControl[0]
	if ctrl.DERControlBase.OpModExpLimW == nil {
		t.Fatal("DERControl missing OpModExpLimW")
	}
	if ctrl.DERControlBase.OpModExpLimW.Value != 3000 {
		t.Errorf("DERControl OpModExpLimW = %d, want 3000", ctrl.DERControlBase.OpModExpLimW.Value)
	}
	if ctrl.Interval.Duration != 120 {
		t.Errorf("DERControl duration = %d, want 120", ctrl.Interval.Duration)
	}
	if ctrl.EventStatus == nil || ctrl.EventStatus.CurrentStatus != 0 {
		t.Error("DERControl should be in Scheduled status (0)")
	}

	// ── Validate MirrorUsagePointList discovered ──────────────
	if tree.MirrorUsagePoints == nil {
		t.Fatal("MirrorUsagePointList is nil")
	}

	t.Log("✓ Full CSIP discovery walk completed successfully")
	t.Logf("  DeviceCapability: %s (pollRate=%d)", tree.DeviceCapability.Href, tree.DeviceCapability.PollRate)
	t.Logf("  Time: quality=%d, tz=%d", tree.Time.Quality, tree.Time.TzOffset)
	t.Logf("  SelfDevice: %s (LFDI=%s)", tree.SelfDevice.Href, tree.SelfDevice.LFDI)
	t.Logf("  FSAs: %d, Programs: %d", len(tree.FSAList.FunctionSetAssignments), len(tree.Programs))
	t.Logf("  DefaultDERControl: OpModExpLimW=%dW", ps.DefaultControl.DERControlBase.OpModExpLimW.Value)
	t.Logf("  DERControl: OpModExpLimW=%dW, start=+%ds, duration=%ds",
		ctrl.DERControlBase.OpModExpLimW.Value,
		ctrl.Interval.Start-tree.Time.CurrentTime,
		ctrl.Interval.Duration)
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
// for non-GET methods (CORE-001).
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
