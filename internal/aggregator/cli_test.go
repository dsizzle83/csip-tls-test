package aggregator

// cli_test.go unit-tests the T06.9 CLI core without a live handshake: the
// headless batch roll-up + CI-gate exit logic (driven with a ConnectAs stub that
// fails, so no wolfSSL handshake is touched), the report JSON schema round-trip,
// the HTTP fault injector, and the REPL command parsing / not-connected guards.
// The live REPL + loopback headless gate are proven under -tags=integration in
// cli_integration_test.go.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

// failEngine returns an engine whose ConnectAs always fails, so Engine.Run yields
// an INCONCLUSIVE verdict (a connect failure is a campaign outcome, not a Go
// error) without touching wolfSSL — the pure-Go path the gate logic is tested on.
func failEngine() *Engine {
	return NewEngine(RunOptions{
		ConnectAs: func(string, Role) (*Conn, error) { return nil, fmt.Errorf("stub: no handshake in a unit test") },
		Resolve:   func(string) (string, error) { return "127.0.0.1:1", nil },
	})
}

func campaignExpecting(id string, expect ...Verdict) *Campaign {
	return &Campaign{
		CampV: CampaignV, ID: id, Name: id, Role: RoleGridService, Target: TargetGateway,
		Steps:            []Step{{Do: StepDiscover}},
		Oracle:           OracleRef{Name: "convergeWithinSLA"},
		ExpectedVerdicts: expect,
	}
}

// TestRunBatch_GateTripsOnUnexpectedVerdict proves the CI gate: a campaign that
// expects PASS but comes back INCONCLUSIVE (connect failed) is a gate failure, so
// GateFailures > 0 and the roll-up reports GATE FAIL.
func TestRunBatch_GateTripsOnUnexpectedVerdict(t *testing.T) {
	var buf bytes.Buffer
	camps := []*Campaign{
		campaignExpecting("expects-pass", VerdictPass),                 // will be INCONCLUSIVE → gate fail
		campaignExpecting("expects-inconclusive", VerdictInconclusive), // matches → ok
	}
	sum, err := RunBatch(context.Background(), failEngine(), camps, nil, t.TempDir(), false, &buf)
	if err != nil {
		t.Fatalf("RunBatch: %v", err)
	}
	if sum.Total != 2 {
		t.Errorf("Total = %d, want 2", sum.Total)
	}
	if sum.GateFailures != 1 {
		t.Errorf("GateFailures = %d, want 1 (the PASS-expecting campaign came back INCONCLUSIVE)", sum.GateFailures)
	}
	out := buf.String()
	if !strings.Contains(out, "GATE FAIL (1)") {
		t.Errorf("roll-up missing GATE FAIL: %q", out)
	}
	if !strings.Contains(out, "UNEXPECTED") {
		t.Errorf("per-campaign line missing UNEXPECTED tag: %q", out)
	}
}

// TestRunBatch_GatePassesWhenExpected proves a batch every one of whose verdicts
// is within its expected set is a clean gate (GateFailures == 0).
func TestRunBatch_GatePassesWhenExpected(t *testing.T) {
	var buf bytes.Buffer
	camps := []*Campaign{
		campaignExpecting("a", VerdictInconclusive),
		campaignExpecting("b", VerdictInconclusive),
	}
	sum, err := RunBatch(context.Background(), failEngine(), camps, nil, "", false, &buf)
	if err != nil {
		t.Fatalf("RunBatch: %v", err)
	}
	if sum.GateFailures != 0 {
		t.Errorf("GateFailures = %d, want 0", sum.GateFailures)
	}
	if !strings.Contains(buf.String(), "GATE PASS") {
		t.Errorf("roll-up missing GATE PASS: %q", buf.String())
	}
}

// TestRunBatch_LoadErrorIsGateFailure proves a load error (a malformed/colliding
// campaign the loader excluded) counts against the gate — a broken campaign in a
// CI dir must not silently pass.
func TestRunBatch_LoadErrorIsGateFailure(t *testing.T) {
	var buf bytes.Buffer
	sum, err := RunBatch(context.Background(), failEngine(), nil, []error{fmt.Errorf("bad.json: decode: boom")}, "", false, &buf)
	if err != nil {
		t.Fatalf("RunBatch: %v", err)
	}
	if sum.GateFailures != 1 {
		t.Errorf("GateFailures = %d, want 1 (the load error)", sum.GateFailures)
	}
	if !strings.Contains(buf.String(), "LOAD-ERR") {
		t.Errorf("roll-up missing LOAD-ERR line: %q", buf.String())
	}
}

// TestReport_SchemaRoundTrips validates the report writer's JSON contract: the
// versioned CampaignReport marshals and unmarshals losslessly for the fields the
// dashboard/CI consume (the -json artifact).
func TestReport_SchemaRoundTrips(t *testing.T) {
	resumed := true
	rep := &CampaignReport{
		CampV: CampaignV, ID: "rt", Name: "round-trip", Role: RoleGridService,
		Target: TargetDevice, Oracle: "resumeAfterDrop", Verdict: VerdictPass,
		ExpectedVerdicts: []Verdict{VerdictPass}, VerdictExpected: true,
		Steps: []StepResult{
			{Index: 0, Do: StepResume, OK: true, Session: &SessionInfo{Role: RoleGridService, Resumed: resumed, Cipher: "TLS13-AES128-GCM-SHA256", TLSVersion: "TLSv1.3"}},
			{Index: 1, Do: StepRenegotiate, OK: true, Reneg: &RenegotiationResult{Attempted: true, Refused: true, SessionUsable: true}},
		},
	}
	rep.SummaryHuman = rep.renderSummary()

	dir := t.TempDir()
	jsonPath, err := rep.WriteReport(dir)
	if err != nil {
		t.Fatalf("WriteReport: %v", err)
	}
	raw, err := os.ReadFile(jsonPath)
	if err != nil {
		t.Fatalf("read report: %v", err)
	}
	var back CampaignReport
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatalf("report JSON does not round-trip: %v", err)
	}
	if back.Verdict != VerdictPass || back.Oracle != "resumeAfterDrop" {
		t.Errorf("round-trip lost fields: %+v", back)
	}
	if len(back.Steps) != 2 || back.Steps[0].Session == nil || !back.Steps[0].Session.Resumed {
		t.Errorf("round-trip lost resume-step session evidence: %+v", back.Steps)
	}
	if back.Steps[1].Reneg == nil || !back.Steps[1].Reneg.Refused {
		t.Errorf("round-trip lost renegotiation evidence: %+v", back.Steps[1])
	}
}

// TestHTTPFaultInjector proves the injector POSTs the raw fault body to the sim's
// /fault endpoint (the live-bench sim_fault path).
func TestHTTPFaultInjector(t *testing.T) {
	var gotBody string
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	inject := HTTPFaultInjector(srv.URL)
	if inject == nil {
		t.Fatal("HTTPFaultInjector returned nil for a non-empty base URL")
	}
	if err := inject("device", json.RawMessage(`{"kind":"drop_session"}`)); err != nil {
		t.Fatalf("inject: %v", err)
	}
	if gotPath != "/fault" {
		t.Errorf("POST path = %q, want /fault", gotPath)
	}
	if gotBody != `{"kind":"drop_session"}` {
		t.Errorf("POST body = %q", gotBody)
	}
	if HTTPFaultInjector("") != nil {
		t.Error("empty base URL should yield a nil injector")
	}
}

// TestREPL_UnconnectedAndParse covers the REPL command paths that need no live
// session: help, unknown verbs, the not-connected guards, and bad-role rejection.
func TestREPL_UnconnectedAndParse(t *testing.T) {
	var buf bytes.Buffer
	connectCalls := 0
	p := NewREPL(
		func(string, Role) (*Conn, error) { connectCalls++; return nil, fmt.Errorf("stub") },
		func(string) (string, error) { return "127.0.0.1:1", nil },
		TargetDevice, Roles(), "", &buf,
	)
	cases := []struct {
		line string
		want string
	}{
		{"help", "verbs:"},
		{"bogus", "unknown verb"},
		{"discover", "not connected"},
		{"write 2 704 WMaxLimPct 50", "not connected"},
		{"connect NotARole", "unknown role"},
		{"connect GridServiceSunSpec", "connect as GridServiceSunSpec"}, // stub fails → error printed, connectAs called
	}
	for _, tc := range cases {
		buf.Reset()
		if quit := p.exec(context.Background(), tc.line); quit {
			t.Fatalf("line %q unexpectedly quit", tc.line)
		}
		if !strings.Contains(buf.String(), tc.want) {
			t.Errorf("exec(%q) output %q, want substring %q", tc.line, buf.String(), tc.want)
		}
	}
	if connectCalls != 1 {
		t.Errorf("connectAs called %d times, want 1 (only the good-role connect)", connectCalls)
	}
	// quit returns true.
	if !p.exec(context.Background(), "quit") {
		t.Error("`quit` did not return quit=true")
	}
}
