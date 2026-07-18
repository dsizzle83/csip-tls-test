//go:build integration

package aggregator

// cli_integration_test.go proves the T06.9 CLI end to end against the loopback
// authz-enforcing mbaps server (startAuthzServer / newTestPKI, shared with the
// other integration tests): the interactive REPL drives a real session through
// connect/discover/write/readback/resume/renegotiate over live mbtls handshakes,
// and the headless batch runner runs a campaign DIR and trips the CI gate
// (GateFailures > 0) on a campaign whose verdict falls outside its expected set —
// the forced-fail the exit-code contract turns into a non-zero exit. Requires the
// amd64 wolfSSL sysroot (desktop, `make test-integration`); TestMain is shared.

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"csip-tls-test/internal/mbtls"
)

// TestCLI_REPLDrivesLoopback runs a scripted REPL session over live handshakes and
// asserts each verb drove the real session: connect, discover, a scale-correct
// write + readback, a resume that RESUMES the TLS session (the T06.8 enhancement),
// a renegotiation that is refused but leaves the session usable, and a structured
// report that is valid JSON.
func TestCLI_REPLDrivesLoopback(t *testing.T) {
	mbtls.ClearSessionCache()
	pki := newTestPKI(t)
	srv := startAuthzServer(t, pki, []uint8{2}, []Role{RoleGridService})
	refs := pki.refs(t)

	var buf bytes.Buffer
	p := NewREPL(
		func(addr string, r Role) (*Conn, error) { return ConnectAs(addr, r, refs) },
		func(string) (string, error) { return srv.addr(), nil },
		TargetDevice, refs.Roles(), "", &buf,
	)
	ctx := context.Background()

	script := []string{
		"connect GridServiceSunSpec",
		"discover 2",
		"write 2 704 WMaxLimPct 50",
		"readback 2 704 WMaxLimPct",
		"resume",
		"renegotiate 2",
		"report",
	}
	outputs := make([]string, len(script))
	for i, line := range script {
		buf.Reset()
		p.exec(ctx, line)
		outputs[i] = buf.String()
	}
	p.disconnect()

	assertContains(t, "connect", outputs[0], "connected as GridServiceSunSpec")
	assertContains(t, "discover", outputs[1], "unit 2")
	assertContains(t, "write", outputs[2], "wrote M704.WMaxLimPct")
	assertContains(t, "readback", outputs[3], "M704.WMaxLimPct = 50")
	// The resume must RESUME the TLS session (discover pumped the ticket).
	assertContains(t, "resume", outputs[4], "resumed=true")
	// Renegotiation is refused by the loopback policy but the session stays usable.
	assertContains(t, "renegotiate", outputs[5], "refused by peer policy")
	assertContains(t, "renegotiate", outputs[5], "still usable")
	// The report is valid JSON carrying the run's observations.
	var rs RunState
	if err := json.Unmarshal([]byte(outputs[6]), &rs); err != nil {
		t.Fatalf("report is not valid JSON: %v\n%s", err, outputs[6])
	}
	if len(rs.Devices) == 0 || len(rs.Writes) == 0 {
		t.Errorf("report missing accumulated devices/writes: %+v", rs)
	}
}

func assertContains(t *testing.T, verb, out, want string) {
	t.Helper()
	if !strings.Contains(out, want) {
		t.Errorf("%s output %q missing %q", verb, out, want)
	}
}

// TestCLI_HeadlessGateTripsOnForcedFail runs a campaign DIR through the headless
// batch runner against the loopback: one campaign that PASSes and matches its
// expected_verdicts (clean), and one identical campaign that declares
// expected_verdicts ["FAIL"] so its PASS is UNEXPECTED — proving the gate trips
// (GateFailures > 0) exactly as the binary's non-zero-exit contract requires, and
// that per-campaign reports are written to -out.
func TestCLI_HeadlessGateTripsOnForcedFail(t *testing.T) {
	mbtls.ClearSessionCache()
	pki := newTestPKI(t)
	srv := startAuthzServer(t, pki, []uint8{2}, []Role{RoleGridService})
	eng := campaignEngine(srv, pki.refs(t))

	dir := t.TempDir()
	writeCampaign(t, filepath.Join(dir, "good.json"), curtailBody("good-curtail", "PASS"))
	writeCampaign(t, filepath.Join(dir, "forced-fail.json"), curtailBody("forced-fail-curtail", "FAIL"))

	out := t.TempDir()
	var buf bytes.Buffer
	sum, err := RunCampaignDir(context.Background(), eng, dir, out, false, &buf)
	if err != nil {
		t.Fatalf("RunCampaignDir: %v", err)
	}
	if sum.Total != 2 {
		t.Fatalf("ran %d campaigns, want 2", sum.Total)
	}
	if sum.GateFailures != 1 {
		t.Fatalf("GateFailures = %d, want 1 (the forced-fail campaign). roll-up:\n%s", sum.GateFailures, buf.String())
	}
	if !strings.Contains(buf.String(), "GATE FAIL (1)") {
		t.Errorf("roll-up missing GATE FAIL: %s", buf.String())
	}
	// Both campaigns wrote a report artifact under -out.
	for _, id := range []string{"good-curtail", "forced-fail-curtail"} {
		if _, err := os.Stat(filepath.Join(out, id, "report.json")); err != nil {
			t.Errorf("report.json not written for %s: %v", id, err)
		}
	}
	// The clean campaign really passed; only the expectation mismatch trips the gate.
	var good, forced *CampaignReport
	for _, r := range sum.Reports {
		switch r.ID {
		case "good-curtail":
			good = r
		case "forced-fail-curtail":
			forced = r
		}
	}
	if good == nil || good.Verdict != VerdictPass || !good.VerdictExpected {
		t.Errorf("good campaign: %+v", good)
	}
	if forced == nil || forced.Verdict != VerdictPass || forced.VerdictExpected {
		t.Errorf("forced-fail campaign should be PASS-but-unexpected: %+v", forced)
	}
}

func writeCampaign(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatalf("write campaign %s: %v", path, err)
	}
}

// curtailBody is a minimal curtail-and-readback campaign parameterised by id and
// the single expected verdict — the same shape as the shipped curtail campaign,
// small enough to run fast in the gate test.
func curtailBody(id, expect string) string {
	return `{
  "camp_v": 1,
  "id": "` + id + `",
  "name": "gate-test curtail",
  "role": "GridServiceSunSpec",
  "target": "device",
  "steps": [
    {"do": "discover", "units": [2]},
    {"do": "write_point", "unit": 2, "model": 704, "point": "WMaxLimPct", "value": 50},
    {"do": "readback", "unit": 2, "model": 704, "point": "WMaxLimPct", "expect": 50, "sla_s": 5, "tol": 1}
  ],
  "oracle": {"name": "convergeWithinSLA"},
  "expected_verdicts": ["` + expect + `"]
}`
}
