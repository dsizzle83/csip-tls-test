package certify

// na_roundtrip_test.go drives the whole path the not-applicable verdict has to
// survive: plan → run → console → bundle.json → REPORT.md → COVERAGE.md →
// Verify. A verdict that is right in the runner and wrong in the artefact is
// worse than no verdict at all, because the artefact is the part a stranger
// reads.

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"csip-tls-test/internal/evidence/bundle"
)

// clientDirectionRun builds a run whose selection contains the Secure SunSpec
// CLIENT-direction rows, against a manifest that claims only the server
// direction — the shape LAB29-001's N/A requirement is written for.
func clientDirectionRun(t *testing.T) (*Runner, string) {
	t.Helper()
	opts, out := baseOptions(t, nil)
	opts.Suites = []string{"ssm"}
	opts.ManifestPath = writeManifest(t, validManifestJSON)
	opts.Out = &bytes.Buffer{}
	// The ssm selection contains the RBAC cluster, whose control-authority
	// precondition this bench cannot prove without a gateway transport. That
	// refusal is the point of preflight_authority_test.go; here it is noise, so
	// the fixture takes the documented exploratory escape and the run is
	// recorded non-gating — which is exactly what a run like this IS.
	opts.SkipPreflight = true
	r, err := New(suitesForCampaigns(t), realCatalog(t), opts)
	if err != nil {
		t.Fatal(err)
	}
	return r, out
}

func TestNotApplicableRoundTripsThroughTheBundleAndVerifies(t *testing.T) {
	r, dir := clientDirectionRun(t)
	rep, err := r.Run(context.Background())
	if err != nil {
		t.Fatalf("Run() = %v", err)
	}

	// 1. The runner recorded it, with a source.
	var na []CaseResult
	for _, c := range rep.Cases {
		if c.Verdict == NotApplicable {
			na = append(na, c)
		}
	}
	if len(na) == 0 {
		t.Fatal("no row was declared N/A although the manifest claims only the server direction")
	}
	for _, c := range na {
		if c.Scope == nil || c.Scope.Source != bundle.NASourceManifest {
			t.Errorf("%s: Scope = %+v, want a manifest-sourced decision", c.Case.UID, c.Scope)
		}
		if c.Case.DUTRole != RoleMBAPSClient {
			t.Errorf("%s: a %s row was declared N/A; only the unclaimed direction should be",
				c.Case.UID, c.Case.DUTRole)
		}
	}
	_, _, _, _, naCount := rep.Counts()
	if naCount != len(na) {
		t.Errorf("Counts() reports %d N/A, the cases hold %d", naCount, len(na))
	}

	// 2. bundle.json round-trips: the verdict, the reason, the source.
	loaded, err := bundle.Load(dir)
	if err != nil {
		t.Fatalf("bundle.Load() = %v", err)
	}
	if loaded.Schema != bundle.SchemaVersion {
		t.Errorf("bundle schema = %q, want %q", loaded.Schema, bundle.SchemaVersion)
	}
	var found int
	for _, c := range loaded.Cases {
		if c.Verdict != bundle.VerdictNotApplicable {
			continue
		}
		found++
		if c.NotApplicable == nil {
			t.Fatalf("%s: bundle.json carries an N/A with no record", c.ID)
		}
		if c.NotApplicable.Source != bundle.NASourceManifest {
			t.Errorf("%s: source = %q", c.ID, c.NotApplicable.Source)
		}
		if !strings.Contains(c.NotApplicable.Detail, "candidate.json") {
			t.Errorf("%s: detail does not name the declaration: %q", c.ID, c.NotApplicable.Detail)
		}
	}
	if found != len(na) {
		t.Errorf("bundle.json holds %d N/A rows, the run produced %d", found, len(na))
	}

	// 3. Verify accepts it. The run took no capture, so Verify reports that
	// (correctly) — what must NOT appear is a problem about an N/A row.
	vr, err := bundle.Verify(dir)
	if err != nil {
		t.Fatalf("bundle.Verify() = %v", err)
	}
	for _, p := range vr.Problems {
		if strings.Contains(p, "N/A") || strings.Contains(p, "not-applicable") {
			t.Errorf("Verify objected to a not-applicable row: %s", p)
		}
	}

	// 4. The artefacts a reviewer reads say it in words.
	report, err := os.ReadFile(filepath.Join(dir, bundle.ReportFile))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(report), "NOT APPLICABLE") {
		t.Error("REPORT.md does not mention the out-of-scope rows")
	}
	coverage, err := os.ReadFile(filepath.Join(dir, "COVERAGE.md"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(coverage), "Not applicable to this candidate") {
		t.Error("COVERAGE.md does not tally the out-of-scope rows separately")
	}
	if !strings.Contains(string(coverage), "manifest") {
		t.Error("COVERAGE.md does not name the declaration that decided the scope")
	}
}

// An N/A row is neither a pass nor a failure, so it must not make the run
// unclean and must not be counted as an evidence gap.
func TestNotApplicableIsNeitherPassNorFail(t *testing.T) {
	r, _ := clientDirectionRun(t)
	rep, err := r.Run(context.Background())
	if err != nil {
		t.Fatalf("Run() = %v", err)
	}
	app, inf := rep.CountsByClaim()
	if app.Fail != 0 || inf.Fail != 0 {
		t.Errorf("an out-of-scope row produced a FAIL: %+v / %+v", app, inf)
	}
	if app.NotApplicable+inf.NotApplicable == 0 {
		t.Fatal("the tally lost the out-of-scope rows entirely")
	}
	if app.InScope()+inf.InScope() == 0 {
		t.Fatal("every row was out of scope; the fixture is not exercising what it claims")
	}
}

// The console must let a reader tell "nobody measured it" from "there was
// nothing to measure" at a glance.
func TestConsoleDistinguishesNotApplicableFromSkip(t *testing.T) {
	r, _ := clientDirectionRun(t)
	if _, err := r.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	out := console(r.opts)
	if !strings.Contains(out, "— N/A") {
		t.Errorf("no N/A line in the console output:\n%s", out)
	}
	if !strings.Contains(out, "NOT a verdict") {
		t.Errorf("the summary does not say N/A is not a verdict:\n%s", out)
	}
}

// The campaign acceptance criterion: an unselected protocol contributes NEITHER
// a FAIL NOR A SKIP — it contributes no row at all.
func TestACampaignCarriesNoRowFromAnotherProtocol(t *testing.T) {
	opts := campaignOptions(t, CampaignMBAPS)
	opts.Out = &bytes.Buffer{}
	opts.SkipPreflight = true
	r, err := New(suitesForCampaigns(t), realCatalog(t), opts)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range r.Plan() {
		switch p.Case.Doc {
		case "CSIP-CONF-v1.3", "LOCAL-EXT-v1", "SS-MODBUS-CLIENT-CONF-v1.1":
			t.Errorf("the mbaps campaign plans %s from %s — a row from a protocol it does not own",
				p.Case.UID, p.Case.Doc)
		}
	}
}

// A campaign's bundle must say WHAT it is evidence for and WHETHER it gates,
// as a field rather than as something to re-lex out of the command line.
func TestBundleRecordsTheCampaignAndTheCandidate(t *testing.T) {
	opts := campaignOptions(t, CampaignMBAPS)
	opts.Out = &bytes.Buffer{}
	opts.SkipPreflight = true
	// No gateway transport is configured here, and a CAMPAIGN would rightly
	// refuse to run without one (TestPreflightAuthority_CampaignWithoutTransport
	// Fails pins that). What this test is about is the bundle's record, so it
	// drives the write path through the EXPLORATORY shape of the same selection
	// — which is also the half that must say, in a field, that it does not gate.
	opts.Campaign = ""
	opts.Suites = []string{"ssm"}
	opts.ApplicableOnly = true
	out := opts.OutDir
	runner, err := New(suitesForCampaigns(t), realCatalog(t), opts)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := runner.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	loaded, err := bundle.Load(out)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Run.Campaign == nil {
		t.Fatal("the bundle carries no campaign record at all; a CI gate cannot read whether it gates")
	}
	if loaded.Run.Campaign.Gating {
		t.Error("an exploratory run produced a GATING bundle")
	}
	if loaded.Run.Campaign.Exploratory == "" {
		t.Error("the bundle does not say WHY it is non-gating")
	}
	if loaded.Run.Candidate == nil || loaded.Run.Candidate.Profile != "one-to-one-7xx-tcp" {
		t.Fatalf("the bundle carries no usable candidate reference: %+v", loaded.Run.Candidate)
	}
	if len(loaded.Run.Candidate.SHA256) != 64 {
		t.Errorf("candidate digest = %q, want a hex sha256", loaded.Run.Candidate.SHA256)
	}
	// The manifest FILE travels with its digest, so a reader can re-derive it.
	copied := filepath.Join(out, "candidate.json")
	raw, err := os.ReadFile(copied)
	if err != nil {
		t.Fatalf("the candidate manifest was not copied into the bundle: %v", err)
	}
	var probe map[string]any
	if err := json.Unmarshal(raw, &probe); err != nil {
		t.Fatalf("the copied manifest is not JSON: %v", err)
	}
}
