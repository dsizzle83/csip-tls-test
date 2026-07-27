package campaign

// report.go renders a campaign for a human and writes it as an evidence bundle
// for everyone else.
//
// The console form is designed around one rule from the strategy (§4.1): THE
// FAULT MANIFEST IS PRINTED WITH THE VERDICT. Not linked, not available in the
// JSON, not printed only on failure — printed, every time, above the verdict.
// The defect this guards against is subtle and was real: a runner that prints
// GATE PASS while having injected nothing looks exactly like a runner that
// passed a hard campaign, and the only difference visible to a tired human at
// 18:00 is the manifest.
//
// The bundle form reuses internal/evidence/bundle, the same artifact the
// conformance runner produces, for three reasons: bundle.Verify is standalone
// so a third party can check a campaign result without this binary; the
// manifest-of-hashes makes a run auditable after the fact, which is what §6
// requires of a local-first strategy; and having one artifact format means an
// operator learns to read evidence once.

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"csip-tls-test/internal/evidence/bundle"
	"csip-tls-test/internal/invariant"
)

// CampaignRunFile is the run record written into a bundle directory: the plan,
// the shrinks, and the verdict.
const CampaignRunFile = "campaign.json"

// Console renders the whole run: header, manifest, per-invariant table,
// violations, verdict. It is the artifact an operator reads without opening
// anything.
func Console(res Result) string {
	var b strings.Builder
	fmt.Fprintf(&b, "\n=== campaign %s ===\n", res.Plan.Label)
	fmt.Fprintf(&b, "fault manifest: %s\n", res.Plan)
	if len(res.ArmErrors) > 0 {
		fmt.Fprintf(&b, "\narm errors (%d) — these actions did NOT take effect, so nothing they would have "+
			"caused was under test:\n", len(res.ArmErrors))
		for _, id := range sortedKeys(res.ArmErrors) {
			fmt.Fprintf(&b, "    %-34s %s\n", id, res.ArmErrors[id])
		}
	}
	fmt.Fprintf(&b, "\nbaseline (before anything was armed): %s\n", res.Baseline)
	if res.Baseline == string(invariant.Fail) {
		b.WriteString("    NOTE: an invariant was ALREADY failing before the adversary moved. That is a standing\n" +
			"    defect this campaign walked past, not one it caused — but it is still a P1.\n")
	}

	fmt.Fprintf(&b, "\ninvariants (%d ticks, %d sub-claims asserted):\n", res.Summary.Ticks, res.Summary.Asserted)
	for _, id := range invariantOrder(res.Summary.PerInvariant) {
		fmt.Fprintf(&b, "    %-4s %s\n", id, res.Summary.PerInvariant[id])
	}

	if len(res.Violations) == 0 {
		b.WriteString("\nno invariant violation observed.\n")
	} else {
		fmt.Fprintf(&b, "\nVIOLATIONS (%d distinct — every one a P1):\n\n", len(res.Signatures()))
		for _, v := range res.Violations {
			b.WriteString(indent(v.String(), "  "))
			b.WriteString("\n")
		}
	}

	verdict := "CAMPAIGN PASS"
	if !res.OK {
		verdict = "CAMPAIGN FAIL"
	}
	fmt.Fprintf(&b, "%s — %s\n", verdict, res.Why)
	fmt.Fprintf(&b, "reproduce: -seed %d -window %s -actions %d -layers %s\n",
		res.Plan.Seed, res.Plan.Window.Round(time.Second), len(res.Plan.Events), strings.Join(res.Plan.Layers, ","))
	return b.String()
}

func indent(s, pad string) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	for i := range lines {
		lines[i] = pad + lines[i]
	}
	return strings.Join(lines, "\n")
}

// invariantOrder returns I1..I10 in numeric order, with anything unrecognised
// after them.
func invariantOrder(m map[string]invariant.Verdict) []string {
	order := []string{"I1", "I2", "I3", "I4", "I5", "I6", "I7", "I8", "I9", "I10"}
	seen := map[string]bool{}
	out := make([]string, 0, len(m))
	for _, id := range order {
		if _, ok := m[id]; ok {
			out = append(out, id)
			seen[id] = true
		}
	}
	for _, id := range sortedVerdictKeys(m) {
		if !seen[id] {
			out = append(out, id)
		}
	}
	return out
}

func sortedVerdictKeys(m map[string]invariant.Verdict) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j] < out[j-1]; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}

// RunRecord is the machine-readable campaign artifact.
type RunRecord struct {
	Schema string `json:"schema"`
	// Label, Seed and the plan are what a reproduction needs.
	Label   string        `json:"label"`
	Seed    int64         `json:"seed"`
	Plan    Plan          `json:"plan"`
	Elapsed time.Duration `json:"elapsed_ns"`
	// Command is the invocation that reproduces this run.
	Command string `json:"command"`
	// Baseline is the pre-attack verdict.
	Baseline string `json:"baseline"`
	// Summary is the invariant roll-up.
	Summary invariant.Summary `json:"summary"`
	// Shrinks are the minimal reproducers, one per distinct violation.
	Shrinks []ShrinkResult `json:"shrinks,omitempty"`
	// ArmErrors are the actions that failed to take effect.
	ArmErrors map[string]string `json:"arm_errors,omitempty"`
	OK        bool              `json:"ok"`
	Why       string            `json:"why"`
}

// Emit writes the campaign's evidence bundle to dir: the invariant cases (via
// the monitor, so the same code produces them here and in gw-mayhem), the
// campaign run record, and the bundle manifest of hashes.
//
// It returns the written bundle so a caller can print its report or verify it.
func Emit(dir string, res Result, shrinks []ShrinkResult, dut bundle.DUT, command string) (*bundle.Bundle, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("campaign: create %s: %w", dir, err)
	}
	commit, dirty := bundle.GitCommit(".")
	host, _ := os.Hostname()
	bld := bundle.NewBuilder(bundle.RunMeta{
		Tool:      "gw-campaign",
		Started:   res.Summary.Started,
		Finished:  res.Summary.Finished,
		GitCommit: commit,
		GitDirty:  dirty,
		DUT:       dut,
		Host:      host,
		Operator:  os.Getenv("USER"),
		Note: fmt.Sprintf("campaign %q, seed %d; reproduce with: %s | %s",
			res.Plan.Label, res.Plan.Seed, command, res.Why),
	})

	if mon := res.Monitor(); mon != nil {
		if err := mon.Emit(bld, res.Summary, dir); err != nil {
			return nil, err
		}
	}

	rec := RunRecord{
		Schema: "lexa-campaign-run/1", Label: res.Plan.Label, Seed: res.Plan.Seed,
		Plan: res.Plan, Elapsed: res.Elapsed, Command: command, Baseline: res.Baseline,
		Summary: res.Summary, Shrinks: shrinks, ArmErrors: res.ArmErrors,
		OK: res.OK, Why: res.Why,
	}
	raw, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("campaign: encode the run record: %w", err)
	}
	path := filepath.Join(dir, CampaignRunFile)
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		return nil, fmt.Errorf("campaign: write %s: %w", path, err)
	}
	bld.AddFile(path)

	// The manifest is a case in its own right. A bundle whose invariant cases
	// all PASS but whose campaign armed nothing is not evidence of safety, and
	// a reader who only opens REPORT.md must be able to see that without
	// reconstructing it.
	bld.AddCase(bundle.TestCaseResult{
		ID:      "CAMPAIGN-MANIFEST",
		Doc:     "lexa-gw docs/ADVERSARIAL_QA_STRATEGY.md §4.1",
		Title:   "the run injected faults, and the manifest of what it injected is recorded with the verdict",
		Verdict: manifestVerdict(res),
		Notes:   "a run that injected no fault is an ERROR, not a pass",
		Assertions: []bundle.Assertion{{
			Claim:    "the campaign armed at least one fault or attempted at least one attack, and recorded all of them",
			Method:   "seeded plan executed concurrently; every arm/clear timestamped into the fault manifest",
			Verdict:  manifestVerdict(res),
			Observed: res.Plan.String(),
			Note:     fmt.Sprintf("%d of %d scheduled actions armed successfully", res.Armed, len(res.Plan.Events)),
		}},
	})

	b, err := bld.Write(dir)
	if err != nil {
		return nil, fmt.Errorf("campaign: write bundle: %w", err)
	}
	return b, nil
}

func manifestVerdict(res Result) bundle.Verdict {
	if res.Armed == 0 {
		return bundle.Fail
	}
	return bundle.Pass
}
