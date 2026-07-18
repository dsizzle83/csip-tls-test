package aggregator

// report.go is the STRUCTURED RUN REPORT (T06.6 verdict layer; the CLI/roll-up
// wiring is T06.9's). A CampaignReport is the verdict-carrying record the engine
// produces for one campaign run: the oracle's verdict, per-step evidence, the raw
// verdict-free observations pulled from the T06.4 RunState, and a one-paragraph
// human summary. It is JSON-serializable and versioned (CampV) so the dashboard
// can render an older run without a redeploy — the same "report schema is
// versioned" discipline the Mayhem sample/result JSON follows.

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// ReadbackRecord is one readback step's evidence: the target point, the value it
// was expected to converge to, and whether/when it got there. The convergence is
// a MEASUREMENT (a data-collection loop stops when the value is within tolerance
// or the SLA elapses); the PASS/FAIL judgment over these records is the oracle's
// (convergeWithinSLA / reversionOnExpiry). Keeping the measurement here and the
// judgment in the oracle preserves the data-vs-code boundary.
type ReadbackRecord struct {
	Unit      uint8   `json:"unit"`
	Model     uint16  `json:"model"`
	Point     string  `json:"point"`
	Phase     string  `json:"phase,omitempty"` // "hold"|"revert" for reversionOnExpiry
	Expect    float64 `json:"expect"`
	Tol       float64 `json:"tol"`
	SLAS      float64 `json:"sla_s"`
	Converged bool    `json:"converged"`
	Final     float64 `json:"final"`    // last value observed (may be NaN-free absent)
	Reads     int     `json:"reads"`    // number of read attempts made
	TookS     float64 `json:"took_s"`   // wall time to converge (or the full SLA if not)
	HadRead   bool    `json:"had_read"` // false ⇒ never got a value ⇒ BLIND, not FAIL
}

// ExceptionCheck is one expect_exception step's evidence: what the gateway
// actually answered (the DenialResult) versus the code the campaign expected, and
// whether they matched. Match is true only when the observed code equals the
// expected code AND the write was NOT accepted — a write that slipped through
// (Wrote=true) is an authz gap, never a match.
type ExceptionCheck struct {
	Result   DenialResult `json:"result"`
	Expected uint8        `json:"expected_code"`
	Match    bool         `json:"match"`
}

// StepResult is the per-step outcome the oracle reasons over. OK is the step's
// mechanical success (the write landed, the readback converged, the exception was
// observed as expected); Err carries a transport-level failure. Exactly one of
// Write/Readback/Exception/Reneg is populated for the verbs that produce that
// evidence; Session is attached by the session-establishing verbs (connect_as,
// resume) so the TLS-fault oracles can read the handshake facts (Resumed) the
// step produced.
type StepResult struct {
	Index     int             `json:"index"`
	Do        string          `json:"do"`
	OK        bool            `json:"ok"`
	Err       string          `json:"err,omitempty"`
	LatencyMS int64           `json:"latency_ms,omitempty"`
	Note      string          `json:"note,omitempty"`
	Write     *WriteRecord    `json:"write,omitempty"`
	Readback  *ReadbackRecord `json:"readback,omitempty"`
	Exception *ExceptionCheck `json:"exception,omitempty"`
	// Session is the handshake-fact snapshot a connect_as/resume step produced —
	// the evidence the resumeAfterDrop oracle reads (Session.Resumed). nil for
	// non-session verbs.
	Session *SessionInfo `json:"session,omitempty"`
	// Reneg is the renegotiation-probe evidence a renegotiate step produced — the
	// evidence the renegotiationRefusal oracle judges. nil for other verbs.
	Reneg *RenegotiationResult `json:"reneg,omitempty"`
}

// CampaignReport is the versioned, JSON-serializable record of one campaign run.
// It layers a verdict onto the T06.4 RunState: Verdict/Findings/Steps are the
// oracle's and the engine's, while Session/Devices/Samples/Denials are the raw
// verdict-free observations copied out of the RunState — so the report is
// self-contained for the dashboard without exposing the mutable recorder.
type CampaignReport struct {
	CampV  int    `json:"camp_v"`
	ID     string `json:"id"`
	Name   string `json:"name"`
	Role   Role   `json:"role"`
	Target string `json:"target"`
	Addr   string `json:"addr,omitempty"`
	Oracle string `json:"oracle"`

	Started   time.Time `json:"started"`
	Ended     time.Time `json:"ended"`
	DurationS float64   `json:"duration_s"`

	Verdict          Verdict   `json:"verdict"`
	ExpectedVerdicts []Verdict `json:"expected_verdicts,omitempty"`
	// VerdictExpected is true when Verdict ∈ ExpectedVerdicts (or the list is
	// empty). The CLI/CI gate (T06.9) exits non-zero when this is false.
	VerdictExpected bool `json:"verdict_expected"`

	Steps    []StepResult `json:"steps"`
	Findings []string     `json:"findings,omitempty"` // the oracle's evidence lines

	// Raw observations, copied from the run recorder after all polls have stopped.
	Session *SessionInfo   `json:"session,omitempty"`
	Devices []Device       `json:"devices,omitempty"`
	Samples []Snapshot     `json:"samples,omitempty"`
	Denials []DenialResult `json:"denials,omitempty"`

	SummaryHuman string `json:"summary_human"`
}

// JSON serializes the report indented, for a report.json artifact or a -json CLI
// dump. It cannot fail on NaN: every numeric that crosses the wire is already
// finite (measPoints drops NaN, ReadbackRecord.Final is absent-safe).
func (r *CampaignReport) JSON() ([]byte, error) {
	return json.MarshalIndent(r, "", "  ")
}

// renderSummary composes the one-paragraph plain-English verdict a bench operator
// reads without opening the JSON. It leads with the verdict and role, then the
// headline evidence (convergence, denials) and the oracle's findings.
func (r *CampaignReport) renderSummary() string {
	var b strings.Builder
	fmt.Fprintf(&b, "[%s] %s (%s) — role %s vs %s", r.Verdict, r.ID, r.Name, r.Role, r.Target)
	if r.Addr != "" {
		fmt.Fprintf(&b, " @ %s", r.Addr)
	}
	fmt.Fprintf(&b, ". Oracle %s over %d steps in %.1fs.", r.Oracle, len(r.Steps), r.DurationS)

	writes, readbacks, converged, denials, denialsOK := 0, 0, 0, 0, 0
	for _, s := range r.Steps {
		if s.Write != nil {
			writes++
		}
		if s.Readback != nil {
			readbacks++
			if s.Readback.Converged {
				converged++
			}
		}
		if s.Exception != nil {
			denials++
			if s.Exception.Match {
				denialsOK++
			}
		}
	}
	if writes > 0 {
		fmt.Fprintf(&b, " %d control write(s).", writes)
	}
	if readbacks > 0 {
		fmt.Fprintf(&b, " %d/%d readback(s) converged.", converged, readbacks)
	}
	if denials > 0 {
		fmt.Fprintf(&b, " %d/%d denial probe(s) answered as expected.", denialsOK, denials)
	}
	if !r.VerdictExpected {
		fmt.Fprintf(&b, " Verdict is OUTSIDE the expected set %v.", r.ExpectedVerdicts)
	}
	if len(r.Findings) > 0 {
		fmt.Fprintf(&b, " Findings: %s", strings.Join(r.Findings, "; "))
	}
	return b.String()
}

// WriteReport writes report.json + summary.md under dir (created if absent) and
// returns the report.json path. The bench operator gets both a machine artifact
// (dashboard-consumable) and a human summary. The full CLI batching/roll-up over
// many campaigns is T06.9; this is the single-campaign writer it composes.
func (r *CampaignReport) WriteReport(dir string) (string, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", fmt.Errorf("aggregator: make report dir %s: %w", dir, err)
	}
	raw, err := r.JSON()
	if err != nil {
		return "", fmt.Errorf("aggregator: marshal report %s: %w", r.ID, err)
	}
	jsonPath := filepath.Join(dir, "report.json")
	if err := os.WriteFile(jsonPath, raw, 0o644); err != nil {
		return "", fmt.Errorf("aggregator: write %s: %w", jsonPath, err)
	}
	md := "# " + r.ID + "\n\n" + r.SummaryHuman + "\n"
	if err := os.WriteFile(filepath.Join(dir, "summary.md"), []byte(md), 0o644); err != nil {
		return "", fmt.Errorf("aggregator: write summary.md: %w", err)
	}
	return jsonPath, nil
}
