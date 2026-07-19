// Package gwmayhem is the lexa-gw gateway's adversarial hostile-QA engine — the
// mbaps/CSIP/southbound counterpart of the dashboard's Mayhem suite
// (cmd/dashboard/mayhem.go). Where Mayhem faults the hub over CSIP, gwmayhem
// plays a HOSTILE / MISBEHAVING AGGREGATOR against the gateway's northbound
// Secure-SunSpec-Modbus (mbaps) :802 server, driving the REAL gateway (or a
// faithful loopback) through the bench's OWN aggregator emulator
// (internal/aggregator) — never the product's securemodbus (referee independence,
// C9). It reuses the aggregator's role sessions, typed control/readback/denial
// primitives, verdict vocabulary, and campaign engine wholesale; this package
// adds the hostile SCENARIO MODEL, the Go-literal families the aggregator's data
// campaigns can't express (the role-denial matrix, cert-authz negatives,
// malformed-write probes, transport abuse), pure oracles by name, and the
// headless runner + gate.
//
// The model mirrors mayScenario exactly: a scenario ARMs a fault (drives the
// adversary), optionally re-applies it per tick, TEARs it down, and hands the
// SAMPLED STATE to a pure ORACLE for one of the five verdicts. Scenarios are DATA
// (qa/gw-scenarios/*.json, compiled through the aggregator campaign schema) PLUS
// Go literals where real logic is needed; a spec ID colliding with a Go scenario's
// is a load-time error (Mayhem's rule), never a silent shadow.
package gwmayhem

import (
	"context"

	"csip-tls-test/internal/aggregator"
)

// Verdict is the shared five-value verdict vocabulary — re-exported from the
// aggregator so a gw-mayhem report reads the same as a Mayhem/aggregator report to
// CI and the dashboard.
type Verdict = aggregator.Verdict

const (
	VerdictPass         = aggregator.VerdictPass
	VerdictDegraded     = aggregator.VerdictDegraded
	VerdictFail         = aggregator.VerdictFail
	VerdictBlind        = aggregator.VerdictBlind
	VerdictInconclusive = aggregator.VerdictInconclusive
)

// Scenario source tags — a scenario is a hand-written Go literal or compiled from
// a qa/gw-scenarios/*.json spec (mirrors mayScenario.Source and the aggregator's
// [go]/[spec] distinction).
const (
	SourceGo   = "go"
	SourceSpec = "spec"
)

// gwScenario is one adversarial test, mirroring mayScenario. arm drives the
// adversary and samples the gateway's response into ev; perTick (optional)
// re-applies an evolving fault across a hold; teardown clears any state the
// adversary left; the named oracle (a pure func over the sampled ev) returns the
// verdict. A spec scenario compiles into this same struct: its arm runs the
// aggregator campaign and stashes the CampaignReport in ev, judged by the
// campaignPassthrough oracle.
type gwScenario struct {
	ID       string
	Desc     string
	Category string
	Source   string // SourceGo | SourceSpec
	// Security marks a security-critical scenario: a non-PASS verdict outside its
	// pinned Expected set is a hard gate failure (the runner exits non-zero).
	Security bool
	// Expected pins the acceptable verdicts (the "expected-FAIL pins the gap"
	// pattern as data). Empty ⇒ ["PASS"] for a security scenario (any non-PASS
	// trips the gate), or "no expectation" for a non-security scenario.
	Expected []Verdict
	// HoldTicks is how many times perTick fires after arm (0 ⇒ perTick unused).
	HoldTicks int

	arm      func(ctx context.Context, w *gwWorld, ev *gwEvidence) error
	perTick  func(ctx context.Context, w *gwWorld, ev *gwEvidence, tick int)
	teardown func(ctx context.Context, w *gwWorld)
	oracle   string // key into oracleRegistry
}

// gwEvidence is the SAMPLED STATE a scenario's arm/perTick accrue and the oracle
// judges — the gw-mayhem analogue of Mayhem's []maySample. It is a plain data
// struct (no live session), so every oracle is a pure function of it and is
// unit-testable by constructing a literal. Each family fills only its own slice;
// its oracle reads only that slice.
type gwEvidence struct {
	Scenario string `json:"scenario"`
	// SetupErr records an arm-time failure (could not connect / discover a target).
	// An oracle turns a non-empty SetupErr into INCONCLUSIVE (a setup problem, not a
	// gateway verdict) unless the scenario is specifically probing a setup outcome.
	SetupErr string `json:"setup_err,omitempty"`

	// MatrixMode records the vendor-access mode the matrix DETECTED on the target
	// (LexaVoltReadOnly is deleted when vendor_access=false), so the evidence names
	// the mode the LexaVolt row was judged against.
	MatrixMode string `json:"matrix_mode,omitempty"`

	Cells    []authzCell     `json:"cells,omitempty"`    // role-denial matrix
	Certs    []certOutcome   `json:"certs,omitempty"`    // cert-authz negatives
	Writes   []writeOutcome  `json:"writes,omitempty"`   // malformed/abusive writes
	Flood    *floodOutcome   `json:"flood,omitempty"`    // transport session flood
	Campaign *campaignResult `json:"campaign,omitempty"` // spec-scenario passthrough
}

// authzCell is one role×op cell of the role-denial matrix: the contract's
// expected grant/deny vs what the gateway actually did.
type authzCell struct {
	Role     string  `json:"role"`
	Op       opClass `json:"op"`
	Unit     uint8   `json:"unit"`
	Expected grant   `json:"expected"`
	// Outcome is the observed result: "granted" | "denied" | "error".
	Outcome string `json:"outcome"`
	ExCode  uint8  `json:"ex_code,omitempty"` // exception code when denied
	Wrote   bool   `json:"wrote,omitempty"`   // write-ctl: the write was accepted
	Note    string `json:"note,omitempty"`
}

// certOutcome is one cert-authz negative fixture's result: which enforcement layer
// the contract says it must fail at, and where it actually failed.
type certOutcome struct {
	Fixture string `json:"fixture"`
	// ExpectLayer is "handshake" (expired / wrong-CA — chain invalid) or "authz"
	// (role-less / malformed / empty / oversize — chain valid, denied at authz 0x01).
	ExpectLayer string `json:"expect_layer"`
	// Handshake is "ok" or "failed" — the observed TLS outcome.
	Handshake    string `json:"handshake"`
	HandshakeErr string `json:"handshake_err,omitempty"`
	// AuthzExCode is the exception a post-handshake read/write returned (expect 0x01)
	// when Handshake=="ok"; DeniedAll is true iff every probed op was denied 0x01.
	AuthzExCode uint8 `json:"authz_ex_code,omitempty"`
	DeniedAll   bool  `json:"denied_all,omitempty"`
	// ProbeErr records a TRANSPORT failure during the post-handshake authz probe
	// (not a protocol exception) — the oracle scores that INCONCLUSIVE, not FAIL,
	// since it could not observe the gateway's authz answer.
	ProbeErr string `json:"probe_err,omitempty"`
	Note     string `json:"note,omitempty"`
}

// writeOutcome is one malformed/abusive-write probe's result vs the ideal
// rejection the gateway should have applied.
type writeOutcome struct {
	Name string `json:"name"`
	// ExpectRejectCode is the exception the gateway MUST answer (0x01 authz / 0x03
	// illegal value / 0x0A unknown unit), or 0 when the ideal outcome is a closed
	// session (a framing violation).
	ExpectRejectCode    uint8 `json:"expect_reject_code,omitempty"`
	ExpectSessionClosed bool  `json:"expect_session_closed,omitempty"`
	// AnyRejectOK relaxes the exact-code check to "rejected with SOME exception and
	// never applied" — for probes whose security property is non-application, not a
	// specific code (write to a non-existent unit: 0x01 or 0x0A both mean "not
	// applied"; write to a read-only point: 0x03 or 0x02 both mean "refused").
	AnyRejectOK bool `json:"any_reject_ok,omitempty"`
	// Observed:
	Accepted      bool   `json:"accepted"`          // the write returned success (a gap for out-of-range)
	ExCode        uint8  `json:"ex_code,omitempty"` // exception code observed
	SessionClosed bool   `json:"session_closed,omitempty"`
	TransportErr  string `json:"transport_err,omitempty"`
	Note          string `json:"note,omitempty"`
}

// floodOutcome is the session-flood transport probe's result.
type floodOutcome struct {
	Attempted   int    `json:"attempted"`
	Established int    `json:"established"`
	Refused     int    `json:"refused"`
	Cap         int    `json:"cap"`          // the session cap the contract expects (MaxSessions)
	CapObserved bool   `json:"cap_observed"` // refusals began at/under the cap
	LanSurvived bool   `json:"lan_survived"` // a control session still worked despite the flood
	Note        string `json:"note,omitempty"`
}

// campaignResult carries a spec scenario's aggregator CampaignReport verdict for
// the campaignPassthrough oracle (the full report is attached to gwReport).
type campaignResult struct {
	Verdict  Verdict  `json:"verdict"`
	Findings []string `json:"findings,omitempty"`
	report   *aggregator.CampaignReport
}

// gwReport is one scenario's verdict-carrying record — the unit the runner rolls
// up into the gate and the evidence table. It reuses the aggregator's Verdict
// vocabulary and, for a spec scenario, embeds the full CampaignReport.
type gwReport struct {
	ID              string                     `json:"id"`
	Desc            string                     `json:"desc"`
	Category        string                     `json:"category"`
	Source          string                     `json:"source"`
	Security        bool                       `json:"security"`
	Verdict         Verdict                    `json:"verdict"`
	Expected        []Verdict                  `json:"expected_verdicts,omitempty"`
	VerdictExpected bool                       `json:"verdict_expected"`
	Findings        []string                   `json:"findings,omitempty"`
	DurationS       float64                    `json:"duration_s"`
	Evidence        *gwEvidence                `json:"evidence,omitempty"`
	Campaign        *aggregator.CampaignReport `json:"campaign,omitempty"`
}

// verdictIn reports whether v is listed in expected. An empty list means "no
// expectation declared" ⇒ always true (never trips the gate), matching the
// aggregator/Mayhem convention.
func verdictIn(v Verdict, expected []Verdict) bool {
	if len(expected) == 0 {
		return true
	}
	for _, e := range expected {
		if e == v {
			return true
		}
	}
	return false
}

// severity ranks verdicts so an oracle folding several per-item outcomes keeps the
// WORST — byte-identical to the aggregator's ordering: FAIL > INCONCLUSIVE > BLIND
// > DEGRADED > PASS.
func severity(v Verdict) int {
	switch v {
	case VerdictFail:
		return 4
	case VerdictInconclusive:
		return 3
	case VerdictBlind:
		return 2
	case VerdictDegraded:
		return 1
	case VerdictPass:
		return 0
	}
	return 3
}

// worse returns the more severe of a, b; an empty verdict loses to any real one.
func worse(a, b Verdict) Verdict {
	if a == "" {
		return b
	}
	if b == "" {
		return a
	}
	if severity(b) > severity(a) {
		return b
	}
	return a
}
