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
	// NeedsBench marks a scenario that cannot run against the plain hermetic :802
	// loopback because it needs the LIVE bench/gateway — either the desktop sims'
	// admin APIs (wave-2 family A/B) or the real gateway's stateful engines the
	// register-echo loopback does not model (wave-3 control-loop reversion timer /
	// exclusive-authority engine). When no bench is wired (a -loopback :802-only
	// run), the runner SKIPS it as an expected INCONCLUSIVE rather than tripping the
	// gate — its hermetic coverage is the pure-oracle unit tests (and, for wave-2,
	// the httptest bench stub).
	NeedsBench bool
	// Extended marks a long-running boundary-dither scenario (wave-3
	// control-setpoint-dither-at-bounds) that a default/full run EXCLUDES so it
	// cannot inflate every campaign's wall-clock time (mirrors mayScenario.Extended,
	// RSK-12). It still runs when named explicitly via -only or opted in via
	// -extended.
	Extended bool
	// NeedsBoard marks a wave-3 BOARD-MUTATING scenario (family D authority/PKI/infra)
	// whose adversary is a board mode-switch / service restart / cert rotation the
	// ORCHESTRATOR arms out of band (never this suite). Until the orchestrator arms
	// it and re-runs with -board-armed <id>, the runner SKIPS it as an expected
	// INCONCLUSIVE and prints the board hook to run. Its arm only OBSERVES the
	// gateway's effect (via :802 / the sims' /state); it never mutates the board.
	NeedsBoard bool
	// Board carries the documented board-control hook commands a NeedsBoard scenario
	// hands to the orchestrator (data, never executed here). See qa/gw-scenarios/
	// board-hooks.md for the full companion.
	Board *boardHook

	arm      func(ctx context.Context, w *gwWorld, ev *gwEvidence) error
	perTick  func(ctx context.Context, w *gwWorld, ev *gwEvidence, tick int)
	teardown func(ctx context.Context, w *gwWorld)
	oracle   string // key into oracleRegistry
}

// boardHook is the documented board-control commands a family-D (authority/PKI/
// infra) scenario hands to the ORCHESTRATOR — the shell steps that put the gateway
// into the mutated state the scenario judges, and restore it afterwards. It is
// DATA: this suite never executes it (board mutation is out of scope for the QA
// run); the orchestrator runs Arm, then re-runs the suite with -board-armed <id> so
// the scenario's arm OBSERVES the effect, then runs Teardown. Design references the
// invariant the observed effect is judged against.
type boardHook struct {
	Arm      string `json:"arm"`      // orchestrator runs this to arm the board mutation
	Observe  string `json:"observe"`  // how the effect is sampled (the arm does this in Go over :802/sims)
	Teardown string `json:"teardown"` // orchestrator runs this to restore the resting state
	Design   string `json:"design"`   // the design contract the effect is judged against
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

	// Wave-2 families. Where the wave-1 families DRIVE the gateway's northbound
	// :802 server as a hostile aggregator, these two OBSERVE the gateway's effect
	// on its DERs (the sim southbound /state) while a HOSTILE HEAD-END (family A)
	// or a MISBEHAVING DER (family B) is armed against it — the fail-closed
	// invariant, not an authz decision.
	NBMalform *nbMalformOutcome `json:"nb_malform,omitempty"` // CSIP-northbound malformation (family A)
	SBFault   *sbFaultOutcome   `json:"sb_fault,omitempty"`   // southbound fault injection (family B)

	// Wave-3 families. Family C drives the gateway's full write→apply→readback
	// control loop adversarially over :802 (the aggregator's control/readback
	// primitives); family D judges the observable effect of a BOARD mutation (mode
	// switch / cert rotation / service restart) the orchestrator arms out of band.
	ControlLoop *controlLoopOutcome  `json:"control_loop,omitempty"`  // control-loop integrity (family C)
	AuthPKI     *authorityPKIOutcome `json:"authority_pki,omitempty"` // authority/PKI/infra (family D)

	// Compound-fault family (gap G4). The perfect-storm scenario composes a
	// northbound head-end outage (family A), a southbound secure comm-loss (family
	// B), and a hostile out-of-range write (the malformed-write family) at ONCE and
	// asserts the gateway holds fail-closed through all three simultaneously.
	PerfectStorm *perfectStormOutcome `json:"perfect_storm,omitempty"` // compound simultaneous-fault (G4)
}

// perfectStormOutcome is the sampled evidence of the perfect-storm compound-fault
// scenario (family G4): a NORTHBOUND head-end outage, a SOUTHBOUND secure comm-loss,
// and a HOSTILE out-of-range write are armed SIMULTANEOUSLY, and the gateway's
// fail-closed behaviour is sampled across the hold. The oracle
// (diagnosePerfectStorm) asserts the compound load opened NO hole a single fault
// does not: the hostile write was rejected and never applied, no absurd setpoint
// was ever projected onto a DER, the safe baseline cap the gateway adopted still
// HELD, the gateway stayed responsive (no wedge under the triple load), and it
// RECOVERED the faulted DER once the storm cleared.
type perfectStormOutcome struct {
	Observed bool `json:"observed"` // baseline + at least one post-arm sample obtained

	CapSet               bool `json:"cap_set"`                // the safe baseline cap (WMaxLimPct=50) took (echo converged) before the storm
	HostileWriteRejected bool `json:"hostile_write_rejected"` // the out-of-range write (WMaxLimPct=150) was rejected, never applied
	AbsurdProjected      bool `json:"absurd_projected"`       // an out-of-range setpoint appeared on a DER during the storm
	Unseated             bool `json:"unseated"`               // the safe baseline cap was dropped to uncapped while the storm held
	Responsive           bool `json:"responsive"`             // the gateway stayed alive under the compound load (:802 answered / secure poll attempted)
	Recovered            bool `json:"recovered"`              // the faulted secure DER's poll resumed after both faults cleared

	Note string `json:"note,omitempty"`
}

// controlLoopOutcome is the sampled evidence of a control-loop-integrity scenario
// (family C): the gateway's write→apply→readback loop is driven adversarially and
// its 704 control-echo projection (WMaxLimPct echoes the commanded value back) is
// sampled. The oracle (diagnoseControlLoop) asserts the loop stayed SOUND — a legal
// write converged to the LAST commanded value (no lost/stale echo), a
// reversion-timer setpoint reverted to the safe default on expiry, the exclusive
// control authority was honored (no cross-interface override), and the loop never
// oscillated or went dark. It reuses the aggregator's converge/reversion judgment
// semantics (convergeWithinSLA / reversionOnExpiry) over a pure evidence value.
type controlLoopOutcome struct {
	Kind     string `json:"kind"` // "rapid-recurtail" | "reversion" | "authority" | "dither"
	Unit     uint8  `json:"unit"`
	Observed bool   `json:"observed"` // at least one readback (or a fault) was sampled

	Commanded []float64 `json:"commanded,omitempty"` // the ordered setpoints the arm wrote
	LastCmd   float64   `json:"last_cmd"`            // the LAST commanded value (converge-to-last target)

	Readbacks []ctlReadback `json:"readbacks,omitempty"` // ordered readback observations the oracle judges

	// Authority (control-conflicting-north-south): the non-authoritative interface
	// probed and whether a value the exclusive mbaps authority never commanded ever
	// appeared on the echo (a cross-interface override — an authority violation).
	AuthorityPeer string  `json:"authority_peer,omitempty"`
	OverrideSeen  bool    `json:"override_seen,omitempty"`
	OverridePct   float64 `json:"override_pct,omitempty"`

	// WentDark: the control loop stopped responding across the hold — a crash / hang
	// / session wedge the adversarial write burst triggered.
	WentDark bool `json:"went_dark,omitempty"`

	Note string `json:"note,omitempty"`
}

// ctlReadback is one control-echo readback observation the control-loop oracle
// judges — the judged fields of the aggregator's ReadbackRecord (converge / hold /
// revert), carried as a pure evidence value so diagnoseControlLoop is unit-testable
// from a literal.
type ctlReadback struct {
	Label     string  `json:"label"`           // human tag ("settle", "confirm", "hold", "revert", "dither@0" …)
	Phase     string  `json:"phase,omitempty"` // "" (converge) | "hold" | "revert"
	Expect    float64 `json:"expect"`
	Final     float64 `json:"final"`
	Tol       float64 `json:"tol"`
	SLAS      float64 `json:"sla_s"`
	HadRead   bool    `json:"had_read"`  // false ⇒ never got a value ⇒ BLIND, not FAIL
	Converged bool    `json:"converged"` // reached Expect within Tol
}

// authorityPKIOutcome is the sampled evidence of a family-D authority/PKI/infra
// scenario. The mutation (a mode switch / cert rotation / service restart / trust-
// store tamper) is BOARD-MUTATING and armed by the ORCHESTRATOR out of band; this
// suite only OBSERVES the effect over :802 / the sims' /state. When the board was
// not armed for this run (the default for a QA run) the oracle returns INCONCLUSIVE
// and prints the hook; when armed it judges the observed effect against the design
// contract; where the effect is only board-observable (certmgr 503 / journal), it
// stays INCONCLUSIVE with a note and the orchestrator supplies the board evidence.
type authorityPKIOutcome struct {
	Kind       string `json:"kind"`
	Contract   string `json:"contract"`    // the design invariant this scenario asserts
	BoardArmed bool   `json:"board_armed"` // the orchestrator armed the board mutation (-board-armed)
	Observed   bool   `json:"observed"`    // a :802/sim effect observation was obtained
	BoardOnly  bool   `json:"board_only"`  // the decisive effect is only board-observable (not judgeable here)
	EffectOK   bool   `json:"effect_ok"`   // the observed effect matches the design contract
	Effect     string `json:"effect,omitempty"`
	Note       string `json:"note,omitempty"`
}

// nbMalformOutcome is the sampled evidence of a CSIP-northbound-malformation
// scenario (family A): a hostile/broken head-end (the gridsim) is armed to serve
// a malformed resource or to fault the WAN, and the gateway's SOUTHBOUND effect
// (the DER's applied WMaxLimPct, read from the sim /state) plus its liveness (the
// secure device's poll-request counter still advancing) are sampled across a
// hold. The oracle asserts the gateway FAILED CLOSED: never applied an absurd or
// malformed setpoint to a DER, never unseated a safe cap it had adopted, and
// never went dark (crash/hang/walker-deadlock).
type nbMalformOutcome struct {
	Kind  string `json:"kind"`  // the gridsim malform/outage/clock adversary armed
	Class string `json:"class"` // "resource" | "pricing" | "curve" | "headend-fault"

	Observed    bool    `json:"observed"`              // at least one post-arm DER state sample was obtained
	Samples     int     `json:"samples"`               // post-arm DER-state samples taken
	LiveObs     int     `json:"liveness_observations"` // samples where gateway liveness was observable (secure poll counter present)
	LiveOK      int     `json:"liveness_ok"`           // of LiveObs, samples where the poll counter had advanced (gateway alive)
	BaselineCap bool    `json:"baseline_cap"`          // a safe non-uncapped cap (pct < ~99) was applied to a DER BEFORE arming
	BaselinePct float64 `json:"baseline_pct"`          // the safe baseline applied pct (NaN if none), the value the gateway must HOLD

	AbsurdApplied bool    `json:"absurd_applied"` // an out-of-range setpoint (pct>100, <0, or NaN) was applied to a DER
	AbsurdPct     float64 `json:"absurd_pct,omitempty"`
	Unseated      bool    `json:"unseated"` // the safe baseline cap was dropped to uncapped and stayed dropped

	Note string `json:"note,omitempty"`
}

// sbFaultOutcome is the sampled evidence of a southbound-fault-injection scenario
// (family B): a MISBEHAVING DER (one sim) is faulted while a HEALTHY DER (the
// other sim) is left alone, and the gateway's response is sampled from both sims'
// /state. The oracle asserts the gateway DIGESTED THE FAULT SAFELY: it stayed
// alive (kept polling the healthy device), ISOLATED the faulted device from the
// healthy one (a faulted SECURE device never takes the PLAIN device down, and
// vice-versa), flagged comm-loss where expected, and never applied an absurd
// projection off garbage registers.
type sbFaultOutcome struct {
	Fault  string `json:"fault"`  // the sim fault kind armed
	Target string `json:"target"` // "secure" (mbapsdev) | "plain" (modsim) — which device was faulted
	Expect string `json:"expect"` // the invariant probed: "comm-loss" | "isolation" | "digest" | "recover"

	Observed bool `json:"observed"` // baseline + at least one post-arm sample obtained

	// Liveness/isolation (measured on the HEALTHY device, which must keep working):
	HealthyName    string `json:"healthy_name,omitempty"`
	HealthyLiveObs int    `json:"healthy_live_obs"` // post-arm samples where the healthy device's liveness was observable
	HealthyLiveOK  int    `json:"healthy_live_ok"`  // of those, samples where it was still alive (isolation held)

	// The FAULTED device's comm-loss signal (its poll session dropped / stalled):
	FaultedPollObservable bool `json:"faulted_poll_observable"` // the faulted device exposes a poll counter (secure only)
	FaultedPolledAtBase   bool `json:"faulted_polled_at_base"`  // the gateway WAS polling the faulted device before the fault
	CommLossObserved      bool `json:"comm_loss_observed"`      // the faulted device's poll stalled/dropped after the fault
	Recovered             bool `json:"recovered"`               // the faulted device's poll resumed after the fault cleared

	// Safety of the digest (only checkable when a DER projection is readable):
	AbsurdProjected bool `json:"absurd_projected"` // a garbage register produced an absurd applied setpoint on the faulted DER

	Note string `json:"note,omitempty"`
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
