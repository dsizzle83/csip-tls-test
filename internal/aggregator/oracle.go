package aggregator

// oracle.go is the ORACLE REGISTRY: the named, code-only pass/fail judges a
// campaign selects from (T06.6). This is the judgment core of the QA driver and
// the load-bearing half of the "oracles are code, scenarios are data" boundary
// (qa/scenarios/README.md). A campaign JSON can only NAME an oracle and pass it
// params; it can never define new decision logic. Adding a judgment the registry
// does not make means writing a new Go oracle and registering it here — the
// campaign still ships as data. This keeps a campaign auditable by inspection and
// keeps the engine from becoming an unreviewed rules engine.
//
// Oracle bodies live here (denyExpected) and in readback.go (convergeWithinSLA,
// reversionOnExpiry). Each is a PURE function of the finished CampaignReport's
// evidence: it reads Steps/Samples/Denials, returns exactly one Verdict plus
// human-readable findings, and mutates nothing.
//
// Reviewer note (T06.8): the TLS-fault probes add sessionSurvival / resumeAfterDrop
// (and the renegotiation-refusal judge) to this registry. They are intentionally
// absent here — this task ships the control/readback/denial oracles only.

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// OracleFunc judges a finished campaign run. It returns the campaign's single
// Verdict and the findings (evidence lines) that justify it. It reads the report
// as read-only evidence and never touches the live session or the recorder.
type OracleFunc func(rep *CampaignReport) (Verdict, []string)

// oracleBuilder decodes a campaign's per-oracle params and yields the ready
// OracleFunc, or an error if the params are malformed — checked at LOAD time
// (validateCampaign builds every oracle to prove its params) so a bad param is a
// load error naming the file, never a run-time surprise.
type oracleBuilder func(params json.RawMessage) (OracleFunc, error)

// oracleRegistry is the authoritative set of campaign oracles. A campaign whose
// oracle.name is not a key here is rejected at load.
var oracleRegistry = map[string]oracleBuilder{
	// convergeWithinSLA: every readback converged to its commanded value within
	// its SLA ⇒ PASS (DEGRADED if any only just made it). The readback-
	// verification core (T06.7).
	"convergeWithinSLA": noParamOracle(convergeWithinSLA),
	// denyExpected: every expect_exception probe was answered with its expected
	// exception code and nothing was wrongly accepted ⇒ PASS. The role-denial
	// judge (exception 01 and nothing else — SunSpecTCP-40/41).
	"denyExpected": noParamOracle(denyExpected),
	// reversionOnExpiry: the ceiling held through the window and then the value
	// returned to the safe default on RvrtTms expiry ⇒ PASS; a value left stuck
	// at the commanded limit ⇒ FAIL (the stuck-curtailment safety class). T06.7.
	"reversionOnExpiry": noParamOracle(reversionOnExpiry),
}

// noParamOracle adapts a plain OracleFunc (the common case — no params) into an
// oracleBuilder, rejecting any params a campaign mistakenly supplies.
func noParamOracle(fn OracleFunc) oracleBuilder {
	return func(params json.RawMessage) (OracleFunc, error) {
		if isNonEmptyParams(params) {
			return nil, fmt.Errorf("takes no params")
		}
		return fn, nil
	}
}

// isNonEmptyParams reports whether params carries real content (not empty, null,
// or {}), so noParamOracle can reject stray params without tripping on the JSON
// zero forms.
func isNonEmptyParams(params json.RawMessage) bool {
	s := strings.TrimSpace(string(params))
	return s != "" && s != "null" && s != "{}"
}

// registeredOracles lists the registered oracle names (sorted) for error
// messages.
func registeredOracles() string {
	names := make([]string, 0, len(oracleRegistry))
	for n := range oracleRegistry {
		names = append(names, n)
	}
	sort.Strings(names)
	return strings.Join(names, ", ")
}

// buildOracle resolves and constructs the oracle for a campaign. The campaign is
// already validated (the same builder ran at load), so this only re-runs the
// pure build; an error here means the registry changed under a loaded campaign
// and is surfaced, never swallowed.
func buildOracle(ref OracleRef) (OracleFunc, error) {
	builder, ok := oracleRegistry[ref.Name]
	if !ok {
		return nil, fmt.Errorf("oracle %q is not registered", ref.Name)
	}
	return builder(ref.Params)
}

// denyExpected judges a role-denial campaign: every expect_exception probe must
// have been answered with the exact exception code it expected, and no probed
// write may have been accepted. This is the SunSpecTCP-40/41 discipline — a
// rejected control is "exception 01 and nothing else", never a partial success
// and never a different code that would hint at the register map.
//
//   - A write that was ACCEPTED (Wrote=true) ⇒ FAIL (an authz gap — the loudest
//     finding: a read-only role wrote a control).
//   - An exception with the WRONG code ⇒ FAIL (a conformance miss).
//   - A probe that hit a transport error (no code observed) ⇒ INCONCLUSIVE for
//     that probe (we could not see the gateway's answer).
//   - No expect_exception step at all ⇒ INCONCLUSIVE (nothing to judge).
func denyExpected(rep *CampaignReport) (Verdict, []string) {
	var findings []string
	verdict := Verdict("")
	checks := 0
	for _, st := range rep.Steps {
		if st.Do != StepExpectException {
			continue
		}
		checks++
		if st.Exception == nil {
			// No exception observed and no acceptance recorded: a transport failure
			// during the probe. We cannot judge the gateway's authz from a broken
			// wire.
			findings = append(findings, fmt.Sprintf("step %d probe unit %d %s: transport error, could not observe the gateway's answer (%s)", st.Index, probeUnit(st), probePoint(st), st.Err))
			verdict = worse(verdict, VerdictInconclusive)
			continue
		}
		ec := st.Exception
		switch {
		case ec.Result.Wrote:
			findings = append(findings, fmt.Sprintf("step %d unit %d %s: write was ACCEPTED — authz gap (expected exception %d)", st.Index, ec.Result.Unit, ec.Result.Point, ec.Expected))
			verdict = worse(verdict, VerdictFail)
		case !ec.Match:
			findings = append(findings, fmt.Sprintf("step %d unit %d %s: answered exception %d, expected %d (no extra info must leak — TCP-40/41)", st.Index, ec.Result.Unit, ec.Result.Point, ec.Result.ExceptionCode, ec.Expected))
			verdict = worse(verdict, VerdictFail)
		default:
			findings = append(findings, fmt.Sprintf("step %d unit %d %s: correctly denied with exception %d", st.Index, ec.Result.Unit, ec.Result.Point, ec.Result.ExceptionCode))
		}
	}
	if checks == 0 {
		return VerdictInconclusive, []string{"denyExpected: no expect_exception step ran — nothing to judge"}
	}
	if verdict == "" {
		verdict = VerdictPass
	}
	return verdict, findings
}

// probeUnit / probePoint pull the target of an expect_exception step for a
// finding line even when no exception was observed (the transport-error case,
// where st.Exception is nil).
func probeUnit(st StepResult) uint8 {
	if st.Exception != nil {
		return st.Exception.Result.Unit
	}
	return 0
}

func probePoint(st StepResult) string {
	if st.Exception != nil {
		return st.Exception.Result.Point
	}
	return ""
}
