package gwmayhem

// oracles.go is the ORACLE REGISTRY — the named, code-only pass/fail judges a
// gw-mayhem scenario selects, the load-bearing half of "oracles are code,
// scenarios are data" applied to the gateway hostile-QA suite. Each oracle is a
// PURE function of the finished gwEvidence: it reads the sampled state, returns
// exactly one Verdict plus human-readable findings, and mutates nothing — so the
// whole judgment layer is unit-testable by constructing an evidence literal, with
// no live gateway (make test-fast). The families in matrix.go / certauthz.go /
// malformed.go / transport_abuse.go SAMPLE; these oracles JUDGE.

import (
	"fmt"
	"sort"
	"strings"
)

// gwOracle judges a finished scenario's sampled state.
type gwOracle func(ev *gwEvidence) (Verdict, []string)

// oracleRegistry is the authoritative set of gw-mayhem oracles, by name. A Go
// scenario names one here; a spec scenario uses campaignPassthrough (its verdict
// comes from the aggregator campaign's own registered oracle).
var oracleRegistry = map[string]gwOracle{
	"authzMatrix":         diagnoseAuthzMatrix,
	"certAuthz":           diagnoseCertAuthz,
	"malformedWrite":      diagnoseMalformedWrite,
	"sessionFlood":        diagnoseSessionFlood,
	"campaignPassthrough": diagnoseCampaign,
}

// registeredOracles lists oracle names (sorted) for error messages.
func registeredOracles() string {
	names := make([]string, 0, len(oracleRegistry))
	for n := range oracleRegistry {
		names = append(names, n)
	}
	sort.Strings(names)
	return strings.Join(names, ", ")
}

// diagnoseAuthzMatrix judges the role-denial matrix: every role×op cell's OBSERVED
// grant/deny must match the RBAC contract (rbac.go). The security-critical
// failures this catches:
//   - expected DENY but the write was ACCEPTED ⇒ FAIL (an authz gap — a read-only
//     or admin role wrote a control it must not).
//   - expected DENY with the WRONG exception code ⇒ FAIL (info leak — a denial must
//     be exactly 0x01 and nothing else, TCP-40/41).
//   - expected GRANT but the op was DENIED ⇒ FAIL (a legitimate read/write blocked
//     — e.g. GridService denied a control write, or any role denied a read).
//   - a cell that hit a transport error ⇒ INCONCLUSIVE for that cell.
//
// No cells at all (or a global setup failure) ⇒ INCONCLUSIVE.
func diagnoseAuthzMatrix(ev *gwEvidence) (Verdict, []string) {
	if len(ev.Cells) == 0 {
		return VerdictInconclusive, []string{setupOrEmpty(ev, "no role×op cells were probed")}
	}
	var findings []string
	if ev.MatrixMode != "" {
		findings = append(findings, "mode: "+ev.MatrixMode)
	}
	verdict := Verdict("")
	for _, c := range ev.Cells {
		switch {
		case c.Outcome == "error":
			findings = append(findings, fmt.Sprintf("%s / %s (unit %d): transport error — could not observe (%s)", c.Role, c.Op, c.Unit, c.Note))
			verdict = worse(verdict, VerdictInconclusive)
		case c.Expected == grantDeny && c.Wrote:
			findings = append(findings, fmt.Sprintf("FAIL %s / %s (unit %d): write was ACCEPTED — authz gap (contract: DENY)", c.Role, c.Op, c.Unit))
			verdict = worse(verdict, VerdictFail)
		case c.Expected == grantDeny && c.Outcome == "granted":
			findings = append(findings, fmt.Sprintf("FAIL %s / %s (unit %d): op was GRANTED — contract requires DENY", c.Role, c.Op, c.Unit))
			verdict = worse(verdict, VerdictFail)
		case c.Expected == grantDeny && c.Outcome == "denied" && c.ExCode != 0x01:
			findings = append(findings, fmt.Sprintf("FAIL %s / %s (unit %d): denied with exception 0x%02x, must be 0x01 and nothing else (TCP-40/41)", c.Role, c.Op, c.Unit, c.ExCode))
			verdict = worse(verdict, VerdictFail)
		case c.Expected == grantDeny:
			findings = append(findings, fmt.Sprintf("ok   %s / %s (unit %d): correctly denied with exception 0x01", c.Role, c.Op, c.Unit))
		case c.Expected == grantAllow && c.Outcome == "denied":
			findings = append(findings, fmt.Sprintf("FAIL %s / %s (unit %d): legitimate op DENIED (0x%02x) — contract requires GRANT", c.Role, c.Op, c.Unit, c.ExCode))
			verdict = worse(verdict, VerdictFail)
		default: // grantAllow && granted
			findings = append(findings, fmt.Sprintf("ok   %s / %s (unit %d): correctly granted", c.Role, c.Op, c.Unit))
		}
	}
	if verdict == "" {
		verdict = VerdictPass
	}
	return verdict, findings
}

// diagnoseCertAuthz judges the cert-authz negatives: each fixture must fail at the
// layer the spec places it. A role error (role-less / malformed / empty / oversize
// — chain VALID) must be an AUTHZ-layer denial (handshake succeeds, every request
// answers exception 0x01, session stays up); a chain error (expired / wrong-CA —
// chain INVALID) must be a HANDSHAKE-layer rejection (no session). Landing at the
// wrong layer is a FAIL: an expired/untrusted cert that gets a session, or a
// role-error cert whose handshake is rejected (hiding the authz decision), both
// break the spec's layer placement.
func diagnoseCertAuthz(ev *gwEvidence) (Verdict, []string) {
	if len(ev.Certs) == 0 {
		return VerdictInconclusive, []string{setupOrEmpty(ev, "no cert fixtures were probed")}
	}
	var findings []string
	verdict := Verdict("")
	for _, c := range ev.Certs {
		switch c.ExpectLayer {
		case "handshake":
			switch c.Handshake {
			case "failed":
				findings = append(findings, fmt.Sprintf("ok   %s: handshake correctly REJECTED (%s)", c.Fixture, firstLine(c.HandshakeErr)))
			case "ok":
				findings = append(findings, fmt.Sprintf("FAIL %s: handshake SUCCEEDED — an invalid-chain cert must be rejected at the TLS layer", c.Fixture))
				verdict = worse(verdict, VerdictFail)
			default:
				findings = append(findings, fmt.Sprintf("%s: handshake outcome unobserved (%s)", c.Fixture, c.Note))
				verdict = worse(verdict, VerdictInconclusive)
			}
		case "authz":
			switch {
			case c.Handshake == "failed":
				findings = append(findings, fmt.Sprintf("FAIL %s: handshake was REJECTED — a role error must land at authz (exception 0x01, session up), not at the TLS layer (%s)", c.Fixture, firstLine(c.HandshakeErr)))
				verdict = worse(verdict, VerdictFail)
			case c.Handshake == "ok" && c.ProbeErr != "":
				findings = append(findings, fmt.Sprintf("%s: handshake up but the authz probe hit a transport error — could not observe (%s)", c.Fixture, firstLine(c.ProbeErr)))
				verdict = worse(verdict, VerdictInconclusive)
			case c.Handshake == "ok" && c.DeniedAll && c.AuthzExCode == 0x01:
				findings = append(findings, fmt.Sprintf("ok   %s: handshake up, every request denied with exception 0x01 (role collapsed to no-role)", c.Fixture))
			case c.Handshake == "ok":
				findings = append(findings, fmt.Sprintf("FAIL %s: handshake up but NOT uniformly denied 0x01 (code=0x%02x denied_all=%t) — role error must be a bare 0x01 on every request (TCP-32)", c.Fixture, c.AuthzExCode, c.DeniedAll))
				verdict = worse(verdict, VerdictFail)
			default:
				findings = append(findings, fmt.Sprintf("%s: outcome unobserved (%s)", c.Fixture, c.Note))
				verdict = worse(verdict, VerdictInconclusive)
			}
		default:
			findings = append(findings, fmt.Sprintf("%s: unknown expect_layer %q", c.Fixture, c.ExpectLayer))
			verdict = worse(verdict, VerdictInconclusive)
		}
	}
	if verdict == "" {
		verdict = VerdictPass
	}
	return verdict, findings
}

// diagnoseMalformedWrite judges the malformed/abusive-write probes: each must be
// rejected exactly as the ideal gateway would — the right exception code, or a
// closed session for a framing violation — and NONE may be silently accepted. The
// safety-critical one is the out-of-range setpoint: a WMaxLimPct>100 that returns
// a write SUCCESS means the gateway would apply an out-of-range value to a DER.
func diagnoseMalformedWrite(ev *gwEvidence) (Verdict, []string) {
	if len(ev.Writes) == 0 {
		return VerdictInconclusive, []string{setupOrEmpty(ev, "no malformed-write probes ran")}
	}
	var findings []string
	verdict := Verdict("")
	for _, w := range ev.Writes {
		switch {
		case w.TransportErr != "" && !w.SessionClosed:
			findings = append(findings, fmt.Sprintf("%s: transport error, could not observe (%s)", w.Name, firstLine(w.TransportErr)))
			verdict = worse(verdict, VerdictInconclusive)
		case w.ExpectSessionClosed:
			if w.SessionClosed {
				findings = append(findings, fmt.Sprintf("ok   %s: framing violation correctly closed the session (no exception PDU leaked)", w.Name))
			} else {
				findings = append(findings, fmt.Sprintf("FAIL %s: framing violation did NOT close the session (accepted=%t code=0x%02x)", w.Name, w.Accepted, w.ExCode))
				verdict = worse(verdict, VerdictFail)
			}
		case w.Accepted:
			findings = append(findings, fmt.Sprintf("FAIL %s: write was ACCEPTED — the gateway must reject it and NEVER apply the value", w.Name))
			verdict = worse(verdict, VerdictFail)
		case w.AnyRejectOK && w.ExCode != 0:
			findings = append(findings, fmt.Sprintf("ok   %s: rejected with exception 0x%02x, not applied (any rejection accepted)", w.Name, w.ExCode))
		case w.AnyRejectOK:
			findings = append(findings, fmt.Sprintf("%s: no exception observed and nothing accepted — could not confirm rejection (%s)", w.Name, w.Note))
			verdict = worse(verdict, VerdictInconclusive)
		case w.ExCode == w.ExpectRejectCode:
			findings = append(findings, fmt.Sprintf("ok   %s: correctly rejected with exception 0x%02x", w.Name, w.ExCode))
		default:
			findings = append(findings, fmt.Sprintf("FAIL %s: rejected with exception 0x%02x, expected 0x%02x", w.Name, w.ExCode, w.ExpectRejectCode))
			verdict = worse(verdict, VerdictFail)
		}
	}
	if verdict == "" {
		verdict = VerdictPass
	}
	return verdict, findings
}

// diagnoseSessionFlood judges the transport session-flood probe: the gateway must
// enforce its concurrent-session cap (over-cap sessions refused) AND never starve a
// legitimate control session while the flood is in progress. A flood that opens
// unbounded sessions (no cap) or that blocks a LAN control session is a FAIL.
func diagnoseSessionFlood(ev *gwEvidence) (Verdict, []string) {
	f := ev.Flood
	if f == nil {
		return VerdictInconclusive, []string{setupOrEmpty(ev, "session flood produced no evidence")}
	}
	var findings []string
	verdict := VerdictPass
	findings = append(findings, fmt.Sprintf("flood: attempted=%d established=%d refused=%d cap=%d", f.Attempted, f.Established, f.Refused, f.Cap))
	if !f.CapObserved {
		findings = append(findings, fmt.Sprintf("FAIL no session cap observed — %d sessions established without refusal (cap expected ≈ %d)", f.Established, f.Cap))
		verdict = worse(verdict, VerdictFail)
	} else {
		findings = append(findings, fmt.Sprintf("ok   session cap enforced — refusals began at/under the expected cap (%d)", f.Cap))
	}
	if !f.LanSurvived {
		findings = append(findings, "FAIL a legitimate control session was starved during the flood (no round trip)")
		verdict = worse(verdict, VerdictFail)
	} else {
		findings = append(findings, "ok   a legitimate control session still round-tripped during the flood (no starvation)")
	}
	if f.Note != "" {
		findings = append(findings, f.Note)
	}
	return verdict, findings
}

// diagnoseCampaign is the spec-scenario passthrough: a spec scenario's arm runs
// the aggregator campaign, whose own registered oracle already produced the
// verdict; this oracle simply surfaces it so specs and Go scenarios roll up
// through one path.
func diagnoseCampaign(ev *gwEvidence) (Verdict, []string) {
	if ev.Campaign == nil {
		return VerdictInconclusive, []string{setupOrEmpty(ev, "spec campaign produced no report")}
	}
	return ev.Campaign.Verdict, ev.Campaign.Findings
}

// setupOrEmpty returns the arm-time setup error if there was one (the real reason
// nothing could be judged), else a generic "nothing to judge" message.
func setupOrEmpty(ev *gwEvidence, empty string) string {
	if ev.SetupErr != "" {
		return "setup failed: " + ev.SetupErr
	}
	return empty
}

// firstLine trims an error string to its first line for a compact finding.
func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}
