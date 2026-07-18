package aggregator

// probes.go is the TLS-FAULT PROBE surface (T06.8): the driver primitives a
// campaign's transport verbs use (Conn.Renegotiate, Conn.Ping) plus the named,
// code-only oracles that judge the resulting evidence — resumeAfterDrop,
// sessionSurvival, and renegotiationRefusal. Like every oracle here, each is a
// PURE function of the finished CampaignReport: it reads the per-step evidence
// (StepResult.Session / StepResult.Reneg / transport errors), returns exactly one
// Verdict plus findings, and mutates nothing. They are registered by name in
// oracle.go's oracleRegistry, so a campaign can only NAME them — the "oracles are
// code, scenarios are data" boundary the bench guards (qa/scenarios/README.md).
//
// These oracles turn the mbtls client-session-reuse enhancement (this task) into
// an observable conformance verdict: resumeAfterDrop asserts a re-established
// session actually RESUMED (SunSpecTCP-46), sessionSurvival asserts the emulator
// recovered from a mid-session drop, and renegotiationRefusal asserts the
// gateway's renegotiation policy is safe (TCP-62 is met by the indication; an
// app-level refusal is optional — the probe asserts the OBSERVED behaviour and
// that the session stays safe, not a specific accept/refuse choice).

import (
	"fmt"
	"strings"

	"lexa-proto/sunspec"
)

// RenegotiationResult is one renegotiate step's evidence: whether the attempt was
// made, whether the peer refused it (the conformant gateway's expected policy —
// it advertises the RFC 5746 indication per TCP-62 but declines an actual
// renegotiation), and whether the session stayed usable (or cleanly recovered)
// afterwards. The renegotiationRefusal oracle judges SAFETY from these fields; it
// does not require a specific accept/refuse choice.
type RenegotiationResult struct {
	Attempted     bool   `json:"attempted"`
	Refused       bool   `json:"refused"`
	RoleAsserted  string `json:"role_asserted,omitempty"`
	SessionUsable bool   `json:"session_usable"`
	Err           string `json:"err,omitempty"`
	Note          string `json:"note,omitempty"`
}

// Renegotiate attempts a client-initiated TLS renegotiation on the live session
// (the renegotiation-refusal probe, T06.8). A non-nil error is the expected
// outcome against a conformant gateway that refuses renegotiation — it is
// returned, not swallowed, so the probe can record it. Renegotiate does NOT mark
// the session broken: a refusal handled entirely client-side (wolfSSL declines
// before anything reaches the wire) leaves the session fully intact, and a
// refusal that DID tear the stream down surfaces on the next op, which redials
// transparently. Either way the caller's liveness read (Ping) establishes whether
// the session survived.
func (c *Conn) Renegotiate() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.ensureConn(); err != nil {
		return err
	}
	return c.sess.Renegotiate()
}

// Ping is a benign liveness read: it reads the SunSpec base marker on unit and
// reports whether the session (re-establishing transparently if the previous one
// broke) can carry a request/response round trip. It is the post-renegotiation /
// post-drop "is the session still usable?" probe, distinct from a control op
// because it never writes and never asserts a value — only that the transport
// works. A gateway exception (e.g. 0x0A for an unmapped unit) still counts as
// "usable": the session round-tripped a frame; the unit map is a separate matter.
func (c *Conn) Ping(unit uint8) error {
	_, err := c.ReadHolding(unit, sunspec.SunSpecBase, 2)
	if _, isEx := AsException(err); isEx {
		return nil // a protocol exception means the session round-tripped fine
	}
	return err
}

// resumeAfterDrop judges a resumption campaign: every re-established session
// (a resume step) must have RESUMED the prior TLS session rather than doing a
// full handshake (SunSpecTCP-46). This is the oracle the mbtls client-session-
// reuse enhancement (T06.8) exists to make judgeable.
//
//   - A resume step that RESUMED (Session.Resumed) ⇒ the expectation held.
//   - A resume step that did a FULL handshake (Resumed=false) ⇒ FAIL: resumption
//     was not offered or the peer declined it.
//   - A resume step that could not re-establish at all (Err set, or no handshake
//     facts) ⇒ INCONCLUSIVE for that step (we never saw a resumption to judge).
//   - No resume step at all ⇒ INCONCLUSIVE (nothing to judge).
func resumeAfterDrop(rep *CampaignReport) (Verdict, []string) {
	var findings []string
	verdict := Verdict("")
	resumeSteps := 0
	for _, st := range rep.Steps {
		if st.Do != StepResume {
			continue
		}
		resumeSteps++
		if st.Err != "" || st.Session == nil {
			findings = append(findings, fmt.Sprintf("step %d: re-establish failed or produced no handshake facts (%s) — cannot judge resumption", st.Index, st.Err))
			verdict = worse(verdict, VerdictInconclusive)
			continue
		}
		if st.Session.Resumed {
			findings = append(findings, fmt.Sprintf("step %d: session RESUMED after re-establish (TCP-46) over %s/%s", st.Index, st.Session.TLSVersion, st.Session.Cipher))
		} else {
			findings = append(findings, fmt.Sprintf("step %d: re-establish did a FULL handshake (Resumed=false) — resumption not offered/accepted (TCP-46)", st.Index))
			verdict = worse(verdict, VerdictFail)
		}
	}
	if resumeSteps == 0 {
		return VerdictInconclusive, []string{"resumeAfterDrop: no resume step ran — nothing to judge"}
	}
	if verdict == "" {
		verdict = VerdictPass
	}
	return verdict, findings
}

// sessionSurvival judges mid-session disconnect recovery: after a disruption (a
// disconnect step, or any step that hit a transport error — e.g. an op that ran
// into an armed drop_session fault), the emulator must RECOVER — a later step
// must re-establish the session and successfully carry an operation. This is the
// resilience half of the TLS-fault probes, orthogonal to whether the recovered
// session resumed.
//
//   - A disruption followed by a later OK session op ⇒ PASS (recovered).
//   - A disruption with NO successful session op after it ⇒ FAIL (never
//     recovered — the campaign ended broken).
//   - No disruption at all ⇒ INCONCLUSIVE (nothing to judge — the campaign never
//     dropped the session).
func sessionSurvival(rep *CampaignReport) (Verdict, []string) {
	lastDisrupt := -1
	disruptWhat := ""
	for idx, st := range rep.Steps {
		switch {
		case st.Do == StepDisconnect:
			lastDisrupt, disruptWhat = idx, fmt.Sprintf("step %d disconnect", st.Index)
		case st.Err != "" && st.Do != StepExpectException:
			// A transport error is a disruption (expect_exception's "error" is the
			// gateway's expected authz answer, not a transport break — excluded).
			lastDisrupt, disruptWhat = idx, fmt.Sprintf("step %d %s transport error (%s)", st.Index, st.Do, st.Err)
		}
	}
	if lastDisrupt < 0 {
		return VerdictInconclusive, []string{"sessionSurvival: no disconnect or transport drop occurred — nothing to judge"}
	}
	for _, st := range rep.Steps[lastDisrupt+1:] {
		if st.OK && isSessionOp(st.Do) {
			return VerdictPass, []string{fmt.Sprintf("recovered from %s: step %d %s succeeded on the re-established session", disruptWhat, st.Index, st.Do)}
		}
	}
	return VerdictFail, []string{fmt.Sprintf("did NOT recover from %s: no successful session operation followed it — the emulator was left disconnected", disruptWhat)}
}

// isSessionOp reports whether a verb exercises the live session (so a successful
// one after a drop proves recovery). sleep/sim_fault/poll-start do not prove the
// session works; a resume, discover, read/write, readback, denial probe, or
// renegotiation does.
func isSessionOp(do string) bool {
	switch do {
	case StepResume, StepDiscover, StepWritePoint, StepWriteMulti,
		StepReadback, StepExpectException, StepRenegotiate:
		return true
	}
	return false
}

// renegotiationRefusal judges the renegotiation-refusal probe: a client-initiated
// renegotiation must leave the session SAFE — whether the gateway refused it (the
// conformant policy: TCP-62 is met by the indication; the actual renegotiation is
// declined) or handled it, the session must stay usable or cleanly recover, never
// left wedged or corrupt. Per the product finding, app-level refusal is optional,
// so this oracle asserts safety, not a specific accept/refuse choice.
//
//   - A renegotiation (refused or handled) after which the session stayed usable
//     ⇒ the expectation held; the observed policy is recorded in the finding.
//   - A renegotiation that left the session unusable (no liveness, no recovery)
//     ⇒ FAIL — an unsafe outcome.
//   - No renegotiate step ⇒ INCONCLUSIVE (nothing to judge).
func renegotiationRefusal(rep *CampaignReport) (Verdict, []string) {
	var findings []string
	verdict := Verdict("")
	checks := 0
	for _, st := range rep.Steps {
		if st.Do != StepRenegotiate || st.Reneg == nil {
			continue
		}
		checks++
		rr := st.Reneg
		policy := "handled by peer"
		if rr.Refused {
			policy = "refused by peer policy (TCP-62 indication-only)"
		}
		if !rr.SessionUsable {
			findings = append(findings, fmt.Sprintf("step %d: renegotiation %s but the session was left UNUSABLE — unsafe (%s)", st.Index, policy, strings.TrimSpace(rr.Err+" "+rr.Note)))
			verdict = worse(verdict, VerdictFail)
			continue
		}
		findings = append(findings, fmt.Sprintf("step %d: renegotiation %s; session stayed safe/usable afterward", st.Index, policy))
	}
	if checks == 0 {
		return VerdictInconclusive, []string{"renegotiationRefusal: no renegotiate step ran — nothing to judge"}
	}
	if verdict == "" {
		verdict = VerdictPass
	}
	return verdict, findings
}
