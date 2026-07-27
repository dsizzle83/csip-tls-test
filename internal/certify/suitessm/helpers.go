package suitessm

// helpers.go holds the shapes every check in this suite repeats, so that a
// check file reads as the procedure it implements rather than as plumbing.
//
// The most important one is wireFact: it re-derives a fact FROM THE CAPTURE and
// mints a frame-cited assertion, or — when the capture cannot show the fact —
// a SKIP that says exactly which step of the lookup failed. There is no path
// through it that produces a PASS from anything other than captured bytes.

import (
	"context"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"csip-tls-test/internal/certify"
	"csip-tls-test/internal/evidence/tlsdis"
)

// suiteName is what every registration in this package binds under.
const suiteName = "ssm"

// mbapsPort is the port SunSpecTCP-1 says mbaps SHOULD use and every SSM-CONF
// procedure names in its reporting requirements.
const mbapsPort = 802

// fallbackClientWait is how long a [C]-half check waits for the gateway's
// southbound client to dial the bench's device sim when the DUT's own cadence
// cannot be read.
//
// It is a FALLBACK, not the number. The gateway's poll cadence is in its own
// configuration and the wait is derived from it — see certify.ObservationWait.
// A constant is wrong in both directions, and run 20260726T225512 shows which:
// 25 s of waiting recorded "no ClientHello from the gateway" on four [C]-half
// assertions, which was a fact about the constant, not about the device.
const fallbackClientWait = 45 * time.Second

// preflight resolves the things nearly every check needs, returning a Result
// the check can hand straight back when one is missing. A missing bench is a
// SKIP with the flag that would fix it, never a silent pass.
type preflight struct {
	Target string
	Remote netip.AddrPort
	PKI    *certify.PKI
}

func prepare(rc *certify.RunCtx, needPKI bool) (preflight, *certify.Result) {
	p := preflight{Target: rc.Targets.Gateway}
	if p.Target == "" {
		r := certify.Skipped("no DUT mbaps address is configured (-gateway host:802)")
		return p, &r
	}
	remote, err := certify.AddrPort(p.Target)
	if err != nil {
		r := certify.Skipped("the DUT address %q is not an ip:port: %v", p.Target, err)
		return p, &r
	}
	p.Remote = remote
	if needPKI {
		if rc.PKI == nil {
			r := certify.Skipped("no mbaps certificate fixture set is configured (-pki certs/mbaps)")
			return p, &r
		}
		p.PKI = rc.PKI
	}
	return p, nil
}

// wireFact re-derives one fact from the capture and cites it.
//
// decide is handed the parsed conversation and returns the verdict, the
// human-readable observation, and the frames that carry it. Returning no frames
// means "this conversation does not contain the fact", which becomes a SKIP
// with the observation as its reason — a check must never be able to assert a
// verdict with nothing behind it.
func wireFact(ev *certify.Evidence, local, remote netip.AddrPort, claim, method string,
	decide func(v *wireView) (certify.Verdict, string, []int)) (certify.Assertion, error) {

	if !ev.HasFrames() {
		return ev.NoEvidence(claim), nil
	}
	v, err := viewFor(ev, local, remote)
	if err != nil {
		return ev.SkipAssertion(claim, method, err.Error()), nil
	}
	verdict, observed, frames := decide(v)
	if len(frames) == 0 {
		return ev.SkipAssertion(claim, method,
			"the capture does not carry the bytes this claim rests on: "+observed), nil
	}
	return ev.CiteFrames(claim, method, verdict, observed, frames)
}

// probeFact is wireFact for a raw probe, with the probe's own connect failure
// turned into a SKIP before the capture is consulted.
func probeFact(ev *certify.Evidence, p *ProbeResult, claim, method string,
	decide func(v *wireView) (certify.Verdict, string, []int)) (certify.Assertion, error) {

	if p.ConnectErr != nil {
		return ev.SkipAssertion(claim, method,
			"the probe never reached the DUT, so nothing was put on the wire: "+p.ConnectErr.Error()), nil
	}
	return wireFact(ev, p.Local, p.Remote, claim, method, decide)
}

// serverHelloFact is the commonest shape of all: a claim about the DUT's
// ServerHello, cited on the frames that ServerHello occupied.
func serverHelloFact(ev *certify.Evidence, p *ProbeResult, claim, method string,
	decide func(sh *tlsdis.ServerHello) (certify.Verdict, string)) (certify.Assertion, error) {

	return probeFact(ev, p, claim, method, func(v *wireView) (certify.Verdict, string, []int) {
		sh, frames := v.ServerHello()
		if sh == nil {
			// No ServerHello is often the POINT (a negative probe), so the
			// caller's decide function still runs and the alert frames carry
			// the citation.
			verdict, observed := decide(nil)
			return verdict, observed, alertOrAllFrames(v)
		}
		verdict, observed := decide(sh)
		return verdict, observed, frames
	})
}

// alertOrAllFrames cites the DUT's fatal alert when there is one, then any
// alert record at all (an encrypted one is still the bytes the refusal arrived
// in, even when its codepoints are unreadable), and otherwise the whole
// conversation — which for a probe the DUT answered with a bare TCP close is
// the only thing there is to point at.
func alertOrAllFrames(v *wireView) []int {
	if a, ok := v.ServerFatalAlert(); ok && len(a.Packets) > 0 {
		return a.Packets
	}
	if v.Server != nil {
		for _, a := range v.Server.Alerts {
			if len(a.Packets) > 0 {
				return a.Packets
			}
		}
	}
	return v.Frames
}

// fatalTeardown answers "did the DUT tear this session down with a fatal
// alert?" for the RBAC-family claims that require the OPPOSITE — SunSpecTCP-29
// through -32 all say a non-compliant role must be judged at the application
// layer, with the secure channel intact.
//
// It resolves encrypted alerts with the run's key log, because a fatal alert
// sent after the handshake is ciphertext and "no fatal alert in the clear" is a
// weaker claim than "no fatal alert". The third return is a caveat to append to
// the observation when an alert record could not be resolved either way; it is
// empty in the normal case.
func fatalTeardown(ev *certify.Evidence, v *wireView) (tlsdis.Alert, bool, string) {
	sc := v.serverAlerts(ev)
	if al, ok := sc.Fatal(); ok {
		return al, true, ""
	}
	if len(sc.Opaque) > 0 {
		return tlsdis.Alert{}, false, fmt.Sprintf(
			" (caveat: %d alert record(s), in frame(s) %v, could not be read — %s — so a fatal alert INSIDE "+
				"the tunnel is not excluded by this observation)", len(sc.Opaque), sc.OpaqueFrames(), sc.Why)
	}
	return tlsdis.Alert{}, false, ""
}

// refusalFact asserts that the DUT refused a provocation, citing whichever
// bytes carry the refusal.
func refusalFact(ev *certify.Evidence, p *ProbeResult, claim, what string) (certify.Assertion, error) {
	const method = "raw ClientHello probe; the DUT's answer read off the socket and re-parsed from the capture"
	return probeFact(ev, p, claim, method, func(v *wireView) (certify.Verdict, string, []int) {
		tail := fmt.Sprintf("the DUT\u2192bench direction of this conversation holds %d TLS record(s)", recordCount(v))
		verdict, observed := refusalFromDirection(v.Server, what, tail)
		return verdict, observed, alertOrAllFrames(v)
	})
}

// noAppDataFact asserts the "no application data was exchanged after the fatal
// alert" criterion that every negative procedure in TLSF and PKI carries.
//
// It is an ABSENCE claim, which is the one shape where citing frames needs care:
// there is no frame that shows a record NOT existing. So it cites the whole
// conversation and states exactly what was scanned, leaving a reader able to
// open those frames and confirm the scan themselves.
func noAppDataFact(ev *certify.Evidence, s *Session, what string) (certify.Assertion, error) {
	claim := "no TLS application_data record was exchanged after the EUT-S refused " + what
	const method = "record-type scan of the DUT→bench direction of this check's own conversation"
	return sessionFact(ev, s, claim, method, func(v *wireView) (certify.Verdict, string, []int) {
		app := v.ServerAppData()
		if len(app) > 0 {
			return certify.Fail, fmt.Sprintf(
				"the DUT sent %d application_data record(s) in frames %v despite the refusal", len(app), app), v.Frames
		}
		return certify.Pass, fmt.Sprintf(
			"the DUT→bench direction holds %d TLS record(s) and none is application_data", recordCount(v)), v.Frames
	})
}

// sessionFact is wireFact for a completing session, keyed on the session's own
// 4-tuple.
func sessionFact(ev *certify.Evidence, s *Session, claim, method string,
	decide func(v *wireView) (certify.Verdict, string, []int)) (certify.Assertion, error) {

	if s == nil {
		return ev.SkipAssertion(claim, method, "no session was established, so it produced no wire evidence"), nil
	}
	return wireFact(ev, s.Local, s.Remote, claim, method, decide)
}

// decryptedFact asserts a criterion that lives inside the tunnel: it recovers
// the plaintext with the run's key log and cites the frames of the records the
// recovered bytes came from.
//
// When decryption is not possible the assertion is a SKIP naming the obstacle.
// The check KNOWS the plaintext — it is one of the two endpoints — but knowing
// is not evidence, and a PASS a reader cannot reproduce is the thing this whole
// framework exists to prevent.
func decryptedFact(ev *certify.Evidence, s *Session, claim, method string,
	decide func(p *plaintext, v *wireView) (certify.Verdict, string, []int)) (certify.Assertion, error) {

	if s == nil {
		return ev.SkipAssertion(claim, method, "no session was established, so there is nothing to decrypt"), nil
	}
	if !ev.HasFrames() {
		return ev.NoEvidence(claim), nil
	}
	v, err := viewFor(ev, s.Local, s.Remote)
	if err != nil {
		return ev.SkipAssertion(claim, method, err.Error()), nil
	}
	pt, err := v.decrypt(ev)
	if err != nil {
		return ev.SkipAssertion(claim, method,
			"the encrypted records could not be recovered from the capture, so this criterion is not "+
				"re-checkable by a reader of the bundle: "+err.Error()), nil
	}
	verdict, observed, frames := decide(pt, v)
	if len(frames) == 0 {
		return ev.SkipAssertion(claim, method,
			"the recovered plaintext does not contain what this claim rests on: "+observed), nil
	}
	return ev.CiteFrames(claim, method, verdict, observed, frames)
}

// ── the [C] half: watching the gateway's own southbound client ──────────────

// clientHalf is the passive observation every [C]-half procedure needs.
//
// This suite cannot make the gateway dial: doing so would mean changing the
// DUT's southbound configuration or restarting a service, and the shared-bench
// constraint forbids both. So it registers the weaker "everything to the device
// sim's endpoint during my window" claim — with the justification the framework
// requires — waits a poll interval, and lets the citation phase find the
// gateway's ClientHello if one arrived.
type clientHalf struct {
	// Endpoint is the bench device sim the gateway dials.
	Endpoint netip.AddrPort
	// GatewayHost is the DUT's address, used to tell its direction from the
	// sim's in the captured conversation.
	GatewayHost netip.Addr
	// Waited is how long the check actually waited.
	Waited time.Duration
	// WaitWhy explains where that number came from: the DUT's own configured
	// poll cadence, or a fallback, and which.
	WaitWhy string
	// Armed is false when the endpoint could not be claimed at all.
	Armed bool
	// Why records the reason when it is not armed.
	Why string
}

// watchClientHalf claims the southbound mbaps device-sim endpoint and waits.
func watchClientHalf(ctx context.Context, rc *certify.RunCtx) *clientHalf {
	c := &clientHalf{}
	target := rc.Targets.MBAPSDev
	if target == "" {
		c.Why = "no southbound mbaps device sim is configured (-mbapsdev host:port), so the gateway's " +
			"client half has no observable peer"
		return c
	}
	ep, err := certify.AddrPort(target)
	if err != nil {
		c.Why = fmt.Sprintf("the device sim address %q is not an ip:port: %v", target, err)
		return c
	}
	c.Endpoint = ep
	if gw, gerr := netip.ParseAddr(rc.Targets.GatewayHost); gerr == nil {
		c.GatewayHost = gw
	}
	reason := "the gateway's SOUTHBOUND mbaps client dials the bench device sim on its own poll schedule; " +
		"this suite is forbidden from reconfiguring or restarting the DUT to trigger it, so it claims every " +
		"conversation with " + ep.String() + " inside this test case's window. The bench opens no connection " +
		"to that endpoint itself, so the only client on it is the DUT."
	if err := rc.ClaimEndpointDuring("tcp", ep, reason); err != nil {
		c.Why = "the endpoint claim was refused: " + err.Error()
		return c
	}
	c.Armed = true

	wait, why := rc.ObservationWait(ctx, certify.ObservationSpec{
		What:       "southbound Modbus poll interval",
		ConfigPath: "/etc/lexa/modbus.json",
		Field:      "poll_interval_s",
		Fallback:   fallbackClientWait,
		Param:      "ssm.client_wait",
		// Four periods, not two: the southbound client holds a keep-alive
		// session, so what has to land inside the window is a RECONNECT, not a
		// poll. The poll interval is the only cadence the DUT publishes and it
		// bounds the reconnect from below; several of them is the honest
		// derivation, and the number is reported either way.
		Periods: 4,
	})
	c.WaitWhy = why
	start := time.Now()
	rc.Logf("waiting %s for the gateway's southbound client to dial %s (%s)", wait, ep, why)
	_ = rc.Sleep(ctx, wait)
	c.Waited = time.Since(start)
	return c
}

// hello finds the gateway's ClientHello among the frames attributed to this
// check, and the conversation it belongs to.
func (c *clientHalf) hello(ev *certify.Evidence) (*tlsdis.ClientHello, *wireView, error) {
	if !c.Armed {
		return nil, nil, fmt.Errorf("the client half was not observed: %s", c.Why)
	}
	if !ev.HasFrames() {
		return nil, nil, fmt.Errorf(
			"no frames were attributed to this test case; the gateway opened no southbound mbaps "+
				"connection to %s during the %s the check waited (%s)",
			c.Endpoint, c.Waited.Round(time.Second), c.WaitWhy)
	}
	for _, st := range ev.Streams() {
		a, b := endpointAddr(st.Key.A), endpointAddr(st.Key.B)
		var local netip.AddrPort
		switch {
		case b == c.Endpoint:
			local = a
		case a == c.Endpoint:
			local = b
		default:
			continue
		}
		if c.GatewayHost.IsValid() && local.Addr() != c.GatewayHost {
			continue
		}
		v, err := parseView(st, local, c.Endpoint)
		if err != nil {
			continue
		}
		if ch, _ := v.ClientHello(); ch != nil {
			return ch, v, nil
		}
	}
	return nil, nil, fmt.Errorf(
		"no ClientHello from the gateway to %s appears in the %d frame(s) attributed to this test case "+
			"during the %s it waited (%s)",
		c.Endpoint, len(ev.Frames()), c.Waited.Round(time.Second), c.WaitWhy)
}

// clientHelloFact asserts a claim about the gateway's own ClientHello.
func (c *clientHalf) fact(ev *certify.Evidence, claim, method string,
	decide func(ch *tlsdis.ClientHello) (certify.Verdict, string)) (certify.Assertion, error) {

	ch, v, err := c.hello(ev)
	if err != nil {
		return ev.SkipAssertion(claim, method, err.Error()), nil
	}
	_, frames := v.ClientHello()
	verdict, observed := decide(ch)
	return ev.CiteFrames(claim, method, verdict, observed, frames)
}

// ── small formatting helpers ────────────────────────────────────────────────

func hexSuites(ids []uint16) string {
	out := make([]string, len(ids))
	for i, id := range ids {
		out[i] = fmt.Sprintf("0x%04X", id)
	}
	return "[" + strings.Join(out, ", ") + "]"
}

func namedSuites(ids []uint16) string {
	out := make([]string, len(ids))
	for i, id := range ids {
		out[i] = fmt.Sprintf("0x%04X %s", id, tlsdis.CipherSuiteName(id))
	}
	return strings.Join(out, ", ")
}

// tally accumulates the live phase's per-iteration outcomes into one declared
// verdict and one notes line.
//
// The declared verdict is the WORST seen, which matters for a partly-skipped
// procedure: certify.Result rolls up worse(declared, assertions), and because
// SKIP sorts BELOW pass, declaring Skip would not hold a case down once one
// sub-criterion passed. A procedure whose material half could not be exercised
// therefore declares WARN — the verdict that does survive the roll-up — and
// says which half in its notes.
type tally struct {
	worst certify.Verdict
	lines []string
}

func (t *tally) add(v certify.Verdict, format string, a ...any) {
	if v.Severity() > t.worst.Severity() {
		t.worst = v
	}
	t.lines = append(t.lines, certify.Glyph(v)+" "+fmt.Sprintf(format, a...))
}

// warn records a caveat that must survive the roll-up: a half of the procedure
// this bench cannot exercise, with the reason.
func (t *tally) caveat(format string, a ...any) {
	t.add(certify.Warn, format, a...)
}

func (t *tally) verdict() certify.Verdict {
	if t.worst == "" {
		return certify.Skip
	}
	return t.worst
}

func (t *tally) notes() string { return strings.Join(t.lines, " · ") }

// inRelativeOrder reports whether want appears in got in that relative order,
// which is how TLSF-001/002 phrase the client-side ordering criterion ("in that
// relative order", not "as a contiguous prefix").
func inRelativeOrder(got, want []uint16) bool {
	i := 0
	for _, g := range got {
		if i < len(want) && g == want[i] {
			i++
		}
	}
	return i == len(want)
}

// joinNote appends to an assertion's Note without losing what was there.
func joinNote(a, b string) string {
	switch {
	case a == "":
		return b
	case b == "":
		return a
	default:
		return a + "; " + b
	}
}
