package suitemodbusclient

// observe.go is the live phase of every check in this suite.
//
// # The DUT dials; the bench watches
//
// Every other suite on this bench drives the DUT by connecting to it. This one
// cannot: in SS-MODBUS-CLIENT-CONF-v1.1 the device under test is the Modbus
// CLIENT, and the bench sims are the servers it polls. The bench therefore has
// no socket of its own to claim, and the only levers it has are
//
//	(a) the sims' simapi control plane — make the server behave in the way the
//	    procedure's step 1 calls for, and
//	(b) time — wait for the DUT's poll loop to come round.
//
// That shapes the whole file. A check's live phase claims the SERVER endpoint
// (see claimServer for why that weaker claim is sound here), optionally arms a
// fault on the sim, waits out one or more poll cycles, restores the sim, and
// hands everything it did to the citation phase.
//
// # Injection policy
//
// Faults are armed through the sim's published POST /fault surface, never by
// touching the DUT, and every armed fault is:
//
//   - recorded verbatim in an assertion's Observed text, so the bundle says
//     what was done to the server rather than leaving a reader to infer it;
//   - cleared in a defer, including on cancellation, so a check that times out
//     does not leave the bench in a fault state for the next test case;
//   - followed by a settle wait that confirms the DUT is polling normally
//     again before the check returns — which is also, for several of these
//     procedures, the recovery criterion itself.
//
// `-param modbus-client.inject=off` disables injection entirely, in which case
// the checks that need it SKIP with that as the stated reason. That switch
// exists for a run against a bench shared with another campaign.

import (
	"context"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"csip-tls-test/internal/certify"
)

// Suite is the registry suite name for this document's checks.
const Suite = "modbus-client"

// Doc is the catalog document these checks implement.
const Doc = "SS-MODBUS-CLIENT-CONF-v1.1"

// Default timings. The DUT's southbound poll interval is configuration, not
// protocol, so it is a parameter with the bench's observed value as the
// default; everything else is derived from it, which keeps a slow bench from
// needing every duration re-tuned by hand.
const (
	defaultPollInterval = 10 * time.Second
	// settleTimeout bounds the wait for the DUT to resume normal polling after
	// a fault is cleared.
	settleTimeout = 60 * time.Second
)

// paramPollInterval / paramInject are the operator-supplied knobs.
const (
	paramPollInterval = "modbus-client.poll-interval-s"
	paramInject       = "modbus-client.inject"
	paramUnitID       = "modbus-client.unit-id"
)

// observer is the live-phase helper every check builds first.
type observer struct {
	rc *certify.RunCtx

	// server is the plain-text SunSpec Modbus server the DUT polls — the one
	// surface in this whole bench whose conformance evidence needs no
	// decryption at all.
	server netip.AddrPort
	// secure is the mbaps (TLS) server the DUT also polls, when configured. It
	// is a SECOND server at a different port, which is what CLI-2 needs, but
	// its Modbus payload is inside TLS and this suite does not have the DUT's
	// keys, so only its connection-level facts are assertable.
	secure    netip.AddrPort
	hasSecure bool

	sim          *certify.SimClient
	pollInterval time.Duration
	injectOK     bool

	// injected records, in order, what was done to the sim. It is quoted
	// verbatim into the assertions so the bundle carries the provocation as
	// well as the observation.
	injected []string
}

// newObserver prepares the live phase, or returns the reason it cannot run.
func newObserver(rc *certify.RunCtx) (*observer, string) {
	if rc.Targets.ModSim == "" {
		return nil, "no plain-text SunSpec Modbus server is configured (-modsim); this document's " +
			"evidence is the DUT's own client traffic to such a server"
	}
	srv, err := certify.AddrPort(rc.Targets.ModSim)
	if err != nil {
		return nil, fmt.Sprintf("the configured -modsim target is unusable: %v", err)
	}
	o := &observer{
		rc:           rc,
		server:       srv,
		pollInterval: defaultPollInterval,
		injectOK:     true,
	}
	if v, ok := rc.Param(paramPollInterval); ok {
		var secs float64
		if _, err := fmt.Sscanf(v, "%g", &secs); err == nil && secs > 0 {
			o.pollInterval = time.Duration(secs * float64(time.Second))
		}
	}
	if v, ok := rc.Param(paramInject); ok && strings.EqualFold(strings.TrimSpace(v), "off") {
		o.injectOK = false
	}
	if rc.Targets.MBAPSDev != "" {
		if ap, err := certify.AddrPort(rc.Targets.MBAPSDev); err == nil {
			o.secure, o.hasSecure = ap, true
		}
	}
	o.sim, _ = rc.Sim("modsim") // nil-safe; callers check simAvailable
	return o, ""
}

// simAvailable reports whether the sim's control plane can be driven.
func (o *observer) simAvailable() bool { return o.sim != nil && o.sim.Available() }

// injectionReason explains, in one sentence, why injection is unavailable.
func (o *observer) injectionReason() string {
	switch {
	case !o.injectOK:
		return fmt.Sprintf("fault injection was disabled for this run (-param %s=off)", paramInject)
	case !o.simAvailable():
		return "modsim's simapi control plane is not configured (-modsim-api), so the server cannot be " +
			"made to behave in the way this procedure's setup step requires"
	default:
		return ""
	}
}

// claimServer registers the endpoint claim this suite's attribution rests on.
//
// It is deliberately the weaker of the two claim forms, and the reason recorded
// with it is the argument for why it is sound here rather than an apology for
// using it: the DUT is the client, so the bench never sees — and cannot
// predict — the ephemeral source port the gateway's poller will use. What the
// bench does know is that the address it names is a dedicated single-purpose
// Modbus listener belonging to this bench, and that conformance runs are
// serialized, so during this check's interval nothing else is talking to it.
// The citation phase does not take that on trust: assertAttributionSound
// re-derives it from the capture by requiring that exactly one conversation
// with that endpoint was attributed.
func (o *observer) claimServer() error {
	reason := fmt.Sprintf("the DUT is the Modbus CLIENT under test and %s is the bench's plain-text "+
		"SunSpec Modbus server, so the bench never learns the DUT's ephemeral source port and cannot "+
		"make a 4-tuple claim; the endpoint is a dedicated single-purpose listener and this conformance "+
		"run is serialized, so no other client dials it during this test case's interval — a claim the "+
		"citation phase re-derives from the capture rather than assumes", o.server)
	return o.rc.ClaimEndpointDuring("tcp", o.server, reason)
}

// claimSecureServer additionally claims the mbaps server's endpoint, for the
// checks whose criterion is about connecting to a SECOND server.
func (o *observer) claimSecureServer() error {
	if !o.hasSecure {
		return fmt.Errorf("no secure Modbus server configured (-mbapsdev)")
	}
	reason := fmt.Sprintf("%s is the bench's Secure SunSpec Modbus (mbaps) device sim — the DUT's second "+
		"southbound server. The DUT dials it, so again no 4-tuple is knowable to the bench; the endpoint "+
		"is single-purpose and the run is serialized. Only the connection-level facts of this endpoint "+
		"are used: its Modbus payload is inside TLS and this suite holds no key material for it",
		o.secure)
	return o.rc.ClaimEndpointDuring("tcp", o.secure, reason)
}

// fault posts a fault spec to the sim and records what was posted.
func (o *observer) fault(ctx context.Context, spec map[string]any, why string) error {
	if !o.simAvailable() {
		return fmt.Errorf("modsim's simapi is not configured")
	}
	if !o.injectOK {
		return fmt.Errorf("fault injection is disabled for this run")
	}
	if err := o.sim.Fault(ctx, spec, nil); err != nil {
		return err
	}
	o.injected = append(o.injected, fmt.Sprintf("POST %s/fault %s (%s)", o.sim.BaseURL, jsonish(spec), why))
	o.rc.Logf("armed on modsim: %s — %s", jsonish(spec), why)
	return nil
}

// clearFault disarms a fault kind, best effort: a failure to clear is logged
// and recorded, never swallowed, because a bench left in a fault state
// invalidates whatever runs next.
func (o *observer) clearFault(kind string) {
	if !o.simAvailable() {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	spec := map[string]any{"kind": kind, "clear": true}
	if err := o.sim.Fault(ctx, spec, nil); err != nil {
		o.injected = append(o.injected, fmt.Sprintf("FAILED to clear %q on modsim: %v", kind, err))
		o.rc.Logf("WARNING: could not clear fault %q on modsim: %v", kind, err)
		return
	}
	o.injected = append(o.injected, fmt.Sprintf("POST %s/fault %s", o.sim.BaseURL, jsonish(spec)))
	o.rc.Logf("cleared on modsim: %s", kind)
}

// injectValue posts a measurement/control override and records it.
func (o *observer) injectValue(ctx context.Context, body map[string]any, why string) error {
	if !o.simAvailable() {
		return fmt.Errorf("modsim's simapi is not configured")
	}
	if !o.injectOK {
		return fmt.Errorf("injection is disabled for this run")
	}
	if err := o.sim.Inject(ctx, body, nil); err != nil {
		return err
	}
	o.injected = append(o.injected, fmt.Sprintf("POST %s/inject %s (%s)", o.sim.BaseURL, jsonish(body), why))
	o.rc.Logf("injected on modsim: %s — %s", jsonish(body), why)
	return nil
}

// forceReconnect severs the DUT's southbound connection so its next poll has to
// re-establish it — which is the only way this bench can make a client that has
// been connected for hours perform its discovery sequence again inside a test
// case's window. tcp_drop is a one-shot action on the sim's listener, not a
// sticky state, so there is nothing to clear.
func (o *observer) forceReconnect(ctx context.Context) error {
	return o.fault(ctx, map[string]any{"kind": "tcp_drop"},
		"sever the DUT's southbound connection so its reconnect performs SunSpec discovery inside this "+
			"test case's observation window")
}

// watch waits out the given number of poll cycles plus a margin.
func (o *observer) watch(ctx context.Context, cycles int) error {
	if cycles < 1 {
		cycles = 1
	}
	d := time.Duration(cycles)*o.pollInterval + o.pollInterval/2
	o.rc.Logf("observing the DUT's southbound traffic for %s (%d poll cycle(s))", d, cycles)
	return o.rc.Sleep(ctx, d)
}

// settle waits for the sim's control plane to answer again, then waits one full
// poll cycle so the DUT's recovery falls inside this test case's window rather
// than the next one's.
//
// The control-plane probe is a liveness check, not a proof that the device has
// recovered: the sim answers /state whether or not a register-path fault is
// armed, and this suite deliberately does not claim otherwise. What proves
// recovery is the wire — a successful transaction after the provocation — and
// that is asserted by the checks that care (ERR-2, PROT-1), from the capture,
// not inferred here.
func (o *observer) settle(ctx context.Context) error {
	if !o.simAvailable() {
		return o.rc.Sleep(ctx, o.pollInterval)
	}
	deadline := time.Now().Add(settleTimeout)
	for time.Now().Before(deadline) {
		var state map[string]any
		if err := o.sim.State(ctx, &state); err == nil {
			break
		}
		o.rc.Logf("waiting for modsim's control plane to answer before finishing")
		if err := o.rc.Sleep(ctx, time.Second); err != nil {
			return err
		}
	}
	return o.watch(ctx, 1)
}

// registerDump reads the sim's own register image — the SERVER's ground truth,
// which is a non-wire source and can therefore only ever back a Narrative
// assertion, never a citation.
func (o *observer) registerDump(ctx context.Context) (map[string]int, error) {
	if !o.simAvailable() {
		return nil, fmt.Errorf("modsim's simapi is not configured")
	}
	var raw map[string]int
	if err := o.sim.Registers(ctx, &raw); err != nil {
		return nil, err
	}
	return raw, nil
}

// journal reads the DUT's Modbus client log. It is introspection of the device
// under test, so anything it supports is a Narrative with "the DUT's own
// journal" named as the source — a client-side log is exactly what these
// procedures' "the Client SHALL accurately log …" criteria are about, and it is
// not, and cannot be, a wire fact.
func (o *observer) journal(ctx context.Context, lines int) ([]string, error) {
	if o.rc.Gateway == nil || !o.rc.Gateway.Available() {
		return nil, fmt.Errorf("gateway introspection is not configured (-gateway-ssh)")
	}
	out, err := o.rc.Gateway.Journal(ctx, "lexa-modbus", lines)
	if err != nil {
		return nil, err
	}
	var keep []string
	for _, l := range strings.Split(string(out), "\n") {
		if s := strings.TrimSpace(l); s != "" {
			keep = append(keep, s)
		}
	}
	return keep, nil
}

// journalSince returns the journal lines added after a marker line count, so a
// check can say "the DUT logged this AFTER I provoked it" rather than "the DUT
// logged this at some point".
func journalSince(before, after []string) []string {
	if len(after) <= len(before) {
		return nil
	}
	// The journal is a rolling tail; align on the last line of the "before"
	// snapshot rather than on counts, which drift when lines age out.
	if len(before) > 0 {
		last := before[len(before)-1]
		for i := len(after) - 1; i >= 0; i-- {
			if after[i] == last {
				return after[i+1:]
			}
		}
	}
	return after
}

// grepJournal returns the lines containing all of the given substrings.
func grepJournal(lines []string, want ...string) []string {
	var out []string
	for _, l := range lines {
		ok := true
		for _, w := range want {
			if !strings.Contains(strings.ToLower(l), strings.ToLower(w)) {
				ok = false
				break
			}
		}
		if ok {
			out = append(out, l)
		}
	}
	return out
}

// injectionNote renders what was done to the bench for an assertion's Observed
// text. An empty list renders as an explicit statement of that, never as
// silence.
func (o *observer) injectionNote() string {
	if len(o.injected) == 0 {
		return "nothing was injected: the DUT was observed in its steady state"
	}
	return "injected: " + strings.Join(o.injected, "; ")
}

// jsonish renders a small map deterministically for a log line. It is not a
// JSON encoder — it exists so the assertion text shows the request body in a
// stable order, which a map's own iteration order would not.
func jsonish(m map[string]any) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sortStrings(keys)
	var sb strings.Builder
	sb.WriteByte('{')
	for i, k := range keys {
		if i > 0 {
			sb.WriteByte(' ')
		}
		fmt.Fprintf(&sb, "%q:%v", k, m[k])
	}
	sb.WriteByte('}')
	return sb.String()
}

func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}
