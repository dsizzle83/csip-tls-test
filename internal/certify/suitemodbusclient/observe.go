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
// re-derives it from the capture, accepting ANY number of conversations with
// that endpoint, however they overlap in time — because no other client can
// ever be one of them, on this endpoint, regardless of count or timing.
// Several of this suite's own checks provoke one reconnect or several
// (CLI-4's base-relocation sweep) as part of their own procedure, and a
// fault-induced reconnect can briefly overlap the connection it replaces
// (the old one's teardown racing the new one's SYN); every one of those is
// still legitimately the DUT.
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

// clearInject posts a best-effort /inject cleanup body, mirroring
// clearFault's contract for the /fault endpoint (best effort; a failure is
// logged and recorded, never swallowed): a check that armed something
// through /inject (a spliced model, a typed sentinel) must leave the bench
// as it found it for whatever runs next.
func (o *observer) clearInject(body map[string]any, what string) {
	if !o.simAvailable() {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := o.sim.Inject(ctx, body, nil); err != nil {
		o.injected = append(o.injected, fmt.Sprintf("FAILED to clear %s on modsim: %v", what, err))
		o.rc.Logf("WARNING: could not clear %s on modsim: %v", what, err)
		return
	}
	o.injected = append(o.injected, fmt.Sprintf("POST %s/inject %s", o.sim.BaseURL, jsonish(body)))
	o.rc.Logf("cleared on modsim: %s", what)
}

// relocate arms a runtime SunSpec-map relocation on the server via modsim's
// relocate fault (sim/southbound/relocate.go, landed 9e35da6) — ALWAYS
// available, unlike the -protofault-gated kinds; no modsim launch flag is
// needed. base is the register address to re-home the map to: 0, 40000 and
// 50000 are the three standard SunSpec bases (CLI-4 §2.4.4 requires
// discovery to work at all three); any other value deliberately serves a
// noncompliant map (ERR-1).
func (o *observer) relocate(ctx context.Context, base uint16) error {
	return o.fault(ctx, map[string]any{"kind": "relocate", "base": int(base)},
		fmt.Sprintf("re-home the server's SunSpec map to base %d, so discovery can be observed there too",
			base))
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

// awaitJournalEvidence blocks until lines added to the DUT's journal since
// before satisfy detect, or a bounded deadline elapses — whichever comes
// first — but never less than minCycles poll intervals.
//
// # Why a flat sleep was not enough
//
// The DUT is an autonomous gateway: it polls modsim southbound on its OWN
// schedule, independent of this check's arm/watch/clear pace — a live-bench
// run (runs/warnmeas-mc-ssm-20260802T134537) measured two consecutive reads
// exactly one poll interval apart (13:51:54 -> 13:52:04, 10s). A check that
// armed a fault and cleared it a fixed few cycles later, with no
// confirmation that the DUT actually polled WHILE it was armed, routinely
// finished before the DUT's next poll even started — that live run's own
// capture showed several fault classes producing "observed: none" even
// though the fault genuinely reached the server the whole time. On the
// exception side specifically the DUT does not just miss a delayed fault:
// it DROPS the session on a Modbus exception and reconnects "on next poll"
// with backoff, so RECOVERY evidence needs the same kind of patience this
// function gives arming.
//
// # What this buys
//
// detect is handed the journal lines ADDED since before (journalSince) and
// reports whether they show whatever this caller is waiting for — the DUT
// reacting to an armed fault, or the DUT resuming normal operation. This
// returns as soon as detect fires (once minCycles have elapsed, so a DUT
// slower than the assumed cadence still gets a fair look), rather than
// always waiting out the full deadline, and returns observed=false with
// whatever it last read once maxCycles is reached without detect ever
// firing — the caller decides what an unconfirmed hold means for its own
// verdict.
//
// A nil detect, or gateway introspection being unavailable, degrades to a
// flat minCycles wait: the best this function can do without a live signal
// to poll.
func (o *observer) awaitJournalEvidence(ctx context.Context, before []string, minCycles, maxCycles int,
	detect func(delta []string) bool) (observed bool, lines []string) {
	if minCycles < 1 {
		minCycles = 1
	}
	if maxCycles < minCycles {
		maxCycles = minCycles
	}
	if err := o.watch(ctx, minCycles); err != nil {
		lines, _ = o.journal(ctx, 400)
		return false, lines
	}
	if detect == nil || o.rc.Gateway == nil || !o.rc.Gateway.Available() {
		lines, _ = o.journal(ctx, 400)
		return false, lines
	}
	tick := o.pollInterval / 4
	if tick <= 0 {
		tick = 100 * time.Millisecond
	}
	deadline := time.Now().Add(time.Duration(maxCycles-minCycles) * o.pollInterval)
	for {
		var err error
		lines, err = o.journal(ctx, 400)
		if err == nil && detect(journalSince(before, lines)) {
			// A small grace period: the journal line and the wire exchange
			// that produced it are not simultaneous, and this function's
			// caller usually clears its fault (or closes the window)
			// immediately after it returns.
			_ = o.rc.Sleep(ctx, tick)
			return true, lines
		}
		if !time.Now().Before(deadline) {
			return false, lines
		}
		if err := o.rc.Sleep(ctx, tick); err != nil {
			return false, lines
		}
	}
}

// deviceErrorish reports whether any line in lines mentions device and looks
// like an error — a quick live-phase predicate for awaitJournalEvidence's
// detect parameter. (err2Journal's own citation-phase assertion applies a
// closely related but not identical filter — it additionally excludes the
// routine "verdict=match" reconciler line and collects the matches to quote
// rather than returning a bool — so this is not a refactor of that
// function, just a shared shape for the live-phase confirmation problem.)
func deviceErrorish(lines []string, device string) bool {
	for _, l := range grepJournal(lines, device) {
		low := strings.ToLower(l)
		if strings.Contains(low, "err") || strings.Contains(low, "fail") ||
			strings.Contains(low, "exception") || strings.Contains(low, "unavailable") ||
			strings.Contains(low, "down") || strings.Contains(low, "warn") {
			return true
		}
	}
	return false
}

// journalShowsRecoveryIntent reports whether lines show the DUT recognising
// a failure and stating it will retry — lexa-modbus's documented pattern for
// a southbound Modbus session loss is "device session dropped — will
// reconnect on next poll" (the live-run journal sample in
// runs/warnmeas-mc-ssm-20260802T134537). It is narrower than deviceErrorish:
// not just "something went wrong" but "and the DUT says it is retrying" —
// the fact that lets a recovery claim downgrade to WARN instead of FAIL when
// the wire itself does not show a completed post-fault exchange within the
// window.
func journalShowsRecoveryIntent(lines []string, device string) bool {
	for _, l := range grepJournal(lines, device) {
		low := strings.ToLower(l)
		if strings.Contains(low, "reconnect") || strings.Contains(low, "will retry") ||
			strings.Contains(low, "retrying") {
			return true
		}
	}
	return false
}

// freshReadback reports whether lines contain a readback log line for
// device — evidence that the DUT completed at least one full poll cycle
// (read, decode, journal), which is what CLI-4's base-relocation sweep and
// READ-2 need before restoring the server or closing the window: a stronger
// signal than "the connection reopened" for "a complete poll happened
// inside this window".
func freshReadback(lines []string, device string) bool {
	_, ok := lastReadback(lines, device)
	return ok
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

// admissionJournal reads lexa-modbus's durable admission journal (an ndjson
// file, not the systemd journal — see checks_error.go's
// admissionJournalPath) over the read-only gateway client. Introspection of
// the device under test, so anything built from it is a Narrative, never a
// citation — the same posture o.journal already takes for the systemd
// journal.
func (o *observer) admissionJournal(ctx context.Context) ([]string, error) {
	if o.rc.Gateway == nil || !o.rc.Gateway.Available() {
		return nil, fmt.Errorf("gateway introspection is not configured (-gateway-ssh)")
	}
	out, err := o.rc.Gateway.ReadFile(ctx, admissionJournalPath)
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
