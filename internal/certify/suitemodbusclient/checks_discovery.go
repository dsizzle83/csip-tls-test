package suitemodbusclient

// checks_discovery.go implements §2.4, the General Client Tests: CLI-1 through
// CLI-5.
//
// All four of the applicable rows share one set of criteria verbatim — "the
// Client SHALL accurately log all Models present in each Server", "…the
// contents of all the Common Model points", "Network or serial traffic SHALL be
// analyzed to verify CUT operations" — and differ only in what the test
// engineer varies between the two servers: address (CLI-1), port (CLI-2), unit
// id (CLI-3), SunSpec base register (CLI-4), baud rate (CLI-5, serial).
//
// evalDiscovery therefore asserts the common criteria once, and each check adds
// the assertions about ITS variable. That also makes the honest gaps visible
// one at a time: this bench can vary the port (two southbound servers on two
// non-standard ports) but not the address, the unit id or the base register,
// because doing any of those would mean editing the DUT's own southbound
// configuration — which the shared-bench constraint forbids, and which would in
// any case make the DUT a different DUT from the one the rest of the bundle
// describes.

import (
	"context"
	"fmt"
	"strings"

	"csip-tls-test/internal/certify"
)

// evalDiscovery asserts the criteria CLI-1..CLI-4 have in common.
//
// It is a pure function of the observed conversation, which is what lets the
// unit tests drive it with a synthetic server that answers correctly and with
// one that does not.
func evalDiscovery(c *Conversation) []finding {
	var out []finding

	base, models, complete, why := c.ModelChain()

	// (1) The SunSpec identifier probe.
	claim := "the DUT probed a standard SunSpec base address and read the 'SunS' identifier"
	method := "FC 0x03 request address + the identifier registers in the matching response, decoded " +
		"independently from the reassembled byte stream"
	if len(models) == 0 && !complete {
		out = append(out, skipf(claim, method,
			"no SunSpec identifier was observed at any of the standard bases %v: %s. On a client that "+
				"has been connected since before this test case began, the identifier probe happens once "+
				"at connect and is not repeated on every poll", StandardBases, why))
	} else if ref, ok := c.Registers.Ref(base); ok {
		hi, _ := c.Registers.Get(base)
		lo, _ := c.Registers.Get(base + 1)
		// Cite both identifier registers only when they are genuinely adjacent
		// in one response; otherwise cite the first alone. A range spanning two
		// responses would silently include whatever lay between them, which is
		// a citation of more than the claim.
		end := ref.end
		if ref2, ok := c.Registers.Ref(base + 1); ok && ref2.end == ref.start+4 {
			end = ref2.end
		}
		out = append(out, bytesf(claim, method, certify.Pass, fromServer, ref.start, end,
			"registers %d..%d read by the DUT hold 0x%04x 0x%04x = %q — the SunSpec identifier at base %d",
			base, base+1, hi, lo, string([]byte{byte(hi >> 8), byte(hi), byte(lo >> 8), byte(lo)}), base))
	}

	// (2) The model chain walk: "the Client SHALL accurately log all Models
	//     present in each Server". The wire cannot show the DUT's log, but it
	//     can show that the DUT read every model header in the chain, which is
	//     the necessary condition for logging them and the only part of the
	//     criterion that is a wire fact at all.
	claim = "the DUT walked the server's complete SunSpec model chain"
	method = "reconstruction of the model chain from the register image the DUT was observed to read: " +
		"each ID/length header pair from base+2 to the 0xFFFF end marker"
	switch {
	case len(models) == 0:
		out = append(out, skipf(claim, method, "no model header was observed: %s", why))
	case !complete:
		out = append(out, framesf(claim, method, certify.Warn, aduFrames(c.Responses...),
			"%d model header(s) were observed but the chain did not reach the 0xFFFF end marker within "+
				"this test case's frames: %s. Observed: %s", len(models), why, describeModels(models)))
	default:
		out = append(out, framesf(claim, method, certify.Pass, aduFrames(c.Responses...),
			"the DUT read every model header from base %d to the 0xFFFF end marker: %d model(s) — %s",
			base, len(models), describeModels(models)))
	}

	// (3) The Common Model contents.
	out = append(out, evalCommonModel(c, models))
	return out
}

// evalCommonModel asserts the "accurately log the contents of all the Common
// Model points" criterion as far as the wire can carry it: the DUT read the
// whole model 1 block, and here are the identity points those bytes decode to.
func evalCommonModel(c *Conversation, models []Model) finding {
	claim := "the DUT read the complete Common Model (model ID 1) block"
	method := "coverage of model 1's body by the DUT's read requests, with the identity points decoded " +
		"independently from the response bytes"
	m, ok := findModel(models, CommonModelID)
	if !ok {
		return skipf(claim, method, "model 1 was not among the model headers observed in this test case")
	}
	body := m.HeaderAddr + 2
	if !m.BodyCovered {
		return skipf(claim, method,
			"model 1 (header at %d, length %d) was found in the chain but this test case did not observe "+
				"the DUT read its whole body", m.HeaderAddr, m.Length)
	}
	var parts []string
	for _, p := range CommonModel {
		if p.Regs > 1 {
			if s, ok := c.Registers.CommonModelString(body, p.Offset, p.Regs); ok {
				parts = append(parts, fmt.Sprintf("%s=%q", p.Name, s))
			}
			continue
		}
		if w, ok := c.Registers.Get(body + p.Offset); ok {
			parts = append(parts, fmt.Sprintf("%s=%d", p.Name, w))
		}
	}
	// Cite the response bytes carrying the first identity point, so a reader
	// opens the pcap on the manufacturer string rather than on a frame number.
	ref, haveRef := c.Registers.Ref(body)
	if !haveRef {
		return skipf(claim, method, "model 1's body registers were reconstructed but carry no byte "+
			"provenance, so the decoded points cannot be cited")
	}
	// Cite the whole body only when it arrived contiguously in one response;
	// a body assembled from several reads would otherwise be cited as a byte
	// range that also covers the messages in between.
	end := ref.end
	if last, ok := c.Registers.Ref(body + m.Length - 1); ok && last.end == ref.start+2*int(m.Length) {
		end = last.end
	}
	return bytesf(claim, method, certify.Pass, fromServer, ref.start, end,
		"model 1 body at %d..%d was fully read; decoded from the cited response bytes: %s",
		body, body+m.Length-1, joinOr(parts, "no identity point decoded"))
}

func joinOr(parts []string, empty string) string {
	if len(parts) == 0 {
		return empty
	}
	s := parts[0]
	for _, p := range parts[1:] {
		s += ", " + p
	}
	return s
}

// ── CLI-1 — General Discovery for SunSpec Servers at Different IPv4 Addresses ──

func checkCLI1(ctx context.Context, rc *certify.RunCtx) (certify.Result, error) {
	o, why := newObserver(rc)
	if o == nil {
		return certify.Skipped("%s", why), nil
	}
	if err := o.claimServer(); err != nil {
		return certify.Result{}, err
	}
	d, derr := o.determinism(ctx)
	if derr != nil {
		return certify.Skipped("%s", deterministicSkip(derr)), nil
	}
	if err := d.begin(ctx, nil); err != nil {
		return certify.Result{}, err
	}
	defer d.restore(ctx)

	// A severed connection is the only way this bench can make a client that
	// has been connected for hours perform its discovery sequence again inside
	// a test case's window — lexa-proto/sunspec/reader.go caches the block
	// layout for the life of a session. The wait afterwards is held on the
	// simulator's own record of the rediscovery, not on a poll interval.
	disc, err := rediscover(ctx, d, "CLI-1")
	if err != nil {
		return certify.Result{}, err
	}

	return certify.Result{
		Verdict: certify.Warn,
		Notes: fmt.Sprintf("discovery against server 1 at %s was observed after a forced rediscovery, "+
			"held on the simulator's transaction ledger rather than on a poll interval; a SECOND server "+
			"at a different IPv4 address needs a DUT configuration change this read-only run must not "+
			"make (see the assertion). %s", o.server, o.injectionNote()),
		Cite: func(_ context.Context, ev *certify.Evidence) ([]certify.Assertion, error) {
			claim := "the DUT performed SunSpec discovery against a server at a given IPv4 address"
			c, pre, ok := citeConversation(ev, o, claim)
			fs := append([]finding(nil), pre...)
			if ok {
				fs = []finding{assertAttributionSound(ev, o)}
				fs = append(fs, framesf(claim,
					"destination IPv4 address of the DUT's southbound TCP connection, from the capture",
					certify.Pass, aduFrames(c.Requests...),
					"the DUT dialled %s from %s and exchanged %d Modbus message(s) there%s",
					c.Server, c.Client, len(c.Requests)+len(c.Responses), disc.note()))
				fs = append(fs, evalDiscovery(c)...)
				fs = append(fs, evalFraming(c)...)
			}
			fs = append(fs, evalRediscovery(disc, d))
			fs = append(fs, commonModelBodyGap())
			fs = append(fs, cli1SecondAddress(o))
			return emit(ev, c, fs), nil
		},
	}, nil
}

// cli1SecondAddress states, once, exactly what a second server at a second
// address would take.
func cli1SecondAddress(o *observer) finding {
	return skipf(
		"the DUT performed SunSpec discovery against a second server at a DIFFERENT IPv4 address",
		"present the single simulated device at a second IPv4 address and have the DUT discover it "+
			"there, per §2.4.1 steps 1-3",
		"THE BENCH HALF IS READY AND THE DUT HALF IS NOT. modsim binds one address with -bind, so "+
			"presenting the same device at a second IPv4 address is a launch argument. What cannot be "+
			"done from inside a conformance run is the other half of §2.4.1 step 2 — 'share the server "+
			"IP addresses … with the CUT operator' — because this DUT reads its southbound endpoint "+
			"from /etc/lexa/modbus.json EXACTLY ONCE, at process start, and offers no runtime path to "+
			"change it: no SIGHUP handler (it installs SIGINT/SIGTERM only), no config file watch, and "+
			"its only HTTP listener serves /metrics. The supported change is an operator write to "+
			"lexa-api's POST /config/modbus, which stages the file and then requests `systemctl restart "+
			"lexa-modbus` — and this harness's gateway client is READ-ONLY BY CONSTRUCTION (its "+
			"allowlist admits observation commands only and restricts systemctl to reporting "+
			"subcommands), because the bench is shared and a conformance run must not change the DUT it "+
			"is measuring. PROMOTING THIS ROW therefore takes an operator procedure rather than a bench "+
			"capability: prepare the second address's modsim and the matching device entry BEFORE the "+
			"run, and record the two discoveries as two runs of this row correlated in the bundle's DUT "+
			"metadata. Note also that the DUT is not commissioned-locked for this to work: the config "+
			"write API refuses outright once /etc/lexa/commissioned exists. Server 1 in this run was %s",
		o.server)
}

// ── CLI-2 — General Discovery for SunSpec Servers at Different Ports ──────────

func checkCLI2(ctx context.Context, rc *certify.RunCtx) (certify.Result, error) {
	o, why := newObserver(rc)
	if o == nil {
		return certify.Skipped("%s", why), nil
	}
	if err := o.claimServer(); err != nil {
		return certify.Result{}, err
	}
	haveSecure := o.hasSecure && o.claimSecureServer() == nil
	d, derr := o.determinism(ctx)
	if derr != nil {
		return certify.Skipped("%s", deterministicSkip(derr)), nil
	}
	if err := d.begin(ctx, nil); err != nil {
		return certify.Result{}, err
	}
	defer d.restore(ctx)
	disc, err := rediscover(ctx, d, "CLI-2")
	if err != nil {
		return certify.Result{}, err
	}

	return certify.Result{
		Notes: fmt.Sprintf("the DUT's two southbound servers are on non-standard ports %d and %s; the "+
			"rediscovery this row observes was held on the simulator's transaction ledger rather than "+
			"on a poll interval. %s", o.server.Port(), secureDesc(o, haveSecure), o.injectionNote()),
		Cite: func(_ context.Context, ev *certify.Evidence) ([]certify.Assertion, error) {
			claim := "the DUT connected to a SunSpec server on a non-standard TCP port and completed discovery"
			c, pre, ok := citeConversation(ev, o, claim)
			fs := append([]finding(nil), pre...)
			if ok {
				fs = []finding{assertAttributionSound(ev, o)}
				fs = append(fs, framesf(claim,
					"destination TCP port of the DUT's southbound connection, from the capture",
					certify.Pass, aduFrames(c.Requests...),
					"the DUT dialled %s — destination port %d, which is not the Modbus default 502 — and "+
						"exchanged %d Modbus message(s) there%s",
					c.Server, c.Server.Port(), len(c.Requests)+len(c.Responses), disc.note()))
				fs = append(fs, evalDiscovery(c)...)
				fs = append(fs, evalFraming(c)...)
			}
			fs = append(fs, evalRediscovery(disc, d))
			fs = append(fs, commonModelBodyGap())
			fs = append(fs, cli2SecondPort(ev, o, haveSecure))
			return emit(ev, c, fs), nil
		},
	}, nil
}

func secureDesc(o *observer, have bool) string {
	if !have {
		return "(no second server configured)"
	}
	return fmt.Sprint(o.secure.Port())
}

// cli2SecondPort asserts the second server's port from its own frames. Only the
// connection-level fact is available: the second server speaks mbaps, so its
// Modbus payload is inside TLS and this suite holds no keys for it.
func cli2SecondPort(ev *certify.Evidence, o *observer, have bool) finding {
	claim := "the DUT connected to a SECOND SunSpec server on a DIFFERENT non-standard TCP port"
	method := "destination TCP port of the DUT's second southbound connection, from the capture"
	if !have {
		return skipf(claim, method, "no second southbound server is configured (-mbapsdev), so the "+
			"procedure's two-server setup could not be provided")
	}
	st, err := ev.StreamOn(o.secure.Port())
	if err != nil {
		return skipf(claim, method, "no conversation with the second server %s was attributed to this "+
			"test case: %v. The DUT polls it on its own schedule, which need not fall inside this "+
			"observation window", o.secure, err)
	}
	var frames []int
	if st.First > 0 {
		frames = append(frames, st.First)
	}
	if st.Last > 0 && st.Last != st.First {
		frames = append(frames, st.Last)
	}
	return framesf(claim, method, certify.Pass, frames,
		"the DUT also held a conversation with %s — destination port %d, distinct from server 1's %d and "+
			"from the Modbus default 502. Its Modbus payload is carried inside TLS (Secure SunSpec "+
			"Modbus), and this suite holds no key material for the DUT's client side, so the model "+
			"discovery ON that connection is not decodable here; only the connection is asserted",
		o.secure, o.secure.Port(), o.server.Port())
}

// ── CLI-3 — General Discovery for SunSpec Servers with Different Unit IDs ─────

// cli3AltUnitID is the unit id the server is re-addressed to. It must differ
// from whatever the DUT is configured with, and 1..247 is the legal range
// (§2.4.3 step 1); 247 is chosen because a device configured at the top of the
// range is vanishingly unlikely, so the row does not have to negotiate with
// the bench's own configuration to be sure it changed something.
const cli3AltUnitID = 247

func checkCLI3(ctx context.Context, rc *certify.RunCtx) (certify.Result, error) {
	o, why := newObserver(rc)
	if o == nil {
		return certify.Skipped("%s", why), nil
	}
	if err := o.claimServer(); err != nil {
		return certify.Result{}, err
	}
	d, derr := o.determinism(ctx)
	if derr != nil {
		return certify.Skipped("%s", deterministicSkip(derr)), nil
	}
	if err := d.begin(ctx, nil); err != nil {
		return certify.Result{}, err
	}
	defer d.restore(ctx)

	disc, err := rediscover(ctx, d, "CLI-3")
	if err != nil {
		return certify.Result{}, err
	}
	want, haveWant := rc.Param(paramUnitID)

	// §2.4.3 step 1 — "run Server 1 … with different Unit IDs". modsim can now
	// re-address the served device at runtime, and the row drives it: the
	// device answers only cli3AltUnitID and returns 0x0B GATEWAY TARGET DEVICE
	// FAILED TO RESPOND to every other, which is what a Modbus gateway does
	// for a unit it does not front.
	//
	// That demonstrates the BENCH half of the procedure. The DUT half — being
	// told the new unit id — needs a configuration change this read-only run
	// must not make, and cli3DifferentUnitIDs says so precisely.
	alt, err := d.meet(ctx,
		map[string]any{"kind": "unit_id", "unit_id": cli3AltUnitID},
		fmt.Sprintf("re-address the served device to unit id %d, so a client still addressing its "+
			"previously configured id is answered 0x%02x GATEWAY TARGET DEVICE FAILED TO RESPOND — "+
			"§2.4.3 step 1's 'different Unit IDs', as a runtime lever", cli3AltUnitID, 0x0B),
		"unit_id", 1)
	if err != nil {
		return certify.Result{}, err
	}

	// Recovery: with the gate cleared the device answers the DUT's configured
	// id again, and the DUT resumes. Held on the ledger like everything else.
	recFence, rerr := d.arm(ctx, map[string]any{"kind": "unit_id", "clear": true},
		"restore the device's original addressing so the DUT's recovery can be observed")
	var recovery LedgerPage
	var recovered bool
	if rerr == nil {
		recovery, recovered, err = d.awaitLedger(ctx, recFence, 1)
		if err != nil {
			return certify.Result{}, err
		}
	}

	return certify.Result{
		Verdict: certify.Warn,
		Notes: fmt.Sprintf("the DUT's unit-id handling was observed against server 1%s, and the served "+
			"device was then RE-ADDRESSED at runtime to unit id %d — a capability this bench did not "+
			"have before — to show what the DUT does when a server's unit id changes under it. Two "+
			"servers with different unit ids, both of which the DUT is configured for, still needs a "+
			"DUT configuration change this run must not make. %s",
			disc.note(), cli3AltUnitID, o.injectionNote()),
		Cite: func(_ context.Context, ev *certify.Evidence) ([]certify.Assertion, error) {
			claim := "every Modbus request the DUT emitted carried the server's configured unit identifier"
			c, pre, ok := citeConversation(ev, o, claim)
			fs := append([]finding(nil), pre...)
			if ok {
				fs = []finding{assertAttributionSound(ev, o)}
				fs = append(fs, evalUnitIDs(c, want, haveWant))
				fs = append(fs, evalDiscovery(c)...)
				fs = append(fs, evalFraming(c)...)
			}
			fs = append(fs, evalRediscovery(disc, d))
			fs = append(fs, evalUnitIDsFromLedger(disc, want, haveWant, d))
			fs = append(fs, evalCLI3Readdressed(alt, d))
			fs = append(fs, evalCLI3Recovery(recovery, recovered, recFence, rerr, d))
			fs = append(fs, commonModelBodyGap())
			fs = append(fs, cli3DifferentUnitIDs())
			return emit(ev, c, fs), nil
		},
	}, nil
}

// evalUnitIDsFromLedger asserts the unit-id discipline from the SERVER's own
// record, which — unlike the capture — cannot miss a request that fell outside
// the window.
func evalUnitIDsFromLedger(disc rediscovery, want string, haveWant bool, d *determinism) finding {
	claim := "every Modbus request the DUT emitted carried one unit identifier, in the legal range " +
		"1..247, and the server echoed it"
	method := "the MBAP unit identifier of every request in the simulator's own transaction ledger " +
		"since the DUT's connection was severed"
	if !disc.Observed || disc.Page.Total == 0 {
		return skipf(claim, method, "no transaction was recorded to read a unit id from")
	}
	seen := map[uint8]int{}
	for _, e := range disc.Page.Entries {
		seen[e.UnitID]++
	}
	ids := make([]int, 0, len(seen))
	for id := range seen {
		ids = append(ids, int(id))
	}
	sortInts(ids)
	switch {
	case len(ids) > 1:
		return narrativef(claim, method, d.ledgerSource(), certify.Warn,
			"the DUT addressed %d distinct unit ids on this server: %v. That is legal — a Modbus "+
				"gateway fronts several units — but it means this row is watching more than one device",
			len(ids), ids)
	case ids[0] == 0 || ids[0] > 247:
		return narrativef(claim, method, d.ledgerSource(), certify.Fail,
			"the DUT addressed unit id %d, outside the legal 1..247 range (0 is the RTU broadcast "+
				"address and has no meaning over Modbus/TCP)", ids[0])
	case haveWant && want != fmt.Sprint(ids[0]):
		return narrativef(claim, method, d.ledgerSource(), certify.Fail,
			"the DUT addressed unit id %d; the operator declared the server's unit id as %q (-param %s)",
			ids[0], want, paramUnitID)
	default:
		return narrativef(claim, method, d.ledgerSource(), certify.Pass,
			"all %d transaction(s) the simulator recorded addressed unit id %d, in the legal range "+
				"1..247. First: %s", disc.Page.Total, ids[0], disc.Page.Entries[0])
	}
}

// evalCLI3Readdressed reports what happened when the served device's unit id
// changed under the DUT.
//
// It carries SKIP, not PASS, and the text says why: it is an OBSERVATION
// adjacent to §2.4.3's criterion, not the criterion. The criterion is that the
// CUT can DISCOVER a server whose unit id differs, which needs the DUT told
// about it; what this shows is that the DUT genuinely uses the unit-id field
// rather than ignoring it, and that the bench can now present the variation.
func evalCLI3Readdressed(m meeting, d *determinism) finding {
	claim := "the served device was re-addressed to a different unit id and the DUT's requests to its " +
		"previously configured id were answered as a gateway-target failure"
	method := fmt.Sprintf("arm modsim's unit_id gate at unit %d and read, from the simulator's own "+
		"ledger, how the DUT's requests were resolved", cli3AltUnitID)
	if m.ArmErr != nil {
		return skipf(claim, method, "the served device could not be re-addressed: %v", m.ArmErr)
	}
	if !m.ok() {
		return skipf(claim, method, "%s", m.reason())
	}
	refused := m.Page.Exceptions()[0x0B]
	if len(refused) == 0 {
		return narrativef(claim, method, d.ledgerSource(), certify.Warn,
			"the device was re-addressed to unit id %d at epoch %d and the DUT's %d transaction(s) "+
				"under it were resolved as %s — none as a gateway-target failure. Either the DUT was "+
				"already addressing unit %d, or the gate did not take",
			cli3AltUnitID, m.Epoch, m.Page.Total, m.Page.Summary(), cli3AltUnitID)
	}
	return narrativef(claim, method, d.ledgerSource(), certify.Skip,
		"OBSERVATION, not the criterion: with the served device re-addressed to unit id %d at epoch %d, "+
			"%d of the DUT's request(s) — still carrying unit id %d — were answered 0x0B GATEWAY TARGET "+
			"DEVICE FAILED TO RESPOND, and the device behind the gate never saw them. First: %s. This "+
			"shows the DUT genuinely ADDRESSES the unit id it is configured with rather than ignoring "+
			"the field, and that this bench can now present a server at a different unit id at all — "+
			"neither of which is §2.4.3's criterion, which is that the CUT DISCOVERS a server whose "+
			"unit id differs. That needs the DUT told the new id; see the assertion below",
		cli3AltUnitID, m.Epoch, len(refused), refused[0].UnitID, refused[0])
}

// evalCLI3Recovery: with the gate cleared, the DUT's own unit id works again.
func evalCLI3Recovery(page LedgerPage, recovered bool, fence uint64, err error, d *determinism) finding {
	claim := "the DUT resumed normal operation once the server answered its configured unit id again"
	method := "a transaction that completed normally AFTER the unit-id gate was cleared, held on the " +
		"simulator's transaction ledger rather than on a clock"
	if err != nil {
		return skipf(claim, method, "the unit-id gate could not be cleared (%v), so there is no "+
			"recovery interval to observe", err)
	}
	if !recovered {
		return narrativef(claim, method, d.ledgerSource(), certify.Fail,
			"with the device's original addressing restored at epoch %d, the DUT issued no transaction "+
				"at all to this server within the barrier's budget", fence)
	}
	good := page.WithOutcome(outcomeAnswered)
	if len(good) == 0 {
		return narrativef(claim, method, d.ledgerSource(), certify.Warn,
			"with the device's original addressing restored at epoch %d the DUT did transact again, but "+
				"none of its %d transaction(s) completed normally: %s", fence, page.Total, page.Summary())
	}
	return narrativef(claim, method, d.ledgerSource(), certify.Pass,
		"with the device's original addressing restored at epoch %d, %d of the DUT's transaction(s) "+
			"completed normally — first: %s. The client recovered from a server that stopped answering "+
			"its unit id", fence, len(good), good[0])
}

func cli3DifferentUnitIDs() finding {
	return skipf(
		"the DUT interacted with two servers carrying DIFFERENT unit identifiers",
		"present the single simulated device at a second unit id and have the DUT discover it there, "+
			"per §2.4.3 steps 1-3",
		"THE BENCH HALF IS READY AND THE DUT HALF IS NOT. modsim can re-address the served device at "+
			"runtime — the preceding assertion drove it — so a server at a different unit id is no "+
			"longer something this bench lacks. What cannot be done from inside a conformance run is "+
			"§2.4.3 step 2, sharing the new unit id with the CUT: this DUT reads devices[].unit_id from "+
			"/etc/lexa/modbus.json EXACTLY ONCE, at process start, applies it to the session with a "+
			"single SetUnitID at connect, and offers no runtime path to change it — no SIGHUP handler "+
			"(it installs SIGINT/SIGTERM only), no config watch, and its only HTTP listener serves "+
			"/metrics. The supported change is an operator write to lexa-api's POST /config/modbus "+
			"followed by `systemctl restart lexa-modbus`, and this harness's gateway client is "+
			"READ-ONLY BY CONSTRUCTION (its allowlist admits observation commands only and restricts "+
			"systemctl to reporting subcommands) because the bench is shared and a conformance run must "+
			"not change the DUT it is measuring. PROMOTING THIS ROW takes an operator procedure, not a "+
			"bench capability: prepare the second unit id in the DUT's config before the run and record "+
			"the two discoveries as two runs of this row correlated in the bundle's DUT metadata")
}

// evalUnitIDs asserts the MBAP unit identifier discipline.
func evalUnitIDs(c *Conversation, want string, haveWant bool) finding {
	claim := "every Modbus request the DUT emitted carried the server's configured unit identifier, " +
		"in the legal range 1..247"
	method := "unit identifier field of every MBAP header in the reassembled DUT→server direction, " +
		"and of every response"
	ids := c.UnitIDs()
	if len(ids) == 0 {
		return skipf(claim, method, "no requests were observed")
	}
	// Responses must echo the request's unit id; a mismatch means the DUT
	// accepted an answer from a different slave.
	echoMismatch := 0
	for _, ex := range c.Exchanges {
		if ex.Response != nil && ex.Response.UnitID != ex.Request.UnitID {
			echoMismatch++
		}
	}
	first := c.Requests[0]
	switch {
	case len(ids) > 1:
		return bytesf(claim, method, certify.Warn, fromDUT, first.Start, first.End,
			"the DUT addressed %d distinct unit ids on one connection: %v", len(ids), ids)
	case ids[0] == 0 || ids[0] > 247:
		return bytesf(claim, method, certify.Fail, fromDUT, first.Start, first.End,
			"the DUT addressed unit id %d, which is outside the legal 1..247 range (0 is the RTU "+
				"broadcast address and has no meaning over Modbus/TCP)", ids[0])
	case echoMismatch > 0:
		return bytesf(claim, method, certify.Fail, fromDUT, first.Start, first.End,
			"%d response(s) carried a unit id different from the request they answered, and the DUT "+
				"consumed them", echoMismatch)
	case haveWant && want != fmt.Sprint(ids[0]):
		return bytesf(claim, method, certify.Fail, fromDUT, first.Start, first.End,
			"the DUT addressed unit id %d; the operator declared the server's unit id as %q "+
				"(-param %s)", ids[0], want, paramUnitID)
	default:
		return bytesf(claim, method, certify.Pass, fromDUT, first.Start, first.End,
			"all %d request(s) addressed unit id %d (legal range 1..247) and every response echoed it. "+
				"First request cited in full: [%s]", len(c.Requests), ids[0], first.Hex())
	}
}

// ── CLI-4 — General Discovery for SunSpec Servers with Different Base Registers ─

// cli4Bases are §2.4.4's three canonical starting registers, in the order the
// procedure walks them (steps 1, 4, 6). The sweep ends at 40000 so the bench is
// left where every other row expects it even before the deferred restore runs.
var cli4Bases = []uint16{0, 50000, 40000}

// baseAttempt is one relocate-and-rediscover leg of the sweep.
type baseAttempt struct {
	Base        uint16
	RelocateErr error
	Disc        rediscovery
}

func checkCLI4(ctx context.Context, rc *certify.RunCtx) (certify.Result, error) {
	o, why := newObserver(rc)
	if o == nil {
		return certify.Skipped("%s", why), nil
	}
	if err := o.claimServer(); err != nil {
		return certify.Result{}, err
	}
	d, derr := o.determinism(ctx)
	if derr != nil {
		return certify.Skipped("%s", deterministicSkip(derr)), nil
	}
	if err := d.begin(ctx, nil); err != nil {
		return certify.Result{}, err
	}
	// The default base is ALWAYS restored, unconditionally deferred: a bench
	// left relocated would corrupt every other row's discovery, not just this
	// one's.
	defer d.restore(ctx)

	// The device's own base first, so the row has a baseline discovery from
	// the map where every other row expects it.
	initial, err := rediscover(ctx, d, "CLI-4 (default base)")
	if err != nil {
		return certify.Result{}, err
	}

	// Then each of the other two standard bases in turn. Each leg relocates,
	// severs the connection, and waits ON THE SIMULATOR'S LEDGER for the
	// rediscovery — so the evidence for a base is the traffic that happened
	// after that base was in force, by construction, instead of being matched
	// back to a conversation by guessing which reconnect was which.
	var sweep []baseAttempt
	if o.injectionReason() == "" {
		for _, b := range cli4Bases {
			att := baseAttempt{Base: b}
			if _, rerr := d.relocate(ctx, b, fmt.Sprintf("re-home the server's SunSpec map to base %d, "+
				"one of §2.4.4's three canonical starting registers, so discovery can be observed "+
				"there too", b)); rerr != nil {
				att.RelocateErr = rerr
				sweep = append(sweep, att)
				continue
			}
			att.Disc, err = rediscover(ctx, d, fmt.Sprintf("CLI-4 (base %d)", b))
			if err != nil {
				return certify.Result{}, err
			}
			sweep = append(sweep, att)
		}
	}

	return certify.Result{
		Verdict: certify.Warn,
		Notes: fmt.Sprintf("the server's SunSpec map was re-homed to each of §2.4.4's three canonical "+
			"starting registers in turn — %v — and the DUT's rediscovery at each was held on the "+
			"simulator's own transaction ledger rather than on a poll interval, so each base's evidence "+
			"is the traffic that happened while THAT base was in force. %s",
			cli4Bases, o.injectionNote()),
		Cite: func(_ context.Context, ev *certify.Evidence) ([]certify.Assertion, error) {
			claim := "the DUT located the SunSpec map by probing a standard base address"
			c, pre, ok := citeConversation(ev, o, claim)
			fs := append([]finding(nil), pre...)
			if ok {
				fs = []finding{assertAttributionSound(ev, o)}
				fs = append(fs, evalBaseProbes(c, initial.Err))
				fs = append(fs, evalDiscovery(c)...)
				fs = append(fs, evalFraming(c)...)
			}
			fs = append(fs, evalRediscovery(initial, d))
			fs = append(fs, evalBaseSweep(sweep, o.injectionReason(), d))
			fs = append(fs, commonModelBodyGap())
			return emit(ev, c, fs), nil
		},
	}, nil
}

// evalBaseSweep is CLI-4's headline criterion: discovery works at every
// canonical base.
//
// Each leg is graded from the simulator's own ledger, fenced at the epoch that
// leg's reconnect happened at. That is what makes the evidence unambiguous:
// the previous version had to match a reconnect back to a base by looking for
// a probe at that address among several attributed conversations, and a
// position-based or address-based guess breaks the moment one leg of the sweep
// fails — which is exactly the partial result this row has to report honestly.
func evalBaseSweep(sweep []baseAttempt, injectionReason string, d *determinism) finding {
	claim := "the DUT completed SunSpec discovery with the server's map at each of the three canonical " +
		"starting registers 0, 40000 and 50000"
	method := "re-home the server's map to each base, sever the DUT's connection, and read from the " +
		"simulator's ledger — fenced at that leg's own epoch — whether the DUT probed the new base and " +
		"read the identifier there"
	if len(sweep) == 0 {
		return skipf(claim, method, "the server's map could not be relocated for this run (%s), so the "+
			"other bases could not be presented to the DUT", injectionReason)
	}
	var parts []string
	ok := 0
	for _, att := range sweep {
		switch {
		case att.RelocateErr != nil:
			parts = append(parts, fmt.Sprintf("base %d: the map could not be re-homed: %v",
				att.Base, att.RelocateErr))
			continue
		case att.Disc.Err != nil:
			parts = append(parts, fmt.Sprintf("base %d: the map moved, but the DUT's connection could "+
				"not be severed to make it re-probe: %v", att.Base, att.Disc.Err))
			continue
		case !att.Disc.Observed:
			parts = append(parts, fmt.Sprintf("base %d: the map moved and the connection was severed at "+
				"epoch %d, but the DUT issued only %d transaction(s) afterwards",
				att.Base, att.Disc.Fence, att.Disc.Page.Total))
			continue
		}
		probed, found := probeAt(att.Disc.Page, att.Base)
		switch {
		case !probed:
			parts = append(parts, fmt.Sprintf("base %d: the DUT read at %v after the relocation and "+
				"never at %d itself", att.Base, att.Disc.Page.Addresses(), att.Base))
		case !found:
			parts = append(parts, fmt.Sprintf("base %d: the DUT probed it, but no response carried the "+
				"SunSpec identifier — the relocation did not take", att.Base))
		default:
			ok++
			parts = append(parts, fmt.Sprintf("base %d: probed and the identifier read back, then %d "+
				"further transaction(s) walking the map", att.Base, att.Disc.Page.Total-1))
		}
	}
	v := certify.Pass
	if ok < len(sweep) {
		v = certify.Warn
	}
	return narrativef(claim, method, d.ledgerSource(), v,
		"%d of %d base(s) completed: %s", ok, len(sweep), strings.Join(parts, "; "))
}

// probeAt reports whether the page shows a read AT base, and whether one of
// them returned the SunSpec identifier.
func probeAt(p LedgerPage, base uint16) (probed, found bool) {
	for _, e := range p.Reads() {
		if e.Addr != base {
			continue
		}
		probed = true
		if vals, ok := e.Values(); ok && len(vals) >= 2 && vals[0] == SunSHigh && vals[1] == SunSLow {
			found = true
		}
	}
	return probed, found
}

// evalBaseProbes asserts which of the three standard bases the DUT probed, and
// — as importantly for ERR-1 — that it probed nothing else.
func evalBaseProbes(c *Conversation, forced error) finding {
	claim := "the DUT probed only standard SunSpec base addresses, and read the map from the one that " +
		"answered"
	method := "start addresses of the DUT's FC 0x03 requests, compared against the three standard " +
		"SunSpec base addresses 0, 40000 and 50000"
	probes := c.BaseProbes()
	if len(probes) == 0 {
		reason := "no read at a standard base address was observed"
		if forced != nil {
			reason += fmt.Sprintf("; no reconnect could be forced (%v), and a client already connected "+
				"when the capture began does not repeat its base probe", forced)
		} else {
			reason += " even though a reconnect was forced, so either the DUT caches the base address " +
				"across reconnects or its probe fell outside this test case's frames"
		}
		return skipf(claim, method, "%s", reason)
	}
	var addrs []uint16
	for _, p := range probes {
		addrs = append(addrs, p.Start)
	}
	ex := c.Exchanges[probes[0].Exchange]
	found := ""
	if hi, ok := c.Registers.Get(probes[0].Start); ok && hi == SunSHigh {
		found = fmt.Sprintf(" The probe at %d returned the SunSpec identifier, and the model-chain walk "+
			"continued from %d.", probes[0].Start, probes[0].Start+2)
	}
	return bytesf(claim, method, certify.Pass, fromDUT, ex.Request.Start, ex.Request.End,
		"the DUT issued %d read(s) at standard base address(es) %v (of the legal set %v) and none at any "+
			"other candidate base.%s First probe cited in full: [%s]",
		len(probes), addrs, StandardBases, found, ex.Request.Hex())
}

// CLI-5 — Different Baud Rates (Optional, serial) — has no check here on
// purpose. The catalog marks it inapplicable (no RS-485 SunSpec server exists
// on this bench to sweep baud rates against), and the framework now turns an
// UNREGISTERED, catalog-inapplicable row into a reasoned bundle.
// VerdictNotApplicable on its own — see certify's scope.go (CatalogScope) and
// register.go's file doc. A suite-authored SKIP repeating that same fact
// would be exactly the "old idiom" N/A exists to retire (CAMPAIGNS.md §5).
