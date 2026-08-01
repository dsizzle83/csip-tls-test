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
	forced := o.forceReconnect(ctx)
	// CLI-1#5 (census 20260731T234821): 2 cycles caught the header-only chain
	// walk but not model 1's separate full-body read that follows it — see
	// the extended-window note on checkCLI3/checkCLI4 for the same fix.
	if err := o.watch(ctx, 3); err != nil {
		return certify.Result{}, err
	}

	// The bench's two southbound servers share one IPv4 address, so the
	// procedure's "two servers at different IP addresses" cannot be provided
	// without editing the DUT's configuration. The check runs anyway, because
	// the half it CAN demonstrate — that the DUT connects to a server at a
	// named IPv4 address and completes discovery there — is real evidence, and
	// the missing half becomes an explicit SKIP rather than an absence.
	return certify.Result{
		Verdict: certify.Warn,
		Notes: fmt.Sprintf("discovery against server 1 at %s was observed; a SECOND server at a "+
			"different IPv4 address could not be provided (see the assertion for why). %s",
			o.server, o.injectionNote()),
		Cite: func(_ context.Context, ev *certify.Evidence) ([]certify.Assertion, error) {
			claim := "the DUT performed SunSpec discovery against a server at a given IPv4 address"
			c, pre, ok := citeConversation(ev, o, claim)
			if !ok {
				return emit(ev, c, append(pre, cli1SecondAddressSkip(o))), nil
			}
			fs := []finding{assertAttributionSound(ev, o)}
			fs = append(fs, framesf(claim,
				"destination IPv4 address of the DUT's southbound TCP connection, from the capture",
				certify.Pass, aduFrames(c.Requests...),
				"the DUT dialled %s from %s and exchanged %d Modbus message(s) there%s",
				c.Server, c.Client, len(c.Requests)+len(c.Responses), reconnectNote(forced)))
			fs = append(fs, evalDiscovery(c)...)
			fs = append(fs, evalFraming(c)...)
			fs = append(fs, cli1SecondAddressSkip(o))
			return emit(ev, c, fs), nil
		},
	}, nil
}

// cli1SecondAddressSkip states, once, why the second server cannot be provided.
func cli1SecondAddressSkip(o *observer) finding {
	second := "the bench's second southbound server (the mbaps device sim)"
	if o.hasSecure {
		second = fmt.Sprintf("the bench's second southbound server, %s,", o.secure)
	}
	return skipf(
		"the DUT performed SunSpec discovery against a second server at a DIFFERENT IPv4 address",
		"comparison of the destination addresses of the DUT's southbound connections",
		"%s shares the IPv4 address %s with server 1 — both sims run on the capture host. Providing a "+
			"server at a second address means adding a device to the DUT's own southbound configuration, "+
			"which this run must not do: the bench is shared, and a DUT whose configuration changed "+
			"mid-run is not the DUT the rest of this bundle describes. Promoting this row to full "+
			"requires a second modsim instance bound to a second address and a corresponding entry in "+
			"the DUT's /etc/lexa/modbus.json, made once before the run and recorded in the bundle's DUT "+
			"metadata", second, o.server.Addr())
}

func reconnectNote(err error) string {
	if err == nil {
		return " after its southbound connection was severed so that its reconnect would perform " +
			"discovery inside this test case's window"
	}
	return fmt.Sprintf(" (no reconnect was forced — %v — so only the DUT's steady-state polling was "+
		"observed; a client that connected before the capture began does not repeat its discovery "+
		"sequence)", err)
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
	forced := o.forceReconnect(ctx)
	if err := o.watch(ctx, 2); err != nil {
		return certify.Result{}, err
	}

	return certify.Result{
		Notes: fmt.Sprintf("the DUT's two southbound servers are on non-standard ports %d and %s. %s",
			o.server.Port(), secureDesc(o, haveSecure), o.injectionNote()),
		Cite: func(_ context.Context, ev *certify.Evidence) ([]certify.Assertion, error) {
			claim := "the DUT connected to a SunSpec server on a non-standard TCP port and completed discovery"
			c, pre, ok := citeConversation(ev, o, claim)
			if !ok {
				return emit(ev, c, pre), nil
			}
			fs := []finding{assertAttributionSound(ev, o)}
			fs = append(fs, framesf(claim,
				"destination TCP port of the DUT's southbound connection, from the capture",
				certify.Pass, aduFrames(c.Requests...),
				"the DUT dialled %s — destination port %d, which is not the Modbus default 502 — and "+
					"exchanged %d Modbus message(s) there%s",
				c.Server, c.Server.Port(), len(c.Requests)+len(c.Responses), reconnectNote(forced)))
			fs = append(fs, evalDiscovery(c)...)
			fs = append(fs, evalFraming(c)...)
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

func checkCLI3(ctx context.Context, rc *certify.RunCtx) (certify.Result, error) {
	o, why := newObserver(rc)
	if o == nil {
		return certify.Skipped("%s", why), nil
	}
	if err := o.claimServer(); err != nil {
		return certify.Result{}, err
	}
	forced := o.forceReconnect(ctx)
	// CLI-3#5 (census 20260731T234821): one more full poll interval so the
	// post-reconnect chain walk's separate full read of model 1's body — not
	// just its header — lands inside this test case's window. See
	// evalCommonModel, the assertion this extension is for.
	if err := o.watch(ctx, 3); err != nil {
		return certify.Result{}, err
	}
	want, haveWant := rc.Param(paramUnitID)

	return certify.Result{
		Verdict: certify.Warn,
		Notes: fmt.Sprintf("the DUT's unit-id handling on server 1 was observed%s; two servers with "+
			"DIFFERENT unit ids could not be provided. %s", reconnectNote(forced), o.injectionNote()),
		Cite: func(_ context.Context, ev *certify.Evidence) ([]certify.Assertion, error) {
			claim := "every Modbus request the DUT emitted carried the server's configured unit identifier"
			c, pre, ok := citeConversation(ev, o, claim)
			if !ok {
				return emit(ev, c, append(pre, cli3DifferentUnitIDs())), nil
			}
			fs := []finding{assertAttributionSound(ev, o)}
			fs = append(fs, evalUnitIDs(c, want, haveWant))
			fs = append(fs, evalDiscovery(c)...)
			fs = append(fs, evalFraming(c)...)
			fs = append(fs, cli3DifferentUnitIDs())
			return emit(ev, c, fs), nil
		},
	}, nil
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

func cli3DifferentUnitIDs() finding {
	return skipf(
		"the DUT interacted with two servers carrying DIFFERENT unit identifiers",
		"comparison of the unit identifiers across the DUT's southbound connections",
		"both of the DUT's configured southbound devices declare unit id 1, so no unit-id VARIATION "+
			"exists on this bench to observe. Providing it means changing a device's unit id in the "+
			"DUT's own /etc/lexa/modbus.json and restarting its Modbus client — a DUT configuration "+
			"change this shared-bench run must not make. Promoting this row to full requires a second "+
			"modsim instance started with a different unit id and a matching device entry, prepared "+
			"before the run")
}

// ── CLI-4 — General Discovery for SunSpec Servers with Different Base Registers ─

func checkCLI4(ctx context.Context, rc *certify.RunCtx) (certify.Result, error) {
	o, why := newObserver(rc)
	if o == nil {
		return certify.Skipped("%s", why), nil
	}
	if err := o.claimServer(); err != nil {
		return certify.Result{}, err
	}
	forced := o.forceReconnect(ctx)
	// CLI-4#5 (census 20260731T234821): see the identical note on checkCLI3.
	if err := o.watch(ctx, 3); err != nil {
		return certify.Result{}, err
	}

	return certify.Result{
		Verdict: certify.Warn,
		Notes: fmt.Sprintf("the DUT's base-address probing was observed against a server whose SunSpec "+
			"map is at 40000; the procedure's other two base addresses could not be provided. %s",
			o.injectionNote()),
		Cite: func(_ context.Context, ev *certify.Evidence) ([]certify.Assertion, error) {
			claim := "the DUT located the SunSpec map by probing a standard base address"
			c, pre, ok := citeConversation(ev, o, claim)
			if !ok {
				return emit(ev, c, append(pre, cli4OtherBases())), nil
			}
			fs := []finding{assertAttributionSound(ev, o)}
			fs = append(fs, evalBaseProbes(c, forced))
			fs = append(fs, evalDiscovery(c)...)
			fs = append(fs, evalFraming(c)...)
			fs = append(fs, cli4OtherBases())
			return emit(ev, c, fs), nil
		},
	}, nil
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

func cli4OtherBases() finding {
	return skipf(
		"the DUT completed discovery with the server's SunSpec map relocated to base 0 and to base 50000",
		"repetition of the discovery sequence with the server's map at each of the three standard bases",
		"the bench's plain-text SunSpec server serves its map at 40000 only; it has no control-plane verb "+
			"for relocating the map, so bases 0 and 50000 cannot be presented to the DUT. Promoting this "+
			"row to full requires a `-base` flag on modsim (or POST /control {\"cmd\":\"relocate\",\"base\":N}) "+
			"and three passes of this check, one per base")
}

// ── CLI-5 — Different Baud Rates (Optional, serial) ───────────────────────────

func checkCLI5(_ context.Context, _ *certify.RunCtx) (certify.Result, error) {
	// Registered although the catalog marks it inapplicable: a registered SKIP
	// carrying its reason is an engineering judgement a reviewer can weigh,
	// while an unregistered uid is indistinguishable from an oversight.
	return certify.Result{
		Verdict: certify.Skip,
		Notes: "not applicable to this bench. The procedure is the optional Modbus RTU baud-rate sweep. " +
			"The DUT does expose a southbound RS-485 client, but every SunSpec server on this bench is " +
			"Modbus TCP, so there is no serial peer to sweep baud rates against and no serial line to " +
			"capture. Promoting this row requires an RS-485 SunSpec server wired to the DUT's " +
			"/dev/lexa/rs485-1 and a line analyser, neither of which is a packet capture — the evidence " +
			"would not live in this bundle's pcap at all.",
		OffWire: true,
		OffWireReason: "the procedure is serial-only: its observables are Modbus RTU frames on an " +
			"RS-485 line, which no Ethernet capture can contain. The row is recorded as addressed and " +
			"not executed, not as passed.",
	}, nil
}
