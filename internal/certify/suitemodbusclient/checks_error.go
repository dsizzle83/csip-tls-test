package suitemodbusclient

// checks_error.go implements §2.9, the Error Tests: ERR-1, ERR-2 and ERR-3.
//
// These are the rows where the bench has to make the SERVER misbehave, and they
// are therefore the rows where this suite's honesty is most load-bearing. The
// plain-text sim has a published fault-injection surface, and two of its fault
// kinds put real Modbus exception responses on the wire — so ERR-2 is driven
// for real, with the provocation quoted in the assertion. The other two rows
// need vocabularies the sim does not have (a relocatable register map for
// ERR-1, a spliced-in unknown model for ERR-3), and they say so, naming the sim
// capability that would promote them, rather than dressing an adjacent
// observation up as the criterion.

import (
	"context"
	"fmt"
	"strings"

	"csip-tls-test/internal/certify"
)

// ── ERR-2 — Exception Tests ───────────────────────────────────────────────────

// exceptionPhase records one armed fault and what it was expected to produce.
type exceptionPhase struct {
	Kind string
	// WantCode is the exception code the sim's documentation says this fault
	// produces. It is recorded so the assertion can report a MISMATCH between
	// the fault's contract and the wire, which would be a bench defect worth
	// knowing about — not silently accept whatever arrived.
	WantCode uint8
	Why      string
	Armed    bool
	Err      error
}

func checkERR2(ctx context.Context, rc *certify.RunCtx) (certify.Result, error) {
	o, why := newObserver(rc)
	if o == nil {
		return certify.Skipped("%s", why), nil
	}
	if err := o.claimServer(); err != nil {
		return certify.Result{}, err
	}
	if r := o.injectionReason(); r != "" {
		return certify.Skipped("this procedure requires the server to return Modbus exceptions, and %s", r), nil
	}

	journalBefore, _ := o.journal(ctx, 200)

	// Baseline: one clean poll cycle, so the capture contains a normal
	// transaction before the provocation as well as after it.
	if err := o.watch(ctx, 1); err != nil {
		return certify.Result{}, err
	}

	phases := []*exceptionPhase{
		{Kind: "exception_code", WantCode: 0x04,
			Why: "make every register read return exception code 0x04 SERVER DEVICE FAILURE, the " +
				"'right device, internally broken' class of §2.9.2 step 1"},
		{Kind: "unit_id_confusion", WantCode: 0x0B,
			Why: "make every register read return exception code 0x0B GATEWAY TARGET DEVICE FAILED TO " +
				"RESPOND, a second and distinct exception class — the addressing failure"},
	}
	for _, p := range phases {
		if err := o.fault(ctx, map[string]any{"kind": p.Kind}, p.Why); err != nil {
			p.Err = err
			rc.Logf("could not arm %s: %v", p.Kind, err)
			continue
		}
		p.Armed = true
		err := o.watch(ctx, 2)
		o.clearFault(p.Kind)
		if err != nil {
			return certify.Result{}, err
		}
	}

	// Recovery: the criterion "the CUT continues to operate normally after each
	// Modbus Exception" is only evidenced if a normal transaction follows.
	if err := o.settle(ctx); err != nil {
		return certify.Result{}, err
	}
	journalAfter, _ := o.journal(ctx, 400)
	newLines := journalSince(journalBefore, journalAfter)

	return certify.Result{
		Verdict: certify.Warn,
		Notes: fmt.Sprintf("two of the four exception classes the procedure names were provoked for "+
			"real and observed on the wire; the other two need server vocabularies this bench does not "+
			"have. %s", o.injectionNote()),
		Cite: func(_ context.Context, ev *certify.Evidence) ([]certify.Assertion, error) {
			claim := "the DUT received Modbus exception responses and continued to operate normally"
			c, pre, ok := citeConversation(ev, o, claim)
			if !ok {
				return emit(ev, c, append(pre, err2UnprovokedCodes()...)), nil
			}
			fs := []finding{assertAttributionSound(ev, o)}
			fs = append(fs, evalERR2(c, phases, o.injectionNote())...)
			fs = append(fs, err2Journal(newLines))
			fs = append(fs, err2UnprovokedCodes()...)
			return emit(ev, c, fs), nil
		},
	}, nil
}

// evalERR2 is ERR-2's decision logic over the observed conversation.
func evalERR2(c *Conversation, phases []*exceptionPhase, injected string) []finding {
	var out []finding
	exceptions := c.Exceptions()

	byCode := map[uint8][]Exchange{}
	for _, ex := range exceptions {
		if code, ok := ex.Response.ExceptionCode(); ok {
			byCode[code] = append(byCode[code], ex)
		}
	}

	for _, p := range phases {
		claim := fmt.Sprintf("the DUT received exception code 0x%02x %s from the server",
			p.WantCode, ExceptionName(p.WantCode))
		method := "exception-bit function code and exception code of a response in the reassembled " +
			"server→DUT direction, after the fault named in Observed was armed on the server"
		if !p.Armed {
			out = append(out, skipf(claim, method,
				"the %q fault could not be armed on the server: %v", p.Kind, p.Err))
			continue
		}
		hits := byCode[p.WantCode]
		if len(hits) == 0 {
			out = append(out, skipf(claim, method,
				"the %q fault was armed on the server (%s) but no response carrying exception code "+
					"0x%02x was attributed to this test case. Observed exception codes: %s. %s",
				p.Kind, p.Why, p.WantCode, describeCodes(byCode), injected))
			continue
		}
		r := hits[0].Response
		out = append(out, bytesf(claim, method, certify.Pass, fromServer, r.Start, r.End,
			"%d response(s) carried function code 0x%02x (request FC 0x%02x with the exception bit set) "+
				"and exception code 0x%02x %s, after the server was made to produce them by %s. "+
				"First exception response cited in full: [%s]",
			len(hits), r.FC, hits[0].Request.FC, p.WantCode, ExceptionName(p.WantCode),
			injected, r.Hex()))
	}

	// The DUT's side of the criterion: it kept transacting.
	claim := "the DUT continued to operate normally after each Modbus exception"
	method := "a complete, non-exception FC 0x03 exchange occurring after the last exception response " +
		"in this test case's frames"
	switch {
	case len(exceptions) == 0:
		out = append(out, skipf(claim, method,
			"no exception response was observed, so there is nothing for the DUT to have recovered from"))
	default:
		last := exceptions[len(exceptions)-1].Response
		if ex, ok := firstSuccessfulReadAfter(c, last.End); ok {
			out = append(out, bytesf(claim, method, certify.Pass, fromServer,
				ex.Response.Start, ex.Response.End,
				"after %d exception response(s), the DUT issued %s and the server answered it normally — "+
					"the client neither abandoned the connection nor stopped polling. Recovery response "+
					"cited: %s", len(exceptions), ex.Request.String(), ex.Response.String()))
		} else {
			out = append(out, framesf(claim, method, certify.Fail, aduFrames(*last),
				"the last %d Modbus message(s) this test case observed were exception responses and no "+
					"successful read followed within the window, so the DUT was not seen to resume "+
					"normal operation after the fault was cleared", len(exceptions)))
		}
	}
	return out
}

// err2Journal reports whether the DUT logged the exceptions. It can only ever
// be a Narrative: a client-side log is not a wire fact.
func err2Journal(lines []string) finding {
	claim := "the DUT logged each Modbus exception it received"
	method := "the DUT's own lexa-modbus journal, read over the read-only gateway client, restricted " +
		"to lines added after the fault was armed"
	source := "journalctl -u lexa-modbus on the device under test"
	if len(lines) == 0 {
		return skipf(claim, method,
			"no journal lines could be read from the DUT (gateway introspection unavailable, or no new "+
				"lines appeared), so the client-side logging criterion is unevidenced here")
	}
	hits := grepJournal(lines, "inv-plain")
	var errs []string
	for _, l := range hits {
		low := strings.ToLower(l)
		if strings.Contains(low, "verdict=match") {
			continue // the routine per-poll reconciler line
		}
		if strings.Contains(low, "err") || strings.Contains(low, "fail") ||
			strings.Contains(low, "exception") || strings.Contains(low, "unavailable") ||
			strings.Contains(low, "down") || strings.Contains(low, "warn") {
			errs = append(errs, l)
		}
	}
	if len(errs) == 0 {
		return narrativef(claim, method, source, certify.Warn,
			"%d journal line(s) were added while the server was returning exceptions, but none of them "+
				"names an error, an exception or an unavailable device for the affected server. The "+
				"DUT may log exceptions at a level this journal read did not capture; as observed, the "+
				"'accurately log all exception codes' criterion is not met", len(lines))
	}
	shown := errs
	if len(shown) > 3 {
		shown = shown[:3]
	}
	return narrativef(claim, method, source, certify.Pass,
		"%d journal line(s) added during the fault report the failure of the affected server. First: %s",
		len(errs), strings.Join(shown, " | "))
}

// err2UnprovokedCodes states, per code, why it was not produced.
func err2UnprovokedCodes() []finding {
	type gap struct {
		code   uint8
		reason string
	}
	gaps := []gap{
		{0x01, "the procedure provokes ILLEGAL FUNCTION by sending a function code the server does not " +
			"implement. The DUT chooses its own function codes and offers no way to make it emit an " +
			"unimplemented one, and the bench cannot inject a request into the DUT's client socket. " +
			"Promoting this row needs a server-side fault that answers 0x01 to a NAMED legitimate " +
			"function code — e.g. POST /fault {\"kind\":\"exception_code\",\"code\":1,\"on_fc\":3}"},
		{0x02, "ILLEGAL DATA ADDRESS is provoked by writing to an unimplemented point. The DUT writes " +
			"only what its reconcilers decide to write, at addresses it discovered, so it will not " +
			"address an unimplemented point on request. Same server-side fault parameter would " +
			"provide it"},
		{0x03, "ILLEGAL DATA VALUE is provoked by writing an enumerated point a value the server does " +
			"not support. Same constraint: the value written is the DUT's, derived from a northbound " +
			"command, and this suite must not drive the northbound surface concurrently"},
	}
	out := make([]finding, 0, len(gaps))
	for _, g := range gaps {
		out = append(out, skipf(
			fmt.Sprintf("the DUT received and logged exception code 0x%02x %s", g.code, ExceptionName(g.code)),
			"provocation of the named exception class on the server, per §2.9.2 step 1",
			"%s", g.reason))
	}
	return out
}

func describeCodes(byCode map[uint8][]Exchange) string {
	if len(byCode) == 0 {
		return "none"
	}
	var parts []string
	for code, ex := range byCode {
		parts = append(parts, fmt.Sprintf("0x%02x %s ×%d", code, ExceptionName(code), len(ex)))
	}
	sortStrings(parts)
	return strings.Join(parts, ", ")
}

// ── ERR-1 — Noncompliant Server ───────────────────────────────────────────────

func checkERR1(ctx context.Context, rc *certify.RunCtx) (certify.Result, error) {
	o, why := newObserver(rc)
	if o == nil {
		return certify.Skipped("%s", why), nil
	}
	if err := o.claimServer(); err != nil {
		return certify.Result{}, err
	}
	forced := o.forceReconnect(ctx)
	if err := o.watch(ctx, 1); err != nil {
		return certify.Result{}, err
	}
	return certify.Result{
		Verdict: certify.Skip,
		Notes: "the server cannot be made noncompliant on this bench: its SunSpec map is fixed at base " +
			"40000 and it has no verb for relocating it to the deliberately off-by-one 40001 the " +
			"procedure calls for. The adjacent fact the wire CAN show — that the DUT probes only legal " +
			"base addresses — is cited, carrying SKIP so it cannot be mistaken for the criterion.",
		Cite: func(_ context.Context, ev *certify.Evidence) ([]certify.Assertion, error) {
			claim := "the DUT logged the server as noncompliant when its SunSpec map was at holding " +
				"register 40001"
			c, pre, ok := citeConversation(ev, o, claim)
			if !ok {
				return emit(ev, c, append(pre, err1Skips()...)), nil
			}
			fs := []finding{assertAttributionSound(ev, o)}
			fs = append(fs, err1Skips()...)
			fs = append(fs, evalERR1Observation(c, forced))
			return emit(ev, c, fs), nil
		},
	}, nil
}

func err1Skips() []finding {
	return []finding{
		skipf("the DUT logged the server as noncompliant when its SunSpec map was at holding register 40001",
			"connect the DUT to a server whose SunSpec map begins one register off a legal base, per §2.9.1 step 1",
			"the bench's plain-text SunSpec server serves its map at base 40000 and exposes no verb for "+
				"relocating it, so the deliberately noncompliant 40001 map this row is built on cannot "+
				"be presented to the DUT at all. Promoting this row to full requires the same sim "+
				"capability CLI-4 needs — a settable map base (`modsim -base 40001`, or POST /control "+
				"{\"cmd\":\"relocate\",\"base\":40001}) — plus a DUT device entry pointing at that instance"),
		skipf("the DUT recovered — did not hang or crash — after connecting to a noncompliant server",
			"process liveness and continued polling after the noncompliant server was presented",
			"the provocation could not be applied (see the previous assertion), so there is no recovery "+
				"to observe. Note that ERR-2 does evidence the DUT's recovery from a server that answers "+
				"every read with an exception, which is a different fault of the same family"),
	}
}

// evalERR1Observation cites the DUT's base-probing behaviour with a SKIP
// verdict: it is adjacent evidence, not the criterion, and the verdict says so.
func evalERR1Observation(c *Conversation, forced error) finding {
	claim := "the DUT probed for the SunSpec identifier only at legal base addresses"
	method := "start addresses of the DUT's FC 0x03 requests, compared against the legal base set"
	probes := c.BaseProbes()
	if len(probes) == 0 {
		return skipf(claim, method,
			"no base-address probe was observed in this test case's frames (forced reconnect: %v)", forced)
	}
	var addrs []uint16
	for _, p := range probes {
		addrs = append(addrs, p.Start)
	}
	ex := c.Exchanges[probes[0].Exchange]
	return bytesf(claim, method, certify.Skip, fromDUT, ex.Request.Start, ex.Request.End,
		"observation only, not the criterion: the DUT probed base address(es) %v, all drawn from the "+
			"legal set %v, and none at 40001. This shows the DUT would not accidentally find a map at "+
			"the noncompliant offset — it does NOT show what the DUT logs when it fails to find one. "+
			"First probe cited: [%s]", addrs, StandardBases, ex.Request.Hex())
}

// ── ERR-3 — Unknown Model ID Test ─────────────────────────────────────────────

func checkERR3(ctx context.Context, rc *certify.RunCtx) (certify.Result, error) {
	o, why := newObserver(rc)
	if o == nil {
		return certify.Skipped("%s", why), nil
	}
	if err := o.claimServer(); err != nil {
		return certify.Result{}, err
	}
	forced := o.forceReconnect(ctx)
	if err := o.watch(ctx, 2); err != nil {
		return certify.Result{}, err
	}
	return certify.Result{
		Verdict: certify.Warn,
		Notes: "no model with an ID unknown to the DUT could be spliced into the server's chain, so the " +
			"row's literal setup was not provided. The BEHAVIOUR the criterion turns on — stepping over " +
			"a model the client does not consume by using its length header, and continuing the walk — " +
			"was observed against the models the DUT does not read.",
		Cite: func(_ context.Context, ev *certify.Evidence) ([]certify.Assertion, error) {
			claim := "the DUT connected without issue to a server carrying a model with an unknown ID"
			c, pre, ok := citeConversation(ev, o, claim)
			if !ok {
				return emit(ev, c, append(pre, err3Skip())), nil
			}
			fs := []finding{assertAttributionSound(ev, o)}
			fs = append(fs, evalERR3(c, forced)...)
			fs = append(fs, err3Skip())
			return emit(ev, c, fs), nil
		},
	}, nil
}

// evalERR3 asserts the skip-by-length behaviour the row's criterion depends on.
func evalERR3(c *Conversation, forced error) []finding {
	claim := "the DUT stepped over a model it did not consume by using its length header, and continued " +
		"the chain walk to the end marker"
	method := "model chain reconstruction: a model whose ID and length registers the DUT read but whose " +
		"body it never requested, followed by a header read at exactly HeaderAddr + 2 + Length"

	base, models, complete, why := c.ModelChain()
	if len(models) == 0 {
		return []finding{skipf(claim, method,
			"no model chain was reconstructed from this test case's frames: %s (forced reconnect: %v)",
			why, forced)}
	}
	var skipped []Model
	for _, m := range models {
		if !m.BodyRead && m.Length > 0 {
			skipped = append(skipped, m)
		}
	}
	if len(skipped) == 0 {
		return []finding{skipf(claim, method,
			"the DUT read the body of every model in the chain (base %d, %d model(s): %s), so no "+
				"step-over occurred to observe. This row needs a model the client does not consume",
			base, len(models), describeModels(models))}
	}
	m := skipped[0]
	v := certify.Pass
	tail := ""
	if !complete {
		v = certify.Warn
		tail = fmt.Sprintf(" The walk did not reach the end marker within this test case's frames (%s), "+
			"so 'continued to the end of the chain' is observed only as far as the frames go.", why)
	}
	out := []finding{framesf(claim, method, v, aduFrames(c.Responses...),
		"the DUT read the header of model %d at %d (length %d) but never requested any of its body "+
			"registers at %d..%d, and its next header read was at %d = %d + 2 + %d — the address the "+
			"length header dictates. %d of the chain's %d model(s) were stepped over this way: %s.%s",
		m.ID, m.HeaderAddr, m.Length, m.HeaderAddr+2, m.HeaderAddr+1+m.Length,
		m.HeaderAddr+2+m.Length, m.HeaderAddr, m.Length,
		len(skipped), len(models), describeModels(models), tail)}

	// The MUST of this row: the unknown model must not appear as discovered.
	out = append(out, skipf(
		"the DUT's list of discovered models does not include the unknown model ID",
		"inspection of the client's reported model inventory",
		"this is a criterion about the CUT's own output, and the DUT publishes no model inventory this "+
			"suite can read: its Modbus client journals the devices it admitted, not the model chain it "+
			"walked. The wire shows the model was not READ, which is necessary but not sufficient for "+
			"the MUST. Promoting it requires either an inventory diagnostic on the DUT or a model with "+
			"a genuinely unknown ID in the chain plus the DUT's admission log"))
	return out
}

func err3Skip() finding {
	return skipf(
		"a model whose ID is absent from the DUT's model definition directory was present in the server's chain",
		"splice a model with an unregistered ID into the server's SunSpec map, per §2.9.3 step 1",
		"the bench's plain-text SunSpec server serves a fixed model chain and has no verb for inserting "+
			"an arbitrary model header, so a genuinely unknown ID could not be presented. Promoting this "+
			"row to full requires a sim capability such as POST /inject {\"insert_model\":{\"id\":65000,"+
			"\"len\":4,\"after\":1}} that splices a header/length pair with an unregistered ID into the "+
			"chain, plus knowledge of the DUT's model definition directory so the chosen ID is certainly "+
			"unknown to it")
}
