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
	"encoding/json"
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
	// OnFC scopes this phase to modsim's TARGETED exception_code fault
	// (sim/southbound/exception_target.go, landed 9e35da6: POST /fault
	// {"kind":"exception_code","code":N,"on_fc":F}) rather than the classic
	// blanket one. Zero means untargeted — the two ORIGINAL phases below,
	// which use their own dedicated fault kinds and must stay byte-for-byte
	// unchanged.
	OnFC  int
	Why   string
	Armed bool
	Err   error
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
		// ERR-2#6/#7/#8 (census compliance-fullsuite-2-20260802T020946): the
		// three classes err2UnprovokedCodes used to SKIP because the DUT
		// never emits an unimplemented function code, addresses an
		// unimplemented point, or writes an out-of-range value of its own
		// choosing. modsim's TARGETED exception_code fault (on_fc) sidesteps
		// that entirely: it scopes the exception to FC 0x03 — the function
		// code the DUT DOES use for every read — so the fault fires on
		// traffic the DUT already emits, rather than needing the DUT to
		// misbehave into triggering it.
		{Kind: "exception_code", WantCode: 0x01, OnFC: FCReadHoldingRegisters,
			Why: "target every FC 0x03 read with exception code 0x01 ILLEGAL FUNCTION (modsim's " +
				"exception_target scoping), since the DUT never emits an unimplemented function code of " +
				"its own choosing"},
		{Kind: "exception_code", WantCode: 0x02, OnFC: FCReadHoldingRegisters,
			Why: "target every FC 0x03 read with exception code 0x02 ILLEGAL DATA ADDRESS, since the DUT " +
				"addresses only registers it discovered and will not request an unimplemented point on demand"},
		{Kind: "exception_code", WantCode: 0x03, OnFC: FCReadHoldingRegisters,
			Why: "target every FC 0x03 read with exception code 0x03 ILLEGAL DATA VALUE, since a value " +
				"the server rejects is normally provoked by a write the DUT's own reconciler decides to make"},
	}
	for _, p := range phases {
		spec := map[string]any{"kind": p.Kind}
		if p.OnFC != 0 {
			spec["code"] = int(p.WantCode)
			spec["on_fc"] = p.OnFC
		}
		if err := o.fault(ctx, spec, p.Why); err != nil {
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
		Notes: fmt.Sprintf("all four exception classes the procedure names were provoked for real and "+
			"observed on the wire: two through the server's blanket read-failure faults, and — since "+
			"modsim's exception_target scoping landed — the remaining two (0x01 ILLEGAL FUNCTION, 0x02 "+
			"ILLEGAL DATA ADDRESS) plus 0x03 ILLEGAL DATA VALUE by targeting the exception at FC 0x03, the "+
			"function code the DUT already uses for every read, rather than needing the DUT to misbehave "+
			"into producing them. %s", o.injectionNote()),
		Cite: func(_ context.Context, ev *certify.Evidence) ([]certify.Assertion, error) {
			claim := "the DUT received Modbus exception responses and continued to operate normally"
			c, pre, ok := citeConversation(ev, o, claim)
			if !ok {
				return emit(ev, c, pre), nil
			}
			fs := []finding{assertAttributionSound(ev, o)}
			fs = append(fs, evalERR2(c, phases, o.injectionNote())...)
			fs = append(fs, err2Journal(newLines))
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

// unregisteredModelID/unregisteredModelLen are the header this check splices
// into the server's chain via modsim's insert_model verb
// (sim/southbound/modelsplice.go, landed 9e35da6): an ID far outside any
// SunSpec-registered range, so it is certainly absent from any client's own
// model definition directory — the same ID this row's SKIP text has quoted
// as the illustrative example since before the verb existed.
const (
	unregisteredModelID  uint16 = 65000
	unregisteredModelLen uint16 = 4
)

// admissionJournalPath is lexa-modbus's durable admission journal — see
// lexa-gw's internal/southbound/admission (journalAdmitted) and
// configs/modbus.json's "journal" block ({"dir":"/var/lib/lexa/journal/modbus"},
// vendored lexa-platform/journal's DefaultName "journal.ndjson"). Read
// read-only, the same pattern err2Journal/info2Interpretation use for the
// systemd journal.
const admissionJournalPath = "/var/lib/lexa/journal/modbus/journal.ndjson"

func checkERR3(ctx context.Context, rc *certify.RunCtx) (certify.Result, error) {
	o, why := newObserver(rc)
	if o == nil {
		return certify.Skipped("%s", why), nil
	}
	if err := o.claimServer(); err != nil {
		return certify.Result{}, err
	}
	device := defaultDeviceName
	if v, ok := rc.Param(paramDevice); ok && v != "" {
		device = v
	}

	journalBefore, journalBeforeErr := o.admissionJournal(ctx)

	// ERR-3#4 (census compliance-fullsuite-2-20260802T020946): splice a
	// model with an ID unknown to any client into the chain, per §2.9.3
	// step 1, before forcing the reconnect whose discovery walk this row
	// evidences.
	var spliceErr error
	if r := o.injectionReason(); r != "" {
		spliceErr = fmt.Errorf("%s", r)
	} else {
		spliceErr = o.injectValue(ctx, map[string]any{
			"insert_model": map[string]any{"id": unregisteredModelID, "len": unregisteredModelLen},
		}, fmt.Sprintf("splice a model with an unregistered ID (%d) into the server's chain immediately "+
			"before the end marker, per §2.9.3 step 1", unregisteredModelID))
	}
	spliced := spliceErr == nil
	if spliced {
		defer o.clearInject(map[string]any{"clear_insert_model": true}, "the spliced model")
	}

	forced := o.forceReconnect(ctx)
	if err := o.watch(ctx, 2); err != nil {
		return certify.Result{}, err
	}
	journalAfter, journalAfterErr := o.admissionJournal(ctx)

	return certify.Result{
		Verdict: certify.Warn,
		Notes: fmt.Sprintf("a model with an ID unknown to any client (%d) was spliced into the server's "+
			"chain immediately before the end marker (spliced=%v), and the DUT's discovery walk over it "+
			"was observed. %s", unregisteredModelID, spliced, o.injectionNote()),
		Cite: func(_ context.Context, ev *certify.Evidence) ([]certify.Assertion, error) {
			claim := "the DUT connected without issue to a server carrying a model with an unknown ID"
			c, pre, ok := citeConversation(ev, o, claim)
			if !ok {
				return emit(ev, c, append(pre,
					evalERR3InsertedModel(nil, spliced, spliceErr),
					err3Inventory(nil, nil, journalBeforeErr, journalAfterErr, device))), nil
			}
			fs := []finding{assertAttributionSound(ev, o)}
			fs = append(fs, evalERR3StepOver(c, forced))
			fs = append(fs, err3Inventory(journalBefore, journalAfter, journalBeforeErr, journalAfterErr, device))
			fs = append(fs, evalERR3InsertedModel(c, spliced, spliceErr))
			return emit(ev, c, fs), nil
		},
	}, nil
}

// evalERR3StepOver is ERR-3 row 2: the DUT stepped over a model it did not
// consume by using its length header, and continued the chain walk. This is
// the general behaviour every model the DUT does not consume already
// demonstrates (712, say) — evalERR3InsertedModel, below, is the SPECIFIC
// claim about the model THIS test case spliced.
func evalERR3StepOver(c *Conversation, forced error) finding {
	claim := "the DUT stepped over a model it did not consume by using its length header, and continued " +
		"the chain walk to the end marker"
	method := "model chain reconstruction: a model whose ID and length registers the DUT read but whose " +
		"body it never requested, followed by a header read at exactly HeaderAddr + 2 + Length"

	base, models, complete, why := c.ModelChain()
	if len(models) == 0 {
		return skipf(claim, method,
			"no model chain was reconstructed from this test case's frames: %s (forced reconnect: %v)",
			why, forced)
	}
	var skipped []Model
	for _, m := range models {
		if !m.BodyRead && m.Length > 0 {
			skipped = append(skipped, m)
		}
	}
	if len(skipped) == 0 {
		return skipf(claim, method,
			"the DUT read the body of every model in the chain (base %d, %d model(s): %s), so no "+
				"step-over occurred to observe. This row needs a model the client does not consume",
			base, len(models), describeModels(models))
	}
	m := skipped[0]
	v := certify.Pass
	tail := ""
	if !complete {
		v = certify.Warn
		tail = fmt.Sprintf(" The walk did not reach the end marker within this test case's frames (%s), "+
			"so 'continued to the end of the chain' is observed only as far as the frames go.", why)
	}
	return framesf(claim, method, v, aduFrames(c.Responses...),
		"the DUT read the header of model %d at %d (length %d) but never requested any of its body "+
			"registers at %d..%d, and its next header read was at %d = %d + 2 + %d — the address the "+
			"length header dictates. %d of the chain's %d model(s) were stepped over this way: %s.%s",
		m.ID, m.HeaderAddr, m.Length, m.HeaderAddr+2, m.HeaderAddr+1+m.Length,
		m.HeaderAddr+2+m.Length, m.HeaderAddr, m.Length,
		len(skipped), len(models), describeModels(models), tail)
}

// evalERR3InsertedModel is ERR-3 row 4: a model whose ID is absent from the
// DUT's model definition directory was present in the server's chain, and
// the DUT stepped over it — read its header, never its body — using the
// length header alone, per §2.9.3 step 1. Unlike evalERR3StepOver (any
// unconsumed model), this asserts the fact specific to the model THIS test
// case spliced: that it was genuinely present, at a genuinely unregistered
// ID, and the DUT did not choke or mis-walk on it.
func evalERR3InsertedModel(c *Conversation, spliced bool, spliceErr error) finding {
	claim := "a model whose ID is absent from the DUT's model definition directory was present in the " +
		"server's chain, and the DUT stepped over it using its length header"
	method := "splice a model with an unregistered ID into the server's SunSpec map (modsim's insert_model " +
		"verb, sim/southbound/modelsplice.go), per §2.9.3 step 1, then reconstruct the model chain from " +
		"the register image the DUT was observed to read"
	if !spliced {
		return skipf(claim, method, "the model could not be spliced into the server's chain: %v", spliceErr)
	}
	if c == nil {
		return skipf(claim, method,
			"the model was spliced (ID %d), but no capture frame was attributed to this test case, so "+
				"the DUT's reaction to it cannot be observed", unregisteredModelID)
	}
	_, models, _, why := c.ModelChain()
	m, ok := findModel(models, unregisteredModelID)
	if !ok {
		return skipf(claim, method,
			"the spliced model (ID %d) was inserted on the server, but this test case's frames do not "+
				"show the DUT reading its header (%s). It may have been spliced too late for this "+
				"reconnect's walk to reach it within this window", unregisteredModelID, why)
	}
	if m.BodyRead {
		return framesf(claim, method, certify.Fail, aduFrames(c.Responses...),
			"the DUT read into the spliced, unregistered model %d's body (header at %d, length %d) — a "+
				"client cannot legitimately consume a model outside its own definition directory",
			m.ID, m.HeaderAddr, m.Length)
	}
	return framesf(claim, method, certify.Pass, aduFrames(c.Responses...),
		"the server's chain carried a genuinely unregistered model (ID %d, header at %d, length %d, "+
			"spliced by this test case immediately before the end marker), and the DUT read only its "+
			"header — stepping over the body by length exactly as it does for a registered model it "+
			"simply does not consume",
		m.ID, m.HeaderAddr, m.Length)
}

// admittedEvent is the shape of one journal.ndjson line this check cares
// about — see lexa-gw's vendored lexa-platform/journal (Event: v/ts/seq/
// type/svc/data) and internal/southbound/admission's admittedPayload
// (Data: device/endpoint/role/nb_unit/manufacturer/model/serial/models/
// actor). Decoded independently, by field name only, rather than by
// importing the gateway's own packages: this suite reads the DUT's output,
// it does not link against it.
type admittedEvent struct {
	Type string `json:"type"`
	Data struct {
		Device string   `json:"device"`
		Models []uint16 `json:"models"`
	} `json:"data"`
}

// parseAdmittedModels scans ndjson lines for the MOST RECENT
// "admission_admitted" event naming device, and returns its models field —
// lexa-modbus's own account of every SunSpec model header it scanned into
// that device's inventory (every block sunspec.Scan walked, known or not —
// see vendor/lexa-proto/sunspec/scanner.go's scanModels).
func parseAdmittedModels(lines []string, device string) (models []uint16, found bool) {
	for _, l := range lines {
		l = strings.TrimSpace(l)
		if l == "" {
			continue
		}
		var ev admittedEvent
		if json.Unmarshal([]byte(l), &ev) != nil {
			continue
		}
		if ev.Type != "admission_admitted" || ev.Data.Device != device {
			continue
		}
		models, found = ev.Data.Models, true
	}
	return models, found
}

func containsModel(models []uint16, id uint16) bool {
	for _, m := range models {
		if m == id {
			return true
		}
	}
	return false
}

// err3Inventory is ERR-3 row 3: the DUT's own reported model inventory must
// not include the unregistered model's ID. It is a criterion about the
// DUT's OWN OUTPUT, not the wire, so it is read from lexa-modbus's
// admission journal over the read-only gateway client — the same pattern
// err2Journal/info2Interpretation use for a client-side-log criterion.
//
// lexa-modbus admits a device, and journals its model inventory, ONCE — at
// first identification; a tcp_drop reconnect resumes polling from the
// already-known block list without re-scanning or re-journaling (see
// cmd/modbus's retryDevice — reconnect is wired to the reconciler's
// reassert-on-reconnect path, not to admission's identify step). So a model
// spliced in AFTER boot is only reflected here if this device's very first
// admission happened to see it, which this test case cannot arrange. That
// is reported honestly as a SKIP naming the mechanism, not silently passed
// off a stale record — but IF a fresh admission event ever does appear
// (an operator-triggered re-identify, a device the bench reboots between
// runs), this now asserts the real criterion from real DUT output instead
// of being unconditionally unavailable.
func err3Inventory(before, after []string, beforeErr, afterErr error, device string) finding {
	claim := "the DUT's list of discovered models does not include the unknown model ID"
	method := fmt.Sprintf("the DUT's own admission journal (%s), read over the read-only gateway client, "+
		"for a fresh admission event naming the device that appeared after the unregistered model was "+
		"spliced", admissionJournalPath)
	source := fmt.Sprintf("cat %s on the device under test", admissionJournalPath)
	if beforeErr != nil || afterErr != nil {
		err := beforeErr
		if err == nil {
			err = afterErr
		}
		return skipf(claim, method, "the DUT's admission journal could not be read: %v", err)
	}
	fresh := journalSince(before, after)
	models, found := parseAdmittedModels(fresh, device)
	if !found {
		return skipf(claim, method,
			"no admission event for device %q was journaled during this test case's window. lexa-modbus "+
				"admits a device — and journals its model inventory — once, at first identification; a "+
				"reconnect resumes polling from the already-known block list without re-scanning or "+
				"re-journaling, so a model spliced in AFTER boot is never recorded here even when the wire "+
				"shows the DUT stepped over it (see the preceding assertion). Promoting this row to full "+
				"needs either a DUT re-identify diagnostic this suite can trigger, or the splice to be in "+
				"place before the device's very first admission", device)
	}
	if containsModel(models, unregisteredModelID) {
		return narrativef(claim, method, source, certify.Fail,
			"the freshly-journaled admission event for device %q reports its discovered models as %v, "+
				"which includes the unregistered ID %d this test case spliced into the chain",
			device, models, unregisteredModelID)
	}
	return narrativef(claim, method, source, certify.Pass,
		"the freshly-journaled admission event for device %q reports its discovered models as %v — the "+
			"unregistered ID %d this test case spliced into the chain is absent",
		device, models, unregisteredModelID)
}
