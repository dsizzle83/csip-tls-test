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

// err2Codes is the full exception set §2.9.2 is about: the four the procedure
// names in step 2 (decimal 1,2,3,4) plus 0x0B, which its own §2.9.2 step 1
// examples reach through a Modbus gateway that cannot deliver to a unit.
//
// Every one of them is provoked SERVER-SIDE, on the client's own legitimate
// FC 0x03 reads, and the row says so. §2.9.2 step 1's examples ("requesting
// illegal function code 0x88", "writing a read-only register") describe an
// operator console making a bad request; the DUT is an autonomous gateway that
// never makes one, and a bench that made it would be testing a client it had
// modified. The criterion is "the CUT appropriately interprets, logs, manages,
// and recovers from Modbus Exceptions" — a fact about how the client HANDLES a
// code, not about how the code was elicited — and the catalog's own note on
// this row records that the doc never maps its examples to codes anyway.
var err2Codes = []struct {
	Code uint8
	Why  string
}{
	{0x01, "ILLEGAL FUNCTION — the server declines the function code entirely"},
	{0x02, "ILLEGAL DATA ADDRESS — the register range is not one the server serves"},
	{0x03, "ILLEGAL DATA VALUE — the request's own parameters are refused"},
	{0x04, "SERVER DEVICE FAILURE — the right device, internally broken"},
	{0x0B, "GATEWAY TARGET DEVICE FAILED TO RESPOND — the addressing failure, which " +
		"is what a Modbus gateway answers for a unit it cannot reach"},
}

// exceptionPhase records one armed class and what the DUT met.
type exceptionPhase struct {
	Code uint8
	Why  string
	M    meeting
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
	d, derr := o.determinism(ctx)
	if derr != nil {
		return certify.Skipped("%s", deterministicSkip(derr)), nil
	}
	device := deviceName(rc)

	journalBefore, _ := o.journal(ctx, 200)
	if err := d.begin(ctx, nil); err != nil {
		return certify.Result{}, err
	}
	defer d.restore(ctx)

	// Every class in turn. Each is armed with an epoch, held until the sim's
	// OWN ledger shows the DUT met it, then cleared — no cycle count, no sleep,
	// and no dependence on the DUT's journal to decide when to stop looking.
	//
	// The LEDGER barrier rather than the poll barrier, deliberately: lexa-gw
	// drops its southbound session on a Modbus exception and reconnects on the
	// next poll (cmd/modbus/main.go:1303-1307), so under a persistent
	// exception it is met once per session and completes no poll cycle at all.
	// Waiting for a cycle here is waiting for something the provocation itself
	// prevents — which is exactly how the previous version of this row spent
	// its budget and then reported "observed: none".
	phases := make([]*exceptionPhase, 0, len(err2Codes))
	for _, c := range err2Codes {
		p := &exceptionPhase{Code: c.Code, Why: c.Why}
		m, err := d.meet(ctx,
			map[string]any{"kind": "exception_code", "code": int(c.Code), "on_fc": 3},
			fmt.Sprintf("answer every FC 0x03 read with exception 0x%02x %s (%s)",
				c.Code, ExceptionName(c.Code), c.Why),
			"exception_code", 1)
		if err != nil {
			return certify.Result{}, err
		}
		p.M = m
		phases = append(phases, p)
	}

	// Recovery: "the CUT continues to operate normally after each Modbus
	// Exception". With every class cleared, the DUT must transact again — and
	// its reconnect-with-backoff is allowed to take its own time, because the
	// barrier waits for the transaction rather than for a clock.
	recoveryFence, ferr := d.arm(ctx, map[string]any{"kind": "exception_code", "clear": true},
		"clear every exception class so the DUT's recovery can be observed")
	if ferr != nil {
		recoveryFence = 0
	}
	var recovery LedgerPage
	var recovered bool
	if recoveryFence > 0 {
		var err error
		recovery, recovered, err = d.awaitLedger(ctx, recoveryFence, 1)
		if err != nil {
			return certify.Result{}, err
		}
	}
	journalAfter, _ := o.journal(ctx, 600)
	newLines := journalSince(journalBefore, journalAfter)

	return certify.Result{
		Verdict: certify.Warn,
		Notes: fmt.Sprintf("all five exception classes §2.9.2 is about — 0x01, 0x02, 0x03, 0x04 and "+
			"0x0B — were provoked on the server in turn, each armed at a named epoch and held until the "+
			"SIMULATOR'S OWN transaction ledger showed the DUT had met it, then cleared. Recovery was "+
			"held the same way. No step of this row waits on a clock. %s", o.injectionNote()),
		Cite: func(_ context.Context, ev *certify.Evidence) ([]certify.Assertion, error) {
			claim := "the DUT received Modbus exception responses and continued to operate normally"
			c, pre, ok := citeConversation(ev, o, claim)
			fs := append([]finding(nil), pre...)
			if ok {
				fs = []finding{assertAttributionSound(ev, o)}
			}
			fs = append(fs, evalERR2(c, phases, d)...)
			fs = append(fs, evalERR2Recovery(c, recovery, recovered, recoveryFence, d))
			fs = append(fs, err2Journal(newLines, device))
			return emit(ev, c, fs), nil
		},
	}, nil
}

// evalERR2 grades each class from the sim's own ledger, and cites the matching
// exception response in the capture when this test case owns it.
//
// The two sources are deliberately not interchangeable. The LEDGER decides
// whether the class was delivered — it is the server's own record and cannot
// miss a transaction that happened. The CAPTURE is what a third party
// re-derives the claim from, so where a frame is available the assertion is
// byte-cited; where the DUT met the fault outside this test case's frames the
// assertion is a Narrative naming the ledger, at WARN, rather than a SKIP
// pretending nothing happened.
func evalERR2(c *Conversation, phases []*exceptionPhase, d *determinism) []finding {
	var out []finding
	var wireByCode map[uint8][]Exchange
	if c != nil {
		wireByCode = map[uint8][]Exchange{}
		for _, ex := range c.Exceptions() {
			if code, ok := ex.Response.ExceptionCode(); ok {
				wireByCode[code] = append(wireByCode[code], ex)
			}
		}
	}

	for _, p := range phases {
		claim := fmt.Sprintf("the DUT received exception code 0x%02x %s from the server",
			p.Code, ExceptionName(p.Code))
		method := "the exception code of the response the server returned to the DUT's own FC 0x03 read, " +
			"after that class was armed at a named control-plane epoch and held until the simulator's " +
			"transaction ledger recorded the DUT meeting it"

		if !p.M.ok() {
			out = append(out, skipf(claim, method, "%s", p.M.reason()))
			continue
		}
		hits := p.M.Page.Exceptions()[p.Code]
		if len(hits) == 0 {
			// The DUT transacted under the fence and got something other than
			// the armed class. That is a BENCH defect — the fault's contract
			// and the wire disagree — and it is reported as one rather than as
			// a DUT finding.
			out = append(out, narrativef(claim, method, d.ledgerSource(), certify.Warn,
				"the class was armed at epoch %d and the DUT issued %d transaction(s) under it, but none "+
					"was answered with 0x%02x. What the server actually returned: %s. That is a "+
					"disagreement between the sim's fault contract and its wire behaviour — a bench "+
					"defect, not a DUT finding",
				p.M.Epoch, p.M.Page.Total, p.Code, p.M.Page.Summary()))
			continue
		}
		if ex := wireByCode[p.Code]; len(ex) > 0 {
			r := ex[0].Response
			out = append(out, bytesf(claim, method, certify.Pass, fromServer, r.Start, r.End,
				"%d response(s) in this test case's frames carried function code 0x%02x (the request's "+
					"FC with the exception bit set) and exception code 0x%02x %s. The server was made to "+
					"produce them by %s, armed at epoch %d; the simulator's own ledger independently "+
					"records %d such transaction(s) — first: %s. Response cited in full: [%s]",
				len(ex), r.FC, p.Code, ExceptionName(p.Code), p.M.Spec, p.M.Epoch,
				len(hits), hits[0], r.Hex()))
			continue
		}
		// No frame for it in this test case. The claim still HOLDS — the
		// server's own record of what it delivered establishes it completely,
		// and the ledger is not the DUT's log — so this is a Narrative PASS
		// naming its source, exactly as ERR-3's inventory assertion is. What
		// it is not is third-party re-derivable from the capture, which the
		// Observed text says and the framework's own uncited-PASS handling
		// weighs.
		out = append(out, narrativef(claim, method, d.ledgerSource(), certify.Pass,
			"the server delivered %d exception 0x%02x %s to the DUT while the class was armed at epoch "+
				"%d — first: %s. No frame carrying one was attributed to this test case, so this rests "+
				"on the simulator's record rather than on a citation into the capture; the DUT's own "+
				"reconnect-with-backoff can place the exchange outside this window even when the "+
				"provocation lands perfectly",
			len(hits), p.Code, ExceptionName(p.Code), p.M.Epoch, hits[0]))
	}
	return out
}

// evalERR2Recovery is the row's actual SHALL: the client keeps working.
func evalERR2Recovery(c *Conversation, page LedgerPage, recovered bool, fence uint64,
	d *determinism) finding {

	claim := "the DUT continued to operate normally after each Modbus exception"
	method := "a complete, non-exception transaction with the server AFTER every exception class was " +
		"cleared, held on the simulator's transaction ledger rather than on a clock so the DUT's own " +
		"reconnect-with-backoff has as long as it needs"
	if fence == 0 {
		return skipf(claim, method, "the exception classes could not be cleared, so there is no recovery "+
			"interval to observe")
	}
	if !recovered {
		return narrativef(claim, method, d.ledgerSource(), certify.Fail,
			"with every exception class cleared at epoch %d, the DUT issued no transaction at all to "+
				"this server within the barrier's budget. The client was not seen to resume normal "+
				"operation after the fault was cleared", fence)
	}
	good := page.WithOutcome(outcomeAnswered)
	if len(good) == 0 {
		return narrativef(claim, method, d.ledgerSource(), certify.Fail,
			"with every exception class cleared at epoch %d the DUT did transact again, but not one of "+
				"its %d transaction(s) completed normally: %s", fence, page.Total, page.Summary())
	}
	// Prefer a byte citation into the capture; fall back to the ledger.
	if c != nil {
		if ex, ok := firstSuccessfulReadAfter(c, 0); ok {
			return bytesf(claim, method, certify.Pass, fromServer, ex.Response.Start, ex.Response.End,
				"after every exception class was cleared at epoch %d the DUT issued %s and the server "+
					"answered it normally — the client neither abandoned the connection nor stopped "+
					"polling. The simulator's own ledger independently records %d completed "+
					"transaction(s) after that epoch, first: %s. Recovery response cited: %s",
				fence, ex.Request.String(), len(good), good[0], ex.Response.String())
		}
	}
	return narrativef(claim, method, d.ledgerSource(), certify.Pass,
		"after every exception class was cleared at epoch %d the DUT issued %d transaction(s) that "+
			"completed normally — first: %s — so the client resumed normal operation. No frame carrying "+
			"one was attributed to this test case, so this rests on the simulator's record rather than "+
			"on a citation into the capture", fence, len(good), good[0])
}

// err2Journal reports whether the DUT logged the exceptions. It can only ever
// be a Narrative: a client-side log is not a wire fact.
func err2Journal(lines []string, device string) finding {
	claim := "the DUT logged each Modbus exception it received"
	method := "the DUT's own lexa-modbus journal, read over the read-only gateway client, restricted " +
		"to lines added after the first class was armed"
	source := "journalctl -u lexa-modbus on the device under test"
	if len(lines) == 0 {
		return skipf(claim, method,
			"no journal lines could be read from the DUT (gateway introspection unavailable, or no new "+
				"lines appeared), so the client-side logging criterion is unevidenced here")
	}
	var errs []string
	for _, l := range grepJournal(lines, device) {
		low := strings.ToLower(l)
		if strings.Contains(low, "verdict=match") {
			continue // the routine per-poll reconciler line
		}
		// lexa-gw's own documented pattern for a southbound session loss is
		// "device session dropped — will reconnect on next poll", which names
		// neither an error nor a failure; a filter that missed it would report
		// a silent client where there is a talkative one.
		if strings.Contains(low, "err") || strings.Contains(low, "fail") ||
			strings.Contains(low, "exception") || strings.Contains(low, "unavailable") ||
			strings.Contains(low, "down") || strings.Contains(low, "warn") ||
			strings.Contains(low, "drop") || strings.Contains(low, "reconnect") {
			errs = append(errs, l)
		}
	}
	if len(errs) == 0 {
		return narrativef(claim, method, source, certify.Warn,
			"%d journal line(s) were added while the server was returning exceptions, but none names an "+
				"error, an exception or an unavailable device for %q. As observed, the 'accurately log "+
				"all exception codes' criterion is not met", len(lines), device)
	}
	named := 0
	for _, l := range errs {
		low := strings.ToLower(l)
		for _, code := range err2Codes {
			if strings.Contains(low, strings.ToLower(ExceptionName(code.Code))) {
				named++
				break
			}
		}
	}
	shown := errs
	if len(shown) > 3 {
		shown = shown[:3]
	}
	if named == 0 {
		return narrativef(claim, method, source, certify.Warn,
			"%d journal line(s) added during the fault report the failure of %q, so the DUT does log "+
				"that something went wrong — but none of them NAMES an exception class. §2.9.2's "+
				"criterion is 'accurately log all exception codes', and a line that says a device is "+
				"unavailable does not say which code it received. First: %s. THE GAP IS DUT-SIDE: the "+
				"product maps Modbus exception codes to opaque transport errors and journals no per-code "+
				"event (see this row's report entry)",
			len(errs), device, strings.Join(shown, " | "))
	}
	return narrativef(claim, method, source, certify.Pass,
		"%d journal line(s) added during the fault report the failure of %q, %d of them naming an "+
			"exception class by name. First: %s", len(errs), device, named, strings.Join(shown, " | "))
}

// ── ERR-1 — Noncompliant Server ───────────────────────────────────────────────

// noncompliantBase is §2.9.1 step 1's deliberately noncompliant map base: one
// register off the legal 40000. The catalog's note on this row records the
// document's own ambiguity about whether "40001" means the data-model address
// or the 1-based holding-register convention in which 40001 IS address 0; the
// intent from CLI-4, which uses 0/40000/50000, is that it is off-by-one from a
// valid base, and that is what this serves.
const noncompliantBase = 40001

func checkERR1(ctx context.Context, rc *certify.RunCtx) (certify.Result, error) {
	o, why := newObserver(rc)
	if o == nil {
		return certify.Skipped("%s", why), nil
	}
	if err := o.claimServer(); err != nil {
		return certify.Result{}, err
	}
	if r := o.injectionReason(); r != "" {
		return certify.Skipped("this procedure requires the server's SunSpec map to be moved off a legal "+
			"base, and %s", r), nil
	}
	d, derr := o.determinism(ctx)
	if derr != nil {
		return certify.Skipped("%s", deterministicSkip(derr)), nil
	}
	device := deviceName(rc)

	journalBefore, _ := o.journal(ctx, 200)
	if err := d.begin(ctx, nil); err != nil {
		return certify.Result{}, err
	}
	defer d.restore(ctx)

	// §2.9.1 step 1: the map starts one register off a legal base. modsim's
	// relocate verb moves the register CONTENT, so the same listener, the same
	// tcp_drop bounce and the same everything keep behaving as they do —
	// only WHERE the model chain starts changes.
	badEpoch, armErr := d.relocate(ctx, noncompliantBase,
		fmt.Sprintf("re-home the server's SunSpec map to holding register %d — one register off the "+
			"legal 40000, which is §2.9.1's noncompliant server", noncompliantBase))

	// §2.9.1 step 2: "attempt to connect the CUT to Server 1". The DUT has
	// been connected for hours, and a client that is already connected never
	// repeats its base probe (lexa-proto/sunspec/reader.go caches the block
	// layout per SESSION), so the connection is severed to make it try.
	var reconnErr error
	var page LedgerPage
	var met bool
	if armErr == nil {
		if _, reconnErr = d.reconnect(ctx,
			"sever the DUT's southbound connection so its reconnect performs the base probe against "+
				"the noncompliant map, inside this test case's window"); reconnErr == nil {
			// Three transactions: the DUT probes all three standard bases
			// (40000, then 0, then 50000 — sunspec/scanner.go's probeBases)
			// before concluding there is no SunSpec map here.
			var err error
			page, met, err = d.awaitLedger(ctx, badEpoch, 3)
			if err != nil {
				return certify.Result{}, err
			}
		}
	}

	// Recovery: put the map back and watch the DUT find it again. "The CUT
	// recovers (does not hang or crash)" is exactly this — it kept probing and
	// succeeded the moment the server became compliant.
	restoreEpoch, restoreErr := d.relocate(ctx, 40000,
		"put the server's SunSpec map back at the legal base 40000 so the DUT's recovery can be observed")
	var recovery LedgerPage
	var recovered bool
	if restoreErr == nil {
		var err error
		recovery, recovered, err = d.awaitLedger(ctx, restoreEpoch, 1)
		if err != nil {
			return certify.Result{}, err
		}
	}

	journalAfter, _ := o.journal(ctx, 600)
	newLines := journalSince(journalBefore, journalAfter)

	return certify.Result{
		Verdict: certify.Warn,
		Notes: fmt.Sprintf("the server's SunSpec map was moved to holding register %d — the "+
			"deliberately noncompliant off-by-one base §2.9.1 calls for — and the DUT's reconnect was "+
			"observed against it, then against the restored legal map. This row previously reported "+
			"'the server cannot be made noncompliant on this bench'; modsim's relocate verb closes "+
			"that, and no step of it waits on a clock. %s", noncompliantBase, o.injectionNote()),
		Cite: func(_ context.Context, ev *certify.Evidence) ([]certify.Assertion, error) {
			claim := "the DUT connected to a server whose SunSpec map begins one register off a legal base"
			c, pre, ok := citeConversation(ev, o, claim)
			fs := append([]finding(nil), pre...)
			if ok {
				fs = []finding{assertAttributionSound(ev, o)}
			}
			fs = append(fs, evalERR1Probes(c, page, met, badEpoch, armErr, reconnErr, d))
			fs = append(fs, err1Journal(newLines, device))
			fs = append(fs, evalERR1Recovery(recovery, recovered, restoreEpoch, restoreErr, d))
			return emit(ev, c, fs), nil
		},
	}, nil
}

// evalERR1Probes is the row's first half: presented with a map at 40001, the
// DUT probed the legal bases, found no identifier, and did NOT go looking at
// the noncompliant offset.
func evalERR1Probes(c *Conversation, page LedgerPage, met bool, epoch uint64,
	armErr, reconnErr error, d *determinism) finding {

	claim := "the DUT probed only legal SunSpec base addresses against a server whose map begins at " +
		"holding register 40001, and found no identifier at any of them"
	method := fmt.Sprintf("the start address of every read the DUT issued after the server's map was "+
		"re-homed to %d, from the simulator's own transaction ledger, cross-checked against the "+
		"identifier registers the responses actually carried", noncompliantBase)
	switch {
	case armErr != nil:
		return skipf(claim, method, "the server's map could not be re-homed to %d: %v",
			noncompliantBase, armErr)
	case reconnErr != nil:
		return skipf(claim, method, "the server's map was re-homed to %d at epoch %d, but the DUT's "+
			"connection could not be severed (%v), and a client already connected does not repeat its "+
			"base probe — lexa-proto/sunspec/reader.go caches the block layout for the life of the "+
			"session", noncompliantBase, epoch, reconnErr)
	case !met:
		return skipf(claim, method, "the server's map was re-homed to %d at epoch %d and the DUT's "+
			"connection was severed, but the DUT issued only %d transaction(s) to this server "+
			"afterwards — fewer than the three base probes a rediscovery makes",
			noncompliantBase, epoch, page.Total)
	}

	reads := page.Reads()
	var illegal []uint16
	probed := map[uint16]bool{}
	foundIdentifier := false
	for _, e := range reads {
		if !IsStandardBase(e.Addr) {
			// A read that is not at a standard base is only interesting if it
			// is a PROBE — a chain walk after a successful discovery reads all
			// sorts of addresses. Against a noncompliant map there is no
			// successful discovery, so any read here is a probe.
			illegal = append(illegal, e.Addr)
			continue
		}
		probed[e.Addr] = true
		if vals, ok := e.Values(); ok && len(vals) >= 2 && vals[0] == SunSHigh && vals[1] == SunSLow {
			foundIdentifier = true
		}
	}
	var bases []uint16
	for b := range probed {
		bases = append(bases, b)
	}
	sortUint16(bases)

	switch {
	case len(illegal) > 0:
		return narrativef(claim, method, d.ledgerSource(), certify.Fail,
			"with the map at %d, the DUT read at %v — address(es) outside the legal SunSpec base set %v. "+
				"A client that hunts for a map at a noncompliant offset would find one there, which is "+
				"precisely the behaviour §2.9.1 exists to rule out", noncompliantBase, illegal, StandardBases)
	case foundIdentifier:
		return narrativef(claim, method, d.ledgerSource(), certify.Fail,
			"with the map at %d, one of the DUT's probes at a legal base nonetheless returned the "+
				"SunSpec identifier — the sim did not actually serve a noncompliant map, so this row's "+
				"provocation did not hold. That is a bench defect, not a DUT finding", noncompliantBase)
	case len(bases) == 0:
		return skipf(claim, method, "the DUT issued %d transaction(s) after the relocation but none at a "+
			"standard base address, so no base probe was observed: %s", page.Total, page.Summary())
	default:
		v := certify.Pass
		tail := ""
		if len(bases) < len(StandardBases) {
			v = certify.Warn
			tail = fmt.Sprintf(" It probed %d of the %d standard bases within this window; a client that "+
				"stops at the first failure is conformant, so this is reported rather than failed.",
				len(bases), len(StandardBases))
		}
		return narrativef(claim, method, d.ledgerSource(), v,
			"with the server's map at holding register %d, the DUT issued %d read(s), at standard base "+
				"address(es) %v and nowhere else. None returned the SunSpec identifier 0x%04x 0x%04x, so "+
				"discovery correctly failed rather than finding a map at the noncompliant offset.%s "+
				"First transaction: %s",
			noncompliantBase, len(reads), bases, SunSHigh, SunSLow, tail, reads[0])
	}
}

// err1Journal is §2.9.1's first criterion, "the Client SHALL accurately log the
// noncompliant server". It is about the client's OWN output and can only ever
// be a Narrative.
func err1Journal(lines []string, device string) finding {
	claim := "the DUT logged the noncompliant server"
	method := "the DUT's own lexa-modbus journal, read over the read-only gateway client, restricted to " +
		"lines added after the server's map was moved off a legal base"
	source := "journalctl -u lexa-modbus on the device under test"
	if len(lines) == 0 {
		return skipf(claim, method, "no journal lines could be read from the DUT (gateway introspection "+
			"unavailable, or no new lines appeared), so the client-side logging criterion is unevidenced "+
			"here")
	}
	var hits []string
	for _, l := range grepJournal(lines, device) {
		low := strings.ToLower(l)
		if strings.Contains(low, "sunspec") || strings.Contains(low, "identif") ||
			strings.Contains(low, "discover") || strings.Contains(low, "scan") ||
			strings.Contains(low, "no such device") || strings.Contains(low, "err") ||
			strings.Contains(low, "fail") {
			hits = append(hits, l)
		}
	}
	if len(hits) == 0 {
		return narrativef(claim, method, source, certify.Warn,
			"%d journal line(s) were added for %q while the server served a map at holding register %d, "+
				"and none of them reports a discovery or identification failure. As observed, the "+
				"'accurately log the noncompliant server' criterion is not met",
			len(lines), device, noncompliantBase)
	}
	shown := hits
	if len(shown) > 3 {
		shown = shown[:3]
	}
	return narrativef(claim, method, source, certify.Pass,
		"%d journal line(s) added while the server's map sat at holding register %d report the failure "+
			"to identify %q. First: %s", len(hits), noncompliantBase, device, strings.Join(shown, " | "))
}

// evalERR1Recovery is §2.9.1's second criterion: the CUT recovers.
func evalERR1Recovery(page LedgerPage, recovered bool, epoch uint64, err error, d *determinism) finding {
	claim := "the DUT recovered — did not hang or crash — after being connected to the noncompliant server"
	method := "a transaction with the server AFTER its map was restored to the legal base 40000, held on " +
		"the simulator's transaction ledger rather than on a clock"
	if err != nil {
		return skipf(claim, method, "the server's map could not be restored to base 40000 (%v), so there "+
			"is no recovery interval to observe", err)
	}
	if !recovered {
		return narrativef(claim, method, d.ledgerSource(), certify.Fail,
			"with the server's map restored to the legal base 40000 at epoch %d, the DUT issued no "+
				"transaction at all to this server within the barrier's budget — it did not resume "+
				"polling after meeting a noncompliant server", epoch)
	}
	good := page.WithOutcome(outcomeAnswered)
	if len(good) == 0 {
		return narrativef(claim, method, d.ledgerSource(), certify.Warn,
			"with the map restored at epoch %d the DUT did transact again — %s — but no transaction "+
				"completed normally within the window", epoch, page.Summary())
	}
	return narrativef(claim, method, d.ledgerSource(), certify.Pass,
		"with the server's map restored to the legal base 40000 at epoch %d, the DUT issued %d "+
			"transaction(s) that completed normally — it kept probing through the noncompliant interval "+
			"and resumed discovery the moment the server became compliant. First: %s",
		epoch, len(good), good[0])
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

	d, derr := o.determinism(ctx)
	if derr != nil {
		return certify.Skipped("%s", deterministicSkip(derr)), nil
	}
	if err := d.begin(ctx, nil); err != nil {
		return certify.Result{}, err
	}
	defer d.restore(ctx)

	journalBefore, journalBeforeErr := o.admissionJournal(ctx)

	// §2.9.3 step 1: splice a model with an ID unknown to any client into the
	// chain, BEFORE forcing the reconnect whose discovery walk this row
	// evidences.
	var spliceErr error
	if _, err := d.inject(ctx, map[string]any{
		"insert_model": map[string]any{"id": unregisteredModelID, "len": unregisteredModelLen},
	}, fmt.Sprintf("splice a model with an unregistered ID (%d) into the server's chain immediately "+
		"before the end marker, per §2.9.3 step 1", unregisteredModelID)); err != nil {
		spliceErr = err
	}
	spliced := spliceErr == nil

	disc, err := rediscover(ctx, d, "ERR-3")
	if err != nil {
		return certify.Result{}, err
	}
	journalAfter, journalAfterErr := o.admissionJournal(ctx)

	return certify.Result{
		Verdict: certify.Warn,
		Notes: fmt.Sprintf("a model with an ID unknown to any client (%d) was spliced into the server's "+
			"chain immediately before the end marker (spliced=%v), and the DUT's rediscovery over it "+
			"was held on the simulator's transaction ledger rather than on a poll interval%s. %s",
			unregisteredModelID, spliced, disc.note(), o.injectionNote()),
		Cite: func(_ context.Context, ev *certify.Evidence) ([]certify.Assertion, error) {
			claim := "the DUT connected without issue to a server carrying a model with an unknown ID"
			c, pre, ok := citeConversation(ev, o, claim)
			fs := append([]finding(nil), pre...)
			if ok {
				fs = []finding{assertAttributionSound(ev, o)}
				fs = append(fs, evalERR3StepOver(c, disc.Err))
			}
			fs = append(fs, evalRediscovery(disc, d))
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
