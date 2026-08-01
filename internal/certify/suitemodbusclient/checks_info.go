package suitemodbusclient

// checks_info.go implements §2.7, the Information Tests: INFO-1 and INFO-2.
//
// Both rows are, on their face, about the CLIENT'S OWN LOG — how it renders an
// ipv6addr, whether it prints an enum as a number, whether it marks a point
// carrying its type's not-implemented sentinel as unimplemented. None of that
// is a wire fact, and a suite that asserted it from a pcap would be asserting
// something it cannot see.
//
// What the wire CAN carry, and what these checks assert, is the half of each
// criterion that is falsifiable here:
//
//   - INFO-1: the DUT read every model's registers, INCLUDING the scale-factor
//     registers, and the value it subsequently reported is the value those raw
//     registers decode to under the SunSpec scale-factor convention. That last
//     part is a real test of "convert all points using the appropriate scale
//     factors" — and to make it exact rather than approximate, the check
//     freezes the server's animation first, so the register the DUT read and
//     the value it reported are the same instant.
//   - INFO-2: the server is made to return the not-implemented sentinel, and
//     the DUT is then observed either reporting −32768 as a measurement (a
//     failure of the criterion) or not reporting it at all (the criterion met).

import (
	"context"
	"fmt"
	"math"
	"regexp"
	"strconv"
	"strings"
	"time"

	"csip-tls-test/internal/certify"
)

// paramDevice names the DUT's device entry for the plain-text server, so the
// journal correlation can pick the right readback line on a gateway with more
// than one southbound device.
const paramDevice = "modbus-client.device"

const defaultDeviceName = "inv-plain"

// readbackRE extracts the watt value the DUT reports for a device from its
// journal. It is deliberately narrow: a loose pattern that matched some other
// number would make a scale-factor assertion that proves nothing.
var readbackRE = regexp.MustCompile(`readback=W=(-?\d+)`)

// ── INFO-1 — SunSpec Type Interpretations ─────────────────────────────────────

func checkINFO1(ctx context.Context, rc *certify.RunCtx) (certify.Result, error) {
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

	// Freeze the server's world so the registers the DUT reads and the value it
	// reports are the same instant. Without this the sim's animation moves
	// between the poll and the log line, and a scale-factor comparison would be
	// comparing two different measurements — which is exactly the kind of
	// almost-right evidence this tool exists not to produce.
	//
	// INFO-1#3 (census 20260731T234821): freezing is not enough by itself.
	// resumeAt is stamped the instant resume is ISSUED, because the DUT polls
	// on its own independent ~10-second schedule — it does not know or care
	// when this check's deferred resume call happens to fire. A poll already
	// in flight at that moment can have some of its responses timestamped
	// before resumeAt and some after, and BOTH land inside this check's own
	// attributed frames: there is no window boundary between them, because it
	// is the same live phase straddling the instant resume actually happened.
	// The citation phase (frozenRegisters, below) uses resumeAt to answer
	// "what did the DUT see while frozen" rather than "what did it see last" —
	// see registersAsOf's doc in modbuswire.go for why ordinary last-write-wins
	// accumulation is the wrong tool for that question even though it is
	// exactly right for every other check in this suite.
	frozen := false
	var resumeAt time.Time
	if o.injectionReason() == "" {
		if err := o.sim.Control(ctx, map[string]any{"cmd": "pause"}, nil); err != nil {
			rc.Logf("could not pause the sim animation: %v", err)
		} else {
			frozen = true
			o.injected = append(o.injected, fmt.Sprintf("POST %s/control {\"cmd\":\"pause\"} (freeze the "+
				"server's animated registers so the value the DUT reads and the value it reports are "+
				"the same instant)", o.sim.BaseURL))
			defer func() {
				cctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
				defer cancel()
				resumeAt = time.Now().UTC()
				if err := o.sim.Control(cctx, map[string]any{"cmd": "resume"}, nil); err != nil {
					rc.Logf("WARNING: could not resume the sim animation: %v", err)
					o.injected = append(o.injected, fmt.Sprintf("FAILED to resume the sim animation: %v", err))
					return
				}
				o.injected = append(o.injected, fmt.Sprintf("POST %s/control {\"cmd\":\"resume\"}", o.sim.BaseURL))
			}()
		}
	}

	journalBefore, _ := o.journal(ctx, 200)
	forced := o.forceReconnect(ctx)
	if err := o.watch(ctx, 2); err != nil {
		return certify.Result{}, err
	}
	journalAfter, _ := o.journal(ctx, 400)
	reported, haveReported := lastReadback(journalSince(journalBefore, journalAfter), device)

	return certify.Result{
		Verdict: certify.Warn,
		Notes: fmt.Sprintf("the DUT's read coverage and its scale-factor interpretation were asserted; "+
			"the per-datatype rendering criteria (a)–(i) are about the client's own log and are not wire "+
			"facts. %s", o.injectionNote()),
		Cite: func(_ context.Context, ev *certify.Evidence) ([]certify.Assertion, error) {
			claim := "the DUT read every model in the server's chain, scale-factor registers included"
			c, pre, ok := citeConversation(ev, o, claim)
			if !ok {
				return emit(ev, c, append(pre, info1RenderingSkips()...)), nil
			}
			fs := []finding{assertAttributionSound(ev, o)}
			fs = append(fs, evalModelCoverage(c, forced))
			fs = append(fs, evalScaleFactor(frozenRegisters(c, frozen, resumeAt, ev), device, reported, haveReported, frozen))
			fs = append(fs, info1RenderingSkips()...)
			return emit(ev, c, fs), nil
		},
	}, nil
}

// evalModelCoverage asserts that the DUT's reads covered the models in the
// chain — the wire-observable precondition for logging their points.
func evalModelCoverage(c *Conversation, forced error) finding {
	claim := "the DUT read the register blocks of the server's models, scale-factor registers included"
	method := "coverage of each model body by the DUT's FC 0x03 requests, from the reconstructed chain"
	base, models, _, why := c.ModelChain()
	if len(models) == 0 {
		return skipf(claim, method, "no model chain was reconstructed: %s (forced reconnect: %v)", why, forced)
	}
	read, covered := 0, 0
	for _, m := range models {
		if m.BodyRead {
			read++
		}
		if m.BodyCovered {
			covered++
		}
	}
	v := certify.Pass
	if read == 0 {
		v = certify.Skip
	}
	return framesf(claim, method, v, aduFrames(c.Responses...),
		"base %d, %d model(s) in the chain; the DUT read into %d of them and fully covered %d. Because a "+
			"model body is read as a contiguous block, every scale-factor register inside a covered "+
			"body was read with its value. Chain: %s",
		base, len(models), read, covered, describeModels(models))
}

// frozenRegisters returns the register image evalScaleFactor should compare
// the DUT's reported value against.
//
// When the run never froze the server (frozen is false — the sim was already
// under fault injection from an earlier case, see checkINFO1), or resume was
// never issued, there is no freeze boundary to respect, so the ordinary,
// fully-accumulated view every other check in this suite relies on is exactly
// right. When it DID freeze, the raw registers must be read as of resumeAt —
// see registersAsOf's doc in modbuswire.go for why: this check's own
// attributed frames can legitimately straddle the moment resume actually
// happened, and last-write-wins over the whole window would let a post-resume
// drifted read silently outvote the frozen one it is supposed to be compared
// against.
func frozenRegisters(c *Conversation, frozen bool, resumeAt time.Time, ev *certify.Evidence) *RegisterView {
	if !frozen || resumeAt.IsZero() {
		return c.Registers
	}
	return registersAsOf(c.Exchanges, resumeAt, func(frame int) (time.Time, bool) {
		p, ok := ev.Index.Packet(frame)
		if !ok || p.Time.IsZero() {
			return time.Time{}, false
		}
		return p.Time, true
	})
}

// evalScaleFactor is the sharp end of INFO-1: the DUT's reported value must be
// derivable from the raw registers it read under the SunSpec convention
// value = raw × 10^sunssf.
//
// It searches the observed register image for a (value, scale-factor) pair that
// yields the reported number, and reports honestly how many candidates it
// found: one is a demonstration, several is a weaker corroboration, and none is
// a finding worth raising, because the DUT reported a number its own reads do
// not account for.
//
// regs is the register image to search — frozenRegisters' choice of "as of the
// freeze" or "everything owned", not necessarily c.Registers directly; see its
// doc for why the two differ.
func evalScaleFactor(regs *RegisterView, device string, reported int, haveReported, frozen bool) finding {
	claim := "the value the DUT reported for the device is the value its raw register reads decode to " +
		"under the SunSpec scale-factor convention"
	method := "search of the register image the DUT was observed to read for a (value, sunssf) pair " +
		"satisfying reported = raw × 10^sunssf, with the server's animation frozen so both refer to " +
		"the same instant"
	if !haveReported {
		return skipf(claim, method,
			"the DUT's reported value for device %q could not be read from its journal (gateway "+
				"introspection unavailable, or no readback line appeared during the window), so there "+
				"is nothing to compare the raw registers against", device)
	}
	if !frozen {
		method += " — NOTE: the animation could NOT be frozen for this run"
	}

	type cand struct {
		valAddr, sfAddr uint16
		raw             int
		sf              int
	}
	var cands []cand
	addrs := regs.Addresses()
	for _, a := range addrs {
		w, _ := regs.Get(a)
		raw := int(int16(w))
		if raw == 0 {
			continue // 0 × anything is 0; it would match every zero report
		}
		for _, sa := range addrs {
			sw, _ := regs.Get(sa)
			sf := int(int16(sw))
			if sf < -10 || sf > 10 || sa == a {
				continue
			}
			if scaled(raw, sf) == float64(reported) {
				cands = append(cands, cand{valAddr: a, sfAddr: sa, raw: raw, sf: sf})
			}
		}
	}
	if len(cands) == 0 {
		return framesf(claim, method, certify.Warn, regs.Frames(),
			"the DUT reported %d W for device %q, but no register it was observed to read while the "+
				"comparison window applies, scaled by any register in range −10..10, yields that value. "+
				"Either the DUT reported a value derived from reads outside this test case's frames, or it "+
				"applied a conversion this comparison does not model. %d register(s) were observed",
			reported, device, regs.Len())
	}
	best := cands[0]
	ref, ok := regs.Ref(best.valAddr)
	if !ok {
		return skipf(claim, method, "the matching register at %d carries no byte provenance", best.valAddr)
	}
	strength := "uniquely"
	if len(cands) > 1 {
		strength = fmt.Sprintf("in %d ways (the register image contains several pairs that agree, so this "+
			"corroborates the conversion rather than pinning the exact point)", len(cands))
	}
	return bytesf(claim, method, certify.Pass, fromServer, ref.start, ref.end,
		"the DUT reported %d W for device %q; register %d, whose raw value 0x%04x = %d the DUT read in "+
			"the cited response bytes, scaled by the sunssf register at %d (value %d) gives %g — matching "+
			"%s. The raw register alone %s the reported value, so the scale factor %s applied",
		reported, device, best.valAddr, uint16(int16(best.raw)), best.raw, best.sfAddr, best.sf,
		scaled(best.raw, best.sf), strength,
		map[bool]string{true: "already equals", false: "does NOT equal"}[best.sf == 0],
		map[bool]string{true: "is 10^0 and is trivially", false: "was necessarily"}[best.sf == 0])
}

func scaled(raw, sf int) float64 {
	return float64(raw) * math.Pow10(sf)
}

// lastReadback extracts the most recent watt readback the DUT journalled for a
// device.
func lastReadback(lines []string, device string) (int, bool) {
	for i := len(lines) - 1; i >= 0; i-- {
		l := lines[i]
		if device != "" && !strings.Contains(l, device) {
			continue
		}
		m := readbackRE.FindStringSubmatch(l)
		if m == nil {
			continue
		}
		if v, err := strconv.Atoi(m[1]); err == nil {
			return v, true
		}
	}
	return 0, false
}

// info1RenderingSkips records the per-datatype rendering criteria as addressed
// and not asserted, with one reason rather than nine copies of it.
func info1RenderingSkips() []finding {
	return []finding{
		skipf("the DUT logged every point of every PICS model in human-readable form, with each "+
			"datatype rendered as §2.7.1 step 2 (a)–(i) prescribes",
			"inspection of the client's own human-readable point log",
			"criteria (a)–(i) prescribe a RENDERING — dotted-quad for ipaddr, RFC-4291 hextets for "+
				"ipv6addr, uppercase colon-separated octets for eui48, hex strings for bitfields, base-10 "+
				"for enums — and a rendering exists only in the client's output, never on the wire. The "+
				"DUT is an autonomous gateway: it decodes the measurement and identity points its "+
				"reconcilers consume and journals those, and has no point-browser mode that prints every "+
				"point of every model. Nine of the datatypes in §2.3's list (ipv6addr, eui48, float64, "+
				"int64, uint64, acc64 among them) do not occur at all in the models this server serves, "+
				"so even a point browser would leave them unexercised here. Promoting this row to full "+
				"needs both a diagnostic dump mode on the DUT and a server whose models span every "+
				"datatype in the list"),
		skipf("the DUT applied the appropriate scale factor to every numerical point",
			"per-point comparison of the DUT's reported values against the raw registers",
			"the DUT reports one derived quantity per device per poll (its watt readback), which the "+
				"preceding assertion tests. A per-POINT sweep needs the DUT to publish every decoded "+
				"point; see the rendering assertion above for the same missing capability"),
	}
}

// ── INFO-2 — Unimplemented Point Interpretations ──────────────────────────────

func checkINFO2(ctx context.Context, rc *certify.RunCtx) (certify.Result, error) {
	o, why := newObserver(rc)
	if o == nil {
		return certify.Skipped("%s", why), nil
	}
	if err := o.claimServer(); err != nil {
		return certify.Result{}, err
	}
	if r := o.injectionReason(); r != "" {
		return certify.Skipped("this procedure requires the server to serve not-implemented sentinel "+
			"values, and %s", r), nil
	}
	device := defaultDeviceName
	if v, ok := rc.Param(paramDevice); ok && v != "" {
		device = v
	}

	journalBefore, _ := o.journal(ctx, 200)
	armed := o.fault(ctx, map[string]any{"kind": "nan_sentinel"},
		"make every register read return the SunSpec not-implemented sentinel 0x8000 (int16 −32768), "+
			"which is §2.7.2 step 2's 'configure points to the unimplemented value' applied to the "+
			"whole register bank")
	if armed != nil {
		return certify.Skipped("the not-implemented sentinel could not be armed on the server: %v", armed), nil
	}
	// INFO-2#1 (census 20260731T234821): hold the sentinel for at least one
	// full poll interval beyond what a bare 2-cycle wait guarantees before
	// clearing it. o.watch(2) already blocks for 2 full cycles before
	// clearFault runs below, but that margin was not enough in the run this
	// case names — the fault was armed and cleared before the DUT, still
	// settling from whatever the preceding test case injected, got back to
	// its next poll at all. One more cycle of margin, consistent with the
	// fix applied to READ-1/WR-1/WR-2 for the same symptom.
	watchErr := o.watch(ctx, 3)
	o.clearFault("nan_sentinel")
	if watchErr != nil {
		return certify.Result{}, watchErr
	}
	journalDuring, _ := o.journal(ctx, 400)
	if err := o.settle(ctx); err != nil {
		return certify.Result{}, err
	}
	duringLines := journalSince(journalBefore, journalDuring)

	return certify.Result{
		Verdict: certify.Warn,
		Notes: fmt.Sprintf("the int16 not-implemented sentinel was served for every register and the "+
			"DUT's interpretation of it observed; the other per-datatype sentinels could not be served. %s",
			o.injectionNote()),
		Cite: func(_ context.Context, ev *certify.Evidence) ([]certify.Assertion, error) {
			claim := "the server returned the not-implemented sentinel and the DUT did not report it as " +
				"a measurement"
			c, pre, ok := citeConversation(ev, o, claim)
			if !ok {
				return emit(ev, c, append(pre, info2Skips()...)), nil
			}
			fs := []finding{assertAttributionSound(ev, o)}
			fs = append(fs, evalINFO2(c, o.injectionNote())...)
			fs = append(fs, info2Interpretation(duringLines, device))
			fs = append(fs, info2Skips()...)
			return emit(ev, c, fs), nil
		},
	}, nil
}

// evalINFO2 asserts, from the wire, that the sentinel really was served.
func evalINFO2(c *Conversation, injected string) []finding {
	claim := "the server returned the type-specific not-implemented sentinel in response to the DUT's reads"
	method := "register values of the FC 0x03 responses in the reassembled server→DUT direction, " +
		"compared against the SunSpec not-implemented sentinel table"
	var best Exchange
	bestN, bestTotal := 0, 0
	var words []uint16
	for _, ex := range c.Reads() {
		if ex.Response == nil || ex.Response.IsException() {
			continue
		}
		_, regs, ok := ex.Response.ReadResponse()
		if !ok || len(regs) == 0 {
			continue
		}
		n, w := SentinelCount(regs)
		if n > bestN {
			best, bestN, bestTotal, words = ex, n, len(regs), w
		}
	}
	if bestN == 0 {
		return []finding{skipf(claim, method,
			"no response carrying a not-implemented sentinel value was attributed to this test case, "+
				"although the fault was armed. %s", injected)}
	}
	types := []string{}
	for _, w := range words {
		types = append(types, fmt.Sprintf("0x%04x (%s)", w, strings.Join(SentinelTypesFor(w), "/")))
	}
	return []finding{bytesf(claim, method, certify.Pass, fromServer, best.Response.Start, best.Response.End,
		"a %d-register response carried %d register(s) holding a not-implemented sentinel value: %s. "+
			"%s. Response cited in full: [%s]",
		bestTotal, bestN, strings.Join(types, ", "), injected, best.Response.Hex())}
}

// info2Interpretation is the criterion itself: did the DUT treat the sentinel
// as N/A, or report it as a reading?
func info2Interpretation(lines []string, device string) finding {
	claim := "the DUT identified the sentinel-valued points as unimplemented rather than reporting the " +
		"sentinel as a measurement"
	method := "the DUT's own readback values while the server served the sentinel, from its journal"
	source := "journalctl -u lexa-modbus on the device under test"
	if len(lines) == 0 {
		return skipf(claim, method,
			"no journal lines could be read from the DUT while the sentinel was being served, so its "+
				"interpretation of the sentinel is unevidenced here")
	}
	v, ok := lastReadback(lines, device)
	if !ok {
		return narrativef(claim, method, source, certify.Pass,
			"while the server returned the sentinel for every register, the DUT journalled no readback "+
				"value at all for device %q in %d line(s) — it did not report the sentinel as a "+
				"measurement", device, len(lines))
	}
	if v == -32768 || v == 32768 {
		return narrativef(claim, method, source, certify.Fail,
			"while the server returned the int16 not-implemented sentinel 0x8000 for every register, the "+
				"DUT journalled readback=W=%d for device %q — it reported the sentinel itself as a "+
				"measurement instead of recognising the point as unimplemented", v, device)
	}
	return narrativef(claim, method, source, certify.Warn,
		"while the server returned the sentinel for every register, the DUT journalled readback=W=%d for "+
			"device %q. That is not the sentinel value, so the DUT did not report the sentinel as a "+
			"measurement — but it did report SOME value, which may be a held last-known-good rather "+
			"than a recognition of the sentinel. Distinguishing the two needs a DUT-side "+
			"point-availability signal this suite cannot read", v, device)
}

func info2Skips() []finding {
	return []finding{
		skipf("at least one unimplemented point was logged for every datatype present in the server's models",
			"seed each datatype's own not-implemented sentinel into a point of that type and read it back",
			"the server's fault surface offers exactly one sentinel — the int16 0x8000, applied to the "+
				"WHOLE register bank — and no way to set an INDIVIDUAL point to its own type's sentinel. "+
				"The other sentinels in the table (0xFFFF for uint16/enum16/bitfield16/count, 0x8000 0x0000 "+
				"for int32, 0xFFFF 0xFFFF for uint32/enum32/bitfield32, a quiet NaN for float32, a "+
				"leading NUL for string, all-ones for eui48) were therefore never served. Promoting this "+
				"row to full requires a per-point sentinel verb, e.g. POST /inject "+
				"{\"unimplemented\":[{\"addr\":40190,\"type\":\"int16\"}]}"),
	}
}
