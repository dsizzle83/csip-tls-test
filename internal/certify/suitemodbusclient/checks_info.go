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
	device := deviceName(rc)
	d, derr := o.determinism(ctx)
	if derr != nil {
		return certify.Skipped("%s", deterministicSkip(derr)), nil
	}
	if err := d.begin(ctx, nil); err != nil {
		return certify.Result{}, err
	}
	defer d.restore(ctx)

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
	disc, err := rediscover(ctx, d, "INFO-1")
	if err != nil {
		return certify.Result{}, err
	}
	// One COMPLETE poll cycle after the rediscovery, so the coverage assertion
	// is about a whole cycle's reads rather than whatever a fixed wait caught.
	cycle, cycleSeen, err := d.awaitPoll(ctx, 1)
	if err != nil {
		return certify.Result{}, err
	}
	journalAfter, _ := o.journal(ctx, 400)
	reported, haveReported := lastReadback(journalSince(journalBefore, journalAfter), device)

	return certify.Result{
		Verdict: certify.Warn,
		Notes: fmt.Sprintf("the DUT's read coverage and its scale-factor interpretation were asserted "+
			"over a forced rediscovery and one complete poll cycle, both held on the simulator rather "+
			"than on a clock; the per-datatype rendering criteria (a)-(i) are about the client's own "+
			"log and are not wire facts. %s", o.injectionNote()),
		Cite: func(_ context.Context, ev *certify.Evidence) ([]certify.Assertion, error) {
			claim := "the DUT read every model in the server's chain, scale-factor registers included"
			c, pre, ok := citeConversation(ev, o, claim)
			fs := append([]finding(nil), pre...)
			if ok {
				fs = []finding{assertAttributionSound(ev, o)}
				fs = append(fs, evalModelCoverage(c, disc.Err))
				fs = append(fs, evalScaleFactor(frozenRegisters(c, frozen, resumeAt, ev), device,
					reported, haveReported, frozen))
			}
			fs = append(fs, evalRediscovery(disc, d))
			fs = append(fs, evalREAD2Cycle(cycle, cycleSeen, d))
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

// infoDatatypes is every datatype §2.7.2 step 2 is about: "for all the data
// types present in the PICS models, update Server 1 to configure at least one
// of these points to the unimplemented value".
//
// The list is the catalog's own — CLI-1's preconditions enumerate exactly these
// twenty-two as the types a test engineer must have captured from the PICS —
// and the not-implemented VALUES are the SunSpec Device Information Model
// Specification's, held independently on each side: this suite's Sentinels
// table (sunspec.go) is what an assertion checks against, and the simulator's
// own table (sim/southbound/sentinel.go) is what serves them. Two tables
// derived from one published spec is not two witnesses, and the suite does not
// claim otherwise — but it does mean a typo in either shows up as a failure
// rather than as agreement.
var infoDatatypes = []string{
	"int16", "uint16", "count", "acc16", "enum16", "bitfield16", "sunssf", "pad",
	"int32", "uint32", "acc32", "enum32", "bitfield32", "ipaddr", "float32", "eui48",
	"int64", "uint64", "acc64", "float64",
	"string", "ipv6addr",
}

// seeded records one datatype's seed: where it went and what words the server
// was asked to serve there.
type seeded struct {
	Type  string
	Addr  uint16
	Words []uint16
}

// infoSentinelWidth is how many registers a datatype's sentinel occupies for
// the purposes of laying the sweep out. It mirrors this suite's own Sentinels
// table and defaults the two variable-width types.
func infoSentinelWidth(typ string) int {
	switch typ {
	case "string":
		return 4 // four registers is a plausible short string field
	case "ipv6addr":
		return 8
	}
	for _, s := range Sentinels {
		if s.Type == typ {
			return len(s.Words)
		}
	}
	return 1
}

// infoSentinelWords is the words this suite expects the server to serve for a
// datatype, from ITS OWN table.
func infoSentinelWords(typ string) []uint16 {
	switch typ {
	case "string", "ipv6addr":
		return make([]uint16, infoSentinelWidth(typ))
	}
	for _, s := range Sentinels {
		if s.Type == typ {
			return append([]uint16(nil), s.Words...)
		}
	}
	return nil
}

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
	d, derr := o.determinism(ctx)
	if derr != nil {
		return certify.Skipped("%s", deterministicSkip(derr)), nil
	}
	device := deviceName(rc)
	if err := d.begin(ctx, nil); err != nil {
		return certify.Result{}, err
	}
	defer d.restore(ctx)

	// PHASE 1 — the whole-bank blanket: every register reads as the int16
	// not-implemented sentinel. It proves the client recognises "this device
	// has nothing to report", which is the coarse half of §2.7.2.
	journalBefore, _ := o.journal(ctx, 200)
	blanket, err := d.meet(ctx, map[string]any{"kind": "nan_sentinel"},
		"make every register read return the SunSpec not-implemented sentinel 0x8000 (int16 -32768), "+
			"which is §2.7.2 step 2's 'configure points to the unimplemented value' applied to the "+
			"whole register bank",
		"nan_sentinel", 1)
	if err != nil {
		return certify.Result{}, err
	}
	journalDuring, _ := o.journal(ctx, 400)
	duringLines := journalSince(journalBefore, journalDuring)

	// PHASE 2 — the per-datatype sweep, which is what §2.7.2 step 2 actually
	// asks for. Every datatype gets its own point, seeded with ITS OWN
	// not-implemented value.
	//
	// WHERE it is seeded matters, and the answer comes from the DUT rather
	// than from a model directory this suite deliberately does not hold: the
	// simulator's poll anchor IS "the block the client reads every cycle",
	// learned from the client's own traffic. Seeding inside it guarantees the
	// DUT reads what was seeded; seeding at an address chosen from a model
	// definition would be this suite consulting the table ERR-3's independence
	// forbids it to hold.
	warm, haveAnchor, err := d.warmUp(ctx)
	if err != nil {
		return certify.Result{}, err
	}
	var sweep []seeded
	var sweepMeet meeting
	var sweepErr error
	if !haveAnchor {
		sweepErr = fmt.Errorf("the simulator has not identified the block the DUT reads every poll "+
			"cycle (%s), so there is nowhere to seed a sentinel the DUT is certain to read",
			pollRuleNote(warm))
	} else {
		// The animation would overwrite a seeded measurement register on its
		// next tick, so the device is frozen for the sweep. It is resumed
		// unconditionally, and the reset in the defer restores the register
		// image whatever happens.
		if cerr := o.sim.Control(ctx, map[string]any{"cmd": "pause"}, nil); cerr == nil {
			o.injected = append(o.injected, fmt.Sprintf("POST %s/control {\"cmd\":\"pause\"} (freeze "+
				"the animation so a seeded sentinel is not overwritten before the DUT reads it)",
				o.sim.BaseURL))
			defer func() {
				cctx, cancel := context.WithTimeout(withoutCancel(ctx), 20*time.Second)
				defer cancel()
				_ = o.sim.Control(cctx, map[string]any{"cmd": "resume"}, nil)
			}()
		}
		a := warm.Poll.Anchor
		// Lay the types out from the far end of the anchor block backwards, so
		// the sweep occupies the block's tail rather than its head — the head
		// carries the model's ID and length headers on many layouts, and a
		// sentinel there would break the chain walk rather than test a point.
		addr := a.Addr + 2
		var entries []map[string]any
		for _, typ := range infoDatatypes {
			w := infoSentinelWidth(typ)
			if uint32(addr)+uint32(w) > uint32(a.Addr)+uint32(max16(a.Count, 1)) {
				break // the block is not long enough for the rest of the sweep
			}
			sweep = append(sweep, seeded{Type: typ, Addr: addr, Words: infoSentinelWords(typ)})
			e := map[string]any{"addr": int(addr), "type": typ}
			if typ == "string" || typ == "ipv6addr" {
				e["len"] = w
			}
			entries = append(entries, e)
			addr += uint16(w)
		}
		if len(entries) == 0 {
			sweepErr = fmt.Errorf("the block the DUT reads (%s) is too short to hold even one seeded "+
				"point after its header", a)
		} else {
			sweepMeet, err = d.meetInject(ctx, map[string]any{"unimplemented": entries},
				fmt.Sprintf("seed %d point(s) — one per SunSpec datatype — inside %s, the block the "+
					"simulator observed the DUT reading every poll cycle, each with its OWN "+
					"not-implemented value per the Device Information Model", len(entries), a), 1)
			if err != nil {
				return certify.Result{}, err
			}
			defer func() {
				cctx, cancel := context.WithTimeout(withoutCancel(ctx), 20*time.Second)
				defer cancel()
				_, _ = d.inject(cctx, map[string]any{"clear_unimplemented": true},
					"restore every seeded point")
			}()
		}
	}

	return certify.Result{
		Verdict: certify.Warn,
		Notes: fmt.Sprintf("the int16 not-implemented sentinel was served for every register, and then "+
			"%d point(s) — one per SunSpec datatype — were seeded with their OWN not-implemented values "+
			"inside the block the simulator observed the DUT reading every cycle. Both phases were held "+
			"on the simulator's transaction ledger rather than on a poll interval. %s",
			len(sweep), o.injectionNote()),
		Cite: func(_ context.Context, ev *certify.Evidence) ([]certify.Assertion, error) {
			claim := "the server returned the not-implemented sentinel and the DUT did not report it as " +
				"a measurement"
			c, pre, ok := citeConversation(ev, o, claim)
			fs := append([]finding(nil), pre...)
			if ok {
				fs = []finding{assertAttributionSound(ev, o)}
				fs = append(fs, evalINFO2(c, o.injectionNote())...)
			}
			fs = append(fs, evalINFO2Blanket(blanket, d))
			fs = append(fs, info2Interpretation(duringLines, device))
			fs = append(fs, evalINFO2Sweep(sweep, sweepMeet, sweepErr, d))
			fs = append(fs, info2RenderingGap())
			return emit(ev, c, fs), nil
		},
	}, nil
}

// evalINFO2Blanket grades the whole-bank phase from the sim's own record.
func evalINFO2Blanket(m meeting, d *determinism) finding {
	claim := "the server served the not-implemented sentinel for every register and the DUT read it"
	method := "arm the whole-bank sentinel at a named epoch, then read from the simulator's ledger what " +
		"the DUT was actually served under it"
	if !m.ok() {
		return skipf(claim, method, "%s", m.reason())
	}
	for _, e := range m.Page.Reads() {
		vals, ok := e.Values()
		if !ok || len(vals) == 0 {
			continue
		}
		n := 0
		for _, v := range vals {
			if len(SentinelTypesFor(v)) > 0 {
				n++
			}
		}
		if n == len(vals) {
			return narrativef(claim, method, d.ledgerSource(), certify.Pass,
				"with the whole-bank sentinel armed at epoch %d, the DUT read %d register(s) at %d and "+
					"every one of them carried a not-implemented value. Transaction: %s",
				m.Epoch, len(vals), e.Addr, e)
		}
	}
	return narrativef(claim, method, d.ledgerSource(), certify.Warn,
		"the whole-bank sentinel was armed at epoch %d and the DUT read %d transaction(s) under it, but "+
			"none came back entirely sentinel-valued: %s", m.Epoch, m.Page.Total, m.Page.Summary())
}

// evalINFO2Sweep is §2.7.2 step 2's real criterion on the SERVER side: one
// point of every datatype present, set to its own unimplemented value, and read
// back by the client.
func evalINFO2Sweep(sweep []seeded, m meeting, sweepErr error, d *determinism) finding {
	claim := "at least one point of EVERY SunSpec datatype was configured to its own not-implemented " +
		"value and the DUT read it back"
	method := "seed one point per datatype inside the block the simulator observed the DUT reading " +
		"every poll cycle, each with the Device Information Model's value for that type, then confirm " +
		"from the simulator's ledger that the DUT's own read returned exactly those words"
	if sweepErr != nil {
		return skipf(claim, method, "the sweep could not be laid out: %v", sweepErr)
	}
	if !m.ok() {
		return skipf(claim, method, "%s", m.reason())
	}
	// Reconstruct the register image from the DUT's own reads under the fence.
	image := map[uint16]uint16{}
	for _, e := range m.Page.Reads() {
		vals, ok := e.Values()
		if !ok {
			continue
		}
		for i, v := range vals {
			image[e.Addr+uint16(i)] = v
		}
	}
	var confirmed, unread, wrong []string
	for _, sd := range sweep {
		got := make([]uint16, 0, len(sd.Words))
		complete := true
		for i := range sd.Words {
			v, ok := image[sd.Addr+uint16(i)]
			if !ok {
				complete = false
				break
			}
			got = append(got, v)
		}
		switch {
		case !complete:
			unread = append(unread, fmt.Sprintf("%s@%d", sd.Type, sd.Addr))
		case !sameWords(got, sd.Words):
			wrong = append(wrong, fmt.Sprintf("%s@%d served %v, wanted %v", sd.Type, sd.Addr, got, sd.Words))
		default:
			confirmed = append(confirmed, fmt.Sprintf("%s@%d", sd.Type, sd.Addr))
		}
	}
	switch {
	case len(wrong) > 0:
		return narrativef(claim, method, d.ledgerSource(), certify.Warn,
			"%d of %d datatype(s) were confirmed on the wire, and %d came back with values other than "+
				"the ones seeded: %s. That is a disagreement between this suite's sentinel table and "+
				"the simulator's — a bench defect, not a DUT finding. Confirmed: %s",
			len(confirmed), len(sweep), len(wrong), strings.Join(wrong, "; "),
			joinOr(confirmed, "none"))
	case len(unread) > 0:
		return narrativef(claim, method, d.ledgerSource(), certify.Warn,
			"%d of %d datatype(s) were seeded and read back by the DUT with exactly their "+
				"not-implemented values — %s — while %d fell outside the registers the DUT read in this "+
				"window: %s. Every type the client's own poll covers is demonstrated; the rest need a "+
				"longer block, or a client that reads more of the chain per cycle",
			len(confirmed), len(sweep), joinOr(confirmed, "none"), len(unread), strings.Join(unread, ", "))
	default:
		return narrativef(claim, method, d.ledgerSource(), certify.Pass,
			"all %d datatype(s) were seeded inside the block the DUT reads every cycle and read back by "+
				"the DUT with exactly the Device Information Model's not-implemented value for each: %s",
			len(sweep), strings.Join(confirmed, ", "))
	}
}

// info2RenderingGap is the half of §2.7.2 that lives in the client's own log
// and cannot be a wire fact.
func info2RenderingGap() finding {
	return skipf(
		"the DUT logged each unimplemented point AS unimplemented rather than reporting its sentinel "+
			"as a value",
		"inspection of the client's own per-point output",
		"§2.7.2's criterion is about the CLIENT'S RENDERING, and this DUT has no per-point output to "+
			"inspect: it journals reconciler decisions and a decoded measurement, not a point browser. "+
			"The wire half — that the server really did serve each datatype's not-implemented value and "+
			"that the DUT really did read it — is asserted above from the simulator's own record. "+
			"Closing the rest needs a point-browser diagnostic on the DUT, and no sim work promotes it. "+
			"Note also that the specification makes three of these types genuinely ambiguous: acc16, "+
			"acc32, acc64, ipaddr and string all have ZERO as their not-implemented value, which is "+
			"also an ordinary reading, so even a perfect client cannot distinguish them on the wire — "+
			"that ambiguity is the Information Model's, not this bench's")
}

func sameWords(a, b []uint16) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
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
