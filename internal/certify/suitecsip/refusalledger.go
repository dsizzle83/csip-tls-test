package suitecsip

// refusalledger.go attributes a SCALAR refusal row's southbound writes to the
// CURRENT control, using the DER simulator's own transaction ledger, instead of
// grading any in-window register movement as this row's write.
//
// ── The gap this closes (HARNESS-TEARDOWN-CANCEL-ONLY-LEAVES-APPLIED-STATE) ──
//
// oracleRefusal's fingerprint diff asks "did the WSet axis registers read the
// same before and after this row's window?" and FAILs on any change. That
// cannot tell WHO moved them. BASIC-013 (opModFixedW) runs immediately before
// BASIC-014 (opModTargetW, the refused axis), commands the very WSet/WSetPct the
// refusal fingerprints, and when its control is RELEASED — its enable bit drops,
// its setpoint reverts — the registers change DURING BASIC-014's window. The
// fingerprint diff counted that prior control's RELEASE as BASIC-014's own write
// and FAILed a correctly-refusing DUT (RUN-2/RUN-3, the BASIC-014 leg of the
// registered issue).
//
// The ledger attributes by IDENTITY, not by movement. modsim's wire tap records
// every southbound Modbus transaction with a monotonic seq and the control-plane
// epoch it fell in (sim/simapi, the deterministic control plane the
// modbus-client suite grades from). A refusal row captures the ledger's
// high-water seq at the instant it PUBLISHES its control (the fence). A write
// the DUT then issues in response to THIS control is stamped seq > fence; a
// prior control's release, which happened before this row published, is stamped
// seq <= fence. So "a write attributable to this row" is exactly "a WSet-axis
// write at seq > fence", and a prior release is excluded by construction — the
// deterministic-oracle discipline this whole file family already uses, applied
// to the refusal axis.
//
// ── Degrade, never to a false PASS ──────────────────────────────────────────
//
// The ledger needs modsim's wire tap (an older sim, or -tap=false, answers GET
// /ledger 501). When it is unavailable, or the axis is one this file does not
// map to a register span, the attribution declines (decided=false) and
// oracleRefusal falls back to its fingerprint diff — the same posture
// awaitFreshDERPoll takes for a missing poll barrier. The ledger is the sharper
// instrument, not the only one.

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"sort"
	"strconv"

	"csip-tls-test/internal/certify"
	"csip-tls-test/internal/invariant"
	"lexa-proto/sunspec"
)

// Modbus write function codes, restated from the wire (sim/simapi/API.md) rather
// than imported so this attributor stands alone, the way ledger.go's decoder
// does in the modbus-client suite.
const (
	fcWriteSingleRegister    = 0x06
	fcWriteMultipleRegisters = 0x10
)

// refusalLedgerFenceParam carries the DER ledger high-water seq captured at the
// moment a scalar refusal row published its control. Its presence is also the
// signal that the ledger WAS reachable at publish time; its absence makes
// oracleRefusal fall back to the fingerprint diff.
const refusalLedgerFenceParam = "iw15.refusal_ledger_fence"

// refusalLedgerFence is the parsed fence: the ledger seq a refusal row's own
// writes must exceed, and whether one was captured at all.
type refusalLedgerFence struct {
	Seq  uint64
	Have bool
}

// simLedgerEntry is the slice of one modsim ledger transaction this attributor
// reads. The sim's record carries more (the full ADUs, timing, the fault that
// shaped it); only the fields an axis-attribution needs are modelled, so a
// sim-side addition does not break this reader.
type simLedgerEntry struct {
	Seq   uint64 `json:"seq"`
	Epoch uint64 `json:"epoch"`
	FC    uint8  `json:"fc"`
	Addr  uint16 `json:"addr"`
	Count uint16 `json:"count"`
}

func (e simLedgerEntry) isWrite() bool {
	return e.FC == fcWriteSingleRegister || e.FC == fcWriteMultipleRegisters
}

// overlaps reports whether this transaction's register range intersects the
// half-open span [lo, hi). A single-register write carries Count 0 or 1.
func (e simLedgerEntry) overlaps(lo, hi uint16) bool {
	n := uint32(e.Count)
	if n == 0 {
		n = 1
	}
	start := uint32(e.Addr)
	return start < uint32(hi) && start+n > uint32(lo)
}

// simLedgerPage is GET /ledger's answer, in the fields this file reads.
type simLedgerPage struct {
	Entries   []simLedgerEntry `json:"entries"`
	Total     int              `json:"total"`
	HighSeq   uint64           `json:"high_seq"`
	NextSeq   uint64           `json:"next_seq"`
	Truncated bool             `json:"truncated"`
}

// captureRefusalLedgerFence records the DER ledger high-water seq at publish
// time for a SCALAR refusal (Points set, no Curve). It is best-effort: a sim
// with no wire tap records no fence and oracleRefusal falls back to the
// fingerprint diff.
func captureRefusalLedgerFence(ctx context.Context, d *Driver, params map[string]string, b *refusalBinding) {
	if b == nil || b.Curve != nil || len(b.Points) == 0 {
		return
	}
	if seq, ok := derLedgerHighSeq(ctx, d.rc); ok {
		params[refusalLedgerFenceParam] = strconv.FormatUint(seq, 10)
	}
}

// parseRefusalLedgerFence recovers the fence a refusal row's Setup captured.
func parseRefusalLedgerFence(params map[string]string) refusalLedgerFence {
	s, ok := params[refusalLedgerFenceParam]
	if !ok {
		return refusalLedgerFence{}
	}
	seq, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return refusalLedgerFence{}
	}
	return refusalLedgerFence{Seq: seq, Have: true}
}

// derLedgerHighSeq reads the DER sim's current ledger high-water seq without
// pulling the whole ledger (a since_seq past the end returns the high-water and
// no entries). ok is false — never fatal — when the sim publishes no ledger.
func derLedgerHighSeq(ctx context.Context, rc *certify.RunCtx) (uint64, bool) {
	page, ok := queryDERLedger(ctx, rc, math.MaxUint64, 1)
	if !ok {
		return 0, false
	}
	return page.HighSeq, true
}

// queryDERLedger fetches GET /ledger?since_seq=&limit= from the DER sim. ok is
// false on any sim that does not answer it (no tap → 501, an older sim, a
// transport error), which is the caller's cue to fall back.
func queryDERLedger(ctx context.Context, rc *certify.RunCtx, sinceSeq uint64, limit int) (simLedgerPage, bool) {
	sim, err := rc.Sim(oracleSimName)
	if err != nil || sim == nil || !sim.Available() {
		return simLedgerPage{}, false
	}
	path := fmt.Sprintf("/ledger?since_seq=%d&limit=%d", sinceSeq, limit)
	raw, err := sim.Raw(ctx, http.MethodGet, path, nil)
	if err != nil {
		return simLedgerPage{}, false
	}
	var page simLedgerPage
	if json.Unmarshal(raw, &page) != nil {
		return simLedgerPage{}, false
	}
	return page, true
}

// refusalAxisSpan maps a scalar refusal's Points to the half-open register span
// [lo, hi) a write of that axis lands in, resolved against the DER's own model
// 704 data base. It returns ok=false for an axis this file does not map — the
// caller then declines the ledger attribution rather than guessing a span.
//
// The WSet axis (the only scalar refusal in the RC0 catalog, BASIC-014) is the
// COMMANDED-SETPOINT region of model 704's WSet sync group:
// [Offset(WSetEna), Offset(WSetRvrtTms)) — WSetEna, WSetMod, WSet, WSetRvrt,
// WSetPct, WSetPctRvrt, WSetEnaRvrt. Covering the enable/mode alongside the
// setpoint is deliberate: a DUT that half-executes a refused axis (writes the
// enable, flips WSetMod on its way to giving up) has written it, and every one
// of those is a landing this row must catch.
//
// The AUTONOMOUS reversion-timer registers — WSetRvrtTms and WSetRvrtRem, the
// last two fields of the group before VarSetEna — are EXCLUDED. modsim's model
// 704 reversion engine decrements WSetRvrtRem on its own wall clock, with no
// Modbus write (sim/southbound/reversion.go), so a prior control still winding
// down inside BASIC-014's window ticks that register without a ledger
// transaction. Including it in the span would let an autonomous countdown be
// mistaken for a southbound write (or, worse, feed the fingerprint-diff
// fallback's default FAIL). A refusal is about the COMMANDED setpoint and its
// enable/mode — not a self-decrementing timer this device drives itself — so the
// span ends at WSetRvrtTms.
func refusalAxisSpan(uv invariant.UnitView, points []string) (lo, hi uint16, ok bool) {
	base, hasBase := uv.Base[704]
	if !hasBase {
		return 0, 0, false
	}
	isWSet := false
	for _, p := range points {
		if p == "WSet" || p == "WSetPct" {
			isWSet = true
		}
	}
	if !isWSet {
		return 0, 0, false
	}
	startOff := sunspec.L704.Offset("WSetEna")
	// End BEFORE the autonomous timer registers (WSetRvrtTms/WSetRvrtRem), not
	// at the next axis (VarSetEna): those two self-decrement with no wire write.
	endOff := sunspec.L704.Offset("WSetRvrtTms")
	if startOff < 0 || endOff <= startOff {
		return 0, 0, false
	}
	return base + uint16(startOff), base + uint16(endOff), true
}

// refusalLedgerAttribution decides a scalar refusal row from the DER's own
// transaction ledger, fenced at the seq the row captured when it published.
//
// It returns decided=false — leaving oracleRefusal to fall back to the
// fingerprint diff — when the fence was never captured (no tap at publish), the
// row is a curve refusal, the axis has no mapped span, or the ledger could not
// be read now. It returns a decided Finding otherwise, and NEVER a PASS it
// cannot account for: an axis that moved with no write the ledger can attribute
// to it — under the fence or before it — is a FAIL, because an unattributable
// change is not an observed refusal.
func refusalLedgerAttribution(ctx context.Context, rc *certify.RunCtx, b *refusalBinding,
	fence refusalLedgerFence, uv invariant.UnitView, baseline, post string) (Finding, bool) {

	if !fence.Have || b.Curve != nil {
		return Finding{}, false
	}
	lo, hi, ok := refusalAxisSpan(uv, b.Points)
	if !ok {
		return Finding{}, false
	}

	// A bounded lookback around the fence so ONE query sees both this control's
	// writes (seq > fence) and the immediately-prior control's release
	// (seq <= fence), without pulling the whole append-only ledger.
	const lookback = 256
	from := uint64(0)
	if fence.Seq > lookback {
		from = fence.Seq - lookback
	}
	page, ok := queryDERLedger(ctx, rc, from, 4096)
	if !ok {
		return Finding{}, false
	}
	if page.Truncated {
		// The sim's ring aged out transactions the query asked for, so a
		// "no fenced write" reading here could be missing a write that WAS
		// there — an absence this page cannot certify. Decline to the
		// fingerprint diff rather than risk a false PASS on a truncated ledger.
		return Finding{}, false
	}

	var fenced, prior []simLedgerEntry
	for _, e := range page.Entries {
		if !e.isWrite() || !e.overlaps(lo, hi) {
			continue
		}
		if e.Seq > fence.Seq {
			fenced = append(fenced, e)
		} else {
			prior = append(prior, e)
		}
	}

	switch {
	case len(fenced) > 0:
		return Finding{Verdict: certify.Fail, Observed: fmt.Sprintf(
			"a southbound WRITE of %s LANDED on the DER under THIS control's own ledger fence (seq>%d), on "+
				"an axis the DUT is supposed to have refused: %s. This row commanded %s. The DER's transaction "+
				"ledger attributes the write to THIS control by its seq, not to any prior row — a gateway that "+
				"answers the head end cannot-comply and then writes the axis anyway has told the head end one "+
				"thing and the device another",
			b.Axis, fence.Seq, describeLedgerWrites(fenced), b.Commanded)}, true

	case baseline == "":
		// No fingerprint baseline was recorded, but the ledger is authoritative
		// on WRITES regardless: it shows this control issued none to the axis
		// under its fence. That certifies the absence the fingerprint diff could
		// not (its own path FAILs an unestablished baseline), so the ledger's
		// stronger evidence is used rather than falling back to that FAIL.
		return Finding{Verdict: certify.Pass, Observed: fmt.Sprintf(
			"no southbound write of %s is attributable to this control: the DER's transaction ledger holds "+
				"no write overlapping its registers %d..%d at seq>%d (this control's publish fence). No "+
				"pre-publication register fingerprint was recorded, but the ledger certifies the absence of a "+
				"write directly. %s",
			b.Axis, lo, hi, fence.Seq, b.Why)}, true

	case post == baseline:
		return Finding{Verdict: certify.Pass, Observed: fmt.Sprintf(
			"no southbound write of %s is attributable to this control: the DER's transaction ledger holds "+
				"no write overlapping its registers %d..%d at seq>%d (this control's publish fence), and the "+
				"axis registers are unchanged across the window (%s). The refusal left no southbound trace. %s",
			b.Axis, lo, hi, fence.Seq, post, b.Why)}, true

	case len(prior) > 0:
		return Finding{Verdict: certify.Pass, Observed: fmt.Sprintf(
			"the %s registers changed across this row's window (%s -> %s), but the DER's transaction ledger "+
				"attributes the change to a PRIOR control's RELEASE (write at seq<=%d, before this control's "+
				"publish fence), NOT to this refused control (no write at seq>%d): %s. A prior row's release is "+
				"not this row's write — attributing it here is exactly the misattribution the ledger fence "+
				"exists to remove. %s",
			b.Axis, baseline, post, fence.Seq, fence.Seq, describeLedgerWrites(prior), b.Why)}, true

	default:
		return Finding{Verdict: certify.Fail, Observed: fmt.Sprintf(
			"the %s registers changed across this row's window (%s -> %s) but the DER's transaction ledger "+
				"holds NO write overlapping its registers %d..%d, either under this control's fence (seq>%d) or "+
				"before it: the oracle cannot attribute the change to any transaction and refuses to certify a "+
				"refusal it cannot account for. An unattributable change is not an observed absence",
			b.Axis, baseline, post, lo, hi, fence.Seq)}, true
	}
}

// describeLedgerWrites renders a set of write transactions for an assertion,
// ascending by seq.
func describeLedgerWrites(es []simLedgerEntry) string {
	sort.Slice(es, func(i, j int) bool { return es[i].Seq < es[j].Seq })
	parts := make([]string, 0, len(es))
	for _, e := range es {
		parts = append(parts, fmt.Sprintf("seq %d (epoch %d) FC 0x%02x at %d×%d", e.Seq, e.Epoch, e.FC, e.Addr, e.Count))
	}
	return joinSemis(parts)
}
