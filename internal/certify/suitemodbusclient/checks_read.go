package suitemodbusclient

// checks_read.go implements §2.5, the Read Tests: READ-1 and READ-2.
//
// The two rows are opposites, and the DUT sits squarely on one side of the
// divide. READ-2 wants a client that reads a whole model body in one request
// and, for a model longer than the 125-register Modbus ceiling, splits it into
// the fewest possible reads. READ-1 wants a client that can read each point
// individually. The gateway is a block reader: it pulls whole SunSpec model
// blocks through its reader and decodes them in memory, and exposes no
// interface at all for requesting one point. That makes READ-2 fully
// demonstrable on this bench and READ-1 not demonstrable at all — and the
// honest report of that difference is one PASS and one SKIP whose reason states
// the missing capability, not two PASSes.

import (
	"context"
	"fmt"
	"sort"

	"csip-tls-test/internal/certify"
)

// ── READ-2 — Multiple Point Reads ─────────────────────────────────────────────

func checkREAD2(ctx context.Context, rc *certify.RunCtx) (certify.Result, error) {
	o, why := newObserver(rc)
	if o == nil {
		return certify.Skipped("%s", why), nil
	}
	if err := o.claimServer(); err != nil {
		return certify.Result{}, err
	}
	// A steady-state poll is enough for READ-2: the DUT re-reads every model it
	// consumes on every cycle. Forcing a reconnect additionally brings the
	// discovery-time reads of models it does NOT consume into the window, which
	// is what makes the model-by-model coverage assertion complete.
	forced := o.forceReconnect(ctx)
	if err := o.watch(ctx, 2); err != nil {
		return certify.Result{}, err
	}
	return certify.Result{
		Notes: fmt.Sprintf("the DUT's southbound read pattern was observed over two poll cycles%s. %s",
			reconnectNote(forced), o.injectionNote()),
		Cite: func(_ context.Context, ev *certify.Evidence) ([]certify.Assertion, error) {
			claim := "the DUT read model bodies in whole-block requests bounded by the Modbus 125-register limit"
			c, pre, ok := citeConversation(ev, o, claim)
			if !ok {
				return emit(ev, c, pre), nil
			}
			fs := []finding{assertAttributionSound(ev, o)}
			fs = append(fs, evalREAD2(c)...)
			fs = append(fs, evalFraming(c)...)
			return emit(ev, c, fs), nil
		},
	}, nil
}

// evalREAD2 is READ-2's decision logic, pure over the observed conversation.
func evalREAD2(c *Conversation) []finding {
	out := []finding{evalReadQuantities(c)}

	_, models, _, why := c.ModelChain()
	if len(models) == 0 {
		out = append(out, skipf(
			"all points after the ID and L points of the Common Model were read in a single request",
			"coverage of model 1's body by a single FC 0x03 request",
			"no model chain was reconstructed from this test case's frames: %s", why))
		return append(out, read2HexLogSkip())
	}

	// (1) The Common Model in one request.
	claim := "all points after the ID and L points of the Common Model (model 1) were read in a single request"
	method := "the smallest set of FC 0x03 requests covering model 1's body, from the DUT→server direction"
	if m, ok := findModel(models, CommonModelID); !ok {
		out = append(out, skipf(claim, method, "model 1 was not among the observed model headers"))
	} else if !m.BodyRead {
		out = append(out, skipf(claim, method,
			"model 1 (header at %d, length %d) was observed in the chain but its body was not read within "+
				"this test case's frames", m.HeaderAddr, m.Length))
	} else if m.BodySingleRead {
		ex := c.Exchanges[m.Reads[0].Exchange]
		out = append(out, bytesf(claim, method, certify.Pass, fromDUT, ex.Request.Start, ex.Request.End,
			"one FC 0x03 request covered model 1's whole body: start %d, quantity %d, for a body of %d "+
				"register(s) at %d..%d. Request cited in full: [%s]",
			m.Reads[0].Start, m.Reads[0].Quantity, m.Length, m.HeaderAddr+2, m.HeaderAddr+1+m.Length,
			ex.Request.Hex()))
	} else {
		ex := c.Exchanges[m.Reads[0].Exchange]
		out = append(out, bytesf(claim, method, certify.Fail, fromDUT, ex.Request.Start, ex.Request.End,
			"model 1's %d-register body was read by %d separate request(s) (%s), although %d registers "+
				"is within the single-request limit of %d",
			m.Length, len(m.Reads), describeSpans(m.Reads), m.Length, MaxReadQuantity))
	}

	// (2) Models longer than the ceiling: maximise each read.
	out = append(out, evalLongModelChunking(c, models))

	// (3) The contrast with READ-1: this row's traffic must NOT be
	//     one-request-per-point.
	out = append(out, evalReadGranularity(c, certify.Pass))

	// (4) The client-side criterion.
	out = append(out, read2HexLogSkip())
	return out
}

// evalLongModelChunking asserts the "maximize the number of points read in each
// holding register read operation" criterion for a model longer than 125
// registers.
func evalLongModelChunking(c *Conversation, models []Model) finding {
	claim := "a model longer than 125 registers was read in multiple reads that maximise the registers " +
		"retrieved per request"
	method := "the quantity field of each FC 0x03 request covering a model body longer than the " +
		"125-register Modbus limit"
	var long []Model
	for _, m := range models {
		if m.Length > MaxReadQuantity && m.BodyRead {
			long = append(long, m)
		}
	}
	if len(long) == 0 {
		return skipf(claim, method,
			"no model whose body exceeds %d registers was read within this test case's frames, so the "+
				"multi-read case did not arise. The server's chain does contain %d model(s); a model "+
				"longer than the limit is needed to exercise this criterion",
			MaxReadQuantity, len(models))
	}
	m := long[0]
	spans := append([]ReadSpan(nil), m.Reads...)
	sort.Slice(spans, func(i, j int) bool { return spans[i].Start < spans[j].Start })
	// Every read except the last one covering the body must be at the ceiling,
	// or the client left registers on the table it could have fetched.
	shortIdx := -1
	for i := 0; i < len(spans)-1; i++ {
		if spans[i].Quantity < MaxReadQuantity {
			shortIdx = i
			break
		}
	}
	ex := c.Exchanges[spans[0].Exchange]
	if shortIdx >= 0 {
		s := spans[shortIdx]
		return bytesf(claim, method, certify.Warn, fromDUT, ex.Request.Start, ex.Request.End,
			"model %d's %d-register body was read as %s; request %d asked for only %d of the %d "+
				"registers available. The procedure allows a short read to avoid splitting a "+
				"multi-register point, so this is reported rather than failed: confirming which it is "+
				"needs the model's point map",
			m.ID, m.Length, describeSpans(spans), shortIdx+1, s.Quantity, MaxReadQuantity)
	}
	return bytesf(claim, method, certify.Pass, fromDUT, ex.Request.Start, ex.Request.End,
		"model %d's %d-register body was read as %s — every request but the last asked for the full "+
			"%d-register maximum, so the body was retrieved in the fewest reads the limit allows. "+
			"First request cited in full: [%s]",
		m.ID, m.Length, describeSpans(spans), MaxReadQuantity, ex.Request.Hex())
}

// evalReadGranularity reports the DUT's read-size distribution. It is the same
// observation for READ-1 and READ-2 read in opposite directions, so both rows
// share it and each supplies the verdict its criterion implies.
func evalReadGranularity(c *Conversation, whenBlock certify.Verdict) finding {
	claim := "the DUT's register reads were whole-block reads rather than one request per point"
	method := "distribution of the quantity field over every FC 0x03 / 0x04 request in the window"
	reads := c.Reads()
	if len(reads) == 0 {
		return skipf(claim, method, "no register reads were observed")
	}
	// The metric is registers, not requests. Counting requests would call a
	// client "point-oriented" merely because its chain walk issues many
	// two-register header probes — which are not point reads at all, and which
	// a block reader necessarily emits.
	narrow, total := 0, 0
	var blockRegs, allRegs int
	var minQ, maxQ uint16 = 0xFFFF, 0
	for _, ex := range reads {
		_, q, _ := ex.Request.ReadRequest()
		total++
		allRegs += int(q)
		if q <= 4 {
			narrow++
		} else {
			blockRegs += int(q)
		}
		if q < minQ {
			minQ = q
		}
		if q > maxQ {
			maxQ = q
		}
	}
	first := reads[0].Request
	block := allRegs > 0 && blockRegs*2 >= allRegs
	v := whenBlock
	if !block {
		v = certify.Warn
	}
	return bytesf(claim, method, v, fromDUT, first.Start, first.End,
		"%d read request(s) fetching %d register(s): quantities from %d to %d; %d request(s) asked for 4 "+
			"registers or fewer (a model-header probe or a single point) and %d register(s) — %d%% of the "+
			"total — arrived in wider block reads. The traffic is %s",
		total, allRegs, minQ, maxQ, narrow, blockRegs, pct(blockRegs, allRegs),
		map[bool]string{true: "block-oriented", false: "dominated by narrow, point-sized reads"}[block])
}

func pct(n, d int) int {
	if d == 0 {
		return 0
	}
	return n * 100 / d
}

func read2HexLogSkip() finding {
	return skipf(
		"the DUT logged every point of every PICS model, with the log data represented as hex strings",
		"inspection of the client's own log output",
		"the criterion is about the CLIENT's log, not about the wire: it requires the CUT to render every "+
			"point of every model as a hex string. The DUT is an autonomous gateway, not a point browser "+
			"— it decodes the measurement and identity points its reconcilers consume and journals those, "+
			"and emits no per-point hex dump. The bytes themselves ARE in this bundle (every response is "+
			"in the capture, and the cited assertions quote the ADUs verbatim in hex), but that is the "+
			"bench's rendering, not the DUT's, and the two must not be confused. Promoting this row to "+
			"full requires a diagnostic mode on the DUT's Modbus client that dumps each decoded point "+
			"with its raw registers")
}

func describeSpans(spans []ReadSpan) string {
	parts := make([]string, 0, len(spans))
	for _, s := range spans {
		parts = append(parts, fmt.Sprintf("start=%d qty=%d", s.Start, s.Quantity))
	}
	return joinOr(parts, "no reads")
}

// ── READ-1 — Single Point Reads ───────────────────────────────────────────────

func checkREAD1(ctx context.Context, rc *certify.RunCtx) (certify.Result, error) {
	o, why := newObserver(rc)
	if o == nil {
		return certify.Skipped("%s", why), nil
	}
	if err := o.claimServer(); err != nil {
		return certify.Result{}, err
	}
	if err := o.watch(ctx, 2); err != nil {
		return certify.Result{}, err
	}
	return certify.Result{
		Verdict: certify.Skip,
		Notes: "the DUT exposes no way to request an individual SunSpec point, so the one-request-" +
			"per-point pattern this row requires cannot be provoked. What the DUT does instead was " +
			"observed and is cited.",
		Cite: func(_ context.Context, ev *certify.Evidence) ([]certify.Assertion, error) {
			claim := "the DUT read every point of the Common Model individually, one request per point"
			c, pre, ok := citeConversation(ev, o, claim)
			if !ok {
				return emit(ev, c, pre), nil
			}
			fs := []finding{assertAttributionSound(ev, o)}
			fs = append(fs, evalREAD1(c)...)
			return emit(ev, c, fs), nil
		},
	}, nil
}

// evalREAD1 is READ-1's decision logic. It returns the criterion's SKIP with
// the reason, plus the wire observation of what the DUT actually does — cited,
// but carrying the SKIP verdict, so an honest record of the DUT's read pattern
// cannot inflate this row's verdict to PASS.
func evalREAD1(c *Conversation) []finding {
	claim := "the DUT read every point of the Common Model individually, one request per point"
	method := "one FC 0x03 request per point, each with a quantity matching that point's register width"

	reads := c.Reads()
	perPoint := 0
	for _, ex := range reads {
		if _, q, _ := ex.Request.ReadRequest(); q <= 4 {
			perPoint++
		}
	}
	var out []finding
	if len(reads) > 0 && perPoint == len(reads) {
		// A client that genuinely reads point by point would pass this row, and
		// the check must be able to say so rather than always skipping.
		first := reads[0].Request
		out = append(out, bytesf(claim, method, certify.Pass, fromDUT, first.Start, first.End,
			"all %d read request(s) asked for 4 registers or fewer — the width of a single SunSpec "+
				"point or narrower. First request cited in full: [%s]", len(reads), first.Hex()))
		out = append(out, read1HexLogSkip())
		return out
	}

	out = append(out, skipf(claim, method,
		"the DUT issues no per-point reads: %d of its %d read request(s) asked for more than 4 "+
			"registers. It reads whole SunSpec model blocks through its block reader and decodes them "+
			"in memory, and exposes no interface — command, API or configuration — for requesting one "+
			"named point. The pattern this row requires therefore cannot be provoked on this DUT at "+
			"all; it is a capability gap in the device, not in the bench, and no amount of sim work "+
			"promotes it. Recording it as a SKIP with this reason is the only honest verdict",
		len(reads)-perPoint, len(reads)))
	// The observation, cited, carrying SKIP so it informs without inflating.
	out = append(out, evalReadGranularity(c, certify.Skip))
	out = append(out, read1HexLogSkip())
	return out
}

func read1HexLogSkip() finding {
	return skipf(
		"the DUT logged all points for all PICS models with the log data represented as hex strings",
		"inspection of the client's own log output",
		"same client-side-log criterion as READ-2: the DUT journals decoded measurements, not per-point "+
			"hex. See the READ-2 assertion of the same claim for the capability that would promote it")
}
