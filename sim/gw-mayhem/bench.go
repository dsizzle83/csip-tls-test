package gwmayhem

// bench.go is the wave-2 BENCH DRIVER: the desktop-side HTTP layer the
// CSIP-northbound-malformation (family A) and southbound-fault-injection (family
// B) scenarios reach through to (a) ARM an adversary — a gridsim malformation /
// WAN outage / clock warp on the head-end, or a sim register/transport fault on a
// DER — and (b) SAMPLE the gateway's effect on its DERs from the sims' own
// /state, the one observation channel that stays reachable when the gateway's
// northbound :802 server is not (its dev /status is loopback-only, confirmed by
// the live probe).
//
// Every call here is a DESKTOP-SIDE / CLIENT-SIDE fault drive against a sim's
// admin API (gridsim :11114, modsim :6020, mbapsdev :6031) — never a
// board-mutating step against the gateway itself. The gateway is only OBSERVED,
// never reconfigured, so a live run is safe to arm.
//
// The observables are deliberately narrow and honest: the DER's applied
// WMaxLimPct (the gateway's projected curtailment) and, for the SECURE device,
// the gateway's live poll-request counter (a mbaps device reports its sessions —
// an advancing counter proves the gateway's southbound loop is alive; a stalled
// one is comm-loss). A hermetic run points these same helpers at the httptest
// bench stub (gwbenchstub) instead of the live sims, so the families' sampling
// and the oracles' judging are provable with no bench (make test-fast).

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"time"
)

// BenchConfig wires a run to the desktop bench: the gridsim head-end admin API
// and the two southbound DER sims (plain modsim + secure mbapsdev). A zero
// BenchConfig disables the wave-2 families (their arms report a setup error the
// oracle turns into INCONCLUSIVE) — the wave-1 authz families need no bench.
type BenchConfig struct {
	GridsimAdmin string      // e.g. http://127.0.0.1:11114 (POST /admin/malform|outage|clock)
	Plain        DERSim      // modsim: tcp/plain SunSpec inverter
	Secure       DERSim      // mbapsdev: mbaps/mTLS SunSpec inverter
	Timing       BenchTiming // settle/sample cadence (tiny in tests, live-sized on the bench)
}

// DERSim describes one southbound DER simulator's admin surface.
type DERSim struct {
	Name    string // "inv-plain" | "inv-secure" (evidence label)
	BaseURL string // e.g. http://127.0.0.1:6020 (simapi: /state /fault /inject /control)
	Secure  bool   // true = mbaps device (state is wrapped in .model and carries .sessions)
}

// configured reports whether a DER sim is wired.
func (d DERSim) configured() bool { return d.BaseURL != "" }

// BenchTiming is the sampling cadence a wave-2 arm uses: wait Settle after arming
// the adversary (so the gateway has walked/polled at least once under the fault),
// then take Samples DER-state reads Interval apart.
type BenchTiming struct {
	Settle   time.Duration
	Interval time.Duration
	Samples  int
}

// DefaultBenchTiming is the live cadence: long enough that the gateway completes
// a northbound walk + a southbound poll cycle under the armed fault before the
// first sample, and that a comm-loss/hold shows across several samples. Tests
// override this with a near-zero cadence.
func DefaultBenchTiming() BenchTiming {
	return BenchTiming{Settle: 8 * time.Second, Interval: 3 * time.Second, Samples: 5}
}

// timing returns the run's cadence, defaulting any unset field to the live value
// so a partially-specified BenchConfig still behaves.
func (b BenchConfig) timing() BenchTiming {
	t := b.Timing
	def := DefaultBenchTiming()
	if t.Settle <= 0 {
		t.Settle = def.Settle
	}
	if t.Interval <= 0 {
		t.Interval = def.Interval
	}
	if t.Samples <= 0 {
		t.Samples = def.Samples
	}
	return t
}

// benchReady reports whether the bench is wired enough for a wave-2 family to
// run: the gridsim admin (family A) or at least one DER sim (family B).
func (b BenchConfig) benchReady() bool {
	return b.GridsimAdmin != "" || b.Plain.configured() || b.Secure.configured()
}

// benchSleep waits d, returning early if ctx is cancelled — every wave-2 hold is
// interruptible so a SIGINT during a long live sample window stops promptly.
func benchSleep(ctx context.Context, d time.Duration) {
	if d <= 0 {
		return
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
	case <-t.C:
	}
}

// benchHTTP is the small HTTP client the bench driver uses. Every request is
// bounded (a wedged sim admin must not hang a scenario) and best-effort — an arm
// or sample failure is recorded as evidence, never a panic.
var benchHTTP = &http.Client{Timeout: 6 * time.Second}

// postJSON POSTs body as JSON to url and discards the response, returning an
// error for a transport failure or a non-2xx status.
func postJSON(ctx context.Context, url string, body any) error {
	raw, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(raw))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := benchHTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("POST %s: status %d", url, resp.StatusCode)
	}
	return nil
}

// getJSON GETs url and decodes the JSON body into v.
func getJSON(ctx context.Context, url string, v any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := benchHTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("GET %s: status %d", url, resp.StatusCode)
	}
	return json.NewDecoder(resp.Body).Decode(v)
}

// ── Adversary drives (family A: the gridsim head-end) ────────────────────────

// armMalform arms a gridsim malformed-resource kind (POST /admin/malform).
func (b BenchConfig) armMalform(ctx context.Context, kind string) error {
	return postJSON(ctx, b.GridsimAdmin+"/admin/malform", map[string]any{"kind": kind})
}

// clearMalform clears any armed gridsim malformation.
func (b BenchConfig) clearMalform(ctx context.Context) error {
	return postJSON(ctx, b.GridsimAdmin+"/admin/malform", map[string]any{"clear": true})
}

// armOutage arms a gridsim northbound WAN outage ("down" | "hang" | "slow").
// durationS auto-clears it on the gridsim side so an aborted run never leaves the
// bench northbound-dead.
func (b BenchConfig) armOutage(ctx context.Context, mode string, durationS, hangS int) error {
	return postJSON(ctx, b.GridsimAdmin+"/admin/outage",
		map[string]any{"mode": mode, "duration_s": durationS, "hang_s": hangS})
}

// clearOutage clears any armed gridsim outage.
func (b BenchConfig) clearOutage(ctx context.Context) error {
	return postJSON(ctx, b.GridsimAdmin+"/admin/outage", map[string]any{"clear": true})
}

// setClock warps the gridsim's served CSIP clock by offsetS seconds (POST
// /admin/clock) — the head-end clock-jump adversary.
func (b BenchConfig) setClock(ctx context.Context, offsetS int64) error {
	return postJSON(ctx, b.GridsimAdmin+"/admin/clock", map[string]any{"offset_s": offsetS})
}

// ── Adversary drives (family B: a southbound DER sim) ────────────────────────

// armFault arms a fault kind on a DER sim (POST /fault). delayS is optional
// (0 omits it).
func (b BenchConfig) armFault(ctx context.Context, sim DERSim, kind string, delayS float64) error {
	body := map[string]any{"kind": kind}
	if delayS > 0 {
		body["delay_s"] = delayS
	}
	return postJSON(ctx, sim.BaseURL+"/fault", body)
}

// clearFault clears a fault kind on a DER sim.
func (b BenchConfig) clearFault(ctx context.Context, sim DERSim, kind string) error {
	return postJSON(ctx, sim.BaseURL+"/fault", map[string]any{"kind": kind, "clear": true})
}

// controlSim sends an animation-control command to a DER sim (POST /control):
// "pause" freezes its register world (a frozen/stale device), "resume" restarts
// it. The gateway keeps polling either way; the fault is that the values stop
// evolving while the world moves on.
func (b BenchConfig) controlSim(ctx context.Context, sim DERSim, cmd string) error {
	return postJSON(ctx, sim.BaseURL+"/control", map[string]any{"cmd": cmd})
}

// ── Observation (the sims' /state) ───────────────────────────────────────────

// derSnapshot is the narrow view of a DER sim's /state the wave-2 oracles judge:
// the gateway's applied curtailment and (secure device only) the gateway's live
// poll-request counter.
type derSnapshot struct {
	AppliedPct    float64 // applied WMaxLimPct (0..100 nominal); NaN if unreadable
	Conn          bool    // the DER reports itself connected/energized
	HasPoll       bool    // the sim exposes a gateway poll-request counter (secure/mbaps only)
	PollRequests  int     // total requests the gateway has issued to this device
	GatewaySessed bool    // the sim currently has a live gateway session
}

// derStateWire matches both /state shapes: modsim serves the model fields at the
// top level, mbapsdev wraps them under "model" and adds "sessions".
type derStateWire struct {
	Advanced *advWire  `json:"advanced"`
	Controls *ctlWire  `json:"controls"`
	Model    *struct { // mbapsdev wrapping
		Advanced *advWire `json:"advanced"`
		Controls *ctlWire `json:"controls"`
	} `json:"model"`
	Sessions []struct {
		Peer     string `json:"peer"`
		Role     string `json:"role"`
		Requests int    `json:"requests"`
	} `json:"sessions"`
}

type advWire struct {
	Wmax704 *struct {
		Ena bool    `json:"ena"`
		Pct float64 `json:"pct"`
	} `json:"wmaxlimpct_704"`
}

type ctlWire struct {
	WMaxLimPctPct float64 `json:"WMaxLimPct_pct"`
	Conn          int     `json:"Conn"`
}

// readDER fetches and parses a DER sim's /state into a derSnapshot.
func (b BenchConfig) readDER(ctx context.Context, sim DERSim) (derSnapshot, error) {
	var wire derStateWire
	if err := getJSON(ctx, sim.BaseURL+"/state", &wire); err != nil {
		return derSnapshot{AppliedPct: math.NaN()}, err
	}
	adv, ctl := wire.Advanced, wire.Controls
	if wire.Model != nil { // mbapsdev
		adv, ctl = wire.Model.Advanced, wire.Model.Controls
	}
	snap := derSnapshot{AppliedPct: math.NaN()}
	// Prefer the 704 applied-limit projection (the gateway-commanded curtailment);
	// fall back to the top-level control mirror.
	switch {
	case adv != nil && adv.Wmax704 != nil:
		snap.AppliedPct = adv.Wmax704.Pct
	case ctl != nil:
		snap.AppliedPct = ctl.WMaxLimPctPct
	}
	if ctl != nil {
		snap.Conn = ctl.Conn != 0
	}
	if len(wire.Sessions) > 0 {
		snap.HasPoll = true
		snap.GatewaySessed = true
		for _, s := range wire.Sessions {
			snap.PollRequests += s.Requests
		}
	}
	return snap, nil
}

// clearBench best-effort clears every adversary this run could have armed —
// called on teardown so an aborted scenario never leaves the bench faulted. The
// gridsim outage/clock are cleared too (clock back to 0 offset).
func (b BenchConfig) clearBench(ctx context.Context) {
	if b.GridsimAdmin != "" {
		_ = b.clearMalform(ctx)
		_ = b.clearOutage(ctx)
		_ = b.setClock(ctx, 0)
	}
}

// absurdPct reports whether an applied WMaxLimPct is out of the logical [0,100]
// range (with a small rounding margin) or a NaN/Inf — i.e. a value no conformant
// gateway should ever project onto a DER. A readable-but-NaN applied pct is NOT
// absurd on its own (the point may be unimplemented this cycle); the caller
// distinguishes "unreadable" from "read an absurd number".
func absurdPct(pct float64) bool {
	if math.IsNaN(pct) || math.IsInf(pct, 0) {
		return false // unreadable, not an observed absurd application
	}
	return pct > 100.5 || pct < -0.5
}

// isCap reports whether an applied pct is a real curtailment (a safe cap below
// ~uncapped), the baseline value the fail-closed invariant says the gateway must
// HOLD through a head-end fault.
func isCap(pct float64) bool {
	return !math.IsNaN(pct) && !math.IsInf(pct, 0) && pct < capThresholdPct
}

// capThresholdPct is the boundary below which an applied WMaxLimPct counts as a
// real curtailment (vs ~100% = uncapped). 99 leaves margin for the ±½-LSB
// rounding a scaled SunSpec percent incurs on the round trip.
const capThresholdPct = 99.0
