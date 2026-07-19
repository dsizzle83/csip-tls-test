package main

// gw.go is the LEXA-GW proof backend: the dashboard's /api/gw/* endpoints that
// present LIVE, VERIFIABLE evidence the secure DER gateway (lexa-gw, the CC93
// dev kit at 69.0.0.2) is behaving as designed. It is deliberately PURE-GO (no
// cgo/mbtls) — every live signal comes from an HTTP read of a desktop-side sim's
// /state, a TCP reachability probe of a gateway/sim port, or the JSON a
// gw-mayhem run already wrote to disk. Three surfaces:
//
//   GET  /api/gw/status          — the live 4-interface topology + gateway
//                                  reachability + the DERs' current telemetry.
//   GET  /api/gw/qa/report       — the newest gw-mayhem verdict board (the
//                                  adversarial-QA proof: every scenario's
//                                  verdict + evidence findings), read from
//                                  logs/gw-mayhem/*.json.
//   POST /api/gw/qa/run {mode}    — kick off a live gw-mayhem run through the
//   GET  /api/gw/qa/run/status      isolation wrapper (scripts/gw-qa-run.sh) so
//                                  a viewer can watch the attacks get refused in
//                                  real time; status streams the per-scenario
//                                  verdicts as they land.
//
// The gw-mayhem engine + the scripts/gw-qa-run.sh wrapper (which pauses the
// standing aggregator and drains the gateway's mbaps session budget so a run is
// deterministic) are the SAME artifacts an operator runs by hand — the dashboard
// only shells out to them, it never re-implements a verdict.

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// gwDriver holds the immutable wiring for the LEXA-GW proof endpoints.
type gwDriver struct {
	repoRoot string // csip-tls-test root (logs/, scripts/, bin/ are resolved under it)
	gwHost   string // the gateway host, e.g. "69.0.0.2"
	modsim   string // plain southbound DER sim /state base, e.g. "http://127.0.0.1:6020"
	mbapsdev string // secure southbound DER sim /state base, e.g. "http://127.0.0.1:6031"
	gridPort int    // CSIP/gridsim listener port on the desktop (reachability probe)

	hc *http.Client

	mu  sync.Mutex
	run *gwRun // the in-flight (or last) live run; nil until the first run
}

// newGWDriver builds the driver. Ports mirror scripts/bench-sims-up.sh's
// desktop layout (modsim simapi 6020, mbapsdev simapi 6031, gridsim 11113).
func newGWDriver(repoRoot, gwHost, modsim, mbapsdev string, gridPort int) *gwDriver {
	return &gwDriver{
		repoRoot: repoRoot, gwHost: gwHost, modsim: modsim, mbapsdev: mbapsdev, gridPort: gridPort,
		hc: &http.Client{Timeout: 2500 * time.Millisecond},
	}
}

func (g *gwDriver) register(mux *http.ServeMux) {
	mux.HandleFunc("/api/gw/status", g.handleStatus)
	mux.HandleFunc("/api/gw/qa/report", g.handleQAReport)
	mux.HandleFunc("/api/gw/qa/run", g.handleQARun)
	mux.HandleFunc("/api/gw/qa/run/status", g.handleQARunStatus)
}

// ── live status ──────────────────────────────────────────────────────────────

// gwIface is one row of the live interface topology.
type gwIface struct {
	ID     string `json:"id"`
	Label  string `json:"label"`
	Dir    string `json:"dir"`    // "south" | "north"
	Proto  string `json:"proto"`  // human protocol name
	Secure bool   `json:"secure"` // mTLS-protected?
	Up     bool   `json:"up"`
	Detail string `json:"detail"`           // endpoint / where it lives
	Metric string `json:"metric,omitempty"` // a live number that proves it's moving
}

type gwStatus struct {
	Host       string    `json:"host"`
	Reachable  bool      `json:"reachable"` // the gateway's northbound mbaps :802 accepts a TCP connection
	Interfaces []gwIface `json:"interfaces"`
	UpdatedAt  string    `json:"updated_at"`
}

func (g *gwDriver) handleStatus(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 4*time.Second)
	defer cancel()

	gw802 := tcpUp(ctx, net.JoinHostPort(g.gwHost, "802"))
	plainW, plainWmax, _, plainUp := g.derTelem(ctx, g.modsim, false)
	secW, _, secCap, secUp := g.derTelem(ctx, g.mbapsdev, true)
	csipUp := tcpUp(ctx, net.JoinHostPort("127.0.0.1", itoa(g.gridPort)))

	st := gwStatus{
		Host:      g.gwHost,
		Reachable: gw802,
		UpdatedAt: nowStamp(),
		Interfaces: []gwIface{
			{
				ID: "sb-plain", Label: "Southbound · SunSpec Modbus (plain)", Dir: "south",
				Proto: "SunSpec Modbus/TCP", Secure: false, Up: plainUp,
				Detail: "modsim DER → gw poll", Metric: telemMetric(plainUp, plainW, plainWmax, -1),
			},
			{
				ID: "sb-secure", Label: "Southbound · Secure SunSpec Modbus (mbaps/mTLS)", Dir: "south",
				Proto: "Secure SunSpec Modbus (mTLS, wolfSSL)", Secure: true, Up: secUp,
				Detail: "mbapsdev DER → gw poll", Metric: telemMetric(secUp, secW, -1, secCap),
			},
			{
				ID: "nb-mbaps", Label: "Northbound · Secure SunSpec Modbus (aggregator)", Dir: "north",
				Proto: "Secure SunSpec Modbus (mTLS, RBAC)", Secure: true, Up: gw802,
				Detail: g.gwHost + ":802 (gateway mbaps server)", Metric: g.lastAggVerdict(),
			},
			{
				ID: "nb-csip", Label: "Northbound · IEEE 2030.5 / CSIP (mTLS)", Dir: "north",
				Proto: "IEEE 2030.5 / CSIP (mTLS)", Secure: true, Up: csipUp,
				Detail: "gridsim head-end :" + itoa(g.gridPort), Metric: upWord(csipUp),
			},
		},
	}
	writeGWJSON(w, http.StatusOK, st)
}

// derTelem fetches a DER sim's /state and pulls the live active power (W), its
// nameplate, and (secure sim only) the applied WMaxLimPct — proof the gateway is
// polling AND controlling the device. wrapped=true reads mbapsdev's .model
// envelope; plain reads modsim's top level.
func (g *gwDriver) derTelem(ctx context.Context, base string, wrapped bool) (w, wmax, cap float64, up bool) {
	var doc map[string]any
	if err := g.getJSON(ctx, base+"/state", &doc); err != nil {
		return -1, -1, -1, false
	}
	if wrapped {
		if m, ok := doc["model"].(map[string]any); ok {
			doc = m
		}
	}
	meas, _ := doc["measurements"].(map[string]any)
	np, _ := doc["nameplate"].(map[string]any)
	ctl, _ := doc["controls"].(map[string]any)
	w, wmax, cap = -1, -1, -1
	if meas != nil {
		w = numOr(meas["W_W"], -1)
	}
	if np != nil {
		wmax = numOr(np["wmax_W"], -1)
	}
	if ctl != nil {
		cap = numOr(ctl["WMaxLimPct_pct"], -1)
	}
	return w, wmax, cap, true
}

// lastAggVerdict summarises the standing aggregator loop's most recent northbound
// run against the gateway :802 (the run JSON scripts/bench-sims-up.sh writes under
// logs/bench/agg). Best-effort: an empty string when nothing has run yet.
func (g *gwDriver) lastAggVerdict() string {
	dir := filepath.Join(g.repoRoot, "logs", "bench", "agg")
	f := newestUnder(dir, ".json")
	if f == "" {
		return ""
	}
	var doc map[string]any
	if b, err := os.ReadFile(f); err == nil {
		_ = json.Unmarshal(b, &doc)
	}
	if v, ok := doc["verdict"].(string); ok && v != "" {
		return "last run: " + v
	}
	return ""
}

// ── QA verdict board (the proof) ─────────────────────────────────────────────

func (g *gwDriver) handleQAReport(w http.ResponseWriter, r *http.Request) {
	// The authoritative board is the MOST COMPREHENSIVE report on disk (highest
	// scenario count), not merely the newest — so a 7-scenario "quick" live run
	// never displaces the full 37-scenario suite proof; a fresh FULL run (equal
	// or greater count, newer mtime) does win the tie.
	f := bestReportFile(filepath.Join(g.repoRoot, "logs", "gw-mayhem"))
	if f == "" {
		writeGWJSON(w, http.StatusOK, map[string]any{"available": false})
		return
	}
	b, err := os.ReadFile(f)
	if err != nil {
		http.Error(w, "read report: "+err.Error(), http.StatusInternalServerError)
		return
	}
	fi, _ := os.Stat(f)
	board, err := parseGWBoard(b)
	if err != nil {
		http.Error(w, "parse report: "+err.Error(), http.StatusInternalServerError)
		return
	}
	board.Available = true
	board.Source = filepath.Base(f)
	if fi != nil {
		board.GeneratedAt = fi.ModTime().Format(time.RFC3339)
	}
	writeGWJSON(w, http.StatusOK, board)
}

// gwReport is one scenario's verdict as the frontend consumes it (a projection
// of the gw-mayhem report shape — see sim/gw-mayhem/scenario.go gwReport).
type gwReport struct {
	ID       string   `json:"id"`
	Desc     string   `json:"desc"`
	Category string   `json:"category"`
	Verdict  string   `json:"verdict"`
	Expected []string `json:"expected"`
	OnPin    bool     `json:"on_pin"` // verdict matched its expected pin (gate-green)
	Security bool     `json:"security"`
	Findings []string `json:"findings"`
	Duration float64  `json:"duration_s"`
}

// gwBoard is the whole verdict board.
type gwBoard struct {
	Available   bool       `json:"available"`
	Source      string     `json:"source,omitempty"`
	GeneratedAt string     `json:"generated_at,omitempty"`
	Total       int        `json:"total"`
	Pass        int        `json:"pass"`
	Fail        int        `json:"fail"`
	Skipped     int        `json:"skipped"` // board-only scenarios that skip (expected INCONCLUSIVE)
	GateGreen   bool       `json:"gate_green"`
	Reports     []gwReport `json:"reports"`
}

// parseGWBoard reshapes a gw-mayhem batch-summary JSON into the board the UI
// renders. It classifies each scenario by whether its verdict landed ON its
// expected pin (gate-green) — a board scenario skipping as an expected
// INCONCLUSIVE is "skipped", not a failure.
func parseGWBoard(raw []byte) (*gwBoard, error) {
	var in struct {
		Total   int `json:"total"`
		Reports []struct {
			ID       string   `json:"id"`
			Desc     string   `json:"desc"`
			Category string   `json:"category"`
			Security bool     `json:"security"`
			Verdict  string   `json:"verdict"`
			Expected []string `json:"expected_verdicts"`
			OnPin    bool     `json:"verdict_expected"`
			Findings []string `json:"findings"`
			Duration float64  `json:"duration_s"`
		} `json:"reports"`
	}
	if err := json.Unmarshal(raw, &in); err != nil {
		return nil, err
	}
	b := &gwBoard{Available: true, Total: in.Total, GateGreen: true}
	for _, r := range in.Reports {
		rep := gwReport{
			ID: r.ID, Desc: r.Desc, Category: r.Category, Verdict: r.Verdict,
			Expected: r.Expected, OnPin: r.OnPin, Security: r.Security,
			Findings: r.Findings, Duration: r.Duration,
		}
		b.Reports = append(b.Reports, rep)
		switch {
		case !r.OnPin:
			b.Fail++
			b.GateGreen = false
		case r.Verdict == "PASS":
			b.Pass++
		default: // an EXPECTED non-PASS (a board scenario's INCONCLUSIVE skip)
			b.Skipped++
		}
	}
	return b, nil
}

// ── live run ─────────────────────────────────────────────────────────────────

// gwRun is the state of one live gw-mayhem run.
type gwRun struct {
	Mode      string     `json:"mode"`  // "quick" | "full"
	State     string     `json:"state"` // "running" | "done" | "error"
	StartedAt string     `json:"started_at"`
	Err       string     `json:"error,omitempty"`
	Lines     []string   `json:"lines"`             // per-scenario verdict lines, streamed as they land
	Board     *gwBoard   `json:"board,omitempty"`   // populated on completion
	cancel    context.CancelFunc `json:"-"`
	outPath   string     `json:"-"`
}

// quickProofIDs is the curated fast set for the "Run live proof" button: the
// security-critical authz + transport scenarios that each finish in well under a
// second, so a viewer watches every verdict turn green in a couple of seconds
// (the comm-loss / compound / southbound families have 20-40 s holds and belong
// to the full suite, not the live-demo path).
var quickProofIDs = []string{
	"authz-role-denial-matrix",
	"authz-cert-negatives",
	"authz-out-of-range-setpoint",
	"authz-malformed-writes",
	"transport-session-flood",
	"transport-renegotiation-refusal",
	"transport-resume-after-drop",
}

func (g *gwDriver) handleQARun(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	var body struct {
		Mode string `json:"mode"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	mode := body.Mode
	if mode != "full" {
		mode = "quick"
	}

	g.mu.Lock()
	if g.run != nil && g.run.State == "running" {
		g.mu.Unlock()
		http.Error(w, "a run is already in progress", http.StatusConflict)
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	run := &gwRun{Mode: mode, State: "running", StartedAt: nowStamp(), cancel: cancel, Lines: []string{}}
	g.run = run
	g.mu.Unlock()

	go g.execRun(ctx, run)
	writeGWJSON(w, http.StatusAccepted, run.snapshot())
}

func (g *gwDriver) handleQARunStatus(w http.ResponseWriter, r *http.Request) {
	g.mu.Lock()
	run := g.run
	g.mu.Unlock()
	if run == nil {
		writeGWJSON(w, http.StatusOK, map[string]any{"state": "idle"})
		return
	}
	writeGWJSON(w, http.StatusOK, run.snapshot())
}

// execRun shells out to scripts/gw-qa-run.sh (the isolation wrapper) and streams
// its per-scenario verdict lines into the run state, then loads the emitted JSON
// board on completion. The wrapper handles pausing/restoring the aggregator.
func (g *gwDriver) execRun(ctx context.Context, run *gwRun) {
	out := filepath.Join(g.repoRoot, "logs", "gw-mayhem", "live-"+strings.ReplaceAll(run.StartedAt, ":", "")+".json")
	run.outPath = out
	args := []string{"-json", "-out", out}
	if run.Mode == "quick" {
		args = append(args, "-only", strings.Join(quickProofIDs, ","))
	}
	cmd := exec.CommandContext(ctx, filepath.Join(g.repoRoot, "scripts", "gw-qa-run.sh"), args...)
	cmd.Dir = g.repoRoot

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		g.finishRun(run, "error", "pipe: "+err.Error())
		return
	}
	cmd.Stderr = cmd.Stdout // fold stderr in (wrapper prints its pause/drain lines there)
	if err := cmd.Start(); err != nil {
		g.finishRun(run, "error", "start: "+err.Error())
		return
	}

	// Stream stdout line-by-line; keep the per-scenario verdict lines (they start
	// with a verdict word) so the UI can tick them off live.
	sc := bufio.NewScanner(stdout)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		if v := scenarioVerdictLine(sc.Text()); v != "" {
			g.mu.Lock()
			run.Lines = append(run.Lines, v)
			g.mu.Unlock()
		}
	}
	waitErr := cmd.Wait()

	// Load the board the run wrote (present even on a non-zero gate exit).
	if b, err := os.ReadFile(out); err == nil {
		if board, perr := parseGWBoard(b); perr == nil {
			board.Available = true
			board.Source = filepath.Base(out)
			board.GeneratedAt = nowStamp()
			g.mu.Lock()
			run.Board = board
			g.mu.Unlock()
		}
	}
	if waitErr != nil && (run.Board == nil) {
		g.finishRun(run, "error", "run: "+waitErr.Error())
		return
	}
	g.finishRun(run, "done", "")
}

func (g *gwDriver) finishRun(run *gwRun, state, errStr string) {
	g.mu.Lock()
	run.State = state
	run.Err = errStr
	g.mu.Unlock()
}

func (run *gwRun) snapshot() gwRun {
	// shallow copy under the caller's lock convention: handlers hold g.mu around
	// reads; execRun appends under g.mu. Copy the slice header + fields.
	cp := *run
	cp.Lines = append([]string(nil), run.Lines...)
	return cp
}

// scenarioVerdictLine keeps a runner output line only if it is a per-scenario
// verdict row (PASS/FAIL/…) or the roll-up, normalising leading whitespace.
func scenarioVerdictLine(line string) string {
	t := strings.TrimSpace(line)
	for _, p := range []string{"PASS", "FAIL", "DEGRADED", "BLIND", "INCONCLUSIVE", "Roll-up", "[PASS]", "[FAIL]"} {
		if strings.HasPrefix(t, p) {
			return t
		}
	}
	return ""
}

// ── small helpers ────────────────────────────────────────────────────────────

func (g *gwDriver) getJSON(ctx context.Context, url string, v any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := g.hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("status %d", resp.StatusCode)
	}
	return json.NewDecoder(resp.Body).Decode(v)
}

func tcpUp(ctx context.Context, addr string) bool {
	d := net.Dialer{Timeout: 1500 * time.Millisecond}
	c, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return false
	}
	_ = c.Close()
	return true
}

// bestReportFile picks the most authoritative gw-mayhem report under dir: the
// one with the highest scenario count (total), breaking ties by newest mtime.
// This keeps the canonical verdict board on the comprehensive full-suite run
// even after an on-demand "quick" run writes a smaller report alongside it.
func bestReportFile(dir string) string {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return ""
	}
	best, bestTotal := "", -1
	var bestMod time.Time
	for _, e := range ents {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		p := filepath.Join(dir, e.Name())
		b, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		var head struct {
			Total int `json:"total"`
		}
		if json.Unmarshal(b, &head) != nil {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		mod := info.ModTime()
		if head.Total > bestTotal || (head.Total == bestTotal && mod.After(bestMod)) {
			best, bestTotal, bestMod = p, head.Total, mod
		}
	}
	return best
}

// newestUnder returns the newest file (by mtime) with the given suffix directly
// under dir, or "" if none.
func newestUnder(dir, suffix string) string {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return ""
	}
	type fm struct {
		path string
		mod  time.Time
	}
	var cands []fm
	for _, e := range ents {
		if e.IsDir() || !strings.HasSuffix(e.Name(), suffix) {
			continue
		}
		if info, err := e.Info(); err == nil {
			cands = append(cands, fm{filepath.Join(dir, e.Name()), info.ModTime()})
		}
	}
	if len(cands) == 0 {
		return ""
	}
	sort.Slice(cands, func(i, j int) bool { return cands[i].mod.After(cands[j].mod) })
	return cands[0].path
}

func numOr(v any, def float64) float64 {
	if f, ok := v.(float64); ok {
		return f
	}
	return def
}

func telemMetric(up bool, w, wmax, cap float64) string {
	if !up {
		return "unreachable"
	}
	parts := []string{}
	if w >= 0 {
		if wmax > 0 {
			parts = append(parts, fmt.Sprintf("W=%.0f/%.0f", w, wmax))
		} else {
			parts = append(parts, fmt.Sprintf("W=%.0f", w))
		}
	}
	if cap >= 0 {
		parts = append(parts, fmt.Sprintf("cap=%.0f%%", cap))
	}
	if len(parts) == 0 {
		return "polled"
	}
	return strings.Join(parts, " · ")
}

func upWord(up bool) string {
	if up {
		return "reachable"
	}
	return "unreachable"
}

func writeGWJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func nowStamp() string { return time.Now().Format(time.RFC3339) }

func itoa(n int) string { return fmt.Sprintf("%d", n) }
