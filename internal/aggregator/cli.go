package aggregator

// cli.go is the CLI CORE (T06.9): the headless batch runner (the CI/gate path)
// and the interactive REPL, both driving the SAME primitives the campaign engine
// uses — the batch runner is a loop of Engine.Run, and the REPL is a thin shell
// over the Conn driver (Discover/WritePoint/ReadPoint/ProbeDenied/Reconnect/
// Renegotiate). There is deliberately no second protocol code path: the binary in
// sim/aggregator/main.go is wiring only (CODING_PRINCIPLES §1), and everything
// with logic lives here with its dependencies injected as function values, so the
// CLI is unit-testable without a live gateway.

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// BatchSummary is the roll-up of a headless batch run: per-verdict counts, the
// individual reports, any per-file load errors, and the number of GATE FAILURES —
// campaigns whose verdict fell outside their expected_verdicts, plus load errors.
// The binary exits non-zero when GateFailures > 0, so a campaign dir is a CI gate.
type BatchSummary struct {
	Total        int               `json:"total"`
	ByVerdict    map[Verdict]int   `json:"by_verdict"`
	GateFailures int               `json:"gate_failures"`
	Reports      []*CampaignReport `json:"reports"`
	LoadErrors   []string          `json:"load_errors,omitempty"`
}

// RunBatch runs each campaign through eng in order, writes each report under
// outDir/<id>/ (report.json + summary.md) when outDir is non-empty, prints a
// one-line verdict per campaign plus a final roll-up to w, and returns the
// BatchSummary. A campaign whose verdict is outside its expected_verdicts, and any
// load error, is a gate failure. RunBatch itself returns an error only for an
// engine MISCONFIGURATION surfaced by Engine.Run (missing ConnectAs/Resolve) — a
// failed campaign is a verdict in the roll-up, never a Go error, so the batch runs
// to completion and the gate sees every result.
func RunBatch(ctx context.Context, eng *Engine, camps []*Campaign, loadErrs []error, outDir string, jsonOut bool, w io.Writer) (BatchSummary, error) {
	sum := BatchSummary{ByVerdict: map[Verdict]int{}}
	for _, e := range loadErrs {
		sum.LoadErrors = append(sum.LoadErrors, e.Error())
		sum.GateFailures++
		fmt.Fprintf(w, "LOAD-ERR  %s\n", e.Error())
	}
	for _, c := range camps {
		rep, err := eng.Run(ctx, c)
		if err != nil {
			return sum, fmt.Errorf("aggregator: run campaign %s: %w", c.ID, err)
		}
		sum.Total++
		sum.ByVerdict[rep.Verdict]++
		sum.Reports = append(sum.Reports, rep)
		if !rep.VerdictExpected {
			sum.GateFailures++
		}
		if outDir != "" {
			if _, werr := rep.WriteReport(filepath.Join(outDir, c.ID)); werr != nil {
				fmt.Fprintf(w, "WARN write report for %s: %v\n", c.ID, werr)
			}
		}
		fmt.Fprintln(w, campaignLine(rep))
	}
	fmt.Fprintln(w, sum.rollupLine())
	if jsonOut {
		if raw, err := json.MarshalIndent(sum, "", "  "); err == nil {
			fmt.Fprintln(w, string(raw))
		}
	}
	return sum, nil
}

// RunCampaignDir loads every *.json in dir and runs them as a batch. Load errors
// (a malformed or id-colliding file) are folded into the gate — a broken campaign
// in a CI dir must not silently pass.
func RunCampaignDir(ctx context.Context, eng *Engine, dir, outDir string, jsonOut bool, w io.Writer) (BatchSummary, error) {
	camps, errs := LoadCampaignDir(dir)
	return RunBatch(ctx, eng, camps, errs, outDir, jsonOut, w)
}

// RunCampaignFile loads and runs a single campaign file as a one-element batch,
// so a single-campaign run and a whole-dir run share the roll-up + gate path.
func RunCampaignFile(ctx context.Context, eng *Engine, path, outDir string, jsonOut bool, w io.Writer) (BatchSummary, error) {
	c, err := LoadCampaign(path)
	if err != nil {
		return RunBatch(ctx, eng, nil, []error{err}, outDir, jsonOut, w)
	}
	return RunBatch(ctx, eng, []*Campaign{c}, nil, outDir, jsonOut, w)
}

// campaignLine is the one-line human verdict for a campaign in a batch print.
func campaignLine(rep *CampaignReport) string {
	tag := "ok       "
	if !rep.VerdictExpected {
		tag = fmt.Sprintf("UNEXPECTED(want %v)", rep.ExpectedVerdicts)
	}
	return fmt.Sprintf("%-12s %-26s %-20s %.2fs  %s", rep.Verdict, rep.ID, rep.Oracle, rep.DurationS, tag)
}

// rollupLine summarises a batch: per-verdict tallies and the gate outcome.
func (s BatchSummary) rollupLine() string {
	var parts []string
	for _, v := range []Verdict{VerdictPass, VerdictDegraded, VerdictFail, VerdictBlind, VerdictInconclusive} {
		if n := s.ByVerdict[v]; n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", n, v))
		}
	}
	tally := strings.Join(parts, ", ")
	if tally == "" {
		tally = "no campaigns"
	}
	gate := "GATE PASS"
	if s.GateFailures > 0 {
		gate = fmt.Sprintf("GATE FAIL (%d)", s.GateFailures)
	}
	return fmt.Sprintf("Roll-up: %d campaign(s) [%s] | %s | %d load error(s)", s.Total, tally, gate, len(s.LoadErrors))
}

// HTTPFaultInjector returns a Fault function for the engine that POSTs a sim_fault
// spec to a live sim's simapi /fault endpoint (the interactive/headless CLI's
// injector for real bench runs — the loopback tests inject in-process instead).
// baseURL is the sim's simapi base (e.g. http://69.0.0.20:6031); the target name
// from the step is accepted for symmetry but the base URL selects the sim. An
// empty baseURL yields nil (sim_fault steps then get a clear per-step error).
func HTTPFaultInjector(baseURL string) func(target string, spec json.RawMessage) error {
	if strings.TrimSpace(baseURL) == "" {
		return nil
	}
	url := strings.TrimRight(baseURL, "/") + "/fault"
	client := &http.Client{Timeout: 5 * time.Second}
	return func(_ string, spec json.RawMessage) error {
		req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(spec))
		if err != nil {
			return fmt.Errorf("aggregator: fault request: %w", err)
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(req)
		if err != nil {
			return fmt.Errorf("aggregator: POST %s: %w", url, err)
		}
		defer resp.Body.Close()
		if resp.StatusCode >= 300 {
			return fmt.Errorf("aggregator: fault POST %s returned %s", url, resp.Status)
		}
		return nil
	}
}

// --- interactive REPL -------------------------------------------------------

// REPL is the interactive aggregator shell: connect as a role, discover, poll,
// write, readback, probe denials, and drive the TLS-fault verbs (disconnect,
// resume, renegotiate) against one live session — every command is one call into
// the same Conn driver the campaign engine uses. It accumulates observations into
// a RunState the `report` verb dumps, so an operator can build up a picture
// interactively and then print a structured report identical in shape to a
// campaign report's raw section.
type REPL struct {
	connectAs   func(addr string, r Role) (*Conn, error)
	resolve     func(target string) (string, error)
	target      string
	roles       []Role
	initialRole Role // auto-connected at Run start when non-empty (the -role flag)
	out         io.Writer

	conn *Conn
	rs   *RunState
}

// NewREPL builds an interactive shell. connectAs/resolve are the same injected
// dependencies the engine takes (so the REPL and the engine share one driver);
// target is the campaign target name to resolve (gateway/device); roles is the set
// a `connect` may name (typically PKIRefs.Roles()); initialRole, when non-empty,
// is connected automatically when Run starts (the -role flag) so an operator drops
// straight into a session.
func NewREPL(connectAs func(addr string, r Role) (*Conn, error), resolve func(target string) (string, error), target string, roles []Role, initialRole Role, out io.Writer) *REPL {
	return &REPL{connectAs: connectAs, resolve: resolve, target: target, roles: roles, initialRole: initialRole, out: out, rs: NewRunState(target, "")}
}

// Run reads commands from in until EOF or a `quit`/`exit`. Each line is dispatched
// by exec; a blank line is ignored. When an initial role was given it is connected
// first. Run always closes the live session on return.
func (p *REPL) Run(ctx context.Context, in io.Reader) error {
	fmt.Fprintln(p.out, "aggregator interactive shell — type `help` for verbs, `quit` to exit")
	if p.initialRole != "" {
		p.doConnect([]string{string(p.initialRole)})
	}
	sc := bufio.NewScanner(in)
	fmt.Fprint(p.out, "> ")
	for sc.Scan() {
		if quit := p.exec(ctx, sc.Text()); quit {
			break
		}
		fmt.Fprint(p.out, "> ")
	}
	p.disconnect()
	return sc.Err()
}

// exec runs one command line and reports whether the shell should quit. It is the
// unit-testable heart of the REPL (no real streams needed): every verb maps to a
// Conn primitive, mirroring the campaign action vocabulary.
func (p *REPL) exec(ctx context.Context, line string) (quit bool) {
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return false
	}
	switch fields[0] {
	case "help", "?":
		p.printHelp()
	case "quit", "exit":
		return true
	case "connect":
		p.doConnect(fields[1:])
	case "discover":
		p.doDiscover(ctx, fields[1:])
	case "poll", "sample":
		p.doSample(fields[1:])
	case "write":
		p.doWrite(fields[1:])
	case "readback", "read":
		p.doRead(fields[1:])
	case "probe":
		p.doProbe(fields[1:])
	case "disconnect":
		p.disconnect()
		fmt.Fprintln(p.out, "session closed")
	case "resume":
		p.doResume(ctx)
	case "renegotiate", "reneg":
		p.doRenegotiate(fields[1:])
	case "report":
		p.doReport()
	default:
		fmt.Fprintf(p.out, "unknown verb %q — type `help`\n", fields[0])
	}
	return false
}

func (p *REPL) printHelp() {
	fmt.Fprint(p.out, strings.Join([]string{
		"verbs:",
		"  connect <role>                 dial the target presenting <role>'s cert",
		"  discover [unit...]             walk the per-device unit map (all, or the listed units)",
		"  poll <unit>                    read one telemetry snapshot of <unit>",
		"  write <unit> <model> <pt> <v>  scale-correct control write",
		"  readback <unit> <model> <pt>   read one point's current engineering value",
		"  probe deny <unit> <model> <pt> attempt a write and report the exception code",
		"  disconnect                     close the session",
		"  resume                         re-establish the session (resuming the TLS session if allowed)",
		"  renegotiate <unit>             attempt a client-initiated TLS renegotiation (refusal probe)",
		"  report                         print the accumulated run state (JSON)",
		"  quit                           exit",
		"roles: " + rolesList(p.roles),
		"",
	}, "\n"))
}

func rolesList(roles []Role) string {
	ss := make([]string, len(roles))
	for i, r := range roles {
		ss[i] = string(r)
	}
	return strings.Join(ss, ", ")
}

func (p *REPL) doConnect(args []string) {
	if len(args) != 1 {
		fmt.Fprintln(p.out, "usage: connect <role>")
		return
	}
	role := Role(args[0])
	if !knownRole(role) {
		fmt.Fprintf(p.out, "unknown role %q (have %s)\n", role, rolesList(p.roles))
		return
	}
	addr, err := p.resolve(p.target)
	if err != nil {
		fmt.Fprintf(p.out, "resolve target %q: %v\n", p.target, err)
		return
	}
	conn, err := p.connectAs(addr, role)
	if err != nil {
		fmt.Fprintf(p.out, "connect as %s: %v\n", role, err)
		return
	}
	p.disconnect()
	p.conn = conn
	si := conn.SessionInfo()
	p.rs.SetSession(si)
	fmt.Fprintf(p.out, "connected as %s to %s — %s / %s, resumed=%t\n", role, addr, si.TLSVersion, si.Cipher, si.Resumed)
}

func (p *REPL) doDiscover(ctx context.Context, args []string) {
	if p.conn == nil {
		fmt.Fprintln(p.out, "not connected — `connect <role>` first")
		return
	}
	units, err := parseUnits(args)
	if err != nil {
		fmt.Fprintf(p.out, "%v\n", err)
		return
	}
	devs, err := p.conn.Discover(ctx, units...)
	if err != nil {
		fmt.Fprintf(p.out, "discover: %v\n", err)
		return
	}
	p.rs.AddDevices(devs)
	for _, d := range devs {
		fmt.Fprintf(p.out, "  unit %d: %s %s (models %v)\n", d.Unit, d.Identity.Manufacturer, d.Identity.Model, d.Models)
	}
	fmt.Fprintf(p.out, "discovered %d device(s)\n", len(devs))
}

func (p *REPL) doSample(args []string) {
	if p.conn == nil {
		fmt.Fprintln(p.out, "not connected — `connect <role>` first")
		return
	}
	if len(args) != 1 {
		fmt.Fprintln(p.out, "usage: poll <unit>")
		return
	}
	unit, err := parseUint8(args[0])
	if err != nil {
		fmt.Fprintf(p.out, "%v\n", err)
		return
	}
	snap := p.conn.Sample(unit)
	p.rs.AddSample(snap)
	fmt.Fprintf(p.out, "  unit %d: stale=%t commLoss=%t points=%v\n", snap.Unit, snap.Stale, snap.CommLoss, snap.Points)
}

func (p *REPL) doWrite(args []string) {
	if p.conn == nil {
		fmt.Fprintln(p.out, "not connected — `connect <role>` first")
		return
	}
	if len(args) != 4 {
		fmt.Fprintln(p.out, "usage: write <unit> <model> <point> <value>")
		return
	}
	unit, model, point, value, err := parseWriteArgs(args)
	if err != nil {
		fmt.Fprintf(p.out, "%v\n", err)
		return
	}
	if werr := p.conn.WritePoint(unit, model, point, value); werr != nil {
		if ex, ok := AsException(werr); ok {
			fmt.Fprintf(p.out, "write rejected with exception %d\n", ex.Code)
		} else {
			fmt.Fprintf(p.out, "write failed: %v\n", werr)
		}
		return
	}
	p.rs.AddWrite(WriteRecord{Unit: unit, Model: model, Point: point, Value: value, OK: true})
	fmt.Fprintf(p.out, "wrote %s.%s = %g on unit %d\n", modelName(model), point, value, unit)
}

func (p *REPL) doRead(args []string) {
	if p.conn == nil {
		fmt.Fprintln(p.out, "not connected — `connect <role>` first")
		return
	}
	if len(args) != 3 {
		fmt.Fprintln(p.out, "usage: readback <unit> <model> <point>")
		return
	}
	unit, err := parseUint8(args[0])
	if err != nil {
		fmt.Fprintf(p.out, "%v\n", err)
		return
	}
	model, err := parseUint16(args[1])
	if err != nil {
		fmt.Fprintf(p.out, "%v\n", err)
		return
	}
	v, err := p.conn.ReadPoint(unit, model, args[2])
	if err != nil {
		fmt.Fprintf(p.out, "read failed: %v\n", err)
		return
	}
	fmt.Fprintf(p.out, "  unit %d %s.%s = %g\n", unit, modelName(model), args[2], v)
}

func (p *REPL) doProbe(args []string) {
	if p.conn == nil {
		fmt.Fprintln(p.out, "not connected — `connect <role>` first")
		return
	}
	if len(args) != 4 || args[0] != "deny" {
		fmt.Fprintln(p.out, "usage: probe deny <unit> <model> <point>")
		return
	}
	unit, model, point, _, err := parseWriteArgs(append([]string{args[1], args[2], args[3]}, "0"))
	if err != nil {
		fmt.Fprintf(p.out, "%v\n", err)
		return
	}
	res, err := p.conn.ProbeDenied(unit, model, point, 1)
	if err != nil {
		fmt.Fprintf(p.out, "probe transport error: %v\n", err)
		return
	}
	p.rs.AddDenial(res)
	if res.Wrote {
		fmt.Fprintf(p.out, "  unit %d %s.%s: write ACCEPTED — authz gap\n", unit, modelName(model), point)
		return
	}
	fmt.Fprintf(p.out, "  unit %d %s.%s: denied with exception %d (stage %s)\n", unit, modelName(model), point, res.ExceptionCode, res.Stage)
}

func (p *REPL) doResume(ctx context.Context) {
	if p.conn == nil {
		fmt.Fprintln(p.out, "not connected — nothing to resume")
		return
	}
	if err := p.conn.Reconnect(ctx); err != nil {
		fmt.Fprintf(p.out, "resume: %v\n", err)
		return
	}
	si := p.conn.SessionInfo()
	p.rs.SetSession(si)
	fmt.Fprintf(p.out, "session re-established — resumed=%t (%s / %s)\n", si.Resumed, si.TLSVersion, si.Cipher)
}

func (p *REPL) doRenegotiate(args []string) {
	if p.conn == nil {
		fmt.Fprintln(p.out, "not connected — `connect <role>` first")
		return
	}
	err := p.conn.Renegotiate()
	if err != nil {
		fmt.Fprintf(p.out, "renegotiation refused by peer policy: %v\n", err)
	} else {
		fmt.Fprintln(p.out, "renegotiation was handled by the peer")
	}
	// Liveness: if a unit is named, confirm the session still round-trips.
	if len(args) == 1 {
		if unit, uerr := parseUint8(args[0]); uerr == nil {
			if lerr := p.conn.Ping(unit); lerr != nil {
				if lerr2 := p.conn.Ping(unit); lerr2 != nil {
					fmt.Fprintf(p.out, "  post-reneg liveness failed even after redial: %v\n", lerr2)
					return
				}
			}
			fmt.Fprintln(p.out, "  session still usable after renegotiation")
		}
	}
}

func (p *REPL) doReport() {
	raw, err := json.MarshalIndent(p.rs, "", "  ")
	if err != nil {
		fmt.Fprintf(p.out, "report: %v\n", err)
		return
	}
	fmt.Fprintln(p.out, string(raw))
}

// disconnect closes the live session if any, idempotently.
func (p *REPL) disconnect() {
	if p.conn != nil {
		_ = p.conn.Close()
		p.conn = nil
	}
}

// --- small arg parsers ------------------------------------------------------

func parseUnits(args []string) ([]uint8, error) {
	units := make([]uint8, 0, len(args))
	for _, a := range args {
		u, err := parseUint8(a)
		if err != nil {
			return nil, err
		}
		units = append(units, u)
	}
	return units, nil
}

func parseWriteArgs(args []string) (unit uint8, model uint16, point string, value float64, err error) {
	if unit, err = parseUint8(args[0]); err != nil {
		return
	}
	if model, err = parseUint16(args[1]); err != nil {
		return
	}
	point = args[2]
	value, err = strconv.ParseFloat(args[3], 64)
	if err != nil {
		err = fmt.Errorf("value %q is not a number", args[3])
	}
	return
}

func parseUint8(s string) (uint8, error) {
	n, err := strconv.ParseUint(s, 10, 8)
	if err != nil {
		return 0, fmt.Errorf("%q is not a unit (0..255)", s)
	}
	return uint8(n), nil
}

func parseUint16(s string) (uint16, error) {
	n, err := strconv.ParseUint(s, 10, 16)
	if err != nil {
		return 0, fmt.Errorf("%q is not a model id", s)
	}
	return uint16(n), nil
}
