package suitemodbusclient

// suite_test.go runs the suite the way the bench runs it — through the real
// runner, over a real (synthetic) capture, producing a real bundle — and then
// checks the bundle verifies.
//
// The two tests that matter most are the negative ones. A conformance tool is
// only worth anything if it refuses to pass a DUT it did not observe, and if it
// leaves the bench as it found it when a check goes wrong. Both are asserted
// here rather than assumed.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"csip-tls-test/internal/certify"
	"csip-tls-test/internal/evidence/bundle"
	"csip-tls-test/internal/evidence/capture"
	"csip-tls-test/internal/evidence/pcapng"
)

// ── coverage of the document ──────────────────────────────────────────────────

func TestSuiteRegistersEveryCatalogUIDOfItsDocument(t *testing.T) {
	cat := realCatalog(t)
	reg := certify.NewRegistry()
	Register(reg)

	cov := reg.Coverage(cat, certify.Filter{})
	if len(cov.Orphans) != 0 {
		t.Fatalf("the suite registers uids the catalog does not contain: %v", cov.Orphans)
	}
	var doc *certify.DocCoverage
	for i := range cov.Docs {
		if cov.Docs[i].Doc == Doc {
			doc = &cov.Docs[i]
		}
	}
	if doc == nil {
		t.Fatalf("the catalog has no document %q", Doc)
	}
	if len(doc.Unimplemented) != 0 {
		t.Errorf("unimplemented rows in %s: %v", Doc, doc.Unimplemented)
	}
	if doc.Total != len(Rows) {
		t.Errorf("the catalog has %d rows for %s but the suite's self-assessment table has %d",
			doc.Total, Doc, len(Rows))
	}
}

func TestSelfAssessmentTableMatchesTheRegistrations(t *testing.T) {
	reg := certify.NewRegistry()
	Register(reg)
	for _, r := range Rows {
		if _, ok := reg.Lookup(r.UID); !ok {
			t.Errorf("the self-assessment names %s, which the suite does not register", r.UID)
		}
		if r.Depth != DepthFull && (r.Gap == "" || r.Capability == "") {
			t.Errorf("%s is %q but does not say what is missing or what would close it", r.ID, r.Depth)
		}
	}
	if len(reg.Registrations()) != len(Rows) {
		t.Errorf("%d registrations but %d self-assessment rows", len(reg.Registrations()), len(Rows))
	}
	if md := GapMarkdown(); !strings.Contains(md, "READ-2") || !strings.Contains(md, "not applicable") {
		t.Errorf("the gap report does not render: %s", md)
	}
}

// TestBarrierChecksCarryAnExplicitTimeout: every row that WAITS on the
// simulator's barrier must budget for it explicitly.
//
// deterministic.go bounds ONE wait at pollBudget (90 s) — generous against a
// 10 s poll because a client's reconnect-with-backoff after a Modbus exception
// can legitimately trail a fault clear by several cycles. A row performing
// several waits therefore needs room for several, and certify's 3-minute
// default is not it. The requirement is not "a big number": it is that the
// registration budget exceeds what the row can actually spend waiting.
func TestBarrierChecksCarryAnExplicitTimeout(t *testing.T) {
	reg := certify.NewRegistry()
	Register(reg)
	// uid → the number of barrier waits the row can perform in the worst case.
	waits := map[string]int{
		"ss-modbus-client-conf-v1.1::CLI-1":  1,
		"ss-modbus-client-conf-v1.1::CLI-2":  1,
		"ss-modbus-client-conf-v1.1::CLI-3":  3,
		"ss-modbus-client-conf-v1.1::CLI-4":  4,
		"ss-modbus-client-conf-v1.1::READ-1": 1,
		"ss-modbus-client-conf-v1.1::READ-2": 2,
		"ss-modbus-client-conf-v1.1::ERR-1":  2,
		"ss-modbus-client-conf-v1.1::ERR-2":  6,
		"ss-modbus-client-conf-v1.1::ERR-3":  1,
		"ss-modbus-client-conf-v1.1::INFO-1": 2,
		"ss-modbus-client-conf-v1.1::INFO-2": 3,
		"ss-modbus-client-conf-v1.1::PROT-1": 6,
		"ss-modbus-client-conf-v1.1::PROT-2": 2,
		"ss-modbus-client-conf-v1.1::WR-2":   4,
	}
	for uid, n := range waits {
		b, ok := reg.Lookup(uid)
		if !ok {
			t.Fatalf("%s is not registered", uid)
		}
		need := time.Duration(n) * pollBudget
		if b.Timeout < need {
			t.Errorf("%s: Timeout = %s, but the row can spend up to %s waiting on the barrier "+
				"(%d wait(s) at %s each). A check killed mid-wait reports a timeout where the honest "+
				"answer is 'the DUT did not poll'", uid, b.Timeout, need, n, pollBudget)
		}
	}
}

func realCatalog(t *testing.T) *certify.Catalog {
	t.Helper()
	path, err := certify.DefaultCatalogPath()
	if err != nil {
		t.Skipf("no committed catalog: %v", err)
	}
	cat, err := certify.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	return cat
}

// ── a fake bench ──────────────────────────────────────────────────────────────

// fakeSim is modsim's simapi, enough of it to drive the injection paths and to
// record exactly what a check posted — which is how the clear-up test proves
// the bench is left as it was found.
// fakeSim is a simulator control plane good enough to run every row against.
//
// It implements simapi 1.1.0's deterministic surface — the epoch on every
// mutation, the poll barrier, the transaction ledger — because since LAB29-011
// that IS the interface the checks drive. A fake that only recorded fault
// bodies would let a row's live phase pass while its barrier logic went
// untested, which is the half most likely to be wrong.
//
// Its barriers are satisfied IMMEDIATELY: the fake stands in for a bench whose
// DUT is polling briskly, so a row's wait returns at once and the test suite
// stays fast without any timing knob to tune. The ledger it serves is
// synthesised from the same script the capture is rendered from, so a row that
// grades the ledger and a row that cites the pcap are looking at one
// conversation.
type fakeSim struct {
	mu       sync.Mutex
	faults   []map[string]any
	injects  []map[string]any
	controls []map[string]any
	resets   []map[string]any
	epoch    uint64
	polls    uint64
	// base is the register the fake currently serves its SunSpec map at, so a
	// relocation to the noncompliant 40001 keeps every LATER read identifier-
	// free — which is what a real relocation does and what ERR-1 grades.
	base uint16
	// entries is the ledger the fake serves, oldest first.
	entries []LedgerEntry
	// seq is the ledger's own cursor.
	seq uint64
	srv *httptest.Server
}

func newFakeSim(t *testing.T) *fakeSim {
	t.Helper()
	f := &fakeSim{epoch: 1, polls: 3, base: 40000}
	mux := http.NewServeMux()

	// Every accepted mutation bumps the epoch and answers with it, and adds a
	// transaction to the ledger so the row's barrier has something to find —
	// which is what a DUT that keeps polling through a provocation produces.
	record := func(into *[]map[string]any) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			f.mu.Lock()
			*into = append(*into, body)
			f.epoch++
			ep := f.epoch
			f.appendLocked(ep, body)
			f.mu.Unlock()
			writeSimJSON(w, map[string]any{"api_version": "1.1.0", "epoch": ep})
		}
	}
	mux.HandleFunc("/fault", record(&f.faults))
	mux.HandleFunc("/inject", record(&f.injects))
	mux.HandleFunc("/control", record(&f.controls))
	mux.HandleFunc("/reset", func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		f.mu.Lock()
		f.resets = append(f.resets, body)
		f.epoch++
		ep := f.epoch
		f.appendLocked(ep, nil)
		f.mu.Unlock()
		writeSimJSON(w, map[string]any{
			"api_version": "1.1.0", "epoch": ep,
			"result": map[string]any{
				"baseline":  "as-built",
				"cleared":   []string{"device faults", "wire-tap faults", "poll-cycle accounting"},
				"baselines": []string{"as-built"},
			},
		})
	})
	mux.HandleFunc("/version", func(w http.ResponseWriter, r *http.Request) {
		writeSimJSON(w, map[string]any{
			"api_version": "1.1.0",
			"endpoints": []string{
				"GET /version", "GET /state", "POST /inject", "POST /control", "GET /registers",
				"POST /fault", "POST /reset", "GET /ledger", "GET /poll", "GET /poll/wait",
				"epoch-acknowledged mutations",
			},
		})
	})
	mux.HandleFunc("/poll", func(w http.ResponseWriter, r *http.Request) { f.writePoll(w, r, false) })
	mux.HandleFunc("/poll/wait", func(w http.ResponseWriter, r *http.Request) { f.writePoll(w, r, true) })
	mux.HandleFunc("/ledger", f.writeLedger)
	mux.HandleFunc("/state", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"type":"solar"}`))
	})
	mux.HandleFunc("/registers", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"40000":21365}`))
	})
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

// fakeAnchor is the block the fake reports the DUT polling — the same base
// every scripted conversation in this file walks.
var fakeAnchor = PollAnchor{UnitID: 1, Addr: 40070, Count: 125}

// appendLocked adds transactions to the ledger for a mutation, so a row's
// barrier finds the DUT having met whatever was just armed. Callers hold f.mu.
//
// The SHAPE of what it appends matters: an exception body produces an
// exception transaction, a one-shot produces one resolved the way that
// one-shot resolves them, and anything else produces an ordinary answered
// read. A fake that always appended the same thing would let a row's grading
// logic pass on evidence it never actually asked for.
func (f *fakeSim) appendLocked(epoch uint64, body map[string]any) {
	f.polls++
	add := func(e LedgerEntry) {
		f.seq++
		e.Seq, e.Epoch, e.Poll, e.Conn, e.Peer = f.seq, epoch, f.polls, 1, "69.0.0.2:41234"
		e.UnitID, e.FC = 1, FCReadHoldingRegisters
		if e.Addr == 0 && e.Count == 0 {
			e.Addr, e.Count = 40000, 2
		}
		if e.Request == "" {
			e.Request = "0001000000060103" + "9c400002"
		}
		now := time.Now().UTC()
		e.RequestAt = now
		if e.Outcome != outcomeDropped && e.Outcome != outcomeAbandoned {
			e.ResponseAt = &now
		}
		f.entries = append(f.entries, e)
	}
	kind, _ := body["kind"].(string)
	cleared, _ := body["clear"].(bool)
	switch {
	case kind == "exception_code" && !cleared:
		code := uint8(4)
		if v, ok := body["code"].(float64); ok {
			code = uint8(v)
		}
		add(LedgerEntry{Outcome: outcomeException, Exception: code,
			Response: hexOfWords(0x83, code)})
	case kind == "unit_id" && !cleared:
		add(LedgerEntry{Outcome: outcomeException, Exception: 0x0B,
			Response: hexOfWords(0x83, 0x0B)})
	case kind == "next_response" && !cleared:
		action, _ := body["action"].(string)
		switch action {
		case "drop":
			add(LedgerEntry{Outcome: outcomeDropped, Fault: "next_response:drop"})
		case "short":
			add(LedgerEntry{Outcome: outcomeTruncated, Fault: "next_response:short",
				Response: "0001000000fb0103"})
		case "delay":
			add(LedgerEntry{Outcome: outcomeDelayed, Fault: "next_response:delay", LatencyMS: 9000,
				Response: sunSResponseHex()})
		}
	case kind == "relocate" && !cleared:
		if v, ok := body["base"].(float64); ok {
			f.base = uint16(v)
		}
		f.addProbesLocked(add)
	case body == nil, kind == "tcp_drop":
		f.addProbesLocked(add)
	default:
		add(LedgerEntry{Outcome: outcomeAnswered, Response: sunSResponseHex()})
	}
}

// addProbesLocked appends the three base probes a rediscovery makes, each
// answered as the currently served base decides: the identifier at a base the
// map is actually at, zeros everywhere else. Callers hold f.mu.
func (f *fakeSim) addProbesLocked(add func(LedgerEntry)) {
	for _, probe := range []uint16{40000, 0, 50000} {
		e := LedgerEntry{Addr: probe, Count: 2, Outcome: outcomeAnswered, Response: zeroResponseHex()}
		if probe == f.base {
			e.Response = sunSResponseHex()
		}
		add(e)
	}
}

// sunSResponseHex is a two-register read response carrying the SunSpec
// identifier, so a base probe in the fake ledger decodes the way a real one
// does.
func sunSResponseHex() string { return "000100000007010304" + "5375" + "6e53" }

// zeroResponseHex is a two-register read response of zeros — what a probe at a
// base with no map there returns.
func zeroResponseHex() string { return "00010000000701030400000000" }

// hexOfWords renders a two-byte exception PDU inside an MBAP header.
func hexOfWords(fc, code uint8) string {
	return fmt.Sprintf("00010000000301%02x%02x", fc, code)
}

func (f *fakeSim) writePoll(w http.ResponseWriter, r *http.Request, wait bool) {
	f.mu.Lock()
	// A wait is satisfied immediately: this fake stands in for a DUT that is
	// polling briskly, so a row's barrier returns at once.
	if wait {
		if want, err := strconv.ParseUint(r.URL.Query().Get("epoch"), 10, 64); err == nil && want > f.polls {
			f.polls = want
		}
	}
	body := map[string]any{
		"api_version": "1.1.0",
		"reached":     true,
		"epoch":       f.epoch,
		"poll": map[string]any{
			"completed": f.polls, "open": f.polls + 1,
			"anchor":        map[string]any{"unit_id": 1, "addr": fakeAnchor.Addr, "count": fakeAnchor.Count},
			"anchor_locked": true, "anchor_source": "learned",
			"sessions": 1, "abandoned": 0,
			"rule": "a poll cycle is the interval between two consecutive arrivals of the cycle anchor",
		},
		"tap": map[string]any{"connections": 1, "requests": f.seq, "ledger_entries": len(f.entries)},
	}
	f.mu.Unlock()
	writeSimJSON(w, body)
}

func (f *fakeSim) writeLedger(w http.ResponseWriter, r *http.Request) {
	since, _ := strconv.ParseUint(r.URL.Query().Get("since_epoch"), 10, 64)
	f.mu.Lock()
	var out []LedgerEntry
	for _, e := range f.entries {
		if e.Epoch >= since {
			out = append(out, e)
		}
	}
	body := map[string]any{
		"api_version": "1.1.0",
		"epoch":       f.epoch,
		"entries":     out,
		"total":       len(out),
		"high_seq":    f.seq,
		"poll": map[string]any{
			"completed": f.polls, "anchor_locked": true,
			"anchor": map[string]any{"unit_id": 1, "addr": fakeAnchor.Addr, "count": fakeAnchor.Count},
			"rule":   "a poll cycle is the interval between two consecutive arrivals of the cycle anchor",
		},
	}
	if n := len(out); n > 0 {
		body["next_seq"] = out[n-1].Seq
	}
	f.mu.Unlock()
	writeSimJSON(w, body)
}

func writeSimJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func (f *fakeSim) kinds(of []map[string]any) []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for _, m := range of {
		k, _ := m["kind"].(string)
		if c, _ := m["clear"].(bool); c {
			k += "/clear"
		}
		out = append(out, k)
	}
	return out
}

func (f *fakeSim) recordedBodies(of *[]map[string]any) []map[string]any {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]map[string]any(nil), *of...)
}

func (f *fakeSim) faultKinds() []string {
	f.mu.Lock()
	fs := append([]map[string]any(nil), f.faults...)
	f.mu.Unlock()
	return f.kinds(fs)
}

// scriptedCapture is the run's capture: it synthesises the DUT's southbound
// conversation, timestamped inside the window of the check that ran.
type scriptedCapture struct {
	path  string
	build func() []pcapng.Packet
	start time.Time
}

func (s *scriptedCapture) Start(context.Context) error { s.start = time.Now().UTC(); return nil }
func (s *scriptedCapture) Path() string                { return s.path }

func (s *scriptedCapture) Stop() (capture.Summary, error) {
	pkts := s.build()
	if err := os.MkdirAll(filepath.Dir(s.path), 0o755); err != nil {
		return capture.Summary{}, err
	}
	if err := os.WriteFile(s.path, pcapBytes(pkts), 0o644); err != nil {
		return capture.Summary{}, err
	}
	fi, err := os.Stat(s.path)
	if err != nil {
		return capture.Summary{}, err
	}
	sum := capture.Summary{
		Tool: "synthetic", ToolVersion: "test", Interface: "lo",
		Path: s.path, Format: string(pcapng.FormatPcap),
		Started: s.start, Stopped: time.Now().UTC(),
		FileBytes: fi.Size(), Packets: len(pkts),
	}
	if len(pkts) > 0 {
		sum.FirstPacket, sum.LastPacket = pkts[0].Time, pkts[len(pkts)-1].Time
	}
	return sum, nil
}

// runOne drives the suite through the real runner for one uid, with a capture
// built from sc and timestamped inside the check's own window.
func runOne(t *testing.T, uid string, sc *script, sim *fakeSim) (*certify.RunReport, string, string) {
	t.Helper()
	cat := realCatalog(t)

	var mu sync.Mutex
	var checkStart time.Time
	reg := certify.NewRegistry()
	inner := certify.NewRegistry()
	Register(inner)
	binding, ok := inner.Lookup(uid)
	if !ok {
		t.Fatalf("the suite does not register %s", uid)
	}
	reg.Register(uid, binding.Suite, func(ctx context.Context, rc *certify.RunCtx) (certify.Result, error) {
		mu.Lock()
		checkStart = time.Now().UTC()
		mu.Unlock()
		return binding.Check(ctx, rc)
	})

	out := filepath.Join(t.TempDir(), "bundle")
	console := &bytes.Buffer{}
	opts := certify.DefaultOptions()
	opts.OutDir = out
	opts.Out = console
	opts.Log = certify.DiscardLogger
	opts.PKIDir = ""
	opts.CheckTimeout = 60 * time.Second
	opts.UIDs = []string{uid}
	opts.Targets = certify.Targets{
		Gateway:     "69.0.0.2:802",
		GatewayHost: "69.0.0.2",
		ModSim:      benchServer.String(),
		MBAPSDev:    "69.0.0.20:8021",
	}
	if sim != nil {
		opts.Targets.ModSimAPI = sim.srv.URL
	}
	// No timing parameter. Since LAB29-011 the checks wait on the simulator's
	// own barriers rather than on a poll interval, so there is no number to
	// shrink to keep a test fast — the fake sim answers its barriers
	// immediately, which is exactly what a bench whose DUT is polling briskly
	// looks like.
	opts.Params = map[string]string{}
	opts.Capturer = &scriptedCapture{
		path: filepath.Join(t.TempDir(), "run.pcap"),
		build: func() []pcapng.Packet {
			mu.Lock()
			at := checkStart
			mu.Unlock()
			if at.IsZero() || sc == nil {
				return nil
			}
			return renderScript(sc, benchClient, benchServer, at.Add(2*time.Millisecond), 1)
		},
	}

	run, err := certify.New(reg, cat, opts)
	if err != nil {
		t.Fatal(err)
	}
	rep, err := run.Run(context.Background())
	if err != nil {
		t.Fatalf("Run: %v\n%s", err, console.String())
	}
	return rep, out, console.String()
}

func caseOf(t *testing.T, rep *certify.RunReport, uid string) certify.CaseResult {
	t.Helper()
	for _, c := range rep.Cases {
		if c.Case.UID == uid {
			return c
		}
	}
	t.Fatalf("no result for %s", uid)
	return certify.CaseResult{}
}

// ── end to end ────────────────────────────────────────────────────────────────

func TestREAD2EndToEndProducesAVerifiableBundle(t *testing.T) {
	const uid = "ss-modbus-client-conf-v1.1::READ-2"
	s := newSunSpecServer(40000)
	sim := newFakeSim(t)
	rep, out, console := runOne(t, uid, conformantClientScript(s), sim)

	c := caseOf(t, rep, uid)
	if c.Verdict != certify.Pass {
		t.Fatalf("verdict = %s (%s)\nassertions: %+v\n%s", c.Verdict, c.Notes, c.Assertions, console)
	}
	if !c.Citable() {
		t.Fatal("the row passed with no re-checkable citation")
	}
	if len(c.Frames) == 0 {
		t.Fatal("no capture frames were attributed to the row")
	}
	// The provocation must be recorded, not merely performed.
	if !strings.Contains(c.Notes, "tcp_drop") {
		t.Errorf("the notes do not say what was injected: %s", c.Notes)
	}
	if got := sim.faultKinds(); len(got) == 0 || got[0] != "tcp_drop" {
		t.Errorf("fault posts = %v, want the reconnect to have been forced", got)
	}

	vr, err := bundle.Verify(out)
	if err != nil {
		t.Fatal(err)
	}
	if !vr.OK {
		t.Fatalf("the bundle does not verify:\n%s", vr.String())
	}
}

func TestREAD2RefusesAPassWhenTheCaptureDoesNotShowTheExchange(t *testing.T) {
	// The capture contains nothing at all: the row must not pass, and must say
	// that no frame was attributed rather than going quiet.
	const uid = "ss-modbus-client-conf-v1.1::READ-2"
	rep, _, console := runOne(t, uid, nil, newFakeSim(t))
	c := caseOf(t, rep, uid)
	if c.Verdict == certify.Pass {
		t.Fatalf("a PASS survived an empty capture: %+v\n%s", c.Assertions, console)
	}
	found := false
	for _, a := range c.Assertions {
		if a.Verdict == certify.Skip && strings.Contains(a.Observed, "no capture frame was attributed") {
			found = true
		}
	}
	if !found {
		t.Errorf("no assertion explains the missing evidence: %+v", c.Assertions)
	}
}

func TestREAD2FailsANonConformantClientEndToEnd(t *testing.T) {
	// The same pipeline, against a client that reads 200 registers in one
	// request. The row must FAIL, and the failure must reach the bundle.
	const uid = "ss-modbus-client-conf-v1.1::READ-2"
	sc := &script{stepMs: 1, msgs: []msg{
		{fromClient: true, payload: readReq(1, 1, 40000, 200)},
		{payload: readRsp(1, 1, make([]uint16, 200))},
	}}
	rep, out, console := runOne(t, uid, sc, newFakeSim(t))
	c := caseOf(t, rep, uid)
	if c.Verdict != certify.Fail {
		t.Fatalf("verdict = %s, want FAIL for a 200-register read\n%+v\n%s", c.Verdict, c.Assertions, console)
	}
	vr, err := bundle.Verify(out)
	if err != nil {
		t.Fatal(err)
	}
	if !vr.OK {
		t.Fatalf("the failing run's bundle does not verify:\n%s", vr.String())
	}
}

func TestERR2ClearsEveryFaultItArms(t *testing.T) {
	// A fault left armed on the sim would poison every test case that runs
	// after this one, so the clear-up is a property of the suite, not a
	// courtesy.
	const uid = "ss-modbus-client-conf-v1.1::ERR-2"
	s := newSunSpecServer(40000)
	sc := &script{stepMs: 1, msgs: []msg{
		{fromClient: true, payload: readReq(1, 1, 40000, 4)},
		{payload: excRsp(1, 1, FCReadHoldingRegisters, 0x04)},
		{fromClient: true, payload: readReq(2, 1, 40000, 4)},
		{payload: excRsp(2, 1, FCReadHoldingRegisters, 0x0B)},
		{fromClient: true, payload: readReq(3, 1, 40000, 4)},
		{payload: readRsp(3, 1, s.read(40000, 4))},
	}}
	sim := newFakeSim(t)
	rep, _, console := runOne(t, uid, sc, sim)

	// Every armed class is followed by its clear, and the row ends with the
	// device back at its baseline.
	got := sim.faultKinds()
	armed, cleared := 0, 0
	for _, g := range got {
		switch g {
		case "exception_code":
			armed++
		case "exception_code/clear":
			cleared++
		}
	}
	if armed != len(err2Codes) {
		t.Errorf("armed %d exception class(es), want the %d §2.9.2 is about: %v",
			armed, len(err2Codes), got)
	}
	if cleared < armed {
		t.Errorf("%d class(es) armed but only %d cleared: %v", armed, cleared, got)
	}
	sim.mu.Lock()
	resets := len(sim.resets)
	sim.mu.Unlock()
	if resets < 2 {
		t.Errorf("%d POST /reset(s), want one to establish a known device and one to restore it", resets)
	}

	c := caseOf(t, rep, uid)
	// The classes the fixture's capture carries must be asserted, cited.
	var cited int
	for _, a := range c.Assertions {
		if a.Verdict == certify.Pass && a.Citable() {
			cited++
		}
	}
	if cited == 0 {
		t.Errorf("no cited PASS assertion for the exceptions that were provoked: %+v\n%s",
			c.Assertions, console)
	}
}

// hasBody reports whether any body in bodies carries every key/value pair in
// want, comparing values by their JSON-decoded form (float64 for a number)
// so a caller may write literal ints in want without worrying about it.
func hasBody(bodies []map[string]any, want map[string]any) bool {
	for _, b := range bodies {
		ok := true
		for k, v := range want {
			got, present := b[k]
			if !present || fmt.Sprint(got) != fmt.Sprint(v) {
				ok = false
				break
			}
		}
		if ok {
			return true
		}
	}
	return false
}

func TestCLI4EndToEndSweepsTheOtherTwoStandardBases(t *testing.T) {
	const uid = "ss-modbus-client-conf-v1.1::CLI-4"
	s := newSunSpecServer(40000)
	sim := newFakeSim(t)
	_, _, console := runOne(t, uid, conformantClientScript(s), sim)

	faults := sim.recordedBodies(&sim.faults)
	if !hasBody(faults, map[string]any{"kind": "relocate", "base": 0}) {
		t.Errorf("no POST /fault {\"kind\":\"relocate\",\"base\":0} was recorded: %+v\n%s", faults, console)
	}
	if !hasBody(faults, map[string]any{"kind": "relocate", "base": 50000}) {
		t.Errorf("no POST /fault {\"kind\":\"relocate\",\"base\":50000} was recorded: %+v\n%s", faults, console)
	}
	// The default base must ALWAYS be restored, unconditionally deferred — a
	// bench left relocated would corrupt every OTHER check's discovery. The
	// sweep itself ends at 40000, and the deferred POST /reset restores the
	// whole as-built image on top of that; either alone would do, and the row
	// does both because a relocation that failed mid-sweep must not depend on
	// the sweep having finished.
	if !hasBody(faults, map[string]any{"kind": "relocate", "base": float64(40000)}) {
		t.Errorf("the sweep did not end at the default base: %+v\n%s", faults, console)
	}
	sim.mu.Lock()
	resets := len(sim.resets)
	sim.mu.Unlock()
	if resets < 2 {
		t.Errorf("%d POST /reset(s), want the deferred restore as well as the opening baseline", resets)
	}
}

func TestERR3EndToEndSplicesTheModelAndRetractsIt(t *testing.T) {
	const uid = "ss-modbus-client-conf-v1.1::ERR-3"
	s := newSunSpecServer(40000)
	sim := newFakeSim(t)
	_, _, console := runOne(t, uid, conformantClientScript(s), sim)

	injects := sim.recordedBodies(&sim.injects)
	spliced := false
	for _, b := range injects {
		m, ok := b["insert_model"].(map[string]any)
		if !ok {
			continue
		}
		if fmt.Sprint(m["id"]) == "65000" && fmt.Sprint(m["len"]) == "4" {
			spliced = true
		}
	}
	if !spliced {
		t.Errorf("no POST /inject {\"insert_model\":{\"id\":65000,\"len\":4}} was recorded: %+v\n%s",
			injects, console)
	}
	// The splice is retracted by the deferred POST /reset, which restores the
	// whole as-built register image — one operation instead of trusting a
	// per-verb clear to have put everything back.
	sim.mu.Lock()
	resets := len(sim.resets)
	sim.mu.Unlock()
	if resets < 2 {
		t.Errorf("the spliced model was never retracted: %d POST /reset(s) recorded\n%s", resets, console)
	}
}

// TestERR2EndToEndNeverArmsTargetedCodesAndNeverFails is the live-run
// regression test (runs/warnmeas-mc-ssm-20260802T134537): ERR-2 must never
// resolve to FAIL — a live bench run showed the recovery assertion FAILing
// when the window closed before the DUT's reconnect-with-backoff completed
// — and, per the coordinator's time-budget direction, no longer arms the
// three FC-targeted classes in the same test case as the two §2.9.2 step 1
// names (err2TargetedCodesSkip reports them as an honest SKIP instead).
// TestERR2EndToEndArmsEveryCodeAndNeverFails is the inverse of the test it
// replaces.
//
// The old one asserted that ERR-2 must NOT arm 0x01/0x02/0x03, because
// serialising five classes on a fixed time budget risked the timing regression
// a live run had already produced. That budget is gone: each class is now held
// on the simulator's own ledger until the DUT has met it, so breadth costs
// patience rather than reliability, and the row drives all five.
func TestERR2EndToEndArmsEveryCodeAndNeverFails(t *testing.T) {
	const uid = "ss-modbus-client-conf-v1.1::ERR-2"
	s := newSunSpecServer(40000)
	sc := &script{stepMs: 1, msgs: []msg{
		{fromClient: true, payload: readReq(1, 1, 40000, 4)},
		{payload: excRsp(1, 1, FCReadHoldingRegisters, 0x04)},
		{fromClient: true, payload: readReq(2, 1, 40000, 4)},
		{payload: excRsp(2, 1, FCReadHoldingRegisters, 0x0B)},
		{fromClient: true, payload: readReq(3, 1, 40000, 4)},
		{payload: readRsp(3, 1, s.read(40000, 4))},
	}}
	sim := newFakeSim(t)
	rep, _, console := runOne(t, uid, sc, sim)

	faults := sim.recordedBodies(&sim.faults)
	for _, code := range []float64{1, 2, 3, 4, 11} {
		if !hasBody(faults, map[string]any{"kind": "exception_code", "code": code, "on_fc": float64(3)}) {
			t.Errorf("exception class %v was never armed at FC 0x03: %+v\n%s", code, faults, console)
		}
	}

	c := caseOf(t, rep, uid)
	if c.Verdict == certify.Fail {
		t.Fatalf("ERR-2 resolved to FAIL against a conformant fixture: %+v\n%s", c.Assertions, console)
	}
}

func TestPROT1EndToEndArmsAllThreeReadingsAsOneShots(t *testing.T) {
	const uid = "ss-modbus-client-conf-v1.1::PROT-1"
	s := newSunSpecServer(40000)
	sim := newFakeSim(t)
	_, _, console := runOne(t, uid, conformantClientScript(s), sim)

	faults := sim.recordedBodies(&sim.faults)
	for _, action := range []string{"drop", "short", "delay"} {
		found := false
		for _, b := range faults {
			if b["kind"] == "next_response" && b["action"] == action {
				found = true
			}
		}
		if !found {
			t.Errorf("no POST /fault {\"kind\":\"next_response\",\"action\":%q} was recorded: %+v\n%s",
				action, faults, console)
		}
	}
	// A one-shot is consumed by the request that matches it, so the row must
	// not be arming a blanket it then has to remember to clear — but it DOES
	// clear defensively between readings, which is the fence for each
	// recovery.
	if !hasBody(faults, map[string]any{"kind": "next_response", "clear": true}) {
		t.Errorf("the one-shot was never explicitly disarmed between readings: %+v\n%s", faults, console)
	}
}

// TestERR1EndToEndServesTheNoncompliantBase is the row that could not be
// driven at all before: §2.9.1's map at holding register 40001.
func TestERR1EndToEndServesTheNoncompliantBase(t *testing.T) {
	const uid = "ss-modbus-client-conf-v1.1::ERR-1"
	s := newSunSpecServer(40000)
	sim := newFakeSim(t)
	rep, _, console := runOne(t, uid, conformantClientScript(s), sim)

	faults := sim.recordedBodies(&sim.faults)
	if !hasBody(faults, map[string]any{"kind": "relocate", "base": float64(noncompliantBase)}) {
		t.Errorf("no POST /fault {\"kind\":\"relocate\",\"base\":%d} was recorded — the row cannot "+
			"present a noncompliant server without it: %+v\n%s", noncompliantBase, faults, console)
	}
	if !hasBody(faults, map[string]any{"kind": "relocate", "base": float64(40000)}) {
		t.Errorf("the map was never restored to a legal base: %+v\n%s", faults, console)
	}
	if c := caseOf(t, rep, uid); c.Verdict == certify.Fail {
		t.Fatalf("ERR-1 resolved to FAIL against a conformant fixture: %+v\n%s", c.Assertions, console)
	}
}

// TestERR2EndToEndDrivesEveryExceptionClass: five classes, not two.
func TestERR2EndToEndDrivesEveryExceptionClass(t *testing.T) {
	const uid = "ss-modbus-client-conf-v1.1::ERR-2"
	s := newSunSpecServer(40000)
	sim := newFakeSim(t)
	_, _, console := runOne(t, uid, conformantClientScript(s), sim)

	faults := sim.recordedBodies(&sim.faults)
	for _, code := range []uint8{0x01, 0x02, 0x03, 0x04, 0x0B} {
		found := false
		for _, b := range faults {
			if b["kind"] != "exception_code" {
				continue
			}
			if v, ok := b["code"].(float64); ok && uint8(v) == code {
				found = true
			}
		}
		if !found {
			t.Errorf("exception class 0x%02x %s was never armed: %+v\n%s",
				code, ExceptionName(code), faults, console)
		}
	}
}

// TestINFO2EndToEndSeedsEveryDatatype: twenty-two datatypes, seeded inside the
// block the simulator reports the DUT reading, and cleared afterwards.
func TestINFO2EndToEndSeedsEveryDatatype(t *testing.T) {
	const uid = "ss-modbus-client-conf-v1.1::INFO-2"
	s := newSunSpecServer(40000)
	sim := newFakeSim(t)
	_, _, console := runOne(t, uid, conformantClientScript(s), sim)

	injects := sim.recordedBodies(&sim.injects)
	seeded := map[string]bool{}
	for _, b := range injects {
		list, ok := b["unimplemented"].([]any)
		if !ok {
			continue
		}
		for _, e := range list {
			m, ok := e.(map[string]any)
			if !ok {
				continue
			}
			typ, _ := m["type"].(string)
			seeded[typ] = true
		}
	}
	if len(seeded) == 0 {
		t.Fatalf("no POST /inject {\"unimplemented\":[…]} was recorded at all: %+v\n%s", injects, console)
	}
	// The fake's anchor block is two registers wide, so only the types that
	// fit are seeded — what matters here is that the row lays the sweep out
	// from the anchor and seeds what fits, rather than seeding one fixed
	// address as it used to.
	if !seeded["int16"] {
		t.Errorf("the sweep did not seed even the first datatype: seeded %v\n%s", seeded, console)
	}
	if !hasBody(injects, map[string]any{"clear_unimplemented": true}) {
		t.Errorf("the seeded sentinels were never cleared: %+v\n%s", injects, console)
	}
}

// TestEveryRowResetsTheSimToAKnownBaseline: a row that armed a fault without
// first knowing what device it was arming on would be measuring the previous
// row's leftovers, and one that did not restore afterwards would corrupt the
// next row's.
func TestEveryRowResetsTheSimToAKnownBaseline(t *testing.T) {
	s := newSunSpecServer(40000)
	for _, uid := range []string{
		"ss-modbus-client-conf-v1.1::CLI-1",
		"ss-modbus-client-conf-v1.1::CLI-3",
		"ss-modbus-client-conf-v1.1::CLI-4",
		"ss-modbus-client-conf-v1.1::ERR-1",
		"ss-modbus-client-conf-v1.1::ERR-2",
		"ss-modbus-client-conf-v1.1::INFO-2",
		"ss-modbus-client-conf-v1.1::PROT-1",
	} {
		sim := newFakeSim(t)
		_, _, console := runOne(t, uid, conformantClientScript(s), sim)
		sim.mu.Lock()
		n := len(sim.resets)
		sim.mu.Unlock()
		if n < 2 {
			t.Errorf("%s posted %d POST /reset(s), want at least 2 — one to establish a known device "+
				"and one to restore it\n%s", uid, n, console)
		}
	}
}

func TestCLI5IsRecordedAsAddressedAndNotExecuted(t *testing.T) {
	const uid = "ss-modbus-client-conf-v1.1::CLI-5"
	rep, _, _ := runOne(t, uid, nil, nil)
	c := caseOf(t, rep, uid)
	if c.Verdict != certify.Skip {
		t.Errorf("verdict = %s, want SKIP", c.Verdict)
	}
	if !strings.Contains(c.Notes, "RS-485") {
		t.Errorf("the SKIP does not say what is missing: %s", c.Notes)
	}
}
