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
type fakeSim struct {
	mu       sync.Mutex
	faults   []map[string]any
	injects  []map[string]any
	controls []map[string]any
	srv      *httptest.Server
}

func newFakeSim(t *testing.T) *fakeSim {
	t.Helper()
	f := &fakeSim{}
	mux := http.NewServeMux()
	record := func(into *[]map[string]any) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			f.mu.Lock()
			*into = append(*into, body)
			f.mu.Unlock()
			w.WriteHeader(http.StatusNoContent)
		}
	}
	mux.HandleFunc("/fault", record(&f.faults))
	mux.HandleFunc("/inject", record(&f.injects))
	mux.HandleFunc("/control", record(&f.controls))
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
	opts.Params = map[string]string{
		// Poll cycles measured in milliseconds keep the test fast; the checks
		// derive every wait from this one number, which is why it is a
		// parameter rather than a constant.
		paramPollInterval: "0.02",
	}
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

	got := sim.faultKinds()
	for _, want := range []string{"exception_code", "exception_code/clear",
		"unit_id_confusion", "unit_id_confusion/clear"} {
		found := false
		for _, g := range got {
			if g == want {
				found = true
			}
		}
		if !found {
			t.Errorf("fault posts = %v, missing %q", got, want)
		}
	}

	c := caseOf(t, rep, uid)
	if c.Verdict == certify.Pass {
		t.Errorf("ERR-2 reported PASS although only two of the four exception classes were provoked")
	}
	// The two classes that WERE provoked must be asserted, cited.
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

// ── wiring: the modsim fault verbs landed in 9e35da6, driven end to end ───────

// recordedBodies snapshots of has posted so far, safe for concurrent use.
func (f *fakeSim) recordedBodies(of *[]map[string]any) []map[string]any {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]map[string]any(nil), *of...)
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
	// The default base must ALWAYS be restored, unconditionally deferred —
	// a bench left relocated would corrupt every OTHER check's discovery.
	if !hasBody(faults, map[string]any{"kind": "relocate", "clear": true}) {
		t.Errorf("the server's default base was never restored: %+v\n%s", faults, console)
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
	if !hasBody(injects, map[string]any{"clear_insert_model": true}) {
		t.Errorf("the spliced model was never retracted: %+v\n%s", injects, console)
	}
}

func TestERR2EndToEndTargetsAllThreeRemainingExceptionCodes(t *testing.T) {
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
	_, _, console := runOne(t, uid, sc, sim)

	faults := sim.recordedBodies(&sim.faults)
	for _, code := range []int{1, 2, 3} {
		if !hasBody(faults, map[string]any{"kind": "exception_code", "code": code, "on_fc": FCReadHoldingRegisters}) {
			t.Errorf("no targeted exception_code fault for code %d, on_fc %d was recorded: %+v\n%s",
				code, FCReadHoldingRegisters, faults, console)
		}
	}
}

func TestPROT1EndToEndArmsAndClearsShortResponse(t *testing.T) {
	const uid = "ss-modbus-client-conf-v1.1::PROT-1"
	s := newSunSpecServer(40000)
	sim := newFakeSim(t)
	_, _, console := runOne(t, uid, conformantClientScript(s), sim)

	faults := sim.recordedBodies(&sim.faults)
	if !hasBody(faults, map[string]any{"kind": "short_response", "truncate_bytes": shortResponseTruncateBytes}) {
		t.Errorf("no POST /fault {\"kind\":\"short_response\",\"truncate_bytes\":%d} was recorded: %+v\n%s",
			shortResponseTruncateBytes, faults, console)
	}
	if !hasBody(faults, map[string]any{"kind": "short_response", "clear": true}) {
		t.Errorf("the short_response fault was never cleared: %+v\n%s", faults, console)
	}
}

func TestINFO2EndToEndSeedsAndClearsTheTypedSentinel(t *testing.T) {
	const uid = "ss-modbus-client-conf-v1.1::INFO-2"
	s := newSunSpecServer(40000)
	sim := newFakeSim(t)
	_, _, console := runOne(t, uid, conformantClientScript(s), sim)

	injects := sim.recordedBodies(&sim.injects)
	seeded := false
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
			if fmt.Sprint(m["addr"]) == fmt.Sprint(infoSentinelAddr) && m["type"] == infoSentinelType {
				seeded = true
			}
		}
	}
	if !seeded {
		t.Errorf("no POST /inject {\"unimplemented\":[{\"addr\":%d,\"type\":%q}]} was recorded: %+v\n%s",
			infoSentinelAddr, infoSentinelType, injects, console)
	}
	if !hasBody(injects, map[string]any{"clear_unimplemented": true}) {
		t.Errorf("the typed sentinel was never cleared: %+v\n%s", injects, console)
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
