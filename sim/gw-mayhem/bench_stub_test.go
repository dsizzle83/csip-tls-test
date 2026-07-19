package gwmayhem

// bench_stub_test.go is the hermetic proof the wave-2 families (nb-malform /
// sb-fault) have TEETH — the httptest analogue of wave-1's mbaps loopback. It
// stands up three in-process HTTP servers modelling the bench's gridsim head-end
// admin API and the two DER sims' /state + /fault + /control surfaces, driven by
// a stubBehavior that plays either a CONFORMANT gateway (fails closed, isolates,
// digests, recovers) or a specific broken one (applies an absurd setpoint, goes
// dark, unseats a cap, wedges the healthy device, never recovers). It then runs
// the REAL arm functions against the stub and asserts the oracle's verdict — so a
// gateway that violated any fail-closed / isolation invariant is caught as a
// FAIL, not a false PASS. Pure Go: it runs in make test-fast (no wolfSSL, no
// bench).

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// stubBehavior selects which gateway the stub models. The zero value is a fully
// CONFORMANT gateway (every field false, baseline uncapped).
type stubBehavior struct {
	baselineCapPct  float64 // applied WMaxLimPct at baseline (0 ⇒ 100 = uncapped)
	crashOnMalform  bool    // nb: the southbound poll stops advancing once a malform/outage is armed
	absurdOnMalform bool    // nb: the applied setpoint goes out-of-range once a malform is armed
	unseatOnMalform bool    // nb: a safe baseline cap is dropped to uncapped once a malform is armed
	wedgeOnFault    bool    // sb: a plain-device fault wedges the (healthy) secure poll — no isolation
	absurdOnFault   bool    // sb: the faulted DER projects an out-of-range setpoint
	noRecover       bool    // sb: a comm-loss on the secure device never heals after the fault clears
}

// commLossFaults are the secure-device fault verbs that stall the gateway's poll
// (a transport comm-loss), vs register faults (nan_sentinel) / freeze that leave
// the device reachable.
var commLossFaults = map[string]bool{"drop_session": true, "stall_handshake": true, "tcp_drop": true}

// benchStub is the shared state behind the three httptest servers.
type benchStub struct {
	mu  sync.Mutex
	beh stubBehavior

	malformArmed bool
	outageArmed  bool
	plainFault   string
	secureFault  string
	secureFrozen bool

	securePolls int  // the gateway's cumulative poll count on the secure device
	secureDead  bool // sticky: a non-recovering comm-loss latched the secure device dead
}

func (s *benchStub) baselinePct() float64 {
	if s.beh.baselineCapPct == 0 {
		return 100
	}
	return s.beh.baselineCapPct
}

// secureAdvances reports whether the gateway polls the secure device on this read
// (and bumps the counter), modelling the armed adversary + the chosen behaviour.
func (s *benchStub) secureAdvances() bool {
	if s.secureDead {
		return false
	}
	if commLossFaults[s.secureFault] { // comm-loss on the secure device itself
		return false
	}
	if s.beh.crashOnMalform && (s.malformArmed || s.outageArmed) {
		return false
	}
	if s.beh.wedgeOnFault && commLossFaults[s.plainFault] {
		return false // broken isolation: a plain-device comm-loss wedges the whole poll loop
	}
	return true
}

func (s *benchStub) securePct() float64 {
	if s.beh.absurdOnMalform && s.malformArmed {
		return 150
	}
	if s.beh.unseatOnMalform && s.malformArmed {
		return 100
	}
	if s.beh.absurdOnFault && s.secureFault != "" {
		return 150
	}
	return s.baselinePct()
}

func (s *benchStub) plainPct() float64 {
	if s.beh.absurdOnFault && s.plainFault != "" {
		return 150
	}
	if s.beh.absurdOnMalform && s.malformArmed {
		return 150
	}
	return s.baselinePct()
}

// start builds the three servers and a BenchConfig pointing at them with a
// near-zero sampling cadence.
func (s *benchStub) start(t *testing.T) BenchConfig {
	t.Helper()
	grid := httptest.NewServer(http.HandlerFunc(s.gridHandler))
	plain := httptest.NewServer(http.HandlerFunc(s.plainHandler))
	secure := httptest.NewServer(http.HandlerFunc(s.secureHandler))
	t.Cleanup(func() { grid.Close(); plain.Close(); secure.Close() })
	return BenchConfig{
		GridsimAdmin: grid.URL,
		Plain:        DERSim{Name: "inv-plain", BaseURL: plain.URL, Secure: false},
		Secure:       DERSim{Name: "inv-secure", BaseURL: secure.URL, Secure: true},
		Timing:       BenchTiming{Settle: time.Millisecond, Interval: time.Millisecond, Samples: 3},
	}
}

func (s *benchStub) gridHandler(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Kind  string `json:"kind"`
		Mode  string `json:"mode"`
		Clear bool   `json:"clear"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	s.mu.Lock()
	defer s.mu.Unlock()
	switch r.URL.Path {
	case "/admin/malform":
		s.malformArmed = !body.Clear && body.Kind != ""
	case "/admin/outage":
		s.outageArmed = !body.Clear && body.Mode != ""
	case "/admin/clock":
		// a clock warp is not itself a fault the stub models beyond staying up
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *benchStub) plainHandler(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	switch r.URL.Path {
	case "/state":
		writeStub(w, map[string]any{
			"advanced": map[string]any{"wmaxlimpct_704": map[string]any{"ena": true, "pct": s.plainPct()}},
			"controls": map[string]any{"WMaxLimPct_pct": s.plainPct(), "Conn": 1},
		})
	case "/fault":
		var b struct {
			Kind  string `json:"kind"`
			Clear bool   `json:"clear"`
		}
		_ = json.NewDecoder(r.Body).Decode(&b)
		if b.Clear {
			s.plainFault = ""
		} else {
			s.plainFault = b.Kind
		}
		w.WriteHeader(http.StatusNoContent)
	case "/control":
		w.WriteHeader(http.StatusNoContent)
	}
}

func (s *benchStub) secureHandler(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	switch r.URL.Path {
	case "/state":
		if s.secureAdvances() {
			s.securePolls++
		} else if s.beh.noRecover && commLossFaults[s.secureFault] {
			s.secureDead = true // latch a non-recovering wedge
		}
		writeStub(w, map[string]any{
			"model": map[string]any{
				"advanced": map[string]any{"wmaxlimpct_704": map[string]any{"ena": true, "pct": s.securePct()}},
				"controls": map[string]any{"WMaxLimPct_pct": s.securePct(), "Conn": 1},
			},
			"sessions": []map[string]any{{"peer": "gw", "role": "SuperAdministratorSunSpec", "requests": s.securePolls}},
		})
	case "/fault":
		var b struct {
			Kind  string `json:"kind"`
			Clear bool   `json:"clear"`
		}
		_ = json.NewDecoder(r.Body).Decode(&b)
		if b.Clear {
			s.secureFault = ""
		} else {
			s.secureFault = b.Kind
		}
		w.WriteHeader(http.StatusNoContent)
	case "/control":
		var b struct {
			Cmd string `json:"cmd"`
		}
		_ = json.NewDecoder(r.Body).Decode(&b)
		s.secureFrozen = b.Cmd == "pause"
		w.WriteHeader(http.StatusNoContent)
	}
}

func writeStub(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

// runNB drives an nb-malform scenario against the stub and returns the verdict.
func runNB(t *testing.T, beh stubBehavior, sc gwScenario) *gwReport {
	t.Helper()
	stub := &benchStub{beh: beh}
	w := &gwWorld{bench: stub.start(t)}
	return runScenario(context.Background(), w, sc)
}

// runSB drives an sb-fault scenario against the stub and returns the verdict.
func runSB(t *testing.T, beh stubBehavior, sc gwScenario) *gwReport {
	t.Helper()
	stub := &benchStub{beh: beh}
	w := &gwWorld{bench: stub.start(t)}
	return runScenario(context.Background(), w, sc)
}

// findScenario returns the scenario with id from a family slice.
func findScenario(t *testing.T, scs []gwScenario, id string) gwScenario {
	t.Helper()
	for _, s := range scs {
		if s.ID == id {
			return s
		}
	}
	t.Fatalf("scenario %q not found", id)
	return gwScenario{}
}

func TestNBMalform_StubTeeth(t *testing.T) {
	fam := northboundMalformScenarios()
	huge := findScenario(t, fam, "nb-malform-huge-activepower")
	outage := findScenario(t, fam, "nb-headend-wan-outage")

	// Conformant gateway (uncapped baseline): stays up, never applies garbage → PASS.
	if rep := runNB(t, stubBehavior{}, huge); rep.Verdict != VerdictPass {
		t.Errorf("conformant nb-malform = %s, want PASS. findings: %v", rep.Verdict, rep.Findings)
	}
	// Applies an absurd setpoint off the malformed resource → FAIL.
	if rep := runNB(t, stubBehavior{absurdOnMalform: true}, huge); rep.Verdict != VerdictFail {
		t.Errorf("absurd-apply nb-malform = %s, want FAIL. findings: %v", rep.Verdict, rep.Findings)
	}
	// Goes dark (walker deadlock) under the outage → FAIL.
	if rep := runNB(t, stubBehavior{crashOnMalform: true}, outage); rep.Verdict != VerdictFail {
		t.Errorf("crash nb-headend = %s, want FAIL. findings: %v", rep.Verdict, rep.Findings)
	}
	// A safe cap that HOLDS through the malformation → PASS.
	if rep := runNB(t, stubBehavior{baselineCapPct: 25}, huge); rep.Verdict != VerdictPass {
		t.Errorf("held-cap nb-malform = %s, want PASS. findings: %v", rep.Verdict, rep.Findings)
	}
	// A safe cap the malformation UNSEATS to uncapped → FAIL.
	if rep := runNB(t, stubBehavior{baselineCapPct: 25, unseatOnMalform: true}, huge); rep.Verdict != VerdictFail {
		t.Errorf("unseat nb-malform = %s, want FAIL. findings: %v", rep.Verdict, rep.Findings)
	}
}

func TestSBFault_StubTeeth(t *testing.T) {
	fam := southboundFaultScenarios()
	plainIso := findScenario(t, fam, "sb-plain-comm-loss-isolation")
	plainGarbage := findScenario(t, fam, "sb-plain-register-garbage")
	secureComm := findScenario(t, fam, "sb-secure-comm-loss")

	// Conformant: a plain comm-loss is isolated, the secure DER keeps being polled → PASS.
	if rep := runSB(t, stubBehavior{}, plainIso); rep.Verdict != VerdictPass {
		t.Errorf("conformant isolation = %s, want PASS. findings: %v", rep.Verdict, rep.Findings)
	}
	// Broken isolation: the plain fault wedges the secure poll → FAIL.
	if rep := runSB(t, stubBehavior{wedgeOnFault: true}, plainIso); rep.Verdict != VerdictFail {
		t.Errorf("no-isolation = %s, want FAIL. findings: %v", rep.Verdict, rep.Findings)
	}
	// A garbage register that projects an absurd setpoint on the faulted DER → FAIL.
	if rep := runSB(t, stubBehavior{absurdOnFault: true}, plainGarbage); rep.Verdict != VerdictFail {
		t.Errorf("absurd-projection = %s, want FAIL. findings: %v", rep.Verdict, rep.Findings)
	}
	// Conformant secure comm-loss: poll stalls under the fault, RECOVERS after clear → PASS.
	if rep := runSB(t, stubBehavior{}, secureComm); rep.Verdict != VerdictPass {
		t.Errorf("comm-loss-recover = %s, want PASS. findings: %v", rep.Verdict, rep.Findings)
	}
	// Secure comm-loss that never heals → FAIL.
	if rep := runSB(t, stubBehavior{noRecover: true}, secureComm); rep.Verdict != VerdictFail {
		t.Errorf("no-recover = %s, want FAIL. findings: %v", rep.Verdict, rep.Findings)
	}
}
