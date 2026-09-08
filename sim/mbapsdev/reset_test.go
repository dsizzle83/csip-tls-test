package main

// reset_test.go proves POST /reset actually round-trips through this
// device's real register world and its own mbaps-transport fault layer
// (WP7-T6, REV0907-E6) — the wiring reset.go and main.go add, exercised the
// same way modsim's own TestStack_ResetRestoresAPokedRegister proves its
// sibling: state after inject/arm → reset → the as-built baseline.
//
// No mtls dial is needed: mbapsdev serves every mbaps request by calling
// RegisterMap.HandleHoldingRegisters directly against mb.regs (dispatch.go's
// doc comment), so the register world is reachable in-process, and the
// control plane under test here is simapi's HTTP surface, not the secure
// Modbus one.

import (
	"encoding/json"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"csip-tls-test/sim/simapi"
	sim "csip-tls-test/sim/southbound"
	"lexa-proto/sunspec"
)

// mbapsdevStack is mbapsdev's serving arrangement for this test: a real
// animated inverter model, its faults layer, and the control plane
// wireDeterministic registers — the SAME call main() makes.
type mbapsdevStack struct {
	t   *testing.T
	mb  *modelBundle
	dev *Device
	api string // control-plane base URL
}

func freeAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("probe listen: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	return addr
}

func newMbapsdevStack(t *testing.T) *mbapsdevStack {
	t.Helper()
	mb, err := newModel("inverter", 5000, 10, "")
	if err != nil {
		t.Fatalf("newModel(inverter): %v", err)
	}
	t.Cleanup(mb.stop)

	dev := &Device{regs: mb.regs, modelFault: mb.fault, sessions: newSessionRegistry()}

	apiAddr := freeAddr(t)
	api := simapi.New(apiAddr,
		func() any { return dev.stateSnapshot(mb.snapshot()) },
		mb.inject,
		mb.registers,
		mb.control,
	)
	api.SetFaultFn(dev.ApplyFault)

	// THE wiring main() calls, unmodified — a test that passes here is a
	// statement about the binary, not about a copy of it.
	epoch := sim.NewEpoch()
	baselines := sim.NewBaselineStore(mb.regs)
	baselines.OnReset("mbaps-transport faults (drop_session, refuse_resume, stall_handshake)", dev.faults.clear)
	if mb.clearFaults != nil {
		baselines.OnReset("device faults (register, lying, legacy-curve, reversion timers)", mb.clearFaults)
	}
	baselines.Capture(sim.BaselineName)
	wireDeterministic(api, epoch, baselines)

	s := &mbapsdevStack{t: t, mb: mb, dev: dev, api: "http://" + apiAddr}
	s.waitAPI()
	return s
}

func (s *mbapsdevStack) waitAPI() {
	s.t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if resp, err := http.Get(s.api + "/version"); err == nil {
			_ = resp.Body.Close()
			return
		}
	}
	s.t.Fatalf("the control plane at %s never came up", s.api)
}

func (s *mbapsdevStack) do(method, path, body string) (int, string) {
	s.t.Helper()
	var rdr io.Reader
	if body != "" {
		rdr = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, s.api+path, rdr)
	if err != nil {
		s.t.Fatalf("new request %s %s: %v", method, path, err)
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		s.t.Fatalf("%s %s: %v", method, path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		s.t.Fatalf("read body of %s %s: %v", method, path, err)
	}
	return resp.StatusCode, string(raw)
}

// TestReset_RestoresARegisterPokedDirectly proves the baseline-image half:
// a register mutated after the as-built capture is put back by POST /reset,
// through the SAME BaselineStore main() wires. sunspec.SunSpecBase (40000,
// the "SunS" marker every SunSpec chain opens with) is used because it is
// GUARANTEED populated on any model this sim can build, so this proof does
// not depend on knowing one model's own register layout.
func TestReset_RestoresARegisterPokedDirectly(t *testing.T) {
	s := newMbapsdevStack(t)

	const addr = sunspec.SunSpecBase
	original := s.mb.regs.Get(addr)
	poked := original ^ 0x1234

	s.mb.regs.Set(addr, poked)
	if got := s.mb.regs.Get(addr); got != poked {
		t.Fatalf("the direct poke did not take: register reads %#04x, want %#04x", got, poked)
	}

	code, raw := s.do(http.MethodPost, "/reset", `{}`)
	if code != http.StatusOK {
		t.Fatalf("POST /reset = %d: %s", code, raw)
	}

	if got := s.mb.regs.Get(addr); got != original {
		t.Fatalf("register %d serves %#04x after POST /reset, want the as-built %#04x — the reset did "+
			"not restore the register image", addr, got, original)
	}
}

// TestReset_DisarmsAnMbapsTransportFault proves the transport-fault half —
// the layer sim.SolarServer.ClearFaults has NO visibility into (faults.go's
// mbapsFaults) — is cleared by the SAME reset, through dev.faults.clear.
func TestReset_DisarmsAnMbapsTransportFault(t *testing.T) {
	s := newMbapsdevStack(t)

	code, raw := s.do(http.MethodPost, "/fault", `{"kind":"drop_session"}`)
	if code != http.StatusOK {
		t.Fatalf("POST /fault drop_session = %d: %s", code, raw)
	}
	if !s.dev.faults.dropArmed() {
		t.Fatal("drop_session did not arm — the fixture, not the reset, is broken")
	}

	code, raw = s.do(http.MethodPost, "/reset", `{}`)
	if code != http.StatusOK {
		t.Fatalf("POST /reset = %d: %s", code, raw)
	}
	if s.dev.faults.dropArmed() {
		t.Fatal("drop_session is still armed after POST /reset — the mbaps-transport fault layer was not " +
			"cleared, so a gating campaign's reset (preflightSimReset) would carry a prior row's armed " +
			"fault straight into the next one")
	}
}

// TestReset_AcknowledgesWithAnEpoch proves the acknowledgement shape
// preflightSimReset reads (internal/certify/preflight.go): a JSON body
// carrying api_version and a monotonically-advancing epoch, not the historic
// 204 an unregistered epoch counter would answer with.
func TestReset_AcknowledgesWithAnEpoch(t *testing.T) {
	s := newMbapsdevStack(t)

	code, raw := s.do(http.MethodPost, "/reset", `{}`)
	if code != http.StatusOK {
		t.Fatalf("POST /reset = %d: %s", code, raw)
	}
	var ack struct {
		APIVersion string `json:"api_version"`
		Epoch      uint64 `json:"epoch"`
	}
	if err := json.Unmarshal([]byte(raw), &ack); err != nil {
		t.Fatalf("decode POST /reset body %q: %v", raw, err)
	}
	if ack.APIVersion == "" {
		t.Error("POST /reset's acknowledgement carries no api_version")
	}
	if ack.Epoch == 0 {
		t.Error("POST /reset's acknowledgement carries epoch=0 — a fence a caller cannot distinguish from " +
			"an unregistered counter")
	}

	code2, raw2 := s.do(http.MethodPost, "/reset", `{}`)
	if code2 != http.StatusOK {
		t.Fatalf("second POST /reset = %d: %s", code2, raw2)
	}
	var ack2 struct {
		Epoch uint64 `json:"epoch"`
	}
	if err := json.Unmarshal([]byte(raw2), &ack2); err != nil {
		t.Fatalf("decode second POST /reset body %q: %v", raw2, err)
	}
	if ack2.Epoch <= ack.Epoch {
		t.Errorf("epoch did not advance across a second reset: %d then %d", ack.Epoch, ack2.Epoch)
	}
}

// TestReset_RefusesAnUnknownBaseline proves preflightSimReset's refusal path
// has something real to hit: an operator (or a stale -param) naming a
// baseline this sim never captured gets a 400 naming the ones that do exist,
// not a silent fall-back to some other image.
func TestReset_RefusesAnUnknownBaseline(t *testing.T) {
	s := newMbapsdevStack(t)
	code, raw := s.do(http.MethodPost, "/reset", `{"baseline":"nope"}`)
	if code != http.StatusBadRequest {
		t.Fatalf("POST /reset with an unknown baseline = %d, want 400: %s", code, raw)
	}
	if !strings.Contains(raw, sim.BaselineName) {
		t.Errorf("the refusal %q does not name the baseline(s) that do exist", raw)
	}
}
