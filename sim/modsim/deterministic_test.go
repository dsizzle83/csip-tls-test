package main

// deterministic_test.go stands up the stack modsim actually serves — a real
// animated SunSpec inverter, a real wire tap in front of it, a real simapi
// control plane — and drives it exactly the way a conformance row does: over
// HTTP, with a Modbus client on the other side, and no sleeps deciding
// anything.
//
// It exists because every piece below it is already unit-tested and the thing
// that breaks is the WIRING. The four endpoints are registered by
// wireDeterministic, which main calls too, so a test that passes here is a
// statement about the binary rather than about a copy of it.

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
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

// stack is modsim's serving arrangement: device ← tap ← client, plus the
// control plane.
type stack struct {
	t         *testing.T
	srv       *sim.SolarServer
	tap       *sim.Tap
	epoch     *sim.Epoch
	baselines *sim.BaselineStore
	poke      *sim.RegisterPoke
	api       string // control-plane base URL
	modbus    string // the address a client dials
}

func newStack(t *testing.T) *stack {
	t.Helper()
	devAddr := freeAddr(t)
	srv, err := sim.NewSolarServer("tcp://"+devAddr, 8000, "SN-TEST-001")
	if err != nil {
		t.Fatalf("NewSolarServer: %v", err)
	}
	t.Cleanup(srv.Stop)

	epoch := sim.NewEpoch()
	tap, err := sim.NewTap(freeAddr(t), devAddr, epoch, sim.NewLedger(0), sim.NewPollTracker())
	if err != nil {
		t.Fatalf("NewTap: %v", err)
	}
	t.Cleanup(tap.Close)

	baselines := sim.NewBaselineStore(srv.Regs)
	poke := sim.NewRegisterPoke(srv.Regs)
	reloc := sim.NewRelocator(srv.Regs)
	baselines.OnReset("relocation", func() { reloc.Relocate(sunspec.SunSpecBase) })
	baselines.OnReset("poked registers", poke.Clear)
	baselines.OnReset("device faults", srv.ClearFaults)
	baselines.OnReset("wire-tap faults", tap.ClearFaults)
	baselines.OnReset("poll-cycle accounting", tap.Polls().Reset)
	baselines.Capture(sim.BaselineName)

	apiAddr := freeAddr(t)
	api := simapi.New(apiAddr,
		func() any { return srv.Snapshot() },
		func(body []byte) error {
			if handled, err := poke.ApplyInject(body); handled {
				return err
			}
			return srv.Inject(body)
		},
		func() any { return srv.Registers() },
		nil,
	)
	api.SetFaultFn(func(body []byte) error {
		if handled, err := reloc.ApplyFault(body); handled {
			return err
		}
		if handled, err := tap.ApplyFault(body); handled {
			return err
		}
		return srv.ApplyFault(body)
	})
	// THE function main calls. Nothing about the control plane is re-created
	// here, which is the point.
	wireDeterministic(api, epoch, baselines, tap)

	s := &stack{t: t, srv: srv, tap: tap, epoch: epoch, baselines: baselines, poke: poke,
		api: "http://" + apiAddr, modbus: tap.Addr()}
	s.waitAPI()
	return s
}

// freeAddr returns a loopback address nothing is listening on. simapi.New and
// the sim server both bind their own listener from a string, so the port has
// to be chosen before either is constructed.
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

func (s *stack) waitAPI() {
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

func (s *stack) do(method, path, body string, out any) (int, string) {
	s.t.Helper()
	var rdr io.Reader
	if body != "" {
		rdr = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, s.api+path, rdr)
	if err != nil {
		s.t.Fatalf("%s %s: %v", method, path, err)
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		s.t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if out != nil && len(raw) > 0 {
		if err := json.Unmarshal(raw, out); err != nil {
			s.t.Fatalf("%s %s: decode %s: %v", method, path, raw, err)
		}
	}
	return resp.StatusCode, string(raw)
}

// ack posts a mutation and returns the epoch it is in force from.
func (s *stack) ack(method, path, body string) simapi.Ack {
	s.t.Helper()
	var a simapi.Ack
	code, raw := s.do(method, path, body, &a)
	if code != http.StatusOK {
		s.t.Fatalf("%s %s = %d: %s", method, path, code, raw)
	}
	if a.Epoch == 0 {
		s.t.Fatalf("%s %s acknowledged with no epoch: %s", method, path, raw)
	}
	return a
}

// ledgerSince fetches the transactions at or after an epoch.
func (s *stack) ledgerSince(epoch uint64) ledgerEnvelope {
	s.t.Helper()
	var page ledgerEnvelope
	code, raw := s.do(http.MethodGet, fmt.Sprintf("/ledger?since_epoch=%d", epoch), "", &page)
	if code != http.StatusOK {
		s.t.Fatalf("GET /ledger = %d: %s", code, raw)
	}
	return page
}

// pollWait blocks on the barrier through HTTP, looping across the endpoint's
// own per-request bound the way a harness does.
func (s *stack) pollWait(want uint64, budget time.Duration) pollEnvelope {
	s.t.Helper()
	deadline := time.Now().Add(budget)
	for {
		var body pollEnvelope
		code, raw := s.do(http.MethodGet, fmt.Sprintf("/poll/wait?epoch=%d&timeout=2s", want), "", &body)
		if code != http.StatusOK {
			s.t.Fatalf("GET /poll/wait = %d: %s", code, raw)
		}
		if body.Reached {
			return body
		}
		if !time.Now().Before(deadline) {
			s.t.Fatalf("the poll barrier did not reach cycle %d within %s (state %+v)", want, budget, body.Poll)
		}
	}
}

// ── A client shaped like the product ──────────────────────────────────────────

// client is a Modbus/TCP client with lexa-gw's poll shape: one connection,
// serialized transactions, an advancing transaction id.
type client struct {
	t    *testing.T
	conn net.Conn
	txn  uint16
	unit uint8
}

func (s *stack) dial() *client {
	s.t.Helper()
	conn, err := net.DialTimeout("tcp", s.modbus, 2*time.Second)
	if err != nil {
		s.t.Fatalf("dial %s: %v", s.modbus, err)
	}
	c := &client{t: s.t, conn: conn, unit: 1}
	s.t.Cleanup(func() { _ = conn.Close() })
	return c
}

func (c *client) request(pdu []byte, deadline time.Duration) ([]byte, error) {
	c.txn++
	out := make([]byte, 7, 7+len(pdu))
	binary.BigEndian.PutUint16(out[0:2], c.txn)
	binary.BigEndian.PutUint16(out[2:4], 0)
	binary.BigEndian.PutUint16(out[4:6], uint16(len(pdu)+1))
	out[6] = c.unit
	out = append(out, pdu...)
	if err := c.conn.SetDeadline(time.Now().Add(deadline)); err != nil {
		return nil, err
	}
	if _, err := c.conn.Write(out); err != nil {
		return nil, err
	}
	hdr := make([]byte, 7)
	if _, err := io.ReadFull(c.conn, hdr); err != nil {
		return nil, err
	}
	n := int(binary.BigEndian.Uint16(hdr[4:6])) - 1
	if n < 0 || n > 300 {
		return nil, fmt.Errorf("implausible MBAP length %d", n+1)
	}
	rest := make([]byte, n)
	if _, err := io.ReadFull(c.conn, rest); err != nil {
		return nil, err
	}
	return append(hdr, rest...), nil
}

func (c *client) read(addr, count uint16, deadline time.Duration) ([]byte, error) {
	pdu := []byte{0x03}
	pdu = binary.BigEndian.AppendUint16(pdu, addr)
	pdu = binary.BigEndian.AppendUint16(pdu, count)
	return c.request(pdu, deadline)
}

func (c *client) mustRead(addr, count uint16) []byte {
	c.t.Helper()
	resp, err := c.read(addr, count, 3*time.Second)
	if err != nil {
		c.t.Fatalf("read %d×%d: %v", addr, count, err)
	}
	return resp
}

func (c *client) writeMultiple(addr uint16, vals []uint16) []byte {
	c.t.Helper()
	pdu := []byte{0x10}
	pdu = binary.BigEndian.AppendUint16(pdu, addr)
	pdu = binary.BigEndian.AppendUint16(pdu, uint16(len(vals)))
	pdu = append(pdu, byte(len(vals)*2))
	for _, v := range vals {
		pdu = binary.BigEndian.AppendUint16(pdu, v)
	}
	resp, err := c.request(pdu, 3*time.Second)
	if err != nil {
		c.t.Fatalf("write %d: %v", addr, err)
	}
	return resp
}

// pollCycle mimics the product's steady-state cycle: the measurement model,
// then its continuation.
func (c *client) pollCycle() {
	c.t.Helper()
	c.mustRead(40070, 60)
	c.mustRead(40130, 20)
}

// ── The cases ─────────────────────────────────────────────────────────────────

// TestStack_ArmAckWaitGrade walks the whole loop a rewritten conformance row
// runs: reset for a known device, arm with an epoch, wait for a poll on the
// barrier, grade the ledger for that fence. No step is decided by elapsed time.
func TestStack_ArmAckWaitGrade(t *testing.T) {
	s := newStack(t)
	c := s.dial()

	// 1. A known device, and the anchor declared so the barrier is usable from
	//    the first cycle rather than after the learning phase.
	reset := s.ack(http.MethodPost, "/reset",
		`{"baseline":"as-built","poll_anchor":{"addr":40070,"count":60}}`)
	res, _ := reset.Result.(map[string]any)
	if res["baseline"] != "as-built" {
		t.Fatalf("reset reported baseline %v", res["baseline"])
	}
	if cleared, _ := res["cleared"].([]any); len(cleared) != 5 {
		t.Fatalf("reset reported %v cleared layers, want the 5 this stack registered", res["cleared"])
	}
	if res["poll_anchor_source"] != "declared" {
		t.Fatalf("poll_anchor_source = %v, want declared", res["poll_anchor_source"])
	}

	// 2. Two cycles so one has completed.
	c.pollCycle()
	c.pollCycle()
	first := s.pollWait(1, 10*time.Second)
	if first.Poll.Anchor.Addr != 40070 {
		t.Fatalf("the barrier used anchor %+v, want the declared 40070", first.Poll.Anchor)
	}

	// 3. Arm a one-shot, ACK carries the epoch it is armed from.
	armed := s.ack(http.MethodPost, "/fault",
		`{"kind":"next_response","action":"drop","on_fc":3,"on_addr":[40070,40130]}`)
	if armed.Epoch <= reset.Epoch {
		t.Fatalf("the arm epoch %d is not later than the reset's %d", armed.Epoch, reset.Epoch)
	}

	// 4. The client meets it, and the transaction it lands in is the one the
	//    fault named — not whichever one happened to be running.
	if _, err := c.read(40070, 60, 300*time.Millisecond); err == nil {
		t.Fatal("the read inside the armed range was answered")
	}

	// 5. Grade the ledger for the fence. It holds that transaction and no
	//    earlier one.
	page := s.ledgerSince(armed.Epoch)
	if len(page.Entries) != 1 {
		t.Fatalf("%d transaction(s) at or after epoch %d, want 1 — the fence must exclude every "+
			"transaction that predates the arm", len(page.Entries), armed.Epoch)
	}
	e := page.Entries[0]
	if e.Outcome != sim.OutcomeDropped {
		t.Fatalf("outcome = %q, want %q", e.Outcome, sim.OutcomeDropped)
	}
	if e.Addr != 40070 || e.Count != 60 || e.FC != 0x03 {
		t.Fatalf("the ledger recorded fc=%#02x addr=%d count=%d, want the read the fault was aimed at",
			e.FC, e.Addr, e.Count)
	}
	if e.Request == "" {
		t.Fatal("the ledger recorded no request bytes")
	}
	if _, err := hex.DecodeString(e.Request); err != nil {
		t.Fatalf("the recorded request is not hex: %v", err)
	}
	if page.APIVersion != simapi.APIVersion {
		t.Errorf("api_version = %q, want %q", page.APIVersion, simapi.APIVersion)
	}
}

// TestStack_LedgerRoundTripsThroughSimapi: every field a row grades on
// survives JSON.
func TestStack_LedgerRoundTripsThroughSimapi(t *testing.T) {
	s := newStack(t)
	c := s.dial()
	fence := s.ack(http.MethodPost, "/reset", `{}`).Epoch

	c.mustRead(40000, 2)
	c.writeMultiple(40070, []uint16{0x1234})

	page := s.ledgerSince(fence)
	if len(page.Entries) != 2 {
		t.Fatalf("%d entries, want 2", len(page.Entries))
	}
	read, write := page.Entries[0], page.Entries[1]
	if !read.IsRead() || read.Addr != 40000 || read.Count != 2 {
		t.Errorf("the read entry decoded as %+v", read)
	}
	if !write.IsWrite() || write.FC != 0x10 || write.Addr != 40070 || write.Count != 1 {
		t.Errorf("the write entry decoded as %+v", write)
	}
	if write.Outcome != sim.OutcomeAnswered {
		t.Errorf("write outcome = %q, want %q", write.Outcome, sim.OutcomeAnswered)
	}
	if read.ResponseAt == nil || read.ResponseAt.Before(read.RequestAt) {
		t.Errorf("the read's timestamps did not survive JSON: request_at=%v response_at=%v",
			read.RequestAt, read.ResponseAt)
	}
	if read.Peer == "" || read.Conn == 0 {
		t.Errorf("connection provenance did not survive JSON: peer=%q conn=%d", read.Peer, read.Conn)
	}
	if page.HighSeq < 2 {
		t.Errorf("high_seq = %d, want at least 2", page.HighSeq)
	}
	if page.Poll.Rule == "" {
		t.Error("the ledger's answer does not carry the poll rule; a bundle must record the definition " +
			"alongside the number")
	}
}

// TestStack_ResetRestoresAPokedRegister is the write rows' teardown: the
// divergence lever must leave the device as it found it.
func TestStack_ResetRestoresAPokedRegister(t *testing.T) {
	s := newStack(t)
	c := s.dial()

	before := c.mustRead(40070, 1)
	original := binary.BigEndian.Uint16(before[9:11])

	if code, raw := s.do(http.MethodPost, "/inject",
		fmt.Sprintf(`{"registers":[{"addr":40070,"value":%d}]}`, original^0x5A5A), nil); code != http.StatusOK {
		t.Fatalf("POST /inject = %d: %s", code, raw)
	}
	after := c.mustRead(40070, 1)
	if binary.BigEndian.Uint16(after[9:11]) == original {
		t.Fatal("the poke did not reach the served register")
	}

	s.ack(http.MethodPost, "/reset", `{}`)
	restored := c.mustRead(40070, 1)
	if got := binary.BigEndian.Uint16(restored[9:11]); got != original {
		t.Fatalf("register 40070 serves %#04x after a reset, want the original %#04x", got, original)
	}
}

// TestStack_ResetDisarmsAOneShot: a row that resets must not inherit the
// previous row's provocation.
func TestStack_ResetDisarmsAOneShot(t *testing.T) {
	s := newStack(t)
	c := s.dial()
	s.ack(http.MethodPost, "/fault", `{"kind":"next_response","action":"drop","on_fc":3}`)
	s.ack(http.MethodPost, "/reset", `{}`)
	c.mustRead(40070, 4) // would hang if the one-shot had survived
}

// TestStack_ResetRefusesAnUnknownBaselineAndDoesNotMoveTheFence.
func TestStack_ResetRefusesAnUnknownBaselineAndDoesNotMoveTheFence(t *testing.T) {
	s := newStack(t)
	before := s.ack(http.MethodPost, "/reset", `{}`).Epoch
	code, raw := s.do(http.MethodPost, "/reset", `{"baseline":"nope"}`, nil)
	if code != http.StatusBadRequest {
		t.Fatalf("POST /reset with an unknown baseline = %d, want 400", code)
	}
	if !strings.Contains(raw, sim.BaselineName) {
		t.Errorf("the refusal %q does not name the baselines that do exist", raw)
	}
	after := s.ack(http.MethodPost, "/reset", `{}`).Epoch
	if after != before+1 {
		t.Fatalf("the epoch moved from %d to %d across a REFUSED reset; a fence must name a change that "+
			"actually happened", before, after)
	}
}

// TestStack_PollBarrierLearnsFromRealTraffic: with no anchor declared, the tap
// works the cycle out from a client shaped like the product.
func TestStack_PollBarrierLearnsFromRealTraffic(t *testing.T) {
	s := newStack(t)
	c := s.dial()
	s.ack(http.MethodPost, "/reset", `{}`)

	// A session's discovery burst, then steady-state cycles.
	c.mustRead(40000, 2)
	c.mustRead(40002, 2)
	c.mustRead(40004, 66)
	for i := 0; i < 4; i++ {
		c.pollCycle()
	}

	var body pollEnvelope
	if code, raw := s.do(http.MethodGet, "/poll", "", &body); code != http.StatusOK {
		t.Fatalf("GET /poll = %d: %s", code, raw)
	}
	if !body.Poll.AnchorLocked {
		t.Fatalf("no anchor was learned from a product-shaped conversation; candidates %+v",
			body.Poll.Learning)
	}
	if body.Poll.Anchor.Addr != 40070 || body.Poll.AnchorSource != "learned" {
		t.Fatalf("anchor = %+v (%s), want the measurement read at 40070, learned",
			body.Poll.Anchor, body.Poll.AnchorSource)
	}
	if body.Poll.Completed < 2 {
		t.Fatalf("completed = %d after four cycles, want at least 2", body.Poll.Completed)
	}
	if body.Tap.Connections != 1 {
		t.Errorf("the tap reports %d connection(s), want 1", body.Tap.Connections)
	}
}

// TestStack_UnitIDGateThroughTheControlPlane is CLI-3's setup step end to end.
func TestStack_UnitIDGateThroughTheControlPlane(t *testing.T) {
	s := newStack(t)
	fence := s.ack(http.MethodPost, "/fault", `{"kind":"unit_id","unit_id":7}`).Epoch

	c := s.dial()
	c.unit = 1
	resp := c.mustRead(40070, 4)
	if resp[7] != 0x83 || resp[8] != 0x0B {
		t.Fatalf("a request for unit 1 answered %x, want exception 0x83/0x0B", resp[7:])
	}
	c.unit = 7
	c.mustRead(40070, 4)

	page := s.ledgerSince(fence)
	if len(page.Entries) != 2 {
		t.Fatalf("%d transaction(s), want 2", len(page.Entries))
	}
	if page.Entries[0].Exception != 0x0B {
		t.Errorf("the refused transaction records exception %#02x", page.Entries[0].Exception)
	}
	if page.Entries[1].Outcome != sim.OutcomeAnswered {
		t.Errorf("the transaction at the new unit id has outcome %q", page.Entries[1].Outcome)
	}
}

// TestStack_UnknownFaultKindStillReachesTheDevice: the tap must not swallow a
// kind it does not own, or every device-level fault would stop working the
// moment the tap was interposed.
func TestStack_UnknownFaultKindStillReachesTheDevice(t *testing.T) {
	s := newStack(t)
	s.ack(http.MethodPost, "/fault", `{"kind":"nan_sentinel"}`)
	c := s.dial()
	resp := c.mustRead(40070, 2)
	if got := binary.BigEndian.Uint16(resp[9:11]); got != 0x8000 {
		t.Fatalf("register 40070 read %#04x with nan_sentinel armed, want the 0x8000 sentinel — the "+
			"device-level fault chain did not run", got)
	}
	code, raw := s.do(http.MethodPost, "/fault", `{"kind":"no_such_kind"}`, nil)
	if code != http.StatusBadRequest {
		t.Fatalf("an unknown kind answered %d, want 400: %s", code, raw)
	}
}

// TestStack_WithoutATapTheEndpointsRefuseByName — -tap=false must not make a
// row read an empty ledger as "the client did nothing".
func TestStack_WithoutATapTheEndpointsRefuseByName(t *testing.T) {
	devAddr := freeAddr(t)
	srv, err := sim.NewSolarServer("tcp://"+devAddr, 8000, "SN-TEST-002")
	if err != nil {
		t.Fatalf("NewSolarServer: %v", err)
	}
	t.Cleanup(srv.Stop)
	epoch := sim.NewEpoch()
	baselines := sim.NewBaselineStore(srv.Regs)
	baselines.Capture(sim.BaselineName)

	apiAddr := freeAddr(t)
	api := simapi.New(apiAddr, func() any { return srv.Snapshot() }, nil, nil, nil)
	api.SetFaultFn(func(body []byte) error {
		if sim.TapFaultRequested(body) {
			return sim.ErrNoTap
		}
		return srv.ApplyFault(body)
	})
	wireDeterministic(api, epoch, baselines, nil)

	s := &stack{t: t, api: "http://" + apiAddr}
	s.waitAPI()

	for _, path := range []string{"/ledger", "/poll", "/poll/wait?epoch=1"} {
		code, raw := s.do(http.MethodGet, path, "", nil)
		if code != http.StatusNotImplemented {
			t.Errorf("GET %s = %d, want 501", path, code)
		}
		if !strings.Contains(raw, "wire tap") {
			t.Errorf("GET %s said %q, want a reason naming the missing tap", path, raw)
		}
	}
	// /reset needs no tap and must keep working.
	if code, raw := s.do(http.MethodPost, "/reset", `{}`, nil); code != http.StatusOK {
		t.Errorf("POST /reset without a tap = %d: %s", code, raw)
	}
	// A tap fault is refused BY NAME, so a row reports SKIP-with-reason.
	code, raw := s.do(http.MethodPost, "/fault", `{"kind":"next_response","action":"drop"}`, nil)
	if code != http.StatusBadRequest || !strings.Contains(raw, "wire tap") {
		t.Errorf("POST /fault next_response without a tap = %d %q, want a 400 naming the tap", code, raw)
	}
}

// TestStack_TCPDropSeversTheClientThroughTheTap is the property every
// discovery row rests on, and the one the tap could most plausibly have
// broken.
//
// tcp_drop bounces the DEVICE's listener. With the tap interposed the client is
// not connected to that listener — it is connected to the tap — so the
// severance only reaches it if the tap propagates its upstream's death to the
// downstream socket. If it did not, every row that forces a rediscovery would
// silently observe a client that never reconnected.
func TestStack_TCPDropSeversTheClientThroughTheTap(t *testing.T) {
	s := newStack(t)
	c := s.dial()
	c.mustRead(40070, 4)

	s.ack(http.MethodPost, "/fault", `{"kind":"tcp_drop"}`)

	// The client's next read on the OLD socket must fail: the connection it
	// held is gone.
	deadline := time.Now().Add(5 * time.Second)
	severed := false
	for time.Now().Before(deadline) {
		if _, err := c.read(40070, 4, 500*time.Millisecond); err != nil {
			severed = true
			break
		}
	}
	if !severed {
		t.Fatal("the client's connection survived a tcp_drop; with the tap interposed the severance " +
			"must be propagated downstream, or every forced-rediscovery row observes a client that " +
			"never reconnected")
	}

	// And a fresh dial works: the device rebound its listener and the tap
	// forwards to it again.
	c2 := s.dial()
	c2.mustRead(40070, 4)

	// The reconnect is visible in the ledger without a capture, which is what
	// the discovery rows grade.
	page := s.ledgerSince(0)
	conns := map[uint64]bool{}
	for _, e := range page.Entries {
		conns[e.Conn] = true
	}
	if len(conns) < 2 {
		t.Fatalf("the ledger reports %d connection(s) across a reconnect, want at least 2", len(conns))
	}
	if st := s.tap.Polls().Snapshot(); st.Sessions < 2 {
		t.Errorf("the poll tracker counted %d session(s), want at least 2", st.Sessions)
	}
}

// TestStack_LedgerBarrierAnswersThroughSimapi covers the endpoint the
// exception and truncation rows wait on — the one the poll barrier cannot
// answer for them.
func TestStack_LedgerBarrierAnswersThroughSimapi(t *testing.T) {
	s := newStack(t)
	c := s.dial()
	fence := s.ack(http.MethodPost, "/reset", `{}`).Epoch

	done := make(chan struct{})
	go func() {
		defer close(done)
		c.mustRead(40070, 4)
		c.mustRead(40074, 4)
	}()

	var body ledgerEnvelope
	code, raw := s.do(http.MethodGet,
		fmt.Sprintf("/ledger?since_epoch=%d&min_entries=2&timeout=10s", fence), "", &body)
	if code != http.StatusOK {
		t.Fatalf("GET /ledger?min_entries= = %d: %s", code, raw)
	}
	<-done
	if body.Total < 2 {
		t.Fatalf("the barrier returned %d transaction(s), want the 2 it waited for", body.Total)
	}
	for _, e := range body.Entries {
		if e.Outcome == "" {
			t.Fatalf("transaction seq %d has no outcome; the barrier returned with one in flight", e.Seq)
		}
	}
}
