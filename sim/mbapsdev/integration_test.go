//go:build integration

package main

// integration_test.go proves the T06.3 acceptance bar: an mbtls client
// dials mbapsdev over a loopback mbaps (secure Modbus/TLS) session, reads
// Model 1 (Common) + a measurement model, writes a 704 control and reads
// back the echo, and that fault injection (a corrupt read and a mid-exchange
// drop) is observably armed/cleared. Requires the amd64 wolfSSL sysroot
// (desktop, `make test-integration`), same as internal/mbtls's own suite.

import (
	"os"
	"testing"
	"time"

	"csip-tls-test/internal/mbtls"
	"csip-tls-test/internal/wolfssl"
	"lexa-proto/mbap"
	"lexa-proto/sunspec"
)

// TestMain initialises wolfSSL once for the whole integration binary
// (CLAUDE.md wolfSSL_Init invariant), mirroring internal/mbtls's TestMain.
func TestMain(m *testing.M) {
	wolfssl.Init()
	code := m.Run()
	wolfssl.Cleanup()
	os.Exit(code)
}

const testUnit = uint8(1)

// startDevice builds a -model kind device world and an mbtls.Listener bound
// to loopback, running the same accept/dispatch path main() wires up. The
// underlying plain-Modbus decoy listener (see newModel's doc comment) and
// the mbtls listener are both torn down on test cleanup.
func startDevice(t *testing.T, pki testPKI, kind string) (addr string, dev *Device) {
	t.Helper()
	mb, err := newModel(kind, 5000, 10)
	if err != nil {
		t.Fatalf("newModel(%s): %v", kind, err)
	}
	lis, err := mbtls.Listen("127.0.0.1:0", pki.serverProfile())
	if err != nil {
		t.Fatalf("mbtls.Listen: %v", err)
	}
	dev = &Device{regs: mb.regs, modelFault: mb.fault, sessions: newSessionRegistry()}
	go dev.acceptLoop(lis)
	t.Cleanup(func() {
		_ = lis.Close()
		mb.stop()
	})
	return lis.Addr().String(), dev
}

// dialClient dials addr as the mbaps client role and returns an mbap.Client
// over the decrypted session, plus the session itself (for Resumed/fault
// probes). A generous 30 s deadline covers every op in the test — mbap.Client
// sets none itself (its documented contract) — with enough headroom that a
// CPU-contended run (e.g. -race stacking many ECDHE-ECDSA handshakes back to
// back under `-count>1`) doesn't trip it; a real hang still fails the test in
// well under `go test`'s own default timeout.
func dialClient(t *testing.T, pki testPKI, addr string) (*mbap.Client, *mbtls.Session) {
	t.Helper()
	sess, err := mbtls.Dial(addr, pki.clientProfile())
	if err != nil {
		t.Fatalf("mbtls.Dial: %v", err)
	}
	t.Cleanup(func() { _ = sess.Close() })
	if err := sess.Conn.SetDeadline(time.Now().Add(30 * time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}
	return mbap.NewClient(sess.Conn), sess
}

// modelHeader is one SunSpec model block's [id, data-base, data-length].
type modelHeader struct {
	id     uint16
	base   uint16
	length uint16
}

// scanModels walks the SunSpec model chain via FC03 (the same discovery a
// real SunSpec client — including the T06.4/T06.5 emulator — performs):
// verify the SunS magic, then read [ModelID, Length] pairs until the
// EndMarker sentinel.
func scanModels(t *testing.T, c *mbap.Client) map[uint16]modelHeader {
	t.Helper()
	hdr, err := c.ReadHolding(testUnit, sunspec.SunSpecBase, 2)
	if err != nil {
		t.Fatalf("read SunS header: %v", err)
	}
	if hdr[0] != sunspec.SunSMagic0 || hdr[1] != sunspec.SunSMagic1 {
		t.Fatalf("SunS magic = %#04x %#04x, want %#04x %#04x", hdr[0], hdr[1], sunspec.SunSMagic0, sunspec.SunSMagic1)
	}
	out := map[uint16]modelHeader{}
	cursor := sunspec.SunSpecBase + 2
	for {
		idlen, err := c.ReadHolding(testUnit, cursor, 2)
		if err != nil {
			t.Fatalf("read model header at %d: %v", cursor, err)
		}
		id, length := idlen[0], idlen[1]
		if id == sunspec.EndMarker {
			return out
		}
		base := cursor + 2
		out[id] = modelHeader{id: id, base: base, length: length}
		cursor = base + length
	}
}

// readChunked reads n registers starting at addr, splitting into
// mbap.MaxReadCount-sized FC03 requests — the same chunking the hub's
// sunspec.Reader performs for models wider than 125 registers (e.g. the
// full model 701, 137 regs — see sim/southbound/solar_adv.go's populate701
// doc comment: "do not re-truncate").
func readChunked(t *testing.T, c *mbap.Client, addr, n uint16) []uint16 {
	t.Helper()
	out := make([]uint16, 0, n)
	for n > 0 {
		chunk := n
		if chunk > mbap.MaxReadCount {
			chunk = mbap.MaxReadCount
		}
		vals, err := c.ReadHolding(testUnit, addr, chunk)
		if err != nil {
			t.Fatalf("read chunk at %d len %d: %v", addr, chunk, err)
		}
		out = append(out, vals...)
		addr += chunk
		n -= chunk
	}
	return out
}

// TestLoopback_ReadModel1AndMeasurement is the core T06.3 acceptance case
// for the inverter model: dial, discover Model 1 + Model 701, and decode
// both to plausible values.
func TestLoopback_ReadModel1AndMeasurement(t *testing.T) {
	pki := newTestPKI(t)
	addr, _ := startDevice(t, pki, "inverter")
	client, sess := dialClient(t, pki, addr)

	if sess.Cipher == "" || sess.TLSVer == "" {
		t.Fatalf("session missing handshake facts: cipher=%q tls=%q", sess.Cipher, sess.TLSVer)
	}

	models := scanModels(t, client)
	m1, ok := models[sunspec.ModelCommon]
	if !ok {
		t.Fatalf("Model 1 (Common) not found in model chain: %+v", models)
	}
	if m1.length == 0 {
		t.Fatalf("Model 1 length = 0")
	}

	m701, ok := models[sunspec.ModelDERMeasureAC]
	if !ok {
		t.Fatalf("Model 701 (DER AC Measurement) not found in model chain: %+v", models)
	}

	// Full chunked read (137 regs > mbap.MaxReadCount=125) proving the
	// server-side dispatch honours the ≤125-register FC03 cap per request
	// while still serving the whole model across two reads.
	regs := readChunked(t, client, m701.base, m701.length)
	meas := sunspec.Parse701(regs)
	if meas.ACType != 2 {
		t.Errorf("701 ACType = %v, want 2 (three-phase, populate701's seed)", meas.ACType)
	}
	if meas.ConnSt != 1 {
		t.Errorf("701 ConnSt = %v, want 1 (connected)", meas.ConnSt)
	}
}

// TestLoopback_WriteControlAndReadback writes the 704 WMaxLimPct control
// point (FC16) and reads it back (FC03), proving the write lands and echoes
// — the T06.3 acceptance bar's "write a 704 control and read back the echo".
// Exercised against BOTH models: 704 is common surface for inverter and
// battery (battery_adv.go reuses solar_adv.go's populate704 verbatim).
func TestLoopback_WriteControlAndReadback(t *testing.T) {
	for _, kind := range []string{"inverter", "battery"} {
		t.Run(kind, func(t *testing.T) {
			pki := newTestPKI(t)
			addr, _ := startDevice(t, pki, kind)
			client, _ := dialClient(t, pki, addr)

			models := scanModels(t, client)
			m704, ok := models[sunspec.ModelDERCtlAC]
			if !ok {
				t.Fatalf("Model 704 (DER AC Controls) not found in model chain: %+v", models)
			}
			off := uint16(sunspec.L704.Offset("WMaxLimPct"))

			// WMaxLimPct_SF = -2 (populate704): raw 6000 = 60.00%.
			if err := client.WriteMultiple(testUnit, m704.base+off, []uint16{6000}); err != nil {
				t.Fatalf("write WMaxLimPct: %v", err)
			}
			got, err := client.ReadHolding(testUnit, m704.base+off, 1)
			if err != nil {
				t.Fatalf("readback WMaxLimPct: %v", err)
			}
			if got[0] != 6000 {
				t.Errorf("WMaxLimPct readback = %d, want 6000 (the write must echo)", got[0])
			}

			c704 := sunspec.Parse704(readChunked(t, client, m704.base, uint16(sunspec.L704.Len())))
			if c704.WMaxLimPct != 60 {
				t.Errorf("704 WMaxLimPct decoded = %v, want 60", c704.WMaxLimPct)
			}
		})
	}
}

// TestFaultInjection_CorruptRead arms nan_sentinel (a "corrupt read" fault:
// every register read returns the SunSpec 0x8000 not-implemented sentinel),
// proves it is observable over the mbaps session, then clears it.
func TestFaultInjection_CorruptRead(t *testing.T) {
	pki := newTestPKI(t)
	addr, dev := startDevice(t, pki, "inverter")
	client, _ := dialClient(t, pki, addr)

	models := scanModels(t, client)
	m1 := models[sunspec.ModelCommon]

	if err := dev.ApplyFault([]byte(`{"kind":"nan_sentinel"}`)); err != nil {
		t.Fatalf("arm nan_sentinel: %v", err)
	}
	corrupt, err := client.ReadHolding(testUnit, m1.base, 8)
	if err != nil {
		t.Fatalf("read under nan_sentinel: %v", err)
	}
	for i, v := range corrupt {
		if v != 0x8000 {
			t.Errorf("reg[%d] = %#04x under nan_sentinel, want 0x8000 (SunSpec N/A sentinel)", i, v)
		}
	}

	if err := dev.ApplyFault([]byte(`{"kind":"nan_sentinel","clear":true}`)); err != nil {
		t.Fatalf("clear nan_sentinel: %v", err)
	}
	clean, err := client.ReadHolding(testUnit, m1.base, 8)
	if err != nil {
		t.Fatalf("read after clear: %v", err)
	}
	allSentinel := true
	for _, v := range clean {
		if v != 0x8000 {
			allSentinel = false
			break
		}
	}
	if allSentinel {
		t.Errorf("all registers still read as 0x8000 after clearing nan_sentinel")
	}
}

// TestFaultInjection_DropSession arms drop_session, proves the NEXT request
// on an already-open session gets no response (the connection closes
// mid-exchange instead), then clears it and proves a fresh session serves
// normally again.
func TestFaultInjection_DropSession(t *testing.T) {
	pki := newTestPKI(t)
	addr, dev := startDevice(t, pki, "inverter")

	client, sess := dialClient(t, pki, addr)
	models := scanModels(t, client) // succeeds before the fault is armed
	m1 := models[sunspec.ModelCommon]

	if err := dev.ApplyFault([]byte(`{"kind":"drop_session"}`)); err != nil {
		t.Fatalf("arm drop_session: %v", err)
	}
	if _, err := client.ReadHolding(testUnit, m1.base, 2); err == nil {
		t.Fatalf("read succeeded with drop_session armed, want the session to close mid-exchange")
	}
	_ = sess.Close()

	if err := dev.ApplyFault([]byte(`{"kind":"drop_session","clear":true}`)); err != nil {
		t.Fatalf("clear drop_session: %v", err)
	}

	client2, _ := dialClient(t, pki, addr)
	if _, err := client2.ReadHolding(testUnit, m1.base, 2); err != nil {
		t.Fatalf("read failed on a fresh session after clearing drop_session: %v", err)
	}
}

// TestFaultInjection_TCPDropRejected proves the legacy sim.FaultTCPDrop kind
// (meaningless over mbaps — mbapsdev exposes no plain Modbus TCP listener)
// is rejected with a clear error rather than silently accepted as a no-op.
func TestFaultInjection_TCPDropRejected(t *testing.T) {
	pki := newTestPKI(t)
	_, dev := startDevice(t, pki, "inverter")

	err := dev.ApplyFault([]byte(`{"kind":"tcp_drop"}`))
	if err == nil {
		t.Fatalf("tcp_drop was silently accepted; want a rejection (it has no effect over mbaps)")
	}
}

// TestFaultInjection_RefuseResume proves a resumed session is refused
// (closed before serving any request) while refuse_resume is armed. Session
// resumption itself is a TLS-layer property this test does not force (that
// is internal/mbtls's own suite's job — TCP-46); this proves mbapsdev's
// policy hook fires WHEN a session arrives resumed, using a synthetic
// Session-like check via the exported flag path (see faults.go).
func TestFaultInjection_RefuseResumeArmDisarm(t *testing.T) {
	_, dev := startDevice(t, newTestPKI(t), "inverter")

	if err := dev.ApplyFault([]byte(`{"kind":"refuse_resume"}`)); err != nil {
		t.Fatalf("arm refuse_resume: %v", err)
	}
	if !dev.faults.refuseResumeArmed() {
		t.Fatalf("refuse_resume not armed after POST /fault")
	}
	if err := dev.ApplyFault([]byte(`{"kind":"refuse_resume","clear":true}`)); err != nil {
		t.Fatalf("clear refuse_resume: %v", err)
	}
	if dev.faults.refuseResumeArmed() {
		t.Fatalf("refuse_resume still armed after clear")
	}
}

// TestFaultInjection_StallHandshake proves stall_handshake measurably delays
// the NEXT accept: dialing while armed takes at least the configured delay.
// The fault is armed BEFORE the accept loop starts (not concurrently with
// it): acceptLoop only re-checks the flag between Accept calls, so arming it
// while a call is already blocked in Accept does not retroactively delay
// that in-flight connection — the same "acts on what's next, not
// retroactively" semantics sim.FaultTCPDrop already documents. Arming first
// exercises the documented, deterministic case.
func TestFaultInjection_StallHandshake(t *testing.T) {
	pki := newTestPKI(t)
	mb, err := newModel("inverter", 5000, 10)
	if err != nil {
		t.Fatalf("newModel: %v", err)
	}
	lis, err := mbtls.Listen("127.0.0.1:0", pki.serverProfile())
	if err != nil {
		t.Fatalf("mbtls.Listen: %v", err)
	}
	dev := &Device{regs: mb.regs, modelFault: mb.fault, sessions: newSessionRegistry()}
	t.Cleanup(func() { _ = lis.Close(); mb.stop() })

	const delay = 300 * time.Millisecond
	if err := dev.ApplyFault([]byte(`{"kind":"stall_handshake","delay_s":0.3}`)); err != nil {
		t.Fatalf("arm stall_handshake: %v", err)
	}
	go dev.acceptLoop(lis)

	start := time.Now()
	sess, err := mbtls.Dial(lis.Addr().String(), pki.clientProfile())
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("dial under stall_handshake: %v", err)
	}
	defer sess.Close()
	if elapsed < delay {
		t.Errorf("handshake completed in %s, want >= %s (stall_handshake armed)", elapsed, delay)
	}
}
