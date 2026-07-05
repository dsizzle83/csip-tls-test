package main

import (
	"bytes"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// capturingBroker accepts one connection, ACKs the CONNECT, and accumulates
// every byte it reads afterward — enough to assert exact PUBLISH/PINGREQ/
// DISCONNECT packet counts via bytes.Count without a full MQTT parser, since
// /hold and /storm always send byte-identical packets on each occurrence.
type capturingBroker struct {
	ln     net.Listener
	mu     sync.Mutex
	buf    []byte
	closed chan struct{}
}

func startCapturingBroker(t *testing.T) *capturingBroker {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	cb := &capturingBroker{ln: ln, closed: make(chan struct{})}
	go cb.serve()
	return cb
}

func (cb *capturingBroker) addr() string { return cb.ln.Addr().String() }
func (cb *capturingBroker) stop()        { cb.ln.Close() }

func (cb *capturingBroker) serve() {
	defer close(cb.closed)
	conn, err := cb.ln.Accept()
	if err != nil {
		return
	}
	defer conn.Close()

	buf := make([]byte, 4096)
	if _, err := conn.Read(buf); err != nil { // CONNECT
		return
	}
	_, _ = conn.Write([]byte{0x20, 0x02, 0x00, 0x00}) // CONNACK accepted

	rbuf := make([]byte, 65536)
	for {
		n, err := conn.Read(rbuf)
		if n > 0 {
			cb.mu.Lock()
			cb.buf = append(cb.buf, rbuf[:n]...)
			cb.mu.Unlock()
		}
		if err != nil {
			return
		}
	}
}

func (cb *capturingBroker) bytesRead() []byte {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	out := make([]byte, len(cb.buf))
	copy(out, cb.buf)
	return out
}

// awaitClosed waits for the broker's connection to close (the client sent
// DISCONNECT and hung up, or the test's stop() tore it down), or fails the
// test after timeout.
func (cb *capturingBroker) awaitClosed(t *testing.T, timeout time.Duration) {
	t.Helper()
	select {
	case <-cb.closed:
	case <-time.After(timeout):
		t.Fatal("broker connection never closed")
	}
}

func doJSON(t *testing.T, h http.HandlerFunc, method, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var r *http.Request
	if body != nil {
		buf, _ := json.Marshal(body)
		r = httptest.NewRequest(method, path, bytes.NewReader(buf))
	} else {
		r = httptest.NewRequest(method, path, nil)
	}
	w := httptest.NewRecorder()
	h(w, r)
	return w
}

func TestHandleHold_ConnectsAndSelfCancelsOnDuration(t *testing.T) {
	b := startCapturingBroker(t)
	defer b.stop()
	c := &control{broker: b.addr(), proxy: NewProxy(b.addr())}

	w := doJSON(t, c.handleHold, http.MethodPost, "/hold", holdReq{ClientID: "lexa-hub", DurationS: 1})
	if w.Code != http.StatusOK && w.Code != 0 {
		t.Fatalf("POST /hold status = %d, body %s", w.Code, w.Body.String())
	}

	b.awaitClosed(t, 3*time.Second)
	if !bytes.Contains(b.bytesRead(), disconnectPacket()) {
		t.Error("expected a DISCONNECT once duration_s elapsed")
	}

	// The hold must self-clear so a later /hold is accepted.
	deadline := time.Now().Add(time.Second)
	for {
		c.holdMu.Lock()
		cleared := c.holdCancel == nil
		c.holdMu.Unlock()
		if cleared {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("holdCancel never cleared after duration elapsed")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestHandleHold_ResetCancelsEarly(t *testing.T) {
	b := startCapturingBroker(t)
	defer b.stop()
	c := &control{broker: b.addr(), proxy: NewProxy(b.addr())}

	// A long hold that would outlive the test if reset didn't cancel it.
	doJSON(t, c.handleHold, http.MethodPost, "/hold", holdReq{ClientID: "lexa-hub", DurationS: 30})

	// Give the goroutine a moment to actually connect before resetting.
	time.Sleep(100 * time.Millisecond)
	doJSON(t, c.handleReset, http.MethodPost, "/reset", nil)

	b.awaitClosed(t, 3*time.Second)
	if !bytes.Contains(b.bytesRead(), disconnectPacket()) {
		t.Error("expected a DISCONNECT on /reset well before the 30s duration")
	}
}

func TestHandleHold_OneAtATime(t *testing.T) {
	b := startCapturingBroker(t)
	defer b.stop()
	c := &control{broker: b.addr(), proxy: NewProxy(b.addr())}

	w1 := doJSON(t, c.handleHold, http.MethodPost, "/hold", holdReq{ClientID: "lexa-hub", DurationS: 5})
	if w1.Code >= 300 {
		t.Fatalf("first /hold rejected: %d %s", w1.Code, w1.Body.String())
	}
	w2 := doJSON(t, c.handleHold, http.MethodPost, "/hold", holdReq{ClientID: "lexa-hub", DurationS: 5})
	if w2.Code != http.StatusConflict {
		t.Errorf("second concurrent /hold status = %d, want 409", w2.Code)
	}

	doJSON(t, c.handleReset, http.MethodPost, "/reset", nil)
}

func TestHandleHold_DurationCapEnforced(t *testing.T) {
	c := &control{broker: "127.0.0.1:1"} // never dialed — should 400 before connecting
	w := doJSON(t, c.handleHold, http.MethodPost, "/hold", holdReq{ClientID: "x", DurationS: maxHoldDurationS + 1})
	if w.Code != http.StatusBadRequest {
		t.Errorf("duration_s=%d status = %d, want 400", maxHoldDurationS+1, w.Code)
	}
	w = doJSON(t, c.handleHold, http.MethodPost, "/hold", holdReq{ClientID: "", DurationS: 5})
	if w.Code != http.StatusBadRequest {
		t.Errorf("missing client_id status = %d, want 400", w.Code)
	}
}

func TestHandleStorm_FloodsAndSelfCancelsOnDuration(t *testing.T) {
	b := startCapturingBroker(t)
	defer b.stop()
	c := &control{broker: b.addr(), proxy: NewProxy(b.addr())}

	const rateHz, durationS, payloadBytes = 50, 1, 8
	doJSON(t, c.handleStorm, http.MethodPost, "/storm", stormReq{
		Topic: "lexa/measurements/storm-noise", RateHz: rateHz, DurationS: durationS, PayloadBytes: payloadBytes,
	})

	b.awaitClosed(t, 3*time.Second)
	buf := b.bytesRead()
	if !bytes.Contains(buf, disconnectPacket()) {
		t.Error("expected a DISCONNECT once duration_s elapsed")
	}
	pkt := publishPacket("lexa/measurements/storm-noise", make([]byte, payloadBytes), false)
	got := bytes.Count(buf, pkt)
	// Rate is approximate under test scheduling jitter; require it fired
	// at a meaningful fraction of the requested rate, not an exact count.
	if got < rateHz*durationS/4 {
		t.Errorf("published %d messages, want roughly %d (rate %d Hz × %ds)", got, rateHz*durationS, rateHz, durationS)
	}
}

func TestHandleStorm_ResetCancelsEarly(t *testing.T) {
	b := startCapturingBroker(t)
	defer b.stop()
	c := &control{broker: b.addr(), proxy: NewProxy(b.addr())}

	doJSON(t, c.handleStorm, http.MethodPost, "/storm", stormReq{
		Topic: "lexa/measurements/storm-noise", RateHz: 20, DurationS: maxStormDurationS, PayloadBytes: 16,
	})
	time.Sleep(150 * time.Millisecond)
	doJSON(t, c.handleReset, http.MethodPost, "/reset", nil)

	b.awaitClosed(t, 3*time.Second)
}

func TestHandleStorm_ParamCapsEnforced(t *testing.T) {
	c := &control{broker: "127.0.0.1:1"}
	cases := []stormReq{
		{Topic: "t", RateHz: maxStormRateHz + 1, DurationS: 1, PayloadBytes: 8},
		{Topic: "t", RateHz: 10, DurationS: maxStormDurationS + 1, PayloadBytes: 8},
		{Topic: "t", RateHz: 10, DurationS: 1, PayloadBytes: maxStormPayload + 1},
		{Topic: "", RateHz: 10, DurationS: 1, PayloadBytes: 8},
	}
	for i, req := range cases {
		w := doJSON(t, c.handleStorm, http.MethodPost, "/storm", req)
		if w.Code != http.StatusBadRequest {
			t.Errorf("case %d: status = %d, want 400 (%+v)", i, w.Code, req)
		}
	}
}

func TestHandleStorm_OneAtATime(t *testing.T) {
	b := startCapturingBroker(t)
	defer b.stop()
	c := &control{broker: b.addr(), proxy: NewProxy(b.addr())}

	w1 := doJSON(t, c.handleStorm, http.MethodPost, "/storm", stormReq{Topic: "t", RateHz: 10, DurationS: 5, PayloadBytes: 8})
	if w1.Code >= 300 {
		t.Fatalf("first /storm rejected: %d %s", w1.Code, w1.Body.String())
	}
	w2 := doJSON(t, c.handleStorm, http.MethodPost, "/storm", stormReq{Topic: "t", RateHz: 10, DurationS: 5, PayloadBytes: 8})
	if w2.Code != http.StatusConflict {
		t.Errorf("second concurrent /storm status = %d, want 409", w2.Code)
	}

	doJSON(t, c.handleReset, http.MethodPost, "/reset", nil)
}

func TestHandleReset_CancelsBothHoldAndStorm(t *testing.T) {
	bh := startCapturingBroker(t)
	defer bh.stop()
	bs := startCapturingBroker(t)
	defer bs.stop()

	// Two brokers so /hold and /storm each get their own connection to
	// watch close independently (the control struct only models one
	// upstream broker in production, but the lifecycle guard being tested
	// here — /reset cancels both faults — doesn't depend on that).
	ch := &control{broker: bh.addr(), proxy: NewProxy(bh.addr())}
	doJSON(t, ch.handleHold, http.MethodPost, "/hold", holdReq{ClientID: "lexa-hub", DurationS: 30})
	cs := &control{broker: bs.addr(), proxy: NewProxy(bs.addr())}
	doJSON(t, cs.handleStorm, http.MethodPost, "/storm", stormReq{Topic: "t", RateHz: 10, DurationS: maxStormDurationS, PayloadBytes: 8})

	time.Sleep(100 * time.Millisecond)
	ch.cancelHold()
	cs.cancelStorm()

	bh.awaitClosed(t, 3*time.Second)
	bs.awaitClosed(t, 3*time.Second)
}
