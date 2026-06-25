package main

import (
	"bytes"
	"net"
	"testing"
	"time"
)

func TestEncodeRemainingLength(t *testing.T) {
	cases := []struct {
		n    int
		want []byte
	}{
		{0, []byte{0x00}},
		{127, []byte{0x7F}},
		{128, []byte{0x80, 0x01}},
		{16383, []byte{0xFF, 0x7F}},
		{16384, []byte{0x80, 0x80, 0x01}},
	}
	for _, c := range cases {
		if got := encodeRemainingLength(c.n); !bytes.Equal(got, c.want) {
			t.Errorf("encodeRemainingLength(%d) = % x, want % x", c.n, got, c.want)
		}
	}
}

func TestPublishPacket_RetainAndTopic(t *testing.T) {
	pkt := publishPacket("lexa/csip/control", []byte("xy"), true)
	if pkt[0] != 0x31 { // PUBLISH (0x30) | retain (0x01)
		t.Errorf("header = %#x, want 0x31 (retain set)", pkt[0])
	}
	noRetain := publishPacket("a/b", []byte("z"), false)
	if noRetain[0] != 0x30 {
		t.Errorf("header = %#x, want 0x30 (retain clear)", noRetain[0])
	}
	// remaining length = 2(topic len) + len(topic) + payload
	if int(pkt[1]) != 2+len("lexa/csip/control")+2 {
		t.Errorf("remaining length = %d, want %d", pkt[1], 2+len("lexa/csip/control")+2)
	}
}

// fakeBroker reads a CONNECT, returns CONNACK, then captures one PUBLISH and
// hands back its decoded topic/payload/retain.
func fakeBroker(t *testing.T) (addr string, got chan publishCapture, stop func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	got = make(chan publishCapture, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
		buf := make([]byte, 4096)
		// Read CONNECT (we don't fully parse it; just consume what's available).
		if _, err := conn.Read(buf); err != nil {
			return
		}
		// CONNACK: accepted.
		_, _ = conn.Write([]byte{0x20, 0x02, 0x00, 0x00})
		n, err := conn.Read(buf)
		if err != nil {
			return
		}
		got <- decodePublish(buf[:n])
	}()
	return ln.Addr().String(), got, func() { ln.Close() }
}

type publishCapture struct {
	topic   string
	payload string
	retain  bool
	ok      bool
}

// decodePublish parses a single QoS-0 PUBLISH packet, bounding the payload by the
// packet's remaining-length field so a coalesced trailing DISCONNECT (sent
// back-to-back by mqttPublish, may arrive in the same TCP read) is not mistaken
// for payload.
func decodePublish(b []byte) publishCapture {
	if len(b) < 2 || b[0]&0xF0 != 0x30 {
		return publishCapture{}
	}
	retain := b[0]&0x01 == 1
	// Decode the variable-length remaining-length field.
	i, remLen, mult := 1, 0, 1
	for i < len(b) {
		remLen += int(b[i]&0x7F) * mult
		more := b[i]&0x80 != 0
		i++
		if !more {
			break
		}
		mult *= 128
	}
	if i+remLen > len(b) {
		remLen = len(b) - i // defensive: never read past the buffer
	}
	body := b[i : i+remLen] // exactly this PUBLISH's variable header + payload
	if len(body) < 2 {
		return publishCapture{}
	}
	tlen := int(body[0])<<8 | int(body[1])
	if 2+tlen > len(body) {
		return publishCapture{}
	}
	topic := string(body[2 : 2+tlen])
	payload := string(body[2+tlen:])
	return publishCapture{topic: topic, payload: payload, retain: retain, ok: true}
}

func TestMqttPublish_RoundTrip(t *testing.T) {
	addr, got, stop := fakeBroker(t)
	defer stop()

	if err := mqttPublish(addr, "test-client", "lexa/csip/control", []byte("{bad json"), true); err != nil {
		t.Fatalf("mqttPublish: %v", err)
	}
	select {
	case cap := <-got:
		if !cap.ok {
			t.Fatal("broker did not decode a PUBLISH")
		}
		if cap.topic != "lexa/csip/control" {
			t.Errorf("topic = %q, want lexa/csip/control", cap.topic)
		}
		if cap.payload != "{bad json" {
			t.Errorf("payload = %q, want malformed body", cap.payload)
		}
		if !cap.retain {
			t.Error("retain flag not set")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("broker never received the PUBLISH")
	}
}
