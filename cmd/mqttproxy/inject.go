package main

import (
	"fmt"
	"net"
	"time"
)

// Message-level MQTT chaos. The TCP proxy can drop/delay the byte stream, but
// faults like a malformed payload, a duplicate retained delivery, or a stale
// retained value live at the MQTT layer — so we publish them straight onto the
// real broker with a minimal hand-rolled MQTT 3.1.1 client (publish-only, QoS 0).
// Keeping it dependency-free avoids pulling an MQTT library into the harness repo
// for a few PUBLISH packets.

// encodeRemainingLength encodes n using MQTT's variable-length scheme (7 bits per
// byte, high bit = "more").
func encodeRemainingLength(n int) []byte {
	var out []byte
	for {
		b := byte(n % 128)
		n /= 128
		if n > 0 {
			b |= 0x80
		}
		out = append(out, b)
		if n == 0 {
			return out
		}
	}
}

// encodeString prefixes s with its 2-byte big-endian length (MQTT UTF-8 string).
func encodeString(s string) []byte {
	out := make([]byte, 2+len(s))
	out[0] = byte(len(s) >> 8)
	out[1] = byte(len(s))
	copy(out[2:], s)
	return out
}

// connectPacket builds a CONNECT with a clean session and the given client ID.
// When user is non-empty, the username (0x80) and password (0x40) connect
// flags are set and the credentials are appended after the client ID in the
// payload order MQTT 3.1.1 §3.1.3 requires (Client Identifier, Will Topic/
// Message [absent here], User Name, Password) — flags byte 0x02 (clean
// session only) becomes 0xC2 (TASK-013 / W7: the broker's ACL now requires
// the qa-inject user for /inject to keep working once anonymous is off).
// An empty user keeps producing the original anonymous CONNECT byte-for-byte,
// so PASSTHROUGH callers (none today — mqttPublish is the only caller) are
// unaffected.
func connectPacket(clientID, user, pass string) []byte {
	var vh []byte
	vh = append(vh, encodeString("MQTT")...) // protocol name
	vh = append(vh, 0x04)                    // protocol level 4 (3.1.1)
	flags := byte(0x02)                      // clean session
	if user != "" {
		flags |= 0x80 | 0x40 // username + password present
	}
	vh = append(vh, flags)
	vh = append(vh, 0x00, 0x3C) // keepalive 60s
	vh = append(vh, encodeString(clientID)...)
	if user != "" {
		vh = append(vh, encodeString(user)...)
		vh = append(vh, encodeString(pass)...)
	}

	pkt := []byte{0x10} // CONNECT
	pkt = append(pkt, encodeRemainingLength(len(vh))...)
	return append(pkt, vh...)
}

// publishPacket builds a QoS-0 PUBLISH (no packet identifier) with the retain bit
// set as requested.
func publishPacket(topic string, payload []byte, retain bool) []byte {
	header := byte(0x30) // PUBLISH, QoS 0, DUP 0
	if retain {
		header |= 0x01
	}
	body := encodeString(topic)
	body = append(body, payload...)

	pkt := []byte{header}
	pkt = append(pkt, encodeRemainingLength(len(body))...)
	return append(pkt, body...)
}

func disconnectPacket() []byte { return []byte{0xE0, 0x00} }

// mqttPublish connects to broker (host:port), publishes one retained-or-not
// message, and disconnects. It reads the CONNACK to confirm the broker accepted
// the session before publishing. user/pass are the qa-inject broker
// credentials (TASK-013 / W7); empty user sends the same anonymous CONNECT
// this always sent, for use against a broker that still allows anonymous.
func mqttPublish(broker, clientID, user, pass, topic string, payload []byte, retain bool) error {
	conn, err := net.DialTimeout("tcp", broker, 5*time.Second)
	if err != nil {
		return fmt.Errorf("dial broker: %w", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	if _, err := conn.Write(connectPacket(clientID, user, pass)); err != nil {
		return fmt.Errorf("write CONNECT: %w", err)
	}
	// CONNACK is a 4-byte packet: 0x20 0x02 <flags> <return code>.
	ack := make([]byte, 4)
	if _, err := readFull(conn, ack); err != nil {
		return fmt.Errorf("read CONNACK: %w", err)
	}
	if ack[0] != 0x20 || ack[3] != 0x00 {
		return fmt.Errorf("broker rejected connection: connack=% x", ack)
	}

	if _, err := conn.Write(publishPacket(topic, payload, retain)); err != nil {
		return fmt.Errorf("write PUBLISH: %w", err)
	}
	_, _ = conn.Write(disconnectPacket())
	return nil
}

// readFull reads len(b) bytes or returns an error (net.Conn.Read may short-read).
func readFull(conn net.Conn, b []byte) (int, error) {
	got := 0
	for got < len(b) {
		n, err := conn.Read(b[got:])
		got += n
		if err != nil {
			return got, err
		}
	}
	return got, nil
}
