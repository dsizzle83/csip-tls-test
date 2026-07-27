package suitessm

// alerts_test.go is the suite-side half of the post-ChangeCipherSpec alert
// defect (internal/evidence/tlsdis holds the other half).
//
// The rule under test: an alert record sent after the CCS is ciphertext, and a
// check may do exactly two things with it — recover it with the run's key log,
// or say it could not. What it may never do is read the AEAD output as a level
// and a description, because that turns a device's real fatal alert into "no
// fatal alert" and a device's silence into a fatal alert that never existed.

import (
	"bytes"
	"strings"
	"testing"

	"csip-tls-test/internal/certify"
	"csip-tls-test/internal/evidence/tlsdis"
)

// alertMapper attributes 16 stream bytes per frame, so the parsed records carry
// frame numbers and an assertion built on them has something to cite.
type alertMapper struct{}

func (alertMapper) PacketsFor(start, end int) []int {
	var out []int
	for off := start; off < end; off++ {
		p := off/16 + 1
		if len(out) == 0 || out[len(out)-1] != p {
			out = append(out, p)
		}
	}
	return out
}

func u16(v uint16) []byte { return []byte{byte(v >> 8), byte(v)} }

func tlsRecord(ct tlsdis.ContentType, frag []byte) []byte {
	out := []byte{byte(ct)}
	out = append(out, u16(tlsdis.VersionTLS12)...)
	out = append(out, u16(uint16(len(frag)))...)
	return append(out, frag...)
}

// abortedSessionServerDirection is the DUT→bench half of a TLS 1.2 session that
// was torn down by an alert AFTER the handshake — the shape TLSF-005 provokes
// on purpose. The alert body is the 26-byte AES-GCM record such an alert has on
// the wire, and its first two bytes are deliberately 0x02 0x28: a parser that
// decodes ciphertext reports "fatal handshake_failure".
func abortedSessionServerDirection() []byte {
	body := append([]byte{0x02, 0x28, 0x77, 0x1A, 0x00, 0x91, 0xC3, 0x5B}, 0x02, 0x28)
	body = append(body, bytes.Repeat([]byte{0xE4}, 16)...)
	var out []byte
	out = append(out, tlsRecord(tlsdis.ContentHandshake, hsServerHelloDone())...)
	out = append(out, tlsRecord(tlsdis.ContentChangeCipherSpec, []byte{1})...)
	out = append(out, tlsRecord(tlsdis.ContentApplicationData, bytes.Repeat([]byte{0x5C}, 48))...)
	out = append(out, tlsRecord(tlsdis.ContentAlert, body)...)
	return out
}

func hsServerHelloDone() []byte {
	return []byte{byte(tlsdis.HandshakeServerHelloDone), 0, 0, 0}
}

func TestServerAlertsNeverDecodesCiphertext(t *testing.T) {
	server, err := tlsdis.ParseDirection(abortedSessionServerDirection(), alertMapper{})
	if err != nil {
		t.Fatalf("ParseDirection: %v", err)
	}
	v := &wireView{Server: server, Frames: []int{1, 2, 3, 4, 5, 6}}
	ev := &certify.Evidence{} // no key log: the run did not export one

	sc := v.serverAlerts(ev)
	if al, ok := sc.Fatal(); ok {
		t.Fatalf("serverAlerts reported a fatal alert %s synthesised from AEAD output", al)
	}
	if len(sc.Alerts) != 0 {
		t.Fatalf("Alerts = %d, want 0: nothing in this direction was readable", len(sc.Alerts))
	}
	if len(sc.Opaque) != 1 {
		t.Fatalf("Opaque = %d, want 1: the alert RECORD is plaintext even though its body is not", len(sc.Opaque))
	}
	if len(sc.OpaqueFrames()) == 0 {
		t.Error("an unresolved alert must still cite the frames it arrived in")
	}
	if !strings.Contains(sc.Why, "key log") {
		t.Errorf("Why = %q, want it to name the missing key log", sc.Why)
	}
	if d := sc.Describe(); !strings.Contains(d, "ENCRYPTED alert record") {
		t.Errorf("Describe() = %q", d)
	}

	// And the verdict: an unreadable alert is UNDETERMINED, never an absence.
	// Both of the wrong answers are wrong in a way that matters — PASS would
	// credit a refusal nobody observed, FAIL would accuse a device of not
	// sending an alert it may well have sent.
	verdict, obs, frames := fatalAlertVerdict(ev, v, "the provocation")
	if verdict != certify.Skip {
		t.Fatalf("fatalAlertVerdict = %s (%s), want SKIP", verdict, obs)
	}
	if !strings.Contains(obs, "undetermined") {
		t.Errorf("observation = %q, want it to say the outcome is undetermined", obs)
	}
	if len(frames) == 0 {
		t.Error("the SKIP must cite the frames of the record it declined to read")
	}
}

// TestFatalAlertVerdictStillFailsRealSilence guards the other direction: the
// honest FAIL must survive. A DUT that answered a provocation with a ServerHello
// and no alert at all is still a failure of every negative test case.
func TestFatalAlertVerdictStillFailsRealSilence(t *testing.T) {
	var data []byte
	data = append(data, tlsRecord(tlsdis.ContentHandshake, hsServerHelloDone())...)
	server, err := tlsdis.ParseDirection(data, alertMapper{})
	if err != nil {
		t.Fatalf("ParseDirection: %v", err)
	}
	v := &wireView{Server: server, Frames: []int{1}}
	verdict, obs, _ := fatalAlertVerdict(&certify.Evidence{}, v, "the provocation")
	if verdict != certify.Fail {
		t.Fatalf("fatalAlertVerdict = %s (%s), want FAIL: there is no alert record here at all", verdict, obs)
	}
}

// TestPlaintextFatalAlertStillPasses guards the third direction: the negative
// cases whose alert fires DURING the handshake (TLSF-003, TLSF-004, PKI-003)
// must go on passing without a key log, because their alert is in the clear.
func TestPlaintextFatalAlertStillPasses(t *testing.T) {
	var data []byte
	data = append(data, tlsRecord(tlsdis.ContentHandshake, hsServerHelloDone())...)
	data = append(data, tlsRecord(tlsdis.ContentAlert, []byte{2, 48})...) // fatal unknown_ca
	server, err := tlsdis.ParseDirection(data, alertMapper{})
	if err != nil {
		t.Fatalf("ParseDirection: %v", err)
	}
	v := &wireView{Server: server, Frames: []int{1}}
	verdict, obs, frames := fatalAlertVerdict(&certify.Evidence{}, v, "an untrusted client certificate")
	if verdict != certify.Pass {
		t.Fatalf("fatalAlertVerdict = %s (%s), want PASS", verdict, obs)
	}
	if !strings.Contains(obs, "unknown_ca") {
		t.Errorf("observation = %q, want the decoded description", obs)
	}
	if len(frames) == 0 {
		t.Error("a PASS must cite the alert's frames")
	}
}
