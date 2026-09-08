//go:build cgo

package tlsprobe

// clienthello_wire_cgo_test.go proves REV0907-E7's ClientHello-shape fix by
// capturing the probe's ACTUAL wire bytes off a loopback listener that never
// completes a handshake. Dial always fails against it, and that is fine: this
// test only needs what was already on the wire before that failure — the
// probe's own ClientHello, sent before it ever sees a byte back.
//
// It parses the capture with internal/evidence/tlsdis, the SAME dissector the
// certify suite re-parses captured campaign evidence with (internal/certify/
// suitessm/wire.go), rather than a second, ad hoc parser — a pass here is
// evidence about the actual wire bytes this build produces, not about a parser
// written to agree with itself.
//
// The finding (MBAPS-CRYP001-WOLFSSL-PROBE-CANNOT-COMPLETE-MTLS-TO-BOARD) is
// that the probe's ClientHello did not match the working mbaps client's
// (internal/mbtls's Dial) closely enough for the board's patched Mbed TLS
// server to complete a session against it. This test pins the two extensions
// that were the gap.

import (
	"context"
	"net"
	"testing"
	"time"

	"csip-tls-test/internal/evidence/tlsdis"
)

// captureClientHello dials spec against a bare TCP listener that accepts one
// connection, reads whatever bytes arrive until the peer goes quiet, and never
// answers. The probe's Dial is therefore guaranteed to fail (no ServerHello
// ever comes back) — the return value this helper cares about is the captured
// bytes, not Dial's error.
func captureClientHello(t *testing.T, spec Spec) *tlsdis.ClientHello {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = ln.Close() }()

	captured := make(chan []byte, 1)
	go func() {
		conn, aerr := ln.Accept()
		if aerr != nil {
			captured <- nil
			return
		}
		defer func() { _ = conn.Close() }()
		var buf []byte
		read := make([]byte, 4096)
		for {
			_ = conn.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
			n, rerr := conn.Read(read)
			if n > 0 {
				buf = append(buf, read[:n]...)
			}
			if rerr != nil {
				break
			}
		}
		captured <- buf
	}()

	spec.Target = ln.Addr().String()
	if spec.Deadline == 0 {
		spec.Deadline = 3 * time.Second
	}
	if _, err := Dial(context.Background(), spec); err == nil {
		t.Fatal("Dial unexpectedly succeeded against a listener that never sends a ServerHello")
	}

	buf := <-captured
	if len(buf) == 0 {
		t.Fatal("no bytes were captured from the probe's connection to the loopback listener")
	}
	dir, err := tlsdis.ParseDirection(buf, nil)
	if dir == nil {
		t.Fatalf("parse the captured bytes as a TLS record stream: %v", err)
	}
	if dir.Handshake == nil {
		t.Fatalf("no handshake was recovered from the captured bytes: %v", err)
	}
	msg, ok := dir.Handshake.Find(tlsdis.HandshakeClientHello)
	if !ok || msg.ClientHello == nil {
		t.Fatalf("the captured bytes carry no ClientHello (handshake types seen: %v)", dir.Handshake.Types())
	}
	return msg.ClientHello
}

// probeSpecForWireTest builds a minimal, valid Spec for captureClientHello:
// real PKI files (Dial validates their presence before it ever opens a
// socket) and a pinned CCM suite, since AES-CCM is this package's whole
// reason to exist and the suite the finding's board session was on.
func probeSpecForWireTest(t *testing.T) Spec {
	t.Helper()
	pki := mintPKI(t)
	return Spec{
		CAFiles:  []string{pki.caFile},
		CertFile: pki.clientCert,
		KeyFile:  pki.clientKey,
		Suite:    TLS12CCM8,
	}
}

// TestProbeClientHelloCarriesMaxFragmentLengthAndSecureRenegotiation is
// REV0907-E7's wire-level proof: the probe's ClientHello must carry the same
// RFC 6066 Maximum Fragment Length request and the same RFC 5746
// secure-renegotiation signal as the working mbaps client
// (internal/mbtls.Dial), because those are exactly the two knobs newClientCTX
// was missing relative to it. The board's Mbed TLS server carries the SunSpec
// CCM MFL patches 0002-0006 and every mbaps session captured against it
// negotiates MFL=1 on the wire; a ClientHello missing the extension is not the
// shape that server has ever completed a session against.
func TestProbeClientHelloCarriesMaxFragmentLengthAndSecureRenegotiation(t *testing.T) {
	ch := captureClientHello(t, probeSpecForWireTest(t))

	if ch.MaxFragmentLength == nil {
		t.Error("the ClientHello carries no max_fragment_length extension (type 1); the working mbaps " +
			"client (internal/mbtls.Dial) always requests one via wolfssl.UseMaxFragment")
	} else if got, want := *ch.MaxFragmentLength, uint8(1); got != want {
		t.Errorf("max_fragment_length = %d, want %d (MFL512, wire value 1 — the code the working "+
			"client requests and the code every captured working session negotiates)", got, want)
	}

	// RFC 5746: a client that supports secure renegotiation signals it either
	// with the renegotiation_info extension (0xff01) or, for a peer that has
	// not yet upgraded to understand the extension, the equivalent
	// TLS_EMPTY_RENEGOTIATION_INFO_SCSV cipher suite value. Against this
	// package's $WOLFSSL_SYSROOT, neither rides the ClientHello unless
	// newClientCTX calls UseSecureRenegotiation — mutation-verified by removing
	// that call and re-running this test, which then fails on this exact
	// assertion — so this is a direct wire check of that call's effect, not
	// merely of the suite list.
	scsv := false
	for _, s := range ch.CipherSuites {
		if s == 0x00FF { // TLS_EMPTY_RENEGOTIATION_INFO_SCSV
			scsv = true
			break
		}
	}
	if !ch.HasRenegotiationInfo && !scsv {
		t.Error("the ClientHello carries neither a renegotiation_info extension (0xff01) nor the empty " +
			"renegotiation SCSV cipher suite; the working mbaps client's ClientHello always carries the " +
			"extension")
	}
}
