//go:build cgo

package suitemodbusserver

// session_cgo.go wires the bench's own mbaps client into this suite.
//
// internal/mbtls is deliberately NOT the product's lexa-platform/securemodbus:
// a conformance bench that shared its TLS profile code with the DUT could not
// independently catch a profile bug. The suite inherits from it a conformant
// handshake — TLS 1.2..1.3, the mandated suite order, an unconditional client
// certificate, P-256, RFC 6066 maximum fragment length — and, when the binary
// was built with -tags keylog and a key log was opened, the NSS key-log export
// that makes the resulting capture decryptable. Without that export the Modbus
// exchanges inside the tunnel are unreadable and this suite's citation phase
// says so on every affected assertion instead of asserting on ciphertext.

import (
	"context"
	"fmt"
	"net"

	"csip-tls-test/internal/certify"
	"csip-tls-test/internal/mbtls"
)

func init() { mbapsDial = dialMBAPS }

// dialMBAPS performs the mbaps mTLS handshake and returns the decrypted stream.
func dialMBAPS(ctx context.Context, addr string, pki *certify.PKI, role string) (net.Conn, func() error, string, error) {
	if pki == nil {
		return nil, nil, "", fmt.Errorf("no PKI fixtures loaded (-pki); an mbaps client must present a role certificate")
	}
	kp, err := pki.Role(role)
	if err != nil {
		return nil, nil, "", err
	}
	if pki.CA == "" {
		return nil, nil, "", fmt.Errorf("PKI fixture set %s has no ca-cert.pem to verify the DUT against", pki.Dir)
	}

	profile := mbtls.DefaultClientProfile(pki.CA, kp.Cert, kp.Key)
	profile.RoleAsserted = role

	type dialResult struct {
		sess *mbtls.Session
		err  error
	}
	done := make(chan dialResult, 1)
	go func() { s, err := mbtls.Dial(addr, profile); done <- dialResult{s, err} }()

	select {
	case <-ctx.Done():
		// The handshake goroutine owns the session; close it when it lands so a
		// cancelled dial cannot leak a wolfSSL handle or a socket.
		go func() {
			if res := <-done; res.sess != nil {
				res.sess.Close()
			}
		}()
		return nil, nil, "", ctx.Err()
	case res := <-done:
		if res.err != nil {
			return nil, nil, "", res.err
		}
		sess := res.sess
		describe := fmt.Sprintf("%s %s", sess.TLSVer, sess.Cipher)
		if sess.Resumed {
			describe += " (resumed)"
		}
		if sess.MFLCode != 0 {
			describe += fmt.Sprintf(" MFL=%d", sess.MFLCode)
		}
		return sess.Conn, func() error { return sess.Close() }, describe, nil
	}
}
