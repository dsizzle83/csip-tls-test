//go:build integration

package tlsserver

import (
	"strings"
	"testing"
)

// TestHappyPath_HandshakeAndDcap is the end-to-end smoke test: real
// mTLS handshake using the CSIP cipher, real DCAP fetch, real response
// parsing. If this passes, Milestone 2 is functionally complete.
func TestHappyPath_HandshakeAndDcap(t *testing.T) {
	addr, srv := startTestServer(t, defaultTestConfig())

	var (
		seenVersion string
		seenCipher  string
	)
	srv.OnHandshake = func(v, c string) {
		seenVersion, seenCipher = v, c
	}

	client, err := dialTestClient(t, addr, testClientConfig{
		CACertPath:     testdataPath("certs/ca-cert.pem"),
		ClientCertPath: testdataPath("certs/client-cert.pem"),
		ClientKeyPath:  testdataPath("certs/client-key.pem"),
	})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()

	if got, want := client.Version(), "TLSv1.2"; got != want {
		t.Errorf("client.Version() = %q, want %q", got, want)
	}
	if got, want := client.Cipher(), "ECDHE-ECDSA-AES128-CCM-8"; got != want {
		t.Errorf("client.Cipher() = %q, want %q", got, want)
	}

	resp, err := client.Request("GET /dcap HTTP/1.1\r\nHost: csip-test\r\n\r\n")
	if err != nil {
		t.Fatalf("Request: %v", err)
	}

	for _, want := range []string{
		"HTTP/1.1 200 OK",
		"Content-Type: application/sep+xml",
		"<DeviceCapability",
		`xmlns="urn:ieee:std:2030.5:ns"`,
	} {
		if !strings.Contains(resp, want) {
			t.Errorf("response missing %q\nfull response:\n%s", want, resp)
		}
	}

	if seenVersion != "TLSv1.2" {
		t.Errorf("server-side OnHandshake version = %q, want TLSv1.2", seenVersion)
	}
	if seenCipher != "ECDHE-ECDSA-AES128-CCM-8" {
		t.Errorf("server-side OnHandshake cipher = %q, want ECDHE-ECDSA-AES128-CCM-8", seenCipher)
	}
}

// TestCipher_IsCSIPCompliant is the single highest-value regression
// test in the suite for CSIP conformance. If anyone ever loosens the
// cipher list — accidentally or otherwise — this test fails on the
// next commit. Cheap, fast, and prevents an entire category of
// non-conformance bugs that would only otherwise be caught at
// SunSpec certification time.
func TestCipher_IsCSIPCompliant(t *testing.T) {
	addr, _ := startTestServer(t, defaultTestConfig())

	client, err := dialTestClient(t, addr, testClientConfig{
		CACertPath:     testdataPath("certs/ca-cert.pem"),
		ClientCertPath: testdataPath("certs/client-cert.pem"),
		ClientKeyPath:  testdataPath("certs/client-key.pem"),
	})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()

	if got := client.Cipher(); got != "ECDHE-ECDSA-AES128-CCM-8" {
		t.Errorf("negotiated cipher = %q, want ECDHE-ECDSA-AES128-CCM-8 (CSIP §5.2.1.1)", got)
	}
	if got := client.Version(); got != "TLSv1.2" {
		t.Errorf("negotiated version = %q, want TLSv1.2 (CSIP §5.2.1.1)", got)
	}
}

// TestRejection table-drives the negative cases. Each row is a category
// of "client doing something wrong that the server must reject" — these
// prove our security posture rather than just our happy path. Adding
// a new rejection scenario means adding one row, no new boilerplate.
//
// As we add new conformance requirements (TLS 1.3 rejection, expired
// cert rejection, missing extKeyUsage rejection, etc.), each becomes a
// new row here.
func TestRejection(t *testing.T) {
	addr, _ := startTestServer(t, defaultTestConfig())

	cases := []struct {
		name string
		cfg  testClientConfig
	}{
		{
			name: "no client cert presented",
			cfg: testClientConfig{
				CACertPath: testdataPath("certs/ca-cert.pem"),
				// no ClientCertPath / ClientKeyPath — proves
				// requireClientCert took effect
			},
		},
		{
			name: "client cert signed by wrong CA",
			cfg: testClientConfig{
				CACertPath:     testdataPath("certs/ca-cert.pem"),
				ClientCertPath: testdataPath("certs/wrong-ca-client-cert.pem"),
				ClientKeyPath:  testdataPath("certs/wrong-ca-client-key.pem"),
			},
		},
		{
			name: "client offers only non-CSIP cipher",
			cfg: testClientConfig{
				CACertPath:     testdataPath("certs/ca-cert.pem"),
				ClientCertPath: testdataPath("certs/client-cert.pem"),
				ClientKeyPath:  testdataPath("certs/client-key.pem"),
				CipherList:     "ECDHE-ECDSA-AES128-GCM-SHA256",
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			client, err := dialTestClient(t, addr, tc.cfg)
			if err == nil {
				client.Close()
				t.Fatal("expected handshake to fail, but it succeeded")
			}
			t.Logf("(expected) handshake rejected: %v", err)
		})
	}
}
