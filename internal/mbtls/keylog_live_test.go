// keylog_live_test.go proves the conformance-evidence chain end to end against
// the LIVE gateway: arm key-log export, dial the real mbaps server on the
// bench board, exchange real Modbus traffic, and leave behind a key log that
// makes a concurrently-taken packet capture decryptable.
//
// It is the acceptance test for internal/wolfssl/keylog.go. Without it the
// keylog code could compile, run, emit plausible-looking hex, and still be
// useless — an evidence bundle whose capture nobody can actually open is worse
// than no bundle, because it looks like proof.
//
// Gated on BOTH the `keylog` build tag and an explicit target, so it never
// runs in an ordinary `go test ./...`:
//
//	CGO_CFLAGS="-I$HOME/.local/wolfssl-amd64-keylog/include" \
//	CGO_LDFLAGS="-L$HOME/.local/wolfssl-amd64-keylog/lib -lwolfssl -lm" \
//	MBAPS_LIVE_TARGET=69.0.0.2:802 MBAPS_KEYLOG_OUT=/tmp/evidence.keylog \
//	go test -tags keylog -run TestLiveKeylog -v ./internal/mbtls/

//go:build keylog

package mbtls

import (
	"os"
	"strings"
	"testing"

	"csip-tls-test/internal/wolfssl"
)

func TestLiveKeylogAgainstGateway(t *testing.T) {
	target := os.Getenv("MBAPS_LIVE_TARGET")
	if target == "" {
		t.Skip("MBAPS_LIVE_TARGET unset — live-gateway keylog proof not requested")
	}
	out := os.Getenv("MBAPS_KEYLOG_OUT")
	if out == "" {
		t.Fatal("MBAPS_KEYLOG_OUT must be set alongside MBAPS_LIVE_TARGET")
	}
	pkiDir := os.Getenv("MBAPS_PKI_DIR")
	if pkiDir == "" {
		pkiDir = "../../certs/mbaps"
	}

	wolfssl.Init()
	defer wolfssl.Cleanup()

	if err := wolfssl.OpenKeylog(out); err != nil {
		t.Fatalf("OpenKeylog(%s): %v", out, err)
	}
	defer wolfssl.CloseKeylog()

	p := DefaultClientProfile(
		pkiDir+"/ca-cert.pem",
		pkiDir+"/clients/grid-service-cert.pem",
		pkiDir+"/clients/grid-service-key.pem",
	)
	sess, err := Dial(target, p)
	if err != nil {
		t.Fatalf("Dial(%s): %v", target, err)
	}
	defer sess.Close()
	t.Logf("connected to %s", target)

	// The key log must contain a usable record for THIS session. A file that
	// exists but holds no secret is the exact silent failure this test exists
	// to catch, so assert on content, not on the file being present.
	b, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read key log: %v", err)
	}
	body := string(b)
	wanted := []string{
		"CLIENT_RANDOM",                   // TLS 1.2 path
		"CLIENT_TRAFFIC_SECRET_0",         // TLS 1.3 path
		"SERVER_TRAFFIC_SECRET_0",         //
		"CLIENT_HANDSHAKE_TRAFFIC_SECRET", //
	}
	var got []string
	for _, w := range wanted {
		if strings.Contains(body, w) {
			got = append(got, w)
		}
	}
	if len(got) == 0 {
		t.Fatalf("key log %s has no usable secret record; contents:\n%s", out, body)
	}
	t.Logf("key log %s: %d bytes, labels present: %v", out, len(b), got)

	// Every record must be "<LABEL> <64 hex> <hex>" — a malformed line is
	// silently ignored by analyzers, which again looks like a decryption
	// failure rather than a producer bug.
	for i, line := range strings.Split(strings.TrimSpace(body), "\n") {
		if line == "" {
			continue
		}
		f := strings.Fields(line)
		if len(f) != 3 {
			t.Errorf("key log line %d: want 3 fields, got %d: %q", i+1, len(f), line)
			continue
		}
		if len(f[1]) != 64 {
			t.Errorf("key log line %d: client_random must be 64 hex chars, got %d", i+1, len(f[1]))
		}
		if len(f[2]) < 32 || len(f[2])%2 != 0 {
			t.Errorf("key log line %d: implausible secret hex length %d", i+1, len(f[2]))
		}
	}
}
