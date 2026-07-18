package main

import (
	"testing"

	"csip-tls-test/internal/mbtls"
)

// fakeSession builds a *mbtls.Session with just the exported handshake-fact
// fields set (Conn/PeerDER/ssl/ctx/raw/file stay zero) — sessionRegistry only
// keys off the pointer identity and reads the exported fields, so this is
// sufficient without a real handshake.
func fakeSession(cipher, tlsVer string, resumed bool) *mbtls.Session {
	return &mbtls.Session{Cipher: cipher, TLSVer: tlsVer, Resumed: resumed}
}

func TestSessionRegistry(t *testing.T) {
	reg := newSessionRegistry()

	s1 := fakeSession("TLS13-AES128-GCM-SHA256", "TLSv1.3", false)
	s2 := fakeSession("ECDHE-ECDSA-AES128-GCM-SHA256", "TLSv1.2", true)

	t1 := reg.add(s1, "10.0.0.1:1234")
	t2 := reg.add(s2, "10.0.0.2:5678")

	if got := len(reg.snapshot()); got != 2 {
		t.Fatalf("snapshot len = %d, want 2", got)
	}

	t1.setRole("SuperAdministratorSunSpec")
	t1.countRequest()
	t1.countRequest()

	var found *sessionInfo
	for _, info := range reg.snapshot() {
		if info.Peer == "10.0.0.1:1234" {
			c := info
			found = &c
		}
	}
	if found == nil {
		t.Fatalf("session 10.0.0.1:1234 not found in snapshot")
	}
	if found.Role != "SuperAdministratorSunSpec" {
		t.Errorf("role = %q, want SuperAdministratorSunSpec", found.Role)
	}
	if found.Requests != 2 {
		t.Errorf("requests = %d, want 2", found.Requests)
	}
	if found.Resumed {
		t.Errorf("s1.Resumed = true, want false")
	}

	reg.remove(t1)
	if got := len(reg.snapshot()); got != 1 {
		t.Fatalf("snapshot len after remove = %d, want 1", got)
	}
	remaining := reg.snapshot()[0]
	if remaining.Peer != "10.0.0.2:5678" || !remaining.Resumed {
		t.Errorf("remaining session = %+v, want peer 10.0.0.2:5678 resumed=true", remaining)
	}

	// Removing an already-removed session is a safe no-op.
	reg.remove(t1)
	reg.remove(t2)
	if got := len(reg.snapshot()); got != 0 {
		t.Errorf("snapshot len after removing all = %d, want 0", got)
	}
}
