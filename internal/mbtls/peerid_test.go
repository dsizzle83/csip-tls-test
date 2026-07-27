package mbtls

// peerid_test.go covers the parts of the server-side peer-identity binding that
// are pure Go: the bound, the LRU order, and the refusal to bind nothing. The
// handshake half — that the binding actually rescues a resumed session whose peer
// chain wolfSSL has evicted, and that an unrecoverable one fails LOUDLY rather
// than silently — needs a real TLS session and lives in
// peerid_integration_test.go.

import (
	"bytes"
	"testing"
)

func id(b byte) []byte  { return []byte{b, b, b, b} }
func der(b byte) []byte { return []byte{0x30, b} }

func TestPeerBinding_RoundTrip(t *testing.T) {
	b := newPeerBinding(4)
	b.put(id(1), der(1))
	got, ok := b.get(id(1))
	if !ok || !bytes.Equal(got, der(1)) {
		t.Fatalf("get(id1) = %x, %t; want %x, true", got, ok, der(1))
	}
	if _, ok := b.get(id(2)); ok {
		t.Error("get(id2) reported a binding that was never made")
	}
}

// A full handshake for a session id already bound must REPLACE the identity, not
// keep the old one: the certificate presented on the wire is authoritative.
func TestPeerBinding_PutReplaces(t *testing.T) {
	b := newPeerBinding(4)
	b.put(id(1), der(1))
	b.put(id(1), der(9))
	got, _ := b.get(id(1))
	if !bytes.Equal(got, der(9)) {
		t.Fatalf("get(id1) = %x after re-put; want the newer %x", got, der(9))
	}
	if n := b.len(); n != 1 {
		t.Errorf("len = %d after re-putting one key; want 1", n)
	}
}

// Nothing to bind must bind nothing — an empty session id or an empty certificate
// must never create an entry that a later get could match by accident.
func TestPeerBinding_IgnoresEmpty(t *testing.T) {
	b := newPeerBinding(4)
	b.put(nil, der(1))
	b.put(id(1), nil)
	b.put(nil, nil)
	if n := b.len(); n != 0 {
		t.Fatalf("len = %d after three empty puts; want 0", n)
	}
	if _, ok := b.get(nil); ok {
		t.Error("get(nil) matched an entry")
	}
}

// The bound is the memory guarantee: a peer that opens an unbounded number of
// distinct TLS sessions must not be able to grow the server's identity table. The
// harness owes the same no-unbounded-growth discipline (I8) it checks the product
// for.
func TestPeerBinding_BoundedByCapacity(t *testing.T) {
	const cap = 8
	b := newPeerBinding(cap)
	for i := 0; i < 200; i++ {
		b.put([]byte{byte(i), byte(i >> 8)}, der(byte(i)))
	}
	if n := b.len(); n != cap {
		t.Fatalf("len = %d after 200 distinct sessions; want the cap %d", n, cap)
	}
}

// Eviction is least-recently-USED, not least-recently-inserted: a long-lived
// resumption chain that keeps reconnecting must not be evicted by a burst of
// one-shot sessions.
func TestPeerBinding_EvictsLeastRecentlyUsed(t *testing.T) {
	b := newPeerBinding(3)
	b.put(id(1), der(1))
	b.put(id(2), der(2))
	b.put(id(3), der(3))
	if _, ok := b.get(id(1)); !ok { // touch id1 -> most recently used
		t.Fatal("id1 missing before eviction")
	}
	b.put(id(4), der(4)) // over capacity: id2 (LRU) must go, not id1
	if _, ok := b.get(id(2)); ok {
		t.Error("id2 survived; the least-recently-USED entry should have been evicted")
	}
	if _, ok := b.get(id(1)); !ok {
		t.Error("id1 was evicted despite being the most recently used")
	}
	if _, ok := b.get(id(4)); !ok {
		t.Error("id4 was not stored")
	}
}

// A nil session, or one with no live wolfSSL handle, must be a no-op rather than a
// crash: resolve runs on every Accept, including paths a future refactor might
// reach with a half-built Session.
func TestPeerBinding_ResolveIgnoresEmptySession(t *testing.T) {
	b := newPeerBinding(4)
	b.resolve(nil, true)
	s := &Session{}
	b.resolve(s, true)
	if s.IdentityLost || s.IdentityRecovered {
		t.Errorf("resolve on a handle-less session set IdentityLost=%t IdentityRecovered=%t; want both false",
			s.IdentityLost, s.IdentityRecovered)
	}
}

// Role() must keep the two no-certificate outcomes apart. Conflating "no role in
// the certificate" with "no certificate to look at" is what let a resumption bug
// in the harness masquerade as an authorization denial for weeks.
func TestSessionRole_DistinguishesLostIdentityFromNoRole(t *testing.T) {
	noRole := &Session{}
	if _, err := noRole.Role(); err != ErrNoRole {
		t.Errorf("Role() on an empty session = %v; want ErrNoRole", err)
	}
	lost := &Session{IdentityLost: true}
	if _, err := lost.Role(); err != ErrPeerIdentityUnavailable {
		t.Errorf("Role() on an identity-lost session = %v; want ErrPeerIdentityUnavailable", err)
	}
	if ErrNoRole == ErrPeerIdentityUnavailable {
		t.Fatal("the two errors are the same value — callers could not tell them apart")
	}
}
