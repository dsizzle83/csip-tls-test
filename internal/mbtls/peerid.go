package mbtls

// peerid.go answers one question for an mbaps SERVER: after a handshake that
// RESUMED an earlier TLS session, who is the peer?
//
// # The defect this exists to close
//
// An mbaps server derives its authorization role from the client's leaf
// certificate (SunSpecTCP-29/30, design doc 01 §3.1). On a RESUMED handshake the
// client sends no Certificate message — that is the whole point of resumption —
// so the role has to come from the session the handshake resumed, not from the
// wire. wolfSSL is supposed to make that transparent: built with SESSION_CERTS,
// wolfSSL_get_peer_certificate falls back to the certificate chain retained on the
// session. The bench's sysroot IS built that way (--enable-sessioncerts, see
// ~/.local/wolfssl-amd64/wolfssl-sysroot-manifest.txt), and for the first handful
// of resumptions it works.
//
// It does not keep working. --enable-sessioncerts also turns on
// WOLFSSL_TICKET_HAVE_ID, under which a TLS 1.3 server does not carry the peer
// chain inside the session ticket: the ticket carries a session ID, and the chain
// is looked up in wolfSSL's own in-process session store. That store is a bounded
// hash table (SESSIONS_PER_ROW × SESSION_ROWS, 3 × 11 by default in the 5.7.6
// build here) and it EVICTS. When the row holding a resumption chain's session is
// evicted, every later handshake in that chain still resumes SUCCESSFULLY —
// wolfSSL_accept returns success, SessionReused reports true, application data
// flows — but the peer chain is gone, and wolfSSL_get_peer_certificate returns
// NULL. To a caller that is indistinguishable from "this peer presented no
// certificate at all".
//
// For a server that maps peer leaf → role → authorization, that is a silent
// collapse to no-role: every request from a properly authenticated, properly
// authorized client is refused. It is silent because nothing errors; it is
// non-deterministic in ONSET because the eviction depends on where random session
// IDs hash; and it is permanent per chain, because once a session carries no
// chain, neither does any session derived from it. Measured on this build with a
// single client identity looping connect/close: the role survived between 7 and 20
// resumptions and then never came back. That is the mechanism behind three
// separate harness symptoms recorded in 4caad35 — an out-of-range write answered
// 0x01 instead of 0x03, a legitimate GridService write refused, a read-only role
// denied its legitimate READS — and behind the whole hermetic gate being
// order-dependent.
//
// # What this does about it
//
// The Listener keeps its own binding from TLS session ID to the peer leaf DER,
// recorded at the handshake where the certificate was actually presented and
// verified. On a resumed handshake whose chain wolfSSL no longer holds, the leaf
// is restored from that binding.
//
// Why this is sound rather than a convenient lie:
//
//   - It is only consulted for a session wolfSSL reports as RESUMED. Resumption is
//     not something a peer can assert; wolfSSL grants it only after the peer proves
//     possession of the resumption secret from the original session. RFC 8446 §2.2
//     is explicit that a resumed session continues the original session's
//     authentication — so restoring the identity the original handshake verified is
//     the standard's own semantics, not an inference.
//   - The key is the TLS session ID, which is the same value wolfSSL uses to find
//     its own store, and which WOLFSSL_TICKET_HAVE_ID carries forward across a
//     resumption chain (measured: constant across 20 consecutive resumptions,
//     including across the point where wolfSSL lost the chain).
//   - A FULL handshake never reads the binding, only writes it. An identity is
//     therefore never restored onto a connection that presented its own credential.
//   - The binding is scoped to one Listener and dies with it, so an identity can
//     never cross between servers.
//   - It holds public certificates only — no keys, no secrets, nothing that would
//     be dangerous to log (contrast sessioncache.go, which holds master secrets).
//   - It is a bounded LRU, so a peer that opens unbounded distinct sessions cannot
//     grow it (the harness owes the same no-unbounded-growth discipline it checks
//     the product for).
//
// And when even the binding cannot answer — a listener restarted underneath a
// still-resumable client, or recovery deliberately disabled — the session is marked
// IdentityLost and Role() reports ErrPeerIdentityUnavailable, which is a DIFFERENT
// error from ErrNoRole. That distinction is the point: "I could not establish this
// peer's identity" and "this peer's certificate carries no role" are different
// facts, and a server that answers a bare authorization denial for the first one is
// reporting a verdict it did not reach. Callers are expected to fail LOUDLY on it.

import (
	"container/list"
	"encoding/hex"
	"errors"
	"sync"

	"csip-tls-test/internal/wolfssl"
)

// ErrPeerIdentityUnavailable reports that the peer authenticated — the handshake
// completed against a listener that demands and verifies a client certificate —
// but the peer's leaf certificate could not be recovered on this connection, so no
// role could be derived. It is deliberately NOT ErrNoRole: ErrNoRole is a fact
// about a certificate the server holds, this is the absence of one. A server that
// answers an authorization denial here is asserting a verdict it never computed;
// the correct response is to refuse the session and say why.
var ErrPeerIdentityUnavailable = errors.New("mbtls: peer identity unavailable on this session (resumed session whose peer certificate could not be recovered)")

// peerBindingCap bounds the per-Listener identity binding. One entry is a session
// ID plus a public leaf (~0.5 KiB), so the cap is a memory bound (~256 KiB), not a
// tuning knob: a peer that opens a large number of distinct TLS sessions must not
// be able to grow the server's memory without limit. Eviction is least-recently-
// used, which is the right policy here because an evicted entry only costs the
// affected chain a loud refusal, never a wrong answer.
const peerBindingCap = 512

// peerBinding is a Listener's bounded LRU from TLS session ID to peer leaf DER.
// The shape deliberately matches sessionCache's (same file-local idiom, same
// locking discipline) so the two read as one design; what differs is what they
// hold — this one holds only public certificates.
type peerBinding struct {
	mu  sync.Mutex
	cap int
	ll  *list.List               // front = most recently used
	m   map[string]*list.Element // hex(session id) -> element(*peerEntry)
}

type peerEntry struct {
	key string
	der []byte
}

func newPeerBinding(capacity int) *peerBinding {
	if capacity <= 0 {
		capacity = peerBindingCap
	}
	return &peerBinding{cap: capacity, ll: list.New(), m: make(map[string]*list.Element, capacity)}
}

// put records der as the peer leaf for session id, refreshing an existing entry
// and evicting the least-recently-used one when over capacity. An empty id or der
// is ignored — there is nothing to bind.
func (b *peerBinding) put(id, der []byte) {
	if len(id) == 0 || len(der) == 0 {
		return
	}
	key := hex.EncodeToString(id)
	b.mu.Lock()
	defer b.mu.Unlock()
	if el, ok := b.m[key]; ok {
		el.Value.(*peerEntry).der = der
		b.ll.MoveToFront(el)
		return
	}
	b.m[key] = b.ll.PushFront(&peerEntry{key: key, der: der})
	for b.ll.Len() > b.cap {
		back := b.ll.Back()
		if back == nil {
			break
		}
		delete(b.m, back.Value.(*peerEntry).key)
		b.ll.Remove(back)
	}
}

// get returns the peer leaf bound to session id, marking it most-recently-used.
func (b *peerBinding) get(id []byte) ([]byte, bool) {
	if len(id) == 0 {
		return nil, false
	}
	key := hex.EncodeToString(id)
	b.mu.Lock()
	defer b.mu.Unlock()
	el, ok := b.m[key]
	if !ok {
		return nil, false
	}
	b.ll.MoveToFront(el)
	return el.Value.(*peerEntry).der, true
}

// len reports how many identities are currently bound (tests; also the number an
// operator would see if this were ever exposed as a metric).
func (b *peerBinding) len() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.ll.Len()
}

// resolve settles s.PeerDER for a freshly accepted SERVER session and records what
// had to be done to get it. Order matters, and each step is a different question:
//
//  1. Did this handshake present a certificate? (wolfSSL parsed one, or retained a
//     chain for the session.) If so it is authoritative — bind it and stop. A full
//     handshake always lands here, which is why an identity is never restored onto
//     a connection that authenticated itself.
//  2. Otherwise, did this handshake RESUME? Only then may the binding answer, and
//     only for the exact session ID wolfSSL itself would have looked up.
//  3. Otherwise the identity is lost. Say so loudly rather than presenting an
//     anonymous peer to an authorization decision.
//
// recovery=false skips step 2 entirely: that is how a test stands up a server that
// reproduces the wolfSSL eviction on demand and proves the loud path is real
// (the StartLoopbackWriteRoles pattern — a check that cannot fail proves nothing).
func (b *peerBinding) resolve(s *Session, recovery bool) {
	if s == nil || s.ssl == nil {
		return
	}
	id := wolfssl.SessionID(s.ssl)
	if len(s.PeerDER) == 0 {
		// Second, independent read of the same fact: PeerCertificateDER re-decodes
		// the retained chain's leaf into an X509, this returns the retained DER
		// directly. They agree in practice; reading both costs nothing and means a
		// future wolfSSL that populates one and not the other does not silently
		// become an identity loss.
		if der := wolfssl.PeerChainLeafDER(s.ssl); len(der) > 0 {
			s.PeerDER = der
		}
	}
	if len(s.PeerDER) > 0 {
		b.put(id, s.PeerDER)
		return
	}
	if recovery && s.Resumed {
		if der, ok := b.get(id); ok {
			s.PeerDER = der
			s.IdentityRecovered = true
			return
		}
	}
	s.IdentityLost = true
}
