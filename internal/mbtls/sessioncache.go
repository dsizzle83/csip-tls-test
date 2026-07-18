package mbtls

// sessioncache.go is the bench's CLIENT-SIDE TLS session-resumption cache
// (T06.8): a bounded, process-local LRU of owned wolfSSL session handles keyed
// by peer address + presented identity, so a Dial to a peer previously handshaked
// with can offer the prior session and RESUME it (SunSpecTCP-46). This is the
// enhancement T06.4 flagged as missing — mbtls.Dial built a fresh CTX per call
// and never replayed a session, so Session.Resumed was structurally always false
// and the resume-after-drop probe (T06.8) could not work.
//
// # Referee independence (C9 / PN-1)
//
// The bench keeps its OWN resumption glue rather than importing the product's
// lexa-platform/securemodbus cache — the same rule that keeps mbtls's whole TLS
// profile independent of the gateway under test. It is derived from the wolfSSL
// session API (internal/wolfssl GetSession/SetSession/FreeSession) and the spec,
// not copied from securemodbus. The shape (bounded LRU, capture-on-close,
// addr+identity key) is a natural consequence of the API, not a shared
// implementation.
//
// SECURITY: a cached handle embeds the TLS master secret. It is never logged,
// serialized, or bus-published, and FreeSession runs on every eviction/replace
// path so a dropped secret does not linger in the heap.

import (
	"container/list"
	"strings"
	"sync"
	"unsafe"

	"csip-tls-test/internal/wolfssl"
)

// clientSessionCacheCap bounds the per-process resumption cache. A bench driving
// a whole role×target matrix touches only a handful of distinct peers, so 16 is
// ample; the bound is a memory/secret-lifetime guard (an unbounded addr-keyed
// cache is trivially inflatable when addresses come from a scanned range), not a
// tuning knob.
const clientSessionCacheCap = 16

// clientSessions is the shared client-side resumption cache. Package-global so a
// fresh Conn.Reconnect (which builds a brand-new mbtls.Session) still finds the
// session captured by the connection it replaces — resumption survives across
// Session and aggregator.Conn instances, keyed only by peer + identity.
var clientSessions = newSessionCache(clientSessionCacheCap)

// sessionCache is a bounded LRU of owned wolfSSL session handles, guarded by a
// mutex so concurrent Dials to one peer cannot free a handle out from under a
// concurrent resume attempt (withSession holds the lock across the wolfSSL
// SetSession call; wolfSSL dups the session internally, so the ssl is
// independent of the cached handle afterwards).
type sessionCache struct {
	mu  sync.Mutex
	cap int
	ll  *list.List               // front = most recently used
	m   map[string]*list.Element // key -> element(*cacheEntry)
}

type cacheEntry struct {
	key  string
	sess unsafe.Pointer // owned *WOLFSSL_SESSION
}

func newSessionCache(capacity int) *sessionCache {
	return &sessionCache{cap: capacity, ll: list.New(), m: make(map[string]*list.Element, capacity)}
}

// withSession runs fn with the cached session handle for key (or nil if none),
// holding the lock for the whole call so the handle cannot be freed by a
// concurrent put/evict while wolfSSL is reading it. Marks the entry
// most-recently-used on a hit.
func (c *sessionCache) withSession(key string, fn func(sess unsafe.Pointer)) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if el, ok := c.m[key]; ok {
		c.ll.MoveToFront(el)
		fn(el.Value.(*cacheEntry).sess)
		return
	}
	fn(nil)
}

// put stores sess for key (most-recently-used), freeing any handle it replaces
// and evicting the least-recently-used entry when over capacity. A nil sess is
// ignored (nothing resumable was captured).
func (c *sessionCache) put(key string, sess unsafe.Pointer) {
	if sess == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if el, ok := c.m[key]; ok {
		ent := el.Value.(*cacheEntry)
		if ent.sess != sess {
			wolfssl.FreeSession(ent.sess)
			ent.sess = sess
		}
		c.ll.MoveToFront(el)
		return
	}
	c.m[key] = c.ll.PushFront(&cacheEntry{key: key, sess: sess})
	for c.ll.Len() > c.cap {
		back := c.ll.Back()
		if back == nil {
			break
		}
		ent := back.Value.(*cacheEntry)
		wolfssl.FreeSession(ent.sess)
		delete(c.m, ent.key)
		c.ll.Remove(back)
	}
}

// evict frees and drops the cached handle for key, if any. Called when a Dial's
// handshake fails (including a rejected resume attempt) so a poisoned session is
// never replayed, and by ClearSessionCache for test hygiene.
func (c *sessionCache) evict(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if el, ok := c.m[key]; ok {
		ent := el.Value.(*cacheEntry)
		wolfssl.FreeSession(ent.sess)
		delete(c.m, key)
		c.ll.Remove(el)
	}
}

// clear frees every cached handle and empties the cache.
func (c *sessionCache) clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	for el := c.ll.Front(); el != nil; el = el.Next() {
		wolfssl.FreeSession(el.Value.(*cacheEntry).sess)
	}
	c.ll.Init()
	c.m = make(map[string]*list.Element, c.cap)
}

// ClearSessionCache frees and drops every cached client session. It exists for
// test isolation: the resumption cache is process-global, so a test that must
// observe a FULL (non-resumed) handshake to a reused address calls this first.
// Production callers never need it — resumption is transparent and always safe
// to attempt.
func ClearSessionCache() { clientSessions.clear() }

// clientCacheKey identifies a resumption slot by peer address plus the exact
// identity presented: the trust anchor (CAFile) and the client leaf chain
// (CertChainFile). Two Dials that agree on all three may share a resumed session;
// a different role (different client cert) or a different trust anchor must NOT —
// a resumed session carries the original peer identity, so resuming across
// identities would silently present the wrong role.
func clientCacheKey(addr string, p Profile) string {
	return strings.Join([]string{addr, "ca:" + p.CAFile, "crt:" + p.CertChainFile}, "|")
}
