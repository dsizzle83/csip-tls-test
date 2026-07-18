package main

// sessions.go — a lightweight registry of currently-connected mbaps sessions,
// folded into GET /state (main.go's stateSnapshot) so the dashboard and
// cross-service QA flows (T06.4 discovery, T06.12 e2e loop) can see who is
// connected — peer address, asserted role, negotiated cipher/version,
// resumption, request count — without a packet capture. mbapsdev itself does
// not use this for any authorization decision (that stays the gateway's job,
// per dispatch.go's doc comment); it is observability only.

import (
	"sync"
	"time"

	"csip-tls-test/internal/mbtls"
)

// sessionInfo is one session's observable facts.
type sessionInfo struct {
	Peer        string    `json:"peer"`
	Role        string    `json:"role,omitempty"`
	Cipher      string    `json:"cipher"`
	TLSVersion  string    `json:"tls_version"`
	Resumed     bool      `json:"resumed"`
	ConnectedAt time.Time `json:"connected_at"`
	Requests    uint64    `json:"requests"`
}

// sessionRegistry tracks the sessionInfo for every currently-dispatching
// session, keyed by the *mbtls.Session identity. All access goes through the
// registry's lock — sessionInfo values themselves are never shared/mutated
// outside it.
type sessionRegistry struct {
	mu       sync.Mutex
	sessions map[*mbtls.Session]*sessionInfo
}

func newSessionRegistry() *sessionRegistry {
	return &sessionRegistry{sessions: make(map[*mbtls.Session]*sessionInfo)}
}

// trackedSession is the handle dispatchSession holds for the session it is
// currently serving: a capability to mutate this ONE session's info via the
// registry's lock, without callers needing to see the map itself.
type trackedSession struct {
	reg  *sessionRegistry
	sess *mbtls.Session
}

// add registers sess and returns a handle to update its info as the
// dispatch loop learns more (role, request count).
func (r *sessionRegistry) add(sess *mbtls.Session, peer string) *trackedSession {
	info := &sessionInfo{
		Peer:        peer,
		Cipher:      sess.Cipher,
		TLSVersion:  sess.TLSVer,
		Resumed:     sess.Resumed,
		ConnectedAt: time.Now(),
	}
	r.mu.Lock()
	r.sessions[sess] = info
	r.mu.Unlock()
	return &trackedSession{reg: r, sess: sess}
}

// remove drops the session from the registry. Safe to call once; a second
// call is a no-op (the map lookup simply misses).
func (r *sessionRegistry) remove(t *trackedSession) {
	t.reg.mu.Lock()
	delete(t.reg.sessions, t.sess)
	t.reg.mu.Unlock()
}

// snapshot returns a point-in-time copy of every tracked session's info, safe
// to JSON-encode without racing the dispatch goroutines.
func (r *sessionRegistry) snapshot() []sessionInfo {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]sessionInfo, 0, len(r.sessions))
	for _, info := range r.sessions {
		out = append(out, *info)
	}
	return out
}

func (t *trackedSession) setRole(role string) {
	t.reg.mu.Lock()
	if info, ok := t.reg.sessions[t.sess]; ok {
		info.Role = role
	}
	t.reg.mu.Unlock()
}

func (t *trackedSession) countRequest() {
	t.reg.mu.Lock()
	if info, ok := t.reg.sessions[t.sess]; ok {
		info.Requests++
	}
	t.reg.mu.Unlock()
}
