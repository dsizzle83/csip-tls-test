package suitecsip

// runwire.go answers one question no single check's frame set can: "did the DUT
// put this message on the wire ANYWHERE in the run?"
//
// # Why a check needs it
//
// The DER self-reports — DERCapability, DERSettings, DERStatus, DERAvailability
// — are cadence- and change-driven. The DUT emits them on its own schedule, on
// a connection it opens when it has something to say, so the report a case is
// written to observe lands inside that case's 90-second window only by luck.
// When it lands outside, the case's own conversations hold no PUT and the
// criterion used to fall straight through to gridsim's admin log, whose answer
// is the SERVER's record rather than the wire.
//
// That fallback decided BASIC-028, CORE-009, CORE-014 and UTIL-002 in
// runs/certfix-validate-20260729T192416 on a sentence that reads "gridsim
// recorded no DERCapability PUT from the DUT anywhere in this run (it recorded:
// )" — a statement about an admin API, offered as a finding about a device. The
// capture says something much stronger and independently checkable: of the 122
// decryptable 2030.5 conversations in that run, not one carries a PUT of any
// kind. That is a fact about the DUT, derived from the wire, and it is the one
// the report should print.
//
// # What it may and may not do
//
// It may LOOK at the whole capture. Evidence.Index exists for exactly this —
// "a check legitimately needs to look at the capture as a whole (to prove the
// ABSENCE of a frame, for instance)". It may NOT CITE what it finds outside the
// check's own frames: those frames belong to another test case, and citing them
// is the precise failure Evidence.CiteFrames exists to refuse. So a run-scoped
// find is reported as a capture-derived narrative naming the frames a reader can
// look at, never as a citation, and the check's OWN conversations are always
// searched first so that an in-window report is cited properly.
//
// # Why the completeness flag is load-bearing
//
// "No PUT anywhere in the capture" is only a fact about the DUT if the capture
// was fully readable. A session whose secret is missing from the key log carries
// application data this scan cannot see, and concluding an absence from it would
// be reporting a decryption gap as a device fault. runWire therefore records
// whether every conversation that carried application data was decrypted, and a
// criterion may draw a negative conclusion only when it was.

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"sync"

	"csip-tls-test/internal/certify"
)

// runWire is the run's whole 2030.5 conversation set, decrypted.
type runWire struct {
	// Sessions are the recovered conversations, in capture order. They are NOT
	// scoped to any check and nothing in them may be cited.
	Sessions []*Transcript

	// Complete reports that every conversation carrying application data was
	// decrypted, so an ABSENCE observed here is a fact about the DUT rather
	// than about the key log. Reason says why it is false.
	Complete bool
	Reason   string

	// Decrypted and Opaque count the conversations either way, for the sentence
	// a criterion prints.
	Decrypted, Opaque int
}

// Filter returns every exchange in the run matching a predicate, in capture
// order. Each carries the conversation it came from (Exchange.In).
func (r *runWire) Filter(pred func(Exchange) bool) []Exchange {
	var out []Exchange
	for _, s := range r.Sessions {
		for _, e := range s.Exchanges {
			if pred(e) {
				out = append(out, e)
			}
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return firstFrame(out[i]) < firstFrame(out[j]) })
	return out
}

// Method returns every request in the run with the given method.
func (r *runWire) Method(method string) []Exchange {
	return r.Filter(func(e Exchange) bool { return e.Req != nil && e.Req.Method == method })
}

// Scope renders the extent this scan actually covered, so a criterion's Observed
// field says how much of the run its statement is about.
func (r *runWire) Scope() string {
	s := fmt.Sprintf("%d decrypted 2030.5 conversation(s) in the run's capture", r.Decrypted)
	if r.Opaque > 0 {
		s += fmt.Sprintf(" (%d further conversation(s) could not be decrypted: %s)", r.Opaque, r.Reason)
	}
	return s
}

// runWireCache memoises the scan per (capture, server endpoint). A campaign runs
// 79 checks against one capture and the scan reassembles and decrypts every
// conversation in it; doing that per check would multiply the citation phase by
// the number of cases for an answer that cannot change between them.
var (
	runWireMu    sync.Mutex
	runWireCache = map[runWireKey]*runWire{}
)

type runWireKey struct {
	index  *certify.FrameIndex
	remote netip.AddrPort
}

// runWireOf returns the run-scoped decrypted view of the capture, computing it
// once per capture and server endpoint.
func runWireOf(ev *certify.Evidence, remote netip.AddrPort) *runWire {
	if ev == nil || ev.Index == nil {
		return &runWire{Reason: "the run has no capture index"}
	}
	key := runWireKey{index: ev.Index, remote: remote}
	runWireMu.Lock()
	defer runWireMu.Unlock()
	if rw, ok := runWireCache[key]; ok {
		return rw
	}
	rw := scanRunWire(ev, remote)
	runWireCache[key] = rw
	return rw
}

// resetRunWireCache drops the memoised scans. Tests only: a run is one process
// and one capture.
func resetRunWireCache() {
	runWireMu.Lock()
	defer runWireMu.Unlock()
	runWireCache = map[runWireKey]*runWire{}
}

func scanRunWire(ev *certify.Evidence, remote netip.AddrPort) *runWire {
	rw := &runWire{Complete: true}
	var opaque []string
	for _, st := range ev.Index.Streams() {
		if st.Key.A.Port != remote.Port() && st.Key.B.Port != remote.Port() {
			continue
		}
		t, err := recoverFrom(ev, st, remote)
		if t == nil {
			// The conversation could not be framed as TLS at all. If it carried
			// no bytes this is a bare SYN/FIN pair and says nothing; recoverFrom
			// only returns nil on a hard failure, which does.
			rw.Complete = false
			opaque = append(opaque, fmt.Sprintf("%s (%v)", st.Key, err))
			continue
		}
		if t.Decrypted {
			rw.Sessions = append(rw.Sessions, t)
			rw.Decrypted++
			continue
		}
		// A conversation with no application data at all — a handshake the
		// server refused, a connection opened and dropped — hides nothing, so
		// it does not spoil the run-wide absence.
		if t.ClientAppRecords == 0 && t.ServerAppRecords == 0 {
			continue
		}
		rw.Opaque++
		rw.Complete = false
		opaque = append(opaque, fmt.Sprintf("%s: %s", st.Key, t.Undecryptable))
	}
	sort.SliceStable(rw.Sessions, func(i, j int) bool {
		return firstFrameOf(rw.Sessions[i]) < firstFrameOf(rw.Sessions[j])
	})
	if len(opaque) > 0 {
		rw.Reason = strings.Join(firstNStrings(opaque, 3), "; ")
		if len(opaque) > 3 {
			rw.Reason += fmt.Sprintf(" (and %d more)", len(opaque)-3)
		}
	}
	return rw
}

func firstNStrings(v []string, n int) []string {
	if len(v) <= n {
		return v
	}
	return v[:n]
}

// framesOf renders an exchange's frames for a narrative that names bytes it may
// not cite, so a reader can still open the capture at the right place.
func framesOf(e Exchange) string {
	fs := e.Frames()
	if len(fs) == 0 {
		return "(no frames recorded)"
	}
	parts := make([]string, 0, len(fs))
	for _, f := range fs {
		parts = append(parts, fmt.Sprint(f))
	}
	return strings.Join(parts, ", ")
}
