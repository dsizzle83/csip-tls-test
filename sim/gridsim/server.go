// Package gridsim implements a minimal IEEE 2030.5 server that serves
// the CSIP conformance test resource tree. It's designed to be used
// both as a test server in Go integration tests and as a standalone
// simulator you can run on your desktop.
//
// The resource tree matches the CSIP Conformance Test Procedures v1.3
// setup for CORE-010 (Function Set Assignments) and CORE-012 (Basic
// DER Program/Control).
//
// Phase 2 features:
//   - LFDI-gated /edev: returns only the connecting device's EndDevice
//     when the X-Peer-LFDI request header is present.
//   - 403 Forbidden for /edev/0 and /edev/1 (dummy aggregator devices).
//   - 3 DERPrograms (primacy 1/5/10) with rich DERControlLists.
//   - MirrorUsagePoint POST flow: POST /mup → 201+Location,
//     POST /mup/{n} → 204, GET /mup/{n} → the registered MUP.
//
// NOTE: this is a test *fixture* for driving CSIP DER-client (EUT) tests, not a
// conformant IEEE 2030.5 server. By default it serves each list whole (results
// == all) — but POST /admin/paginate arms a positive-pagination mode that
// honors the s/l query parameters and serves a list across multiple pages
// (paginate.go, audit P1-1). It does not emit a 400 for a missing Host header,
// and serves an otherwise-fixed resource tree. Do not present it as a
// server-under-test; the lab Test Server fills that role.
package gridsim

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"csip-tls-test/internal/csip/identity"
	"csip-tls-test/internal/tariff"
	"csip-tls-test/sim/simapi"
	model "lexa-proto/csipmodel"
)

// ContentType is the IEEE 2030.5 mandated content type (GEN.003).
const ContentType = "application/sep+xml"

// Server holds the resource tree and serves it over HTTP.
type Server struct {
	mu        sync.RWMutex
	resources map[string]interface{} // path → resource struct
	// curveHrefs is the set of INDIVIDUALLY-addressable DERCurve paths this
	// server has minted (curve.go's publishCurveResourcesLocked). It is kept
	// beside resources rather than derived from it by prefix-matching, so a
	// teardown removes exactly what a curve POST added and can never delete a
	// resource some other lever put at a /derp/{p}/dc/... path.
	curveHrefs map[string]bool
	mux        *http.ServeMux
	ClientLFDI string // The LFDI of the client we expect to connect
	clientSFDI uint64 // derived from ClientLFDI; updated by SetClientCertDER

	// clockSkew (seconds) is added to wall time wherever the server reports
	// or stamps CSIP time (/tm, admin server_time, control intervals). The
	// hub derives ClockOffset from /tm, so setting a skew warps the hub's
	// entire sense of server time — used by the dashboard's accelerated
	// bench-replay to fast-forward TOU windows and DER event schedules.
	// Atomic: read in handlers that hold s.mu in different orders.
	clockSkew atomic.Int64

	// dataPlaneAddr is the address the 2030.5 (mTLS) listener is serving, as
	// the embedding binary read it back from the kernel. Guarded by mu. See
	// SetDataPlaneAddr for why a process has to publish which sockets are its.
	dataPlaneAddr string
	// tlsPosture is the evidence-grade posture of the embedding binary's TLS
	// data plane, or nil when it never declared one. See SetTLSPosture.
	tlsPosture *AdminTLSPosture

	// chain is the runtime certificate-chain lever behind /admin/chain, wired
	// by the embedding binary via SetChainSwapper. It carries its OWN mutex —
	// a swap loads files and talks to the TLS server, which has no business
	// holding the resource lock every CSIP request contends on. See chain.go.
	chain chainLever

	// MirrorUsagePoint store (Phase 2 POST /mup flow).
	// mupNextID is protected by mu; do not read/write outside the mu lock.
	mupNextID int32

	// mupMu/mups is the durable admin record of every registered
	// MirrorUsagePoint (BASIC-029's /admin/mups lever, audit 2026-07-30). It is
	// SEPARATE from s.resources[location] above: model.MirrorUsagePoint has no
	// field for the ReadingType elements a registration POST carries, so
	// xml.Unmarshal drops them silently on the way into that struct, and the
	// 2030.5-shaped resource therefore cannot answer "what ReadingType did the
	// DUT declare". mups is where the raw-body facts /admin/mups needs to
	// publish — deviceLFDI, ReadingType uoms, reading count, created-at —
	// actually survive. It is SERVER STATE, not a log: a restart wipes it
	// honestly, and unlike the request log it is never evicted, which is the
	// whole point — see suitecsip.critMUPRegistered's doc for why the request
	// log alone made BASIC-029 flap. Guarded by its own mutex rather than mu,
	// like every other admin-observability store in this package (derPutMu,
	// logEventMu, …).
	mupMu sync.Mutex
	mups  []mupRecord

	// derHomeGen counts how many times RehomeDER has re-homed a DER's
	// DERCapability/DERSettings hrefs (CSIP IG §6.3.5.2 lever for CORE-009/
	// CORE-014 — see rehome.go). 0 means every DER still sits at the hrefs
	// buildResourceTree gave it. Guarded by mu, like every other resource-tree
	// fact: a re-home IS a resource-tree mutation (new hrefs installed, old ones
	// removed), so it needs the same lock the request handlers take.
	derHomeGen int

	// advertisedPollRate is what -poll-rate-s asked for, in seconds, or 0 when
	// nothing overrode the built-in rates. It is remembered rather than only
	// applied because control lists are CREATED after start-up: every
	// POST /admin/control and /admin/curve installs a fresh
	// DERControlList/ExtendedDERControlList, and one installed at the
	// hardcoded default silently undoes the override for the whole walk (the
	// client paces at the SLOWEST advertised rate). Guarded by mu.
	advertisedPollRate uint32

	// malformKind, when non-empty, makes serveXML emit a deliberately
	// non-conformant variant of the matching resource (QA fault injection via
	// POST /admin/malform). Guarded by mu. See malform.go.
	malformKind string

	// explicitNil maps a control to the DERControlBase elements it serves as
	// PRESENT AND EXPLICITLY NULL (xsi:nil) rather than by value or by
	// omission — RC0 §9.5 row 9's release shape, armed per control by
	// POST /admin/control null_axes. Empty on a server nobody armed, and an
	// empty map is what makes the document byte-identical to the pre-lever
	// one. Guarded by mu. See explicitnil.go.
	explicitNil map[explicitNilKey][]string

	// Northbound outage injection (QA fault injection via POST /admin/outage).
	// outageMode "" = healthy; see outage.go. outageSeq invalidates a pending
	// auto-clear when a newer arm/clear supersedes it. Guarded by mu.
	outageMode  string
	outageHangS int
	outageSeq   uint64

	// Response log (CORE-022: client POSTs Response on event transitions)
	responseMu sync.Mutex
	responses  []model.Response
	// complianceAlerts records every Response classifyResponseStatus judges
	// worth an operator's attention — the legacy extension (status ==
	// alertStatusFloor, 0xF0 exactly, F10) and the SD-02 Table 27 classes
	// (4/5/8/10/252/253/254) — with the server receive time, surfaced via GET
	// /admin/alerts so the dashboard can show when the hub reports it cannot
	// meet a control. Guarded by responseMu.
	complianceAlerts []ComplianceAlert

	// logBuf feeds GET /admin/logs (SSE). The sim/server binary tees the
	// standard logger into LogWriter() so every request log line streams to
	// the dashboard's unified Logs tab.
	logBuf *simapi.LogBuffer

	// Dynamic §10.5 pricing (dashboard V2, POST /admin/tariff). When tariff is
	// non-nil the pricing tree (/tp…) is generated from it for a rolling 48 h
	// window centered on s.Now(); nil means the legacy static two-tier tree
	// (buildPricing). tariffIntervals is the merged, contiguous interval set the
	// current tree was built from; tariffWin{Start,End} are the generated window
	// bounds and tariffActive{Start,End} the bounds of the interval currently in
	// ActiveTimeTariffIntervalList (the fast-path staleness check). All of these
	// are guarded by mu, exactly like s.resources. See pricing_dynamic.go.
	tariff            *tariff.Tariff
	tariffIntervals   []pricingIv
	tariffWinStart    int64
	tariffWinEnd      int64
	tariffActiveStart int64
	tariffActiveEnd   int64

	// DER* report PUT store (WP-4 / CORE-009). Last body received per
	// resource path (dercap/derset/derstat/deravail), surfaced via
	// GET /admin/derputs and ReceivedDERPuts. Guarded by derPutMu.
	derPutMu sync.Mutex
	derPuts  map[string]DERPut

	// LogEvent store (WP-6 / BASIC-027). Time-ordered list the client POSTs
	// to its LogEventListLink, surfaced via GET /admin/logevents and
	// ReceivedLogEvents. logEvents/logEventNextID are guarded by logEventMu.
	logEventMu     sync.Mutex
	logEvents      []model.LogEvent
	logEventNextID int32

	// ERR-001 redirect injection (QA, default off): while armed, the first N
	// GETs of a configured path answer 301/302 + Location. Guarded by
	// redirectMu. See redirect.go.
	redirectMu sync.Mutex
	redirect   redirectState

	// resource_410 injection (QA, default off): while armed, GETs of a
	// configured path answer 410 Gone. Guarded by goneMu. See gone.go.
	goneMu sync.Mutex
	gone   goneState

	// event_delay injection (QA, default off): while armed, GETs of a
	// configured path sleep before serving. Guarded by delayMu; delaySeq
	// invalidates a pending auto-clear. See delay.go.
	delayMu  sync.Mutex
	delay    delayState
	delaySeq uint64

	// positive list pagination (QA, default off): while armed, GETs of a
	// paginatable list honor s/l and serve one page with honest all/results.
	// Guarded by paginateMu. See paginate.go.
	paginateMu sync.Mutex
	paginate   paginateState

	// fleet is the CTP Figure-15 aggregator topology (default off — nil).
	// Guarded by mu, like every other resource-tree fact. See fleet.go.
	fleet *fleetState

	// subs is the Subscription/Notification function set (default off — nil).
	// The POINTER is guarded by mu; the store behind it carries its own mutex,
	// which sits BELOW mu in the lock order (see subState). Nothing may take
	// that mutex while holding mu, which is why the SubscriptionList resources
	// are generated at GET time rather than stored in s.resources.
	subs *subState
}

// NewServer creates a grid sim with a complete CSIP conformance resource tree.
// clientLFDI is the hex-encoded LFDI of the client device (from their cert).
func NewServer(clientLFDI string) *Server {
	s := &Server{
		resources:  make(map[string]interface{}),
		curveHrefs: make(map[string]bool),
		mux:        http.NewServeMux(),
		ClientLFDI: clientLFDI,
		logBuf:     simapi.NewLogBuffer(),
	}
	s.buildResourceTree()
	// The static tree's own DERCurve entries get individual hrefs too. Before
	// this, /derp/0/dc/0 — the href the fixture curve carries in its own
	// Resource — answered 404 on a bench where no admin lever had run, so the
	// default tree advertised a curve it did not serve.
	for p := 0; p <= 2; p++ {
		if cl, ok := s.resources[fmt.Sprintf("/derp/%d/dc", p)].(*model.DERCurveList); ok {
			s.publishCurveResourcesLocked(p, cl)
		}
	}
	s.mux.HandleFunc("/", s.handleRequest)
	return s
}

// LogWriter returns the io.Writer the embedding binary tees its standard
// logger into so GET /admin/logs can stream request logs:
//
//	log.SetOutput(io.MultiWriter(os.Stderr, sim.LogWriter()))
func (s *Server) LogWriter() io.Writer { return s.logBuf }

// Handler returns the http.Handler for use with your TLS server.
func (s *Server) Handler() http.Handler {
	return s.mux
}

// SetClientCertDER derives the LFDI and SFDI from the peer certificate's DER
// bytes and rebuilds the /edev resource. Call this once per connection after
// the mTLS handshake completes. Safe to call from any goroutine.
func (s *Server) SetClientCertDER(der []byte) {
	lfdi, sfdi := identity.FromCertificateDER(der)
	s.mu.Lock()
	s.ClientLFDI = lfdi.String()
	s.clientSFDI = uint64(sfdi)
	s.rebuildEndDeviceList()
	s.mu.Unlock()
	log.Printf("[gridsim] client identity from cert: LFDI=%s SFDI=%d", lfdi, sfdi)
}

// Now returns the server's notion of current CSIP time: wall clock plus the
// configured skew. Use this for every value a client can observe (/tm,
// control intervals, admin server_time) so warped time stays coherent.
func (s *Server) Now() int64 {
	return time.Now().Unix() + s.clockSkew.Load()
}

// SetClockSkew sets the offset (seconds) between served CSIP time and the
// wall clock. Zero restores real time.
func (s *Server) SetClockSkew(offsetS int64) {
	s.clockSkew.Store(offsetS)
}

// ClockSkew returns the currently configured skew in seconds.
func (s *Server) ClockSkew() int64 {
	return s.clockSkew.Load()
}

// SetAdvertisedPollRate overrides the pollRate this server advertises on every
// resource class a poll_rate_mode=honor client paces its walk from:
// DeviceCapability, Time, and each DERProgram's DERControlList — including the
// EXTENDED (curve-linked) form of that list. Zero leaves the built-in values
// alone.
//
// The rate is also REMEMBERED, and every control list created afterwards adopts
// it. Without that the override lasts exactly until the first
// POST /admin/control or /admin/curve, each of which installs a fresh list at
// the hardcoded 60 — and since a conformant client paces at the SLOWEST
// advertised rate, one such list drags the whole walk back to 60 s however fast
// /dcap says to go. That is a live-bench trap, not a theoretical one: the CSIP
// scenario rows post controls as their setup step, so it fires on the cases that
// need the fast cadence most.
//
// # WHY THIS LEVER EXISTS
//
// A conformant 2030.5 client in poll_rate_mode=honor paces its whole-tree walk
// at the SLOWEST advertised class pollRate, so that no resource is fetched more
// often than the server asked for. Against gridsim's defaults that maximum is
// /tm's 900 s, and the DUT correctly walks once every 15 minutes.
//
// That is right, and it makes the CSIP suite untestable: the [C]-half checks
// observe a walk the DUT opens on its own schedule, and waiting 15 minutes per
// case over ~79 cases is not a test run anybody will sit through. On
// 2026-07-28 a full run SKIPped every CSIP case for exactly this reason, and
// the mass-skip read as a DUT fault for several rounds before the capture
// showed one clean walk 12m45s into a 22-minute window — the gateway was
// behaving perfectly.
//
// The fix belongs on the SERVER, not the DUT. pollRate is the server's to
// choose, so a conformance run advertises a fast one and leaves the device in
// its shipping configuration. Lowering the DUT's own poll_rate_mode to
// "override" would also produce frequent walks, but it would certify a mode the
// product does not ship with.
func (s *Server) SetAdvertisedPollRate(seconds uint32) {
	if seconds == 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.advertisedPollRate = seconds
	// Every resource class the client's pacing looks at, not just /dcap and
	// /tm: lexa-gw's advertisedPollSeconds takes the MAXIMUM over
	// DeviceCapability, Time, and EACH DERProgram's DERControlList, so one
	// missed DERControlList pins the whole walk to its rate. Setting /dcap and
	// /tm alone moved the observed cadence from 900s to 300s and no further —
	// a DERControlList was still advertising 300.
	var n int
	for _, r := range s.resources {
		switch v := r.(type) {
		case *model.DeviceCapability:
			v.PollRate = seconds
			n++
		case *model.Time:
			v.PollRate = seconds
			n++
		case *model.DERControlList:
			v.PollRate = seconds
			n++
		case *model.ExtendedDERControlList:
			// The curve-linked list is the same resource class to a client —
			// it shares its XMLName with the scalar DERControlList (curve.go)
			// and AdvertisedPollRate has always counted it. Setting one form
			// and not the other left the max pinned by whichever the tree
			// happened to hold.
			v.PollRate = seconds
			n++
		}
	}
	log.Printf("[gridsim] advertised pollRate set to %ds on %d resource(s) "+
		"(DeviceCapability, Time, DERControlList incl. the extended form); "+
		"control lists created from now on adopt it", seconds, n)
}

// controlListPollRateLocked is the pollRate a newly created DERControlList or
// ExtendedDERControlList should advertise: whatever -poll-rate-s configured, or
// the built-in default when nothing did. Caller must hold s.mu.
func (s *Server) controlListPollRateLocked() uint32 {
	if s.advertisedPollRate != 0 {
		return s.advertisedPollRate
	}
	return defaultControlListPollRate
}

// defaultControlListPollRate is the built-in cadence a control list advertises
// when no override is configured. It is the value every call site here used
// literally before controlListPollRateLocked existed, so an un-overridden tree
// serves byte-identical XML.
const defaultControlListPollRate = 60

// AdvertisedPollRate returns the pollRate, in seconds, that a client in
// poll_rate_mode "honor" will pace its whole-tree walk at — 0 when the tree
// advertises none at all.
//
// It is the MAXIMUM over the resource classes such a client's pacing looks at,
// for the reason SetAdvertisedPollRate gives at length: lexa-gw takes the
// maximum so that no resource is fetched more often than its server asked for,
// which means one DERControlList still saying 300 pins the walk to 300 however
// fast /dcap says to go. The extended (curve-linked) list counts too — POST
// /admin/curve installs one with a hardcoded 60, so a tree that has been
// curve-bound may advertise something other than what -poll-rate-s set.
//
// This exists so the number is ASKABLE. A conformance harness sizing an
// observation window around "the DUT's cadence" was reading the DUT's own
// configured discovery interval, which under poll_rate_mode "honor" is only a
// floor — the rate the walk actually keeps is this one, and it is the server's
// to choose. A harness that derives a window from the wrong one waits
// confidently for a walk that was never going to arrive inside it, and records
// the silence as a fact about the device.
func (s *Server) AdvertisedPollRate() uint32 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.advertisedPollRateLocked()
}

// advertisedPollRateLocked is AdvertisedPollRate for callers already holding
// s.mu — the admin status handler holds it for the whole response.
func (s *Server) advertisedPollRateLocked() uint32 {
	var top uint32
	for _, r := range s.resources {
		var pr uint32
		switch v := r.(type) {
		case *model.DeviceCapability:
			pr = v.PollRate
		case *model.Time:
			pr = v.PollRate
		case *model.DERControlList:
			pr = v.PollRate
		case *model.ExtendedDERControlList:
			pr = v.PollRate
		}
		if pr > top {
			top = pr
		}
	}
	return top
}

// SetDataPlaneAddr records the address the embedding binary's 2030.5 listener
// actually accepted from the kernel, so GET /admin/status can answer "which
// data plane does THIS process serve?".
//
// The admin API and the 2030.5 listener are two sockets, and nothing outside
// the process guarantees a client holding one is talking to the process holding
// the other. On 2026-07-28 an orphaned gridsim survived its own SIGTERM and
// kept :11114 while its replacement took :11113 and logged "address already in
// use" for the admin port before carrying on. The DUT then talked to the new
// process while the conformance harness read its server-side observations from
// the eight-hour-old orphan, which had of course recorded no DUT traffic. Every
// case so misread was published as a device that never dialled.
//
// Publishing this address, and the pid beside it, is what lets a harness refuse
// that run in its first second instead of misattributing a whole campaign.
func (s *Server) SetDataPlaneAddr(addr string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.dataPlaneAddr = addr
}

// DataPlaneAddr returns the address recorded by SetDataPlaneAddr — empty when
// the embedding binary never set one, which is an honest "unknown" rather than
// a guess a caller could mistake for a fact.
func (s *Server) DataPlaneAddr() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.dataPlaneAddr
}

// SetTLSPosture records the EVIDENCE-GRADE posture of the embedding binary's
// TLS data plane, so GET /admin/status can answer it.
//
// # Why this is published at all
//
// Two of gridsim's launch flags decide whether a conformance run's evidence CAN
// exist, and neither is observable from outside the process:
//
//	-no-tickets      a RESUMED TLS session carries no Certificate message (RFC
//	                 5077 §3.1, RFC 8446 §2.2 for 1.3). A capture window that
//	                 catches one therefore has NO certificate exchange to cite —
//	                 which is exactly how csip-tls-test's RPT-060 came to fail
//	                 with no attributable fresh handshake in any COMM-004
//	                 scenario, long after the bench that produced it had gone
//	                 home (audit LAB29-011).
//	-idle-timeout-s  without it a 2030.5 client holds ONE connection across
//	                 every poll cycle, so the whole run is one session and no
//	                 per-scenario window begins with a ClientHello to observe.
//
// A harness cannot infer either from the traffic: the absence of a handshake in
// a window looks the same whether tickets were enabled or the DUT simply had
// nothing to say. So the launch posture is published, and a run that DEPENDS on
// it proves it before case 1 rather than discovering it at report time.
//
// A gridsim whose embedding binary never calls this reports NO tls object at
// all — not a false one. "Unreported" and "reported false" are different facts
// and a fail-closed caller must be able to tell them apart: the first is an old
// binary, the second is a misconfigured bench.
func (s *Server) SetTLSPosture(noTickets bool, idle time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tlsPosture = &AdminTLSPosture{
		NoTickets:    noTickets,
		IdleTimeoutS: int(idle / time.Second),
	}
}

// TLSPosture returns the posture recorded by SetTLSPosture, or nil when the
// embedding binary never declared one.
func (s *Server) TLSPosture() *AdminTLSPosture {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.tlsPosture == nil {
		return nil
	}
	cp := *s.tlsPosture
	return &cp
}

// rebuildEndDeviceList reconstructs the /edev resource with the current
// ClientLFDI and clientSFDI. Caller must hold s.mu for writing.
func (s *Server) rebuildEndDeviceList() { s.rebuildEndDeviceListLocked() }

// rebuildEndDeviceListLocked is rebuildEndDeviceList's body, named so the
// Subscription and fleet levers can call it from code that already holds s.mu.
//
// The three shapes it can serve are the three configurations gridsim has:
// the fleet's five-EndDevice Figure-15 list, the default three-EndDevice list
// widened with SubscriptionListLinks, or — when neither lever is on — exactly
// the bytes this simulator has always served.
func (s *Server) rebuildEndDeviceListLocked() {
	if s.fleet != nil {
		s.buildFleetLocked()
		return
	}
	if s.subs != nil {
		s.rebuildSubscribableEndDeviceListLocked()
		return
	}

	boolTrue := true
	now := time.Now().Unix()

	s.resources["/edev"] = &model.EndDeviceList{
		Resource: model.Resource{Href: "/edev"},
		All:      3,
		Results:  3,
		PollRate: 300,
		EndDevice: []model.EndDevice{
			{
				Resource:    model.Resource{Href: "/edev/0"},
				LFDI:        "0000000000000000000000000000000000000001",
				SFDI:        100000001,
				ChangedTime: now - 1000,
			},
			{
				Resource:    model.Resource{Href: "/edev/1"},
				LFDI:        "0000000000000000000000000000000000000002",
				SFDI:        100000002,
				ChangedTime: now - 500,
			},
			{
				Resource:         model.Resource{Href: "/edev/2"},
				LFDI:             s.ClientLFDI,
				SFDI:             s.clientSFDI,
				ChangedTime:      now,
				Enabled:          &boolTrue,
				RegistrationLink: &model.Link{Href: "/edev/2/reg"},
				DERListLink: &model.ListLink{
					Link: model.Link{Href: "/edev/2/der"},
					All:  1,
				},
				FunctionSetAssignmentsListLink: &model.ListLink{
					Link: model.Link{Href: "/edev/2/fsa"},
					All:  1,
				},
				LogEventListLink: &model.ListLink{
					Link: model.Link{Href: "/edev/2/lev"},
					All:  0,
				},
			},
		},
	}
}

// handleRequest dispatches GET and POST requests.
func (s *Server) handleRequest(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path
	peerLFDI := r.Header.Get("X-Peer-LFDI")
	log.Printf("[gridsim] %s %s (peer=%s)", r.Method, path, peerLFDI)

	// Northbound outage injection (QA): fail every CSIP request while armed.
	// Sits above routing so the whole served tree — including /dcap and /tm —
	// disappears at once, exactly like a dead or wedged head-end.
	if s.outageIntercept(w) {
		return
	}

	switch r.Method {
	case http.MethodGet:
		s.handleGET(w, r, path, peerLFDI, r.URL.Query())
	case http.MethodPost:
		s.handlePOST(w, r, path, peerLFDI)
	case http.MethodPut:
		// DER* report PUT (WP-4 / CORE-009): dercap/derset/derstat/deravail
		// under an EndDevice's DER tree accept the client's self-report.
		// Any other path falls through to 405.
		s.handlePUT(w, r, path)
	case http.MethodDelete:
		// A Subscription is the one resource in this tree a client may DELETE
		// (IEEE 2030.5 §10.1 / CORE-019's cancellation). Every other path keeps
		// the 405 + Allow answer it has always had, so a run without the
		// Subscription function set behaves exactly as before.
		if s.handleSubscriptionRequest(w, r, path) {
			return
		}
		w.Header().Set("Allow", "GET, POST, PUT")
		w.WriteHeader(http.StatusMethodNotAllowed)
	case http.MethodPatch, http.MethodHead, http.MethodOptions:
		// Known HTTP method, not allowed here → 405 with an Allow header
		// listing valid methods (GEN.045).
		w.Header().Set("Allow", "GET, POST, PUT")
		w.WriteHeader(http.StatusMethodNotAllowed)
	default:
		// Unrecognised method token (e.g. FOO) → 501 Not Implemented.
		w.WriteHeader(http.StatusNotImplemented)
	}
}

func (s *Server) handleGET(w http.ResponseWriter, r *http.Request, path, peerLFDI string, query url.Values) {
	// ERR-001 redirect injection (QA, default off): while armed, the first N
	// GETs of the configured path answer 301/302 + Location so the hub's
	// redirect_max follow path is exercised on the wire. Sits above routing
	// and LFDI gating so the redirect fires before any resource lookup.
	if s.redirectIntercept(w, path) {
		return
	}

	// resource_410 injection (QA, default off): a chosen served resource
	// answers 410 Gone so the hub's fail-closed "hold last-known-good on a
	// gone resource" path is exercised. Above routing, like the redirect
	// intercept, so it fires before any resource lookup or LFDI gating.
	if s.goneIntercept(w, path) {
		return
	}

	// event_delay injection (QA, default off): stall the configured path
	// before serving so the hub's discovery timeout/hang tolerance is
	// exercised without a full outage. Unlike gone/redirect it writes no
	// response — it sleeps, then normal serving proceeds below.
	s.delayIntercept(path)

	// LFDI-gated: /edev/0 and /edev/1 are dummy aggregator devices.
	// A connecting client may only see its own EndDevice sub-resources.
	if peerLFDI != "" {
		if path == "/edev/0" || strings.HasPrefix(path, "/edev/0/") ||
			path == "/edev/1" || strings.HasPrefix(path, "/edev/1/") {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		// Return a filtered EndDeviceList showing only the connecting device —
		// or, in fleet mode, the aggregator's own EndDevice plus the managed
		// devices the server has assigned to it (fleet.go).
		if path == "/edev" {
			if s.serveFleetEndDeviceList(w, peerLFDI) {
				return
			}
			s.serveFilteredEndDeviceList(w, peerLFDI)
			return
		}
	}

	// The Subscription function set (default off) is served from its own store
	// rather than from the resource map, so it is routed before the lookup.
	if s.handleSubscriptionRequest(w, r, path) {
		return
	}

	// Keep /tm current: refresh CurrentTime on every GET so the hub's
	// computed clock offset tracks the configured skew (zero in normal
	// operation, per CSIP §5.2.1.3; non-zero during accelerated replay).
	if path == "/tm" {
		s.mu.Lock()
		if tm, ok := s.resources["/tm"].(*model.Time); ok {
			tm.CurrentTime = s.Now()
		}
		s.mu.Unlock()
	}

	// Dynamic pricing (dashboard V2): keep the §10.5 tree centered on server
	// time. Cheap when no tariff is loaded — the RLock test short-circuits on
	// tariff==nil and never touches the write lock, so the legacy static tree
	// serves byte-for-byte as before. Only /tp… reads can go stale.
	if strings.HasPrefix(path, "/tp") {
		s.refreshPricingIfStale()
	}

	s.mu.RLock()
	resource, ok := s.resources[path]
	s.mu.RUnlock()

	if !ok {
		log.Printf("[gridsim] 404: no resource at %s", path)
		w.WriteHeader(http.StatusNotFound)
		return
	}
	// Positive pagination (QA, default off): when armed, slice a list resource
	// to the requested s/l page with honest all/results so a client must page
	// to see every entry (audit P1-1). A no-op — resource unchanged — when
	// pagination is disarmed or resource is not a paginatable list.
	resource = s.applyPagination(path, resource, query)
	s.serveXML(w, resource)
}

// serveFilteredEndDeviceList builds an EndDeviceList containing only the
// EndDevice whose LFDI matches peerLFDI. Case-insensitive comparison.
//
// It handles both list shapes gridsim can hold: the default
// model.EndDeviceList and the widened fleetEndDeviceList the fleet and
// Subscription levers install (fleet.go). A stranger reaching this path while
// the fleet is served gets the same one-device answer it always got — the
// fleet is disclosed by serveFleetEndDeviceList to the aggregator alone.
func (s *Server) serveFilteredEndDeviceList(w http.ResponseWriter, peerLFDI string) {
	s.mu.RLock()
	res := s.resources["/edev"]
	s.mu.RUnlock()

	switch edl := res.(type) {
	case *model.EndDeviceList:
		var filtered []model.EndDevice
		for _, ed := range edl.EndDevice {
			if strings.EqualFold(ed.LFDI, peerLFDI) {
				filtered = append(filtered, ed)
			}
		}
		n := uint32(len(filtered))
		s.serveXML(w, &model.EndDeviceList{
			Resource:  model.Resource{Href: "/edev"},
			All:       n,
			Results:   n,
			PollRate:  edl.PollRate,
			EndDevice: filtered,
		})
	case *fleetEndDeviceList:
		var filtered []fleetEndDevice
		for _, ed := range edl.EndDevice {
			if strings.EqualFold(ed.LFDI, peerLFDI) {
				filtered = append(filtered, ed)
			}
		}
		n := uint32(len(filtered))
		s.serveXML(w, &fleetEndDeviceList{
			Href: "/edev", All: n, Results: n,
			PollRate: edl.PollRate, Subscribable: edl.Subscribable, EndDevice: filtered,
		})
	default:
		w.WriteHeader(http.StatusInternalServerError)
	}
}

func (s *Server) handlePOST(w http.ResponseWriter, r *http.Request, path, peerLFDI string) {
	switch {
	case path == "/mup":
		s.handleMUPCreate(w, r, peerLFDI)
	case strings.HasPrefix(path, "/mup/"):
		s.handleMUPReadings(w, r, path)
	case strings.HasPrefix(path, "/rsps/") && strings.HasSuffix(path, "/r"):
		s.handleResponsePost(w, r, path)
	case isLogEventListPath(path):
		s.handleLogEventPost(w, r, path, peerLFDI)
	// The client's Subscription POST (default off): 201 Created with a
	// Location header naming the created subscription. See subscribe.go.
	case s.handleSubscriptionRequest(w, r, path):
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

// handleMUPCreate handles POST /mup to register a new MirrorUsagePoint.
// Returns 201 Created with a Location header pointing to the new resource.
func (s *Server) handleMUPCreate(w http.ResponseWriter, r *http.Request, peerLFDI string) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	var mup model.MirrorUsagePoint
	if err := xml.Unmarshal(body, &mup); err != nil {
		log.Printf("[gridsim] POST /mup: unmarshal error: %v", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	if peerLFDI != "" {
		mup.DeviceLFDI = peerLFDI
	}
	if mup.PostRate == 0 {
		mup.PostRate = 900 // default: 15 min
	}

	s.mu.Lock()
	// Generate ID and store atomically under the same lock to prevent
	// a gap between ID allocation and resource insertion.
	id := s.mupNextID
	s.mupNextID++
	location := fmt.Sprintf("/mup/%d", id)
	mup.Href = location
	s.resources[location] = &mup
	// Update the MUP list count and entries.
	if ml, ok := s.resources["/mup"].(*model.MirrorUsagePointList); ok {
		ml.All++
		ml.Results++
		ml.MirrorUsagePoint = append(ml.MirrorUsagePoint, mup)
	}
	s.mu.Unlock()

	// Durable admin record (see the mups field doc): captures the ReadingType
	// uoms the model.MirrorUsagePoint unmarshal above silently dropped, keyed
	// by the href just allocated so a later POST /mup/{n} of readings can find
	// and extend it. Deliberately a SEPARATE lock from s.mu/s.resources: this
	// store exists only for GET /admin/mups to read, never for the 2030.5 data
	// plane, so it has no business contending with every CSIP request.
	s.mupMu.Lock()
	s.mups = append(s.mups, mupRecord{
		Href:         location,
		LFDI:         mup.DeviceLFDI,
		ReadingTypes: mupReadingTypeUOMs(body),
		CreatedAt:    s.Now(),
		// The RAW bytes, not a re-marshal of the decoded struct. A decode
		// cannot tell an absent mandatory element from a present zero, and
		// that distinction is the entire subject of the MirrorUsagePoint
		// element oracle this feeds (suitecsip's critMUPElementsAndRoleFlags).
		// Re-marshalling here would erase the defect before anyone could grade
		// it.
		Body: string(body),
	})
	s.mupMu.Unlock()

	w.Header().Set("Location", location)
	w.WriteHeader(http.StatusCreated)
	log.Printf("[gridsim] POST /mup → created %s (postRate=%d)", location, mup.PostRate)
}

// handleMUPReadings handles POST /mup/{n} to accept periodic meter readings.
// Returns 204 No Content on success.
func (s *Server) handleMUPReadings(w http.ResponseWriter, r *http.Request, path string) {
	body, _ := io.ReadAll(r.Body) // readings are not persisted whole; only the admin summary below survives

	s.mu.RLock()
	_, ok := s.resources[path]
	s.mu.RUnlock()

	if !ok {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	// Roll this reading into the durable admin record: bump the count and fold
	// in any ReadingType this POST declares for itself (the standard 2030.5
	// shape — model.MirrorMeterReading.ReadingType — as distinct from one
	// embedded at registration, which mupReadingTypeUOMs also catches).
	s.mupMu.Lock()
	for i := range s.mups {
		if s.mups[i].Href == path {
			s.mups[i].Readings++
			s.mups[i].ReadingTypes = mergeUOMs(s.mups[i].ReadingTypes, mupReadingTypeUOMs(body))
			break
		}
	}
	s.mupMu.Unlock()

	w.WriteHeader(http.StatusNoContent)
	log.Printf("[gridsim] POST %s → readings accepted (204)", path)
}

// mupRecord is the durable, admin-visible record of one registered
// MirrorUsagePoint. Guarded by mupMu. See AdminMUP / handleAdminMUPs for the
// JSON shape this is published as, and the mups field doc on Server for why it
// exists apart from s.resources.
type mupRecord struct {
	Href         string
	LFDI         string
	ReadingTypes []uint8
	Readings     int
	CreatedAt    int64
	// Body is the registration POST's sep+xml, verbatim.
	//
	// It is kept for the same reason AdminDERPut keeps one: a criterion that
	// grades the CONTENT of what the DUT registered — which elements it carried,
	// what its roleFlags said — cannot work from a summary, and registration is a
	// ONE-TIME event that routinely predates the window of the case that grades
	// it, so the transcript is not always available to fall back on. Summarised
	// fields (LFDI, ReadingTypes) stay, because a reader of /admin/mups wants
	// them without parsing; the body is what makes the store gradable.
	Body string
}

// mupReadingTypeUOMs scans a MirrorUsagePoint or MirrorMeterReading POST body
// for every uom value nested anywhere under a ReadingType element (2030.5
// Table 11: 38=W real power, 63=var reactive, 33=Hz frequency, 29=V voltage).
// It reads the raw bytes rather than unmarshalling into model.MirrorUsagePoint
// (which has no ReadingType field at all — xml.Unmarshal drops one silently)
// or model.MirrorMeterReading (whose ReadingType nests one level differently
// than the DUT observed on this bench actually sends it, embedding ReadingType
// straight inside the MirrorUsagePoint registration POST rather than a
// separate MirrorMeterReading resource). /admin/mups exists to publish what
// arrived, not what either struct happens to declare, so this walks the token
// stream directly instead of unmarshalling into either shape.
func mupReadingTypeUOMs(body []byte) []uint8 {
	dec := xml.NewDecoder(bytes.NewReader(body))
	var stack []string
	var uoms []uint8
	for {
		tok, err := dec.Token()
		if err != nil {
			break
		}
		switch t := tok.(type) {
		case xml.StartElement:
			stack = append(stack, t.Name.Local)
		case xml.EndElement:
			if len(stack) > 0 {
				stack = stack[:len(stack)-1]
			}
		case xml.CharData:
			if len(stack) >= 2 && stack[len(stack)-1] == "uom" && stack[len(stack)-2] == "ReadingType" {
				if v, perr := strconv.ParseUint(strings.TrimSpace(string(t)), 10, 8); perr == nil {
					uoms = append(uoms, uint8(v))
				}
			}
		}
	}
	return uoms
}

// mergeUOMs appends the uom values in add that are not already in existing,
// preserving existing's order (first-seen keeps its position), so /admin/mups
// reports a stable, deduplicated list across repeated MirrorMeterReading
// POSTs of the same ReadingType instead of growing without bound.
func mergeUOMs(existing, add []uint8) []uint8 {
	seen := make(map[uint8]bool, len(existing))
	for _, u := range existing {
		seen[u] = true
	}
	out := existing
	for _, u := range add {
		if !seen[u] {
			seen[u] = true
			out = append(out, u)
		}
	}
	return out
}

// AdminMUP is one registered MirrorUsagePoint, surfaced read-only by GET
// /admin/mups. It is SERVER STATE, not a log entry — a restart wipes it
// honestly — and it exists because registration is a ONE-TIME event (the DUT
// registers once, at its first contact with this MirrorUsagePointList) while
// gridsim's request log is a bounded ring that a case window opening well
// after that one-time POST can find has already moved past (audit
// 2026-07-30, runs/perphase-basic029-v3-20260730T223730). This answers a
// different question than the log does: not "did the window see a POST" but
// "does a MirrorUsagePoint bearing this LFDI exist right now" — see
// suitecsip.critMUPRegistered (internal/certify/suitecsip/basic.go), which
// consults this endpoint as its second-strongest tier: after an in-window wire
// citation, before conceding the request log's ring gap.
type AdminMUP struct {
	Href         string  `json:"href"`
	LFDI         string  `json:"lfdi"`
	ReadingTypes []uint8 `json:"reading_types,omitempty"` // uom values, 2030.5 Table 11 (38 = W, real power)
	Readings     int     `json:"readings"`                // MirrorMeterReading POSTs accepted since registration
	CreatedAt    int64   `json:"created_at"`              // gridsim server time (Unix seconds) at POST /mup
	// Body is the registration POST's sep+xml verbatim, exactly as AdminDERPut
	// carries a DER self-report's. See mupRecord.Body for why a summary is not
	// enough.
	Body string `json:"body,omitempty"`
}

// ReceivedMUPs returns a copy of the durable MirrorUsagePoint records, in
// registration order (oldest first).
func (s *Server) ReceivedMUPs() []AdminMUP {
	s.mupMu.Lock()
	defer s.mupMu.Unlock()
	out := make([]AdminMUP, 0, len(s.mups))
	for _, m := range s.mups {
		out = append(out, AdminMUP{
			Href:         m.Href,
			LFDI:         m.LFDI,
			ReadingTypes: append([]uint8(nil), m.ReadingTypes...),
			Readings:     m.Readings,
			CreatedAt:    m.CreatedAt,
			Body:         m.Body,
		})
	}
	return out
}

// handleAdminMUPs serves GET /admin/mups — read-only, like every other admin
// observation surface. See AdminMUP.
func (s *Server) handleAdminMUPs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"mups":        s.ReceivedMUPs(),
		"server_time": s.Now(),
	})
}

// serveXML marshals resource to IEEE 2030.5 XML and writes it to w.
func (s *Server) serveXML(w http.ResponseWriter, resource interface{}) {
	// QA: if a malform mode is armed and matches this resource, serve the
	// deliberately non-conformant bytes instead of the well-formed marshal.
	//
	// The malform check runs against the STORED resource, ahead of the
	// wire-shape conversion below, so a malform mode still selects on the same
	// types it always has.
	data, malformed := s.malformedXML(resource)
	if !malformed {
		var err error
		// DERCurve and DERCurveList marshal through a standard-shaped local
		// type (curvexml.go), which emits IEEE 2030.5-2018's element set in the
		// standard's own sequence with every [1] element present, zeros
		// included.
		//
		// THE DEFECTS IT WAS BUILT AGAINST ARE FIXED UPSTREAM. This comment used
		// to read "the vendored struct drops three minOccurs=1 elements, orders
		// curveType before CurveData against the XSD's own sequence, and carries
		// two elements sep 2.0.4 does not declare" — and none of the three is
		// true of the pinned csipmodel any more (lexa-proto 9856710 and
		// 13e9106). The shape stays because the guarantee is worth having
		// LOCALLY: this is the one place that decides what a DERCurve looks like
		// on the wire, and a bench whose document validity depends on a
		// dependency's struct tags is one re-vendor away from serving invalid
		// evidence again. Everything else marshals exactly as it always did.
		out, _ := curveForWire(resource)
		data, err = xml.MarshalIndent(out, "", "  ")
		if err != nil {
			log.Printf("[gridsim] marshal error: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
	}
	// Explicit-nil overlay (QA, default off): a DERControlBase element the
	// operator armed as PRESENT AND NULL is spliced into the marshalled bytes
	// at its sequence position, because encoding/xml cannot express xsi:nil
	// from any struct. Applied to whatever the branches above produced —
	// malformed bytes included — since both are wire-layer overlays and the
	// marker is keyed by mRID, so a document carrying no armed control is
	// returned unchanged. See explicitnil.go.
	//
	// A failure here is NOT served. The overlay only fails when the document
	// would otherwise go out silently missing the marker the run is about, or
	// carrying one element twice; either makes a bundle that has to be
	// withdrawn, and a 500 makes the bench stop instead.
	if overlay := s.explicitNilOverlay(resource); len(overlay) > 0 {
		spliced, err := applyExplicitNil(data, overlay)
		if err != nil {
			log.Printf("[gridsim] %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		data = spliced
	}
	xmlDecl := []byte(`<?xml version="1.0" encoding="UTF-8"?>` + "\n")
	body := append(xmlDecl, data...)
	w.Header().Set("Content-Type", ContentType)
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(body)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

// buildResourceTree creates the full CSIP conformance test resource tree.
// This matches CORE-010 setup: 3 EndDevices, the client's device is last,
// with a full FSA → 3 DERPrograms → DERControl chain.
func (s *Server) buildResourceTree() {
	boolTrue := true
	now := time.Now().Unix()

	// ── DeviceCapability (/dcap) ──────────────────────────────
	s.resources["/dcap"] = &model.DeviceCapability{
		Resource: model.Resource{Href: "/dcap"},
		PollRate: 300,
		TimeLink: &model.Link{Href: "/tm"},
		EndDeviceListLink: &model.ListLink{
			Link: model.Link{Href: "/edev"},
			All:  3,
		},
		MirrorUsagePointListLink: &model.ListLink{
			Link: model.Link{Href: "/mup"},
			All:  0,
		},
		ResponseSetListLink: &model.ListLink{
			Link: model.Link{Href: "/rsps"},
			All:  1,
		},
		SelfDeviceLink: &model.Link{Href: "/sdev"},
	}

	// ── ResponseSetList (/rsps) ───────────────────────────────
	// One ResponseSet per program (CORE-022 / GEN.044). Clients POST
	// Response resources to /rsps/0/r to acknowledge event transitions.
	s.resources["/rsps"] = &model.ResponseSetList{
		Resource: model.Resource{Href: "/rsps"},
		All:      1,
		Results:  1,
		ResponseSet: []model.ResponseSet{
			{
				Resource: model.Resource{Href: "/rsps/0"},
				MRID:     "RSP-SP-001",
				ResponseList: &model.ListLink{
					Link: model.Link{Href: "/rsps/0/r"},
					All:  0,
				},
			},
		},
	}
	s.resources["/rsps/0"] = &model.ResponseSet{
		Resource: model.Resource{Href: "/rsps/0"},
		MRID:     "RSP-SP-001",
		ResponseList: &model.ListLink{
			Link: model.Link{Href: "/rsps/0/r"},
			All:  0,
		},
	}

	// ── Time (/tm) ────────────────────────────────────────────
	s.resources["/tm"] = &model.Time{
		Resource:    model.Resource{Href: "/tm"},
		CurrentTime: now,
		DstEndTime:  now - 86400,
		DstOffset:   3600,
		TzOffset:    -18000,
		Quality:     7,
		PollRate:    900,
	}

	// ── EndDeviceList (/edev) ─────────────────────────────────
	s.resources["/edev"] = &model.EndDeviceList{
		Resource: model.Resource{Href: "/edev"},
		All:      3,
		Results:  3,
		PollRate: 300,
		EndDevice: []model.EndDevice{
			{
				Resource:    model.Resource{Href: "/edev/0"},
				LFDI:        "0000000000000000000000000000000000000001",
				SFDI:        100000001,
				ChangedTime: now - 1000,
			},
			{
				Resource:    model.Resource{Href: "/edev/1"},
				LFDI:        "0000000000000000000000000000000000000002",
				SFDI:        100000002,
				ChangedTime: now - 500,
			},
			{
				Resource:         model.Resource{Href: "/edev/2"},
				LFDI:             s.ClientLFDI,
				SFDI:             123456789,
				ChangedTime:      now,
				Enabled:          &boolTrue,
				RegistrationLink: &model.Link{Href: "/edev/2/reg"},
				DERListLink: &model.ListLink{
					Link: model.Link{Href: "/edev/2/der"},
					All:  1,
				},
				FunctionSetAssignmentsListLink: &model.ListLink{
					Link: model.Link{Href: "/edev/2/fsa"},
					All:  1,
				},
				LogEventListLink: &model.ListLink{
					Link: model.Link{Href: "/edev/2/lev"},
					All:  0,
				},
			},
		},
	}

	// ── Registration (/edev/2/reg) ────────────────────────────
	s.resources["/edev/2/reg"] = &model.Registration{
		Resource:           model.Resource{Href: "/edev/2/reg"},
		DateTimeRegistered: now - 86400,
		PIN:                111115,
	}

	// ── DERList (/edev/2/der) ─────────────────────────────────
	s.resources["/edev/2/der"] = &model.DERList{
		Resource: model.Resource{Href: "/edev/2/der"},
		All:      1,
		Results:  1,
		DER: []model.DER{
			{
				Resource:            model.Resource{Href: "/edev/2/der/0"},
				DERCapabilityLink:   &model.Link{Href: "/edev/2/der/0/dercap"},
				DERSettingsLink:     &model.Link{Href: "/edev/2/der/0/derset"},
				DERStatusLink:       &model.Link{Href: "/edev/2/der/0/derstat"},
				DERAvailabilityLink: &model.Link{Href: "/edev/2/der/0/deravail"},
			},
		},
	}

	// ── DERCapability (/edev/2/der/0/dercap) ──────────────────
	s.resources["/edev/2/der/0/dercap"] = &model.DERCapability{
		Resource: model.Resource{Href: "/edev/2/der/0/dercap"},
		Type:     80, // PV (photovoltaic)
		RtgMaxW:  model.ActivePower{Multiplier: 0, Value: 10000},
	}

	// ── DERSettings (/edev/2/der/0/derset) ───────────────────
	s.resources["/edev/2/der/0/derset"] = &model.DERSettings{
		Resource:    model.Resource{Href: "/edev/2/der/0/derset"},
		SetMaxW:     &model.ActivePower{Multiplier: 0, Value: 10000},
		UpdatedTime: now,
	}

	// ── DERStatus (/edev/2/der/0/derstat) ────────────────────
	genConnected := uint8(1)
	opMode := uint8(1)
	s.resources["/edev/2/der/0/derstat"] = &model.DERStatus{
		Resource:              model.Resource{Href: "/edev/2/der/0/derstat"},
		GenConnectStatus:      &genConnected,
		OperationalModeStatus: &opMode,
		ReadingTime:           now,
	}

	// ── DERAvailability (/edev/2/der/0/deravail) ─────────────
	// Present so the walker discovers DERAvailabilityLink and so the DER*
	// report PUT half (WP-4) has a fourth target to write. GET serves this
	// baseline; a client PUT is stored/inspectable via GET /admin/derputs.
	availDur := uint32(3600)
	s.resources["/edev/2/der/0/deravail"] = &model.DERAvailability{
		Resource:             model.Resource{Href: "/edev/2/der/0/deravail"},
		ReadingTime:          now,
		AvailabilityDuration: &availDur,
	}

	// ── LogEventList (/edev/2/lev) ────────────────────────────
	// The EndDevice's LogEventListLink target (WP-6 / BASIC-027). A client
	// POSTs LogEvent resources here; GET returns the accumulated list.
	s.resources["/edev/2/lev"] = &model.LogEventList{
		Resource: model.Resource{Href: "/edev/2/lev"},
		All:      0,
		Results:  0,
		PollRate: 300,
	}

	// ── FunctionSetAssignmentsList (/edev/2/fsa) ──────────────
	s.resources["/edev/2/fsa"] = &model.FunctionSetAssignmentsList{
		Resource: model.Resource{Href: "/edev/2/fsa"},
		All:      1,
		Results:  1,
		PollRate: 300,
		FunctionSetAssignments: []model.FunctionSetAssignments{
			{
				Resource:    model.Resource{Href: "/edev/2/fsa/0"},
				MRID:        "FSA-SP-001",
				Description: "Service Point FSA",
				DERProgramListLink: &model.ListLink{
					Link: model.Link{Href: "/edev/2/fsa/0/derp"},
					All:  3,
				},
				TariffProfileListLink: &model.ListLink{
					Link: model.Link{Href: "/tp"},
					All:  1,
				},
				CustomerAccountListLink: &model.ListLink{
					Link: model.Link{Href: "/ca"},
					All:  1,
				},
				TimeLink: &model.Link{Href: "/tm"},
			},
		},
	}

	// ── DERProgramList (/edev/2/fsa/0/derp) ───────────────────
	// 3 programs with different primacy levels (lower = higher priority).
	s.resources["/edev/2/fsa/0/derp"] = &model.DERProgramList{
		Resource: model.Resource{Href: "/edev/2/fsa/0/derp"},
		All:      3,
		Results:  3,
		PollRate: 60,
		DERProgram: []model.DERProgram{
			{
				// Service Point program — highest priority.
				Resource:              model.Resource{Href: "/derp/0"},
				MRID:                  "DERP-SP-001",
				Description:           "Service Point DER Program",
				Primacy:               1,
				DefaultDERControlLink: &model.Link{Href: "/derp/0/dderc"},
				DERControlListLink: &model.ListLink{
					Link: model.Link{Href: "/derp/0/derc"},
					All:  4,
				},
				DERCurveListLink: &model.ListLink{
					Link: model.Link{Href: "/derp/0/dc"},
					All:  1,
				},
				ActiveDERControlListLink: &model.ListLink{
					Link: model.Link{Href: "/derp/0/actderc"},
					All:  1,
				},
			},
			{
				// Site-level program — middle priority.
				Resource:              model.Resource{Href: "/derp/1"},
				MRID:                  "DERP-SITE-001",
				Description:           "Site-Level DER Program",
				Primacy:               5,
				DefaultDERControlLink: &model.Link{Href: "/derp/1/dderc"},
				DERControlListLink: &model.ListLink{
					Link: model.Link{Href: "/derp/1/derc"},
					All:  2,
				},
				ActiveDERControlListLink: &model.ListLink{
					Link: model.Link{Href: "/derp/1/actderc"},
					All:  0,
				},
			},
			{
				// System-level program — lowest priority (utility-wide baseline).
				Resource:              model.Resource{Href: "/derp/2"},
				MRID:                  "DERP-SYS-001",
				Description:           "System-Level DER Program",
				Primacy:               10,
				DefaultDERControlLink: &model.Link{Href: "/derp/2/dderc"},
				DERControlListLink: &model.ListLink{
					Link: model.Link{Href: "/derp/2/derc"},
					All:  1,
				},
				ActiveDERControlListLink: &model.ListLink{
					Link: model.Link{Href: "/derp/2/actderc"},
					All:  0,
				},
			},
		},
	}

	s.buildProgram0(now)
	s.buildProgram1(now)
	s.buildProgram2(now)
	s.buildPricing(now)
	s.buildExtended(now)

	// ── MirrorUsagePointList (/mup) ───────────────────────────
	s.resources["/mup"] = &model.MirrorUsagePointList{
		Resource: model.Resource{Href: "/mup"},
		All:      0,
		Results:  0,
	}
}

// defaultConnectEnergizeAbsent records why none of the three built-in
// DefaultDERControls carries opModConnect or opModEnergize, and how a row that
// wants either one turns it on.
//
// # What they used to do, and what it cost
//
// All three shipped opModConnect=true AND opModEnergize=true, unconditionally.
// A DefaultDERControl is not an event: it is what the DER falls back to whenever
// no control is active, so those two elements were a CONTINUOUS STANDING COMMAND
// to connect and energize, underneath every row any bench ever ran. Two rows
// were confounded by it in two successive campaigns (Wave-I and Leg-B) and would
// have been again:
//
//	BENCH-000 row (j)     a DER pre-disconnected at the cabinet, which a gateway
//	                      holding no ownership record must LEAVE ALONE. It cannot
//	                      be left alone while the head end says "energize" on
//	                      every poll cycle.
//	BASIC-009's ES half   commands connect=false/energize=false and grades model
//	                      123 Conn and model 703 ES. With the default commanding
//	                      the opposite underneath, the row measured which of the
//	                      two won — not whether the DUT honoured the control.
//
// # ABSENT, not false
//
// An absent element and a false element are DIFFERENT DOCUMENTS to a 2030.5
// client, and the difference is the whole point. `false` is still a command — it
// says DISCONNECT — so a row that needs the axis merely NOT ENGAGED would get
// the opposite of what it asked for. Only absence leaves the axis unspoken and
// the DER holding whatever state the row put it in.
//
// The catalog's own procedure table agrees for connect: BASIC-009's Figure 9 row
// records "opmodConnect: Default (blank/not specified)" — blank, not false.
// (It prints "Default true" for opModEnergize, which is a statement about the
// PROCEDURE's starting conditions, not about what a fixture must serve
// unprompted; a row that wants that shape now asks for it and gets it recorded
// in its own request.)
//
// # The lever
//
// POST /admin/default's `base` is the same adminCtrlReq POST /admin/control
// takes, and it has carried `connect` and `energize` all along (buildBase). So
// engaging either axis is one admin call and needs no new surface:
//
//	POST /admin/default
//	{"program":0,"base":{"connect":true,"energize":true,"exp_lim_W":5000}}
//
// RESTATE exp_lim_W as shown. A POST REPLACES THE WHOLE BASE
// (putDefaultBaseLocked), so a body naming only connect would silently drop the
// export cap that several mayhem scenarios reason about by name.
//
// The fleet's own program nodes (fleet.go fleetProgramLocked) have always built
// their defaults with neither element, so this change makes programs 0-2 agree
// with the fleet rather than diverge from it.

// buildProgram0 builds the Service Point program (primacy=1) with a rich
// set of DERControls that exercise overlapping/superseded, cancelled,
// randomized, and actively-executing scenarios.
func (s *Server) buildProgram0(now int64) {
	ptrue := true

	// ── DefaultDERControl (/derp/0/dderc) ─────────────────────
	//
	// THE CONNECT AND ENERGIZE AXES ARE DELIBERATELY ABSENT — see
	// defaultConnectEnergizeAbsent below for why, and for the lever that
	// engages them when a row wants them.
	s.resources["/derp/0/dderc"] = &model.DefaultDERControl{
		Resource:    model.Resource{Href: "/derp/0/dderc"},
		MRID:        "DDERC-SP-001",
		Description: "Default: export limit 5kW",
		DERControlBase: model.DERControlBase{
			OpModExpLimW: &model.ActivePower{Multiplier: 0, Value: 5000},
		},
	}

	// ── DERControlList (/derp/0/derc) ─────────────────────────
	// Four controls demonstrating the full range of event states:
	//   SP-001 — scheduled, potentiallySuperseded by SP-002 (same interval, newer)
	//   SP-002 — scheduled, supersedes SP-001 (same start, longer duration, newer creationTime)
	//   SP-003 — cancelled (currentStatus=2, IEEE Std 2030.5-2018 Annex B,
	//            p.159-160 — REV0907-B1: NOT 6, which is Table 27's Response
	//            status for "event cancelled", a different enumeration); client
	//            must drop it
	//   SP-004 — scheduled future, randomizeStart=30s for device staggering
	eventStart := now + 180 // 3 minutes from now

	s.resources["/derp/0/derc"] = &model.DERControlList{
		Resource: model.Resource{Href: "/derp/0/derc"},
		All:      4,
		Results:  4,
		PollRate: 60,
		DERControl: []model.DERControl{
			{
				// SP-001: superseded by SP-002.
				Resource:     model.Resource{Href: "/derp/0/derc/0"},
				MRID:         "DERC-SP-001",
				Description:  "Limit export to 3kW (potentially superseded)",
				CreationTime: now,
				EventStatus: &model.EventStatus{
					CurrentStatus:         0, // Scheduled
					DateTime:              now,
					PotentiallySuperseded: true,
				},
				Interval: model.DateTimeInterval{
					Duration: 120,
					Start:    eventStart,
				},
				DERControlBase: model.DERControlBase{
					OpModExpLimW: &model.ActivePower{Multiplier: 0, Value: 3000},
				},
			},
			{
				// SP-002: supersedes SP-001 (same start, later creationTime).
				Resource:     model.Resource{Href: "/derp/0/derc/1"},
				MRID:         "DERC-SP-002",
				Description:  "Limit export to 2.5kW (supersedes SP-001)",
				CreationTime: now + 1,
				EventStatus: &model.EventStatus{
					CurrentStatus:         0, // Scheduled
					DateTime:              now + 1,
					PotentiallySuperseded: false,
				},
				Interval: model.DateTimeInterval{
					Duration: 300, // longer — will outlast SP-001's window
					Start:    eventStart,
				},
				DERControlBase: model.DERControlBase{
					OpModExpLimW: &model.ActivePower{Multiplier: 0, Value: 2500},
				},
			},
			{
				// SP-003: cancelled — client must skip it.
				Resource:     model.Resource{Href: "/derp/0/derc/2"},
				MRID:         "DERC-SP-003",
				Description:  "Cancelled control (client must ignore)",
				CreationTime: now - 600,
				EventStatus: &model.EventStatus{
					CurrentStatus:         model.EventStatusCancelled, // 2 — REV0907-B1: not 6
					DateTime:              now - 60,
					PotentiallySuperseded: false,
				},
				Interval: model.DateTimeInterval{
					Duration: 120,
					Start:    now - 600,
				},
				DERControlBase: model.DERControlBase{
					OpModExpLimW: &model.ActivePower{Multiplier: 0, Value: 4000},
				},
			},
			{
				// SP-004: future control with randomizeStart for device staggering.
				Resource:     model.Resource{Href: "/derp/0/derc/3"},
				MRID:         "DERC-SP-004",
				Description:  "Randomized export limit 3.5kW",
				CreationTime: now,
				EventStatus: &model.EventStatus{
					CurrentStatus:         0, // Scheduled
					DateTime:              now,
					PotentiallySuperseded: false,
				},
				Interval: model.DateTimeInterval{
					Duration: 180,
					Start:    now + 600,
				},
				RandomizeStart: int32Ptr(30),
				DERControlBase: model.DERControlBase{
					OpModExpLimW: &model.ActivePower{Multiplier: 0, Value: 3500},
					OpModConnect: &ptrue,
				},
			},
		},
	}

	// ── ActiveDERControlList (/derp/0/actderc) ────────────────
	// One control currently executing (started 60s ago, 600s total).
	s.resources["/derp/0/actderc"] = &model.DERControlList{
		Resource: model.Resource{Href: "/derp/0/actderc"},
		All:      1,
		Results:  1,
		PollRate: 60,
		DERControl: []model.DERControl{
			{
				Resource:     model.Resource{Href: "/derp/0/actderc/0"},
				MRID:         "DERC-SP-000",
				Description:  "Currently active: export limit 2kW",
				CreationTime: now - 300,
				EventStatus: &model.EventStatus{
					CurrentStatus:         1, // Active
					DateTime:              now - 60,
					PotentiallySuperseded: false,
				},
				Interval: model.DateTimeInterval{
					Duration: 600,
					Start:    now - 60,
				},
				DERControlBase: model.DERControlBase{
					OpModExpLimW: &model.ActivePower{Multiplier: 0, Value: 2000},
				},
			},
		},
	}
}

// buildProgram1 builds the Site-Level program (primacy=5).
func (s *Server) buildProgram1(now int64) {
	// Connect/energize absent — see defaultConnectEnergizeAbsent.
	s.resources["/derp/1/dderc"] = &model.DefaultDERControl{
		Resource:    model.Resource{Href: "/derp/1/dderc"},
		MRID:        "DDERC-SITE-001",
		Description: "Site default: export limit 7kW",
		DERControlBase: model.DERControlBase{
			OpModExpLimW: &model.ActivePower{Multiplier: 0, Value: 7000},
		},
	}

	// Two non-overlapping scheduled controls.
	s.resources["/derp/1/derc"] = &model.DERControlList{
		Resource: model.Resource{Href: "/derp/1/derc"},
		All:      2,
		Results:  2,
		PollRate: 120,
		DERControl: []model.DERControl{
			{
				Resource:     model.Resource{Href: "/derp/1/derc/0"},
				MRID:         "DERC-SITE-001",
				Description:  "Site: limit to 6kW (morning peak)",
				CreationTime: now,
				EventStatus: &model.EventStatus{
					CurrentStatus:         0,
					DateTime:              now,
					PotentiallySuperseded: false,
				},
				Interval: model.DateTimeInterval{
					Duration: 3600,
					Start:    now + 3600,
				},
				DERControlBase: model.DERControlBase{
					OpModExpLimW: &model.ActivePower{Multiplier: 0, Value: 6000},
				},
			},
			{
				Resource:     model.Resource{Href: "/derp/1/derc/1"},
				MRID:         "DERC-SITE-002",
				Description:  "Site: limit to 5kW (afternoon peak)",
				CreationTime: now,
				EventStatus: &model.EventStatus{
					CurrentStatus:         0,
					DateTime:              now,
					PotentiallySuperseded: false,
				},
				Interval: model.DateTimeInterval{
					Duration: 7200,
					Start:    now + 7200,
				},
				DERControlBase: model.DERControlBase{
					OpModExpLimW: &model.ActivePower{Multiplier: 0, Value: 5000},
				},
			},
		},
	}

	s.resources["/derp/1/actderc"] = &model.DERControlList{
		Resource: model.Resource{Href: "/derp/1/actderc"},
		All:      0,
		Results:  0,
	}
}

// buildProgram2 builds the System-Level program (primacy=10, lowest priority).
func (s *Server) buildProgram2(now int64) {
	// Connect/energize absent — see defaultConnectEnergizeAbsent.
	s.resources["/derp/2/dderc"] = &model.DefaultDERControl{
		Resource:    model.Resource{Href: "/derp/2/dderc"},
		MRID:        "DDERC-SYS-001",
		Description: "System default: export limit 9kW (utility-wide baseline)",
		DERControlBase: model.DERControlBase{
			OpModExpLimW: &model.ActivePower{Multiplier: 0, Value: 9000},
		},
	}

	s.resources["/derp/2/derc"] = &model.DERControlList{
		Resource: model.Resource{Href: "/derp/2/derc"},
		All:      1,
		Results:  1,
		PollRate: 300,
		DERControl: []model.DERControl{
			{
				Resource:     model.Resource{Href: "/derp/2/derc/0"},
				MRID:         "DERC-SYS-001",
				Description:  "System: utility-wide curtailment 8kW",
				CreationTime: now,
				EventStatus: &model.EventStatus{
					CurrentStatus:         0,
					DateTime:              now,
					PotentiallySuperseded: false,
				},
				Interval: model.DateTimeInterval{
					Duration: 14400,
					Start:    now + 1800,
				},
				DERControlBase: model.DERControlBase{
					OpModExpLimW: &model.ActivePower{Multiplier: 0, Value: 8000},
				},
			},
		},
	}

	s.resources["/derp/2/actderc"] = &model.DERControlList{
		Resource: model.Resource{Href: "/derp/2/actderc"},
		All:      0,
		Results:  0,
	}
}

// handleResponsePost handles POST /rsps/{n}/r — client acknowledging an event.
// Per GEN.044 / CORE-022: client POSTs a Response resource with status
// 1=Received, 2=Started, or 3=Completed. Returns 201 Created.
func (s *Server) handleResponsePost(w http.ResponseWriter, r *http.Request, path string) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	var resp model.Response
	if err := xml.Unmarshal(body, &resp); err != nil {
		log.Printf("[gridsim] POST %s: unmarshal Response error: %v", path, err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	// WP-7 (D5): accept BOTH the legacy LEXA 0xF0 extension AND the IEEE 2030.5
	// Table 27 CannotComply-family codes the hub now sends by default, and
	// record which vocabulary AND which SD-02 class arrived so a test can
	// assert the flip and the corrected taxonomy.
	alert, vocab, class := classifyResponseStatus(resp.Status)
	s.responseMu.Lock()
	s.responses = append(s.responses, resp)
	if alert {
		s.complianceAlerts = append(s.complianceAlerts, ComplianceAlert{
			Subject:    resp.Subject,
			Status:     resp.Status,
			Vocab:      vocab,
			Class:      class,
			LFDI:       resp.EndDeviceLFDI,
			ReceivedAt: s.Now(),
		})
	}
	s.responseMu.Unlock()
	if alert {
		log.Printf("[gridsim] ALERT: client reports status=%d (vocab=%s class=%s) for subject=%s",
			resp.Status, vocab, class, resp.Subject)
	} else {
		log.Printf("[gridsim] POST %s → Response accepted: subject=%s status=%d",
			path, resp.Subject, resp.Status)
	}
	w.WriteHeader(http.StatusCreated)
}

// CannotComply wire vocabularies (WP-7, D5). Recorded on each ComplianceAlert
// so tests can assert the hub's default code-flip from the LEXA extension to
// the IEEE 2030.5 Table 27 codes.
const (
	VocabLegacy  = "legacy"  // the LEXA extension, wire value 0xF0 exactly (F10 — no manufacturer range)
	VocabTable27 = "table27" // IEEE 2030.5 Table 27 standard status codes
)

// SD-02 (docs/design/SD02_RESPONSE_SEMANTICS_RC0_2026-08-17.md, lexa-gw) Class
// values: the taxonomy classifyResponseStatus assigns WITHIN VocabTable27, so
// a caller that cares WHICH KIND of Table 27 signal arrived — a lifecycle
// opt-out/opt-in acknowledgement, an EffectiveEndTime-only partial, or a
// receipt-time rejection — does not have to re-derive it from the raw status
// a second time. Empty for a legacy-vocab (0xF0) alert and for a non-alert
// plain lifecycle status (1/2/3/6/7).
const (
	ClassOptOut            = "opt-out"              // 4  — preference-driven opt-out; may precede EffectiveStartTime
	ClassOptIn             = "opt-in"               // 5  — preference-driven opt-in / recovery
	ClassEndOfEventPartial = "end-of-event-partial" // 8/10 — EffectiveEndTime-only
	ClassReceiptRejection  = "receipt-rejection"    // 252/253/254 — sent at receipt
)

// classifyResponseStatus reports whether a Response status is one gridsim's
// GET /admin/alerts should surface, under which wire vocabulary, and (within
// VocabTable27) which SD-02 class.
//
// Before WP-7 the hub reported "cannot comply" exclusively via the LEXA 0xF0
// extension; WP-7 flipped the default to IEEE 2030.5 Table 27. Until SD-02
// corrected it, BOTH this classifier and the product read Table 27's own
// EffectiveEndTime-only partial (8, and 10 alongside it) as the onset
// "cannot comply" signal, and neither recognised 4/5 at all — lexa-proto's
// csipmodel constants for those two were themselves transposed at the time,
// so nothing in this codebase ever exercised them. SD-02
// (docs/design/SD02_RESPONSE_SEMANTICS_RC0_2026-08-17.md, lexa-gw)
// established, from the licensed IEEE 2030.5-2018 text (Table 27, p.74-76),
// the taxonomy this function now applies:
//
//	4/5   (OptOut/OptIn)                — lifecycle acknowledgements of a
//	                                       preference-driven opt-out/opt-in;
//	                                       send-time "at time user actively
//	                                       chose … or when device
//	                                       automatically opts out/in due to
//	                                       user preference", which MAY
//	                                       precede EffectiveStartTime.
//	8/10  (PartialOptOut/NoParticipation) — EffectiveEndTime-ONLY partials for
//	                                       an ADMITTED, (partially) executed
//	                                       event. Never onset, never receipt.
//	252/253/254                         — receipt-time rejections.
//
// All three classes are recognised as alerts: gridsim's /admin/alerts exists
// to surface anything beyond a plain lifecycle acknowledgement an operator
// would want visibility into, and a preference-driven opt-out is exactly that
// under the corrected reading — the hub admitting a curtailment is no less
// operator-relevant for arriving via Table 27's own lifecycle-ack vocabulary
// (4) instead of the former non-conformant onset-8 shape. A caller built
// against the PRE-SD-02 reading — alert only on 8/10/252/253/254, nothing on
// 4/5 — would silently stop observing a corrected product's opt-out
// admissions and misreport them as silent non-compliance; this is exactly the
// "your own suites go red for the wrong reason" failure SD-02 warns about, so
// every caller of this function (dashboards included) must key on Class, not
// on the pre-SD-02 assumption that 8 is the onset signal.
//
// The normal PLAIN lifecycle acks (1 received / 2 started / 3 completed) and
// the server-driven event-lifecycle acks (6 cancelled / 7 superseded) are NOT
// alerts — they are recorded in ReceivedResponses like every other Response,
// but they do not raise a compliance alert. (In this codebase the hub emits 3
// at a *clean* end-of-event, so treating 3 as an alert would fire on every
// normal completion.)
func classifyResponseStatus(status uint8) (alert bool, vocab, class string) {
	// Table 27 codes are checked FIRST: the rejection codes 252/253/254 fall
	// numerically inside Table 27's own RESERVED range (15-251 and 255 — the
	// standard defines no manufacturer range at all, F10) but are standard
	// IEEE codes of their own, so they must resolve to table27, not legacy.
	switch status {
	case model.ResponseOptOut: // 4
		return true, VocabTable27, ClassOptOut
	case model.ResponseOptIn: // 5
		return true, VocabTable27, ClassOptIn
	case model.ResponsePartialOptOut, // 8  — EffectiveEndTime-only partial
		model.ResponseNoParticipation: // 10 — EffectiveEndTime-only partial
		return true, VocabTable27, ClassEndOfEventPartial
	case model.ResponseRejectedParam, // 252 — rejected (param not applicable)
		model.ResponseRejectedInvalid, // 253 — receipt reject (invalid content)
		model.ResponseRejectedExpired: // 254 — rejected (already expired)
		return true, VocabTable27, ClassReceiptRejection
	}
	if status == alertStatusFloor { // 0xF0 EXACTLY — the only value the LEXA extension ever used (F10)
		return true, VocabLegacy, ""
	}
	// 0xF1-0xFB and 0xFF: Table 27's own RESERVED range (15-251, 255) that
	// this product has never assigned any meaning to — NOT the legacy
	// extension (which only ever spoke 0xF0) and not a standard code either.
	// Before F10 this fell through the `>=` range check below and was
	// misclassified as legacy; an unassigned reserved value is unclassified,
	// not silently absorbed into the one wire mode this product actually
	// speaks.
	return false, "", ""
}

// alertStatusFloor is the Response status the LEXA legacy CannotComply
// extension uses (see model.ResponseCannotComply). Despite the name, this is
// now an EXACT match, not a floor of a range: F10 tightened
// classifyResponseStatus from "status >= alertStatusFloor" (which
// misclassified the WHOLE 0xF0–0xFF span, including Table 27's own reserved
// values 0xF1-0xFB/0xFF that this product has never used, as the legacy
// extension) to "status == alertStatusFloor", since 0xF0 is the only value
// the extension has ever spoken. classifyResponseStatus additionally
// recognises the SD-02-corrected Table 27 codes (4/5/8/10/252/253/254) as
// alerts, entirely independently of this constant.
const alertStatusFloor uint8 = 0xF0

// ComplianceAlert is a Response recorded with the server receive time,
// returned by GET /admin/alerts, that classifyResponseStatus judged worth an
// operator's attention (beyond a plain lifecycle acknowledgement).
type ComplianceAlert struct {
	Subject    string `json:"subject"`     // DERControl mRID the alert is about
	Status     uint8  `json:"status"`      // 2030.5 Response status (the raw wire code)
	Vocab      string `json:"vocab"`       // "legacy" (0xF0) or "table27" (WP-7 default)
	Class      string `json:"class"`       // SD-02 class within table27: opt-out/opt-in/end-of-event-partial/receipt-rejection; empty for legacy
	LFDI       string `json:"lfdi"`        // responding device
	ReceivedAt int64  `json:"received_at"` // gridsim server time (Unix seconds)
}

// ComplianceAlerts returns a copy of all CannotComply alerts received.
func (s *Server) ComplianceAlerts() []ComplianceAlert {
	s.responseMu.Lock()
	defer s.responseMu.Unlock()
	out := make([]ComplianceAlert, len(s.complianceAlerts))
	copy(out, s.complianceAlerts)
	return out
}

// ReceivedResponses returns a copy of all Response resources POSTed by
// clients. Useful for verifying CORE-022 / GEN.044 compliance in tests.
func (s *Server) ReceivedResponses() []model.Response {
	s.responseMu.Lock()
	defer s.responseMu.Unlock()
	out := make([]model.Response, len(s.responses))
	copy(out, s.responses)
	return out
}

// AddResource lets you inject or override resources in the tree,
// useful for testing different scenarios. Safe to call while the server is
// serving — the write is guarded by the same mutex the request handlers use
// (audit finding Q-2).
func (s *Server) AddResource(path string, resource interface{}) {
	s.mu.Lock()
	s.resources[path] = resource
	s.mu.Unlock()
}

func int32Ptr(v int32) *int32 { return &v }
