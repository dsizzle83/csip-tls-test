package gridsim

// subscribe.go — the IEEE 2030.5 Subscription/Notification function set
// (default OFF).
//
// # What it is for
//
// Fourteen of the twenty-two rows the DER AGGREGATOR CLIENT re-scope pulled in
// turn on subscription and notification: AGG-001, CORE-018, CORE-019, ERR-002,
// MAINT-001/003/004/005 and UTIL-003 all begin by having the client subscribe
// to a resource and end with the server pushing a Notification when it changes.
// Until this file existed, sim/gridsim served no SubscriptionListLink and
// originated no Notification, so every one of those criteria could only report
// SKIP naming the gap.
//
// # The subset implemented, and why exactly this much
//
// The conformance suite probes four things, and they are what the subset is
// built around (internal/certify/suitecsip/criteria_agg.go):
//
//	critSubscriptionAdvertised — the DUT's EndDevice carries a
//	    SubscriptionListLink and the FunctionSetAssignmentsList beneath it is
//	    subscribable="1" (unconditional subscription).
//	critSubscriptionPosted     — the DUT POSTs a Subscription whose
//	    <subscribedResource> names the resource the row demands, and the server
//	    answers 201 Created WITH a Location header. All three are asserted, and
//	    once the server advertises the function set a missing POST is a real
//	    FAIL rather than a bench gap — see
//	    TestSubscriptionPostedDistinguishesBenchGapFromDUTFault.
//
// On top of those two the CTP procedures need the other half of the lifecycle,
// so this file also implements GET of the list and of one subscription, DELETE
// of one subscription, and the server-originated Notification POST on change.
//
// What is deliberately NOT implemented: conditional subscriptions (Condition /
// level 3 — the CTP setups all say "an attribute that can be subscribed to",
// i.e. unconditional), Notification status values other than 0 (default) and 1
// (subscription cancelled), and the Notification's own retry/backoff policy.
// Each is named here rather than left as an unexplained absence.
//
// # Delivery, and the one thing this simulator cannot do
//
// A Notification travels on a connection the SERVER dials, and IEEE 2030.5
// requires that connection to be the same mTLS profile as the client's. gridsim
// is pure Go by design — its unit tests run with no wolfSSL sysroot — and Go's
// crypto/tls does not implement the CSIP-mandatory
// ECDHE-ECDSA-AES128-CCM-8 suite, so this package CANNOT dial a conformant
// notification connection itself.
//
// So it does not pretend to. Delivery goes through the Notifier seam, exactly
// as the certificate-chain lever goes through ChainSwapper (chain.go): the
// built-in notifier speaks plain HTTP, which is what a bench listener on the
// same wire can accept, and an embedding binary that has a wolfSSL client can
// install one that speaks mTLS. An https:// notificationURI with no such
// notifier installed is REFUSED and the refusal is recorded verbatim in the
// notification log, because a silently-dropped Notification would read on the
// other end as a DUT that never answered one.

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	model "lexa-proto/csipmodel"
)

// notifyTimeout bounds one Notification POST. Dispatch is SYNCHRONOUS with the
// mutation that caused it (see notifyChanged), so this is also the worst case a
// POST /admin/control pays per matching subscription.
const notifyTimeout = 5 * time.Second

// ── wire types ───────────────────────────────────────────────────────────────

// sepSubscription is the 2030.5 Subscription resource, in gridsim's own
// declaration for the same reason fleetEndDevice is: lexa-proto/csipmodel is
// version-pinned in lockstep with the product repo and carries no Subscription
// type, and this is a bench-fixture concern.
type sepSubscription struct {
	XMLName xml.Name `xml:"urn:ieee:std:2030.5:ns Subscription"`

	Href string `xml:"href,attr,omitempty"`

	SubscribedResource string `xml:"subscribedResource"`
	Encoding           uint8  `xml:"encoding,omitempty"`
	Level              string `xml:"level,omitempty"`
	Limit              uint32 `xml:"limit,omitempty"`
	NotificationURI    string `xml:"notificationURI"`
}

// sepSubscriptionList is the list served at an EndDevice's SubscriptionListLink.
type sepSubscriptionList struct {
	XMLName xml.Name `xml:"urn:ieee:std:2030.5:ns SubscriptionList"`

	Href     string `xml:"href,attr,omitempty"`
	All      uint32 `xml:"all,attr"`
	Results  uint32 `xml:"results,attr"`
	PollRate uint32 `xml:"pollRate,attr,omitempty"`

	Subscription []sepSubscription `xml:"Subscription"`
}

// Notification status values this simulator originates.
const (
	// NotifyDefault is status 0, "Default Status".
	NotifyDefault uint8 = 0
	// NotifyCancelled is status 1, "Subscription canceled, no additional
	// information" — what ERR-002 and CORE-019 have the server send.
	NotifyCancelled uint8 = 1
)

// sepNotification is the resource the server POSTs to a notificationURI.
//
// The payload element is <Resource xsi:type="…">, which is how IEEE Std
// 2030.5-2018 carries a polymorphic subscribed resource — §4.7's resource
// design rules (p.24) require the xsi:type on a list's subordinate resources,
// and the Annex C Notification example (p.278) shows this exact shape. Its children are written verbatim from the
// marshalled resource (see newNotification): re-encoding them through a typed
// field would mean teaching this file about every resource that can be
// subscribed to.
type sepNotification struct {
	XMLName xml.Name `xml:"urn:ieee:std:2030.5:ns Notification"`

	Href               string `xml:"href,attr,omitempty"`
	SubscribedResource string `xml:"subscribedResource,attr"`

	Status          uint8           `xml:"status"`
	SubscriptionURI string          `xml:"subscriptionURI"`
	Resource        *notifyResource `xml:"Resource,omitempty"`
}

// notifyResource is the Notification's payload wrapper.
type notifyResource struct {
	XMLName xml.Name `xml:"Resource"`
	XSINS   string   `xml:"xmlns:xsi,attr"`
	XSIType string   `xml:"xsi:type,attr"`
	Href    string   `xml:"href,attr,omitempty"`
	Inner   []byte   `xml:",innerxml"`
}

// ── store ────────────────────────────────────────────────────────────────────

// Subscription is one live subscription, as GET /admin/subscriptions reports it.
type Subscription struct {
	ID                 int    `json:"id"`
	Href               string `json:"href"`       // /edev/2/sub/0
	EndDevice          string `json:"end_device"` // /edev/2
	SubscribedResource string `json:"subscribed_resource"`
	NotificationURI    string `json:"notification_uri"`
	Limit              uint32 `json:"limit,omitempty"`
	CreatedAt          int64  `json:"created_at"`
	// Notifications counts the Notifications gridsim has POSTed on this
	// subscription, so a check can tell "the server never pushed" from "the
	// server pushed and the DUT never answered".
	Notifications int `json:"notifications"`
}

// NotificationRecord is one Notification POST attempt, kept so the bench can
// prove what it sent and what came back.
type NotificationRecord struct {
	At                 int64  `json:"at"`
	SubscriptionHref   string `json:"subscription_href"`
	SubscribedResource string `json:"subscribed_resource"`
	NotificationURI    string `json:"notification_uri"`
	Status             uint8  `json:"notification_status"` // the 2030.5 <status> sent
	// HTTPStatus is what the client answered — 201 Created is what CORE-018 and
	// CORE-019 require (Annex A seq 44 removes 204 for those two rows), and 0
	// means the POST never got an answer at all.
	HTTPStatus int    `json:"http_status"`
	Bytes      int    `json:"bytes"`
	Error      string `json:"error,omitempty"`
}

// subState holds every subscription and the notification log. Its mutex is
// LOWER in the lock order than Server.mu: notifyChanged takes this one, then
// takes s.mu to read the changed resource. Nothing may take it while holding
// s.mu, which is why the SubscriptionList resources are generated at GET time
// rather than stored in s.resources.
type subState struct {
	mu     sync.Mutex
	next   int
	subs   []*Subscription
	log    []NotificationRecord
	notify Notifier
}

// Notifier delivers one Notification to a client's notificationURI.
//
// The seam exists because gridsim is pure Go and the CSIP-mandatory cipher is
// not in crypto/tls — see the file comment. An implementation returns the HTTP
// status the client answered.
type Notifier interface {
	Notify(ctx context.Context, uri string, body []byte) (status int, err error)
}

// SetNotifier installs the transport Notifications are delivered over,
// replacing the built-in plain-HTTP one. Call it before serving.
func (s *Server) SetNotifier(n Notifier) {
	s.mu.Lock()
	st := s.subs
	s.mu.Unlock()
	if st == nil {
		return
	}
	st.mu.Lock()
	st.notify = n
	st.mu.Unlock()
}

// EnableSubscriptions turns on the Subscription/Notification function set: the
// EndDevices gridsim serves start advertising a SubscriptionListLink, the
// FunctionSetAssignmentsList becomes subscribable="1", and a change to a
// subscribed resource is pushed to the subscriber's notificationURI.
//
// Off by default, and the default tree is byte-identical without it.
func (s *Server) EnableSubscriptions() {
	s.mu.Lock()
	if s.subs == nil {
		s.subs = &subState{notify: httpNotifier{}}
	}
	s.rebuildEndDeviceListLocked()
	s.applySubscribableLocked()
	s.mu.Unlock()
	log.Printf("[gridsim] Subscription/Notification function set ENABLED " +
		"(SubscriptionListLink advertised, subscribable=1, Notifications pushed on change)")
}

// SubscriptionsEnabled reports whether the function set is being served.
func (s *Server) SubscriptionsEnabled() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.subs != nil
}

// Subscriptions returns a copy of the live subscriptions.
func (s *Server) Subscriptions() []Subscription {
	st := s.subStore()
	if st == nil {
		return nil
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	out := make([]Subscription, 0, len(st.subs))
	for _, sub := range st.subs {
		out = append(out, *sub)
	}
	return out
}

// SentNotifications returns a copy of the notification log.
func (s *Server) SentNotifications() []NotificationRecord {
	st := s.subStore()
	if st == nil {
		return nil
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	return append([]NotificationRecord(nil), st.log...)
}

func (s *Server) subStore() *subState {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.subs
}

// ── advertisement ────────────────────────────────────────────────────────────

// rebuildSubscribableEndDeviceListLocked serves the DEFAULT three-EndDevice
// tree widened with the SubscriptionListLink the function set needs.
//
// It exists because CORE-018, CORE-019 and ERR-002 are about the DUT's own
// EndDevice and do not need the Figure-15 fleet: subscription without the fleet
// has to be a usable configuration, or those three rows would be gated on a
// fixture they never mention. The shape below is the same three entries
// rebuildEndDeviceListLocked builds — the two dummy devices that exist to be
// 403'd, and the DUT's — with the link added.
func (s *Server) rebuildSubscribableEndDeviceListLocked() {
	boolTrue := true
	now := time.Now().Unix()
	sfdi := s.clientSFDI
	if sfdi == 0 {
		sfdi = 123456789 // the built-in value the default tree serves pre-handshake
	}
	s.resources["/edev"] = &fleetEndDeviceList{
		Href: "/edev", All: 3, Results: 3, PollRate: 300, Subscribable: 1,
		EndDevice: []fleetEndDevice{
			{
				Href: "/edev/0", LFDI: "0000000000000000000000000000000000000001",
				SFDI: 100000001, ChangedTime: now - 1000,
			},
			{
				Href: "/edev/1", LFDI: "0000000000000000000000000000000000000002",
				SFDI: 100000002, ChangedTime: now - 500,
			},
			{
				Href: "/edev/2", LFDI: s.ClientLFDI, SFDI: sfdi, ChangedTime: now,
				Subscribable:     1,
				Enabled:          &boolTrue,
				RegistrationLink: &model.Link{Href: "/edev/2/reg"},
				DERListLink: &model.ListLink{
					Link: model.Link{Href: "/edev/2/der"}, All: 1,
				},
				FunctionSetAssignmentsListLink: &model.ListLink{
					Link: model.Link{Href: "/edev/2/fsa"}, All: 1,
				},
				LogEventListLink: &model.ListLink{
					Link: model.Link{Href: "/edev/2/lev"}, All: 0,
				},
				SubscriptionListLink: &model.ListLink{Link: model.Link{Href: "/edev/2/sub"}},
			},
		},
	}
}

// applySubscribableLocked marks the DUT's own FunctionSetAssignmentsList
// subscribable="1".
//
// That attribute is a pass criterion, not decoration: critSubscriptionAdvertised
// requires "the FunctionSetAssignmentsList beneath it with subscribable=1
// (unconditional subscription)" and reports SKIP for subscribable=0, because
// what the server advertises is the bench's job. The shared
// model.FunctionSetAssignmentsList carries no field for the attribute (it is a
// version-pinned lexa-proto type), so the list is widened into gridsim's own
// fleetFSAList here.
//
// The DERControlLists are NOT widened, and the omission is deliberate rather
// than forgotten: model.DERControlList has no subscribable field either, but
// unlike the FSAList nothing asserts one, and re-typing the list the whole
// admin control path writes to would buy an attribute no criterion reads.
// gridsim accepts a Subscription against those hrefs regardless — a
// subscribedResource is just an href.
func (s *Server) applySubscribableLocked() {
	if fsa, ok := s.resources["/edev/2/fsa"].(*model.FunctionSetAssignmentsList); ok {
		wide := &fleetFSAList{
			Href: fsa.Href, All: fsa.All, Results: fsa.Results, PollRate: fsa.PollRate,
			Subscribable:           1,
			FunctionSetAssignments: append([]model.FunctionSetAssignments(nil), fsa.FunctionSetAssignments...),
		}
		for i := range wide.FunctionSetAssignments {
			wide.FunctionSetAssignments[i].Subscribable = 1
		}
		s.resources["/edev/2/fsa"] = wide
	}
	if pl, ok := s.resources["/edev/2/fsa/0/derp"].(*model.DERProgramList); ok {
		for i := range pl.DERProgram {
			pl.DERProgram[i].Subscribable = 1
		}
	}
}

// ── routing ──────────────────────────────────────────────────────────────────

// subPath splits a request path into the EndDevice href and the subscription id
// it addresses: ("/edev/2", -1) for the list, ("/edev/2", 3) for one
// subscription, ("", -1) for anything else.
func subPath(path string) (edev string, id int) {
	i := strings.Index(path, "/sub")
	if i < 0 || !strings.HasPrefix(path, "/edev/") {
		return "", -1
	}
	edev, rest := path[:i], path[i+len("/sub"):]
	switch {
	case rest == "":
		return edev, -1
	case strings.HasPrefix(rest, "/"):
		n, err := strconv.Atoi(rest[1:])
		if err != nil {
			return "", -1
		}
		return edev, n
	default:
		return "", -1
	}
}

// handleSubscriptionRequest serves the Subscription function set. It returns
// false when the path is not one of its own, so the ordinary resource lookup
// still runs.
func (s *Server) handleSubscriptionRequest(w http.ResponseWriter, r *http.Request, path string) bool {
	st := s.subStore()
	if st == nil {
		return false
	}
	edev, id := subPath(path)
	if edev == "" {
		return false
	}
	if !s.hasEndDevice(edev) {
		w.WriteHeader(http.StatusNotFound)
		return true
	}

	switch {
	case r.Method == http.MethodGet && id < 0:
		s.serveXML(w, st.list(edev))
	case r.Method == http.MethodGet:
		sub := st.get(edev, id)
		if sub == nil {
			w.WriteHeader(http.StatusNotFound)
			return true
		}
		s.serveXML(w, toSEPSubscription(*sub))
	case r.Method == http.MethodPost && id < 0:
		s.createSubscription(w, r, st, edev)
	case r.Method == http.MethodDelete && id >= 0:
		if !st.delete(edev, id) {
			w.WriteHeader(http.StatusNotFound)
			return true
		}
		log.Printf("[gridsim] DELETE %s → subscription removed (204)", path)
		w.WriteHeader(http.StatusNoContent)
	default:
		w.Header().Set("Allow", "GET, POST, DELETE")
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
	return true
}

// hasEndDevice reports whether the server serves an EndDevice at this href. It
// is what keeps a POST to /edev/99/sub from creating a subscription against a
// device that does not exist.
func (s *Server) hasEndDevice(href string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if href == "/edev/2" {
		return true // the DUT's own EndDevice, present in every tree
	}
	_, ok := s.resources[href]
	return ok
}

// createSubscription is the POST half of critSubscriptionPosted: 201 Created
// with a Location header naming the created subscription. Both halves are
// asserted by the conformance suite, and a 201 without a Location is a FAIL
// there — it names nothing the client could later cancel.
func (s *Server) createSubscription(w http.ResponseWriter, r *http.Request, st *subState, edev string) {
	body, err := readAllLimited(r)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	var in sepSubscription
	if err := xml.Unmarshal(body, &in); err != nil {
		log.Printf("[gridsim] POST %s/sub: unmarshal Subscription error: %v", edev, err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if strings.TrimSpace(in.SubscribedResource) == "" || strings.TrimSpace(in.NotificationURI) == "" {
		log.Printf("[gridsim] POST %s/sub: rejected (subscribedResource=%q notificationURI=%q)",
			edev, in.SubscribedResource, in.NotificationURI)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	sub := st.add(edev, in, s.Now())
	w.Header().Set("Location", sub.Href)
	w.WriteHeader(http.StatusCreated)
	log.Printf("[gridsim] POST %s/sub → 201 Created %s (subscribedResource=%s notificationURI=%s limit=%d)",
		edev, sub.Href, sub.SubscribedResource, sub.NotificationURI, sub.Limit)
}

func readAllLimited(r *http.Request) ([]byte, error) {
	var buf bytes.Buffer
	_, err := buf.ReadFrom(http.MaxBytesReader(nil, r.Body, 1<<20))
	return buf.Bytes(), err
}

func toSEPSubscription(sub Subscription) *sepSubscription {
	return &sepSubscription{
		Href:               sub.Href,
		SubscribedResource: sub.SubscribedResource,
		Limit:              sub.Limit,
		NotificationURI:    sub.NotificationURI,
	}
}

// ── store operations ─────────────────────────────────────────────────────────

func (st *subState) add(edev string, in sepSubscription, now int64) Subscription {
	st.mu.Lock()
	defer st.mu.Unlock()
	id := st.next
	st.next++
	sub := &Subscription{
		ID:                 id,
		Href:               fmt.Sprintf("%s/sub/%d", edev, id),
		EndDevice:          edev,
		SubscribedResource: strings.TrimSpace(in.SubscribedResource),
		NotificationURI:    strings.TrimSpace(in.NotificationURI),
		Limit:              in.Limit,
		CreatedAt:          now,
	}
	st.subs = append(st.subs, sub)
	return *sub
}

func (st *subState) get(edev string, id int) *Subscription {
	st.mu.Lock()
	defer st.mu.Unlock()
	for _, s := range st.subs {
		if s.ID == id && s.EndDevice == edev {
			c := *s
			return &c
		}
	}
	return nil
}

func (st *subState) delete(edev string, id int) bool {
	st.mu.Lock()
	defer st.mu.Unlock()
	for i, s := range st.subs {
		if s.ID == id && s.EndDevice == edev {
			st.subs = append(st.subs[:i], st.subs[i+1:]...)
			return true
		}
	}
	return false
}

func (st *subState) list(edev string) *sepSubscriptionList {
	st.mu.Lock()
	defer st.mu.Unlock()
	out := &sepSubscriptionList{Href: edev + "/sub", PollRate: 300}
	for _, s := range st.subs {
		if s.EndDevice == edev {
			out.Subscription = append(out.Subscription, *toSEPSubscription(*s))
		}
	}
	out.All = uint32(len(out.Subscription))
	out.Results = out.All
	return out
}

// matching returns copies of every subscription whose subscribedResource is the
// changed href.
func (st *subState) matching(href string) []Subscription {
	st.mu.Lock()
	defer st.mu.Unlock()
	var out []Subscription
	for _, s := range st.subs {
		if normalizeHref(s.SubscribedResource) == normalizeHref(href) {
			out = append(out, *s)
		}
	}
	return out
}

// normalizeHref strips a query string and a trailing slash so that a
// subscription posted against "/derp/0/derc?l=10" still matches a change to
// "/derp/0/derc". A client is entitled to subscribe with the list parameters it
// intends to page with, and refusing to match one would look to the operator
// like a server that never notifies.
func normalizeHref(h string) string {
	if i := strings.IndexByte(h, '?'); i >= 0 {
		h = h[:i]
	}
	if len(h) > 1 {
		h = strings.TrimSuffix(h, "/")
	}
	return h
}

func (st *subState) record(rec NotificationRecord, subHref string) {
	st.mu.Lock()
	defer st.mu.Unlock()
	st.log = append(st.log, rec)
	for _, s := range st.subs {
		if s.Href == subHref {
			s.Notifications++
		}
	}
}

// ── notification ─────────────────────────────────────────────────────────────

// notifyChanged pushes a Notification for every subscription on each changed
// resource href.
//
// Dispatch is SYNCHRONOUS with the mutation that caused it. That costs the
// caller up to notifyTimeout per matching subscription, and it buys the one
// property a conformance bench needs: when POST /admin/control returns, the
// Notification it caused is already on the wire. An asynchronous dispatch would
// race every check that posts a control and then reads the server's log, and
// the race would show up as an intermittent missing Notification — which reads
// as a DUT fault.
//
// It must be called with NO gridsim lock held.
func (s *Server) notifyChanged(hrefs ...string) {
	st := s.subStore()
	if st == nil || len(hrefs) == 0 {
		return
	}
	for _, href := range hrefs {
		for _, sub := range st.matching(href) {
			s.pushNotification(st, sub, href, NotifyDefault)
		}
	}
}

// CancelSubscription pushes the status=1 "Subscription canceled" Notification
// ERR-002 and CORE-019 are about, and removes the subscription. It returns
// false when no such subscription exists.
func (s *Server) CancelSubscription(href string) bool {
	st := s.subStore()
	if st == nil {
		return false
	}
	var found *Subscription
	for _, sub := range s.Subscriptions() {
		if sub.Href == href {
			c := sub
			found = &c
			break
		}
	}
	if found == nil {
		return false
	}
	s.pushNotification(st, *found, found.SubscribedResource, NotifyCancelled)
	st.delete(found.EndDevice, found.ID)
	return true
}

func (s *Server) pushNotification(st *subState, sub Subscription, href string, status uint8) {
	body, err := s.newNotification(sub, href, status)
	rec := NotificationRecord{
		At: s.Now(), SubscriptionHref: sub.Href, SubscribedResource: href,
		NotificationURI: sub.NotificationURI, Status: status, Bytes: len(body),
	}
	if err != nil {
		rec.Error = err.Error()
		st.record(rec, sub.Href)
		log.Printf("[gridsim] Notification for %s NOT built: %v", sub.Href, err)
		return
	}

	st.mu.Lock()
	n := st.notify
	st.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), notifyTimeout)
	defer cancel()
	code, nerr := n.Notify(ctx, sub.NotificationURI, body)
	rec.HTTPStatus = code
	if nerr != nil {
		rec.Error = nerr.Error()
	}
	st.record(rec, sub.Href)
	if nerr != nil {
		log.Printf("[gridsim] Notification POST %s (%s) FAILED: %v", sub.NotificationURI, href, nerr)
		return
	}
	log.Printf("[gridsim] Notification POST %s (%s, status=%d) → HTTP %d",
		sub.NotificationURI, href, status, code)
}

// newNotification marshals the Notification body for one subscription.
//
// The subscribed resource is serialized as it would be served, truncated to the
// subscription's limit when it is a list — MAINT-001's pass criterion is
// explicit that "the notification resource body for the EndDeviceList was
// correctly formed using the limit parameter requested by the Client in the
// original subscription request".
func (s *Server) newNotification(sub Subscription, href string, status uint8) ([]byte, error) {
	n := &sepNotification{
		SubscribedResource: normalizeHref(href),
		Status:             status,
		SubscriptionURI:    sub.Href,
	}
	if status != NotifyCancelled {
		s.mu.RLock()
		res, ok := s.resources[normalizeHref(href)]
		s.mu.RUnlock()
		if !ok {
			return nil, fmt.Errorf("no resource is served at %s, so there is nothing to notify about",
				normalizeHref(href))
		}
		if sub.Limit > 0 {
			res = pageResource(res, 0, int(sub.Limit))
		}
		payload, err := xml.Marshal(res)
		if err != nil {
			return nil, fmt.Errorf("marshal %s: %w", href, err)
		}
		local, inner, err := splitRootElement(payload)
		if err != nil {
			return nil, err
		}
		n.Resource = &notifyResource{
			XSINS:   "http://www.w3.org/2001/XMLSchema-instance",
			XSIType: local,
			Href:    normalizeHref(href),
			Inner:   inner,
		}
	}
	out, err := xml.MarshalIndent(n, "", "  ")
	if err != nil {
		return nil, err
	}
	return append([]byte(`<?xml version="1.0" encoding="UTF-8"?>`+"\n"), out...), nil
}

// splitRootElement returns a marshalled resource's root local name and the
// bytes between its start and end tags.
//
// It exists because the Notification carries the subscribed resource as
// <Resource xsi:type="DERControlList">…</Resource>, i.e. the resource's
// CHILDREN under a differently-named element. Re-encoding through a typed field
// would mean this file knowing every subscribable resource type; taking the
// inner XML off the marshalled bytes means it knows none of them.
func splitRootElement(doc []byte) (local string, inner []byte, err error) {
	dec := xml.NewDecoder(bytes.NewReader(doc))
	tok, err := dec.Token()
	for err == nil {
		if se, ok := tok.(xml.StartElement); ok {
			start := int(dec.InputOffset())
			var depth int
			for {
				t, terr := dec.Token()
				if terr != nil {
					return "", nil, fmt.Errorf("read %s: %w", se.Name.Local, terr)
				}
				switch t.(type) {
				case xml.StartElement:
					depth++
				case xml.EndElement:
					if depth == 0 {
						end := int(dec.InputOffset())
						// InputOffset after an EndElement is just past "</name>".
						closeTag := len("</" + se.Name.Local + ">")
						if se.Name.Space != "" {
							// The encoder writes no prefix for a default
							// namespace, so the close tag is the local name.
							_ = se.Name.Space
						}
						if end-closeTag < start {
							return se.Name.Local, nil, nil
						}
						return se.Name.Local, doc[start : end-closeTag], nil
					}
					depth--
				}
			}
		}
		tok, err = dec.Token()
	}
	return "", nil, fmt.Errorf("no element found in the marshalled resource")
}

// httpNotifier is the built-in delivery transport: a plain HTTP POST of
// application/sep+xml.
//
// It refuses https:// rather than dialling it, because gridsim cannot negotiate
// the CSIP-mandatory cipher (see the file comment) and a Notification delivered
// over some OTHER TLS profile would be evidence about a connection the standard
// does not describe.
type httpNotifier struct{}

func (httpNotifier) Notify(ctx context.Context, uri string, body []byte) (int, error) {
	if strings.HasPrefix(strings.ToLower(uri), "https://") {
		return 0, fmt.Errorf("notificationURI %s is https, and this simulator is pure Go: Go's crypto/tls "+
			"does not implement the CSIP-mandatory ECDHE-ECDSA-AES128-CCM-8 suite, so it cannot dial a "+
			"conformant 2030.5 notification connection. Install a Notifier (Server.SetNotifier) from a "+
			"binary that has an mTLS client, or point the subscription at an http:// bench listener", uri)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, uri, bytes.NewReader(body))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Content-Type", ContentType)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, err
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = bytes.NewBuffer(nil).ReadFrom(resp.Body)
	return resp.StatusCode, nil
}

// ── admin ────────────────────────────────────────────────────────────────────

// handleAdminSubscriptions serves GET /admin/subscriptions — every live
// subscription with the notificationURI the DUT registered.
//
// The notificationURI is the interesting field and the reason this endpoint
// exists at all: a Notification arrives on a connection the SERVER dials, so a
// conformance harness that wants to attribute those frames has to learn the
// DUT's inbound listener address from somewhere. It cannot be known statically
// — the DUT chooses it — and this is where the server, which was told, publishes
// it. See internal/certify/suitecsip/check.go's notification claim.
//
// DELETE /admin/subscriptions?href=… cancels one with a status=1 Notification,
// which is the lever ERR-002 and CORE-019 need.
func (s *Server) handleAdminSubscriptions(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		subs := s.Subscriptions()
		if subs == nil {
			subs = []Subscription{}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"enabled":       s.SubscriptionsEnabled(),
			"subscriptions": subs,
			"server_time":   s.Now(),
		})
	case http.MethodDelete:
		href := r.URL.Query().Get("href")
		if href == "" {
			http.Error(w, "href query parameter required", http.StatusBadRequest)
			return
		}
		if !s.CancelSubscription(href) {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

// handleAdminNotifications serves GET /admin/notifications — what gridsim
// pushed and what the client answered.
func (s *Server) handleAdminNotifications(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	recs := s.SentNotifications()
	if recs == nil {
		recs = []NotificationRecord{}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"enabled":       s.SubscriptionsEnabled(),
		"notifications": recs,
		"server_time":   s.Now(),
	})
}
