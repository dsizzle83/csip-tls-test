package gridsim

// subscribe_test.go drives the whole Subscription lifecycle the CTP's
// aggregator rows walk — POST → 201 + Location → GET → change → Notification →
// DELETE → silence — against the served bytes.
//
// The two assertions worth naming, because both are properties a plausible
// implementation gets wrong in a way no smoke test would notice:
//
//	1. the 201 MUST carry a Location. A 201 without one names nothing the client
//	   could later cancel, and critSubscriptionPosted FAILs it.
//	2. a DELETED subscription MUST stop being notified. A notifier that kept
//	   pushing would look, from the client's side, exactly like a server that
//	   ignored the cancellation.

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// notifySink is a stand-in for the DUT's inbound notification listener. It
// records every body it is POSTed and answers with the status the CTP requires.
type notifySink struct {
	mu     sync.Mutex
	bodies [][]byte
	status int
	url    string
	srv    *httptest.Server
}

func newNotifySink(t *testing.T, status int) *notifySink {
	t.Helper()
	sink := &notifySink{status: status}
	sink.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		sink.mu.Lock()
		sink.bodies = append(sink.bodies, b)
		st := sink.status
		sink.mu.Unlock()
		if got := r.Header.Get("Content-Type"); got != ContentType {
			t.Errorf("Notification POST Content-Type = %q, want %q (GEN.003)", got, ContentType)
		}
		w.WriteHeader(st)
	}))
	sink.url = sink.srv.URL + "/notif"
	t.Cleanup(sink.srv.Close)
	return sink
}

func (n *notifySink) got() [][]byte {
	n.mu.Lock()
	defer n.mu.Unlock()
	return append([][]byte(nil), n.bodies...)
}

// subBench is a gridsim with the function set on, its CSIP handler and its
// admin handler.
type subBench struct {
	s     *Server
	csip  *httptest.Server
	admin *httptest.Server
}

func newSubBench(t *testing.T) *subBench {
	t.Helper()
	s := NewServer(testAggLFDI)
	s.EnableSubscriptions()
	b := &subBench{s: s, csip: httptest.NewServer(s.Handler()), admin: httptest.NewServer(s.AdminHandler())}
	t.Cleanup(b.csip.Close)
	t.Cleanup(b.admin.Close)
	return b
}

// subscribe POSTs a Subscription the way the DUT would and returns the response.
func (b *subBench) subscribe(t *testing.T, edev, resource, uri string, limit int) *http.Response {
	t.Helper()
	body := fmt.Sprintf(`<Subscription xmlns="%s"><subscribedResource>%s</subscribedResource>`+
		`<limit>%d</limit><notificationURI>%s</notificationURI></Subscription>`,
		csipNamespace, resource, limit, uri)
	resp, err := http.Post(b.csip.URL+edev+"/sub", ContentType, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })
	return resp
}

func (b *subBench) do(t *testing.T, method, path string, body string) (*http.Response, []byte) {
	t.Helper()
	var rdr io.Reader
	if body != "" {
		rdr = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, b.csip.URL+path, rdr)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	out, _ := io.ReadAll(resp.Body)
	return resp, out
}

func (b *subBench) postControl(t *testing.T, program int, mrid string) {
	t.Helper()
	body := fmt.Sprintf(`{"program":%d,"mrid":%q,"start_offset_s":120,"duration_s":60,"exp_lim_W":1500}`,
		program, mrid)
	resp, err := http.Post(b.admin.URL+"/admin/control", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("POST /admin/control = %d", resp.StatusCode)
	}
}

// TestSubscriptionLifecycle is the whole round trip.
func TestSubscriptionLifecycle(t *testing.T) {
	b := newSubBench(t)
	sink := newNotifySink(t, http.StatusCreated)

	// The advertisement the DUT follows to get here.
	_, edev := b.do(t, "GET", "/edev", "")
	if !strings.Contains(string(edev), `<SubscriptionListLink href="/edev/2/sub"`) {
		t.Fatalf("the EndDeviceList advertises no SubscriptionListLink:\n%s", edev)
	}

	// POST → 201 Created with a Location.
	resp := b.subscribe(t, "/edev/2", "/derp/0/derc", sink.url, 0)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("POST /edev/2/sub = %d, want 201 Created", resp.StatusCode)
	}
	loc := resp.Header.Get("Location")
	if loc == "" {
		t.Fatal("201 Created with no Location header: it names nothing the client could later cancel, " +
			"and critSubscriptionPosted FAILs exactly this")
	}

	// GET the created subscription and the list that holds it.
	getResp, body := b.do(t, "GET", loc, "")
	if getResp.StatusCode != 200 {
		t.Fatalf("GET %s = %d", loc, getResp.StatusCode)
	}
	var sub struct {
		XMLName  xml.Name `xml:"Subscription"`
		Resource string   `xml:"subscribedResource"`
		URI      string   `xml:"notificationURI"`
	}
	if err := xml.Unmarshal(body, &sub); err != nil {
		t.Fatal(err)
	}
	if sub.Resource != "/derp/0/derc" || sub.URI != sink.url {
		t.Errorf("GET %s returned subscribedResource=%q notificationURI=%q, want %q / %q",
			loc, sub.Resource, sub.URI, "/derp/0/derc", sink.url)
	}
	_, listBody := b.do(t, "GET", "/edev/2/sub", "")
	if !strings.Contains(string(listBody), `all="1"`) {
		t.Errorf("the SubscriptionList does not report the one subscription:\n%s", listBody)
	}

	// A change to the subscribed resource pushes exactly one Notification.
	b.postControl(t, 0, "CERT-SUBTEST")
	if got := len(sink.got()); got != 1 {
		t.Fatalf("the change produced %d Notifications, want 1", got)
	}

	// DELETE → 204, and no further Notification.
	delResp, _ := b.do(t, "DELETE", loc, "")
	if delResp.StatusCode != http.StatusNoContent {
		t.Fatalf("DELETE %s = %d, want 204", loc, delResp.StatusCode)
	}
	b.postControl(t, 0, "CERT-SUBTEST-2")
	if got := len(sink.got()); got != 1 {
		t.Errorf("a cancelled subscription was notified again (%d total); to the client that is "+
			"indistinguishable from a server that ignored the DELETE", got)
	}

	// The server's own record agrees.
	if n := len(b.s.SentNotifications()); n != 1 {
		t.Errorf("gridsim logged %d Notifications, want 1", n)
	}
	if rec := b.s.SentNotifications()[0]; rec.HTTPStatus != http.StatusCreated {
		t.Errorf("the log records HTTP %d for the client's answer, want 201", rec.HTTPStatus)
	}
}

// TestNotificationPayloadShape reads the pushed body the way a conformance
// criterion would: the 2030.5 namespace on the root, the subscribedResource it
// was sent for, the subscriptionURI that identifies which subscription, and the
// changed resource carried as the polymorphic <Resource xsi:type="…">.
func TestNotificationPayloadShape(t *testing.T) {
	b := newSubBench(t)
	sink := newNotifySink(t, http.StatusCreated)

	b.subscribe(t, "/edev/2", "/derp/0/derc", sink.url, 0)
	b.postControl(t, 0, "CERT-SHAPE")

	bodies := sink.got()
	if len(bodies) != 1 {
		t.Fatalf("got %d Notifications, want 1", len(bodies))
	}
	body := bodies[0]

	var n struct {
		XMLName            xml.Name `xml:"Notification"`
		SubscribedResource string   `xml:"subscribedResource,attr"`
		Status             int      `xml:"status"`
		SubscriptionURI    string   `xml:"subscriptionURI"`
		Resource           struct {
			Type string `xml:"type,attr"`
			Href string `xml:"href,attr"`
			Ctrl []struct {
				MRID string `xml:"mRID"`
			} `xml:"DERControl"`
		} `xml:"Resource"`
	}
	if err := xml.Unmarshal(body, &n); err != nil {
		t.Fatalf("the Notification is not well-formed 2030.5 XML: %v\n%s", err, body)
	}
	if n.XMLName.Space != csipNamespace {
		t.Errorf("the Notification root is in namespace %q, want %q — a payload without it unmarshals to "+
			"zero values in every 2030.5 client", n.XMLName.Space, csipNamespace)
	}
	if n.SubscribedResource != "/derp/0/derc" {
		t.Errorf("subscribedResource=%q, want /derp/0/derc", n.SubscribedResource)
	}
	if n.Status != int(NotifyDefault) {
		t.Errorf("status=%d, want %d for an ordinary change", n.Status, NotifyDefault)
	}
	if !strings.HasPrefix(n.SubscriptionURI, "/edev/2/sub/") {
		t.Errorf("subscriptionURI=%q does not name the subscription it belongs to", n.SubscriptionURI)
	}
	if n.Resource.Type != "DERControlList" {
		t.Errorf("the payload's xsi:type is %q, want DERControlList", n.Resource.Type)
	}
	var found bool
	for _, c := range n.Resource.Ctrl {
		if c.MRID == "CERT-SHAPE" {
			found = true
		}
	}
	if !found {
		t.Errorf("the notified DERControlList does not carry the control that caused the Notification:\n%s",
			body)
	}
	if !bytes.Contains(body, []byte(`xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"`)) {
		t.Error("the payload wrapper uses xsi:type without declaring the xsi namespace")
	}
}

// TestNotificationHonoursTheSubscriptionLimit covers MAINT-001's pass
// criterion: "The notification resource body for the EndDeviceList was
// correctly formed using the limit parameter requested by the Client in the
// original subscription request."
func TestNotificationHonoursTheSubscriptionLimit(t *testing.T) {
	b := newSubBench(t)
	sink := newNotifySink(t, http.StatusCreated)

	b.subscribe(t, "/edev/2", "/derp/0/derc", sink.url, 2)
	b.postControl(t, 0, "CERT-LIMIT")

	bodies := sink.got()
	if len(bodies) != 1 {
		t.Fatalf("got %d Notifications, want 1", len(bodies))
	}
	var n struct {
		Resource struct {
			Ctrl []struct{} `xml:"DERControl"`
		} `xml:"Resource"`
	}
	if err := xml.Unmarshal(bodies[0], &n); err != nil {
		t.Fatal(err)
	}
	if got := len(n.Resource.Ctrl); got != 2 {
		t.Errorf("the Notification carried %d DERControls for a subscription with limit=2; the default "+
			"program holds five after this test's POST, so an unlimited body would carry all of them", got)
	}
}

// TestSubscriptionRejectsAnIncompleteRequest keeps the bench from creating a
// subscription it can never deliver on — a subscription with no notificationURI
// would sit in the list looking live and notify nobody.
func TestSubscriptionRejectsAnIncompleteRequest(t *testing.T) {
	b := newSubBench(t)

	for name, body := range map[string]string{
		"no notificationURI": `<Subscription xmlns="` + csipNamespace +
			`"><subscribedResource>/derp/0/derc</subscribedResource></Subscription>`,
		"no subscribedResource": `<Subscription xmlns="` + csipNamespace +
			`"><notificationURI>http://127.0.0.1:9/n</notificationURI></Subscription>`,
		"not XML at all": `{"subscribedResource":"/derp/0/derc"}`,
	} {
		resp, err := http.Post(b.csip.URL+"/edev/2/sub", ContentType, strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("%s: POST = %d, want 400", name, resp.StatusCode)
		}
	}

	// And a subscription against an EndDevice the server does not serve.
	resp, err := http.Post(b.csip.URL+"/edev/99/sub", ContentType, strings.NewReader(
		`<Subscription xmlns="`+csipNamespace+`"><subscribedResource>/derp/0/derc</subscribedResource>`+
			`<notificationURI>http://127.0.0.1:9/n</notificationURI></Subscription>`))
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("POST /edev/99/sub = %d, want 404", resp.StatusCode)
	}
}

// TestHTTPSNotificationIsRefusedLoudly pins the one thing this simulator cannot
// do, and pins that it says so.
//
// gridsim is pure Go and Go's crypto/tls has no ECDHE-ECDSA-AES128-CCM-8, so it
// cannot dial a conformant 2030.5 notification connection. A silently-dropped
// Notification would read on the other end as a DUT that never answered one,
// which is a DUT finding invented out of a bench limitation — so the refusal is
// recorded verbatim in the notification log instead.
func TestHTTPSNotificationIsRefusedLoudly(t *testing.T) {
	b := newSubBench(t)

	b.subscribe(t, "/edev/2", "/derp/0/derc", "https://69.0.0.2:8443/notif", 0)
	b.postControl(t, 0, "CERT-HTTPS")

	recs := b.s.SentNotifications()
	if len(recs) != 1 {
		t.Fatalf("got %d notification records, want 1 (the attempt must be recorded, not dropped)", len(recs))
	}
	rec := recs[0]
	if rec.HTTPStatus != 0 {
		t.Errorf("HTTPStatus=%d for a refused delivery, want 0", rec.HTTPStatus)
	}
	for _, want := range []string{"ECDHE-ECDSA-AES128-CCM-8", "SetNotifier"} {
		if !strings.Contains(rec.Error, want) {
			t.Errorf("the recorded refusal does not mention %q, so it is not a work item: %s", want, rec.Error)
		}
	}

	// And a Notifier that CAN speak mTLS makes it work — the seam is real.
	var got int
	b.s.SetNotifier(notifierFunc(func(_ context.Context, uri string, body []byte) (int, error) {
		got++
		return http.StatusCreated, nil
	}))
	b.postControl(t, 0, "CERT-HTTPS-2")
	if got != 1 {
		t.Errorf("the installed Notifier was called %d times, want 1", got)
	}
}

type notifierFunc func(ctx context.Context, uri string, body []byte) (int, error)

func (f notifierFunc) Notify(ctx context.Context, uri string, body []byte) (int, error) {
	return f(ctx, uri, body)
}

// TestCancelSubscriptionPushesStatus1 covers the lever ERR-002 and CORE-019
// need: the server cancels a subscription and tells the client with a
// Notification carrying status 1.
func TestCancelSubscriptionPushesStatus1(t *testing.T) {
	b := newSubBench(t)
	sink := newNotifySink(t, http.StatusCreated)

	resp := b.subscribe(t, "/edev/2", "/derp/0/derc", sink.url, 0)
	loc := resp.Header.Get("Location")

	del, err := http.NewRequest("DELETE", b.admin.URL+"/admin/subscriptions?href="+loc, nil)
	if err != nil {
		t.Fatal(err)
	}
	dresp, err := http.DefaultClient.Do(del)
	if err != nil {
		t.Fatal(err)
	}
	_ = dresp.Body.Close()
	if dresp.StatusCode != http.StatusNoContent {
		t.Fatalf("DELETE /admin/subscriptions = %d, want 204", dresp.StatusCode)
	}

	bodies := sink.got()
	if len(bodies) != 1 {
		t.Fatalf("got %d Notifications, want 1 cancellation", len(bodies))
	}
	var n struct {
		Status int `xml:"status"`
	}
	if err := xml.Unmarshal(bodies[0], &n); err != nil {
		t.Fatal(err)
	}
	if n.Status != int(NotifyCancelled) {
		t.Errorf("the cancellation Notification carries status=%d, want %d", n.Status, NotifyCancelled)
	}
	if len(b.s.Subscriptions()) != 0 {
		t.Error("the cancelled subscription is still in the server's list")
	}
}

// TestAdminSurfaceReportsBothCapabilities is what a preflight reads. The point
// of the endpoints is that a run can PROBE rather than assume, so the fields
// have to be there and have to be right.
func TestAdminSurfaceReportsBothCapabilities(t *testing.T) {
	b := newSubBench(t)
	if err := b.s.EnableFleet(FleetSize); err != nil {
		t.Fatal(err)
	}
	sink := newNotifySink(t, http.StatusCreated)
	b.subscribe(t, "/edev/2", "/derp/0/derc", sink.url, 0)
	b.postControl(t, 0, "CERT-STATUS")

	var status struct {
		Fleet struct {
			Enabled        bool     `json:"enabled"`
			Size           int      `json:"size"`
			Devices        []string `json:"devices"`
			AggregatorHref string   `json:"aggregator_href"`
		} `json:"fleet"`
		Subscription struct {
			Enabled       bool `json:"enabled"`
			Subscriptions int  `json:"subscriptions"`
			Notifications int  `json:"notifications"`
		} `json:"subscription"`
	}
	getJSON(t, b.admin.URL+"/admin/status", &status)

	if !status.Fleet.Enabled || status.Fleet.Size != FleetSize {
		t.Errorf("/admin/status fleet = %+v, want enabled with %d devices", status.Fleet, FleetSize)
	}
	if strings.Join(status.Fleet.Devices, ",") != "EDA1,EDA2,EDB1,EDB2" {
		t.Errorf("/admin/status fleet devices = %v", status.Fleet.Devices)
	}
	if status.Fleet.AggregatorHref != "/edev/2" {
		t.Errorf("/admin/status aggregator_href = %q, want /edev/2", status.Fleet.AggregatorHref)
	}
	if !status.Subscription.Enabled || status.Subscription.Subscriptions != 1 ||
		status.Subscription.Notifications != 1 {
		t.Errorf("/admin/status subscription = %+v, want enabled with 1 subscription and 1 notification",
			status.Subscription)
	}

	// /admin/subscriptions carries the notificationURI, which is the only place
	// a harness can learn the DUT's inbound listener address.
	var subs struct {
		Subscriptions []struct {
			Href               string `json:"href"`
			SubscribedResource string `json:"subscribed_resource"`
			NotificationURI    string `json:"notification_uri"`
			Notifications      int    `json:"notifications"`
		} `json:"subscriptions"`
	}
	getJSON(t, b.admin.URL+"/admin/subscriptions", &subs)
	if len(subs.Subscriptions) != 1 || subs.Subscriptions[0].NotificationURI != sink.url {
		t.Fatalf("/admin/subscriptions = %+v, want the one subscription with notificationURI %s",
			subs.Subscriptions, sink.url)
	}
	if subs.Subscriptions[0].Notifications != 1 {
		t.Errorf("the subscription reports %d Notifications, want 1",
			subs.Subscriptions[0].Notifications)
	}

	var fleet struct {
		Enabled bool `json:"enabled"`
		Devices []struct {
			Name string `json:"name"`
			Node string `json:"node"`
			LFDI string `json:"lfdi"`
			PIN  uint32 `json:"pin"`
		} `json:"devices"`
		Nodes map[string]struct {
			Href    string `json:"href"`
			Primacy int    `json:"primacy"`
			Alias   *int   `json:"aliases_program"`
		} `json:"nodes"`
	}
	getJSON(t, b.admin.URL+"/admin/fleet", &fleet)
	if len(fleet.Devices) != FleetSize {
		t.Fatalf("/admin/fleet lists %d devices, want %d", len(fleet.Devices), FleetSize)
	}
	if fleet.Devices[0].Node != "SPA1" {
		t.Errorf("EDA1's node is %q; UTIL-001 setup step 3 assigns it to SPA1", fleet.Devices[0].Node)
	}
	// The alias is published because two of the eleven nodes ARE gridsim's
	// existing programs, and nothing else on the wire says so.
	if n, ok := fleet.Nodes["TFA"]; !ok || n.Alias == nil || *n.Alias != 0 {
		t.Errorf("/admin/fleet does not report that TFA aliases program 0: %+v", fleet.Nodes["TFA"])
	}
	if n := fleet.Nodes["SGA"]; n.Primacy != 2 {
		t.Errorf("SGA primacy = %d; CTP MAINT-005 setup step 5 states 2", n.Primacy)
	}
}

func getJSON(t *testing.T, url string, out any) {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != 200 {
		t.Fatalf("GET %s = %d", url, resp.StatusCode)
	}
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		t.Fatalf("decode %s: %v", url, err)
	}
}

// TestSubscriptionsAreOffByDefault pins the other half of the golden test: with
// the lever off the paths do not exist and the tree does not advertise them.
func TestSubscriptionsAreOffByDefault(t *testing.T) {
	s := NewServer(testAggLFDI)
	srv := httptest.NewServer(s.Handler())
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/edev/2/sub")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("GET /edev/2/sub = %d with the function set off, want 404", resp.StatusCode)
	}

	req, _ := http.NewRequest("DELETE", srv.URL+"/edev/2/sub/0", nil)
	dresp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = dresp.Body.Close()
	if dresp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("DELETE with the function set off = %d, want the 405 gridsim has always answered",
			dresp.StatusCode)
	}
	if got := dresp.Header.Get("Allow"); got != "GET, POST, PUT" {
		t.Errorf("Allow = %q, want the unchanged \"GET, POST, PUT\"", got)
	}
}
