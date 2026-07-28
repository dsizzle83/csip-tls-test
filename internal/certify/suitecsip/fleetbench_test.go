package suitecsip

// fleetbench_test.go closes the loop between the two halves of this change: the
// criteria in criteria_agg.go and the fixture sim/gridsim now serves.
//
// teeth_agg_test.go already proves the criteria have teeth against SYNTHETIC
// payloads — a hand-written five-EndDevice list passes, a one-EndDevice list
// SKIPs. That is the right test for the decision logic and the wrong one for
// this question, because a hand-written fixture shares its author's assumptions
// with the check. What is asserted here instead is that the bytes GRIDSIM
// ACTUALLY SERVES satisfy those same criteria, so the SKIPs the aggregator rows
// report today will really turn into verdicts on the next bench run rather than
// into a different SKIP nobody predicted.
//
// Nothing in criteria_agg.go or aggregator.go is modified to make this pass. If
// a criterion below does not go live, that is the finding.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"csip-tls-test/internal/certify"
	"csip-tls-test/sim/gridsim"
)

const benchLFDI = "AABBCCDDEEFF00112233445566778899AABBCCDD"

// benchFixture starts a gridsim with the levers the DER AGGREGATOR CLIENT rows
// need and returns a fetcher that speaks to it as the DUT would.
func benchFixture(t *testing.T, fleet, subscription bool) (*gridsim.Server, func(path string) (int, string)) {
	t.Helper()
	s := gridsim.NewServer(benchLFDI)
	if subscription {
		s.EnableSubscriptions()
	}
	if fleet {
		if err := s.EnableFleet(gridsim.FleetSize); err != nil {
			t.Fatal(err)
		}
	}
	srv := httptest.NewServer(s.Handler())
	t.Cleanup(srv.Close)

	return s, func(path string) (int, string) {
		t.Helper()
		req, err := http.NewRequest(http.MethodGet, srv.URL+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("X-Peer-LFDI", benchLFDI)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		var b strings.Builder
		buf := make([]byte, 8192)
		for {
			n, rerr := resp.Body.Read(buf)
			b.Write(buf[:n])
			if rerr != nil {
				break
			}
		}
		return resp.StatusCode, b.String()
	}
}

// TestGridsimFleetSatisfiesTheFleetCriterion is the fixture half of
// TestFleetCriterionSkipsRatherThanFailsOnAShortList: the same criterion, the
// same code path, real bytes.
func TestGridsimFleetSatisfiesTheFleetCriterion(t *testing.T) {
	// Before: gridsim's default tree, and the criterion must still SKIP. This is
	// the regression guard on the honest answer — if the fleet lever ever became
	// the default, this is what would notice.
	_, plain := benchFixture(t, false, false)
	code, body := plain("/edev")
	if code != 200 {
		t.Fatalf("GET /edev on the default tree = %d", code)
	}
	f := critAggregatorFleet().Wire(nil, synthTranscript(get("/edev", 200, body)))
	if f.Verdict != certify.Skip {
		t.Fatalf("the default single-EndDevice tree produced %s, want SKIP (observed: %s)",
			f.Verdict, f.Observed)
	}

	// After: the Figure-15 fixture, and the criterion goes live.
	_, fleet := benchFixture(t, true, true)
	code, body = fleet("/edev")
	if code != 200 {
		t.Fatalf("GET /edev on the fleet tree = %d", code)
	}
	f = critAggregatorFleet().Wire(nil, synthTranscript(get("/edev", 200, body)))
	if f.Unavailable != "" {
		t.Fatalf("the fleet criterion declined to decide on gridsim's own output: %s", f.Unavailable)
	}
	if f.Verdict != certify.Pass {
		t.Fatalf("gridsim's Figure-15 EndDeviceList produced %s, want PASS — the fixture and the criterion "+
			"disagree, and this is exactly the gap this test exists to catch (observed: %s)",
			f.Verdict, f.Observed)
	}
	for _, want := range []string{"5 EndDevice instance(s)", "5 with a FunctionSetAssignmentsListLink",
		"5 with a DERListLink", "5 with a SubscriptionListLink"} {
		if !strings.Contains(f.Observed, want) {
			t.Errorf("the PASS does not record %q: %s", want, f.Observed)
		}
	}
}

// TestGridsimSatisfiesTheSubscriptionPrecondition drives critSubscriptionAdvertised
// — the criterion CORE-018, CORE-019 and ERR-002 all open with — against the
// real advertisement.
func TestGridsimSatisfiesTheSubscriptionPrecondition(t *testing.T) {
	_, plain := benchFixture(t, false, false)
	_, edev := plain("/edev")
	_, fsa := plain("/edev/2/fsa")
	f := critSubscriptionAdvertised().Wire(nil, synthTranscript(
		get("/edev", 200, edev), get("/edev/2/fsa", 200, fsa)))
	if f.Verdict != certify.Skip {
		t.Fatalf("the default tree produced %s for the subscription precondition, want SKIP (observed: %s)",
			f.Verdict, f.Observed)
	}

	_, bench := benchFixture(t, true, true)
	_, edev = bench("/edev")
	_, fsa = bench("/edev/2/fsa")
	f = critSubscriptionAdvertised().Wire(nil, synthTranscript(
		get("/edev", 200, edev), get("/edev/2/fsa", 200, fsa)))
	if f.Unavailable != "" {
		t.Fatalf("the precondition declined to decide: %s", f.Unavailable)
	}
	if f.Verdict != certify.Pass {
		t.Fatalf("gridsim advertises the function set but the precondition produced %s: %s",
			f.Verdict, f.Observed)
	}
}

// TestGridsimTurnsTheSubscriptionCriterionIntoADUTQuestion is the important
// one, and it is about who is being measured.
//
// critSubscriptionPosted is written so that a missing Subscription POST is a
// BENCH gap while the server offers nothing, and a DUT FAILURE once it does.
// Enabling the function set therefore does not merely turn a SKIP into a PASS —
// it moves the row from being about gridsim to being about the gateway. Both
// sides of that are asserted here against real server output.
func TestGridsimTurnsTheSubscriptionCriterionIntoADUTQuestion(t *testing.T) {
	s, bench := benchFixture(t, true, true)
	_, edev := bench("/edev")
	c := critSubscriptionPosted("EndDeviceList", "the aggregator EndDevice's SubscriptionListLink")

	// The bench offers it and the DUT ignored it: a real finding, not a SKIP.
	f := c.Wire(nil, synthTranscript(get("/edev", 200, edev)))
	if f.Unavailable != "" {
		t.Fatalf("with the function set advertised the criterion still declines to decide: %s", f.Unavailable)
	}
	if f.Verdict != certify.Fail {
		t.Fatalf("a DUT that ignored an ADVERTISED SubscriptionListLink produced %s, want FAIL: %s",
			f.Verdict, f.Observed)
	}

	// Now make the POST the DUT would make, against the real server, and feed
	// the real request and the real response to the criterion.
	srv := httptest.NewServer(s.Handler())
	defer srv.Close()
	subBody := `<Subscription xmlns="` + Namespace + `">` +
		`<subscribedResource>/edev</subscribedResource>` +
		`<notificationURI>http://69.0.0.2:8443/notif</notificationURI></Subscription>`
	resp, err := http.Post(srv.URL+"/edev/2/sub", "application/sep+xml", strings.NewReader(subBody))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("gridsim answered the Subscription POST %d, want 201 Created", resp.StatusCode)
	}
	loc := resp.Header.Get("Location")
	if loc == "" {
		t.Fatal("gridsim answered 201 with no Location, which critSubscriptionPosted FAILs")
	}

	f = c.Wire(nil, synthTranscript(
		get("/edev", 200, edev),
		post("/edev/2/sub", subBody, resp.StatusCode, "Location", loc),
	))
	if f.Verdict != certify.Pass {
		t.Fatalf("the real POST/201/Location exchange produced %s: %s", f.Verdict, f.Observed)
	}
	if !strings.Contains(f.Observed, loc) {
		t.Errorf("the PASS does not cite the Location gridsim returned (%s): %s", loc, f.Observed)
	}
}

// TestGridsimNotificationParsesAsSEP reads a Notification gridsim actually
// pushed with THIS suite's own sep+xml reader — the one the criteria use — so
// the payload is checked against the reader that will have to cite it, not
// against encoding/xml's tolerance.
func TestGridsimNotificationParsesAsSEP(t *testing.T) {
	got := make(chan []byte, 4)
	listener := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buf := make([]byte, 1<<20)
		n, _ := r.Body.Read(buf)
		got <- buf[:n]
		w.WriteHeader(http.StatusCreated)
	}))
	defer listener.Close()

	s, _ := benchFixture(t, true, true)
	srv := httptest.NewServer(s.Handler())
	defer srv.Close()
	admin := httptest.NewServer(s.AdminHandler())
	defer admin.Close()

	subBody := `<Subscription xmlns="` + Namespace + `">` +
		`<subscribedResource>/derp/0/derc</subscribedResource>` +
		`<notificationURI>` + listener.URL + `/notif</notificationURI></Subscription>`
	resp, err := http.Post(srv.URL+"/edev/2/sub", "application/sep+xml", strings.NewReader(subBody))
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()

	ctrl := `{"program":0,"mrid":"CERT-NOTIFY","start_offset_s":120,"duration_s":60,"exp_lim_W":1500}`
	cresp, err := http.Post(admin.URL+"/admin/control", "application/json", strings.NewReader(ctrl))
	if err != nil {
		t.Fatal(err)
	}
	_ = cresp.Body.Close()

	var body []byte
	select {
	case body = <-got:
	default:
		t.Fatal("gridsim pushed no Notification for the changed DERControlList")
	}

	doc, err := ParseSEP(body)
	if err != nil {
		t.Fatalf("the Notification does not parse as sep+xml: %v\n%s", err, body)
	}
	if doc.Local() != "Notification" {
		t.Fatalf("the pushed root element is <%s>, want <Notification>", doc.Local())
	}
	if doc.Name.Space != Namespace {
		t.Fatalf("the Notification's namespace is %q, want %q — this suite's reader keeps namespaces "+
			"precisely so a payload that omits it cannot pass as conformant", doc.Name.Space, Namespace)
	}
	if v, ok := doc.Attr("subscribedResource"); !ok || v != "/derp/0/derc" {
		t.Errorf("subscribedResource attribute = %q (present=%v), want /derp/0/derc", v, ok)
	}
	if v, ok := doc.UintOf("status"); !ok || v != 0 {
		t.Errorf("<status> = %d (present=%v), want 0 for an ordinary change", v, ok)
	}
	if v, ok := doc.TextOf("subscriptionURI"); !ok || !strings.HasPrefix(v, "/edev/2/sub/") {
		t.Errorf("<subscriptionURI> = %q, want the created subscription's href", v)
	}
	res := doc.Child("Resource")
	if res == nil {
		t.Fatalf("the Notification carries no <Resource> payload:\n%s", body)
	}
	if v, ok := res.Attr("type"); !ok || v != "DERControlList" {
		t.Errorf("the payload's xsi:type = %q (present=%v), want DERControlList", v, ok)
	}
	var mrids []string
	for _, c := range res.Children("DERControl") {
		if m, ok := c.TextOf("mRID"); ok {
			mrids = append(mrids, m)
		}
	}
	if !contains(mrids, "CERT-NOTIFY") {
		t.Errorf("the notified DERControlList does not carry the control that caused it (%v)", mrids)
	}
}

// TestNotificationEndpointRefusesWhatItCannotProve pins the claim helper's
// judgement. A capture claim asserts that particular frames are a test case's
// evidence, so it is made from an address the DUT itself published and from
// nothing else.
func TestNotificationEndpointRefusesWhatItCannotProve(t *testing.T) {
	for uri, want := range map[string]string{
		"https://69.0.0.2:8443/notif": "69.0.0.2:8443",
		"http://69.0.0.2/notif":       "69.0.0.2:80",
		"https://69.0.0.2/notif":      "69.0.0.2:443",
		"http://[fd00::2]:8443/n":     "[fd00::2]:8443",
	} {
		ep, err := notificationEndpoint(uri)
		if err != nil {
			t.Errorf("%s: %v", uri, err)
			continue
		}
		if ep.String() != want {
			t.Errorf("%s → %s, want %s", uri, ep, want)
		}
	}

	// A NAME is refused, and the refusal says why rather than resolving it.
	_, err := notificationEndpoint("https://gateway.local:8443/notif")
	if err == nil {
		t.Fatal("a hostname notificationURI was resolved into a capture claim; that rests the attribution " +
			"on this machine's DNS agreeing with the DUT's")
	}
	if !strings.Contains(err.Error(), "is a name, not an address") {
		t.Errorf("the refusal does not explain itself: %v", err)
	}

	for _, bad := range []string{"", "://nonsense", "ftp://69.0.0.2/n"} {
		if _, err := notificationEndpoint(bad); err == nil {
			t.Errorf("%q was accepted as a claimable endpoint", bad)
		}
	}
}

// TestNotificationClaimIsMadeFromTheServersRecord walks the whole leg: the DUT
// subscribes, gridsim records the notificationURI, and the check learns the
// DUT's inbound listener address from the server rather than from a
// configuration nobody supplied.
func TestNotificationClaimIsMadeFromTheServersRecord(t *testing.T) {
	s, _ := benchFixture(t, true, true)
	csip := httptest.NewServer(s.Handler())
	defer csip.Close()
	admin := httptest.NewServer(s.AdminHandler())
	defer admin.Close()

	subBody := `<Subscription xmlns="` + Namespace + `">` +
		`<subscribedResource>/edev</subscribedResource>` +
		`<notificationURI>https://69.0.0.2:8443/notif</notificationURI></Subscription>`
	resp, err := http.Post(csip.URL+"/edev/2/sub", "application/sep+xml", strings.NewReader(subBody))
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()

	rc := &certify.RunCtx{
		Case:    &certify.Case{UID: "csip-conf-v1.3::AGG-001"},
		GridSim: certify.NewAdminClient(admin.URL, http.DefaultClient),
		Targets: certify.Targets{GridSim: "127.0.0.1:11111", GridSimAdmin: admin.URL},
	}
	win := certify.NewWindow(rc.Case.UID, Suite)
	if err := rc.AttachWindow(win); err != nil {
		t.Fatal(err)
	}
	win.Open(time.Now())

	d := NewDriver(rc)
	subs := d.Subscriptions(context.Background())
	if len(subs) != 1 {
		t.Fatalf("the driver read %d subscriptions from /admin/subscriptions, want 1", len(subs))
	}
	if subs[0].NotificationURI != "https://69.0.0.2:8443/notif" {
		t.Fatalf("notificationURI = %q", subs[0].NotificationURI)
	}

	obs := &Observation{Case: rc.Case, Params: map[string]string{}}
	claimNotificationEndpoints(context.Background(), rc, d, obs)

	want := netip.MustParseAddrPort("69.0.0.2:8443")
	var found bool
	for _, c := range win.Claims() {
		if c.Remote == want {
			found = true
			if !strings.Contains(c.Note, "notificationURI") {
				t.Errorf("the claim's recorded reason does not say where the address came from: %s", c.Note)
			}
		}
	}
	if !found {
		t.Fatalf("no capture claim was made on the DUT's notification listener; claims: %v", win.Claims())
	}
	if got := obs.Param(notifyClaimParam); !strings.Contains(got, "69.0.0.2:8443") {
		t.Errorf("the run record does not name what was claimed: %q", got)
	}

	// A listener the check cannot prove an address for is reported, not guessed.
	resp2, err := http.Post(csip.URL+"/edev/3/sub", "application/sep+xml", strings.NewReader(
		`<Subscription xmlns="`+Namespace+`">`+
			`<subscribedResource>/edev/3/fsa</subscribedResource>`+
			`<notificationURI>https://gateway.local:8443/notif</notificationURI></Subscription>`))
	if err != nil {
		t.Fatal(err)
	}
	_ = resp2.Body.Close()

	obs2 := &Observation{Case: rc.Case, Params: map[string]string{}}
	claimNotificationEndpoints(context.Background(), rc, d, obs2)
	rec := obs2.Param(notifyClaimParam)
	if !strings.Contains(rec, "NOT claimed") || !strings.Contains(rec, "gateway.local") {
		t.Errorf("an unclaimable listener was not reported as unattributed: %q", rec)
	}
}

// TestFleetCapabilityIsReadableFromAdminStatus pins the probe the preflight and
// the checks use, through this suite's own AdminStatus shape rather than
// gridsim's.
func TestFleetCapabilityIsReadableFromAdminStatus(t *testing.T) {
	for _, tc := range []struct {
		name               string
		fleet, subscribe   bool
		wantFleet, wantSub bool
	}{
		{"default bench", false, false, false, false},
		{"fleet only", true, false, true, false},
		{"both", true, true, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, _ := benchFixture(t, tc.fleet, tc.subscribe)
			admin := httptest.NewServer(s.AdminHandler())
			defer admin.Close()

			rc := &certify.RunCtx{
				Case:    &certify.Case{UID: "csip-conf-v1.3::AGG-001"},
				GridSim: certify.NewAdminClient(admin.URL, http.DefaultClient),
				Targets: certify.Targets{GridSimAdmin: admin.URL},
			}
			view := NewDriver(rc).Snapshot(context.Background())
			if got := view.Status.Fleet.Enabled; got != tc.wantFleet {
				t.Errorf("status.fleet.enabled = %v, want %v", got, tc.wantFleet)
			}
			if got := view.Status.Subscription.Enabled; got != tc.wantSub {
				t.Errorf("status.subscription.enabled = %v, want %v", got, tc.wantSub)
			}
			if tc.wantFleet {
				if view.Status.Fleet.Size != gridsim.FleetSize {
					t.Errorf("status.fleet.size = %d, want %d", view.Status.Fleet.Size, gridsim.FleetSize)
				}
				if got := strings.Join(view.Status.Fleet.Devices, ","); got != "EDA1,EDA2,EDB1,EDB2" {
					t.Errorf("status.fleet.devices = %q", got)
				}
			}
		})
	}
}
