package suitecsip

// notify_test.go drives the subscription/notification criteria against a real
// in-process gridsim: the DUT's Subscription is really POSTed, the change is
// really made, and the Notification is really delivered to a listener that
// answers with a status of this test's choosing.
//
// Nothing here is synthesised except the DUT, which is the point. The criteria
// have to distinguish three things that a bundle reader must never see
// conflated, and only a real server can produce all three:
//
//	the DUT answered wrongly            → FAIL
//	the server pushed nothing           → SKIP, saying whether anyone subscribed
//	the server could not DELIVER        → SKIP naming the Notifier, never a FAIL
//
// The third is the one this file exists for. gridsim is pure Go and cannot dial
// the CSIP-mandatory cipher, so an https:// notificationURI is REFUSED — and a
// refusal recorded as "the DUT did not answer" would be a bench limitation
// reported as a device defect, on every aggregator row at once.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"csip-tls-test/internal/certify"
	"csip-tls-test/sim/gridsim"
)

// notifyBench starts gridsim with both levers on plus a listener standing in for
// the DUT's notificationURI, subscribes to subscribedResource as the DUT would,
// and returns a function that re-reads the server view after a change.
//
// answer is what the fake DUT replies to every Notification.
func notifyBench(t *testing.T, subscribedResource string, answer int) (
	admin string, refresh func() *Observation, deliveries *int64) {
	t.Helper()

	var count int64
	listener := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&count, 1)
		w.WriteHeader(answer)
	}))
	t.Cleanup(listener.Close)

	s, _ := benchFixture(t, true, true)
	csip := httptest.NewServer(s.Handler())
	t.Cleanup(csip.Close)
	adminSrv := httptest.NewServer(s.AdminHandler())
	t.Cleanup(adminSrv.Close)

	body := `<Subscription xmlns="` + Namespace + `">` +
		`<subscribedResource>` + subscribedResource + `</subscribedResource>` +
		`<limit>5</limit>` +
		`<notificationURI>` + listener.URL + `/notif</notificationURI></Subscription>`
	resp, err := http.Post(csip.URL+"/edev/2/sub", "application/sep+xml", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("gridsim answered the Subscription POST %d, want 201", resp.StatusCode)
	}

	rc := &certify.RunCtx{
		Case:    &certify.Case{UID: "csip-conf-v1.3::CORE-018"},
		GridSim: certify.NewAdminClient(adminSrv.URL, http.DefaultClient),
		Targets: certify.Targets{GridSimAdmin: adminSrv.URL},
	}
	d := NewDriver(rc)
	return adminSrv.URL, func() *Observation {
		return &Observation{Case: rc.Case, Params: map[string]string{},
			Server: d.Snapshot(context.Background())}
	}, &count
}

// change pulls the same lever touchSubscribedResources does: a rebind of a
// managed device, which rebuilds /edev and notifies its subscribers.
func change(t *testing.T, adminURL string) {
	t.Helper()
	rc := &certify.RunCtx{
		Case:    &certify.Case{},
		GridSim: certify.NewAdminClient(adminURL, http.DefaultClient),
		Targets: certify.Targets{GridSimAdmin: adminURL},
	}
	d := NewDriver(rc)
	if err := touchSubscribedResources(context.Background(), d, map[string]string{}); err != nil {
		t.Fatalf("the procedure's change could not be made: %v", err)
	}
}

func serverFinding(t *testing.T, name string, c criterion, o *Observation) Finding {
	t.Helper()
	if c.Server == nil {
		t.Fatalf("%s: criterion has no server evaluator", name)
	}
	return c.Server(&o.Server)
}

// TestNotificationAnsweredDecidesOnWhatTheDUTReplied is the criterion turning
// from a declared SKIP into a verdict, both ways.
func TestNotificationAnsweredDecidesOnWhatTheDUTReplied(t *testing.T) {
	t.Run("201 Created is conformant", func(t *testing.T) {
		admin, refresh, delivered := notifyBench(t, "/edev", http.StatusCreated)
		change(t, admin)
		if *delivered == 0 {
			t.Fatal("gridsim delivered no Notification for the changed EndDeviceList")
		}
		o := refresh()
		f := serverFinding(t, "answered", critNotificationAnswered(o, []int{201}, "seq 44"), o)
		if f.Unavailable != "" {
			t.Fatalf("the criterion declined to decide on a delivered Notification: %s", f.Unavailable)
		}
		if f.Verdict != certify.Pass {
			t.Fatalf("a DUT answering 201 produced %s: %s", f.Verdict, f.Observed)
		}
	})

	t.Run("204 fails a row Annex A seq 44 tightened", func(t *testing.T) {
		admin, refresh, _ := notifyBench(t, "/edev", http.StatusNoContent)
		change(t, admin)
		o := refresh()

		// CORE-018 accepts only 201: a 204 is a real finding about the DUT.
		f := serverFinding(t, "answered (seq 44)",
			critNotificationAnswered(o, []int{201}, "Annex A seq 44 removes the 204"), o)
		if f.Verdict != certify.Fail {
			t.Fatalf("a DUT answering 204 where seq 44 removed it produced %s: %s", f.Verdict, f.Observed)
		}
		if !strings.Contains(f.Observed, "204") {
			t.Errorf("the FAIL does not name the status the DUT sent: %s", f.Observed)
		}

		// ERR-002 keeps both, and the SAME reply must pass there. Getting this
		// backwards fails a conformant client on one row or passes a
		// non-conformant one on another.
		f = serverFinding(t, "answered (ERR-002)",
			critNotificationAnswered(o, []int{201, 204}, "ERR-002 step 3 admits either"), o)
		if f.Verdict != certify.Pass {
			t.Fatalf("204 on a row that admits it produced %s: %s", f.Verdict, f.Observed)
		}
	})
}

// TestNotificationCriteriaSkipWhenTheNotifierCannotDial is the arm that must
// never become a FAIL.
//
// gridsim's built-in notifier refuses https:// because Go's crypto/tls has no
// ECDHE-ECDSA-AES128-CCM-8. The DUT in that run was never given a Notification
// to answer, so nothing about it has been measured — and the SKIP has to say so
// AND name the lever, or the next operator reads it as a device defect.
func TestNotificationCriteriaSkipWhenTheNotifierCannotDial(t *testing.T) {
	s, _ := benchFixture(t, true, true)
	csip := httptest.NewServer(s.Handler())
	defer csip.Close()
	adminSrv := httptest.NewServer(s.AdminHandler())
	defer adminSrv.Close()

	body := `<Subscription xmlns="` + Namespace + `">` +
		`<subscribedResource>/edev</subscribedResource>` +
		`<notificationURI>https://69.0.0.2:8443/notif</notificationURI></Subscription>`
	resp, err := http.Post(csip.URL+"/edev/2/sub", "application/sep+xml", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()

	change(t, adminSrv.URL)

	rc := &certify.RunCtx{
		Case:    &certify.Case{UID: "csip-conf-v1.3::AGG-001"},
		GridSim: certify.NewAdminClient(adminSrv.URL, http.DefaultClient),
		Targets: certify.Targets{GridSimAdmin: adminSrv.URL},
	}
	o := &Observation{Case: rc.Case, Params: map[string]string{},
		Server: NewDriver(rc).Snapshot(context.Background())}

	if len(o.Server.Notifications) == 0 {
		t.Fatal("gridsim recorded no Notification attempt at all; the refusal is supposed to be logged, " +
			"because a silently dropped Notification reads on the other end as a DUT that never answered")
	}
	for name, c := range map[string]criterion{
		"pushed":   critNotificationPushed(o, "EndDeviceList", "because the row says so"),
		"answered": critNotificationAnswered(o, []int{201}, "because the row says so"),
	} {
		f := serverFinding(t, name, c, o)
		if f.Unavailable == "" {
			t.Fatalf("%s: an undeliverable Notification produced a verdict (%s: %s). A bench transport "+
				"limitation must never be reported as a finding about the DUT", name, f.Verdict, f.Observed)
		}
		for _, want := range []string{"SetNotifier", "ECDHE-ECDSA-AES128-CCM-8", "sim/server"} {
			if !strings.Contains(f.Unavailable, want) {
				t.Errorf("%s: the SKIP does not name the lever (%q): %s", name, want, f.Unavailable)
			}
		}
	}
}

// TestNotificationCriteriaSkipWhenTheFunctionSetIsOff pins the other lever, and
// the distinction between "nobody subscribed" and "nothing changed" — which is
// the difference between a row that is about the DUT and one that is not.
func TestNotificationCriteriaSkipWhenTheFunctionSetIsOff(t *testing.T) {
	_, off := benchObservation(t, false, false)
	f := serverFinding(t, "answered (subscription lever off)",
		critNotificationAnswered(off, []int{201}, "why"), off)
	if f.Unavailable == "" {
		t.Fatalf("with no function set served the criterion produced %s: %s", f.Verdict, f.Observed)
	}
	if !strings.Contains(f.Unavailable, "-subscription") {
		t.Errorf("the SKIP does not name the flag: %s", f.Unavailable)
	}

	// Function set on, nobody subscribed: a different sentence entirely.
	_, on := benchObservation(t, true, true)
	f = serverFinding(t, "answered (nobody subscribed)",
		critNotificationAnswered(on, []int{201}, "why"), on)
	if f.Unavailable == "" {
		t.Fatalf("with no subscription the criterion produced %s: %s", f.Verdict, f.Observed)
	}
	if !strings.Contains(f.Unavailable, "holds no Subscription") {
		t.Errorf("the SKIP does not distinguish 'nobody subscribed' from 'nothing changed': %s", f.Unavailable)
	}
}

// TestCancellationCriterionReadsTheStatusOneNotification covers CORE-019 step 11
// and ERR-002 step 5, and the lever this suite pulls for them.
func TestCancellationCriterionReadsTheStatusOneNotification(t *testing.T) {
	admin, refresh, _ := notifyBench(t, "/edev", http.StatusCreated)

	// Before the cancel there is no status=1 Notification, and the criterion
	// must say so rather than borrowing the ordinary ones' verdict.
	change(t, admin)
	o := refresh()
	f := serverFinding(t, "cancelled (lever not pulled)", critNotificationCancelled(o, []int{201}), o)
	if f.Unavailable == "" {
		t.Fatalf("with no cancellation sent the criterion produced %s: %s", f.Verdict, f.Observed)
	}
	if !strings.Contains(f.Unavailable, "/admin/subscriptions") {
		t.Errorf("the SKIP does not name the lever: %s", f.Unavailable)
	}

	// Pull it, through the same helper the rows use.
	rc := &certify.RunCtx{
		Case:    &certify.Case{},
		GridSim: certify.NewAdminClient(admin, http.DefaultClient),
		Targets: certify.Targets{GridSimAdmin: admin},
	}
	params := map[string]string{}
	if err := cancelOneSubscription(context.Background(), NewDriver(rc), params); err != nil {
		t.Fatalf("cancel: %v", err)
	}
	if params[cancelledSub] == "" {
		t.Error("the cancellation did not record which subscription it was about")
	}

	o = refresh()
	f = serverFinding(t, "cancelled (answered 201)", critNotificationCancelled(o, []int{201}), o)
	if f.Unavailable != "" {
		t.Fatalf("after the cancellation the criterion still declines: %s", f.Unavailable)
	}
	if f.Verdict != certify.Pass {
		t.Fatalf("a DUT answering the status=1 Notification 201 produced %s: %s", f.Verdict, f.Observed)
	}
}

// TestChangeLeverRefusesRatherThanInventingANotification pins the honest
// failure of the post-subscription change: with nobody subscribed there is
// nothing whose change would be notified, and the hook says that instead of
// mutating the bench for no reason.
func TestChangeLeverRefusesRatherThanInventingANotification(t *testing.T) {
	s, _ := benchFixture(t, true, true)
	adminSrv := httptest.NewServer(s.AdminHandler())
	defer adminSrv.Close()
	rc := &certify.RunCtx{
		Case:    &certify.Case{},
		GridSim: certify.NewAdminClient(adminSrv.URL, http.DefaultClient),
		Targets: certify.Targets{GridSimAdmin: adminSrv.URL},
	}
	err := touchSubscribedResources(context.Background(), NewDriver(rc), map[string]string{})
	if err == nil {
		t.Fatal("the change hook mutated the bench with no subscriber to notify")
	}
	if !strings.Contains(err.Error(), "holds no Subscription") {
		t.Errorf("the refusal does not say why: %v", err)
	}
}

// TestFleetRebindIsRestored guards the shared bench. A device left detached
// would be missing from the EndDeviceList of every test case that follows, and
// those cases would report it as a DUT finding.
func TestFleetRebindIsRestored(t *testing.T) {
	s, _ := benchFixture(t, true, true)
	adminSrv := httptest.NewServer(s.AdminHandler())
	defer adminSrv.Close()
	rc := &certify.RunCtx{
		Case:    &certify.Case{},
		GridSim: certify.NewAdminClient(adminSrv.URL, http.DefaultClient),
		Targets: certify.Targets{GridSimAdmin: adminSrv.URL},
	}
	d := NewDriver(rc)
	ctx := context.Background()

	before := d.Fleet(ctx)
	if len(before) != gridsim.FleetSize {
		t.Fatalf("the bench serves %d managed devices, want %d", len(before), gridsim.FleetSize)
	}
	if err := d.RebindDevice(ctx, before[len(before)-1].Name, "-"); err != nil {
		t.Fatal(err)
	}
	detached := 0
	for _, dev := range d.Fleet(ctx) {
		if dev.ManagedBy == "" {
			detached++
		}
	}
	if detached != 1 {
		t.Fatalf("%d device(s) detached, want 1 — the lever MAINT-001 uses did not take", detached)
	}

	restoreFleetBinding(ctx, d)
	for _, dev := range d.Fleet(ctx) {
		if dev.ManagedBy == "" {
			t.Errorf("%s is still detached after cleanup; every later test case would see a short "+
				"EndDeviceList and report it as a DUT finding", dev.Name)
		}
	}
}
