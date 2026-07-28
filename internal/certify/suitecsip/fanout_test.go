package suitecsip

// fanout_test.go drives the criteria that stopped being declared SKIPs when the
// bench grew the Figure-15 fleet and the Subscription/Notification function set.
//
// Every one of them is exercised on all three arms, because the three are what
// the change is FOR and confusing any two of them is the failure mode:
//
//	PASS         the fixture is served and the DUT did what the row states.
//	FAIL         the fixture is served and the DUT did not. This is the arm the
//	             re-scope exists to be able to reach — a short fan-out, an
//	             ignored subscription — and until this file it was unreachable.
//	unavailable  the LEVER IS OFF. Never a FAIL: what the simulator serves is a
//	             fact about the bench, and a false FAIL on a bench gap is the
//	             worst outcome available here because it looks like diligence.
//
// The device LFDIs are taken from a REAL in-process gridsim rather than written
// out here. They are derived by the simulator (SHA-256 over a documented
// preimage), so a hand-written fixture would share this file's guess about them
// with nothing, and the criteria would pass against a bench that serves other
// values entirely.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"csip-tls-test/internal/certify"
	"csip-tls-test/sim/gridsim"
)

// benchObservation starts an in-process gridsim with the levers on and returns
// the Observation a check's citation phase would be handed, with the server view
// really read back through the suite's own Driver.
func benchObservation(t *testing.T, fleet, subscription bool) (*gridsim.Server, *Observation) {
	t.Helper()
	s, _ := benchFixture(t, fleet, subscription)
	admin := httptest.NewServer(s.AdminHandler())
	t.Cleanup(admin.Close)

	rc := &certify.RunCtx{
		Case:    &certify.Case{UID: "csip-conf-v1.3::AGG-003"},
		GridSim: certify.NewAdminClient(admin.URL, http.DefaultClient),
		Targets: certify.Targets{GridSimAdmin: admin.URL},
	}
	view := NewDriver(rc).Snapshot(context.Background())
	return s, &Observation{Case: rc.Case, Params: map[string]string{}, Server: view}
}

// deviceResponse is the Response POST an aggregator sends on behalf of one
// managed EndDevice: the same shape as responsePOST, with the endDeviceLFDI
// that makes it attributable to a device.
func deviceResponse(lfdi, mrid string, status int) Exchange {
	return post("/rsps/0/r", `<DERControlResponse xmlns="`+Namespace+`">`+
		`<endDeviceLFDI>`+lfdi+`</endDeviceLFDI>`+
		`<subject>`+mrid+`</subject><status>`+itoa(int64(status))+`</status></DERControlResponse>`, 201)
}

// lfdiOf reads a managed device's LFDI out of the observation, failing the test
// rather than silently comparing against "".
func lfdiOf(t *testing.T, o *Observation, name string) string {
	t.Helper()
	d, ok := o.Server.FleetDeviceNamed(name)
	if !ok || d.LFDI == "" {
		t.Fatalf("gridsim's /admin/fleet reports no LFDI for %s; the fixture and the evaluator disagree "+
			"about what the fleet is", name)
	}
	return d.LFDI
}

// TestResponseFanOutFailsAShortFanOut is the single most important test in this
// file, and it is the one the whole re-scope was blocked on.
//
// AGG-003 states its Response bullet for EDA1 AND EDA2. An aggregator that
// answered for one of them is non-conformant, and before the fleet existed this
// criterion could only ever report SKIP — which reads, to anyone scanning a
// bundle, exactly like "nothing to see here".
func TestResponseFanOutFailsAShortFanOut(t *testing.T) {
	_, o := benchObservation(t, true, true)
	eda1, eda2 := lfdiOf(t, o, "EDA1"), lfdiOf(t, o, "EDA2")

	f := aggFanOut{
		What: "the full Response lifecycle is POSTed for the TFA event", Devices: "EDA1 and EDA2",
		Names: edaPair, MRID: "CERT-AGG003", Statuses: []int{1, 2, 3},
	}
	c := critResponseFanOut(o, f)

	// Both devices, every status: the row's bullet is satisfied.
	full := synthTranscript(
		deviceResponse(eda1, "CERT-AGG003", 1), deviceResponse(eda1, "CERT-AGG003", 2),
		deviceResponse(eda1, "CERT-AGG003", 3),
		deviceResponse(eda2, "CERT-AGG003", 1), deviceResponse(eda2, "CERT-AGG003", 2),
		deviceResponse(eda2, "CERT-AGG003", 3),
	)
	got := wantVerdict(t, "fan-out (both devices, full lifecycle)", c, full, certify.Pass)
	if !strings.Contains(got.Observed, "EDA1 and EDA2") {
		t.Errorf("the PASS does not name the devices it is about: %s", got.Observed)
	}

	// EDA1 only. THIS is the finding, and it must be a FAIL with both counts.
	short := synthTranscript(
		deviceResponse(eda1, "CERT-AGG003", 1), deviceResponse(eda1, "CERT-AGG003", 2),
		deviceResponse(eda1, "CERT-AGG003", 3),
	)
	got = wantVerdict(t, "fan-out (one of two devices answered)", c, short, certify.Fail)
	for _, want := range []string{"1 of the 2", "EDA2"} {
		if !strings.Contains(got.Observed, want) {
			t.Errorf("the FAIL does not cite %q, so a reader cannot see how short the fan-out was: %s",
				want, got.Observed)
		}
	}

	// A gateway that answers under its OWN LFDI rather than the managed
	// devices' is the realistic shape of the failure, and it must not be
	// mistaken for silence.
	ownLFDI := synthTranscript(
		deviceResponse(benchLFDI, "CERT-AGG003", 1), deviceResponse(benchLFDI, "CERT-AGG003", 2),
	)
	got = wantVerdict(t, "fan-out (aggregator answered under its own LFDI)", c, ownLFDI, certify.Fail)
	if !strings.Contains(got.Observed, "none of the named devices") {
		t.Errorf("the FAIL does not report the stranger LFDIs it saw: %s", got.Observed)
	}

	// Both devices present but the window ended before status 3: a MEASUREMENT,
	// not a finding, exactly as critEventLifecycle already treats it.
	partial := synthTranscript(
		deviceResponse(eda1, "CERT-AGG003", 1), deviceResponse(eda1, "CERT-AGG003", 2),
		deviceResponse(eda2, "CERT-AGG003", 1), deviceResponse(eda2, "CERT-AGG003", 2),
	)
	got = wantVerdict(t, "fan-out (both devices, window shorter than the event)", c, partial, certify.Warn)
	if !strings.Contains(got.Observed, waitParam) {
		t.Errorf("the WARN does not tell the operator how to close it out: %s", got.Observed)
	}

	// Silence is not evidence of anything.
	wantUnavailable(t, "fan-out (no Response at all)", c, synthTranscript())
}

// TestResponseFanOutSkipsWhenTheFleetLeverIsOff is the other half of the same
// principle: with gridsim serving one EndDevice there are no per-device LFDIs
// to group by, and the criterion must decline rather than fail the DUT for it.
func TestResponseFanOutSkipsWhenTheFleetLeverIsOff(t *testing.T) {
	_, o := benchObservation(t, false, false)
	c := critResponseFanOut(o, aggFanOut{
		What: "the full Response lifecycle is POSTed", Devices: "EDA1 and EDA2",
		Names: edaPair, MRID: "CERT-AGG003", Statuses: []int{1, 2, 3},
	})

	// Even with Responses on the wire — a DUT doing everything right — the
	// answer is "we could not tell", because we cannot say whose they are.
	tr := synthTranscript(
		deviceResponse("AABB", "CERT-AGG003", 1), deviceResponse("CCDD", "CERT-AGG003", 1))
	reason := wantUnavailable(t, "fan-out (fleet lever off)", c, tr)
	for _, want := range []string{"EDA1", "-fleet 4", "SIM_FLEET=4"} {
		if !strings.Contains(reason, want) {
			t.Errorf("the SKIP does not name the lever (%q): %s", want, reason)
		}
	}
}

// TestNoResponseFanOutNeedsEvidenceOfAbsence pins AGG-003's untagged negative
// bullet, "Client fails if EDB1 and/or EDB2 POSTs any responses to the TFA
// event", and the trap in every absence claim: a silent window supports it
// vacuously.
func TestNoResponseFanOutNeedsEvidenceOfAbsence(t *testing.T) {
	_, o := benchObservation(t, true, true)
	eda1 := lfdiOf(t, o, "EDA1")
	edb1 := lfdiOf(t, o, "EDB1")

	c := critNoResponseFanOut(o, aggFanOut{
		What: "NO Response is POSTed for the TFA event", Devices: "EDB1 and EDB2",
		Names: edbPair, MRID: "CERT-AGG003", Absent: true,
	})

	wantUnavailable(t, "negative fan-out (nobody answered at all)", c, synthTranscript())

	inScopeOnly := synthTranscript(
		deviceResponse(eda1, "CERT-AGG003", 1), deviceResponse(eda1, "CERT-AGG003", 2))
	wantVerdict(t, "negative fan-out (only in-scope devices answered)", c, inScopeOnly, certify.Pass)

	leaked := synthTranscript(
		deviceResponse(eda1, "CERT-AGG003", 1), deviceResponse(edb1, "CERT-AGG003", 1))
	got := wantVerdict(t, "negative fan-out (an out-of-scope device answered)", c, leaked, certify.Fail)
	if !strings.Contains(got.Observed, "EDB1") {
		t.Errorf("the FAIL does not name the device that answered when it should not have: %s", got.Observed)
	}
}

// TestForbiddenStatusIsDecisive covers the half of the precedence bullets that
// has no other wire artefact: AGG-007's EDB1/EDB2 are outside the TFA program,
// so the SY control "is executed normally" for them — which means their
// Responses are 2 and 3 and never 14.
//
// A forbidden status is checked BEFORE the completeness of the wanted ones,
// because it is a statement about what the DUT DID and no short window excuses
// it.
func TestForbiddenStatusIsDecisive(t *testing.T) {
	_, o := benchObservation(t, true, true)
	edb1, edb2 := lfdiOf(t, o, "EDB1"), lfdiOf(t, o, "EDB2")

	c := critResponseFanOut(o, aggFanOut{
		What: "the SY DERControl is executed normally, with no supersession status",
		Devices: "EDB1 and EDB2", Names: edbPair, MRID: "CERT-AGG007SY",
		Statuses: []int{2, 3}, Forbidden: []int{7, 14},
	})

	clean := synthTranscript(
		deviceResponse(edb1, "CERT-AGG007SY", 2), deviceResponse(edb1, "CERT-AGG007SY", 3),
		deviceResponse(edb2, "CERT-AGG007SY", 2), deviceResponse(edb2, "CERT-AGG007SY", 3),
	)
	wantVerdict(t, "forbidden (none present)", c, clean, certify.Pass)

	// A status 14 from a device outside the superseding program: the row says
	// this is wrong, and an incomplete window must not excuse it.
	dirty := synthTranscript(
		deviceResponse(edb1, "CERT-AGG007SY", 2), deviceResponse(edb1, "CERT-AGG007SY", 14),
	)
	got := wantVerdict(t, "forbidden (status 14 from an out-of-program device)", c, dirty, certify.Fail)
	if !strings.Contains(got.Observed, "EDB1 reported status 14") {
		t.Errorf("the FAIL does not say who reported what: %s", got.Observed)
	}
}

// TestPerDeviceResourceWalksEachDevicesOwnSubTree covers UTIL-002's and
// UTIL-003's fan-out, which is a WALK rather than an acknowledgment: the
// aggregator has to reach each managed EndDevice's own resources.
func TestPerDeviceResourceWalksEachDevicesOwnSubTree(t *testing.T) {
	_, o := benchObservation(t, true, true)
	href := func(name string) string {
		d, _ := o.Server.FleetDeviceNamed(name)
		return d.Href
	}

	c := critPerDeviceResource(o, "the aggregator GETs that device's FunctionSetAssignments",
		"EDA1, EDA2, EDB1 and EDB2", managedDevices, "GET", []string{"/fsa"})

	all := synthTranscript(
		get(href("EDA1")+"/fsa", 200, ""), get(href("EDA2")+"/fsa/0", 200, ""),
		get(href("EDB1")+"/fsa", 200, ""), get(href("EDB2")+"/fsa/0/derp", 200, ""),
	)
	wantVerdict(t, "per-device walk (all four reached)", c, all, certify.Pass)

	two := synthTranscript(get(href("EDA1")+"/fsa", 200, ""), get(href("EDA2")+"/fsa", 200, ""))
	got := wantVerdict(t, "per-device walk (only the EDA pair reached)", c, two, certify.Fail)
	for _, want := range []string{"2 of the 4", "EDB1, EDB2"} {
		if !strings.Contains(got.Observed, want) {
			t.Errorf("the FAIL does not cite %q: %s", want, got.Observed)
		}
	}

	// The DUT never walked a managed device at all. That is not evidence it
	// refuses to — it may simply not have got that far in this window.
	wantUnavailable(t, "per-device walk (nothing reached)", c,
		synthTranscript(get("/dcap", 200, ""), get("/edev", 200, "")))
}
