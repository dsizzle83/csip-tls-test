package suitecsip

// rehome_flow_test.go drives CORE-014's re-home flow against a REAL in-process
// gridsim, the same sim-backed pattern notify_test.go and fleetbench_test.go
// use: nothing about the SERVER side is synthesised. What stands in for the
// DUT is a plain PUT to whatever href the server's DERList currently
// advertises — a real DUT's own behaviour is out of scope for this suite's
// unit tests (there is no cgo/mTLS stack here), but the SERVER's half of the
// mechanism — the lever moving the hrefs, the DERList advertising the new
// ones, the old ones 404ing, and gridsim's admin log correctly attributing a
// PUT made to the NEW href — is exactly what this test exercises for real.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"csip-tls-test/internal/certify"
	"csip-tls-test/sim/gridsim"
)

// rehomeFlowBench starts a gridsim (CSIP + admin listeners) and a Driver
// wired to it, mirroring notifyBench in notify_test.go.
func rehomeFlowBench(t *testing.T) (csipURL string, d *Driver) {
	t.Helper()
	s := gridsim.NewServer("")
	csip := httptest.NewServer(s.Handler())
	t.Cleanup(csip.Close)
	admin := httptest.NewServer(s.AdminHandler())
	t.Cleanup(admin.Close)

	rc := &certify.RunCtx{
		Case:    &certify.Case{UID: "csip-conf-v1.3::CORE-014"},
		GridSim: certify.NewAdminClient(admin.URL, http.DefaultClient),
		Targets: certify.Targets{GridSimAdmin: admin.URL},
	}
	return csip.URL, NewDriver(rc)
}

// TestCORE014Flow_RehomeThenPUTToNewHrefIsObserved is the deliverable's
// end-to-end proof: Driver.RehomeDER moves the hrefs, a PUT to the NEW ones
// is accepted and attributed by gridsim's admin log to the NEW path, and the
// same ServerView-tier evaluator CORE-014's criteria use (critDERPut) grades
// it a PASS — i.e. "Grade the PUT assertions against the post-re-home
// window" actually happens, not just "the lever exists".
func TestCORE014Flow_RehomeThenPUTToNewHrefIsObserved(t *testing.T) {
	ctx := context.Background()
	csipURL, d := rehomeFlowBench(t)

	baseline := d.Snapshot(ctx)
	if got := baseline.PutsFor("DERCapability"); len(got) != 0 {
		t.Fatalf("baseline already carries a DERCapability PUT: %+v", got)
	}

	capHref, setHref, err := d.RehomeDER(ctx)
	if err != nil {
		t.Fatalf("RehomeDER: %v", err)
	}
	if capHref == "/edev/2/der/0/dercap" || setHref == "/edev/2/der/0/derset" {
		t.Fatalf("RehomeDER did not move the hrefs: cap=%s set=%s", capHref, setHref)
	}

	// The DUT's next discovery walk would read these NEW hrefs straight out of
	// the DERList gridsim now serves — confirm that is really true before
	// simulating the PUT a walk would cause.
	resp, err := http.Get(csipURL + "/edev/2/der")
	if err != nil {
		t.Fatalf("GET /edev/2/der: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /edev/2/der = %d, want 200", resp.StatusCode)
	}

	// Simulate the DUT's on-change PUTs, to the NEW hrefs.
	capBody := `<DERCapability xmlns="urn:ieee:std:2030.5:ns"><type>80</type>` +
		`<rtgMaxW><multiplier>0</multiplier><value>10000</value></rtgMaxW></DERCapability>`
	setBody := `<DERSettings xmlns="urn:ieee:std:2030.5:ns"><setMaxW><multiplier>0</multiplier>` +
		`<value>8000</value></setMaxW></DERSettings>`
	doPUT(t, csipURL+capHref, capBody)
	doPUT(t, csipURL+setHref, setBody)

	after := d.Snapshot(ctx)
	view := after.Since(baseline)

	capPuts := view.PutsFor("DERCapability")
	if len(capPuts) != 1 {
		t.Fatalf("PutsFor(DERCapability) after re-home = %+v, want exactly 1", capPuts)
	}
	if capPuts[0].Path != capHref {
		t.Errorf("the recorded PUT's path = %q, want the NEW href %q", capPuts[0].Path, capHref)
	}
	setPuts := view.PutsFor("DERSettings")
	if len(setPuts) != 1 {
		t.Fatalf("PutsFor(DERSettings) after re-home = %+v, want exactly 1", setPuts)
	}
	if setPuts[0].Path != setHref {
		t.Errorf("the recorded PUT's path = %q, want the NEW href %q", setPuts[0].Path, setHref)
	}

	// The exact evaluator CORE-014's Criteria list uses (core.go) must grade
	// this a PASS from the ServerView tier.
	if f := critDERPut("DERCapability").Server(&view); f.Verdict != certify.Pass {
		t.Errorf("critDERPut(DERCapability).Server on the post-re-home window = %s (%s)", f.Verdict, f.Observed)
	}
	if f := critDERPut("DERSettings").Server(&view); f.Verdict != certify.Pass {
		t.Errorf("critDERPut(DERSettings).Server on the post-re-home window = %s (%s)", f.Verdict, f.Observed)
	}

	// The OLD hrefs are gone: a walk that (incorrectly) still remembered them
	// would find nothing, which is the whole point of moving the resource
	// rather than merely change-flagging it in place.
	oldResp, err := http.Get(csipURL + "/edev/2/der/0/dercap")
	if err != nil {
		t.Fatalf("GET the old DERCapability href: %v", err)
	}
	_ = oldResp.Body.Close()
	if oldResp.StatusCode != http.StatusNotFound {
		t.Errorf("GET the OLD DERCapability href = %d, want 404", oldResp.StatusCode)
	}
}

// TestCORE014Flow_RehomeNoteCarriesTimeAndHrefs proves the bundle-narrative
// deliverable: after a Change hook stashes rehome_at/rehome_cap_href/
// rehome_set_href in an Observation's Params (exactly as coreDERSettings's and
// coreAdvancedEndDevice's Change closures do in core.go), rehomeNote produces
// prose naming the scripted action, its time, both new hrefs, and CSIP IG
// §6.3.5.2 — so a reader of the evidence bundle cannot mistake the PUTs that
// follow for a spontaneous DUT event.
func TestCORE014Flow_RehomeNoteCarriesTimeAndHrefs(t *testing.T) {
	o := &Observation{Params: map[string]string{
		"rehome_at":       "2026-07-30T12:00:00Z",
		"rehome_cap_href": "/edev/2/der/0/g1/dercap",
		"rehome_set_href": "/edev/2/der/0/g1/derset",
	}}
	note := rehomeNote(o)
	for _, want := range []string{
		"2026-07-30T12:00:00Z", "/edev/2/der/0/g1/dercap", "/edev/2/der/0/g1/derset",
		"6.3.5.2", "TEST SERVER", "scripted",
	} {
		if !strings.Contains(note, want) {
			t.Errorf("rehomeNote is missing %q: %s", want, note)
		}
	}

	// No rehome_at means the Change hook never ran (no gridsim, or it failed):
	// the note must be silent rather than printing empty hrefs.
	if got := rehomeNote(&Observation{Params: map[string]string{}}); got != "" {
		t.Errorf("rehomeNote with no rehome_at should be empty, got %q", got)
	}
}

// doPUT issues a live PUT with body against url and requires a 204 — the
// real HTTP round trip a fixture *http.Request (see siblings_test.go's
// mustPUT) does not make.
func doPUT(t *testing.T, url, body string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPut, url, strings.NewReader(body))
	if err != nil {
		t.Fatalf("build PUT %s: %v", url, err)
	}
	req.Header.Set("Content-Type", "application/sep+xml")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("PUT %s: %v", url, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("PUT %s = %d, want 204", url, resp.StatusCode)
	}
}
