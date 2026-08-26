package certify

// preflight_evidence_test.go pins a check whose entire value is that it fires
// in a run's first second.
//
// Every refusal below corresponds to a way a COMM-004 trace cannot exist, and
// the campaign that produced audit finding LAB29-011 hit one of them — gridsim
// started without -no-tickets — and did not find out until RPT-060, the last row
// of the last document, tried to assemble a submission out of eight windows
// full of resumed sessions.

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// evidenceAdmin stands up a gridsim admin API answering /admin/status with the
// given TLS posture. A nil tls omits the key entirely, which is what a gridsim
// built before Server.SetTLSPosture answers — a different fact from a posture
// reported false, and the check has to tell them apart.
func evidenceAdmin(t *testing.T, pollRateS int, tls map[string]any) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/admin/status" {
			http.NotFound(w, r)
			return
		}
		body := map[string]any{
			"programs": []any{}, "server_time": 1, "pid": 4242,
			"data_plane": "127.0.0.1:11113", "poll_rate_s": pollRateS,
		}
		if tls != nil {
			body["tls"] = tls
		}
		_ = json.NewEncoder(w).Encode(body)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// goodPosture is the bench posture the split-bench soak was proven under:
// GRIDSIM_NO_TICKETS=1, GRIDSIM_IDLE_S=30, GRIDSIM_POLL_S=60.
func goodPosture() map[string]any {
	return map[string]any{"no_tickets": true, "idle_timeout_s": 30}
}

// evidenceRunner builds a csip evidence run against the real catalog, with the
// generic requirements already satisfied so each test can break exactly one
// thing.
func evidenceRunner(t *testing.T, mutate func(*Options)) (*Runner, *Reporter, *bytes.Buffer) {
	t.Helper()
	opts := campaignOptions(t, CampaignCSIP)
	opts.Evidence = true
	opts.NoCapture = false
	opts.KeyLogPath = t.TempDir() + "/run.keylog"
	opts.Params = map[string]string{
		EvidenceParamCOMM004: "csip-conf-v1.3::COMM-004,csip-conf-v1.3::COMM-004A",
	}
	if mutate != nil {
		mutate(&opts)
	}
	r, err := New(suitesForCampaigns(t), realCatalog(t), opts)
	if err != nil {
		t.Fatal(err)
	}
	var console bytes.Buffer
	return r, NewReporter(&console), &console
}

// wantRefusal runs the preflight and asserts the message names each fragment.
func wantRefusal(t *testing.T, r *Runner, rep *Reporter, want ...string) {
	t.Helper()
	err := r.preflightEvidence(context.Background(), rep, r.Plan())
	if err == nil {
		t.Fatal("preflightEvidence accepted a bench that cannot produce the artefact")
	}
	for _, w := range want {
		if !strings.Contains(err.Error(), w) {
			t.Errorf("the refusal does not mention %q:\n%v", w, err)
		}
	}
}

// ── the invocation ────────────────────────────────────────────────────────

// -evidence is a MODIFIER on a campaign. An exploratory run is marked NOT
// GATING whatever its bench looked like, so there is nothing for the claim to
// attach to — and a word in a bundle with no consequence is worse than no word.
func TestEvidenceRequiresACampaign(t *testing.T) {
	opts, _ := baseOptions(t, nil)
	opts.Evidence = true
	_, err := New(suitesForCampaigns(t), realCatalog(t), opts)
	if err == nil {
		t.Fatal("New() accepted -evidence with no -campaign")
	}
	if !strings.Contains(err.Error(), "-evidence requires -campaign") {
		t.Errorf("the refusal does not say what is wrong: %v", err)
	}
}

func TestEvidenceRefusesARunWithNoCapture(t *testing.T) {
	r, rep, _ := evidenceRunner(t, func(o *Options) { o.NoCapture = true })
	wantRefusal(t, r, rep, "-no-capture", "exported from it")
}

func TestEvidenceRefusesARunWithNoKeylog(t *testing.T) {
	r, rep, _ := evidenceRunner(t, func(o *Options) { o.KeyLogPath = "" })
	wantRefusal(t, r, rep, "-keylog", "cannot be decrypted")
}

// ── the scenarios ─────────────────────────────────────────────────────────

func TestEvidenceRefusesUnnamedCOMM004Scenarios(t *testing.T) {
	r, rep, _ := evidenceRunner(t, func(o *Options) { o.Params = map[string]string{} })
	wantRefusal(t, r, rep, EvidenceParamCOMM004, "Chapter 5", "RPT-060")
}

// A uid this run will not execute produces no frames, so its trace cannot be
// written however well the bench is posed. Catching it here is the difference
// between a typo costing a second and a typo costing a campaign.
func TestEvidenceRefusesAScenarioThisRunWillNotExecute(t *testing.T) {
	r, rep, _ := evidenceRunner(t, func(o *Options) {
		o.Params = map[string]string{EvidenceParamCOMM004: "csip-conf-v1.3::COMM-004Z"}
	})
	wantRefusal(t, r, rep, "COMM-004Z", "produces no frames")
}

func TestEvidenceRefusesAScenarioFromAnotherFamily(t *testing.T) {
	r, rep, _ := evidenceRunner(t, func(o *Options) {
		o.Params = map[string]string{EvidenceParamCOMM004: "csip-conf-v1.3::COMM-002"}
	})
	wantRefusal(t, r, rep, "COMM-002", "not a COMM-004 scenario")
}

// ── the bench posture ─────────────────────────────────────────────────────

func TestEvidenceRefusesABenchWithNoAdminAPI(t *testing.T) {
	r, rep, _ := evidenceRunner(t, func(o *Options) { o.Targets.GridSimAdmin = "" })
	wantRefusal(t, r, rep, "-gridsim-admin", "RFC 5077")
}

// UNREPORTED is not FALSE. A gridsim that publishes no posture is an old
// binary or another server entirely; either way the precondition is UNPROVEN,
// and an unproven precondition is what produced the failure this check exists
// to prevent.
func TestEvidenceRefusesAGridsimThatPublishesNoPosture(t *testing.T) {
	admin := evidenceAdmin(t, 60, nil)
	r, rep, _ := evidenceRunner(t, func(o *Options) { o.Targets.GridSimAdmin = admin.URL })
	wantRefusal(t, r, rep, "publishes no TLS posture", "UNPROVEN", "4242")
}

// The headline case: the one the audit found.
func TestEvidenceRefusesABenchIssuingSessionTickets(t *testing.T) {
	admin := evidenceAdmin(t, 60, map[string]any{"no_tickets": false, "idle_timeout_s": 30})
	r, rep, _ := evidenceRunner(t, func(o *Options) { o.Targets.GridSimAdmin = admin.URL })
	wantRefusal(t, r, rep, "no_tickets=false", "RFC 5077", "-no-tickets", "GRIDSIM_NO_TICKETS=1")
}

func TestEvidenceRefusesABenchThatNeverClosesAnIdleConnection(t *testing.T) {
	admin := evidenceAdmin(t, 60, map[string]any{"no_tickets": true, "idle_timeout_s": 0})
	r, rep, _ := evidenceRunner(t, func(o *Options) { o.Targets.GridSimAdmin = admin.URL })
	wantRefusal(t, r, rep, "idle_timeout_s=0", "ONE session", "GRIDSIM_IDLE_S=30")
}

// Without a uniform advertised pollRate there is no single boundary between one
// scenario's session and the next to hold the idle timeout against — and the
// built-ins would pace a poll_rate_mode=honor DUT's whole walk at 900 s anyway.
func TestEvidenceRefusesABenchWithNoUniformPollRate(t *testing.T) {
	admin := evidenceAdmin(t, 0, goodPosture())
	r, rep, _ := evidenceRunner(t, func(o *Options) { o.Targets.GridSimAdmin = admin.URL })
	wantRefusal(t, r, rep, "poll_rate_s=0", "900", "GRIDSIM_POLL_S=60")
}

// The timeout has to fire INSIDE the cadence. At or above it, the DUT's
// connection is still open when the next scenario's window opens.
func TestEvidenceRefusesAnIdleTimeoutAtOrAboveThePollCadence(t *testing.T) {
	for _, idle := range []int{60, 120} {
		admin := evidenceAdmin(t, 60, map[string]any{"no_tickets": true, "idle_timeout_s": idle})
		r, rep, _ := evidenceRunner(t, func(o *Options) { o.Targets.GridSimAdmin = admin.URL })
		wantRefusal(t, r, rep, "must fire INSIDE the poll cadence", "30 s idle against a 60 s pollRate")
	}
}

// ── the passing case, and the no-op case ──────────────────────────────────

func TestEvidenceAcceptsTheProvenBenchPosture(t *testing.T) {
	admin := evidenceAdmin(t, 60, goodPosture())
	r, rep, console := evidenceRunner(t, func(o *Options) { o.Targets.GridSimAdmin = admin.URL })
	if err := r.preflightEvidence(context.Background(), rep, r.Plan()); err != nil {
		t.Fatalf("the proven bench posture was refused: %v", err)
	}
	// A passing precondition that says nothing is a precondition nobody can
	// audit afterwards.
	for _, want := range []string{"no session tickets", "30 s", "60 s pollRate", "2 COMM-004 scenario"} {
		if !strings.Contains(console.String(), want) {
			t.Errorf("the console does not record %q:\n%s", want, console)
		}
	}
}

// A campaign with no additional evidence contract keeps the generic
// requirements and says out loud that it claims nothing further, rather than
// implying a proof it did not make.
func TestEvidenceOnACampaignWithNoContractClaimsNothingFurther(t *testing.T) {
	opts := campaignOptions(t, CampaignModbusClient)
	opts.Evidence = true
	opts.NoCapture = false
	opts.KeyLogPath = t.TempDir() + "/run.keylog"
	r, err := New(suitesForCampaigns(t), realCatalog(t), opts)
	if err != nil {
		t.Fatal(err)
	}
	var console bytes.Buffer
	rep := NewReporter(&console)
	if err := r.preflightEvidence(context.Background(), rep, r.Plan()); err != nil {
		t.Fatalf("preflightEvidence = %v", err)
	}
	if !strings.Contains(console.String(), "no contract beyond the capture and the key log") {
		t.Errorf("the console does not say what was and was not proven:\n%s", &console)
	}
}

// Without -evidence the check does nothing at all, even against a bench that
// would fail every rule above. A run that did not ask for the claim must behave
// exactly as it did before this file existed.
func TestWithoutEvidenceTheCheckIsANoOp(t *testing.T) {
	admin := evidenceAdmin(t, 0, map[string]any{"no_tickets": false, "idle_timeout_s": 0})
	r, rep, console := evidenceRunner(t, func(o *Options) {
		o.Evidence = false
		o.NoCapture = true
		o.KeyLogPath = ""
		o.Params = map[string]string{}
		o.Targets.GridSimAdmin = admin.URL
	})
	if err := r.preflightEvidence(context.Background(), rep, r.Plan()); err != nil {
		t.Fatalf("preflightEvidence refused a run that never claimed the evidence posture: %v", err)
	}
	if console.String() != "" {
		t.Errorf("a run with no -evidence produced evidence-preflight output:\n%s", console)
	}
}
