package certify

// campaign_test.go pins the closed selection, the flag combinations a campaign
// refuses, and the zero-selection refusal.
//
// The fixtures here use the REAL catalog and a registry that mirrors the real
// suite-per-document map, because a campaign's whole content is which rows it
// selects and a miniature catalog cannot answer that. The mapping itself is held
// against the linked suites in internal/certify/suites/campaign_test.go, which
// is the one package that can import both.

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// docSuites mirrors internal/certify/suites' own registration map: which suite
// owns each catalog document. TestSuiteDocumentMapMatchesTheLinkedSuites (in
// package suites) holds it against the real registrations.
var docSuites = map[string]string{
	"CSIP-CONF-v1.3":             "csip",
	"LOCAL-EXT-v1":               "csip",
	"SSM-CONF-v0.8":              "ssm",
	"SS-MODBUS-CONF-v1.4":        "modbus-server",
	"SS-1547-TEST-v1.1":          "modbus-server",
	"SS-MODBUS-CLIENT-CONF-v1.1": "modbus-client",
	"SS-TEST-PKI":                "pki",
	"SS-CSIP-RESULTS-v1.1":       "results-report",
	"SS-MODBUS-RESULTS-v1.2":     "results-report",
}

// realCatalog loads the committed catalog: 283 rows across nine documents.
func realCatalog(t *testing.T) *Catalog {
	t.Helper()
	cat, err := Load(filepath.Join("..", "..", CatalogFile))
	if err != nil {
		t.Fatalf("load the real catalog: %v", err)
	}
	return cat
}

// suitesForCampaigns registers every catalog row under the suite that owns its
// document, with a check that does nothing. It stands in for the linked suites
// so a campaign's SELECTION can be tested here without the import cycle.
func suitesForCampaigns(t *testing.T) *Registry {
	t.Helper()
	reg := NewRegistry()
	for _, c := range realCatalog(t).All() {
		suite, ok := docSuites[c.Doc]
		if !ok {
			t.Fatalf("catalog document %q has no suite in docSuites — the map and the catalog have "+
				"diverged, and every campaign test below would silently select fewer rows", c.Doc)
		}
		reg.Register(c.UID, suite, func(ctx context.Context, rc *RunCtx) (Result, error) {
			return Skipped("fixture"), nil
		})
	}
	return reg
}

const validManifestJSON = `{
  "profile": "one-to-one-7xx-tcp",
  "topology": {"configured_der": 1, "role": "inverter", "northbound_units": [1]},
  "csip": {"role": "der-client", "end_devices": 1, "der_resources": 1},
  "secure_sunspec": {"roles": ["server"], "transport": "tls-tcp", "port": 802},
  "modbus_client": {"transport": "tcp", "device_count": 1, "generation": "7xx"},
  "authority_profiles": ["csip", "mbaps"],
  "models": [1, 701, 702, 703, 704, 705, 706, 707, 708, 709, 710, 711, 712]
}`

func writeManifest(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "candidate.json")
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func campaignOptions(t *testing.T, name Campaign) Options {
	t.Helper()
	opts, _ := baseOptions(t, nil)
	opts.Campaign = name
	opts.ManifestPath = writeManifest(t, validManifestJSON)
	return opts
}

// ── the table ─────────────────────────────────────────────────────────────

func TestCampaignTableMatchesTheAudit(t *testing.T) {
	want := map[Campaign]struct {
		suites    []string
		authority AuthorityProfile
	}{
		CampaignCSIP:         {[]string{"csip"}, AuthorityCSIP},
		CampaignMBAPS:        {[]string{"ssm", "modbus-server", "pki"}, AuthorityMBAPS},
		CampaignModbusClient: {[]string{"modbus-client"}, AuthorityAny},
	}
	got := Campaigns()
	if len(got) != len(want) {
		t.Fatalf("Campaigns() has %d entries, want %d", len(got), len(want))
	}
	for _, spec := range got {
		w, ok := want[spec.Name]
		if !ok {
			t.Errorf("unexpected campaign %q", spec.Name)
			continue
		}
		if strings.Join(spec.Suites, ",") != strings.Join(w.suites, ",") {
			t.Errorf("%s expands to %v, want %v", spec.Name, spec.Suites, w.suites)
		}
		if spec.Authority != w.authority {
			t.Errorf("%s requires authority %q, want %q", spec.Name, spec.Authority, w.authority)
		}
		if strings.TrimSpace(spec.Precondition) == "" {
			t.Errorf("%s states no precondition; the refusal message would then say only that a check "+
				"failed, not what the bench must look like", spec.Name)
		}
		if !spec.ApplicableOnly() {
			t.Errorf("%s does not imply -applicable; a campaign's subject is the rows the product "+
				"CLAIMS", spec.Name)
		}
	}
}

// ── expansion and the flags a campaign refuses ────────────────────────────

func TestCampaignExpandsToItsSuitesAndImpliesApplicable(t *testing.T) {
	opts := campaignOptions(t, CampaignMBAPS)
	r, err := New(suitesForCampaigns(t), realCatalog(t), opts)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(r.opts.Suites, ","); got != "ssm,modbus-server,pki" {
		t.Errorf("resolved suites = %q", got)
	}
	if !r.opts.ApplicableOnly {
		t.Error("a campaign did not imply -applicable")
	}
	for _, p := range r.Plan() {
		if suite := docSuites[p.Case.Doc]; suite != "ssm" && suite != "modbus-server" && suite != "pki" {
			t.Fatalf("the mbaps campaign selected %s from suite %q, which it does not own", p.Case.UID, suite)
		}
		if !p.Case.Applicable {
			t.Fatalf("the mbaps campaign selected %s, which the catalog marks inapplicable", p.Case.UID)
		}
	}
}

func TestCampaignRefusesToBeCombinedWithSuite(t *testing.T) {
	opts := campaignOptions(t, CampaignCSIP)
	opts.Suites = []string{"ssm"}
	_, err := New(suitesForCampaigns(t), realCatalog(t), opts)
	if err == nil {
		t.Fatal("New() = nil, want a refusal: -campaign and -suite are different selections")
	}
	if !strings.Contains(err.Error(), "-suite") {
		t.Errorf("error does not name the conflict:\n%v", err)
	}
}

func TestCampaignRequiresAManifest(t *testing.T) {
	opts, _ := baseOptions(t, nil)
	opts.Campaign = CampaignCSIP
	_, err := New(suitesForCampaigns(t), realCatalog(t), opts)
	if err == nil || !strings.Contains(err.Error(), "-manifest") {
		t.Fatalf("New() = %v, want a refusal naming -manifest", err)
	}
}

func TestCampaignRejectsAnUnknownName(t *testing.T) {
	opts, _ := baseOptions(t, nil)
	opts.Campaign = "modbus"
	opts.ManifestPath = writeManifest(t, validManifestJSON)
	_, err := New(suitesForCampaigns(t), realCatalog(t), opts)
	if err == nil {
		t.Fatal("New() accepted an unknown campaign")
	}
	if !strings.Contains(err.Error(), "modbus-client") {
		t.Errorf("error does not list the campaigns that DO exist:\n%v", err)
	}
}

// An unselected protocol must contribute neither a FAIL nor a SKIP — the
// acceptance criterion the whole mechanism exists for.
func TestCampaignSelectionsAreDisjointByProtocol(t *testing.T) {
	cat, reg := realCatalog(t), suitesForCampaigns(t)
	seen := map[string]Campaign{}
	for _, spec := range Campaigns() {
		opts := campaignOptions(t, spec.Name)
		r, err := New(reg, cat, opts)
		if err != nil {
			t.Fatalf("%s: %v", spec.Name, err)
		}
		plan := r.Plan()
		if len(plan) == 0 {
			t.Fatalf("%s selected no rows at all", spec.Name)
		}
		for _, p := range plan {
			if other, dup := seen[p.Case.UID]; dup {
				t.Errorf("%s and %s both select %s — the campaigns overlap and a row's verdict would "+
					"belong to two claims", other, spec.Name, p.Case.UID)
			}
			seen[p.Case.UID] = spec.Name
		}
		t.Logf("campaign %-14s selects %3d row(s)", spec.Name, len(plan))
	}
}

// ── zero selection ────────────────────────────────────────────────────────

// The vacuous-pass bug: every selector valid, no case in all of them, a clean
// exit 0 over an empty bundle.
func TestZeroSelectionIsRefusedWithTheOffendingUIDs(t *testing.T) {
	opts, _ := baseOptions(t, nil)
	opts.Suites = []string{"modbus-server"}
	opts.UIDs = []string{"ssm-conf-v0.8::RBAC-002"}
	_, err := New(suitesForCampaigns(t), realCatalog(t), opts)
	if err == nil {
		t.Fatal("New() = nil for a selection that matches nothing; a run of nothing exits clean and " +
			"is indistinguishable at the exit code from a run of everything")
	}
	for _, want := range []string{"ZERO test cases", "ssm-conf-v0.8::RBAC-002", "suite ssm"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error does not mention %q:\n%v", want, err)
		}
	}
}

func TestZeroSelectionNamesApplicableAsTheCause(t *testing.T) {
	opts, _ := baseOptions(t, nil)
	opts.ApplicableOnly = true
	// PKI-005 is in the catalog and marked inapplicable, so -applicable drops it
	// and the selection empties.
	opts.UIDs = []string{"ssm-conf-v0.8::PKI-005"}
	_, err := New(suitesForCampaigns(t), realCatalog(t), opts)
	if err == nil {
		t.Fatal("New() = nil, want a refusal")
	}
	if !strings.Contains(err.Error(), "-applicable") {
		t.Errorf("error does not blame -applicable, which is the actual cause:\n%v", err)
	}
}

func TestNonEmptySelectionStillConstructs(t *testing.T) {
	opts, _ := baseOptions(t, nil)
	opts.Suites = []string{"ssm"}
	opts.UIDs = []string{"ssm-conf-v0.8::RBAC-002"}
	if _, err := New(suitesForCampaigns(t), realCatalog(t), opts); err != nil {
		t.Fatalf("New() = %v for a selection that DOES match", err)
	}
}

// A campaign narrowed by -uid is a legitimate triage run and must still enforce
// the campaign's preconditions — but its bundle must NOT go on claiming to be
// the campaign, or one row stamped `gating: true` gets read as the whole thing.
func TestANarrowedCampaignIsNotTheCampaign(t *testing.T) {
	cases := map[string]func(*Options){
		"-uid":         func(o *Options) { o.UIDs = []string{"ssm-conf-v0.8::RBAC-002"} },
		"-doc":         func(o *Options) { o.Docs = []string{"SSM-CONF-v0.8"} },
		"-role":        func(o *Options) { o.Roles = []DUTRole{RoleMBAPSServer} },
		"-automatable": func(o *Options) { o.MinAutomatable = AutoFull },
	}
	for name, narrow := range cases {
		t.Run(name, func(t *testing.T) {
			opts := campaignOptions(t, CampaignMBAPS)
			opts.Out = &bytes.Buffer{}
			opts.SkipPreflight = true
			narrow(&opts)
			r, err := New(suitesForCampaigns(t), realCatalog(t), opts)
			if err != nil {
				t.Fatalf("New() = %v; narrowing a campaign is a legitimate triage run", err)
			}
			if got := campaignNarrowed(&r.opts); got == "" {
				t.Fatalf("campaignNarrowed() = %q, want it to name %s", got, name)
			}
			rep := &RunReport{Campaign: r.campaign}
			if !rep.Gating() {
				t.Fatal("the fixture is wrong: an un-narrowed campaign should gate")
			}
		})
	}
}

// And the whole campaign, un-narrowed, still gates.
func TestAnUnnarrowedCampaignGates(t *testing.T) {
	opts := campaignOptions(t, CampaignMBAPS)
	r, err := New(suitesForCampaigns(t), realCatalog(t), opts)
	if err != nil {
		t.Fatal(err)
	}
	if got := campaignNarrowed(&r.opts); got != "" {
		t.Errorf("campaignNarrowed() = %q for a whole campaign, want empty", got)
	}
}
