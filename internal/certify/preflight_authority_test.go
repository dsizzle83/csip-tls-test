package certify

// preflight_authority_test.go pins the control-authority precondition: the run
// must PROVE the DUT is in the posture its rows need, before case 1, or not run.
//
// The original of this file pinned one thing — that the RBAC cluster refuses to
// run under Authority=='csip'. That is still here (TestCheckAuthority_
// WrongPostureRefuses and TestPreflightAuthority_RBACSelectionArmsTheCheck), and
// everything else is the three ways the original could still let a run through:
// a control row outside the RBAC prefix, a posture read from a config file
// rather than from the live system, and no gateway transport at all.

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"testing"
)

func planWith(uids ...string) []Planned {
	var plan []Planned
	for _, uid := range uids {
		plan = append(plan, Planned{
			Case:        &Case{UID: uid},
			Implemented: true,
		})
	}
	return plan
}

// fakeDUT is a Gateway.Runner standing in for a device: it answers the four
// read-only commands this check issues and records every one, so a test can
// assert both the answer and that nothing else was run.
type fakeDUT struct {
	t *testing.T
	// mode is the dev API's GET /mode body.
	mode string
	// modeJSON and overlay are the two config files; empty means "absent", and
	// the fake then fails the cat exactly as a missing file would.
	modeJSON string
	overlay  string
	token    string
	// status and inventory are the topology endpoints.
	status    string
	inventory string
	// ran records every command, post-unquoting, as one space-joined string.
	ran []string
}

func (f *fakeDUT) runner() func(context.Context, string, ...string) ([]byte, error) {
	return func(_ context.Context, name string, args ...string) ([]byte, error) {
		f.t.Helper()
		if name != "ssh" || len(args) < 3 {
			f.t.Fatalf("unexpected transport %s %v", name, args)
		}
		cmd := unquoteArgs(args[3:])
		f.ran = append(f.ran, strings.Join(cmd, " "))
		switch {
		case len(cmd) == 2 && cmd[0] == "cat" && cmd[1] == devAPITokenPath:
			return answer(f.token)
		case len(cmd) == 2 && cmd[0] == "cat" && cmd[1] == gatewayModePath:
			return answer(f.modeJSON)
		case len(cmd) == 2 && cmd[0] == "cat" && cmd[1] == gatewayModeOverlayPath:
			return answer(f.overlay)
		case cmd[0] == "wget" && strings.HasSuffix(cmd[len(cmd)-1], "/mode"):
			return answer(f.mode)
		case cmd[0] == "wget" && strings.HasSuffix(cmd[len(cmd)-1], "/southbound/inventory"):
			return answer(f.inventory)
		case cmd[0] == "wget" && strings.HasSuffix(cmd[len(cmd)-1], "/status"):
			return answer(f.status)
		}
		f.t.Fatalf("the authority preflight ran an unexpected command: %v", cmd)
		return nil, nil
	}
}

func answer(body string) ([]byte, error) {
	if body == "" {
		return nil, fmt.Errorf("no such file or directory")
	}
	return []byte(body), nil
}

// unquoteArgs undoes shellQuote so a fake can dispatch on the command the DUT
// would actually have executed rather than on its transport encoding.
func unquoteArgs(args []string) []string {
	out := make([]string, len(args))
	for i, a := range args {
		if len(a) >= 2 && a[0] == '\'' && a[len(a)-1] == '\'' {
			a = strings.ReplaceAll(a[1:len(a)-1], `'\''`, "'")
		}
		out[i] = a
	}
	return out
}

// modeBody renders the dev API's GET /mode document.
func modeBody(authority string, csipEnabled, failsafe bool) string {
	return fmt.Sprintf(`{"mode":"gateway","since":1,"actor":"","intent_id":"",`+
		`"control_authority":%q,"csip_enabled":%t,"vendor_access":false,"failsafe_engaged":%t}`,
		authority, csipEnabled, failsafe)
}

func healthyDUT(t *testing.T, authority string) *fakeDUT {
	t.Helper()
	return &fakeDUT{
		t:        t,
		token:    "s3cr3t\n",
		mode:     modeBody(authority, authority == "csip", false),
		modeJSON: fmt.Sprintf(`{"v":1,"authority":%q,"csip_enabled":true}`, authority),
	}
}

func gatewayFor(f *fakeDUT) *Gateway { return &Gateway{SSH: "cc93", Runner: f.runner()} }

// ── the classification ────────────────────────────────────────────────────

func TestPlanAuthorityDemand(t *testing.T) {
	cases := []struct {
		name string
		plan []Planned
		want map[AuthorityProfile]int
	}{
		{"empty plan", nil, map[AuthorityProfile]int{}},
		{
			"a read-only CSIP row needs no posture",
			planWith("csip-conf-v1.3::BASIC-001", "csip-conf-v1.3::CORE-005"),
			map[AuthorityProfile]int{},
		},
		{
			"the RBAC cluster demands mbaps",
			planWith("ssm-conf-v0.8::RBAC-002", "ssm-conf-v0.8::RBAC-012"),
			map[AuthorityProfile]int{AuthorityMBAPS: 2},
		},
		{
			"a CSIP control row demands csip — the prefix guard never saw these",
			planWith("csip-conf-v1.3::BASIC-006", "csip-conf-v1.3::CORE-022", "local-ext-v1::EXT-001"),
			map[AuthorityProfile]int{AuthorityCSIP: 3},
		},
		{
			"a northbound WRITE row demands mbaps",
			planWith("ss-modbus-conf-v1.4::MOD-3", "ss-modbus-conf-v1.4::REV-1"),
			map[AuthorityProfile]int{AuthorityMBAPS: 2},
		},
		{
			"a northbound READ row does not",
			planWith("ss-modbus-conf-v1.4::MB-2", "ss-modbus-conf-v1.4::DEV-1"),
			map[AuthorityProfile]int{},
		},
		{
			"a mixed selection demands both",
			planWith("csip-conf-v1.3::BASIC-006", "ssm-conf-v0.8::RBAC-002"),
			map[AuthorityProfile]int{AuthorityCSIP: 1, AuthorityMBAPS: 1},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := planAuthorityDemand(tc.plan)
			if len(got.Rows) != len(tc.want) {
				t.Fatalf("demand = %v, want %v", got.Rows, tc.want)
			}
			for a, n := range tc.want {
				if len(got.Rows[a]) != n {
					t.Errorf("demand[%s] = %v, want %d row(s)", a, got.Rows[a], n)
				}
			}
		})
	}
}

// A row that will skip anyway costs nothing to measure under the wrong posture,
// so it must not arm a check operators would then learn to bypass.
func TestPlanAuthorityDemand_SkippedRowsDoNotArmIt(t *testing.T) {
	plan := []Planned{
		{Case: &Case{UID: "ssm-conf-v0.8::RBAC-002"}, Implemented: true, Skip: "missing capability: pki"},
		{Case: &Case{UID: "ssm-conf-v0.8::RBAC-004"}, Implemented: false},
		{Case: &Case{UID: "csip-conf-v1.3::BASIC-006"}, Scope: &ScopeDecision{Reason: "out of scope"}},
	}
	if d := planAuthorityDemand(plan); len(d.Rows) != 0 {
		t.Errorf("planAuthorityDemand = %v, want no demand from rows that will not run", d.Rows)
	}
}

// ── reading the LIVE posture ──────────────────────────────────────────────

func TestReadAuthority_ReadsTheLiveDevAPIAndCrossChecksTheConfig(t *testing.T) {
	dut := healthyDUT(t, "mbaps")
	got, err := ReadAuthority(context.Background(), gatewayFor(dut), "")
	if err != nil {
		t.Fatalf("ReadAuthority() = %v", err)
	}
	if got.Live != AuthorityMBAPS {
		t.Errorf("Live = %q, want mbaps", got.Live)
	}
	if got.Configured != AuthorityMBAPS || got.ConfiguredFrom != gatewayModePath {
		t.Errorf("Configured = %q from %s, want mbaps from %s", got.Configured, got.ConfiguredFrom, gatewayModePath)
	}
	if !got.Authenticated {
		t.Error("Authenticated = false, want the bearer token to have been used")
	}
	// The LIVE half must come from the dev API, not from the config file. That
	// is the whole difference between this check and the one it replaced.
	wantURL := DefaultDevAPI + "/mode"
	if got.LiveFrom != wantURL {
		t.Errorf("LiveFrom = %q, want %q", got.LiveFrom, wantURL)
	}
	var sawWget bool
	for _, c := range dut.ran {
		if strings.HasPrefix(c, "wget ") && strings.HasSuffix(c, "/mode") {
			sawWget = true
			if !strings.Contains(c, "Authorization: Bearer s3cr3t") {
				t.Errorf("the /mode fetch carried no bearer header: %q", c)
			}
		}
	}
	if !sawWget {
		t.Errorf("no dev API /mode fetch was made; commands run: %v", dut.ran)
	}
}

// The runtime overlay is the configured posture when it declares one: reading
// only mode.json would report every legitimately-flipped device as a
// disagreement.
func TestReadAuthority_OverlayIsTheConfiguredPosture(t *testing.T) {
	dut := healthyDUT(t, "csip")
	dut.modeJSON = `{"v":1,"authority":"mbaps","csip_enabled":true}`
	dut.overlay = `{"v":1,"authority":"csip"}`
	got, err := ReadAuthority(context.Background(), gatewayFor(dut), "")
	if err != nil {
		t.Fatalf("ReadAuthority() = %v", err)
	}
	if got.Configured != AuthorityCSIP || got.ConfiguredFrom != gatewayModeOverlayPath {
		t.Errorf("Configured = %q from %s, want csip from the overlay", got.Configured, got.ConfiguredFrom)
	}
	if err := CheckAuthority(got, AuthorityCSIP, "", nil); err != nil {
		t.Errorf("CheckAuthority() = %v, want nil: live and the overlay agree", err)
	}
}

func TestReadAuthority_DevAPIUnreachableIsAnError(t *testing.T) {
	dut := healthyDUT(t, "mbaps")
	dut.mode = "" // the fake fails the fetch, as a dead lexa-api would
	_, err := ReadAuthority(context.Background(), gatewayFor(dut), "")
	if err == nil {
		t.Fatal("ReadAuthority() = nil, want an error: an unreadable posture is not a proven one")
	}
	if !strings.Contains(err.Error(), "/mode") {
		t.Errorf("error = %q, want it to name the endpoint", err)
	}
}

func TestReadAuthority_NoGatewayIsAnError(t *testing.T) {
	if _, err := ReadAuthority(context.Background(), &Gateway{}, ""); err == nil {
		t.Fatal("ReadAuthority() = nil with no transport, want an error")
	}
}

// ── grading the reading ───────────────────────────────────────────────────

// THE HEADLINE CASE, carried over from the original file: a prior CSIP control
// left the DUT in "csip" and the RBAC cluster is about to run against it. This
// must refuse, not silently measure the D1 lock-screen as an RBAC finding.
//
// This is also the MUTATION SENTINEL for the fail-closed rule. Turn
// CheckAuthority's mismatch branch back into a warning — return nil after
// printing — and this test fails on the first assertion, because a nil error is
// exactly what "warn instead of fail" produces.
func TestCheckAuthority_WrongPostureRefuses(t *testing.T) {
	dut := healthyDUT(t, "csip")
	r, err := ReadAuthority(context.Background(), gatewayFor(dut), "")
	if err != nil {
		t.Fatal(err)
	}
	spec, _ := LookupCampaign("mbaps")
	err = CheckAuthority(r, AuthorityMBAPS, spec.Precondition, nil)
	if err == nil {
		t.Fatal("CheckAuthority() = nil, want a REFUSAL: the DUT is in csip and the rows need mbaps")
	}
	for _, want := range []string{
		`"mbaps"`, `"csip"`, "10-csip-mode.json", "SuperAdministratorSunSpec",
		"RBAC-002-MODEL704-REG40298-WRITE-DENIED-ALL-ROLES",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error does not mention %q:\n%v", want, err)
		}
	}
	// The old message told operators the intent lever did not work. It does.
	if strings.Contains(err.Error(), "does NOT fix this") || strings.Contains(err.Error(), "never subscribed") {
		t.Errorf("the refusal still carries the stale claim that the authority intent is a no-op:\n%v", err)
	}
	if !strings.Contains(err.Error(), "authority intent") {
		t.Errorf("the refusal does not offer the intent lever as a remedy:\n%v", err)
	}
}

func TestCheckAuthority_RightPostureProceeds(t *testing.T) {
	dut := healthyDUT(t, "mbaps")
	r, err := ReadAuthority(context.Background(), gatewayFor(dut), "")
	if err != nil {
		t.Fatal(err)
	}
	if err := CheckAuthority(r, AuthorityMBAPS, "", nil); err != nil {
		t.Errorf("CheckAuthority() = %v, want nil", err)
	}
}

func TestCheckAuthority_UnknownPostureRefuses(t *testing.T) {
	r := AuthorityReading{Live: "quantum", Configured: "quantum", ConfiguredFrom: gatewayModePath}
	err := CheckAuthority(r, AuthorityMBAPS, "", nil)
	if err == nil || !strings.Contains(err.Error(), "quantum") {
		t.Fatalf("CheckAuthority() = %v, want a refusal naming the unrecognised posture", err)
	}
}

// The cross-check the requirement asks for: live and configured must AGREE.
func TestCheckAuthority_LiveAndConfiguredMustAgree(t *testing.T) {
	dut := healthyDUT(t, "mbaps")
	dut.modeJSON = `{"v":1,"authority":"csip","csip_enabled":true}`
	r, err := ReadAuthority(context.Background(), gatewayFor(dut), "")
	if err != nil {
		t.Fatal(err)
	}
	err = CheckAuthority(r, AuthorityMBAPS, "", nil)
	if err == nil {
		t.Fatal("CheckAuthority() = nil, want a refusal: live mbaps, configured csip")
	}
	if !strings.Contains(err.Error(), "LIVE") || !strings.Contains(err.Error(), "CONFIGURED") {
		t.Errorf("error does not name both readings:\n%v", err)
	}
}

func TestCheckAuthority_NoConfiguredValueRefuses(t *testing.T) {
	r := AuthorityReading{Live: AuthorityMBAPS, ConfiguredFrom: gatewayModePath}
	if err := CheckAuthority(r, AuthorityMBAPS, "", nil); err == nil {
		t.Fatal("CheckAuthority() = nil with nothing to cross-check against, want a refusal")
	}
}

// AuthorityAny does not mean "anything goes": it means the live posture must be
// one the candidate CLAIMS.
func TestCheckAuthority_AnyStillRequiresTheCandidateToClaimIt(t *testing.T) {
	r := AuthorityReading{Live: AuthorityLocal, Configured: AuthorityLocal, ConfiguredFrom: gatewayModePath}
	claims := func(a AuthorityProfile) bool { return a == AuthorityCSIP || a == AuthorityMBAPS }
	err := CheckAuthority(r, AuthorityAny, "", claims)
	if err == nil || !strings.Contains(err.Error(), "authority_profiles") {
		t.Fatalf("CheckAuthority() = %v, want a refusal naming the manifest's authority_profiles", err)
	}
	if err := CheckAuthority(r, AuthorityAny, "", nil); err != nil {
		t.Errorf("CheckAuthority() with no manifest predicate = %v, want nil", err)
	}
}

// A refusal that knows why the flip will not work should say so.
func TestCheckAuthority_MentionsCSIPDisabledAndFailsafe(t *testing.T) {
	r := AuthorityReading{
		Live: AuthorityMBAPS, Configured: AuthorityMBAPS, ConfiguredFrom: gatewayModePath,
		CSIPEnabled: false, FailsafeEngaged: true,
	}
	err := CheckAuthority(r, AuthorityCSIP, "", nil)
	if err == nil {
		t.Fatal("want a refusal")
	}
	if !strings.Contains(err.Error(), "csip_enabled=false") {
		t.Errorf("error does not warn that csip_enabled is false:\n%v", err)
	}
	if !strings.Contains(err.Error(), "FAILSAFE ENGAGED") {
		t.Errorf("error does not warn about the fail-safe:\n%v", err)
	}
}

// ── the runner's wrapper ──────────────────────────────────────────────────

func TestPreflightAuthority_SilentWhenNoRowNeedsIt(t *testing.T) {
	opts, _ := baseOptions(t, nil)
	opts.GatewaySSH = "cc93"
	r, err := New(NewRegistry(), catalogFile(t), opts)
	if err != nil {
		t.Fatal(err)
	}
	var console bytes.Buffer
	out, err := r.preflightAuthority(context.Background(), NewReporter(&console), planWith("csip-conf-v1.3::BASIC-001"))
	if err != nil {
		t.Fatalf("preflightAuthority() = %v, want nil (no row needs a posture)", err)
	}
	if out.Reading != nil || console.Len() != 0 {
		t.Errorf("preflightAuthority spoke when nothing needed it: %q", console.String())
	}
}

// The original behaviour, preserved: an EXPLORATORY selection that names RBAC
// rows by hand still refuses under the wrong posture.
func TestPreflightAuthority_RBACSelectionArmsTheCheck(t *testing.T) {
	dut := healthyDUT(t, "csip")
	opts, _ := baseOptions(t, nil)
	opts.GatewaySSH = "cc93"
	r, err := New(NewRegistry(), catalogFile(t), opts)
	if err != nil {
		t.Fatal(err)
	}
	// Inject the fake DUT by giving the runner the same transport the real one
	// would build. r.gateway() has no seam, so drive checkable core directly
	// with the plan the runner would have produced.
	demandPlan := planWith("ssm-conf-v0.8::RBAC-002")
	want, because, armed := r.authorityRequirement(NewReporter(&bytes.Buffer{}), demandPlan)
	if !armed || want != AuthorityMBAPS {
		t.Fatalf("authorityRequirement = (%q, armed=%v), want mbaps armed", want, armed)
	}
	reading, err := ReadAuthority(context.Background(), gatewayFor(dut), "")
	if err != nil {
		t.Fatal(err)
	}
	if err := CheckAuthority(reading, want, because, nil); err == nil {
		t.Fatal("an exploratory RBAC selection under Authority=csip was allowed to run")
	}
}

// FAIL CLOSED, the change that matters most: no transport used to be a console
// line and a `return nil`. It is an error now.
func TestPreflightAuthority_NoTransportFailsClosed(t *testing.T) {
	opts, _ := baseOptions(t, nil)
	r, err := New(NewRegistry(), catalogFile(t), opts)
	if err != nil {
		t.Fatal(err)
	}
	var console bytes.Buffer
	_, err = r.preflightAuthority(context.Background(), NewReporter(&console), planWith("ssm-conf-v0.8::RBAC-002"))
	if err == nil {
		t.Fatal("preflightAuthority() = nil with no gateway transport, want a REFUSAL — the one " +
			"invocation that cannot check the precondition must not be the one that proceeds regardless")
	}
	for _, want := range []string{"-gateway-ssh", "-gateway-exec", "-skip-preflight"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error does not name %s as the remedy:\n%v", want, err)
		}
	}
}

// The one escape, and its price: an exploratory run may proceed with
// -skip-preflight, and the bundle then records that it is not gating.
func TestPreflightAuthority_SkipPreflightDowngradesRatherThanWaives(t *testing.T) {
	opts, _ := baseOptions(t, nil)
	opts.SkipPreflight = true
	r, err := New(NewRegistry(), catalogFile(t), opts)
	if err != nil {
		t.Fatal(err)
	}
	var console bytes.Buffer
	out, err := r.preflightAuthority(context.Background(), NewReporter(&console), planWith("ssm-conf-v0.8::RBAC-002"))
	if err != nil {
		t.Fatalf("preflightAuthority() = %v, want nil for an exploratory -skip-preflight run", err)
	}
	if out.Unchecked == "" {
		t.Error("the run was allowed through with no record that the precondition was never established")
	}
	if !strings.Contains(console.String(), "NOT GATING") {
		t.Errorf("console does not say the run is non-gating: %q", console.String())
	}
}

// -skip-preflight is NOT a way past a wrong reading. Its only effect on this
// check is the no-transport escape above.
func TestPreflightAuthority_SkipPreflightDoesNotWaveThroughAWrongPosture(t *testing.T) {
	dut := healthyDUT(t, "csip")
	reading, err := ReadAuthority(context.Background(), gatewayFor(dut), "")
	if err != nil {
		t.Fatal(err)
	}
	// CheckAuthority takes no skip flag at all — the absence IS the guarantee,
	// and this test states it so a future signature change has to face it.
	if err := CheckAuthority(reading, AuthorityMBAPS, "", nil); err == nil {
		t.Fatal("a wrong posture was accepted")
	}
}

// A campaign cannot proceed without a transport, whatever flags are set.
func TestPreflightAuthority_CampaignWithoutTransportFails(t *testing.T) {
	opts := campaignOptions(t, CampaignMBAPS)
	opts.SkipPreflight = true
	r, err := New(suitesForCampaigns(t), realCatalog(t), opts)
	if err != nil {
		t.Fatal(err)
	}
	var console bytes.Buffer
	_, err = r.preflightAuthority(context.Background(), NewReporter(&console), nil)
	if err == nil {
		t.Fatal("a -campaign ran with no way to prove its own precondition, and -skip-preflight set")
	}
	if !strings.Contains(err.Error(), "A campaign proves its preconditions") {
		t.Errorf("error does not say why a campaign is different:\n%v", err)
	}
}

// A selection needing two postures at once cannot be satisfied by any device.
// It is reported and disarmed rather than refused, because that is every
// whole-catalog run.
func TestPreflightAuthority_ConflictingDemandDisarmsAndSaysSo(t *testing.T) {
	opts, _ := baseOptions(t, nil)
	opts.GatewaySSH = "cc93"
	r, err := New(NewRegistry(), catalogFile(t), opts)
	if err != nil {
		t.Fatal(err)
	}
	var console bytes.Buffer
	plan := planWith("csip-conf-v1.3::BASIC-006", "ssm-conf-v0.8::RBAC-002")
	_, _, armed := r.authorityRequirement(NewReporter(&console), plan)
	if armed {
		t.Error("a selection demanding two postures armed the check; no device can satisfy it")
	}
	for _, want := range []string{"MORE THAN ONE", "EXPLORATORY", "csip", "mbaps"} {
		if !strings.Contains(console.String(), want) {
			t.Errorf("console does not mention %q: %s", want, console.String())
		}
	}
}
