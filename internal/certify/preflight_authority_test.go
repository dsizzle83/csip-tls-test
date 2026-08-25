package certify

// preflight_authority_test.go pins the RBAC-002-MODEL704-REG40298-WRITE-
// DENIED-ALL-ROLES fix (lexa-gw/docs/known_issues.json): the RBAC/mbaps-
// authority cluster must never run measuring a DUT still holding
// Authority=='csip' from an earlier CSIP-content-publishing case in the same
// battery.

import (
	"bytes"
	"context"
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

func TestPlanRequiresMbapsAuthority(t *testing.T) {
	cases := []struct {
		name string
		plan []Planned
		want bool
	}{
		{"empty plan", nil, false},
		{"no RBAC rows", planWith("csip-conf-v1.3::BASIC-006", "csip-conf-v1.3::BASIC-011"), false},
		{"RBAC-002 planned", planWith("csip-conf-v1.3::BASIC-006", "ssm-conf-v0.8::RBAC-002"), true},
		{"RBAC-012 planned", planWith("ssm-conf-v0.8::RBAC-012"), true},
		{"a non-RBAC ssm row does not arm it", planWith("ssm-conf-v0.8::PKI-004"), false},
		{
			"RBAC row present but SKIPped does not arm it",
			[]Planned{{Case: &Case{UID: "ssm-conf-v0.8::RBAC-002"}, Implemented: true, Skip: "missing capability: pki"}},
			false,
		},
		{
			"RBAC row present but unimplemented does not arm it",
			[]Planned{{Case: &Case{UID: "ssm-conf-v0.8::RBAC-002"}, Implemented: false}},
			false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := planRequiresMbapsAuthority(tc.plan); got != tc.want {
				t.Errorf("planRequiresMbapsAuthority(%v) = %v, want %v", tc.plan, got, tc.want)
			}
		})
	}
}

// fakeMode returns a Gateway.Runner that answers `cat /etc/lexa/mode.json`
// with the given authority value, and fails any other command — pinning that
// this check reads nothing else off the DUT.
func fakeMode(t *testing.T, authority string) func(context.Context, string, ...string) ([]byte, error) {
	t.Helper()
	return func(_ context.Context, name string, args ...string) ([]byte, error) {
		// Gateway.Run shells out through ssh itself (name="ssh", the real
		// command riding along in args), the same shape TestGatewayCommandsAreShaped
		// in clients_test.go pins.
		if name != "ssh" || len(args) == 0 || args[len(args)-2] != "cat" || args[len(args)-1] != "/etc/lexa/mode.json" {
			t.Fatalf("checkMbapsAuthority ran an unexpected command: %s %v", name, args)
		}
		return []byte(`{"authority":"` + authority + `"}`), nil
	}
}

func TestCheckMbapsAuthority_MbapsPasses(t *testing.T) {
	gw := &Gateway{SSH: "cc93", Runner: fakeMode(t, "mbaps")}
	var console bytes.Buffer
	if err := checkMbapsAuthority(context.Background(), gw, NewReporter(&console)); err != nil {
		t.Fatalf("checkMbapsAuthority() = %v, want nil (Authority is mbaps)", err)
	}
	if !strings.Contains(console.String(), `Authority="mbaps"`) {
		t.Errorf("reporter output = %q, want a line confirming Authority=%q", console.String(), "mbaps")
	}
}

// The headline case: a prior CSIP-content-publishing case left Authority at
// 'csip', and the RBAC cluster is about to run against it. This must refuse,
// not silently measure the D1 lock-screen as an RBAC finding.
func TestCheckMbapsAuthority_CsipRefuses(t *testing.T) {
	gw := &Gateway{SSH: "cc93", Runner: fakeMode(t, "csip")}
	var console bytes.Buffer
	err := checkMbapsAuthority(context.Background(), gw, NewReporter(&console))
	if err == nil {
		t.Fatal("checkMbapsAuthority() = nil, want a refusal (Authority is csip)")
	}
	for _, want := range []string{
		`"csip"`, "10-csip-mode.json", "SuperAdministratorSunSpec",
		"RBAC-002-MODEL704-REG40298-WRITE-DENIED-ALL-ROLES", "systemctl restart lexa-mode",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error = %q, want it to mention %q", err.Error(), want)
		}
	}
}

func TestCheckMbapsAuthority_UnknownValueRefuses(t *testing.T) {
	gw := &Gateway{SSH: "cc93", Runner: fakeMode(t, "local")}
	var console bytes.Buffer
	if err := checkMbapsAuthority(context.Background(), gw, NewReporter(&console)); err == nil {
		t.Fatal("checkMbapsAuthority() = nil, want a refusal (Authority is neither mbaps nor csip)")
	}
}

// No -gateway-ssh: this check cannot do anything, and it must say so rather
// than fail the run outright — the same posture preflight's own
// no-admin-API branch takes, and consistent with the RBAC rows' own
// "gateway"/"bench" capability tags already tolerating its absence elsewhere.
func TestCheckMbapsAuthority_NoGatewayWarnsButDoesNotFail(t *testing.T) {
	gw := &Gateway{}
	var console bytes.Buffer
	if err := checkMbapsAuthority(context.Background(), gw, NewReporter(&console)); err != nil {
		t.Fatalf("checkMbapsAuthority() = %v, want nil (no -gateway-ssh is a warning, not a failure)", err)
	}
	if !strings.Contains(console.String(), "-gateway-ssh") {
		t.Errorf("reporter output = %q, want a line naming -gateway-ssh as the gap", console.String())
	}
}

// preflightAuthority is the wrapper Run() actually calls: it must stay silent
// (no Gateway.Run call at all) when the plan holds no RBAC row, even with a
// -gateway-ssh configured, and it must honour -skip-preflight exactly like
// preflight() does.
func TestPreflightAuthority_SilentWhenNotNeeded(t *testing.T) {
	opts, _ := baseOptions(t, nil)
	opts.GatewaySSH = "cc93"
	r, err := New(NewRegistry(), catalogFile(t), opts)
	if err != nil {
		t.Fatal(err)
	}
	var console bytes.Buffer
	plan := planWith("csip-conf-v1.3::BASIC-006")
	if err := r.preflightAuthority(context.Background(), NewReporter(&console), plan); err != nil {
		t.Fatalf("preflightAuthority() = %v, want nil (no RBAC row planned)", err)
	}
	if console.Len() != 0 {
		t.Errorf("reporter output = %q, want silence when the cluster is not selected", console.String())
	}
}

func TestPreflightAuthority_SkipPreflightBypassesIt(t *testing.T) {
	opts, _ := baseOptions(t, nil)
	opts.GatewaySSH = "cc93"
	opts.SkipPreflight = true
	r, err := New(NewRegistry(), catalogFile(t), opts)
	if err != nil {
		t.Fatal(err)
	}
	var console bytes.Buffer
	plan := planWith("ssm-conf-v0.8::RBAC-002")
	if err := r.preflightAuthority(context.Background(), NewReporter(&console), plan); err != nil {
		t.Fatalf("preflightAuthority() = %v, want nil (-skip-preflight)", err)
	}
}
