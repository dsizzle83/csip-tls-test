package certify

// gatewayexec_test.go pins the LOCAL introspection transport and the ssh
// quoting that had to come with it.
//
// The property that matters most is negative: making the DUT reachable without
// ssh must not make anything reachable that was not reachable before. The
// read-only allowlist runs before either transport, on the same argument
// vector, and TestGatewayExecEnforcesTheAllowlistBeforeExec is what says so.

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func recordingRunner(rec *[]string) func(context.Context, string, ...string) ([]byte, error) {
	return func(_ context.Context, name string, args ...string) ([]byte, error) {
		*rec = append(*rec, strings.Join(append([]string{name}, args...), " "))
		return []byte("ok"), nil
	}
}

func TestGatewayExecRunsThePrefixedCommandWithNoSSH(t *testing.T) {
	var ran []string
	g := &Gateway{Exec: []string{"docker", "exec", "gw"}, Runner: recordingRunner(&ran)}
	if !g.Available() {
		t.Fatal("Available() = false for a configured -gateway-exec")
	}
	if _, err := g.Run(context.Background(), "cat", "/etc/lexa/mode.json"); err != nil {
		t.Fatal(err)
	}
	if len(ran) != 1 || ran[0] != "docker exec gw cat /etc/lexa/mode.json" {
		t.Fatalf("ran %v, want the prefix and the command as one argv with no ssh", ran)
	}
}

// The whole point of the transport split: the allowlist is checked BEFORE the
// prefix runs, exactly as it is for ssh.
func TestGatewayExecEnforcesTheAllowlistBeforeExec(t *testing.T) {
	var ran []string
	g := &Gateway{Exec: []string{"docker", "exec", "gw"}, Runner: recordingRunner(&ran)}
	_, err := g.Run(context.Background(), "rm", "-rf", "/etc/lexa")
	if !errors.Is(err, ErrNotReadOnly) {
		t.Fatalf("Run() = %v, want ErrNotReadOnly", err)
	}
	if len(ran) != 0 {
		t.Fatalf("a refused command still reached the transport: %v", ran)
	}
	// And the systemctl sub-command rule survives the new path too.
	if _, err := g.Run(context.Background(), "systemctl", "restart", "lexa-mode"); !errors.Is(err, ErrNotReadOnly) {
		t.Errorf("Run(systemctl restart) = %v, want ErrNotReadOnly", err)
	}
	if _, err := g.Run(context.Background(), "systemctl", "is-active", "lexa-mode"); err != nil {
		t.Errorf("Run(systemctl is-active) = %v, want it permitted", err)
	}
}

func TestGatewayRefusesBothTransportsAtOnce(t *testing.T) {
	var ran []string
	g := &Gateway{SSH: "cc93", Exec: []string{"docker", "exec", "gw"}, Runner: recordingRunner(&ran)}
	_, err := g.Run(context.Background(), "cat", "/etc/lexa/mode.json")
	if err == nil {
		t.Fatal("Run() = nil with both transports configured, want a refusal rather than a silent choice")
	}
	if len(ran) != 0 {
		t.Fatalf("a refused command still reached a transport: %v", ran)
	}
}

func TestGatewayDescribeNamesTheOperatorsOwnFlag(t *testing.T) {
	if got := (&Gateway{SSH: "cc93"}).Describe(); got != "-gateway-ssh cc93" {
		t.Errorf("Describe() = %q", got)
	}
	if got := (&Gateway{Exec: []string{"docker", "exec", "gw"}}).Describe(); got != "-gateway-exec docker exec gw" {
		t.Errorf("Describe() = %q", got)
	}
	if got := (&Gateway{}).Describe(); got != "(no gateway)" {
		t.Errorf("Describe() = %q", got)
	}
}

// ── ssh argument quoting ──────────────────────────────────────────────────

// Every command this client ran before the dev API arrived must go over the
// wire BYTE-IDENTICALLY, or this fix silently changes what forty checks execute.
func TestSSHQuotingLeavesOrdinaryCommandsUntouched(t *testing.T) {
	var ran []string
	g := &Gateway{SSH: "cc93", Runner: recordingRunner(&ran)}
	for _, args := range [][]string{
		{"cat", "/etc/lexa/mode.json"},
		{"journalctl", "-u", "lexa-mode", "-n", "200", "--no-pager", "-o", "short-iso"},
		{"systemctl", "is-active", "lexa-mbaps"},
		{"wget", "-qO-", "http://127.0.0.1:9102/metrics"},
	} {
		ran = ran[:0]
		if _, err := g.Run(context.Background(), args...); err != nil {
			t.Fatal(err)
		}
		want := "ssh -o BatchMode=yes cc93 " + strings.Join(args, " ")
		if ran[0] != want {
			t.Errorf("ssh argv changed:\n got %q\nwant %q", ran[0], want)
		}
	}
}

// ssh concatenates its trailing arguments and the REMOTE SHELL splits them
// again. An unquoted header would arrive as three arguments.
func TestSSHQuotingProtectsAnArgumentWithSpaces(t *testing.T) {
	var ran []string
	g := &Gateway{SSH: "cc93", Runner: recordingRunner(&ran)}
	_, err := g.Run(context.Background(), "wget", "-qO-", "--header", "Authorization: Bearer abc123",
		"https://127.0.0.1:9100/mode")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(ran[0], `'Authorization: Bearer abc123'`) {
		t.Fatalf("the header was not quoted for the remote shell: %q", ran[0])
	}
}

func TestShellQuote(t *testing.T) {
	cases := map[string]string{
		"cat":                      "cat",
		"/etc/lexa/mode.json":      "/etc/lexa/mode.json",
		"-qO-":                     "-qO-",
		"https://127.0.0.1:9100/x": "https://127.0.0.1:9100/x",
		"Authorization: Bearer a":  `'Authorization: Bearer a'`,
		"":                         "''",
		"it's":                     `'it'\''s'`,
		"a;rm -rf /":               `'a;rm -rf /'`,
		"$(whoami)":                `'$(whoami)'`,
		"back`tick`":               "'back`tick`'",
	}
	for in, want := range cases {
		if got := shellQuote(in); got != want {
			t.Errorf("shellQuote(%q) = %q, want %q", in, got, want)
		}
	}
}

// ── the flag's own value ──────────────────────────────────────────────────

func TestSplitCommandPrefix(t *testing.T) {
	cases := []struct {
		in   string
		want []string
	}{
		{"docker exec c", []string{"docker", "exec", "c"}},
		{"scripts/lab/lab-exec", []string{"scripts/lab/lab-exec"}},
		{"  spaced   out  ", []string{"spaced", "out"}},
		{`"/opt/my lab/exec" --into gw`, []string{"/opt/my lab/exec", "--into", "gw"}},
		{`nsenter -t 1 -n -- ''`, []string{"nsenter", "-t", "1", "-n", "--", ""}},
	}
	for _, tc := range cases {
		got, err := SplitCommandPrefix(tc.in)
		if err != nil {
			t.Errorf("SplitCommandPrefix(%q) = %v", tc.in, err)
			continue
		}
		if strings.Join(got, "\x00") != strings.Join(tc.want, "\x00") {
			t.Errorf("SplitCommandPrefix(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// A prefix truncated at a stray quote would run a DIFFERENT command against the
// DUT than the one on the command line.
func TestSplitCommandPrefixRefusesAmbiguity(t *testing.T) {
	for _, in := range []string{`docker exec "c`, `docker exec 'c`, "", "   "} {
		if _, err := SplitCommandPrefix(in); err == nil {
			t.Errorf("SplitCommandPrefix(%q) = nil, want a refusal rather than a guess", in)
		}
	}
}

func TestNewRefusesBothGatewayFlags(t *testing.T) {
	opts, _ := baseOptions(t, nil)
	opts.GatewaySSH = "cc93"
	opts.GatewayExec = "docker exec gw"
	_, err := New(NewRegistry(), catalogFile(t), opts)
	if err == nil || !strings.Contains(err.Error(), "mutually exclusive") {
		t.Fatalf("New() = %v, want a refusal", err)
	}
}

func TestNewRefusesAMalformedGatewayExec(t *testing.T) {
	opts, _ := baseOptions(t, nil)
	opts.GatewayExec = `docker exec "gw`
	if _, err := New(NewRegistry(), catalogFile(t), opts); err == nil {
		t.Fatal("New() accepted an unterminated -gateway-exec quote; the failure would then arrive on " +
			"the first introspection call, forty minutes in")
	}
}

// Either transport must satisfy the "gateway" capability, or every
// config-derived check skips on a local run that could read them perfectly well.
func TestGatewayExecSatisfiesTheGatewayCapability(t *testing.T) {
	opts, _ := baseOptions(t, nil)
	opts.GatewayExec = "docker exec gw"
	r, err := New(NewRegistry(), catalogFile(t), opts)
	if err != nil {
		t.Fatal(err)
	}
	if !r.capabilities()["gateway"] {
		t.Error("-gateway-exec did not satisfy the \"gateway\" capability")
	}
}
