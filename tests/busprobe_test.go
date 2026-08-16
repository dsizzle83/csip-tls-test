package integration_test

// The internal-bus (MQTT) ACL probe's own gate.
//
// scripts/qa-bus-probe.py is the only piece of this harness that speaks MQTT on
// the wire, and it is the one that decides whether the gateway's internal
// control bus is ACL-confined. It ran for months with a defect that made its
// PASS meaningless: it sent a SUBSCRIBE and read exactly ONE packet, treating
// anything that was not a SUBACK as "the broker disconnected us, which is the
// ACL acting". On the live bench the packet it usually read was the RETAINED
// lexa/mode document its own in-lane subscription had just earned — so a broker
// that GRANTED the out-of-lane lane and delivered from it scored identically to
// one that refused it. Both printed PASS.
//
// Nothing in Go can hold that closed, so these tests run the scripts themselves:
// the probe against scripted brokers on loopback (its --selftest table, one case
// per classification), and the runner against ACL fixtures with ssh/scp faked,
// which is where the "worst of the two halves" verdict rule lives.
//
// Both skip rather than fail where python3/bash are absent — this suite runs in
// the pure-Go CI job as well as on the desktop.

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestBusProbeSelfTest runs scripts/qa-bus-probe.py --selftest, which drives the
// lane-isolation classifier against a scripted broker once per outcome: refused
// by SUBACK 0x80, refused with a retained in-lane document arriving first (the
// exact shape the old one-packet read mis-scored), granted-and-leaking,
// granted-with-nothing-to-leak, refused by close, silent broker, and an in-lane
// grant this deployment does not have.
func TestBusProbeSelfTest(t *testing.T) {
	python := lookPath(t, "python3")
	cmd := exec.Command(python, filepath.Join("..", "scripts", "qa-bus-probe.py"), "--selftest")
	out, err := cmd.CombinedOutput()
	t.Logf("qa-bus-probe.py --selftest:\n%s", out)
	if err != nil {
		t.Fatalf("probe self-test failed (%v). Each case names the broker behaviour it "+
			"scripts, so the failing line says which classification moved.", err)
	}
	if !strings.Contains(string(out), "SELFTEST: PASS") {
		t.Fatalf("self-test did not report PASS")
	}
	// The two cases that make this gate worth having, named explicitly: if
	// someone deletes them, the table still passes and proves less.
	for _, want := range []string{"old probe read that PUBLISH as the out-lane answer", "old probe scored this PASS"} {
		if !strings.Contains(string(out), want) {
			t.Errorf("the self-test no longer covers the false-PASS shape %q — that case is the "+
				"reason this file exists; a table without it cannot tell a confined bus from a "+
				"leaking one", want)
		}
	}
}

// TestBusProbeRunnerVerdictIsWorstOfBothHalves pins scripts/gw-qa-bus.sh's
// verdict rule against the deployed ACL it reads. The runner has two sources of
// evidence — what the broker was TOLD (the acl file) and what it DOES (the live
// probe) — and the run's verdict must be the worse of them: a configuration
// finding is not cancelled by a live pass, and an unreachable board never
// upgrades to a pass just because the ACL file looks clean.
//
// ssh and scp are faked, so the live half is always unreachable here (exit != 0
// from the fake ssh); what is under test is the cross-check and the combination.
func TestBusProbeRunnerVerdictIsWorstOfBothHalves(t *testing.T) {
	bash := lookPath(t, "bash")
	dir := t.TempDir()

	// A minimal stand-in for systemd/mosquitto/acl: one confined subject
	// (lexa-cloudlink, read on lexa/mode only) and the owner of the lane it
	// must not reach (lexa-mode, sole writer of lexa/desired/#).
	const confined = "user lexa-cloudlink\n" +
		"topic write lexa/cloudlink/status\n" +
		"topic read  lexa/mode\n" +
		"topic read  lexa/mbaps/sessions\n" +
		"\n" +
		"user lexa-mode\n" +
		"topic write lexa/desired/#\n"
	widened := strings.Replace(confined,
		"topic read  lexa/mbaps/sessions\n",
		"topic read  lexa/mbaps/sessions\ntopic read  lexa/desired/#\n", 1)
	noInLane := strings.Replace(confined, "topic read  lexa/mode\n", "", 1)

	fakebin := filepath.Join(dir, "bin")
	if err := os.MkdirAll(fakebin, 0o755); err != nil {
		t.Fatal(err)
	}
	// The fake board: it serves the ACL fixture and refuses to run anything
	// else, which is the "board unreachable" half of every case below.
	write(t, filepath.Join(fakebin, "ssh"), "#!/bin/bash\ncase \"$2\" in *lexa-acl*) cat \"$FAKE_ACL\";; *) echo 'fake ssh: no board' >&2; exit 255;; esac\n")
	write(t, filepath.Join(fakebin, "scp"), "#!/bin/bash\nexit 0\n")

	cases := []struct {
		name     string
		acl      string
		wantExit int
		wantLine string
	}{
		{
			name:     "confined ACL, board unreachable — undecided, never a pass",
			acl:      confined,
			wantExit: 2,
			wantLine: "ACL cross-check OK",
		},
		{
			name:     "ACL grants the out-of-lane filter — a finding on its own",
			acl:      widened,
			wantExit: 1,
			wantLine: "ACL cross-check FAIL",
		},
		{
			name:     "subject has no in-lane grant — the probe is aimed wrong, not the bus broken",
			acl:      noInLane,
			wantExit: 2,
			wantLine: "ACL cross-check INCONCLUSIVE",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			aclPath := filepath.Join(dir, "acl")
			write(t, aclPath, tc.acl)

			cmd := exec.Command(bash, filepath.Join("..", "scripts", "gw-qa-bus.sh"))
			cmd.Env = append(os.Environ(),
				"PATH="+fakebin+string(os.PathListSeparator)+os.Getenv("PATH"),
				"FAKE_ACL="+aclPath)
			out, err := cmd.CombinedOutput()
			got := exitCode(err)
			t.Logf("gw-qa-bus.sh:\n%s", out)
			if got != tc.wantExit {
				t.Errorf("exit = %d, want %d (0=pass 1=violated 2=undecided)", got, tc.wantExit)
			}
			if !strings.Contains(string(out), tc.wantLine) {
				t.Errorf("output does not contain %q", tc.wantLine)
			}
			if strings.Contains(string(out), "gw-qa-bus: PASS") {
				t.Errorf("reported PASS with no live probe result — an unmeasured bus is not a confined one")
			}
		})
	}
}

func lookPath(t *testing.T, bin string) string {
	t.Helper()
	p, err := exec.LookPath(bin)
	if err != nil {
		t.Skipf("%s not available: %v", bin, err)
	}
	return p
}

func write(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o755); err != nil {
		t.Fatal(err)
	}
}

func exitCode(err error) int {
	if err == nil {
		return 0
	}
	if ee, ok := err.(*exec.ExitError); ok {
		return ee.ExitCode()
	}
	return -1
}
