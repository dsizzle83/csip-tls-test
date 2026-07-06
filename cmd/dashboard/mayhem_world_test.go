package main

import (
	"strconv"
	"strings"
	"testing"
)

// TestFillDiskCommand_HasFloorGuardAndReserve locks the size math and floor
// guard TASK-050 requires: refuse below diskFloorKiB free, and always
// subtract diskReserveKiB before fallocating — the two properties that keep
// the ballast from ever bricking a tight partition. fillDiskCommand is a pure
// string builder specifically so this is testable without SSH.
func TestFillDiskCommand_HasFloorGuardAndReserve(t *testing.T) {
	cmd := fillDiskCommand()

	if !strings.Contains(cmd, "fallocate") {
		t.Error("command must use fallocate (not dd — RSK-14, no SD-card write churn)")
	}
	if strings.Contains(cmd, "dd ") || strings.Contains(cmd, "dd if=") {
		t.Error("command must not shell out to dd")
	}
	if !strings.Contains(cmd, ballastPath) {
		t.Errorf("command must target the fixed, greppable ballast path %q", ballastPath)
	}
	if !strings.Contains(cmd, ballastDir) {
		t.Errorf("command must size against %q (mosquitto/journald's partition)", ballastDir)
	}

	floorStr := strconv.Itoa(diskFloorKiB)
	if !strings.Contains(cmd, floorStr) {
		t.Errorf("command must guard on the %d KiB floor", diskFloorKiB)
	}
	reserveStr := strconv.Itoa(diskReserveKiB)
	if !strings.Contains(cmd, reserveStr) {
		t.Errorf("command must reserve %d KiB", diskReserveKiB)
	}
	if !strings.Contains(cmd, "exit 1") {
		t.Error("command must refuse (non-zero exit) when free space is below the floor, not fill anyway")
	}
	// The arithmetic must subtract the reserve from avail, not just the
	// floor: avail - diskReserveKiB is the size fallocate gets.
	if !strings.Contains(cmd, "avail - "+reserveStr) {
		t.Errorf("command must fallocate (avail - %d) KiB, got: %s", diskReserveKiB, cmd)
	}
	// Reserve must never exceed the floor, or a partition just above the
	// floor could compute a negative/zero fallocate size.
	if diskReserveKiB > diskFloorKiB {
		t.Errorf("diskReserveKiB (%d) must not exceed diskFloorKiB (%d)", diskReserveKiB, diskFloorKiB)
	}
}

// ── netem packet-chaos (TASK-052 / GAP-11) ──────────────────────────────────

// TestNetemPeerIP locks the peer-selection rule FIX-H requires: the hub's
// peer for iface discovery is a sim Pi, every other node's peer is the
// desktop — and NEVER a node's own default route (that's the whole point of
// using a peer route lookup instead).
func TestNetemPeerIP(t *testing.T) {
	if got := netemPeerIP("hub"); got == netemDesktopIP || got == "" {
		t.Errorf("netemPeerIP(hub) = %q, want a sim Pi (not the desktop, not empty)", got)
	}
	for _, node := range []string{"solar", "battery", "meter", "ev"} {
		if got := netemPeerIP(node); got != netemDesktopIP {
			t.Errorf("netemPeerIP(%s) = %q, want the desktop %q (gridsim is every sim Pi's real peer)", node, got, netemDesktopIP)
		}
	}
}

// TestNetemIfaceDiscoverCmd locks FIX-H: the iface MUST come from a peer
// route lookup, never a hardcoded name or the default route. This is the
// exact bug class TASK-052 exists to prevent — a dual-homed Pi's default
// route goes out its WiFi WAN iface, so netem on "the default route" would
// silently no-op.
func TestNetemIfaceDiscoverCmd(t *testing.T) {
	const peer = "69.0.0.20"
	cmd := netemIfaceDiscoverCmd(peer)

	if !strings.Contains(cmd, "ip -o route get "+peer) {
		t.Errorf("command must discover the iface via `ip -o route get %s`, got: %s", peer, cmd)
	}
	if strings.Contains(cmd, "eth0") {
		t.Error("command must never hardcode eth0 — Pis vary")
	}
	if strings.Contains(cmd, "ip route show default") || strings.Contains(cmd, "ip route | grep default") {
		t.Error("command must never fall back to the default route")
	}
	if !strings.Contains(cmd, "exit 1") {
		t.Error("command must refuse (non-zero exit) when iface discovery comes back empty, not guess")
	}
}

// TestNetemApplyCommand locks the properties TASK-052's code-review checklist
// names: `replace` (not `add`, so re-arming doesn't error), `sudo -n`
// (password-required nodes fail fast, never hang), the self-healing
// scheduled reset baked into every apply, and no `disown` (not a POSIX /bin/sh
// builtin).
func TestNetemApplyCommand(t *testing.T) {
	const peer = "69.0.0.10"
	profile := "loss 5% delay 50ms 10ms"
	cmd := netemApplyCommand(peer, profile, 110)

	if !strings.Contains(cmd, "tc qdisc replace") {
		t.Errorf("command must use `tc qdisc replace` (not add), got: %s", cmd)
	}
	if strings.Contains(cmd, "qdisc add") {
		t.Error("command must not use `tc qdisc add` — re-arming an active qdisc would error")
	}
	if !strings.Contains(cmd, "sudo -n") {
		t.Error("command must use sudo -n throughout (fail fast, never prompt/hang)")
	}
	if !strings.Contains(cmd, "netem "+profile) {
		t.Errorf("command must apply the given profile verbatim, got: %s", cmd)
	}
	if !strings.Contains(cmd, "sleep 110") {
		t.Error("command must schedule the self-healing reset at the given auto-reset delay")
	}
	if !strings.Contains(cmd, "tc qdisc del") {
		t.Error("command must schedule a qdisc delete as the self-heal")
	}
	if strings.Contains(cmd, "disown") {
		t.Error("command must not use disown — not a builtin on a POSIX /bin/sh (e.g. dash)")
	}
	if !strings.Contains(cmd, "ip -o route get "+peer) {
		t.Error("command must discover the iface via the given peer route")
	}
}

// TestNetemResetCommand locks the idempotency TASK-052 requires: a missing
// qdisc (already clean, or the self-heal already fired) must never be an
// error.
func TestNetemResetCommand(t *testing.T) {
	cmd := netemResetCommand("69.0.0.20")
	if !strings.Contains(cmd, "tc qdisc del") {
		t.Errorf("command must delete the root qdisc, got: %s", cmd)
	}
	if !strings.Contains(cmd, "|| true") {
		t.Error("command must not error when the qdisc is already absent")
	}
}

// TestNetemExpectedDelayMs locks the profile-parsing the self-check relies
// on to size its expectations.
func TestNetemExpectedDelayMs(t *testing.T) {
	cases := []struct {
		profile string
		wantMs  float64
		wantOK  bool
	}{
		{"loss 5% delay 50ms 10ms", 50, true},
		{"reorder 25% delay 100ms", 100, true},
		{"delay 80ms 40ms distribution normal", 80, true},
		{"loss 5%", 0, false}, // no delay component at all
		{"", 0, false},
	}
	for _, c := range cases {
		ms, ok := netemExpectedDelayMs(c.profile)
		if ok != c.wantOK || (ok && ms != c.wantMs) {
			t.Errorf("netemExpectedDelayMs(%q) = (%v, %v), want (%v, %v)", c.profile, ms, ok, c.wantMs, c.wantOK)
		}
	}
}

// TestNetemSelfCheckPassed locks the verdict logic that is the actual
// safety net for FIX-H: no measurable RTT rise must never pass, since that
// is exactly what a wrong-interface (default-route) no-op looks like.
func TestNetemSelfCheckPassed(t *testing.T) {
	profile := "loss 5% delay 50ms 10ms" // 50ms expected delay

	if ok, msg := netemSelfCheckPassed(profile, 1.0, 60.0); !ok {
		t.Errorf("a clear 59ms rise under a 50ms delay profile must pass, got fail: %s", msg)
	}
	if ok, msg := netemSelfCheckPassed(profile, 1.0, 1.2); ok {
		t.Errorf("a ~0ms delta (the wrong-interface no-op signature) must never pass, got pass: %s", msg)
	}
	if ok, _ := netemSelfCheckPassed(profile, 5.0, 5.0+netemSelfCheckThresholdMs-0.1); ok {
		t.Error("a delta just under the threshold must fail, not pass")
	}
	if ok, _ := netemSelfCheckPassed(profile, 5.0, 5.0+netemSelfCheckThresholdMs+0.1); !ok {
		t.Error("a delta just over the threshold must pass")
	}
	// A loss-only profile has nothing for RTT to measure — must refuse
	// (never silently pass) rather than guess.
	if ok, msg := netemSelfCheckPassed("loss 5%", 1.0, 60.0); ok {
		t.Errorf("a loss-only profile (no delay term) must not be judged by RTT, got pass: %s", msg)
	}
}

// TestParsePingAvgMs locks the parser against iputils-ping's real summary
// line format.
func TestParsePingAvgMs(t *testing.T) {
	out := `PING 69.0.0.11 (69.0.0.11) 56(84) bytes of data.
64 bytes from 69.0.0.11: icmp_seq=1 ttl=64 time=0.456 ms
64 bytes from 69.0.0.11: icmp_seq=2 ttl=64 time=0.398 ms
64 bytes from 69.0.0.11: icmp_seq=3 ttl=64 time=0.512 ms

--- 69.0.0.11 ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 2003ms
rtt min/avg/max/mdev = 0.398/0.455/0.512/0.047 ms
`
	avg, err := parsePingAvgMs(out)
	if err != nil {
		t.Fatalf("parsePingAvgMs: %v", err)
	}
	if avg != 0.455 {
		t.Errorf("avg = %v, want 0.455", avg)
	}

	if _, err := parsePingAvgMs("garbage, no rtt line here"); err == nil {
		t.Error("parsePingAvgMs must error on unparseable output, not return a silent zero")
	}
}

// TestNodeSSHTarget_RefusesDesktop locks the single most important guard in
// this whole harness: whatever node resolves to the desktop IP must be
// refused outright, because that's gridsim's host AND the host running this
// very dashboard process. A netem apply there would cut the dashboard and
// the SSH session needed to undo it.
func TestNodeSSHTarget_RefusesDesktop(t *testing.T) {
	d := newMayhemDriver(map[string]string{
		"gridsim": "http://" + netemDesktopIP + ":11112",
		"hub":     "http://69.0.0.1:9100",
		"solar":   "http://69.0.0.10:6020",
	})

	if _, err := d.nodeSSHTarget("gridsim"); err == nil {
		t.Fatal("nodeSSHTarget(gridsim) must refuse — gridsim resolves to the desktop")
	}
	if _, err := d.nodeSSHTarget("hub"); err != nil {
		t.Errorf("nodeSSHTarget(hub) should succeed, got: %v", err)
	}
	if _, err := d.nodeSSHTarget("nonexistent-node"); err == nil {
		t.Error("nodeSSHTarget must error on an unknown node rather than guess")
	}
}

// TestNodeSSHTarget_DefaultUser locks the dmitri default (docs/BENCH.md) and
// the LEXA_SSH_USER override, mirroring hubSSHTarget's existing contract.
func TestNodeSSHTarget_DefaultUser(t *testing.T) {
	d := newMayhemDriver(map[string]string{"solar": "http://69.0.0.10:6020"})

	target, err := d.nodeSSHTarget("solar")
	if err != nil {
		t.Fatalf("nodeSSHTarget: %v", err)
	}
	if target != "dmitri@69.0.0.10" {
		t.Errorf("target = %q, want dmitri@69.0.0.10", target)
	}

	t.Setenv("LEXA_SSH_USER", "otheruser")
	target, err = d.nodeSSHTarget("solar")
	if err != nil {
		t.Fatalf("nodeSSHTarget: %v", err)
	}
	if target != "otheruser@69.0.0.10" {
		t.Errorf("target = %q, want otheruser@69.0.0.10 (LEXA_SSH_USER override)", target)
	}
}
