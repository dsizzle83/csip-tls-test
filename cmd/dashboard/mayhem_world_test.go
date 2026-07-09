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

// ── Hub-local clock step (TASK-038 / GAP-04) ────────────────────────────────

// TestHubClockNTPCommand locks the timedatectl toggle shape.
func TestHubClockNTPCommand(t *testing.T) {
	if got := hubClockNTPCommand(true); !strings.Contains(got, "timedatectl set-ntp true") {
		t.Errorf("hubClockNTPCommand(true) = %q, want it to enable NTP", got)
	}
	if got := hubClockNTPCommand(false); !strings.Contains(got, "timedatectl set-ntp false") {
		t.Errorf("hubClockNTPCommand(false) = %q, want it to disable NTP", got)
	}
	if !strings.HasPrefix(hubClockNTPCommand(true), "sudo ") || !strings.HasPrefix(hubClockNTPCommand(false), "sudo ") {
		t.Error("hubClockNTPCommand must use sudo — the hub Pi's passwordless sudo is what makes this scenario possible at all")
	}
}

// TestHubClockStepCommand locks the portable relative-step form: `date -s`
// gets an ABSOLUTE timestamp resolved by `date -d '<N> seconds'`, never a
// bare relative spec handed straight to -s (not every date -s build accepts
// one). Must work for both a positive (forward) and negative (backward) delta.
func TestHubClockStepCommand(t *testing.T) {
	fwd := hubClockStepCommand(3600)
	if !strings.Contains(fwd, "date -d '3600 seconds'") {
		t.Errorf("hubClockStepCommand(3600) = %q, want a date -d '3600 seconds' resolution", fwd)
	}
	if !strings.Contains(fwd, `sudo date -s "$(`) {
		t.Errorf("hubClockStepCommand(3600) = %q, want sudo date -s fed the resolved timestamp via $(...)", fwd)
	}

	back := hubClockStepCommand(-3600)
	if !strings.Contains(back, "date -d '-3600 seconds'") {
		t.Errorf("hubClockStepCommand(-3600) = %q, want a date -d '-3600 seconds' resolution", back)
	}

	// The two must be exact inverses of each other's delta so a
	// forward-then-back (or back-then-forward) pair is a true round trip.
	if !strings.Contains(fwd, "3600") || !strings.Contains(back, "-3600") {
		t.Errorf("fwd/back commands are not inverse deltas: fwd=%q back=%q", fwd, back)
	}
}

// TestHubClockDriftOK locks the teardown drift check's decision logic — the
// property the acceptance criteria and the task's "abort at any tick" design
// both depend on: within hubClockDriftToleranceS of a known-good reference is
// OK regardless of sign, past it is not, and this must hold whether the hub
// is ahead of or behind the reference.
func TestHubClockDriftOK(t *testing.T) {
	const ref = int64(1_800_000_000)

	cases := []struct {
		name    string
		hubUnix int64
		want    bool
	}{
		{"exact match", ref, true},
		{"60s ahead", ref + 60, true},
		{"60s behind", ref - 60, true},
		{"exactly at tolerance ahead", ref + hubClockDriftToleranceS, true},
		{"exactly at tolerance behind", ref - hubClockDriftToleranceS, true},
		{"1s past tolerance ahead", ref + hubClockDriftToleranceS + 1, false},
		{"1s past tolerance behind", ref - hubClockDriftToleranceS - 1, false},
		{"stuck +1h (never restored)", ref + 3600, false},
		{"stuck -1h (never restored)", ref - 3600, false},
	}
	for _, c := range cases {
		if got := hubClockDriftOK(c.hubUnix, ref); got != c.want {
			t.Errorf("%s: hubClockDriftOK(%d, %d) = %v, want %v", c.name, c.hubUnix, ref, got, c.want)
		}
	}
}

// TestHubClockAbsoluteCorrectionCommand locks the abort-safe correction path:
// an ABSOLUTE `date -s @<unix>` set, never another relative step (which would
// compound rather than correct if a run aborted partway through its own
// relative steps).
func TestHubClockAbsoluteCorrectionCommand(t *testing.T) {
	const ref = int64(1_800_000_000)
	cmd := hubClockAbsoluteCorrectionCommand(ref)
	if !strings.Contains(cmd, "sudo date -s @1800000000") {
		t.Errorf("hubClockAbsoluteCorrectionCommand(%d) = %q, want an absolute sudo date -s @%d", ref, cmd, ref)
	}
	if strings.Contains(cmd, "date -d") {
		t.Errorf("hubClockAbsoluteCorrectionCommand must be a plain absolute set, not another relative resolution: %q", cmd)
	}
}

// TestWorldScenarios_ClockStepPairPresent locks the acceptance criterion
// "--list shows local-clock-step-forward and local-clock-step-back": the
// catalogue worldScenarios() feeds /api/qa/scenarios (and thus mayhem.py
// --list) must contain both new IDs, each with a distinct ID (no collision
// with any existing scenario) and a sane Category/HoldS.
func TestWorldScenarios_ClockStepPairPresent(t *testing.T) {
	d := newMayhemDriver(map[string]string{"hub": "http://69.0.0.1:9100"})
	scs := d.worldScenarios()

	seen := map[string]int{}
	for _, sc := range scs {
		seen[sc.ID]++
	}
	for _, id := range []string{"local-clock-step-forward", "local-clock-step-back"} {
		if seen[id] != 1 {
			t.Errorf("worldScenarios() must contain exactly one %q, got %d", id, seen[id])
		}
	}
	for id, n := range seen {
		if n > 1 {
			t.Errorf("duplicate scenario ID %q (%d copies) — every ID in the catalogue must be unique", id, n)
		}
	}

	var fwd, back *mayScenario
	for _, sc := range scs {
		switch sc.ID {
		case "local-clock-step-forward":
			fwd = sc
		case "local-clock-step-back":
			back = sc
		}
	}
	if fwd == nil || back == nil {
		t.Fatal("both clock-step scenarios must be present")
	}
	for _, sc := range []*mayScenario{fwd, back} {
		if sc.HoldS <= 0 {
			t.Errorf("%s: HoldS = %d, want > 0", sc.ID, sc.HoldS)
		}
		if sc.setup == nil || sc.perTick == nil || sc.evaluate == nil || sc.teardown == nil {
			t.Errorf("%s: every scenario stage (setup/perTick/evaluate/teardown) must be wired", sc.ID)
		}
	}
}

// Note: the INCONCLUSIVE-without-SSH acceptance criterion (both scenarios'
// setup calls d.hubSSH("true") first, identically to the established
// hub-restart-mid-cap/disk-full precedent — see worldScenarios()) is
// deliberately NOT exercised here with a real ssh subprocess: doing so would
// shell out and attempt a real network connection, which this task's lane
// forbids while a bench soak is mid-run. That path is structurally identical
// to the two existing scenarios' setup (same d.hubSSH("true") probe, same
// %w-wrapped "hub SSH unavailable" error naming SSH), which is unverified by
// a unit test either — HIL verification (LEXA_SSH_USER=nobody against the
// real bench) is scoped to the later batched validation session per the
// launch brief.

// ── WS-2 consumer-restart-after-quiescence (docs/refactor/HANDOFF.md §8) ────

// TestWorldScenarios_ConsumerRestartAfterQuiescencePresent locks the
// catalogue-registration shape of the new scenario: present exactly once,
// every stage wired, Extended (its hold is well past 6 min — RSK-12), and an
// SSH probe in setup identical in spirit to hub-restart-mid-cap/disk-full's
// (same INCONCLUSIVE-without-SSH contract, not re-verified here with a real
// subprocess — see the note above).
func TestWorldScenarios_ConsumerRestartAfterQuiescencePresent(t *testing.T) {
	d := newMayhemDriver(map[string]string{"hub": "http://69.0.0.1:9100"})
	scs := d.worldScenarios()

	var found *mayScenario
	n := 0
	for _, sc := range scs {
		if sc.ID == "consumer-restart-after-quiescence" {
			found = sc
			n++
		}
	}
	if n != 1 {
		t.Fatalf(`worldScenarios() must contain exactly one "consumer-restart-after-quiescence", got %d`, n)
	}
	if !found.Extended {
		t.Error("consumer-restart-after-quiescence must be Extended (RSK-12) — its hold is minutes long")
	}
	if found.HoldS <= 360 {
		t.Errorf("HoldS = %d, want > 360 (must exceed 6 min per the task's own note)", found.HoldS)
	}
	if found.HoldS != consumerRestartQuiescenceS+consumerRestartRecoveryWindowS {
		t.Errorf("HoldS = %d, want quiescence(%d)+recovery(%d)", found.HoldS, consumerRestartQuiescenceS, consumerRestartRecoveryWindowS)
	}
	if found.setup == nil || found.perTick == nil || found.evaluate == nil || found.teardown == nil {
		t.Error("every scenario stage (setup/perTick/evaluate/teardown) must be wired")
	}
}

// consumerRestartSamples builds a timeline for
// diagnoseConsumerRestartAfterQuiescence: n samples at 1 Hz, GridOK/
// HubReachable true throughout (this scenario's judging signal is the
// inverter's own ceiling register, not grid/solar telemetry, so those stay
// healthy by default in every fixture below — the specific field each test
// cares about is set by mut).
func consumerRestartSamples(n int, mut func(i int, s *maySample)) []maySample {
	out := make([]maySample, n)
	for i := range out {
		s := maySample{T: float64(i), GridOK: true, SolarOK: true, HubReachable: true}
		mut(i, &s)
		out[i] = s
	}
	return out
}

// TestDiagnoseConsumerRestartAfterQuiescence_Pass: the cap holds through
// quiescence, the restart happens at consumerRestartQuiescenceS, and the
// standing cap is back (ceiling register never above the restore floor,
// hub re-adopts exportCap) within a few seconds — a clean recovery.
func TestDiagnoseConsumerRestartAfterQuiescence_Pass(t *testing.T) {
	s := consumerRestartSamples(consumerRestartHoldS, func(i int, smp *maySample) {
		smp.SolarCeilingOK, smp.SolarCeilingEna, smp.SolarCeilingPct = true, true, 0
		// Adopted throughout except a brief gap right at the restart tick
		// (lexa-modbus down for a couple of seconds while it restarts).
		restarting := i >= consumerRestartQuiescenceS && i < consumerRestartQuiescenceS+3
		smp.HubAdopted, smp.AdoptedTyp = !restarting, "exportCap"
	})
	f := diagnoseConsumerRestartAfterQuiescence(scFor("consumer-restart-after-quiescence"), exportCons(), s)
	if f.Verdict != "PASS" {
		t.Fatalf("verdict = %s, want PASS (%s): %v", f.Verdict, f.Headline, f.Diagnosis)
	}
}

// TestDiagnoseConsumerRestartAfterQuiescence_FailOpenReproduced is the core
// WS-2 regression pin: if the ceiling register EVER reads restore
// (uncurtailed) after the restart, this must be FAIL regardless of what the
// hub's own /status claims — ground truth from the device is what convicts
// the bug.
func TestDiagnoseConsumerRestartAfterQuiescence_FailOpenReproduced(t *testing.T) {
	s := consumerRestartSamples(consumerRestartHoldS, func(i int, smp *maySample) {
		smp.SolarCeilingOK = true
		if i < consumerRestartQuiescenceS {
			smp.SolarCeilingEna, smp.SolarCeilingPct = true, 0
			smp.HubAdopted, smp.AdoptedTyp = true, "exportCap"
			return
		}
		// Post-restart: seedRestoreCeiling's fail-open — the inverter is
		// reconnected to the fully-open ceiling, and /status confidently
		// (wrongly) still claims exportCap is adopted.
		smp.SolarCeilingEna, smp.SolarCeilingPct = true, 100
		smp.HubAdopted, smp.AdoptedTyp = true, "exportCap"
	})
	f := diagnoseConsumerRestartAfterQuiescence(scFor("consumer-restart-after-quiescence"), exportCons(), s)
	if f.Verdict != "FAIL" {
		t.Fatalf("verdict = %s, want FAIL (%s)", f.Verdict, f.Headline)
	}
	assertDiag(t, f, "WS-2")
}

// TestDiagnoseConsumerRestartAfterQuiescence_FailOpenViaDisabledLimit covers
// the OTHER possible restore encoding this oracle defends against: the
// device's WMaxLimPct_Ena bit reporting disabled (limit not enforced at all)
// rather than pct climbing to ~100 — either one is "uncurtailed".
func TestDiagnoseConsumerRestartAfterQuiescence_FailOpenViaDisabledLimit(t *testing.T) {
	s := consumerRestartSamples(consumerRestartHoldS, func(i int, smp *maySample) {
		smp.SolarCeilingOK = true
		if i < consumerRestartQuiescenceS {
			smp.SolarCeilingEna, smp.SolarCeilingPct = true, 0
		} else {
			smp.SolarCeilingEna, smp.SolarCeilingPct = false, 0 // limiting disabled == restore
		}
		smp.HubAdopted, smp.AdoptedTyp = true, "exportCap"
	})
	f := diagnoseConsumerRestartAfterQuiescence(scFor("consumer-restart-after-quiescence"), exportCons(), s)
	if f.Verdict != "FAIL" {
		t.Fatalf("verdict = %s, want FAIL (%s)", f.Verdict, f.Headline)
	}
}

// TestDiagnoseConsumerRestartAfterQuiescence_NeverReAdopted: no fail-open
// write landed (ceiling register stays low the whole time), but the hub also
// never shows the cap adopted again after the restart — a different bug
// (stuck reconciler), still worth a distinct FAIL rather than a false PASS.
func TestDiagnoseConsumerRestartAfterQuiescence_NeverReAdopted(t *testing.T) {
	s := consumerRestartSamples(consumerRestartHoldS, func(i int, smp *maySample) {
		smp.SolarCeilingOK, smp.SolarCeilingEna, smp.SolarCeilingPct = true, true, 0
		smp.HubAdopted, smp.AdoptedTyp = i < consumerRestartQuiescenceS, "exportCap"
	})
	f := diagnoseConsumerRestartAfterQuiescence(scFor("consumer-restart-after-quiescence"), exportCons(), s)
	if f.Verdict != "FAIL" {
		t.Fatalf("verdict = %s, want FAIL (%s)", f.Verdict, f.Headline)
	}
	if !containsFold(f.Headline, "never observably re-adopted") {
		t.Errorf("headline = %q, want it to name the never-re-adopted failure mode", f.Headline)
	}
}

// TestDiagnoseConsumerRestartAfterQuiescence_Degraded: no fail-open write,
// and the cap DOES come back, but only well past
// consumerRestartRecoveryWindowS — slow, not broken.
func TestDiagnoseConsumerRestartAfterQuiescence_Degraded(t *testing.T) {
	readoptAt := consumerRestartQuiescenceS + consumerRestartRecoveryWindowS + 10
	n := readoptAt + 5
	s := consumerRestartSamples(n, func(i int, smp *maySample) {
		smp.SolarCeilingOK, smp.SolarCeilingEna, smp.SolarCeilingPct = true, true, 0
		smp.HubAdopted, smp.AdoptedTyp = i < consumerRestartQuiescenceS || i >= readoptAt, "exportCap"
	})
	f := diagnoseConsumerRestartAfterQuiescence(scFor("consumer-restart-after-quiescence"), exportCons(), s)
	if f.Verdict != "DEGRADED" {
		t.Fatalf("verdict = %s, want DEGRADED (%s)", f.Verdict, f.Headline)
	}
}

// TestDiagnoseConsumerRestartAfterQuiescence_BlindOnCeilingProbeGap: an
// otherwise-clean-looking run (re-adopts fast, no restore observed) whose
// ceiling register probe was absent for most of the window must not be
// certified PASS — the WS-3 constraint-aware BLIND floor (mayJudgeAbsentBlindFrac)
// applies to this scenario's own judging sensor exactly as it does to every
// other oracle's.
func TestDiagnoseConsumerRestartAfterQuiescence_BlindOnCeilingProbeGap(t *testing.T) {
	s := consumerRestartSamples(consumerRestartHoldS, func(i int, smp *maySample) {
		// The solar sim answered only the first ~5% of ticks — well under the
		// 80% availability floor (1 - mayJudgeAbsentBlindFrac).
		smp.SolarCeilingOK = i < consumerRestartHoldS/20
		smp.SolarCeilingEna, smp.SolarCeilingPct = true, 0
		smp.HubAdopted, smp.AdoptedTyp = true, "exportCap"
	})
	f := diagnoseConsumerRestartAfterQuiescence(scFor("consumer-restart-after-quiescence"), exportCons(), s)
	if f.Verdict != "BLIND" {
		t.Fatalf("verdict = %s, want BLIND (probe mostly absent must never certify PASS)", f.Verdict)
	}
	assertDiag(t, f, "solar ceiling register")
}

// TestDiagnoseConsumerRestartAfterQuiescence_NoSamples: the run-integrity
// contract every diagnoser shares (mayhem_test.go's siblings) — an empty
// timeline is INCONCLUSIVE, never a verdict this oracle didn't actually judge.
func TestDiagnoseConsumerRestartAfterQuiescence_NoSamples(t *testing.T) {
	f := diagnoseConsumerRestartAfterQuiescence(scFor("consumer-restart-after-quiescence"), exportCons(), nil)
	if f.Verdict != "INCONCLUSIVE" {
		t.Fatalf("verdict = %s, want INCONCLUSIVE", f.Verdict)
	}
}
