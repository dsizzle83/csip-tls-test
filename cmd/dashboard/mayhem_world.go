package main

// mayhem_world.go — the "what the world actually does" scenario wave (QA gap
// review 2026-07-01, docs/QA_GAPS_20260701.md). The original 42 scenarios fault
// the DEVICES and the BUS; this wave faults the three surfaces the field breaks
// most and the suite did not: the WAN to the utility server, the meter's
// installation, and time itself — plus dynamic environment shapes (cloud
// flicker, control churn) and lifecycle edges (release while a device is dark,
// the hub's own process dying) that static mid-hold faults never exercise.
//
// Scenario IDs here:
//
//	wan-outage-hold          utility server dies mid-control — keep enforcing
//	wan-outage-expiry        control expires DURING the outage — release blind
//	northbound-hang          server wedges (accept-then-stall) — don't wedge with it
//	meter-ct-inverted        CT clamp backwards — don't be confidently wrong
//	clock-jump-forward       NTP step expires everything at once — release cleanly
//	control-churn            utility rewrites the cap every ~12 s — track, don't hunt
//	pv-flicker               cloud-edge sawtooth under a cap — hold without hunting
//	release-while-rebooting  cap released while the inverter is dark — no stale latch
//	hub-restart-mid-cap      the hub process itself dies and restarts — re-adopt
//
// hub-restart-mid-cap needs SSH to the hub Pi (BatchMode, passwordless sudo per
// docs/BENCH.md); when SSH is unavailable the scenario reports INCONCLUSIVE at
// setup rather than a misleading verdict.
//
// netem-loss-export-cap, netem-reorder-northbound, netem-jitter-evse
// (TASK-052 / GAP-11): the first scenarios that fault the actual wire. Every
// fault above is app-layer (simapi /inject or /fault, gridsim
// /admin/outage) — real LANs corrupt, reorder, and delay packets, and
// nothing here reached the wire until now. See the "netem packet-chaos"
// section below for the harness.
//
// export-dither-at-breach, soc-dither-at-reserve (TASK-054 / GAP-08): guard-
// threshold dither sweeps — ±ε square waves sitting ON the optimizer's decision
// lines (cap+complianceBreachW, SOCReserve) for several minutes, rather than
// holding or ramping a fault once. EXTENDED-SET (mayScenario.Extended):
// excluded from a default/full run — RSK-12 — run via --only or
// --extended/include_extended. See the "Guard-threshold dither sweeps" section
// below.

import (
	"errors"
	"fmt"
	"log"
	"net/url"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// Outage modes — mirror sim/gridsim/outage.go (OutageDown / OutageHang).
const (
	gridsimOutageDown = "down"
	gridsimOutageHang = "hang"
)

// gridsimOutage arms/clears the northbound outage injector (sim/gridsim/outage.go).
func (d *mayhemDriver) gridsimOutage(mode string, durationS, hangS int) error {
	return d.post("gridsim", "/admin/outage", map[string]any{
		"mode": mode, "duration_s": durationS, "hang_s": hangS,
	})
}

func (d *mayhemDriver) gridsimOutageClear() {
	_ = d.post("gridsim", "/admin/outage", map[string]any{"clear": true})
}

// suppressDefault clears the bench's program-0 DefaultDERControl (a 5 kW export
// cap) for the duration of a recovery-oracle scenario and returns the restore
// func for teardown. After an event releases, the hub CORRECTLY falls back to
// that default, whose conservative export ratchet (limit × (1−margin) ≈ 4 kW
// target → ceiling ≈ 4.4 kW) holds solar at ~92% of a 4.8 kW potential — which
// the diagnoseRecovery ≥95%-of-potential bar misreads as a stuck ceiling (the
// QA v5 clock-jump-forward FAILs all ended at 4245–4500 W of 4800). Clearing
// the default makes "release" unambiguously mean "unconstrained". Every
// diagnoseRecovery scenario must use this (wan-outage-expiry pioneered it,
// QA 2026-07-02 fix #6; clock-jump-forward / curtailment-release /
// release-while-rebooting inherited the artifact until 2026-07-03).
func (d *mayhemDriver) suppressDefault() func() {
	var saved map[string]any
	_ = d.getJSON("gridsim", "/admin/default?program=0", &saved)
	_ = d.post("gridsim", "/admin/default", map[string]any{"program": 0, "clear": true})
	return func() {
		if len(saved) > 0 {
			_ = d.post("gridsim", "/admin/default", map[string]any{"program": 0, "base": saved})
		}
	}
}

// hubSSHTarget derives user@host for the hub Pi from the hub backend URL.
// User defaults to dmitri (docs/BENCH.md); override with LEXA_SSH_USER.
func (d *mayhemDriver) hubSSHTarget() (string, error) {
	u, err := url.Parse(d.backends["hub"])
	if err != nil || u.Hostname() == "" {
		return "", fmt.Errorf("cannot derive hub host from %q", d.backends["hub"])
	}
	user := os.Getenv("LEXA_SSH_USER")
	if user == "" {
		user = "dmitri"
	}
	return user + "@" + u.Hostname(), nil
}

// hubSSH runs a command on the hub Pi non-interactively. BatchMode means a
// missing key/agent fails fast instead of prompting inside the dashboard.
func (d *mayhemDriver) hubSSH(command string) error {
	target, err := d.hubSSHTarget()
	if err != nil {
		return err
	}
	cmd := exec.Command("ssh",
		"-o", "BatchMode=yes",
		"-o", "ConnectTimeout=4",
		target, command)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("ssh %s %q: %v (%s)", target, command, err, out)
	}
	return nil
}

// hubSSHOutput is hubSSH for a caller that needs stdout back (e.g. reading
// the hub's configured MQTT client ID, TASK-049) rather than only a
// fire-and-check-exit-status result. Same BatchMode/timeout contract.
func (d *mayhemDriver) hubSSHOutput(command string) (string, error) {
	target, err := d.hubSSHTarget()
	if err != nil {
		return "", err
	}
	cmd := exec.Command("ssh",
		"-o", "BatchMode=yes",
		"-o", "ConnectTimeout=4",
		target, command)
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("ssh %s %q: %v", target, command, err)
	}
	return strings.TrimSpace(string(out)), nil
}

// ── netem packet-chaos (TASK-052 / GAP-11) ──────────────────────────────────
//
// tc netem faults the actual bench-LAN wire — loss, reorder, delay, jitter —
// on a bench Pi's real interface over SSH. Cheap and brutal: app-layer
// injection (simapi /inject, gridsim /admin/outage, mqttproxy) cannot
// reproduce what a real LAN does daily. scripts/netem.sh is the standalone
// CLI form of the same primitive (manual use, TASK-078's soak); the helpers
// below are what the curated netem-* scenarios call directly.
//
// netemDesktopIP is the desktop's bench IP (docs/BENCH.md) — gridsim AND
// this very dashboard process live there. netem must NEVER target it:
// doing so would sever the dashboard's own network path and the SSH
// session that would need to undo it. Guarded in nodeSSHTarget; do not
// remove or bypass this guard.
const netemDesktopIP = "69.0.0.20"

// netemSelfCheckThresholdMs is the minimum RTT rise (post-apply minus
// baseline) netemModifier requires before it trusts an apply actually
// landed. The bench Pis are dual-homed (a WiFi uplink is their default
// route); if `tc netem` landed there instead of the real bench-LAN iface,
// every scenario downstream would silently no-op and PASS for the wrong
// reason — exactly the failure mode GAP-11 exists to catch. Set well under
// the smallest curated profile's delay term (50ms) so ping/scheduler jitter
// can't false-trip it, but far enough above zero that a true no-op cannot
// pass.
const netemSelfCheckThresholdMs = 15.0

// nodeAddr resolves node's bare host (no scheme/port) from d.backends.
// node is one of the simapi/backend keys wired in main.go — "hub", "solar",
// "battery", "meter", "ev" ("gridsim" resolves too, but see nodeSSHTarget's
// desktop guard: it is never a valid netem target).
func (d *mayhemDriver) nodeAddr(node string) (string, error) {
	base, ok := d.backends[node]
	if !ok {
		return "", fmt.Errorf("unknown node %q", node)
	}
	u, err := url.Parse(base)
	if err != nil || u.Hostname() == "" {
		return "", fmt.Errorf("cannot derive %s host from %q", node, base)
	}
	return u.Hostname(), nil
}

// nodeSSHTarget derives user@host for an arbitrary bench node — hubSSHTarget
// generalized to every node the netem scenarios touch (hubSSHTarget itself
// is untouched; existing callers keep using it). Refuses any node that
// resolves to the desktop: netem there would cut the dashboard and the SSH
// session that would need to undo it. This guard is load-bearing.
func (d *mayhemDriver) nodeSSHTarget(node string) (string, error) {
	host, err := d.nodeAddr(node)
	if err != nil {
		return "", err
	}
	if host == netemDesktopIP {
		return "", fmt.Errorf("refusing node %q: resolves to the desktop (%s) — netem must never target it", node, netemDesktopIP)
	}
	user := os.Getenv("LEXA_SSH_USER")
	if user == "" {
		user = "dmitri"
	}
	return user + "@" + host, nil
}

// nodeSSH runs command on the given bench node non-interactively (BatchMode:
// a missing key/agent fails fast instead of prompting inside the dashboard).
// Generalizes hubSSH to any node.
func (d *mayhemDriver) nodeSSH(node, command string) error {
	target, err := d.nodeSSHTarget(node)
	if err != nil {
		return err
	}
	cmd := exec.Command("ssh",
		"-o", "BatchMode=yes",
		"-o", "ConnectTimeout=4",
		target, command)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("ssh %s %q: %v (%s)", target, command, err, out)
	}
	return nil
}

// netemPeerIP returns the peer IP netem's iface-discovery route lookup
// should target for node — NEVER node's own default route (the bench Pis
// are dual-homed via WiFi; their default route goes out the WAN iface, not
// the 69.0.0.x LAN, so netem there would silently no-op — see
// scripts/netem.sh's header and TASK-052's FIX-H). The hub's peer is a sim
// Pi; every sim Pi's peer is the desktop (gridsim).
func netemPeerIP(node string) string {
	if node == "hub" {
		return "69.0.0.10" // solar-pi; any provisioned sim Pi works as the hub's peer
	}
	return netemDesktopIP
}

// netemIfaceDiscoverCmd is the shell fragment every netem remote command
// starts with: resolve $IFACE via the peer route (never the default route)
// and refuse (exit 1) rather than guess if that lookup comes back empty.
// Pulled out as a pure string builder so the logic is unit-testable without
// SSH — mirrors fillDiskCommand's pattern (TASK-050).
func netemIfaceDiscoverCmd(peerIP string) string {
	return fmt.Sprintf(
		`IFACE=$(ip -o route get %s 2>/dev/null | awk '{for(i=1;i<=NF;i++) if ($i=="dev"){print $(i+1); exit}}'); `+
			`if [ -z "$IFACE" ]; then echo "netem: could not discover iface via ip -o route get %s" >&2; exit 1; fi`,
		peerIP, peerIP)
}

// netemApplyCommand builds the full remote command netemApply runs over
// SSH: discover the real bench-LAN iface, `replace` (not `add` — re-arming
// must not error on an already-active qdisc) the root qdisc with profile,
// then schedule a self-healing reset in a detached background subshell so a
// lost teardown (dashboard crash, hard abort) still clears it after
// autoResetS seconds. `sudo -n` throughout — a node without passwordless
// sudo fails fast, never hangs on a password prompt inside the dashboard
// process. The self-heal deliberately does not use `disown` (not a builtin
// on a POSIX /bin/sh such as dash) — plain `&` with fds redirected to
// /dev/null is the portable idiom (mirrors scripts/netem.sh).
func netemApplyCommand(peerIP, profile string, autoResetS int) string {
	return fmt.Sprintf(
		`%s; sudo -n tc qdisc replace dev "$IFACE" root netem %s && sudo -n sh -c '(sleep %d; tc qdisc del dev '"$IFACE"' root) >/dev/null 2>&1 &'`,
		netemIfaceDiscoverCmd(peerIP), profile, autoResetS)
}

// netemResetCommand builds the remote command netemReset runs: discover the
// iface and delete its root qdisc. `|| true` so a missing qdisc (already
// clean, or the self-heal already fired) is never an error.
func netemResetCommand(peerIP string) string {
	return fmt.Sprintf(`%s; sudo -n tc qdisc del dev "$IFACE" root 2>/dev/null || true`,
		netemIfaceDiscoverCmd(peerIP))
}

// netemApply arms a tc netem profile (raw `tc ... netem` argument string,
// e.g. "loss 5% delay 50ms 10ms") on node's bench-LAN interface, with a
// self-healing scheduled reset after autoResetS seconds regardless of
// whether netemReset is ever called.
func (d *mayhemDriver) netemApply(node, profile string, autoResetS int) error {
	return d.nodeSSH(node, netemApplyCommand(netemPeerIP(node), profile, autoResetS))
}

// netemReset clears node's netem qdisc immediately — the fast teardown
// path; the scheduled reset netemApply arms is the safety net if this is
// never reached.
func (d *mayhemDriver) netemReset(node string) error {
	return d.nodeSSH(node, netemResetCommand(netemPeerIP(node)))
}

// netemExpectedDelayMs extracts the base delay (ms) from a tc netem profile
// string such as "loss 5% delay 50ms 10ms reorder 25%" — the first numeric
// token after the "delay" keyword, with a trailing "ms" stripped. Pure so
// it's unit-testable; used only to size the self-check's expectations.
func netemExpectedDelayMs(profile string) (ms float64, ok bool) {
	fields := strings.Fields(profile)
	for i, f := range fields {
		if f == "delay" && i+1 < len(fields) {
			v := strings.TrimSuffix(fields[i+1], "ms")
			if n, err := strconv.ParseFloat(v, 64); err == nil {
				return n, true
			}
		}
	}
	return 0, false
}

// netemSelfCheckPassed decides the post-apply RTT self-check from measured
// before/after averages — pure so it's unit-testable without a real ping. A
// profile with no delay component cannot be judged by RTT at all (a
// loss-only profile would need a `tc -s qdisc show` packet-counter check
// instead); every curated netem-* scenario in this file includes a delay
// term specifically so this check always applies to them.
func netemSelfCheckPassed(profile string, beforeMs, afterMs float64) (bool, string) {
	expected, ok := netemExpectedDelayMs(profile)
	if !ok {
		return false, fmt.Sprintf("netem self-check: profile %q has no delay component — RTT delta cannot judge it (needs a tc -s qdisc packet-counter check instead)", profile)
	}
	delta := afterMs - beforeMs
	if delta < netemSelfCheckThresholdMs {
		return false, fmt.Sprintf("netem self-check FAILED: RTT rose only %.1fms (before %.1fms, after %.1fms) under a %.0fms delay profile — below the %.0fms floor, netem likely landed on the wrong interface (default-route trap)", delta, beforeMs, afterMs, expected, netemSelfCheckThresholdMs)
	}
	return true, fmt.Sprintf("netem self-check passed: RTT rose %.1fms (before %.1fms, after %.1fms) under a %.0fms delay profile", delta, beforeMs, afterMs, expected)
}

// parsePingAvgMs extracts the average RTT from iputils-ping's summary line
// ("rtt min/avg/max/mdev = 0.123/0.456/0.789/0.012 ms"). Pure so it's
// unit-testable without actually pinging.
func parsePingAvgMs(output string) (float64, error) {
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		idx := strings.LastIndex(line, "= ")
		if idx < 0 || !strings.Contains(line, "/") {
			continue
		}
		rest := strings.TrimSuffix(strings.TrimSpace(line[idx+2:]), " ms")
		parts := strings.Split(rest, "/")
		if len(parts) < 2 {
			continue
		}
		if avg, err := strconv.ParseFloat(parts[1], 64); err == nil {
			return avg, nil
		}
	}
	return 0, fmt.Errorf("could not parse ping average from output: %q", output)
}

// pingRTTMs runs a handful of local ICMP echoes to host and returns the
// average RTT in ms. Only ever called by the netem self-check (a few pings
// bracketing an apply), never inside the per-tick sampling loop.
func pingRTTMs(host string) (float64, error) {
	cmd := exec.Command("ping", "-c", "3", "-W", "2", host)
	out, err := cmd.Output()
	if err != nil {
		return 0, fmt.Errorf("ping %s: %w", host, err)
	}
	return parsePingAvgMs(string(out))
}

// netemModifier arms profile on node for the scenario's hold (holdS
// seconds) and returns a teardown closure — mirrors suppressDefault's
// modifier-returns-restore-closure shape. Sequence:
//
//  1. Probe sudo -n on node: the sim Pis are NOT guaranteed passwordless
//     sudo (only the hub is, per docs/BENCH.md / TASK-052's prerequisites)
//     — missing it returns an error here, which the caller's setup
//     surfaces as INCONCLUSIVE (mayhem.go's run loop treats any setup
//     error that way), never a hang or a password prompt.
//  2. Baseline-ping node, apply with a self-healing autoReset of holdS+30s
//     (30s margin past the scenario's own teardown so the fast path always
//     wins first), then ping again.
//  3. Self-check the delta (netemSelfCheckPassed): no measurable RTT rise
//     means netem silently landed on the wrong interface (the dual-homed
//     default-route trap) — reset immediately and return an error so the
//     scenario NEVER runs against a no-op fault (that would be a false
//     PASS, exactly the failure mode GAP-11 exists to catch).
func (d *mayhemDriver) netemModifier(node, profile string, holdS int) (func(), error) {
	if err := d.nodeSSH(node, "sudo -n true"); err != nil {
		return nil, fmt.Errorf("netem: node %q lacks passwordless sudo (or SSH is unavailable): %w", node, err)
	}
	host, err := d.nodeAddr(node)
	if err != nil {
		return nil, err
	}
	before, err := pingRTTMs(host)
	if err != nil {
		return nil, fmt.Errorf("netem: baseline ping to %s (%s) failed: %w", node, host, err)
	}
	autoReset := holdS + 30
	if err := d.netemApply(node, profile, autoReset); err != nil {
		return nil, fmt.Errorf("netem: apply on %q failed: %w", node, err)
	}
	time.Sleep(1 * time.Second) // let the new qdisc take effect before judging it
	after, err := pingRTTMs(host)
	if err != nil {
		_ = d.netemReset(node)
		return nil, fmt.Errorf("netem: post-apply ping to %s (%s) failed: %w", node, host, err)
	}
	ok, msg := netemSelfCheckPassed(profile, before, after)
	if !ok {
		_ = d.netemReset(node)
		return nil, errors.New(msg)
	}
	log.Printf("mayhem: netem[%s]: %s", node, msg)
	return func() { _ = d.netemReset(node) }, nil
}

// diagnoseSurvival adapts diagnoseMalform's verdict ladder — survive, hold the
// safe cap, no CannotComply excuse on an export cap, sustained unseat = FAIL,
// transient-with-recovery = DEGRADED — to the non-malform survivability
// scenarios (WAN outage, wedged server, hub restart), rewording the findings so
// the report names the actual fault. The first run of wan-outage-hold showed
// why the ladder matters here: diagnoseConstraint's CannotComply-excuse path
// scored a dropped-then-recovered cap as an acceptable resource limit, which an
// export cap never is.
func diagnoseSurvival(label string) func(*mayScenario, *activeConstraint, []maySample) mayFinding {
	reword := func(s string) string {
		s = strings.ReplaceAll(s, "the malformed resource", label)
		s = strings.ReplaceAll(s, "malformed resource", label)
		s = strings.ReplaceAll(s, "The "+label, capitalizeFirst(label)) // sentence-initial "The malformed resource"
		return s
	}
	return func(sc *mayScenario, cons *activeConstraint, s []maySample) mayFinding {
		f := diagnoseMalform(sc, cons, s)
		f.Headline = reword(f.Headline)
		for i := range f.Diagnosis {
			f.Diagnosis[i] = reword(f.Diagnosis[i])
		}
		f.Fix = sc.Fix // keep the scenario's own fix pointer, not the walker/parser one
		return f
	}
}

// capitalizeFirst upper-cases the first rune of a label for sentence-initial use.
func capitalizeFirst(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

// diagnoseMeterInversion judges the CT-clamp-backwards scenario. The ground
// truth (meter sim /state) still shows the real export breach; the hub's Modbus
// view shows the opposite direction. Three outcomes, worst first:
//
//	FAIL     — sustained true breach, no CannotComply, no meter-distrust flag:
//	           the hub is confidently wrong, the exact harm a backwards CT does.
//	DEGRADED — the breach stood but the hub either flagged the meter or posted
//	           CannotComply: it knew something was wrong and said so.
//	PASS     — the cap held anyway: the hub cross-checked its way past the lie
//	           (device-telemetry energy balance / actuation-response check).
func diagnoseMeterInversion(sc *mayScenario, cons *activeConstraint, s []maySample) mayFinding {
	f := baseFinding(sc)
	if len(s) == 0 {
		f.Verdict = "INCONCLUSIVE"
		f.Headline = "no samples"
		return f
	}
	f.Metrics = scanSamples(cons, s)
	breaches := invExport(cons, s) // sustained post-settling TRUE breaches
	flagged := false
	for _, smp := range s {
		if smp.MeterStale {
			flagged = true
			break
		}
	}

	switch {
	case len(breaches) == 0:
		f.Verdict = "PASS"
		f.Headline = "cap held despite the inverted meter"
		f.Diagnosis = []string{
			"The grid meter reported every flow with its sign flipped, and the hub still kept the site inside the cap — its device-side telemetry cross-check did not let the backwards CT drive control.",
		}
	case f.Metrics.ReportedCannot || flagged:
		f.Verdict = "DEGRADED"
		f.Headline = "breach stood, but the hub distrusted the meter / admitted noncompliance"
		f.Diagnosis = []string{
			fmt.Sprintf("True export breached the cap for %.0fs (peak +%.0f W) while the meter claimed the opposite direction.", f.Metrics.BreachSeconds, f.Metrics.PeakBreachW),
			"The hub surfaced the problem (meter flagged implausible and/or CannotComply posted) instead of silently asserting compliance — operators get a signal to check the install.",
			invSummaryLine("INV-EXPORT (ground truth)", breaches),
		}
	default:
		f.Verdict = "FAIL"
		f.Headline = "confidently wrong: hub trusted the inverted meter and asserted compliance"
		f.Diagnosis = []string{
			fmt.Sprintf("True export breached the cap for %.0fs (peak +%.0f W); the hub's meter view showed a compliant import the whole time, so it did nothing, flagged nothing, admitted nothing.", f.Metrics.BreachSeconds, f.Metrics.PeakBreachW),
			"A backwards CT clamp is the most common metering install error in the field. Passive per-sample plausibility cannot catch it — every value is in range, only the direction lies.",
			"Detection requires an actuation cross-check: when the hub commands a known change (curtail 1 kW), the meter must move the expected direction; moving the WRONG way on repeated actuations convicts the sign.",
			decisionLine(s),
		}
		f.Fix = "Add an actuation-response direction check to the telemetry plausibility engine (orchestrator): on each commanded delta, verify the meter's response sign; N inverted responses ⇒ mark the meter untrusted, fail conservative, raise an alarm."
	}
	return f
}

// ── Disk-full ballast (TASK-050) ─────────────────────────────────────────────
//
// A fallocate'd file fills the hub Pi's /var/lib partition (mosquitto
// persistence + journald + the TASK-039/040 event journal typically share the
// root partition there) to near-full, deterministically and instantly — no
// dd write churn, which would needlessly wear the SD card (RSK-14) just to
// test what happens when it fills. The ballast is the single most dangerous
// artifact in the suite: it is sized with a hard floor so a bad size never
// bricks the node, and every path (normal finish, abort, a scenario error)
// must remove it — see disk-full's teardown and the run() always-teardown
// property this scenario depends on (verified in mayhem.go: teardown runs
// unconditionally after holdAndSample returns, whether that return was a
// clean finish or a ctx-cancelled abort).
const (
	ballastPath = "/var/lib/mayhem-ballast.bin"
	ballastDir  = "/var/lib" // partition fillDisk sizes against (mosquitto/journald's typical home there)

	// diskFloorKiB is the minimum free space (1K blocks, df's default unit)
	// fillDisk requires before it will act at all — a partition already this
	// tight fails safe to INCONCLUSIVE rather than risk a bricked node.
	diskFloorKiB = 61440 // 60 MiB
	// diskReserveKiB is always left free after filling, so sshd/journald/
	// teardown itself can still run without physical access to the Pi.
	diskReserveKiB = 20480 // 20 MiB
)

// fillDiskCommand builds the single SSH command fillDisk runs: read free
// space, refuse (exit non-zero) if it's below diskFloorKiB, else fallocate
// everything past diskReserveKiB. Extracted as a pure string builder so the
// size math and floor guard are unit-testable without SSH.
func fillDiskCommand() string {
	return fmt.Sprintf(
		`set -e; avail=$(df --output=avail %s | tail -1); `+
			`if [ "$avail" -lt %d ]; then echo "insufficient free space (${avail} KiB, need >= %d KiB)" >&2; exit 1; fi; `+
			`size=$((avail - %d)); sudo fallocate -l ${size}K %s`,
		ballastDir, diskFloorKiB, diskFloorKiB, diskReserveKiB, ballastPath)
}

// fillDisk fills the hub Pi's ballastDir partition to near-full. Safe to call
// repeatedly (a re-run against an already-full disk just refuses again, since
// avail will already be under the floor).
func (d *mayhemDriver) fillDisk() error { return d.hubSSH(fillDiskCommand()) }

// freeDisk removes the ballast file. Idempotent (`rm -f`) — always safe to
// call, including when no ballast exists.
func (d *mayhemDriver) freeDisk() error { return d.hubSSH(`sudo rm -f ` + ballastPath) }

// ── Hub-local clock step (TASK-038 / GAP-04) ────────────────────────────────
//
// Every clock scenario before this one (clock-jitter, clock-jump-forward)
// steps the SERVER's clock via gridsim /admin/clock — the hub's own wall
// clock has zero coverage, and NTP's first sync after commissioning is
// exactly this: the hub Pi's local clock jumps while the server's does not.
// TASK-037 anchors freshness/expiry on a monotonic clock at onCSIPControl
// arrival specifically so a local step cannot expire or flap an active
// control; this pair of scenarios (local-clock-step-forward/-back) is the
// validation harness for that anchoring.
//
// systemd-timesyncd will immediately correct a manual `date -s` step, so
// every step disables NTP first (hubClockNTP(false)) and the matching
// restore re-enables it (hubClockNTP(true)) — mirrored by the teardown drift
// check below, which is unconditional and abort-safe.

// hubClockNTPCommand builds the timedatectl toggle. Pure string builder
// (mirrors fillDiskCommand/netemApplyCommand) so its shape is unit-testable
// without SSH.
func hubClockNTPCommand(on bool) string {
	if on {
		return "sudo timedatectl set-ntp true"
	}
	return "sudo timedatectl set-ntp false"
}

// hubClockNTP enables/disables the hub Pi's NTP client (systemd-timesyncd).
func (d *mayhemDriver) hubClockNTP(on bool) error {
	return d.hubSSH(hubClockNTPCommand(on))
}

// hubClockStepCommand builds the remote command that steps the hub's own
// wall clock by deltaSec seconds (positive = forward, negative = back).
// Composed via `date -d '<N> seconds'` (GNU date's relative-spec form,
// accepting a leading '-') rather than `date -s '+1 hour'` directly — not
// every date -s accepts a relative spec, but every date -d does, so
// computing the absolute target with -d and only ever calling -s with that
// resolved timestamp is the portable form (task mechanics note).
func hubClockStepCommand(deltaSec int) string {
	return fmt.Sprintf(`sudo date -s "$(date -d '%d seconds')"`, deltaSec)
}

// hubClockStep steps the hub Pi's wall clock by deltaSec seconds. Caller is
// responsible for disabling NTP first (hubClockNTP(false)) or timesyncd will
// immediately correct it back.
func (d *mayhemDriver) hubClockStep(deltaSec int) error {
	return d.hubSSH(hubClockStepCommand(deltaSec))
}

// hubClockDriftToleranceS is the teardown drift check's threshold (Acceptance
// criteria: "within 120 s of desktop"). Below this, the hub clock is close
// enough to the desktop's (untouched) wall clock that no absolute correction
// is needed — NTP re-enabling (once a source exists) will finish the job.
const hubClockDriftToleranceS = 120

// hubClockDriftOK decides the teardown drift check: is the hub's reported
// unix time (hubUnix) within hubClockDriftToleranceS of a known-good
// reference (desktopUnix, the dashboard host's own untouched clock)? Pure so
// the decision logic is unit-testable without SSH — this is the function the
// task's "unit test for the teardown drift check's decision logic" targets.
// Extracted specifically because "subtract what the perTick step added" is
// wrong when a run aborts before or after that step ever ran; reading the
// hub's ACTUAL current clock and comparing it to a reference is correct at
// every abort point.
func hubClockDriftOK(hubUnix, desktopUnix int64) bool {
	delta := hubUnix - desktopUnix
	if delta < 0 {
		delta = -delta
	}
	return delta <= hubClockDriftToleranceS
}

// hubClockAbsoluteCorrectionCommand builds the absolute-correction command
// the teardown drift check issues when hubClockDriftOK is false: set the
// hub's clock directly to a known-good unix timestamp (`date -s @<unix>`),
// rather than another relative step (which would compound rather than
// correct if the run aborted partway through its own relative steps).
func hubClockAbsoluteCorrectionCommand(desktopUnix int64) string {
	return fmt.Sprintf("sudo date -s @%d", desktopUnix)
}

// hubClockStepTeardown is the shared, unconditional, abort-safe teardown for
// both local-clock-step scenarios: re-enable NTP, then read the hub's actual
// current clock and correct it absolutely if it drifted past tolerance. This
// is correct whether the run finished normally, aborted before the perTick
// restore step ran, or aborted after it — unlike "subtract what was added",
// which is only correct on a clean finish.
func (d *mayhemDriver) hubClockStepTeardown() {
	if err := d.hubClockNTP(true); err != nil {
		log.Printf("mayhem: clock-step teardown: hubClockNTP(true) failed: %v", err)
	}
	out, err := d.hubSSHOutput("date +%s")
	if err != nil {
		log.Printf("mayhem: clock-step teardown: could not read hub clock to verify drift (manual check needed: ssh dmitri@69.0.0.1 timedatectl): %v", err)
		return
	}
	hubUnix, err := strconv.ParseInt(out, 10, 64)
	if err != nil {
		log.Printf("mayhem: clock-step teardown: could not parse hub clock output %q: %v", out, err)
		return
	}
	desktopUnix := time.Now().Unix()
	if hubClockDriftOK(hubUnix, desktopUnix) {
		return
	}
	log.Printf("mayhem: clock-step teardown: hub clock drifted %ds past tolerance — applying absolute correction", hubUnix-desktopUnix)
	if err := d.hubSSH(hubClockAbsoluteCorrectionCommand(desktopUnix)); err != nil {
		log.Printf("mayhem: clock-step teardown: absolute correction FAILED — manual cleanup needed (ssh dmitri@69.0.0.1 sudo date -s @%d && sudo timedatectl set-ntp true): %v", desktopUnix, err)
	}
}

// worldScenarios is appended to the curated suite by scenarios().
func (d *mayhemDriver) worldScenarios() []*mayScenario {
	const loadLow = 250.0

	// armExportCap is the standard "PV pushing hard, battery full ⇒ curtailment
	// is the only lever" preamble shared by the survivability scenarios.
	armExportCap := func(d *mayhemDriver, holdS int, desc string) (*activeConstraint, error) {
		_ = d.post("battery", "/inject", map[string]any{"SoC_pct": 100, "Conn": 1})
		d.injectEnv(d.pvHighW, loadLow)
		return d.postCap("exportCap", 0, holdS, desc)
	}

	return []*mayScenario{
		{
			ID: "wan-outage-hold", Name: "Utility server dies mid-control",
			Category:   "Northbound resilience (INV-EXPORT survivability)",
			Hypothesis: "The WAN to the 2030.5 head-end drops for 45 s while a zero-export cap is active — every CSIP request fails fast with 503. The single most common field event a DERMS sees.",
			Expected:   "Keep enforcing the last-known-good control through the outage (it is still valid) and re-sync when the server returns. An unreachable server must never mean an unenforced control.",
			HoldS:      90,
			Fix:        "Northbound walker must fail closed to last-known-good on discovery errors; the orchestrator keeps enforcing until ValidUntil regardless of server reachability.",
			setup: func(d *mayhemDriver) (*activeConstraint, error) {
				return armExportCap(d, 90, "mayhem: cap through a WAN outage")
			},
			perTick: func(d *mayhemDriver, i int) {
				d.injectEnv(d.pvHighW, loadLow)
				if i == 15 { // cap adopted and settled; now the WAN dies for 45 s
					_ = d.gridsimOutage(gridsimOutageDown, 45, 0)
				}
			},
			evaluate: diagnoseSurvival("the WAN outage"),
			teardown: func(d *mayhemDriver) { d.gridsimOutageClear() },
		},
		func() *mayScenario {
			// diagnoseRecovery scenario: the program-0 default must be
			// suppressed so "release" means "unconstrained" (see suppressDefault).
			var restoreDefault func()
			return &mayScenario{
				ID: "wan-outage-expiry", Name: "Control expires while the utility server is dark",
				Category:   "Northbound resilience (INV-EXPIRED / INV-RESTORE)",
				Hypothesis: "A generation-limit control expires DURING a WAN outage. With the server unreachable there is no walk to 'tell' the hub the control ended — expiry must come from the hub's own clock discipline.",
				Expected:   "Release the control at ValidUntil using local time + last-known clock offset: uncurtail the inverter and stop claiming the control. Never hold a dead control hostage to a dead WAN.",
				HoldS:      90,
				Fix:        "Scheduler expiry must be evaluated locally (serverNow = wall + last offset), not only on a successful re-walk; release path must emit the uncurtail (restoreOnGenLimitClear).",
				setup: func(d *mayhemDriver) (*activeConstraint, error) {
					restoreDefault = d.suppressDefault()
					d.injectEnv(d.pvHighW, loadLow)
					// holdS=10 ⇒ duration 30 s: expires ~t=25–30, well inside the outage.
					return d.postCap("genLimit", 1000, 10, "mayhem: gen limit expiring during WAN outage")
				},
				perTick: func(d *mayhemDriver, i int) {
					d.injectEnv(d.pvHighW, loadLow)
					if i == 12 { // before expiry; dark until ~t=72, long past it
						_ = d.gridsimOutage(gridsimOutageDown, 60, 0)
					}
				},
				evaluate: diagnoseRecovery,
				teardown: func(d *mayhemDriver) {
					d.gridsimOutageClear()
					d.deleteControls(0)
					if restoreDefault != nil {
						restoreDefault()
					}
				},
			}
		}(),
		{
			ID: "northbound-hang", Name: "Utility server wedges: accepts, then stalls every request",
			Category:   "Northbound resilience (INV-EXPORT survivability)",
			Hypothesis: "The head-end (or a middlebox) goes half-dead: TLS accepts, requests are read, responses never come inside any sane deadline. A fetcher without its own timeout wedges the whole northbound with it.",
			Expected:   "The hub's fetcher must enforce its own deadline, contain the stall to the northbound, keep /status responsive, and keep enforcing the still-valid cap. Degrade discovery, not control.",
			HoldS:      80,
			Fix:        "Per-request deadline on the WolfSSLFetcher (and walk-level bound); a slow server must surface as a discovery error, not a hung goroutine holding the session.",
			setup: func(d *mayhemDriver) (*activeConstraint, error) {
				return armExportCap(d, 80, "mayhem: cap under a wedged head-end")
			},
			perTick: func(d *mayhemDriver, i int) {
				d.injectEnv(d.pvHighW, loadLow)
				if i == 15 { // 40 s of accept-then-stall (25 s per request)
					_ = d.gridsimOutage(gridsimOutageHang, 40, 25)
				}
			},
			evaluate: diagnoseSurvival("the wedged head-end"), // survivability + the cap must hold
			teardown: func(d *mayhemDriver) { d.gridsimOutageClear() },
		},
		{
			ID: "meter-ct-inverted", Name: "Grid meter CT clamp installed backwards",
			Category:   "Sensor integrity (INV-EXPORT ground truth)",
			Hypothesis: "The revenue meter's CT clamp is on backwards — the classic install error. Every import reads as an export and vice versa. Values are perfectly plausible; only the direction lies. Under a zero-export cap the hub sees a healthy import while the site back-feeds at full PV.",
			Expected:   "Do not be confidently wrong. Cross-check the meter against device telemetry / actuation response, distrust a meter that moves the wrong way, fail conservative, and raise an alarm. Asserting compliance while exporting is the worst outcome this suite can produce.",
			HoldS:      75,
			Fix:        "Actuation-response direction check in the telemetry plausibility engine (see finding).",
			setup: func(d *mayhemDriver) (*activeConstraint, error) {
				cons, err := armExportCap(d, 75, "mayhem: zero-export cap on an inverted meter")
				if err != nil {
					return nil, err
				}
				// Let the hub adopt the cap on honest readings first, then flip the
				// CT: an install error present from boot is indistinguishable from a
				// swapped source; flipping mid-run also models a meter swap-out.
				go func() {
					time.Sleep(8 * time.Second)
					_ = d.post("meter", "/fault", map[string]any{"kind": "invert_sign"})
				}()
				return cons, nil
			},
			perTick:  func(d *mayhemDriver, i int) { d.injectEnv(d.pvHighW, loadLow) },
			evaluate: diagnoseMeterInversion,
			teardown: func(d *mayhemDriver) {
				_ = d.post("meter", "/fault", map[string]any{"kind": "invert_sign", "clear": true})
			},
		},
		func() *mayScenario {
			// diagnoseRecovery scenario: the program-0 default must be
			// suppressed so "release" means "unconstrained" (see suppressDefault).
			// Before 2026-07-03 this scenario inherited the default-cap artifact:
			// after the jump expired the event, the hub fell back to the 5 kW
			// default whose ratchet held solar at 4245-4500 W of 4800 — under the
			// 95% bar — producing 5/10 false FAILs in QA v5.
			var restoreDefault func()
			return &mayScenario{
				ID: "clock-jump-forward", Name: "Server clock steps 2 h forward mid-control",
				Category:   "Time integrity (INV-EXPIRED / INV-RESTORE)",
				Hypothesis: "The head-end's clock steps two hours forward (NTP step after a long holdover, a DST bug). In server time every active control is instantly long-expired.",
				Expected:   "Follow server time (CSIP: the server clock is authoritative): treat the control as expired, release it, uncurtail, and re-walk for whatever is now active. No stale enforcement, no crash, no flapping.",
				// 90 s, not 75: release lands ~t=25-35 (jump at 15 + expiry confirm
				// ticks) and the inverter needs ~30 s to climb back to ≥95% of
				// potential — at 75 s the verdict was a race against the ramp's last
				// seconds (QA v4: 2/10 FAILs ended at 4250-4500 W of 4800, mid-climb).
				HoldS: 90,
				Fix:   "Clock-offset resync on /tm each walk; scheduler expiry honours the new offset within one cycle (expiry confirm ticks bound the release latency).",
				setup: func(d *mayhemDriver) (*activeConstraint, error) {
					restoreDefault = d.suppressDefault()
					d.injectEnv(d.pvHighW, loadLow)
					// Long-duration control (would cover the window) — the JUMP is what
					// expires it, not the interval.
					return d.postCap("genLimit", 1000, 580, "mayhem: gen limit under a +2h clock step")
				},
				perTick: func(d *mayhemDriver, i int) {
					d.injectEnv(d.pvHighW, loadLow)
					if i == 15 { // adopted and settled; now time lurches
						_ = d.post("gridsim", "/admin/clock", map[string]any{"offset_s": 7200})
					}
				},
				evaluate: diagnoseRecovery, // released ⇒ solar back to potential by the tail
				teardown: func(d *mayhemDriver) {
					_ = d.post("gridsim", "/admin/clock", map[string]any{"offset_s": 0})
					d.deleteControls(0)
					if restoreDefault != nil {
						restoreDefault()
					}
				},
			}
		}(),
		{
			ID: "control-churn", Name: "Utility rewrites the export cap every ~12 s",
			Category:   "CSIP scheduling (INV-EXPORT / INV-HUNT)",
			Hypothesis: "During a volatile event the utility supersedes the cap over and over — delete-and-replace every ~12 s, alternating 0 W and 500 W. Every replacement is a new mRID, a new adoption, a new guard session.",
			Expected:   "Track each replacement within a cycle and enforce whichever cap is current — every phase satisfies the looser 500 W bound, so measured export must never sustain above it, and the loop must not hunt across replacements.",
			HoldS:      80,
			Fix:        "Adoption path must handle rapid mRID turnover without dropping to no-control between replacements (fail-closed hold covers the gap); breach-guard sessions must reset cleanly on genuinely-new caps.",
			setup: func(d *mayhemDriver) (*activeConstraint, error) {
				_ = d.post("battery", "/inject", map[string]any{"SoC_pct": 100, "Conn": 1})
				d.injectEnv(d.pvHighW, loadLow)
				if _, err := d.postCap("exportCap", 0, 80, "mayhem: churn cap #0 (0 W)"); err != nil {
					return nil, err
				}
				// Judged against the LOOSER of the two alternating caps: correct
				// enforcement of either phase keeps export ≤ 500 W all window.
				return &activeConstraint{Typ: "exportCap", LimW: 500}, nil
			},
			perTick: func(d *mayhemDriver, i int) {
				d.injectEnv(d.pvHighW, loadLow)
				if i > 0 && i%12 == 0 {
					d.deleteControls(0)
					lim, tag := 0.0, "0 W"
					if (i/12)%2 == 1 {
						lim, tag = 500, "500 W"
					}
					_, _ = d.postCap("exportCap", lim, 80, "mayhem: churn cap ("+tag+")")
				}
			},
			evaluate: diagnoseConstraint,
			teardown: func(d *mayhemDriver) { d.deleteControls(0) },
		},
		{
			ID: "pv-flicker", Name: "Cloud-edge PV sawtooth under a zero-export cap",
			Category:   "Environment dynamics (INV-EXPORT / INV-HUNT)",
			Hypothesis: "Broken cloud rakes the array: PV swings full-to-40%-to-full every few seconds while a zero-export cap is active. Every other scenario holds the environment still; the field never does.",
			Expected:   "Hold the cap across the swings without hunting: an absolute curtailment ceiling rides through PV dips (output = min(potential, ceiling)); the loop must not chase the flicker with curtail/release cycles.",
			HoldS:      80,
			Fix:        "Curtailment must be a held absolute ceiling, not a per-tick recomputation chasing the last meter sample (sticky-guard); INV-HUNT flags chasing.",
			setup: func(d *mayhemDriver) (*activeConstraint, error) {
				return armExportCap(d, 80, "mayhem: zero-export cap under PV flicker")
			},
			perTick: func(d *mayhemDriver, i int) {
				pv := d.pvHighW
				if (i/3)%2 == 1 { // 3 s up, 3 s down — cloud-edge cadence
					pv = d.pvHighW * 0.4
				}
				d.injectEnv(pv, loadLow)
			},
			evaluate: diagnoseConstraint,
			teardown: func(d *mayhemDriver) {},
		},
		{
			ID: "export-dither-at-breach", Name: "Export dithers ±ε across the compliance-breach band",
			Category:   "Value-domain (INV-EXPORT/INV-HUNT)",
			Hypothesis: "Metered export oscillates in a small band straddling cap+complianceBreachW (~100 W) for several minutes — sensor noise, or a flickering load, sitting exactly on the optimizer's leaky-counter decision line. Every other export scenario either holds still or ramps once; this one never leaves the line.",
			Expected:   "The cap holds with bounded breach-seconds, the loop does not hunt (INV-HUNT clean — 300 W hysteresis), and the hub never posts a CannotComply for a dither that never sustains past the breach-tick window. CannotComply is reserved for a REAL sustained excursion — proven separately by a control run that temporarily widens the dither past exportBreachTicks (see docs/QA_FINDINGS.md; not a committed code path).",
			HoldS:      ditherHoldS,
			Extended:   true, // ≥5 min — GAP-08 boundary soak; excluded from a default run (RSK-12), see filterExtended
			Fix:        "If CannotComply fires or INV-HUNT flags here, the leaky expOverTicks counter is not actually hold-biased at the boundary — tighten its decay/threshold in the optimizer (GAP-08).",
			setup: func(d *mayhemDriver) (*activeConstraint, error) {
				return armExportCap(d, ditherHoldS, "mayhem: zero export cap with export dithering at the compliance-breach band")
			},
			perTick: ditherSquareWave(ditherHalfPeriodTicks, func(d *mayhemDriver, over bool) {
				load := loadLow
				if !over {
					load += exportDitherLoadDeltaW
				}
				d.injectEnv(d.pvHighW, load)
			}),
			evaluate: diagnoseExportDither,
		},
		{
			ID: "soc-dither-at-reserve", Name: "Battery SoC dithers ±ε across the 20% reserve line",
			Category:   "Value-domain (INV-SOC)",
			Hypothesis: "A nearly-empty pack under a discharge demand reports SoC oscillating ±1 pt across the 20% SOCReserve line for several minutes — telemetry noise at the exact line the reserve guard (dischargingAtReserve) toggles on. Every other SoC scenario forces a single extreme value and holds it; this one straddles the decision boundary continuously.",
			Expected:   "No over-discharge past the reserve line on any sample, and the battery's discharge/hold decision tracks the injected dither cadence without extra chatter — a stable guard at the boundary, not a coin-flip.",
			HoldS:      ditherHoldS,
			Extended:   true, // ≥5 min — GAP-08 boundary soak; excluded from a default run (RSK-12), see filterExtended
			Fix:        "If the pack discharges past 20% or the guard chatters faster than the injected cadence, the reserve guard is not actually hold-biased at the boundary — debounce/tighten dischargingAtReserve (GAP-08).",
			setup: func(d *mayhemDriver) (*activeConstraint, error) {
				_ = d.post("battery", "/inject", map[string]any{"SoC_pct": socDitherHighPct, "Conn": 1})
				d.injectEnv(300, 5000) // low PV, heavy load ⇒ forced import unless the battery discharges (battery-soc-refuse preamble)
				return d.postCap("importCap", 0, ditherHoldS, "mayhem: zero import cap driving battery discharge, SoC dithering at the 20% reserve line")
			},
			perTick: ditherSquareWave(ditherHalfPeriodTicks, func(d *mayhemDriver, low bool) {
				soc := socDitherHighPct
				if low {
					soc = socDitherLowPct
				}
				_ = d.post("battery", "/inject", map[string]any{"SoC_pct": soc}) // re-inject every tick — pendingSoC must be re-asserted to stick (battery.go:49)
				d.injectEnv(300, 5000)
			}),
			evaluate: diagnoseSocDither,
		},
		func() *mayScenario {
			// diagnoseRecovery scenario: the program-0 default must be
			// suppressed so "release" means "unconstrained" (see suppressDefault).
			var restoreDefault func()
			return &mayScenario{
				ID: "release-while-rebooting", Name: "Cap released while the inverter is dark",
				Category:   "Recovery (INV-RESTORE, release-edge)",
				Hypothesis: "The generation-limit event ends at the exact moment the inverter is off the bus (reboot, link loss). The hub's release-edge uncurtail cannot reach a dark device; when the inverter returns it still holds the stale ceiling and nobody is left to clear it.",
				Expected:   "Re-assert or clear device state on reconnect: an inverter that returns with a stale ceiling and no active control must be restored to full output within a cycle — not left clamped indefinitely.",
				// 95 s, not 80: the device returns at t=45 and needs a poll cycle to
				// reconcile plus ~30 s of ramp to reach the ≥95% restore bar — at
				// 80 s a correct recovery could still be mid-climb at the window end
				// (QA v4: one FAIL ended at 4500 W of 4800, ramping).
				HoldS: 95,
				Fix:   "Southbound re-assert-on-reconnect (Phase 4): on device return, reconcile its registers against the CURRENT control set (none ⇒ restore full output). The optimizer-side release edge (restoreOnGenLimitClear) cannot write a dark device.",
				setup: func(d *mayhemDriver) (*activeConstraint, error) {
					restoreDefault = d.suppressDefault()
					d.injectEnv(d.pvHighW, loadLow)
					// Cap posted, adopted, and enforced first; judged on recovery.
					return d.postCap("genLimit", 1000, 15, "mayhem: gen limit released while inverter dark")
				},
				perTick: func(d *mayhemDriver, i int) {
					d.injectEnv(d.pvHighW, loadLow)
					switch i {
					case 18: // inverter goes dark (every Modbus read fails)
						_ = d.post("solar", "/fault", map[string]any{"kind": "exception_code"})
					case 22: // the event ends while the device cannot hear the release
						d.deleteControls(0)
					case 45: // the inverter returns — still wearing the stale ceiling
						_ = d.post("solar", "/fault", map[string]any{"kind": "exception_code", "clear": true})
					}
				},
				evaluate: diagnoseRecovery,
				teardown: func(d *mayhemDriver) {
					_ = d.post("solar", "/fault", map[string]any{"kind": "exception_code", "clear": true})
					d.deleteControls(0)
					if restoreDefault != nil {
						restoreDefault()
					}
				},
			}
		}(),
		{
			ID: "hub-restart-mid-cap", Name: "The hub process dies and restarts under a cap",
			Category:   "Hub resilience (INV-EXPORT survivability)",
			Hypothesis: "The orchestrator itself restarts mid-event — watchdog, OOM, power blip, deploy. Field reality for an always-on controller. State must come back from the retained bus/CSIP walk, not from luck.",
			Expected:   "Come back enforcing: re-read the retained control, re-adopt within a cycle or two, and never emit an un-commanded restore during shutdown/startup. The cap outage window must be bounded by the restart itself, not by rediscovery drift.",
			HoldS:      90,
			Fix:        "Startup must treat the retained CSIP control as live state (not wait for a fresh event); shutdown must not release device setpoints it was commanded to hold.",
			setup: func(d *mayhemDriver) (*activeConstraint, error) {
				// SSH probe first: without bench SSH this scenario cannot run, and an
				// INCONCLUSIVE setup error beats a fake verdict.
				if err := d.hubSSH("true"); err != nil {
					return nil, fmt.Errorf("hub SSH unavailable (need key auth to the hub Pi): %w", err)
				}
				return armExportCap(d, 90, "mayhem: cap across a hub restart")
			},
			perTick: func(d *mayhemDriver, i int) {
				d.injectEnv(d.pvHighW, loadLow)
				if i == 15 { // adopted and settled; now the orchestrator dies
					go func() { _ = d.hubSSH("sudo systemctl restart lexa-hub") }()
				}
			},
			evaluate: diagnoseSurvival("the hub restart"), // survivability (bounded /status gap) + the cap must hold
			teardown: func(d *mayhemDriver) {},
		},
		{
			ID: "disk-full", Name: "Hub Pi's storage partition fills mid-cap",
			Category:   "Persistence (INV-EXPORT survivability)",
			Hypothesis: "The hub Pi's storage partition fills — log growth, journal growth, a runaway process — while a zero-export cap is active. mosquitto's autosave can't persist, journald stalls/drops, and the event journal (TASK-039/040) starts hitting ENOSPC on every Append.",
			Expected:   "Keep enforcing the cap (the control is held in RAM and on an already-connected broker session — persistence failing is not the same as control failing), surface the condition rather than silently ignore it, and recover cleanly with no wedge once space returns.",
			HoldS:      80,
			Fix:        "TASK-039/040's ENOSPC handling (edge-logged, counted, returns an error, never panics — AD-011) is the product-side mitigation; a lost cap or a wedge here means some write path downstream of the journal blocks unboundedly on ENOSPC instead of failing fast.",
			setup: func(d *mayhemDriver) (*activeConstraint, error) {
				// SSH probe first: without bench SSH neither the fill nor the
				// teardown removal can run, and INCONCLUSIVE beats risking a
				// ballast nobody can clean up.
				if err := d.hubSSH("true"); err != nil {
					return nil, fmt.Errorf("hub SSH unavailable (need key auth to the hub Pi): %w", err)
				}
				return armExportCap(d, 80, "mayhem: cap under a full disk")
			},
			perTick: func(d *mayhemDriver, i int) {
				d.injectEnv(d.pvHighW, loadLow)
				switch i {
				case 15: // cap adopted and settled; now the partition fills
					go func() {
						if err := d.fillDisk(); err != nil {
							log.Printf("mayhem: disk-full: fillDisk: %v", err)
						}
					}()
				case 45: // ~30s full; space returns, recovery window follows
					go func() {
						if err := d.freeDisk(); err != nil {
							log.Printf("mayhem: disk-full: freeDisk: %v", err)
						}
					}()
				}
			},
			// diagnoseSurvival: cap must hold through the fault; a bounded
			// transient is acceptable, a sustained unseat is not. The hub's own
			// journald timestamps are not trustworthy here (the point of the
			// fault is that journald itself may be stalling) — survival is
			// judged from ground truth (sims) + /status, per diagnoseSurvival's
			// existing contract.
			evaluate: diagnoseSurvival("the full disk"),
			teardown: func(d *mayhemDriver) {
				// The ballast is the most dangerous artifact in the suite:
				// teardown ALWAYS removes it, on a clean finish or an abort —
				// run() calls scenario teardown unconditionally after the hold
				// phase returns, even when ctx was cancelled mid-hold. The one
				// gap this cannot cover is the dashboard process itself
				// crashing mid-run, which skips teardown entirely; recovery
				// then requires a manual
				// `ssh dmitri@69.0.0.1 sudo rm -f /var/lib/mayhem-ballast.bin`.
				if err := d.freeDisk(); err != nil {
					log.Printf("mayhem: disk-full: teardown freeDisk FAILED — manual cleanup needed (ssh dmitri@69.0.0.1 sudo rm -f %s): %v", ballastPath, err)
				}
				// Let the broker/journal settle before the next scenario runs,
				// so a persistence-family neighbor doesn't inherit a
				// still-draining store.
				time.Sleep(2 * time.Second)
			},
		},
		func() *mayScenario {
			// netemModifier-as-modifier: mirrors suppressDefault's
			// arm-in-setup / restore-in-teardown shape. netemTeardown stays
			// nil if netemModifier itself failed (missing SSH/sudo, or the
			// self-check refused a no-op apply) — teardown's nil-check
			// covers that, and its unconditional deleteControls(0) still
			// clears the cap this scenario posted before netem was armed.
			var netemTeardown func()
			return &mayScenario{
				ID: "netem-loss-export-cap", Name: "Export cap held under 5% packet loss + jitter on the hub's bench-LAN uplink",
				Category:   "Transport chaos (INV-EXPORT survivability, GAP-11)",
				Hypothesis: "Every fault above this one is app-layer (simapi /inject, gridsim /admin/outage) — nothing so far has touched the wire. Real LANs drop and jitter packets daily; this arms actual `tc netem` loss+delay on the hub Pi's real interface, degrading its Modbus polls to the sims AND its northbound link to gridsim at once (the hub has one LAN iface — this models a genuinely bad hub uplink, not a surgically isolated single link).",
				Expected:   "Hold the zero-export cap through real packet loss and jitter — a dropped or delayed sample is not a lost control, and the loop must not hunt chasing gappy telemetry (INV-HUNT clean).",
				HoldS:      80,
				Fix:        "Modbus/telemetry read paths must tolerate bench-LAN loss the same way they already tolerate the app-layer twin (modbus-latency's bounded-read timeout); a FAIL here means real packet loss defeats a protection that so far only ever saw perfect app-layer faults.",
				setup: func(d *mayhemDriver) (*activeConstraint, error) {
					cons, err := armExportCap(d, 80, "mayhem: zero-export cap under netem loss+jitter on the hub uplink")
					if err != nil {
						return nil, err
					}
					reset, err := d.netemModifier("hub", "loss 5% delay 50ms 10ms", 80)
					if err != nil {
						return nil, err
					}
					netemTeardown = reset
					return cons, nil
				},
				perTick:  func(d *mayhemDriver, i int) { d.injectEnv(d.pvHighW, loadLow) },
				evaluate: diagnoseConstraint,
				teardown: func(d *mayhemDriver) {
					if netemTeardown != nil {
						netemTeardown()
					}
					d.deleteControls(0)
				},
			}
		}(),
		func() *mayScenario {
			var netemTeardown func()
			return &mayScenario{
				ID: "netem-reorder-northbound", Name: "Generation limit rides out 25% reorder + 100ms delay on the utility link",
				Category:   "Transport chaos (INV-EXPORT survivability, GAP-11)",
				Hypothesis: "The utility link (hub↔gridsim — and, since the hub has one LAN iface, incidentally hub↔sims too) reorders a quarter of its packets and adds 100ms of delay while a generation-limit control is active. TCP tolerates reordering, but a walker/fetcher that quietly assumes in-order, low-latency responses can still misbehave under it — double-adoption, a spurious re-walk storm, or a wedge waiting on a response that arrived out of sequence.",
				Expected:   "The walker/fetcher must ride it out: the same SO_RCVTIMEO-bounded reads and fail-closed hold that northbound-hang and wan-outage-hold probe for an outright-down/wedged server must also cover reordering and added latency — degraded discovery cadence, never a dropped control.",
				HoldS:      80,
				Fix:        "Per-request deadline + fail-closed hold (northbound-hang's fix) must cover reordering/delay too, not just an outright-down or wedged server.",
				setup: func(d *mayhemDriver) (*activeConstraint, error) {
					_ = d.post("battery", "/inject", map[string]any{"SoC_pct": 100, "Conn": 1})
					d.injectEnv(d.pvHighW, loadLow)
					cons, err := d.postCap("genLimit", 1000, 80, "mayhem: gen limit under netem reorder+delay on the utility link")
					if err != nil {
						return nil, err
					}
					reset, err := d.netemModifier("hub", "reorder 25% delay 100ms", 80)
					if err != nil {
						return nil, err
					}
					netemTeardown = reset
					return cons, nil
				},
				perTick:  func(d *mayhemDriver, i int) { d.injectEnv(d.pvHighW, loadLow) },
				evaluate: diagnoseSurvival("packet reorder"),
				teardown: func(d *mayhemDriver) {
					if netemTeardown != nil {
						netemTeardown()
					}
					d.deleteControls(0)
				},
			}
		}(),
		func() *mayScenario {
			var netemTeardown func()
			return &mayScenario{
				ID: "netem-jitter-evse", Name: "EV import cap holds under delay jitter on the charger's link",
				Category:   "Transport chaos (INV-EVMAX, GAP-11)",
				Hypothesis: "The EVSE's OCPP link jitters (variable delay, not loss) while an import cap constrains an active charging session — WebSocket keepalives and SetChargingProfile calls ride a noisy link, not the clean one every other EV scenario assumes.",
				Expected:   "Never command the EVSE over its station max regardless of link jitter (INV-EVMAX — checked by the cross-cutting safety audit on every scenario's samples, not just this one's own oracle) and keep converging the import cap once profiles land despite the jitter.",
				HoldS:      70,
				Fix:        "OCPP call/response handling must tolerate variable RTT without mis-tracking session state or over-committing current (lexa-ocpp).",
				setup: func(d *mayhemDriver) (*activeConstraint, error) {
					_ = d.post("battery", "/inject", map[string]any{"SoC_pct": 12, "Conn": 1}) // just above the reserve floor: a near-empty non-lever, no INV-SOC noise
					_ = d.post("ev", "/inject", map[string]any{"action": "set_soc", "soc_pct": 30})
					_ = d.post("ev", "/inject", map[string]any{"action": "start_session", "connector_id": 1})
					d.injectEnv(300, 500)
					cons, err := d.postCap("importCap", 2000, 70, "mayhem: import cap under netem jitter on the EVSE link")
					if err != nil {
						return nil, err
					}
					reset, err := d.netemModifier("ev", "delay 80ms 40ms distribution normal", 70)
					if err != nil {
						return nil, err
					}
					netemTeardown = reset
					return cons, nil
				},
				perTick:  func(d *mayhemDriver, i int) { d.injectEnv(300, 500) },
				evaluate: diagnoseConstraint,
				teardown: func(d *mayhemDriver) {
					if netemTeardown != nil {
						netemTeardown()
					}
					d.deleteControls(0)
					_ = d.post("ev", "/inject", map[string]any{"action": "stop_session", "connector_id": 1})
				},
			}
		}(),
		{
			ID: "local-clock-step-forward", Name: "Hub Pi's own wall clock steps +1h mid-control",
			Category:   "Time integrity (local clock, INV-EXPORT survivability)",
			Hypothesis: "NTP steps the hub's OWN clock +1 h mid-control (the classic first sync after commissioning, or a holdover recovery). Every wall-clock comparison ON THE HUB moves; the server's clock did not. Journald timestamps on the hub jump during this run — expected, and not evidence of anything (do not oracle on hub log timestamps, only ground-truth sims + /status).",
			Expected:   "Keep enforcing the cap (it is still valid in SERVER time — TASK-037's monotonic anchoring at onCSIPControl arrival), no enforcement flap, no mass staleness of device telemetry, recover cleanly once the clock is restored.",
			HoldS:      90,
			Fix:        "TASK-037: anchor freshness/expiry on a monotonic clock captured at onCSIPControl arrival, not on wall-clock deltas — a local wall-clock step must never read every control as instantly expired (expiryConfirmTicks).",
			setup: func(d *mayhemDriver) (*activeConstraint, error) {
				// SSH probe first: without bench SSH this scenario cannot step (or
				// safely restore) the hub's clock, and INCONCLUSIVE beats risking a
				// clock nobody can clean up.
				if err := d.hubSSH("true"); err != nil {
					return nil, fmt.Errorf("hub SSH unavailable (need key auth to the hub Pi): %w", err)
				}
				return armExportCap(d, 90, "mayhem: cap through +1h local clock step")
			},
			perTick: func(d *mayhemDriver, i int) {
				d.injectEnv(d.pvHighW, loadLow)
				switch i {
				case 15: // cap adopted and settled; now the hub's OWN clock steps forward
					go func() {
						if err := d.hubClockNTP(false); err != nil {
							log.Printf("mayhem: local-clock-step-forward: hubClockNTP(false): %v", err)
							return
						}
						if err := d.hubClockStep(3600); err != nil {
							log.Printf("mayhem: local-clock-step-forward: hubClockStep(+3600): %v", err)
						}
					}()
				case 55: // restore before the hold ends
					go func() {
						if err := d.hubClockStep(-3600); err != nil {
							log.Printf("mayhem: local-clock-step-forward: hubClockStep(-3600): %v", err)
						}
						if err := d.hubClockNTP(true); err != nil {
							log.Printf("mayhem: local-clock-step-forward: hubClockNTP(true): %v", err)
						}
					}()
				}
			},
			evaluate: diagnoseSurvival("the local clock step"),
			teardown: func(d *mayhemDriver) { d.hubClockStepTeardown() },
		},
		{
			ID: "local-clock-step-back", Name: "Hub Pi's own wall clock steps -1h mid-control",
			Category:   "Time integrity (local clock, INV-EXPIRED / INV-EXPORT survivability)",
			Hypothesis: "NTP steps the hub's OWN clock -1 h mid-control (a holdover clock ahead of true time, corrected backward). Every wall-clock comparison ON THE HUB moves backward; the server's clock did not. Journald timestamps on the hub jump backward during this run — expected, not evidence of anything.",
			Expected:   "Keep enforcing the cap through the backward step (still valid in SERVER time) with no flap; additionally, the control must NOT be held past its genuine server-time expiry once that later arrives — INV-EXPIRED (grace-bounded, invariants.go) is already part of the safetyAudit every scenario's samples get, and a local backward step must never extend a control's real life.",
			HoldS:      90,
			Fix:        "Same TASK-037 anchoring as the forward case: expiry compares against the monotonic-anchored deadline, so a local clock running backward can neither expire a live control early nor keep a genuinely-expired one alive.",
			setup: func(d *mayhemDriver) (*activeConstraint, error) {
				if err := d.hubSSH("true"); err != nil {
					return nil, fmt.Errorf("hub SSH unavailable (need key auth to the hub Pi): %w", err)
				}
				return armExportCap(d, 90, "mayhem: cap through -1h local clock step")
			},
			perTick: func(d *mayhemDriver, i int) {
				d.injectEnv(d.pvHighW, loadLow)
				switch i {
				case 15: // cap adopted and settled; now the hub's OWN clock steps backward
					go func() {
						if err := d.hubClockNTP(false); err != nil {
							log.Printf("mayhem: local-clock-step-back: hubClockNTP(false): %v", err)
							return
						}
						if err := d.hubClockStep(-3600); err != nil {
							log.Printf("mayhem: local-clock-step-back: hubClockStep(-3600): %v", err)
						}
					}()
				case 55: // restore before the hold ends
					go func() {
						if err := d.hubClockStep(3600); err != nil {
							log.Printf("mayhem: local-clock-step-back: hubClockStep(+3600): %v", err)
						}
						if err := d.hubClockNTP(true); err != nil {
							log.Printf("mayhem: local-clock-step-back: hubClockNTP(true): %v", err)
						}
					}()
				}
			},
			evaluate: diagnoseSurvival("the local clock step"),
			teardown: func(d *mayhemDriver) { d.hubClockStepTeardown() },
		},
	}
}

// ── Guard-threshold dither sweeps (GAP-08, TASK-054) ────────────────────────
//
// export-dither-at-breach and soc-dither-at-reserve drive a measurement in a
// small ±ε square wave exactly at the optimizer's decision line — metered
// export at cap+complianceBreachW (lexa-hub optimizer.go, ~100 W) and battery
// SoC at SOCReserve (optimizer.go, 20%) — for several minutes. Every other
// scenario in this suite either holds a fault steady or ramps it once; these
// are the first to sit ON the line and oscillate, probing the belief that the
// product's leaky breach counters (expOverTicks, genGuard.overCount) are
// "hold-biased": a value dithering across the line should decay back down
// between over-band ticks and never accumulate to a CannotComply, and the
// reserve guard (dischargingAtReserve) should toggle cleanly rather than
// chatter.
//
// Both are EXTENDED-SET (HoldS ≈ 5 min, an order of magnitude longer than the
// rest of the suite) and are excluded from a default/full run — see
// mayScenario.Extended / filterExtended — so they do not inflate every FAST
// development campaign (RSK-12). Run them explicitly
// (`mayhem.py --only export-dither-at-breach,soc-dither-at-reserve`) or via
// `--extended` / include_extended for nightly / release-gate campaigns.
//
// The CannotComply biconditional this family exists to prove ("CannotComply
// fires iff the breach is sustained, never on the dither alone") has two
// halves: the pure-dither run here proves the "not sustained ⇒ no
// CannotComply" half. The other half — a SUSTAINED excursion DOES post
// CannotComply, proving the oracle isn't just trivially always-false — is a
// one-off CONTROL RUN against the bench, not a committed code path: widen
// exportDitherLoadDeltaW / hold one phase past scaleTicks(exportBreachTicks),
// run `--only export-dither-at-breach` once, confirm CannotComply, then
// revert. Do not commit that widened value.

const (
	// ditherHoldS is the scenario hold for both guard-threshold dither
	// sweeps: "≥5 min" per GAP-08, long enough for a real soak rather than a
	// blip. Both scenarios are marked Extended because of it (RSK-12).
	ditherHoldS = 300

	// ditherHalfPeriodTicks is the length, in perTick ticks, of each phase of
	// the dither square wave. At the harness's default 1 sample/tick (1 s,
	// mayDefaultSampleMs) that is a ~4 s half-cycle — comfortably under
	// exportBreachTicks(3) * tunedTickInterval(3s) ≈ 9 s FAST
	// (lexa-hub optimizer.go scaleTicks/exportBreachTicks), so no single
	// over-band phase can, by itself, sustain long enough to trip the
	// product's leaky breach counter. A custom --sample-ms changes the
	// wall-clock length of a "tick" and is not compensated for here — keep
	// the default cadence for these two scenarios.
	ditherHalfPeriodTicks = 4

	// exportDitherLoadDeltaW (Δ) is how much the dithered LOAD phase adds to
	// loadLow: less load ⇒ more residual export past the hub's curtailment.
	// Starting point only — Δ is the one thing 06 §4.5 permits tuning (never
	// the oracle margins); verify empirically on the bench that the low-load
	// phase's residual export sits just over cap+complianceBreachW (~100 W)
	// and the high-load phase sits comfortably under it, both within the
	// 300 W INV-HUNT hysteresis so only genuine hunting — never the injected
	// dither itself — could flag INV-HUNT.
	exportDitherLoadDeltaW = 150.0

	// socDitherLowPct / socDitherHighPct straddle the product's SOCReserve
	// (20%, lexa-hub optimizer.go NewDefaultOptimizer) by ±1 point — enough
	// for pendingSoC (batsim) to visibly cross the reserve guard each
	// half-cycle without being a real over/under-discharge event on its own.
	socDitherLowPct  = 19.0
	socDitherHighPct = 21.0

	// socDitherReserveLine mirrors the product's SOCReserve default. This is
	// intentionally NOT invariants.go's invSocReserveFloorPct (the harness's
	// own 10% safety backstop, mirroring batsim's SoCRsvMin) — that
	// invariant keeps auditing every scenario unchanged (06 §4.5 / TASK-054
	// "Things that must NOT change"); this scenario's own primary judgment
	// is against the higher, product-specific reserve line it is actually
	// probing.
	socDitherReserveLine = 20.0

	// battFlapSlack is the tolerance (in excess sign transitions over the
	// dither's own expected cadence) before extra battery charge/discharge
	// transitions count as command chatter rather than tracking the injected
	// SoC dither. See batteryCommandFlaps / expectedDitherTransitions.
	battFlapSlack = 3
)

// ditherSquareWave returns a perTick func that alternates a two-phase square
// wave every halfPeriodTicks ticks, calling apply(d, phaseA) on EVERY tick
// (not just on a flip) so a phase's state is continuously re-asserted —
// required because some sims override their own animation only for as long
// as they keep being told to (batsim's pendingSoC, sim/southbound/battery.go
// ~line 49/138; re-injecting once per phase-flip is not enough). Shared by
// both dither scenarios so their cadence never drifts apart.
func ditherSquareWave(halfPeriodTicks int, apply func(d *mayhemDriver, phaseA bool)) func(d *mayhemDriver, i int) {
	if halfPeriodTicks < 1 {
		halfPeriodTicks = 1
	}
	return func(d *mayhemDriver, i int) {
		apply(d, (i/halfPeriodTicks)%2 == 0)
	}
}

// expectedDitherTransitions is how many charge/discharge sign transitions a
// battery correctly tracking the injected SoC dither should show over a
// scenario's hold: at most one per half-cycle. Assumes the default 1
// sample/tick cadence (see ditherHalfPeriodTicks).
func expectedDitherTransitions(sc *mayScenario) int {
	if ditherHalfPeriodTicks <= 0 {
		return 0
	}
	n := sc.HoldS / ditherHalfPeriodTicks
	if n < 1 {
		n = 1
	}
	return n
}

// batteryCommandFlaps counts BatterySimW sign transitions (charge↔discharge)
// after the settling window, filtered by invSocActiveW so idle jitter around
// zero never counts as a transition — the natural ±invSocActiveW dead-band is
// this check's analogue of invHunt's 300 W hysteresis. A reserve guard
// correctly tracking a dithering SoC input toggles roughly once per
// half-cycle; a chattering one re-decides WITHIN a half-cycle on its own,
// producing far more transitions than the injected dither accounts for
// (expectedDitherTransitions).
func batteryCommandFlaps(s []maySample) int {
	flips := 0
	sign := 0 // -1 charging, +1 discharging, 0 idle/unknown
	for _, smp := range s {
		if smp.T <= mayConvergeDeadlineS || !smp.BatterySimOK {
			continue
		}
		var cur int
		switch {
		case smp.BatterySimW > invSocActiveW:
			cur = 1
		case smp.BatterySimW < -invSocActiveW:
			cur = -1
		default:
			continue // idle jitter — not a transition either way
		}
		if sign != 0 && cur != sign {
			flips++
		}
		sign = cur
	}
	return flips
}

// socReserveOverDischarge flags samples where the battery is DISCHARGING
// (simulator ground truth) while its forced SoC sits at/below the product's
// SOCReserve line — the boundary dischargingAtReserve exists to guard.
// Deliberately separate from invariants.go's invSOC (which guards the
// harness's own lower 10% safety floor, invSocReserveFloorPct, and must not
// change per 06 §4.5 / TASK-054 "Things that must NOT change") — this
// predicate is scenario-local because the line being probed here is higher
// and product-specific, not the harness's hard backstop.
func socReserveOverDischarge(s []maySample) []invViolation {
	var v []invViolation
	for _, smp := range s {
		if smp.T <= mayConvergeDeadlineS || !smp.BatterySimOK {
			continue
		}
		if smp.BatterySimW > invSocActiveW && smp.BatSimSOC <= socDitherReserveLine {
			v = append(v, invViolation{
				Inv:    "INV-SOC-RESERVE",
				T:      smp.T,
				Detail: fmt.Sprintf("discharging %.0f W at SoC %.0f%% (≤ SOCReserve %.0f%%)", smp.BatterySimW, smp.BatSimSOC, socDitherReserveLine),
			})
		}
	}
	return v
}

// diagnoseExportDither judges export-dither-at-breach: the CannotComply
// biconditional's "not sustained ⇒ no CannotComply" half, plus INV-HUNT. A
// repeating dither is EXPECTED to leave breach-seconds non-zero (each
// over-band phase is a momentary excursion) — unlike diagnoseConstraint, the
// bar here is not "breach-seconds == 0" but that no single excursion ever
// sustains into a CannotComply or a hunting control loop.
func diagnoseExportDither(sc *mayScenario, cons *activeConstraint, s []maySample) mayFinding {
	f := baseFinding(sc)
	if len(s) == 0 {
		f.Verdict = "INCONCLUSIVE"
		f.Headline = "no samples collected (aborted before any reading)"
		return f
	}
	m := scanSamples(cons, s)
	f.Metrics = m
	capStr := fmt.Sprintf("%s ≤ %.0f W", cons.Typ, cons.LimW)

	if m.SampleErrors > len(s)/2 {
		f.Verdict = "INCONCLUSIVE"
		f.Headline = "meter unreachable for most of the run — cannot judge the dither"
		f.Diagnosis = []string{
			fmt.Sprintf("The grid meter failed to read on %d of %d samples.", m.SampleErrors, len(s)),
		}
		return f
	}

	hunt := invHunt(cons, s)
	end := s[len(s)-1].T

	switch {
	case m.ReportedCannot:
		f.Verdict = "FAIL"
		f.Headline = fmt.Sprintf("CannotComply posted during a pure ±ε dither at %s — the biconditional is broken", capStr)
		f.Diagnosis = []string{
			fmt.Sprintf("Breach-seconds %.0f of %.0fs, peak overshoot %.0f W — this is dither (each over-band phase well under exportBreachTicks' sustained window), yet the hub self-reported CannotComply.", m.BreachSeconds, end, m.PeakBreachW),
			"The leaky breach counter (expOverTicks / genGuard.overCount) is not actually hold-biased at the boundary: it accumulated across a dither that never sustained past its own decay.",
			invSummaryLine("INV-HUNT", hunt),
		}
		f.Fix = "Tighten the leaky counter's decay/threshold at the boundary (lexa-hub optimizer.go expOverTicks, scaleTicks(exportBreachTicks)) so a dither that never sustains cannot accumulate to CannotComply."
	case len(hunt) > 0:
		f.Verdict = "FAIL"
		f.Headline = fmt.Sprintf("control loop hunted around %s during the boundary dither (INV-HUNT)", capStr)
		f.Diagnosis = []string{
			invSummaryLine("INV-HUNT", hunt),
			"A boundary-dither scenario exists specifically to probe hunting at the decision line; unlike the generic cross-cutting safety audit (which only demotes a PASS to DEGRADED), sustained oscillation here is the primary finding, not a secondary one.",
		}
		f.Fix = "The curtailment ceiling must be a held absolute value (sticky-guard), not re-chased every tick against a dithering measurement."
	default:
		f.Verdict = "PASS"
		f.Headline = fmt.Sprintf("held %s through a %.0fs boundary dither with no CannotComply and no hunting", capStr, end)
		f.Diagnosis = []string{
			fmt.Sprintf("Export dithered across the cap+complianceBreachW band for %.0fs (breach-seconds %.0f, peak %.0f W) without a single CannotComply and without INV-HUNT flagging — confirms the leaky counter's hold-bias at the boundary.", end, m.BreachSeconds, m.PeakBreachW),
		}
		f.Fix = "No code fix required — this is the confirming result GAP-08 asked for."
	}
	f.Diagnosis = append(f.Diagnosis, invSummaryLine("INV-EXPORT", invExport(cons, s)))
	return f
}

// diagnoseSocDither judges soc-dither-at-reserve: no over-discharge past the
// product's SOCReserve line, and no battery command chatter beyond what the
// injected dither itself explains.
func diagnoseSocDither(sc *mayScenario, cons *activeConstraint, s []maySample) mayFinding {
	f := baseFinding(sc)
	if len(s) == 0 {
		f.Verdict = "INCONCLUSIVE"
		f.Headline = "no samples collected (aborted before any reading)"
		return f
	}
	f.Metrics = scanSamples(cons, s)
	end := s[len(s)-1].T

	reserveViol := socReserveOverDischarge(s)
	flips := batteryCommandFlaps(s)
	expected := expectedDitherTransitions(sc)
	excess := flips - expected

	switch {
	case len(reserveViol) > 0:
		f.Verdict = "FAIL"
		f.Headline = fmt.Sprintf("battery discharged past SOCReserve on %d samples during the reserve-line dither", len(reserveViol))
		f.Diagnosis = []string{
			invSummaryLine("INV-SOC-RESERVE", reserveViol),
			"SoC dithered ±1 pt across the 20% reserve line; a correct reserve guard (dischargingAtReserve) must stop discharge at/below the line on every sample it sees, not just on average.",
		}
		f.Fix = "lexa-hub optimizer.go dischargingAtReserve / SOCReserve guard — verify it re-evaluates every tick against the MEASURED SoC, not a stale or hysteresis-delayed read."
	case excess > battFlapSlack:
		f.Verdict = "FAIL"
		f.Headline = fmt.Sprintf("battery command chattered %d times (expected ~%d) during the reserve-line dither", flips, expected)
		f.Diagnosis = []string{
			fmt.Sprintf("Measured %d charge/discharge sign transitions against an expected ~%d from the injected dither cadence alone — the reserve guard is re-deciding within a single dither phase, not just tracking the injected SoC.", flips, expected),
			"Command chatter at the reserve line wears the pack's contactor in the field even when no safety envelope is actually breached.",
		}
		f.Fix = "Debounce the dischargingAtReserve guard's decision (the same sticky-guard pattern INV-HUNT expects of curtailment) so it does not re-toggle faster than the measurement can physically change."
	default:
		f.Verdict = "PASS"
		f.Headline = fmt.Sprintf("held the SoC-reserve line clean through a %.0fs boundary dither", end)
		f.Diagnosis = []string{
			fmt.Sprintf("SoC dithered ±1 pt across SOCReserve(20%%) for %.0fs: no post-settling over-discharge past reserve, and battery command transitions (%d) tracked the injected cadence (expected ~%d) without excess chatter.", end, flips, expected),
		}
		f.Fix = "No code fix required — confirms the reserve guard is stable at the boundary."
	}
	return f
}
