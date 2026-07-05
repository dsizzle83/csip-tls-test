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

import (
	"fmt"
	"log"
	"net/url"
	"os"
	"os/exec"
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
	}
}
