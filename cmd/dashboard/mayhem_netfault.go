// Track G-netfault — L3 network-partition + DNS-failure Mayhem scenarios
// (audit docs/QA_COMPLETENESS_AUDIT.md P2-3, Batch 3b). New file per the
// "one concern = one file, scenarios + oracles together" convention.
//
// mayhem_world.go's netem-* scenarios DEGRADE the wire (loss/reorder/delay);
// these two SEVER it — the field events netem cannot model:
//
//	net-partition-gridsim — a real L3 partition of the hub↔gridsim path
//	                        (iptables DROP, both directions, port-scoped to
//	                        gridsim's :11111 so the dashboard's hub:9100 probe
//	                        stays alive). INV-EXPORT survivability: the hub must
//	                        hold last-known-good through the partition and
//	                        re-sync after it clears — the #1 field event (WAN
//	                        loss) at the transport layer instead of app-layer 503.
//	net-dns-fail          — a DNS blackout (resolv.conf → an unroutable
//	                        nameserver). On an IP-configured bench northbound
//	                        this proves the hub does not WEDGE on DNS loss; a
//	                        hostname-configured deployment would exercise the
//	                        resolve path itself.
//
// Both need SSH + passwordless sudo + iptables on the hub (docs/BENCH.md); off
// bench (no hub SSH) each reports INCONCLUSIVE at setup rather than a misleading
// verdict — same gate local-clock-step-forward uses. The standalone CLI form of
// the same primitives is scripts/netfault.sh (manual use / soak); the pure
// command builders below and that script are parallel implementations, exactly
// as netem.sh parallels mayhem_world.go's netemApplyCommand.
//
// The fault is armed only AFTER the export cap is adopted (armAfterCapAdopted),
// so the hub has a live control to HOLD through the partition — arming before
// the first walk would just stop the cap ever being adopted, testing nothing.

package main

import (
	"fmt"
	"log"
	"time"
)

// gridsimNorthboundPort is gridsim's mTLS northbound listener (docs/BENCH.md:
// desktop 69.0.0.20, mTLS :11111, admin :11112). The partition drops ONLY this
// port so the dashboard↔hub /status path (hub:9100) — gridsim and the dashboard
// share the desktop host — stays reachable and the survival oracle can see the
// hub throughout.
const gridsimNorthboundPort = 11111

// ── pure remote-command builders (unit-testable, like netemApplyCommand) ──────

// partitionApplyCommand drops TCP to/from gridsimIP:port in BOTH directions and
// schedules a self-healing delete after autoResetS seconds (so a lost teardown
// still clears it). `-I` inserts at the top so the DROP wins; `-C` verifies the
// rule actually landed (set -e ⇒ a silent no-op fails the apply, the GAP-11
// false-PASS guard); `sudo -n` never hangs on a prompt. The self-heal subshell
// mirrors netemApplyCommand's (no `disown` — not a POSIX /bin/sh builtin).
func partitionApplyCommand(gridsimIP string, port, autoResetS int) string {
	return fmt.Sprintf("set -e; "+
		"sudo -n iptables -I OUTPUT -d %s -p tcp --dport %d -j DROP; "+
		"sudo -n iptables -I INPUT -s %s -p tcp --sport %d -j DROP; "+
		"sudo -n iptables -C OUTPUT -d %s -p tcp --dport %d -j DROP; "+
		"sudo -n sh -c '(sleep %d; iptables -D OUTPUT -d %s -p tcp --dport %d -j DROP; iptables -D INPUT -s %s -p tcp --sport %d -j DROP) >/dev/null 2>&1 &'",
		gridsimIP, port, gridsimIP, port, gridsimIP, port, autoResetS, gridsimIP, port, gridsimIP, port)
}

// partitionResetCommand deletes the partition rules immediately (idempotent).
func partitionResetCommand(gridsimIP string, port int) string {
	return fmt.Sprintf("set +e; "+
		"sudo -n iptables -D OUTPUT -d %s -p tcp --dport %d -j DROP 2>/dev/null; "+
		"sudo -n iptables -D INPUT -s %s -p tcp --sport %d -j DROP 2>/dev/null; true",
		gridsimIP, port, gridsimIP, port)
}

// dnsFailApplyCommand backs up resolv.conf and points it at an unroutable
// nameserver (192.0.2.1, TEST-NET-1), then schedules a self-healing restore.
// grep verifies the swap landed (set -e no-op guard).
func dnsFailApplyCommand(autoResetS int) string {
	const bak = "/etc/resolv.conf.netfault.bak"
	const blackhole = "192.0.2.1"
	return fmt.Sprintf("set -e; "+
		"sudo -n sh -c '[ -f %s ] || cp /etc/resolv.conf %s'; "+
		"sudo -n sh -c 'printf \"nameserver %s\\n\" > /etc/resolv.conf'; "+
		"grep -q %s /etc/resolv.conf; "+
		"sudo -n sh -c '(sleep %d; [ -f %s ] && mv %s /etc/resolv.conf) >/dev/null 2>&1 &'",
		bak, bak, blackhole, blackhole, autoResetS, bak, bak)
}

// dnsFailResetCommand restores resolv.conf from the backup if present.
func dnsFailResetCommand() string {
	const bak = "/etc/resolv.conf.netfault.bak"
	return fmt.Sprintf("set +e; sudo -n sh -c '[ -f %s ] && mv %s /etc/resolv.conf'; true", bak, bak)
}

// ── driver plumbing (run the builders over the hub's SSH, like netemApply) ────

func (d *mayhemDriver) partitionApply(gridsimIP string, port, autoResetS int) error {
	return d.hubSSH(partitionApplyCommand(gridsimIP, port, autoResetS))
}
func (d *mayhemDriver) partitionReset(gridsimIP string, port int) {
	if err := d.hubSSH(partitionResetCommand(gridsimIP, port)); err != nil {
		log.Printf("mayhem: net-partition reset FAILED — manual cleanup: ssh hub sudo iptables -D … (%v)", err)
	}
}
func (d *mayhemDriver) dnsFailApply(autoResetS int) error {
	return d.hubSSH(dnsFailApplyCommand(autoResetS))
}
func (d *mayhemDriver) dnsFailReset() {
	if err := d.hubSSH(dnsFailResetCommand()); err != nil {
		log.Printf("mayhem: net-dns-fail reset FAILED — manual cleanup: ssh hub sudo mv /etc/resolv.conf.netfault.bak /etc/resolv.conf (%v)", err)
	}
}

// ── scenarios ────────────────────────────────────────────────────────────────

func (d *mayhemDriver) netFaultScenarios() []*mayScenario {
	return []*mayScenario{
		netPartitionScenario(),
		netDNSFailScenario(),
	}
}

// armExportCapNetfault is the "PV hard, battery full ⇒ curtailment is the only
// export lever" preamble the netfault survival scenarios share (worldScenarios'
// armExportCap is a closure private to that function).
func (d *mayhemDriver) armExportCapNetfault(holdS int, desc string) (*activeConstraint, error) {
	_ = d.post("battery", "/inject", map[string]any{"SoC_pct": 100, "Conn": 1})
	d.injectEnv(d.pvHighW, 250)
	return d.postCap("exportCap", 0, holdS, desc)
}

func netPartitionScenario() *mayScenario {
	const holdS = 95
	return &mayScenario{
		ID:         "net-partition-gridsim",
		Name:       "Hub↔gridsim L3 partition (iptables DROP both ways) — hold the cap, re-sync after",
		Category:   "Transport chaos (INV-EXPORT survivability, P2-3)",
		Hypothesis: "The utility WAN is not 'down' at the app layer (a clean 503) — the PATH is severed: TCP to gridsim's :11111 is black-holed both directions while a zero-export cap is active. Every fault above this that models WAN loss does it app-layer (gridsim /admin/outage); this cuts the actual wire (iptables), scoped to gridsim's port so hub:9100 /status stays observable.",
		Expected:   "Keep enforcing the last-known-good export cap through the partition (it is still valid) and re-sync when the path heals — a severed WAN must never mean an unenforced control. /status keeps answering (its port is not partitioned) and the cap is never unseated.",
		HoldS:      holdS,
		Fix:        "Northbound walker fails closed to last-known-good on any fetch error (transport-severed included); the orchestrator enforces until ValidUntil regardless of server reachability (same guarantee wan-outage-hold probes, at L3 instead of app layer).",
		setup: func(d *mayhemDriver) (*activeConstraint, error) {
			// SSH probe first: without bench SSH+sudo we cannot partition (or
			// safely un-partition) the hub — INCONCLUSIVE beats a false verdict.
			if err := d.hubSSH("sudo -n true"); err != nil {
				return nil, fmt.Errorf("hub SSH/passwordless-sudo unavailable (need it to run iptables on the hub): %w", err)
			}
			cons, err := d.armExportCapNetfault(holdS, "mayhem: cap through an L3 hub↔gridsim partition")
			if err != nil {
				return nil, err
			}
			// Sever only AFTER the cap is adopted (else it never adopts). Self-heal
			// margin past teardown so the fast path (teardown) always wins first.
			d.armAfterCapAdopted(cons.Typ, cons.LimW, 2*time.Second, 60*time.Second, func() {
				if err := d.partitionApply(netemDesktopIP, gridsimNorthboundPort, holdS); err != nil {
					log.Printf("mayhem: net-partition-gridsim: partitionApply: %v", err)
				}
			})
			return cons, nil
		},
		perTick:  func(d *mayhemDriver, i int) { d.injectEnv(d.pvHighW, 250) },
		evaluate: diagnoseSurvival("the hub↔gridsim network partition"),
		teardown: func(d *mayhemDriver) {
			d.partitionReset(netemDesktopIP, gridsimNorthboundPort)
			d.deleteControls(0)
		},
	}
}

func netDNSFailScenario() *mayScenario {
	const holdS = 90
	return &mayScenario{
		ID:         "net-dns-fail",
		Name:       "DNS blackout (resolv.conf → unroutable) — the hub must not wedge",
		Category:   "Transport chaos (INV-EXPORT survivability, P2-3)",
		Hypothesis: "The hub's DNS server goes away: resolv.conf is repointed at an unroutable nameserver so every unicast lookup fails/times out while a zero-export cap is active. On an IP-configured bench northbound this mainly proves the hub does not WEDGE waiting on a dead resolver; a hostname-configured deployment would additionally exercise the resolve-and-reconnect path. mDNS/DNS-SD (multicast) is unaffected.",
		Expected:   "Keep enforcing the last-known-good cap and keep /status answering — a DNS failure degrades discovery at worst, never the control loop, and never a hung goroutine on a blocking resolve.",
		HoldS:      holdS,
		Fix:        "Any name resolution on the northbound/telemetry path must be deadline-bounded (never an unbounded blocking lookup); the control loop holds last-known-good regardless of DNS health.",
		setup: func(d *mayhemDriver) (*activeConstraint, error) {
			if err := d.hubSSH("sudo -n true"); err != nil {
				return nil, fmt.Errorf("hub SSH/passwordless-sudo unavailable (need it to rewrite resolv.conf on the hub): %w", err)
			}
			cons, err := d.armExportCapNetfault(holdS, "mayhem: cap through a DNS blackout")
			if err != nil {
				return nil, err
			}
			d.armAfterCapAdopted(cons.Typ, cons.LimW, 2*time.Second, 60*time.Second, func() {
				if err := d.dnsFailApply(holdS); err != nil {
					log.Printf("mayhem: net-dns-fail: dnsFailApply: %v", err)
				}
			})
			return cons, nil
		},
		perTick:  func(d *mayhemDriver, i int) { d.injectEnv(d.pvHighW, 250) },
		evaluate: diagnoseSurvival("the DNS blackout"),
		teardown: func(d *mayhemDriver) {
			d.dnsFailReset()
			d.deleteControls(0)
		},
	}
}
