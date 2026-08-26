package certify

// preset.go is the loopback lab's address book.
//
// # Why a preset instead of a runbook line
//
// Running the whole engine against a gateway on THIS host means overriding nine
// target flags at once, and the nine are not independent: gridsim's data port
// and its admin port must name one process (preflight.go refuses them
// otherwise), the capture interface must be the one the traffic actually crosses
// (loopback traffic never appears on enp1s0, and every citation then silently
// becomes impossible), and the metrics endpoint must be the DUT's loopback one.
// A nine-flag line copied between a runbook, a Makefile and three shells drifts,
// and each way it drifts produces a run that looks fine and cites nothing.
//
// So the set is named once, here, and -preset local expands it.
//
// # THE ADDRESSES ARE THE LAB'S OWN, NOT A SECOND SET THAT RESEMBLES IT
//
// The block below is transcribed from the two files that OWN the lab's
// topology, and from nowhere else:
//
//	lexa-gw   scripts/lab/lib.sh          the DUT, its port, the metrics and
//	                                      dev-API ports, and the lab port block
//	csip-tls-test scripts/lab/lab-sims-up.sh  the simulators' half of that block
//
// A preset that "looked about right" would be worse than no preset: every flag
// it filled in wrongly would still produce a run, and the run would measure
// nothing while reporting a device.
//
// Three addresses, on purpose (lib.sh's topology note). certify tells a captured
// frame's direction by comparing its source against the DUT's, and on
// 127.0.0.1-for-everything every frame looks like it came from the DUT:
//
//	127.0.0.2    the DUT (mnemonic for the bench's 69.0.0.2)
//	127.0.0.20   the simulators (mnemonic for the bench's 69.0.0.20)
//	127.0.0.1    this harness, and the DUT's own loopback-bound services
//
// # The ports, and where they come from
//
//	gateway 127.0.0.2:802     THE PRODUCT'S OWN PORT. Not a lab mirror: cmd/mbaps
//	                          REFUSES TO START on any port the candidate manifest
//	                          does not claim (configs/candidate.json
//	                          secure_sunspec.port = 802, enforced by
//	                          Config.validateCandidate — the LAB29-004 fail-closed
//	                          shape rule), and the lab runs that manifest
//	                          BYTE-IDENTICALLY because its sha256 is a load-time
//	                          fact every bundle cites. A lab manifest edited to
//	                          say 8802 would be a different shape with a different
//	                          digest. The lab's rootless user namespace shares the
//	                          host's network namespace, so binding 802 needs the
//	                          host sysctl net.ipv4.ip_unprivileged_port_start —
//	                          a one-time owner prerequisite `lab.sh preflight`
//	                          checks hard. There is deliberately no high-port
//	                          fallback.
//	gridsim 127.0.0.20:21113 / admin :21114
//	modsim  127.0.0.20:15020 / simapi :16020
//	mbapsdev 127.0.0.20:18021 / simapi :16031
//	                          lab-sims-up.sh's defaults. The block is DISJOINT
//	                          from the bench's (11113/11114, 5020/6020,
//	                          8021/6031) because this desktop serves the bench
//	                          board from those ports and sim/simapi binds the
//	                          wildcard address — a lab that reused them would
//	                          silently attach the local loop to the simulators a
//	                          live bench campaign is grading.
//	metrics http://127.0.0.1:9102/metrics
//	                          lexa-northbound's endpoint. The lab does NOT
//	                          rewrite metrics_addr, and the shared network
//	                          namespace makes the product's own loopback address
//	                          reachable from here.
//	dev API https://127.0.0.1:9100
//	                          lexa-api. genconfig.sh writes listen_addr
//	                          127.0.0.1:$LAB_API_PORT (9100) and leaves tls=true,
//	                          so this is the shipped DefaultDevAPI unchanged.
//
// # Explicit flags always win
//
// The preset fills in what the operator did NOT type. It is applied from the set
// of flags the parser actually visited, not by comparing against defaults —
// comparing against defaults cannot tell `-gridsim 69.0.0.20:11113` (typed, and
// happens to equal the default) from a value nobody set, and would silently
// discard the first.

import (
	"flag"
	"fmt"
	"sort"
	"strings"
)

// Preset names a bench topology.
type Preset string

// The presets.
const (
	// PresetLocal is the host-native lab of lexa-gw's docs/LAB_LOOP.md: the
	// production binaries in a rootless user namespace on THIS host, the DUT on
	// 127.0.0.2 and the simulators on 127.0.0.20.
	PresetLocal Preset = "local"
)

// presetTargets is one preset's address book, keyed by the FLAG NAME it fills
// in — so "which flag does this override?" has exactly one answer and a test can
// assert every key is a real flag.
type presetSpec struct {
	Name    Preset
	Summary string
	// Flags maps flag name to the value the preset supplies.
	Flags map[string]string
}

var presets = []presetSpec{{
	Name:    PresetLocal,
	Summary: "the host-native lab: DUT on 127.0.0.2, simulators on 127.0.0.20 (lexa-gw scripts/lab)",
	Flags: map[string]string{
		// THE PRODUCT'S OWN PORT, not a lab mirror. See the file doc: cmd/mbaps
		// fail-closes on any port the byte-identical candidate manifest does not
		// claim, so the lab grants 802 through the host sysctl instead of moving
		// the listener.
		"gateway":          "127.0.0.2:802",
		"gridsim":          "127.0.0.20:21113",
		"gridsim-admin":    "http://127.0.0.20:21114",
		"modsim":           "127.0.0.20:15020",
		"modsim-api":       "http://127.0.0.20:16020",
		"mbapsdev":         "127.0.0.20:18021",
		"mbapsdev-api":     "http://127.0.0.20:16031",
		"metrics-endpoint": "http://127.0.0.1:9102/metrics",
		"dev-api":          DefaultDevAPI,
		// Loopback traffic crosses lo and nothing else. Leaving the bench NIC
		// here would produce a capture with zero frames and a bundle full of
		// PASSes downgraded "for want of a citation", which reads as sloppy
		// checks rather than as the wrong interface.
		"iface": "lo",
	},
}}

// PresetNames lists the -preset values.
func PresetNames() []string {
	out := make([]string, len(presets))
	for i, p := range presets {
		out[i] = string(p.Name)
	}
	return out
}

// LookupPreset resolves a -preset value, fold-insensitively.
func LookupPreset(name string) (presetSpec, bool) {
	for _, p := range presets {
		if strings.EqualFold(string(p.Name), name) {
			return p, true
		}
	}
	return presetSpec{}, false
}

// PresetFlagNames lists the flags a preset supplies, sorted. Exported so a test
// can hold them against the bound flag set.
func PresetFlagNames(name string) []string {
	p, ok := LookupPreset(name)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(p.Flags))
	for k := range p.Flags {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// ApplyPreset fills in the target flags the operator did not set.
//
// set is the flag names the parser VISITED — flag.FlagSet.Visit's set, not
// VisitAll's. Anything in it is left exactly as typed.
//
// The values go back through the same flag.Value objects the command line would
// have used, so a preset cannot reach a field the command line cannot, and a
// flag with parsing or side effects (endpointFlag writes into Targets.Extra)
// behaves identically either way.
func ApplyPreset(fs *flag.FlagSet, name string, set map[string]bool) error {
	if name == "" {
		return nil
	}
	p, ok := LookupPreset(name)
	if !ok {
		return fmt.Errorf("certify: no preset named %q (have: %s)", name, strings.Join(PresetNames(), ", "))
	}
	for _, flagName := range PresetFlagNames(name) {
		if set[flagName] {
			continue
		}
		f := fs.Lookup(flagName)
		if f == nil {
			// A preset naming a flag nobody binds would silently fill in
			// nothing. Refuse: TestPresetFlagsAllExist catches this at test
			// time, and this catches an entry point that binds a subset.
			return fmt.Errorf("certify: -preset %s supplies -%s, which this command does not have",
				name, flagName)
		}
		if err := f.Value.Set(p.Flags[flagName]); err != nil {
			return fmt.Errorf("certify: -preset %s: -%s=%q: %w", name, flagName, p.Flags[flagName], err)
		}
	}
	return nil
}

// PresetSummary renders the preset table for a -help line.
func PresetSummary() string {
	parts := make([]string, len(presets))
	for i, p := range presets {
		parts[i] = fmt.Sprintf("%s (%s)", p.Name, p.Summary)
	}
	return strings.Join(parts, "; ")
}
