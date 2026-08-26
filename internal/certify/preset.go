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
// # The ports, and where they come from
//
// Every port below is the DEFAULT the bench's own launcher already uses
// (csip-tls-test scripts/bench-sims-up.sh), so a preset run and a bench run
// address the same simulators and a value learned in one place is true in the
// other. The single exception is the gateway's own mbaps listener, and it is
// called out rather than buried:
//
//	gateway :8802   the DUT's Secure SunSpec Modbus server. THE FIELD PORT IS
//	                802, which is privileged; a gateway running unprivileged on a
//	                developer's host cannot bind it, so the lab mirror is 8802.
//	                Nothing about the protocol depends on the number, and the
//	                bundle records the address that was actually dialled.
//	gridsim :11113 / admin :11114
//	                bench-sims-up.sh's defaults. NOT 11111/11112: those belong to
//	                a Production-PKI demo gridsim, and this bench's gateway
//	                presents an mbaps-PKI leaf.
//	modsim :5020 / simapi :6020
//	mbapsdev :8021 / simapi :6031
//	metrics http://127.0.0.1:9102/metrics
//	                lexa-northbound's endpoint, loopback-only by product design.
//	dev API https://127.0.0.1:9100
//	                lexa-api. HTTPS with a per-device self-signed leaf, bearer
//	                token from /etc/lexa/api.token.
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
	// PresetLocal is the loopback lab: the DUT and every simulator on this host.
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
	Summary: "the loopback lab: DUT and simulators on this host (127.0.0.1)",
	Flags: map[string]string{
		"gateway":          "127.0.0.1:8802",
		"gridsim":          "127.0.0.1:11113",
		"gridsim-admin":    "http://127.0.0.1:11114",
		"modsim":           "127.0.0.1:5020",
		"modsim-api":       "http://127.0.0.1:6020",
		"mbapsdev":         "127.0.0.1:8021",
		"mbapsdev-api":     "http://127.0.0.1:6031",
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
