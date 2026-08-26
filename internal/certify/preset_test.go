package certify

// preset_test.go pins the two properties a preset must have: every flag it
// supplies exists, and an explicit flag always wins.

import (
	"flag"
	"strings"
	"testing"
)

func boundFlags(t *testing.T) (*flag.FlagSet, *Options) {
	t.Helper()
	fs := flag.NewFlagSet("certify", flag.ContinueOnError)
	fs.SetOutput(&strings.Builder{})
	opts := DefaultOptions()
	opts.BindFlags(fs)
	return fs, &opts
}

// A preset naming a flag nobody binds fills in nothing, silently — which is
// exactly the "nine flags copied between three shells" failure it exists to
// prevent, wearing a different hat.
func TestPresetFlagsAllExist(t *testing.T) {
	fs, _ := boundFlags(t)
	for _, name := range PresetNames() {
		for _, f := range PresetFlagNames(name) {
			if fs.Lookup(f) == nil {
				t.Errorf("-preset %s supplies -%s, which Options.BindFlags does not bind", name, f)
			}
		}
	}
}

func TestPresetLocalFillsInTheLoopbackBench(t *testing.T) {
	fs, opts := boundFlags(t)
	if err := fs.Parse(nil); err != nil {
		t.Fatal(err)
	}
	if err := ApplyPreset(fs, "local", map[string]bool{}); err != nil {
		t.Fatal(err)
	}
	opts.Targets.Normalise()
	want := map[string]string{
		"gateway":       "127.0.0.1:8802",
		"gridsim":       "127.0.0.1:11113",
		"gridsim-admin": "http://127.0.0.1:11114",
		"modsim":        "127.0.0.1:5020",
		"modsim-api":    "http://127.0.0.1:6020",
		"mbapsdev":      "127.0.0.1:8021",
		"mbapsdev-api":  "http://127.0.0.1:6031",
	}
	got := map[string]string{
		"gateway":       opts.Targets.Gateway,
		"gridsim":       opts.Targets.GridSim,
		"gridsim-admin": opts.Targets.GridSimAdmin,
		"modsim":        opts.Targets.ModSim,
		"modsim-api":    opts.Targets.ModSimAPI,
		"mbapsdev":      opts.Targets.MBAPSDev,
		"mbapsdev-api":  opts.Targets.MBAPSDevAPI,
	}
	for k, w := range want {
		if got[k] != w {
			t.Errorf("-%s = %q, want %q", k, got[k], w)
		}
	}
	if opts.Targets.Endpoint(TargetMetrics) != "http://127.0.0.1:9102/metrics" {
		t.Errorf("metrics endpoint = %q", opts.Targets.Endpoint(TargetMetrics))
	}
	if opts.DevAPI != DefaultDevAPI {
		t.Errorf("-dev-api = %q, want %q", opts.DevAPI, DefaultDevAPI)
	}
	// Loopback traffic crosses lo and nothing else: a preset that left the
	// bench NIC here would produce a capture with zero frames.
	if opts.Iface != "lo" {
		t.Errorf("-iface = %q, want lo", opts.Iface)
	}
	// gridsim and its admin API must name ONE host, or preflight refuses the
	// run the preset just configured.
	if !strings.Contains(opts.Targets.GridSimAdmin, "127.0.0.1") ||
		!strings.HasPrefix(opts.Targets.GridSim, "127.0.0.1:") {
		t.Error("the preset's gridsim data and admin addresses do not name one host")
	}
}

func TestPresetDoesNotOverrideAnExplicitFlag(t *testing.T) {
	fs, opts := boundFlags(t)
	if err := fs.Parse([]string{"-gridsim", "192.168.0.188:11113", "-iface", "wlp2s0"}); err != nil {
		t.Fatal(err)
	}
	set := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { set[f.Name] = true })
	if err := ApplyPreset(fs, "local", set); err != nil {
		t.Fatal(err)
	}
	if opts.Targets.GridSim != "192.168.0.188:11113" {
		t.Errorf("-gridsim = %q, want the explicit value to win", opts.Targets.GridSim)
	}
	if opts.Iface != "wlp2s0" {
		t.Errorf("-iface = %q, want the explicit value to win", opts.Iface)
	}
	// And the ones NOT typed are still filled in.
	if opts.Targets.ModSim != "127.0.0.1:5020" {
		t.Errorf("-modsim = %q, want the preset to have filled it", opts.Targets.ModSim)
	}
}

// An explicit value that HAPPENS to equal the default must still win. This is
// the case a compare-against-defaults implementation cannot get right, and the
// reason ApplyPreset takes fs.Visit's set instead.
func TestPresetHonoursAnExplicitValueEqualToTheDefault(t *testing.T) {
	fs, opts := boundFlags(t)
	def := DefaultTargets().GridSim
	if err := fs.Parse([]string{"-gridsim", def}); err != nil {
		t.Fatal(err)
	}
	set := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { set[f.Name] = true })
	if err := ApplyPreset(fs, "local", set); err != nil {
		t.Fatal(err)
	}
	if opts.Targets.GridSim != def {
		t.Errorf("-gridsim = %q, want the typed value %q to survive", opts.Targets.GridSim, def)
	}
}

func TestNoPresetChangesNothing(t *testing.T) {
	fs, opts := boundFlags(t)
	before := opts.Targets
	if err := ApplyPreset(fs, "", map[string]bool{}); err != nil {
		t.Fatal(err)
	}
	if opts.Targets.Gateway != before.Gateway || opts.Iface != DefaultOptions().Iface {
		t.Error("an empty -preset changed the configuration")
	}
}

func TestUnknownPresetIsRefused(t *testing.T) {
	fs, _ := boundFlags(t)
	err := ApplyPreset(fs, "labbb", map[string]bool{})
	if err == nil || !strings.Contains(err.Error(), "local") {
		t.Fatalf("ApplyPreset() = %v, want a refusal listing the presets that exist", err)
	}
}
