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
	// Transcribed from the two files that OWN the lab topology — lexa-gw
	// scripts/lab/lib.sh and csip-tls-test scripts/lab/lab-sims-up.sh. A value
	// here that drifts from those makes every -preset local run address
	// something that is not the lab, and a run against nothing still writes a
	// bundle.
	want := map[string]string{
		"gateway":       "127.0.0.2:802",
		"gridsim":       "127.0.0.20:21113",
		"gridsim-admin": "http://127.0.0.20:21114",
		"modsim":        "127.0.0.20:15020",
		"modsim-api":    "http://127.0.0.20:16020",
		"mbapsdev":      "127.0.0.20:18021",
		"mbapsdev-api":  "http://127.0.0.20:16031",
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
	if !strings.Contains(opts.Targets.GridSimAdmin, "127.0.0.20") ||
		!strings.HasPrefix(opts.Targets.GridSim, "127.0.0.20:") {
		t.Error("the preset's gridsim data and admin addresses do not name one host")
	}
	// The DUT must NOT share an address with the simulators or the harness.
	// certify decides a captured frame's direction by comparing its source
	// against the DUT's; on one address for everything, every frame reads as
	// the DUT's and the SERVER-direction assertions become meaningless.
	if opts.Targets.GatewayHost != "127.0.0.2" {
		t.Errorf("DUT host = %q, want 127.0.0.2 — a distinct address is what makes frame direction decidable",
			opts.Targets.GatewayHost)
	}
	if strings.HasPrefix(opts.Targets.GridSim, opts.Targets.GatewayHost+":") {
		t.Error("the preset puts the simulators on the DUT's own address, which erases frame direction")
	}
	// 802 is the product's own port and the candidate manifest's claim
	// (secure_sunspec.port). cmd/mbaps refuses to start on any other, so a
	// preset naming one would address a listener that cannot exist.
	if _, port, _ := strings.Cut(opts.Targets.Gateway, ":"); port != "802" {
		t.Errorf("-gateway port = %q, want 802 — the candidate manifest claims it and cmd/mbaps "+
			"fail-closes on anything else", port)
	}
}

// The lab's port block is DISJOINT from the bench's on purpose: this desktop
// serves the bench board from 11113/11114, 5020/6020 and 8021/6031, and
// sim/simapi binds the wildcard address so a second set cannot be separated by
// address. A preset that reused one of them would silently attach a local loop
// to the simulators a live bench campaign is grading — and nothing in the run
// would say so.
func TestPresetLocalDoesNotCollideWithTheBenchPorts(t *testing.T) {
	fs, opts := boundFlags(t)
	if err := fs.Parse(nil); err != nil {
		t.Fatal(err)
	}
	if err := ApplyPreset(fs, "local", map[string]bool{}); err != nil {
		t.Fatal(err)
	}
	bench := DefaultTargets()
	benchPorts := map[string]string{}
	for name, addr := range map[string]string{
		"gridsim":       bench.GridSim,
		"gridsim-admin": bench.GridSimAdmin,
		"modsim":        bench.ModSim,
		"modsim-api":    bench.ModSimAPI,
		"mbapsdev":      bench.MBAPSDev,
		"mbapsdev-api":  bench.MBAPSDevAPI,
	} {
		benchPorts[portOf(addr)] = name
	}
	for name, addr := range map[string]string{
		"gridsim":       opts.Targets.GridSim,
		"gridsim-admin": opts.Targets.GridSimAdmin,
		"modsim":        opts.Targets.ModSim,
		"modsim-api":    opts.Targets.ModSimAPI,
		"mbapsdev":      opts.Targets.MBAPSDev,
		"mbapsdev-api":  opts.Targets.MBAPSDevAPI,
	} {
		if clash, ok := benchPorts[portOf(addr)]; ok {
			t.Errorf("-preset local -%s = %s reuses the BENCH's -%s port; sim/simapi binds the wildcard "+
				"address, so the lab would attach to the bench's simulators", name, addr, clash)
		}
	}
}

// portOf pulls the port out of a host:port or a URL, for the collision test.
func portOf(addr string) string {
	addr = strings.TrimPrefix(strings.TrimPrefix(addr, "http://"), "https://")
	addr = strings.TrimSuffix(addr, "/")
	_, port, ok := strings.Cut(addr, ":")
	if !ok {
		return ""
	}
	return port
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
	if opts.Targets.ModSim != "127.0.0.20:15020" {
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
