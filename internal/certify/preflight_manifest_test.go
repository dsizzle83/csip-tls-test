package certify

// preflight_manifest_test.go proves the fail-closed flip: on a GATING campaign a
// topology claim the DUT could not be ASKED about (no gateway, an unreadable
// inventory, an admitted count of zero while the manifest declares a device) is
// FATAL, while the same gap on an exploratory run is a recorded WARN. Before the
// flip every one of these was a bare warn-and-continue on both paths.

import (
	"context"
	"strings"
	"testing"
)

// manifestPreflight builds a manifest-preflight runner over validManifestJSON,
// optionally gating, optionally with a fakeDUT wired into the gateway transport
// (reused from preflight_authority_test.go).
func manifestPreflight(t *testing.T, gating bool, f *fakeDUT) *Runner {
	t.Helper()
	r := &Runner{manifest: loadManifest(t, validManifestJSON), opts: Options{}}
	if gating {
		r.campaign = CampaignSpec{Name: "csip"}
	}
	if f != nil {
		r.opts.GatewaySSH = "cc93"
		r.gwRunner = f.runner()
	}
	return r
}

func runManifestPreflight(t *testing.T, r *Runner) error {
	t.Helper()
	return r.preflightManifest(context.Background(), NewReporter(&strings.Builder{}))
}

// No gateway at all: the manifest's topology claims cannot be checked against the
// device. Fatal on gating, a warn on an exploratory run.
func TestPreflightManifest_NoGatewayFatalOnGating(t *testing.T) {
	if err := runManifestPreflight(t, manifestPreflight(t, true, nil)); err == nil {
		t.Fatal("preflightManifest did not refuse a GATING run with no gateway introspection")
	} else {
		for _, want := range []string{"GATING", "gateway"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("the refusal does not name %q:\n%v", want, err)
			}
		}
	}
	if err := runManifestPreflight(t, manifestPreflight(t, false, nil)); err != nil {
		t.Fatalf("preflightManifest REFUSED an EXPLORATORY run with no gateway, want a WARN: %v", err)
	}
}

// Inventory unreadable: /southbound/inventory AND the /status fallback both fail.
// Fatal on gating, a warn on an exploratory run.
func TestPreflightManifest_UnreadableInventoryFatalOnGating(t *testing.T) {
	blind := func() *fakeDUT { return &fakeDUT{t: t, token: "s3cr3t\n"} } // inventory+status empty -> both error
	if err := runManifestPreflight(t, manifestPreflight(t, true, blind())); err == nil {
		t.Fatal("preflightManifest did not refuse a GATING run whose DUT inventory could not be read")
	} else if !strings.Contains(err.Error(), "GATING") {
		t.Errorf("the refusal does not name the gating posture:\n%v", err)
	}
	if err := runManifestPreflight(t, manifestPreflight(t, false, blind())); err != nil {
		t.Fatalf("preflightManifest REFUSED an EXPLORATORY run whose inventory could not be read, want a WARN: %v", err)
	}
}

// The DUT admitted NO device while the manifest declares one: unproven topology.
// Fatal on gating, a warn on an exploratory run.
func TestPreflightManifest_StaleInventoryFatalOnGating(t *testing.T) {
	stale := func() *fakeDUT {
		return &fakeDUT{t: t, token: "s3cr3t\n", inventory: `{"devices":[],"stale":true}`}
	}
	if err := runManifestPreflight(t, manifestPreflight(t, true, stale())); err == nil {
		t.Fatal("preflightManifest did not refuse a GATING run where the DUT admitted no device but the " +
			"manifest declares one")
	} else if !strings.Contains(err.Error(), "GATING") {
		t.Errorf("the refusal does not name the gating posture:\n%v", err)
	}
	if err := runManifestPreflight(t, manifestPreflight(t, false, stale())); err != nil {
		t.Fatalf("preflightManifest REFUSED an EXPLORATORY run on a stale inventory, want a WARN: %v", err)
	}
}

// The happy path still passes: a gating run whose DUT topology MATCHES the
// manifest is not refused — the flip must not turn a clean bench red.
func TestPreflightManifest_MatchingInventoryPassesOnGating(t *testing.T) {
	ok := &fakeDUT{t: t, token: "s3cr3t\n",
		inventory: `{"devices":[{"device":"der0","transport":"tcp","role":"inverter","nb_unit":1,"models":[704]}],"stale":false}`}
	if err := runManifestPreflight(t, manifestPreflight(t, true, ok)); err != nil {
		t.Fatalf("preflightManifest refused a GATING run whose DUT topology MATCHES the manifest: %v", err)
	}
}

// A genuine CONTRADICTION (the DUT admits a device whose role disagrees with the
// manifest) is fatal on BOTH paths — unchanged by the flip, which only touches
// the "could not be proven" cases, never the "shown to be wrong" ones.
func TestPreflightManifest_ContradictionFatalOnBothPaths(t *testing.T) {
	wrong := func() *fakeDUT {
		return &fakeDUT{t: t, token: "s3cr3t\n",
			inventory: `{"devices":[{"device":"der0","transport":"tcp","role":"battery","nb_unit":1,"models":[704]}],"stale":false}`}
	}
	if err := runManifestPreflight(t, manifestPreflight(t, true, wrong())); err == nil {
		t.Fatal("preflightManifest did not refuse a GATING run whose DUT role CONTRADICTS the manifest")
	}
	if err := runManifestPreflight(t, manifestPreflight(t, false, wrong())); err == nil {
		t.Fatal("preflightManifest did not refuse an EXPLORATORY run whose DUT role CONTRADICTS the " +
			"manifest — a contradiction is fatal on both paths")
	}
}
