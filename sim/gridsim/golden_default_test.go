package gridsim

// golden_default_test.go pins the DEFAULT resource tree byte for byte.
//
// The DER AGGREGATOR CLIENT work (fleet.go, subscribe.go) added two levers that
// change what this simulator serves: a five-EndDevice topology and a
// Subscription function set that puts a SubscriptionListLink on every EndDevice
// and a subscribable attribute on the FunctionSetAssignmentsList. Both are off
// by default, and "off by default" is a claim that has to be checkable — the
// direct-DER-client rows of CSIP-CONF-v1.3 were certified against the
// single-EndDevice tree, and a lever that leaked one byte into it would
// re-measure them against a fixture nobody agreed to.
//
// The golden was generated from the tree as it stood at a51e13d, BEFORE either
// lever existed (git worktree at that commit, this same dumper). So the file
// this test compares against is not a snapshot of the new code's own output —
// it is the old code's, and a difference is a regression rather than a
// disagreement with a golden somebody regenerated.
//
// Regenerate ONLY when the default tree is deliberately changed:
//
//	go test ./sim/gridsim -run TestDefaultTreeIsByteIdentical -update-golden

import (
	"encoding/xml"
	"flag"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

var updateGolden = flag.Bool("update-golden", false,
	"rewrite testdata/default-tree.golden from this run's output")

// unixSeconds matches the ten-digit epoch stamps the tree carries (creationTime,
// changedTime, currentTime, interval starts). They move every run and are the
// only thing in the tree that legitimately does, so they are normalised and
// everything else is compared literally.
var unixSeconds = regexp.MustCompile(`\b1[0-9]{9}\b`)

// defaultTreeDump renders every resource in the tree as "path\n<xml>", sorted by
// path, with epoch stamps normalised.
func defaultTreeDump(t *testing.T, s *Server) string {
	t.Helper()
	s.mu.RLock()
	paths := make([]string, 0, len(s.resources))
	for p := range s.resources {
		paths = append(paths, p)
	}
	s.mu.RUnlock()
	sort.Strings(paths)

	var b strings.Builder
	for _, p := range paths {
		s.mu.RLock()
		res := s.resources[p]
		s.mu.RUnlock()
		data, err := xml.MarshalIndent(res, "", "  ")
		if err != nil {
			t.Fatalf("marshal %s: %v", p, err)
		}
		b.WriteString("=== " + p + "\n")
		b.Write(unixSeconds.ReplaceAll(data, []byte("EPOCH")))
		b.WriteString("\n")
	}
	return b.String()
}

func TestDefaultTreeIsByteIdentical(t *testing.T) {
	got := defaultTreeDump(t, NewServer("ABCDEF0123456789ABCDEF0123456789ABCDEF01"))

	golden := filepath.Join("testdata", "default-tree.golden")
	if *updateGolden {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(golden, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
		t.Logf("wrote %s (%d bytes)", golden, len(got))
		return
	}

	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatalf("read the golden default tree: %v", err)
	}
	if got == string(want) {
		return
	}
	// Report the first differing line rather than two multi-kilobyte blobs.
	gl, wl := strings.Split(got, "\n"), strings.Split(string(want), "\n")
	for i := 0; i < len(gl) && i < len(wl); i++ {
		if gl[i] != wl[i] {
			t.Fatalf("the default resource tree changed at line %d — the single-EndDevice tree is what the "+
				"direct-DER-client rows were certified against, so a change here is a change to evidence "+
				"already published:\n  was: %s\n  now: %s", i+1, wl[i], gl[i])
		}
	}
	t.Fatalf("the default resource tree changed length: %d lines, was %d", len(gl), len(wl))
}

// TestNeitherLeverIsOnByDefault is the same claim stated the other way round,
// so that a future change which regenerates the golden without thinking still
// trips over the property the golden exists to protect.
func TestNeitherLeverIsOnByDefault(t *testing.T) {
	s := NewServer("ABCDEF0123456789ABCDEF0123456789ABCDEF01")
	if s.FleetEnabled() {
		t.Error("the CTP Figure-15 fleet is on without EnableFleet")
	}
	if s.SubscriptionsEnabled() {
		t.Error("the Subscription function set is on without EnableSubscriptions")
	}
	dump := defaultTreeDump(t, s)
	for _, forbidden := range []string{"SubscriptionListLink", "subscribable", "/edev/3", "/derp/spa1"} {
		if strings.Contains(dump, forbidden) {
			t.Errorf("the default tree carries %q, which belongs to a lever that is supposed to be off",
				forbidden)
		}
	}
}
