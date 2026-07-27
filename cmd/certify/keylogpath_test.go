package main

import (
	"path/filepath"
	"strings"
	"testing"
)

// TestKeylogOutsideBundle pins the containment rule. The live case that
// motivated it: a real run invoked with -out runs/<ts>/ -keylog runs/<ts>/keys.log
// produced a bundle holding byte-identical session secrets at BOTH keys.log and
// capture/keys.log, each listed in the manifest, and it verified cleanly — the
// duplication was invisible.
func TestKeylogOutsideBundle(t *testing.T) {
	tests := []struct {
		name    string
		keylog  string
		out     string
		wantErr bool
	}{
		{name: "the live-run mistake: keylog directly inside out", keylog: "runs/x/keys.log", out: "runs/x", wantErr: true},
		{name: "nested deeper inside the bundle", keylog: "runs/x/capture/keys.log", out: "runs/x", wantErr: true},
		{name: "sibling of the bundle is fine", keylog: "runs/x-keys.log", out: "runs/x", wantErr: false},
		{name: "elsewhere entirely is fine", keylog: "/tmp/keys.log", out: "runs/x", wantErr: false},
		{name: "a prefix-sharing sibling is not inside", keylog: "runs/x2/keys.log", out: "runs/x", wantErr: false},
		{name: "no bundle written at all", keylog: "/tmp/keys.log", out: "", wantErr: false},
		{name: "no keylog requested", keylog: "", out: "runs/x", wantErr: false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := keylogOutsideBundle(tc.keylog, tc.out)
			if (err != nil) != tc.wantErr {
				t.Fatalf("keylogOutsideBundle(%q, %q) error = %v, wantErr %v", tc.keylog, tc.out, err, tc.wantErr)
			}
			if err != nil && !strings.Contains(err.Error(), "-keylog") {
				t.Errorf("error does not name the offending flag: %v", err)
			}
		})
	}
}

// TestKeylogOutsideBundleAbsoluteAndRelativeAgree pins that the check is about
// the resolved paths, not their spelling — the same location expressed two ways
// must give the same answer, or the guard is trivially bypassed.
func TestKeylogOutsideBundleAbsoluteAndRelativeAgree(t *testing.T) {
	abs, err := filepath.Abs("runs/x/keys.log")
	if err != nil {
		t.Fatal(err)
	}
	if keylogOutsideBundle(abs, "runs/x") == nil {
		t.Error("an absolute keylog path inside a relative -out was allowed")
	}
	if keylogOutsideBundle("runs/x/./keys.log", "runs/x") == nil {
		t.Error("an unclean path inside the bundle was allowed")
	}
}
