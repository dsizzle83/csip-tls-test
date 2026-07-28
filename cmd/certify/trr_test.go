package main

// trr_test.go covers the -trr mode's own decisions: the ones that happen before
// any evidence is read, and the one flag-parsing rule that would silently
// produce the wrong package if it were wrong.
//
// Nothing here touches a network, a bench, or a device.

import (
	"strings"
	"testing"
)

func TestTRRNeedsAnOutputDirectory(t *testing.T) {
	code, _, errOut := exec(t, "-trr", t.TempDir())
	if code != exitUsage {
		t.Errorf("exit %d, want %d", code, exitUsage)
	}
	if !strings.Contains(errOut, "-trr-out") {
		t.Errorf("stderr does not name the missing flag: %q", errOut)
	}
	// And it says WHY there is no default, because "required flag" without a
	// reason reads as an oversight.
	if !strings.Contains(errOut, "stop verifying") {
		t.Errorf("stderr does not explain why there is no default: %q", errOut)
	}
}

func TestTRROnSomethingThatIsNotABundle(t *testing.T) {
	code, _, errOut := exec(t, "-trr", t.TempDir(), "-trr-out", t.TempDir())
	if code != exitUsage {
		t.Errorf("exit %d, want %d", code, exitUsage)
	}
	if !strings.Contains(errOut, "not a readable evidence bundle") {
		t.Errorf("stderr does not explain: %q", errOut)
	}
}

func TestTRRIsAModeLikeTheOthers(t *testing.T) {
	code, _, errOut := exec(t, "-trr", "runs/x", "-report", "runs/y")
	if code != exitUsage {
		t.Errorf("exit %d, want %d", code, exitUsage)
	}
	if !strings.Contains(errOut, "pick one") {
		t.Errorf("stderr does not name the conflict: %q", errOut)
	}
}

// TestTRRSourceKeepsItsDocumentList is the flag-parsing rule that matters.
//
// -doc, -uid and -suite all split on commas, and a -trr that did the same would
// tear `runs/full=ss-modbus-conf-v1.4,ssm-conf-v0.8` into a bundle path and a
// second "bundle" called ssm-conf-v0.8. The package that came out would cover
// the wrong documents and the only symptom would be a missing verdict row.
func TestTRRSourceKeepsItsDocumentList(t *testing.T) {
	c := &cli{}
	f := repeatFlag{&c.trr}
	if err := f.Set("runs/full=ss-modbus-conf-v1.4,ssm-conf-v0.8"); err != nil {
		t.Fatal(err)
	}
	if err := f.Set("runs/csip=csip-conf-v1.3"); err != nil {
		t.Fatal(err)
	}
	if len(c.trr) != 2 {
		t.Fatalf("-trr parsed %d source(s), want 2: %q", len(c.trr), c.trr)
	}
	if c.trr[0] != "runs/full=ss-modbus-conf-v1.4,ssm-conf-v0.8" {
		t.Errorf("the document list was split off its bundle: %q", c.trr[0])
	}
}
