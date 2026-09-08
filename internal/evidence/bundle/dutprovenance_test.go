package bundle

// dutprovenance_test.go pins REV0907-E2: a GATING bundle whose DUT record
// cannot name the artefact its verdicts describe (an unconfirmed build, or no
// image identity at all) must FAIL -verify. internal/certify's runner never
// writes such a bundle by construction (verifyDUTBuild REQUIRES -dut-build on
// a gating campaign and refuses an unreadable/mismatched DUT status before a
// bundle is ever written), so this exercises the defensive check Verify still
// runs for every bundle it did not itself just write — a hand-edited one, or
// an old bundle.json from before this field existed.

import (
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func gatingDUTBundle(t *testing.T, gating bool, dut DUT) *Bundle {
	t.Helper()
	b := &Bundle{Run: RunMeta{
		Campaign: &CampaignRecord{Name: "csip", Gating: gating},
		DUT:      dut,
	}}
	dir := writeBundleDir(t, b)
	loaded, err := Load(dir)
	if err != nil {
		t.Fatalf("Load() = %v", err)
	}
	return loaded
}

// The complete, correctly-produced shape: BuildReported and ImageBuildID both
// present, and Build (the operator's claim) matches BuildReported tolerantly
// — exactly what a real gating campaign's writeBundle (dutRecord) produces.
func TestVerifyAcceptsGatingWithCompleteDUTProvenance(t *testing.T) {
	loaded := gatingDUTBundle(t, true, DUT{
		Build: "212253a", BuildReported: "212253a1b2c3", ImageBuildID: "e230d5911111", ImageProfile: "image",
	})
	rep := &VerifyReport{OK: true}
	verifyDUTProvenance(loaded, rep)
	if !rep.OK || len(rep.Problems) != 0 {
		t.Errorf("a complete gating DUT record was flagged: ok=%v problems=%v", rep.OK, rep.Problems)
	}
}

// An empty dut.build_reported is exactly what a bundle written before
// REV0907-E2, or one hand-edited to remove it, looks like — refused.
func TestVerifyRefusesGatingWithEmptyBuildReported(t *testing.T) {
	loaded := gatingDUTBundle(t, true, DUT{Build: "212253a", ImageBuildID: "e230d5911111"})
	rep := &VerifyReport{OK: true}
	verifyDUTProvenance(loaded, rep)
	if rep.OK {
		t.Fatal("a gating bundle with empty dut.build_reported verified clean")
	}
	found := false
	for _, p := range rep.Problems {
		if strings.Contains(p, "dut.build_reported is empty") {
			found = true
		}
	}
	if !found {
		t.Errorf("no problem named the empty build_reported: %v", rep.Problems)
	}
}

// An empty dut.image_build_id — an older DUT (or a hand-edited bundle) — is
// refused independently of whether build_reported is fine, because RRS §2.1
// needs the ARTEFACT identity, not just the commit.
func TestVerifyRefusesGatingWithEmptyImageBuildID(t *testing.T) {
	loaded := gatingDUTBundle(t, true, DUT{Build: "212253a", BuildReported: "212253a1b2c3"})
	rep := &VerifyReport{OK: true}
	verifyDUTProvenance(loaded, rep)
	if rep.OK {
		t.Fatal("a gating bundle with empty dut.image_build_id verified clean")
	}
	found := false
	for _, p := range rep.Problems {
		if strings.Contains(p, "dut.image_build_id is empty") {
			found = true
		}
	}
	if !found {
		t.Errorf("no problem named the empty image_build_id: %v", rep.Problems)
	}
}

// A PROVEN CONTRADICTION: the operator's claim and the DUT's own report name
// different builds outright (not merely different abbreviation lengths of the
// same one). This is the shape internal/certify's own preflight refuses
// before a bundle is even written; here it is the defensive re-check.
func TestVerifyRefusesGatingWithBuildMismatch(t *testing.T) {
	loaded := gatingDUTBundle(t, true, DUT{
		Build: "212253a", BuildReported: "9999999abcdef", ImageBuildID: "e230d5911111",
	})
	rep := &VerifyReport{OK: true}
	verifyDUTProvenance(loaded, rep)
	if rep.OK {
		t.Fatal("a gating bundle with a build/build_reported mismatch verified clean")
	}
	for _, want := range []string{"212253a", "9999999abcdef", "does not match"} {
		found := false
		for _, p := range rep.Problems {
			if strings.Contains(p, want) {
				found = true
			}
		}
		if !found {
			t.Errorf("no problem mentions %q: %v", want, rep.Problems)
		}
	}
}

// The TOLERANT match must not false-positive as a mismatch: a short claim
// against a longer reported build_id (the routine case — an operator types
// the 7-char sha they flashed, buildid.Resolve keeps 12) is NOT a
// contradiction, and must verify clean.
func TestVerifyAcceptsGatingWithAbbreviatedBuildMatch(t *testing.T) {
	loaded := gatingDUTBundle(t, true, DUT{
		Build: "212253a", BuildReported: "212253a1b2c3d", ImageBuildID: "e230d5911111",
	})
	rep := &VerifyReport{OK: true}
	verifyDUTProvenance(loaded, rep)
	if !rep.OK || len(rep.Problems) != 0 {
		t.Errorf("an abbreviated-but-matching build was flagged as a mismatch: ok=%v problems=%v", rep.OK, rep.Problems)
	}
}

// An EXPLORATORY bundle is exempt: nothing requires -dut-build on a poke, and
// an empty or partial DUT record there is simply what an operator with no
// gateway transport configured produced.
func TestVerifyIgnoresExploratoryWithIncompleteDUTProvenance(t *testing.T) {
	loaded := gatingDUTBundle(t, false, DUT{})
	rep := &VerifyReport{OK: true}
	verifyDUTProvenance(loaded, rep)
	if !rep.OK || len(rep.Problems) != 0 {
		t.Errorf("an exploratory bundle with no DUT provenance was flagged: ok=%v problems=%v", rep.OK, rep.Problems)
	}
}

// A bundle carrying no campaign record at all has nothing for this check to
// say anything about — same posture verifyCampaignWeakening's own test takes.
func TestVerifyIgnoresADUTCheckOnABundleWithNoCampaignRecord(t *testing.T) {
	b := &Bundle{}
	dir := writeBundleDir(t, b)
	loaded, err := Load(dir)
	if err != nil {
		t.Fatalf("Load() = %v", err)
	}
	rep := &VerifyReport{OK: true}
	verifyDUTProvenance(loaded, rep)
	if !rep.OK || len(rep.Problems) != 0 {
		t.Errorf("a campaign-less bundle was flagged: ok=%v problems=%v", rep.OK, rep.Problems)
	}
}

// TestVerify_EndToEndRefusesGatingWithIncompleteDUTProvenance proves
// verifyDUTProvenance is actually WIRED into the public Verify() entry point
// — every other test in this file calls verifyDUTProvenance directly, which
// would keep passing even if Verify() stopped calling it. It goes through
// Builder.Write (a real MANIFEST.sha256, matching every genuine bundle)
// rather than writeBundleDir's raw JSON, since Verify()'s manifest check runs
// ahead of this one and would abort the run before ever reaching it. Verify()
// runs the DUT check ahead of its "no capture file" exit, so a capture-less
// bundle is still enough to reach it.
func TestVerify_EndToEndRefusesGatingWithIncompleteDUTProvenance(t *testing.T) {
	b := NewBuilder(RunMeta{
		Tool: "dutprovenance-test", Started: time.Unix(1_700_000_000, 0).UTC(), Finished: time.Unix(1_700_000_060, 0).UTC(),
		DUT: DUT{Build: "212253a"}, // no BuildReported, no ImageBuildID
	})
	b.SetCampaign(CampaignRecord{Name: "csip", Gating: true})
	dir := filepath.Join(t.TempDir(), "bundle")
	if _, err := b.Write(dir); err != nil {
		t.Fatalf("Write: %v", err)
	}

	rep, err := Verify(dir)
	if err != nil {
		t.Fatalf("Verify() = %v", err)
	}
	if rep.OK {
		t.Fatal("Verify() reported OK on a gating bundle with no dut.build_reported/image_build_id")
	}
	found := false
	for _, p := range rep.Problems {
		if strings.Contains(p, "dut.build_reported is empty") {
			found = true
		}
	}
	if !found {
		t.Errorf("Verify()'s problems do not include the DUT provenance refusal: %v", rep.Problems)
	}
}

func TestDutBuildMatches(t *testing.T) {
	cases := []struct {
		claimed, reported string
		want              bool
	}{
		{"212253a", "212253a1b2c3d", true}, // claimed is a prefix of the longer reported build
		{"212253a1b2c3d", "212253a", true}, // reported is a prefix of the longer claim
		{"212253a", "212253a-dirty", true}, // the -dirty suffix does not break the prefix
		{"V1.4.0", "v1.4.0", true},         // case-insensitive exact match
		{"212253a", "9999999", false},      // a real mismatch
		{"212", "2123456", false},          // too short to prefix-match (avoids trivial hits)
		{"212", "212", true},               // but an exact short match still counts
		{"212253a", "", false},             // nothing reported never matches
		{"", "212253a", false},             // an empty claim never matches
	}
	for _, tc := range cases {
		if got := dutBuildMatches(tc.claimed, tc.reported); got != tc.want {
			t.Errorf("dutBuildMatches(%q, %q) = %v, want %v", tc.claimed, tc.reported, got, tc.want)
		}
	}
}
