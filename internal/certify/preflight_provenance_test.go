package certify

// preflight_provenance_test.go proves the gating run refuses evidence it cannot
// trace: a dirty/unidentifiable harness tree, or a DUT build that does not match
// -dut-build (or could not be read to check). The harness-tree decision is tested
// through checkHarnessTree, whose (head, dirty) is an argument rather than a live
// git read, so the cases are deterministic; the DUT-build check runs against the
// authority test's fakeDUT wired into the gateway transport.

import (
	"context"
	"strings"
	"testing"

	"csip-tls-test/internal/evidence/bundle"
)

func provReporter() *Reporter { return NewReporter(&strings.Builder{}) }

// ── The harness tree ────────────────────────────────────────────────────────

func TestCheckHarnessTree_DirtyIsFatalOnGatingUnlessAllowed(t *testing.T) {
	gating := func(allowDirty bool) *Runner {
		return &Runner{campaign: CampaignSpec{Name: "csip"}, opts: Options{AllowDirty: allowDirty}}
	}
	exploratory := &Runner{opts: Options{}}

	// Clean tree: proceeds, records not-dirty.
	var out provenanceOutcome
	if err := gating(false).checkHarnessTree(provReporter(), "abc123def456", false, &out); err != nil {
		t.Fatalf("a clean tree was refused on a gating run: %v", err)
	}
	if out.Dirty || out.HarnessHead != "abc123def456" {
		t.Errorf("clean outcome not recorded: %+v", out)
	}

	// Dirty tree, gating, NOT allowed: FATAL.
	err := gating(false).checkHarnessTree(provReporter(), "abc123def456", true, &out)
	if err == nil {
		t.Fatal("a DIRTY harness tree was not refused on a gating campaign")
	}
	for _, want := range []string{"GATING", "DIRTY", "-allow-dirty"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not name %q:\n%v", want, err)
		}
	}

	// Dirty tree, gating, -allow-dirty: proceeds, records the escape hatch.
	out = provenanceOutcome{}
	if err := gating(true).checkHarnessTree(provReporter(), "abc123def456", true, &out); err != nil {
		t.Fatalf("-allow-dirty did not let a gating run proceed on a dirty tree: %v", err)
	}
	if !out.AllowDirtyUsed || !out.Dirty {
		t.Errorf("the dirty/allow-dirty outcome was not recorded: %+v", out)
	}

	// Dirty tree, EXPLORATORY: a warn, never a refusal.
	out = provenanceOutcome{}
	if err := exploratory.checkHarnessTree(provReporter(), "abc123def456", true, &out); err != nil {
		t.Fatalf("a dirty tree was refused on an EXPLORATORY run, want a WARN: %v", err)
	}
}

func TestCheckHarnessTree_UndeterminableHeadIsFatalOnGating(t *testing.T) {
	gating := &Runner{campaign: CampaignSpec{Name: "csip"}}
	var out provenanceOutcome
	err := gating.checkHarnessTree(provReporter(), "", false, &out)
	if err == nil {
		t.Fatal("a gating run with an UNDETERMINABLE harness HEAD was not refused")
	}
	if !strings.Contains(err.Error(), "GATING") {
		t.Errorf("the refusal does not name the gating posture:\n%v", err)
	}
	// -allow-dirty covers the unidentifiable tree too.
	allowed := &Runner{campaign: CampaignSpec{Name: "csip"}, opts: Options{AllowDirty: true}}
	if err := allowed.checkHarnessTree(provReporter(), "", false, &out); err != nil {
		t.Fatalf("-allow-dirty did not cover an undeterminable HEAD on a gating run: %v", err)
	}
}

// ── The DUT build ───────────────────────────────────────────────────────────

func provRunner(t *testing.T, gating bool, dutBuild string, f *fakeDUT) *Runner {
	t.Helper()
	r := &Runner{opts: Options{DUT: bundle.DUT{Build: dutBuild}}}
	if gating {
		r.campaign = CampaignSpec{Name: "csip"}
	}
	if f != nil {
		r.opts.GatewaySSH = "cc93"
		r.gwRunner = f.runner()
	}
	return r
}

func statusDUT(t *testing.T, fw, buildID string) *fakeDUT {
	return &fakeDUT{t: t, token: "s3cr3t\n",
		status: `{"fw":"` + fw + `","build_id":"` + buildID + `"}`}
}

// statusDUTWithImage is statusDUT plus the two image-identity fields
// (REV0907-E2): GET /status's image_build_id / image_profile, exactly as
// lexa-gw cmd/api/handlers.go stamps them when internal/buildid.ImageBuildID/
// ImageOrigin can read the DUT's rootfs build-id file.
func statusDUTWithImage(t *testing.T, fw, buildID, imageBuildID, imageProfile string) *fakeDUT {
	return &fakeDUT{t: t, token: "s3cr3t\n",
		status: `{"fw":"` + fw + `","build_id":"` + buildID + `","image_build_id":"` + imageBuildID +
			`","image_profile":"` + imageProfile + `"}`}
}

func TestVerifyDUTBuild_MatchAndMismatch(t *testing.T) {
	// MATCH (a short sha the operator flashed vs the DUT's longer build_id):
	// proceeds and records the reported build.
	var out provenanceOutcome
	if err := provRunner(t, true, "212253a", statusDUT(t, "dev", "212253a1b2c3")).
		verifyDUTBuild(context.Background(), provReporter(), &out); err != nil {
		t.Fatalf("a matching DUT build was refused: %v", err)
	}
	if out.DUTBuildID != "212253a1b2c3" {
		t.Errorf("the DUT-reported build was not recorded: %+v", out)
	}

	// MISMATCH on a GATING run: FATAL.
	out = provenanceOutcome{}
	err := provRunner(t, true, "212253a", statusDUT(t, "dev", "9999999abcdef")).
		verifyDUTBuild(context.Background(), provReporter(), &out)
	if err == nil {
		t.Fatal("a DUT build that does not match -dut-build was not refused on a gating campaign")
	}
	for _, want := range []string{"GATING", "MISMATCH"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not name %q:\n%v", want, err)
		}
	}

	// MISMATCH on an EXPLORATORY run: a warn, not a refusal.
	out = provenanceOutcome{}
	if err := provRunner(t, false, "212253a", statusDUT(t, "dev", "9999999abcdef")).
		verifyDUTBuild(context.Background(), provReporter(), &out); err != nil {
		t.Fatalf("a DUT build mismatch refused an EXPLORATORY run, want a WARN: %v", err)
	}
}

func TestVerifyDUTBuild_UnreadableWithClaimIsFatalOnGating(t *testing.T) {
	// -dut-build supplied, but the DUT's /status cannot be read: FATAL on gating.
	blind := &fakeDUT{t: t, token: "s3cr3t\n"} // status empty -> read error
	var out provenanceOutcome
	err := provRunner(t, true, "212253a", blind).verifyDUTBuild(context.Background(), provReporter(), &out)
	if err == nil {
		t.Fatal("a supplied -dut-build that could not be read was not refused on a gating campaign")
	}
	if !strings.Contains(err.Error(), "GATING") {
		t.Errorf("the refusal does not name the gating posture:\n%v", err)
	}

	// -dut-build supplied, but NO gateway to read it through: FATAL on gating,
	// naming the missing transport.
	out = provenanceOutcome{}
	err = provRunner(t, true, "212253a", nil).verifyDUTBuild(context.Background(), provReporter(), &out)
	if err == nil {
		t.Fatal("a supplied -dut-build with no gateway to verify it was not refused on a gating campaign")
	}
	if !strings.Contains(err.Error(), "gateway") {
		t.Errorf("the refusal does not name the missing gateway transport:\n%v", err)
	}
}

// TestVerifyDUTBuild_NoClaimRequiredOnGating pins REV0907-E2: a GATING
// campaign may not run at all without a declared -dut-build — before this, an
// omitted flag silently produced a bundle whose dut.build was simply empty,
// verified against nothing.
func TestVerifyDUTBuild_NoClaimRequiredOnGating(t *testing.T) {
	var out provenanceOutcome
	err := provRunner(t, true, "", statusDUT(t, "1.4.0", "cc93abc")).
		verifyDUTBuild(context.Background(), provReporter(), &out)
	if err == nil {
		t.Fatal("a GATING campaign with no -dut-build was not refused")
	}
	for _, want := range []string{"GATING", "-dut-build"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not name %q:\n%v", want, err)
		}
	}
}

// TestVerifyDUTBuild_NoClaimRecordsButNeverFailsOnExploratory: an EXPLORATORY
// run has nothing requiring -dut-build. The DUT-reported build (and image
// identity) is still recorded, and the run is never failed on it.
func TestVerifyDUTBuild_NoClaimRecordsButNeverFailsOnExploratory(t *testing.T) {
	var out provenanceOutcome
	if err := provRunner(t, false, "", statusDUTWithImage(t, "1.4.0", "cc93abc", "cc93abc111122", "image")).
		verifyDUTBuild(context.Background(), provReporter(), &out); err != nil {
		t.Fatalf("verifyDUTBuild failed an EXPLORATORY run with no -dut-build to check: %v", err)
	}
	if out.DUTBuildFW != "1.4.0" || out.DUTBuildID != "cc93abc" {
		t.Errorf("the DUT-reported build was not recorded for a no-claim run: %+v", out)
	}
	if out.DUTImageBuildID != "cc93abc111122" || out.DUTImageProfile != "image" {
		t.Errorf("the DUT-reported image identity was not recorded for a no-claim run: %+v", out)
	}
}

// TestVerifyDUTBuild_RecordsImageIdentity pins that a matching -dut-build
// claim still records the DUT's IMAGE identity (image_build_id/image_profile)
// alongside the build match — the artefact question RRS §2.1 needs answered,
// which BuildReported alone cannot answer (REV0907-E2).
func TestVerifyDUTBuild_RecordsImageIdentity(t *testing.T) {
	var out provenanceOutcome
	if err := provRunner(t, true, "212253a", statusDUTWithImage(t, "dev", "212253a1b2c3", "e230d5911111", "dev-deploy")).
		verifyDUTBuild(context.Background(), provReporter(), &out); err != nil {
		t.Fatalf("a matching DUT build was refused: %v", err)
	}
	if out.DUTImageBuildID != "e230d5911111" {
		t.Errorf("DUTImageBuildID = %q, want %q", out.DUTImageBuildID, "e230d5911111")
	}
	if out.DUTImageProfile != "dev-deploy" {
		t.Errorf("DUTImageProfile = %q, want %q", out.DUTImageProfile, "dev-deploy")
	}
}

// TestVerifyDUTBuild_OlderDUTWithNoImageFieldsStillMatches: a DUT running a
// lexa-gw build that predates image_build_id/image_profile on /status must
// not be refused for lacking fields it cannot possibly report — only
// bundle.Verify's static check (REV0907-E2) refuses a GATING bundle for that,
// and only once the bundle is actually written.
func TestVerifyDUTBuild_OlderDUTWithNoImageFieldsStillMatches(t *testing.T) {
	var out provenanceOutcome
	if err := provRunner(t, true, "212253a", statusDUT(t, "dev", "212253a1b2c3")).
		verifyDUTBuild(context.Background(), provReporter(), &out); err != nil {
		t.Fatalf("a matching DUT build with no image fields was refused: %v", err)
	}
	if out.DUTImageBuildID != "" || out.DUTImageProfile != "" {
		t.Errorf("image identity was fabricated for a DUT that reported none: %+v", out)
	}
}

// ── The comparison ──────────────────────────────────────────────────────────

func TestBuildIdentityMatches(t *testing.T) {
	cases := []struct {
		claimed, fw, buildID string
		want                 bool
	}{
		{"212253a", "dev", "212253a", true},       // exact against build_id
		{"212253a", "dev", "212253a1b2c3d", true}, // claimed is a prefix of the longer build_id
		{"212253a1b2c3d", "dev", "212253a", true}, // build_id is a prefix of the longer claim
		{"212253a", "dev", "212253a-dirty", true}, // the -dirty suffix does not break the prefix
		{"V1.4.0", "v1.4.0", "cc93abc", true},     // case-insensitive match against fw
		{"212253a", "dev", "9999999", false},      // a real mismatch
		{"212", "dev", "2123456", false},          // too short to prefix-match (avoids trivial hits)
		{"212", "dev", "212", true},               // but an exact short match still counts
		{"212253a", "", "", false},                // a DUT that reported nothing never matches
		{"", "dev", "212253a", false},             // an empty claim never matches
	}
	for _, tc := range cases {
		if got := buildIdentityMatches(tc.claimed, tc.fw, tc.buildID); got != tc.want {
			t.Errorf("buildIdentityMatches(%q, fw=%q, build_id=%q) = %v, want %v",
				tc.claimed, tc.fw, tc.buildID, got, tc.want)
		}
	}
}

// ── The bundle note ─────────────────────────────────────────────────────────

func TestProvenanceNote(t *testing.T) {
	// The DUT build is recorded whenever it was read.
	if note := provenanceNote(provenanceOutcome{DUTBuildFW: "1.4.0", DUTBuildID: "cc93abc"}); !strings.Contains(note, "DUT build reported") {
		t.Errorf("the DUT build was not recorded in the note: %q", note)
	}
	// The DUT's image identity is recorded in the same line (REV0907-E2),
	// even when the build fields themselves are absent — an older DUT with no
	// build_id but a hand-set image_profile is still worth stating.
	note := provenanceNote(provenanceOutcome{DUTImageBuildID: "e230d5911111", DUTImageProfile: "image"})
	for _, want := range []string{"image_build_id=e230d5911111", "image_profile=image"} {
		if !strings.Contains(note, want) {
			t.Errorf("the DUT image identity was not recorded in the note: %q (want %q)", note, want)
		}
	}
	// -allow-dirty over a dirty tree is recorded, with the weakened footing named.
	note = provenanceNote(provenanceOutcome{AllowDirtyUsed: true, Dirty: true, HarnessHead: "abc123"})
	for _, want := range []string{"-allow-dirty USED", "DIRTY", "not reproducible"} {
		if !strings.Contains(note, want) {
			t.Errorf("the allow-dirty note does not say %q: %q", want, note)
		}
	}
	// A clean tree with -allow-dirty passed but inert records nothing.
	if note := provenanceNote(provenanceOutcome{AllowDirtyUsed: true, Dirty: false, HarnessHead: "abc123"}); note != "" {
		t.Errorf("an inert -allow-dirty produced a note: %q", note)
	}
	// Nothing to say: no note.
	if note := provenanceNote(provenanceOutcome{HarnessHead: "abc123"}); note != "" {
		t.Errorf("a clean run produced a spurious provenance note: %q", note)
	}
}

// ── dutRecord (writeBundle's DUT record) ────────────────────────────────────

// TestDutRecord_MergesClaimWithMeasured pins that writeBundle's bundle.DUT
// carries BOTH the operator's claims (name/address/identity/role/build) AND
// what the provenance preflight actually measured (BuildReported/
// ImageBuildID/ImageProfile) — never one overwriting the other, since they
// answer different questions (REV0907-E2).
func TestDutRecord_MergesClaimWithMeasured(t *testing.T) {
	r := &Runner{opts: Options{DUT: bundle.DUT{
		Name: "bench-inv-1", Address: "69.0.0.2:802", Identity: "0x1234", Role: "inverter",
		Build: "212253a",
	}}}
	prov := provenanceOutcome{
		DUTBuildFW: "dev", DUTBuildID: "212253a1b2c3",
		DUTImageBuildID: "e230d5911111", DUTImageProfile: "image",
	}

	got := r.dutRecord(prov)

	if got.Name != "bench-inv-1" || got.Address != "69.0.0.2:802" || got.Identity != "0x1234" || got.Role != "inverter" {
		t.Errorf("the operator's DUT claims were not preserved: %+v", got)
	}
	if got.Build != "212253a" {
		t.Errorf("Build = %q, want the operator's CLAIM %q untouched", got.Build, "212253a")
	}
	if got.BuildReported != "212253a1b2c3" {
		t.Errorf("BuildReported = %q, want the DUT-MEASURED build_id %q", got.BuildReported, "212253a1b2c3")
	}
	if got.ImageBuildID != "e230d5911111" {
		t.Errorf("ImageBuildID = %q, want %q", got.ImageBuildID, "e230d5911111")
	}
	if got.ImageProfile != "image" {
		t.Errorf("ImageProfile = %q, want %q", got.ImageProfile, "image")
	}
}

// TestDutRecord_NothingMeasuredLeavesReportedFieldsEmpty: a run that never
// reached (or could not use) the gateway transport records no measured
// fields — dutRecord must not fabricate one from the operator's claim.
func TestDutRecord_NothingMeasuredLeavesReportedFieldsEmpty(t *testing.T) {
	r := &Runner{opts: Options{DUT: bundle.DUT{Build: "212253a"}}}
	got := r.dutRecord(provenanceOutcome{})
	if got.BuildReported != "" || got.ImageBuildID != "" || got.ImageProfile != "" {
		t.Errorf("dutRecord fabricated measured fields with nothing to measure from: %+v", got)
	}
	if got.Build != "212253a" {
		t.Errorf("Build = %q, want the operator's claim preserved", got.Build)
	}
}
