package certify

// preflightsigning_test.go pins WP7-T4 / REV0907-E4: a GATING campaign
// refuses to run with no -sign-key, because an unsigned MANIFEST.sha256
// detects piecemeal tampering but not a whole-bundle rewrite that rehashes
// itself to agree (see bundle/sign.go, bundle/verify.go's VerifySigned).
//
// Unlike the switches preflight_weakened_test.go covers, an unsigned GATING
// run has no legitimate disclosed shape: unprovable's gating branch refuses
// the run before writeBundle is ever reached, so "unsigned" never appears in
// Runner.weakened or bundle.CampaignRecord.Weakened — there would be nothing
// for a reader to see it on.

import (
	"context"
	"crypto/ed25519"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"csip-tls-test/internal/evidence/bundle"
)

// genSignKeyPair generates a fresh signing key the way certify -gen-sign-key
// does, and loads the private half back the way -sign-key does.
func genSignKeyPair(t *testing.T) (priv ed25519.PrivateKey, privPath string) {
	t.Helper()
	dir := t.TempDir()
	privPath, _, _, err := bundle.GenerateSignKey(dir)
	if err != nil {
		t.Fatalf("GenerateSignKey: %v", err)
	}
	priv, err = bundle.LoadSignKey(privPath)
	if err != nil {
		t.Fatalf("LoadSignKey: %v", err)
	}
	return priv, privPath
}

func TestPreflightSigningRefusesGatingWithNoSignKey(t *testing.T) {
	r := &Runner{campaign: CampaignSpec{Name: "csip"}}
	rep := NewReporter(&strings.Builder{})
	err := r.preflightSigning(rep)
	if err == nil {
		t.Fatal("a GATING campaign with no -sign-key was accepted")
	}
	for _, want := range []string{"GATING", "-campaign csip", "-sign-key", "SIGNED"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("refusal does not mention %q: %v", want, err)
		}
	}
}

func TestPreflightSigningAcceptsGatingWithSignKey(t *testing.T) {
	priv, _ := genSignKeyPair(t)
	r := &Runner{campaign: CampaignSpec{Name: "csip"}, signKey: priv}
	rep := NewReporter(&strings.Builder{})
	if err := r.preflightSigning(rep); err != nil {
		t.Fatalf("a GATING campaign WITH -sign-key was refused: %v", err)
	}
}

func TestPreflightSigningWarnsExploratoryWithNoSignKey(t *testing.T) {
	r := &Runner{} // no campaign name: exploratory
	rep := NewReporter(&strings.Builder{})
	if err := r.preflightSigning(rep); err != nil {
		t.Fatalf("an EXPLORATORY run (no -campaign) with no -sign-key was refused: %v", err)
	}
	if len(r.weakened) != 0 {
		t.Errorf("preflightSigning recorded %v in Runner.weakened — an unsigned run has no legitimate "+
			"disclosed shape to record on a GATING campaign, since unprovable's gating branch already "+
			"refuses it outright before this could ever reach a bundle", r.weakened)
	}
}

// The default posture (a real -sign-key) must never touch the audit trail or
// refuse anything, gating or not.
func TestPreflightSigningWithKeyRecordsNothing(t *testing.T) {
	priv, _ := genSignKeyPair(t)
	gating := &Runner{campaign: CampaignSpec{Name: "csip"}, signKey: priv}
	if err := gating.preflightSigning(NewReporter(&strings.Builder{})); err != nil {
		t.Fatalf("a signed GATING run was refused: %v", err)
	}
	if len(gating.weakened) != 0 {
		t.Errorf("a signed run recorded: %v", gating.weakened)
	}
}

// The audit trail — or rather its absence — must reach the bundle this
// package actually writes on a real end-to-end run, not just the in-memory
// field a unit test can inspect directly: same double-check discipline as
// TestWeakenedSwitchesReachTheWrittenBundle, applied to the one switch that
// must NEVER appear.
func TestUnsignedExploratoryBundleCarriesNoWeakenedSigningEntryOrSigFile(t *testing.T) {
	cat := catalogFile(t)
	reg := NewRegistry()
	reg.Register("doc-a::A-001", "x", noopCheck)
	opts, out := baseOptions(t, nil)
	run, err := New(reg, cat, opts)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := run.Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}
	b, err := bundle.Load(out)
	if err != nil {
		t.Fatal(err)
	}
	if b.Run.Campaign != nil {
		for _, w := range b.Run.Campaign.Weakened {
			if strings.Contains(w, "sign") {
				t.Errorf("campaign.weakened unexpectedly names signing: %v", b.Run.Campaign.Weakened)
			}
		}
	}
	if _, err := os.Stat(filepath.Join(out, bundle.ManifestSigFile)); err == nil {
		t.Error("an unsigned run's bundle carries a MANIFEST.sha256.sig")
	}
}

// -sign-key actually reaches the written bundle end to end: an exploratory
// run given -sign-key produces a bundle whose manifest signature checks out
// against the matching public key.
func TestSignKeyReachesTheWrittenBundle(t *testing.T) {
	_, privPath := genSignKeyPair(t)
	pubPath := strings.TrimSuffix(privPath, ".key") + ".pub" // GenerateSignKey's own naming
	pub, err := bundle.LoadVerifyKey(pubPath)
	if err != nil {
		t.Fatal(err)
	}

	cat := catalogFile(t)
	reg := NewRegistry()
	reg.Register("doc-a::A-001", "x", noopCheck)
	opts, out := baseOptions(t, nil)
	opts.SignKeyPath = privPath
	run, err := New(reg, cat, opts)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := run.Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}

	// baseOptions(t, nil) runs -no-capture (no bench, no NIC — see
	// runner_test.go), so bundle.VerifySigned's OWN "no capture, nothing to
	// re-check" refusal is orthogonal to what this test is pinning: that
	// -sign-key's key actually reached writeBundle and produced a signature
	// checkable against the matching public key. Checking the signature
	// directly isolates that from the capture question, which
	// TestRunnerEndToEndProducesAVerifiableBundle already covers elsewhere.
	if err := bundle.VerifyManifestSignature(out, pub); err != nil {
		t.Fatalf("the -sign-key'd bundle's manifest does not verify against the matching public key: %v", err)
	}
}

// A bad -sign-key path is a startup error, not a surprise forty minutes into
// a bench run.
func TestBadSignKeyPathIsAConstructionError(t *testing.T) {
	cat := catalogFile(t)
	reg := NewRegistry()
	reg.Register("doc-a::A-001", "x", noopCheck)
	opts, _ := baseOptions(t, nil)
	opts.SignKeyPath = filepath.Join(t.TempDir(), "does-not-exist.key")
	if _, err := New(reg, cat, opts); err == nil {
		t.Fatal("New accepted a -sign-key path that does not exist")
	}
}
