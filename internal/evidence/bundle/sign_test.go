package bundle

// sign_test.go pins WP7-T4 / REV0907-E4: MANIFEST.sha256's detached ed25519
// signature, and specifically the attack a hash-only manifest cannot catch —
// a whole bundle rewritten and rehashed to agree with itself.

import (
	"bytes"
	"crypto/ed25519"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"csip-tls-test/internal/evidence/capture"
)

// signedBundle writes a minimal, real, self-verifying bundle (one real
// capture, one case) signed with priv — or unsigned, when priv is nil — and
// returns its directory and the path of the capture file AS COPIED INTO the
// bundle (not the source file Write copied it from).
func signedBundle(t *testing.T, priv ed25519.PrivateKey) (dir, capturePath string) {
	t.Helper()
	work := t.TempDir()
	srcCapture := filepath.Join(work, "run.pcapng")
	writeSyntheticCapture(t, srcCapture)

	b := NewBuilder(RunMeta{Tool: "evidence-engine-test", Operator: "bench"})
	b.SetCapture(capture.Summary{Tool: "dumpcap", Format: "pcapng"}, srcCapture)
	b.AddCase(TestCaseResult{ID: "SIGN-1", Title: "signing fixture", Verdict: Pass})
	if priv != nil {
		b.SetSignKey(priv)
	}

	dir = filepath.Join(work, "bundle")
	bd, err := b.Write(dir)
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	return dir, filepath.Join(dir, filepath.FromSlash(bd.Files.Capture))
}

// genKeyPair generates a fresh signing key through the same path an operator
// uses (certify -gen-sign-key), and loads both halves back the way -sign-key
// and -pubkey do.
func genKeyPair(t *testing.T) (privPath, pubPath string, priv ed25519.PrivateKey, pub ed25519.PublicKey, keyID string) {
	t.Helper()
	dir := t.TempDir()
	var err error
	privPath, pubPath, keyID, err = GenerateSignKey(dir)
	if err != nil {
		t.Fatalf("GenerateSignKey: %v", err)
	}
	priv, err = LoadSignKey(privPath)
	if err != nil {
		t.Fatalf("LoadSignKey: %v", err)
	}
	pub, err = LoadVerifyKey(pubPath)
	if err != nil {
		t.Fatalf("LoadVerifyKey: %v", err)
	}
	return privPath, pubPath, priv, pub, keyID
}

func hasProblemContaining(rep *VerifyReport, sub string) bool {
	for _, p := range rep.Problems {
		if strings.Contains(p, sub) {
			return true
		}
	}
	return false
}

// --- key generation ----------------------------------------------------------

func TestGenerateSignKeyRoundTrips(t *testing.T) {
	dir := t.TempDir()
	privPath, pubPath, keyID, err := GenerateSignKey(dir)
	if err != nil {
		t.Fatalf("GenerateSignKey: %v", err)
	}

	fi, err := os.Stat(privPath)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("private key %s mode = %v, want 0600 — an operator's signing key must not land readable "+
			"by anyone else, even briefly", privPath, fi.Mode().Perm())
	}

	priv, err := LoadSignKey(privPath)
	if err != nil {
		t.Fatalf("LoadSignKey: %v", err)
	}
	pub, err := LoadVerifyKey(pubPath)
	if err != nil {
		t.Fatalf("LoadVerifyKey: %v", err)
	}
	if got := KeyID(pub); got != keyID {
		t.Errorf("KeyID(pub) = %s, want %s (what GenerateSignKey itself returned)", got, keyID)
	}
	// The two halves must actually be a pair, not just two well-formed keys.
	msg := []byte("pairing check")
	sig := ed25519.Sign(priv, msg)
	if !ed25519.Verify(pub, msg, sig) {
		t.Fatal("GenerateSignKey's private and public key files are not a matching pair")
	}
}

// --- sign → verify OK ---------------------------------------------------------

func TestSignAndVerifySignedBundleOK(t *testing.T) {
	_, _, priv, pub, _ := genKeyPair(t)
	dir, _ := signedBundle(t, priv)

	if _, err := os.Stat(filepath.Join(dir, ManifestSigFile)); err != nil {
		t.Fatalf("Write did not produce %s: %v", ManifestSigFile, err)
	}

	rep, err := VerifySigned(dir, pub)
	if err != nil {
		t.Fatalf("VerifySigned: %v", err)
	}
	if !rep.OK {
		t.Fatalf("VerifySigned reported problems on a freshly signed, untampered bundle: %v", rep.Problems)
	}
	if rep.Unsigned {
		t.Error("VerifySigned reported Unsigned=true after actually checking a signature")
	}
}

// Plain Verify (what every OTHER caller in this codebase uses — a run's own
// self-check, -report, -trr) never has a public key, so it must report
// Unsigned even over a bundle that IS signed: what matters is what THIS
// verification checked, not what the bundle carries. See VerifyReport.Unsigned.
func TestVerifyPlainReportsUnsignedEvenOnASignedBundle(t *testing.T) {
	_, _, priv, _, _ := genKeyPair(t)
	dir, _ := signedBundle(t, priv)

	rep, err := Verify(dir)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !rep.Unsigned {
		t.Error("plain Verify (no pubkey) reported Unsigned=false — it never checked a signature at all")
	}
	if !rep.OK {
		t.Errorf("a signed, untampered bundle failed plain Verify: %v", rep.Problems)
	}
}

// An ordinary unsigned bundle (no -sign-key) must also report Unsigned from
// plain Verify — the common case, and the field's default reading.
func TestVerifyOfUnsignedBundleReportsUnsigned(t *testing.T) {
	dir, _ := signedBundle(t, nil)
	rep, err := Verify(dir)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !rep.Unsigned {
		t.Error("Verify of an unsigned bundle reported Unsigned=false")
	}
	if !rep.OK {
		t.Errorf("an unsigned, untampered bundle failed plain Verify: %v", rep.Problems)
	}
}

// -verify -pubkey against a bundle that was never signed at all must fail —
// a caller who supplied a public key asked, explicitly, for this bundle to
// prove who signed it, and a missing MANIFEST.sha256.sig has not.
func TestVerifySignedFailsWithNoSignatureFile(t *testing.T) {
	_, _, _, pub, _ := genKeyPair(t)
	dir, _ := signedBundle(t, nil)

	rep, err := VerifySigned(dir, pub)
	if err != nil {
		t.Fatalf("VerifySigned: %v", err)
	}
	if rep.OK {
		t.Fatal("VerifySigned accepted a bundle carrying no MANIFEST.sha256.sig at all")
	}
}

// A public key that never signed this bundle must be refused, the ordinary
// wrong-key case (as opposed to tampering).
func TestVerifySignedFailsWithWrongPublicKey(t *testing.T) {
	_, _, priv, _, _ := genKeyPair(t)
	_, _, _, otherPub, _ := genKeyPair(t)
	dir, _ := signedBundle(t, priv)

	rep, err := VerifySigned(dir, otherPub)
	if err != nil {
		t.Fatalf("VerifySigned: %v", err)
	}
	if rep.OK {
		t.Fatal("VerifySigned accepted a signature against a public key that never signed it")
	}
}

// --- tamper: one byte of the manifest, after signing --------------------------

// TestVerifySignedFailsOnTamperedManifestByte is the manifest-level tamper
// check: edit MANIFEST.sha256 itself after it was signed, and the signature
// — computed over the ORIGINAL bytes — must no longer cover it.
func TestVerifySignedFailsOnTamperedManifestByte(t *testing.T) {
	_, _, priv, pub, _ := genKeyPair(t)
	dir, _ := signedBundle(t, priv)

	mp := filepath.Join(dir, ManifestFile)
	raw, err := os.ReadFile(mp)
	if err != nil {
		t.Fatal(err)
	}
	tampered := flipOneHexDigit(t, raw)
	if err := os.WriteFile(mp, tampered, 0o644); err != nil {
		t.Fatal(err)
	}

	rep, err := VerifySigned(dir, pub)
	if err != nil {
		t.Fatalf("VerifySigned: %v", err)
	}
	if rep.OK {
		t.Fatal("VerifySigned accepted a MANIFEST.sha256 tampered after it was signed")
	}
	if !hasProblemContaining(rep, "signature") {
		t.Errorf("problems do not mention the signature check at all: %v", rep.Problems)
	}
}

// flipOneHexDigit changes the first ASCII digit '0'-'9' found in raw and
// returns a modified copy, so a manifest tamper stays inside a 64-char sha256
// field (structure — spacing, path, line count — untouched) rather than
// corrupting the line format itself, which sha256sum-format files are
// virtually certain to contain within their first checksum.
func flipOneHexDigit(t *testing.T, raw []byte) []byte {
	t.Helper()
	out := append([]byte(nil), raw...)
	for i, c := range out {
		if c >= '0' && c <= '9' {
			if c == '9' {
				out[i] = '0'
			} else {
				out[i] = c + 1
			}
			return out
		}
	}
	t.Fatal("flipOneHexDigit: no ASCII digit found to tamper")
	return nil
}

// --- REV0907-E4: the whole-bundle rewrite --------------------------------------

// TestVerifySignedFailsOnWholeBundleRewrite is the attack this feature
// exists for. Rewrite the capture, then rehash the manifest to agree with
// the rewrite — exactly what MANIFEST.sha256's own internal-consistency
// check cannot catch, because internal consistency is all it ever claimed to
// establish (see Verify's doc). Plain Verify must ACCEPT this bundle: the
// files agree with each other again. VerifySigned, given the ORIGINAL public
// key, must REFUSE it: the manifest it now hashes to was never signed.
func TestVerifySignedFailsOnWholeBundleRewrite(t *testing.T) {
	_, _, priv, pub, _ := genKeyPair(t)
	dir, capturePath := signedBundle(t, priv)

	// Rewrite the capture: flip one byte inside a real packet's payload (the
	// mbaps exception code), leaving the pcapng structure — block lengths,
	// packet count — intact so the capture still reads back as valid.
	raw, err := os.ReadFile(capturePath)
	if err != nil {
		t.Fatal(err)
	}
	idx := bytes.Index(raw, mbapsResponse)
	if idx < 0 {
		t.Fatal("test fixture bug: mbapsResponse payload not found in the capture")
	}
	rewritten := append([]byte(nil), raw...)
	rewritten[idx+len(mbapsResponse)-1] ^= 0xFF // the exception code byte
	if bytes.Equal(rewritten, raw) {
		t.Fatal("test fixture bug: the rewrite produced no change")
	}
	if err := os.WriteFile(capturePath, rewritten, 0o644); err != nil {
		t.Fatal(err)
	}

	// Rehash the manifest to agree with the rewrite — the attack itself.
	if err := WriteManifest(dir); err != nil {
		t.Fatal(err)
	}

	plain, err := Verify(dir)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !plain.OK {
		t.Fatalf("plain Verify did not accept the internally-consistent rewrite (test fixture problem?): %v",
			plain.Problems)
	}

	signed, err := VerifySigned(dir, pub)
	if err != nil {
		t.Fatalf("VerifySigned: %v", err)
	}
	if signed.OK {
		t.Fatal("VerifySigned accepted a whole-bundle rewrite that rehashed the manifest to agree with " +
			"itself (REV0907-E4) — this is exactly the attack a signature exists to catch")
	}
}
