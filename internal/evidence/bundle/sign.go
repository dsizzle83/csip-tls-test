package bundle

// sign.go signs and verifies MANIFEST.sha256 with a detached ed25519
// signature (WP7-T4, REV0907-E4).
//
// # What a hash-only manifest cannot catch
//
// Verify's own doc already says this plainly: MANIFEST.sha256 establishes
// that every file in a bundle directory agrees with EVERY OTHER file in it —
// internal consistency — and nothing stops somebody who controls the whole
// directory from rewriting the capture AND rehashing the manifest to match
// the rewrite. Every check Verify runs still passes, because internal
// consistency is all a hash ever claimed to establish. REV0907-E4 names
// exactly this: a bundle that "verifies" clean while describing traffic that
// never happened.
//
// A signature closes that gap by tying the manifest to a key nobody but the
// operator holds and this tool never writes to disk unencrypted-adjacent —
// the private key lives OUTSIDE the repository, on the operator's own
// machine, and only its public half ever leaves it. Rewriting the bundle
// after the fact still produces a manifest that hashes correctly against the
// (also rewritten) files; it does not produce one the original signature
// verifies against, because the attacker does not have the key.
//
// # What it still does not claim
//
// A signature says WHO held the key that signed this manifest, not WHO ran
// the test or WHETHER the DUT behaved as recorded. It is not a certificate
// chain, there is no PKI here, and a lab receiving a bundle still has to get
// the operator's public key through a channel it trusts (see
// docs/CONFORMANCE_TOOL.md §4). What it adds over the unsigned baseline is
// narrow and load-bearing: non-repudiation of the manifest bytes, which is
// exactly the gap Verify's own doc names as out of scope for a hash alone.
//
// # Format
//
// MANIFEST.sha256.sig sits beside MANIFEST.sha256 and carries one small JSON
// object (ManifestSignature): the algorithm name (so a future scheme can be
// added without an old verifier misreading it as ed25519), a key id (the
// first 8 bytes of sha256(the raw 32-byte ed25519 public key), hex — enough
// to tell two keys apart in a report without printing a whole key), and the
// raw 64-byte ed25519 signature, base64-encoded. The signature covers
// MANIFEST.sha256's bytes exactly as WriteManifest produced them — not a
// digest of a digest, not the bundle directory as a whole, just the one file
// whose job is already to speak for everything else in the directory.

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// ManifestSigFile is MANIFEST.sha256's detached signature, written beside it
// by Write when a signing key was supplied. Its ABSENCE is the normal case —
// most bundles are unsigned — and Verify never requires it; only
// VerifySigned, given a public key, looks for it. See knownSchema's sibling
// discipline: this file is optional metadata, not a schema-versioned part of
// bundle.json.
const ManifestSigFile = "MANIFEST.sha256.sig"

// AlgEd25519 is the only signature algorithm this package writes or checks.
const AlgEd25519 = "ed25519"

// ManifestSignature is ManifestSigFile's JSON shape.
type ManifestSignature struct {
	// Alg names the scheme, so a verifier meeting a future one refuses it by
	// name rather than by a signature check that happens to fail.
	Alg string `json:"alg"`
	// KeyID is the first 8 bytes of sha256(the raw ed25519 public key), hex —
	// what a report can print to say WHICH key signed a bundle without
	// printing the key itself, and what a lab compares against the key id of
	// the pubkey PEM they were actually handed.
	KeyID string `json:"key_id"`
	// Sig is the raw 64-byte ed25519 signature over MANIFEST.sha256's bytes,
	// base64-encoded (standard alphabet, padded).
	Sig string `json:"sig"`
}

// KeyID computes the identifier ManifestSignature.KeyID carries for pub: the
// first 8 bytes of sha256(pub), hex. It is deliberately truncated — this is a
// label for a report, not a fingerprint an operator is expected to compare
// byte for byte; the full public key is what -pubkey actually checks the
// signature against.
func KeyID(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:8])
}

// GenerateSignKey creates a fresh ed25519 keypair and writes it into dir as
// two PEM files: sign-ed25519.key (PKCS#8, mode 0600 — the operator's signing
// key, and it belongs OUTSIDE any repository, never committed) and
// sign-ed25519.pub (PKIX public key, ordinary file mode — what a
// certification lab is actually given, so they can check a bundle's
// signature without ever holding the private half). Returns the paths
// written and the key id (see KeyID), for a caller to print once, at the
// moment of creation — the one time an operator needs to see it.
func GenerateSignKey(dir string) (privPath, pubPath, keyID string, err error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", "", "", fmt.Errorf("bundle: generate ed25519 key: %w", err)
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", "", "", fmt.Errorf("bundle: create %s: %w", dir, err)
	}
	privDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return "", "", "", fmt.Errorf("bundle: marshal private key: %w", err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", "", "", fmt.Errorf("bundle: marshal public key: %w", err)
	}
	privPath = filepath.Join(dir, "sign-ed25519.key")
	pubPath = filepath.Join(dir, "sign-ed25519.pub")
	// The private key is written 0600 BEFORE anything reads it back — an
	// operator's signing key sitting world-readable, even briefly, is a
	// finding of its own.
	if err := os.WriteFile(privPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER}), 0o600); err != nil {
		return "", "", "", fmt.Errorf("bundle: write %s: %w", privPath, err)
	}
	if err := os.WriteFile(pubPath, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}), 0o644); err != nil {
		return "", "", "", fmt.Errorf("bundle: write %s: %w", pubPath, err)
	}
	return privPath, pubPath, KeyID(pub), nil
}

// LoadSignKey reads a PKCS#8 PEM ed25519 private key, as GenerateSignKey
// writes one — the -sign-key flag's input.
func LoadSignKey(path string) (ed25519.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("bundle: read sign key %s: %w", path, err)
	}
	blk, _ := pem.Decode(data)
	if blk == nil {
		return nil, fmt.Errorf("bundle: %s is not a PEM file", path)
	}
	key, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
	if err != nil {
		return nil, fmt.Errorf("bundle: %s: not a PKCS#8 private key: %w", path, err)
	}
	priv, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("bundle: %s holds a %T key, not ed25519", path, key)
	}
	return priv, nil
}

// LoadVerifyKey reads a PKIX PEM ed25519 public key, as GenerateSignKey
// writes one — the -pubkey flag's input.
func LoadVerifyKey(path string) (ed25519.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("bundle: read public key %s: %w", path, err)
	}
	blk, _ := pem.Decode(data)
	if blk == nil {
		return nil, fmt.Errorf("bundle: %s is not a PEM file", path)
	}
	key, err := x509.ParsePKIXPublicKey(blk.Bytes)
	if err != nil {
		return nil, fmt.Errorf("bundle: %s: not a PKIX public key: %w", path, err)
	}
	pub, ok := key.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("bundle: %s holds a %T key, not ed25519", path, key)
	}
	return pub, nil
}

// signManifest signs manifestPath's exact on-disk bytes with priv and writes
// the detached signature to sigPath.
func signManifest(manifestPath, sigPath string, priv ed25519.PrivateKey) error {
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		return fmt.Errorf("bundle: read %s to sign: %w", manifestPath, err)
	}
	pub, ok := priv.Public().(ed25519.PublicKey)
	if !ok {
		return errors.New("bundle: signing key has no ed25519 public half")
	}
	sig := ed25519.Sign(priv, data)
	out := ManifestSignature{Alg: AlgEd25519, KeyID: KeyID(pub), Sig: base64.StdEncoding.EncodeToString(sig)}
	js, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return fmt.Errorf("bundle: encode %s: %w", filepath.Base(sigPath), err)
	}
	js = append(js, '\n')
	if err := os.WriteFile(sigPath, js, 0o644); err != nil {
		return fmt.Errorf("bundle: write %s: %w", sigPath, err)
	}
	return nil
}

// VerifyManifestSignature checks dir's MANIFEST.sha256.sig against
// MANIFEST.sha256's bytes ON DISK, using pub.
//
// It reads the manifest bytes itself rather than accepting a digest Verify
// already computed, deliberately: the whole point of a signature is to catch
// the case a hash re-check alone cannot — the entire bundle, manifest
// included, rewritten to agree with itself (REV0907-E4). A signature check
// that trusted an already-derived digest would be checking the rewritten
// world's own arithmetic, not the file.
func VerifyManifestSignature(dir string, pub ed25519.PublicKey) error {
	sigData, err := os.ReadFile(filepath.Join(dir, ManifestSigFile))
	if err != nil {
		return fmt.Errorf("bundle: read %s: %w", ManifestSigFile, err)
	}
	var sig ManifestSignature
	if err := json.Unmarshal(sigData, &sig); err != nil {
		return fmt.Errorf("bundle: parse %s: %w", ManifestSigFile, err)
	}
	if sig.Alg != AlgEd25519 {
		return fmt.Errorf("bundle: %s declares algorithm %q, this verifier only checks %q",
			ManifestSigFile, sig.Alg, AlgEd25519)
	}
	raw, err := base64.StdEncoding.DecodeString(sig.Sig)
	if err != nil {
		return fmt.Errorf("bundle: %s: signature is not valid base64: %w", ManifestSigFile, err)
	}
	manifestData, err := os.ReadFile(filepath.Join(dir, ManifestFile))
	if err != nil {
		return fmt.Errorf("bundle: read %s: %w", ManifestFile, err)
	}
	if !ed25519.Verify(pub, manifestData, raw) {
		return fmt.Errorf("bundle: %s does not verify against %s with the supplied public key (key_id %s "+
			"recorded in the signature): either the manifest changed since it was signed, or this is the "+
			"wrong key", ManifestSigFile, ManifestFile, sig.KeyID)
	}
	return nil
}
