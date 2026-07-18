//go:build integration

package mbtls

// mbaps_fixtures_integration_test.go proves the COMMITTED certs/mbaps/ tree
// (T06.1) is not just structurally valid PEM/ASN.1 (mbaps_fixtures_test.go)
// but genuinely interoperates over a real wolfSSL handshake: the device
// server leaf loads into an mbtls.Listener (T06.1 acceptance: "server certs
// load into an mbtls.Listener"), every happy-path role cert completes mutual
// auth against it and has its role extracted end-to-end, and the two
// TLS/chain-level negatives (wrong-ca, expired) are rejected at the
// handshake while the five role-parse-level negatives complete the
// handshake and fail only at RoleFromDER — the same design-01-§3.1 split
// handshake_integration_test.go already pins for the package's own
// runtime-minted fixtures, reproduced here against the on-disk fixtures the
// aggregator emulator (T06.4) and ssm-conformance (T06.10) will actually
// load from disk.
//
// package mbtls (not mbtls_test): shares startServer/waitAccept/
// acceptResult and TestMain (wolfSSL_Init exactly once per test binary,
// CLAUDE.md invariant) with handshake_integration_test.go in this package.

import (
	"bytes"
	"crypto/x509"
	"encoding/asn1"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
)

// mbapsClientKeyPath swaps a manifest cert path's "-cert.pem" suffix for
// "-key.pem" — the fixed naming convention cmd/gen-mbaps-certs writes.
func mbapsClientKeyPath(certRelPath string) string {
	const suffix = "-cert.pem"
	base := certRelPath[:len(certRelPath)-len(suffix)]
	return base + "-key.pem"
}

// ── freshness guard (orphaned committed cert / gitignored key) ─────────────
//
// certs/mbaps/*-cert.pem is git-tracked; certs/mbaps/*-key.pem is gitignored
// (CLAUDE.md "Keys" invariant, repo-wide `*-key.pem` glob, "never commit,
// ever"). `make gen-mbaps-certs` mints a fresh, self-consistent tree — NEW
// keys AND new certs every run ("destructive-but-deterministic",
// certs/mbaps/README.md) — and nothing else does. Two ways the on-disk keys
// end up orphaned from the on-disk certs:
//
//   - a fresh checkout has the committed certs but NO local keys at all
//     (nobody ever ran `make gen-mbaps-certs` here); or
//   - this checkout DID run `make gen-mbaps-certs` at some point, and the
//     committed certs were since reverted/updated (a later commit, a `git
//     checkout`, a merge) without regenerating — the on-disk keys are now
//     minted for a DIFFERENT generation than the certs sitting next to them.
//
// Either way the committed cert's public key and the on-disk key's public
// key no longer match. Feed that mismatched pair into a wolfSSL handshake
// and every case in both TestMbapsFixtures_* tests below fails identically
// with a bare wolfSSL VERIFY_SIGN_ERROR (-330) — indistinguishable from a
// real protocol regression unless you already know to suspect the fixtures.
// This has already bitten once.
//
// ensureMbapsFixturesFresh compares every fixture's cert pubkey against its
// key pubkey BEFORE either test dials anything. On any mismatch/missing key
// it auto-regenerates the whole tree via the same scripts/gen-mbaps-certs.sh
// a developer would run by hand — safe, because the tree is DESIGNED to be
// destructively regenerated and certs/mbaps/README.md already documents
// local churn from that command as normal and uncommitted. If regeneration
// itself fails, or the result is somehow still inconsistent, it skips with a
// precise, actionable message instead of letting the suite run into a
// cryptic -330.
//
// Scope: only this file uses this guard. sim/mbapsdev's, internal/
// aggregator's, and sim/ssm-conformance's OWN integration tests all mint
// throwaway runtime PKI instead (see their testpki_test.go/pki_test.go doc
// comments) specifically to avoid ever depending on committed keys; only
// the two tests in this file exist to prove the COMMITTED tree itself, so
// only they need this check. Live consumers of certs/mbaps (sim/
// ssm-conformance -pki, sim/aggregator, sim/mbapsdev's default flags) are
// untouched by this guard — it only ever runs inside
// `go test -tags=integration ./internal/mbtls/...`.
var (
	mbapsFreshnessOnce sync.Once
	mbapsFreshnessSkip string // set once; non-empty => both tests t.Skip with this message
)

// ensureMbapsFixturesFresh is the guard's entry point — called first thing by
// both TestMbapsFixtures_* tests. The check (and any regen) runs at most once
// per test binary; the second caller reuses the cached result.
func ensureMbapsFixturesFresh(t *testing.T, root string) {
	t.Helper()
	mbapsFreshnessOnce.Do(func() {
		mbapsFreshnessSkip = mbapsHealFixtures(root)
	})
	if mbapsFreshnessSkip != "" {
		t.Skip(mbapsFreshnessSkip)
	}
}

// mbapsHealFixtures checks every manifest fixture's cert/key pubkey match and
// auto-regenerates the tree if any are stale or missing. Returns "" once the
// tree is fresh, or an actionable skip message if it could not be made so.
func mbapsHealFixtures(root string) string {
	m, err := loadMbapsManifestFile(root)
	if err != nil {
		return fmt.Sprintf("bench mbaps fixtures: could not read %s/manifest.json: %v — run `make gen-mbaps-certs`", root, err)
	}

	issues := mbapsStaleFixtures(root, m)
	if len(issues) == 0 {
		return ""
	}

	fmt.Fprintf(os.Stderr, "mbaps_fixtures_integration_test: stale/missing keys detected (%v) — auto-regenerating certs/mbaps/ via scripts/gen-mbaps-certs.sh (local-only churn; certs/mbaps/*-key.pem is gitignored by design, never committed)\n", issues)

	out, err := regenMbapsFixtures(root)
	if err != nil {
		return fmt.Sprintf("bench mbaps keys are stale/missing (%v) and auto-regen via scripts/gen-mbaps-certs.sh FAILED: %v\nscript output:\n%s\nFix: run `make gen-mbaps-certs` by hand, then re-run the tests.", issues, err, out)
	}

	m2, err := loadMbapsManifestFile(root)
	if err != nil {
		return fmt.Sprintf("bench mbaps auto-regen ran but manifest.json is unreadable afterwards: %v — run `make gen-mbaps-certs` by hand.", err)
	}
	if remaining := mbapsStaleFixtures(root, m2); len(remaining) > 0 {
		return fmt.Sprintf("bench mbaps keys are STILL stale/missing after auto-regen (%v) — run `make gen-mbaps-certs` by hand and check scripts/gen-mbaps-certs.sh / cmd/gen-mbaps-certs for a real bug.", remaining)
	}

	fmt.Fprintln(os.Stderr, "mbaps_fixtures_integration_test: certs/mbaps/ regenerated and self-consistent — proceeding")
	return ""
}

// mbapsStaleFixtures returns the fixture names whose committed cert's public
// key does not match its (gitignored, local-only) private key on disk —
// a missing key counts as stale. Checks the device server leaf plus every
// client and negative fixture: everything either TestMbapsFixtures_* test
// dials with.
func mbapsStaleFixtures(root string, m mbapsManifest) []string {
	var stale []string
	check := func(name, certRel, keyRel string) {
		ok, err := mbapsPubKeysMatch(filepath.Join(root, certRel), filepath.Join(root, keyRel))
		if err != nil || !ok {
			stale = append(stale, name)
		}
	}
	check("device", m.Device.Cert, m.Device.Key)
	for _, c := range m.Clients {
		check(c.Name, c.Cert, mbapsClientKeyPath(c.Cert))
	}
	for _, n := range m.Negatives {
		check(n.Name, n.Cert, mbapsClientKeyPath(n.Cert))
	}
	return stale
}

// mbapsPubKeysMatch reports whether certPath's leaf public key equals
// keyPath's public key.
func mbapsPubKeysMatch(certPath, keyPath string) (bool, error) {
	certSPKI, err := mbapsCertSPKI(certPath)
	if err != nil {
		return false, fmt.Errorf("cert %s: %w", certPath, err)
	}
	keySPKI, err := mbapsKeySPKI(keyPath)
	if err != nil {
		return false, fmt.Errorf("key %s: %w", keyPath, err)
	}
	return bytes.Equal(certSPKI, keySPKI), nil
}

// mbapsCertSPKI reads a PEM chain file's leaf (first block) and returns the
// raw DER of its SubjectPublicKeyInfo. It reaches SPKI via the same
// tolerant, duplicate-extension-safe ASN.1 walk role.go's certExtensions
// uses (certificateDER/tbsCertificateDER), NOT crypto/x509.ParseCertificate:
// the standard parser hard-fails on the two-role negative fixture's
// duplicate role extension before ever reaching the public key (see
// certExtensions's doc comment in role.go) — this freshness guard checks
// that fixture too, so it cannot depend on a parser that rejects it outright
// for an unrelated reason.
func mbapsCertSPKI(certPath string) ([]byte, error) {
	b, err := os.ReadFile(certPath)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(b)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found")
	}
	var cert certificateDER
	if _, err := asn1.Unmarshal(block.Bytes, &cert); err != nil {
		return nil, fmt.Errorf("parse certificate: %w", err)
	}
	return cert.TBS.PublicKey.FullBytes, nil
}

// mbapsKeySPKI reads an EC private key PEM file (x509.MarshalECPrivateKey /
// "EC PRIVATE KEY", cmd/gen-mbaps-certs's writeKeyPEM) and returns the DER of
// its public key in the same SubjectPublicKeyInfo shape mbapsCertSPKI
// returns, so the two are directly byte-comparable.
func mbapsKeySPKI(keyPath string) ([]byte, error) {
	b, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(b)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found")
	}
	key, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse EC private key: %w", err)
	}
	return x509.MarshalPKIXPublicKey(&key.PublicKey)
}

// regenMbapsFixtures shells out to the same scripts/gen-mbaps-certs.sh a
// developer would run by hand (`make gen-mbaps-certs`). root is
// ".../certs/mbaps" relative to this package's directory (go test's CWD is
// always the package dir); the script resolves its own repo root from its
// own argv[0], so passing it an absolute path keeps that resolution correct
// regardless of the caller's CWD.
func regenMbapsFixtures(root string) (string, error) {
	repoRoot, err := filepath.Abs(filepath.Join(root, "..", ".."))
	if err != nil {
		return "", err
	}
	script := filepath.Join(repoRoot, "scripts", "gen-mbaps-certs.sh")
	cmd := exec.Command("bash", script)
	cmd.Dir = repoRoot
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// loadMbapsManifestFile is loadMbapsManifest (mbaps_fixtures_test.go) without
// the *testing.T — the freshness guard runs inside a sync.Once closure that
// has no test handle to Fatalf on, so read/parse failures must return as
// plain errors instead.
func loadMbapsManifestFile(root string) (mbapsManifest, error) {
	b, err := os.ReadFile(filepath.Join(root, "manifest.json"))
	if err != nil {
		return mbapsManifest{}, err
	}
	var m mbapsManifest
	if err := json.Unmarshal(b, &m); err != nil {
		return mbapsManifest{}, err
	}
	return m, nil
}

// mbapsDeviceListener stands up an mbtls.Listener using the COMMITTED device
// server leaf + its trust anchor exactly as sim/mbapsdev's default flags
// would load them (-ca certs/mbaps/dev-ca.pem -cert
// certs/mbaps/dev-server-cert.pem -key certs/mbaps/dev-server-key.pem),
// proving those on-disk files are handshake-ready, not just parseable.
func mbapsDeviceListener(t *testing.T, root string, m mbapsManifest) (addr string, results <-chan acceptResult) {
	t.Helper()
	profile := DefaultServerProfile(
		filepath.Join(root, m.Device.CA),
		filepath.Join(root, m.Device.Cert),
		filepath.Join(root, m.Device.Key),
	)
	return startServer(t, profile)
}

// TestMbapsFixtures_DeviceListener_AllRoles proves every committed happy-path
// role cert dials the committed device listener successfully and the server
// extracts the expected role — the full T06.1 tree exercised over a real
// mTLS handshake, not just parsed in isolation.
func TestMbapsFixtures_DeviceListener_AllRoles(t *testing.T) {
	root := mbapsFixtureRoot(t)
	ensureMbapsFixturesFresh(t, root)
	m := loadMbapsManifest(t, root)
	addr, results := mbapsDeviceListener(t, root, m)

	for _, f := range m.Clients {
		t.Run(f.Name, func(t *testing.T) {
			clientProfile := DefaultClientProfile(
				filepath.Join(root, m.Device.CA),
				filepath.Join(root, f.Cert),
				filepath.Join(root, mbapsClientKeyPath(f.Cert)),
			)
			cs, err := Dial(addr, clientProfile)
			if err != nil {
				t.Fatalf("Dial as %s: %v", f.Name, err)
			}
			defer cs.Close()

			ss, err := waitAccept(t, results)
			if err != nil {
				t.Fatalf("server Accept: %v", err)
			}
			defer ss.Close()

			got, err := ss.Role()
			if err != nil {
				t.Fatalf("server RoleFromDER: %v", err)
			}
			if got != f.ExpectRole {
				t.Errorf("extracted role %q, want %q", got, f.ExpectRole)
			}
		})
	}
}

// TestMbapsFixtures_NegativeHandshakes drives every committed negative
// fixture against the committed device listener and asserts the
// design-01-§3.1 split: wrong-ca and expired fail the handshake itself
// (chain_valid=false in the manifest); the five role-parse negatives
// (no-role, two-role, bad-encoding, empty-role, oversize-role) complete the
// handshake — the TLS session comes up — and fail only when the server asks
// RoleFromDER for the role.
//
// The chain_valid=false cases pin MaxTLS=TLS12 on both peers, mirroring
// TestHandshake_WrongCA_Rejected/TestHandshake_NoClientCert_Rejected in
// handshake_integration_test.go: under TLS 1.3 a rejected client cert
// surfaces post-handshake (analogous to ruling C12's no-cert case), so
// Dial/Accept themselves would report success and the rejection would only
// show up on a subsequent read — TLS 1.2 surfaces it during the handshake,
// which is what this test asserts on. This is a test-harness detail, not a
// gap in mbtls's TLS 1.3 enforcement (unchanged from the existing pattern).
func TestMbapsFixtures_NegativeHandshakes(t *testing.T) {
	root := mbapsFixtureRoot(t)
	ensureMbapsFixturesFresh(t, root)
	m := loadMbapsManifest(t, root)

	for _, f := range m.Negatives {
		f := f
		t.Run(f.Name, func(t *testing.T) {
			serverProfile := DefaultServerProfile(
				filepath.Join(root, m.Device.CA),
				filepath.Join(root, m.Device.Cert),
				filepath.Join(root, m.Device.Key),
			)
			clientProfile := DefaultClientProfile(
				filepath.Join(root, m.Device.CA),
				filepath.Join(root, f.Cert),
				filepath.Join(root, mbapsClientKeyPath(f.Cert)),
			)
			if !f.ChainValid {
				serverProfile.MaxTLS = TLS12
				clientProfile.MaxTLS = TLS12
			}
			addr, results := startServer(t, serverProfile)
			cs, dialErr := Dial(addr, clientProfile)

			if !f.ChainValid {
				// wrong-ca / expired: the handshake itself must be rejected —
				// no Session on either side, no application bytes ever flow.
				if dialErr == nil {
					cs.Close()
					t.Fatalf("Dial with %s cert succeeded, want handshake rejection (chain_valid=false)", f.Name)
				}
				ss, aerr := waitAccept(t, results)
				if aerr == nil {
					ss.Close()
					t.Fatalf("server Accept succeeded for %s cert, want rejection", f.Name)
				}
				return
			}

			// Role-parse negatives: handshake succeeds (session up); the
			// role error surfaces only when RoleFromDER runs.
			if dialErr != nil {
				t.Fatalf("Dial with %s cert failed, want handshake success (role errors are AuthZ-layer, not handshake-layer): %v", f.Name, dialErr)
			}
			defer cs.Close()
			ss, err := waitAccept(t, results)
			if err != nil {
				t.Fatalf("server Accept: %v", err)
			}
			defer ss.Close()

			wantErr := mbapsRoleErrByName[f.ExpectRoleErr]
			role, rerr := ss.Role()
			if wantErr != nil {
				if !errors.Is(rerr, wantErr) {
					t.Errorf("RoleFromDER err = %v, want errors.Is(%v)", rerr, wantErr)
				}
				return
			}
			if rerr != nil {
				t.Fatalf("unexpected RoleFromDER error: %v", rerr)
			}
			if role != f.ExpectRole {
				t.Errorf("extracted role %q, want %q", role, f.ExpectRole)
			}
		})
	}
}
