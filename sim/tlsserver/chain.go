package tlsserver

// chain.go is the runtime certificate-chain lever: the ability to change which
// chain and key this server presents to NEW connections, without restarting the
// process and without disturbing connections already open.
//
// # Why it has to exist at all
//
// Four CSIP conformance rows — COMM-004 D, E, F and G — ask whether the DUT
// REJECTS a non-conformant server chain (a MICA with a critical
// extendedKeyUsage carrying an invalid value, a non-critical name extension, a
// non-critical policyMapping, or a self-signed device certificate). A test that
// asks that question has to PRESENT such a chain. Until now the bench's 2030.5
// server took its chain from sim/server's start-up flags and offered no way to
// change it, so the only way to present a fixture was to restart the process —
// which invalidates the evidence of every test case already run against the
// running instance, because the peer that produced those frames is no longer
// the peer the bundle claims. Those four rows therefore SKIPped.
//
// # What "atomic" means here, precisely
//
// A wolfSSL WOLFSSL_CTX is where the certificate, the key and the verify
// locations live, and a WOLFSSL session takes its credential from the CTX it
// was created from. So a swap does NOT mutate the live CTX — mutating it under
// a handshake in flight is how a fixture becomes a crash. It builds a SECOND,
// fully configured CTX and flips one pointer. Every connection accepted after
// the flip is created from the new CTX; every connection accepted before it
// keeps the CTX it was born with, for as long as it lives.
//
// That leaves exactly one question: when is it safe to free the CTX nobody is
// installing any more? A live connection still holds sessions derived from it.
// This file answers it with an explicit reference count rather than relying on
// wolfSSL's internal CTX refcounting, because the lifetime rule then lives in
// the same file as the swap that creates it and can be read in one sitting:
//
//	installed         →  +1, dropped when the credential is superseded
//	each connection   →  +1 at accept, -1 when handleConn returns
//	count reaches 0   →  wolfSSL_CTX_free, exactly once
//
// # The key log
//
// wolfssl.EnableCtxKeylog registers the secret-export callback ON THE CTX, so a
// new CTX starts with NO export and its sessions would be captured as
// undecryptable ciphertext — a hole in the evidence exactly where the
// interesting handshake is. newCredential therefore calls it on every CTX it
// builds, on the same line as the rest of the CTX configuration, so the two can
// never be separated. (EnableTLS13Keylog is per-SESSION and is already armed in
// handleConn, so it needs nothing here.)

import (
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"csip-tls-test/internal/wolfssl"
)

// ChainInfo names the certificate chain a server is presenting. It is what
// GET /admin/chain reports and what a conformance check compares against the
// leaf it actually saw on the wire.
type ChainInfo struct {
	// Label is the operator-supplied name of the installed chain, or
	// "startup" for the one the process was launched with.
	Label string
	// LeafSHA256 is the hex SHA-256 of the leaf certificate's DER. This is the
	// field that settles "was my fixture the chain on the wire?" — the harness
	// hashes the Certificate message's first entry and compares.
	LeafSHA256 string
	// ChainLen is the number of certificates in the presented chain.
	ChainLen int
	// Subjects are the certificates' subject DNs, leaf first, for a human
	// reading a report.
	Subjects []string
	// Issuers are the corresponding issuer DNs, leaf first. The LAST entry is
	// the DN of the trust anchor the chain expects the peer to hold, which is
	// how a check can tell whether its fixture is anchored where the bench's
	// normal chain is anchored.
	Issuers []string
	// CertPath and KeyPath are where the material was loaded from.
	CertPath, KeyPath string
	// Original reports whether this is the chain the process started with.
	Original bool
	// Warnings records anything about the material that could not be checked,
	// most often a leaf whose deliberate malformation defeats a strict parser.
	// It is reported rather than fatal: refusing would make the lever unable to
	// serve the fixtures it exists for. Empty on a clean load.
	Warnings []string
	// InstalledUnix is when this chain became the one served.
	InstalledUnix int64
	// Swaps counts how many times SwapChain has been applied since start-up,
	// so a bundle can record that the bench was driven and how often.
	Swaps int
}

// credential is one loaded chain: a configured wolfSSL CTX plus the facts about
// it, reference-counted so it outlives the swap that retired it for exactly as
// long as a connection is still using it.
type credential struct {
	ctx  unsafe.Pointer
	info ChainInfo
	// refs is 1 while installed, plus 1 per live connection. See the file
	// comment for the whole lifetime rule.
	refs atomic.Int32
}

func (c *credential) acquire() { c.refs.Add(1) }

// release drops one reference and frees the CTX when the last one goes.
func (c *credential) release() {
	if c.refs.Add(-1) == 0 {
		wolfssl.FreeCtx(c.ctx)
		c.ctx = nil
	}
}

// newCredential builds and fully configures a CTX for one chain + key.
//
// Everything New() used to do inline lives here, so a swapped-in credential is
// configured identically to the one the process started with — same cipher
// list, same client-certificate requirement, same ticket policy, same key-log
// export. A swap that quietly dropped one of those would change the DUT's
// observed environment in a way no test case declared.
func newCredential(cfg Config, certPath, chainPath, keyPath string) (unsafe.Pointer, error) {
	ctx, err := wolfssl.NewServerCtx()
	if err != nil {
		return nil, err
	}
	ok := false
	defer func() {
		if !ok {
			wolfssl.FreeCtx(ctx)
		}
	}()

	if err := wolfssl.SetCipherList(ctx, cfg.CipherList); err != nil {
		return nil, err
	}
	// Chain file (leaf + intermediates) takes precedence when configured, so
	// the server can present a depth-3/4 chain; otherwise load the single leaf.
	if chainPath != "" {
		if err := wolfssl.UseCertChainFile(ctx, chainPath); err != nil {
			return nil, err
		}
	} else if err := wolfssl.UseCertFile(ctx, certPath); err != nil {
		return nil, err
	}
	if err := wolfssl.UseKeyFile(ctx, keyPath); err != nil {
		return nil, err
	}
	// The verify locations are NOT part of a swap. They decide which CA this
	// server accepts the DUT's OWN certificate under, and changing that would
	// stop the DUT authenticating for a reason that has nothing to do with the
	// chain under test — a rejection the check would then misattribute.
	if err := wolfssl.LoadVerifyLocations(ctx, cfg.CACertPath); err != nil {
		return nil, err
	}
	wolfssl.RequireClientCert(ctx)

	if cfg.NoSessionTickets {
		if err := wolfssl.SetNoTicketTLS12(ctx); err != nil {
			return nil, err
		}
		wolfssl.SetSessionCacheOff(ctx)
	}

	// See the file comment: CTX-level, so it MUST be re-registered per CTX.
	wolfssl.EnableCtxKeylog(ctx)

	ok = true
	return ctx, nil
}

// describeChain reads a PEM certificate file and reports what is in it.
//
// The fingerprint is taken from the DER bytes directly, never from a parsed
// structure, so it is available for every certificate a PEM file can hold. The
// subject and issuer DNs go through crypto/x509 and are BEST EFFORT: a fixture
// whose whole purpose is a deliberately malformed extension may not parse, and
// refusing to serve it would make the lever unable to present exactly the
// chains it exists to present. An unparsed certificate is named as such and its
// fingerprint still identifies it on the wire, which is what the criteria
// actually match on.
func describeChain(path string) (ChainInfo, []byte, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return ChainInfo{}, nil, fmt.Errorf("tlsserver: read %s: %w", path, err)
	}
	var info ChainInfo
	var leafDER []byte
	rest := raw
	for {
		var blk *pem.Block
		blk, rest = pem.Decode(rest)
		if blk == nil {
			break
		}
		if blk.Type != "CERTIFICATE" {
			continue
		}
		if info.ChainLen == 0 {
			leafDER = blk.Bytes
			sum := sha256.Sum256(blk.Bytes)
			info.LeafSHA256 = hex.EncodeToString(sum[:])
		}
		info.ChainLen++
		subj, iss := certNames(blk.Bytes)
		info.Subjects = append(info.Subjects, subj)
		info.Issuers = append(info.Issuers, iss)
	}
	if info.ChainLen == 0 {
		return ChainInfo{}, nil, fmt.Errorf("tlsserver: %s holds no CERTIFICATE PEM block", path)
	}
	return info, leafDER, nil
}

// checkKeyPair verifies that the private key in keyPath belongs to the leaf
// certificate, and returns a warning when it could not be checked.
//
// It exists because wolfSSL does NOT check. wolfSSL_CTX_use_PrivateKey_file
// accepts a key that has nothing to do with the loaded certificate and reports
// success; the mismatch surfaces later, as every handshake failing. On a
// conformance bench that is the worst possible failure mode: the lever reports
// the fixture installed, the DUT then fails to connect for a reason that has
// nothing to do with the fixture's defect, and the check credits the DUT with a
// rejection it never made. Measured against wolfSSL on 2026-07-28, which is why
// this function is here rather than trusted to the loader.
//
// A leaf that does not PARSE is a warning, not an error. Some of the fixtures
// this lever exists to serve are deliberately malformed, and a strict parser
// refusing them is the fixture working as intended — the private key is still
// loaded, the handshake will still be attempted, and the fingerprint still
// identifies the chain on the wire.
func checkKeyPair(leafDER []byte, keyPath string) (warning string, err error) {
	raw, err := os.ReadFile(keyPath)
	if err != nil {
		return "", fmt.Errorf("tlsserver: read key %s: %w", keyPath, err)
	}
	signer, err := parsePrivateKeyPEM(raw)
	if err != nil {
		return "", fmt.Errorf("tlsserver: %s: %w", keyPath, err)
	}
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		return fmt.Sprintf("the leaf certificate does not parse (%v), so its public key could not be "+
			"checked against %s; if this is a deliberately malformed fixture that is expected, and the "+
			"chain is still identified on the wire by its SHA-256", err, keyPath), nil
	}
	pub, ok := leaf.PublicKey.(interface{ Equal(crypto.PublicKey) bool })
	if !ok {
		return fmt.Sprintf("the leaf's %T public key cannot be compared, so the key pair was not verified",
			leaf.PublicKey), nil
	}
	if !pub.Equal(signer.Public()) {
		return "", fmt.Errorf("tlsserver: the private key in %s does not belong to the leaf certificate "+
			"(subject %s) — wolfSSL would load this pair happily and then fail every handshake, which a "+
			"conformance run would misread as the peer rejecting the chain", keyPath, leaf.Subject)
	}
	return "", nil
}

// parsePrivateKeyPEM decodes the first private-key block in a PEM file, in any
// of the three encodings the bench's tooling emits.
func parsePrivateKeyPEM(raw []byte) (crypto.Signer, error) {
	rest := raw
	for {
		var blk *pem.Block
		blk, rest = pem.Decode(rest)
		if blk == nil {
			return nil, fmt.Errorf("no private key PEM block found")
		}
		if !strings.Contains(blk.Type, "PRIVATE KEY") {
			continue
		}
		for _, parse := range []func([]byte) (any, error){
			func(b []byte) (any, error) { return x509.ParsePKCS8PrivateKey(b) },
			func(b []byte) (any, error) { return x509.ParseECPrivateKey(b) },
			func(b []byte) (any, error) { return x509.ParsePKCS1PrivateKey(b) },
		} {
			k, err := parse(blk.Bytes)
			if err != nil {
				continue
			}
			if s, ok := k.(crypto.Signer); ok {
				return s, nil
			}
		}
		return nil, fmt.Errorf("private key does not parse as PKCS#8, SEC1 or PKCS#1")
	}
}

// ── Server surface ───────────────────────────────────────────────────────────

// chainState is the Server's mutable half of this file, kept in one struct so
// the mutex protects an obvious set of fields.
type chainState struct {
	mu   sync.Mutex
	cur  *credential
	orig ChainInfo
	// origLoader records whether the START-UP chain was loaded with wolfSSL's
	// multi-certificate loader (-cert-chain) or the single-leaf one (-cert).
	// RestoreChain replays that choice rather than re-deriving it from the
	// file, so a restore puts the process back exactly where it started even
	// when the operator passed a one-certificate file to -cert-chain.
	origLoader bool
	swaps      int
}

// ActiveChain reports the chain new connections are currently being offered.
func (s *Server) ActiveChain() ChainInfo {
	s.chain.mu.Lock()
	defer s.chain.mu.Unlock()
	if s.chain.cur == nil {
		return ChainInfo{}
	}
	info := s.chain.cur.info
	info.Swaps = s.chain.swaps
	return info
}

// OriginalChain reports the chain the process was launched with, whether or not
// it is the one currently installed. RestoreChain returns to exactly this.
func (s *Server) OriginalChain() ChainInfo {
	s.chain.mu.Lock()
	defer s.chain.mu.Unlock()
	info := s.chain.orig
	info.Swaps = s.chain.swaps
	return info
}

// SwapChain installs certPath (a PEM file holding the leaf first, then any
// intermediates, excluding the trust anchor) and keyPath as the credential this
// server presents to NEW connections. label names the chain in reports.
//
// Connections already established are UNAFFECTED and keep serving under the
// chain they handshook with: their wolfSSL sessions were created from the old
// CTX and that CTX stays alive until the last of them closes. That is a
// property a conformance check depends on rather than merely tolerates — the
// harness itself may be holding an admin connection, and a swap that killed
// live sessions would be indistinguishable, in the capture, from the DUT
// rejecting the new chain.
//
// The whole credential is built and validated BEFORE anything is installed, so
// a bad fixture (unreadable file, key that does not match the leaf) leaves the
// server serving what it was serving and returns an error the caller can
// report. There is no window in which the listener has no credential.
func (s *Server) SwapChain(label, certPath, keyPath string) (ChainInfo, error) {
	if label == "" {
		return ChainInfo{}, fmt.Errorf("tlsserver: SwapChain needs a label naming the chain")
	}
	// A swapped-in fixture is loaded through the multi-certificate loader
	// whenever it holds more than one certificate, which is what the D/E/F
	// SERCA→MICA→leaf fixtures need; a lone self-signed leaf (G) goes through
	// the single-certificate loader.
	info, _, err := describeChain(certPath)
	if err != nil {
		return ChainInfo{}, err
	}
	return s.installChain(label, certPath, keyPath, false, info.ChainLen > 1)
}

// RestoreChain reinstalls the chain the process started with.
//
// It rebuilds the credential from the original files rather than retaining the
// start-up CTX, so a restore works identically however many swaps preceded it
// and cannot be defeated by the start-up CTX having been freed. Callers should
// treat a non-nil error here as serious: a bench left presenting a fixture
// chain fails every conformance case that follows it.
func (s *Server) RestoreChain() (ChainInfo, error) {
	s.chain.mu.Lock()
	orig, loader := s.chain.orig, s.chain.origLoader
	s.chain.mu.Unlock()
	if orig.CertPath == "" {
		return ChainInfo{}, fmt.Errorf("tlsserver: no original chain recorded to restore")
	}
	return s.installChain(orig.Label, orig.CertPath, orig.KeyPath, true, loader)
}

// installChain is the shared install path for New, SwapChain and RestoreChain.
func (s *Server) installChain(label, certPath, keyPath string, original, chainLoader bool) (ChainInfo, error) {
	info, leafDER, err := describeChain(certPath)
	if err != nil {
		return ChainInfo{}, err
	}
	// Verify the pair BEFORE building anything. See checkKeyPair for what
	// wolfSSL will otherwise let through.
	warn, err := checkKeyPair(leafDER, keyPath)
	if err != nil {
		return ChainInfo{}, err
	}
	if warn != "" {
		info.Warnings = append(info.Warnings, warn)
	}

	chainPath, leafPath := certPath, ""
	if !chainLoader {
		chainPath, leafPath = "", certPath
	}
	ctx, err := newCredential(s.cfg, leafPath, chainPath, keyPath)
	if err != nil {
		return ChainInfo{}, fmt.Errorf("tlsserver: load chain %q from %s: %w", label, certPath, err)
	}

	info.Label = label
	info.CertPath, info.KeyPath = certPath, keyPath
	info.Original = original
	info.InstalledUnix = time.Now().Unix()

	cred := &credential{ctx: ctx, info: info}
	cred.refs.Store(1) // the installed reference

	s.chain.mu.Lock()
	old := s.chain.cur
	s.chain.cur = cred
	if !original {
		s.chain.swaps++
	}
	info.Swaps = s.chain.swaps
	s.chain.cur.info.Swaps = s.chain.swaps
	s.chain.mu.Unlock()

	// Drop the installed reference on the credential we just replaced. It is
	// freed here only if no connection is using it; otherwise the last
	// connection to close frees it.
	if old != nil {
		old.release()
	}
	return info, nil
}

// acquireCredential takes a reference on the currently installed credential.
// The caller MUST release it. Returns nil when the server has been closed.
func (s *Server) acquireCredential() *credential {
	s.chain.mu.Lock()
	defer s.chain.mu.Unlock()
	if s.chain.cur == nil {
		return nil
	}
	s.chain.cur.acquire()
	return s.chain.cur
}

// certNames returns a certificate's subject and issuer DNs, best effort.
func certNames(der []byte) (subject, issuer string) {
	c, err := x509.ParseCertificate(der)
	if err != nil {
		return "(unparsed certificate)", "(unparsed certificate)"
	}
	return c.Subject.String(), c.Issuer.String()
}
