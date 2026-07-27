package tlsdecrypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"hash"
	"strings"

	"csip-tls-test/internal/evidence/aead"
	"csip-tls-test/internal/evidence/tlsdis"
)

// suiteParams is everything the record layer needs to know about a cipher
// suite: how big its key and nonce are, how the nonce is built, how long the
// tag is, and which hash drives its key schedule.
type suiteParams struct {
	Name string
	// KeyLen is the AEAD key size in bytes.
	KeyLen int
	// FixedIVLen is the implicit IV: 4 bytes of salt for the TLS 1.2 GCM/CCM
	// suites, 12 for TLS 1.3 and for TLS 1.2 ChaCha20-Poly1305.
	FixedIVLen int
	// RecordIVLen is the explicit per-record nonce carried in the record
	// itself: 8 bytes for TLS 1.2 GCM/CCM, 0 everywhere else.
	RecordIVLen int
	TagLen      int
	// Hash drives the TLS 1.2 PRF and the TLS 1.3 HKDF.
	Hash func() hash.Hash
	// New builds the AEAD for a key.
	New func(key []byte) (cipher.AEAD, error)
}

// tls13Suites is an explicit table, because TLS 1.3 has exactly five suites and
// their parameters do not follow from their names in the same regular way the
// TLS 1.2 registry's do.
var tls13Suites = map[uint16]suiteParams{
	0x1301: {Name: "TLS_AES_128_GCM_SHA256", KeyLen: 16, FixedIVLen: 12, TagLen: 16, Hash: sha256.New, New: newGCM(16)},
	0x1302: {Name: "TLS_AES_256_GCM_SHA384", KeyLen: 32, FixedIVLen: 12, TagLen: 16, Hash: sha512.New384, New: newGCM(16)},
	0x1303: {Name: "TLS_CHACHA20_POLY1305_SHA256", KeyLen: 32, FixedIVLen: 12, TagLen: 16, Hash: sha256.New, New: aead.NewChaCha20Poly1305},
	0x1304: {Name: "TLS_AES_128_CCM_SHA256", KeyLen: 16, FixedIVLen: 12, TagLen: 16, Hash: sha256.New, New: newCCM(12, 16)},
	0x1305: {Name: "TLS_AES_128_CCM_8_SHA256", KeyLen: 16, FixedIVLen: 12, TagLen: 8, Hash: sha256.New, New: newCCM(12, 8)},
}

func newGCM(tagLen int) func([]byte) (cipher.AEAD, error) {
	return func(key []byte) (cipher.AEAD, error) {
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, err
		}
		return cipher.NewGCMWithTagSize(block, tagLen)
	}
}

func newCCM(nonceLen, tagLen int) func([]byte) (cipher.AEAD, error) {
	return func(key []byte) (cipher.AEAD, error) {
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, err
		}
		return aead.NewCCM(block, nonceLen, tagLen)
	}
}

// suiteFor resolves a suite's record-layer parameters.
//
// For TLS 1.2 the parameters are derived from the IANA registry NAME rather
// than from a second hand-maintained table. That is deliberate: the registry
// names are machine-regular (AES_128 / AES_256 / GCM / CCM / CCM_8 /
// CHACHA20_POLY1305 / SHA384), tlsdis already carries the complete registry,
// and a derived table cannot drift out of step with the names a report prints.
// The alternative — transcribing forty-odd suites' key sizes by hand — is
// exactly the kind of table that develops a wrong entry nobody notices until a
// device negotiates that one suite. Every derivation is pinned by tests.
//
// Non-AEAD suites (CBC, RC4, NULL) are refused rather than half-supported: they
// are forbidden by the specifications this bench certifies against, and a
// decryptor that quietly produced nothing for them would look like a capture
// problem instead of a conformance finding.
func suiteFor(version, id uint16) (suiteParams, error) {
	if version == tlsdis.VersionTLS13 {
		p, ok := tls13Suites[id]
		if !ok {
			return suiteParams{}, fmt.Errorf("tlsdecrypt: %s is not a TLS 1.3 cipher suite", tlsdis.CipherSuiteName(id))
		}
		return p, nil
	}
	if version != tlsdis.VersionTLS12 {
		return suiteParams{}, fmt.Errorf("tlsdecrypt: %s records cannot be decrypted (only TLS 1.2 and TLS 1.3 use AEAD suites)",
			tlsdis.VersionName(version))
	}

	name := tlsdis.CipherSuiteName(id)
	if !tlsdis.KnownCipherSuite(id) {
		return suiteParams{}, fmt.Errorf("tlsdecrypt: cipher suite 0x%04X is not in the IANA registry", id)
	}

	p := suiteParams{Name: name, Hash: sha256.New}
	if strings.HasSuffix(name, "SHA384") {
		p.Hash = sha512.New384
	}

	switch {
	case strings.Contains(name, "_AES_128_"):
		p.KeyLen = 16
	case strings.Contains(name, "_AES_256_"):
		p.KeyLen = 32
	case strings.Contains(name, "_CHACHA20_POLY1305"):
		p.KeyLen = 32
	default:
		return suiteParams{}, fmt.Errorf("tlsdecrypt: %s is not an AEAD suite this engine can decrypt", name)
	}

	switch {
	case strings.Contains(name, "_CHACHA20_POLY1305"):
		// RFC 7905: no explicit nonce; the 12-byte IV is XORed with the
		// sequence number, exactly as in TLS 1.3.
		p.FixedIVLen, p.RecordIVLen, p.TagLen = 12, 0, 16
		p.New = aead.NewChaCha20Poly1305
	case strings.Contains(name, "_GCM"):
		p.FixedIVLen, p.RecordIVLen, p.TagLen = 4, 8, 16
		p.New = newGCM(16)
	case strings.Contains(name, "_CCM_8"):
		p.FixedIVLen, p.RecordIVLen, p.TagLen = 4, 8, 8
		p.New = newCCM(12, 8)
	case strings.Contains(name, "_CCM"):
		p.FixedIVLen, p.RecordIVLen, p.TagLen = 4, 8, 16
		p.New = newCCM(12, 16)
	default:
		return suiteParams{}, fmt.Errorf("tlsdecrypt: %s is not an AEAD suite this engine can decrypt", name)
	}
	return p, nil
}
