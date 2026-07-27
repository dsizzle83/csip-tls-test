package tlsdecrypt

import (
	"crypto/hkdf"
	"crypto/hmac"
	"fmt"
	"hash"
)

// hkdfLabel serialises RFC 8446 §7.1's HkdfLabel structure:
//
//	struct {
//	    uint16 length;
//	    opaque label<7..255>  = "tls13 " + Label;
//	    opaque context<0..255>;
//	} HkdfLabel;
//
// It is a separate function with its own test because every TLS 1.3 key in the
// engine passes through it, and a wrong byte here fails as an AEAD
// authentication error five layers away — the "looks like a broken capture"
// failure mode this package exists to avoid.
func hkdfLabel(label string, context []byte, length int) []byte {
	full := "tls13 " + label
	out := make([]byte, 0, 2+1+len(full)+1+len(context))
	out = append(out, byte(length>>8), byte(length))
	out = append(out, byte(len(full)))
	out = append(out, full...)
	out = append(out, byte(len(context)))
	out = append(out, context...)
	return out
}

// expandLabel is HKDF-Expand-Label (RFC 8446 §7.1).
func expandLabel(h func() hash.Hash, secret []byte, label string, context []byte, length int) ([]byte, error) {
	if length < 0 || length > 255*h().Size() {
		return nil, fmt.Errorf("tlsdecrypt: cannot expand %d bytes from HKDF-Expand-Label", length)
	}
	out, err := hkdf.Expand(h, secret, string(hkdfLabel(label, context, length)), length)
	if err != nil {
		return nil, fmt.Errorf("tlsdecrypt: HKDF-Expand-Label(%q): %w", label, err)
	}
	return out, nil
}

// trafficKeys derives the record-protection key and IV from a traffic secret
// (RFC 8446 §7.3).
func trafficKeys(h func() hash.Hash, secret []byte, keyLen, ivLen int) (key, iv []byte, err error) {
	key, err = expandLabel(h, secret, "key", nil, keyLen)
	if err != nil {
		return nil, nil, err
	}
	iv, err = expandLabel(h, secret, "iv", nil, ivLen)
	if err != nil {
		return nil, nil, err
	}
	return key, iv, nil
}

// nextTrafficSecret advances a traffic secret across a KeyUpdate
// (RFC 8446 §7.2).
func nextTrafficSecret(h func() hash.Hash, secret []byte) ([]byte, error) {
	return expandLabel(h, secret, "traffic upd", nil, h().Size())
}

// prf12 is the TLS 1.2 pseudo-random function (RFC 5246 §5): P_hash over
// label||seed, with A(0) = seed and A(i) = HMAC(secret, A(i-1)).
//
// TLS 1.2 replaced TLS 1.0/1.1's MD5+SHA-1 split with a single hash chosen by
// the cipher suite — which is what makes SunSpecTCP-56/57 ("MUST NOT use
// HMAC-SHA-1 in the PRF; MUST use HMAC-SHA-256") checkable at all.
func prf12(h func() hash.Hash, secret []byte, label string, seed []byte, length int) []byte {
	full := make([]byte, 0, len(label)+len(seed))
	full = append(full, label...)
	full = append(full, seed...)

	out := make([]byte, 0, length)
	a := full
	for len(out) < length {
		mac := hmac.New(h, secret)
		mac.Write(a)
		a = mac.Sum(nil)

		mac.Reset()
		mac.Write(a)
		mac.Write(full)
		out = append(out, mac.Sum(nil)...)
	}
	return out[:length]
}

// keyBlock12 derives a TLS 1.2 AEAD key block: client key, server key, client
// IV, server IV — in that order, with no MAC keys, because AEAD suites carry
// their integrity inside the cipher (RFC 5246 §6.3, RFC 5288 §3).
func keyBlock12(p suiteParams, masterSecret, clientRandom, serverRandom []byte) (clientKey, serverKey, clientIV, serverIV []byte) {
	seed := make([]byte, 0, 64)
	seed = append(seed, serverRandom...) // server random FIRST for key expansion
	seed = append(seed, clientRandom...)

	need := 2*p.KeyLen + 2*p.FixedIVLen
	block := prf12(p.Hash, masterSecret, "key expansion", seed, need)

	off := 0
	clientKey = block[off : off+p.KeyLen]
	off += p.KeyLen
	serverKey = block[off : off+p.KeyLen]
	off += p.KeyLen
	clientIV = block[off : off+p.FixedIVLen]
	off += p.FixedIVLen
	serverIV = block[off : off+p.FixedIVLen]
	return clientKey, serverKey, clientIV, serverIV
}
