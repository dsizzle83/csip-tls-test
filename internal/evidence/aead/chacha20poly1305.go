package aead

import (
	"crypto/cipher"
	"crypto/subtle"
	"encoding/binary"
	"fmt"
	"math/big"
)

// ChaCha20-Poly1305 (RFC 8439), implemented here rather than imported.
//
// # Why not golang.org/x/crypto/chacha20poly1305
//
// The evidence engine is standard-library-only by construction: it must build
// with CGO_ENABLED=0 from a repository that vendors strictly, and a verifier a
// certification body runs should need nothing but a Go toolchain. x/crypto is
// present in this repo's module graph but its chacha20poly1305 package is not
// vendored, and adding it would put a dependency between an evidence claim and
// a module that can be revised out from under the archive.
//
// # Why math/big for Poly1305
//
// Poly1305 is arithmetic modulo 2^130-5. Every fast implementation carries that
// value in 26-bit or 44-bit limbs with hand-rolled carry propagation, which is
// where Poly1305 bugs live. This one uses math/big: the field arithmetic is
// then a direct transcription of RFC 8439 §2.5 and can be audited by reading
// it. The cost is speed, and speed is irrelevant here — this code decrypts a
// capture file once, offline, with keys the operator already holds. There is no
// secret-dependent timing surface worth defending: the key came out of an NSS
// key log sitting in the same directory.

const (
	chachaKeySize   = 32
	chachaNonceSize = 12
	poly1305TagSize = 16
)

// polyP is 2^130 - 5.
var polyP = new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 130), big.NewInt(5))

// poly1305Clamp masks r as RFC 8439 §2.5 requires.
var poly1305Clamp = [16]byte{
	0xFF, 0xFF, 0xFF, 0x0F, 0xFC, 0xFF, 0xFF, 0x0F,
	0xFC, 0xFF, 0xFF, 0x0F, 0xFC, 0xFF, 0xFF, 0x0F,
}

type chacha20poly1305 struct {
	key [chachaKeySize]byte
}

// NewChaCha20Poly1305 returns the RFC 8439 AEAD for a 32-byte key.
func NewChaCha20Poly1305(key []byte) (cipher.AEAD, error) {
	if len(key) != chachaKeySize {
		return nil, fmt.Errorf("aead: ChaCha20-Poly1305 key is %d bytes, want %d", len(key), chachaKeySize)
	}
	c := &chacha20poly1305{}
	copy(c.key[:], key)
	return c, nil
}

func (c *chacha20poly1305) NonceSize() int { return chachaNonceSize }
func (c *chacha20poly1305) Overhead() int  { return poly1305TagSize }

func (c *chacha20poly1305) Seal(dst, nonce, plaintext, additionalData []byte) []byte {
	if len(nonce) != chachaNonceSize {
		panic("aead: incorrect ChaCha20-Poly1305 nonce length")
	}
	ret, out := sliceForAppend(dst, len(plaintext)+poly1305TagSize)
	chacha20XOR(out[:len(plaintext)], plaintext, &c.key, nonce, 1)
	tag := poly1305Tag(c.oneTimeKey(nonce), additionalData, out[:len(plaintext)])
	copy(out[len(plaintext):], tag[:])
	return ret
}

func (c *chacha20poly1305) Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	if len(nonce) != chachaNonceSize {
		return nil, fmt.Errorf("aead: ChaCha20-Poly1305 nonce is %d bytes, want %d", len(nonce), chachaNonceSize)
	}
	if len(ciphertext) < poly1305TagSize {
		return nil, fmt.Errorf("aead: ChaCha20-Poly1305 ciphertext is %d bytes, shorter than the 16-byte tag: %w",
			len(ciphertext), ErrOpen)
	}
	body := ciphertext[:len(ciphertext)-poly1305TagSize]
	wantTag := ciphertext[len(ciphertext)-poly1305TagSize:]

	tag := poly1305Tag(c.oneTimeKey(nonce), additionalData, body)
	if subtle.ConstantTimeCompare(tag[:], wantTag) != 1 {
		return nil, ErrOpen
	}
	ret, out := sliceForAppend(dst, len(body))
	chacha20XOR(out, body, &c.key, nonce, 1)
	return ret, nil
}

// oneTimeKey derives the per-message Poly1305 key from ChaCha20 block 0
// (RFC 8439 §2.6).
func (c *chacha20poly1305) oneTimeKey(nonce []byte) [32]byte {
	var block [64]byte
	chacha20Block(&block, &c.key, nonce, 0)
	var k [32]byte
	copy(k[:], block[:32])
	return k
}

// chacha20Block produces one 64-byte keystream block.
func chacha20Block(out *[64]byte, key *[32]byte, nonce []byte, counter uint32) {
	var s [16]uint32
	// "expand 32-byte k"
	s[0], s[1], s[2], s[3] = 0x61707865, 0x3320646e, 0x79622d32, 0x6b206574
	for i := 0; i < 8; i++ {
		s[4+i] = binary.LittleEndian.Uint32(key[i*4 : i*4+4])
	}
	s[12] = counter
	s[13] = binary.LittleEndian.Uint32(nonce[0:4])
	s[14] = binary.LittleEndian.Uint32(nonce[4:8])
	s[15] = binary.LittleEndian.Uint32(nonce[8:12])

	x := s
	for i := 0; i < 10; i++ { // 20 rounds = 10 column+diagonal double rounds
		quarterRound(&x, 0, 4, 8, 12)
		quarterRound(&x, 1, 5, 9, 13)
		quarterRound(&x, 2, 6, 10, 14)
		quarterRound(&x, 3, 7, 11, 15)
		quarterRound(&x, 0, 5, 10, 15)
		quarterRound(&x, 1, 6, 11, 12)
		quarterRound(&x, 2, 7, 8, 13)
		quarterRound(&x, 3, 4, 9, 14)
	}
	for i := 0; i < 16; i++ {
		binary.LittleEndian.PutUint32(out[i*4:i*4+4], x[i]+s[i])
	}
}

func rotl32(v uint32, n uint) uint32 { return v<<n | v>>(32-n) }

func quarterRound(x *[16]uint32, a, b, c, d int) {
	x[a] += x[b]
	x[d] = rotl32(x[d]^x[a], 16)
	x[c] += x[d]
	x[b] = rotl32(x[b]^x[c], 12)
	x[a] += x[b]
	x[d] = rotl32(x[d]^x[a], 8)
	x[c] += x[d]
	x[b] = rotl32(x[b]^x[c], 7)
}

// chacha20XOR encrypts src into dst starting at the given block counter.
func chacha20XOR(dst, src []byte, key *[32]byte, nonce []byte, counter uint32) {
	var ks [64]byte
	for off := 0; off < len(src); off += 64 {
		chacha20Block(&ks, key, nonce, counter+uint32(off/64))
		n := len(src) - off
		if n > 64 {
			n = 64
		}
		for i := 0; i < n; i++ {
			dst[off+i] = src[off+i] ^ ks[i]
		}
	}
}

// poly1305Tag computes the AEAD tag over
// aad || pad16(aad) || ciphertext || pad16(ciphertext) || len(aad) || len(ct),
// with both lengths as little-endian 64-bit values (RFC 8439 §2.8).
func poly1305Tag(key [32]byte, aad, ciphertext []byte) [16]byte {
	var msg []byte
	msg = append(msg, aad...)
	msg = append(msg, make([]byte, pad16(len(aad)))...)
	msg = append(msg, ciphertext...)
	msg = append(msg, make([]byte, pad16(len(ciphertext)))...)
	var lens [16]byte
	binary.LittleEndian.PutUint64(lens[0:8], uint64(len(aad)))
	binary.LittleEndian.PutUint64(lens[8:16], uint64(len(ciphertext)))
	msg = append(msg, lens[:]...)
	return poly1305(key, msg)
}

func pad16(n int) int {
	if n%16 == 0 {
		return 0
	}
	return 16 - n%16
}

// poly1305 is RFC 8439 §2.5, transcribed directly.
func poly1305(key [32]byte, msg []byte) [16]byte {
	var rBytes [16]byte
	for i := 0; i < 16; i++ {
		rBytes[i] = key[i] & poly1305Clamp[i]
	}
	r := leBytesToInt(rBytes[:])
	s := leBytesToInt(key[16:32])

	acc := new(big.Int)
	block := new(big.Int)
	for off := 0; off < len(msg); off += 16 {
		end := off + 16
		if end > len(msg) {
			end = len(msg)
		}
		// Append the 0x01 byte that makes the block a (8n+1)-bit number.
		chunk := make([]byte, end-off+1)
		copy(chunk, msg[off:end])
		chunk[end-off] = 1

		block.SetBytes(reverse(chunk))
		acc.Add(acc, block)
		acc.Mul(acc, r)
		acc.Mod(acc, polyP)
	}
	acc.Add(acc, s)

	var tag [16]byte
	buf := acc.Bytes() // big-endian
	// Keep the low 128 bits, little-endian.
	for i := 0; i < 16 && i < len(buf); i++ {
		tag[i] = buf[len(buf)-1-i]
	}
	return tag
}

func leBytesToInt(b []byte) *big.Int { return new(big.Int).SetBytes(reverse(b)) }

func reverse(b []byte) []byte {
	out := make([]byte, len(b))
	for i := range b {
		out[len(b)-1-i] = b[i]
	}
	return out
}
