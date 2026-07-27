package aead

import (
	"crypto/cipher"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
)

// ErrOpen is returned when authentication fails. It carries no detail on
// purpose — an offline decryptor has nothing to hide, but callers should not
// build logic on the difference between "wrong key" and "tampered ciphertext",
// which the construction cannot distinguish anyway.
var ErrOpen = errors.New("aead: message authentication failed")

// ccm implements Counter with CBC-MAC (NIST SP 800-38C) over any 128-bit block
// cipher, with a configurable nonce and tag size.
//
// # Why this exists
//
// TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8 (0xC0AE) is the cipher suite CSIP
// §5.2.1.1 mandates and the one this bench's gateways actually negotiate. Go's
// standard library ships GCM and nothing else: there is no crypto/cipher CCM,
// and crypto/tls has never implemented a CCM suite. An evidence engine that
// cannot decrypt the mandatory suite can decrypt everything except the traffic
// that matters most, so CCM is implemented here from the specification.
//
// # Implementation notes
//
// CCM is CTR encryption plus a CBC-MAC over a formatted header, the additional
// data, and the plaintext (§A.2). The two are joined by encrypting the MAC with
// counter block zero, whose keystream is used for nothing else. The formatting
// is where implementations go wrong, so the two length encodings are spelled
// out below rather than folded into clever arithmetic:
//
//   - B0's flags byte packs "is there AAD", the tag size as (t-2)/2, and the
//     length-field size as q-1. q is fixed by the nonce: q = 15 - len(nonce).
//   - The AAD length prefix is 2 bytes below 2^16-2^8, then a 0xFF 0xFE escape
//     with 4 bytes, then 0xFF 0xFF with 8.
//
// This implementation is not constant-time in the CBC-MAC padding and does not
// try to be: it decrypts captures with keys the operator already holds, from a
// key log the operator already has. There is no secret to leak by timing. The
// tag comparison still uses subtle.ConstantTimeCompare, because that one costs
// nothing and keeps the code honest for any future reuse.
type ccm struct {
	block     cipher.Block
	nonceSize int
	tagSize   int
}

// NewCCM returns an AEAD implementing CCM over block with the given nonce and
// tag sizes.
//
// SP 800-38C constrains both: the nonce is 7..13 bytes and the tag is one of
// 4, 6, 8, 10, 12, 14, 16. TLS 1.2's CCM suites use a 12-byte nonce (4 bytes of
// key-block salt plus an 8-byte explicit nonce) with an 8-byte tag for the _8
// suites and 16 otherwise; TLS 1.3's use the same 12-byte nonce built from the
// per-record sequence number.
func NewCCM(block cipher.Block, nonceSize, tagSize int) (cipher.AEAD, error) {
	if block.BlockSize() != 16 {
		return nil, fmt.Errorf("aead: CCM needs a 128-bit block cipher, got %d-bit", block.BlockSize()*8)
	}
	if nonceSize < 7 || nonceSize > 13 {
		return nil, fmt.Errorf("aead: CCM nonce size %d is outside the 7..13 range NIST SP 800-38C allows", nonceSize)
	}
	switch tagSize {
	case 4, 6, 8, 10, 12, 14, 16:
	default:
		return nil, fmt.Errorf("aead: CCM tag size %d is not one of 4,6,8,10,12,14,16", tagSize)
	}
	return &ccm{block: block, nonceSize: nonceSize, tagSize: tagSize}, nil
}

func (c *ccm) NonceSize() int { return c.nonceSize }
func (c *ccm) Overhead() int  { return c.tagSize }

// maxPlaintext is the largest message the length field can express: q bytes of
// big-endian length, where q = 15 - nonceSize.
func (c *ccm) maxPlaintext() uint64 {
	q := 15 - c.nonceSize
	if q >= 8 {
		return ^uint64(0)
	}
	return 1<<(8*uint(q)) - 1
}

func (c *ccm) Seal(dst, nonce, plaintext, additionalData []byte) []byte {
	if len(nonce) != c.nonceSize {
		panic("aead: incorrect CCM nonce length")
	}
	if uint64(len(plaintext)) > c.maxPlaintext() {
		panic("aead: message too long for this CCM nonce size")
	}
	tag := c.cbcMAC(nonce, plaintext, additionalData)

	ret, out := sliceForAppend(dst, len(plaintext)+c.tagSize)
	counter := c.counterBlock(nonce, 0)
	var s0 [16]byte
	c.block.Encrypt(s0[:], counter)

	// Counter 1 onwards encrypts the message; counter 0 is reserved for the tag.
	c.ctr(out[:len(plaintext)], plaintext, nonce, 1)
	for i := 0; i < c.tagSize; i++ {
		out[len(plaintext)+i] = tag[i] ^ s0[i]
	}
	return ret
}

func (c *ccm) Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	if len(nonce) != c.nonceSize {
		return nil, fmt.Errorf("aead: CCM nonce is %d bytes, want %d", len(nonce), c.nonceSize)
	}
	if len(ciphertext) < c.tagSize {
		return nil, fmt.Errorf("aead: CCM ciphertext is %d bytes, shorter than the %d-byte tag: %w",
			len(ciphertext), c.tagSize, ErrOpen)
	}
	body := ciphertext[:len(ciphertext)-c.tagSize]
	wantTag := ciphertext[len(ciphertext)-c.tagSize:]
	if uint64(len(body)) > c.maxPlaintext() {
		return nil, fmt.Errorf("aead: CCM ciphertext is longer than this nonce size can address: %w", ErrOpen)
	}

	counter := c.counterBlock(nonce, 0)
	var s0 [16]byte
	c.block.Encrypt(s0[:], counter)

	plaintext := make([]byte, len(body))
	c.ctr(plaintext, body, nonce, 1)

	tag := c.cbcMAC(nonce, plaintext, additionalData)
	for i := 0; i < c.tagSize; i++ {
		tag[i] ^= s0[i]
	}
	if subtle.ConstantTimeCompare(tag[:c.tagSize], wantTag) != 1 {
		// Never hand back plaintext that did not authenticate. A partially
		// decrypted record presented as valid is the single worst thing an
		// evidence tool can do.
		return nil, ErrOpen
	}
	ret, out := sliceForAppend(dst, len(plaintext))
	copy(out, plaintext)
	return ret, nil
}

// counterBlock builds A_i: flags(q-1) || nonce || i.
func (c *ccm) counterBlock(nonce []byte, i uint64) []byte {
	q := 15 - c.nonceSize
	blk := make([]byte, 16)
	blk[0] = byte(q - 1)
	copy(blk[1:], nonce)
	for j := 0; j < q; j++ {
		blk[15-j] = byte(i >> (8 * uint(j)))
	}
	return blk
}

// ctr runs CTR mode from the given starting counter.
func (c *ccm) ctr(dst, src, nonce []byte, start uint64) {
	var ks [16]byte
	for off := 0; off < len(src); off += 16 {
		c.block.Encrypt(ks[:], c.counterBlock(nonce, start+uint64(off/16)))
		n := len(src) - off
		if n > 16 {
			n = 16
		}
		for j := 0; j < n; j++ {
			dst[off+j] = src[off+j] ^ ks[j]
		}
	}
}

// cbcMAC computes T over B0 || formatted AAD || plaintext, zero-padded to whole
// blocks, with a zero IV.
func (c *ccm) cbcMAC(nonce, plaintext, additionalData []byte) [16]byte {
	q := 15 - c.nonceSize

	// B0's flags byte: bit 6 set when AAD is present, bits 5..3 carry
	// (tagSize-2)/2, bits 2..0 carry q-1.
	adata := 0
	if len(additionalData) > 0 {
		adata = 1
	}
	var b0 [16]byte
	b0[0] = byte(adata<<6 | ((c.tagSize-2)/2)<<3 | (q - 1))
	copy(b0[1:], nonce)
	n := uint64(len(plaintext))
	for j := 0; j < q; j++ {
		b0[15-j] = byte(n >> (8 * uint(j)))
	}

	var x [16]byte
	c.block.Encrypt(x[:], b0[:])

	if len(additionalData) > 0 {
		var hdr []byte
		a := uint64(len(additionalData))
		switch {
		case a < (1<<16 - 1<<8):
			hdr = make([]byte, 2)
			binary.BigEndian.PutUint16(hdr, uint16(a))
		case a <= 1<<32-1:
			hdr = make([]byte, 6)
			hdr[0], hdr[1] = 0xFF, 0xFE
			binary.BigEndian.PutUint32(hdr[2:], uint32(a))
		default:
			hdr = make([]byte, 10)
			hdr[0], hdr[1] = 0xFF, 0xFF
			binary.BigEndian.PutUint64(hdr[2:], a)
		}
		c.macBlocks(&x, hdr, additionalData)
	}
	c.macBlocks(&x, nil, plaintext)
	return x
}

// macBlocks folds prefix||data into the running CBC-MAC state, zero-padding to
// a block boundary at the end.
func (c *ccm) macBlocks(x *[16]byte, prefix, data []byte) {
	var blk [16]byte
	filled := 0
	feed := func(b []byte) {
		for _, v := range b {
			blk[filled] = v
			filled++
			if filled == 16 {
				for i := range blk {
					x[i] ^= blk[i]
				}
				c.block.Encrypt(x[:], x[:])
				blk = [16]byte{}
				filled = 0
			}
		}
	}
	feed(prefix)
	feed(data)
	if filled > 0 {
		for i := filled; i < 16; i++ {
			blk[i] = 0
		}
		for i := range blk {
			x[i] ^= blk[i]
		}
		c.block.Encrypt(x[:], x[:])
	}
}

// sliceForAppend mirrors the helper crypto/cipher's own AEADs use: extend dst
// by n bytes and return both the whole slice and the tail to write into.
func sliceForAppend(in []byte, n int) (head, tail []byte) {
	if total := len(in) + n; cap(in) >= total {
		head = in[:total]
	} else {
		head = make([]byte, total)
		copy(head, in)
	}
	tail = head[len(in):]
	return
}
