package aead

import (
	"bytes"
	"crypto/aes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
)

// ccmVector is one RFC 3610 packet vector. All twelve use the same AES-128 key
// (C0 C1 … CF) and the same shape: a 13-byte nonce, an 8- or 12-byte cleartext
// header used as additional data, and a counting-pattern payload.
//
// The expected outputs are the RFC's, re-derived from the RFC's inputs and
// cross-checked against an independent AES-CCM implementation while this file
// was written. Packet vector #1's output is quoted verbatim in RFC 3610 §8 and
// matches byte for byte, which anchors the whole table.
type ccmVector struct {
	name   string
	tagLen int
	nonce  string
	aad    string
	pt     string
	out    string
}

var rfc3610Key = mustHex("c0c1c2c3c4c5c6c7c8c9cacbcccdcecf")

var rfc3610 = []ccmVector{
	{name: "packet vector #1", tagLen: 8,
		nonce: "00000003020100a0a1a2a3a4a5",
		aad:   "0001020304050607",
		pt:    "08090a0b0c0d0e0f101112131415161718191a1b1c1d1e",
		out:   "588c979a61c663d2f066d0c2c0f989806d5f6b61dac38417e8d12cfdf926e0"},
	{name: "packet vector #2", tagLen: 8,
		nonce: "00000004020100a0a1a2a3a4a5",
		aad:   "0001020304050607",
		pt:    "08090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
		out:   "0665e2b1c445ec686a174698a194efa66222f42d88e8990e791583a562a632f6"},
	{name: "packet vector #3", tagLen: 8,
		nonce: "00000005020100a0a1a2a3a4a5",
		aad:   "0001020304050607",
		pt:    "08090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20",
		out:   "1952e3b42c3b119d0302e8d2f2ed0a84c5c257170f5b3591df271ded54ed503d1f"},
	{name: "packet vector #4", tagLen: 8,
		nonce: "00000006020100a0a1a2a3a4a5",
		aad:   "000102030405060708090a0b",
		pt:    "0c0d0e0f101112131415161718191a1b1c1d1e",
		out:   "d6458b9f4643e6b18b8293bbeb9f3a6488a1e21b953b1d70791d6e"},
	{name: "packet vector #5", tagLen: 8,
		nonce: "00000007020100a0a1a2a3a4a5",
		aad:   "000102030405060708090a0b",
		pt:    "0c0d0e0f101112131415161718191a1b1c1d1e1f",
		out:   "7c857ef94116dcb2d830363340fafb0dcafc2e2de82bfbcd5a6353f7"},
	{name: "packet vector #6", tagLen: 8,
		nonce: "00000008020100a0a1a2a3a4a5",
		aad:   "000102030405060708090a0b",
		pt:    "0c0d0e0f101112131415161718191a1b1c1d1e1f20",
		out:   "246f4cab5f113457153f7aee79dca2ba90e506a0863701199bb523d475"},
	{name: "packet vector #7", tagLen: 10,
		nonce: "00000009020100a0a1a2a3a4a5",
		aad:   "0001020304050607",
		pt:    "08090a0b0c0d0e0f101112131415161718191a1b1c1d1e",
		out:   "a2c93619caef78ef57183c3308703d01b0286b0f2ba9accbbeb3b8ca5e378dfc11"},
	{name: "packet vector #8", tagLen: 10,
		nonce: "0000000a020100a0a1a2a3a4a5",
		aad:   "0001020304050607",
		pt:    "08090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
		out:   "d3b4e702b8f235ff04221a0d0070ade348728c1b6e262d23d7e160972bb655550905"},
	{name: "packet vector #9", tagLen: 10,
		nonce: "0000000b020100a0a1a2a3a4a5",
		aad:   "0001020304050607",
		pt:    "08090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20",
		out:   "7470dcae4181263b234890a88e04bcaaa0e07ffe7b26bec3653138358c975983814dc6"},
	{name: "packet vector #10", tagLen: 10,
		nonce: "0000000c020100a0a1a2a3a4a5",
		aad:   "000102030405060708090a0b",
		pt:    "0c0d0e0f101112131415161718191a1b1c1d1e",
		out:   "209cf21aebf5a976141abf45db21f6f78a37a5a6c6e757d75c00699c20"},
	{name: "packet vector #11", tagLen: 10,
		nonce: "0000000d020100a0a1a2a3a4a5",
		aad:   "000102030405060708090a0b",
		pt:    "0c0d0e0f101112131415161718191a1b1c1d1e1f",
		out:   "c9f82409678f8c7af649df5dea25e787b94c0f7cee30c735e3209bec9205"},
	{name: "packet vector #12", tagLen: 10,
		nonce: "0000000e020100a0a1a2a3a4a5",
		aad:   "000102030405060708090a0b",
		pt:    "0c0d0e0f101112131415161718191a1b1c1d1e1f20",
		out:   "42de326d9d4e46703ba6220f96ccb821bd77a9ea93f091e960a4f48f1116fe"},
}

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func TestCCMRFC3610Vectors(t *testing.T) {
	block, err := aes.NewCipher(rfc3610Key)
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range rfc3610 {
		t.Run(v.name, func(t *testing.T) {
			nonce, aad, pt, want := mustHex(v.nonce), mustHex(v.aad), mustHex(v.pt), mustHex(v.out)
			c, err := NewCCM(block, len(nonce), v.tagLen)
			if err != nil {
				t.Fatal(err)
			}
			got := c.Seal(nil, nonce, pt, aad)
			if !bytes.Equal(got, want) {
				t.Fatalf("Seal:\n got %x\nwant %x", got, want)
			}
			back, err := c.Open(nil, nonce, want, aad)
			if err != nil {
				t.Fatalf("Open: %v", err)
			}
			if !bytes.Equal(back, pt) {
				t.Fatalf("Open:\n got %x\nwant %x", back, pt)
			}
		})
	}
}

// TestCCMRejectsTampering walks a bit through every position of a sealed
// message and demands authentication failure at each one. A CCM whose tag
// check were wrong would still round-trip its own output — only tampering
// exposes it.
func TestCCMRejectsTampering(t *testing.T) {
	block, _ := aes.NewCipher(rfc3610Key)
	v := rfc3610[0]
	nonce, aad, sealed := mustHex(v.nonce), mustHex(v.aad), mustHex(v.out)
	c, err := NewCCM(block, len(nonce), v.tagLen)
	if err != nil {
		t.Fatal(err)
	}
	for i := range sealed {
		bad := append([]byte(nil), sealed...)
		bad[i] ^= 0x80
		if _, err := c.Open(nil, nonce, bad, aad); !errors.Is(err, ErrOpen) {
			t.Fatalf("flipping a bit at offset %d of %d was accepted (err=%v)", i, len(sealed), err)
		}
	}
	// Tampering with the additional data must fail too, even though the AAD is
	// not itself encrypted.
	badAAD := append([]byte(nil), aad...)
	badAAD[0] ^= 1
	if _, err := c.Open(nil, nonce, sealed, badAAD); !errors.Is(err, ErrOpen) {
		t.Fatalf("modified additional data was accepted (err=%v)", err)
	}
	// A different nonce must fail.
	badNonce := append([]byte(nil), nonce...)
	badNonce[0] ^= 1
	if _, err := c.Open(nil, badNonce, sealed, aad); !errors.Is(err, ErrOpen) {
		t.Fatalf("wrong nonce was accepted (err=%v)", err)
	}
}

// TestCCMTLSParameters covers the two shapes TLS actually uses: a 12-byte
// nonce with an 8-byte tag (the _8 suites, including the CSIP-mandatory
// 0xC0AE) and the same nonce with a 16-byte tag.
func TestCCMTLSParameters(t *testing.T) {
	key := make([]byte, 16)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	block, _ := aes.NewCipher(key)
	for _, tagLen := range []int{8, 16} {
		c, err := NewCCM(block, 12, tagLen)
		if err != nil {
			t.Fatal(err)
		}
		if c.NonceSize() != 12 || c.Overhead() != tagLen {
			t.Fatalf("NonceSize/Overhead = %d/%d", c.NonceSize(), c.Overhead())
		}
		nonce := make([]byte, 12)
		aad := []byte{0, 0, 0, 0, 0, 0, 0, 1, 23, 3, 3, 0, 42}
		for _, n := range []int{0, 1, 15, 16, 17, 31, 32, 33, 1000} {
			pt := make([]byte, n)
			for i := range pt {
				pt[i] = byte(i)
			}
			sealed := c.Seal(nil, nonce, pt, aad)
			if len(sealed) != n+tagLen {
				t.Fatalf("sealed length = %d, want %d", len(sealed), n+tagLen)
			}
			back, err := c.Open(nil, nonce, sealed, aad)
			if err != nil {
				t.Fatalf("n=%d tag=%d: %v", n, tagLen, err)
			}
			if !bytes.Equal(back, pt) {
				t.Fatalf("round trip mismatch at n=%d", n)
			}
		}
	}
}

// TestCCMAADLengthEncodings crosses the two escape thresholds in the AAD length
// prefix (2 bytes below 2^16-2^8, then 0xFF 0xFE plus 4 bytes). Getting the
// boundary wrong produces a MAC that is right for every small message and wrong
// for every large one — precisely the bug a short-message test would miss.
func TestCCMAADLengthEncodings(t *testing.T) {
	key := make([]byte, 16)
	block, _ := aes.NewCipher(key)
	c, err := NewCCM(block, 12, 8)
	if err != nil {
		t.Fatal(err)
	}
	nonce := make([]byte, 12)
	pt := []byte("payload")
	for _, n := range []int{1, 15, 16, 17, 0xFEFE, 0xFEFF, 0xFF00, 0xFF01, 0x10000} {
		aad := make([]byte, n)
		for i := range aad {
			aad[i] = byte(i)
		}
		sealed := c.Seal(nil, nonce, pt, aad)
		back, err := c.Open(nil, nonce, sealed, aad)
		if err != nil {
			t.Fatalf("aad length %d: %v", n, err)
		}
		if !bytes.Equal(back, pt) {
			t.Fatalf("aad length %d: round trip mismatch", n)
		}
		// A one-byte-longer AAD must not authenticate, which proves the length
		// really is bound into the MAC.
		if _, err := c.Open(nil, nonce, sealed, append(aad, 0)); !errors.Is(err, ErrOpen) {
			t.Fatalf("aad length %d: a longer AAD authenticated", n)
		}
	}
}

func TestCCMParameterValidation(t *testing.T) {
	block, _ := aes.NewCipher(make([]byte, 16))
	for _, tc := range []struct {
		name             string
		nonceSize, tagSz int
		wantErr          string
	}{
		{"nonce too short", 6, 8, "outside the 7..13 range"},
		{"nonce too long", 14, 8, "outside the 7..13 range"},
		{"odd tag size", 12, 7, "not one of"},
		{"tag too small", 12, 2, "not one of"},
		{"tag too large", 12, 18, "not one of"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := NewCCM(block, tc.nonceSize, tc.tagSz); err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("err = %v, want one containing %q", err, tc.wantErr)
			}
		})
	}
	if _, err := NewCCM(shortBlock{}, 12, 8); err == nil || !strings.Contains(err.Error(), "128-bit block cipher") {
		t.Fatalf("err = %v, want a block-size complaint", err)
	}

	c, _ := NewCCM(block, 12, 8)
	if _, err := c.Open(nil, make([]byte, 11), make([]byte, 20), nil); err == nil {
		t.Error("Open with a wrong-size nonce must fail")
	}
	if _, err := c.Open(nil, make([]byte, 12), make([]byte, 4), nil); !errors.Is(err, ErrOpen) {
		t.Error("Open of a ciphertext shorter than the tag must fail")
	}
}

// TestCCMNonceSizeBoundsMessageLength proves the length field is honoured: a
// 13-byte nonce leaves q=2, so messages are capped at 65535 bytes.
func TestCCMNonceSizeBoundsMessageLength(t *testing.T) {
	block, _ := aes.NewCipher(make([]byte, 16))
	c, err := NewCCM(block, 13, 8)
	if err != nil {
		t.Fatal(err)
	}
	nonce := make([]byte, 13)
	ok := c.Seal(nil, nonce, make([]byte, 65535), nil)
	if len(ok) != 65535+8 {
		t.Fatalf("sealed length = %d", len(ok))
	}
	defer func() {
		if recover() == nil {
			t.Fatal("sealing a message longer than the length field can express must panic, not truncate")
		}
	}()
	c.Seal(nil, nonce, make([]byte, 65536), nil)
}

// TestCCMSealAppends checks the dst-append contract crypto/cipher.AEAD
// specifies, since tlsdecrypt relies on it.
func TestCCMSealAppends(t *testing.T) {
	block, _ := aes.NewCipher(rfc3610Key)
	v := rfc3610[0]
	nonce, aad, pt, want := mustHex(v.nonce), mustHex(v.aad), mustHex(v.pt), mustHex(v.out)
	c, _ := NewCCM(block, len(nonce), v.tagLen)
	prefix := []byte("KEEP")
	got := c.Seal(prefix, nonce, pt, aad)
	if !bytes.HasPrefix(got, prefix) {
		t.Fatal("Seal must append to dst")
	}
	if !bytes.Equal(got[len(prefix):], want) {
		t.Fatalf("appended output differs:\n got %x\nwant %x", got[len(prefix):], want)
	}
	opened, err := c.Open(prefix, nonce, want, aad)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(opened, prefix) || !bytes.Equal(opened[len(prefix):], pt) {
		t.Fatal("Open must append to dst")
	}
}

// shortBlock is a cipher.Block with the wrong block size, for the constructor's
// validation path.
type shortBlock struct{}

func (shortBlock) BlockSize() int          { return 8 }
func (shortBlock) Encrypt(dst, src []byte) {}
func (shortBlock) Decrypt(dst, src []byte) {}
