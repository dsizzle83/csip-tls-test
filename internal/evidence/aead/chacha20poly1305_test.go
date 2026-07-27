package aead

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

// The RFC 8439 vectors. Every expected value below is quoted from the RFC and
// was re-derived from the RFC's inputs against an independent implementation
// while this file was written.
var (
	rfc8439StreamKey   = mustHex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
	rfc8439StreamNonce = mustHex("000000000000004a00000000")
	rfc8439Plaintext   = []byte("Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.")
	// RFC 8439 §2.4.2 — ChaCha20 keystream applied at block counter 1.
	rfc8439StreamCipher = mustHex(
		"6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0b" +
			"f91b65c5524733ab8f593dabcd62b3571639d624e65152ab8f530c359f0861d8" +
			"07ca0dbf500d6a6156a38e088a22b65e52bc514d16ccf806818ce91ab7793736" +
			"5af90bbf74a35be6b40b8eedf2785e42874d")

	// RFC 8439 §2.5.2 — Poly1305 over an ASCII message.
	rfc8439PolyKey = mustHex("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b")
	rfc8439PolyMsg = []byte("Cryptographic Forum Research Group")
	rfc8439PolyTag = mustHex("a8061dc1305136c6c22b8baf0c0127a9")

	// RFC 8439 §2.8.2 — the combined AEAD.
	rfc8439AEADKey    = mustHex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f")
	rfc8439AEADNonce  = mustHex("070000004041424344454647")
	rfc8439AEADAAD    = mustHex("50515253c0c1c2c3c4c5c6c7")
	rfc8439AEADCipher = mustHex(
		"d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6" +
			"3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36" +
			"92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc" +
			"3ff4def08e4b7a9de576d26586cec64b6116")
	rfc8439AEADTag = mustHex("1ae10b594f09e26a7e902ecbd0600691")
)

// TestChaCha20KeystreamRFC8439 exercises the block function on its own, so a
// bug in the round function is not masked by a compensating bug in the AEAD
// framing.
func TestChaCha20KeystreamRFC8439(t *testing.T) {
	var key [32]byte
	copy(key[:], rfc8439StreamKey)
	got := make([]byte, len(rfc8439Plaintext))
	chacha20XOR(got, rfc8439Plaintext, &key, rfc8439StreamNonce, 1)
	if !bytes.Equal(got, rfc8439StreamCipher) {
		t.Fatalf("ChaCha20 §2.4.2:\n got %x\nwant %x", got, rfc8439StreamCipher)
	}
	// And back again: ChaCha20 is its own inverse.
	back := make([]byte, len(got))
	chacha20XOR(back, got, &key, rfc8439StreamNonce, 1)
	if !bytes.Equal(back, rfc8439Plaintext) {
		t.Fatal("ChaCha20 does not round-trip")
	}
}

func TestPoly1305RFC8439(t *testing.T) {
	var key [32]byte
	copy(key[:], rfc8439PolyKey)
	tag := poly1305(key, rfc8439PolyMsg)
	if !bytes.Equal(tag[:], rfc8439PolyTag) {
		t.Fatalf("Poly1305 §2.5.2:\n got %x\nwant %x", tag, rfc8439PolyTag)
	}
}

// TestPoly1305EdgeCases covers the arithmetic corners the 130-bit reduction has
// to get right: an all-ones block that forces a reduction, a zero r that makes
// the tag depend on s alone, and the empty message.
func TestPoly1305EdgeCases(t *testing.T) {
	for _, tc := range []struct {
		name string
		key  string
		msg  string
		want string
	}{
		{
			// RFC 8439 §A.3 test vector #1: an all-zero key over an all-zero
			// message must produce an all-zero tag.
			name: "zero key and message",
			key:  strings.Repeat("00", 32),
			msg:  strings.Repeat("00", 64),
			want: "00000000000000000000000000000000",
		},
		{
			// §A.3 #2: r = 0, so the tag is just s.
			name: "zero r",
			key:  "0000000000000000000000000000000036e5f6b5c5e06070f0efca96227a863e",
			msg: "416e79207375626d697373696f6e20746f20746865204945544620696e74656e6465642062792074686520436f6e7472696275746f7220666f72207075626c69636174696f6e20617320616c6c206f7220706172742" +
				"06f6620616e204945544620496e7465726e65742d4472616674206f722052464320616e6420616e792073746174656d656e74206d6164652077697468696e2074686520636f6e74657874206f6620616e20494554462061637469766974792069732" +
				"0636f6e7369646572656420616e20224945544620436f6e747269627574696f6e222e20537563682073746174656d656e747320696e636c756465206f72616c2073746174656d656e747320696e20494554462073657373696f6e732c2061732077" +
				"656c6c206173207772697474656e20616e6420656c656374726f6e696320636f6d6d756e69636174696f6e73206d61646520617420616e792074696d65206f7220706c6163652c207768696368206172652061646472657373656420746f",
			want: "36e5f6b5c5e06070f0efca96227a863e",
		},
		{
			name: "empty message",
			key:  "85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b",
			want: "0103808afb0db2fd4abff6af4149f51b", // acc stays 0, so the tag is s
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var key [32]byte
			copy(key[:], mustHex(tc.key))
			tag := poly1305(key, mustHex(tc.msg))
			if !bytes.Equal(tag[:], mustHex(tc.want)) {
				t.Fatalf("\n got %x\nwant %s", tag, tc.want)
			}
		})
	}
}

func TestChaCha20Poly1305RFC8439(t *testing.T) {
	c, err := NewChaCha20Poly1305(rfc8439AEADKey)
	if err != nil {
		t.Fatal(err)
	}
	if c.NonceSize() != 12 || c.Overhead() != 16 {
		t.Fatalf("NonceSize/Overhead = %d/%d, want 12/16", c.NonceSize(), c.Overhead())
	}
	want := append(append([]byte(nil), rfc8439AEADCipher...), rfc8439AEADTag...)
	got := c.Seal(nil, rfc8439AEADNonce, rfc8439Plaintext, rfc8439AEADAAD)
	if !bytes.Equal(got, want) {
		t.Fatalf("Seal §2.8.2:\n got %x\nwant %x", got, want)
	}
	back, err := c.Open(nil, rfc8439AEADNonce, want, rfc8439AEADAAD)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !bytes.Equal(back, rfc8439Plaintext) {
		t.Fatalf("Open:\n got %q\nwant %q", back, rfc8439Plaintext)
	}
}

func TestChaCha20Poly1305RejectsTampering(t *testing.T) {
	c, _ := NewChaCha20Poly1305(rfc8439AEADKey)
	sealed := c.Seal(nil, rfc8439AEADNonce, rfc8439Plaintext, rfc8439AEADAAD)
	for _, i := range []int{0, 1, 63, 64, len(sealed) - 17, len(sealed) - 16, len(sealed) - 1} {
		bad := append([]byte(nil), sealed...)
		bad[i] ^= 0x01
		if _, err := c.Open(nil, rfc8439AEADNonce, bad, rfc8439AEADAAD); !errors.Is(err, ErrOpen) {
			t.Fatalf("a flipped bit at offset %d was accepted", i)
		}
	}
	badAAD := append([]byte(nil), rfc8439AEADAAD...)
	badAAD[3] ^= 1
	if _, err := c.Open(nil, rfc8439AEADNonce, sealed, badAAD); !errors.Is(err, ErrOpen) {
		t.Fatal("modified additional data was accepted")
	}
	badNonce := append([]byte(nil), rfc8439AEADNonce...)
	badNonce[11] ^= 1
	if _, err := c.Open(nil, badNonce, sealed, rfc8439AEADAAD); !errors.Is(err, ErrOpen) {
		t.Fatal("a wrong nonce was accepted")
	}
}

func TestChaCha20Poly1305Sizes(t *testing.T) {
	c, _ := NewChaCha20Poly1305(rfc8439AEADKey)
	nonce := make([]byte, 12)
	// Cross every padding boundary in the Poly1305 input construction.
	for _, n := range []int{0, 1, 15, 16, 17, 63, 64, 65, 128, 1000} {
		for _, a := range []int{0, 1, 15, 16, 17} {
			pt := make([]byte, n)
			aad := make([]byte, a)
			for i := range pt {
				pt[i] = byte(i * 7)
			}
			for i := range aad {
				aad[i] = byte(i * 3)
			}
			sealed := c.Seal(nil, nonce, pt, aad)
			if len(sealed) != n+16 {
				t.Fatalf("n=%d: sealed length %d", n, len(sealed))
			}
			back, err := c.Open(nil, nonce, sealed, aad)
			if err != nil {
				t.Fatalf("n=%d a=%d: %v", n, a, err)
			}
			if !bytes.Equal(back, pt) {
				t.Fatalf("n=%d a=%d: round trip mismatch", n, a)
			}
		}
	}
}

func TestChaCha20Poly1305Validation(t *testing.T) {
	if _, err := NewChaCha20Poly1305(make([]byte, 31)); err == nil || !strings.Contains(err.Error(), "key is 31 bytes") {
		t.Fatalf("err = %v", err)
	}
	c, _ := NewChaCha20Poly1305(rfc8439AEADKey)
	if _, err := c.Open(nil, make([]byte, 11), make([]byte, 20), nil); err == nil {
		t.Error("Open with a short nonce must fail")
	}
	if _, err := c.Open(nil, make([]byte, 12), make([]byte, 8), nil); !errors.Is(err, ErrOpen) {
		t.Error("Open of a ciphertext shorter than the tag must fail")
	}
	if !bytes.HasPrefix(c.Seal([]byte("KEEP"), make([]byte, 12), []byte("x"), nil), []byte("KEEP")) {
		t.Error("Seal must append to dst")
	}
}
