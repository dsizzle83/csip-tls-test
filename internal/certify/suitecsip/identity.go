package suitecsip

// identity.go implements the IEEE 2030.5 §6.3 device credentials arithmetic:
// the certificate fingerprint, the LFDI and SFDI derived from it, and the
// mod-10 check-digit rule shared by the SFDI and the registration PIN.
//
// It is deliberately implemented here rather than imported. BASIC-001's whole
// point is that the SFDI and LFDI the SERVER serves match what the CLIENT
// computed from its own certificate; if the bench derived those values with the
// same code the product does, a shared bug would make a non-conformant device
// pass. This file is written from the standard's text and pinned by a unit test
// against the standard's own worked example (§6.3.2–6.3.4), which is the only
// external check available for arithmetic this small.
//
// The catalog records an erratum on BASIC-001 step 4(b): "SFDI is a 16-bit
// left-truncated value ... expressed as 40 hexadecimal digits" describes the
// LFDI, and "16-bit" is a typo for 160-bit. The code below implements the
// corrected rule, and the checks that use it say so in their method text.

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
)

// Fingerprint is the SHA-256 of the complete DER-encoded certificate, which is
// the root of every 2030.5 identifier.
func Fingerprint(der []byte) [32]byte { return sha256.Sum256(der) }

// LFDI is the fingerprint left-truncated to 160 bits, rendered as 40 lower-case
// hexadecimal digits — the form the <lFDI> element carries (HexBinary160, no
// separators; the "groups of four" in §6.3.3 is a display convention only).
func LFDI(der []byte) string {
	fp := Fingerprint(der)
	return hex.EncodeToString(fp[:20])
}

// SFDI is the fingerprint left-truncated to 36 bits, expressed in decimal with
// a sum-of-digits check digit right-concatenated (§6.3.2). The result is what
// the <sFDI> element carries.
//
// The truncation is of the BIT string, not of the decimal rendering: the top 36
// bits of the fingerprint are read as an unsigned integer, which is at most 11
// decimal digits, and the check digit makes 12.
func SFDI(der []byte) uint64 {
	fp := Fingerprint(der)
	// The top 36 bits are the first four octets plus the high nibble of the
	// fifth.
	var v uint64
	for i := 0; i < 4; i++ {
		v = v<<8 | uint64(fp[i])
	}
	v = v<<4 | uint64(fp[4]>>4)
	return AppendCheckDigit(v)
}

// AppendCheckDigit right-concatenates the sum-of-digits check digit, so that
// the digits of the result sum to zero modulo ten (§6.3.2, §6.3.4). It is the
// construction behind both the SFDI and the registration PIN.
func AppendCheckDigit(v uint64) uint64 {
	return v*10 + uint64((10-digitSum(v)%10)%10)
}

// ValidCheckDigit reports whether a value already carries a conformant check
// digit: the sum of ALL its digits, the check digit included, is zero modulo
// ten. This is the input-validation rule of §6.3.2 and §6.3.4, and it is what a
// client applies to a server-supplied pIN before trusting it.
func ValidCheckDigit(v uint64) bool { return digitSum(v)%10 == 0 }

func digitSum(v uint64) int {
	s := 0
	for v > 0 {
		s += int(v % 10)
		v /= 10
	}
	return s
}

// SFDIDigits reports how many decimal digits an SFDI has. §6.3.2 fixes the
// display form at 11 digits plus the check digit; a fingerprint whose top 36
// bits are small yields fewer, which is a legal value but an unusual one, so
// checks report the count rather than requiring exactly 12.
func SFDIDigits(v uint64) int {
	if v == 0 {
		return 1
	}
	n := 0
	for v > 0 {
		n++
		v /= 10
	}
	return n
}

// NormalizeLFDI strips the display separators and lower-cases an LFDI so a
// value read from XML can be compared with a computed one. It returns an error
// for anything that is not 40 hexadecimal digits, because a comparison that
// silently normalises garbage to garbage would report a mismatch as a
// conformance failure of the DUT rather than as bad input.
func NormalizeLFDI(s string) (string, error) {
	clean := strings.Map(func(r rune) rune {
		switch r {
		case ' ', '-', ':', '\t', '\n', '\r':
			return -1
		}
		return r
	}, s)
	clean = strings.ToLower(clean)
	if len(clean) != 40 {
		return "", fmt.Errorf("suitecsip: %q is not a 40-digit LFDI (got %d characters after stripping separators)", s, len(clean))
	}
	if _, err := hex.DecodeString(clean); err != nil {
		return "", fmt.Errorf("suitecsip: %q is not hexadecimal: %w", s, err)
	}
	return clean, nil
}
