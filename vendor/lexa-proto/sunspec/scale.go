package sunspec

import "math"

// notImplemented is the SunSpec sentinel value for int16 scale factors meaning
// "this point is not implemented on this device".
const notImplemented = int16(-32768) // 0x8000 reinterpreted as int16

// Valid sunssf domain (LXR-004). The SunSpec information-model specification
// defines a scale factor as a signed power-of-ten exponent in [-10, +10]:
// 10^-10..10^10 spans every physical quantity a DER register carries. Any
// other register value is NOT a scale factor a conforming device could have
// intended — it is corruption or hostility, and treating it as arithmetic is
// how a garbage read becomes a plausible-looking measurement (or a saturated
// command). The independent referee in csip-tls-test/internal/diff pins the
// same bound.
const (
	MinValidSF int16 = -10
	MaxValidSF int16 = 10
)

// ValidSF reports whether sf is inside the legal sunssf domain. The
// notImplemented sentinel (-32768) is NOT valid — it means "no scale factor",
// which callers must handle explicitly (decode → NaN, encode → refuse).
func ValidSF(sf int16) bool { return sf >= MinValidSF && sf <= MaxValidSF }

// ApplyScaleUint converts an unsigned SunSpec register value to a float64 by
// applying the given scale factor: actual = raw × 10^sf.
// Returns math.NaN() when sf is the "not implemented" sentinel (0x8000) or
// any value outside the legal sunssf domain [-10,+10] (LXR-004): a corrupt or
// hostile scale factor must never be laundered into a plausible number.
func ApplyScaleUint(raw uint16, sf int16) float64 {
	if !ValidSF(sf) {
		return math.NaN()
	}
	return float64(raw) * math.Pow10(int(sf))
}

// ApplyScaleSigned converts a signed SunSpec register value (int16 stored in
// a uint16 word) to a float64 by applying the given scale factor.
// Returns math.NaN() when sf is the "not implemented" sentinel or outside the
// legal sunssf domain [-10,+10] (LXR-004).
func ApplyScaleSigned(raw uint16, sf int16) float64 {
	if !ValidSF(sf) {
		return math.NaN()
	}
	return float64(int16(raw)) * math.Pow10(int(sf))
}

// EncodeOutcome reports what an Encode* call actually did with the value, so
// a writer can distinguish "applied" from "applied as something else" — the
// silent-saturation gap the differential referee flagged (LXR-004): the old
// bare-uint16 signature had no room for the fact that a value did not fit.
type EncodeOutcome uint8

const (
	// EncodeExact: the value was representable (after nearest-integer
	// rounding at the given scale factor) and encoded as-is.
	EncodeExact EncodeOutcome = iota
	// EncodeSaturatedHigh: the finite value exceeded the register's max-valid
	// high edge and was clamped onto it. The register no longer carries the
	// requested value.
	EncodeSaturatedHigh
	// EncodeSaturatedLow: the finite value was below the register's min-valid
	// edge (signed: −32767; unsigned: 0) and was clamped onto it.
	EncodeSaturatedLow
	// EncodeNotImplemented: the value was non-finite (NaN/±Inf) — there is no
	// representable magnitude — so the reserved NOT_IMPLEMENTED sentinel was
	// encoded (audit SUN-004).
	EncodeNotImplemented
	// EncodeBadSF: the scale factor is outside the legal sunssf domain
	// (including the 0x8000 sentinel); nothing can be represented against it.
	// The returned raw word is the reserved NOT_IMPLEMENTED sentinel, never a
	// fabricated data value (LXR-004: the old contract returned raw 0, which
	// reads on the wire as a real command of zero).
	EncodeBadSF
)

// Saturated reports whether the encoded register no longer carries the
// requested value (either clamp direction).
func (o EncodeOutcome) Saturated() bool {
	return o == EncodeSaturatedHigh || o == EncodeSaturatedLow
}

// Representable reports whether the register carries the requested value
// exactly (after rounding). Anything else must be surfaced by the caller —
// refused, compensated, or reported — never treated as success.
func (o EncodeOutcome) Representable() bool { return o == EncodeExact }

// EncodeScaleSigned converts a float64 engineering value to a signed uint16
// register word under sf, reporting exactly what happened (see EncodeOutcome).
// Contract per audit SUN-004:
//   - non-finite → reserved NOT_IMPLEMENTED sentinel (0x8000), EncodeNotImplemented;
//   - finite out-of-range → clamp to the MAX-VALID int16 edge (+32767 high,
//     −32767 low — never the reserved 0x8000), EncodeSaturated*;
//   - sf outside the sunssf domain → sentinel, EncodeBadSF.
func EncodeScaleSigned(val float64, sf int16) (uint16, EncodeOutcome) {
	if !ValidSF(sf) {
		return sentI16, EncodeBadSF
	}
	if math.IsNaN(val) || math.IsInf(val, 0) {
		return sentI16, EncodeNotImplemented
	}
	rounded := math.Round(val / math.Pow10(int(sf)))
	if rounded > maxValidI16 {
		return 0x7FFF, EncodeSaturatedHigh // +32767
	}
	if rounded < minValidI16 {
		return 0x8001, EncodeSaturatedLow // −32767; −32768/0x8000 is reserved
	}
	return uint16(int16(rounded)), EncodeExact
}

// EncodeScaleUint converts a float64 engineering value to an unsigned uint16
// register word under sf, reporting exactly what happened. Same contract as
// EncodeScaleSigned with the unsigned edges (65534 high — 0xFFFF is the
// reserved sentinel — and floor 0 low).
func EncodeScaleUint(val float64, sf int16) (uint16, EncodeOutcome) {
	if !ValidSF(sf) {
		return sentU16, EncodeBadSF
	}
	if math.IsNaN(val) || math.IsInf(val, 0) {
		return sentU16, EncodeNotImplemented
	}
	if val < 0 {
		return 0, EncodeSaturatedLow
	}
	rounded := math.Round(val / math.Pow10(int(sf)))
	if rounded > maxValidU16 {
		return uint16(maxValidU16), EncodeSaturatedHigh // 65534 (0xFFFE)
	}
	if rounded < 0 {
		return 0, EncodeSaturatedLow
	}
	return uint16(rounded), EncodeExact
}

// RawFromScaleSigned converts a float64 value back to a uint16 register word
// given the target scale factor, discarding the outcome. Kept for round-trip
// codec uses (sweeps, simulators) where the caller controls the scale factor.
// Command writers must use EncodeScaleSigned and act on the outcome instead —
// a discarded saturation is exactly the silent-corruption class LXR-004 names.
//
// NOTE the LXR-004 contract change: an out-of-domain scale factor (including
// the 0x8000 sentinel) now yields the reserved NOT_IMPLEMENTED sentinel
// (0x8000), NOT raw 0 as previously — raw 0 reads on the wire as a real
// command of zero (0 W, 0 %, PF 0.00) fabricated from nothing.
func RawFromScaleSigned(val float64, sf int16) uint16 {
	raw, _ := EncodeScaleSigned(val, sf)
	return raw
}

// RawFromScaleUint converts a float64 value to a uint16 register word given
// the target scale factor, discarding the outcome. See RawFromScaleSigned for
// the contract, with the unsigned sentinel (0xFFFF) on a bad scale factor.
func RawFromScaleUint(val float64, sf int16) uint16 {
	raw, _ := EncodeScaleUint(val, sf)
	return raw
}
