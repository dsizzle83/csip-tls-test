// Package sunspecgolden is an independently-sourced golden of SunSpec model
// register layouts (point offsets, sizes, types and scale-factor pairings),
// used as the referee for TestLexaProtoLayoutsMatchGolden.
//
// WP4-T5/T6 (finding REV0907-E8): both the conformance sims
// (sim/southbound/solar.go) and the ride-through oracle
// (internal/certify/suitecsip/ridethrough.go) previously took their SunSpec
// register offsets from lexa-proto/sunspec — the SAME package the product
// under test also consumes. A wrong offset in lexa-proto (model 120's table
// was wrong at 22 of its 25 named points; see golden_test.go) is invisible to
// a sim seeded from lexa-proto's own constants and to an oracle computed from
// lexa-proto's own layout: the bug and the referee agree with each other and
// disagree with reality together. docs/CODING_PRINCIPLES.md and
// docs/ADVERSARIAL_QA_STRATEGY.md §5 (rule PN-1/C9/AD-003(f)) require a
// referee built from the standard's own text or a hand-computed golden value
// instead — this package IS that golden value for SunSpec register geometry.
//
// The table in golden_gen.go is generated (go:generate, see gen/main.go) from
// an INDEPENDENTLY FETCHED copy of the SunSpec Alliance model JSON
// (github.com/sunspec/models), pinned and checksummed in
// testdata/models/SOURCES.md. It is never derived from, diffed against, or
// copied from lexa-proto's vendored sunspec package or lexa-gw's own SunSpec
// documentation.
package sunspecgolden

// FieldType names a SunSpec point's declared data type using the model
// JSON's own type token (e.g. "uint16", "sunssf", "acc64") rather than any
// lexa-proto enum, so this package carries no dependency on the thing it
// referees. golden_test.go maps these tokens onto lexa-proto's
// sunspec.FieldType for comparison.
type FieldType string

// The SunSpec point types this golden covers, verbatim from the model JSON's
// "type" key.
const (
	Uint16     FieldType = "uint16"
	Int16      FieldType = "int16"
	Enum16     FieldType = "enum16"
	Bitfield16 FieldType = "bitfield16"
	Sunssf     FieldType = "sunssf"
	Uint32     FieldType = "uint32"
	Int32      FieldType = "int32"
	Enum32     FieldType = "enum32"
	Bitfield32 FieldType = "bitfield32"
	Acc32      FieldType = "acc32"
	Uint64     FieldType = "uint64"
	Int64      FieldType = "int64"
	Acc64      FieldType = "acc64"
	String     FieldType = "string"
	Pad        FieldType = "pad"
)

// Point is one named SunSpec register (or multi-register value), transcribed
// from the independently-fetched model JSON.
// Point (WP4-T5, REV0907-E8) is one entry in the golden — see the package doc
// above for why this table exists and where it comes from.
type Point struct {
	// Name is the point's SunSpec name, verbatim from the model JSON (e.g.
	// "WRtg", "WAval").
	Name string
	// Offset is the 0-based register offset within the model's DATA block —
	// i.e. after the two-register model ID+L header, matching the same
	// convention lexa-proto's Reader.ReadModel / Layout.Offset use.
	Offset int
	// Size is the point's register width (the model JSON's own "size" key,
	// which for every SunSpec type equals its register count directly — 1 for
	// a 16-bit point, 2 for a 32-bit point, 4 for a 64-bit point, and the
	// declared length for a string).
	Size int
	// Type is the point's SunSpec data type.
	Type FieldType
	// SF is the name of this point's scale-factor point, or "" if the point
	// is unscaled. Matches the model JSON's "sf" key.
	SF string
}

// Block (WP4-T6, REV0907-E8) returns the golden point list for a named model
// block (e.g. "M120", "M705Hdr", "M705Crv"), and whether that block exists in
// the golden. This is the lookup sim/southbound/solar.go's goldenOffset and
// golden_test.go's comparisons both use, rather than reaching into the
// package-level Golden map directly.
func Block(name string) ([]Point, bool) {
	p, ok := Golden[name]
	return p, ok
}
