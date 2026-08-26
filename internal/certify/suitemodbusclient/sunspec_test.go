package suitemodbusclient

// sunspec_test.go covers the SunSpec layer's edge cases — the ones where an
// over-eager implementation would invent a fact: a chain that never terminates,
// a zero-length model, a sentinel word that belongs to six datatypes at once.

import (
	"testing"
)

func TestChainRefusesAnIdentifierThatIsNotSunS(t *testing.T) {
	v := newRegisterView()
	v.apply(40000, []uint16{0x0000, 0x0000}, ADU{})
	models, complete, why := v.Chain(40000)
	if complete || len(models) != 0 {
		t.Fatalf("a chain was walked from a bogus identifier: %d model(s)", len(models))
	}
	if why == "" {
		t.Error("no reason was given")
	}
}

func TestChainRefusesAZeroLengthAdvance(t *testing.T) {
	// A model header whose length is 0 makes the next header its own body's
	// start; the walk still advances by 2, so this is legal. A length that
	// would make the chain stand still must be refused instead of looping.
	v := newRegisterView()
	v.apply(40000, []uint16{SunSHigh, SunSLow, 5, 0, ModelChainEnd}, ADU{})
	models, complete, _ := v.Chain(40000)
	if !complete {
		t.Fatalf("a zero-length model stopped the walk: %+v", models)
	}
	if len(models) != 1 || models[0].Length != 0 {
		t.Fatalf("models = %+v", models)
	}
	ann := annotateModels(models, nil)
	if !ann[0].BodyCovered || !ann[0].BodySingleRead {
		t.Error("a zero-length model must be trivially covered, not reported as skipped")
	}
}

func TestChainStopsAtAnUnobservedHeader(t *testing.T) {
	v := newRegisterView()
	// Identifier and one model header, then nothing: the next header at 40010
	// was never read.
	v.apply(40000, []uint16{SunSHigh, SunSLow, 1, 6}, ADU{})
	models, complete, why := v.Chain(40000)
	if complete {
		t.Fatal("the walk reported completeness without seeing the end marker")
	}
	if len(models) != 1 {
		t.Fatalf("models = %+v", models)
	}
	if why == "" {
		t.Error("the walk stopped without saying which header it lacked")
	}
}

func TestAnnotateModelsDistinguishesSkippedFromPartial(t *testing.T) {
	models := []Model{{HeaderAddr: 40002, ID: 1, Length: 10}, {HeaderAddr: 40014, ID: 2, Length: 10}}
	spans := []ReadSpan{
		{Start: 40004, Quantity: 10}, // model 1's whole body, one request
		{Start: 40016, Quantity: 4},  // model 2's body, partially
	}
	got := annotateModels(models, spans)
	if !got[0].BodyCovered || !got[0].BodySingleRead {
		t.Errorf("model 1 = %+v, want fully covered by a single read", got[0])
	}
	if got[1].BodyCovered || !got[1].BodyRead || got[1].BodySingleRead {
		t.Errorf("model 2 = %+v, want read but neither covered nor single-read", got[1])
	}
}

func TestSentinelTypesAreManyToOneAndSaySo(t *testing.T) {
	types := SentinelTypesFor(0xFFFF)
	if len(types) < 4 {
		t.Fatalf("0xFFFF maps to %v; it is the sentinel for several 16-bit types", types)
	}
	// 0x8000 is the LEADING word of int16, sunssf, pad, int32 and int64 alike,
	// and the lookup must say all of them rather than pick one: without a point
	// map there is no way to know which type a register belongs to, and a check
	// that named one would be inventing precision.
	want8000 := []string{"int16", "int32", "int64", "pad", "sunssf"}
	got := SentinelTypesFor(0x8000)
	if len(got) != len(want8000) {
		t.Errorf("0x8000 = %v, want %v", got, want8000)
	}
	for i := range got {
		if i < len(want8000) && got[i] != want8000[i] {
			t.Errorf("0x8000 = %v, want %v", got, want8000)
			break
		}
	}
	// 0x0000 is the widest of all — five types whose not-implemented value is
	// indistinguishable from an ordinary reading of zero.
	if got := SentinelTypesFor(0x0000); len(got) < 5 {
		t.Errorf("0x0000 = %v, want at least acc16/acc32/acc64/ipaddr/string/ipv6addr", got)
	}
	if got := SentinelTypesFor(0x1234); len(got) != 0 {
		t.Errorf("0x1234 is not any type's sentinel, got %v", got)
	}
}

func TestSentinelCountReportsTheDistinctWords(t *testing.T) {
	n, words := SentinelCount([]uint16{0x8000, 0x1234, 0xFFFF, 0x8000, 0x0042})
	if n != 3 {
		t.Errorf("n = %d, want 3", n)
	}
	if len(words) != 2 || words[0] != 0x8000 || words[1] != 0xFFFF {
		t.Errorf("words = %v", words)
	}
}

func TestCommonModelStringRefusesAHalfReadPoint(t *testing.T) {
	v := newRegisterView()
	v.apply(40004, []uint16{0x4C45, 0x5841}, ADU{}) // "LEXA", only 2 of 16 registers
	if s, ok := v.CommonModelString(40004, 0, 16); ok {
		t.Errorf("a 16-register string decoded from 2 registers: %q", s)
	}
	if s, ok := v.CommonModelString(40004, 0, 2); !ok || s != "LEXA" {
		t.Errorf("CommonModelString = %q,%v, want LEXA", s, ok)
	}
}

func TestIsStandardBase(t *testing.T) {
	for _, b := range []uint16{0, 40000, 50000} {
		if !IsStandardBase(b) {
			t.Errorf("%d is a standard SunSpec base", b)
		}
	}
	if IsStandardBase(40001) {
		t.Error("40001 is ERR-1's deliberately noncompliant base, not a standard one")
	}
}
