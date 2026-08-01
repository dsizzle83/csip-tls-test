package sim

// faultlayers_noop_test.go — "zero behaviour change when unused" pin for
// this QA batch (relocate.go, exception_target.go, sentinel.go,
// modelsplice.go). Each is constructed unconditionally by modsim/main.go
// and layered around the sim's existing hooks; this test builds the SAME
// wrapping sequence main.go performs and requires a register-for-register
// match against a bare, unwrapped SolarServer over the STATIC part of the
// image (the SunS header + the complete Model 1 Common block), which
// nothing in this package's animation loop ever rewrites — so the
// comparison is not sensitive to which wall-clock second the test happens
// to run in.
//
// wire.go's Mangler and protorelay.go's ProtoRelay are NOT included here:
// both are opt-in, gated behind their own modsim flags (-mangle,
// -protofault) and are simply never constructed when unused — see
// protorelay_test.go's TestProtoRelay_WriteFrame_DefaultPassthrough and
// wire_test.go's TestMangler_PassesThroughUnarmed for their own unarmed
// pins.

import "testing"

func TestFaultLayers_ByteIdenticalWhenUnused(t *testing.T) {
	baseline, err := NewSolarServer("tcp://127.0.0.1:0", 8000, "")
	if err != nil {
		t.Fatalf("baseline sim: %v", err)
	}
	t.Cleanup(baseline.Stop)

	wrapped, err := NewSolarServer("tcp://127.0.0.1:0", 8000, "")
	if err != nil {
		t.Fatalf("wrapped sim: %v", err)
	}
	t.Cleanup(wrapped.Stop)

	// Exactly modsim/main.go's wiring, minus the two opt-in relays.
	_ = NewRelocator(wrapped.Regs) // constructed, never told to move
	texc := NewTargetedException()
	wrapped.Regs.OnRead = texc.WrapOnRead(wrapped.Regs.OnRead)
	wrapped.Regs.OnWriteError = texc.OnWriteError
	_ = NewSentinelInjector(wrapped.Regs) // constructed, Seed never called
	_ = NewModelSplicer(wrapped.Regs)     // constructed, Insert never called

	// SunS header (40000-40001) through the complete Model 1 Common block
	// (40002-40069): entirely static content, safe against animation timing.
	for addr := uint16(40000); addr < 40070; addr++ {
		want := baseline.Regs.Get(addr)
		got := wrapped.Regs.Get(addr)
		if got != want {
			t.Fatalf("register %d = %d on the wrapped sim, want the baseline's %d — "+
				"a layer changed default behaviour", addr, got, want)
		}
	}
}
