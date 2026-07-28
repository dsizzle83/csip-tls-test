package simapi

import (
	"fmt"
	"testing"
)

// TestSinceStaysExactAcrossTheWrap is the regression test for the defect that
// produced 22 false CSIP failures on 2026-07-28.
//
// The harness derived "what happened since I last looked" from the RING's
// length. That is correct until the ring fills; after that len() is pinned at
// maxLogLines and the computed delta is empty forever, while the device under
// test goes on doing exactly what it was asked to do. The failure mode is the
// dangerous one: an empty delta reads as "the DUT did nothing", so a healthy
// gateway is reported as non-conformant rather than the run erroring out.
//
// This test asserts the cursor keeps the delta exact across the wrap, which the
// length-based scheme cannot do at any ring size.
func TestSinceStaysExactAcrossTheWrap(t *testing.T) {
	lb := NewLogBuffer()

	write := func(n int) {
		t.Helper()
		for i := 0; i < n; i++ {
			if _, err := fmt.Fprintf(lb, "line %d\n", i); err != nil {
				t.Fatalf("write: %v", err)
			}
		}
	}

	// Fill well past the ring so it is guaranteed to have evicted.
	write(maxLogLines)
	full := lb.Since(0)
	if got := len(full.Lines); got != maxLogLines {
		t.Fatalf("after filling: got %d lines, want %d", got, maxLogLines)
	}
	cursor := full.Next

	// The length-based scheme's exact failure: the ring is full, so len() can
	// no longer grow. Anything written now is invisible to a length delta.
	const after = 50
	write(after)

	got := lb.Since(cursor)
	if len(got.Lines) != after {
		t.Errorf("delta across the wrap = %d lines, want %d "+
			"(a length-based delta would report 0 here — the false-FAIL bug)",
			len(got.Lines), after)
	}
	if got.Dropped != 0 {
		t.Errorf("Dropped = %d, want 0: the reader's cursor was still retained", got.Dropped)
	}
	if got.Next != cursor+after {
		t.Errorf("Next = %d, want %d", got.Next, cursor+after)
	}
	if len(got.Lines) > 0 && got.Lines[0] != "line 0" {
		t.Errorf("first line of the delta = %q, want %q", got.Lines[0], "line 0")
	}
}

// TestSinceReportsWhatItEvicted pins the other half of the contract: when a
// reader falls far enough behind that its cursor is gone, the loss is REPORTED.
// Silently returning the surviving suffix is what let truncation masquerade as
// silence in the first place.
func TestSinceReportsWhatItEvicted(t *testing.T) {
	lb := NewLogBuffer()
	if _, err := fmt.Fprint(lb, "first\n"); err != nil {
		t.Fatalf("write: %v", err)
	}
	cursor := uint64(0) // a reader holding the very beginning

	// Overrun the ring by a known amount.
	const overrun = 25
	for i := 0; i < maxLogLines+overrun; i++ {
		if _, err := fmt.Fprintf(lb, "x %d\n", i); err != nil {
			t.Fatalf("write: %v", err)
		}
	}

	got := lb.Since(cursor)
	// 1 ("first") + maxLogLines + overrun written; maxLogLines retained.
	wantDropped := uint64(1 + overrun)
	if got.Dropped != wantDropped {
		t.Errorf("Dropped = %d, want %d", got.Dropped, wantDropped)
	}
	if len(got.Lines) != maxLogLines {
		t.Errorf("Lines = %d, want %d (the surviving ring)", len(got.Lines), maxLogLines)
	}
	if got.Next != uint64(1+maxLogLines+overrun) {
		t.Errorf("Next = %d, want %d", got.Next, 1+maxLogLines+overrun)
	}
}

// TestSinceHandlesAFutureCursor guards the arithmetic: a cursor past the end
// must clamp rather than panic on the slice index.
func TestSinceHandlesAFutureCursor(t *testing.T) {
	lb := NewLogBuffer()
	if _, err := fmt.Fprint(lb, "only\n"); err != nil {
		t.Fatalf("write: %v", err)
	}
	got := lb.Since(9999)
	if len(got.Lines) != 0 {
		t.Errorf("Lines = %d, want 0", len(got.Lines))
	}
	if got.Next != 1 {
		t.Errorf("Next = %d, want 1", got.Next)
	}
}
